from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tempfile
from typing import Any
import unicodedata
from urllib.parse import urlparse
from urllib.request import urlopen
import uuid
import zipfile


MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_ENTRY_BYTES = 96 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 192 * 1024 * 1024
PLATFORM = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
BINARY_NAME = "hermes-memory.exe" if os.name == "nt" else "hermes-memory"
MANAGED_PATHS = (
    f"bin/{BINARY_NAME}",
    "plugins/vault-standalone/__init__.py",
    "plugins/vault-standalone/plugin.yaml",
)
DOCUMENT_PATHS = (
    "README.md",
    "LICENSE",
    "install-memory-vault.py",
    "installer/__init__.py",
    "installer/hermes_memory_vault_installer.py",
)
ALLOWED_PATHS = frozenset((*MANAGED_PATHS, *DOCUMENT_PATHS, "SHA256SUMS"))
INSTALLER_ROOT = Path("memory-vault") / "installer"
INSTALL_MANIFEST = INSTALLER_ROOT / "install-manifest.json"
RELEASE_BASE_URL = "https://github.com/Nando2392/hermes-memory-vault/releases/download"
ALLOWED_DOWNLOAD_HOSTS = frozenset(
    {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
)


class InstallError(RuntimeError):
    """Raised when installer validation or transaction processing fails."""


@dataclass(frozen=True)
class DownloadedRelease:
    """Paths and trusted external checksum for a downloaded explicit release."""

    bundle: Path
    release_manifest: Path
    expected_sha256: str


def _download_file(
    url: str,
    destination: Path,
    *,
    max_bytes: int,
    opener: Any,
) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise InstallError("release URL is not an allowed HTTPS origin")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    try:
        try:
            response_context = opener(url, timeout=30)
            with response_context as response:
                final = urlparse(response.geturl())
                if final.scheme != "https" or final.hostname not in ALLOWED_DOWNLOAD_HOSTS:
                    raise InstallError("release redirect left the HTTPS host allowlist")
                raw_length = response.headers.get("Content-Length")
                if raw_length is not None:
                    try:
                        content_length = int(raw_length)
                    except ValueError as error:
                        raise InstallError("release response has invalid Content-Length") from error
                    if content_length < 0 or content_length > max_bytes:
                        raise InstallError("release asset exceeds size limit")
                total = 0
                with temporary.open("xb") as writer:
                    while chunk := response.read(1024 * 1024):
                        total += len(chunk)
                        if total > max_bytes:
                            raise InstallError("release asset exceeds size limit")
                        writer.write(chunk)
                    writer.flush()
                    os.fsync(writer.fileno())
        except InstallError:
            raise
        except Exception as error:
            raise InstallError("release download failed") from error
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)


def download_release(
    tag: str,
    destination: Path,
    *,
    opener: Any = urlopen,
) -> DownloadedRelease:
    """Download one explicit GitHub release and its external attestations."""
    _semver(tag)
    if not destination.is_absolute():
        raise InstallError("download destination must be absolute")
    asset_name = f"hermes-memory-vault-{tag}-{PLATFORM}.zip"
    checksum_name = f"{asset_name}.sha256"
    manifest_name = f"release-manifest-{tag}-{PLATFORM}.json"
    manifest_checksum_name = f"{manifest_name}.sha256"
    base = f"{RELEASE_BASE_URL}/{tag}"
    bundle = destination / asset_name
    checksum = destination / checksum_name
    manifest = destination / manifest_name
    manifest_checksum = destination / manifest_checksum_name
    _download_file(f"{base}/{asset_name}", bundle, max_bytes=MAX_ARCHIVE_BYTES, opener=opener)
    _download_file(f"{base}/{checksum_name}", checksum, max_bytes=4096, opener=opener)
    _download_file(f"{base}/{manifest_name}", manifest, max_bytes=1024 * 1024, opener=opener)
    _download_file(
        f"{base}/{manifest_checksum_name}",
        manifest_checksum,
        max_bytes=4096,
        opener=opener,
    )
    try:
        checksum_text = checksum.read_text(encoding="ascii", errors="strict")
    except (OSError, UnicodeError) as error:
        raise InstallError("invalid external checksum file") from error
    expected_line = checksum_text.strip().split()
    if (
        len(expected_line) != 2
        or len(expected_line[0]) != 64
        or any(character not in "0123456789abcdef" for character in expected_line[0].lower())
        or expected_line[1].lstrip("*") != asset_name
    ):
        raise InstallError("invalid external checksum file")
    expected_sha256 = expected_line[0].lower()
    if sha256_file(bundle) != expected_sha256:
        raise InstallError("downloaded archive checksum mismatch")
    _verify_release_manifest_checksum(manifest)
    return DownloadedRelease(bundle, manifest, expected_sha256)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _posix_parent_fd(path: Path) -> int:
    if not path.is_absolute():
        raise InstallError("atomic target must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


@contextmanager
def _windows_parent_fence(path: Path):
    import ctypes
    from ctypes import wintypes

    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = ctypes.windll.kernel32.CloseHandle
    invalid_handle = wintypes.HANDLE(-1).value
    handles: list[int] = []
    current = Path(path.anchor)
    try:
        for part in (None, *path.parts[1:]):
            if part is not None:
                current = current / part
                try:
                    current.mkdir()
                except FileExistsError:
                    pass
            handle = create_file(
                str(current),
                0x80,
                0x1 | 0x2,
                None,
                3,
                0x02000000 | 0x00200000,
                None,
            )
            if handle == invalid_handle:
                raise InstallError("could not fence target directory")
            handles.append(handle)
            if _is_reparse_point(current) or not current.is_dir() or current.is_symlink():
                raise InstallError("target directory changed during transaction")
        yield
    finally:
        for handle in reversed(handles):
            close_handle(handle)


def _atomic_write_payload(target: Path, payload: bytes, mode: int = 0o600) -> None:
    temporary_name = f".{target.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    if os.name == "nt":
        with _windows_parent_fence(target.parent):
            temporary = target.parent / temporary_name
            try:
                with temporary.open("xb") as writer:
                    writer.write(payload)
                    writer.flush()
                    os.fsync(writer.fileno())
                os.replace(temporary, target)
            finally:
                temporary.unlink(missing_ok=True)
        return

    parent_fd = _posix_parent_fd(target.parent)
    temporary_fd = -1
    try:
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
            dir_fd=parent_fd,
        )
        view = memoryview(payload)
        while view:
            written = os.write(temporary_fd, view)
            view = view[written:]
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        os.replace(
            temporary_name,
            target.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def _atomic_copy(source: Path, target: Path) -> None:
    _require_safe_existing_file(source, "atomic copy source")
    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor = os.open(source, source_flags)
    try:
        source_stat = os.fstat(descriptor)
        if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_nlink != 1:
            raise InstallError("atomic copy source changed during transaction")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    _atomic_write_payload(target, b"".join(chunks), stat.S_IMODE(source_stat.st_mode))


def _atomic_write_json(target: Path, value: dict[str, Any]) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    _atomic_write_payload(target, payload)


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = os.lstat(path).st_file_attributes
    except (AttributeError, FileNotFoundError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _require_safe_root(home: Path) -> Path:
    if not home.is_absolute():
        raise InstallError("Hermes home must be an absolute path")
    if not home.exists() or not home.is_dir() or home.is_symlink() or _is_reparse_point(home):
        raise InstallError("Hermes home is not a safe directory")
    resolved = home.resolve(strict=True)
    if resolved != home:
        raise InstallError("Hermes home traverses a link or ambiguous path")
    return resolved


def _require_safe_existing_file(path: Path, label: str) -> None:
    if path.is_symlink() or _is_reparse_point(path) or not path.is_file():
        raise InstallError(f"unsafe {label}")
    if os.stat(path, follow_symlinks=False).st_nlink != 1:
        raise InstallError(f"hardlinked {label}")


def _safe_target(home: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or ":" in relative or "\\" in relative:
        raise InstallError("unsafe managed path")
    candidate = home.joinpath(*pure.parts)
    parent = home
    for part in pure.parts[:-1]:
        parent = parent / part
        if parent.exists() and (not parent.is_dir() or parent.is_symlink() or _is_reparse_point(parent)):
            raise InstallError("managed path traverses an unsafe directory")
    if candidate.exists():
        _require_safe_existing_file(candidate, "managed target")
    return candidate


def _verify_release_manifest_checksum(path: Path) -> None:
    _require_safe_existing_file(path, "release manifest")
    checksum_path = path.with_suffix(".json.sha256")
    _require_safe_existing_file(checksum_path, "release manifest checksum")
    try:
        checksum_fields = checksum_path.read_text(
            encoding="ascii", errors="strict"
        ).strip().split()
    except (OSError, UnicodeError) as error:
        raise InstallError("invalid release manifest checksum") from error
    if (
        len(checksum_fields) != 2
        or len(checksum_fields[0]) != 64
        or any(
            character not in "0123456789abcdef"
            for character in checksum_fields[0].lower()
        )
        or checksum_fields[1].lstrip("*") != path.name
        or sha256_file(path) != checksum_fields[0].lower()
    ):
        raise InstallError("release manifest checksum mismatch")


def _load_release_manifest(path: Path, *, bundle: Path, archive_sha256: str) -> dict[str, Any]:
    _verify_release_manifest_checksum(path)
    try:
        manifest = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InstallError("invalid release manifest") from error
    archive = manifest.get("archive")
    files = manifest.get("files")
    commit = manifest.get("git_commit")
    git_tree = manifest.get("git_tree")
    reviewed_digest = manifest.get("reviewed_staged_diff_sha256")
    release = manifest.get("release")
    expected_archive_name = (
        f"hermes-memory-vault-{release}-{PLATFORM}.zip"
        if isinstance(release, str)
        else ""
    )
    if isinstance(release, str):
        _semver(release)
    if (
        manifest.get("schema_version") != 1
        or not isinstance(release, str)
        or manifest.get("platform") != PLATFORM
        or not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit.lower())
        or not isinstance(git_tree, str)
        or len(git_tree) != 40
        or any(character not in "0123456789abcdef" for character in git_tree.lower())
        or not isinstance(reviewed_digest, str)
        or len(reviewed_digest) != 64
        or any(
            character not in "0123456789abcdef"
            for character in reviewed_digest.lower()
        )
        or not isinstance(archive, dict)
        or bundle.name != expected_archive_name
        or archive.get("name") != bundle.name
        or archive.get("sha256") != archive_sha256
        or not isinstance(files, dict)
        or set(files) != set((*MANAGED_PATHS, *DOCUMENT_PATHS))
    ):
        raise InstallError("release manifest does not match archive, platform, or file set")
    for digest in files.values():
        if not isinstance(digest, str) or len(digest) != 64:
            raise InstallError("release manifest contains an invalid file digest")
    return manifest


def _parse_sha256sums(payload: bytes) -> dict[str, str]:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise InstallError("SHA256SUMS is not strict UTF-8") from error
    result: dict[str, str] = {}
    for line in text.splitlines():
        if not line or len(line) < 67 or line[64:66] not in (" *", "  "):
            raise InstallError("invalid SHA256SUMS format")
        digest = line[:64].lower()
        name = line[66:]
        if any(character not in "0123456789abcdef" for character in digest):
            raise InstallError("invalid SHA256SUMS digest")
        if name in result:
            raise InstallError("duplicate SHA256SUMS entry")
        result[name] = digest
    expected = set((*MANAGED_PATHS, *DOCUMENT_PATHS))
    if set(result) != expected:
        raise InstallError("SHA256SUMS file set mismatch")
    return result


def _validate_zip_info(info: zipfile.ZipInfo, seen: set[str]) -> str:
    name = info.filename.replace("\\", "/")
    pure = PurePosixPath(name)
    normalized = unicodedata.normalize("NFC", name)
    folded = normalized.casefold()
    unix_mode = (info.external_attr >> 16) & 0o170000
    if (
        name != normalized
        or pure.is_absolute()
        or not pure.parts
        or ".." in pure.parts
        or ":" in name
        or name.startswith("/")
        or name.endswith("/")
        or name not in ALLOWED_PATHS
        or folded in seen
        or stat.S_ISLNK(unix_mode)
        or (unix_mode not in (0, stat.S_IFREG))
        or info.file_size > MAX_ENTRY_BYTES
    ):
        raise InstallError("archive contains an unsafe or unexpected entry")
    seen.add(folded)
    return name


def _stage_bundle(bundle: Path, staging: Path, manifest: dict[str, Any]) -> dict[str, str]:
    try:
        archive = zipfile.ZipFile(bundle)
    except (OSError, zipfile.BadZipFile) as error:
        raise InstallError("invalid ZIP archive") from error
    with archive:
        seen: set[str] = set()
        infos: dict[str, zipfile.ZipInfo] = {}
        total = 0
        for info in archive.infolist():
            name = _validate_zip_info(info, seen)
            total += info.file_size
            if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise InstallError("archive exceeds uncompressed size limit")
            infos[name] = info
        if set(infos) != ALLOWED_PATHS:
            raise InstallError("archive file allowlist mismatch")
        sums = _parse_sha256sums(archive.read(infos["SHA256SUMS"]))
        staged_hashes: dict[str, str] = {}
        for name in (*MANAGED_PATHS, *DOCUMENT_PATHS):
            target = staging.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with archive.open(infos[name], "r") as reader, target.open("xb") as writer:
                while chunk := reader.read(1024 * 1024):
                    digest.update(chunk)
                    writer.write(chunk)
                writer.flush()
                os.fsync(writer.fileno())
            actual = digest.hexdigest()
            if actual != sums[name] or actual != manifest["files"][name]:
                raise InstallError("bundle file integrity check failed")
            staged_hashes[name] = actual
        binary = staging.joinpath(*PurePosixPath(MANAGED_PATHS[0]).parts)
        if os.name != "nt":
            binary.chmod(0o755)
        return staged_hashes


def _read_installed_manifest(home: Path) -> dict[str, Any] | None:
    path = home / INSTALL_MANIFEST
    if not path.exists():
        return None
    _require_safe_existing_file(path, "installation manifest")
    try:
        value = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InstallError("invalid installation manifest") from error
    return value if isinstance(value, dict) else None


def _installation_matches(
    home: Path,
    current: dict[str, Any] | None,
    release: dict[str, Any],
) -> bool:
    if current is None:
        return False
    managed = current.get("managed_files")
    if (
        current.get("schema_version") != 1
        or current.get("version") != release["release"]
        or current.get("platform") != PLATFORM
        or not isinstance(managed, dict)
        or set(managed) != set(MANAGED_PATHS)
    ):
        return False
    for relative in MANAGED_PATHS:
        target = _safe_target(home, relative)
        if not target.exists() or release["files"][relative] != sha256_file(target):
            return False
    return True


def _install_manifest_value(
    manifest: dict[str, Any], bundle: Path, archive_sha256: str
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "version": manifest["release"],
        "platform": PLATFORM,
        "git_commit": manifest["git_commit"],
        "archive": bundle.name,
        "archive_sha256": archive_sha256,
        "managed_files": {
            relative: manifest["files"][relative] for relative in MANAGED_PATHS
        },
        "source": "local-bundle",
    }


def _semver(value: Any) -> tuple[int, int, int]:
    if not isinstance(value, str) or not value.startswith("v"):
        raise InstallError("release version is not supported SemVer")
    parts = value[1:].split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise InstallError("release version is not supported SemVer")
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def _activate_provider(home: Path) -> None:
    environment = os.environ.copy()
    environment["HERMES_HOME"] = str(home)
    try:
        result = subprocess.run(
            ["hermes", "config", "set", "memory.provider", "vault-standalone"],
            env=environment,
            text=True,
            encoding="utf-8",
            errors="strict",
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise InstallError("Hermes provider activation failed") from error
    if result.returncode != 0:
        raise InstallError("Hermes provider activation failed")


def install_bundle(
    *,
    bundle: Path,
    expected_sha256: str,
    release_manifest: Path,
    home: Path,
    activate: bool,
    dry_run: bool = False,
    allow_downgrade: bool = False,
) -> dict[str, Any]:
    home = _require_safe_root(home)
    configured_binary = os.environ.get("HERMES_MEMORY_BIN", "").strip()
    if configured_binary:
        configured_path = Path(configured_binary)
        managed_binary = home.joinpath(*PurePosixPath(MANAGED_PATHS[0]).parts)
        if (
            not configured_path.is_absolute()
            or configured_path.resolve(strict=False) != managed_binary.resolve(strict=False)
        ):
            raise InstallError(
                "HERMES_MEMORY_BIN is authoritative and points outside this profile installation"
            )
    bundle = bundle.resolve(strict=True)
    _require_safe_existing_file(bundle, "bundle")
    if bundle.stat().st_size > MAX_ARCHIVE_BYTES:
        raise InstallError("archive exceeds download size limit")
    expected_sha256 = expected_sha256.strip().lower()
    archive_sha256 = sha256_file(bundle)
    if len(expected_sha256) != 64 or archive_sha256 != expected_sha256:
        raise InstallError("external archive checksum mismatch")
    manifest = _load_release_manifest(
        release_manifest.resolve(strict=True),
        bundle=bundle,
        archive_sha256=archive_sha256,
    )
    current = _read_installed_manifest(home)
    if _installation_matches(home, current, manifest):
        unchanged = {
            "action": "unchanged",
            "version": manifest["release"],
            "changed": False,
            "archive_sha256": archive_sha256,
        }
        if dry_run:
            return {**unchanged, "dry_run": True}
        if activate:
            _activate_provider(home)
        _atomic_write_json(
            home / INSTALL_MANIFEST,
            _install_manifest_value(manifest, bundle, archive_sha256),
        )
        return {**unchanged, "activated": activate}
    if (
        current is not None
        and _semver(manifest["release"]) < _semver(current.get("version"))
        and not allow_downgrade
    ):
        raise InstallError("downgrade requires --allow-downgrade")
    action = "update" if current is not None else "install"
    if dry_run:
        with tempfile.TemporaryDirectory(prefix="hermes-memory-vault-dry-run-") as raw_staging:
            _stage_bundle(bundle, Path(raw_staging), manifest)
        return {
            "action": action,
            "version": manifest["release"],
            "changed": False,
            "dry_run": True,
        }

    for relative in (*MANAGED_PATHS, str(INSTALL_MANIFEST).replace("\\", "/")):
        _safe_target(home, relative)
    _safe_target(home, "memory-vault/installer/backups/.preflight")

    with tempfile.TemporaryDirectory(prefix="hermes-memory-vault-staging-") as raw_staging:
        staging = Path(raw_staging)
        staged_hashes = _stage_bundle(bundle, staging, manifest)
        backup_root = home / INSTALLER_ROOT / "backups"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = backup_root / f"{stamp}-{uuid.uuid4().hex[:8]}"
        backup_files = backup / "files"
        backup_files.mkdir(parents=True, exist_ok=False)
        backup_record: dict[str, Any] = {
            "schema_version": 1,
            "home": str(home),
            "target_version": manifest["release"],
            "archive_sha256": archive_sha256,
            "files": [],
        }
        for relative in (*MANAGED_PATHS, str(INSTALL_MANIFEST).replace("\\", "/")):
            target = _safe_target(home, relative)
            item: dict[str, Any] = {"path": relative, "existed": target.exists()}
            if target.exists():
                destination = backup_files.joinpath(*PurePosixPath(relative).parts)
                _atomic_copy(target, destination)
                item["sha256"] = sha256_file(destination)
            backup_record["files"].append(item)
        _atomic_write_json(backup / "backup-manifest.json", backup_record)

        try:
            for relative in MANAGED_PATHS:
                source = staging.joinpath(*PurePosixPath(relative).parts)
                target = _safe_target(home, relative)
                _atomic_copy(source, target)
                if sha256_file(target) != staged_hashes[relative]:
                    raise InstallError("post-install integrity check failed")
            install_manifest = _install_manifest_value(
                manifest, bundle, archive_sha256
            )
            _atomic_write_json(home / INSTALL_MANIFEST, install_manifest)
            if activate:
                _activate_provider(home)
        except Exception:
            for item in reversed(backup_record["files"]):
                target = _safe_target(home, item["path"])
                if item["existed"]:
                    source = backup_files.joinpath(*PurePosixPath(item["path"]).parts)
                    if sha256_file(source) != item["sha256"]:
                        raise InstallError("backup integrity check failed during rollback")
                    _atomic_copy(source, target)
                else:
                    target.unlink(missing_ok=True)
            raise

    return {
        "action": action,
        "version": manifest["release"],
        "changed": True,
        "archive_sha256": archive_sha256,
        "backup": str(backup),
        "activated": activate,
    }
