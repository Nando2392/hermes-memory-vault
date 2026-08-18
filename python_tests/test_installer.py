from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

import installer.hermes_memory_vault_installer as installer_module
from installer.hermes_memory_vault_installer import (
    BINARY_NAME,
    InstallError,
    PLATFORM,
    download_release,
    install_bundle,
)


BINARY_PATH = f"bin/{BINARY_NAME}"
MANAGED_CONTENT = {
    BINARY_PATH: b"vault-binary-v0.2.0",
    "plugins/vault/__init__.py": b"def register(ctx):\n    pass\n",
    "plugins/vault/plugin.yaml": b"name: vault\nversion: 0.2.0\n",
    "README.md": b"# test bundle\n",
    "LICENSE": b"MIT\n",
    "install-memory-vault.py": b"# standalone wrapper\n",
    "installer/__init__.py": b'"""installer"""\n',
    "installer/hermes_memory_vault_installer.py": b"# installer module\n",
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_atomic_copy_preserves_binary_payload_byte_for_byte(tmp_path: Path) -> None:
    source = tmp_path / "source.exe"
    target = tmp_path / "target.exe"
    payload = b"MZ\r\n" + bytes(range(256)) + b"\x1a" + b"\x00\xff" * 8192
    source.write_bytes(payload)

    installer_module._atomic_copy(source, target)

    assert target.read_bytes() == payload


def make_bundle(
    root: Path,
    *,
    version: str = "v0.2.0",
    managed_content: dict[str, bytes] | None = None,
    git_commit: str = "a" * 40,
) -> tuple[Path, Path, str]:
    content_map = managed_content or MANAGED_CONTENT
    bundle = root / f"hermes-memory-vault-{version}-{PLATFORM}.zip"
    sums = "".join(
        f"{sha256_bytes(content)} *{name}\n"
        for name, content in content_map.items()
    ).encode("utf-8")
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in content_map.items():
            archive.writestr(name, content)
        archive.writestr("SHA256SUMS", sums)
    bundle_sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
    manifest = root / f"release-manifest-{version}.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "release": version,
                "platform": PLATFORM,
                "git_commit": git_commit,
                "git_tree": "b" * 40,
                "reviewed_staged_diff_sha256": "c" * 64,
                "archive": {"name": bundle.name, "sha256": bundle_sha},
                "files": {
                    name: sha256_bytes(content)
                    for name, content in content_map.items()
                },
            }
        ),
        encoding="utf-8",
    )
    manifest.with_suffix(".json.sha256").write_text(
        f"{hashlib.sha256(manifest.read_bytes()).hexdigest()} *{manifest.name}\n",
        encoding="ascii",
    )
    return bundle, manifest, bundle_sha


def replace_zip_entry(bundle: Path, entry: str, content: bytes) -> None:
    with zipfile.ZipFile(bundle, "r") as archive:
        values = {
            info.filename: archive.read(info)
            for info in archive.infolist()
            if info.filename != entry
        }
    values[entry] = content
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in values.items():
            archive.writestr(name, value)


def update_manifest_archive_checksum(manifest: Path, bundle: Path) -> str:
    bundle_sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["archive"]["sha256"] = bundle_sha
    manifest.write_text(json.dumps(value), encoding="utf-8")
    manifest.with_suffix(".json.sha256").write_text(
        f"{hashlib.sha256(manifest.read_bytes()).hexdigest()} *{manifest.name}\n",
        encoding="ascii",
    )
    return bundle_sha


def append_zip_entry(bundle: Path, name: str, content: bytes = b"attack") -> None:
    with zipfile.ZipFile(bundle, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, content)


def test_clean_install_from_verified_local_bundle(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    bundle, manifest, bundle_sha = make_bundle(source)

    result = install_bundle(
        bundle=bundle,
        expected_sha256=bundle_sha,
        release_manifest=manifest,
        home=home,
        activate=False,
    )

    assert result["action"] == "install"
    assert result["version"] == "v0.2.0"
    assert result["changed"] is True
    assert (home / "bin" / BINARY_NAME).read_bytes() == MANAGED_CONTENT[
        BINARY_PATH
    ]
    assert (home / "plugins" / "vault" / "__init__.py").read_bytes() == MANAGED_CONTENT[
        "plugins/vault/__init__.py"
    ]
    install_manifest = json.loads(
        (home / "memory-vault" / "installer" / "install-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert install_manifest["version"] == "v0.2.0"
    assert install_manifest["archive_sha256"] == bundle_sha
    assert set(install_manifest["managed_files"]) == {
        BINARY_PATH,
        "plugins/vault/__init__.py",
        "plugins/vault/plugin.yaml",
    }


def test_reinstall_same_version_is_idempotent_without_new_backup(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    bundle, manifest, bundle_sha = make_bundle(source)
    install_bundle(
        bundle=bundle,
        expected_sha256=bundle_sha,
        release_manifest=manifest,
        home=home,
        activate=False,
    )
    binary = home / "bin" / BINARY_NAME
    before_mtime = binary.stat().st_mtime_ns
    backups = home / "memory-vault" / "installer" / "backups"
    before_backups = sorted(path.name for path in backups.iterdir())

    result = install_bundle(
        bundle=bundle,
        expected_sha256=bundle_sha,
        release_manifest=manifest,
        home=home,
        activate=False,
    )

    assert result == {
        "action": "unchanged",
        "version": "v0.2.0",
        "changed": False,
        "archive_sha256": bundle_sha,
        "activated": False,
    }
    assert binary.stat().st_mtime_ns == before_mtime
    assert sorted(path.name for path in backups.iterdir()) == before_backups


def test_update_replaces_only_managed_files_and_preserves_user_data(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    old_content = {
        **MANAGED_CONTENT,
        BINARY_PATH: b"vault-binary-v0.1.1",
        "plugins/vault/plugin.yaml": b"name: vault\nversion: 0.1.1\n",
    }
    old_bundle, old_manifest, old_sha = make_bundle(
        source, version="v0.1.1", managed_content=old_content
    )
    install_bundle(
        bundle=old_bundle,
        expected_sha256=old_sha,
        release_manifest=old_manifest,
        home=home,
        activate=False,
    )
    preserved = {
        "memory-vault/memory.db": b"db-bytes",
        "memory-vault/memory.db-wal": b"wal-bytes",
        "memory-vault/memory.db-shm": b"shm-bytes",
        "memory-vault/events.jsonl": b'{"event":"bytes"}\n',
        "memory-vault/vault/session.md": b"# export bytes\n",
        "config.yaml": b"model: custom\n",
    }
    for relative, content in preserved.items():
        target = home / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    new_bundle, new_manifest, new_sha = make_bundle(source)

    result = install_bundle(
        bundle=new_bundle,
        expected_sha256=new_sha,
        release_manifest=new_manifest,
        home=home,
        activate=False,
    )

    assert result["action"] == "update"
    assert (home / "bin" / BINARY_NAME).read_bytes() == MANAGED_CONTENT[
        BINARY_PATH
    ]
    for relative, content in preserved.items():
        assert (home / relative).read_bytes() == content


def test_downgrade_requires_explicit_flag_before_any_write(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    current_bundle, current_manifest, current_sha = make_bundle(source)
    install_bundle(
        bundle=current_bundle,
        expected_sha256=current_sha,
        release_manifest=current_manifest,
        home=home,
        activate=False,
    )
    before_binary = (home / "bin" / BINARY_NAME).read_bytes()
    backups = home / "memory-vault" / "installer" / "backups"
    before_backups = sorted(path.name for path in backups.iterdir())
    old_content = {
        **MANAGED_CONTENT,
        BINARY_PATH: b"older-binary",
        "plugins/vault/plugin.yaml": b"name: vault\nversion: 0.1.1\n",
    }
    old_bundle, old_manifest, old_sha = make_bundle(
        source, version="v0.1.1", managed_content=old_content
    )

    with pytest.raises(InstallError, match="downgrade"):
        install_bundle(
            bundle=old_bundle,
            expected_sha256=old_sha,
            release_manifest=old_manifest,
            home=home,
            activate=False,
        )

    assert (home / "bin" / BINARY_NAME).read_bytes() == before_binary
    assert sorted(path.name for path in backups.iterdir()) == before_backups


def test_failure_during_second_swap_rolls_back_all_managed_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    old_content = {
        **MANAGED_CONTENT,
        BINARY_PATH: b"old-binary",
        "plugins/vault/__init__.py": b"old-plugin-init\n",
        "plugins/vault/plugin.yaml": b"name: vault\nversion: 0.1.1\n",
    }
    old_bundle, old_manifest, old_sha = make_bundle(
        source, version="v0.1.1", managed_content=old_content
    )
    install_bundle(
        bundle=old_bundle,
        expected_sha256=old_sha,
        release_manifest=old_manifest,
        home=home,
        activate=False,
    )
    before = {
        relative: (home / relative).read_bytes()
        for relative in (
            BINARY_PATH,
            "plugins/vault/__init__.py",
            "plugins/vault/plugin.yaml",
            "memory-vault/installer/install-manifest.json",
        )
    }
    sentinel = home / "memory-vault" / "events.jsonl"
    sentinel.write_bytes(b"preserve-rollback-sentinel\n")
    bundle, manifest, bundle_sha = make_bundle(source)
    real_atomic_copy = installer_module._atomic_copy
    failed = False

    def fail_second_managed_swap(copy_source: Path, copy_target: Path) -> None:
        nonlocal failed
        if (
            not failed
            and copy_target == home / "plugins" / "vault" / "__init__.py"
            and "staging-" in str(copy_source)
        ):
            failed = True
            raise OSError("induced second swap failure")
        real_atomic_copy(copy_source, copy_target)

    monkeypatch.setattr(installer_module, "_atomic_copy", fail_second_managed_swap)

    with pytest.raises(OSError, match="induced second swap failure"):
        install_bundle(
            bundle=bundle,
            expected_sha256=bundle_sha,
            release_manifest=manifest,
            home=home,
            activate=False,
        )

    assert failed is True
    for relative, content in before.items():
        assert (home / relative).read_bytes() == content
    assert sentinel.read_bytes() == b"preserve-rollback-sentinel\n"


def test_dry_run_validates_internal_checksums_without_writing_home(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    bundle, manifest, _bundle_sha = make_bundle(source)
    replace_zip_entry(bundle, "SHA256SUMS", b"0" * 64 + b" *README.md\n")
    bundle_sha = update_manifest_archive_checksum(manifest, bundle)

    with pytest.raises(InstallError, match="SHA256SUMS"):
        install_bundle(
            bundle=bundle,
            expected_sha256=bundle_sha,
            release_manifest=manifest,
            home=home,
            activate=False,
            dry_run=True,
        )

    assert list(home.iterdir()) == []


def test_tampered_release_manifest_is_rejected_by_external_checksum(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    bundle, manifest, bundle_sha = make_bundle(source)
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["git_commit"] = "d" * 40
    manifest.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(InstallError, match="manifest checksum"):
        install_bundle(
            bundle=bundle,
            expected_sha256=bundle_sha,
            release_manifest=manifest,
            home=home,
            activate=False,
        )

    assert list(home.iterdir()) == []


def test_external_binary_override_blocks_profile_install_before_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    external = tmp_path / "external" / "hermes-memory.exe"
    external.parent.mkdir()
    external.write_bytes(b"external-authoritative-binary")
    monkeypatch.setenv("HERMES_MEMORY_BIN", str(external))
    bundle, manifest, bundle_sha = make_bundle(source)

    with pytest.raises(InstallError, match="HERMES_MEMORY_BIN"):
        install_bundle(
            bundle=bundle,
            expected_sha256=bundle_sha,
            release_manifest=manifest,
            home=home,
            activate=False,
        )

    assert list(home.iterdir()) == []
    assert external.read_bytes() == b"external-authoritative-binary"


def test_activate_uses_public_hermes_config_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    bundle, manifest, bundle_sha = make_bundle(source)
    calls: list[tuple[list[str], dict[str, str]]] = []

    def capture_run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs["env"]))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", capture_run)

    result = install_bundle(
        bundle=bundle,
        expected_sha256=bundle_sha,
        release_manifest=manifest,
        home=home,
        activate=True,
    )

    assert result["activated"] is True
    assert [command for command, _env in calls] == [
        ["hermes", "config", "set", "memory.provider", "vault"]
    ]
    assert calls[0][1]["HERMES_HOME"] == str(home)
    assert not (home / "config.yaml").exists()


def test_activate_is_applied_when_installation_is_already_current(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    bundle, manifest, bundle_sha = make_bundle(source)
    install_bundle(
        bundle=bundle,
        expected_sha256=bundle_sha,
        release_manifest=manifest,
        home=home,
        activate=False,
    )
    calls: list[list[str]] = []

    def capture_run(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", capture_run)

    result = install_bundle(
        bundle=bundle,
        expected_sha256=bundle_sha,
        release_manifest=manifest,
        home=home,
        activate=True,
    )

    assert result["action"] == "unchanged"
    assert result["activated"] is True
    assert calls == [["hermes", "config", "set", "memory.provider", "vault"]]


def test_same_version_rebuild_with_identical_managed_files_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first_source = tmp_path / "first-source"
    first_source.mkdir()
    second_source = tmp_path / "second-source"
    second_source.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    first_bundle, first_manifest, first_sha = make_bundle(first_source)
    install_bundle(
        bundle=first_bundle,
        expected_sha256=first_sha,
        release_manifest=first_manifest,
        home=home,
        activate=False,
    )
    binary = home / BINARY_PATH
    before_mtime = binary.stat().st_mtime_ns
    backups = home / "memory-vault" / "installer" / "backups"
    before_backups = sorted(path.name for path in backups.iterdir())
    rebuilt_content = {**MANAGED_CONTENT, "README.md": b"# rebuilt release\n"}
    second_bundle, second_manifest, second_sha = make_bundle(
        second_source,
        managed_content=rebuilt_content,
        git_commit="d" * 40,
    )
    calls: list[list[str]] = []

    def capture_run(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", capture_run)

    result = install_bundle(
        bundle=second_bundle,
        expected_sha256=second_sha,
        release_manifest=second_manifest,
        home=home,
        activate=True,
    )

    assert result["action"] == "unchanged"
    assert result["archive_sha256"] == second_sha
    assert result["activated"] is True
    assert binary.stat().st_mtime_ns == before_mtime
    assert sorted(path.name for path in backups.iterdir()) == before_backups
    installed = json.loads(
        (home / "memory-vault" / "installer" / "install-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert installed["git_commit"] == "d" * 40
    assert installed["archive_sha256"] == second_sha
    assert calls == [["hermes", "config", "set", "memory.provider", "vault"]]


def test_hardlinked_managed_target_is_rejected_before_staging(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    binary = home / "bin" / BINARY_NAME
    binary.parent.mkdir(parents=True)
    victim = tmp_path / "victim.exe"
    victim.write_bytes(b"must-not-change")
    os.link(victim, binary)
    bundle, manifest, bundle_sha = make_bundle(source)

    with pytest.raises(InstallError, match="hardlinked"):
        install_bundle(
            bundle=bundle,
            expected_sha256=bundle_sha,
            release_manifest=manifest,
            home=home,
            activate=False,
        )

    assert victim.read_bytes() == b"must-not-change"
    assert not (home / "memory-vault").exists()


def test_reparse_backup_root_is_rejected_before_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    backup_root = home / "memory-vault" / "installer" / "backups"
    backup_root.mkdir(parents=True)
    bundle, manifest, bundle_sha = make_bundle(source)
    real_is_reparse = installer_module._is_reparse_point
    monkeypatch.setattr(
        installer_module,
        "_is_reparse_point",
        lambda path: path == backup_root or real_is_reparse(path),
    )

    with pytest.raises(InstallError, match="unsafe directory"):
        install_bundle(
            bundle=bundle,
            expected_sha256=bundle_sha,
            release_manifest=manifest,
            home=home,
            activate=False,
        )

    assert list(backup_root.iterdir()) == []


def test_parent_swap_during_copy_cannot_escape_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    bundle, manifest, bundle_sha = make_bundle(source)
    real_atomic_copy = installer_module._atomic_copy
    attacked = False

    def racing_copy(source_path: Path, target_path: Path) -> None:
        nonlocal attacked
        expected_target = home / "bin" / BINARY_NAME
        if target_path == expected_target and not attacked:
            attacked = True
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.parent.rename(home / "bin-before-race")
            if os.name == "nt":
                result = subprocess.run(
                    ["cmd.exe", "/c", "mklink", "/J", str(target_path.parent), str(outside)],
                    capture_output=True,
                    check=False,
                    text=True,
                )
                assert result.returncode == 0, result.stderr
            else:
                target_path.parent.symlink_to(outside, target_is_directory=True)
        real_atomic_copy(source_path, target_path)

    monkeypatch.setattr(installer_module, "_atomic_copy", racing_copy)

    with pytest.raises(InstallError, match="unsafe|race|directory"):
        install_bundle(
            bundle=bundle,
            expected_sha256=bundle_sha,
            release_manifest=manifest,
            home=home,
            activate=False,
        )

    assert attacked is True
    assert not (outside / BINARY_NAME).exists()


def test_download_explicit_release_fetches_only_expected_https_assets(
    tmp_path: Path,
) -> None:
    asset_name = f"hermes-memory-vault-v0.2.0-{PLATFORM}.zip"
    bundle_bytes = b"PK-test-release-bundle"
    bundle_sha = hashlib.sha256(bundle_bytes).hexdigest()
    manifest_bytes = json.dumps(
        {
            "schema_version": 1,
            "release": "v0.2.0",
            "platform": PLATFORM,
            "git_commit": "a" * 40,
            "git_tree": "b" * 40,
            "reviewed_staged_diff_sha256": "c" * 64,
            "archive": {"name": asset_name, "sha256": bundle_sha},
            "files": {},
        }
    ).encode("utf-8")
    payloads = {
        asset_name: bundle_bytes,
        f"{asset_name}.sha256": f"{bundle_sha} *{asset_name}\n".encode("ascii"),
        f"release-manifest-v0.2.0-{PLATFORM}.json": manifest_bytes,
        f"release-manifest-v0.2.0-{PLATFORM}.json.sha256": (
            f"{hashlib.sha256(manifest_bytes).hexdigest()} *release-manifest-v0.2.0-{PLATFORM}.json\n"
        ).encode("ascii"),
    }
    requested: list[str] = []

    class FakeResponse:
        def __init__(self, url: str, payload: bytes) -> None:
            self.url = url
            self.payload = payload
            self.offset = 0
            self.headers = {"Content-Length": str(len(payload))}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def geturl(self) -> str:
            return self.url

        def read(self, size: int = -1) -> bytes:
            if size < 0:
                size = len(self.payload) - self.offset
            chunk = self.payload[self.offset : self.offset + size]
            self.offset += len(chunk)
            return chunk

    def fake_open(url: str, *, timeout: int):
        assert timeout == 30
        requested.append(url)
        return FakeResponse(url, payloads[url.rsplit("/", 1)[-1]])

    downloaded = download_release("v0.2.0", tmp_path / "download", opener=fake_open)

    assert downloaded.bundle.read_bytes() == bundle_bytes
    assert downloaded.expected_sha256 == bundle_sha
    assert downloaded.release_manifest.read_bytes() == manifest_bytes
    assert requested == [
        f"https://github.com/Nando2392/hermes-memory-vault/releases/download/v0.2.0/{asset_name}",
        f"https://github.com/Nando2392/hermes-memory-vault/releases/download/v0.2.0/{asset_name}.sha256",
        f"https://github.com/Nando2392/hermes-memory-vault/releases/download/v0.2.0/release-manifest-v0.2.0-{PLATFORM}.json",
        f"https://github.com/Nando2392/hermes-memory-vault/releases/download/v0.2.0/release-manifest-v0.2.0-{PLATFORM}.json.sha256",
    ]

    payloads[f"release-manifest-v0.2.0-{PLATFORM}.json.sha256"] = (
        f"{'0' * 64} *release-manifest-v0.2.0-{PLATFORM}.json\n"
    ).encode("ascii")
    with pytest.raises(InstallError, match="manifest checksum"):
        download_release("v0.2.0", tmp_path / "tampered", opener=fake_open)


def test_standalone_cli_installs_local_bundle_and_outputs_json(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    bundle, manifest, bundle_sha = make_bundle(source)
    script = Path(__file__).parents[1] / "install-memory-vault.py"

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "install",
            "--home",
            str(home),
            "--bundle",
            str(bundle),
            "--sha256",
            bundle_sha,
            "--release-manifest",
            str(manifest),
        ],
        text=True,
        encoding="utf-8",
        errors="strict",
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["success"] is True
    assert payload["action"] == "install"
    assert (home / "plugins" / "vault" / "plugin.yaml").is_file()


def test_bad_external_checksum_is_rejected_before_writes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    bundle, manifest, _bundle_sha = make_bundle(source)

    with pytest.raises(InstallError, match="external archive checksum"):
        install_bundle(
            bundle=bundle,
            expected_sha256="0" * 64,
            release_manifest=manifest,
            home=home,
            activate=False,
        )

    assert list(home.iterdir()) == []


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "../escape.txt",
        "/absolute.txt",
        "plugins/vault/plugin.yaml:stream",
        "README.MD",
    ],
)
def test_unsafe_or_ambiguous_zip_entries_are_rejected_before_writes(
    tmp_path: Path, unsafe_name: str
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    bundle, manifest, _bundle_sha = make_bundle(source)
    append_zip_entry(bundle, unsafe_name)
    bundle_sha = update_manifest_archive_checksum(manifest, bundle)

    with pytest.raises(InstallError, match="unsafe or unexpected"):
        install_bundle(
            bundle=bundle,
            expected_sha256=bundle_sha,
            release_manifest=manifest,
            home=home,
            activate=False,
        )

    assert list(home.iterdir()) == []
