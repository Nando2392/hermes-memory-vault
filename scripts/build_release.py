from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import subprocess
import zipfile


@dataclass(frozen=True)
class ReleaseAssets:
    archive: Path
    checksum: Path
    manifest: Path
    manifest_checksum: Path


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _regular_file(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"release input is not a regular file: {path.name}")
    return path.read_bytes()


def build_release(
    *,
    repo: Path,
    dist: Path,
    version: str,
    platform: str,
    git_commit: str,
    git_tree: str,
    reviewed_digest: str,
) -> ReleaseAssets:
    if re.fullmatch(r"v\d+\.\d+\.\d+", version) is None:
        raise ValueError("version must be vMAJOR.MINOR.PATCH")
    if platform not in {"windows-x86_64", "linux-x86_64"}:
        raise ValueError("unsupported release platform")
    if re.fullmatch(r"[0-9a-f]{40}", git_commit) is None or re.fullmatch(
        r"[0-9a-f]{40}", git_tree
    ) is None:
        raise ValueError("invalid git provenance")
    if re.fullmatch(r"[0-9a-f]{64}", reviewed_digest) is None:
        raise ValueError("invalid reviewed digest")

    binary_name = "hermes-memory.exe" if platform == "windows-x86_64" else "hermes-memory"
    source_paths = {
        f"bin/{binary_name}": repo / "target" / "release" / binary_name,
        "plugins/vault/__init__.py": repo / "plugin" / "vault" / "__init__.py",
        "plugins/vault/plugin.yaml": repo / "plugin" / "vault" / "plugin.yaml",
        "README.md": repo / "README.md",
        "LICENSE": repo / "LICENSE",
        "install-memory-vault.py": repo / "install-memory-vault.py",
        "installer/__init__.py": repo / "installer" / "__init__.py",
        "installer/hermes_memory_vault_installer.py": repo
        / "installer"
        / "hermes_memory_vault_installer.py",
    }
    payload = {name: _regular_file(path) for name, path in source_paths.items()}
    file_hashes = {name: _sha256(value) for name, value in payload.items()}
    sums = "".join(f"{file_hashes[name]} *{name}\n" for name in sorted(payload)).encode(
        "utf-8"
    )
    archive_name = f"hermes-memory-vault-{version}-{platform}.zip"
    dist.mkdir(parents=True, exist_ok=True)
    archive_path = dist / archive_name
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in (*payload.keys(), "SHA256SUMS"):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            mode = 0o755 if name == f"bin/{binary_name}" else 0o644
            info.external_attr = (0o100000 | mode) << 16
            archive.writestr(info, sums if name == "SHA256SUMS" else payload[name])
    archive_sha = _sha256(archive_path.read_bytes())
    checksum_path = dist / f"{archive_name}.sha256"
    checksum_path.write_text(f"{archive_sha} *{archive_name}\n", encoding="ascii")
    manifest_path = dist / f"release-manifest-{version}-{platform}.json"
    manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "release": version,
                "platform": platform,
                "git_commit": git_commit,
                "git_tree": git_tree,
                "reviewed_staged_diff_sha256": reviewed_digest,
                "archive": {"name": archive_name, "sha256": archive_sha},
                "files": file_hashes,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    manifest_checksum_path = dist / f"{manifest_path.name}.sha256"
    manifest_checksum_path.write_text(
        f"{_sha256(manifest_path.read_bytes())} *{manifest_path.name}\n",
        encoding="ascii",
    )
    return ReleaseAssets(
        archive_path,
        checksum_path,
        manifest_path,
        manifest_checksum_path,
    )


def _git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        text=True,
        encoding="utf-8",
        errors="strict",
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError("git provenance lookup failed")
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Build deterministic Memory Vault release assets")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--reviewed-digest", required=True)
    args = parser.parse_args()
    repo = args.repo.resolve(strict=True)
    assets = build_release(
        repo=repo,
        dist=args.dist.resolve(),
        version=args.version,
        platform=args.platform,
        git_commit=_git(repo, "rev-parse", "HEAD"),
        git_tree=_git(repo, "rev-parse", "HEAD^{tree}"),
        reviewed_digest=args.reviewed_digest,
    )
    print(
        json.dumps(
            {
                "archive": str(assets.archive),
                "manifest": str(assets.manifest),
                "manifest_checksum": str(assets.manifest_checksum),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
