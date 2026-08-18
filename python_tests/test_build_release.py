from __future__ import annotations

import hashlib
import json
from pathlib import Path
import zipfile

from scripts.build_release import build_release


def test_build_release_emits_verified_standalone_assets(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    dist = tmp_path / "dist"
    files = {
        "target/release/hermes-memory.exe": b"release-binary",
        "plugin/vault/__init__.py": b"plugin-init",
        "plugin/vault/plugin.yaml": b"name: vault\nversion: 0.2.0\n",
        "README.md": b"readme",
        "LICENSE": b"license",
        "install-memory-vault.py": b"wrapper",
        "installer/__init__.py": b"package",
        "installer/hermes_memory_vault_installer.py": b"module",
    }
    for relative, content in files.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)

    result = build_release(
        repo=repo,
        dist=dist,
        version="v0.2.0",
        platform="windows-x86_64",
        git_commit="a" * 40,
        git_tree="b" * 40,
        reviewed_digest="c" * 64,
    )

    assert result.archive.is_file()
    assert result.checksum.read_text(encoding="ascii").strip() == (
        f"{hashlib.sha256(result.archive.read_bytes()).hexdigest()} *{result.archive.name}"
    )
    assert result.manifest_checksum.read_text(encoding="ascii").strip() == (
        f"{hashlib.sha256(result.manifest.read_bytes()).hexdigest()} *{result.manifest.name}"
    )
    manifest = json.loads(result.manifest.read_text(encoding="utf-8"))
    assert manifest["release"] == "v0.2.0"
    assert manifest["git_commit"] == "a" * 40
    assert manifest["reviewed_staged_diff_sha256"] == "c" * 64
    with zipfile.ZipFile(result.archive) as archive:
        assert set(archive.namelist()) == {
            "bin/hermes-memory.exe",
            "plugins/vault/__init__.py",
            "plugins/vault/plugin.yaml",
            "README.md",
            "LICENSE",
            "install-memory-vault.py",
            "installer/__init__.py",
            "installer/hermes_memory_vault_installer.py",
            "SHA256SUMS",
        }
        sums = archive.read("SHA256SUMS").decode("utf-8")
        assert hashlib.sha256(b"release-binary").hexdigest() in sums
