from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile

from installer.hermes_memory_vault_installer import (
    InstallError,
    download_release,
    install_bundle,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Transactional standalone installer/updater for Hermes Memory Vault"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    install = subparsers.add_parser("install")
    install.add_argument("--home", type=Path, required=True)
    source = install.add_mutually_exclusive_group(required=True)
    source.add_argument("--bundle", type=Path)
    source.add_argument("--tag")
    install.add_argument("--sha256")
    install.add_argument("--release-manifest", type=Path)
    install.add_argument("--activate", action="store_true")
    install.add_argument("--dry-run", action="store_true")
    install.add_argument("--allow-downgrade", action="store_true")
    return parser.parse_args()


def _install(args: argparse.Namespace) -> dict[str, object]:
    if args.bundle is not None:
        if args.sha256 is None or args.release_manifest is None:
            raise InstallError(
                "local bundle requires --sha256 and --release-manifest"
            )
        return install_bundle(
            bundle=args.bundle,
            expected_sha256=args.sha256,
            release_manifest=args.release_manifest,
            home=args.home,
            activate=args.activate,
            dry_run=args.dry_run,
            allow_downgrade=args.allow_downgrade,
        )
    if args.sha256 is not None or args.release_manifest is not None:
        raise InstallError("--sha256 and --release-manifest are only valid with --bundle")
    with tempfile.TemporaryDirectory(prefix="hermes-memory-vault-release-") as raw:
        downloaded = download_release(args.tag, Path(raw))
        return install_bundle(
            bundle=downloaded.bundle,
            expected_sha256=downloaded.expected_sha256,
            release_manifest=downloaded.release_manifest,
            home=args.home,
            activate=args.activate,
            dry_run=args.dry_run,
            allow_downgrade=args.allow_downgrade,
        )


def main() -> int:
    args = parse_args()
    try:
        result = _install(args)
    except (InstallError, OSError, ValueError) as error:
        print(
            json.dumps({"success": False, "error": str(error)}, ensure_ascii=False),
            file=sys.stderr,
        )
        return 1
    print(json.dumps({"success": True, **result}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
