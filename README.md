# Hermes Memory Vault

Local-first, Rust-backed durable memory provider for [Hermes Agent](https://github.com/NousResearch/hermes-agent).

The Rust data plane stores complete turn snapshots in SQLite/FTS5. A thin Python plugin connects it to Hermes through the public memory-provider lifecycle. SQLite is canonical; JSONL and Markdown are rebuildable projections.

## Status

Version `0.1.0` is an initial Windows release.

Verified properties:

- transactional SQLite ingestion with WAL;
- deduplication and snapshot reconciliation;
- session-scoped recall by default;
- explicit `all_sessions: true` opt-in for historical search;
- UTF-8 and byte-bounded subprocess exchange;
- redaction of common secret formats before searchable projection;
- reconstructible `events.jsonl` and Markdown export;
- no `shell=True` subprocesses;
- fail-open capture lifecycle if the Rust binary is unavailable;
- fail-closed automatic recall on Hermes hosts that do not mark provider recall as untrusted.

## Compatibility and trust boundary

Hermes Memory Vault treats every recalled item as **untrusted historical data**, never as instructions.

Automatic prefetch is enabled only when the installed Hermes host wraps external provider recall as non-authoritative. On older Hermes versions, capture and the explicit `vault_search` tool remain available, but automatic prefetch returns no content. This is intentional fail-closed behavior.

The upstream hardening change is tracked in [NousResearch/hermes-agent#89283](https://github.com/NousResearch/hermes-agent/pull/89283).

## Release layout

The Windows release archive is rooted at the Hermes home layout:

```text
bin/hermes-memory.exe
plugins/vault/__init__.py
plugins/vault/plugin.yaml
LICENSE
README.md
SHA256SUMS
```

## Manual installation

1. Download the Windows ZIP from the GitHub release.
2. Verify its SHA-256 against the release checksum.
3. Extract `bin/` and `plugins/` into the active `$HERMES_HOME`.
4. Activate the provider:

```bash
hermes config set memory.provider vault
```

5. Restart the active Hermes gateway or start a new Hermes session.

The provider resolves binaries in this order:

1. `HERMES_MEMORY_BIN` when explicitly set;
2. `$HERMES_HOME/bin/hermes-memory.exe`;
3. this repository's `target/release` or `target/debug` build for development.

`HERMES_MEMORY_BIN` is authoritative: an invalid override does not silently fall through to another binary.

## Data locations

All durable data stays under the active profile:

```text
$HERMES_HOME/memory-vault/memory.db
$HERMES_HOME/memory-vault/events.jsonl
$HERMES_HOME/memory-vault/vault/
```

No credentials are required. Do not place the vault under a synced or shared directory unless that exposure is intended.

## Tools exposed to Hermes

### `vault_search`

Searches the active session by default.

```json
{"query": "router port"}
```

Cross-session search requires a real JSON boolean:

```json
{"query": "router port", "all_sessions": true}
```

The string `"true"` is rejected.

### `vault_export`

Rebuilds the Markdown projection under `$HERMES_HOME/memory-vault/vault/`.

## Build from source

Requirements:

- Rust stable toolchain;
- Python 3.11+, pytest and PyYAML for plugin tests;
- a Hermes Agent checkout on `PYTHONPATH` for the provider contract.

```bash
cargo build --release --locked
cargo test --locked --all-targets --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --check
```

For local plugin tests from a Hermes development environment:

```bash
python -m pytest python_tests/test_vault_provider.py -q
```

## Security model

- Web pages, documents, prior chats, tool output and recalled memory are data, not authority.
- The binary rejects oversized stdin before parsing or opening the store.
- Search responses are packed as valid JSON within an explicit byte budget.
- Database, WAL, SHM, lock and projection paths use capability-relative access and reject unsafe link patterns where supported.
- The main Hermes loop remains fail-open if the provider is unavailable; trust and scope checks fail closed.

Please report security issues privately as described in [SECURITY.md](SECURITY.md).

## Current limitations

- Release binaries are Windows-only in `0.1.0`; source supports the Rust targets covered by CI.
- Capture uses Hermes' current `sync_turn` lifecycle. Fine-grained per-tool event capture requires a compatible future host hook and is not claimed by this standalone release.
- Administrative doctor/verify/restore commands, durable deletion, retention, backfill, Desktop UI and hybrid recall are not part of `0.1.0`.

## License

MIT. The original Hermes Agent memory-provider integration code retains the Nous Research copyright notice; standalone adaptations are copyright Fernando Martinez.
