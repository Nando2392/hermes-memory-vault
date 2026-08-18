# Hermes Memory Vault

Local-first, Rust-backed durable memory provider for [Hermes Agent](https://github.com/NousResearch/hermes-agent).

The Rust data plane stores complete turn snapshots in SQLite/FTS5. A thin Python plugin connects it to Hermes through the public memory-provider lifecycle. SQLite is canonical; JSONL and Markdown are rebuildable projections.

## Status

Version `0.2.2` adds a durable pre-compaction checkpoint through Hermes'
public `on_pre_compress` memory-provider hook and removes lock contention from
the projection hot path. The standalone transactional installer carries the
Rust binary and user plugin; it does not patch or modify a Hermes Agent
checkout. Version `0.2.1` was never published because release verification
exposed the contention defect.

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
- fail-closed automatic recall on Hermes hosts that do not mark provider recall as untrusted;
- durable full-transcript checkpoint before automatic context compression.

## Compatibility and trust boundary

Hermes Memory Vault treats every recalled item as **untrusted historical data**, never as instructions.

Automatic prefetch is enabled only when the installed Hermes host wraps external provider recall as non-authoritative. On older Hermes versions, capture and the explicit `vault_search` tool remain available, but automatic prefetch returns no content. This is intentional fail-closed behavior.

Before Hermes compacts a primary session, the provider snapshots the complete
intact transcript and then writes an idempotent `checkpoint:pre_compress`
record. Only after both writes succeed does it return bounded continuity
context to the compressor. Instruction-shaped historical excerpts are kept on
disk but blocked from the compressor context. This guarantees recoverability
of the original transcript; it does not claim that an LLM summary is a
lossless semantic representation.

To compact at 35% on every supported route, including Codex models whose host
default may auto-raise to 85%, configure Hermes through its public CLI:

```bash
hermes config set compression.threshold 0.35
hermes config set compression.codex_gpt55_autoraise false
hermes config set compression.in_place true
```

The upstream hardening change is tracked in [NousResearch/hermes-agent#89283](https://github.com/NousResearch/hermes-agent/pull/89283).

## Release layout

The release archive contains the managed Hermes-home payload plus the verified
standalone installer:

```text
bin/hermes-memory.exe
plugins/vault-standalone/__init__.py
plugins/vault-standalone/plugin.yaml
LICENSE
README.md
SHA256SUMS
install-memory-vault.py
installer/__init__.py
installer/hermes_memory_vault_installer.py
```

Only `bin/hermes-memory[.exe]` and `plugins/vault-standalone/*` are installed into the
active profile. Memory databases, WAL/SHM files, JSONL, Markdown exports,
configuration, credentials and unrelated files are never managed by the
installer.

## Transactional installation and update

Download the ZIP, its `.sha256`, the release manifest, and the manifest's
`.json.sha256` sidecar into the same directory. The installer authenticates both
the archive and provenance manifest before staging any profile writes:

```bash
python install-memory-vault.py install \
  --home C:/path/to/active/hermes-home \
  --bundle C:/path/to/hermes-memory-vault-v0.2.2-windows-x86_64.zip \
  --sha256 <64-hex-release-checksum> \
  --release-manifest C:/path/to/release-manifest-v0.2.2-windows-x86_64.json \
  --activate
```

An explicit release tag can be fetched directly from the allowlisted GitHub
release origin:

```bash
python install-memory-vault.py install \
  --home C:/path/to/active/hermes-home \
  --tag v0.2.2 \
  --activate
```

Use `--dry-run` for full validation without profile writes. Reinstalling the
same verified version is idempotent. Downgrades require
`--allow-downgrade`. `HERMES_MEMORY_BIN` remains authoritative; an override
outside the target profile blocks installation rather than pretending the new
binary will be active. Managed writes are fenced against concurrent
symlink/junction parent swaps: POSIX uses descriptor-relative no-follow writes,
and Windows holds non-delete-sharing directory handles through atomic replace.

Activation uses only `hermes config set memory.provider vault-standalone`. The
unique provider name avoids collision with Hermes' bundled `vault` provider,
which intentionally has precedence over same-named user plugins. Restart the
active Hermes surface after installation so new sessions load the provider.

## Manual installation (fallback)

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

- Published binary platforms are listed per release; source and installer paths are covered on Windows and Linux by CI.
- Capture uses Hermes' current `sync_turn` lifecycle. Fine-grained per-tool event capture requires a compatible future host hook and is not claimed by this standalone release.
- Administrative doctor/verify/restore commands, durable deletion, retention, backfill, Desktop UI and hybrid recall are not part of `0.2.0`.

## License

MIT. The original Hermes Agent memory-provider integration code retains the Nous Research copyright notice; standalone adaptations are copyright Fernando Martinez.
