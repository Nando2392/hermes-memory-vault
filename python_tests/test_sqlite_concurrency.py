"""Cross-process SQLite/WAL compatibility on generated stores only."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
import subprocess

RUST_BIN = Path(__file__).parents[1] / "target" / "debug" / (
    "hermes-memory.exe" if os.name == "nt" else "hermes-memory"
)


def ingest(root: Path, identifier: str) -> None:
    """Run a bounded CLI writer against a test-owned root."""
    result = subprocess.run(
        [str(RUST_BIN), "ingest", "--root", str(root)],
        input=json.dumps({
            "id": identifier,
            "session_id": "synthetic",
            "workspace": "synthetic",
            "kind": "user",
            "content": "synthetic WAL compatibility record",
            "timestamp": 1.0,
            "metadata": {},
        }),
        text=True,
        capture_output=True,
        timeout=30,
        check=True,
    )
    assert json.loads(result.stdout) == {"duplicates": 0, "inserted": 1}


def test_independent_cli_writers_converge_without_split_sidecars(tmp_path: Path) -> None:
    root = tmp_path / "vault"
    identifiers = [f"process-{index}" for index in range(32)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda identifier: ingest(root, identifier), identifiers))
    with sqlite3.connect(root / "memory.db") as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        actual = {row[0] for row in connection.execute("SELECT id FROM records")}
        checkpoint = connection.execute(
            "SELECT current_generation, projected_generation, projected_records "
            "FROM projection_state"
        ).fetchone()
    rows = [json.loads(line) for line in (root / "events.jsonl").read_text().splitlines()]
    assert actual == set(identifiers)
    assert len(rows) == len(identifiers)
    assert {row["id"] for row in rows} == actual
    assert checkpoint == (32, 32, 32)


def test_native_reader_snapshot_and_cli_writer_share_wal_locks(tmp_path: Path) -> None:
    root = tmp_path / "vault"
    ingest(root, "initial")
    reader = sqlite3.connect(root / "memory.db", timeout=0)
    checkpointer = sqlite3.connect(root / "memory.db", timeout=0)
    try:
        reader.execute("BEGIN")
        assert reader.execute("SELECT count(*) FROM records").fetchone()[0] == 1
        ingest(root, "while-reader-active")
        assert reader.execute("SELECT count(*) FROM records").fetchone()[0] == 1
        assert checkpointer.execute("SELECT count(*) FROM records").fetchone()[0] == 2
        assert checkpointer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 1
        reader.rollback()
        assert checkpointer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
        assert checkpointer.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        reader.close()
        checkpointer.close()
    ingest(root, "after-checkpoint")
    with sqlite3.connect(root / "memory.db") as connection:
        assert connection.execute("SELECT count(*) FROM records").fetchone()[0] == 3
