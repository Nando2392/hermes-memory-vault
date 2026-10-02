#![cfg(windows)]

use hermes_memory::{
    logical_migration::export_from_staged_sqlite_copy, MemoryStore, SnapshotItem, SnapshotRequest,
};
use serde_json::json;
use std::{fs, io::Cursor, path::Path};
use tempfile::TempDir;

fn snapshot(words: &[&str]) -> SnapshotRequest {
    SnapshotRequest {
        session_id: "synthetic-session".into(),
        workspace: "synthetic-workspace".into(),
        items: words
            .iter()
            .map(|word| SnapshotItem {
                kind: "message".into(),
                content: (*word).into(),
                timestamp: 42.0,
                metadata: json!({}),
            })
            .collect(),
    }
}
fn stage(source: &Path, staged: &Path) {
    fs::create_dir_all(staged).unwrap();
    assert!(fs::metadata(source.join("memory.db-wal")).unwrap().len() > 0);
    // No writers run while this synthetic DB+WAL+SHM copy is made.
    for name in ["memory.db", "memory.db-wal", "memory.db-shm"] {
        fs::copy(source.join(name), staged.join(name)).unwrap();
    }
}
fn archive(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    export_from_staged_sqlite_copy(path.join("memory.db"), &mut bytes).unwrap();
    bytes
}
fn fixture() -> (TempDir, Vec<u8>) {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("original");
    let store = MemoryStore::open(&source).unwrap();
    store
        .ingest_snapshot(&snapshot(&["alpha", "alpha", "beta"]))
        .unwrap();
    let staged = temp.path().join("staged");
    stage(&source, &staged);
    let bytes = archive(&staged);
    (temp, bytes)
}
fn inventory(path: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().into_string().unwrap(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}
#[test]
fn checkpointed_db_only_roundtrip_preserves_fields_and_continuation() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("original");
    let original = MemoryStore::open(&root).unwrap();
    let mut request = snapshot(&["alpha", "alpha", "beta"]);
    request.items[2].timestamp = 43.25;
    request.items[2].metadata = json!({"nested": [true, 7, "unicode λ"]});
    original.ingest_snapshot(&request).unwrap();
    let wal_stage = temp.path().join("wal-control");
    stage(&root, &wal_stage);
    let expected = archive(&wal_stage);
    drop(original); // SQLite's real last-close checkpoint removes both sidecars.
    assert!(!root.join("memory.db-wal").exists());
    assert!(!root.join("memory.db-shm").exists());
    let staged = temp.path().join("db-only");
    fs::create_dir(&staged).unwrap();
    fs::copy(root.join("memory.db"), staged.join("memory.db")).unwrap();
    let before = inventory(&staged);
    let bytes = archive(&staged);
    assert_eq!(
        bytes, expected,
        "every record/state/counter field and ordering"
    );
    assert_eq!(inventory(&staged), before);
    let destination = temp.path().join("destination");
    let migrated = MemoryStore::open(&destination).unwrap();
    let receipt = migrated
        .import_logical_archive_once(Cursor::new(&bytes), &pinned(&bytes))
        .unwrap();
    assert_eq!(
        (
            receipt.records,
            receipt.snapshot_states,
            receipt.snapshot_counters
        ),
        (3, 3, 2)
    );
    assert_eq!(
        fs::read(root.join("events.jsonl")).unwrap(),
        fs::read(destination.join("events.jsonl")).unwrap()
    );
    let original = MemoryStore::open(&root).unwrap();
    assert_eq!(migrated.ingest_snapshot(&request).unwrap(), (0, 0));
    for words in [
        vec!["beta", "alpha"],
        vec!["summary"],
        vec!["summary", "alpha", "alpha"],
        vec![],
    ] {
        assert_eq!(
            original.ingest_snapshot(&snapshot(&words)).unwrap(),
            migrated.ingest_snapshot(&snapshot(&words)).unwrap()
        );
        assert_eq!(
            fs::read(root.join("events.jsonl")).unwrap(),
            fs::read(destination.join("events.jsonl")).unwrap()
        );
    }
    assert_eq!(inventory(&staged), before);
}
#[test]
fn prepared_broker_index_and_receipt_reexport_without_digest_change() {
    let (temp, bytes) = fixture();
    let root = temp.path().join("broker");
    let store = MemoryStore::open(&root).unwrap();
    store
        .import_logical_archive_once(Cursor::new(&bytes), &pinned(&bytes))
        .unwrap();
    store.prepare_export_index().unwrap();
    let staged = temp.path().join("broker-staged");
    stage(&root, &staged);
    let before = inventory(&staged);
    assert_eq!(archive(&staged), bytes);
    assert_eq!(inventory(&staged), before);
}
#[test]
fn altered_export_index_definition_is_rejected() {
    for ddl in [
        "CREATE INDEX records_export_order ON records(timestamp)",
        "CREATE INDEX records_export_order ON snapshot_state(workspace)",
        "CREATE INDEX alien ON records(workspace)",
        "CREATE TRIGGER records_export_order AFTER INSERT ON records BEGIN SELECT 1; END",
    ] {
        let (temp, bytes) = fixture();
        let root = temp.path().join("broker");
        let store = MemoryStore::open(&root).unwrap();
        store
            .import_logical_archive_once(Cursor::new(&bytes), &pinned(&bytes))
            .unwrap();
        let db = rusqlite::Connection::open(root.join("memory.db")).unwrap();
        db.execute_batch(ddl).unwrap();
        let staged = temp.path().join("bad-index");
        stage(&root, &staged);
        let before = inventory(&staged);
        assert!(export_from_staged_sqlite_copy(staged.join("memory.db"), Vec::new()).is_err());
        assert_eq!(inventory(&staged), before);
    }
}
#[test]
fn damaged_or_incomplete_sidecars_fail_without_repair() {
    for (name, replacement) in [
        ("memory.db-wal", None),
        ("memory.db-shm", None),
        ("memory.db-wal", Some(vec![])),
        ("memory.db-wal", Some(vec![0; 32])),
        ("memory.db-shm", Some(vec![])),
        ("memory.db-shm", Some(vec![0; 32768])),
    ] {
        let (temp, _) = fixture();
        let staged = temp.path().join("staged");
        match replacement {
            Some(bytes) => fs::write(staged.join(name), bytes).unwrap(),
            None => fs::remove_file(staged.join(name)).unwrap(),
        }
        let before = inventory(&staged);
        assert!(
            export_from_staged_sqlite_copy(staged.join("memory.db"), Vec::new()).is_err(),
            "accepted {name}"
        );
        assert_eq!(inventory(&staged), before);
    }
}
#[test]
fn db_only_pins_deny_write_delete_and_detect_new_sidecars() {
    struct CheckDuringExport<'a> {
        staged: &'a Path,
        create: bool,
    }
    impl std::io::Write for CheckDuringExport<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            assert!(fs::OpenOptions::new()
                .write(true)
                .open(self.staged.join("memory.db"))
                .is_err());
            assert!(fs::remove_file(self.staged.join("memory.db")).is_err());
            assert!(fs::rename(
                self.staged.join("memory.db"),
                self.staged.join("renamed.db")
            )
            .is_err());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            if self.create {
                fs::write(self.staged.join("memory.db-wal"), b"unexpected")?;
            }
            Ok(())
        }
    }
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("original");
    drop(MemoryStore::open(&root).unwrap());
    let staged = temp.path().join("staged");
    fs::create_dir(&staged).unwrap();
    fs::copy(root.join("memory.db"), staged.join("memory.db")).unwrap();
    let before = inventory(&staged);
    export_from_staged_sqlite_copy(
        staged.join("memory.db"),
        CheckDuringExport {
            staged: &staged,
            create: false,
        },
    )
    .unwrap();
    assert_eq!(inventory(&staged), before);
    // Deliberately violate namespace exclusivity via the output callback.
    assert!(export_from_staged_sqlite_copy(
        staged.join("memory.db"),
        CheckDuringExport {
            staged: &staged,
            create: true
        }
    )
    .is_err());
    assert_eq!(
        fs::read(staged.join("memory.db")).unwrap(),
        before["memory.db"]
    );
}
struct Unreadable;
impl std::io::Read for Unreadable {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        panic!("idempotent admission must not read input")
    }
}
impl std::io::BufRead for Unreadable {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        panic!("idempotent admission must not inspect input")
    }
    fn consume(&mut self, _: usize) {
        panic!("must not consume input")
    }
}
fn pinned(bytes: &[u8]) -> String {
    entries(bytes).last().unwrap()["receipt"]["logical_sha256"]
        .as_str()
        .unwrap()
        .to_owned()
}
#[test]
fn once_receipt_survives_reopen_and_later_ingestion_without_reading_input() {
    let (temp, bytes) = fixture();
    let root = temp.path().join("once");
    let store = MemoryStore::open(&root).unwrap();
    let pin = pinned(&bytes);
    let receipt = store
        .import_logical_archive_once(Cursor::new(&bytes), &pin)
        .unwrap();
    assert_eq!(receipt.records, 3);
    assert_eq!(
        store.import_logical_archive_once(Unreadable, &pin).unwrap(),
        receipt
    );
    store
        .ingest_snapshot(&snapshot(&["later legitimate row"]))
        .unwrap();
    drop(store);
    let store = MemoryStore::open(&root).unwrap();
    assert_eq!(
        store.import_logical_archive_once(Unreadable, &pin).unwrap(),
        receipt
    );
    assert!(store
        .import_logical_archive_once(Unreadable, &"f".repeat(64))
        .is_err());
    let db = rusqlite::Connection::open(root.join("memory.db")).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM records", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM broker_migrations", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
#[test]
fn once_receipt_is_derived_metadata_not_exported() {
    let (temp, bytes) = fixture();
    let root = temp.path().join("once-export");
    let store = MemoryStore::open(&root).unwrap();
    store
        .import_logical_archive_once(Cursor::new(&bytes), &pinned(&bytes))
        .unwrap();
    let staged = temp.path().join("once-staged");
    stage(&root, &staged);
    assert_eq!(archive(&staged), bytes);
    store.ingest_snapshot(&snapshot(&["later row"])).unwrap();
    let later = temp.path().join("once-staged-later");
    stage(&root, &later);
    let later_bytes = archive(&later);
    assert_ne!(pinned(&later_bytes), pinned(&bytes));
    let target = MemoryStore::open(temp.path().join("later-target")).unwrap();
    assert_eq!(
        target
            .import_logical_archive_once(Cursor::new(&later_bytes), &pinned(&later_bytes))
            .unwrap()
            .records,
        4
    );
}
#[test]
fn receipt_schema_and_payload_are_exact_on_retry_and_export() {
    for mutation in [
        "ALTER TABLE broker_migrations ADD COLUMN alien TEXT",
        "UPDATE broker_migrations SET receipt_json=json_set(receipt_json,'$.records',1000001)",
        "UPDATE broker_migrations SET receipt_json=json_set(receipt_json,'$.logical_sha256','bad')",
        "UPDATE broker_migrations SET receipt_json=json_set(receipt_json,'$.extra',1)",
        "UPDATE broker_migrations SET receipt_json=printf('%.*c',513,'x')",
        "DELETE FROM broker_migrations",
        "DROP TABLE broker_migrations; CREATE TABLE broker_migrations(singleton INTEGER PRIMARY KEY,receipt_json TEXT NOT NULL)",
        "CREATE TABLE alien(data TEXT)",
    ] {
        let (temp, bytes) = fixture();
        let root = temp.path().join("once-invalid");
        let store = MemoryStore::open(&root).unwrap();
        let pin = pinned(&bytes);
        store.import_logical_archive_once(Cursor::new(&bytes), &pin).unwrap();
        let db = rusqlite::Connection::open(root.join("memory.db")).unwrap();
        db.execute_batch(mutation).unwrap();
        if !mutation.starts_with("CREATE TABLE alien") {
            assert!(store.import_logical_archive_once(Unreadable, &pin).is_err(), "invalid receipt accepted: {mutation}");
        }
        let staged = temp.path().join("staged-invalid");
        stage(&root, &staged);
        assert!(export_from_staged_sqlite_copy(staged.join("memory.db"), Vec::new()).is_err(), "invalid source accepted: {mutation}");
    }
}
#[test]
fn once_pin_mismatch_rolls_back_and_nonempty_without_receipt_never_infers_success() {
    let (temp, bytes) = fixture();
    let root = temp.path().join("pinned-destination");
    let store = MemoryStore::open(&root).unwrap();
    for pin in ["f".repeat(64), "".into(), "A".repeat(64)] {
        assert!(store
            .import_logical_archive_once(Cursor::new(&bytes), &pin)
            .is_err());
        let db = rusqlite::Connection::open(root.join("memory.db")).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM records", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(db.query_row("SELECT count(*) FROM sqlite_schema WHERE name IN ('broker_migrations','migration_known_ids')", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
    }
    store.import_logical_archive(Cursor::new(&bytes)).unwrap();
    assert!(store
        .import_logical_archive_once(Unreadable, &pinned(&bytes))
        .is_err());
}
#[test]
fn empty_once_archive_is_durable_and_cannot_be_replaced() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("empty-source");
    let _source = MemoryStore::open(&source).unwrap();
    let staged = temp.path().join("empty-staged");
    stage(&source, &staged);
    let bytes = archive(&staged);
    let root = temp.path().join("empty-destination");
    let store = MemoryStore::open(&root).unwrap();
    let receipt = store
        .import_logical_archive_once(Cursor::new(&bytes), &pinned(&bytes))
        .unwrap();
    assert_eq!(receipt.records, 0);
    drop(store);
    let store = MemoryStore::open(&root).unwrap();
    assert_eq!(
        store
            .import_logical_archive_once(Unreadable, &pinned(&bytes))
            .unwrap(),
        receipt
    );
    assert!(store
        .import_logical_archive_once(Unreadable, &"f".repeat(64))
        .is_err());
}
#[test]
fn once_postcommit_projection_fault_retains_receipt_and_reopen_repairs_without_reimport() {
    use hermes_memory::logical_migration::MigrationError;
    let (temp, bytes) = fixture();
    let root = temp.path().join("once-fault");
    let store = MemoryStore::open(&root).unwrap();
    fs::remove_file(root.join("events.jsonl")).unwrap();
    fs::create_dir(root.join("events.jsonl")).unwrap();
    let receipt = match store.import_logical_archive_once(Cursor::new(&bytes), &pinned(&bytes)) {
        Err(MigrationError::OutcomeUnknown { receipt }) => receipt,
        other => panic!("expected postcommit fault, got {other:?}"),
    };
    // Simulate loss of the in-memory success response. Only SQLite may retain it.
    drop(store);
    fs::remove_dir(root.join("events.jsonl")).unwrap();
    let store = MemoryStore::open(&root).unwrap();
    assert_eq!(
        store
            .import_logical_archive_once(Unreadable, &pinned(&bytes))
            .unwrap(),
        receipt
    );
    assert_eq!(
        fs::read_to_string(root.join("events.jsonl"))
            .unwrap()
            .lines()
            .count(),
        3
    );
    assert_eq!(
        store
            .ingest_snapshot(&snapshot(&["alpha", "alpha", "beta"]))
            .unwrap(),
        (0, 0)
    );
}
#[test]
fn half_megabyte_content_and_metadata_roundtrip_exactly() {
    let temp = TempDir::new().unwrap();
    let source = temp.path().join("large-source");
    let original = MemoryStore::open(&source).unwrap();
    let mut request = snapshot(&["placeholder"]);
    request.items[0].content = "x".repeat(512 * 1024);
    request.items[0].metadata = json!({"note": "y".repeat(512 * 1024)});
    original.ingest_snapshot(&request).unwrap();
    let staged = temp.path().join("large-staged");
    stage(&source, &staged);
    let bytes = archive(&staged);
    let destination = temp.path().join("large-destination");
    let store = MemoryStore::open(&destination).unwrap();
    let receipt = store
        .import_logical_archive_once(Cursor::new(&bytes), &pinned(&bytes))
        .unwrap();
    assert_eq!(receipt.records, 1);
    assert_eq!(store.ingest_snapshot(&request).unwrap(), (0, 0));
    assert!(
        fs::read(source.join("events.jsonl")).unwrap()
            == fs::read(destination.join("events.jsonl")).unwrap()
    );
}
fn entries(bytes: &[u8]) -> Vec<serde_json::Value> {
    std::str::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}
fn resigned(mut values: Vec<serde_json::Value>) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut trailer = values.pop().unwrap();
    let mut h = Sha256::new();
    h.update(b"hermes-logical-migration-v1\0");
    let mut result = Vec::new();
    for value in values {
        let mut line = serde_json::to_vec(&value).unwrap();
        line.push(b'\n');
        h.update(&line);
        result.extend(line);
    }
    trailer["receipt"]["logical_sha256"] = json!(format!("{:x}", h.finalize()));
    result.extend(serde_json::to_vec(&trailer).unwrap());
    result.push(b'\n');
    result
}
fn rejected_empty(store: &MemoryStore, root: &Path, bytes: &[u8], label: &str) {
    assert!(
        store.import_logical_archive(Cursor::new(bytes)).is_err(),
        "must reject {label}"
    );
    let trailer = std::str::from_utf8(bytes)
        .ok()
        .and_then(|s| s.lines().last())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
    let pin = trailer
        .as_ref()
        .and_then(|v| v["receipt"]["logical_sha256"].as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| "0".repeat(64));
    assert!(
        store
            .import_logical_archive_once(Cursor::new(bytes), &pin)
            .is_err(),
        "once must reject {label}"
    );
    let db = rusqlite::Connection::open(root.join("memory.db")).unwrap();
    assert_eq!(db.query_row("SELECT count(*) FROM sqlite_schema WHERE name IN ('broker_migrations','migration_known_ids')", [], |r| r.get::<_, i64>(0)).unwrap(), 0, "no receipt or scratch table after rollback {label}");
    for table in ["records", "snapshot_state", "snapshot_counters"] {
        let count: i64 = db
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "rollback {label}");
    }
    assert!(fs::read(root.join("events.jsonl")).unwrap().is_empty());
}
#[test]
fn invalid_fields_and_reference_graph_roll_back_even_with_recomputed_digest() {
    let (temp, bytes) = fixture();
    let root = temp.path().join("destination");
    let store = MemoryStore::open(&root).unwrap();
    for (kind, field, value) in [
        ("record", "id", json!("")),
        ("record", "id", json!("x".repeat(4097))),
        ("record", "session_id", json!("a\0b")),
        ("record", "content", json!("password=synthetic-secret")),
        (
            "record",
            "content",
            json!("x".repeat(hermes_memory::logical_migration::MAX_FIELD_BYTES + 1)),
        ),
        ("record", "metadata", json!({"secret": "synthetic-secret"})),
        (
            "record",
            "metadata",
            json!({"note": "x".repeat(hermes_memory::logical_migration::MAX_FIELD_BYTES)}),
        ),
        ("counter", "next_occurrence", json!(0)),
        ("counter", "next_occurrence", json!(-1)),
        ("counter", "next_occurrence", json!(9223372036854775807_i64)),
        ("counter", "next_occurrence", json!(4)),
        ("counter", "fingerprint", json!("f".repeat(64))),
        ("state", "fingerprint", json!("f".repeat(64))),
        ("state", "record_id", json!("synthetic-missing")),
        ("state", "workspace", json!("other")),
        ("state", "position", json!(9)),
    ] {
        let mut values = entries(&bytes);
        let entry = values.iter_mut().find(|v| v["type"] == kind).unwrap();
        entry[field] = value;
        rejected_empty(&store, &root, &resigned(values), field);
    }
    store.import_logical_archive(Cursor::new(&bytes)).unwrap();
}
#[test]
fn source_schema_and_export_fields_are_allowlisted_without_writes() {
    for mutation in [
        "PRAGMA user_version=3",
        "ALTER TABLE records ADD COLUMN alien TEXT",
        "UPDATE records SET content='password=synthetic-secret'",
        &format!(
            "UPDATE records SET content=printf('%.*c',{},'x')",
            hermes_memory::logical_migration::MAX_FIELD_BYTES + 1
        ),
        &format!(
            "UPDATE records SET metadata_json=json_object('note',printf('%.*c',{},'x'))",
            hermes_memory::logical_migration::MAX_FIELD_BYTES
        ),
    ] {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("source");
        let store = MemoryStore::open(&root).unwrap();
        store.ingest_snapshot(&snapshot(&["alpha"])).unwrap();
        let db = rusqlite::Connection::open(root.join("memory.db")).unwrap();
        db.execute_batch(mutation).unwrap();
        let staged = temp.path().join("staged");
        stage(&root, &staged);
        let before = ["memory.db", "memory.db-wal", "memory.db-shm"]
            .map(|n| fs::read(staged.join(n)).unwrap());
        assert!(
            export_from_staged_sqlite_copy(staged.join("memory.db"), Vec::new()).is_err(),
            "source mutation must be rejected"
        );
        let after = ["memory.db", "memory.db-wal", "memory.db-shm"]
            .map(|n| fs::read(staged.join(n)).unwrap());
        assert!(
            before == after,
            "rejected staged source must remain byte identical"
        );
    }
}
#[test]
fn malformed_truncated_duplicate_and_tampered_archives_roll_back() {
    let (temp, bytes) = fixture();
    let root = temp.path().join("destination");
    let store = MemoryStore::open(&root).unwrap();
    for cut in [0, 1, bytes.len() / 2, bytes.len() - 1] {
        rejected_empty(&store, &root, &bytes[..cut], "truncated");
    }
    let mut trailing = bytes.clone();
    trailing.push(b' ');
    rejected_empty(&store, &root, &trailing, "trailing");
    for kind in ["record", "counter", "state"] {
        let mut values = entries(&bytes);
        let index = values.iter().position(|v| v["type"] == kind).unwrap();
        values.insert(index, values[index].clone());
        let count = match kind {
            "record" => "records",
            "counter" => "snapshot_counters",
            _ => "snapshot_states",
        };
        let last = values.len() - 1;
        let n = values[last]["receipt"][count].as_u64().unwrap();
        values[last]["receipt"][count] = json!(n + 1);
        rejected_empty(&store, &root, &resigned(values), "duplicate");
    }
    for (index, field, value) in [
        (0, "format", json!(2)),
        (0, "source_schema", json!(3)),
        (1, "extra", json!("ATTACH DATABASE 'x'")),
    ] {
        let mut values = entries(&bytes);
        values[index][field] = value;
        rejected_empty(&store, &root, &resigned(values), "schema or unknown field");
    }
    let mut values = entries(&bytes);
    values[1]["content"] = json!("changed");
    let tampered = values
        .iter()
        .map(|v| serde_json::to_string(v).unwrap() + "\n")
        .collect::<String>();
    rejected_empty(&store, &root, tampered.as_bytes(), "tampered digest");
    store.import_logical_archive(Cursor::new(&bytes)).unwrap();
    assert!(
        store.import_logical_archive(Cursor::new(&bytes)).is_err(),
        "retry refuses nonempty store"
    );
}
#[test]
fn exact_known_occurrences_cannot_be_replaced_or_removed() {
    let (temp, bytes) = fixture();
    let root = temp.path().join("destination");
    let store = MemoryStore::open(&root).unwrap();
    let original = entries(&bytes);
    for mode in 0..4 {
        let mut values = original.clone();
        let state = values.iter().position(|v| v["type"] == "state").unwrap();
        match mode {
            0 => {
                values[state + 1]["record_id"] = values[state]["record_id"].clone();
            }
            1 => {
                values[state]["record_id"] = values[state + 2]["record_id"].clone();
            }
            2 => {
                let counter = values.iter().position(|v| v["type"] == "counter").unwrap();
                values.remove(counter);
                let last = values.len() - 1;
                values[last]["receipt"]["snapshot_counters"] = json!(1);
            }
            _ => {
                values[1]["id"] = json!("synthetic-counterfeit-id");
            }
        }
        rejected_empty(
            &store,
            &root,
            &resigned(values),
            "exact occurrence identity",
        );
    }
}
#[test]
fn plain_records_and_redacted_tool_snapshot_identity_survive() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("source");
    let original = MemoryStore::open(&root).unwrap();
    original
        .ingest(&hermes_memory::MemoryRecord {
            id: "msg-direct-id".into(),
            session_id: "plain".into(),
            workspace: "other".into(),
            kind: "note".into(),
            content: "password=synthetic".into(),
            timestamp: 3.25,
            metadata: json!({"token":"synthetic"}),
        })
        .unwrap();
    let mut request = snapshot(&["tool result", "tool result"]);
    request.items[0].metadata = json!({"tool_call_id":"synthetic-call-a", "token":"synthetic"});
    request.items[1].metadata = json!({"tool_call_id":"synthetic-call-b"});
    original.ingest_snapshot(&request).unwrap();
    let staged = temp.path().join("staged");
    stage(&root, &staged);
    let bytes = archive(&staged);
    let dest = temp.path().join("destination");
    let migrated = MemoryStore::open(&dest).unwrap();
    migrated.import_logical_archive(Cursor::new(bytes)).unwrap();
    request.items.reverse();
    assert_eq!(
        original.ingest_snapshot(&request).unwrap(),
        migrated.ingest_snapshot(&request).unwrap()
    );
    assert!(
        fs::read(root.join("events.jsonl")).unwrap()
            == fs::read(dest.join("events.jsonl")).unwrap()
    );
}
#[test]
fn missing_staged_shm_is_rejected_without_creating_any_source_file() {
    let (temp, _) = fixture();
    let staged = temp.path().join("staged");
    fs::remove_file(staged.join("memory.db-shm")).unwrap();
    let before = fs::read(staged.join("memory.db")).unwrap();
    assert!(export_from_staged_sqlite_copy(staged.join("memory.db"), Vec::new()).is_err());
    assert!(!staged.join("memory.db-shm").exists());
    assert!(before == fs::read(staged.join("memory.db")).unwrap());
}
#[test]
fn huge_unterminated_stream_is_rejected_after_bounded_reads() {
    use std::io::{BufReader, Read};
    struct Infinite {
        read: usize,
    }
    impl Read for Infinite {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            out.fill(b'x');
            self.read += out.len();
            Ok(out.len())
        }
    }
    let temp = TempDir::new().unwrap();
    let store = MemoryStore::open(temp.path()).unwrap();
    let mut reader = BufReader::with_capacity(8192, Infinite { read: 0 });
    assert!(store.import_logical_archive(&mut reader).is_err());
    assert!(reader.get_ref().read <= hermes_memory::logical_migration::MAX_LINE_BYTES + 8192);
}
#[test]
fn postcommit_projection_failure_is_outcome_unknown_and_reopen_recovers() {
    use hermes_memory::logical_migration::MigrationError;
    let (temp, bytes) = fixture();
    let root = temp.path().join("destination");
    let store = MemoryStore::open(&root).unwrap();
    fs::remove_file(root.join("events.jsonl")).unwrap();
    fs::create_dir(root.join("events.jsonl")).unwrap();
    let result = store.import_logical_archive(Cursor::new(&bytes));
    assert!(
        matches!(result, Err(MigrationError::OutcomeUnknown { ref receipt }) if receipt.records == 3)
    );
    assert!(store.import_logical_archive(Cursor::new(&bytes)).is_err());
    drop(store);
    fs::remove_dir(root.join("events.jsonl")).unwrap();
    let recovered = MemoryStore::open(&root).unwrap();
    assert_eq!(
        recovered
            .ingest_snapshot(&snapshot(&["alpha", "alpha", "beta"]))
            .unwrap(),
        (0, 0)
    );
    assert_eq!(
        fs::read_to_string(root.join("events.jsonl"))
            .unwrap()
            .lines()
            .count(),
        3
    );
}
#[test]
fn real_v1_logical_schema_exports_without_upgrading_staged_copy() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("source");
    let store = MemoryStore::open(&root).unwrap();
    store.ingest_snapshot(&snapshot(&["alpha"])).unwrap();
    let db = rusqlite::Connection::open(root.join("memory.db")).unwrap();
    for column in [
        "projection_format",
        "projected_records",
        "projected_max_rowid",
        "projected_last_timestamp",
        "projected_modified_ns",
    ] {
        db.execute_batch(&format!(
            "ALTER TABLE projection_state DROP COLUMN {column}"
        ))
        .unwrap();
    }
    db.execute_batch("PRAGMA user_version=1").unwrap();
    let staged = temp.path().join("staged");
    stage(&root, &staged);
    let before =
        ["memory.db", "memory.db-wal", "memory.db-shm"].map(|n| fs::read(staged.join(n)).unwrap());
    let bytes = archive(&staged);
    assert_eq!(entries(&bytes)[0]["source_schema"], 1);
    let target = MemoryStore::open(temp.path().join("destination")).unwrap();
    assert_eq!(
        target
            .import_logical_archive(Cursor::new(bytes))
            .unwrap()
            .records,
        1
    );
    assert!(
        before
            == ["memory.db", "memory.db-wal", "memory.db-shm"]
                .map(|n| fs::read(staged.join(n)).unwrap())
    );
}
#[test]
fn migration_at_each_edit_reorder_precompress_boundary_preserves_exact_ids() {
    let snapshots = [
        vec!["alpha", "alpha"],
        vec!["alpha", "alpha", "beta"],
        vec!["beta", "alpha"],
        vec!["edited", "alpha", "alpha"],
        vec!["summary"],
        vec!["summary", "alpha", "alpha"],
        vec![],
    ];
    for cut in 0..=snapshots.len() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("source");
        let original = MemoryStore::open(&root).unwrap();
        for words in &snapshots[..cut] {
            original.ingest_snapshot(&snapshot(words)).unwrap();
        }
        let staged = temp.path().join("staged");
        stage(&root, &staged);
        let bytes = archive(&staged);
        assert!(bytes == archive(&staged), "deterministic export");
        let dest = temp.path().join("destination");
        let migrated = MemoryStore::open(&dest).unwrap();
        migrated.import_logical_archive(Cursor::new(bytes)).unwrap();
        for words in &snapshots[cut..] {
            assert_eq!(
                original.ingest_snapshot(&snapshot(words)).unwrap(),
                migrated.ingest_snapshot(&snapshot(words)).unwrap()
            );
            assert!(
                fs::read(root.join("events.jsonl")).unwrap()
                    == fs::read(dest.join("events.jsonl")).unwrap(),
                "exact logical IDs and content match"
            );
        }
        let query = hermes_memory::SearchRequest {
            query: "alpha beta summary".into(),
            session_id: None,
            workspace: None,
            limit: 100,
            max_bytes: 100000,
        };
        assert!(
            original.search(&query).unwrap() == migrated.search(&query).unwrap(),
            "FTS is rebuilt from imported records"
        );
    }
}
#[test]
fn staged_wal_roundtrip_preserves_every_snapshot_continuation() {
    let temp = TempDir::new().unwrap();
    let original_path = temp.path().join("original");
    let original = MemoryStore::open(&original_path).unwrap();
    original
        .ingest_snapshot(&snapshot(&["alpha", "alpha", "beta"]))
        .unwrap();
    let staged = temp.path().join("staged");
    stage(&original_path, &staged);
    let before: Vec<_> = ["memory.db", "memory.db-wal", "memory.db-shm"]
        .map(|n| fs::read(staged.join(n)).unwrap())
        .into();
    let bytes = archive(&staged);
    let migrated_path = temp.path().join("migrated");
    let migrated = MemoryStore::open(&migrated_path).unwrap();
    let receipt = migrated
        .import_logical_archive(Cursor::new(&bytes))
        .unwrap();
    assert_eq!(receipt.records, 3);
    assert_eq!(receipt.snapshot_states, 3);
    assert_eq!(receipt.snapshot_counters, 2);
    assert_eq!(receipt.logical_sha256.len(), 64);
    for words in [
        vec!["alpha", "alpha", "beta"],
        vec!["alpha", "beta", "gamma"],
        vec!["gamma", "alpha", "alpha"],
        vec!["summary"],
        vec!["summary", "alpha", "alpha"],
        vec![],
    ] {
        assert_eq!(
            original.ingest_snapshot(&snapshot(&words)).unwrap(),
            migrated.ingest_snapshot(&snapshot(&words)).unwrap()
        );
        assert!(
            fs::read(original_path.join("events.jsonl")).unwrap()
                == fs::read(migrated_path.join("events.jsonl")).unwrap(),
            "logical records and exact IDs must match without printing content"
        );
    }
    for (index, name) in ["memory.db", "memory.db-wal", "memory.db-shm"]
        .iter()
        .enumerate()
    {
        assert!(
            before[index] == fs::read(staged.join(name)).unwrap(),
            "staged source must not change"
        );
    }
}
