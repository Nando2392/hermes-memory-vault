//! Ordinary test-owned SQLite fixtures only. No installed/native helper.
use super::*;

#[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
fn closed_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let owner = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let root = owner.path().join("store");
    let store = crate::data::open_owned_fixture_store(&root).unwrap();
    store.ingest_snapshot(&crate::data::snapshot()).unwrap();
    store.ingest_many(&[crate::data::record(0)]).unwrap();
    drop(store);
    (owner, root)
}

#[cfg(windows)]
fn parity(root: &Path) -> Vec<u8> {
    let database = root.join("memory.db");
    let before = crate::data::inventory(root).unwrap();
    let mut ordinary = Vec::new();
    let actual = export(&database, root, &mut ordinary).unwrap();
    let mut windows = Vec::new();
    let expected =
        hermes_memory::logical_migration::export_from_staged_sqlite_copy(&database, &mut windows)
            .unwrap();
    assert_eq!(actual, expected);
    assert_eq!(ordinary, windows);
    assert_eq!(before, crate::data::inventory(root).unwrap());
    ordinary
}

#[cfg(windows)]
#[test]
fn byte_parity_binds_ties_escaping_nested_metadata_counters_and_sql_mutations() {
    let owner = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let root = owner.path().join("ordinary # unicode é store");
    let store = crate::data::open_owned_fixture_store(&root).unwrap();
    let mut snapshot = crate::data::snapshot();
    snapshot.items.push(snapshot.items[0].clone());
    snapshot.items.push(hermes_memory::SnapshotItem {
        kind: "assistant".into(),
        content: "line\nquote \" and \\ slash é 😀".into(),
        timestamp: -0.125,
        metadata: serde_json::json!({"nested":[null,true,{"z":1,"a":"\n\t\\\" é"}],"number":1.25}),
    });
    assert_eq!(store.ingest_snapshot(&snapshot).unwrap(), (3, 0));
    snapshot.items.swap(0, 2);
    store.ingest_snapshot(&snapshot).unwrap();
    for first in [0, 256] {
        let records: Vec<_> = (first..first + 256)
            .map(|n| {
                let mut r = crate::data::record(n);
                r.timestamp = 17.125; // timestamp ties must retain physical ingestion order
                r.content = format!("ordinary {n} newline\nquote \" \\ unicode é 😀");
                r.metadata =
                    serde_json::json!({"nested":[null,false,{"z":n,"a":"\n\t\\\""}],"float":0.125});
                r
            })
            .collect();
        assert_eq!(store.ingest_many(&records).unwrap(), (256, 0));
    }
    store.prepare_export_index().unwrap();
    assert!(root.join("memory.db-wal").is_file());
    assert!(root.join("memory.db-shm").is_file());
    drop(store);
    assert!(!root.join("memory.db-wal").exists());
    assert!(!root.join("memory.db-shm").exists());
    let initial = parity(&root);
    let database = root.join("memory.db");
    for sql in [
        "UPDATE records SET content='changed content' WHERE rowid=4",
        "UPDATE records SET metadata_json='{\"a\":null,\"b\":[true,1.25]}' WHERE rowid=5",
        "UPDATE records SET timestamp=-1.25 WHERE rowid=6",
        "UPDATE records SET rowid=10000 WHERE rowid=7",
        "UPDATE snapshot_counters SET next_occurrence=next_occurrence+1",
        "UPDATE snapshot_state SET record_id='different-id' WHERE position=0",
    ] {
        let before = parity(&root);
        let connection = Connection::open(&database).unwrap();
        assert!(connection.execute(sql, []).unwrap() > 0);
        drop(connection);
        let changed = parity(&root);
        assert_ne!(
            before, changed,
            "each mutation must change logical bytes: {sql}"
        );
    }
    assert_ne!(initial, parity(&root));
}

#[cfg(windows)]
#[test]
fn byte_parity_binds_generated_imported_and_final_broker_rows() {
    let owner = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let generation = crate::data::generate_with_spec_for_owned_store(
        &owner.path().join("seed"),
        &crate::data::FixtureSpec {
            shape: crate::data::FixtureShape::RepresentativeV2,
            target_jsonl_bytes: 32768,
        },
    )
    .unwrap();
    let seed_root = owner.path().join("seed/source");
    assert_eq!(
        parity(&seed_root),
        fs::read(owner.path().join("seed/archive.jsonl")).unwrap()
    );
    let root = owner.path().join("store");
    let store = crate::data::open_owned_fixture_store(&root).unwrap();
    store
        .import_logical_archive_once(
            std::io::BufReader::new(
                fs::File::open(owner.path().join("seed/archive.jsonl")).unwrap(),
            ),
            generation["logical_sha256"].as_str().unwrap(),
        )
        .unwrap();
    drop(store);
    assert_eq!(parity(&seed_root), parity(&root)); // deployment receipt is validated, not transported
    let store = hermes_memory::MemoryStore::open(&root).unwrap();
    let manifest = crate::full_manifest::FullManifest::new(
        crate::full_manifest::WorkloadSpec::full20x256_v1(),
        16,
    )
    .unwrap();
    for id in 0..62 {
        store.ingest_many(&manifest.records(id).unwrap()).unwrap();
    }
    assert_eq!(
        store.ingest_snapshot(&crate::data::snapshot()).unwrap(),
        (0, 0)
    );
    store.prepare_export_index().unwrap();
    drop(store);
    assert_ne!(parity(&seed_root), parity(&root));
    crate::full_oracles::verify_owned_stopped_sqlite(
        &owner,
        &root.join("memory.db"),
        &generation,
        &manifest,
    )
    .unwrap();
}

#[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
#[test]
fn owned_export_refuses_every_sidecar_and_nonregular_before_output() {
    let (_owner, root) = closed_fixture();
    let database = root.join("memory.db");
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = std::path::PathBuf::from(format!("{}{suffix}", database.display()));
        for directory in [false, true] {
            if directory {
                fs::create_dir(&sidecar).unwrap();
            } else {
                fs::write(&sidecar, b"").unwrap();
            }
            let before = fs::read(&database).unwrap();
            let mut bytes = Vec::new();
            assert!(export(&database, &root, &mut bytes).is_err());
            assert!(bytes.is_empty());
            assert_eq!(before, fs::read(&database).unwrap());
            if directory {
                fs::remove_dir(sidecar.clone()).unwrap();
            } else {
                fs::remove_file(sidecar.clone()).unwrap();
            }
        }
    }
    // Ordinary fixture-file cleanup only; never delete real broker WAL/SHM.
    let saved = root.join("saved.db");
    fs::rename(&database, &saved).unwrap();
    fs::create_dir(&database).unwrap();
    let mut bytes = Vec::new();
    assert!(export(&database, &root, &mut bytes).is_err());
    assert!(bytes.is_empty());
    fs::remove_dir(&database).unwrap();
    fs::rename(saved, &database).unwrap();
    assert!(export(&database, &root, std::io::sink()).is_ok());
}

#[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
#[test]
fn owned_export_refuses_hardlink_and_outside_scope_before_output() {
    let (owner, root) = closed_fixture();
    let database = root.join("memory.db");
    let alias = owner.path().join("alias.db");
    fs::hard_link(&database, &alias).unwrap();
    let mut bytes = Vec::new();
    assert!(export(&database, &root, &mut bytes).is_err());
    assert!(bytes.is_empty());
    fs::remove_file(alias).unwrap();
    assert!(export(&database, owner.path(), &mut bytes).is_err());
    assert!(bytes.is_empty());
    assert!(export(&database, &root, std::io::sink()).is_ok());
}

#[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
#[test]
fn owned_export_rejects_malformed_schema_receipt_types_and_bounded_fields() {
    for sql in [
        "PRAGMA user_version=1",
        "CREATE TABLE unexpected(payload TEXT)",
        "ALTER TABLE records ADD COLUMN unexpected TEXT",
        "UPDATE records SET metadata_json='{'",
        "UPDATE records SET content=x'0102'",
        "UPDATE records SET content=CAST(zeroblob(8388609) AS TEXT)",
        "UPDATE records SET metadata_json=CAST(zeroblob(8388609) AS TEXT)",
        "UPDATE records SET content=replace(CAST(zeroblob(8388608) AS TEXT),char(0),char(10)) WHERE rowid=2",
        "UPDATE records SET id=CAST(zeroblob(4097) AS TEXT) WHERE rowid=2",
        "UPDATE snapshot_counters SET next_occurrence=0",
        "UPDATE snapshot_counters SET next_occurrence=1000001",
        "UPDATE snapshot_state SET position=-1",
        "UPDATE snapshot_state SET fingerprint='bad'",
        "CREATE TABLE broker_migrations(singleton INTEGER, receipt_json TEXT)",
        "CREATE TABLE broker_migrations(singleton INTEGER PRIMARY KEY CHECK(singleton=1), receipt_json TEXT NOT NULL); INSERT INTO broker_migrations VALUES(1,'{}')",
        "UPDATE records SET content='password=unredacted'",
        "UPDATE records SET metadata_json='{\"password\":\"unredacted\"}'",
    ] {
        let (_owner,root)=closed_fixture();
        let database=root.join("memory.db");
        let connection=Connection::open(&database).unwrap();
        connection.execute_batch(sql).unwrap();
        drop(connection);
        let before=crate::data::inventory(&root).unwrap();
        let error = export(&database, &root, std::io::sink()).unwrap_err();
        if sql.contains("8388609") || sql.contains("4097") {
            assert!(matches!(error, MigrationError::Invalid("source field bounds")), "{sql}: {error}");
        } else if sql.contains("8388608") {
            assert!(matches!(error, MigrationError::Invalid("archive bounds")), "{sql}: {error}");
        }
        assert_eq!(before,crate::data::inventory(&root).unwrap());
    }
}

#[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
#[test]
fn owned_export_propagates_write_and_flush_failures_without_source_changes() {
    struct Fail {
        flush: bool,
    }
    impl Write for Fail {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.flush {
                Ok(bytes.len())
            } else {
                Err(std::io::Error::other("owned injected write"))
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("owned injected flush"))
        }
    }
    let (_owner, root) = closed_fixture();
    let database = root.join("memory.db");
    let before = crate::data::inventory(&root).unwrap();
    for flush in [false, true] {
        assert!(matches!(
            export(&database, &root, Fail { flush }),
            Err(MigrationError::Io(_))
        ));
    }
    assert_eq!(before, crate::data::inventory(&root).unwrap());
}

#[cfg(not(windows))]
#[test]
fn production_staged_export_refuses_before_source_or_output_io() {
    let owner = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let sentinel = owner.path().join("sentinel");
    fs::write(&sentinel, b"unchanged").unwrap();
    let before = fs::read(&sentinel).unwrap();
    for path in [
        owner.path().join("absent"),
        sentinel.clone(),
        owner.path().to_path_buf(),
    ] {
        let mut bytes = Vec::new();
        assert!(matches!(
            hermes_memory::logical_migration::export_from_staged_sqlite_copy(&path, &mut bytes),
            Err(MigrationError::Invalid(
                "read-only staged WAL export requires Windows"
            ))
        ));
        assert!(bytes.is_empty());
    }
    assert_eq!(before, fs::read(&sentinel).unwrap());
    assert_eq!(fs::read_dir(owner.path()).unwrap().count(), 1);
}
