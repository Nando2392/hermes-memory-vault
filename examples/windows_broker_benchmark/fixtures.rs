//! Post-stop read-only evidence of what the actual broker imported at startup.
use crate::{contract::ensure, data::Result};
use serde_json::{json, Value};
use std::path::Path;
/// Independent of final SQLite and its projection: replay the pinned initial
/// logical archive and insert the pilot's single acknowledged canary in row order.
/// Snapshot identities/state are trusted only through the original archive digest;
/// seed payloads are additionally checked against the deterministic fixture.
/// This is deliberately NOT an arbitrary-operation-manifest or 600 MiB oracle.
fn pilot_expected_sqlite_digest(generation: &Value, additions: u64) -> Result<String> {
    let spec: crate::data::FixtureSpec =
        serde_json::from_value(generation["fixture_spec"].clone())?;
    ensure(
        spec == crate::data::FixtureSpec::representative_6_mib(),
        "SQLite oracle supports only representative 6 MiB pilot",
    )?;
    ensure(
        additions == 1,
        "SQLite oracle requires single known pilot addition; broader manifest unavailable",
    )?;
    representative_expected_sqlite_digest(generation, &[crate::client::known_record()])
}
fn representative_expected_sqlite_digest(
    generation: &Value,
    additions: &[hermes_memory::MemoryRecord],
) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::{BufRead, Read};
    let spec: crate::data::FixtureSpec =
        serde_json::from_value(generation["fixture_spec"].clone())?;
    spec.validate()?;
    ensure(
        spec.target_jsonl_bytes <= 6 * 1024 * 1024,
        "small oracle target bound",
    )?;
    let seeds = generation["seed_records"].as_u64().ok_or("pilot seeds")?;
    ensure(
        (16..=crate::data::MAX_SEED_RECORDS).contains(&seeds)
            && generation["records"].as_u64() == seeds.checked_add(1),
        "pilot seed/record bound",
    )?;
    let file = std::fs::File::open(
        generation["archive"]
            .as_str()
            .ok_or("pilot initial archive path")?,
    )?;
    ensure(
        file.metadata()?.is_file() && file.metadata()?.len() <= 8 * 1024 * 1024,
        "pilot archive byte bound",
    )?;
    let mut reader = std::io::BufReader::new(file);
    let mut initial = Sha256::new();
    initial.update(b"hermes-logical-migration-v1\0");
    let mut expected = initial.clone();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    let mut total = 0u64;
    let mut records = 0u64;
    let mut phase = 0;
    let mut counters = 0;
    let mut states = 0;
    loop {
        ensure(
            std::time::Instant::now() < deadline,
            "pilot SQLite expectation deadline",
        )?;
        let mut bytes = Vec::new();
        (&mut reader).take(4097).read_until(b'\n', &mut bytes)?;
        total += bytes.len() as u64;
        ensure(
            !bytes.is_empty()
                && bytes.len() <= 4096
                && bytes.last() == Some(&b'\n')
                && total <= 8 * 1024 * 1024,
            "pilot archive line/total bound or truncation",
        )?;
        let mut entry: Value = serde_json::from_slice(&bytes)?;
        match entry["type"].as_str().ok_or("pilot archive entry type")? {
            "header" => {
                ensure(
                    total == bytes.len() as u64
                        && entry == json!({"type":"header", "format":1, "source_schema":2}),
                    "pilot archive header",
                )?;
            }
            "record" => {
                ensure(
                    phase == 0 && records <= seeds,
                    "pilot archive record order/count",
                )?;
                entry
                    .as_object_mut()
                    .ok_or("pilot record object")?
                    .remove("type");
                let record: hermes_memory::MemoryRecord = serde_json::from_value(entry)?;
                if records == 0 {
                    let snapshot = crate::data::snapshot();
                    let item = &snapshot.items[0];
                    ensure(
                        record.session_id == snapshot.session_id
                            && record.workspace == snapshot.workspace
                            && record.kind == item.kind
                            && record.content == item.content
                            && record.timestamp == item.timestamp
                            && record.metadata == item.metadata,
                        "pilot snapshot payload",
                    )?;
                } else {
                    ensure(
                        record == crate::data::representative_record(records - 1)?,
                        "pilot deterministic seed payload",
                    )?;
                }
                records += 1;
            }
            "counter" => {
                ensure(
                    phase == 0 && records == seeds + 1,
                    "pilot counter order/count",
                )?;
                #[derive(serde::Serialize)]
                struct Record<'a> {
                    #[serde(rename = "type")]
                    tag: &'static str,
                    #[serde(flatten)]
                    record: &'a hermes_memory::MemoryRecord,
                }
                for record in additions {
                    let mut addition = serde_json::to_vec(&Record {
                        tag: "record",
                        record,
                    })?;
                    addition.push(b'\n');
                    ensure(addition.len() <= 4096, "pilot addition line bound")?;
                    expected.update(&addition);
                }
                phase = 1;
                counters += 1;
            }
            "state" => {
                ensure(phase == 1, "pilot state order/count")?;
                phase = 2;
                states += 1;
            }
            "trailer" => {
                ensure(
                    phase == 2 && counters == 1 && states == 1,
                    "pilot archive snapshot counts",
                )?;
                let receipt: hermes_memory::logical_migration::MigrationReceipt =
                    serde_json::from_value(entry["receipt"].clone())?;
                let initial_hash = format!("{:x}", initial.finalize());
                ensure(
                    receipt.logical_sha256 == initial_hash
                        && generation["logical_sha256"].as_str() == Some(initial_hash.as_str())
                        && receipt.records == records
                        && receipt.snapshot_states == 1
                        && receipt.snapshot_counters == 1,
                    "pilot initial archive digest/receipt mismatch",
                )?;
                ensure(
                    reader.read(&mut [0; 1])? == 0,
                    "pilot archive trailing bytes",
                )?;
                return Ok(format!("{:x}", expected.finalize()));
            }
            _ => return Err("unsupported pilot archive entry".into()),
        }
        initial.update(&bytes);
        expected.update(&bytes);
    }
}

pub fn verify_stopped_import(database: &Path, generation: &Value) -> Result<Value> {
    verify_stopped_import_with_expected(database, generation, 1)
}

/// Count expectations come from the acknowledged operation manifest, not from
/// observations of the final store. This does not replace the payload oracle.
pub fn verify_stopped_import_with_expected(
    database: &Path,
    generation: &Value,
    expected_additions: u64,
) -> Result<Value> {
    verify_stopped_import_inner(database, generation, expected_additions, false)
}
#[allow(dead_code)] // Internal sandbox only; no native/workflow admission.
pub fn verify_stopped_two_warmup(database: &Path, generation: &Value) -> Result<Value> {
    verify_stopped_import_inner(database, generation, 2, true)
}
fn verify_stopped_import_inner(
    database: &Path,
    generation: &Value,
    expected_additions: u64,
    two_warmups: bool,
) -> Result<Value> {
    let initial = generation["records"].as_u64().ok_or("generation count")?;
    let expected = initial
        .checked_add(expected_additions)
        .ok_or("final record count overflow")?;
    ensure(
        initial > 0 && expected <= hermes_memory::logical_migration::MAX_ROWS,
        "final record row bound",
    )?;
    ensure(
        generation["snapshot_states"] == 1 && generation["snapshot_counters"] == 1,
        "generation snapshot counts",
    )?;
    let hash = generation["logical_sha256"]
        .as_str()
        .ok_or("generation logical hash")?;
    ensure(
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "generation logical hash encoding",
    )?;
    // A stopped, cleanly closed broker is required; never ignore a live WAL.
    for suffix in ["-wal", "-shm"] {
        ensure(
            !std::path::PathBuf::from(format!("{}{suffix}", database.display())).exists(),
            "broker sidecars remain after stop; refuse immutable inspection",
        )?;
    }
    let expected_payload = if two_warmups {
        Some(representative_expected_sqlite_digest(
            generation,
            &[
                crate::data::TwoWarmupManifest.record(0)?,
                crate::data::TwoWarmupManifest.record(1)?,
            ],
        )?)
    } else if generation.get("fixture_spec").is_some() {
        Some(pilot_expected_sqlite_digest(
            generation,
            expected_additions,
        )?)
    } else {
        None // Legacy arbitrary additions retain their separate count/receipt contract.
    };
    let final_export = hermes_memory::logical_migration::export_from_staged_sqlite_copy(
        database,
        std::io::sink(),
    )?;
    if let Some(expected_payload) = &expected_payload {
        ensure(
            final_export.logical_sha256 == *expected_payload,
            "broker SQLite logical payload differs from independently expected pilot dataset",
        )?;
    }
    ensure(
        final_export.records == expected,
        "broker final record count differs from import plus expected additions",
    )?;
    ensure(
        final_export.snapshot_states == 1 && final_export.snapshot_counters == 1,
        "broker snapshot state/counter count changed",
    )?;
    let path = database.canonicalize()?;
    let path = path.to_str().ok_or("database encoding")?;
    let path = path
        .strip_prefix(r"\\?\")
        .unwrap_or(path)
        .replace('\\', "/");
    let mut uri = String::from("file:");
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"/:._-".contains(&b) {
            uri.push(b as char);
        } else {
            uri.push_str(&format!("%{b:02X}"));
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    let connection = rusqlite::Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )?;
    let receipt: String = connection.query_row(
        "SELECT receipt_json FROM broker_migrations WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let imported: Value = serde_json::from_str(&receipt)?;
    for key in [
        "records",
        "snapshot_states",
        "snapshot_counters",
        "logical_sha256",
    ] {
        ensure(
            imported[key] == generation[key],
            "actual startup migration receipt differs from staged export",
        )?;
    }
    Ok(
        json!({"persisted_startup_receipt":imported,"final_read_only_export":final_export,"expected_final_logical_sha256":expected_payload,"source":"actual stopped broker SQLite, immutable read-only; not source fixture counts"}),
    )
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::*;
    #[cfg(windows)]
    #[test]
    fn pilot_sqlite_same_count_mutation_rejected_with_projection_receipt_unchanged() {
        // Ordinary files only; no SCM, privileged service, or live vault.
        let dir = tempfile::tempdir().unwrap();
        let generation = crate::data::generate_with_spec(
            &dir.path().join("seed"),
            &crate::data::FixtureSpec::representative_6_mib(),
        )
        .unwrap();
        let root = dir.path().join("imported");
        let store = hermes_memory::MemoryStore::open(&root).unwrap();
        store
            .import_logical_archive_once(
                std::io::BufReader::new(
                    std::fs::File::open(dir.path().join("seed/archive.jsonl")).unwrap(),
                ),
                generation["logical_sha256"].as_str().unwrap(),
            )
            .unwrap();
        store.ingest_many(&[crate::client::known_record()]).unwrap();
        drop(store);
        let database = root.join("memory.db");
        assert!(verify_stopped_import_with_expected(&database, &generation, 1).is_ok());
        let projection = crate::data::hash_file(&root.join("events.jsonl")).unwrap();
        let connection = rusqlite::Connection::open(&database).unwrap();
        let receipt: String = connection
            .query_row("SELECT receipt_json FROM broker_migrations", [], |r| {
                r.get(0)
            })
            .unwrap();
        drop(connection);
        for (column, value) in [
            ("metadata_json", "{\"fixture\":\"changed\"}"),
            ("content", "changed ordinary payload"),
        ] {
            let connection = rusqlite::Connection::open(&database).unwrap();
            let original: String = connection
                .query_row(
                    &format!("SELECT {column} FROM records WHERE id='benchmark-000000000000'"),
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                connection
                    .execute(
                        &format!(
                            "UPDATE records SET {column}=?1 WHERE id='benchmark-000000000000'"
                        ),
                        [value]
                    )
                    .unwrap(),
                1
            );
            let unchanged: String = connection
                .query_row("SELECT receipt_json FROM broker_migrations", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(receipt, unchanged);
            drop(connection);
            assert_eq!(
                projection,
                crate::data::hash_file(&root.join("events.jsonl")).unwrap()
            );
            let final_export = hermes_memory::logical_migration::export_from_staged_sqlite_copy(
                &database,
                std::io::sink(),
            )
            .unwrap();
            assert_eq!(
                final_export.records,
                generation["records"].as_u64().unwrap() + 1
            );
            let error = verify_stopped_import_with_expected(&database, &generation, 1).unwrap_err();
            assert!(
                error.to_string().contains("SQLite logical payload"),
                "{error}"
            );
            let connection = rusqlite::Connection::open(&database).unwrap();
            connection
                .execute(
                    &format!("UPDATE records SET {column}=?1 WHERE id='benchmark-000000000000'"),
                    [original],
                )
                .unwrap();
            drop(connection);
            assert!(verify_stopped_import_with_expected(&database, &generation, 1).is_ok());
        }
    }

    #[cfg(windows)]
    #[test]
    fn stopped_expected_additions_preserve_receipt_and_sidecar_oracles() {
        let dir = tempfile::tempdir().unwrap();
        let generation = crate::data::generate(&dir.path().join("seed"), 8192).unwrap();
        let root = dir.path().join("imported");
        let store = hermes_memory::MemoryStore::open(&root).unwrap();
        store
            .import_logical_archive_once(
                std::io::BufReader::new(
                    std::fs::File::open(dir.path().join("seed/archive.jsonl")).unwrap(),
                ),
                generation["logical_sha256"].as_str().unwrap(),
            )
            .unwrap();
        store
            .ingest_many(&[crate::data::record(900_000), crate::data::record(900_001)])
            .unwrap();
        drop(store);
        let database = root.join("memory.db");
        assert!(verify_stopped_import_with_expected(&database, &generation, 2).is_ok());
        assert!(verify_stopped_import(&database, &generation).is_err());
        for n in [0, 1, 3, u64::MAX] {
            assert!(verify_stopped_import_with_expected(&database, &generation, n).is_err());
        }
        for key in [
            "records",
            "snapshot_states",
            "snapshot_counters",
            "logical_sha256",
        ] {
            let mut wrong = generation.clone();
            wrong[key] = if key == "logical_sha256" {
                json!("0".repeat(64))
            } else {
                json!(42)
            };
            assert!(verify_stopped_import_with_expected(&database, &wrong, 2).is_err());
        }
        for suffix in ["-wal", "-shm"] {
            let sidecar = std::path::PathBuf::from(format!("{}{suffix}", database.display()));
            std::fs::write(&sidecar, b"sentinel").unwrap();
            let err = verify_stopped_import_with_expected(&database, &generation, 2).unwrap_err();
            assert!(err.to_string().contains("sidecars"));
            std::fs::remove_file(sidecar).unwrap();
        }
        let connection = rusqlite::Connection::open(&database).unwrap();
        let raw: String = connection
            .query_row(
                "SELECT receipt_json FROM broker_migrations WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let mut altered: Value = serde_json::from_str(&raw).unwrap();
        altered["unknown"] = json!(true);
        connection
            .execute(
                "UPDATE broker_migrations SET receipt_json=?1 WHERE singleton=1",
                [altered.to_string()],
            )
            .unwrap();
        drop(connection);
        assert!(verify_stopped_import_with_expected(&database, &generation, 2).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn real_six_mib_roundtrip_receipt_snapshot_duplicate_and_export() {
        // Ordinary temporary files only: NOT evidence of SCM/CLI end-to-end execution.
        let dir = tempfile::tempdir().unwrap();
        let generation =
            crate::data::generate(&dir.path().join("staged"), 6 * 1024 * 1024).unwrap();
        let source = dir.path().join("staged/source");
        let imported_root = dir.path().join("imported");
        let store = hermes_memory::MemoryStore::open(&imported_root).unwrap();
        let archive = std::io::BufReader::new(
            std::fs::File::open(dir.path().join("staged/archive.jsonl")).unwrap(),
        );
        let receipt = store
            .import_logical_archive_once(archive, generation["logical_sha256"].as_str().unwrap())
            .unwrap();
        assert_eq!(receipt.records, generation["records"].as_u64().unwrap());
        let known = crate::client::known_record();
        assert_eq!(
            store.ingest_many(std::slice::from_ref(&known)).unwrap(),
            (1, 0)
        );
        assert_eq!(
            store.ingest_many(std::slice::from_ref(&known)).unwrap(),
            (0, 1)
        );
        assert_eq!(
            store.ingest_snapshot(&crate::data::snapshot()).unwrap(),
            (0, 0)
        );
        store.prepare_export_index().unwrap();
        let vault = dir.path().join("markdown");
        let sessions =
            hermes_memory::client_export::render_markdown(&vault, crate::data::WORKSPACE, |r| {
                store.export_page(r, "test").map_err(|e| {
                    hermes_memory::MemoryError::Io(std::io::Error::other(e.to_string()))
                })
            })
            .unwrap();
        assert_eq!(sessions, 3);
        let export =
            crate::client::verify_export(&vault, generation["seed_records"].as_u64().unwrap())
                .unwrap();
        assert_eq!(export["records"], receipt.records + 1);
        assert!(crate::client::verify_export(
            &vault,
            generation["seed_records"].as_u64().unwrap() + 1
        )
        .is_err());
        // A successful export CLI/count is insufficient: actual content tampering fails.
        let mut changed = false;
        for file in export["files"].as_array().unwrap() {
            let path = std::path::Path::new(file["path"].as_str().unwrap());
            let text = std::fs::read_to_string(path).unwrap();
            if text.contains(&known.content) {
                std::fs::write(path, text.replace(&known.content, "tampered payload")).unwrap();
                changed = true;
            }
        }
        assert!(changed);
        assert!(
            crate::client::verify_export(&vault, generation["seed_records"].as_u64().unwrap())
                .is_err()
        );
        drop(store);
        let actual = verify_stopped_import(&imported_root.join("memory.db"), &generation).unwrap();
        assert_eq!(
            actual["persisted_startup_receipt"]["logical_sha256"],
            generation["logical_sha256"]
        );
        assert_eq!(
            crate::data::inventory(&source).unwrap(),
            generation["source_before"]
        );
        let mut wrong = generation.clone();
        wrong["logical_sha256"] = serde_json::json!("0".repeat(64));
        assert!(verify_stopped_import(&imported_root.join("memory.db"), &wrong).is_err());
    }
}
