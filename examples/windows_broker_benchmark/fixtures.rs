//! Post-stop read-only evidence of what the actual broker imported at startup.
#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::*;
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
use crate::{contract::ensure, data::Result};
use serde_json::{json, Value};
use std::path::Path;
pub fn verify_stopped_import(database: &Path, generation: &Value) -> Result<Value> {
    // A stopped, cleanly closed broker is required; never ignore a live WAL.
    for suffix in ["-wal", "-shm"] {
        ensure(
            !std::path::PathBuf::from(format!("{}{suffix}", database.display())).exists(),
            "broker sidecars remain after stop; refuse immutable inspection",
        )?;
    }
    let final_export = hermes_memory::logical_migration::export_from_staged_sqlite_copy(
        database,
        std::io::sink(),
    )?;
    ensure(
        final_export.records == generation["records"].as_u64().ok_or("generation count")? + 1,
        "broker final record count differs from import plus known ingest",
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
        json!({"persisted_startup_receipt":imported,"final_read_only_export":final_export,"source":"actual stopped broker SQLite, immutable read-only; not source fixture counts"}),
    )
}
