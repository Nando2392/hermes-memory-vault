use hermes_memory::MemoryRecord;
pub const WORKSPACE: &str = "disposable-benchmark";
pub fn record(index: u64) -> MemoryRecord {
    MemoryRecord {
        id: format!("benchmark-{index:012}"),
        session_id: "benchmark-seed".into(),
        workspace: WORKSPACE.into(),
        kind: "user".into(),
        content: "ordinary benchmark text "
            .repeat(90)
            .chars()
            .take(2048)
            .collect(),
        timestamp: 1_700_000_000.0 + index as f64,
        metadata: serde_json::json!({"fixture": true, "index": index}),
    }
}
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
pub fn hash_file(path: &Path) -> Result<String> {
    let mut input = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
pub fn inventory(root: &Path) -> Result<serde_json::Value> {
    let mut files = std::collections::BTreeMap::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err("fixture contains nonregular entry".into());
        }
        files.insert(entry.file_name().to_string_lossy().into_owned(), serde_json::json!({"bytes": entry.metadata()?.len(), "sha256": hash_file(&entry.path())?}));
    }
    Ok(serde_json::to_value(files)?)
}
pub fn snapshot() -> hermes_memory::SnapshotRequest {
    hermes_memory::SnapshotRequest {
        session_id: "benchmark-snapshot".into(),
        workspace: WORKSPACE.into(),
        items: vec![hermes_memory::SnapshotItem {
            kind: "user".into(),
            content: "snapshot benchmark reference".into(),
            timestamp: 1_600_000_000.0,
            metadata: serde_json::json!({"fixture": true}),
        }],
    }
}
pub fn generate(root: &Path, bytes: u64) -> Result<serde_json::Value> {
    if bytes == 0 || bytes > 900 * 1024 * 1024 {
        return Err("fixture target must be 1..900 MiB in bytes".into());
    }
    fs::create_dir(root)?; // CreateNew: refuse any previously existing namespace.
    let source = root.join("source");
    let store = hermes_memory::MemoryStore::open(&source)?;
    store.ingest_snapshot(&snapshot())?;
    let mut count = 0u64;
    while fs::metadata(source.join("events.jsonl"))?.len() < bytes {
        // A bounded batch, never a corpus-sized Vec. Keep tiny pure tests tiny.
        let batch_len = if bytes < 1024 * 1024 { 4 } else { 256 };
        let batch: Vec<_> = (count..count + batch_len).map(record).collect();
        let (inserted, duplicates) = store.ingest_many(&batch)?;
        if inserted != batch.len() || duplicates != 0 {
            return Err("seed ingest acknowledgement mismatch".into());
        }
        count += inserted as u64;
    }
    drop(store); // Close SQLite before immutable/read-only logical export.
    let before = inventory(&source)?;
    let archive = root.join("archive.jsonl");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&archive)?;
    let receipt = hermes_memory::logical_migration::export_from_staged_sqlite_copy(
        source.join("memory.db"),
        &mut output,
    )?;
    output.flush()?;
    output.sync_all()?;
    drop(output);
    let after = inventory(&source)?;
    if before != after {
        return Err("read-only export changed source inventory/content".into());
    }
    let archive_bytes = fs::metadata(&archive)?.len();
    if archive_bytes > hermes_memory::logical_migration::MAX_ARCHIVE_BYTES {
        return Err("archive exceeds 1 GiB core guard".into());
    }
    if receipt.records != count + 1
        || receipt.snapshot_states != 1
        || receipt.snapshot_counters != 1
    {
        return Err("logical receipt fixture count mismatch".into());
    }
    let report = serde_json::json!({"source": source, "archive": archive,
        "archive_sha256": hash_file(&archive)?, "archive_bytes": archive_bytes,
        "logical_sha256": receipt.logical_sha256, "seed_records": count,
        "records": receipt.records, "snapshot_states": receipt.snapshot_states,
        "snapshot_counters": receipt.snapshot_counters,
        "jsonl_bytes": fs::metadata(source.join("events.jsonl"))?.len(),
        "source_before": before, "source_after": after});
    let report_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("generation.json"))?;
    serde_json::to_writer_pretty(report_file, &report)?;
    Ok(report)
}
#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn fresh_fixture_exports_real_records_snapshots_and_preserves_source() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("owned");
        let report = super::generate(&root, 8192).unwrap();
        assert!(report["jsonl_bytes"].as_u64().unwrap() >= 8192);
        assert!(report["records"].as_u64().unwrap() >= 4);
        assert_eq!(report["snapshot_states"], 1);
        assert_eq!(report["snapshot_counters"], 1);
        assert_eq!(report["source_before"], report["source_after"]);
        assert_eq!(report["archive_sha256"].as_str().unwrap().len(), 64);
        assert!(
            super::generate(&root, 8192).is_err(),
            "never adopt existing fixture"
        );
    }
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn fixture_generation_refuses_unsupported_direct_store_without_source_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("owned");
        let error = generate(&root, 8192).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<hermes_memory::MemoryError>(),
            Some(hermes_memory::MemoryError::Io(error))
                if error.kind() == std::io::ErrorKind::Unsupported
        ));
        // generate reserves its namespace before direct open refuses. No SQLite,
        // projection, archive or success report may be produced inside it.
        assert!(root.is_dir());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        assert!(
            generate(&root, 8192).is_err(),
            "never adopt reserved fixture"
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }

    #[test]
    fn deterministic_records_have_unique_ids_monotonic_times_and_safe_payload() {
        let a = record(0);
        let b = record(1);
        assert_eq!(a, record(0));
        assert_ne!(a.id, b.id);
        assert!(b.timestamp > a.timestamp);
        assert_eq!(a.content.len(), 2048);
        assert!(a.content.is_ascii());
        a.validate().unwrap();
        assert_eq!(a.workspace, "disposable-benchmark");
    }
}
