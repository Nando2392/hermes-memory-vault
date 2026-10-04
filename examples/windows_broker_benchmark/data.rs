use hermes_memory::MemoryRecord;
pub const WORKSPACE: &str = "disposable-benchmark";
pub const MAX_SEED_RECORDS: u64 = 400_000;
pub const MAX_SEED_LINE_BYTES: usize = 4096;
pub const MAX_SEED_BATCH_BYTES: u64 = 1_048_576;
const MAX_SEED_BATCH_RECORDS: u64 = 256;
const MAX_SEED_FRAME_BYTES: u64 = 2_097_152;

#[allow(dead_code)]
pub(crate) fn validate_seed_batch(batch: &[MemoryRecord], prior: u64) -> Result<u64> {
    let end = prior
        .checked_add(batch.len() as u64)
        .ok_or("seed count overflow")?;
    if batch.is_empty() || batch.len() > MAX_SEED_BATCH_RECORDS as usize || end > MAX_SEED_RECORDS {
        return Err("seed row/batch bound".into());
    }
    let mut bytes = 0u64;
    for record in batch {
        record.validate()?;
        if [
            &record.id,
            &record.session_id,
            &record.kind,
            &record.workspace,
        ]
        .iter()
        .any(|s| s.len() > 256)
            || record.content.len() > 1024 * 1024
        {
            return Err("seed protocol field bound".into());
        }
        let mut line = LimitedWriter::new(std::io::sink(), MAX_SEED_LINE_BYTES as u64);
        serde_json::to_writer(&mut line, record)?;
        line.write_all(b"\n")?;
        bytes = bytes
            .checked_add(line.written)
            .ok_or("seed batch byte overflow")?;
        if bytes > MAX_SEED_BATCH_BYTES {
            return Err("seed batch byte bound".into());
        }
    }
    seed_frame_bytes(batch)?;
    Ok(bytes)
}

fn seed_frame_bytes(batch: &[MemoryRecord]) -> Result<u64> {
    // Include the fixed-workspace enrollment policy and maximum request ID.
    // Counting into a sink avoids a second serialized batch allocation.
    #[derive(serde::Serialize)]
    struct Body<'a> {
        records: &'a [MemoryRecord],
    }
    #[derive(serde::Serialize)]
    struct Frame<'a> {
        protocol: u32,
        request_id: &'a str,
        op: &'a str,
        body: Body<'a>,
        policy: hermes_memory::workspace_policy::Policy,
    }
    let request_id = "r".repeat(128);
    let frame = Frame {
        protocol: 1,
        request_id: &request_id,
        op: "ingest",
        body: Body { records: batch },
        policy: hermes_memory::workspace_policy::Policy {
            scope_mode: hermes_memory::workspace_policy::ScopeMode::Fixed,
            legacy_root_key: "a".repeat(64),
        },
    };
    let mut writer = LimitedWriter::new(std::io::sink(), MAX_SEED_FRAME_BYTES);
    serde_json::to_writer(&mut writer, &frame)?;
    Ok(writer.written)
}

/// Fixed representative-v2 shape. Smaller targets exercise the same bounded writer
/// in ordinary-file tests; the eventual CLI must separately admit case sizes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureSpec {
    pub shape: FixtureShape,
    pub target_jsonl_bytes: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FixtureShape {
    #[serde(rename = "representative-v2")]
    RepresentativeV2,
}
#[allow(dead_code)] // Prerequisite API; not wired into the small controller.
impl FixtureSpec {
    pub fn representative_6_mib() -> Self {
        Self {
            shape: FixtureShape::RepresentativeV2,
            target_jsonl_bytes: 6 * 1024 * 1024,
        }
    }
    pub fn representative_600_mib() -> Self {
        Self {
            shape: FixtureShape::RepresentativeV2,
            target_jsonl_bytes: 600 * 1024 * 1024,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.target_jsonl_bytes == 0 || self.target_jsonl_bytes > 600 * 1024 * 1024 {
            return Err("representative target must be 1..600 MiB in bytes".into());
        }
        Ok(())
    }
}
#[allow(dead_code)]
pub fn representative_record(index: u64) -> Result<MemoryRecord> {
    if index >= MAX_SEED_RECORDS {
        return Err("representative seed index exceeds row bound".into());
    }
    let mut r = record(index);
    r.session_id = format!("benchmark-seed-{:02}", index % 16);
    let text = format!(
        "ordinary benchmark seed {index:012} session {:02} ",
        index % 16
    );
    r.content = text.repeat(2048 / text.len() + 1);
    r.content.truncate(2048);
    r.metadata = serde_json::json!({"fixture": "representative-v2", "index": index});
    Ok(r)
}
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
/// Closed admission for this seam; later schedules may reuse deterministic ordinal records.
#[derive(Clone, Copy, Debug)]
pub struct TwoWarmupManifest;
#[allow(dead_code)] // Internal sandbox only; no native/workflow admission.
impl TwoWarmupManifest {
    pub const OPERATIONS: u32 = 2;
    pub fn record(self, id: u32) -> Result<MemoryRecord> {
        if id >= Self::OPERATIONS {
            return Err("only two warmup operations admitted".into());
        }
        let r = MemoryRecord {
            id: format!("benchmark-workload-v1-{id:06}"),
            session_id: "benchmark-client".into(),
            workspace: WORKSPACE.into(),
            kind: "user".into(),
            content: format!("deterministic warmup {id:06} ").repeat(64),
            timestamp: 1_710_000_000.0 + f64::from(id),
            metadata: serde_json::json!({"workload":"two-warmup-v1", "operation_id":id}),
        };
        r.validate()?;
        if serde_json::to_vec(&r)?.len() > MAX_SEED_LINE_BYTES - 1 {
            return Err("warmup record byte bound".into());
        }
        Ok(r)
    }
    pub fn payload(self, id: u32) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&[self.record(id)?])?)
    }
    pub fn cli_epoch(self, id: u32) -> Result<u64> {
        self.record(id)?;
        Ok(3 + u64::from(id))
    }
}
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
/// Refuse an entire excess write before forwarding any of its bytes.
struct LimitedWriter<W> {
    inner: W,
    limit: u64,
    written: u64,
}
impl<W: Write> LimitedWriter<W> {
    fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            limit,
            written: 0,
        }
    }
}
impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .written
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| std::io::Error::other("fixture writer byte limit"))?;
        let n = self.inner.write(bytes)?;
        self.written = next - (bytes.len() - n) as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
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
    generate_inner(
        root,
        bytes,
        None,
        hermes_memory::logical_migration::MAX_ARCHIVE_BYTES,
        |path| Ok(hermes_memory::MemoryStore::open(path)?),
        production_fixture_export,
    )
}

#[allow(dead_code)] // Deliberately not admitted by the current CLI.
pub fn generate_with_spec(root: &Path, spec: &FixtureSpec) -> Result<serde_json::Value> {
    spec.validate()?;
    generate_inner(
        root,
        spec.target_jsonl_bytes,
        Some(spec),
        hermes_memory::logical_migration::MAX_ARCHIVE_BYTES,
        |path| Ok(hermes_memory::MemoryStore::open(path)?),
        production_fixture_export,
    )
}

#[cfg(test)]
pub(crate) fn open_owned_fixture_store(root: &Path) -> Result<hermes_memory::MemoryStore> {
    #[cfg(all(target_os = "linux", feature = "experimental-broker"))]
    {
        use std::os::unix::fs::DirBuilderExt;
        // Reserve only a fresh child; never chmod or repair an existing namespace.
        fs::DirBuilder::new().mode(0o700).create(root)?;
        Ok(hermes_memory::MemoryStore::open_broker(root)?)
    }
    #[cfg(not(all(target_os = "linux", feature = "experimental-broker")))]
    {
        Ok(hermes_memory::MemoryStore::open(root)?)
    }
}

#[cfg(test)]
pub(crate) fn generate_with_spec_for_owned_store(
    root: &Path,
    spec: &FixtureSpec,
) -> Result<serde_json::Value> {
    spec.validate()?;
    // Direct POSIX refusal must precede even the outer fixture reservation.
    #[cfg(not(any(windows, all(target_os = "linux", feature = "experimental-broker"))))]
    {
        hermes_memory::MemoryStore::open(root.join("source"))?;
    }
    generate_inner(
        root,
        spec.target_jsonl_bytes,
        Some(spec),
        hermes_memory::logical_migration::MAX_ARCHIVE_BYTES,
        open_owned_fixture_store,
        |database, output| {
            Ok(crate::owned_fixture_export::export(
                database,
                database.parent().ok_or("fixture parent")?,
                output,
            )?)
        },
    )
}

fn production_fixture_export(
    database: &Path,
    output: &mut dyn Write,
) -> Result<hermes_memory::logical_migration::MigrationReceipt> {
    Ok(hermes_memory::logical_migration::export_from_staged_sqlite_copy(database, output)?)
}

fn generate_inner(
    root: &Path,
    bytes: u64,
    spec: Option<&FixtureSpec>,
    archive_limit: u64,
    open_store: impl FnOnce(&Path) -> Result<hermes_memory::MemoryStore>,
    export: impl FnOnce(
        &Path,
        &mut dyn Write,
    ) -> Result<hermes_memory::logical_migration::MigrationReceipt>,
) -> Result<serde_json::Value> {
    let maximum_jsonl = bytes
        .checked_add(MAX_SEED_BATCH_BYTES)
        .ok_or("target byte overflow")?;
    fs::create_dir(root)?; // CreateNew: refuse any previously existing namespace.
    let source = root.join("source");
    let store = open_store(&source)?;
    store.ingest_snapshot(&snapshot())?;
    let mut count = 0u64;
    while fs::metadata(source.join("events.jsonl"))?.len() < bytes {
        // A bounded batch, never a corpus-sized Vec. Keep tiny pure tests tiny.
        let batch_len = if bytes < 1024 * 1024 { 4 } else { 256 };
        let end = count.checked_add(batch_len).ok_or("seed count overflow")?;
        if spec.is_some()
            && (end > MAX_SEED_RECORDS
                || end.checked_add(1).ok_or("snapshot row overflow")?
                    > hermes_memory::logical_migration::MAX_ROWS)
        {
            return Err("fixture seed row bound".into());
        }
        let batch: Vec<_> = (count..end)
            .map(|index| {
                if spec.is_some() {
                    representative_record(index)
                } else {
                    Ok(record(index))
                }
            })
            .collect::<Result<_>>()?;
        let expected_jsonl = if spec.is_some() {
            let addition = validate_seed_batch(&batch, count)?;
            let current = fs::metadata(source.join("events.jsonl"))?.len();
            let next = current
                .checked_add(addition)
                .ok_or("projection byte overflow")?;
            if next >= maximum_jsonl {
                return Err("fixture projection bound before ingest".into());
            }
            Some(next)
        } else {
            None
        };
        let (inserted, duplicates) = store.ingest_many(&batch)?;
        if inserted != batch.len() || duplicates != 0 {
            return Err("seed ingest acknowledgement mismatch".into());
        }
        count = count
            .checked_add(inserted as u64)
            .ok_or("seed count overflow")?;
        if let Some(expected) = expected_jsonl {
            if fs::metadata(source.join("events.jsonl"))?.len() != expected {
                return Err("actual projection differs from validated seed serialization".into());
            }
        }
    }
    drop(store); // Close SQLite before immutable/read-only logical export.
    let before = inventory(&source)?;
    let archive = root.join("archive.jsonl");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&archive)?;
    let receipt = export(
        &source.join("memory.db"),
        &mut LimitedWriter::new(&mut output, archive_limit),
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
    let mut report = serde_json::json!({"source": source, "archive": archive,
        "archive_sha256": hash_file(&archive)?, "archive_bytes": archive_bytes,
        "logical_sha256": receipt.logical_sha256, "seed_records": count,
        "records": receipt.records, "snapshot_states": receipt.snapshot_states,
        "snapshot_counters": receipt.snapshot_counters,
        "jsonl_bytes": fs::metadata(source.join("events.jsonl"))?.len(),
        "source_before": before, "source_after": after});
    if let Some(spec) = spec {
        report["fixture_spec"] = serde_json::to_value(spec)?;
    }
    let report_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("generation.json"))?;
    serde_json::to_writer_pretty(report_file, &report)?;
    Ok(report)
}

// These helpers are assertion-bearing refusal scenarios, not successful-store substitutes.
#[cfg(all(
    test,
    not(any(windows, all(target_os = "linux", feature = "experimental-broker")))
))]
fn assert_typed_unsupported<T>(result: Result<T>) {
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("unsupported fixture unexpectedly acquired a store"),
    };
    match error.downcast_ref::<hermes_memory::MemoryError>() {
        Some(hermes_memory::MemoryError::Io(io)) => {
            assert_eq!(io.kind(), std::io::ErrorKind::Unsupported);
            assert_eq!(io.to_string(), "direct POSIX memory storage is unsupported; use the separately provisioned experimental broker");
        }
        other => panic!("expected typed MemoryError::Io(Unsupported), got {other:?}"),
    }
}

#[cfg(all(
    test,
    not(any(windows, all(target_os = "linux", feature = "experimental-broker")))
))]
fn refusal_snapshot(root: &Path) -> std::collections::BTreeMap<std::path::PathBuf, String> {
    fn visit(
        base: &Path,
        path: &Path,
        out: &mut std::collections::BTreeMap<std::path::PathBuf, String>,
    ) {
        let metadata = fs::symlink_metadata(path).unwrap();
        let kind = metadata.file_type();
        let mut value = if kind.is_symlink() {
            format!("symlink:{:?}", fs::read_link(path).unwrap())
        } else if kind.is_dir() {
            "directory".to_string()
        } else {
            assert!(kind.is_file());
            format!("file:{:?}", fs::read(path).unwrap())
        };
        value.push_str(&format!(":readonly={}", metadata.permissions().readonly()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            value.push_str(&format!(
                ":mode={}:uid={}:gid={}:dev={}:ino={}:links={}",
                metadata.mode(),
                metadata.uid(),
                metadata.gid(),
                metadata.dev(),
                metadata.ino(),
                metadata.nlink()
            ));
        }
        out.insert(path.strip_prefix(base).unwrap().to_path_buf(), value);
        if kind.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(base, &entry.unwrap().path(), out);
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    visit(root, root, &mut out);
    out
}

#[cfg(all(
    test,
    not(any(windows, all(target_os = "linux", feature = "experimental-broker")))
))]
pub(crate) fn assert_owned_store_refusal(bytes: u64, seed: &str, store: &str) {
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let root = temp.path();
    // Deliberate harness setup is part of the baseline, not an operation artifact.
    for dir in ["scratch", "controller", "install"] {
        fs::create_dir(root.join(dir)).unwrap();
    }
    fs::write(root.join("sentinel"), b"caller-owned baseline").unwrap();
    let before = refusal_snapshot(root);
    if bytes != 0 {
        let spec = FixtureSpec {
            shape: FixtureShape::RepresentativeV2,
            target_jsonl_bytes: bytes,
        };
        for _ in 0..2 {
            assert_typed_unsupported(generate_with_spec_for_owned_store(&root.join(seed), &spec));
            assert_eq!(refusal_snapshot(root), before);
        }
    }
    for _ in 0..2 {
        assert_typed_unsupported(open_owned_fixture_store(&root.join(store)));
        assert_eq!(refusal_snapshot(root), before);
    }
    for leaf in [seed, store, "export", "scratch/export", "full-report.json"] {
        assert!(
            !root.join(leaf).exists(),
            "unexpected operation artifact: {leaf}"
        );
    }
    for parent in [seed, store] {
        for leaf in [
            "source",
            "archive.jsonl",
            "generation.json",
            "memory.db",
            "memory.db-wal",
            "memory.db-shm",
            "events.jsonl",
            "memory.lock",
            "memory.init.lock",
        ] {
            assert!(!root.join(parent).join(leaf).exists());
        }
    }
    for id in 0..64 {
        for phase in ["ready", "release", "done", "validated-ack"] {
            for dir in ["scratch", "controller"] {
                assert!(!root
                    .join(format!("{dir}/full20x256-v1-op-{id}-{phase}.json"))
                    .exists());
            }
        }
        for extension in [
            "attempt",
            "result.json",
            "intent.json",
            "stdin",
            "stdout",
            "stderr",
        ] {
            assert!(!root
                .join("scratch")
                .join(crate::full_workload_receipt::label(id))
                .with_extension(extension)
                .exists());
        }
    }
    assert_eq!(refusal_snapshot(root), before);
    println!("owned fixture contract: typed Unsupported; unchanged baseline; no admitted runner, retained receipt, ACK, commit, oracle or report execution");
}

#[cfg(all(
    test,
    not(any(windows, all(target_os = "linux", feature = "experimental-broker")))
))]
pub(crate) fn assert_owned_refusal_sentinels() {
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let root = temp.path();
    let populated = root.join("populated");
    fs::create_dir(&populated).unwrap();
    let sentinel = root.join("sentinel");
    fs::write(
        &sentinel,
        b"caller-owned database/sidecar/projection sentinel",
    )
    .unwrap();
    for name in [
        "memory.db",
        "memory.db-wal",
        "memory.db-shm",
        "events.jsonl",
    ] {
        fs::hard_link(&sentinel, populated.join(name)).unwrap();
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&populated, root.join("alias")).unwrap();
    let before = refusal_snapshot(root);
    let spec = FixtureSpec {
        shape: FixtureShape::RepresentativeV2,
        target_jsonl_bytes: 8192,
    };
    let invalid = FixtureSpec {
        target_jsonl_bytes: 0,
        ..spec.clone()
    };
    let error = generate_with_spec_for_owned_store(&root.join("invalid"), &invalid).unwrap_err();
    assert_eq!(
        error.to_string(),
        "representative target must be 1..600 MiB in bytes"
    );
    assert_eq!(refusal_snapshot(root), before);
    let mut paths = vec![root.join("absent"), root.join("missing/child"), populated];
    #[cfg(unix)]
    paths.push(root.join("alias"));
    for path in paths {
        for _ in 0..2 {
            assert_typed_unsupported(generate_with_spec_for_owned_store(&path, &spec));
            assert_eq!(refusal_snapshot(root), before);
            assert_typed_unsupported(open_owned_fixture_store(&path));
            assert_eq!(refusal_snapshot(root), before);
        }
    }
    assert_eq!(
        fs::read(sentinel).unwrap(),
        b"caller-owned database/sidecar/projection sentinel"
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn owned_store_seed_preserves_records_source_and_namespace_reservation() {
        #[cfg(not(any(windows, all(target_os = "linux", feature = "experimental-broker"))))]
        {
            crate::data::assert_owned_store_refusal(8192, "owned-seed", "store");
            crate::data::assert_owned_refusal_sentinels();
        }
        #[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
        {
            let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
            let root = temp.path().join("owned-seed");
            let spec = FixtureSpec {
                shape: FixtureShape::RepresentativeV2,
                target_jsonl_bytes: 8192,
            };
            let generated = generate_with_spec_for_owned_store(&root, &spec).unwrap();
            assert_eq!(generated["seed_records"], 4);
            assert_eq!(generated["records"], 5);
            assert_eq!(generated["snapshot_states"], 1);
            assert_eq!(generated["snapshot_counters"], 1);
            assert_eq!(generated["source_before"], generated["source_after"]);
            let lines = std::io::BufRead::lines(std::io::BufReader::new(
                File::open(root.join("source/events.jsonl")).unwrap(),
            ));
            for (index, line) in lines.skip(1).enumerate() {
                let actual: MemoryRecord = serde_json::from_str(&line.unwrap()).unwrap();
                assert_eq!(actual, representative_record(index as u64).unwrap());
            }
            assert!(generate_with_spec_for_owned_store(&root, &spec).is_err());
            let invalid_root = temp.path().join("invalid");
            let invalid = FixtureSpec {
                target_jsonl_bytes: 0,
                ..spec
            };
            assert!(generate_with_spec_for_owned_store(&invalid_root, &invalid).is_err());
            assert!(!invalid_root.exists());
        }
    }

    #[test]
    fn two_warmup_manifest_has_distinct_bounded_exact_payloads() {
        let first = TwoWarmupManifest.record(0).unwrap();
        let second = TwoWarmupManifest.record(1).unwrap();
        assert_ne!(first.id, second.id);
        assert!(first.timestamp > record(MAX_SEED_RECORDS - 1).timestamp);
        assert!(second.timestamp > first.timestamp);
        assert_eq!(first.session_id, "benchmark-client");
        let payload = TwoWarmupManifest.payload(0).unwrap();
        let decoded: Vec<MemoryRecord> = serde_json::from_slice(&payload).unwrap();
        assert_eq!(decoded, [first]);
        assert!(payload.len() <= MAX_SEED_LINE_BYTES + 2);
        assert_eq!(TwoWarmupManifest.cli_epoch(0).unwrap(), 3);
        assert_eq!(TwoWarmupManifest.cli_epoch(1).unwrap(), 4);
        assert!(TwoWarmupManifest.record(2).is_err());
        assert!(TwoWarmupManifest.record(20).is_err());
    }
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

    #[test]
    fn bounded_archive_writer_refuses_excess_before_forwarding() {
        let mut output = Vec::new();
        {
            let mut writer = LimitedWriter::new(&mut output, 3);
            writer.write_all(b"abc").unwrap();
            assert!(writer.write_all(b"d").is_err());
            assert_eq!(writer.written, 3);
        }
        assert_eq!(output, b"abc");
        let mut writer = LimitedWriter::new(Vec::new(), u64::MAX);
        writer.written = u64::MAX;
        assert!(writer.write_all(b"x").is_err());
        assert!(writer.inner.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn representative_generation_crosses_actual_jsonl_target_once() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("representative");
        let spec = FixtureSpec {
            shape: FixtureShape::RepresentativeV2,
            target_jsonl_bytes: 8192,
        };
        let generated = generate_with_spec(&root, &spec).unwrap();
        let actual = generated["jsonl_bytes"].as_u64().unwrap();
        assert!(actual >= spec.target_jsonl_bytes);
        assert!(actual < spec.target_jsonl_bytes + MAX_SEED_BATCH_BYTES);
        assert_eq!(
            generated["fixture_spec"],
            serde_json::to_value(&spec).unwrap()
        );
        assert_eq!(generated["seed_records"], 4);
        assert_eq!(generated["records"], 5);
        assert_eq!(generated["source_before"], generated["source_after"]);
        let lines = std::io::BufRead::lines(std::io::BufReader::new(
            File::open(root.join("source/events.jsonl")).unwrap(),
        ));
        for (index, line) in lines.skip(1).enumerate() {
            let actual: MemoryRecord = serde_json::from_str(&line.unwrap()).unwrap();
            assert_eq!(actual, representative_record(index as u64).unwrap());
        }
        assert!(generate_with_spec(&root, &spec).is_err());
        let invalid_root = temp.path().join("invalid");
        let mut invalid = spec;
        invalid.target_jsonl_bytes = 0;
        assert!(generate_with_spec(&invalid_root, &invalid).is_err());
        assert!(!invalid_root.exists());
    }

    #[cfg(windows)]
    #[test]
    fn representative_archive_cap_keeps_partial_file_bounded_without_success_report() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("capped");
        let spec = FixtureSpec {
            shape: FixtureShape::RepresentativeV2,
            target_jsonl_bytes: 8192,
        };
        assert!(generate_inner(
            &root,
            spec.target_jsonl_bytes,
            Some(&spec),
            100,
            |path| { Ok(hermes_memory::MemoryStore::open(path)?) },
            production_fixture_export
        )
        .is_err());
        assert!(fs::metadata(root.join("archive.jsonl")).unwrap().len() <= 100);
        assert!(!root.join("generation.json").exists());
        assert!(generate_with_spec(&root, &spec).is_err());
    }

    #[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
    #[test]
    fn owned_seed_export_cap_retains_partial_without_success_or_source_mutation() {
        let owner = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
        let root = owner.path().join("capped");
        let spec = FixtureSpec {
            shape: FixtureShape::RepresentativeV2,
            target_jsonl_bytes: 8192,
        };
        let mut before = None;
        assert!(generate_inner(
            &root,
            spec.target_jsonl_bytes,
            Some(&spec),
            100,
            open_owned_fixture_store,
            |database, output| {
                before = Some(inventory(database.parent().unwrap())?);
                Ok(crate::owned_fixture_export::export(
                    database,
                    database.parent().unwrap(),
                    output,
                )?)
            }
        )
        .is_err());
        assert!(fs::metadata(root.join("archive.jsonl")).unwrap().len() <= 100);
        assert!(!root.join("generation.json").exists());
        assert_eq!(before.unwrap(), inventory(&root.join("source")).unwrap());
        assert!(generate_with_spec_for_owned_store(&root, &spec).is_err());
    }

    #[test]
    fn seed_frame_bound_counts_enrolled_policy_and_full_envelope() {
        let records = [representative_record(0).unwrap()];
        let expected = serde_json::to_vec(&serde_json::json!({
            "protocol": 1, "request_id": "r".repeat(128), "op": "ingest",
            "body": {"records": records},
            "policy": {"scope_mode": "fixed", "legacy_root_key": "a".repeat(64)}
        }))
        .unwrap();
        assert_eq!(seed_frame_bytes(&records).unwrap(), expected.len() as u64);
        assert!(expected.len() < MAX_SEED_FRAME_BYTES as usize);
    }

    #[test]
    fn seed_batch_bounds_admit_exact_sizes_and_refuse_before_ingest() {
        let batch: Vec<_> = (0..256)
            .map(|n| representative_record(n).unwrap())
            .collect();
        let bytes = validate_seed_batch(&batch, MAX_SEED_RECORDS - 256).unwrap();
        assert!(bytes < MAX_SEED_BATCH_BYTES);
        assert!(validate_seed_batch(&batch, MAX_SEED_RECORDS - 255).is_err());
        assert!(validate_seed_batch(&batch, u64::MAX).is_err());
        let mut excess = batch.clone();
        excess.push(representative_record(256).unwrap());
        assert!(validate_seed_batch(&excess, 0).is_err());
        assert!(validate_seed_batch(&[], 0).is_err());
        let mut r = representative_record(0).unwrap();
        let base = serde_json::to_vec(&r).unwrap().len() + 1;
        r.content.push_str(&"a".repeat(MAX_SEED_LINE_BYTES - base));
        assert_eq!(
            validate_seed_batch(std::slice::from_ref(&r), 0).unwrap(),
            4096
        );
        let exact = vec![r.clone(); 256];
        assert_eq!(validate_seed_batch(&exact, 0).unwrap(), 1_048_576);
        r.content.push('a');
        assert!(validate_seed_batch(&[r], 0).is_err());
    }

    #[test]
    fn representative_spec_and_records_are_closed_and_deterministic() {
        let small = FixtureSpec::representative_6_mib();
        let large = FixtureSpec::representative_600_mib();
        assert_eq!(small.target_jsonl_bytes, 6 * 1024 * 1024);
        assert_eq!(large.target_jsonl_bytes, 600 * 1024 * 1024);
        small.validate().unwrap();
        large.validate().unwrap();
        let mut value = serde_json::to_value(&small).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<FixtureSpec>(value).is_err());
        for index in 0..32 {
            let r = representative_record(index).unwrap();
            assert_eq!(r, representative_record(index).unwrap());
            assert_eq!(r.content.len(), 2048);
            assert!(r
                .content
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b' '));
            assert!(r.content.contains("ordinary benchmark"));
            assert_eq!(r.session_id, format!("benchmark-seed-{:02}", index % 16));
            assert_eq!(r.timestamp, 1_700_000_000.0 + index as f64);
            r.validate().unwrap();
        }
        assert_ne!(
            representative_record(0).unwrap().content,
            representative_record(1).unwrap().content
        );
        assert!(representative_record(MAX_SEED_RECORDS).is_err());
        let mut invalid = small;
        invalid.target_jsonl_bytes = u64::MAX;
        assert!(invalid.validate().is_err());
    }

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
