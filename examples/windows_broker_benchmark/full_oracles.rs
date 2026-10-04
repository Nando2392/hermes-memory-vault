//! Full-only streaming storage and renderer oracles. No native acquisition.
#[cfg(test)]
#[path = "full_oracles_tests.rs"]
mod tests;
use crate::data::Result;
use crate::full_manifest::FullManifest;
use crate::{contract::ensure, data};
use data::WORKSPACE;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read},
    time::{Duration, Instant},
};
fn open_regular(path: &Path, cap: u64) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    ensure(
        meta.is_file() && meta.len() <= cap,
        "full oracle bounded regular file",
    )?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure(
            meta.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                == 0,
            "full oracle reparse file",
        )?;
    }
    Ok(file)
}
fn snapshot(source: &Path) -> Result<hermes_memory::MemoryRecord> {
    let mut reader = BufReader::new(open_regular(source, 7 * 1024 * 1024)?);
    let mut bytes = Vec::new();
    reader.by_ref().take(4097).read_until(b'\n', &mut bytes)?;
    ensure(
        bytes.len() <= 4096 && bytes.last() == Some(&b'\n'),
        "full snapshot line bound",
    )?;
    let record: hermes_memory::MemoryRecord = serde_json::from_slice(&bytes)?;
    let request = data::snapshot();
    let item = &request.items[0];
    ensure(
        record.session_id == request.session_id
            && record.workspace == request.workspace
            && record.kind == item.kind
            && record.content == item.content
            && record.timestamp == item.timestamp
            && record.metadata == item.metadata,
        "full initial snapshot payload",
    )?;
    Ok(record)
}
fn exact(reader: &mut impl Read, expected: &[u8]) -> Result<()> {
    ensure(expected.len() <= 8192, "full oracle block bound")?;
    let mut actual = vec![0; expected.len()];
    reader.read_exact(&mut actual)?;
    ensure(actual == expected, "full oracle exact payload mismatch")
}
fn seeds(manifest: &FullManifest) -> Result<u64> {
    manifest
        .final_records()
        .checked_sub(5143)
        .ok_or_else(|| "full seed count".into())
}
pub fn verify_projection(path: &Path, source: &Path, manifest: &FullManifest) -> Result<Value> {
    let initial = open_regular(source, 7 * 1024 * 1024)?.metadata()?.len();
    let cap = (0..64).try_fold(initial, |n, id| -> Result<u64> {
        n.checked_add(manifest.operation(id)?.appended_jsonl_bytes)
            .ok_or_else(|| "full projection quota overflow".into())
    })?;
    let file = open_regular(path, cap)?;
    let bytes = file.metadata()?.len();
    let mut reader = BufReader::new(file.take(cap.checked_add(1).ok_or("full quota overflow")?));
    let deadline = Instant::now() + Duration::from_secs(60);
    for record in
        std::iter::once(Ok(snapshot(source)?)).chain(manifest.expected_seed_and_addition_records())
    {
        ensure(
            Instant::now() < deadline,
            "full projection verification deadline",
        )?;
        let mut expected = serde_json::to_vec(&record?)?;
        expected.push(b'\n');
        exact(&mut reader, &expected)?;
    }
    ensure(
        reader.read(&mut [0; 1])? == 0 && bytes == cap,
        "full projection EOF/exact byte bound",
    )?;
    Ok(
        serde_json::json!({"records":manifest.final_records(),"bytes":bytes,"exact_records_including_metadata_verified":true}),
    )
}
pub fn expected_logical_digest(generation: &Value, manifest: &FullManifest) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::{BufRead, Read};
    let spec: crate::data::FixtureSpec =
        serde_json::from_value(generation["fixture_spec"].clone())?;
    spec.validate()?;
    ensure(
        generation["seed_records"].as_u64() == Some(seeds(manifest)?),
        "full manifest/generation seed mismatch",
    )?;
    let archive_cap = generation["archive_bytes"]
        .as_u64()
        .ok_or("full archive quota")?;
    ensure(
        archive_cap <= 10 * 1024 * 1024,
        "full initial archive quota",
    )?;
    let archive = Path::new(
        generation["archive"]
            .as_str()
            .ok_or("full initial archive")?,
    );
    ensure(
        data::hash_file(archive)? == generation["archive_sha256"],
        "full initial archive raw pin",
    )?;
    ensure(
        data::inventory(Path::new(
            generation["source"].as_str().ok_or("full source")?,
        ))? == generation["source_before"],
        "full initial source inventory changed",
    )?;
    ensure(
        spec.target_jsonl_bytes <= 6 * 1024 * 1024,
        "small oracle target bound",
    )?;
    let seeds = generation["seed_records"].as_u64().ok_or("full seeds")?;
    ensure(
        (16..=crate::data::MAX_SEED_RECORDS).contains(&seeds)
            && generation["records"].as_u64() == seeds.checked_add(1),
        "full seed/record bound",
    )?;
    let file = open_regular(archive, archive_cap)?;
    ensure(
        file.metadata()?.is_file() && file.metadata()?.len() <= archive_cap,
        "full archive byte bound",
    )?;
    let mut reader = std::io::BufReader::new(file.take(archive_cap + 1));
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
            "full SQLite expectation deadline",
        )?;
        let mut bytes = Vec::new();
        (&mut reader).take(4097).read_until(b'\n', &mut bytes)?;
        total += bytes.len() as u64;
        ensure(
            !bytes.is_empty()
                && bytes.len() <= 4096
                && bytes.last() == Some(&b'\n')
                && total <= archive_cap,
            "full archive line/total bound or truncation",
        )?;
        let mut entry: Value = serde_json::from_slice(&bytes)?;
        match entry["type"].as_str().ok_or("full archive entry type")? {
            "header" => {
                ensure(
                    total == bytes.len() as u64
                        && entry == json!({"type":"header", "format":1, "source_schema":2}),
                    "full archive header",
                )?;
            }
            "record" => {
                ensure(
                    phase == 0 && records <= seeds,
                    "full archive record order/count",
                )?;
                entry
                    .as_object_mut()
                    .ok_or("full record object")?
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
                        "full snapshot payload",
                    )?;
                } else {
                    ensure(
                        record == crate::data::representative_record(records - 1)?,
                        "full deterministic seed payload",
                    )?;
                }
                records += 1;
            }
            "counter" => {
                ensure(
                    phase == 0 && records == seeds + 1,
                    "full counter order/count",
                )?;
                #[derive(serde::Serialize)]
                struct Record<'a> {
                    #[serde(rename = "type")]
                    tag: &'static str,
                    #[serde(flatten)]
                    record: &'a hermes_memory::MemoryRecord,
                }
                for record in manifest
                    .expected_seed_and_addition_records()
                    .skip(seeds as usize)
                {
                    let record = record?;
                    let mut addition = serde_json::to_vec(&Record {
                        tag: "record",
                        record: &record,
                    })?;
                    addition.push(b'\n');
                    ensure(addition.len() <= 4096, "full addition line bound")?;
                    expected.update(&addition);
                }
                phase = 1;
                counters += 1;
            }
            "state" => {
                ensure(phase == 1, "full state order/count")?;
                phase = 2;
                states += 1;
            }
            "trailer" => {
                ensure(
                    phase == 2 && counters == 1 && states == 1,
                    "full archive snapshot counts",
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
                    "full initial archive digest/receipt mismatch",
                )?;
                ensure(
                    reader.read(&mut [0; 1])? == 0,
                    "full archive trailing bytes",
                )?;
                return Ok(format!("{:x}", expected.finalize()));
            }
            _ => return Err("unsupported full archive entry".into()),
        }
        initial.update(&bytes);
        expected.update(&bytes);
    }
}

pub fn verify_stopped_sqlite(
    database: &Path,
    generation: &Value,
    manifest: &FullManifest,
) -> Result<Value> {
    for suffix in ["-wal", "-shm"] {
        ensure(
            !std::path::PathBuf::from(format!("{}{suffix}", database.display())).try_exists()?,
            "full stopped sidecars remain",
        )?;
    }
    let expected_payload = expected_logical_digest(generation, manifest)?;
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
    drop(connection);
    let final_export = hermes_memory::logical_migration::export_from_staged_sqlite_copy(
        database,
        std::io::sink(),
    )?;
    ensure(
        final_export.records == manifest.final_records()
            && final_export.snapshot_states == 1
            && final_export.snapshot_counters == 1
            && final_export.logical_sha256 == expected_payload,
        "full final SQLite logical payload mismatch",
    )?;
    Ok(
        json!({"persisted_startup_receipt":imported,"final_read_only_export":final_export,"expected_final_logical_sha256":expected_payload}),
    )
}

fn full_segment(identifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(identifier.as_bytes());
    let suffix = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{identifier}-{suffix}")
}
fn full_sessions() -> Vec<String> {
    let mut sessions = vec!["benchmark-client".to_owned()];
    sessions.extend((0..16).map(|n| format!("benchmark-seed-{n:02}")));
    sessions.push("benchmark-snapshot".to_owned());
    sessions
}
fn exact_bytes(reader: &mut impl Read, expected: &str) -> Result<()> {
    ensure(expected.len() <= 8192, "expected block bound")?;
    let mut actual = vec![0; expected.len()];
    reader.read_exact(&mut actual)?;
    ensure(
        actual == expected.as_bytes(),
        "exact export payload mismatch",
    )
}
fn exact_record(reader: &mut impl Read, record: &hermes_memory::MemoryRecord) -> Result<()> {
    exact_bytes(
        reader,
        &format!(
            "## {} · {}\n\n- id: {}\n- timestamp: {}\n\n### Content\n\n> {}\n\n",
            record.kind, record.id, record.id, record.timestamp, record.content
        ),
    )
}
pub fn verify_export(vault: &Path, source: &Path, manifest: &FullManifest) -> Result<Value> {
    let seeds = seeds(manifest)?;
    ensure(
        (16..=data::MAX_SEED_RECORDS).contains(&seeds),
        "full seed count bound",
    )?;
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    let mut root_entries = 0;
    for entry in fs::read_dir(vault)? {
        let entry = entry?;
        root_entries += 1;
        let allowed = (entry.file_name() == "Index.md" && entry.file_type()?.is_file())
            || (entry.file_name() == "Sessions" && entry.file_type()?.is_dir());
        ensure(root_entries <= 2 && allowed, "full root membership/type")?;
    }
    ensure(root_entries == 2, "missing full root entry")?;
    let snapshot = snapshot(source)?;
    let index = open_regular(&vault.join("Index.md"), 16384)?;
    ensure(index.metadata()?.len() <= 16384, "full index bound")?;
    let workspace_segment = full_segment(WORKSPACE);
    let mut index = BufReader::new(index);
    exact_bytes(&mut index, "# Hermes Memory Vault\n\n")?;
    for session in full_sessions() {
        exact_bytes(
            &mut index,
            &format!(
                "- [[Sessions/{workspace_segment}/{}]]\n",
                full_segment(&session)
            ),
        )?;
    }
    ensure(index.read(&mut [0; 1])? == 0, "extra full index data")?;
    let mut seen = [false; 18];
    let mut files = Vec::new();
    let mut workspaces = 0;
    for workspace in fs::read_dir(vault.join("Sessions"))? {
        workspaces += 1;
        let workspace = workspace?;
        ensure(
            workspaces == 1
                && workspace.file_type()?.is_dir()
                && workspace.file_name() == workspace_segment.as_str(),
            "full workspace count/type",
        )?;
        for entry in fs::read_dir(workspace.path())? {
            let entry = entry?;
            ensure(
                files.len() < 18
                    && entry.file_type()?.is_file()
                    && entry.metadata()?.len() <= 20 * 1024 * 1024,
                "full note count/type/size",
            )?;
            let mut reader = BufReader::new(
                open_regular(&entry.path(), 20 * 1024 * 1024)?.take(20 * 1024 * 1024 + 1),
            );
            exact_bytes(
                &mut reader,
                &format!("---\nworkspace: {WORKSPACE}\nsession_id: "),
            )?;
            let mut session = String::new();
            reader.by_ref().take(129).read_line(&mut session)?;
            ensure(
                session.len() <= 128 && session.ends_with('\n'),
                "full session bound",
            )?;
            let session = session.trim_end_matches('\n');
            let slot = if session == "benchmark-client" {
                16
            } else if session == "benchmark-snapshot" {
                17
            } else {
                let n: usize = session
                    .strip_prefix("benchmark-seed-")
                    .ok_or("unknown full session")?
                    .parse()?;
                ensure(
                    n < 16 && session == format!("benchmark-seed-{n:02}"),
                    "full session shape",
                )?;
                n
            };
            ensure(
                entry.file_name() == format!("{}.md", full_segment(session)).as_str(),
                "full note canonical path",
            )?;
            ensure(!seen[slot], "duplicate full session")?;
            seen[slot] = true;
            exact_bytes(
                &mut reader,
                &format!("generated_by: hermes-memory\n---\n\n# Session {session}\n\n"),
            )?;
            if slot < 16 {
                for n in (slot as u64..seeds).step_by(16) {
                    ensure(
                        std::time::Instant::now() < deadline,
                        "full verification deadline",
                    )?;
                    exact_record(&mut reader, &data::representative_record(n)?)?;
                }
            } else if slot == 16 {
                for addition in manifest
                    .expected_seed_and_addition_records()
                    .skip(seeds as usize)
                {
                    ensure(
                        Instant::now() < deadline,
                        "full export verification deadline",
                    )?;
                    exact_record(&mut reader, &addition?)?;
                }
            } else {
                exact_record(&mut reader, &snapshot)?;
            }
            ensure(
                reader.read(&mut [0; 1])? == 0,
                "extra full export record/data",
            )?;
            files.push(json!({"path":entry.path(),"bytes":entry.metadata()?.len(),"sha256":data::hash_file(&entry.path())?}));
        }
    }
    ensure(seen.iter().all(|v| *v), "missing full session")?;
    Ok(
        json!({"records":manifest.final_records(),"sessions":18,"files":files,"exact_payloads_verified":true,"snapshot_payload_verified":true,"index_sha256":data::hash_file(&vault.join("Index.md"))?}),
    )
}
