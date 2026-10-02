//! Synthetic legacy bootstrap fixture; no live database is copied.
use super::*;

pub(super) fn service_command(
    root: &Path,
    name: &str,
    server: &str,
    client: &str,
    pipe: &str,
) -> String {
    format!("\"{}\" service --root \"{}\" --temp-dir \"{}\" --bootstrap-config \"{}\" --pipe \"{}\" --server-sid {} --client-sid {} --workspace {} --service-name {}", root.join("bin/hermes-memory-broker.exe").display(), root.join("runtime-store").display(), root.join("runtime-temp").display(), root.join("migration").join("bootstrap.json").display(), pipe, server, client, WORKSPACE, name)
}

fn migration_snapshot() -> Value {
    json!({"session_id":"migration-snapshot","workspace":WORKSPACE,"items":[{"kind":"note","content":"migrationfruit snapshot 日本語","timestamp":1.0,"metadata":{"source":"synthetic-legacy","version":1}}]})
}

fn inventory(root: &Path) -> Result<Value> {
    use sha2::{Digest, Sha256};
    fn visit(
        root: &Path,
        path: &Path,
        out: &mut std::collections::BTreeMap<String, Value>,
    ) -> Result<()> {
        for entry in fs::read_dir(path)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            ensure(!metadata.file_type().is_symlink(), "source symlink")?;
            let key = path.strip_prefix(root)?.to_string_lossy().into_owned();
            if metadata.is_dir() {
                out.insert(key, json!({"directory":true}));
                visit(root, &path, out)?;
            } else {
                let bytes = fs::read(&path)?;
                out.insert(
                    key,
                    json!({"bytes":bytes.len(),"sha256":format!("{:x}", Sha256::digest(bytes))}),
                );
            }
        }
        Ok(())
    }
    let mut files = std::collections::BTreeMap::new();
    visit(root, root, &mut files)?;
    Ok(serde_json::to_value(files)?)
}

pub(super) fn build_fixture(source: &Path) -> Result<(Vec<u8>, Value)> {
    ensure(
        source.is_absolute() && source.is_dir() && fs::read_dir(source)?.next().is_none(),
        "source must be explicit existing empty fixture child",
    )?;
    let store = hermes_memory::MemoryStore::open(source)?;
    let record = json!({"id":"migration-ingest-one","session_id":"migration-session","workspace":WORKSPACE,"kind":"note","content":"migrationfruit legacy 日本語","timestamp":0.5,"metadata":{"source":"synthetic-legacy","nested":[1,true]}});
    ensure(
        store.ingest_many(&[serde_json::from_value(record)?])? == (1, 0),
        "legacy ingest counts",
    )?;
    let snapshot = migration_snapshot();
    ensure(
        store.ingest_snapshot(&serde_json::from_value(snapshot.clone())?)? == (1, 0),
        "legacy snapshot counts",
    )?;
    let expected = store.search(&hermes_memory::SearchRequest {
        query: "migrationfruit".into(),
        workspace: Some(WORKSPACE.into()),
        session_id: None,
        limit: 20,
        max_bytes: 65536,
    })?;
    drop(store);
    let before = inventory(source)?;
    let mut archive = Vec::new();
    let receipt = hermes_memory::logical_migration::export_from_staged_sqlite_copy(
        source.join("memory.db"),
        &mut archive,
    )?;
    let after = inventory(source)?;
    ensure(
        before == after,
        "staged exporter mutated source inventory/hash",
    )?;
    ensure(
        receipt.records == 2 && receipt.snapshot_states == 1 && receipt.snapshot_counters == 1,
        "migration counts differ",
    )?;
    let entries = std::str::from_utf8(&archive)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let states: Vec<_> = entries.iter().filter(|v| v["type"] == "state").collect();
    let counters: Vec<_> = entries.iter().filter(|v| v["type"] == "counter").collect();
    let proof = json!({"source":source,"source_schema":entries[0]["source_schema"],"before":before,"after":after,"receipt":receipt,"expected_records":expected,"snapshot":snapshot,"states":states,"counters":counters,"source_provenance":"synthetic legacy MemoryStore, closed before export; no live DB copy"});
    Ok((archive, proof))
}

pub(super) fn verify_persisted(db: &Connection, proof: &Value) -> Result<Value> {
    let receipts = db
        .prepare("SELECT receipt_json FROM broker_migrations ORDER BY singleton")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure(receipts.len() == 1, "migration receipt singleton differs")?;
    let receipt: Value = serde_json::from_str(&receipts[0])?;
    ensure(
        receipt == proof["receipt"],
        "persisted migration receipt differs",
    )?;
    let states = db.prepare("SELECT session_id,workspace,position,fingerprint,record_id FROM snapshot_state WHERE session_id='migration-snapshot' ORDER BY session_id,workspace,position")?.query_map([], |r| Ok(json!({"type":"state","session_id":r.get::<_,String>(0)?,"workspace":r.get::<_,String>(1)?,"position":r.get::<_,i64>(2)?,"fingerprint":r.get::<_,String>(3)?,"record_id":r.get::<_,String>(4)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
    let counters = db.prepare("SELECT session_id,workspace,fingerprint,next_occurrence FROM snapshot_counters WHERE session_id='migration-snapshot' ORDER BY session_id,workspace,fingerprint")?.query_map([], |r| Ok(json!({"type":"counter","session_id":r.get::<_,String>(0)?,"workspace":r.get::<_,String>(1)?,"fingerprint":r.get::<_,String>(2)?,"next_occurrence":r.get::<_,i64>(3)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
    ensure(
        json!(states) == proof["states"] && json!(counters) == proof["counters"],
        "migrated snapshot canonical state/counters differ",
    )?;
    Ok(json!({"receipt":receipt,"states":states,"counters":counters}))
}

pub(super) fn final_proof(root: &Path) -> Result<Value> {
    let proof = read_report(&root.join("migration"), "fixture.json", deadline())?;
    ensure(
        inventory(&root.join("migration/legacy-source"))? == proof["before"],
        "legacy source changed after SCM cycle",
    )?;
    let db = Connection::open_with_flags(
        root.join("runtime-store/memory.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    verify_persisted(&db, &proof)
}

pub(super) fn verify_client(
    proof: &Value,
    mut invoke: impl FnMut(&str, &str, &[&str], &[u8]) -> Result<Value>,
) -> Result<Value> {
    let search = invoke(
        "migration-search",
        "search",
        &[
            "--query",
            "migrationfruit",
            "--workspace",
            WORKSPACE,
            "--limit",
            "20",
            "--max-bytes",
            "65536",
        ],
        b"",
    )?;
    ensure(
        search["response"] == proof["expected_records"],
        "migrated full records differ",
    )?;
    let snapshot = invoke(
        "migration-snapshot",
        "snapshot",
        &[],
        &serde_json::to_vec(&proof["snapshot"])?,
    )?;
    ensure(
        snapshot["response"] == json!({"inserted":0,"duplicates":0}),
        "migrated snapshot state/counter replay differs",
    )?;
    let duplicate = invoke(
        "migration-duplicate",
        "ingest",
        &[],
        &serde_json::to_vec(&proof["expected_records"][0])?,
    )?;
    ensure(
        duplicate["response"] == json!({"inserted":0,"duplicates":1}),
        "migrated record duplicate differs",
    )?;
    Ok(json!({"search":search,"snapshot":snapshot,"duplicate":duplicate}))
}

fn directory_access(dir: &Path) -> Result<Vec<u32>> {
    let list = error_code(fs::read_dir(dir).map(drop));
    let path = dir.join("bootstrap-access-probe");
    let create = error_code(
        fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map(drop),
    );
    // Cleanup failure is not an access denial: preserve the actual create result.
    if create == 0 {
        fs::remove_file(&path)?;
    }
    Ok(vec![list, create])
}
fn exact_access(positive: &[u32], negative: &[u32]) -> bool {
    positive == [0, 0] && negative == [5, 5]
}

pub(super) fn client_acl(root: &Path) -> Result<Value> {
    let positive = directory_access(&root.join("scratch"))?;
    let negative = directory_access(&root.join("runtime-temp"))?;
    ensure(
        exact_access(&positive, &negative),
        "private TEMP positive/negative matrix incomplete",
    )?;
    let mut immutable = Vec::new();
    let scratch = root.join("scratch/bootstrap-file-control");
    fs::write(&scratch, b"positive")?;
    for name in ["bootstrap.json", "archive.jsonl"] {
        let path = root.join("migration").join(name);
        ensure(!fs::read(&path)?.is_empty(), "bootstrap read control empty")?;
        for access in [GENERIC_WRITE, WRITE_DAC] {
            use std::os::windows::fs::OpenOptionsExt;
            let attempt =
                |p: &Path| error_code(fs::OpenOptions::new().access_mode(access).open(p).map(drop));
            let allow = attempt(&scratch);
            let deny = attempt(&path);
            ensure(
                allow == 0 && deny == 5,
                "bootstrap source/config is writable or control failed",
            )?;
            immutable.push(json!({"file":name,"access":access,"positive":allow,"negative":deny}));
        }
    }
    fs::remove_file(scratch)?;
    ensure(
        immutable.len() == 4,
        "bootstrap immutable matrix incomplete",
    )?;
    Ok(
        json!({"temp_operations":["list","create_new"],"temp_positive":positive,"temp_negative":negative,"immutable":immutable,"positive_count":6,"deny_count":6,"qualification":"private TEMP admission/VFS selection at C startup, not actual spill"}),
    )
}

/// Only the elevated, admitted disposable SCM fixture calls provisioning.
pub(super) fn prepare(root: &Path, server: &str, client: &str) -> Result<Value> {
    use std::io::Write;
    let temp = root.join("runtime-temp");
    mkdir(&temp, &format!("(A;OICI;FA;;;{server})"))?;
    let temp_acl = audit_dir(&temp, &[server], &[], false)?;
    let migration = root.join("migration");
    let readers = format!("(A;OICI;FRFX;;;{server})(A;OICI;FRFX;;;{client})");
    mkdir(&migration, &readers)?;
    let source = migration.join("legacy-source");
    mkdir(&source, &readers)?;
    let (archive, mut proof) = build_fixture(&source)?;
    let archive_path = migration.join("archive.jsonl");
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&archive_path)?;
    file.write_all(&archive)?;
    file.sync_all()?;
    drop(file);
    let config = json!({"schema":1,"archive_path":archive_path,"logical_sha256":proof["receipt"]["logical_sha256"]});
    write_report(&migration, "bootstrap.json", &config)?;
    proof["config"] = config;
    proof["acl"] = json!({"migration":audit_dir(&migration, &[], &[server,client], false)?,"source":audit_dir(&source, &[], &[server,client], false)?,"temp":temp_acl});
    proof["temp_qualification"] = json!("C startup admits private TEMP and verifies actual store VFS selection before READY; NOT actual SQLite spill");
    proof["startup_negative"] = json!("NOT_TESTED: optional wrong-pin SCM cycle deliberately omitted; no transient PID assumptions added");
    write_report(&migration, "fixture.json", &proof)?;
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_temp_denials_require_two_matching_positive_controls() {
        let root = tempfile::tempdir().unwrap();
        let positive = directory_access(root.path()).unwrap();
        assert_eq!(positive, vec![0, 0]);
        assert!(exact_access(&positive, &[5, 5]));
        assert!(!exact_access(&positive, &[5]));
        assert!(!exact_access(&positive, &[5, 32]));
        assert!(!exact_access(&[0, 5], &[5, 5]));
    }
    #[test]
    fn migrated_cli_contract_requires_full_records_snapshot_replay_and_duplicate() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("legacy");
        fs::create_dir(&source).unwrap();
        let (archive, proof) = build_fixture(&source).unwrap();
        let store = hermes_memory::MemoryStore::open(root.path().join("destination")).unwrap();
        store
            .import_logical_archive_once(
                std::io::Cursor::new(&archive),
                proof["receipt"]["logical_sha256"].as_str().unwrap(),
            )
            .unwrap();
        let mut calls = Vec::new();
        let receipt = verify_client(&proof, |label, op, args, input| {
            calls.push(label.to_string());
            let response = match op {
                "search" => {
                    assert_eq!(args[0..2], ["--query", "migrationfruit"]);
                    serde_json::to_value(store.search(&hermes_memory::SearchRequest {
                        query: "migrationfruit".into(),
                        workspace: Some(WORKSPACE.into()),
                        session_id: None,
                        limit: 20,
                        max_bytes: 65536,
                    })?)?
                }
                "snapshot" => {
                    let (inserted, duplicates) =
                        store.ingest_snapshot(&serde_json::from_slice(input)?)?;
                    json!({"inserted":inserted,"duplicates":duplicates})
                }
                "ingest" => {
                    let record = serde_json::from_slice(input)?;
                    let (inserted, duplicates) = store.ingest_many(&[record])?;
                    json!({"inserted":inserted,"duplicates":duplicates})
                }
                _ => return Err("unexpected CLI operation".into()),
            };
            Ok(json!({"response":response}))
        })
        .unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            receipt["snapshot"]["response"],
            json!({"inserted":0,"duplicates":0})
        );
        assert!(verify_client(&proof, |_, _, _, _| Ok(json!({"response":[]}))).is_err());
    }
    #[test]
    fn scm_command_pins_private_temp_and_admin_bootstrap_under_same_fixture() {
        let root = Path::new("C:/owned-fixture");
        let command = service_command(root, "fixture", "S-1-5-80-1", "S-1-5-80-2", "pipe");
        assert!(command.contains("--temp-dir \"C:/owned-fixture\\runtime-temp\""));
        assert!(
            command.contains("--bootstrap-config \"C:/owned-fixture\\migration\\bootstrap.json\"")
        );
    }
    #[test]
    fn legacy_fixture_exports_without_source_mutation_and_preserves_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("legacy");
        fs::create_dir(&source).unwrap();
        let (archive, proof) = build_fixture(&source).unwrap();
        println!(
            "SYNTHETIC_FIXTURE {}",
            serde_json::to_string(&proof).unwrap()
        );
        assert_eq!(proof["receipt"]["records"], 2);
        assert_eq!(proof["receipt"]["snapshot_states"], 1);
        assert_eq!(proof["receipt"]["snapshot_counters"], 1);
        assert_eq!(proof["before"], proof["after"]);
        assert_eq!(proof["expected_records"].as_array().unwrap().len(), 2);
        let destination =
            hermes_memory::MemoryStore::open(root.path().join("destination")).unwrap();
        let digest = proof["receipt"]["logical_sha256"].as_str().unwrap();
        destination
            .import_logical_archive_once(std::io::Cursor::new(&archive), digest)
            .unwrap();
        let db = Connection::open(root.path().join("destination/memory.db")).unwrap();
        assert_eq!(
            verify_persisted(&db, &proof).unwrap()["receipt"],
            proof["receipt"]
        );
        db.execute(
            "UPDATE snapshot_counters SET next_occurrence = next_occurrence + 1",
            [],
        )
        .unwrap();
        assert!(verify_persisted(&db, &proof).is_err());
        db.execute(
            "UPDATE snapshot_counters SET next_occurrence = next_occurrence - 1",
            [],
        )
        .unwrap();
        drop(db);
        let request = serde_json::from_value(proof["snapshot"].clone()).unwrap();
        assert_eq!(destination.ingest_snapshot(&request).unwrap(), (0, 0));
        let record = serde_json::from_value(proof["expected_records"][0].clone()).unwrap();
        assert_eq!(destination.ingest_many(&[record]).unwrap(), (0, 1));
        destination
            .import_logical_archive_once(std::io::Cursor::new(&archive), digest)
            .unwrap();
    }
}
