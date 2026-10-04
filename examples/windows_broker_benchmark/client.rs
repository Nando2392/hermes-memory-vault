//! Runs only as the SCM-dispatched virtual-account B worker.
use crate::{
    contract::{self, ensure, Job},
    data::{self, Result, WORKSPACE},
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read},
    path::Path,
    time::Duration,
};
#[cfg(test)]
mod pilot_tests {
    use super::*;
    #[cfg(windows)]
    fn pilot_export_fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let store = hermes_memory::MemoryStore::open(&source).unwrap();
        store.ingest_snapshot(&data::snapshot()).unwrap();
        for n in 0..16 {
            store
                .ingest(&data::representative_record(n).unwrap())
                .unwrap();
        }
        store.ingest(&known_record()).unwrap();
        let vault = temp.path().join("vault");
        store.export_markdown(&vault, Some(WORKSPACE)).unwrap();
        verify_pilot_export(&vault, &source.join("events.jsonl"), 16).unwrap();
        (temp, source, vault)
    }

    #[cfg(windows)]
    #[test]
    fn pilot_index_rejects_missing_link() {
        let (_temp, source, vault) = pilot_export_fixture();
        let index = fs::read_to_string(vault.join("Index.md")).unwrap();
        let missing = index
            .lines()
            .take(19)
            .map(|line| format!("{line}\n"))
            .collect::<String>();
        fs::write(vault.join("Index.md"), missing).unwrap();
        assert!(verify_pilot_export(&vault, &source.join("events.jsonl"), 16).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn pilot_index_rejects_extra_link_and_garbage() {
        let (_temp, source, vault) = pilot_export_fixture();
        let index = fs::read_to_string(vault.join("Index.md")).unwrap();
        for extra in ["- [[Sessions/extra/unique]]\n", "garbage\n", "\n"] {
            fs::write(vault.join("Index.md"), format!("{index}{extra}")).unwrap();
            assert!(verify_pilot_export(&vault, &source.join("events.jsonl"), 16).is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn pilot_export_rejects_root_extra() {
        let (_temp, source, vault) = pilot_export_fixture();
        for directory in [false, true] {
            let extra = vault.join("extra");
            if directory {
                fs::create_dir(&extra).unwrap();
            } else {
                fs::write(&extra, "extra").unwrap();
            }
            assert!(verify_pilot_export(&vault, &source.join("events.jsonl"), 16).is_err());
            if directory {
                fs::remove_dir(&extra).unwrap();
            } else {
                fs::remove_file(&extra).unwrap();
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn pilot_export_rejects_noncanonical_paths() {
        let (_temp, source, vault) = pilot_export_fixture();
        let workspace = fs::read_dir(vault.join("Sessions"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let renamed = workspace.with_file_name("wrong-workspace");
        fs::rename(&workspace, &renamed).unwrap();
        assert!(verify_pilot_export(&vault, &source.join("events.jsonl"), 16).is_err());
        fs::rename(&renamed, &workspace).unwrap();
        let note = fs::read_dir(&workspace)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        fs::rename(&note, workspace.join("wrong-note.md")).unwrap();
        assert!(verify_pilot_export(&vault, &source.join("events.jsonl"), 16).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn pilot_final_jsonl_rejects_extra_unique_record() {
        let (temp, source, _vault) = pilot_export_fixture();
        let original = fs::read_to_string(source.join("events.jsonl")).unwrap();
        let extra = data::representative_record(16).unwrap();
        assert!(original
            .lines()
            .all(|line| serde_json::from_str::<Value>(line).unwrap()["id"] != extra.id));
        let final_path = temp.path().join("final.jsonl");
        fs::write(&final_path, &original).unwrap();
        verify_pilot_projection(&final_path, &source.join("events.jsonl"), 16).unwrap();
        fs::write(
            &final_path,
            format!("{original}{}\n", serde_json::to_string(&extra).unwrap()),
        )
        .unwrap();
        assert!(verify_pilot_projection(&final_path, &source.join("events.jsonl"), 16).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn pilot_final_jsonl_rejects_same_count_unique_replacement() {
        let (temp, source, _vault) = pilot_export_fixture();
        let original = fs::read_to_string(source.join("events.jsonl")).unwrap();
        let extra = data::representative_record(16).unwrap();
        let mut records: Vec<Value> = original
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(records.iter().all(|record| record["id"] != extra.id));
        records[1] = serde_json::to_value(extra).unwrap();
        let replacement = records
            .iter()
            .map(|record| format!("{record}\n"))
            .collect::<String>();
        assert_eq!(replacement.lines().count(), original.lines().count());
        let final_path = temp.path().join("final.jsonl");
        fs::write(&final_path, &original).unwrap();
        verify_pilot_projection(&final_path, &source.join("events.jsonl"), 16).unwrap();
        fs::write(&final_path, replacement).unwrap();
        assert!(verify_pilot_projection(&final_path, &source.join("events.jsonl"), 16).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn ordinary_legacy_export_retains_permissive_index_and_root() {
        let temp = tempfile::tempdir().unwrap();
        let store = hermes_memory::MemoryStore::open(&temp.path().join("source")).unwrap();
        store.ingest_snapshot(&data::snapshot()).unwrap();
        for n in 0..16 {
            store.ingest(&data::record(n)).unwrap();
        }
        store.ingest(&known_record()).unwrap();
        let vault = temp.path().join("vault");
        store.export_markdown(&vault, Some(WORKSPACE)).unwrap();
        fs::write(
            vault.join("Index.md"),
            "# Hermes Memory Vault\nlegacy index\n",
        )
        .unwrap();
        fs::write(vault.join("legacy-extra"), "legacy").unwrap();
        assert_eq!(verify_export(&vault, 16).unwrap()["records"], 18);
    }

    #[cfg(windows)]
    #[test]
    fn pilot_final_jsonl_checks_metadata_missing_duplicate_and_payload() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let store = hermes_memory::MemoryStore::open(&source).unwrap();
        store.ingest_snapshot(&data::snapshot()).unwrap();
        for n in 0..16 {
            store
                .ingest(&data::representative_record(n).unwrap())
                .unwrap();
        }
        store.ingest(&known_record()).unwrap();
        drop(store);
        let original = fs::read(source.join("events.jsonl")).unwrap();
        let final_path = temp.path().join("final.jsonl");
        fs::write(&final_path, &original).unwrap();
        verify_pilot_projection(&final_path, &source.join("events.jsonl"), 16).unwrap();
        let text = String::from_utf8(original).unwrap();
        let mut records: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        records[1]["metadata"] = json!({"tampered":true});
        let altered = records.iter().map(|v| format!("{v}\n")).collect::<String>();
        let missing = text
            .lines()
            .skip(1)
            .map(|l| format!("{l}\n"))
            .collect::<String>();
        for bad in [
            altered,
            missing,
            format!("{text}{text}"),
            text.replace("ordinary", "tampered"),
        ] {
            fs::write(&final_path, bad).unwrap();
            assert!(
                verify_pilot_projection(&final_path, &source.join("events.jsonl"), 16).is_err()
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn representative_six_mib_ordinary_roundtrip_not_scm_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let generation = data::generate_with_spec(
            &dir.path().join("staged"),
            &data::FixtureSpec::representative_6_mib(),
        )
        .unwrap();
        let source = dir.path().join("staged/source");
        let imported = dir.path().join("imported");
        let store = hermes_memory::MemoryStore::open(&imported).unwrap();
        let receipt = store
            .import_logical_archive_once(
                BufReader::new(File::open(dir.path().join("staged/archive.jsonl")).unwrap()),
                generation["logical_sha256"].as_str().unwrap(),
            )
            .unwrap();
        assert_eq!(receipt.records, generation["records"].as_u64().unwrap());
        assert!(fs::metadata(imported.join("events.jsonl")).unwrap().len() >= 6 * 1024 * 1024);
        assert_eq!(store.ingest_many(&[known_record()]).unwrap(), (1, 0));
        assert_eq!(store.ingest_many(&[known_record()]).unwrap(), (0, 1));
        assert_eq!(store.ingest_snapshot(&data::snapshot()).unwrap(), (0, 0));
        store.prepare_export_index().unwrap();
        let vault = dir.path().join("vault");
        let sessions = hermes_memory::client_export::render_markdown(&vault, WORKSPACE, |r| {
            store
                .export_page(r, "pilot-test")
                .map_err(|e| hermes_memory::MemoryError::Io(std::io::Error::other(e.to_string())))
        })
        .unwrap();
        assert_eq!(sessions, 18);
        let export = verify_pilot_export(
            &vault,
            &source.join("events.jsonl"),
            generation["seed_records"].as_u64().unwrap(),
        )
        .unwrap();
        assert_eq!(export["records"], receipt.records + 1);
        drop(store);
        verify_pilot_projection(
            &imported.join("events.jsonl"),
            &source.join("events.jsonl"),
            generation["seed_records"].as_u64().unwrap(),
        )
        .unwrap();
        let stopped = crate::fixtures::verify_stopped_import_with_expected(
            &imported.join("memory.db"),
            &generation,
            1,
        )
        .unwrap();
        assert_eq!(
            stopped["persisted_startup_receipt"]["logical_sha256"],
            generation["logical_sha256"]
        );
        assert_eq!(
            data::inventory(&source).unwrap(),
            generation["source_before"]
        );
    }

    #[cfg(windows)]
    #[test]
    fn pilot_verifier_exact_payload_missing_duplicate_and_extra() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let store = hermes_memory::MemoryStore::open(&source).unwrap();
        store.ingest_snapshot(&data::snapshot()).unwrap();
        for n in 0..16 {
            store
                .ingest(&data::representative_record(n).unwrap())
                .unwrap();
        }
        store.ingest(&known_record()).unwrap();
        let vault = temp.path().join("vault");
        store.export_markdown(&vault, Some(WORKSPACE)).unwrap();
        assert_eq!(
            verify_pilot_export(&vault, &source.join("events.jsonl"), 16).unwrap()["records"],
            18
        );
        let notes: Vec<_> = fs::read_dir(vault.join("Sessions"))
            .unwrap()
            .flat_map(|w| fs::read_dir(w.unwrap().path()).unwrap())
            .map(|n| n.unwrap().path())
            .collect();
        let note = notes
            .iter()
            .find(|p| {
                fs::read_to_string(p)
                    .unwrap()
                    .contains("session_id: benchmark-seed-00\n")
            })
            .unwrap();
        let original = fs::read_to_string(note).unwrap();
        for bad in [
            original.replace("ordinary", "tampered"),
            original.split("## user").next().unwrap().to_owned(),
            format!("{original}{original}"),
        ] {
            fs::write(note, bad).unwrap();
            assert!(verify_pilot_export(&vault, &source.join("events.jsonl"), 16).is_err());
        }
        fs::write(note, original).unwrap();
        fs::copy(note, note.with_extension("extra.md")).unwrap();
        assert!(verify_pilot_export(&vault, &source.join("events.jsonl"), 16).is_err());
    }
}
// Exact fixture-v2 oracle: one bounded record/block at a time, no corpus strings
// or set of IDs. Seed sessions have a deterministic ascending index sequence.
fn pilot_snapshot(source: &Path) -> Result<hermes_memory::MemoryRecord> {
    let mut line = String::new();
    BufReader::new(File::open(source)?)
        .take(4097)
        .read_line(&mut line)?;
    ensure(
        line.len() <= 4096 && line.ends_with('\n'),
        "snapshot line bound",
    )?;
    let record: hermes_memory::MemoryRecord = serde_json::from_str(&line)?;
    let request = data::snapshot();
    let item = &request.items[0];
    ensure(
        record.session_id == request.session_id
            && record.workspace == request.workspace
            && record.kind == item.kind
            && record.content == item.content
            && record.timestamp == item.timestamp
            && record.metadata == item.metadata,
        "source snapshot payload mismatch",
    )?;
    Ok(record)
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
/// Final stopped projection oracle includes metadata, which Markdown omits.
/// Canonical timestamp order lets us compare one record at a time without an ID set.
pub fn verify_pilot_projection(path: &Path, source: &Path, seeds: u64) -> Result<Value> {
    verify_representative_projection(path, source, seeds, &[known_record()])
}
#[allow(dead_code)] // Internal sandbox only; no native/workflow admission.
pub fn verify_two_warmup_projection(path: &Path, source: &Path, seeds: u64) -> Result<Value> {
    verify_representative_projection(
        path,
        source,
        seeds,
        &[
            data::TwoWarmupManifest.record(0)?,
            data::TwoWarmupManifest.record(1)?,
        ],
    )
}
fn verify_representative_projection(
    path: &Path,
    source: &Path,
    seeds: u64,
    additions: &[hermes_memory::MemoryRecord],
) -> Result<Value> {
    ensure(
        (16..=data::MAX_SEED_RECORDS).contains(&seeds),
        "pilot seed count bound",
    )?;
    let file = File::open(path)?;
    let bytes = file.metadata()?.len();
    ensure(
        file.metadata()?.is_file() && bytes <= 8 * 1024 * 1024,
        "6 MiB pilot final projection bound",
    )?;
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    let mut reader = BufReader::new(file);
    let mut record = |r: &hermes_memory::MemoryRecord| -> Result<()> {
        ensure(
            std::time::Instant::now() < deadline,
            "pilot final verification deadline",
        )?;
        let mut expected = serde_json::to_string(r)?;
        expected.push('\n');
        exact_bytes(&mut reader, &expected)
    };
    record(&pilot_snapshot(source)?)?;
    for n in 0..seeds {
        record(&data::representative_record(n)?)?;
    }
    for addition in additions {
        record(addition)?;
    }
    ensure(
        reader.read(&mut [0; 1])? == 0,
        "extra final projection record",
    )?;
    Ok(
        json!({"records":seeds+1+additions.len() as u64,"bytes":bytes,"exact_records_including_metadata_verified":true,"verification":"post-stop, sequential streaming, outside measurement"}),
    )
}
// Fixture identifiers are already safe ASCII; match the renderer's SHA-256
// suffix without accepting arbitrary note paths supplied by the artifact.
fn pilot_segment(identifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(identifier.as_bytes());
    let suffix = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{identifier}-{suffix}")
}
fn pilot_sessions() -> Vec<String> {
    let mut sessions = vec!["benchmark-client".to_owned()];
    sessions.extend((0..16).map(|n| format!("benchmark-seed-{n:02}")));
    sessions.push("benchmark-snapshot".to_owned());
    sessions
}
pub fn verify_pilot_export(vault: &Path, source: &Path, seeds: u64) -> Result<Value> {
    verify_representative_export(vault, source, seeds, &[known_record()])
}
#[allow(dead_code)] // Internal sandbox only; no native/workflow admission.
pub fn verify_two_warmup_export(vault: &Path, source: &Path, seeds: u64) -> Result<Value> {
    verify_representative_export(
        vault,
        source,
        seeds,
        &[
            data::TwoWarmupManifest.record(0)?,
            data::TwoWarmupManifest.record(1)?,
        ],
    )
}
fn verify_representative_export(
    vault: &Path,
    source: &Path,
    seeds: u64,
    additions: &[hermes_memory::MemoryRecord],
) -> Result<Value> {
    ensure(
        (16..=data::MAX_SEED_RECORDS).contains(&seeds),
        "pilot seed count bound",
    )?;
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    let mut root_entries = 0;
    for entry in fs::read_dir(vault)? {
        let entry = entry?;
        root_entries += 1;
        let allowed = (entry.file_name() == "Index.md" && entry.file_type()?.is_file())
            || (entry.file_name() == "Sessions" && entry.file_type()?.is_dir());
        ensure(root_entries <= 2 && allowed, "pilot root membership/type")?;
    }
    ensure(root_entries == 2, "missing pilot root entry")?;
    let snapshot = pilot_snapshot(source)?;
    let index = File::open(vault.join("Index.md"))?;
    ensure(index.metadata()?.len() <= 16384, "pilot index bound")?;
    let workspace_segment = pilot_segment(WORKSPACE);
    let mut index = BufReader::new(index);
    exact_bytes(&mut index, "# Hermes Memory Vault\n\n")?;
    for session in pilot_sessions() {
        exact_bytes(
            &mut index,
            &format!(
                "- [[Sessions/{workspace_segment}/{}]]\n",
                pilot_segment(&session)
            ),
        )?;
    }
    ensure(index.read(&mut [0; 1])? == 0, "extra pilot index data")?;
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
            "pilot workspace count/type",
        )?;
        for entry in fs::read_dir(workspace.path())? {
            let entry = entry?;
            ensure(
                files.len() < 18
                    && entry.file_type()?.is_file()
                    && entry.metadata()?.len() <= 128 * 1024 * 1024,
                "pilot note count/type/size",
            )?;
            let mut reader = BufReader::new(File::open(entry.path())?);
            exact_bytes(
                &mut reader,
                &format!("---\nworkspace: {WORKSPACE}\nsession_id: "),
            )?;
            let mut session = String::new();
            reader.by_ref().take(129).read_line(&mut session)?;
            ensure(
                session.len() <= 128 && session.ends_with('\n'),
                "pilot session bound",
            )?;
            let session = session.trim_end_matches('\n');
            let slot = if session == "benchmark-client" {
                16
            } else if session == "benchmark-snapshot" {
                17
            } else {
                let n: usize = session
                    .strip_prefix("benchmark-seed-")
                    .ok_or("unknown pilot session")?
                    .parse()?;
                ensure(
                    n < 16 && session == format!("benchmark-seed-{n:02}"),
                    "pilot session shape",
                )?;
                n
            };
            ensure(
                entry.file_name() == format!("{}.md", pilot_segment(session)).as_str(),
                "pilot note canonical path",
            )?;
            ensure(!seen[slot], "duplicate pilot session")?;
            seen[slot] = true;
            exact_bytes(
                &mut reader,
                &format!("generated_by: hermes-memory\n---\n\n# Session {session}\n\n"),
            )?;
            if slot < 16 {
                for n in (slot as u64..seeds).step_by(16) {
                    ensure(
                        std::time::Instant::now() < deadline,
                        "pilot verification deadline",
                    )?;
                    exact_record(&mut reader, &data::representative_record(n)?)?;
                }
            } else if slot == 16 {
                for addition in additions {
                    exact_record(&mut reader, addition)?;
                }
            } else {
                exact_record(&mut reader, &snapshot)?;
            }
            ensure(
                reader.read(&mut [0; 1])? == 0,
                "extra pilot export record/data",
            )?;
            files.push(json!({"path":entry.path(),"bytes":entry.metadata()?.len(),"sha256":data::hash_file(&entry.path())?}));
        }
    }
    ensure(seen.iter().all(|v| *v), "missing pilot session")?;
    Ok(
        json!({"records":seeds+1+additions.len() as u64,"sessions":18,"files":files,"exact_payloads_verified":true,"snapshot_payload_verified":true,"index_sha256":data::hash_file(&vault.join("Index.md"))?}),
    )
}
/// Internal ordinary-file seam: no native lifecycle or CLI admission is implied.
#[allow(dead_code)] // Awaiting separately reviewed native case integration.
pub fn execute_two_warmup_sandbox(
    root: &Path,
    epoch: &str,
    deadline: std::time::Instant,
    cancelled: fn() -> bool,
    mut insert: impl FnMut(u32, u64, &[u8]) -> Result<(u64, u64)>,
) -> Result<()> {
    use contract::PilotPhase;
    let manifest = data::TwoWarmupManifest;
    let mut barrier = contract::OperationBarrier::new(root, epoch, 2)?;
    for id in 0..data::TwoWarmupManifest::OPERATIONS {
        let payload = manifest.payload(id)?;
        let cli_epoch = manifest.cli_epoch(id)?;
        barrier.publish(id, PilotPhase::Ready)?;
        barrier.wait(
            id,
            PilotPhase::Release,
            deadline.min(std::time::Instant::now() + Duration::from_secs(60)),
            cancelled,
        )?;
        ensure(
            !cancelled() && std::time::Instant::now() < deadline,
            "warmup cancelled/expired before mutation",
        )?;
        // Unknown commit errors propagate without retry, Done, or a next operation.
        let (inserted, duplicates) = insert(id, cli_epoch, &payload)?;
        let receipt = contract::WarmupReceipt {
            schema: 3,
            operation_id: id,
            cli_epoch,
            payload,
            inserted,
            duplicates,
        };
        receipt.validate(id)?;
        let value = serde_json::to_value(receipt)?;
        ensure(
            serde_json::to_vec_pretty(&value)?.len() < 65536,
            "warmup receipt bound",
        )?;
        contract::json_new(
            &root.join(format!("scratch/workload-op-{id}-receipt.json")),
            &value,
        )?;
        barrier.publish(id, PilotPhase::Done)?;
        // No search/export/scan or second mutation while awaiting ACK.
        barrier.wait(
            id,
            PilotPhase::Acknowledged,
            deadline.min(std::time::Instant::now() + Duration::from_secs(60)),
            cancelled,
        )?;
    }
    Ok(())
}
#[cfg(all(test, windows))]
mod two_warmup_tests {
    use super::*;
    #[test]
    fn two_real_inserts_require_exact_final_payload_oracles() {
        exact_roundtrip(32768, true);
    }
    #[test]
    fn representative_six_mib_two_warmup_sandbox_not_native_lifecycle() {
        exact_roundtrip(6 * 1024 * 1024, false);
    }
    fn exact_roundtrip(target: u64, mutations: bool) {
        let temp = tempfile::tempdir().unwrap();
        let staged = temp.path().join("staged");
        let generation = data::generate_with_spec(
            &staged,
            &data::FixtureSpec {
                shape: data::FixtureShape::RepresentativeV2,
                target_jsonl_bytes: target,
            },
        )
        .unwrap();
        let imported = temp.path().join("imported");
        let store = hermes_memory::MemoryStore::open(&imported).unwrap();
        store
            .import_logical_archive_once(
                BufReader::new(File::open(staged.join("archive.jsonl")).unwrap()),
                generation["logical_sha256"].as_str().unwrap(),
            )
            .unwrap();
        std::fs::create_dir(temp.path().join("scratch")).unwrap();
        std::fs::create_dir(temp.path().join("controller")).unwrap();
        drop(store);
        std::thread::scope(|scope| {
            let root = temp.path();
            let imported = &imported;
            let child = scope.spawn(move || {
                let store = hermes_memory::MemoryStore::open(imported).unwrap();
                execute_two_warmup_sandbox(
                    root,
                    "exact-fixture",
                    std::time::Instant::now() + Duration::from_secs(10),
                    contract::never_cancel,
                    |_, _, payload| {
                        let records: Vec<hermes_memory::MemoryRecord> =
                            serde_json::from_slice(payload)?;
                        let (a, b) = store.ingest_many(&records)?;
                        Ok((a as u64, b as u64))
                    },
                )
                .map_err(|e| e.to_string())
            });
            crate::controller::two_warmup_sandbox_intervals(
                root,
                "exact-fixture",
                &imported.join("events.jsonl"),
                std::time::Instant::now() + Duration::from_secs(10),
                contract::never_cancel,
                |_, _| Ok(Value::Null),
            )
            .unwrap();
            child.join().unwrap().unwrap();
        });
        let store = hermes_memory::MemoryStore::open(&imported).unwrap();
        store.prepare_export_index().unwrap();
        let vault = temp.path().join("vault");
        hermes_memory::client_export::render_markdown(&vault, WORKSPACE, |r| {
            store
                .export_page(r, "two-warmup-test")
                .map_err(|e| hermes_memory::MemoryError::Io(std::io::Error::other(e.to_string())))
        })
        .unwrap();
        drop(store);
        let seeds = generation["seed_records"].as_u64().unwrap();
        verify_two_warmup_projection(
            &imported.join("events.jsonl"),
            &staged.join("source/events.jsonl"),
            seeds,
        )
        .unwrap();
        verify_two_warmup_export(&vault, &staged.join("source/events.jsonl"), seeds).unwrap();
        let sqlite =
            crate::fixtures::verify_stopped_two_warmup(&imported.join("memory.db"), &generation)
                .unwrap();
        assert_eq!(sqlite["final_read_only_export"]["records"], seeds + 3);
        assert_eq!(
            data::inventory(&staged.join("source")).unwrap(),
            generation["source_before"]
        );
        println!("two-warmup ordinary oracle: target={target} seeds={seeds} final={} native_handle_verified=false", seeds + 3);
        if !mutations {
            return;
        }
        let projection = imported.join("events.jsonl");
        let original = fs::read_to_string(&projection).unwrap(); // Tiny mutation fixture only.
        let source = staged.join("source/events.jsonl");
        let lines: Vec<_> = original.lines().collect();
        for mutation in 0..6 {
            let mut changed = lines.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
            let last = changed.len() - 1;
            match mutation {
                0..=2 => {
                    let mut record: hermes_memory::MemoryRecord =
                        serde_json::from_str(&changed[last]).unwrap();
                    match mutation {
                        0 => record.content.push('x'),
                        1 => record.metadata = json!({"tampered":true}),
                        _ => record.id.push('x'),
                    }
                    changed[last] = serde_json::to_string(&record).unwrap();
                }
                3 => {
                    changed.pop();
                }
                4 => {
                    changed.push(changed[last].clone());
                }
                _ => {
                    changed[last] = changed[last - 1].clone();
                }
            }
            fs::write(&projection, format!("{}\n", changed.join("\n"))).unwrap();
            assert!(
                verify_two_warmup_projection(&projection, &source, seeds).is_err(),
                "mutation {mutation}"
            );
        }
        fs::write(&projection, original).unwrap();
        let index = vault.join("Index.md");
        let original_index = fs::read(&index).unwrap();
        fs::write(&index, b"# Hermes Memory Vault\n\n").unwrap();
        assert!(verify_two_warmup_export(&vault, &source, seeds).is_err());
        fs::write(&index, original_index).unwrap();
        let note = vault
            .join("Sessions")
            .join(pilot_segment(WORKSPACE))
            .join(format!("{}.md", pilot_segment("benchmark-client")));
        let original_note = fs::read_to_string(&note).unwrap();
        fs::write(
            &note,
            original_note.replace("deterministic warmup 000001", "deterministic warmup 999999"),
        )
        .unwrap();
        assert!(verify_two_warmup_export(&vault, &source, seeds).is_err());
        fs::write(&note, original_note).unwrap();
        let connection = rusqlite::Connection::open(imported.join("memory.db")).unwrap();
        connection
            .execute(
                "UPDATE records SET content=?1 WHERE id=?2",
                rusqlite::params!["tampered", data::TwoWarmupManifest.record(1).unwrap().id],
            )
            .unwrap();
        drop(connection);
        assert!(crate::fixtures::verify_stopped_two_warmup(
            &imported.join("memory.db"),
            &generation
        )
        .is_err());
        assert!(verify_two_warmup_projection(&projection, &source, seeds).is_ok());
    }
}
fn snapshot_bytes() -> Result<Vec<u8>> {
    let s = data::snapshot();
    let items: Vec<_> = s.items.iter().map(|i| json!({"kind":i.kind,"content":i.content,"timestamp":i.timestamp,"metadata":i.metadata})).collect();
    Ok(serde_json::to_vec(
        &json!({"session_id":s.session_id,"workspace":s.workspace,"items":items}),
    )?)
}
pub fn known_record() -> hermes_memory::MemoryRecord {
    let mut r = data::record(9_000_000);
    r.session_id = "benchmark-client".into();
    r.content = "hmvsmallcanary actual broker client durable record".into();
    r
}
/// Enumerate only the fresh export tree; verify actual Markdown IDs and payloads.
pub fn verify_export(vault: &Path, seeds: u64) -> Result<Value> {
    ensure(seeds <= 100_000, "small export count bound")?;
    let index = fs::read_to_string(vault.join("Index.md"))?;
    ensure(
        index.starts_with("# Hermes Memory Vault\n"),
        "missing export index",
    )?;
    let mut ids = BTreeSet::new();
    let mut known = false;
    let mut snapshot = false;
    let mut files = Vec::new();
    for workspace in fs::read_dir(vault.join("Sessions"))? {
        let workspace = workspace?;
        ensure(
            workspace.file_type()?.is_dir(),
            "export workspace must be directory",
        )?;
        for entry in fs::read_dir(workspace.path())? {
            let entry = entry?;
            ensure(entry.file_type()?.is_file(), "export note must be regular")?;
            for line in BufReader::new(File::open(entry.path())?).lines() {
                let line = line?;
                if let Some(id) = line.strip_prefix("- id: ") {
                    ensure(ids.insert(id.to_owned()), "duplicate Markdown record")?;
                }
                known |= line == format!("> {}", known_record().content);
                snapshot |= line == "> snapshot benchmark reference";
            }
            files.push(json!({"path":entry.path(),"bytes":entry.metadata()?.len(),"sha256":data::hash_file(&entry.path())?}));
        }
    }
    for n in 0..seeds {
        ensure(ids.contains(&data::record(n).id), "seed absent from export")?;
    }
    ensure(
        ids.contains(&known_record().id) && known && snapshot,
        "export missing exact known/snapshot payload",
    )?;
    ensure(
        ids.len() as u64 == seeds + 2 && files.len() == 3,
        "export record/session count mismatch",
    )?;
    Ok(
        json!({"records":ids.len(),"sessions":files.len(),"files":files,"index_sha256":data::hash_file(&vault.join("Index.md"))?,"known_payload_verified":known,"snapshot_payload_verified":snapshot}),
    )
}
#[cfg(all(windows, feature = "experimental-broker"))]
pub fn worker(root: &Path) -> Result<()> {
    let scratch = root.join("scratch");
    let mut report = json!({"schema":1,"pass":false,"commands":[]});
    let result = execute(root, &mut report);
    if let Err(ref e) = result {
        report["error"] = json!(e.to_string());
    }
    report["pass"] = json!(result.is_ok());
    // Completion marker is separate: controller never consumes partially written JSON.
    contract::json_new(&scratch.join("client-result.json"), &report)?;
    contract::json_new(&scratch.join("client-done.json"), &json!({"complete":true}))?;
    result
}
#[cfg(all(windows, feature = "experimental-broker"))]
fn execute(root: &Path, report: &mut Value) -> Result<()> {
    let reader =
        hermes_memory::windows_enrollment::open_admin_owned_file(&root.join("job.json"), 65536)?;
    let job: Job = serde_json::from_reader(reader)?;
    if let Some(pilot) = &job.pilot {
        pilot.validate()?;
    }
    let two_warmup = if root.join("two-warmup-job.json").try_exists()? {
        let reader = hermes_memory::windows_enrollment::open_admin_owned_file(
            &root.join("two-warmup-job.json"),
            65536,
        )?;
        let mode: crate::two_warmup::TwoWarmupJob = serde_json::from_reader(reader)?;
        mode.validate()?;
        ensure(job.pilot.is_none(), "pilot/two-warmup mode conflict")?;
        Some(mode)
    } else {
        None
    };
    let insert_record = if two_warmup.is_some() {
        data::TwoWarmupManifest.record(0)?
    } else {
        known_record()
    };
    ensure(
        job.case.install_root == root.join("install-small")
            && job.case.legacy_root == root.join("small/source"),
        "job outside fixture",
    )?;
    ensure(
        job.client == job.case.install_root.join("bin/hermes-memory-client.exe"),
        "client outside installed pinned payload",
    )?;
    ensure(
        data::hash_file(&job.client)? == job.case.client_sha256,
        "client executable pin changed",
    )?;
    let enrollment = hermes_memory::windows_enrollment::load_from_enrollment(
        &job.enrollment,
        &job.case.legacy_root,
    )?;
    ensure(
        enrollment.client_sid == job.case.client_sid,
        "B TokenUser/enrollment SID mismatch",
    )?;
    report["enrollment"] = json!({"client_sid":enrollment.client_sid,"server_sid":enrollment.server_sid,"pipe":enrollment.pipe,"scope_mode":enrollment.scope_mode,"legacy_root_key":enrollment.legacy_root_key});
    // Query-only write-access request: do not actually write even if policy fails.
    let denied = OpenOptions::new()
        .write(true)
        .open(job.case.legacy_root.join("memory.db"));
    ensure(
        denied
            .as_ref()
            .err()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied),
        "B unexpectedly has local SQLite write access",
    )?;
    report["local_sqlite_write_denied"] = json!(true);
    let before = data::inventory(&job.case.legacy_root)?;
    let scratch = root.join("scratch");
    let enroll = contract::text(&job.enrollment)?;
    let call = |label: &str,
                operation: &str,
                extra: &[&str],
                input: Vec<u8>,
                report: &mut Value|
     -> Result<Value> {
        ensure(!crate::scm::stop_requested(), "B stop requested")?;
        let mut args = job.case.client_args(operation, &enroll)?;
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        let observation = contract::command(
            &job.client,
            &args,
            &input,
            &scratch,
            label,
            Duration::from_secs(45),
            crate::scm::stop_requested,
        )?;
        report["commands"]
            .as_array_mut()
            .ok_or("commands array")?
            .push(observation.clone());
        Ok(observation)
    };
    let ping = call(
        "scoped-search",
        "search",
        &["--query", "ordinary", "--workspace", WORKSPACE],
        vec![],
        report,
    )?;
    let hits = contract::output(&ping)?;
    ensure(
        hits.as_array().is_some_and(|hits| {
            !hits.is_empty() && hits.iter().all(|h| h["workspace"] == WORKSPACE)
        }),
        "scoped search failed",
    )?;
    let mut barrier = job
        .pilot
        .as_ref()
        .map(|pilot| contract::PilotBarrier::new(root, &pilot.epoch))
        .transpose()?;
    let ingest = if let Some(mode) = &two_warmup {
        let args = job.case.client_args("ingest", &enroll)?;
        let mut last = Value::Null;
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        report["schema"] = json!(4);
        report["case"] = json!("representative-6MiB-two-warmup");
        execute_two_warmup_sandbox(
            root,
            &mode.epoch,
            deadline,
            crate::scm::stop_requested,
            |id, _, payload| {
                let label = format!("warmup-op-{id}");
                let receipt = crate::two_warmup::measured_insert(
                    &contract::CommandRequest {
                        exe: &job.client,
                        args: &args,
                        input: payload,
                        directory: &scratch,
                        label: &label,
                        timeout: deadline
                            .saturating_duration_since(std::time::Instant::now())
                            .min(Duration::from_secs(45)),
                        cancelled: crate::scm::stop_requested,
                    },
                    &mode.epoch,
                    id,
                )?;
                let value = serde_json::to_value(&receipt)?;
                ensure(
                    serde_json::to_vec_pretty(&value)?.len() < 65536,
                    "native receipt bound",
                )?;
                contract::json_new(&scratch.join(format!("warmup-op-{id}-native.json")), &value)?;
                report["commands"]
                    .as_array_mut()
                    .ok_or("commands array")?
                    .push(receipt.command.clone());
                last = receipt.command;
                Ok((receipt.warmup.inserted, receipt.warmup.duplicates))
            },
        )?;
        report["two_warmup"] = json!({"schema":4,"case_epoch":mode.epoch,"expected_additions":2,"sampling_complete":false,"full_workload_complete":false,"performance_policy_status":"unapproved"});
        last
    } else if let Some(barrier) = &mut barrier {
        use contract::PilotPhase;
        // No source scans, export or subsequent broker command until C end sample.
        barrier.publish(PilotPhase::Ready)?;
        barrier.wait(
            PilotPhase::Release,
            Duration::from_secs(60),
            crate::scm::stop_requested,
        )?;
        let args = job.case.client_args("ingest", &enroll)?;
        let input = serde_json::to_vec(&insert_record)?;
        let observation = contract::command_measured(
            &contract::CommandRequest {
                exe: &job.client,
                args: &args,
                input: &input,
                directory: &scratch,
                label: "pilot-insert",
                timeout: Duration::from_secs(45),
                cancelled: crate::scm::stop_requested,
            },
            &crate::measure::SamplePolicy::cli(3, 0),
        )?;
        report["commands"]
            .as_array_mut()
            .ok_or("commands array")?
            .push(observation.clone());
        observation
    } else {
        call(
            "ingest",
            "ingest",
            &[],
            serde_json::to_vec(&insert_record)?,
            report,
        )?
    };
    ensure(
        contract::output(&ingest)? == json!({"inserted":1,"duplicates":0}),
        "known ingest acknowledgement",
    )?;
    if let Some(barrier) = &mut barrier {
        barrier.publish(contract::PilotPhase::Done)?;
        barrier.wait(
            contract::PilotPhase::Acknowledged,
            Duration::from_secs(60),
            crate::scm::stop_requested,
        )?;
        report["pilot"] = json!({"schema":1,"operation_id":0,"stage":"pilot-first-warmup-only","expected_additions":1,"sampling_complete":false,"performance_policy_status":"unapproved","measurement":ingest["measurement"]});
    }
    let duplicate = call(
        "duplicate",
        "ingest",
        &[],
        serde_json::to_vec(&insert_record)?,
        report,
    )?;
    ensure(
        contract::output(&duplicate)? == json!({"inserted":0,"duplicates":1}),
        "duplicate retransmission acknowledgement",
    )?;
    let snapshot = call(
        "unchanged-snapshot",
        "snapshot",
        &[],
        snapshot_bytes()?,
        report,
    )?;
    ensure(
        contract::output(&snapshot)? == json!({"inserted":0,"duplicates":0}),
        "imported unchanged snapshot replay",
    )?;
    let found = call(
        "known-search",
        "search",
        &[
            "--query",
            if two_warmup.is_some() {
                "deterministic warmup 000000"
            } else {
                "hmvsmallcanary"
            },
            "--workspace",
            WORKSPACE,
        ],
        vec![],
        report,
    )?;
    let found = contract::output(&found)?;
    let expected_record = serde_json::to_value(&insert_record)?;
    ensure(
        found
            .as_array()
            .is_some_and(|hits| hits.len() == 1 && hits[0] == expected_record),
        "known search exact record mismatch",
    )?;
    let wrong = call(
        "wrong-workspace",
        "search",
        &["--query", "ordinary", "--workspace", "not-authorized"],
        vec![],
        report,
    )?;
    denial(&wrong)?;
    // Correct protected enrollment, wrong lexical root: must fail before fallback.
    let mut wrong_case = job.case.clone();
    wrong_case.legacy_root = root.join("absent-wrong-root");
    let mut args = wrong_case.client_args("search", &enroll)?;
    args.extend([
        "--query".into(),
        "ordinary".into(),
        "--workspace".into(),
        WORKSPACE.into(),
    ]);
    let wrong = contract::command(
        &job.client,
        &args,
        b"",
        &scratch,
        "wrong-root",
        Duration::from_secs(15),
        crate::scm::stop_requested,
    )?;
    report["commands"]
        .as_array_mut()
        .ok_or("commands array")?
        .push(wrong.clone());
    denial(&wrong)?;
    ensure(
        !wrong_case.legacy_root.exists(),
        "wrong configuration created local fallback root",
    )?;
    let wrong_enrollment = root.join("wrong-server-enrollment.json");
    let admitted_wrong = hermes_memory::windows_enrollment::load_from_enrollment(
        &wrong_enrollment,
        &job.case.legacy_root,
    )?;
    ensure(
        admitted_wrong.server_sid != enrollment.server_sid,
        "negative server pin is not different",
    )?;
    let mut args = job
        .case
        .client_args("search", &contract::text(&wrong_enrollment)?)?;
    args.extend([
        "--query".into(),
        "ordinary".into(),
        "--workspace".into(),
        WORKSPACE.into(),
    ]);
    let wrong = contract::command(
        &job.client,
        &args,
        b"",
        &scratch,
        "wrong-server-pin",
        Duration::from_secs(15),
        crate::scm::stop_requested,
    )?;
    report["commands"]
        .as_array_mut()
        .ok_or("commands array")?
        .push(wrong.clone());
    denial(&wrong)?;
    report["wrong_server_enrollment_admitted_but_pipe_peer_denied"] = json!(true);
    let vault = scratch.join("export");
    let vault_text = contract::text(&vault)?;
    let export = call(
        "export",
        "export",
        &["--workspace", WORKSPACE, "--vault", &vault_text],
        vec![],
        report,
    )?;
    ensure(
        contract::output(&export)?
            == json!({"sessions":if job.pilot.is_some() || two_warmup.is_some() {18} else {3}}),
        "export session count",
    )?;
    report["export"] = if two_warmup.is_some() {
        verify_two_warmup_export(
            &vault,
            &job.case.legacy_root.join("events.jsonl"),
            job.seed_records,
        )?
    } else if job.pilot.is_some() {
        verify_pilot_export(
            &vault,
            &job.case.legacy_root.join("events.jsonl"),
            job.seed_records,
        )?
    } else {
        verify_export(&vault, job.seed_records)?
    };
    ensure(
        before == data::inventory(&job.case.legacy_root)?,
        "client altered local source",
    )?;
    report["source_unchanged"] = json!(true);
    Ok(())
}
fn denial(value: &Value) -> Result<()> {
    ensure(
        value["exit_code"].as_i64().is_some_and(|c| c != 0)
            && value["timed_out"] == false
            && value["stop_requested"] == false
            && value["stderr"]
                .as_str()
                .is_some_and(|s| s.contains("unauthorized")),
        "wrong configuration was not explicitly denied",
    )
}
