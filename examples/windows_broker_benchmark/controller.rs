//! Controller for exactly one 6 MiB staged-legacy case, not a 600 MiB benchmark.
use crate::{
    contract::{self, ensure},
    data::{self, Result},
    Options,
};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
const CLIENT_REPORT_LIMIT: u64 = 1024 * 1024;

#[cfg(windows)]
fn open_client_report(path: &Path) -> Result<File> {
    use std::os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileType, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_TYPE_DISK,
    };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    // Check the opened handle, not a path that B can replace. Reject pipes/devices
    // before any read; OPEN_REPARSE_POINT prevents following a replaced leaf.
    // SAFETY: file owns the live handle throughout this query and the later read.
    ensure(
        unsafe { GetFileType(file.as_raw_handle()) } == FILE_TYPE_DISK,
        "B report must be a regular non-reparse disk file",
    )?;
    let metadata = file.metadata()?;
    ensure(
        metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "B report must be a regular non-reparse disk file",
    )?;
    ensure(metadata.len() < CLIENT_REPORT_LIMIT, "B report size bound")?;
    Ok(file)
}

fn read_client_report(file: &mut File) -> Result<Value> {
    use std::io::Read;
    // B retains write access: metadata is only an early rejection, not a read bound.
    let mut bytes = Vec::new();
    file.take(CLIENT_REPORT_LIMIT + 1).read_to_end(&mut bytes)?;
    ensure(
        bytes.len() < CLIENT_REPORT_LIMIT as usize,
        "B report size bound",
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Sequencing/receipt/append controller, usable without lifecycle authority.
/// `sample` must close over one retained observer; ordinary adapters return null.
#[allow(dead_code)] // Native admission and same-handle metrics remain a later review gate.
pub fn two_warmup_sandbox_intervals(
    root: &Path,
    epoch: &str,
    projection: &Path,
    deadline: Instant,
    cancelled: fn() -> bool,
    mut sample: impl FnMut(u32, bool) -> Result<Value>,
) -> Result<Value> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};
    let mut barrier = contract::OperationBarrier::new(root, epoch, 2)?;
    let mut evidence = Vec::with_capacity(2);
    for id in 0..crate::data::TwoWarmupManifest::OPERATIONS {
        barrier.wait(
            id,
            contract::PilotPhase::Ready,
            deadline.min(Instant::now() + Duration::from_secs(60)),
            cancelled,
        )?;
        let mut file = File::open(projection)?;
        let before_bytes = file.metadata()?.len();
        ensure(before_bytes <= 8 * 1024 * 1024, "warmup projection bound")?;
        let before_hash = crate::data::hash_file(projection)?; // Outside sample bracket.
        let before = sample(id, false)?;
        barrier.publish(id, contract::PilotPhase::Release)?;
        barrier.wait(
            id,
            contract::PilotPhase::Done,
            deadline.min(Instant::now() + Duration::from_secs(60)),
            cancelled,
        )?;
        let after = sample(id, true)?; // Before receipt reads or any corpus hashing.
        let receipt_file = File::open(root.join(format!("scratch/workload-op-{id}-receipt.json")))?;
        ensure(
            receipt_file.metadata()?.is_file() && receipt_file.metadata()?.len() <= 65536,
            "warmup receipt bound",
        )?;
        let receipt: contract::WarmupReceipt = serde_json::from_reader(receipt_file.take(65537))?;
        receipt.validate(id)?;
        let mut expected = serde_json::to_vec(&crate::data::TwoWarmupManifest.record(id)?)?;
        expected.push(b'\n');
        ensure(
            file.metadata()?.len() == before_bytes + expected.len() as u64,
            "warmup exact append length",
        )?;
        file.seek(SeekFrom::Start(0))?;
        let mut prefix = (&mut file).take(before_bytes);
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let n = prefix.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
        }
        ensure(
            format!("{:x}", hash.finalize()) == before_hash,
            "warmup prefix mutation",
        )?;
        let mut actual = vec![0; expected.len()];
        file.read_exact(&mut actual)?;
        ensure(
            actual == expected && file.read(&mut [0; 1])? == 0,
            "warmup exact append payload",
        )?;
        // The callback seam does not certify a native C handle or projection path identity.
        evidence.push(json!({"operation_id":id,"cli_epoch":receipt.cli_epoch,"payload_bytes":receipt.payload.len(),"before_release":before,"after_done":after,"receipt_validated":true,"exact_append_verified":true,"hashing":"outside bracket"}));
        ensure(
            !cancelled() && Instant::now() < deadline,
            "warmup cancelled/expired before ACK",
        )?;
        barrier.publish(id, contract::PilotPhase::Acknowledged)?;
    }
    Ok(
        json!({"schema":3,"case":"representative-two-warmup-sandbox","operations":evidence,"sampling_complete":false,"native_handle_verified":false,"performance_policy_status":"unapproved"}),
    )
}
#[cfg(all(test, windows))]
mod two_warmup_sequence_tests {
    use super::*;
    #[test]
    fn controller_observes_both_boundaries_before_ack_for_each_operation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir(root.join("scratch")).unwrap();
        std::fs::create_dir(root.join("controller")).unwrap();
        let store = hermes_memory::MemoryStore::open(root.join("store")).unwrap();
        store
            .ingest_many(&[crate::data::representative_record(0).unwrap()])
            .unwrap();
        let mut observations = Vec::new();
        // Complete store initialization before either peer starts its operation deadline.
        std::thread::scope(|scope| {
            let child = scope.spawn(move || {
                crate::client::execute_two_warmup_sandbox(
                    root,
                    "boundaries",
                    Instant::now() + Duration::from_secs(5),
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
            let report = two_warmup_sandbox_intervals(
                root,
                "boundaries",
                &root.join("store/events.jsonl"),
                Instant::now() + Duration::from_secs(5),
                contract::never_cancel,
                |id, after| {
                    assert!(root
                        .join(format!("scratch/workload-op-{id}-ready.json"))
                        .exists());
                    assert_eq!(
                        root.join(format!("scratch/workload-op-{id}-done.json"))
                            .exists(),
                        after
                    );
                    assert!(!root
                        .join(format!("controller/workload-op-{id}-acknowledged.json"))
                        .exists());
                    observations.push(if after {
                        "after-done"
                    } else {
                        "before-release"
                    });
                    Ok(Value::Null) // No fabricated native measurements.
                },
            )
            .unwrap();
            assert_eq!(report["operations"].as_array().unwrap().len(), 2);
            assert_eq!(report["native_handle_verified"], false);
            child.join().unwrap().unwrap();
        });
        assert_eq!(
            observations,
            [
                "before-release",
                "after-done",
                "before-release",
                "after-done"
            ]
        );
    }
    #[test]
    fn unknown_commit_error_is_not_retried_or_published_as_done() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir(root.join("scratch")).unwrap();
        std::fs::create_dir(root.join("controller")).unwrap();
        let store = hermes_memory::MemoryStore::open(root.join("store")).unwrap();
        std::thread::scope(|scope| {
            let child = scope.spawn(move || {
                let mut calls = 0;
                let result = crate::client::execute_two_warmup_sandbox(
                    root,
                    "unknown-commit",
                    Instant::now() + Duration::from_secs(2),
                    contract::never_cancel,
                    |_, _, payload| {
                        calls += 1;
                        let records: Vec<hermes_memory::MemoryRecord> =
                            serde_json::from_slice(payload)?;
                        store.ingest_many(&records)?;
                        Err("unknown commit injected after real insertion".into())
                    },
                );
                assert!(result.unwrap_err().to_string().contains("unknown commit"));
                assert_eq!(calls, 1);
            });
            let mut barrier = contract::OperationBarrier::new(root, "unknown-commit", 2).unwrap();
            barrier
                .wait(
                    0,
                    contract::PilotPhase::Ready,
                    Instant::now() + Duration::from_secs(2),
                    contract::never_cancel,
                )
                .unwrap();
            barrier.publish(0, contract::PilotPhase::Release).unwrap();
            child.join().unwrap();
            assert!(!root.join("scratch/workload-op-0-done.json").exists());
            assert!(!root.join("scratch/workload-op-1-ready.json").exists());
        });
    }
    #[test]
    fn bad_receipt_after_done_never_acknowledges_or_advances() {
        static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        fn cancelled() -> bool {
            STOP.load(std::sync::atomic::Ordering::SeqCst)
        }
        STOP.store(false, std::sync::atomic::Ordering::SeqCst);
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir(root.join("scratch")).unwrap();
        std::fs::create_dir(root.join("controller")).unwrap();
        let store = hermes_memory::MemoryStore::open(root.join("store")).unwrap();
        store
            .ingest_many(&[crate::data::representative_record(0).unwrap()])
            .unwrap();
        drop(store);
        std::thread::scope(|scope| {
            let child = scope.spawn(move || {
                let store = hermes_memory::MemoryStore::open(root.join("store")).unwrap();
                crate::client::execute_two_warmup_sandbox(
                    root,
                    "bad-receipt",
                    Instant::now() + Duration::from_secs(10),
                    cancelled,
                    |_, _, payload| {
                        let records: Vec<hermes_memory::MemoryRecord> =
                            serde_json::from_slice(payload)?;
                        let (a, b) = store.ingest_many(&records)?;
                        Ok((a as u64, b as u64))
                    },
                )
                .map_err(|e| e.to_string())
            });
            let result = two_warmup_sandbox_intervals(
                root,
                "bad-receipt",
                &root.join("store/events.jsonl"),
                Instant::now() + Duration::from_secs(10),
                contract::never_cancel,
                |id, after| {
                    if after {
                        let path = root.join(format!("scratch/workload-op-{id}-receipt.json"));
                        let mut value: Value = serde_json::from_reader(File::open(&path)?)?;
                        value["cli_epoch"] = json!(999);
                        std::fs::write(path, serde_json::to_vec(&value)?)?;
                    }
                    Ok(Value::Null)
                },
            );
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("receipt/payload mismatch"));
            STOP.store(true, std::sync::atomic::Ordering::SeqCst);
            assert!(child.join().unwrap().is_err());
        });
        assert!(!root
            .join("controller/workload-op-0-acknowledged.json")
            .exists());
        assert!(!root.join("scratch/workload-op-1-ready.json").exists());
    }
    #[test]
    fn exact_receipt_mutations_and_unknown_fields_are_refused() {
        for mutation in 0..8 {
            let receipt = contract::WarmupReceipt {
                schema: 3,
                operation_id: 0,
                cli_epoch: 3,
                payload: crate::data::TwoWarmupManifest.payload(0).unwrap(),
                inserted: 1,
                duplicates: 0,
            };
            receipt.validate(0).unwrap();
            let mut value = serde_json::to_value(receipt).unwrap();
            match mutation {
                0 => value["schema"] = json!(1),
                1 => value["operation_id"] = json!(1),
                2 => value["cli_epoch"] = json!(4),
                3 => value["inserted"] = json!(0),
                4 => value["duplicates"] = json!(1),
                5 => value["payload"][0] = json!(0),
                6 => {
                    value.as_object_mut().unwrap().remove("payload");
                }
                _ => value["unknown"] = json!(true),
            }
            match serde_json::from_value::<contract::WarmupReceipt>(value) {
                Ok(bad) => assert!(bad.validate(0).is_err()),
                Err(_) => assert!(mutation >= 6),
            }
        }
    }
    #[test]
    fn missing_ack_does_not_execute_second_real_insert() {
        static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        fn cancelled() -> bool {
            STOP.load(std::sync::atomic::Ordering::SeqCst)
        }
        STOP.store(false, std::sync::atomic::Ordering::SeqCst);
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("scratch")).unwrap();
        std::fs::create_dir(temp.path().join("controller")).unwrap();
        std::thread::scope(|scope| {
            let root = temp.path();
            let child = scope.spawn(move || {
                let store = hermes_memory::MemoryStore::open(root.join("store")).unwrap();
                crate::client::execute_two_warmup_sandbox(
                    root,
                    "missing-ack",
                    Instant::now() + Duration::from_secs(10),
                    cancelled,
                    |_, _, payload| {
                        let records: Vec<hermes_memory::MemoryRecord> =
                            serde_json::from_slice(payload)?;
                        let (inserted, duplicates) = store.ingest_many(&records)?;
                        Ok((inserted as u64, duplicates as u64))
                    },
                )
                .map_err(|e| e.to_string())
            });
            let mut barrier = contract::OperationBarrier::new(root, "missing-ack", 2).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            barrier
                .wait(
                    0,
                    contract::PilotPhase::Ready,
                    deadline,
                    contract::never_cancel,
                )
                .unwrap();
            barrier.publish(0, contract::PilotPhase::Release).unwrap();
            barrier
                .wait(
                    0,
                    contract::PilotPhase::Done,
                    deadline,
                    contract::never_cancel,
                )
                .unwrap();
            STOP.store(true, std::sync::atomic::Ordering::SeqCst);
            assert!(child.join().unwrap().unwrap_err().contains("cancelled"));
            assert!(!root.join("scratch/workload-op-1-ready.json").exists());
        });
        let text = std::fs::read_to_string(temp.path().join("store/events.jsonl")).unwrap();
        assert!(!text.contains("benchmark-workload-v1-000001"));
    }
}
pub(crate) fn validate_warmup_command(value: &Value, id: u32) -> Result<()> {
    ensure(
        contract::output(value)? == json!({"inserted":1,"duplicates":0}),
        "warmup exact acknowledgement",
    )?;
    let measurement: crate::measure::CommandMeasurement =
        serde_json::from_value(value["measurement"].clone())?;
    measurement.validate()?;
    let manifest = data::TwoWarmupManifest;
    let policy = crate::measure::SamplePolicy::cli(manifest.cli_epoch(id)?, id);
    ensure(
        measurement.identity == policy.identity
            && measurement.operation_id == id
            && measurement.command_success
            && measurement.payload_bytes == manifest.payload(id)?.len() as u64,
        "warmup measurement identity/payload mismatch",
    )
}
fn validate_pilot_receipt(value: &Value) -> Result<()> {
    ensure(
        contract::output(value)? == json!({"inserted":1,"duplicates":0}),
        "pilot exact acknowledgement",
    )?;
    let measurement: crate::measure::CommandMeasurement =
        serde_json::from_value(value["measurement"].clone())?;
    measurement.validate()?;
    let policy = crate::measure::SamplePolicy::cli(3, 0);
    ensure(
        measurement.identity == policy.identity
            && measurement.operation_id == policy.operation_id
            && measurement.command_success
            && measurement.payload_bytes
                == serde_json::to_vec(&crate::client::known_record())?.len() as u64,
        "pilot measurement identity/payload mismatch",
    )
}
fn validate(o: &Options) -> Result<()> {
    ensure(
        o.large_mib.is_none(),
        "--large-mib is unsupported; this controller executes ONLY the real 6 MiB case",
    )?;
    ensure(
        o.run
            && o.allow_disposable_services
            && o.allow_virtual_accounts
            && o.allow_acl_mutation
            && o.reviewed,
        "requires --run and all three explicit consents plus --reviewed",
    )?;
    ensure(
        o.result.is_some()
            && o.broker_exe.is_some()
            && o.client_exe.is_some()
            && o.admin_exe.is_some(),
        "requires --result --broker-exe --client-exe --admin-exe",
    )
}
fn executable(path: &Path) -> Result<PathBuf> {
    ensure(
        path.is_absolute()
            && path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("exe")),
        "provide absolute .exe paths",
    )?;
    ensure(
        fs::symlink_metadata(path)?.is_file(),
        "executable must be regular",
    )?;
    let canonical = fs::canonicalize(path)?;
    let text = contract::text(&canonical)?;
    Ok(PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text)))
}
pub fn run(options: Options) -> Result<()> {
    validate(&options)?;
    #[cfg(not(all(windows, feature = "experimental-broker")))]
    {
        Err("requires Windows and --features experimental-broker".into())
    }
    #[cfg(all(windows, feature = "experimental-broker"))]
    {
        // No file writes, ACLs or SCM mutations before all deployment/native gates.
        crate::policy::disposable_gates(
            options.allow_disposable_services,
            options.allow_virtual_accounts,
            options.allow_acl_mutation,
            options.reviewed,
        )?;
        let administrator = crate::scm::administrator()?;
        let broker = executable(options.broker_exe.as_deref().ok_or("broker path")?)?;
        let client = executable(options.client_exe.as_deref().ok_or("client path")?)?;
        let admin = executable(options.admin_exe.as_deref().ok_or("admin path")?)?;
        ensure(
            broker != client && broker != admin && client != admin,
            "executable roles must be distinct",
        )?;
        let pins = json!({"broker":data::hash_file(&broker)?,"client":data::hash_file(&client)?,"admin":data::hash_file(&admin)?});
        let result_path = options.result.as_deref().ok_or("result path")?;
        let mut result_file = if options.representative_full_workload {
            crate::full_native::reserve_report(result_path)?
        } else {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(result_path)?
        };
        let mut report = json!({"schema":1,"case":"small-6MiB","pass":false,"administrator":administrator,"executable_sha256":pins,"commands":[],"metrics":{"measured":false,"reason":"small correctness case; no 600 MiB or process-IO claim"},"fixture_disposal":"retained for hosted VM disposal; no recursive cleanup"});
        if options.representative_small_pilot {
            report["schema"] = json!(2);
            report["case"] = json!("representative-6MiB-pilot");
            report["metrics"] = json!({"measured":false,"sampling_complete":false,"performance_policy_status":"unapproved","workload":"one first-warmup insert; NOT full warmup/20-sample steady workload"});
        }
        if options.representative_two_warmup {
            report["schema"] = json!(4);
            report["case"] = json!("representative-6MiB-two-warmup");
            report["metrics"] = json!({"measured":false,"sampling_complete":false,"performance_policy_status":"unapproved","expected_warmups":2,"full_workload_complete":false,"workload":"exactly two warmups; no steady-state20 admission"});
        }
        let outcome = small(
            &broker,
            &client,
            &admin,
            &mut report,
            options.representative_small_pilot,
            options.representative_two_warmup,
            options.representative_full_workload,
        );
        if let Err(ref e) = outcome {
            report["error"] = json!(e.to_string());
        }
        report["pass"] = json!(outcome.is_ok());
        if options.representative_full_workload {
            let publication = (|| -> Result<()> {
                let full = crate::full_native::FullReport::from_observations(&report, true)?;
                crate::full_native::write_report_bounded(result_path, &full)
            })();
            return crate::full_native::preserve_primary(outcome, publication);
        }
        serde_json::to_writer_pretty(&mut result_file, &report)?;
        result_file.write_all(b"\n")?;
        result_file.sync_all()?;
        outcome
    }
}
#[cfg(all(windows, feature = "experimental-broker"))]
fn small(
    broker: &Path,
    client: &Path,
    admin_source: &Path,
    report: &mut Value,
    pilot: bool,
    two_warmup: bool,
    full_workload: bool,
) -> Result<()> {
    let mut fixture = crate::scm::Fixture::create(true, true)?;
    let root = fixture.root().to_owned();
    report["fixture"] = json!({"root":root,"client_service":fixture.client_name(),"client_sid":fixture.client_sid()});
    let logs = root.join("controller");
    fs::create_dir(&logs)?;
    let admin = root.join("bin/hermes-memory-admin.exe");
    let mut source = File::open(admin_source)?;
    let mut copied = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&admin)?;
    std::io::copy(&mut source, &mut copied)?;
    copied.sync_all()?;
    drop(copied);
    ensure(
        data::hash_file(&admin)? == report["executable_sha256"]["admin"],
        "admin copy pin mismatch",
    )?;
    // Retain protected admin/ancestor handles through all helper invocations.
    let _admin_pin = hermes_memory::windows_enrollment::open_admin_owned_file(&admin, 1 << 30)?;
    let install = root.join("install-small");
    let receipt = install.join("receipt.json");
    let mut prepared = false;
    let mut observed = None;
    let mut generation = Value::Null;
    let operation = (|| -> Result<()> {
        generation = if pilot || two_warmup || full_workload {
            data::generate_with_spec(
                &root.join("small"),
                &data::FixtureSpec::representative_6_mib(),
            )?
        } else {
            data::generate(&root.join("small"), 6 * 1024 * 1024)?
        };
        report["generation"] = generation.clone();
        let manifest = json!({"kind":"benchmark-generated-executable-pins-not-a-vendor-release", "broker_sha256":report["executable_sha256"]["broker"],"client_sha256":report["executable_sha256"]["client"],"admin_sha256":report["executable_sha256"]["admin"]});
        contract::json_new(&root.join("release-manifest.json"), &manifest)?;
        let case = small_case(
            &root,
            broker,
            client,
            fixture.broker_name("small")?,
            fixture.client_sid(),
        )?;
        ensure(
            case.broker_sha256 == report["executable_sha256"]["broker"]
                && case.client_sha256 == report["executable_sha256"]["client"],
            "payload changed after preflight hash",
        )?;
        let mut plan_args = case.prepare_args()?;
        plan_args[0] = "plan".into();
        plan_args.remove(1); // plan is read-only and does not receive mutation consent.
        let plan = admin_call(&admin, &plan_args, &logs, "plan", report)?;
        report["plan"] = plan.clone();
        let enrollment = PathBuf::from(plan["enrollment"].as_str().ok_or("plan enrollment")?);
        let actual_receipt = admin_call(&admin, &case.prepare_args()?, &logs, "prepare", report)?;
        prepared = true;
        report["receipt"] = actual_receipt;
        // Read-only native file/ancestor admission; production prepare creates only fresh NTFS roots.
        let _receipt_pin =
            hermes_memory::windows_enrollment::open_admin_owned_file(&receipt, 65536)?;
        let args = vec![
            "activate".into(),
            "--allow-machine-provision".into(),
            "--receipt".into(),
            contract::text(&receipt)?,
            "--archive-source".into(),
            generation["archive"].as_str().ok_or("archive path")?.into(),
            "--archive-sha256".into(),
            generation["archive_sha256"]
                .as_str()
                .ok_or("archive pin")?
                .into(),
            "--expected-logical-sha256".into(),
            generation["logical_sha256"]
                .as_str()
                .ok_or("logical pin")?
                .into(),
        ];
        report["activation"] = admin_call(&admin, &args, &logs, "activate", report)?;
        report["status"] = admin_call(
            &admin,
            &receipt_args("status", &receipt)?,
            &logs,
            "status",
            report,
        )?;
        let tracked = fixture.observe_broker(&receipt, "small")?;
        report["broker_before"] = tracked.observation()?;
        observed = Some(tracked);
        let job = contract::Job {
            case,
            enrollment,
            client: install.join("bin/hermes-memory-client.exe"),
            seed_records: generation["seed_records"].as_u64().ok_or("seed count")?,
            pilot: if pilot {
                Some(contract::PilotJob {
                    schema: 1,
                    fixture_spec: data::FixtureSpec::representative_6_mib(),
                    epoch: fixture.client_name().to_owned(),
                })
            } else {
                None
            },
        };
        // Deliberately wrong server pin in a separately protected enrollment.
        // It is not a forged success: B must admit the config then reject the real pipe peer.
        let mut wrong: Value = serde_json::from_reader(
            hermes_memory::windows_enrollment::open_admin_owned_file(&job.enrollment, 65536)?,
        )?;
        let candidates = [
            "S-1-5-80-1-2-3-4-5",
            "S-1-5-80-1-2-3-4-6",
            "S-1-5-80-1-2-3-4-7",
        ];
        let wrong_sid = candidates
            .into_iter()
            .find(|sid| wrong["server_sid"] != *sid && wrong["client_sid"] != *sid)
            .ok_or("wrong SID candidate")?;
        wrong["server_sid"] = json!(wrong_sid);
        contract::json_new(&root.join("wrong-server-enrollment.json"), &wrong)?;
        if two_warmup {
            contract::json_new(
                &root.join("two-warmup-job.json"),
                &crate::two_warmup::TwoWarmupJob {
                    schema: 4,
                    epoch: fixture.client_name().to_owned(),
                    fixture_spec: data::FixtureSpec::representative_6_mib(),
                },
            )?;
        }
        if full_workload {
            let mode = crate::full_native::FullWorkloadJob {
                schema: 1,
                protocol: crate::full_native::FullJobProtocol::Full20x256NativeJobV1,
                case_epoch: fixture.client_name().to_owned(),
                fixture_spec: data::FixtureSpec::representative_6_mib(),
                workload_spec: crate::full_manifest::WorkloadSpec::full20x256_v1(),
                seed_records: job.seed_records,
            };
            mode.validate(&job)?;
            contract::json_new(&root.join("full-workload-job.json"), &mode)?;
        }
        contract::json_new(&root.join("job.json"), &job)?;
        report["client_start"] = fixture.start_client()?;
        if full_workload {
            crate::full_native::controller_native_intervals(
                &root,
                fixture.client_name(),
                &fixture,
                observed.as_ref().ok_or("missing retained C")?,
                &job,
                &generation,
                report,
            )?;
        }
        if two_warmup {
            native_two_warmup_intervals(
                &root,
                fixture.client_name(),
                &fixture,
                observed.as_ref().ok_or("missing retained C")?,
                &job,
                report,
            )?;
        }
        if let Some(pilot_job) = &job.pilot {
            pilot_interval(
                &root,
                pilot_job,
                &fixture,
                observed.as_ref().ok_or("missing retained C")?,
                report,
            )?;
        }
        let deadline = Instant::now() + Duration::from_secs(if full_workload { 60 } else { 360 });
        while !root.join("scratch/client-done.json").exists() {
            ensure(
                Instant::now() < deadline,
                "B worker completion deadline; evidence retained",
            )?;
            let current = fixture.observe_client()?;
            ensure(
                current["process"]["exited"] != true,
                "B exited before completion",
            )?;
            std::thread::sleep(Duration::from_millis(100));
        }
        if full_workload {
            report["client"] =
                crate::full_native::read_report(&root.join("scratch/client-result.json"))?;
            crate::full_native::validate_report(
                &report["client"],
                fixture.client_name(),
                job.seed_records,
                report["metrics"]["controller_retained_commands"]
                    .as_array()
                    .ok_or("full retained commands")?,
            )?;
        } else {
            let mut file = open_client_report(&root.join("scratch/client-result.json"))?;
            report["client"] = read_client_report(&mut file)?;
        }
        report["client_observation"] = fixture.observe_client()?;
        if pilot || two_warmup {
            let commands = report["client"]["commands"]
                .as_array()
                .ok_or("pilot commands missing")?;
            let measured: Vec<_> = commands
                .iter()
                .filter(|v| v.get("measurement").is_some())
                .collect();
            ensure(
                measured.len() == if two_warmup { 2 } else { 1 },
                "pilot requires exactly one measured command",
            )?;
            if two_warmup {
                validate_final_warmup_commands(
                    commands,
                    report["metrics"]["controller_retained_receipts"]
                        .as_array()
                        .ok_or("controller-retained receipts missing")?,
                )?;
            } else {
                validate_pilot_receipt(measured[0])?;
            }
        }
        ensure(
            report["client"]["pass"] == true,
            "B client validation failed; see nested report",
        )?;
        ensure(
            data::inventory(&root.join("small/source"))? == generation["source_before"],
            "source changed during broker/client operations",
        )?;
        report["source_unchanged"] = json!(true);
        Ok(())
    })();
    // Always attempt bounded cooperative stops using only owned service capabilities.
    let b_stop = fixture.stop_client();
    report["client_stop"] = match &b_stop {
        Ok(v) => v.clone(),
        Err(e) => json!({"error":e.to_string()}),
    };
    let c_stop = if prepared {
        admin_call(
            &admin,
            &receipt_args("stop", &receipt)?,
            &logs,
            "stop",
            report,
        )
        .map(Some)
    } else {
        Ok(None)
    };
    report["broker_stop"] = match &c_stop {
        Ok(v) => json!(v),
        Err(e) => json!({"error":e.to_string()}),
    };
    let c_exit = if let Some(tracked) = &observed {
        tracked.wait_exit(Duration::from_secs(30)).map(Some)
    } else {
        Ok(None)
    };
    report["broker_exit"] = match &c_exit {
        Ok(v) => json!(v),
        Err(e) => json!({"error":e.to_string()}),
    };
    operation?;
    b_stop?;
    c_stop?;
    c_exit?;
    ensure(
        report["client_stop"]["process"]["exited"] == true
            && report["client_stop"]["process"]["exit_code"] == 0
            && report["client_stop"]["scm_exit_code"] == 0,
        "B did not stop cleanly",
    )?;
    ensure(
        report["broker_exit"]["exited"] == true && report["broker_exit"]["exit_code"] == 0,
        "C did not stop cleanly",
    )?;
    report["startup_import"] = if full_workload {
        let manifest = crate::full_manifest::FullManifest::new(
            crate::full_manifest::WorkloadSpec::full20x256_v1(),
            generation["seed_records"].as_u64().ok_or("full seeds")?,
        )?;
        crate::full_oracles::verify_stopped_sqlite(
            &install.join("store/memory.db"),
            &generation,
            &manifest,
        )?
    } else if two_warmup {
        crate::fixtures::verify_stopped_two_warmup(&install.join("store/memory.db"), &generation)?
    } else if pilot {
        crate::fixtures::verify_stopped_import_with_expected(
            &install.join("store/memory.db"),
            &generation,
            1,
        )?
    } else {
        crate::fixtures::verify_stopped_import(&install.join("store/memory.db"), &generation)?
    };
    ensure(
        data::inventory(&root.join("small/source"))? == generation["source_before"],
        "source changed after shutdown",
    )?;
    if full_workload {
        let manifest = crate::full_manifest::FullManifest::new(
            crate::full_manifest::WorkloadSpec::full20x256_v1(),
            generation["seed_records"].as_u64().ok_or("full seeds")?,
        )?;
        report["final_payloads"] = crate::full_oracles::verify_projection(
            &install.join("store/events.jsonl"),
            &root.join("small/source/events.jsonl"),
            &manifest,
        )?;
        report["export"] = crate::full_oracles::verify_export(
            &root.join("scratch/export"),
            &root.join("small/source/events.jsonl"),
            &manifest,
        )?;
        report["workload_complete"] = json!(true);
        report["correctness_complete"] = json!(true);
    }
    if two_warmup {
        report["final_payloads"] = crate::client::verify_two_warmup_projection(
            &install.join("store/events.jsonl"),
            &root.join("small/source/events.jsonl"),
            generation["seed_records"].as_u64().ok_or("seed count")?,
        )?;
    }
    if pilot {
        report["final_payloads"] = crate::client::verify_pilot_projection(
            &install.join("store/events.jsonl"),
            &root.join("small/source/events.jsonl"),
            generation["seed_records"].as_u64().ok_or("seed count")?,
        )?;
    }
    report["broker_after"] = observed
        .as_ref()
        .ok_or("no broker observation")?
        .observation()?;
    // Delete only the retained stopped B registration; files and C remain for VM disposal.
    fixture.delete_client()?;
    report["client_registration_deleted"] = json!(true);
    Ok(())
}
#[cfg(all(windows, feature = "experimental-broker"))]
fn process_sample(sample: crate::metrics::ProcessSnapshot) -> Value {
    json!({"logical_io":crate::measure::LogicalIo::from(sample.logical_io),"private_bytes":sample.private_bytes,"working_set_bytes":sample.working_set_bytes,"lifetime_peak_private_bytes":sample.peak_private_bytes,"lifetime_peak_working_set_bytes":sample.peak_working_set_bytes})
}
#[cfg(all(windows, feature = "experimental-broker"))]
fn pilot_interval(
    root: &Path,
    job: &contract::PilotJob,
    fixture: &crate::scm::Fixture,
    broker: &crate::scm::ObservedService,
    report: &mut Value,
) -> Result<()> {
    use contract::PilotPhase;
    use std::io::{Read, Seek, SeekFrom};
    job.validate()?;
    let mut barrier = contract::PilotBarrier::new(root, &job.epoch)?;
    barrier.wait(
        PilotPhase::Ready,
        Duration::from_secs(60),
        contract::never_cancel,
    )?;
    let projection = root.join("install-small/store/events.jsonl");
    // Quiescent full-prefix scan BEFORE baseline: explicitly warm-cache evidence.
    let before_file = crate::metrics::snapshot_jsonl(&projection)?;
    ensure(
        before_file.length >= 6 * 1024 * 1024,
        "broker representative corpus below 6 MiB",
    )?;
    let before_b = fixture.sample_client()?;
    let before_c = broker.sample()?;
    let start = Instant::now();
    report["metrics"]["pilot_interval"] = json!({"schema":1,"operation_id":0,"stage":"pilot-first-warmup-only","case_epoch":job.epoch,"broker_epoch":1,"supervisor_epoch":2,"cli_epoch":3,"broker_before":process_sample(before_c),"supervisor_before":process_sample(before_b),"coverage":"two boundary samples only; no cadence or interval peak claim","logical_io_semantics":"process logical IO, not physical disk or broker-store-only IO","memory_semantics":"sampled lower bounds; lifetime peaks include startup; no sum of peaks","hashing":"outside measured interval; warm-cache evidence"});
    barrier.publish(PilotPhase::Release)?;
    barrier.wait(
        PilotPhase::Done,
        Duration::from_secs(60),
        contract::never_cancel,
    )?;
    let after_c = broker.sample()?; // SAME retained receipt-admitted handle; no PID reopen.
    let span = start.elapsed().as_micros();
    let after_b = fixture.sample_client()?;
    let c_delta = after_c.logical_io.checked_delta(&before_c.logical_io)?;
    let b_delta = after_b.logical_io.checked_delta(&before_b.logical_io)?;
    let evidence = &mut report["metrics"]["pilot_interval"];
    evidence["broker_after"] = process_sample(after_c);
    evidence["supervisor_after"] = process_sample(after_b);
    evidence["broker_logical_io_delta"] = json!(crate::measure::LogicalIo::from(c_delta));
    evidence["supervisor_logical_io_delta"] = json!(crate::measure::LogicalIo::from(b_delta));
    evidence["handshake_span_us"] = json!(span);
    // Done is quiescent until ACK; corpus hashing and projection/export verification
    // are outside C interval. B harness serialization/capture remains supervisor overhead.
    let after_file = crate::metrics::verify_append(&projection, &before_file)?;
    let mut expected = serde_json::to_vec(&crate::client::known_record())?;
    expected.push(b'\n');
    ensure(
        after_file.length.checked_sub(before_file.length) == Some(expected.len() as u64),
        "pilot exact append length",
    )?;
    let mut file = File::open(&projection)?;
    file.seek(SeekFrom::Start(before_file.length))?;
    let mut actual = vec![0; expected.len()];
    file.read_exact(&mut actual)?;
    ensure(actual == expected, "pilot exact appended payload")?;
    evidence["projection"] = json!({"before_bytes":before_file.length,"after_bytes":after_file.length,"before_sha256":before_file.prefix_sha256,"after_sha256":after_file.prefix_sha256,"volume_serial_number":after_file.identity.volume_serial_number,"file_id":after_file.identity.file_id,"same_identity":true,"exact_append_verified":true});
    report["metrics"]["measured"] = json!(true);
    barrier.publish(PilotPhase::Acknowledged)?;
    Ok(())
}
#[cfg(all(windows, feature = "experimental-broker"))]
fn native_two_warmup_intervals(
    root: &Path,
    epoch: &str,
    fixture: &crate::scm::Fixture,
    broker: &crate::scm::ObservedService,
    job: &contract::Job,
    report: &mut Value,
) -> Result<()> {
    use std::io::Read;
    let projection = root.join("install-small/store/events.jsonl");
    let mut baseline = None;
    let mut previous_identity = None;
    let mut retained_receipts = Vec::with_capacity(2);
    // Preserve partial boundary/receipt evidence even if a later check fails.
    report["metrics"]["native_intervals"] = json!([]);
    report["metrics"]["controller_retained_receipts"] = json!([]);
    let result = two_warmup_sandbox_intervals(
        root,
        epoch,
        &projection,
        Instant::now() + Duration::from_secs(120),
        contract::never_cancel,
        |id, after| {
            if !after {
                let file = crate::metrics::snapshot_jsonl(&projection)?;
                ensure(
                    file.length >= 6 * 1024 * 1024 && file.length <= 8 * 1024 * 1024,
                    "native representative projection bound",
                )?;
                if let Some(identity) = &previous_identity {
                    ensure(
                        file.identity == *identity,
                        "native projection identity changed between warmups",
                    )?;
                }
                previous_identity = Some(file.identity.clone());
                let b = fixture.sample_client()?;
                let c = broker.sample()?;
                let value = json!({"case_epoch":epoch,"operation_id":id,"broker_epoch":1,"supervisor_epoch":2,"cli_epoch":data::TwoWarmupManifest.cli_epoch(id)?,"broker":process_sample(c),"supervisor":process_sample(b)});
                report["metrics"]["native_intervals"].as_array_mut().ok_or("interval array")?.push(json!({"operation_id":id,"before_release":value,"after_done":null,"receipt_validated":false}));
                baseline = Some((file, c, b, Instant::now()));
                Ok(value)
            } else {
                // SAME retained C and B handles; no reopening by PID or service query.
                let c = broker.sample()?;
                let b = fixture.sample_client()?;
                let (file, before_c, before_b, started) =
                    baseline.take().ok_or("missing warmup baseline")?;
                let span = started.elapsed().as_micros();
                let c_delta = c.logical_io.checked_delta(&before_c.logical_io)?;
                let b_delta = b.logical_io.checked_delta(&before_b.logical_io)?;
                let value = json!({"case_epoch":epoch,"operation_id":id,"broker_epoch":1,"supervisor_epoch":2,"cli_epoch":data::TwoWarmupManifest.cli_epoch(id)?,"broker":process_sample(c),"supervisor":process_sample(b),"broker_logical_io_delta":crate::measure::LogicalIo::from(c_delta),"supervisor_logical_io_delta":crate::measure::LogicalIo::from(b_delta),"handshake_span_us":span});
                report["metrics"]["native_intervals"][id as usize]["after_done"] = value.clone();
                // End samples already captured: all receipt/file hashing below is outside.
                let after_file = crate::metrics::verify_append(&projection, &file)?;
                let path = root.join(format!("scratch/warmup-op-{id}-native.json"));
                let mut input = open_client_report(&path)?;
                ensure(input.metadata()?.len() <= 65536, "native receipt bound")?;
                let mut bytes = Vec::new();
                (&mut input).take(65537).read_to_end(&mut bytes)?;
                ensure(bytes.len() <= 65536, "native receipt bound")?;
                let receipt: crate::two_warmup::NativeReceipt = serde_json::from_slice(&bytes)?;
                receipt.validate(epoch, id)?;
                let label = format!("warmup-op-{id}");
                let mismatches = crate::two_warmup::installed_command_mismatches(
                    &receipt.command,
                    &job.client,
                    &job.case
                        .client_args("ingest", &contract::text(&job.enrollment)?)?,
                    root,
                    id,
                );
                if !mismatches.is_empty() {
                    report["metrics"]["native_intervals"][id as usize]
                        ["command_correlation_failure"] =
                        json!({"operation_id":id,"mismatched_fields":mismatches});
                }
                ensure(
                    mismatches.is_empty(),
                    "native installed command correlation mismatch",
                )?;
                let mut captured =
                    open_client_report(&root.join(format!("scratch/{label}.result.json")))?;
                ensure(
                    read_client_report(&mut captured)? == receipt.command,
                    "native captured command receipt mismatch",
                )?;
                let mut stdin = File::open(root.join(format!("scratch/{label}.stdin")))?;
                let mut actual = Vec::new();
                (&mut stdin).take(4098).read_to_end(&mut actual)?;
                ensure(
                    actual == receipt.warmup.payload,
                    "native captured stdin payload mismatch",
                )?;
                report["metrics"]["native_intervals"][id as usize]["receipt_validated"] =
                    json!(true);
                report["metrics"]["native_intervals"][id as usize]["projection"] = json!({"same_identity":true,"before_bytes":file.length,"after_bytes":after_file.length,"volume_serial_number":after_file.identity.volume_serial_number,"file_id":after_file.identity.file_id});
                // Own the complete validated command before returning to the ACK path.
                retained_receipts.push(receipt.command);
                report["metrics"]["controller_retained_receipts"] = json!(retained_receipts);
                Ok(value)
            }
        },
    )?;
    report["metrics"]["operations"] = result["operations"].clone();
    report["metrics"]["warmup_commands"] = crate::measure::summarize_stage(
        crate::measure::CommandStage::Warmup,
        &retained_receipts
            .iter()
            .map(|command| serde_json::from_value(command["measurement"].clone()))
            .collect::<std::result::Result<Vec<_>, _>>()?,
    )?;
    report["metrics"]["measured"] = json!(true);
    report["metrics"]["native_handle_verified"] = json!(true);
    report["metrics"]["warmups_complete"] = json!(true);
    report["metrics"]["coverage"] = json!("beforeRelease/afterDone boundary samples per operation only; no cadence, interval peaks or full-workload claim");
    report["metrics"]["hashing"] = json!("outside measured brackets; warm-cache evidence");
    report["metrics"]["logical_io_semantics"] = json!("retained C/B process logical IO, not physical or store-only IO; CLI child lifetime IO separate");
    report["metrics"]["memory_semantics"] = json!(
        "boundary sampled lower bounds; lifetime peaks include startup; no simultaneous peak sum"
    );
    Ok(())
}
#[cfg(all(windows, feature = "experimental-broker"))]
fn receipt_args(operation: &str, receipt: &Path) -> Result<Vec<String>> {
    Ok(vec![
        operation.into(),
        "--allow-machine-provision".into(),
        "--receipt".into(),
        contract::text(receipt)?,
    ])
}
#[cfg(all(windows, feature = "experimental-broker"))]
fn admin_call(
    exe: &Path,
    args: &[String],
    logs: &Path,
    label: &str,
    report: &mut Value,
) -> Result<Value> {
    let value = contract::command(
        exe,
        args,
        b"",
        logs,
        label,
        Duration::from_secs(90),
        contract::never_cancel,
    )?;
    report["commands"]
        .as_array_mut()
        .ok_or("commands array")?
        .push(value.clone());
    contract::output(&value)
}

#[cfg(all(windows, feature = "experimental-broker"))]
fn small_case(
    root: &Path,
    broker: &Path,
    client: &Path,
    service_name: String,
    client_sid: &str,
) -> Result<crate::commands::Case> {
    let broker_copy = root.join("bin/hermes-memory-broker.exe");
    let client_copy = root.join("bin/hermes-memory-client.exe");
    // Build outputs can have hardlink aliases. Fresh files inherit the fixture's
    // protected bin policy, not the source ACLs or build-cache link identity.
    for (source, destination) in [(broker, &broker_copy), (client, &client_copy)] {
        let mut input = File::open(source)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
    }
    Ok(crate::commands::Case {
        legacy_root: root.join("small/source"),
        install_root: root.join("install-small"),
        service_name,
        client_sid: client_sid.into(),
        broker_sha256: data::hash_file(&broker_copy)?,
        client_sha256: data::hash_file(&client_copy)?,
        broker_source: broker_copy,
        client_source: client_copy,
        release_sha256: data::hash_file(&root.join("release-manifest.json"))?,
        default_enrollment: false,
    })
}

#[cfg(any(test, all(windows, feature = "experimental-broker")))]
fn validate_final_warmup_commands(commands: &[Value], retained: &[Value]) -> Result<()> {
    let measured: Vec<_> = commands
        .iter()
        .filter(|command| command.get("measurement").is_some())
        .collect();
    ensure(
        retained.len() == 2 && measured == retained.iter().collect::<Vec<_>>(),
        "final commands differ from exact controller-retained receipts",
    )?;
    for (id, command) in measured.iter().enumerate() {
        validate_warmup_command(command, id as u32)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn final_two_warmup_report_rejects_exact_receipt_drift() {
        // Synthetic wire input only, not native execution evidence.
        let retained: Vec<Value> = (0..2)
            .map(|id| {
                let payload = data::TwoWarmupManifest.payload(id).unwrap();
                let mut measurement = crate::measure::CommandMeasurement::new(
                    &crate::measure::SamplePolicy::cli(u64::from(id) + 3, id),
                    payload.len() as u64,
                );
                measurement.command_success = true;
                measurement.child_exit_us = Some(1);
                json!({"exe":"C:/fixture/client.exe","args":["ingest"],
                    "stdout":"{\"inserted\":1,\"duplicates\":0}","stderr":"",
                    "stdout_file":format!("C:/fixture/scratch/warmup-op-{id}.stdout"),
                    "stderr_file":format!("C:/fixture/scratch/warmup-op-{id}.stderr"),
                    "capture_complete":true,"success":true,"measurement":measurement})
            })
            .collect();
        validate_final_warmup_commands(&retained, &retained).unwrap();
        assert!(validate_final_warmup_commands(&retained, &[]).is_err());
        assert!(validate_final_warmup_commands(&retained, &retained[..1]).is_err());
        let mut reordered = retained.clone();
        reordered.reverse();
        assert!(validate_final_warmup_commands(&reordered, &retained).is_err());
        for id in 0..2 {
            for (field, value) in [
                ("exe", json!("C:/unrelated/not-installed.exe")),
                ("args", json!(["unrelated", "--not-ingest"])),
                (
                    "stdout_file",
                    json!(format!("C:/unrelated/captures/warmup-op-{id}.stdout")),
                ),
                (
                    "stderr_file",
                    json!(format!("C:/unrelated/captures/warmup-op-{id}.stderr")),
                ),
                ("stdout", json!("{ \"inserted\": 1, \"duplicates\": 0 }")),
                ("stderr", json!("drift")),
                ("measurement", {
                    let mut measurement = retained[id]["measurement"].clone();
                    measurement["child_exit_us"] = json!(2);
                    measurement
                }),
                ("capture_complete", json!(false)),
            ] {
                let mut commands = retained.clone();
                commands[id][field] = value;
                assert!(
                    validate_final_warmup_commands(&commands, &retained).is_err(),
                    "accepted final {field} drift for operation {id}"
                );
            }
        }
    }

    #[test]
    fn native_two_warmup_command_receipts_bind_exact_operation_epoch_and_payload() {
        for id in 0..2 {
            let payload = data::TwoWarmupManifest.payload(id).unwrap();
            let mut measurement = crate::measure::CommandMeasurement::new(
                &crate::measure::SamplePolicy::cli(u64::from(id) + 3, id),
                payload.len() as u64,
            );
            measurement.command_success = true;
            measurement.child_exit_us = Some(1);
            let value = json!({"success":true,"stdout":"{\"inserted\":1,\"duplicates\":0}","measurement":measurement});
            validate_warmup_command(&value, id).unwrap();
            for mutation in 0..5 {
                let mut bad = value.clone();
                match mutation {
                    0 => bad["measurement"]["operation_id"] = json!(2),
                    1 => bad["measurement"]["identity"]["epoch"] = json!(99),
                    2 => bad["measurement"]["payload_bytes"] = json!(1),
                    3 => bad["measurement"]["command_success"] = json!(false),
                    _ => bad["stdout"] = json!("{\"inserted\":0,\"duplicates\":1}"),
                }
                assert!(validate_warmup_command(&bad, id).is_err());
            }
            assert!(validate_warmup_command(&value, 2).is_err());
        }
    }

    #[test]
    fn two_warmup_opt_in_is_explicit_and_preserves_refusal_outputs() {
        let temp = tempfile::tempdir().unwrap();
        let result = temp.path().join("result.json");
        fs::write(&result, b"keep me\n").unwrap();
        let options = Options::try_parse_from([
            "benchmark",
            "--representative-two-warmup",
            "--result",
            result.to_str().unwrap(),
        ])
        .expect("two warmup CLI path must be admitted by parser");
        assert!(run(options).is_err());
        assert_eq!(fs::read(&result).unwrap(), b"keep me\n");
        let options = Options::try_parse_from([
            "benchmark",
            "--representative-two-warmup",
            "--large-mib",
            "600",
        ])
        .unwrap();
        assert!(validate(&options)
            .unwrap_err()
            .to_string()
            .contains("--large-mib"));
        assert!(Options::try_parse_from([
            "benchmark",
            "--representative-two-warmup",
            "--representative-small-pilot",
        ])
        .is_err());
    }

    #[test]
    fn client_report_enforces_consumed_boundary_and_json_eof() {
        use std::io::{Seek, SeekFrom};
        let mut file = tempfile::tempfile().unwrap();
        for length in [
            CLIENT_REPORT_LIMIT - 1,
            CLIENT_REPORT_LIMIT,
            CLIENT_REPORT_LIMIT + 1,
            CLIENT_REPORT_LIMIT * 2,
        ] {
            let mut bytes = vec![b' '; length as usize];
            bytes[..2].copy_from_slice(b"{}");
            file.set_len(0).unwrap();
            file.rewind().unwrap();
            file.write_all(&bytes).unwrap();
            file.rewind().unwrap();
            let outcome = read_client_report(&mut file);
            assert_eq!(
                file.stream_position().unwrap(),
                length.min(CLIENT_REPORT_LIMIT + 1)
            );
            if length < CLIENT_REPORT_LIMIT {
                assert_eq!(outcome.unwrap(), json!({}));
            } else {
                assert_eq!(outcome.unwrap_err().to_string(), "B report size bound");
            }
        }
        for bytes in [b"{".as_slice(), b"{}{}", b"{} trailing", b"", b"\xff"] {
            file.set_len(0).unwrap();
            file.rewind().unwrap();
            file.write_all(bytes).unwrap();
            file.rewind().unwrap();
            let error = read_client_report(&mut file).unwrap_err();
            assert!(error.downcast_ref::<serde_json::Error>().is_some());
            assert_eq!(file.seek(SeekFrom::End(0)).unwrap(), bytes.len() as u64);
        }
        // An invalid first byte must not reach serde when the file is oversized.
        file.set_len(CLIENT_REPORT_LIMIT * 2).unwrap();
        file.rewind().unwrap();
        file.write_all(b"!").unwrap();
        file.rewind().unwrap();
        assert_eq!(
            read_client_report(&mut file).unwrap_err().to_string(),
            "B report size bound"
        );
        assert_eq!(file.stream_position().unwrap(), CLIENT_REPORT_LIMIT + 1);
    }

    #[cfg(windows)]
    #[test]
    fn client_report_open_rejects_oversize_and_retains_the_admitted_handle() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client-result.json");
        fs::write(&path, b"{\"pass\":true}").unwrap();
        let mut file = open_client_report(&path).unwrap();
        let retained = temp.path().join("retained.json");
        fs::rename(&path, &retained).unwrap();
        let replacement = File::create(&path).unwrap();
        replacement.set_len(CLIENT_REPORT_LIMIT).unwrap();
        assert_eq!(
            open_client_report(&path).unwrap_err().to_string(),
            "B report size bound"
        );
        assert_eq!(read_client_report(&mut file).unwrap(), json!({"pass":true}));
        assert_eq!(fs::read(&retained).unwrap(), b"{\"pass\":true}");
        assert_eq!(replacement.metadata().unwrap().len(), CLIENT_REPORT_LIMIT);
    }

    #[cfg(windows)]
    #[test]
    fn client_report_rejects_nonregular_and_reparse_handles() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("directory");
        fs::create_dir(&directory).unwrap();
        let junction = temp.path().join("junction");
        // Directory junctions need no symlink privilege or ACL mutation.
        let output = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&directory)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(fs::symlink_metadata(&junction)
            .unwrap()
            .file_type()
            .is_symlink());
        for path in [directory.as_path(), junction.as_path(), Path::new("NUL")] {
            assert_eq!(
                open_client_report(path).unwrap_err().to_string(),
                "B report must be a regular non-reparse disk file",
                "{path:?}"
            );
        }
        fs::remove_dir(&junction).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn client_report_growth_after_metadata_is_bounded_before_json() {
        use std::io::Seek;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client-result.json");
        fs::write(&path, b"\"").unwrap();
        // The production open has already observed and accepted the short file.
        let mut file = open_client_report(&path).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 1);
        let mut writer = OpenOptions::new().append(true).open(&path).unwrap();
        writer
            .write_all(&vec![b'x'; (CLIENT_REPORT_LIMIT * 2) as usize])
            .unwrap();
        writer.write_all(b"\"").unwrap();
        writer.sync_all().unwrap();
        let outcome = read_client_report(&mut file);
        let consumed = file.stream_position().unwrap();
        assert!(
            consumed <= CLIENT_REPORT_LIMIT + 1,
            "consumed {consumed} bytes"
        );
        assert_eq!(consumed, CLIENT_REPORT_LIMIT + 1);
        assert_eq!(outcome.unwrap_err().to_string(), "B report size bound");
    }

    #[cfg(all(windows, feature = "experimental-broker"))]
    #[test]
    fn small_plan_owns_single_link_payloads_from_hardlinked_build_outputs() {
        use hermes_memory::windows_provision::{checked_plan, Inputs};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("fixture");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("release-manifest.json"), b"synthetic manifest").unwrap();
        let broker = temp.path().join("broker.exe");
        let client = temp.path().join("client.exe");
        for path in [&broker, &client] {
            fs::write(path, b"synthetic payload, never executed").unwrap();
            fs::hard_link(path, path.with_extension("alias")).unwrap();
        }
        let case = small_case(
            &root,
            &broker,
            &client,
            "HMVBenchmark-synthetic".into(),
            "S-1-5-80-1-2-3-4-5",
        )
        .unwrap();
        let args = case.prepare_args().unwrap();
        let value = |key: &str| args[args.iter().position(|v| v == key).unwrap() + 1].clone();
        let inputs = Inputs {
            legacy_root: value("--legacy-root"),
            client_sid: value("--client-sid"),
            workspace: value("--workspace"),
            scope_mode: Default::default(),
            install_root: value("--install-root"),
            service_name: Some(value("--service-name")),
            broker_source: value("--broker-source"),
            broker_sha256: value("--broker-sha256"),
            client_source: value("--client-source"),
            client_sha256: value("--client-sha256"),
            release_sha256: value("--release-sha256"),
        };
        let mut original = inputs.clone();
        original.broker_source = contract::text(&broker).unwrap();
        original.client_source = contract::text(&client).unwrap();
        assert_eq!(
            checked_plan(&original).unwrap_err().to_string(),
            "source must be bounded regular non-reparse single-link disk file"
        );
        checked_plan(&inputs).expect("fixture-owned copies must pass strict source admission");
        assert_eq!(
            case.broker_source,
            root.join("bin/hermes-memory-broker.exe")
        );
        assert_eq!(
            case.client_source,
            root.join("bin/hermes-memory-client.exe")
        );
        for (source, copy) in [
            (&broker, &case.broker_source),
            (&client, &case.client_source),
        ] {
            assert_eq!(
                data::hash_file(source).unwrap(),
                data::hash_file(copy).unwrap()
            );
        }
        assert!(!root.join("install-small").exists());
        // A second attempt must not overwrite any fixture payload.
        assert!(small_case(
            &root,
            &broker,
            &client,
            "HMVBenchmark-synthetic".into(),
            "S-1-5-80-1-2-3-4-5"
        )
        .is_err());
    }

    #[test]
    fn pilot_receipt_rejects_wrong_epoch_payload_and_ack() {
        let mut measurement = crate::measure::CommandMeasurement::new(
            &crate::measure::SamplePolicy::cli(3, 0),
            serde_json::to_vec(&crate::client::known_record())
                .unwrap()
                .len() as u64,
        );
        measurement.command_success = true;
        measurement.child_exit_us = Some(1);
        let value = json!({"success":true,"stdout":"{\"inserted\":1,\"duplicates\":0}","measurement":measurement});
        validate_pilot_receipt(&value).unwrap(); // Synthetic no-memory sample stays incomplete.
        for (field, replacement) in [
            ("operation_id", json!(2)),
            ("payload_bytes", json!(1)),
            ("command_success", json!(false)),
        ] {
            let mut bad = value.clone();
            bad["measurement"][field] = replacement;
            assert!(validate_pilot_receipt(&bad).is_err());
        }
        let mut bad = value.clone();
        bad["measurement"]["identity"]["epoch"] = json!(4);
        assert!(validate_pilot_receipt(&bad).is_err());
        let mut bad = value;
        bad["stdout"] = json!("{\"inserted\":0,\"duplicates\":1}");
        assert!(validate_pilot_receipt(&bad).is_err());
    }
    #[test]
    fn representative_pilot_requires_all_consents_and_still_refuses_600() {
        let args = [
            "benchmark",
            "--representative-small-pilot",
            "--run",
            "--allow-disposable-services",
            "--allow-virtual-accounts",
            "--allow-acl-mutation",
            "--reviewed",
            "--result",
            "result.json",
            "--broker-exe",
            "broker.exe",
            "--client-exe",
            "client.exe",
            "--admin-exe",
            "admin.exe",
        ];
        let options = Options::try_parse_from(args).expect("explicit pilot parser");
        assert!(validate(&options).is_ok());
        for missing in [
            "--run",
            "--allow-disposable-services",
            "--allow-virtual-accounts",
            "--allow-acl-mutation",
            "--reviewed",
        ] {
            let reduced: Vec<_> = args.iter().filter(|a| **a != missing).copied().collect();
            assert!(validate(&Options::try_parse_from(reduced).unwrap()).is_err());
        }
        let mut options = options;
        options.large_mib = Some(600);
        assert!(validate(&options).is_err());
    }
    #[test]
    fn small_case_requires_every_opt_in_and_rejects_large() {
        let args = [
            "benchmark",
            "--run",
            "--allow-disposable-services",
            "--allow-virtual-accounts",
            "--allow-acl-mutation",
            "--reviewed",
            "--result",
            "result.json",
            "--broker-exe",
            "broker.exe",
            "--client-exe",
            "client.exe",
            "--admin-exe",
            "admin.exe",
        ];
        let mut options = Options::try_parse_from(args).unwrap();
        assert!(validate(&options).is_ok());
        options.large_mib = Some(600);
        assert!(validate(&options).is_err());
        options.large_mib = None;
        options.allow_virtual_accounts = false;
        assert!(validate(&options).is_err());
        options.allow_virtual_accounts = true;
        options.allow_acl_mutation = false;
        assert!(validate(&options).is_err());
        options.allow_acl_mutation = true;
        options.allow_disposable_services = false;
        assert!(validate(&options).is_err());
        options.allow_disposable_services = true;
        options.reviewed = false;
        assert!(validate(&options).is_err());
        assert!(validate(&Options::try_parse_from(["benchmark"]).unwrap()).is_err());
    }
}
