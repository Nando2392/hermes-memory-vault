//! Ordinary tests only. No installed subprocess or lifecycle acquisition.
use super::*;
use clap::Parser;
use serde_json::json;
fn commands() -> Vec<Value> {
    let manifest = crate::full_manifest::FullManifest::new(
        crate::full_manifest::WorkloadSpec::full20x256_v1(),
        16,
    )
    .unwrap();
    (0..64).map(|id| {
        let op = manifest.operation(id).unwrap();
        let mut m = crate::measure::CommandMeasurement::new(&crate::measure::SamplePolicy::cli(op.cli_epoch, id), op.payload_bytes);
        m.command_success = true;
        m.child_exit_us = Some(2);
        json!({"exe":"C:/ordinary/client.exe","args":["ordinary"],"exit_code":0,"success":true,"child_exited":true,"capture_complete":true,"spawn_error":null,"capture_error":null,"kill_error":null,"wait_error":null,"stdout_overflow":false,"stderr_overflow":false,"timed_out":false,"stop_requested":false,"stdout_file":format!("C:/ordinary/full20x256-v1-op-{id}.stdout"),"stderr_file":format!("C:/ordinary/full20x256-v1-op-{id}.stderr"),"stderr":"","stdout": if id == 63 {json!({"sessions":18}).to_string()} else {json!({"inserted":op.inserted,"duplicates":op.duplicates}).to_string()}, "measurement":m, "elapsed_us":3})
    }).collect()
}
#[test]
fn exact_full64_final_correlation_rejects_missing_duplicate_reorder_and_leaf_drift() {
    let retained = commands();
    validate_final_commands(&retained, &retained).unwrap();
    assert!(validate_final_commands(&retained[..63], &retained).is_err());
    let mut reordered = retained.clone();
    reordered.swap(1, 2);
    assert!(validate_final_commands(&reordered, &retained).is_err());
    let mut duplicate = retained.clone();
    duplicate[63] = duplicate[62].clone();
    assert!(validate_final_commands(&duplicate, &retained).is_err());
    for id in 0..64 {
        let mut changed = retained.clone();
        changed[id]["elapsed_us"] = json!(4);
        assert!(validate_final_commands(&changed, &retained).is_err());
    }
}
#[test]
fn full_worker_report_binds_case_manifest_seed_namespace_before_final_equality() {
    let retained = commands();
    let worker=FullReport::from_observations(&json!({"pass":true,"commands":retained,"case_epoch":"ordinary","seed_records":16,"workload_complete":true}),false).unwrap();
    let original = serde_json::to_value(worker).unwrap();
    validate_report(&original, "ordinary", 16, &retained).unwrap();
    for field in [
        "case_epoch",
        "seed_records",
        "role",
        "workload_spec",
        "case",
    ] {
        let mut bad = original.clone();
        match field {
            "case_epoch" => bad[field] = json!("stale"),
            "seed_records" => {
                bad[field] = json!(17);
                bad["final_records"] = json!(5160)
            }
            "role" => bad[field] = json!("Controller"),
            "workload_spec" => bad[field]["schema"] = json!(2),
            _ => bad[field] = json!("old-case"),
        }
        assert!(
            validate_report(&bad, "ordinary", 16, &retained).is_err(),
            "accepted {field} drift"
        );
    }
}
#[test]
fn closed_full_job_is_bound_to_original_job_and_refuses_old_or_large_modes() {
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let case = ordinary_case(temp.path());
    let mut original = crate::contract::Job {
        client: case.install_root.join("bin/hermes-memory-client.exe"),
        enrollment: "Enrollment".into(),
        case,
        seed_records: 16,
        pilot: None,
    };
    let job = FullWorkloadJob {
        schema: 1,
        protocol: FullJobProtocol::Full20x256NativeJobV1,
        case_epoch: "ordinary".into(),
        fixture_spec: crate::data::FixtureSpec::representative_6_mib(),
        workload_spec: crate::full_manifest::WorkloadSpec::full20x256_v1(),
        seed_records: 16,
    };
    job.validate(&original).unwrap();
    original.seed_records = 17;
    assert!(job.validate(&original).is_err());
    original.seed_records = 16;
    original.pilot = Some(crate::contract::PilotJob {
        schema: 1,
        fixture_spec: crate::data::FixtureSpec::representative_6_mib(),
        epoch: "old".into(),
    });
    assert!(job.validate(&original).is_err());
    original.pilot = None;
    let valid = serde_json::to_value(&job).unwrap();
    for field in [
        "schema",
        "protocol",
        "case_epoch",
        "fixture_spec",
        "workload_spec",
        "seed_records",
    ] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<FullWorkloadJob>(missing).is_err());
    }
    for change in 0..4 {
        let mut bad = valid.clone();
        match change {
            0 => bad["schema"] = json!(2),
            1 => bad["case_epoch"] = json!(""),
            2 => bad["fixture_spec"]["target_jsonl_bytes"] = json!(629145600),
            _ => bad["seed_records"] = json!(17),
        }
        assert!(serde_json::from_value::<FullWorkloadJob>(bad)
            .unwrap()
            .validate(&original)
            .is_err());
    }
}
#[test]
fn full_report_reader_refuses_unclosed_namespace_before_correlation() {
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let path = temp.path().join("report.json");
    std::fs::write(
        &path,
        br#"{"schema":5,"case":"representative-6MiB-full20x256-v1","commands":[],"unknown":true}"#,
    )
    .unwrap();
    assert!(read_report(&path).is_err());
}
#[test]
fn controller_report_reservation_refuses_existing_output_and_never_retries_unknown_slot() {
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let path = temp.path().join("report.json");
    let reserved = reserve_report(&path).unwrap();
    assert!(!path.exists());
    drop(reserved);
    assert!(path.with_extension("full-attempt").exists());
    assert!(reserve_report(&path).is_err());
    let occupied = temp.path().join("occupied.json");
    std::fs::write(&occupied, b"sentinel").unwrap();
    assert!(reserve_report(&occupied).is_err());
    assert_eq!(std::fs::read(&occupied).unwrap(), b"sentinel");
    assert!(!occupied.with_extension("full-attempt").exists());
}
#[test]
fn full_report_refuses_correctness_from_unclosed_oracle_and_boundary_values() {
    // Synthetic negative input only; never native proof or published evidence.
    let retained = commands();
    let worker=FullReport::from_observations(&json!({"pass":true,"commands":retained,"case_epoch":"ordinary","seed_records":16,"workload_complete":true}),false).unwrap();
    let observed = json!({"pass":true,"client":worker,"generation":{"seed_records":16},"correctness_complete":true,"source_unchanged":true,"startup_import":{"records":5159},"final_payloads":{"records":5159},"export":{"records":5159,"sessions":18},"metrics":{"controller_retained_commands":retained,"operations":vec![json!("not a boundary");64],"native_handle_verified":false}});
    assert!(FullReport::from_observations(&observed, true).is_err());
}
#[test]
fn full_report_bounded_publication_has_closed_explicit_fields_and_no_clobber() {
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let path = temp.path().join("report.json");
    let mut report =
        FullReport::from_observations(&json!({"pass":false,"commands":[]}), false).unwrap();
    write_report_bounded(&path, &report).unwrap();
    let original = std::fs::read(&path).unwrap();
    assert!(read_report(&path).is_ok());
    assert!(write_report_bounded(&path, &report).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), original);
    let mut raw: Value = serde_json::from_slice(&original).unwrap();
    raw.as_object_mut().unwrap().remove("error");
    let absent = temp.path().join("absent-null.json");
    std::fs::write(&absent, serde_json::to_vec(&raw).unwrap()).unwrap();
    assert!(read_report(&absent).is_err());
    report.diagnostics = json!("x".repeat(16 * 1024 * 1024));
    let overflow = temp.path().join("overflow.json");
    assert!(write_report_bounded(&overflow, &report).is_err());
    assert!(!overflow.exists() && !overflow.with_extension("pending").exists());
}
#[test]
fn cleanup_and_report_failure_preserve_original_failure() {
    assert_eq!(
        preserve_primary(
            Err("primary unknown commit".into()),
            Err("secondary report sync".into())
        )
        .unwrap_err()
        .to_string(),
        "primary unknown commit"
    );
    assert_eq!(
        preserve_primary(Ok(()), Err("secondary stop".into()))
            .unwrap_err()
            .to_string(),
        "secondary stop"
    );
}
#[test]
fn explicit_full_selector_is_available_and_mutually_exclusive() {
    assert!(
        crate::Options::try_parse_from(["benchmark", "--representative-full-workload"]).is_ok()
    );
    for other in [
        "--representative-small-pilot",
        "--representative-two-warmup",
    ] {
        assert!(crate::Options::try_parse_from([
            "benchmark",
            "--representative-full-workload",
            other
        ])
        .is_err());
    }
}

use crate::{
    contract::CommandRequest,
    full_workload_receipt::Adapter,
    measure::{CommandMeasurement, LogicalIo, MemoryCoverage, SamplePolicy, Timepoint},
};
use std::{
    path::Path,
    time::{Duration, Instant},
};
fn measured_fixture(request: &CommandRequest<'_>, policy: &SamplePolicy, output: &Value) -> Value {
    let io = LogicalIo {
        read_operations: 1,
        write_operations: 2,
        other_operations: 3,
        read_bytes: 4,
        write_bytes: 5,
        other_bytes: 6,
    };
    let mut m = CommandMeasurement::new(policy, request.input.len() as u64);
    m.command_success = true;
    m.child_exit_us = Some(2);
    m.live_attempts = 1;
    m.live_samples = 1;
    m.first_sample_us = Some(1);
    m.last_sample_us = Some(1);
    m.memory = Some(MemoryCoverage {
        sampled_private_bytes: 1,
        sampled_working_set_bytes: 1,
        observed_lifetime_peak_private_bytes: 1,
        observed_lifetime_peak_working_set_bytes: 1,
    });
    m.timepoints.push(Timepoint {
        since_spawn_start_us: 1,
        logical_io: io,
        private_bytes: 1,
        working_set_bytes: 1,
        lifetime_peak_private_bytes: 1,
        lifetime_peak_working_set_bytes: 1,
    });
    m.final_lifetime_logical_io = Some(io);
    let prefix = request.directory.join(request.label);
    let value = json!({"exe":request.exe,"args":request.args,"exit_code":0,"success":true,"child_exited":true,"capture_complete":true,"spawn_error":null,"capture_error":null,"kill_error":null,"wait_error":null,"stdout_overflow":false,"stderr_overflow":false,"timed_out":false,"stop_requested":false,"elapsed_us":3,"stdout":output.to_string(),"stderr":"","stdout_file":prefix.with_extension("stdout"),"stderr_file":prefix.with_extension("stderr"),"measurement":m});
    for (ext,bytes) in [("stdin",request.input.to_vec()),("stdout",output.to_string().into_bytes()),("stderr",vec![]),("result.json",serde_json::to_vec(&value).unwrap()),("intent.json",serde_json::to_vec(&json!({"exe":request.exe,"args":request.args,"deadline_ms":request.timeout.as_millis(),"measurement_policy":policy})).unwrap())] { std::fs::write(prefix.with_extension(ext),bytes).unwrap(); }
    value
}

fn ordinary_case(root: &Path) -> crate::commands::Case {
    crate::commands::Case {
        legacy_root: root.join("seed/source"),
        install_root: root.join("install"),
        service_name: "unused".into(),
        client_sid: "unused".into(),
        broker_source: root.join("broker"),
        client_source: root.join("client"),
        broker_sha256: "a".repeat(64),
        client_sha256: "b".repeat(64),
        release_sha256: "c".repeat(64),
        default_enrollment: false,
    }
}
#[test]
fn shared_full64_orchestration_runs_real_store_and_retains_before_each_ack() {
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let root = temp.path();
    let generation = crate::data::generate_with_spec(
        &root.join("seed"),
        &crate::data::FixtureSpec::representative_6_mib(),
    )
    .unwrap();
    for dir in ["scratch", "controller"] {
        std::fs::create_dir(root.join(dir)).unwrap();
    }
    let case = ordinary_case(root);
    let manifest = crate::full_manifest::FullManifest::new(
        crate::full_manifest::WorkloadSpec::full20x256_v1(),
        generation["seed_records"].as_u64().unwrap(),
    )
    .unwrap();
    let store = hermes_memory::MemoryStore::open(root.join("install/store")).unwrap();
    store
        .import_logical_archive_once(
            std::io::BufReader::new(std::fs::File::open(root.join("seed/archive.jsonl")).unwrap()),
            generation["logical_sha256"].as_str().unwrap(),
        )
        .unwrap();
    store.prepare_export_index().unwrap();
    let adapter = Adapter {
        root,
        case: &case,
        enrollment: "Enrollment",
        epoch: "ordinary",
        timeout: Duration::from_secs(30),
        cancelled: crate::contract::never_cancel,
    };
    let mut commands = vec![];
    let mut retained = vec![];
    let mut boundaries = vec![];
    let mut calls = vec![];
    std::thread::scope(|scope| {
        let peer = scope.spawn(|| {
            execute_peer_with_runner(
                &adapter,
                &manifest,
                Instant::now() + Duration::from_secs(300),
                &mut commands,
                |request, policy| {
                    calls.push(policy.operation_id);
                    let output = match policy.operation_id {
                        0..=61 => {
                            let records: Vec<hermes_memory::MemoryRecord> =
                                serde_json::from_slice(request.input)?;
                            let (i, d) = store.ingest_many(&records)?;
                            json!({"inserted":i,"duplicates":d})
                        }
                        62 => {
                            let snapshot = serde_json::from_slice(request.input)?;
                            let (i, d) = store.ingest_snapshot(&snapshot)?;
                            json!({"inserted":i,"duplicates":d})
                        }
                        _ => {
                            let sessions = hermes_memory::client_export::render_markdown(
                                &root.join("scratch/export"),
                                crate::data::WORKSPACE,
                                |r| {
                                    store.export_page(r, "ordinary").map_err(|e| {
                                        hermes_memory::MemoryError::Io(std::io::Error::other(
                                            e.to_string(),
                                        ))
                                    })
                                },
                            )?;
                            json!({"sessions":sessions})
                        }
                    };
                    Ok(measured_fixture(request, policy, &output))
                },
            )
            .map_err(|e| e.to_string())
        });
        controller_intervals(
            &adapter,
            &manifest,
            &root.join("install/store/events.jsonl"),
            generation["jsonl_bytes"].as_u64().unwrap(),
            Instant::now() + Duration::from_secs(300),
            &mut retained,
            &mut boundaries,
            |id, after| {
                assert_eq!(
                    root.join(format!("scratch/full20x256-v1-op-{id}-done.json"))
                        .exists(),
                    after
                );
                assert!(!root
                    .join(format!(
                        "controller/full20x256-v1-op-{id}-validated-ack.json"
                    ))
                    .exists());
                Ok(Value::Null)
            },
        )
        .unwrap();
        peer.join().unwrap().unwrap();
    });
    assert_eq!(calls, (0..64).collect::<Vec<_>>());
    assert_eq!(boundaries.len(), 64);
    validate_final_commands(&commands, &retained).unwrap();
    drop(store);
    let projection = crate::full_oracles::verify_projection(
        &root.join("install/store/events.jsonl"),
        &root.join("seed/source/events.jsonl"),
        &manifest,
    )
    .unwrap();
    let imported = crate::full_oracles::verify_stopped_sqlite(
        &root.join("install/store/memory.db"),
        &generation,
        &manifest,
    )
    .unwrap();
    let exported = crate::full_oracles::verify_export(
        &root.join("scratch/export"),
        &root.join("seed/source/events.jsonl"),
        &manifest,
    )
    .unwrap();
    let worker=FullReport::from_observations(&json!({"pass":true,"commands":commands,"case_epoch":"ordinary","seed_records":generation["seed_records"],"workload_complete":true}),false).unwrap();
    let report=FullReport::from_observations(&json!({"pass":true,"client":worker,"generation":generation,"correctness_complete":true,"source_unchanged":true,"startup_import":imported,"final_payloads":projection,"export":exported,"metrics":{"controller_retained_commands":retained,"operations":boundaries,"native_handle_verified":false}}),true).unwrap();
    assert!(
        !report.native_handle_verified && !report.measurement_complete && !report.release_ready
    );
    let path = root.join("full-report.json");
    write_report_bounded(&path, &report).unwrap();
    let persisted = read_report(&path).unwrap();
    validate_final_commands(
        persisted["commands"].as_array().unwrap(),
        persisted["controller_retained_commands"]
            .as_array()
            .unwrap(),
    )
    .unwrap();
    let bytes = std::fs::metadata(root.join("install/store/events.jsonl"))
        .unwrap()
        .len();
    assert!(bytes > 8 * 1024 * 1024);
    println!("ordinary shared orchestration: operations={} additions={} seeds={} final_records={} projection_bytes={bytes} native_handle_verified=false",calls.len(),manifest.expected_additions(),generation["seed_records"],manifest.final_records());
}

#[test]
fn shared_peer_unknown_real_commit_has_no_done_or_retry() {
    use crate::full_workload_barrier::{FullBarrier, Phase, Role};
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let root = temp.path();
    for dir in ["scratch", "controller"] {
        std::fs::create_dir(root.join(dir)).unwrap();
    }
    let case = ordinary_case(root);
    let manifest = crate::full_manifest::FullManifest::new(
        crate::full_manifest::WorkloadSpec::full20x256_v1(),
        16,
    )
    .unwrap();
    let store = hermes_memory::MemoryStore::open(root.join("store")).unwrap();
    let adapter = Adapter {
        root,
        case: &case,
        enrollment: "Enrollment",
        epoch: "unknown",
        timeout: Duration::from_secs(1),
        cancelled: crate::contract::never_cancel,
    };
    let mut commands = vec![];
    let mut calls = 0;
    std::thread::scope(|scope| {
        let peer = scope.spawn(|| {
            execute_peer_with_runner(
                &adapter,
                &manifest,
                Instant::now() + Duration::from_secs(10),
                &mut commands,
                |request, _| {
                    calls += 1;
                    let records: Vec<hermes_memory::MemoryRecord> =
                        serde_json::from_slice(request.input)?;
                    store.ingest_many(&records)?;
                    Err("unknown real commit".into())
                },
            )
            .map_err(|e| e.to_string())
        });
        let mut controller =
            FullBarrier::new(root, "unknown", Role::Controller, &manifest).unwrap();
        controller
            .wait(
                0,
                Phase::Ready,
                Instant::now() + Duration::from_secs(5),
                || false,
                || {},
            )
            .unwrap();
        controller.publish(0, Phase::Release).unwrap();
        assert!(peer
            .join()
            .unwrap()
            .unwrap_err()
            .contains("unknown real commit"));
    });
    assert_eq!(calls, 1);
    assert!(commands.is_empty());
    assert!(root.join("scratch/full20x256-v1-op-0.attempt").exists());
    for path in [
        "scratch/full20x256-v1-op-0-done.json",
        "scratch/full20x256-v1-op-1-ready.json",
        "controller/full20x256-v1-op-0-validated-ack.json",
        "controller/full20x256-v1-op-1-release.json",
    ] {
        assert!(!root.join(path).exists());
    }
    assert!(execute_peer_with_runner(
        &adapter,
        &manifest,
        Instant::now() + Duration::from_secs(5),
        &mut commands,
        |_, _| {
            calls += 1;
            Err("retry forbidden".into())
        }
    )
    .is_err());
    assert_eq!(calls, 1);
}
#[test]
fn shared_controller_invalid_after_done_receipt_withholds_ack_and_next_release() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static STOP: AtomicBool = AtomicBool::new(false);
    fn cancelled() -> bool {
        STOP.load(Ordering::SeqCst)
    }
    STOP.store(false, Ordering::SeqCst);
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let root = temp.path();
    for dir in ["scratch", "controller"] {
        std::fs::create_dir(root.join(dir)).unwrap();
    }
    let case = ordinary_case(root);
    let manifest = crate::full_manifest::FullManifest::new(
        crate::full_manifest::WorkloadSpec::full20x256_v1(),
        16,
    )
    .unwrap();
    let store = hermes_memory::MemoryStore::open(root.join("store")).unwrap();
    let initial = std::fs::metadata(root.join("store/events.jsonl"))
        .unwrap()
        .len();
    let adapter = Adapter {
        root,
        case: &case,
        enrollment: "Enrollment",
        epoch: "invalid",
        timeout: Duration::from_secs(5),
        cancelled,
    };
    let mut commands = vec![];
    let mut retained = vec![];
    let mut boundaries = vec![];
    std::thread::scope(|scope| {
        let peer = scope.spawn(|| {
            execute_peer_with_runner(
                &adapter,
                &manifest,
                Instant::now() + Duration::from_secs(60),
                &mut commands,
                |request, policy| {
                    let records: Vec<hermes_memory::MemoryRecord> =
                        serde_json::from_slice(request.input)?;
                    let (i, d) = store.ingest_many(&records)?;
                    Ok(measured_fixture(
                        request,
                        policy,
                        &json!({"inserted":i,"duplicates":d}),
                    ))
                },
            )
            .map_err(|e| e.to_string())
        });
        let result = controller_intervals(
            &adapter,
            &manifest,
            &root.join("store/events.jsonl"),
            initial,
            Instant::now() + Duration::from_secs(60),
            &mut retained,
            &mut boundaries,
            |id, after| {
                if after && id == 21 {
                    let path = root
                        .join("scratch")
                        .join(crate::full_workload_receipt::label(id))
                        .with_extension("result.json");
                    let mut value: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
                    value["elapsed_us"] = json!(999);
                    std::fs::write(path, serde_json::to_vec(&value)?)?;
                }
                Ok(Value::Null)
            },
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("full measured result differs"));
        STOP.store(true, Ordering::SeqCst);
        assert!(peer.join().unwrap().is_err());
    });
    STOP.store(false, Ordering::SeqCst);
    assert_eq!(retained.len(), 21);
    assert_eq!(commands.len(), 22);
    assert!(!root
        .join("controller/full20x256-v1-op-21-validated-ack.json")
        .exists());
    assert!(!root
        .join("controller/full20x256-v1-op-22-release.json")
        .exists());
    assert!(!root.join("scratch/full20x256-v1-op-22-ready.json").exists());
}
#[test]
fn shared_peer_missing_release_never_invokes_runner() {
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let root = temp.path();
    for dir in ["scratch", "controller"] {
        std::fs::create_dir(root.join(dir)).unwrap();
    }
    let case = ordinary_case(root);
    let manifest = crate::full_manifest::FullManifest::new(
        crate::full_manifest::WorkloadSpec::full20x256_v1(),
        16,
    )
    .unwrap();
    let adapter = Adapter {
        root,
        case: &case,
        enrollment: "Enrollment",
        epoch: "missing",
        timeout: Duration::from_secs(1),
        cancelled: crate::contract::never_cancel,
    };
    let mut commands = vec![];
    let mut called = false;
    assert!(execute_peer_with_runner(
        &adapter,
        &manifest,
        Instant::now() + Duration::from_millis(50),
        &mut commands,
        |_, _| {
            called = true;
            Err("must not run".into())
        }
    )
    .is_err());
    assert!(!called && commands.is_empty());
    assert!(!root.join("scratch/full20x256-v1-op-0.attempt").exists());
}
