//! Synthetic ordinary fixtures only: NOT native measured execution proof.
use super::*;
use crate::measure::{LogicalIo, MemoryCoverage, Timepoint};
use serde_json::json;
fn ordinary_tempdir() -> tempfile::TempDir {
    tempfile::tempdir_in(std::env::var_os("TMPDIR").expect("Hermes scratch TMPDIR")).unwrap()
}
fn case(root: &Path) -> crate::commands::Case {
    crate::commands::Case {
        legacy_root: root.join("source"),
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
fn fixture(request: &CommandRequest<'_>, policy: &SamplePolicy, op: &Operation) -> Value {
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
    let output = if op.stage == Stage::Export {
        json!({"sessions":18})
    } else {
        json!({"inserted":op.inserted,"duplicates":op.duplicates})
    };
    let prefix = request.directory.join(request.label);
    let value = json!({"exe":request.exe,"args":request.args,"exit_code":0,"success":true,"child_exited":true,"capture_complete":true,"spawn_error":null,"capture_error":null,"kill_error":null,"wait_error":null,"stdout_overflow":false,"stderr_overflow":false,"timed_out":false,"stop_requested":false,"elapsed_us":3,"stdout":output.to_string(),"stderr":"","stdout_file":prefix.with_extension("stdout"),"stderr_file":prefix.with_extension("stderr"),"measurement":m});
    for (ext,bytes) in [("stdin",request.input.to_vec()),("stdout",output.to_string().into_bytes()),("stderr",vec![]),("result.json",serde_json::to_vec(&value).unwrap()),("intent.json",serde_json::to_vec(&json!({"exe":request.exe,"args":request.args,"deadline_ms":request.timeout.as_millis(),"measurement_policy":policy})).unwrap())] { std::fs::write(prefix.with_extension(ext),bytes).unwrap(); }
    value
}
#[test]
fn full_workload_receipt_all64_exact_actual_captures() {
    let temp = ordinary_tempdir();
    let root = temp.path();
    std::fs::create_dir(root.join("scratch")).unwrap();
    let c = case(root);
    let manifest =
        FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
    let adapter = Adapter {
        root,
        case: &c,
        enrollment: r"c:\Protected\Enrollment.json",
        epoch: "Case-Epoch",
        timeout: Duration::from_secs(1),
        cancelled: crate::contract::never_cancel,
    };
    for id in 0..64 {
        let op = manifest.operation(id).unwrap();
        let payload = manifest.payload(id).unwrap();
        let args = adapter.args(&op).unwrap();
        let mut expected_args: Vec<String> = vec![
            "--enrollment".into(),
            adapter.enrollment.into(),
            (if id == 62 {
                "snapshot"
            } else if id == 63 {
                "export"
            } else {
                "ingest"
            })
            .into(),
            "--root".into(),
            c.legacy_root.to_str().unwrap().into(),
        ];
        if id == 63 {
            expected_args.extend([
                "--workspace".into(),
                crate::data::WORKSPACE.into(),
                "--vault".into(),
                root.join("scratch").join("export").to_str().unwrap().into(),
            ]);
        }
        assert_eq!(args, expected_args);
        let exe = adapter.exe();
        let label = label(id);
        let directory = root.join("scratch");
        let request = adapter.request(&exe, &args, &payload, &label, &directory);
        let command = fixture(&request, &SamplePolicy::cli(op.cli_epoch, id), &op);
        let receipt = Receipt {
            schema: 1,
            protocol: Protocol::Full20x256ReceiptV1,
            case_epoch: adapter.epoch.into(),
            command_label: label,
            operation_id: id,
            cli_epoch: op.cli_epoch,
            payload: payload.clone(),
            command: serde_json::from_value(command).unwrap(),
        };
        let ack = adapter
            .validate(&manifest, &op, &payload, &receipt)
            .unwrap();
        assert_eq!(ack.operation_id, id);
        assert_eq!(ack.sessions, op.sessions);
    }
}
#[test]
fn full_workload_receipt_execute_once_persist_no_clobber() {
    let temp = ordinary_tempdir();
    let root = temp.path();
    std::fs::create_dir(root.join("scratch")).unwrap();
    let c = case(root);
    let manifest =
        FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
    let a = Adapter {
        root,
        case: &c,
        enrollment: "Enrollment.json",
        epoch: "Case",
        timeout: Duration::from_secs(1),
        cancelled: crate::contract::never_cancel,
    };
    let op = manifest.operation(0).unwrap();
    let payload = manifest.payload(0).unwrap();
    let mut calls = 0;
    a.execute(
        &manifest,
        &op,
        &payload,
        Instant::now() + Duration::from_secs(5),
        |r, p| {
            calls += 1;
            Ok(fixture(r, p, &op))
        },
    )
    .unwrap();
    assert_eq!(calls, 1);
    let bytes = std::fs::read(a.receipt_path(0)).unwrap();
    let receipt: Receipt = decode(&bytes).unwrap();
    a.validate(&manifest, &op, &payload, &receipt).unwrap();
    assert!(a
        .execute(
            &manifest,
            &op,
            &payload,
            Instant::now() + Duration::from_secs(5),
            |_, _| {
                calls += 1;
                Err("must not run".into())
            }
        )
        .is_err());
    assert_eq!(calls, 1);
    assert_eq!(std::fs::read(a.receipt_path(0)).unwrap(), bytes);
}

#[test]
fn full_workload_receipt_controller_retains_full_command_before_ack() {
    use crate::full_workload_barrier::{FullBarrier, Phase, Role};
    let temp = ordinary_tempdir();
    let root = temp.path();
    for dir in ["scratch", "controller"] {
        std::fs::create_dir(root.join(dir)).unwrap();
    }
    let c = case(root);
    let m = FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
    let a = Adapter {
        root,
        case: &c,
        enrollment: "Enrollment",
        epoch: "Case",
        timeout: Duration::from_secs(1),
        cancelled: crate::contract::never_cancel,
    };
    let op = m.operation(0).unwrap();
    let payload = m.payload(0).unwrap();
    let mut peer = FullBarrier::new(root, "Case", Role::Peer, &m).unwrap();
    let mut controller = FullBarrier::new(root, "Case", Role::Controller, &m).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    peer.publish(0, Phase::Ready).unwrap();
    controller
        .wait(0, Phase::Ready, deadline, || false, || {})
        .unwrap();
    controller.publish(0, Phase::Release).unwrap();
    peer.wait(0, Phase::Release, deadline, || false, || {})
        .unwrap();
    a.execute(&m, &op, &payload, deadline, |r, p| Ok(fixture(r, p, &op)))
        .unwrap();
    peer.publish(0, Phase::Done).unwrap();
    controller
        .wait(0, Phase::Done, deadline, || false, || {})
        .unwrap();
    let mut retained = vec![];
    a.acknowledge(&mut controller, &m, 0, &mut retained, deadline)
        .unwrap();
    assert_eq!(retained.len(), 1);
    let disk: Receipt = decode(&std::fs::read(a.receipt_path(0)).unwrap()).unwrap();
    assert_eq!(retained[0], serde_json::to_value(disk.command).unwrap());
    assert!(root
        .join("controller/full20x256-v1-op-0-validated-ack.json")
        .exists());
    peer.wait(0, Phase::ValidatedAck, deadline, || false, || {})
        .unwrap();
}

fn with_one(test: impl FnOnce(&Adapter<'_>, &FullManifest, &Operation, &[u8], &Receipt)) {
    with_operation(22, test);
}
fn with_operation(
    id: u32,
    test: impl FnOnce(&Adapter<'_>, &FullManifest, &Operation, &[u8], &Receipt),
) {
    let temp = ordinary_tempdir();
    let root = temp.path();
    std::fs::create_dir(root.join("scratch")).unwrap();
    let c = case(root);
    let m = FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
    let a = Adapter {
        root,
        case: &c,
        enrollment: r"c:\Protected\Enrollment.json",
        epoch: "Case-Epoch",
        timeout: Duration::from_secs(1),
        cancelled: crate::contract::never_cancel,
    };
    let op = m.operation(id).unwrap();
    let payload = m.payload(id).unwrap();
    let args = a.args(&op).unwrap();
    let exe = a.exe();
    let name = label(op.id);
    let directory = root.join("scratch");
    let request = a.request(&exe, &args, &payload, &name, &directory);
    let command = fixture(&request, &SamplePolicy::cli(op.cli_epoch, op.id), &op);
    let receipt = Receipt {
        schema: 1,
        protocol: Protocol::Full20x256ReceiptV1,
        case_epoch: a.epoch.into(),
        command_label: name,
        operation_id: op.id,
        cli_epoch: op.cli_epoch,
        payload: payload.clone(),
        command: serde_json::from_value(command).unwrap(),
    };
    a.validate(&m, &op, &payload, &receipt).unwrap();
    test(&a, &m, &op, &payload, &receipt);
}
#[test]
fn full_workload_receipt_independent_exact_correlation_mutations() {
    with_one(|a, m, op, payload, r| {
        let original = serde_json::to_value(r).unwrap();
        for (pointer, new) in [
            ("/schema", json!(2)),
            ("/case_epoch", json!("case-epoch")),
            ("/command_label", json!("full20x256-v1-op-23")),
            ("/operation_id", json!(23)),
            ("/cli_epoch", json!(26)),
            ("/payload/0", json!(0)),
            (
                "/command/exe",
                json!(a.exe().to_str().unwrap().to_lowercase()),
            ),
            ("/command/args/1", json!("C:\\Protected\\Enrollment.json")),
            ("/command/args/2", json!("snapshot")),
            (
                "/command/stdout_file",
                json!(a.root.join("controller").join("full20x256-v1-op-22.stdout")),
            ),
            (
                "/command/stderr_file",
                json!(a.root.join("scratch").join("full20x256-v1-op-21.stderr")),
            ),
            ("/command/exit_code", json!(1)),
            ("/command/success", json!(false)),
            ("/command/child_exited", json!(false)),
            ("/command/capture_complete", json!(false)),
            ("/command/timed_out", json!(true)),
            ("/command/stop_requested", json!(true)),
            ("/command/stdout_overflow", json!(true)),
            ("/command/stderr_overflow", json!(true)),
            ("/command/spawn_error", json!("spawn")),
            ("/command/capture_error", json!("capture")),
            ("/command/kill_error", json!("kill")),
            ("/command/wait_error", json!("wait")),
            ("/command/measurement/identity/role", json!("broker-c")),
            ("/command/measurement/identity/epoch", json!(3)),
            ("/command/measurement/operation_id", json!(0)),
            ("/command/measurement/payload_bytes", json!(1)),
            ("/command/measurement/command_success", json!(false)),
            ("/command/measurement/child_exit_us", Value::Null),
            (
                "/command/measurement/final_lifetime_logical_io",
                Value::Null,
            ),
            ("/command/measurement/final_io_error", json!("bad")),
            ("/command/measurement/live_attempts", json!(0)),
            (
                "/command/measurement/timepoints/0/logical_io/read_bytes",
                json!(99),
            ),
            (
                "/command/stdout",
                json!("{\"inserted\":0,\"duplicates\":256}"),
            ),
            (
                "/command/stdout",
                json!("{\"inserted\":256,\"duplicates\":0,\"extra\":0}"),
            ),
            (
                "/command/stdout",
                json!("{\"inserted\":256,\"inserted\":256,\"duplicates\":0}"),
            ),
            (
                "/command/stdout",
                json!("{\"inserted\":256.0,\"duplicates\":0}"),
            ),
        ] {
            let mut bad = original.clone();
            *bad.pointer_mut(pointer).unwrap() = new;
            let r: Receipt = decode(&serde_json::to_vec(&bad).unwrap()).unwrap();
            assert!(
                a.validate(m, op, payload, &r).is_err(),
                "accepted {pointer}: {bad}"
            );
        }
        for change in 0..3 {
            let mut bad = original.clone();
            let args = bad["command"]["args"].as_array_mut().unwrap();
            match change {
                0 => {
                    args.pop();
                }
                1 => args.push(json!("--extra")),
                _ => args.swap(0, 2),
            }
            let r: Receipt = decode(&serde_json::to_vec(&bad).unwrap()).unwrap();
            assert!(a.validate(m, op, payload, &r).is_err());
        }
        let mut wrong = op.clone();
        wrong.appended_jsonl_bytes += 1;
        assert!(a.validate(m, &wrong, payload, r).is_err());
    });
}
#[test]
fn full_workload_receipt_closed_schema_independent_wire_mutations() {
    with_one(|_, _, _, _, r| {
        let original = serde_json::to_value(r).unwrap();
        fn walk(value: &Value, prefix: String, paths: &mut Vec<String>) {
            if let Value::Object(map) = value {
                for (k, v) in map {
                    let path = format!("{prefix}/{k}");
                    paths.push(path.clone());
                    walk(v, path, paths);
                }
            } else if let Value::Array(values) = value {
                if !prefix.ends_with("payload") {
                    for (i, v) in values.iter().enumerate() {
                        walk(v, format!("{prefix}/{i}"), paths);
                    }
                }
            }
        }
        let mut paths = vec![];
        walk(&original, String::new(), &mut paths);
        for path in paths {
            let (parent, key) = path.rsplit_once('/').unwrap();
            let mut bad = original.clone();
            bad.pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert!(
                decode::<Receipt>(&serde_json::to_vec(&bad).unwrap()).is_err(),
                "missing accepted {path}"
            );
            let mut bad = original.clone();
            *bad.pointer_mut(&path).unwrap() = json!({"unknown":true});
            assert!(
                decode::<Receipt>(&serde_json::to_vec(&bad).unwrap()).is_err(),
                "wrong type accepted {path}"
            );
        }
        for parent in [
            "",
            "/command",
            "/command/measurement",
            "/command/measurement/identity",
            "/command/measurement/memory",
            "/command/measurement/timepoints/0",
            "/command/measurement/final_lifetime_logical_io",
        ] {
            let mut bad = original.clone();
            bad.pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unknown".into(), json!(0));
            assert!(decode::<Receipt>(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        let bytes = serde_json::to_string(&original).unwrap();
        let duplicate = bytes.replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1);
        assert!(decode::<Receipt>(duplicate.as_bytes()).is_err());
        for replacement in ["-1", "18446744073709551616", "1.0", "true", "\"1\""] {
            let bad = bytes.replacen(
                "\"operation_id\":22",
                &format!("\"operation_id\":{replacement}"),
                1,
            );
            assert!(decode::<Receipt>(bad.as_bytes()).is_err());
        }
    });
}
#[test]
fn full_workload_receipt_full_result_and_capture_drift_refused() {
    with_one(|a, m, op, payload, r| {
        let prefix = a.root.join("scratch").join(label(op.id));
        let original = serde_json::to_value(&r.command).unwrap();
        // Full equality catches even semantically valid independent drift in
        // elapsed/counters/memory/formatting, not just the manifest ACK fields.
        for (pointer, new) in [
            ("/elapsed_us", json!(4)),
            (
                "/measurement/final_lifetime_logical_io/other_bytes",
                json!(7),
            ),
            ("/measurement/memory/sampled_private_bytes", json!(2)),
            ("/stdout", json!("{ \"inserted\":256, \"duplicates\":0 }")),
            ("/stderr", json!("warning")),
        ] {
            let mut disk = original.clone();
            *disk.pointer_mut(pointer).unwrap() = new;
            std::fs::write(
                prefix.with_extension("result.json"),
                serde_json::to_vec(&disk).unwrap(),
            )
            .unwrap();
            assert!(
                a.validate(m, op, payload, r).is_err(),
                "full equality omitted {pointer}"
            );
        }
        std::fs::write(
            prefix.with_extension("result.json"),
            serde_json::to_vec(&original).unwrap(),
        )
        .unwrap();
        for ext in ["stdin", "stdout", "stderr", "intent.json"] {
            let path = prefix.with_extension(ext);
            let bytes = std::fs::read(&path).unwrap();
            std::fs::write(&path, b"different").unwrap();
            assert!(
                a.validate(m, op, payload, r).is_err(),
                "capture drift {ext}"
            );
            std::fs::write(path, bytes).unwrap();
        }
        let mut missing = original.clone();
        missing["measurement"]
            .as_object_mut()
            .unwrap()
            .remove("final_io_error");
        std::fs::write(
            prefix.with_extension("result.json"),
            serde_json::to_vec(&missing).unwrap(),
        )
        .unwrap();
        assert!(a.validate(m, op, payload, r).is_err());
    });
}
#[test]
fn full_workload_receipt_all64_execute_done_retain_ack() {
    use crate::full_workload_barrier::{FullBarrier, Phase, Role};
    let temp = ordinary_tempdir();
    let root = temp.path();
    for dir in ["scratch", "controller"] {
        std::fs::create_dir(root.join(dir)).unwrap();
    }
    let c = case(root);
    let m = FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
    let a = Adapter {
        root,
        case: &c,
        enrollment: "Enrollment",
        epoch: "Case",
        timeout: Duration::from_secs(1),
        cancelled: crate::contract::never_cancel,
    };
    let mut peer = FullBarrier::new(root, "Case", Role::Peer, &m).unwrap();
    let mut controller = FullBarrier::new(root, "Case", Role::Controller, &m).unwrap();
    let mut retained = vec![];
    let mut calls = [0; 64];
    for id in 0..64 {
        let deadline = Instant::now() + Duration::from_secs(10);
        let op = m.operation(id).unwrap();
        let payload = m.payload(id).unwrap();
        peer.publish(id, Phase::Ready).unwrap();
        controller
            .wait(id, Phase::Ready, deadline, || false, || {})
            .unwrap();
        controller.publish(id, Phase::Release).unwrap();
        peer.wait(id, Phase::Release, deadline, || false, || {})
            .unwrap();
        a.execute(&m, &op, &payload, deadline, |r, p| {
            calls[id as usize] += 1;
            Ok(fixture(r, p, &op))
        })
        .unwrap();
        assert!(a.receipt_path(id).exists());
        peer.publish(id, Phase::Done).unwrap();
        controller
            .wait(id, Phase::Done, deadline, || false, || {})
            .unwrap();
        assert!(!root
            .join("controller")
            .join(format!("{}-validated-ack.json", label(id)))
            .exists());
        if id < 63 {
            assert!(controller.publish(id + 1, Phase::Release).is_err());
            assert!(peer.publish(id + 1, Phase::Ready).is_err());
        }
        a.acknowledge(&mut controller, &m, id, &mut retained, deadline)
            .unwrap();
        assert_eq!(retained.len(), id as usize + 1);
        peer.wait(id, Phase::ValidatedAck, deadline, || false, || {})
            .unwrap();
    }
    assert_eq!(calls, [1; 64]);
    assert!(peer.complete() && controller.complete());
    assert_eq!(retained.len(), 64);
}

#[test]
fn full_workload_receipt_unknown_commit_blocks_done_ack_retry() {
    use crate::full_workload_barrier::{run_peer, FullBarrier, Phase, Role};
    let temp = ordinary_tempdir();
    let root = temp.path();
    for dir in ["scratch", "controller"] {
        std::fs::create_dir(root.join(dir)).unwrap();
    }
    let c = case(root);
    let m = FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
    let a = Adapter {
        root,
        case: &c,
        enrollment: "Enrollment",
        epoch: "Case",
        timeout: Duration::from_secs(1),
        cancelled: crate::contract::never_cancel,
    };
    let mut calls = 0;
    std::thread::scope(|scope| {
        let child = scope.spawn(|| {
            run_peer(
                root,
                "Case",
                &m,
                Instant::now() + Duration::from_secs(10),
                || false,
                |op, payload| {
                    a.execute(
                        &m,
                        op,
                        payload,
                        Instant::now() + Duration::from_secs(5),
                        |_, _| {
                            calls += 1;
                            Err("unknown commit".into())
                        },
                    )
                },
                |_, _| {},
            )
            .map_err(|e| e.to_string())
        });
        let mut controller = FullBarrier::new(root, "Case", Role::Controller, &m).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        controller
            .wait(0, Phase::Ready, deadline, || false, || {})
            .unwrap();
        controller.publish(0, Phase::Release).unwrap();
        assert!(child
            .join()
            .unwrap()
            .unwrap_err()
            .contains("unknown commit"));
        assert!(controller.publish(1, Phase::Release).is_err());
    });
    assert_eq!(calls, 1);
    for path in [
        "scratch/full20x256-v1-op-0-done.json",
        "controller/full20x256-v1-op-0-validated-ack.json",
        "scratch/full20x256-v1-op-1-ready.json",
    ] {
        assert!(!root.join(path).exists());
    }
    assert!(!a.receipt_path(0).exists());
    assert!(root.join("scratch/full20x256-v1-op-0.attempt").exists());
    let op = m.operation(0).unwrap();
    assert!(a
        .execute(
            &m,
            &op,
            &m.payload(0).unwrap(),
            Instant::now() + Duration::from_secs(5),
            |_, _| {
                calls += 1;
                Err("retry forbidden".into())
            }
        )
        .is_err());
    assert_eq!(calls, 1);
}
thread_local! { static STOP:std::cell::Cell<bool>=const {std::cell::Cell::new(false)}; }
fn stopped() -> bool {
    STOP.with(|s| s.get())
}
#[test]
fn full_workload_receipt_cancelled_runner_no_receipt_or_retry() {
    with_one(|a, m, _, _, _| {
        let a = Adapter {
            cancelled: stopped,
            ..*a
        };
        let op = m.operation(0).unwrap();
        let payload = m.payload(0).unwrap();
        let mut calls = 0;
        let result = a.execute(
            m,
            &op,
            &payload,
            Instant::now() + Duration::from_secs(5),
            |r, p| {
                calls += 1;
                let value = fixture(r, p, &op);
                STOP.with(|s| s.set(true));
                Ok(value)
            },
        );
        STOP.with(|s| s.set(false));
        assert!(result.is_err());
        assert_eq!(calls, 1);
        assert!(!a.receipt_path(0).exists());
        assert!(a
            .execute(
                m,
                &op,
                &payload,
                Instant::now() + Duration::from_secs(5),
                |_, _| {
                    calls += 1;
                    Err("retry".into())
                }
            )
            .is_err());
        assert_eq!(calls, 1);
    });
}
#[test]
fn full_workload_receipt_preflight_refuses_before_runner() {
    with_one(|a, m, _, _, _| {
        let op = m.operation(0).unwrap();
        let payload = m.payload(0).unwrap();
        let mut calls = 0;
        let bad = Adapter {
            timeout: Duration::ZERO,
            ..*a
        };
        assert!(bad
            .execute(
                m,
                &op,
                &payload,
                Instant::now() + Duration::from_secs(5),
                |_, _| {
                    calls += 1;
                    Err("not run".into())
                }
            )
            .is_err());
        assert!(a
            .execute(
                m,
                &op,
                b"wrong",
                Instant::now() + Duration::from_secs(5),
                |_, _| {
                    calls += 1;
                    Err("not run".into())
                }
            )
            .is_err());
        assert!(a
            .execute(m, &op, &payload, Instant::now(), |_, _| {
                calls += 1;
                Err("not run".into())
            })
            .is_err());
        assert!(a
            .execute(
                m,
                &op,
                &payload,
                Instant::now() + Duration::from_millis(100),
                |_, _| {
                    calls += 1;
                    Err("not run".into())
                }
            )
            .is_err());
        for ext in ["stdin", "stdout", "stderr", "intent.json", "result.json"] {
            let path = a.root.join("scratch").join(label(0)).with_extension(ext);
            std::fs::write(&path, b"sentinel").unwrap();
            assert!(a
                .execute(
                    m,
                    &op,
                    &payload,
                    Instant::now() + Duration::from_secs(5),
                    |_, _| {
                        calls += 1;
                        Err("not run".into())
                    }
                )
                .is_err());
            assert_eq!(std::fs::read(&path).unwrap(), b"sentinel");
            std::fs::remove_file(&path).unwrap();
        }
        assert_eq!(calls, 0);
    });
}
#[test]
fn full_workload_receipt_controller_invalid_actual_withholds_ack() {
    use crate::full_workload_barrier::{FullBarrier, Phase, Role};
    let temp = ordinary_tempdir();
    let root = temp.path();
    for dir in ["scratch", "controller"] {
        std::fs::create_dir(root.join(dir)).unwrap();
    }
    let c = case(root);
    let m = FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
    let a = Adapter {
        root,
        case: &c,
        enrollment: "Enrollment",
        epoch: "Case",
        timeout: Duration::from_secs(1),
        cancelled: crate::contract::never_cancel,
    };
    let mut peer = FullBarrier::new(root, "Case", Role::Peer, &m).unwrap();
    let mut controller = FullBarrier::new(root, "Case", Role::Controller, &m).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    peer.publish(0, Phase::Ready).unwrap();
    controller
        .wait(0, Phase::Ready, deadline, || false, || {})
        .unwrap();
    controller.publish(0, Phase::Release).unwrap();
    peer.wait(0, Phase::Release, deadline, || false, || {})
        .unwrap();
    let op = m.operation(0).unwrap();
    a.execute(&m, &op, &m.payload(0).unwrap(), deadline, |r, p| {
        Ok(fixture(r, p, &op))
    })
    .unwrap();
    peer.publish(0, Phase::Done).unwrap();
    controller
        .wait(0, Phase::Done, deadline, || false, || {})
        .unwrap();
    let result = root
        .join("scratch")
        .join(label(0))
        .with_extension("result.json");
    let mut bad: Value = serde_json::from_slice(&std::fs::read(&result).unwrap()).unwrap();
    bad["elapsed_us"] = json!(4);
    std::fs::write(result, serde_json::to_vec(&bad).unwrap()).unwrap();
    let mut retained = vec![];
    assert!(a
        .acknowledge(&mut controller, &m, 0, &mut retained, deadline)
        .is_err());
    assert!(retained.is_empty());
    assert!(!root
        .join("controller/full20x256-v1-op-0-validated-ack.json")
        .exists());
    assert!(controller.publish(1, Phase::Release).is_err());
    assert!(peer.publish(1, Phase::Ready).is_err());
}
#[test]
fn full_workload_receipt_persist_no_clobber_destination_pending_competitors() {
    with_one(|a, _, _, _, r| {
        let destination = a.root.join("receipt.json");
        std::fs::write(&destination, b"sentinel").unwrap();
        assert!(persist(&destination, r).is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"sentinel");
        assert!(destination.with_extension("pending").exists());
        let destination = a.root.join("occupied.json");
        std::fs::write(destination.with_extension("pending"), b"pending-sentinel").unwrap();
        assert!(persist(&destination, r).is_err());
        assert_eq!(
            std::fs::read(destination.with_extension("pending")).unwrap(),
            b"pending-sentinel"
        );
        assert!(!destination.exists());
        let destination = a.root.join("competing.json");
        let bytes = serde_json::to_vec(r).unwrap();
        let wins = std::thread::scope(|scope| {
            let jobs: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        let receipt: Receipt = decode(&bytes).unwrap();
                        persist(&destination, &receipt).is_ok()
                    })
                })
                .collect();
            jobs.into_iter()
                .map(|job| job.join().unwrap())
                .filter(|won| *won)
                .count()
        });
        assert_eq!(wins, 1);
        assert_eq!(std::fs::read(&destination).unwrap(), bytes);
        assert_eq!(
            std::fs::read(destination.with_extension("pending")).unwrap(),
            bytes
        );
    });
}
#[test]
fn full_workload_receipt_bounded_regular_reads_and_capture_overflow() {
    with_one(|a, m, op, payload, r| {
        let path = a.root.join("read-bound");
        std::fs::write(&path, b"12345").unwrap();
        assert_eq!(read_bounded(&path, 5).unwrap(), b"12345");
        assert!(read_bounded(&path, 4).is_err());
        assert!(read_bounded(a.root, 100).is_err());
        assert!(read_bounded(&a.root.join("absent"), 100).is_err());
        let prefix = a.root.join("scratch").join(label(op.id));
        let path = prefix.with_extension("stderr");
        std::fs::write(path, vec![0; 1024 * 1024 + 1]).unwrap();
        assert!(a.validate(m, op, payload, r).is_err());
    });
}

#[test]
fn full_workload_receipt_late_cooperative_runner_refused_without_retry() {
    with_one(|a, m, _, _, _| {
        let a = Adapter {
            timeout: Duration::from_millis(5),
            ..*a
        };
        let op = m.operation(0).unwrap();
        let payload = m.payload(0).unwrap();
        let mut calls = 0;
        let result = a.execute(
            m,
            &op,
            &payload,
            Instant::now() + Duration::from_secs(5),
            |r, p| {
                calls += 1;
                let value = fixture(r, p, &op);
                std::thread::sleep(Duration::from_millis(20));
                Ok(value)
            },
        );
        assert!(
            result.is_err(),
            "late runner accepted despite request timeout"
        );
        assert_eq!(calls, 1);
        assert!(!a.receipt_path(0).exists());
        assert!(a
            .execute(
                m,
                &op,
                &payload,
                Instant::now() + Duration::from_secs(5),
                |_, _| {
                    calls += 1;
                    Err("retry".into())
                }
            )
            .is_err());
        assert_eq!(calls, 1);
    });
}
#[test]
fn full_workload_receipt_serialization_caps_before_file_creation() {
    assert_eq!(encode_bounded(&json!("abc"), 5).unwrap(), b"\"abc\"");
    assert!(encode_bounded(&json!("abc"), 4).is_err());
    // Escaping is part of cap accounting, not just unescaped field length.
    assert!(encode_bounded(&json!("\n\n"), 4).is_err());
}
#[test]
fn full_workload_receipt_cap_plus_one_after_metadata_growth_same_handle() {
    struct Counted {
        read: usize,
    }
    impl Read for Counted {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            buffer.fill(0);
            self.read += buffer.len();
            Ok(buffer.len())
        }
    }
    let mut reader = Counted { read: 0 };
    assert!(read_capped(&mut reader, 4).is_err());
    assert_eq!(reader.read, 5);
    let temp = ordinary_tempdir();
    let path = temp.path().join("grown");
    std::fs::write(&path, b"1234").unwrap();
    let file = std::fs::File::open(&path).unwrap();
    assert_eq!(file.metadata().unwrap().len(), 4);
    std::fs::write(&path, b"12345").unwrap();
    assert!(read_capped(file, 4).is_err());
}

#[test]
fn full_workload_receipt_every_actual_command_leaf_independently_bound() {
    with_one(|a, m, op, payload, r| {
        let original = serde_json::to_value(&r.command).unwrap();
        fn leaves(v: &Value, prefix: String, out: &mut Vec<String>) {
            match v {
                Value::Object(map) => {
                    for (k, v) in map {
                        leaves(v, format!("{prefix}/{k}"), out)
                    }
                }
                Value::Array(values) => {
                    if values.is_empty() {
                        out.push(prefix)
                    } else {
                        for (i, v) in values.iter().enumerate() {
                            leaves(v, format!("{prefix}/{i}"), out)
                        }
                    }
                }
                _ => out.push(prefix),
            }
        }
        let mut paths = vec![];
        leaves(&original, String::new(), &mut paths);
        let result = a
            .root
            .join("scratch")
            .join(label(op.id))
            .with_extension("result.json");
        for path in paths {
            let mut bad = original.clone();
            let old = bad.pointer_mut(&path).unwrap();
            *old = match old {
                Value::Bool(v) => json!(!*v),
                Value::Number(n) => json!(n.as_u64().unwrap() + 1),
                Value::String(s) => json!(format!("{s}-drift")),
                Value::Null => json!("error"),
                Value::Array(_) => json!([0]),
                _ => panic!("not a leaf"),
            };
            std::fs::write(&result, serde_json::to_vec(&bad).unwrap()).unwrap();
            assert!(
                a.validate(m, op, payload, r).is_err(),
                "actual command leaf not bound: {path}"
            );
        }
    });
}
#[test]
fn full_workload_receipt_every_stage_semantics_not_counts_regenerated_from_manifest() {
    for id in [0, 2, 22, 42, 62, 63] {
        with_operation(id, |a, m, op, payload, r| {
            let original = serde_json::to_value(r).unwrap();
            let bad_outputs = if id == 63 {
                vec![
                    json!({"inserted":0,"duplicates":0}),
                    json!({"sessions":17}),
                    json!({"sessions":18,"records":999}),
                    json!({"sessions":"18"}),
                ]
            } else {
                vec![
                    json!({"sessions":18}),
                    json!({"inserted":op.inserted+1,"duplicates":op.duplicates}),
                    json!({"inserted":op.inserted,"duplicates":op.duplicates+1}),
                    json!({"inserted":op.inserted,"duplicates":op.duplicates,"extra":true}),
                ]
            };
            for output in bad_outputs {
                let mut bad = original.clone();
                bad["command"]["stdout"] = json!(output.to_string());
                let receipt: Receipt = decode(&serde_json::to_vec(&bad).unwrap()).unwrap();
                let prefix = a.root.join("scratch").join(label(id));
                std::fs::write(prefix.with_extension("stdout"), output.to_string()).unwrap();
                std::fs::write(
                    prefix.with_extension("result.json"),
                    serde_json::to_vec(&bad["command"]).unwrap(),
                )
                .unwrap();
                assert!(
                    a.validate(m, op, payload, &receipt).is_err(),
                    "accepted stage output {id}: {output}"
                );
            }
        });
    }
}
