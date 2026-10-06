//! Ordinary tests only. No installed subprocess or lifecycle acquisition.
use super::*;
use clap::Parser;
use serde_json::json;

fn cadence_omitted_complete_fixture() -> Cadence {
    let mut c = Cadence::new("ordinary", 0, 3);
    for i in 0..16 {
        let t = if i == 0 { 0 } else { i * 2000 + 4 };
        if i == 1 {
            c.release_begin_us = Some(4);
            c.release_end_us = Some(4);
        }
        if i == 15 {
            c.done_validated_us = Some(t);
        }
        let slot = if i > 0 && i < 15 {
            c.due(t).unwrap()
        } else {
            None
        };
        c.record_pair(
            slot,
            i == 0,
            i == 15,
            [
                (t, t + 1, Ok(cadence_read(CadenceRole::SupervisorB, i + 1))),
                (t + 2, t + 3, Ok(cadence_read(CadenceRole::BrokerC, i + 1))),
            ],
        )
        .unwrap();
    }
    c.finish(30008).unwrap();
    c.validate("ordinary", 0, 3).unwrap();
    c
}
fn cadence_negative_report(mut c: Cadence) -> FullReport {
    if let Some(stop) = c.state.terminal.clone() {
        if !c.state.primary_finalized {
            let outcome = if matches!(stop.action, OperationAction::Gate(_)) {
                FailureObservation::AdmissionStopped
            } else {
                FailureObservation::ReturnedError
            };
            transition(&mut c.state, Transition::PrimaryStop(stop.primary, outcome)).unwrap();
        }
    }
    let case_stop = c.state.terminal.as_ref().map(|stop| CaseStop {
        position: 0,
        acknowledged_prefix: 0,
        cause: CaseStopCause::Operation(stop.stage),
        primary: stop.primary.clone(),
    });
    let manifest =
        FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
    let boundary = BoundaryEvidence {
        operation_id: 0,
        cli_epoch: 3,
        descriptor: Descriptor::from_operation(&manifest.operation(0).unwrap()),
        before_release: serde_json::from_value(boundary_observation(&c, false).unwrap()).unwrap(),
        after_done: serde_json::from_value(boundary_observation(&c, true).unwrap()).unwrap(),
        receipt_validated: c.failure.is_none(),
        exact_append_verified: c.failure.is_none(),
        cadence: c,
    };
    let mut report =
        FullReport::from_observations(&json!({"pass":false,"commands":[]}), false).unwrap();
    report.role = ReportRole::Controller;
    report.case_epoch = Some("ordinary".into());
    report.seed_records = Some(16);
    report.final_records = Some(5159);
    report.operations = Some(vec![boundary]);
    report.error = case_stop.as_ref().map(|stop| stop.primary.clone());
    report.case_stop = case_stop;
    report
}
#[test]
fn cadence_review_balanced_omitted_failures_cannot_complete_or_publish() {
    let original = cadence_omitted_complete_fixture();
    for role in 0..2 {
        for failure in 0..4 {
            let mut c = original.clone();
            let r = if role == 0 {
                &mut c.supervisor
            } else {
                &mut c.broker
            };
            r.successful_live_samples -= 1;
            r.omitted_points -= 1;
            if failure == 3 {
                r.attempts -= 1;
                r.not_attempted_due_to_abort += 1;
            } else {
                let kind = match failure {
                    0 => {
                        r.query_errors += 1;
                        "query"
                    }
                    1 => {
                        r.exit_observations += 1;
                        "exit"
                    }
                    _ => {
                        r.counter_regressions += 1;
                        "invalid-sample"
                    }
                };
                r.error = Some(CadenceFailure {
                    role: Some(r.role),
                    kind: kind.into(),
                    os_code: None,
                    text: "hidden omitted failure".into(),
                });
            }
            let report = cadence_negative_report(c);
            assert!(
                encode_report(&report).is_err(),
                "accepted role={role} failure={failure}"
            );
            let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
            let path = temp.path().join("invalid.json");
            assert!(write_report_bounded(&path, &report).is_err());
            assert!(!path.exists() && !path.with_extension("pending").exists());
            std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
            assert!(read_report(&path).is_err());
        }
    }
}
// Coordinated conservation is not enough: a terminal acquisition cannot be
// followed by Done, a receipt, or another operation, even in a negative report.
fn terminal_state_coordinated_case(supervisor: bool, kind: &str) {
    let mut c = cadence_omitted_complete_fixture();
    let r = if supervisor {
        &mut c.supervisor
    } else {
        &mut c.broker
    };
    r.successful_live_samples -= 1;
    r.omitted_points -= 1;
    if kind == "abort" {
        r.attempts -= 1;
        r.not_attempted_due_to_abort = 1;
    } else {
        match kind {
            "query" => r.query_errors = 1,
            "exit" => r.exit_observations = 1,
            _ => r.counter_regressions = 1,
        }
        r.error = Some(CadenceFailure {
            role: Some(r.role),
            kind: kind.into(),
            os_code: None,
            text: "coordinated terminal fault".into(),
        });
    }
    let role = r.role;
    if supervisor {
        c.requested_coverage.supervisor_live -= 1;
    } else {
        c.requested_coverage.broker_live -= 1;
    }
    if kind == "abort" {
        if supervisor {
            c.requested_coverage.supervisor_aborted = 1;
        } else {
            c.requested_coverage.broker_aborted = 1;
        }
    }
    c.requested_coverage.both_live -= 1;
    c.both_live_pairs -= 1;
    c.partial_pairs = 1;
    c.failure = Some(CadenceFailure {
        role: Some(role),
        kind: kind.into(),
        os_code: None,
        text: "coordinated terminal fault".into(),
    });
    c.evidence_complete = false;
    c.cadence_target_met = false;
    let mut report = cadence_negative_report(c);
    // Setting flags and adding an arbitrary error must not mask phase forgery.
    report.error = Some("arbitrary negative report".into());
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let path = temp.path().join("forged.json");
    assert!(
        report.validate().is_err(),
        "terminal phase accepted {role:?}/{kind}"
    );
    assert!(encode_report(&report).is_err());
    assert!(write_report_bounded(&path, &report).is_err());
    assert!(!path.exists() && !path.with_extension("pending").exists());
    std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
    assert!(read_report(&path).is_err());
}
#[test]
fn terminal_state_supervisor_query() {
    terminal_state_coordinated_case(true, "query");
}
#[test]
fn terminal_state_supervisor_exit() {
    terminal_state_coordinated_case(true, "exit");
}
#[test]
fn terminal_state_supervisor_regression() {
    terminal_state_coordinated_case(true, "invalid-sample");
}
#[test]
fn terminal_state_supervisor_abort() {
    terminal_state_coordinated_case(true, "abort");
}
#[test]
fn terminal_state_broker_query() {
    terminal_state_coordinated_case(false, "query");
}
#[test]
fn terminal_state_broker_exit() {
    terminal_state_coordinated_case(false, "exit");
}
#[test]
fn terminal_state_broker_regression() {
    terminal_state_coordinated_case(false, "invalid-sample");
}
#[test]
fn terminal_state_broker_abort() {
    terminal_state_coordinated_case(false, "abort");
}

#[test]
fn terminal_shared_eight_baseline_failures_keep_primary_and_no_retry() {
    use crate::full_workload_barrier::{FullBarrier, Phase, Role};
    for failed_role in [CadenceRole::SupervisorB, CadenceRole::BrokerC] {
        for kind in 0..4 {
            let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
            let root = temp.path();
            for name in ["scratch", "controller"] {
                std::fs::create_dir(root.join(name)).unwrap();
            }
            let projection = root.join("projection");
            std::fs::write(&projection, b"seed\n").unwrap();
            let case = ordinary_case(root);
            let adapter = Adapter {
                root,
                case: &case,
                enrollment: "unused",
                epoch: "ordinary",
                timeout: Duration::from_secs(1),
                cancelled: crate::contract::never_cancel,
            };
            let manifest =
                FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
            let mut peer = FullBarrier::new(root, "ordinary", Role::Peer, &manifest).unwrap();
            peer.publish(0, Phase::Ready).unwrap();
            let mut observed = json!({"pass":false,"generation":{"seed_records":16}});
            let mut calls = vec![];
            let primary = reported_controller_intervals(
                &adapter,
                &manifest,
                &projection,
                5,
                Instant::now() + Duration::from_secs(10),
                &mut observed,
                |id, event| {
                    assert_eq!(id, 0);
                    calls.push(event);
                    if let FullEvent::Acquire(role) = event {
                        if role == failed_role {
                            match kind {
                                0 => {
                                    return Err(std::io::Error::other("shared primary query").into())
                                }
                                1 => {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::BrokenPipe,
                                        "shared primary exit",
                                    )
                                    .into())
                                }
                                2 => {
                                    let mut read = cadence_read(role, 1);
                                    read.sample.private_bytes =
                                        read.sample.lifetime_peak_private_bytes + 1;
                                    return Ok(serde_json::to_value(read)?);
                                }
                                _ => return Err(Box::new(AbortedAcquisition)),
                            }
                        }
                        return Ok(serde_json::to_value(cadence_read(role, 1))?);
                    }
                    Ok(Value::Null)
                },
            )
            .unwrap_err()
            .to_string();
            assert_eq!(
                calls,
                vec![
                    FullEvent::BeforeRelease,
                    FullEvent::Acquire(CadenceRole::SupervisorB),
                    FullEvent::Acquire(CadenceRole::BrokerC)
                ]
            );
            assert_eq!(observed["error"], primary);
            let report = FullReport::from_observations(&observed, true).unwrap();
            let path = root.join("partial.json");
            write_report_bounded(&path, &report).unwrap();
            let back = read_report(&path).unwrap();
            assert_eq!(back["error"], primary);
            assert!(!report.pass && !report.workload_complete && !report.correctness_complete);
            assert_eq!(back["operations"], observed["metrics"]["operations"]);
            for phase in ["release", "validated-ack"] {
                assert!(!root
                    .join(format!("controller/full20x256-v1-op-0-{phase}.json"))
                    .exists());
            }
            assert!(!root
                .join("controller/full20x256-v1-op-1-release.json")
                .exists());
            let saved = observed.clone();
            assert!(reported_controller_intervals(
                &adapter,
                &manifest,
                &projection,
                5,
                Instant::now() + Duration::from_secs(10),
                &mut observed,
                |_, _| panic!("retry forbidden")
            )
            .is_err());
            assert_eq!(saved, observed);
            assert_eq!(
                preserve_primary(
                    Err(primary.clone().into()),
                    Err("secondary publication".into())
                )
                .unwrap_err()
                .to_string(),
                primary
            );
            // Flags alone do not mask a terminal fault, nor do extra operations
            // or commands in an otherwise negative report.
            for mutation in 0..5 {
                let mut forged = serde_json::to_value(&report).unwrap();
                match mutation {
                    0 => forged["pass"] = json!(true),
                    1 => forged["workload_complete"] = json!(true),
                    2 => forged["correctness_complete"] = json!(true),
                    3 => {
                        let next = forged["operations"][0].clone();
                        forged["operations"].as_array_mut().unwrap().push(next);
                    }
                    _ => forged["controller_retained_commands"] = json!([commands()[0].clone()]),
                }
                let forged: FullReport = serde_json::from_value(forged).unwrap();
                assert!(forged.validate().is_err());
                assert!(encode_report(&forged).is_err());
            }
            println!(
                "shared terminal {failed_role:?}/{kind}: primary={primary}, ACK=false, retry=false"
            );
        }
    }
}

#[test]
fn cadence_review_unacquired_request_cannot_be_fabricated_after_done() {
    let mut c = cadence_omitted_complete_fixture();
    c.requested_samples += 1;
    c.missed_slots -= 1;
    c.unacquired_requests = 1;
    let failure: Box<dyn std::error::Error> = "fabricated cancellation after Done".into();
    c.fault(None, &*failure);
    assert!(c.validate("ordinary", 0, 3).is_err());
}
#[test]
fn cadence_review_requested_zero_cannot_hide_interior_pairs() {
    let mut c = cadence_omitted_complete_fixture();
    c.requested_samples = 0;
    c.missed_slots = c.accounted_slots;
    c.cadence_target_met = false;
    assert!(c.validate("ordinary", 0, 3).is_err());
}
#[test]
fn cadence_review_endpoint_only_cannot_fabricate_requested_target() {
    let mut c = Cadence::new("ordinary", 0, 3);
    c.record_pair(
        None,
        true,
        false,
        [
            (1, 2, Ok(cadence_read(CadenceRole::SupervisorB, 1))),
            (3, 4, Ok(cadence_read(CadenceRole::BrokerC, 1))),
        ],
    )
    .unwrap();
    c.release_begin_us = Some(100);
    c.release_end_us = Some(110);
    c.done_validated_us = Some(2100);
    c.record_pair(
        None,
        false,
        true,
        [
            (2101, 2102, Ok(cadence_read(CadenceRole::SupervisorB, 2))),
            (2103, 2104, Ok(cadence_read(CadenceRole::BrokerC, 2))),
        ],
    )
    .unwrap();
    c.finish(2110).unwrap();
    c.validate("ordinary", 0, 3).unwrap();
    c.requested_samples = 1;
    c.missed_slots = 0;
    c.cadence_target_met = true;
    assert!(c.validate("ordinary", 0, 3).is_err());
}

#[test]
fn cadence_review_native_failure_without_client_preserves_epoch_and_primary() {
    let mut c = Cadence::new("ordinary", 0, 3);
    let primary: Box<dyn std::error::Error> = "primary sample failure".into();
    c.fault(None, &*primary);
    transition(
        &mut c.state,
        Transition::PrimaryStop(primary.to_string(), FailureObservation::ReturnedError),
    )
    .unwrap();
    c.finish(10).unwrap();
    let manifest =
        FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
    let boundary = json!({"operation_id":0,"cli_epoch":3,"descriptor":Descriptor::from_operation(&manifest.operation(0).unwrap()),"before_release":null,"after_done":null,"receipt_validated":false,"exact_append_verified":false,"cadence":c});
    let observed = json!({"pass":false,"error":"primary sample failure","generation":{"seed_records":16},"metrics":{"case_epoch":"ordinary","operations":[boundary],"controller_retained_commands":[],"native_handle_verified":false}});
    let report = FullReport::from_observations(&observed, true).unwrap();
    assert_eq!(report.case_epoch.as_deref(), Some("ordinary"));
    assert_eq!(report.error.as_deref(), Some("primary sample failure"));
    assert!(report.commands.is_empty() && !report.workload_complete && !report.pass);
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let path = temp.path().join("partial.json");
    write_report_bounded(&path, &report).unwrap();
    let read = read_report(&path).unwrap();
    assert_eq!(read["error"], "primary sample failure");
    assert_eq!(
        read["operations"][0]["cadence"]["failure"]["text"],
        "primary sample failure"
    );
}
#[test]
fn cadence_review_early_cancel_and_unacquired_due_keep_partial_report() {
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let root = temp.path();
    for dir in ["scratch", "controller"] {
        std::fs::create_dir(root.join(dir)).unwrap();
    }
    let case = ordinary_case(root);
    let adapter = Adapter {
        root,
        case: &case,
        enrollment: "unused",
        epoch: "ordinary",
        timeout: Duration::from_secs(1),
        cancelled: || true,
    };
    let manifest =
        FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
    let mut observed = json!({"pass":false,"generation":{"seed_records":16}});
    let error = reported_controller_intervals(
        &adapter,
        &manifest,
        &root.join("absent"),
        0,
        Instant::now() + Duration::from_secs(5),
        &mut observed,
        |_, _| panic!("cancelled acquisition"),
    )
    .unwrap_err()
    .to_string();
    assert_eq!(observed["error"], error);
    assert!(observed.get("client").is_none());
    let report = FullReport::from_observations(&observed, true).unwrap();
    assert_eq!(report.case_epoch.as_deref(), Some("ordinary"));
    assert!(report.commands.is_empty());
    let ready = &report.operations.as_ref().unwrap()[0].cadence;
    assert_eq!(report.operations.as_ref().unwrap().len(), 1);
    assert_eq!(ready.pair_attempts, 0);
    assert_eq!(ready.state.stage, ControllerStage::Ready);
    assert!(ready.state.terminal.is_some());
    let path = root.join("early-cancel.json");
    write_report_bounded(&path, &report).unwrap();
    assert_eq!(read_report(&path).unwrap()["error"], error);
    let mut c = Cadence::new("ordinary", 0, 3);
    c.record_pair(
        None,
        true,
        false,
        [
            (0, 1, Ok(cadence_read(CadenceRole::SupervisorB, 1))),
            (2, 3, Ok(cadence_read(CadenceRole::BrokerC, 1))),
        ],
    )
    .unwrap();
    c.release_begin_us = Some(4);
    c.release_end_us = Some(4);
    let origin = Instant::now();
    let slot = c.due(2004).unwrap();
    let result = acquire_pair(
        &mut c,
        origin,
        slot,
        false,
        false,
        &adapter,
        Instant::now() + Duration::from_secs(5),
        &mut 0,
        &mut |_, _| panic!("due aborted before B"),
    );
    c.fault(None, &*result.unwrap_err());
    c.finish(2005).unwrap();
    c.validate("ordinary", 0, 3).unwrap();
    assert_eq!(c.unacquired_requests, 1);
    assert_eq!(c.requested_coverage.pairs, 0);
    assert_eq!(c.requested_samples, 1);
    assert_eq!(c.pair_attempts, 1);
    assert!(!c.evidence_complete);
    for path in [
        "controller/full20x256-v1-op-0-validated-ack.json",
        "controller/full20x256-v1-op-0-release.json",
    ] {
        assert!(!root.join(path).exists());
    }
}
#[test]
fn cadence_review_omitted_real_failures_preserve_all_sample_summaries() {
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    for failed_role in [CadenceRole::SupervisorB, CadenceRole::BrokerC] {
        for kind in 0..3 {
            let mut c = Cadence::new("ordinary", 0, 3);
            for i in 0..15 {
                let t = if i == 0 { 0 } else { i * 2000 + 4 };
                if i == 1 {
                    c.release_begin_us = Some(4);
                    c.release_end_us = Some(4);
                }
                let slot = if i == 0 { None } else { c.due(t).unwrap() };
                c.record_pair(
                    slot,
                    i == 0,
                    false,
                    [
                        (t, t + 1, Ok(cadence_read(CadenceRole::SupervisorB, i + 1))),
                        (t + 2, t + 3, Ok(cadence_read(CadenceRole::BrokerC, i + 1))),
                    ],
                )
                .unwrap();
            }
            let slot = c.due(30004).unwrap();
            let read = |role| -> Result<RetainedRead> {
                if role != failed_role {
                    return Ok(cadence_read(role, 16));
                }
                match kind {
                    0 => Err(std::io::Error::other("omitted query failure").into()),
                    1 => Err(
                        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "omitted exit").into(),
                    ),
                    _ => Ok(cadence_read(role, 1)),
                }
            };
            let primary = c
                .record_pair(
                    slot,
                    false,
                    false,
                    [
                        (30004, 30005, read(CadenceRole::SupervisorB)),
                        (30006, 30007, read(CadenceRole::BrokerC)),
                    ],
                )
                .unwrap_err()
                .to_string();
            c.finish(30008).unwrap();
            c.validate("ordinary", 0, 3).unwrap();
            let failed = if failed_role == CadenceRole::SupervisorB {
                &c.supervisor
            } else {
                &c.broker
            };
            assert_eq!(failed.omitted_points, 3);
            assert_eq!(failed.successful_live_samples, 15);
            assert_eq!(failed.query_errors, u64::from(kind == 0));
            assert_eq!(failed.exit_observations, u64::from(kind == 1));
            assert_eq!(failed.counter_regressions, u64::from(kind == 2));
            assert_eq!(c.both_live_pairs, 15);
            assert_eq!(c.partial_pairs, 1);
            assert!(!c.evidence_complete && !c.cadence_target_met);
            let mut report = cadence_negative_report(c);
            report.error = Some(primary.clone());
            let path = temp
                .path()
                .join(format!("partial-{failed_role:?}-{kind}.json"));
            write_report_bounded(&path, &report).unwrap();
            let wire = read_report(&path).unwrap();
            assert_eq!(wire["error"], primary);
            assert_eq!(wire["operations"][0]["cadence"]["partial_pairs"], 1);
            assert_eq!(wire["pass"], false);
        }
    }
}
#[test]
fn cadence_schema6_keeps_global_completeness_false() {
    let report =
        FullReport::from_observations(&json!({"pass":false,"commands":[]}), false).unwrap();
    assert_eq!(report.schema, 8);
    assert!(
        !report.sampling_complete
            && !report.measurement_complete
            && !report.performance_complete
            && !report.release_ready
    );
}
#[test]
fn cadence_forced_endpoints_account_missing_slots_and_edges() {
    let mut c = Cadence::new("ordinary", 0, 3);
    c.record_pair(
        None,
        true,
        false,
        [
            (10, 20, Ok(cadence_read(CadenceRole::SupervisorB, 1))),
            (21, 40, Ok(cadence_read(CadenceRole::BrokerC, 2))),
        ],
    )
    .unwrap();
    c.release_begin_us = Some(50);
    c.release_end_us = Some(90);
    assert_eq!(c.due(6100).unwrap(), Some(3));
    assert_eq!(c.missed_slots, 2);
    c.record_pair(
        Some(3),
        false,
        false,
        [
            (6100, 6110, Ok(cadence_read(CadenceRole::SupervisorB, 3))),
            (6120, 6130, Ok(cadence_read(CadenceRole::BrokerC, 4))),
        ],
    )
    .unwrap();
    c.done_validated_us = Some(8100);
    c.record_pair(
        None,
        false,
        true,
        [
            (8110, 8120, Ok(cadence_read(CadenceRole::SupervisorB, 5))),
            (8130, 8140, Ok(cadence_read(CadenceRole::BrokerC, 6))),
        ],
    )
    .unwrap();
    c.finish(8200).unwrap();
    assert_eq!(c.missed_slots, 3);
    assert_eq!(c.supervisor.observation_max_gap_us, Some(6090));
    assert_eq!(c.broker.observation_max_gap_us, Some(6090));
    assert!(c.evidence_complete && !c.cadence_target_met);
    c.validate("ordinary", 0, 3).unwrap();
}

#[test]
fn cadence_bounded_prefix_preserves_omitted_maxima_and_gap() {
    let mut c = Cadence::new("ordinary", 0, 3);
    for i in 0..15 {
        if i == 1 {
            c.release_begin_us = Some(0);
            c.release_end_us = Some(0);
        }
        if i == 14 {
            c.done_validated_us = Some(90000);
        }
        let t = if i == 14 { 90000 } else { i * 2000 };
        let slot = if i > 0 && i < 14 {
            transition(&mut c.state, Transition::Reserve(i)).unwrap();
            Some(i)
        } else {
            None
        };
        c.record_pair(
            slot,
            i == 0,
            i == 14,
            [
                (t, t + 10, Ok(cadence_read(CadenceRole::SupervisorB, i + 1))),
                (
                    t + 11,
                    t + 20,
                    Ok(cadence_read(CadenceRole::BrokerC, i + 1)),
                ),
            ],
        )
        .unwrap();
    }
    assert_eq!(c.supervisor.prefix.len(), 12);
    assert_eq!(c.supervisor.omitted_points, 3);
    assert_eq!(c.supervisor.maxima.as_ref().unwrap().private_bytes, 15);
    assert_eq!(c.supervisor.max_consecutive_gap_us, Some(64000));
    assert!(c.supervisor.end.is_some());
}

#[test]
fn cadence_fault_preserves_other_role_and_classifies_every_attempt() {
    for exited in [false, true] {
        let mut c = Cadence::new("ordinary", 0, 3);
        let e = std::io::Error::new(
            if exited {
                std::io::ErrorKind::BrokenPipe
            } else {
                std::io::ErrorKind::Other
            },
            "injected",
        );
        assert!(c
            .record_pair(
                None,
                true,
                false,
                [
                    (0, 1, Err(e.into())),
                    (2, 3, Ok(cadence_read(CadenceRole::BrokerC, 1)))
                ]
            )
            .is_err());
        c.finish(4).unwrap();
        assert_eq!(c.supervisor.attempts, 1);
        assert_eq!(c.supervisor.exit_observations, u64::from(exited));
        assert_eq!(c.supervisor.query_errors, u64::from(!exited));
        assert_eq!(c.broker.successful_live_samples, 1);
        assert_eq!(c.partial_pairs, 1);
        assert!(c.failure.is_some() && c.supervisor.maxima.is_none() && !c.evidence_complete);
    }
}
#[test]
fn cadence_all_six_regressions_after_prefix_and_identity_fault_fail_closed() {
    for field in 0..9 {
        let mut c = Cadence::new("ordinary", 0, 3);
        for i in 0..13 {
            if i == 1 {
                c.release_begin_us = Some(0);
                c.release_end_us = Some(0);
            }
            let slot = if i > 0 {
                transition(&mut c.state, Transition::Reserve(i)).unwrap();
                Some(i)
            } else {
                None
            };
            c.record_pair(
                slot,
                i == 0,
                false,
                [
                    (
                        i * 10,
                        i * 10 + 1,
                        Ok(cadence_read(CadenceRole::SupervisorB, 100)),
                    ),
                    (
                        i * 10 + 2,
                        i * 10 + 3,
                        Ok(cadence_read(CadenceRole::BrokerC, 100)),
                    ),
                ],
            )
            .unwrap();
        }
        let mut read = cadence_read(CadenceRole::SupervisorB, 100);
        match field {
            0 => read.sample.logical_io.read_operations = 0,
            1 => read.sample.logical_io.write_operations = 0,
            2 => read.sample.logical_io.other_operations = 0,
            3 => read.sample.logical_io.read_bytes = 0,
            4 => read.sample.logical_io.write_bytes = 0,
            5 => read.sample.logical_io.other_bytes = 0,
            6 => read.sample.lifetime_peak_private_bytes = 99,
            7 => read.role = CadenceRole::BrokerC,
            _ => read.epoch = 1,
        }
        c.done_validated_us = Some(140);
        assert!(
            c.record_pair(
                None,
                false,
                true,
                [
                    (140, 141, Ok(read)),
                    (142, 143, Ok(cadence_read(CadenceRole::BrokerC, 101)))
                ]
            )
            .is_err(),
            "accepted {field}"
        );
        assert_eq!(c.supervisor.successful_live_samples, 13);
        assert_eq!(c.supervisor.counter_regressions, u64::from(field < 7));
        assert_eq!(c.supervisor.query_errors, u64::from(field >= 7));
        assert_eq!(c.broker.successful_live_samples, 14);
        assert!(c.supervisor.end.is_none() && c.failure.is_some());
    }
}
#[test]
fn cadence_clock_fault_and_pair_ceiling_fail_without_panicking() {
    let mut c = Cadence::new("ordinary", 0, 3);
    assert!(c
        .record_pair(
            None,
            true,
            false,
            [
                (2, 1, Ok(cadence_read(CadenceRole::SupervisorB, 1))),
                (3, 4, Ok(cadence_read(CadenceRole::BrokerC, 1)))
            ]
        )
        .is_err());
    let mut c = Cadence::new("ordinary", 0, 3);
    c.pair_attempts = 30002;
    assert!(c
        .record_pair(
            None,
            true,
            false,
            [
                (0, 1, Ok(cadence_read(CadenceRole::SupervisorB, 1))),
                (2, 3, Ok(cadence_read(CadenceRole::BrokerC, 1)))
            ]
        )
        .is_err());
    let mut c = Cadence::new("ordinary", 0, 3);
    c.requested_samples = u64::MAX;
    c.release_begin_us = Some(0);
    assert!(c.due(2000).is_err());
}

fn cadence_complete_fixture() -> Cadence {
    let mut c = Cadence::new("ordinary", 0, 3);
    c.record_pair(
        None,
        true,
        false,
        [
            (10, 20, Ok(cadence_read(CadenceRole::SupervisorB, 1))),
            (21, 40, Ok(cadence_read(CadenceRole::BrokerC, 1))),
        ],
    )
    .unwrap();
    c.release_begin_us = Some(100);
    c.release_end_us = Some(1000);
    c.done_validated_us = Some(1500);
    c.record_pair(
        None,
        false,
        true,
        [
            (1600, 20000, Ok(cadence_read(CadenceRole::SupervisorB, 2))),
            (20001, 30000, Ok(cadence_read(CadenceRole::BrokerC, 2))),
        ],
    )
    .unwrap();
    c.finish(35000).unwrap();
    c
}
#[test]
fn cadence_operational_gap_clips_slow_endpoint_outside_release_done() {
    let mut split = Cadence::new("ordinary", 0, 3);
    split
        .record_pair(
            None,
            true,
            false,
            [
                (10, 20, Ok(cadence_read(CadenceRole::SupervisorB, 1))),
                (21, 40, Ok(cadence_read(CadenceRole::BrokerC, 1))),
            ],
        )
        .unwrap();
    split.release_begin_us = Some(100);
    split.release_end_us = Some(100);
    // This test isolates gap clipping, not nominal-slot timing admission.
    transition(&mut split.state, Transition::Reserve(1)).unwrap();
    split
        .record_pair(
            Some(1),
            false,
            false,
            [
                (1000, 1010, Ok(cadence_read(CadenceRole::SupervisorB, 2))),
                (1011, 1020, Ok(cadence_read(CadenceRole::BrokerC, 2))),
            ],
        )
        .unwrap();
    split.done_validated_us = Some(1500);
    split
        .record_pair(
            None,
            false,
            true,
            [
                (2000, 20000, Ok(cadence_read(CadenceRole::SupervisorB, 3))),
                (20001, 30000, Ok(cadence_read(CadenceRole::BrokerC, 3))),
            ],
        )
        .unwrap();
    split.finish(35000).unwrap();
    assert_eq!(split.supervisor.operational_max_gap_us, Some(910));
    assert_eq!(split.broker.operational_max_gap_us, Some(920));
    let c = cadence_complete_fixture();
    assert_eq!(c.supervisor.operational_max_gap_us, Some(1400));
    assert_eq!(c.broker.operational_max_gap_us, Some(1400));
    assert_eq!(c.supervisor.observation_max_gap_us, Some(19980));
    assert_eq!(c.broker.observation_max_gap_us, Some(29960));
    assert!(c.evidence_complete && c.cadence_target_met);
}
#[test]
fn cadence_validation_rejects_forged_edges_counts_endpoints_and_online_extrema() {
    let original = cadence_complete_fixture();
    original.validate("ordinary", 0, 3).unwrap();
    for fault in 0..14 {
        let mut c = original.clone();
        match fault {
            0 => c.supervisor.end = None,
            1 => c.supervisor.baseline = None,
            2 => c.supervisor.omitted_points = 1,
            3 => c.supervisor.observation_max_gap_us = Some(0),
            4 => c.supervisor.maxima.as_mut().unwrap().private_bytes = 0,
            5 => c.supervisor.first_sample_us = Some(1),
            6 => c.supervisor.last.as_mut().unwrap().sample_end_us = 1,
            7 => c.supervisor.attempts = 0,
            8 => c.release_end_us = None,
            9 => c.observation_envelope_end_us = None,
            10 => c.missed_slots = 100,
            11 => {
                c.supervisor
                    .baseline_to_end_io
                    .as_mut()
                    .unwrap()
                    .other_bytes = 100
            }
            12 => c.supervisor.epoch = 1,
            _ => c.supervisor.prefix[0].read.role = CadenceRole::BrokerC,
        }
        assert!(c.validate("ordinary", 0, 3).is_err(), "accepted {fault}");
    }
    let mut empty = Cadence::new("ordinary", 0, 3);
    empty.finish(100).unwrap();
    assert!(
        empty.supervisor.first_sample_us.is_none()
            && empty.supervisor.observation_max_gap_us.is_none()
    );
    empty.validate("ordinary", 0, 3).unwrap();
}

#[test]
fn cadence_report_validation_checks_nested_partial_evidence_and_closed_nulls() {
    let manifest =
        FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
    let boundary = json!({"operation_id":0,"cli_epoch":3,"descriptor":Descriptor::from_operation(&manifest.operation(0).unwrap()),"before_release":null,"after_done":null,"receipt_validated":false,"exact_append_verified":false,"cadence":cadence_complete_fixture()});
    let observed = json!({"pass":false,"client":{"case_epoch":"ordinary","commands":[]},"generation":{"seed_records":16},"metrics":{"operations":[boundary],"native_handle_verified":false}});
    // Complete sampler evidence without receipt/append must not be admitted as complete.
    assert!(FullReport::from_observations(&observed, true).is_err());
}
#[test]
fn cadence_malformed_clock_and_large_serialized_evidence_are_rejected() {
    let mut c = cadence_complete_fixture();
    c.done_validated_us = Some(0);
    assert!(c.validate("ordinary", 0, 3).is_err());
    let mut c = cadence_complete_fixture();
    c.case_epoch = "x".repeat(32768);
    assert!(c.validate(&c.case_epoch, 0, 3).is_err());
}

#[test]
fn cadence_shared_fault_paths_retain_partial_without_ack_or_next_runner() {
    #[cfg(not(any(windows, all(target_os = "linux", feature = "experimental-broker"))))]
    {
        crate::data::assert_owned_store_refusal(0, "seed", "store");
    }
    #[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
    {
        use std::sync::atomic::{AtomicBool, Ordering};
        static STOP: AtomicBool = AtomicBool::new(false);
        fn stopped() -> bool {
            STOP.load(Ordering::SeqCst)
        }
        // Each variant owns its root and cancellation flag, no native process is started.
        for fault in 0..7 {
            STOP.store(false, Ordering::SeqCst);
            let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
            let root = temp.path();
            for dir in ["scratch", "controller"] {
                std::fs::create_dir(root.join(dir)).unwrap();
            }
            let case = ordinary_case(root);
            let manifest =
                FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
            let store = crate::data::open_owned_fixture_store(&root.join("store")).unwrap();
            let initial = std::fs::metadata(root.join("store/events.jsonl"))
                .unwrap()
                .len();
            let adapter = Adapter {
                root,
                case: &case,
                enrollment: "Enrollment",
                epoch: "ordinary",
                timeout: Duration::from_secs(2),
                cancelled: stopped,
            };
            let mut commands = vec![];
            let mut observed = json!({"pass":false,"generation":{"seed_records":16}});
            let mut events = vec![];
            let mut runner_calls = 0;
            let mut b_calls = 0;
            let mut seen_done = false;
            std::thread::scope(|scope| {
                let peer = scope.spawn(|| {
                    execute_peer_with_runner(
                        &adapter,
                        &manifest,
                        Instant::now() + Duration::from_secs(10),
                        &mut commands,
                        |req, policy| {
                            runner_calls += 1;
                            assert_eq!(policy.operation_id, 0);
                            // Withhold Done long enough to exercise actual missing-path polling.
                            std::thread::sleep(Duration::from_millis(30));
                            let records: Vec<hermes_memory::MemoryRecord> =
                                serde_json::from_slice(req.input)?;
                            let (i, d) = store.ingest_many(&records)?;
                            Ok(measured_fixture(
                                req,
                                policy,
                                &json!({"inserted":i,"duplicates":d}),
                            ))
                        },
                    )
                    .map_err(|e| e.to_string())
                });
                let result = reported_controller_intervals(
                    &adapter,
                    &manifest,
                    &root.join("store/events.jsonl"),
                    initial,
                    Instant::now() + Duration::from_secs(5),
                    &mut observed,
                    |id, event| {
                        assert_eq!(id, 0);
                        events.push(event);
                        if fault == 6 && event == FullEvent::ReleasePublishBegin {
                            STOP.store(true, Ordering::SeqCst);
                        }
                        if event == FullEvent::DoneObserved {
                            seen_done = true;
                        }
                        if event == FullEvent::IntervalFinalize && fault == 3 {
                            return Err("injected finalize hash fault".into());
                        }
                        if let FullEvent::Acquire(role) = event {
                            if role == CadenceRole::SupervisorB {
                                b_calls += 1;
                                if (fault == 0 && b_calls == 1)
                                    || (fault == 1 && b_calls == 2)
                                    || (fault == 2 && seen_done)
                                {
                                    return Err(
                                        std::io::Error::other("injected query fault").into()
                                    );
                                }
                                if fault == 4 && b_calls == 1 {
                                    STOP.store(true, Ordering::SeqCst);
                                }
                                if fault == 5 && b_calls == 1 {
                                    return Ok(
                                        json!({"role":"SupervisorB","epoch":1,"sample":cadence_read(role,1).sample}),
                                    );
                                }
                            }
                            return Ok(serde_json::to_value(cadence_read(role, b_calls as u64))?);
                        }
                        Ok(Value::Null)
                    },
                );
                let primary = result.unwrap_err().to_string();
                assert_eq!(observed["error"], primary);
                assert!(observed.get("client").is_none());
                bind_report_epoch(&mut observed, "ordinary").unwrap();
                assert!(bind_report_epoch(&mut observed, "other").is_err());
                STOP.store(true, Ordering::SeqCst);
                assert!(peer.join().unwrap().is_err());
            });
            STOP.store(false, Ordering::SeqCst);
            if fault == 6 {
                assert!(!root
                    .join("controller/full20x256-v1-op-0-release.json")
                    .exists());
            }
            let boundaries = observed["metrics"]["operations"].as_array().unwrap();
            assert_eq!(boundaries.len(), 1);
            assert!(observed["metrics"]["controller_retained_commands"]
                .as_array()
                .unwrap()
                .is_empty());
            assert!(runner_calls <= 1);
            assert!(!root
                .join("controller/full20x256-v1-op-0-validated-ack.json")
                .exists());
            assert!(!root
                .join("controller/full20x256-v1-op-1-release.json")
                .exists());
            let c: Cadence = serde_json::from_value(boundaries[0]["cadence"].clone()).unwrap();
            assert!(c.failure.is_some() && !c.evidence_complete);
            c.validate("ordinary", 0, 3).unwrap();
            // Partial nested evidence must remain serializable after faults.
            let report = FullReport::from_observations(&observed, true).unwrap();
            assert!(report.commands.is_empty() && !report.workload_complete && !report.pass);
            let path = root.join("partial-report.json");
            write_report_bounded(&path, &report).unwrap();
            let persisted = read_report(&path).unwrap();
            assert_eq!(persisted["error"], observed["error"]);
            assert_eq!(persisted["operations"], observed["metrics"]["operations"]);
            assert!(write_report_bounded(&path, &report).is_err());
            let before_retry = observed.clone();
            STOP.store(true, Ordering::SeqCst);
            let retry = reported_controller_intervals(
                &adapter,
                &manifest,
                &root.join("store/events.jsonl"),
                initial,
                Instant::now() + Duration::from_secs(5),
                &mut observed,
                |_, _| panic!("retry acquisition forbidden"),
            );
            assert!(retry.unwrap_err().to_string().contains("already attempted"));
            assert_eq!(observed, before_retry);
            STOP.store(false, Ordering::SeqCst);
            let mut wrong = observed.clone();
            wrong["client"] = json!({"case_epoch":"other","commands":[]});
            assert!(FullReport::from_observations(&wrong, true).is_err());
            if fault == 4 {
                assert_eq!(c.broker.not_attempted_due_to_abort, 1);
            } else {
                assert!(c.broker.attempts >= 1);
            }
            println!(
                "ordinary fault={fault} pairs={} B={} C={} runner_calls={runner_calls} ACK=false",
                c.pair_attempts, c.supervisor.attempts, c.broker.attempts
            );
        }
    }
}

#[test]
fn cadence_failed_reads_keep_acquisition_spans_and_per_role_os_errors() {
    let mut c = Cadence::new("ordinary", 0, 3);
    assert!(c
        .record_pair(
            None,
            true,
            false,
            [
                (10, 1010, Err(std::io::Error::from_raw_os_error(5).into())),
                (1011, 2020, Err(std::io::Error::from_raw_os_error(6).into()))
            ]
        )
        .is_err());
    c.finish(2030).unwrap();
    assert_eq!(
        c.supervisor
            .last_attempt_span
            .as_ref()
            .unwrap()
            .sample_begin_us,
        10
    );
    assert_eq!(c.supervisor.max_attempt_span_us, Some(1000));
    assert_eq!(c.broker.max_attempt_span_us, Some(1009));
    assert_eq!(c.supervisor.error.as_ref().unwrap().os_code, Some(5));
    assert_eq!(c.broker.error.as_ref().unwrap().os_code, Some(6));
    c.validate("ordinary", 0, 3).unwrap();
}

#[test]
fn cadence_requested_slot_drift_and_omitted_last_regression_are_rejected() {
    let mut c = Cadence::new("ordinary", 0, 3);
    c.record_pair(
        None,
        true,
        false,
        [
            (0, 1, Ok(cadence_read(CadenceRole::SupervisorB, 1))),
            (2, 3, Ok(cadence_read(CadenceRole::BrokerC, 1))),
        ],
    )
    .unwrap();
    c.release_begin_us = Some(10);
    c.release_end_us = Some(10);
    let slot = c.due(2010).unwrap();
    c.record_pair(
        slot,
        false,
        false,
        [
            (2010, 2011, Ok(cadence_read(CadenceRole::SupervisorB, 2))),
            (2012, 2013, Ok(cadence_read(CadenceRole::BrokerC, 2))),
        ],
    )
    .unwrap();
    c.done_validated_us = Some(3000);
    c.record_pair(
        None,
        false,
        true,
        [
            (3000, 3001, Ok(cadence_read(CadenceRole::SupervisorB, 3))),
            (3002, 3003, Ok(cadence_read(CadenceRole::BrokerC, 3))),
        ],
    )
    .unwrap();
    c.finish(3010).unwrap();
    c.validate("ordinary", 0, 3).unwrap();
    c.supervisor.prefix[1].requested_slot = Some(100);
    assert!(c.validate("ordinary", 0, 3).is_err());
}

#[test]
fn cadence_pair_skew_and_duration_overflow_reject_forged_aggregates() {
    let mut c = cadence_complete_fixture();
    c.max_pair_span_us = Some(0);
    assert!(c.validate("ordinary", 0, 3).is_err());
    assert!(duration_us(Duration::from_secs(u64::MAX)).is_err());
    assert_eq!(duration_us(Duration::from_nanos(1999)).unwrap(), 1);
}

fn cadence_read(role: CadenceRole, n: u64) -> RetainedRead {
    RetainedRead {
        role,
        epoch: role.epoch(),
        sample: ProcessEvidence {
            logical_io: LogicalIo {
                read_operations: n,
                write_operations: n,
                other_operations: n,
                read_bytes: n,
                write_bytes: n,
                other_bytes: n,
            },
            private_bytes: n,
            working_set_bytes: n,
            lifetime_peak_private_bytes: n,
            lifetime_peak_working_set_bytes: n,
        },
    }
}
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
        // Synthetic retained receipts must model the same completed measurement
        // contract as the actual adapter, not merely a successful exit flag.
        m.live_attempts = 1;
        m.live_samples = 1;
        m.first_sample_us = Some(1);
        m.last_sample_us = Some(1);
        m.memory = Some(MemoryCoverage {
            sampled_private_bytes: 1, sampled_working_set_bytes: 1,
            observed_lifetime_peak_private_bytes: 1, observed_lifetime_peak_working_set_bytes: 1,
        });
        let io = LogicalIo { read_operations: 1, write_operations: 2, other_operations: 3,
            read_bytes: 4, write_bytes: 5, other_bytes: 6 };
        m.timepoints.push(Timepoint { since_spawn_start_us: 1, logical_io: io,
            private_bytes: 1, working_set_bytes: 1, lifetime_peak_private_bytes: 1,
            lifetime_peak_working_set_bytes: 1 });
        m.final_lifetime_logical_io = Some(io);
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
    #[cfg(not(any(windows, all(target_os = "linux", feature = "experimental-broker"))))]
    {
        crate::data::assert_owned_store_refusal(6291456, "seed", "install/store");
    }
    #[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
    {
        let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
        let root = temp.path();
        let generation = crate::data::generate_with_spec_for_owned_store(
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
        std::fs::create_dir(root.join("install")).unwrap();
        let store = crate::data::open_owned_fixture_store(&root.join("install/store")).unwrap();
        store
            .import_logical_archive_once(
                std::io::BufReader::new(
                    std::fs::File::open(root.join("seed/archive.jsonl")).unwrap(),
                ),
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
        let mut finalization = json!({});
        let source_before = crate::data::inventory(&root.join("seed/source")).unwrap();
        let registration = root.join("ordinary-worker-registration");
        std::fs::write(&registration, b"test-owned ordinary worker").unwrap();
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
                |id, event| {
                    if event == FullEvent::ReleasePublishEnd && id == 0 {
                        let until = Instant::now() + Duration::from_secs(10);
                        while !root.join("scratch/full20x256-v1-op-0-done.json").exists() {
                            ensure(
                                Instant::now() < until,
                                "ordinary immediate Done setup deadline",
                            )?;
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    }
                    if let FullEvent::Acquire(role) = event {
                        let n = 3 + u64::from(id);
                        return Ok(serde_json::to_value(cadence_read(role, n))?);
                    }
                    if event == FullEvent::DoneObserved {
                        assert!(root
                            .join(format!("scratch/full20x256-v1-op-{id}-done.json"))
                            .exists());
                    }
                    assert!(!root
                        .join(format!(
                            "controller/full20x256-v1-op-{id}-validated-ack.json"
                        ))
                        .exists());
                    Ok(Value::Null)
                },
            )
            .unwrap();
            observed_case_action(&mut finalization, true, CaseAction::WorkerWait, |_| {
                peer.join().unwrap().map_err(|e| e.into())
            })
            .unwrap();
        });
        observed_case_action(&mut finalization, true, CaseAction::WorkerRead, |_| {
            validate_final_commands(&commands, &retained)
        })
        .unwrap();
        observed_case_action(
            &mut finalization,
            true,
            CaseAction::WorkerObservation,
            |_| {
                assert_eq!(calls, (0..64).collect::<Vec<_>>());
                assert_eq!(boundaries.len(), 64);
                for (id, b) in boundaries.iter().enumerate() {
                    let c: Cadence = serde_json::from_value(b["cadence"].clone()).unwrap();
                    c.validate("ordinary", id as u32, id as u64 + 3).unwrap();
                    assert!(c.evidence_complete);
                    if id == 0 {
                        assert_eq!(c.requested_samples, 0);
                        assert_eq!(c.pair_attempts, 2);
                    }
                    for r in [&c.supervisor, &c.broker] {
                        assert_eq!(r.forced_baseline_attempts, 1);
                        assert_eq!(r.forced_end_attempts, 1);
                        assert!(r.prefix.len() <= 12);
                    }
                }
                Ok(())
            },
        )
        .unwrap();
        observed_case_action(
            &mut finalization,
            true,
            CaseAction::SourceBeforeStop,
            |_| {
                ensure(
                    crate::data::inventory(&root.join("seed/source"))? == source_before,
                    "ordinary source before stop",
                )
            },
        )
        .unwrap();
        // Ordinary counterparts use the joined peer, stopped store and owned marker;
        // these callbacks are not SCM/process custody or native stop evidence.
        observed_case_action(&mut finalization, true, CaseAction::StopClient, |_| {
            ensure(commands.len() == 64, "ordinary joined peer command count")
        })
        .unwrap();
        observed_case_action(&mut finalization, true, CaseAction::StopBroker, |_| {
            drop(store);
            Ok(())
        })
        .unwrap();
        observed_case_action(&mut finalization, true, CaseAction::WaitBrokerExit, |_| {
            File::open(root.join("install/store/memory.db"))?;
            Ok(())
        })
        .unwrap();
        observed_case_action(&mut finalization, true, CaseAction::CleanExits, |_| {
            ensure(
                commands
                    .iter()
                    .all(|c| c["child_exited"] == true && c["success"] == true),
                "ordinary returned runner outcomes",
            )
        })
        .unwrap();
        let imported =
            observed_case_action(&mut finalization, true, CaseAction::StoppedSqlite, |_| {
                crate::full_oracles::verify_owned_stopped_sqlite(
                    &temp,
                    &root.join("install/store/memory.db"),
                    &generation,
                    &manifest,
                )
            })
            .unwrap();
        observed_case_action(&mut finalization, true, CaseAction::SourceAfterStop, |_| {
            ensure(
                crate::data::inventory(&root.join("seed/source"))? == source_before,
                "ordinary source after stop",
            )
        })
        .unwrap();
        let projection =
            observed_case_action(&mut finalization, true, CaseAction::Projection, |_| {
                crate::full_oracles::verify_projection(
                    &root.join("install/store/events.jsonl"),
                    &root.join("seed/source/events.jsonl"),
                    &manifest,
                )
            })
            .unwrap();
        let exported = observed_case_action(&mut finalization, true, CaseAction::Export, |_| {
            crate::full_oracles::verify_export(
                &root.join("scratch/export"),
                &root.join("seed/source/events.jsonl"),
                &manifest,
            )
        })
        .unwrap();
        observed_case_action(
            &mut finalization,
            true,
            CaseAction::FinalBrokerObservation,
            |_| {
                ensure(
                    File::open(root.join("install/store/memory.db"))?
                        .metadata()?
                        .is_file(),
                    "ordinary stopped store observation",
                )
            },
        )
        .unwrap();
        observed_case_action(&mut finalization, true, CaseAction::DeleteClient, |_| {
            std::fs::remove_file(&registration)?;
            Ok(())
        })
        .unwrap();
        let worker=FullReport::from_observations(&json!({"pass":true,"commands":commands,"case_epoch":"ordinary","seed_records":generation["seed_records"],"workload_complete":true}),false).unwrap();
        let report=FullReport::from_observations(&json!({"case_actions":finalization["case_actions"],"pass":true,"client":worker,"generation":generation,"correctness_complete":true,"source_unchanged":true,"startup_import":imported,"final_payloads":projection,"export":exported,"metrics":{"controller_retained_commands":retained,"operations":boundaries,"native_handle_verified":false}}),true).unwrap();
        assert!(
            !report.native_handle_verified && !report.measurement_complete && !report.release_ready
        );
        let path = root.join("full-report.json");
        write_report_bounded(&path, &report).unwrap();
        let persisted = read_report(&path).unwrap();
        let operations = report.operations.as_ref().unwrap();
        let pairs: u64 = operations.iter().map(|o| o.cadence.pair_attempts).sum();
        let missed: u64 = operations.iter().map(|o| o.cadence.missed_slots).sum();
        let omitted: u64 = operations
            .iter()
            .map(|o| o.cadence.supervisor.omitted_points + o.cadence.broker.omitted_points)
            .sum();
        let cadence_bytes: usize = operations
            .iter()
            .map(|o| serde_json::to_vec(&o.cadence).unwrap().len())
            .sum();
        let report_bytes = std::fs::metadata(&path).unwrap().len();
        assert!(cadence_bytes <= 2097152 && report_bytes <= REPORT_LIMIT);
        println!("ordinary injected B/C metrics (NOT native): intervals={} pairs={pairs} missed_slots={missed} omitted_points={omitted} cadence_bytes={cadence_bytes} report_bytes={report_bytes} schema={}",operations.len(),report.schema);
        if let Some(directory) = std::env::var_os("CADENCE_TEST_ARTIFACT_DIR") {
            let artifact =
                std::path::PathBuf::from(directory).join("ordinary-injected-full64-schema7.json");
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&artifact)
                .unwrap();
            file.write_all(&encode_report(&report).unwrap()).unwrap();
            assert_eq!(read_report(&artifact).unwrap(), persisted);
            println!("ordinary injected report artifact={}", artifact.display());
        }
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
}

#[test]
fn shared_peer_unknown_real_commit_has_no_done_or_retry() {
    #[cfg(not(any(windows, all(target_os = "linux", feature = "experimental-broker"))))]
    {
        // Refused acquisition: no admitted commit, not an unknown-after-commit observation.
        crate::data::assert_owned_store_refusal(0, "seed", "store");
    }
    #[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
    {
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
        let store = crate::data::open_owned_fixture_store(&root.join("store")).unwrap();
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
}
#[test]
fn shared_controller_invalid_after_done_receipt_withholds_ack_and_next_release() {
    #[cfg(not(any(windows, all(target_os = "linux", feature = "experimental-broker"))))]
    {
        crate::data::assert_owned_store_refusal(0, "seed", "store");
    }
    #[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
    {
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
        let store = crate::data::open_owned_fixture_store(&root.join("store")).unwrap();
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
                |id, event| {
                    if let FullEvent::Acquire(role) = event {
                        return Ok(serde_json::to_value(cadence_read(role, 3 + u64::from(id)))?);
                    }
                    if event == FullEvent::DoneObserved && id == 21 {
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

// Frozen accepted witness: the failure is at slot15/ordinal16, followed by
// slot16/ordinal17. Negative flags and primary error must not authorize it.
fn state_machine_exact_accepted_witness() -> FullReport {
    // Rebase the exact old contradiction onto the new closed schema; the real
    // slot15 abort supplies the cut, not a guessed reconstruction of old data.
    let mut value: Value = serde_json::from_str(r###"{"schema":6,"role":"Controller","case":"representative-6MiB-full20x256-v1","case_epoch":"architecture","workload_spec":{"schema":1,"kind":"Full20x256V1"},"seed_records":16,"additions":5142,"final_records":5159,"sessions":18,"commands":[],"controller_retained_commands":[],"operations":[{"operation_id":0,"cli_epoch":3,"descriptor":{"id":0,"cli_epoch":3,"stage":"warmup","records":1,"inserted":1,"duplicates":0,"replay_source":null,"payload_bytes":2260,"appended_jsonl_bytes":2259,"sessions":null},"before_release":{"broker_epoch":1,"supervisor_epoch":2,"cli_epoch":3,"broker":{"logical_io":{"read_operations":100,"write_operations":100,"other_operations":100,"read_bytes":100,"write_bytes":100,"other_bytes":100},"private_bytes":100,"working_set_bytes":100,"lifetime_peak_private_bytes":1100,"lifetime_peak_working_set_bytes":1100},"supervisor":{"logical_io":{"read_operations":100,"write_operations":100,"other_operations":100,"read_bytes":100,"write_bytes":100,"other_bytes":100},"private_bytes":100,"working_set_bytes":100,"lifetime_peak_private_bytes":1100,"lifetime_peak_working_set_bytes":1100},"broker_logical_io_delta":null,"supervisor_logical_io_delta":null,"handshake_span_us":null},"after_done":null,"receipt_validated":false,"exact_append_verified":false,"cadence":{"schema":1,"case_epoch":"architecture","operation_id":0,"cli_epoch":3,"origin_us":0,"nominal_period_us":2000,"release_begin_us":4,"release_end_us":4,"done_validated_us":null,"observation_envelope_end_us":32010,"accounted_slots":16,"requested_samples":16,"missed_slots":0,"pair_attempts":17,"baseline_coverage":{"pairs":1,"supervisor_live":1,"broker_live":1,"both_live":1,"supervisor_aborted":0,"broker_aborted":0},"requested_coverage":{"pairs":16,"supervisor_live":16,"broker_live":15,"both_live":15,"supervisor_aborted":0,"broker_aborted":1},"end_coverage":{"pairs":0,"supervisor_live":0,"broker_live":0,"both_live":0,"supervisor_aborted":0,"broker_aborted":0},"unacquired_requests":0,"both_live_pairs":16,"partial_pairs":1,"max_pair_span_us":3,"last_pair_end_us":32007,"supervisor":{"last_attempt_span":{"sample_begin_us":32004,"sample_end_us":32005},"max_attempt_span_us":1,"error":null,"role":"SupervisorB","epoch":2,"attempts":17,"successful_live_samples":17,"exit_observations":0,"query_errors":0,"counter_regressions":0,"not_attempted_due_to_abort":0,"forced_baseline_attempts":1,"forced_end_attempts":0,"baseline":{"sample_begin_us":0,"sample_end_us":1,"requested_slot":null,"read":{"role":"SupervisorB","epoch":2,"sample":{"logical_io":{"read_operations":100,"write_operations":100,"other_operations":100,"read_bytes":100,"write_bytes":100,"other_bytes":100},"private_bytes":100,"working_set_bytes":100,"lifetime_peak_private_bytes":1100,"lifetime_peak_working_set_bytes":1100}}},"end":null,"prefix":[{"sample_begin_us":0,"sample_end_us":1,"requested_slot":null,"read":{"role":"SupervisorB","epoch":2,"sample":{"logical_io":{"read_operations":100,"write_operations":100,"other_operations":100,"read_bytes":100,"write_bytes":100,"other_bytes":100},"private_bytes":100,"working_set_bytes":100,"lifetime_peak_private_bytes":1100,"lifetime_peak_working_set_bytes":1100}}},{"sample_begin_us":2004,"sample_end_us":2005,"requested_slot":1,"read":{"role":"SupervisorB","epoch":2,"sample":{"logical_io":{"read_operations":101,"write_operations":101,"other_operations":101,"read_bytes":101,"write_bytes":101,"other_bytes":101},"private_bytes":101,"working_set_bytes":101,"lifetime_peak_private_bytes":1101,"lifetime_peak_working_set_bytes":1101}}},{"sample_begin_us":4004,"sample_end_us":4005,"requested_slot":2,"read":{"role":"SupervisorB","epoch":2,"sample":{"logical_io":{"read_operations":102,"write_operations":102,"other_operations":102,"read_bytes":102,"write_bytes":102,"other_bytes":102},"private_bytes":102,"working_set_bytes":102,"lifetime_peak_private_bytes":1102,"lifetime_peak_working_set_bytes":1102}}},{"sample_begin_us":6004,"sample_end_us":6005,"requested_slot":3,"read":{"role":"SupervisorB","epoch":2,"sample":{"logical_io":{"read_operations":103,"write_operations":103,"other_operations":103,"read_bytes":103,"write_bytes":103,"other_bytes":103},"private_bytes":103,"working_set_bytes":103,"lifetime_peak_private_bytes":1103,"lifetime_peak_working_set_bytes":1103}}},{"sample_begin_us":8004,"sample_end_us":8005,"requested_slot":4,"read":{"role":"SupervisorB","epoch":2,"sample":{"logical_io":{"read_operations":104,"write_operations":104,"other_operations":104,"read_bytes":104,"write_bytes":104,"other_bytes":104},"private_bytes":104,"working_set_bytes":104,"lifetime_peak_private_bytes":1104,"lifetime_peak_working_set_bytes":1104}}},{"sample_begin_us":10004,"sample_end_us":10005,"requested_slot":5,"read":{"role":"SupervisorB","epoch":2,"sample":{"logical_io":{"read_operations":105,"write_operations":105,"other_operations":105,"read_bytes":105,"write_bytes":105,"other_bytes":105},"private_bytes":105,"working_set_bytes":105,"lifetime_peak_private_bytes":1105,"lifetime_peak_working_set_bytes":1105}}},{"sample_begin_us":12004,"sample_end_us":12005,"requested_slot":6,"read":{"role":"SupervisorB","epoch":2,"sample":{"logical_io":{"read_operations":106,"write_operations":106,"other_operations":106,"read_bytes":106,"write_bytes":106,"other_bytes":106},"private_bytes":106,"working_set_bytes":106,"lifetime_peak_private_bytes":1106,"lifetime_peak_working_set_bytes":1106}}},{"sample_begin_us":14004,"sample_end_us":14005,"requested_slot":7,"read":{"role":"SupervisorB","epoch":2,"sample":{"logical_io":{"read_operations":107,"write_operations":107,"other_operations":107,"read_bytes":107,"write_bytes":107,"other_bytes":107},"private_bytes":107,"working_set_bytes":107,"lifetime_peak_private_bytes":1107,"lifetime_peak_working_set_bytes":1107}}},{"sample_begin_us":16004,"sample_end_us":16005,"requested_slot":8,"read":{"role":"SupervisorB","epoch":2,"sample":{"logical_io":{"read_operations":108,"write_operations":108,"other_operations":108,"read_bytes":108,"write_bytes":108,"other_bytes":108},"private_bytes":108,"working_set_bytes":108,"lifetime_peak_private_bytes":1108,"lifetime_peak_working_set_bytes":1108}}},{"sample_begin_us":18004,"sample_end_us":18005,"requested_slot":9,"read":{"role":"SupervisorB","epoch":2,"sample":{"logical_io":{"read_operations":109,"write_operations":109,"other_operations":109,"read_bytes":109,"write_bytes":109,"other_bytes":109},"private_bytes":109,"working_set_bytes":109,"lifetime_peak_private_bytes":1109,"lifetime_peak_working_set_bytes":1109}}},{"sample_begin_us":20004,"sample_end_us":20005,"requested_slot":10,"read":{"role":"SupervisorB","epoch":2,"sample":{"logical_io":{"read_operations":110,"write_operations":110,"other_operations":110,"read_bytes":110,"write_bytes":110,"other_bytes":110},"private_bytes":110,"working_set_bytes":110,"lifetime_peak_private_bytes":1110,"lifetime_peak_working_set_bytes":1110}}},{"sample_begin_us":22004,"sample_end_us":22005,"requested_slot":11,"read":{"role":"SupervisorB","epoch":2,"sample":{"logical_io":{"read_operations":111,"write_operations":111,"other_operations":111,"read_bytes":111,"write_bytes":111,"other_bytes":111},"private_bytes":111,"working_set_bytes":111,"lifetime_peak_private_bytes":1111,"lifetime_peak_working_set_bytes":1111}}}],"omitted_points":5,"first_sample_us":1,"last":{"sample_begin_us":32004,"sample_end_us":32005,"requested_slot":16,"read":{"role":"SupervisorB","epoch":2,"sample":{"logical_io":{"read_operations":116,"write_operations":116,"other_operations":116,"read_bytes":116,"write_bytes":116,"other_bytes":116},"private_bytes":116,"working_set_bytes":116,"lifetime_peak_private_bytes":1116,"lifetime_peak_working_set_bytes":1116}}},"max_consecutive_gap_us":2004,"observation_max_gap_us":2004,"operational_max_gap_us":2001,"max_acquisition_span_us":1,"maxima":{"logical_io":{"read_operations":116,"write_operations":116,"other_operations":116,"read_bytes":116,"write_bytes":116,"other_bytes":116},"private_bytes":116,"working_set_bytes":116,"lifetime_peak_private_bytes":1116,"lifetime_peak_working_set_bytes":1116},"baseline_to_end_io":null},"broker":{"last_attempt_span":{"sample_begin_us":32006,"sample_end_us":32007},"max_attempt_span_us":1,"error":null,"role":"BrokerC","epoch":1,"attempts":16,"successful_live_samples":16,"exit_observations":0,"query_errors":0,"counter_regressions":0,"not_attempted_due_to_abort":1,"forced_baseline_attempts":1,"forced_end_attempts":0,"baseline":{"sample_begin_us":2,"sample_end_us":3,"requested_slot":null,"read":{"role":"BrokerC","epoch":1,"sample":{"logical_io":{"read_operations":100,"write_operations":100,"other_operations":100,"read_bytes":100,"write_bytes":100,"other_bytes":100},"private_bytes":100,"working_set_bytes":100,"lifetime_peak_private_bytes":1100,"lifetime_peak_working_set_bytes":1100}}},"end":null,"prefix":[{"sample_begin_us":2,"sample_end_us":3,"requested_slot":null,"read":{"role":"BrokerC","epoch":1,"sample":{"logical_io":{"read_operations":100,"write_operations":100,"other_operations":100,"read_bytes":100,"write_bytes":100,"other_bytes":100},"private_bytes":100,"working_set_bytes":100,"lifetime_peak_private_bytes":1100,"lifetime_peak_working_set_bytes":1100}}},{"sample_begin_us":2006,"sample_end_us":2007,"requested_slot":1,"read":{"role":"BrokerC","epoch":1,"sample":{"logical_io":{"read_operations":101,"write_operations":101,"other_operations":101,"read_bytes":101,"write_bytes":101,"other_bytes":101},"private_bytes":101,"working_set_bytes":101,"lifetime_peak_private_bytes":1101,"lifetime_peak_working_set_bytes":1101}}},{"sample_begin_us":4006,"sample_end_us":4007,"requested_slot":2,"read":{"role":"BrokerC","epoch":1,"sample":{"logical_io":{"read_operations":102,"write_operations":102,"other_operations":102,"read_bytes":102,"write_bytes":102,"other_bytes":102},"private_bytes":102,"working_set_bytes":102,"lifetime_peak_private_bytes":1102,"lifetime_peak_working_set_bytes":1102}}},{"sample_begin_us":6006,"sample_end_us":6007,"requested_slot":3,"read":{"role":"BrokerC","epoch":1,"sample":{"logical_io":{"read_operations":103,"write_operations":103,"other_operations":103,"read_bytes":103,"write_bytes":103,"other_bytes":103},"private_bytes":103,"working_set_bytes":103,"lifetime_peak_private_bytes":1103,"lifetime_peak_working_set_bytes":1103}}},{"sample_begin_us":8006,"sample_end_us":8007,"requested_slot":4,"read":{"role":"BrokerC","epoch":1,"sample":{"logical_io":{"read_operations":104,"write_operations":104,"other_operations":104,"read_bytes":104,"write_bytes":104,"other_bytes":104},"private_bytes":104,"working_set_bytes":104,"lifetime_peak_private_bytes":1104,"lifetime_peak_working_set_bytes":1104}}},{"sample_begin_us":10006,"sample_end_us":10007,"requested_slot":5,"read":{"role":"BrokerC","epoch":1,"sample":{"logical_io":{"read_operations":105,"write_operations":105,"other_operations":105,"read_bytes":105,"write_bytes":105,"other_bytes":105},"private_bytes":105,"working_set_bytes":105,"lifetime_peak_private_bytes":1105,"lifetime_peak_working_set_bytes":1105}}},{"sample_begin_us":12006,"sample_end_us":12007,"requested_slot":6,"read":{"role":"BrokerC","epoch":1,"sample":{"logical_io":{"read_operations":106,"write_operations":106,"other_operations":106,"read_bytes":106,"write_bytes":106,"other_bytes":106},"private_bytes":106,"working_set_bytes":106,"lifetime_peak_private_bytes":1106,"lifetime_peak_working_set_bytes":1106}}},{"sample_begin_us":14006,"sample_end_us":14007,"requested_slot":7,"read":{"role":"BrokerC","epoch":1,"sample":{"logical_io":{"read_operations":107,"write_operations":107,"other_operations":107,"read_bytes":107,"write_bytes":107,"other_bytes":107},"private_bytes":107,"working_set_bytes":107,"lifetime_peak_private_bytes":1107,"lifetime_peak_working_set_bytes":1107}}},{"sample_begin_us":16006,"sample_end_us":16007,"requested_slot":8,"read":{"role":"BrokerC","epoch":1,"sample":{"logical_io":{"read_operations":108,"write_operations":108,"other_operations":108,"read_bytes":108,"write_bytes":108,"other_bytes":108},"private_bytes":108,"working_set_bytes":108,"lifetime_peak_private_bytes":1108,"lifetime_peak_working_set_bytes":1108}}},{"sample_begin_us":18006,"sample_end_us":18007,"requested_slot":9,"read":{"role":"BrokerC","epoch":1,"sample":{"logical_io":{"read_operations":109,"write_operations":109,"other_operations":109,"read_bytes":109,"write_bytes":109,"other_bytes":109},"private_bytes":109,"working_set_bytes":109,"lifetime_peak_private_bytes":1109,"lifetime_peak_working_set_bytes":1109}}},{"sample_begin_us":20006,"sample_end_us":20007,"requested_slot":10,"read":{"role":"BrokerC","epoch":1,"sample":{"logical_io":{"read_operations":110,"write_operations":110,"other_operations":110,"read_bytes":110,"write_bytes":110,"other_bytes":110},"private_bytes":110,"working_set_bytes":110,"lifetime_peak_private_bytes":1110,"lifetime_peak_working_set_bytes":1110}}},{"sample_begin_us":22006,"sample_end_us":22007,"requested_slot":11,"read":{"role":"BrokerC","epoch":1,"sample":{"logical_io":{"read_operations":111,"write_operations":111,"other_operations":111,"read_bytes":111,"write_bytes":111,"other_bytes":111},"private_bytes":111,"working_set_bytes":111,"lifetime_peak_private_bytes":1111,"lifetime_peak_working_set_bytes":1111}}}],"omitted_points":4,"first_sample_us":3,"last":{"sample_begin_us":32006,"sample_end_us":32007,"requested_slot":16,"read":{"role":"BrokerC","epoch":1,"sample":{"logical_io":{"read_operations":116,"write_operations":116,"other_operations":116,"read_bytes":116,"write_bytes":116,"other_bytes":116},"private_bytes":116,"working_set_bytes":116,"lifetime_peak_private_bytes":1116,"lifetime_peak_working_set_bytes":1116}}},"max_consecutive_gap_us":4000,"observation_max_gap_us":4000,"operational_max_gap_us":4000,"max_acquisition_span_us":1,"maxima":{"logical_io":{"read_operations":116,"write_operations":116,"other_operations":116,"read_bytes":116,"write_bytes":116,"other_bytes":116},"private_bytes":116,"working_set_bytes":116,"lifetime_peak_private_bytes":1116,"lifetime_peak_working_set_bytes":1116},"baseline_to_end_io":null},"evidence_complete":false,"cadence_target_met":false,"failure":{"role":"BrokerC","kind":"abort","os_code":null,"text":"cadence acquisition aborted"}}}],"source_oracle":null,"import_oracle":null,"projection_oracle":null,"export_oracle":null,"correctness_complete":false,"workload_complete":false,"measurement_complete":false,"sampling_complete":false,"native_handle_verified":false,"performance_policy_status":"unapproved","performance_complete":false,"release_ready":false,"pass":false,"error":"cadence acquisition aborted","diagnostics":{"error":"cadence acquisition aborted","generation":{"seed_records":16},"pass":false}}"###).unwrap();
    value["schema"] = json!(8);
    value["case_actions"] = Value::Null;
    value["case_stop"] = json!({"position":0,"acknowledged_prefix":0,"cause":{"Operation":"Done"},"primary":"cadence acquisition aborted"});
    let c = &mut value["operations"][0]["cadence"];
    c["schema"] = json!(3);
    let mut closed = state_machine_requested_abort_prefix(15).state;
    let primary = closed.terminal.as_ref().unwrap().primary.clone();
    transition(
        &mut closed,
        Transition::PrimaryStop(primary, FailureObservation::ReturnedError),
    )
    .unwrap();
    c["state"] = serde_json::to_value(closed).unwrap();
    for role in ["supervisor", "broker"] {
        let r = &mut c[role];
        for key in ["baseline", "end", "last"] {
            if let Some(point) = r[key].as_object_mut() {
                let slot = point["requested_slot"].as_u64();
                point.insert("ordinal".into(), json!(slot.map_or(1, |s| s + 1)));
                point.insert(
                    "class".into(),
                    json!(if slot.is_some() {
                        "Requested"
                    } else {
                        "Baseline"
                    }),
                );
            }
        }
        for point in r["prefix"].as_array_mut().unwrap() {
            let slot = point["requested_slot"].as_u64();
            point["ordinal"] = json!(slot.map_or(1, |s| s + 1));
            point["class"] = json!(if slot.is_some() {
                "Requested"
            } else {
                "Baseline"
            });
        }
    }
    serde_json::from_value(value).unwrap()
}
#[test]
fn state_machine_exact_witness_validate_rejects_order() {
    let report = state_machine_exact_accepted_witness();
    assert!(
        report.validate().is_err(),
        "accepted post-terminal slot16 after slot15 abort"
    );
}
#[test]
fn state_machine_exact_witness_encode_rejects_order() {
    let report = state_machine_exact_accepted_witness();
    assert!(
        encode_report(&report).is_err(),
        "encoded post-terminal slot16"
    );
}
#[test]
fn state_machine_exact_witness_writer_rejects_before_creation() {
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let path = temp.path().join("rejected.json");
    let report = state_machine_exact_accepted_witness();
    let result = write_report_bounded(&path, &report);
    assert!(result.is_err(), "published post-terminal slot16");
    assert!(!path.exists());
    assert!(!path.with_extension("pending").exists());
}
#[test]
fn state_machine_exact_witness_reader_rejects_forged_bytes() {
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let path = temp.path().join("forged.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&state_machine_exact_accepted_witness()).unwrap(),
    )
    .unwrap();
    assert!(
        read_report(&path).is_err(),
        "read forged post-terminal slot16"
    );
}
fn state_machine_requested_abort_prefix(successes: u64) -> Cadence {
    let mut c = Cadence::new("architecture", 0, 3);
    c.record_pair(
        None,
        true,
        false,
        [
            (0, 1, Ok(cadence_read(CadenceRole::SupervisorB, 100))),
            (2, 3, Ok(cadence_read(CadenceRole::BrokerC, 100))),
        ],
    )
    .unwrap();
    c.release_begin_us = Some(4);
    c.release_end_us = Some(4);
    for slot in 1..successes {
        let t = slot * 2000 + 4;
        let reserved = c.due(t).unwrap();
        c.record_pair(
            reserved,
            false,
            false,
            [
                (
                    t,
                    t + 1,
                    Ok(cadence_read(CadenceRole::SupervisorB, 100 + slot)),
                ),
                (
                    t + 2,
                    t + 3,
                    Ok(cadence_read(CadenceRole::BrokerC, 100 + slot)),
                ),
            ],
        )
        .unwrap();
    }
    let t = successes * 2000 + 4;
    let slot = c.due(t).unwrap();
    let primary = c
        .record_pair(
            slot,
            false,
            false,
            [
                (
                    t,
                    t + 1,
                    Ok(cadence_read(CadenceRole::SupervisorB, 100 + successes)),
                ),
                (t + 2, t + 3, Err(Box::new(AbortedAcquisition))),
            ],
        )
        .unwrap_err()
        .to_string();
    assert_eq!(primary, "cadence acquisition aborted");
    c
}
#[test]
fn state_machine_terminal_due_rejects_before_at_after_retention() {
    let mut admitted = Vec::new();
    for successes in [1, 12, 15] {
        let mut c = state_machine_requested_abort_prefix(successes);
        let before = serde_json::to_value(&c).unwrap();
        let result = c.due((successes + 1) * 2000 + 4);
        if result.is_ok() || serde_json::to_value(&c).unwrap() != before {
            admitted.push(successes);
        }
    }
    assert!(
        admitted.is_empty(),
        "post-terminal due admitted or mutated: {admitted:?}"
    );
}
#[test]
fn state_machine_terminal_pair_rejects_before_at_after_retention() {
    let mut admitted = Vec::new();
    for successes in [1, 12, 15] {
        let mut c = state_machine_requested_abort_prefix(successes);
        let before = serde_json::to_value(&c).unwrap();
        let t = (successes + 1) * 2000 + 4;
        let result = c.record_pair(
            Some(successes + 1),
            false,
            false,
            [
                (
                    t,
                    t + 1,
                    Ok(cadence_read(CadenceRole::SupervisorB, 101 + successes)),
                ),
                (
                    t + 2,
                    t + 3,
                    Ok(cadence_read(CadenceRole::BrokerC, 101 + successes)),
                ),
            ],
        );
        if result.is_ok() || serde_json::to_value(&c).unwrap() != before {
            admitted.push(successes);
        }
    }
    assert!(
        admitted.is_empty(),
        "post-terminal pair admitted or mutated: {admitted:?}"
    );
}

thread_local! {
    // Per-test controller thread, not shared across default-thread tests.
    static STATE_MACHINE_ACK_CANCEL_PATH: std::cell::RefCell<Option<std::path::PathBuf>> = const { std::cell::RefCell::new(None) };
}
fn state_machine_cancel_after_published_ack() -> bool {
    STATE_MACHINE_ACK_CANCEL_PATH.with(|path| path.borrow().as_ref().is_some_and(|p| p.exists()))
}
#[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
fn state_machine_actual_completed_facts(fault: u8) -> FullReport {
    use crate::full_workload_barrier::{FullBarrier, Phase, Role};
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let root = temp.path();
    for directory in ["scratch", "controller"] {
        std::fs::create_dir(root.join(directory)).unwrap();
    }
    let case = ordinary_case(root);
    let manifest =
        FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
    let store = crate::data::open_owned_fixture_store(&root.join("store")).unwrap();
    let projection = root.join("store/events.jsonl");
    let initial = std::fs::metadata(&projection).unwrap().len();
    let ack_path = root.join("controller/full20x256-v1-op-0-validated-ack.json");
    let cancelled: fn() -> bool = if fault == 2 {
        STATE_MACHINE_ACK_CANCEL_PATH.with(|path| *path.borrow_mut() = Some(ack_path.clone()));
        state_machine_cancel_after_published_ack
    } else {
        crate::contract::never_cancel
    };
    let controller_adapter = Adapter {
        root,
        case: &case,
        enrollment: "Enrollment",
        epoch: "state-machine",
        timeout: Duration::from_secs(1),
        cancelled,
    };
    let peer_adapter = Adapter {
        cancelled: crate::contract::never_cancel,
        ..controller_adapter
    };
    let mut peer = FullBarrier::new(root, "state-machine", Role::Peer, &manifest).unwrap();
    peer.publish(0, Phase::Ready).unwrap();
    let mut observed = json!({"pass":false,"generation":{"seed_records":16}});
    let mut events = Vec::new();
    let mut runner_calls = 0;
    let result = reported_controller_intervals(
        &controller_adapter,
        &manifest,
        &projection,
        initial,
        Instant::now() + Duration::from_secs(20),
        &mut observed,
        |id, event| {
            assert_eq!(id, 0, "no operation after terminal publication");
            events.push(event);
            if event == FullEvent::ReleasePublishEnd {
                let deadline = Instant::now() + Duration::from_secs(5);
                peer.wait(0, Phase::Release, deadline, || false, || {})
                    .unwrap();
                let op = manifest.operation(0)?;
                peer_adapter.execute(
                    &manifest,
                    &op,
                    &manifest.payload(0)?,
                    deadline,
                    |request, policy| {
                        runner_calls += 1;
                        let records: Vec<hermes_memory::MemoryRecord> =
                            serde_json::from_slice(request.input)?;
                        let (inserted, duplicates) = store.ingest_many(&records)?;
                        Ok(measured_fixture(
                            request,
                            policy,
                            &json!({"inserted":inserted,"duplicates":duplicates}),
                        ))
                    },
                )?;
                peer.publish(0, Phase::Done)?;
            }
            if event == FullEvent::IntervalFinalize {
                if fault >= 3 {
                    crate::full_workload_barrier::PUBLICATION_FAULT
                        .with(|edge| edge.set(Some(fault - 3)));
                }
                if fault == 0 {
                    let path = peer_adapter.receipt_path(0);
                    let mut receipt: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
                    receipt["command"]["stdout"] = json!("invalid receipt semantic output");
                    std::fs::write(&path, serde_json::to_vec(&receipt)?)?;
                } else if fault == 1 {
                    // Actual no-clobber publication failure after the validator retains.
                    std::fs::write(
                        ack_path.with_extension("pending"),
                        b"owned collision sentinel",
                    )?;
                }
            }
            if let FullEvent::Acquire(role) = event {
                return Ok(serde_json::to_value(cadence_read(role, 1))?);
            }
            Ok(Value::Null)
        },
    );
    crate::full_workload_barrier::PUBLICATION_FAULT.with(|edge| edge.set(None));
    // Clear the fixture admission seam before any assertion can unwind.
    STATE_MACHINE_ACK_CANCEL_PATH.with(|path| *path.borrow_mut() = None);
    let primary = result.unwrap_err().to_string();
    assert_eq!(observed["error"], primary);
    assert_eq!(runner_calls, 1);
    assert_eq!(ack_path.exists(), fault == 2 || fault == 6);
    assert!(!root
        .join("controller/full20x256-v1-op-1-release.json")
        .exists());
    assert_eq!(
        observed["metrics"]["controller_retained_commands"]
            .as_array()
            .unwrap()
            .len(),
        usize::from(fault > 0)
    );
    let saved = observed.clone();
    assert!(reported_controller_intervals(
        &controller_adapter,
        &manifest,
        &projection,
        initial,
        Instant::now() + Duration::from_secs(5),
        &mut observed,
        |_, _| panic!("retry forbidden after failed or confirmed ACK"),
    )
    .is_err());
    assert_eq!(observed, saved);
    assert!(events.contains(&FullEvent::IntervalFinalize));
    let boundary = &observed["metrics"]["operations"][0];
    assert!(boundary["cadence"]["supervisor"]["end"].is_object());
    assert!(boundary["cadence"]["broker"]["end"].is_object());
    assert_eq!(
        boundary["exact_append_verified"], true,
        "completed append verification erased for fault {fault}"
    );
    assert_eq!(
        boundary["receipt_validated"],
        fault > 0,
        "completed receipt validation erased for fault {fault}"
    );
    assert_eq!(boundary["cadence"]["state"]["command_retained"], fault > 0);
    assert_eq!(
        boundary["cadence"]["state"]["ack"],
        if fault == 0 {
            "NotStarted"
        } else if fault == 2 {
            "Confirmed"
        } else {
            "Unknown"
        }
    );
    let report = FullReport::from_observations(&observed, true).unwrap();
    let path = root.join("completed-facts.json");
    write_report_bounded(&path, &report).unwrap();
    assert_eq!(read_report(&path).unwrap()["error"], primary);
    report
}
#[test]
fn state_machine_append_fact_survives_actual_receipt_failure() {
    #[cfg(not(any(windows, all(target_os = "linux", feature = "experimental-broker"))))]
    {
        crate::data::assert_owned_store_refusal(0, "seed", "store");
    }
    #[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
    {
        state_machine_actual_completed_facts(0);
    }
}
#[test]
fn state_machine_retained_receipt_survives_actual_ack_collision() {
    #[cfg(not(any(windows, all(target_os = "linux", feature = "experimental-broker"))))]
    {
        crate::data::assert_owned_store_refusal(0, "seed", "store");
    }
    #[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
    {
        state_machine_actual_completed_facts(1);
    }
}
#[test]
fn state_machine_completed_ack_survives_postpublication_cancellation() {
    #[cfg(not(any(windows, all(target_os = "linux", feature = "experimental-broker"))))]
    {
        crate::data::assert_owned_store_refusal(0, "seed", "store");
    }
    #[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
    {
        state_machine_actual_completed_facts(2);
    }
}

#[test]
fn state_machine_unknown_ack_write_sync_link_and_after_link() {
    #[cfg(not(any(windows, all(target_os = "linux", feature = "experimental-broker"))))]
    {
        crate::data::assert_owned_store_refusal(0, "seed", "store");
    }
    #[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
    {
        for fault in 3..=6 {
            state_machine_actual_completed_facts(fault);
        }
    }
}
#[test]
fn state_machine_phase_capsule_replays_no_fabricated_ack() {
    let original = cadence_complete_fixture();
    original.validate("ordinary", 0, 3).unwrap();
    for fault in 0..5 {
        let mut c = original.clone();
        match fault {
            0 => c.state.ack = Publication::Confirmed,
            1 => c.state.command_retained = true,
            2 => c.state.append_verified = true,
            3 => c.state.receipt_validated = true,
            _ => c.state.stage = ControllerStage::Ack,
        }
        assert!(
            c.validate("ordinary", 0, 3).is_err(),
            "accepted phase forgery {fault}"
        );
    }
}

#[test]
fn state_machine_relabelled_cut_cannot_hide_slot16_success() {
    let mut report = state_machine_exact_accepted_witness();
    let c = &mut report.operations.as_mut().unwrap()[0].cadence;
    c.state.pairs = 17;
    c.state.classes[1] = 16;
    c.state.last_live = [17, 16];
    c.state.last_attempt = [17, 16];
    c.state.last_slot = 16;
    let cut = c.state.last_pair.as_mut().unwrap();
    cut.ordinal = 17;
    cut.slot = Some(16);
    cut.spans = [[32004, 32005], [32006, 32007]];
    cut.abort_check_span = Some([32006, 32007]);
    c.state.terminal.as_mut().unwrap().pair_count = 17;
    assert!(report
        .validate()
        .unwrap_err()
        .to_string()
        .contains("ordinal"));
    assert!(encode_report(&report).is_err());
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let path = temp.path().join("relabelled.json");
    assert!(write_report_bounded(&path, &report).is_err());
    assert!(!path.exists() && !path.with_extension("pending").exists());
    std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
    assert!(read_report(&path).is_err());
}
#[test]
fn state_machine_fault_matrix_genuine_prefixes_and_illegal_continuations() {
    use AcquisitionClass::{Baseline, End, Requested};
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let mut rows = 0;
    for class in [Baseline, Requested, End] {
        for successes in [1u64, 12, 15] {
            if class == Baseline && successes != 1 {
                continue;
            }
            for zero_span in [false, true] {
                for role in [CadenceRole::SupervisorB, CadenceRole::BrokerC] {
                    for fault in 0..14 {
                        if fault == 11 && role == CadenceRole::SupervisorB {
                            continue;
                        }
                        if fault >= 12 && role != CadenceRole::SupervisorB {
                            continue;
                        }
                        let mut c = Cadence::new("ordinary", 0, 3);
                        let spans = |t| {
                            if zero_span {
                                [[t, t], [t, t]]
                            } else {
                                [[t, t + 1], [t + 2, t + 3]]
                            }
                        };
                        if class != Baseline {
                            let [[bb, be], [cb, ce]] = spans(0);
                            c.record_pair(
                                None,
                                true,
                                false,
                                [
                                    (bb, be, Ok(cadence_read(CadenceRole::SupervisorB, 100))),
                                    (cb, ce, Ok(cadence_read(CadenceRole::BrokerC, 100))),
                                ],
                            )
                            .unwrap();
                            c.release_begin_us = Some(4);
                            c.release_end_us = Some(4);
                            for slot in 1..successes {
                                let t = 4 + slot * 2000;
                                let reserved = c.due(t).unwrap();
                                let [[bb, be], [cb, ce]] = spans(t);
                                c.record_pair(
                                    reserved,
                                    false,
                                    false,
                                    [
                                        (bb, be, Ok(cadence_read(CadenceRole::SupervisorB, 100))),
                                        (cb, ce, Ok(cadence_read(CadenceRole::BrokerC, 100))),
                                    ],
                                )
                                .unwrap();
                            }
                        }
                        let t = if class == Baseline {
                            0
                        } else {
                            4 + successes * 2000
                        };
                        let slot = if class == Requested {
                            c.due(t).unwrap()
                        } else {
                            None
                        };
                        if class == End {
                            c.done_validated_us = Some(t);
                        }
                        let bad = |r| -> Result<RetainedRead> {
                            match fault {
                                0 | 12 | 13 => Err(std::io::Error::other("matrix query").into()),
                                1 => Err(std::io::Error::new(
                                    std::io::ErrorKind::BrokenPipe,
                                    "matrix exit",
                                )
                                .into()),
                                11 => Err(Box::new(AbortedAcquisition)),
                                _ => {
                                    let mut read = cadence_read(r, 100);
                                    match fault {
                                        2 => read.epoch = 999,
                                        3 => read.sample.logical_io.read_operations = 0,
                                        4 => read.sample.logical_io.write_operations = 0,
                                        5 => read.sample.logical_io.other_operations = 0,
                                        6 => read.sample.logical_io.read_bytes = 0,
                                        7 => read.sample.logical_io.write_bytes = 0,
                                        8 => read.sample.logical_io.other_bytes = 0,
                                        9 => read.sample.lifetime_peak_private_bytes = 0,
                                        _ => read.sample.lifetime_peak_working_set_bytes = 0,
                                    }
                                    // No previous IO exists at baseline. Invalid-peak
                                    // rows cover that class; IO regressions need a prefix.
                                    if class == Baseline && (3..=8).contains(&fault) {
                                        read.sample.lifetime_peak_private_bytes = 0;
                                    }
                                    Ok(read)
                                }
                            }
                        };
                        let b = if role == CadenceRole::SupervisorB {
                            bad(role)
                        } else {
                            Ok(cadence_read(CadenceRole::SupervisorB, 100))
                        };
                        let cr = if fault == 12 {
                            bad(CadenceRole::BrokerC)
                        } else if fault == 13 {
                            Err(Box::new(AbortedAcquisition) as Box<dyn std::error::Error>)
                        } else if role == CadenceRole::BrokerC {
                            bad(role)
                        } else {
                            Ok(cadence_read(CadenceRole::BrokerC, 100))
                        };
                        let [[bb, be], [cb, ce]] = spans(t);
                        let primary = c
                            .record_pair(
                                slot,
                                class == Baseline,
                                class == End,
                                [(bb, be, b), (cb, ce, cr)],
                            )
                            .unwrap_err()
                            .to_string();
                        c.finish(t + 4).unwrap();
                        c.validate("ordinary", 0, 3).unwrap();
                        let before = serde_json::to_value(&c).unwrap();
                        assert!(c.due(t + 4000).is_err());
                        assert!(c
                            .record_pair(
                                Some(999),
                                false,
                                false,
                                [
                                    (
                                        t + 4000,
                                        t + 4000,
                                        Ok(cadence_read(CadenceRole::SupervisorB, 100))
                                    ),
                                    (
                                        t + 4000,
                                        t + 4000,
                                        Ok(cadence_read(CadenceRole::BrokerC, 100))
                                    )
                                ]
                            )
                            .is_err());
                        assert!(transition(&mut c.state, Transition::AckAttempt).is_err());
                        assert_eq!(serde_json::to_value(&c).unwrap(), before);
                        let decoded: Cadence = serde_json::from_value(before).unwrap();
                        decoded.validate("ordinary", 0, 3).unwrap();
                        if fault == 0
                            && role == CadenceRole::SupervisorB
                            && !zero_span
                            && (successes == 15 || class == Baseline)
                        {
                            let mut report = cadence_negative_report(c.clone());
                            report.error = Some(primary.clone());
                            report.case_stop = Some(CaseStop {
                                position: 0,
                                acknowledged_prefix: 0,
                                cause: CaseStopCause::Operation(
                                    report.operations.as_ref().unwrap()[0].cadence.state.stage,
                                ),
                                primary: primary.clone(),
                            });
                            report.controller_retained_commands = Some(vec![]);
                            report.validate().unwrap();
                            let path = temp.path().join(format!("row-{rows}.json"));
                            write_report_bounded(&path, &report).unwrap();
                            assert_eq!(read_report(&path).unwrap()["error"], primary);
                        }
                        for r in [&mut c.supervisor, &mut c.broker] {
                            r.last = Some(CadencePoint {
                                ordinal: c.state.pairs + 1,
                                class: Requested,
                                sample_begin_us: t + 4000,
                                sample_end_us: t + 4000,
                                requested_slot: Some(999),
                                read: cadence_read(r.role, 100),
                            });
                        }
                        assert!(c.validate("ordinary", 0, 3).is_err());
                        eprintln!("matrix row={rows} class={class:?} prefix={successes} zero={zero_span} role={role:?} fault={fault}");
                        rows += 1;
                    }
                }
            }
        }
    }
    assert_eq!(rows, 350);
}

mod state_machine_retained_oracle {
    use super::*;
    fn read(role: CadenceRole, n: u64) -> RetainedRead {
        RetainedRead {
            role,
            epoch: role.epoch(),
            sample: ProcessEvidence {
                logical_io: crate::measure::LogicalIo {
                    read_operations: n,
                    write_operations: 2 * n,
                    other_operations: 3 * n,
                    read_bytes: 5 * n,
                    write_bytes: 7 * n,
                    other_bytes: 11 * n,
                },
                private_bytes: if n == 14 { 900 } else { n },
                working_set_bytes: if n == 14 { 800 } else { 2 * n },
                lifetime_peak_private_bytes: 1000 + n,
                lifetime_peak_working_set_bytes: 1100 + n,
            },
        }
    }
    #[test]
    fn state_machine_1000_clock_counter_oracles() {
        let cases: Value =
            serde_json::from_str(include_str!("tests/cadence/clock-oracle.json")).unwrap();
        for v in cases.as_array().unwrap() {
            let mut c = Cadence::new("independent", 0, 3);
            let times = v["times"].as_array().unwrap();
            for (i, t) in times.iter().enumerate() {
                let a: Vec<u64> = t
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|n| n.as_u64().unwrap())
                    .collect();
                let baseline = i == 0;
                let end = i + 1 == times.len();
                if i == 1 {
                    c.release_begin_us = v["release"].as_u64();
                    c.release_end_us = v["release_end"].as_u64();
                }
                if end {
                    c.done_validated_us = v["done"].as_u64();
                }
                let slot = if !baseline && !end {
                    c.due(a[0]).unwrap()
                } else {
                    None
                };
                c.record_pair(
                    slot,
                    baseline,
                    end,
                    [
                        (a[0], a[1], Ok(read(CadenceRole::SupervisorB, i as u64 + 1))),
                        (a[2], a[3], Ok(read(CadenceRole::BrokerC, i as u64 + 1))),
                    ],
                )
                .unwrap();
            }
            c.finish(v["envelope"].as_u64().unwrap()).unwrap();
            c.validate("independent", 0, 3).unwrap();
            assert_eq!(c.requested_samples, v["requested"].as_u64().unwrap());
            assert_eq!(c.missed_slots, v["missed"].as_u64().unwrap());
            for (r, key) in [(&c.supervisor, "b"), (&c.broker, "c")] {
                assert_eq!(r.observation_max_gap_us, v[key][0].as_u64());
                assert_eq!(r.operational_max_gap_us, v[key][1].as_u64());
                assert_eq!(r.prefix.len(), 12);
                assert_eq!(r.omitted_points, times.len() as u64 - 12);
                assert_eq!(r.maxima.as_ref().unwrap().private_bytes, 900);
                assert_eq!(r.maxima.as_ref().unwrap().working_set_bytes, 800);
                assert_eq!(
                    r.baseline_to_end_io.as_ref().unwrap().other_bytes,
                    11 * (times.len() as u64 - 1)
                );
            }
        }
        println!("1000 independent Python-derived synthetic clock/counter cases passed actual candidate accumulator");
    }
}

#[test]
fn state_machine_case_finalization_preserves_all64_confirmed_acks() {
    let manifest =
        FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
    let values = commands();
    let mut operations = vec![];
    for id in 0..64 {
        let mut c = cadence_complete_fixture();
        c.operation_id = id;
        c.cli_epoch = u64::from(id) + 3;
        for stage in [
            ControllerStage::Append,
            ControllerStage::Receipt,
            ControllerStage::Retention,
            ControllerStage::Ack,
            ControllerStage::PostAck,
            ControllerStage::Complete,
        ] {
            if stage == ControllerStage::Complete {
                transition(&mut c.state, Transition::BeginGate).unwrap();
                transition(&mut c.state, Transition::EndGate).unwrap();
            }
            transition(
                &mut c.state,
                if stage == ControllerStage::Complete {
                    Transition::Seal
                } else {
                    Transition::Stage(stage)
                },
            )
            .unwrap();
            match stage {
                ControllerStage::Append => {
                    transition(&mut c.state, Transition::AppendVerified).unwrap()
                }
                ControllerStage::Receipt => {
                    transition(&mut c.state, Transition::ReceiptValidated).unwrap()
                }
                ControllerStage::Retention => {
                    transition(&mut c.state, Transition::CommandRetained).unwrap()
                }
                ControllerStage::Ack => {
                    transition(&mut c.state, Transition::AckAttempt).unwrap();
                    transition(&mut c.state, Transition::AckOutcome(Publication::Confirmed))
                        .unwrap();
                }
                _ => {}
            }
        }
        if id < 63 {
            transition(&mut c.state, Transition::PeerReady).unwrap();
        }
        operations.push(json!({"operation_id":id,"cli_epoch":c.cli_epoch,"descriptor":Descriptor::from_operation(&manifest.operation(id).unwrap()),
            "before_release":boundary_observation(&c,false).unwrap(),"after_done":boundary_observation(&c,true).unwrap(),
            "exact_append_verified":true,"receipt_validated":true,"cadence":c}));
    }
    let mut observed = json!({"pass":false,"error":"owned finalization failure","generation":{"seed_records":16},
        "client":{"case_epoch":"ordinary","commands":values,"workload_complete":true},
        "metrics":{"case_epoch":"ordinary","operations":operations,"controller_retained_commands":values,"native_handle_verified":false}});
    assert!(
        observed_case_action::<()>(&mut observed, true, CaseAction::WorkerWait, |_| Err(
            "owned finalization failure".into()
        ))
        .is_err()
    );
    let report = FullReport::from_observations(&observed, true).unwrap();
    assert_eq!(report.case_stop.as_ref().unwrap().position, 64);
    assert_eq!(report.case_stop.as_ref().unwrap().acknowledged_prefix, 64);
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let path = temp.path().join("final-stop.json");
    write_report_bounded(&path, &report).unwrap();
    let wire = read_report(&path).unwrap();
    assert_eq!(wire["operations"].as_array().unwrap().len(), 64);
    assert_eq!(
        wire["controller_retained_commands"]
            .as_array()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(wire["error"], "owned finalization failure");
    for pointer in ["/case_stop/position", "/case_stop/acknowledged_prefix"] {
        let mut bad = wire.clone();
        *bad.pointer_mut(pointer).unwrap() = json!(63);
        let bad: FullReport = serde_json::from_value(bad).unwrap();
        assert!(bad.validate().is_err());
    }
}
#[test]
fn state_machine_closed_schema_requires_terminal_and_rejects_old_incomplete() {
    let mut c = state_machine_requested_abort_prefix(15);
    c.finish(30008).unwrap();
    c.validate("architecture", 0, 3).unwrap();
    let original = serde_json::to_value(c).unwrap();
    for mutation in 0..9 {
        let mut value = original.clone();
        match mutation {
            0 => {
                value["state"].as_object_mut().unwrap().remove("terminal");
            }
            1 => value["state"]["terminal"] = Value::Null,
            2 => value["state"]["terminal"]["stage"] = json!("UnknownPhase"),
            3 => value["state"]["unexpected"] = json!(true),
            4 => value["schema"] = json!(1),
            5 => value["state"]["last_pair"]["outcomes"][0] = json!("NotAttemptedAbort"),
            6 => value["state"]["last_pair"]["abort_check_span"] = Value::Null,
            7 => value["broker"]["last"]["ordinal"] = json!(16),
            _ => value["state"]["ack"] = json!("Confirmed"),
        }
        assert_ne!(value, original);
        if let Ok(c) = serde_json::from_value::<Cadence>(value) {
            assert!(
                c.validate("architecture", 0, 3).is_err(),
                "mutation {mutation}"
            );
        }
    }
    let mut old = serde_json::to_value(state_machine_exact_accepted_witness()).unwrap();
    old["schema"] = json!(6);
    old.as_object_mut().unwrap().remove("case_stop");
    assert!(serde_json::from_value::<FullReport>(old).is_err());
}

#[test]
fn state_machine_case_pair_budget_is_checked_before_bounded_replay() {
    assert_eq!(bounded_case_pairs([150128].into_iter()).unwrap(), 150128);
    assert!(bounded_case_pairs([150128, 1].into_iter()).is_err());
    assert!(bounded_case_pairs([u64::MAX, 1].into_iter()).is_err());
    assert!(bounded_case_pairs([30002; 64].into_iter()).is_err());
}
#[test]
fn state_machine_raw_clock_fault_is_bounded_readable_and_terminal() {
    let mut c = Cadence::new("ordinary", 0, 3);
    assert!(c
        .record_pair(
            None,
            true,
            false,
            [
                (2, 1, Ok(cadence_read(CadenceRole::SupervisorB, 100))),
                (3, 4, Ok(cadence_read(CadenceRole::BrokerC, 100)))
            ]
        )
        .is_err());
    c.finish(10).unwrap();
    c.validate("ordinary", 0, 3).unwrap();
    let value = serde_json::to_value(&c).unwrap();
    assert_eq!(
        value["state"]["clock_fault"]["spans"],
        json!([[2, 1], [3, 4]])
    );
    assert!(c.due(2000).is_err());
    assert_eq!(serde_json::to_value(&c).unwrap(), value);
}
#[test]
fn state_machine_worst_case_capsule_stays_within_existing_limits() {
    let mut c = cadence_omitted_complete_fixture();
    let error: Box<dyn std::error::Error> = "\0".repeat(2048).into();
    c.fault(None, &*error);
    c.supervisor.error = Some(CadenceFailure::new(Some(CadenceRole::SupervisorB), &*error));
    c.broker.error = Some(CadenceFailure::new(Some(CadenceRole::BrokerC), &*error));
    c.case_epoch = "A".repeat(256);
    let mut value = serde_json::to_value(&c).unwrap();
    fn maximize(v: &mut Value) {
        match v {
            Value::Number(n) if n.is_u64() => *v = json!(u64::MAX),
            Value::Array(a) => {
                for v in a {
                    maximize(v);
                }
            }
            Value::Object(o) => {
                for v in o.values_mut() {
                    maximize(v);
                }
            }
            _ => {}
        }
    }
    maximize(&mut value);
    let bytes = serde_json::to_vec(&value).unwrap().len();
    eprintln!(
        "constant capsule worst-case numeric/escaped-text bytes={bytes}; case64={}",
        bytes * 64
    );
    assert!(bytes <= 32768);
    assert!(bytes * 64 <= 2097152);
}

#[test]
fn review_fix_retained_receipt_semantics_actual_collision() {
    #[cfg(not(any(windows, all(target_os = "linux", feature = "experimental-broker"))))]
    {
        crate::data::assert_owned_store_refusal(0, "seed", "store");
    }
    #[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
    {
        let report = state_machine_actual_completed_facts(1);
        assert_eq!(review_fix_ingresses(&report), [true; 4]);
        let mut results = Vec::new();
        for field in ["success", "exit_code", "capture_complete", "stdout"] {
            let mut raw = serde_json::to_value(&report).unwrap();
            let command = &mut raw["controller_retained_commands"][0];
            let original = command[field].clone();
            command[field] = match field {
                "success" | "capture_complete" => json!(false),
                "exit_code" => json!(23),
                _ => json!("{\"inserted\":0,\"duplicates\":0}"),
            };
            assert_ne!(original, command[field]);
            let bad: FullReport = serde_json::from_value(raw).unwrap();
            let result = review_fix_ingresses(&bad);
            println!("review-fix retained {field} ingress={result:?}");
            results.push(result);
        }
        assert!(
            results.iter().all(|r| *r == [false; 4]),
            "retained contradictions accepted: {results:?}"
        );
    }
}

#[test]
fn review_fix_attempted_unretained_failure_is_not_completed_receipt() {
    #[cfg(not(any(windows, all(target_os = "linux", feature = "experimental-broker"))))]
    {
        crate::data::assert_owned_store_refusal(0, "seed", "store");
    }
    #[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
    {
        let retained = state_machine_actual_completed_facts(1);
        let mut attempted = state_machine_actual_completed_facts(0);
        let mut command =
            serde_json::to_value(&retained.controller_retained_commands.as_ref().unwrap()[0])
                .unwrap();
        command["success"] = json!(false);
        command["exit_code"] = json!(23);
        command["capture_complete"] = json!(false);
        command["stdout"] = json!("failed command without valid semantic stdout");
        command["measurement"]["command_success"] = json!(false);
        attempted
            .commands
            .push(serde_json::from_value(command).unwrap());
        assert!(attempted
            .controller_retained_commands
            .as_ref()
            .unwrap()
            .is_empty());
        assert_eq!(review_fix_ingresses(&attempted), [true; 4]);
    }
}
#[test]
fn review_fix_semantic_contract_all64_operations() {
    let manifest =
        FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
    for (id, value) in commands().into_iter().enumerate() {
        let op = manifest.operation(id as u32).unwrap();
        let command: crate::full_workload_receipt::MeasuredCommand =
            serde_json::from_value(value.clone()).unwrap();
        crate::full_workload_receipt::validate_retained_command(&command, &op).unwrap();
        for field in [
            "success",
            "exit_code",
            "capture_complete",
            "stdout",
            "payload",
            "final_io",
            "live_samples",
        ] {
            let mut bad = value.clone();
            match field {
                "success" | "capture_complete" => bad[field] = json!(false),
                "exit_code" => bad[field] = json!(23),
                "stdout" => bad[field] = json!("{}"),
                "payload" => bad["measurement"]["payload_bytes"] = json!(op.payload_bytes + 1),
                "final_io" => bad["measurement"]["final_lifetime_logical_io"] = Value::Null,
                _ => bad["measurement"]["live_samples"] = json!(0),
            }
            assert_ne!(bad, value);
            let bad = serde_json::from_value(bad).unwrap();
            assert!(
                crate::full_workload_receipt::validate_retained_command(&bad, &op).is_err(),
                "id={id} field={field}"
            );
        }
    }
}

#[test]
fn review_fix_exact_frozen_malformed_witnesses_all_ingresses() {
    let witnesses = Path::new(file!())
        .parent()
        .unwrap()
        .join("tests/cadence/seal");
    let control: FullReport = serde_json::from_slice(
        &std::fs::read(witnesses.join("actual_genuine_retained_unknown_ack.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(review_fix_ingresses(&control), [true; 4]);
    for name in ["success", "exit_code", "capture_complete", "stdout"] {
        let bad: FullReport = serde_json::from_slice(
            &std::fs::read(witnesses.join(format!("malformed_retained_prefix_{name}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            review_fix_ingresses(&bad),
            [false; 4],
            "frozen retained {name}"
        );
    }
    let bad: FullReport = serde_json::from_slice(
        &std::fs::read(witnesses.join("workload_complete_without_last_ack.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        review_fix_ingresses(&bad),
        [false; 4],
        "exact frozen final ACK"
    );
}

// Exact synthetic witness bytes are repository-owned; provenance is beside them.
fn case_closure_asset(name: &str) -> FullReport {
    serde_json::from_slice(
        &std::fs::read(
            Path::new(file!())
                .parent()
                .unwrap()
                .join("tests/cadence/case-closure")
                .join(name),
        )
        .unwrap(),
    )
    .unwrap()
}
#[test]
fn case_closure_exact_owner_witness_all_ingresses() {
    assert_eq!(
        review_fix_ingresses(&case_closure_asset("owner-control.json")),
        [true; 4]
    );
    let bad = case_closure_asset("owner-contradiction.json");
    let accepted = review_fix_ingresses(&bad);
    println!("exact retained owner contradiction ingresses={accepted:?}");
    assert_eq!(accepted, [false; 4]);
}
#[test]
fn case_closure_actual_shared_partials_keep_primary_and_cleanup() {
    #[cfg(not(any(windows, all(target_os = "linux", feature = "experimental-broker"))))]
    {
        crate::data::assert_owned_store_refusal(0, "seed", "store");
    }
    #[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
    {
        for fault in [1, 2] {
            let report = state_machine_actual_completed_facts(fault);
            let mut observation = json!({"pass":false,"error":report.error,"generation":{"seed_records":16},
            "metrics":{"case_epoch":report.case_epoch,"operations":report.operations,
                "controller_retained_commands":report.controller_retained_commands,"native_handle_verified":false}});
            let primary = observation["error"].as_str().unwrap().to_owned();
            let error: Box<dyn std::error::Error> = primary.clone().into();
            observed_case_operation_failure(&mut observation, true, Some(&*error)).unwrap();
            for action in [
                CaseAction::StopClient,
                CaseAction::StopBroker,
                CaseAction::WaitBrokerExit,
            ] {
                let result = observed_case_action(&mut observation, true, action, |_| {
                    if action == CaseAction::StopBroker {
                        Err("secondary ordinary cleanup".into())
                    } else {
                        Ok(())
                    }
                });
                assert_eq!(result.is_err(), action == CaseAction::StopBroker);
            }
            let control = FullReport::from_observations(&observation, true).unwrap();
            assert_eq!(control.error.as_deref(), Some(primary.as_str()));
            assert_eq!(review_fix_ingresses(&control), [true; 4]);
            let original = serde_json::to_value(&control).unwrap();
            for replacement in [Value::Null, json!("foreign primary")] {
                let mut bad = original.clone();
                bad["case_actions"]["operation_failure"] = replacement;
                assert_ne!(bad, original);
                assert_eq!(
                    review_fix_ingresses(&serde_json::from_value(bad).unwrap()),
                    [false; 4]
                );
            }
            let mut bad = original.clone();
            bad["error"] = json!("secondary ordinary cleanup");
            bad["case_stop"]["primary"] = bad["error"].clone();
            assert_ne!(bad, original);
            assert_eq!(
                review_fix_ingresses(&serde_json::from_value(bad).unwrap()),
                [false; 4]
            );
            println!("case closure actual partial fault={fault} retained command + primary + secondary cleanup; no retry");
        }
    }
}
#[test]
fn case_closure_all14_failure_conservation_crossproduct() {
    let base = serde_json::to_value(case_closure_asset("delete-control.json")).unwrap();
    let mut rows = 0;
    for (fault, owner) in case_action_alphabet().into_iter().enumerate() {
        let mut observed = json!({});
        for (index, action) in case_action_alphabet().into_iter().enumerate() {
            if index > fault && !action.cleanup() {
                continue;
            }
            let mut called = false;
            let result = observed_case_action(&mut observed, true, action, |_| {
                called = true;
                if index == fault {
                    Err("entered ordinary primary".into())
                } else if index > fault && action == CaseAction::StopBroker {
                    Err("secondary cleanup".into())
                } else {
                    Ok(())
                }
            });
            assert!(called);
            assert_eq!(
                result.is_err(),
                index == fault || (index > fault && action == CaseAction::StopBroker)
            );
        }
        let mut raw = base.clone();
        raw["case_actions"] = observed["case_actions"].clone();
        raw["error"] = json!("entered ordinary primary");
        raw["case_stop"] = json!({"position":64,"acknowledged_prefix":64,
            "cause":{"Action":owner},"primary":"entered ordinary primary"});
        let control: FullReport = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(review_fix_ingresses(&control), [true; 4], "owner={owner:?}");
        // Presence, cause, text and frontier/index jointly mutated; each changed
        // field is asserted non-noop, and each candidate visits all four ingresses.
        for error_present in [false, true] {
            for stop_present in [false, true] {
                for cause_foreign in [false, true] {
                    for text_foreign in [false, true] {
                        for index_foreign in [false, true] {
                            if error_present
                                && stop_present
                                && !cause_foreign
                                && !text_foreign
                                && !index_foreign
                            {
                                continue;
                            }
                            let mut bad = raw.clone();
                            if !error_present {
                                bad["error"] = Value::Null;
                            }
                            if !stop_present {
                                bad["case_stop"] = Value::Null;
                            } else {
                                if cause_foreign {
                                    bad["case_stop"]["cause"] =
                                        json!({"Action":case_action_alphabet()[(fault + 1) % 14]});
                                }
                                if text_foreign {
                                    bad["case_stop"]["primary"] = json!("foreign text");
                                }
                                if index_foreign {
                                    bad["case_stop"]["position"] = json!(63);
                                }
                            }
                            assert_ne!(bad, raw);
                            assert_eq!(
                                review_fix_ingresses(&serde_json::from_value(bad).unwrap()),
                                [false; 4],
                                "fault={fault}"
                            );
                            rows += 1;
                        }
                    }
                }
            }
        }
        let mut bad = raw.clone();
        bad["case_actions"]["operation_failure"] = json!("foreign operation owner");
        assert_eq!(
            review_fix_ingresses(&serde_json::from_value(bad).unwrap()),
            [false; 4]
        );
    }
    println!("case closure all14 entered faults first/interior/last: crossproduct rows={rows}; all4 ingresses; ordinary callbacks not native stops");
}
#[test]
fn case_closure_exact_delete_witness_all_ingresses() {
    assert_eq!(
        review_fix_ingresses(&case_closure_asset("delete-control.json")),
        [true; 4]
    );
    let bad = case_closure_asset("delete-erased.json");
    let accepted = review_fix_ingresses(&bad);
    println!("exact entered DeleteClient erased primary ingresses={accepted:?}");
    assert_eq!(accepted, [false; 4]);
}
fn review_fix_ingresses(report: &FullReport) -> [bool; 4] {
    let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let path = temp.path().join("report.json");
    let accepted = [
        report.validate().is_ok(),
        encode_report(report).is_ok(),
        write_report_bounded(&path, report).is_ok(),
    ];
    if accepted[2] {
        assert!(path.exists());
    } else {
        assert!(!path.exists(), "rejected writer must not create target");
    }
    std::fs::write(&path, serde_json::to_vec(report).unwrap()).unwrap();
    [
        accepted[0],
        accepted[1],
        accepted[2],
        read_report(&path).is_ok(),
    ]
}
#[test]
fn review_fix_complete_requires_every_confirmed_ack() {
    let path = Path::new(file!())
        .parent()
        .unwrap()
        .join("tests/cadence/seal/original_full64.json");
    let report: FullReport =
        serde_json::from_value(read_report(Path::new(&path)).unwrap()).unwrap();
    assert_eq!(review_fix_ingresses(&report), [true; 4]);
    let mut outcomes = Vec::new();
    for id in [0, 31, 63] {
        for ack in [
            Publication::NotStarted,
            Publication::Attempted,
            Publication::Unknown,
        ] {
            let mut raw = serde_json::to_value(&report).unwrap();
            raw["operations"][id]["cadence"]["state"]["stage"] = json!("Ack");
            raw["operations"][id]["cadence"]["state"]["ack"] = serde_json::to_value(ack).unwrap();
            // Remove next-READY so the final operation witness and boundary audit
            // fail on completion, not an unrelated peer-consumption prerequisite.
            raw["operations"][id]["cadence"]["state"]["peer_consumption"] = json!("NotObserved");
            let bad: FullReport = serde_json::from_value(raw).unwrap();
            let result = review_fix_ingresses(&bad);
            println!("review-fix complete id={id} ack={ack:?} ingress={result:?}");
            outcomes.push(result);
        }
    }
    assert!(
        outcomes.iter().all(|result| *result == [false; 4]),
        "incomplete ACK accepted: {outcomes:?}"
    );
}

#[test]
fn causal_exact_three_witnesses_all_four_ingresses() {
    let directory = Path::new(file!())
        .parent()
        .unwrap()
        .join("tests/cadence/seal");
    let control: FullReport = serde_json::from_slice(
        &std::fs::read(directory.join("actual_genuine_retained_unknown_ack.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(review_fix_ingresses(&control), [true; 4]);
    let mut results = Vec::new();
    for name in [
        "cause-mutation-0.json",
        "cause-mutation-1.json",
        "cause-mutation-4.json",
    ] {
        let bytes = std::fs::read(directory.join(name)).unwrap();
        let report: FullReport = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(report.schema, control.schema);
        let result = review_fix_ingresses(&report);
        println!("exact causal witness {name}: {result:?}");
        results.push(result);
    }
    assert_eq!(results, vec![[false; 4]; 3]);
}

fn causal_report_prefix(id: usize, ack: Publication) -> FullReport {
    let mut raw: Value =
        serde_json::from_str(include_str!("tests/cadence/seal/original_full64.json")).unwrap();
    raw["operations"].as_array_mut().unwrap().truncate(id + 1);
    raw["commands"].as_array_mut().unwrap().truncate(id + 1);
    raw["controller_retained_commands"]
        .as_array_mut()
        .unwrap()
        .truncate(id + 1);
    for field in ["pass", "correctness_complete", "workload_complete"] {
        raw[field] = json!(false);
    }
    let primary = "synthetic causal boundary";
    // Synthetic operation prefixes did not enter case finalization callbacks.
    raw["case_actions"] = Value::Null;
    raw["error"] = json!(primary);
    raw["case_stop"] = json!({"position":id,"acknowledged_prefix":id + usize::from(ack == Publication::Confirmed),
        "primary":primary,"cause":{"Operation":"Ack"}});
    let c = &mut raw["operations"][id]["cadence"];
    c["state"]["stage"] = json!("Ack");
    c["state"]["sealed"] = json!(false);
    c["state"]["primary_finalized"] = json!(true);
    c["state"]["post_ack_checked"] = json!(false);
    c["state"]["action"] = json!({"Phase":"Ack"});
    c["state"]["ack"] = serde_json::to_value(ack).unwrap();
    c["state"]["peer_consumption"] = json!("NotObserved");
    c["state"]["terminal"] = json!({"cause":if ack == Publication::Unknown {"PublicationUnknown"} else {"ControllerFailure"},
        "action":{"Phase":"Ack"},"stage":"Ack","pair_count":c["state"]["pairs"],"pending_slot":null,"primary":primary});
    c["failure"] = json!({"role":null,"kind":"controller","os_code":null,"text":primary});
    c["evidence_complete"] = json!(false);
    c["cadence_target_met"] = json!(false);
    if ack == Publication::Confirmed {
        raw["case_stop"]["cause"] = json!({"Operation":"PostAck"});
        let c = &mut raw["operations"][id]["cadence"];
        c["state"]["stage"] = json!("PostAck");
        c["state"]["action"] = json!({"Gate":"PostAck"});
        c["state"]["terminal"]["stage"] = json!("PostAck");
        c["state"]["terminal"]["action"] = json!({"Gate":"PostAck"});
        c["state"]["terminal"]["cause"] = json!("AdmissionStopped");
    }
    serde_json::from_value(raw).unwrap()
}
#[test]
fn causal_coordinated_first_interior_final_all_ingresses() {
    for id in [0, 31, 63] {
        for ack in [Publication::Unknown, Publication::Confirmed] {
            let report = causal_report_prefix(id, ack);
            assert_eq!(
                review_fix_ingresses(&report),
                [true; 4],
                "control {id} {ack:?}"
            );
            let original = serde_json::to_value(&report).unwrap();
            for cause in [
                StopCause::PublicationUnknown,
                StopCause::AcquisitionFault,
                StopCause::InvalidClock,
                StopCause::AdmissionStopped,
                StopCause::ControllerFailure,
            ] {
                let expected = match ack {
                    Publication::Unknown => cause == StopCause::PublicationUnknown,
                    _ => matches!(cause, StopCause::AdmissionStopped),
                };
                if original["operations"][id]["cadence"]["state"]["terminal"]["cause"]
                    == serde_json::to_value(cause).unwrap()
                {
                    continue; // Already exercised control, not a mutation.
                }
                let mut raw = original.clone();
                raw["operations"][id]["cadence"]["state"]["terminal"]["cause"] =
                    serde_json::to_value(cause).unwrap();
                assert_ne!(raw, original);
                let bad = serde_json::from_value(raw).unwrap();
                assert_eq!(
                    review_fix_ingresses(&bad),
                    [expected; 4],
                    "cause {id} {ack:?} {cause:?}"
                );
            }
            if ack == Publication::Unknown {
                let mut raw = original.clone();
                raw["operations"][id]["cadence"]["state"]["ack"] = json!("Confirmed");
                raw["case_stop"]["acknowledged_prefix"] = json!(id + 1);
                let bad = serde_json::from_value(raw).unwrap();
                assert_eq!(review_fix_ingresses(&bad), [false; 4]);
                let mut raw = original.clone();
                raw["operations"][id]["cadence"]["state"]["terminal"] = Value::Null;
                raw["operations"][id]["cadence"]["failure"] = Value::Null;
                raw["operations"][id]["cadence"]["evidence_complete"] = json!(true);
                raw["case_stop"]["cause"] = json!("ExternalObservation");
                raw["case_stop"]["position"] = json!(id + 1);
                let bad = serde_json::from_value(raw).unwrap();
                assert_eq!(review_fix_ingresses(&bad), [false; 4]);
            }
        }
    }
}

#[test]
fn causal_reducer_outcome_admissibility_table() {
    use ControllerStage::*;
    let causes = [
        StopCause::AcquisitionFault,
        StopCause::AdmissionStopped,
        StopCause::PublicationUnknown,
        StopCause::ControllerFailure,
        StopCause::InvalidClock,
    ];
    let mut rows = 0;
    // Every admitted stage and both publication roles; build the positive
    // phase path through actual transition events, not preselected scalars.
    let mut state = WorkloadState::new();
    let mut prefixes = vec![state.clone()];
    for stage in [
        Preparation,
        Baseline,
        Release,
        Done,
        End,
        Finalize,
        Append,
        Receipt,
        Retention,
        Ack,
        PostAck,
        Complete,
    ] {
        match stage {
            Release | Finalize => {
                let ordinal = state.pairs + 1;
                transition(
                    &mut state,
                    Transition::Close(PairCut {
                        ordinal,
                        class: if stage == Release {
                            AcquisitionClass::Baseline
                        } else {
                            AcquisitionClass::End
                        },
                        slot: None,
                        spans: [[0, 0]; 2],
                        outcomes: [ReadOutcome::Live; 2],
                        abort_check_span: None,
                    }),
                )
                .unwrap();
            }
            _ => {}
        }
        if stage == ControllerStage::Complete {
            transition(&mut state, Transition::BeginGate).unwrap();
            transition(&mut state, Transition::EndGate).unwrap();
        }
        transition(
            &mut state,
            if stage == ControllerStage::Complete {
                Transition::Seal
            } else {
                Transition::Stage(stage)
            },
        )
        .unwrap();
        prefixes.push(state.clone());
        match stage {
            Release => {
                transition(&mut state, Transition::ReleaseAttempt).unwrap();
                prefixes.push(state.clone());
                for outcome in [Publication::Unknown, Publication::Confirmed] {
                    let mut s = state.clone();
                    transition(&mut s, Transition::ReleaseOutcome(outcome)).unwrap();
                    prefixes.push(s);
                }
                transition(
                    &mut state,
                    Transition::ReleaseOutcome(Publication::Confirmed),
                )
                .unwrap();
            }
            Done => {
                transition(&mut state, Transition::DoneValidated).unwrap();
                prefixes.push(state.clone());
            }
            Append => {
                transition(&mut state, Transition::AppendVerified).unwrap();
                prefixes.push(state.clone());
            }
            Receipt => {
                transition(&mut state, Transition::ReceiptValidated).unwrap();
                prefixes.push(state.clone());
            }
            Retention => {
                transition(&mut state, Transition::CommandRetained).unwrap();
                prefixes.push(state.clone());
            }
            Ack => {
                transition(&mut state, Transition::AckAttempt).unwrap();
                prefixes.push(state.clone());
                for outcome in [Publication::Unknown, Publication::Confirmed] {
                    let mut s = state.clone();
                    transition(&mut s, Transition::AckOutcome(outcome)).unwrap();
                    prefixes.push(s);
                }
                transition(&mut state, Transition::AckOutcome(Publication::Confirmed)).unwrap();
            }
            _ => {}
        }
    }
    for s in prefixes {
        let unknown = s.ack == Publication::Unknown || s.release == Publication::Unknown;
        assert_eq!(
            transition(&mut s.clone(), Transition::CausalBoundary).is_ok(),
            !unknown
        );
        for cause in causes {
            let mut t = s.clone();
            t.terminal = Some(TerminalCut {
                action: t.action.unwrap_or(OperationAction::Phase(t.stage)),
                cause,
                stage: t.stage,
                pair_count: t.pairs,
                pending_slot: t.pending_slot,
                primary: "table".into(),
            });
            let expected = if s.sealed
                || s.stage == ControllerStage::PostAck
                || (s.stage == ControllerStage::Ack && s.ack == Publication::Confirmed)
            {
                false
            } else if unknown {
                cause == StopCause::PublicationUnknown
            } else {
                matches!(cause, StopCause::ControllerFailure)
            };
            assert_eq!(
                transition(&mut t, Transition::CausalBoundary).is_ok(),
                expected,
                "stage={:?} cause={cause:?}",
                s.stage
            );
            rows += 1;
        }
    }
    // All reachable sequential role-pair outcome combinations: B is always
    // attempted; C may be skipped only by the between-role admission check.
    for class in [
        AcquisitionClass::Baseline,
        AcquisitionClass::Requested,
        AcquisitionClass::End,
    ] {
        for b in [
            ReadOutcome::Live,
            ReadOutcome::Exit,
            ReadOutcome::QueryError,
            ReadOutcome::InvalidSample,
        ] {
            for c in [
                ReadOutcome::Live,
                ReadOutcome::Exit,
                ReadOutcome::QueryError,
                ReadOutcome::InvalidSample,
                ReadOutcome::NotAttemptedAbort,
            ] {
                let mut s = WorkloadState::new();
                if class != AcquisitionClass::Baseline {
                    transition(
                        &mut s,
                        Transition::Close(PairCut {
                            ordinal: 1,
                            class: AcquisitionClass::Baseline,
                            slot: None,
                            spans: [[0, 0]; 2],
                            outcomes: [ReadOutcome::Live; 2],
                            abort_check_span: None,
                        }),
                    )
                    .unwrap();
                }
                let slot = if class == AcquisitionClass::Requested {
                    Some(1)
                } else {
                    None
                };
                if let Some(slot) = slot {
                    transition(&mut s, Transition::Reserve(slot)).unwrap();
                }
                let ordinal = s.pairs + 1;
                transition(
                    &mut s,
                    Transition::Close(PairCut {
                        ordinal,
                        class,
                        slot,
                        spans: [[0, 0]; 2],
                        outcomes: [b, c],
                        abort_check_span: if c == ReadOutcome::NotAttemptedAbort {
                            Some([0, 0])
                        } else {
                            None
                        },
                    }),
                )
                .unwrap();
                for cause in causes {
                    let mut t = s.clone();
                    t.terminal = Some(TerminalCut {
                        action: t.action.unwrap_or(OperationAction::Phase(t.stage)),
                        cause,
                        stage: t.stage,
                        pair_count: t.pairs,
                        pending_slot: t.pending_slot,
                        primary: "pair table".into(),
                    });
                    let expected = cause
                        == if [b, c] == [ReadOutcome::Live; 2] {
                            StopCause::ControllerFailure
                        } else {
                            StopCause::AcquisitionFault
                        };
                    assert_eq!(
                        transition(&mut t, Transition::CausalBoundary).is_ok(),
                        expected
                    );
                    rows += 1;
                }
                let mut clock = s.clone();
                transition(
                    &mut clock,
                    Transition::ClockFault(ClockFaultCut {
                        ordinal: ordinal + 1,
                        class,
                        slot: None,
                        spans: [[1, 0], [0, 0]],
                    }),
                )
                .unwrap();
                for cause in causes {
                    clock.terminal.as_mut().unwrap().cause = cause;
                    assert_eq!(
                        transition(&mut clock.clone(), Transition::CausalBoundary).is_ok(),
                        matches!(cause, StopCause::InvalidClock)
                    );
                    rows += 1;
                }
            }
        }
    }
    println!("causal admissibility rows={rows}");
}

fn case_action_fixture() -> CaseActions {
    // Explicit synthetic structural control, not native finalization evidence.
    let mut actions = CaseActions::default();
    for action in case_action_alphabet() {
        case_transition(&mut actions, CaseTransition::Enter(action)).unwrap();
        case_transition(&mut actions, CaseTransition::Outcome(action, None)).unwrap();
    }
    actions
}
fn case_action_alphabet() -> [CaseAction; 14] {
    use CaseAction::*;
    [
        WorkerWait,
        WorkerRead,
        WorkerObservation,
        SourceBeforeStop,
        StopClient,
        StopBroker,
        WaitBrokerExit,
        CleanExits,
        StoppedSqlite,
        SourceAfterStop,
        Projection,
        Export,
        FinalBrokerObservation,
        DeleteClient,
    ]
}
#[test]
fn operation_seal_case_action_entered_outcome_matrix() {
    let actions = case_action_alphabet();
    let mut edges = 0;
    for fault in 0..14 {
        let mut observation = json!({});
        for (index, action) in actions.iter().copied().enumerate() {
            if index > fault && !action.cleanup() {
                continue;
            }
            let mut invoked = false;
            let result = observed_case_action(&mut observation, true, action, |_| {
                invoked = true;
                if index == fault {
                    Err("observed primary".into())
                } else {
                    Ok(())
                }
            });
            assert!(invoked);
            assert_eq!(result.is_err(), index == fault);
        }
        let state: CaseActions =
            serde_json::from_value(observation["case_actions"].clone()).unwrap();
        state.validate().unwrap();
        assert_eq!(state.failure().unwrap().action, actions[fault]);
        assert_eq!(
            state.failure().unwrap().error.as_deref(),
            Some("observed primary")
        );
        assert!(!state.complete());
        for action in actions {
            for error in [None, Some("foreign outcome".into())] {
                let mut bad = state.clone();
                assert!(case_transition(&mut bad, CaseTransition::Outcome(action, error)).is_err());
                assert_eq!(bad, state);
                edges += 1;
            }
            let mut entered = CaseActions::default();
            for prefix in actions.iter().take(action as usize) {
                case_transition(&mut entered, CaseTransition::Enter(*prefix)).unwrap();
                case_transition(&mut entered, CaseTransition::Outcome(*prefix, None)).unwrap();
            }
            case_transition(&mut entered, CaseTransition::Enter(action)).unwrap();
            for owner in actions {
                let mut outcome = entered.clone();
                let accepted =
                    case_transition(&mut outcome, CaseTransition::Outcome(owner, None)).is_ok();
                assert_eq!(accepted, owner == action);
                if !accepted {
                    assert_eq!(outcome, entered);
                }
                edges += 1;
            }
        }
    }
    let success = case_action_fixture();
    assert!(success.complete());
    for action in actions {
        let mut bad = success.clone();
        assert!(case_transition(&mut bad, CaseTransition::Enter(action)).is_err());
        assert_eq!(bad, success);
    }
    println!("case entered-owner/outcome edges={edges}; fault callbacks=14; no native actions");
}

#[test]
fn operation_seal_case_finite_state_edge_exploration() {
    use std::collections::{HashSet, VecDeque};
    let actions = case_action_alphabet();
    let mut queue = VecDeque::from([CaseActions::default()]);
    let mut seen = HashSet::new();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    while let Some(state) = queue.pop_front() {
        let key = serde_json::to_string(&state).unwrap();
        if !seen.insert(key) {
            continue;
        }
        assert!(seen.len() <= 50000, "state exploration ceiling");
        for action in actions {
            let last = state.records.last().map_or(-1, |r| r.action as i16);
            let fault = state.operation_failure.is_some()
                || state.records.iter().any(|r| r.error.is_some());
            let a = action as i16;
            let expected = state.entered.is_none()
                && state.records.len() < 14
                && (!fault || (4..=6).contains(&a))
                && if (4..=6).contains(&a) {
                    a > last
                } else {
                    a == last + 1
                };
            let mut next = state.clone();
            let actual = case_transition(&mut next, CaseTransition::Enter(action)).is_ok();
            assert_eq!(
                actual, expected,
                "independent enter rule {state:?} {action:?}"
            );
            if actual {
                accepted += 1;
                queue.push_back(next);
            } else {
                rejected += 1;
                assert_eq!(next, state);
            }
            for error in [None, Some("model observed failure".to_owned())] {
                let mut next = state.clone();
                let actual =
                    case_transition(&mut next, CaseTransition::Outcome(action, error)).is_ok();
                assert_eq!(actual, state.entered == Some(action));
                if actual {
                    accepted += 1;
                    queue.push_back(next);
                } else {
                    rejected += 1;
                    assert_eq!(next, state);
                }
            }
        }
        let mut next = state.clone();
        let actual = case_transition(
            &mut next,
            CaseTransition::OperationFailed("model operation primary".into()),
        )
        .is_ok();
        assert_eq!(
            actual,
            state.records.is_empty()
                && state.entered.is_none()
                && state.operation_failure.is_none()
        );
        if actual {
            accepted += 1;
            queue.push_back(next);
        } else {
            rejected += 1;
            assert_eq!(next, state);
        }
        assert!(accepted + rejected <= 1000000, "edge exploration ceiling");
    }
    println!("closed case BFS states={} accepted={accepted} rejected={rejected} all14 actions/all outcomes/operation-owner; exhaustive finite alphabet", seen.len());
}

#[test]
fn operation_seal_relabelled_terminal_owners_all_ingresses() {
    for id in [0, 31, 63] {
        let control = causal_report_prefix(id, Publication::Confirmed);
        assert_eq!(review_fix_ingresses(&control), [true; 4]);
        let original = serde_json::to_value(control).unwrap();
        for cause in ["ControllerFailure", "AdmissionStopped"] {
            for sealed in [false, true] {
                let mut raw = original.clone();
                raw["operations"][id]["cadence"]["state"]["stage"] = json!("Complete");
                raw["operations"][id]["cadence"]["state"]["sealed"] = json!(sealed);
                raw["operations"][id]["cadence"]["state"]["post_ack_checked"] = json!(true);
                let key = if cause == "AdmissionStopped" {
                    "Gate"
                } else {
                    "Phase"
                };
                let action = json!({key:"Complete"});
                raw["operations"][id]["cadence"]["state"]["action"] = action.clone();
                raw["operations"][id]["cadence"]["state"]["terminal"]["action"] = action;
                raw["operations"][id]["cadence"]["state"]["terminal"]["stage"] = json!("Complete");
                raw["operations"][id]["cadence"]["state"]["terminal"]["cause"] = json!(cause);
                raw["case_stop"]["cause"] = json!({"Operation":"Complete"});
                assert_ne!(raw, original);
                let bad: FullReport = serde_json::from_value(raw).unwrap();
                assert_eq!(
                    review_fix_ingresses(&bad),
                    [false; 4],
                    "id={id} cause={cause} sealed={sealed}"
                );
            }
        }
    }
}

#[test]
fn operation_seal_case_error_requires_entered_finalization_action() {
    let mut raw = serde_json::to_value(causal_report_prefix(63, Publication::Confirmed)).unwrap();
    let c = &mut raw["operations"][63]["cadence"];
    c["state"]["stage"] = json!("Complete");
    c["state"]["sealed"] = json!(true);
    c["state"]["primary_finalized"] = json!(false);
    c["state"]["post_ack_checked"] = json!(true);
    c["state"]["action"] = Value::Null;
    c["state"]["terminal"] = Value::Null;
    c["failure"] = Value::Null;
    c["evidence_complete"] = json!(true);
    c["cadence_target_met"] = json!(false);
    raw["case_stop"]["cause"] = json!("ExternalObservation");
    raw["case_stop"]["position"] = json!(64);
    let report: FullReport = serde_json::from_value(raw).unwrap();
    assert_eq!(
        review_fix_ingresses(&report),
        [false; 4],
        "no entered case action owns this finalization failure"
    );
}

#[test]
fn operation_seal_is_absorbing_for_every_operational_event() {
    let report = causal_report_prefix(63, Publication::Confirmed);
    let state = &report.operations.as_ref().unwrap()[0].cadence.state;
    assert!(state.complete_confirmed());
    for id in [0, 31, 63] {
        let mut closed = state.clone();
        closed.peer_consumption = PeerConsumption::NotObserved;
        let cut = closed.last_pair.clone().unwrap();
        let events = vec![
            Transition::Seal,
            Transition::BeginGate,
            Transition::EndGate,
            Transition::AdmitPair,
            Transition::AdmitClass(AcquisitionClass::Baseline, None),
            Transition::Reserve(1),
            Transition::Close(cut),
            Transition::ClockFault(ClockFaultCut {
                ordinal: closed.pairs + 1,
                class: AcquisitionClass::End,
                slot: None,
                spans: [[1, 0]; 2],
            }),
            Transition::Stage(ControllerStage::Complete),
            Transition::AppendVerified,
            Transition::ReceiptValidated,
            Transition::CommandRetained,
            Transition::AckAttempt,
            Transition::AckOutcome(Publication::Unknown),
            Transition::ReleaseAttempt,
            Transition::ReleaseOutcome(Publication::Unknown),
            Transition::DoneValidated,
            Transition::Stop("late operation failure".into()),
            Transition::PrimaryStop(
                "late admission".into(),
                FailureObservation::AdmissionStopped,
            ),
        ];
        for (index, event) in events.into_iter().enumerate() {
            let before = closed.clone();
            assert!(
                transition(&mut closed, event).is_err(),
                "id={id} event={index}"
            );
            assert_eq!(closed, before, "atomic rejection id={id} event={index}");
        }
        transition(&mut closed, Transition::PeerReady).unwrap();
        assert!(transition(&mut closed, Transition::PeerReady).is_err());
        transition(&mut closed, Transition::CausalBoundary).unwrap();
        let stopped_report = causal_report_prefix(id as usize, Publication::Unknown);
        let mut stopped = stopped_report
            .operations
            .as_ref()
            .unwrap()
            .last()
            .unwrap()
            .cadence
            .state
            .clone();
        let before = stopped.clone();
        for event in [
            Transition::BeginGate,
            Transition::EndGate,
            Transition::Seal,
            Transition::AdmitPair,
            Transition::PeerReady,
            Transition::Stop("retry".into()),
            Transition::PrimaryStop("rewrite".into(), FailureObservation::AdmissionStopped),
        ] {
            assert!(transition(&mut stopped, event).is_err());
            assert_eq!(stopped, before);
        }
        transition(&mut stopped, Transition::CausalBoundary).unwrap();
    }
}

#[test]
fn causal_architecture_complete_operation_cannot_claim_new_failure() {
    let mut raw = serde_json::to_value(causal_report_prefix(63, Publication::Confirmed)).unwrap();
    raw["operations"][63]["cadence"]["state"]["stage"] = json!("Complete");
    raw["operations"][63]["cadence"]["state"]["terminal"]["stage"] = json!("Complete");
    raw["case_stop"]["cause"] = json!({"Operation":"Complete"});
    let report: FullReport = serde_json::from_value(raw.clone()).unwrap();
    let result = review_fix_ingresses(&report);
    let temp = Path::new(&std::env::var_os("TMPDIR").unwrap())
        .join("architecture-complete-operation-cause.json");
    std::fs::write(&temp, serde_json::to_vec_pretty(&raw).unwrap()).unwrap();
    println!(
        "architectural Complete-operation terminal ingress={result:?} witness={}",
        temp.display()
    );
    assert_eq!(
        result, [false; 4],
        "Complete has returned successfully; later external case failure cannot be operation-owned"
    );
}
