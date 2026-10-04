use super::*;
use crate::full_manifest::WorkloadSpec;

fn root() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for name in ["scratch", "controller"] {
        std::fs::create_dir(dir.path().join(name)).unwrap();
    }
    dir
}
fn ack(op: &Operation) -> Ack {
    Ack {
        schema: 1,
        operation_id: op.id,
        cli_epoch: op.cli_epoch,
        payload_bytes: op.payload_bytes,
        inserted: op.inserted,
        duplicates: op.duplicates,
        sessions: op.sessions,
    }
}
fn wait(b: &mut FullBarrier<'_>, id: u32, phase: Phase) {
    b.wait(
        id,
        phase,
        Instant::now() + Duration::from_secs(5),
        || false,
        || {},
    )
    .unwrap();
}
#[test]
fn exactly_64_operations_require_validated_receipt_before_next_release() {
    let dir = root();
    let m = FullManifest::new(WorkloadSpec::full20x256_v1(), 16).unwrap();
    let mut peer = FullBarrier::new(dir.path(), "run", Role::Peer, &m).unwrap();
    let mut controller = FullBarrier::new(dir.path(), "run", Role::Controller, &m).unwrap();
    for id in 0..64 {
        peer.publish(id, Phase::Ready).unwrap();
        wait(&mut controller, id, Phase::Ready);
        controller.publish(id, Phase::Release).unwrap();
        wait(&mut peer, id, Phase::Release);
        peer.publish(id, Phase::Done).unwrap();
        wait(&mut controller, id, Phase::Done);
        assert!(peer.publish(id + 1, Phase::Ready).is_err());
        assert!(controller.publish(id + 1, Phase::Release).is_err());
        assert!(controller.publish(id, Phase::ValidatedAck).is_err());
        assert!(controller
            .acknowledge(
                id,
                &(),
                |_, _, _| Err("receipt incomplete".into()),
                || false
            )
            .is_err());
        assert!(!controller.path(id, Phase::ValidatedAck).exists());
        controller
            .acknowledge(
                id,
                &(),
                |op, payload, _| {
                    assert_eq!(payload, m.payload(id).unwrap());
                    Ok(ack(op))
                },
                || false,
            )
            .unwrap();
        wait(&mut peer, id, Phase::ValidatedAck);
    }
    assert!(peer.complete() && controller.complete());
    assert!(peer.publish(64, Phase::Ready).is_err());
    assert!(controller
        .acknowledge(63, &(), |op, _, _| Ok(ack(op)), || false)
        .is_err());
}

#[test]
fn distant_future_publication_is_rejected_without_advancing() {
    let dir = root();
    let m = FullManifest::new(WorkloadSpec::full20x256_v1(), 16).unwrap();
    let mut peer = FullBarrier::new(dir.path(), "run", Role::Peer, &m).unwrap();
    let sentinel = peer.path(63, Phase::ValidatedAck);
    std::fs::write(&sentinel, b"future-sentinel").unwrap();
    assert!(peer.publish(0, Phase::Ready).is_err());
    assert_eq!(peer.next, 0);
    assert_eq!(std::fs::read(sentinel).unwrap(), b"future-sentinel");
}

#[test]
fn ordinary_peer_observes_missing_ack_then_runs_all_64_callbacks() {
    use std::cell::Cell;
    use std::sync::mpsc::channel;
    let dir = root();
    let m = FullManifest::new(WorkloadSpec::full20x256_v1(), 16).unwrap();
    let (events, observed) = channel();
    let (resume, resumed) = channel();
    std::thread::scope(|scope| {
        let path = dir.path();
        let mref = &m;
        let peer = scope.spawn(move || {
            let probed = Cell::new(false);
            run_peer(
                path,
                "run",
                mref,
                Instant::now() + Duration::from_secs(60),
                || false,
                |op, payload| {
                    assert_eq!(payload, mref.payload(op.id).unwrap());
                    // Ordinary receipt only; no command/measurement/native claim.
                    crate::contract::json_new(
                        &path.join(format!("ordinary-{}.json", op.id)),
                        &ack(op),
                    )?;
                    events.send((op.id, Phase::Done)).unwrap();
                    Ok(())
                },
                |id, phase| {
                    if id == 0 && phase == Phase::ValidatedAck && !probed.replace(true) {
                        events.send((id, phase)).unwrap();
                        resumed.recv_timeout(Duration::from_secs(10)).unwrap();
                    }
                },
            )
            .unwrap();
        });
        let mut controller = FullBarrier::new(path, "run", Role::Controller, &m).unwrap();
        for id in 0..64 {
            wait(&mut controller, id, Phase::Ready);
            controller.publish(id, Phase::Release).unwrap();
            assert_eq!(
                observed.recv_timeout(Duration::from_secs(10)).unwrap(),
                (id, Phase::Done)
            );
            wait(&mut controller, id, Phase::Done);
            if id == 0 {
                assert_eq!(
                    observed.recv_timeout(Duration::from_secs(10)).unwrap(),
                    (0, Phase::ValidatedAck)
                );
                assert!(!controller.path(0, Phase::ValidatedAck).exists());
                assert!(!controller.path(1, Phase::Ready).exists());
                assert!(!path.join("ordinary-1.json").exists());
                assert!(controller.publish(1, Phase::Release).is_err());
            }
            let receipt: Ack = serde_json::from_slice(
                &std::fs::read(path.join(format!("ordinary-{id}.json"))).unwrap(),
            )
            .unwrap();
            controller
                .acknowledge(
                    id,
                    &receipt,
                    |op, _, r| {
                        assert_eq!(*r, ack(op));
                        Ok(r.clone())
                    },
                    || false,
                )
                .unwrap();
            if id == 0 {
                resume.send(()).unwrap();
            }
        }
        peer.join().unwrap();
        assert!(controller.complete());
    });
    assert!(dir.path().join("ordinary-63.json").exists());
}

#[test]
fn pure_message_state_rejects_wrong_future_duplicate_stale_bindings() {
    let m = FullManifest::new(WorkloadSpec::full20x256_v1(), 16).unwrap();
    // validate() is pure: no directories/files are consulted or created.
    let mut b = FullBarrier::new(Path::new("not-accessed"), "run", Role::Peer, &m).unwrap();
    for id in 0..64 {
        for phase in PHASES {
            let valid = Message {
                schema: 1,
                protocol: Protocol::Full20x256BarrierV1,
                epoch: "run".into(),
                operation_id: id,
                cli_epoch: m.operation(id).unwrap().cli_epoch,
                phase,
                ack: (phase == Phase::ValidatedAck).then(|| ack(&m.operation(id).unwrap())),
            };
            b.validate(&valid, id, phase).unwrap();
            let original = serde_json::to_value(&valid).unwrap();
            for (field, value) in [
                ("schema", serde_json::json!(2)),
                ("epoch", serde_json::json!("stale")),
                ("cli_epoch", serde_json::json!(valid.cli_epoch + 1)),
                ("operation_id", serde_json::json!(u32::MAX)),
                ("phase", serde_json::json!(PHASES[(phase as usize + 1) % 4])),
            ] {
                let mut bad = original.clone();
                bad[field] = value;
                let bad: Message = serde_json::from_value(bad).unwrap();
                assert!(b.validate(&bad, id, phase).is_err());
                assert_eq!(b.next, id as usize * 4 + phase as usize);
            }
            b.next += 1;
            assert!(b.validate(&valid, id, phase).is_err());
        }
    }
    assert!(b.complete());
}

#[test]
fn malformed_wire_and_ack_never_advance_or_change_files() {
    use serde_json::json;
    let m = FullManifest::new(WorkloadSpec::full20x256_v1(), 16).unwrap();
    let valid = json!({"schema":1,"protocol":"Full20x256BarrierV1","epoch":"run",
        "operation_id":0,"cli_epoch":3,"phase":"ready","ack":null});
    let mut wires = vec![
        b"{".to_vec(),
        vec![b' '; 1025],
        b"null".to_vec(),
        br#"{"schema":1,"schema":1}"#.to_vec(),
    ];
    for (field, values) in [
        (
            "schema",
            vec![
                json!(true),
                json!("1"),
                json!(1.5),
                json!(-1),
                json!(256),
                json!(null),
                json!(2),
            ],
        ),
        (
            "operation_id",
            vec![
                json!(true),
                json!("0"),
                json!(-1),
                json!(4294967296u64),
                json!(63),
            ],
        ),
        (
            "cli_epoch",
            vec![json!(true), json!("3"), json!(-1), json!(3.5), json!(4)],
        ),
        ("protocol", vec![json!("other"), json!(null)]),
        ("epoch", vec![json!("stale"), json!(null)]),
        ("phase", vec![json!("done"), json!("unknown")]),
        (
            "ack",
            vec![serde_json::to_value(ack(&m.operation(0).unwrap())).unwrap()],
        ),
        ("unknown", vec![json!(true)]),
    ] {
        for value in values {
            let mut bad = valid.clone();
            bad[field] = value;
            wires.push(serde_json::to_vec(&bad).unwrap());
        }
    }
    let mut overflow = valid.clone();
    overflow["cli_epoch"] = json!("OVERFLOW_VALUE");
    wires.push(
        serde_json::to_string(&overflow)
            .unwrap()
            .replace("\"OVERFLOW_VALUE\"", "18446744073709551616")
            .into_bytes(),
    );
    for field in [
        "schema",
        "protocol",
        "epoch",
        "operation_id",
        "cli_epoch",
        "phase",
    ] {
        let mut bad = valid.clone();
        bad.as_object_mut().unwrap().remove(field);
        wires.push(serde_json::to_vec(&bad).unwrap());
    }
    for bytes in wires {
        let dir = root();
        let mut b = FullBarrier::new(dir.path(), "run", Role::Controller, &m).unwrap();
        let path = b.path(0, Phase::Ready);
        std::fs::write(&path, &bytes).unwrap();
        assert!(b
            .wait(
                0,
                Phase::Ready,
                Instant::now() + Duration::from_secs(1),
                || false,
                || panic!("not missing")
            )
            .is_err());
        assert_eq!(b.next, 0);
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
    let dir = root();
    let mut b = FullBarrier::new(dir.path(), "run", Role::Peer, &m).unwrap();
    b.next = 3;
    let mut wrong = ack(&m.operation(0).unwrap());
    wrong.inserted += 1;
    let message = Message {
        schema: 1,
        protocol: Protocol::Full20x256BarrierV1,
        epoch: "run".into(),
        operation_id: 0,
        cli_epoch: 3,
        phase: Phase::ValidatedAck,
        ack: Some(wrong),
    };
    std::fs::write(
        b.path(0, Phase::ValidatedAck),
        serde_json::to_vec(&message).unwrap(),
    )
    .unwrap();
    assert!(b
        .wait(
            0,
            Phase::ValidatedAck,
            Instant::now() + Duration::from_secs(1),
            || false,
            || {}
        )
        .is_err());
    assert_eq!(b.next, 3);
}

#[test]
fn cancellation_deadlines_partial_pending_and_no_clobber_fail_closed() {
    use std::cell::Cell;
    let m = FullManifest::new(WorkloadSpec::full20x256_v1(), 16).unwrap();
    let dir = root();
    for epoch in ["", &"x".repeat(257)] {
        assert!(FullBarrier::new(dir.path(), epoch, Role::Peer, &m).is_err());
    }
    let mut p = FullBarrier::new(dir.path(), "run", Role::Peer, &m).unwrap();
    let mut c = FullBarrier::new(dir.path(), "run", Role::Controller, &m).unwrap();
    assert!(c.publish(0, Phase::Ready).is_err());
    assert!(p
        .wait(
            0,
            Phase::Ready,
            Instant::now() + Duration::from_secs(1),
            || false,
            || {}
        )
        .is_err());
    // Partial staging is invisible; an actual missing observation triggers cancel.
    let staging = p.path(0, Phase::Ready).with_extension("pending");
    std::fs::write(&staging, b"{").unwrap();
    let missing = Cell::new(false);
    assert!(c
        .wait(
            0,
            Phase::Ready,
            Instant::now() + Duration::from_secs(1),
            || missing.get(),
            || missing.set(true)
        )
        .is_err());
    assert!(missing.get());
    assert_eq!(c.next, 0);
    assert!(p.publish(0, Phase::Ready).is_err());
    assert_eq!(std::fs::read(&staging).unwrap(), b"{");
    std::fs::remove_file(staging).unwrap();
    p.publish(0, Phase::Ready).unwrap();
    let bytes = std::fs::read(p.path(0, Phase::Ready)).unwrap();
    assert!(p.publish(0, Phase::Ready).is_err());
    assert_eq!(std::fs::read(p.path(0, Phase::Ready)).unwrap(), bytes);
    for deadline in [Instant::now(), Instant::now() + Duration::from_secs(61)] {
        assert!(c.wait(0, Phase::Ready, deadline, || false, || {}).is_err());
    }
    let mut checks = 0;
    assert!(c
        .wait(
            0,
            Phase::Ready,
            Instant::now() + Duration::from_secs(1),
            || {
                checks += 1;
                checks > 1
            },
            || {}
        )
        .is_err());
    assert_eq!(checks, 2);
    assert_eq!(c.next, 0);
    wait(&mut c, 0, Phase::Ready);
    c.publish(0, Phase::Release).unwrap();
    wait(&mut p, 0, Phase::Release);
    p.publish(0, Phase::Done).unwrap();
    wait(&mut c, 0, Phase::Done);
    let mut checks = 0;
    assert!(c
        .acknowledge(
            0,
            &(),
            |op, _, _| Ok(ack(op)),
            || {
                checks += 1;
                checks > 1
            }
        )
        .is_err());
    assert_eq!(c.next, 3);
    assert!(!c.path(0, Phase::ValidatedAck).exists());
    assert!(c
        .acknowledge(
            0,
            &(),
            |op, _, _| {
                let mut bad = ack(op);
                bad.cli_epoch += 1;
                Ok(bad)
            },
            || false
        )
        .is_err());
    assert_eq!(c.next, 3);
    let escaped = root();
    let mut p = FullBarrier::new(escaped.path(), &"\0".repeat(256), Role::Peer, &m).unwrap();
    assert!(p.publish(0, Phase::Ready).is_err());
    assert_eq!(
        std::fs::read_dir(escaped.path().join("scratch"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn peer_callback_failure_or_cancellation_never_publishes_done_or_retries() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let m = FullManifest::new(WorkloadSpec::full20x256_v1(), 16).unwrap();
    for cancel_after_execute in [false, true] {
        let dir = root();
        let calls = AtomicUsize::new(0);
        let cancelled = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let peer = scope.spawn(|| {
                run_peer(
                    dir.path(),
                    "run",
                    &m,
                    Instant::now() + Duration::from_secs(20),
                    || cancelled.load(Ordering::SeqCst),
                    |op, _| {
                        assert_eq!(op.id, 0);
                        calls.fetch_add(1, Ordering::SeqCst);
                        if cancel_after_execute {
                            cancelled.store(true, Ordering::SeqCst);
                            Ok(())
                        } else {
                            Err("unknown commit: do not retry".into())
                        }
                    },
                    |_, _| {},
                )
                .map_err(|error| error.to_string())
            });
            let mut c = FullBarrier::new(dir.path(), "run", Role::Controller, &m).unwrap();
            wait(&mut c, 0, Phase::Ready);
            c.publish(0, Phase::Release).unwrap();
            assert!(peer.join().unwrap().is_err());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(!c.path(0, Phase::Done).exists());
            assert!(!c.path(0, Phase::ValidatedAck).exists());
            assert!(!c.path(1, Phase::Ready).exists());
        });
    }
    let dir = root();
    for deadline in [Instant::now(), Instant::now() + Duration::from_secs(1)] {
        assert!(run_peer(
            dir.path(),
            "run",
            &m,
            deadline,
            || true,
            |_, _| panic!("must not execute"),
            |_, _| panic!("must not poll")
        )
        .is_err());
    }
    assert_eq!(
        std::fs::read_dir(dir.path().join("scratch"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn timeout_is_observed_after_real_missing_message_and_future_wait_fails_closed() {
    let m = FullManifest::new(WorkloadSpec::full20x256_v1(), 16).unwrap();
    let dir = root();
    let mut c = FullBarrier::new(dir.path(), "run", Role::Controller, &m).unwrap();
    let mut polls = 0;
    assert!(c
        .wait(
            0,
            Phase::Ready,
            Instant::now() + Duration::from_millis(40),
            || false,
            || polls += 1
        )
        .is_err());
    assert!(polls > 0);
    assert_eq!(c.next, 0);
    let future = c.path(63, Phase::Done);
    std::fs::write(&future, b"future").unwrap();
    assert!(c
        .wait(
            0,
            Phase::Ready,
            Instant::now() + Duration::from_secs(1),
            || false,
            || panic!("future must be rejected before polling")
        )
        .is_err());
    assert_eq!(c.next, 0);
    assert_eq!(std::fs::read(future).unwrap(), b"future");
}
