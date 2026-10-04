//! Shared bounded CLI capture. Only direct children are terminated on deadline;
//! SCM processes are stopped cooperatively by the owning adapter, never killed.
use crate::data::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub case: crate::commands::Case,
    pub enrollment: PathBuf,
    pub client: PathBuf,
    pub seed_records: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pilot: Option<PilotJob>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PilotJob {
    pub schema: u8,
    pub fixture_spec: crate::data::FixtureSpec,
    pub epoch: String,
}
impl PilotJob {
    pub fn validate(&self) -> Result<()> {
        ensure(
            self.schema == 1
                && self.fixture_spec == crate::data::FixtureSpec::representative_6_mib(),
            "only representative 6 MiB pilot admitted",
        )?;
        ensure(
            !self.epoch.is_empty() && self.epoch.len() <= 256,
            "pilot epoch bound",
        )
    }
}
/// Single-operation protocol. Publication uses a fully synced, create-new staging
/// file and a no-replace hard link, so readers never observe partial JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PilotPhase {
    Ready,
    Release,
    Done,
    Acknowledged,
}
impl PilotPhase {
    fn index(self) -> usize {
        self as usize
    }
    fn name(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Release => "release",
            Self::Done => "done",
            Self::Acknowledged => "acknowledged",
        }
    }
}
const PILOT_PHASES: [PilotPhase; 4] = [
    PilotPhase::Ready,
    PilotPhase::Release,
    PilotPhase::Done,
    PilotPhase::Acknowledged,
];
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PilotMessage {
    schema: u8,
    epoch: String,
    operation_id: u32,
    phase: PilotPhase,
}
/// Separate ordinary-file integration receipt; never a pilot Job/schema extension.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Internal sandbox only; no native/workflow admission.
pub struct WarmupReceipt {
    pub schema: u8,
    pub operation_id: u32,
    pub cli_epoch: u64,
    pub payload: Vec<u8>,
    pub inserted: u64,
    pub duplicates: u64,
}
#[allow(dead_code)] // Internal sandbox only; no native/workflow admission.
impl WarmupReceipt {
    pub fn validate(&self, id: u32) -> Result<()> {
        let manifest = crate::data::TwoWarmupManifest;
        ensure(
            self.schema == 3
                && self.operation_id == id
                && self.cli_epoch == manifest.cli_epoch(id)?
                && self.payload == manifest.payload(id)?
                && self.inserted == 1
                && self.duplicates == 0,
            "two-warmup exact receipt/payload mismatch",
        )
    }
}
pub struct PilotBarrier {
    root: PathBuf,
    epoch: String,
    next: usize,
}
impl PilotBarrier {
    pub fn new(root: &Path, epoch: &str) -> Result<Self> {
        ensure(!epoch.is_empty() && epoch.len() <= 256, "pilot epoch bound")?;
        Ok(Self {
            root: root.into(),
            epoch: epoch.into(),
            next: 0,
        })
    }
    fn path(&self, phase: PilotPhase) -> PathBuf {
        let dir = match phase {
            PilotPhase::Ready | PilotPhase::Done => "scratch",
            _ => "controller",
        };
        self.root
            .join(dir)
            .join(format!("pilot-{}.json", phase.name()))
    }
    fn validate_files(&self, phase: PilotPhase) -> Result<()> {
        ensure(self.next == phase.index(), "pilot phase out of order")?;
        for future in &PILOT_PHASES[self.next + 1..] {
            ensure(
                !self.path(*future).try_exists()?,
                "pilot future phase already exists",
            )?;
        }
        Ok(())
    }
    pub fn publish(&mut self, phase: PilotPhase) -> Result<()> {
        self.validate_files(phase)?;
        let destination = self.path(phase);
        let staging = destination.with_extension("pending");
        json_new(
            &staging,
            &PilotMessage {
                schema: 1,
                epoch: self.epoch.clone(),
                operation_id: 0,
                phase,
            },
        )?;
        std::fs::hard_link(&staging, &destination)?;
        self.next += 1;
        Ok(())
    }
    pub fn wait(
        &mut self,
        phase: PilotPhase,
        timeout: Duration,
        cancelled: fn() -> bool,
    ) -> Result<()> {
        ensure(
            !timeout.is_zero() && timeout <= Duration::from_secs(60),
            "pilot deadline bound",
        )?;
        let deadline = Instant::now() + timeout;
        loop {
            ensure(
                !cancelled() && Instant::now() < deadline,
                "pilot barrier cancelled or timed out",
            )?;
            self.validate_files(phase)?;
            match File::open(self.path(phase)) {
                Ok(file) => {
                    ensure(
                        file.metadata()?.is_file() && file.metadata()?.len() <= 1024,
                        "pilot message size/type bound",
                    )?;
                    let mut bytes = Vec::new();
                    file.take(1025).read_to_end(&mut bytes)?;
                    ensure(bytes.len() <= 1024, "pilot message grew")?;
                    let message: PilotMessage = serde_json::from_slice(&bytes)?;
                    ensure(
                        message.schema == 1
                            && message.epoch == self.epoch
                            && message.operation_id == 0
                            && message.phase == phase,
                        "stale or invalid pilot message",
                    )?;
                    self.next += 1;
                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    thread::sleep(Duration::from_millis(2))
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}
/// Internal schema-2 tracer bullet: exactly two warmups, no public admission.
/// Each peer observes all four phases before advancing its operation ID. The
/// barrier conveys sequencing only, not receipt validation or service authority.
#[allow(dead_code)]
pub struct OperationBarrier {
    root: PathBuf,
    epoch: String,
    next: usize,
}
#[allow(dead_code)]
impl OperationBarrier {
    pub fn new(root: &Path, epoch: &str, operation_limit: u32) -> Result<Self> {
        ensure(operation_limit == 2, "only two internal warmups admitted")?;
        ensure(
            !epoch.is_empty() && epoch.len() <= 256,
            "operation epoch bound",
        )?;
        Ok(Self {
            root: root.into(),
            epoch: epoch.into(),
            next: 0,
        })
    }
    fn path(&self, id: u32, phase: PilotPhase) -> PathBuf {
        let dir = match phase {
            PilotPhase::Ready | PilotPhase::Done => "scratch",
            _ => "controller",
        };
        self.root
            .join(dir)
            .join(format!("workload-op-{id}-{}.json", phase.name()))
    }
    fn validate_files(&self, id: u32, phase: PilotPhase) -> Result<()> {
        ensure(
            id < 2 && self.next == id as usize * 4 + phase.index(),
            "operation phase out of order",
        )?;
        // Eight fixed publication paths; never enumerate an untrusted directory.
        for future in self.next + 1..8 {
            ensure(
                !self
                    .path((future / 4) as u32, PILOT_PHASES[future % 4])
                    .try_exists()?,
                "operation future phase already exists",
            )?;
        }
        Ok(())
    }
    pub fn publish(&mut self, id: u32, phase: PilotPhase) -> Result<()> {
        self.validate_files(id, phase)?;
        let destination = self.path(id, phase);
        ensure(
            !destination.try_exists()?,
            "operation publication already exists",
        )?;
        let staging = destination.with_extension("pending");
        let bytes = serde_json::to_vec(&PilotMessage {
            schema: 2,
            epoch: self.epoch.clone(),
            operation_id: id,
            phase,
        })?;
        ensure(bytes.len() <= 1024, "operation message size bound")?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::hard_link(staging, destination)?;
        self.next += 1;
        Ok(())
    }
    pub fn wait(
        &mut self,
        id: u32,
        phase: PilotPhase,
        deadline: Instant,
        cancelled: fn() -> bool,
    ) -> Result<()> {
        let now = Instant::now();
        ensure(
            deadline > now && deadline.duration_since(now) <= Duration::from_secs(60),
            "operation deadline bound",
        )?;
        loop {
            ensure(
                !cancelled() && Instant::now() < deadline,
                "operation barrier cancelled or timed out",
            )?;
            self.validate_files(id, phase)?;
            match File::open(self.path(id, phase)) {
                Ok(file) => {
                    ensure(
                        file.metadata()?.is_file() && file.metadata()?.len() <= 1024,
                        "operation message size/type bound",
                    )?;
                    let mut bytes = Vec::new();
                    file.take(1025).read_to_end(&mut bytes)?;
                    ensure(bytes.len() <= 1024, "operation message grew")?;
                    let message: PilotMessage = serde_json::from_slice(&bytes)?;
                    ensure(
                        message.schema == 2
                            && message.epoch == self.epoch
                            && message.operation_id == id
                            && message.phase == phase,
                        "stale or invalid operation message",
                    )?;
                    ensure(
                        !cancelled() && Instant::now() < deadline,
                        "operation barrier cancelled or timed out",
                    )?;
                    self.next += 1;
                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    thread::sleep(Duration::from_millis(2))
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

#[cfg(test)]
mod repeated_tests {
    use super::*;

    fn root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for dir in ["scratch", "controller"] {
            std::fs::create_dir(root.path().join(dir)).unwrap();
        }
        root
    }

    #[test]
    fn cancellation_during_message_validation_refuses_to_advance() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CHECKS: AtomicUsize = AtomicUsize::new(0);
        fn cancel_after_first_check() -> bool {
            CHECKS.fetch_add(1, Ordering::SeqCst) != 0
        }
        let root = root();
        let mut writer = OperationBarrier::new(root.path(), "epoch", 2).unwrap();
        writer.publish(0, PilotPhase::Ready).unwrap();
        let mut reader = OperationBarrier::new(root.path(), "epoch", 2).unwrap();
        assert!(reader
            .wait(
                0,
                PilotPhase::Ready,
                Instant::now() + Duration::from_secs(1),
                cancel_after_first_check
            )
            .is_err());
        assert_eq!(reader.next, 0);
    }

    #[test]
    fn invalid_wire_messages_never_advance_the_reader() {
        let valid = json!({"schema":2,"epoch":"epoch","operation_id":0,"phase":"ready"});
        let mut invalid = vec![b"{".to_vec(), vec![b' '; 1025]];
        for (field, value) in [
            ("schema", json!(1)),
            ("epoch", json!("stale")),
            ("operation_id", json!(1)),
            ("phase", json!("done")),
            ("unknown", json!(true)),
        ] {
            let mut message = valid.clone();
            message[field] = value;
            invalid.push(serde_json::to_vec(&message).unwrap());
        }
        for bytes in invalid {
            let root = root();
            let mut reader = OperationBarrier::new(root.path(), "epoch", 2).unwrap();
            let path = reader.path(0, PilotPhase::Ready);
            std::fs::write(&path, &bytes).unwrap();
            assert!(reader
                .wait(
                    0,
                    PilotPhase::Ready,
                    Instant::now() + Duration::from_millis(100),
                    never_cancel
                )
                .is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert_eq!(reader.next, 0);
        }
    }

    #[test]
    fn partial_pending_timeout_and_cancellation_cannot_authorize_an_operation() {
        let root = root();
        let mut barrier = OperationBarrier::new(root.path(), "epoch", 2).unwrap();
        let staging = barrier.path(0, PilotPhase::Ready).with_extension("pending");
        std::fs::write(&staging, b"{").unwrap();
        let started = Instant::now();
        assert!(barrier
            .wait(
                0,
                PilotPhase::Ready,
                started + Duration::from_millis(20),
                never_cancel
            )
            .is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(barrier
            .wait(
                0,
                PilotPhase::Ready,
                Instant::now() + Duration::from_secs(1),
                || true
            )
            .is_err());
        assert!(barrier
            .wait(0, PilotPhase::Ready, Instant::now(), never_cancel)
            .is_err());
        assert!(barrier.publish(0, PilotPhase::Ready).is_err());
        assert_eq!(std::fs::read(&staging).unwrap(), b"{");
        assert_eq!(barrier.next, 0);
        assert!(!barrier.path(0, PilotPhase::Ready).exists());
    }

    #[test]
    fn constructor_sequence_duplicate_and_stale_operation_bounds() {
        let root = root();
        for limit in [0, 1, 3, u32::MAX] {
            assert!(OperationBarrier::new(root.path(), "epoch", limit).is_err());
        }
        for epoch in ["", &"x".repeat(257)] {
            assert!(OperationBarrier::new(root.path(), epoch, 2).is_err());
        }
        let mut barrier = OperationBarrier::new(root.path(), "epoch", 2).unwrap();
        for id in [1, 2, u32::MAX] {
            assert!(barrier.publish(id, PilotPhase::Ready).is_err());
        }
        assert!(barrier.publish(0, PilotPhase::Done).is_err());
        barrier.publish(0, PilotPhase::Ready).unwrap();
        let path = barrier.path(0, PilotPhase::Ready);
        let before = std::fs::read(&path).unwrap();
        assert!(barrier.publish(0, PilotPhase::Ready).is_err());
        assert_eq!(before, std::fs::read(&path).unwrap());
        for phase in [
            PilotPhase::Release,
            PilotPhase::Done,
            PilotPhase::Acknowledged,
        ] {
            barrier.publish(0, phase).unwrap();
        }
        assert!(barrier.publish(0, PilotPhase::Done).is_err());
        assert!(barrier
            .wait(
                0,
                PilotPhase::Acknowledged,
                Instant::now() + Duration::from_secs(1),
                never_cancel
            )
            .is_err());
        barrier.publish(1, PilotPhase::Ready).unwrap();
    }

    #[test]
    fn second_peer_is_paused_until_controller_acknowledges_first() {
        paused_peer_case(Duration::ZERO);
    }

    #[test]
    fn paused_peer_startup_delay_does_not_spend_ack_wait_budget() {
        paused_peer_case(Duration::from_secs(6));
    }

    fn paused_peer_case(startup_delay: Duration) {
        use std::cell::Cell;
        use std::sync::mpsc::channel;

        // This callback cancels only after one real missing-file poll. No sleep
        // or peer startup latency is used as evidence that ACK was withheld.
        thread_local! {
            static ACK_POLLS: Cell<usize> = const { Cell::new(0) };
        }
        fn cancel_after_missing_ack_poll() -> bool {
            ACK_POLLS.with(|polls| {
                let previous = polls.get();
                polls.set(previous + 1);
                previous != 0
            })
        }
        let root = root();
        let (peer_tx, controller_rx) = channel();
        let (controller_tx, peer_rx) = channel();
        let phase_timeout = Duration::from_secs(5);
        // Fixture readiness is separately bounded, including the injected 6s
        // scheduling delay. The real barrier keeps its five-second wait budget.
        let coordination_timeout = Duration::from_secs(10);
        thread::scope(|scope| {
            let path = root.path();
            let peer = scope.spawn(move || {
                thread::sleep(startup_delay);
                let mut b = OperationBarrier::new(path, "epoch", 2).unwrap();
                for id in 0..2 {
                    b.publish(id, PilotPhase::Ready).unwrap();
                    peer_tx.send((id, PilotPhase::Ready)).unwrap();
                    assert_eq!(
                        peer_rx.recv_timeout(coordination_timeout).unwrap(),
                        (id, PilotPhase::Release)
                    );
                    b.wait(
                        id,
                        PilotPhase::Release,
                        Instant::now() + phase_timeout,
                        never_cancel,
                    )
                    .unwrap();
                    std::fs::write(path.join(format!("peer-warmup-{id}")), [id as u8]).unwrap();
                    b.publish(id, PilotPhase::Done).unwrap();
                    if id == 0 {
                        ACK_POLLS.with(|polls| polls.set(0));
                        assert_eq!(
                            b.wait(
                                id,
                                PilotPhase::Acknowledged,
                                Instant::now() + phase_timeout,
                                cancel_after_missing_ack_poll,
                            )
                            .unwrap_err()
                            .to_string(),
                            "operation barrier cancelled or timed out"
                        );
                        ACK_POLLS.with(|polls| assert_eq!(polls.get(), 2));
                        assert_eq!(b.next, 3);
                        assert!(!b.path(0, PilotPhase::Acknowledged).exists());
                        assert!(!b.path(1, PilotPhase::Ready).exists());
                        assert!(!path.join("peer-warmup-1").exists());
                    }
                    // Done readiness includes the explicit missing-ACK probe.
                    peer_tx.send((id, PilotPhase::Done)).unwrap();
                    assert_eq!(
                        peer_rx.recv_timeout(coordination_timeout).unwrap(),
                        (id, PilotPhase::Acknowledged)
                    );
                    b.wait(
                        id,
                        PilotPhase::Acknowledged,
                        Instant::now() + phase_timeout,
                        never_cancel,
                    )
                    .unwrap();
                    peer_tx.send((id, PilotPhase::Acknowledged)).unwrap();
                }
            });
            let mut c = OperationBarrier::new(path, "epoch", 2).unwrap();
            for id in 0..2 {
                assert_eq!(
                    controller_rx.recv_timeout(coordination_timeout).unwrap(),
                    (id, PilotPhase::Ready)
                );
                c.wait(
                    id,
                    PilotPhase::Ready,
                    Instant::now() + phase_timeout,
                    never_cancel,
                )
                .unwrap();
                c.publish(id, PilotPhase::Release).unwrap();
                controller_tx.send((id, PilotPhase::Release)).unwrap();
                assert_eq!(
                    controller_rx.recv_timeout(coordination_timeout).unwrap(),
                    (id, PilotPhase::Done)
                );
                c.wait(
                    id,
                    PilotPhase::Done,
                    Instant::now() + phase_timeout,
                    never_cancel,
                )
                .unwrap();
                if id == 0 {
                    assert!(!c.path(0, PilotPhase::Acknowledged).exists());
                    assert!(!c.path(1, PilotPhase::Ready).exists());
                    assert!(!path.join("peer-warmup-1").exists());
                }
                c.publish(id, PilotPhase::Acknowledged).unwrap();
                controller_tx.send((id, PilotPhase::Acknowledged)).unwrap();
                assert_eq!(
                    controller_rx.recv_timeout(coordination_timeout).unwrap(),
                    (id, PilotPhase::Acknowledged)
                );
            }
            peer.join().unwrap();
        });
        assert_eq!(
            std::fs::read(root.path().join("peer-warmup-1")).unwrap(),
            [1]
        );
    }

    #[test]
    fn existing_destination_and_pending_sentinels_are_never_overwritten() {
        for pending in [false, true] {
            let root = root();
            let mut barrier = OperationBarrier::new(root.path(), "epoch", 2).unwrap();
            let destination = barrier.path(0, PilotPhase::Ready);
            let staging = destination.with_extension("pending");
            std::fs::write(&destination, b"destination-sentinel").unwrap();
            if pending {
                std::fs::write(&staging, b"pending-sentinel").unwrap();
            }
            assert!(barrier.publish(0, PilotPhase::Ready).is_err());
            assert_eq!(
                std::fs::read(&destination).unwrap(),
                b"destination-sentinel"
            );
            if pending {
                assert_eq!(std::fs::read(&staging).unwrap(), b"pending-sentinel");
            } else {
                assert!(!staging.exists());
            }
        }
    }

    #[test]
    fn escaped_epoch_cannot_publish_an_oversized_message() {
        let root = root();
        let mut barrier = OperationBarrier::new(root.path(), &"\0".repeat(256), 2).unwrap();
        assert!(barrier.publish(0, PilotPhase::Ready).is_err());
        for dir in ["scratch", "controller"] {
            assert_eq!(std::fs::read_dir(root.path().join(dir)).unwrap().count(), 0);
        }
    }

    #[test]
    fn absolute_wait_deadline_is_capped_before_consuming_a_message() {
        let root = root();
        let mut writer = OperationBarrier::new(root.path(), "epoch", 2).unwrap();
        writer.publish(0, PilotPhase::Ready).unwrap();
        let mut reader = OperationBarrier::new(root.path(), "epoch", 2).unwrap();
        assert!(reader
            .wait(
                0,
                PilotPhase::Ready,
                Instant::now() + Duration::from_secs(61),
                never_cancel
            )
            .is_err());
        reader
            .wait(
                0,
                PilotPhase::Ready,
                Instant::now() + Duration::from_secs(1),
                never_cancel,
            )
            .unwrap();
    }

    #[test]
    fn early_future_publications_refuse_without_advancing_or_clobbering() {
        for (id, phase) in [
            (0, PilotPhase::Release),
            (1, PilotPhase::Ready),
            (1, PilotPhase::Acknowledged),
        ] {
            let root = root();
            let mut barrier = OperationBarrier::new(root.path(), "epoch", 2).unwrap();
            let sentinel = barrier.path(id, phase);
            std::fs::write(&sentinel, b"early-sentinel").unwrap();
            assert!(barrier.publish(0, PilotPhase::Ready).is_err());
            assert!(barrier
                .wait(
                    0,
                    PilotPhase::Ready,
                    Instant::now() + Duration::from_millis(20),
                    never_cancel
                )
                .is_err());
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"early-sentinel");
            assert!(!barrier.path(0, PilotPhase::Ready).exists());
            std::fs::remove_file(sentinel).unwrap();
            barrier.publish(0, PilotPhase::Ready).unwrap();
        }
    }

    #[test]
    fn two_warmups_cannot_start_second_before_first_acknowledgement() {
        let root = root();
        let mut b = OperationBarrier::new(root.path(), "owned-epoch", 2).unwrap();
        let mut c = OperationBarrier::new(root.path(), "owned-epoch", 2).unwrap();
        // This tests phase ordering, not fsync/setup throughput. Each wait consumes
        // an already-published message; keep its two-second bound local to that wait.
        for id in 0..2 {
            b.publish(id, PilotPhase::Ready).unwrap();
            c.wait(
                id,
                PilotPhase::Ready,
                Instant::now() + Duration::from_secs(2),
                never_cancel,
            )
            .unwrap();
            c.publish(id, PilotPhase::Release).unwrap();
            b.wait(
                id,
                PilotPhase::Release,
                Instant::now() + Duration::from_secs(2),
                never_cancel,
            )
            .unwrap();
            // Ordinary-file stand-in for a warmup, not a broker correctness claim.
            std::fs::write(
                root.path().join(format!("warmup-{id}")),
                format!("insert-{id}"),
            )
            .unwrap();
            b.publish(id, PilotPhase::Done).unwrap();
            c.wait(
                id,
                PilotPhase::Done,
                Instant::now() + Duration::from_secs(2),
                never_cancel,
            )
            .unwrap();
            if id == 0 {
                assert!(b.publish(1, PilotPhase::Ready).is_err());
                assert!(c.publish(1, PilotPhase::Release).is_err());
                assert!(!root.path().join("warmup-1").exists());
            }
            c.publish(id, PilotPhase::Acknowledged).unwrap();
            b.wait(
                id,
                PilotPhase::Acknowledged,
                Instant::now() + Duration::from_secs(2),
                never_cancel,
            )
            .unwrap();
        }
        for id in 0..2 {
            assert_eq!(
                std::fs::read_to_string(root.path().join(format!("warmup-{id}"))).unwrap(),
                format!("insert-{id}")
            );
        }
        assert!(b.publish(2, PilotPhase::Ready).is_err());
        for dir in ["scratch", "controller"] {
            assert_eq!(std::fs::read_dir(root.path().join(dir)).unwrap().count(), 8);
        }
    }
}

#[cfg(test)]
mod pilot_tests {
    use super::*;
    #[test]
    fn pilot_two_peers_release_exactly_one_operation_before_ack() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        let root = tempfile::tempdir().unwrap();
        for dir in ["scratch", "controller"] {
            std::fs::create_dir(root.path().join(dir)).unwrap();
        }
        let operations = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            let ops = operations.clone();
            let path = root.path();
            scope.spawn(move || {
                let mut b = PilotBarrier::new(path, "owned-epoch").unwrap();
                b.publish(PilotPhase::Ready).unwrap();
                b.wait(PilotPhase::Release, Duration::from_secs(2), never_cancel)
                    .unwrap();
                ops.fetch_add(1, Ordering::SeqCst);
                b.publish(PilotPhase::Done).unwrap();
                b.wait(
                    PilotPhase::Acknowledged,
                    Duration::from_secs(2),
                    never_cancel,
                )
                .unwrap();
            });
            let mut c = PilotBarrier::new(path, "owned-epoch").unwrap();
            c.wait(PilotPhase::Ready, Duration::from_secs(2), never_cancel)
                .unwrap();
            assert_eq!(operations.load(Ordering::SeqCst), 0);
            c.publish(PilotPhase::Release).unwrap();
            c.wait(PilotPhase::Done, Duration::from_secs(2), never_cancel)
                .unwrap();
            assert_eq!(operations.load(Ordering::SeqCst), 1);
            c.publish(PilotPhase::Acknowledged).unwrap();
        });
        assert_eq!(
            std::fs::read_dir(root.path().join("scratch"))
                .unwrap()
                .count(),
            4
        );
        assert_eq!(
            std::fs::read_dir(root.path().join("controller"))
                .unwrap()
                .count(),
            4
        );
    }
    #[test]
    fn pilot_job_rejects_schema_large_unknown_and_unbounded_epoch() {
        let valid = PilotJob {
            schema: 1,
            fixture_spec: crate::data::FixtureSpec::representative_6_mib(),
            epoch: "nonce".into(),
        };
        valid.validate().unwrap();
        let original = serde_json::to_value(&valid).unwrap();
        for (field, value) in [
            ("schema", json!(2)),
            ("epoch", json!("")),
            ("epoch", json!("x".repeat(257))),
        ] {
            let mut bad = original.clone();
            bad[field] = value;
            assert!(serde_json::from_value::<PilotJob>(bad)
                .unwrap()
                .validate()
                .is_err());
        }
        let mut bad = original.clone();
        bad["fixture_spec"]["target_jsonl_bytes"] = json!(629145600);
        assert!(serde_json::from_value::<PilotJob>(bad)
            .unwrap()
            .validate()
            .is_err());
        let mut bad = original;
        bad["unrecognized"] = json!(true);
        assert!(serde_json::from_value::<PilotJob>(bad).is_err());
    }

    #[test]
    fn pilot_barrier_is_bounded_ordered_and_no_clobber() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("scratch")).unwrap();
        std::fs::create_dir(temp.path().join("controller")).unwrap();
        let mut barrier = PilotBarrier::new(temp.path(), "test-epoch").unwrap();
        assert!(barrier
            .wait(PilotPhase::Ready, Duration::from_millis(1), never_cancel)
            .is_err());
        assert!(barrier.publish(PilotPhase::Done).is_err());
        barrier.publish(PilotPhase::Ready).unwrap();
        let original = std::fs::read(temp.path().join("scratch/pilot-ready.json")).unwrap();
        assert!(barrier.publish(PilotPhase::Ready).is_err());
        assert_eq!(
            std::fs::read(temp.path().join("scratch/pilot-ready.json")).unwrap(),
            original
        );
        let mut stale = PilotBarrier::new(temp.path(), "stale-epoch").unwrap();
        assert!(stale
            .wait(PilotPhase::Ready, Duration::from_millis(20), never_cancel)
            .is_err());
        for phase in [
            PilotPhase::Release,
            PilotPhase::Done,
            PilotPhase::Acknowledged,
        ] {
            barrier.publish(phase).unwrap();
        }
        let mut reader = PilotBarrier::new(temp.path(), "test-epoch").unwrap();
        assert!(reader
            .wait(PilotPhase::Ready, Duration::from_millis(20), never_cancel)
            .is_err());
        let other = tempfile::tempdir().unwrap();
        std::fs::create_dir(other.path().join("scratch")).unwrap();
        std::fs::write(
            other.path().join("scratch/pilot-ready.json"),
            vec![b' '; 1025],
        )
        .unwrap();
        assert!(PilotBarrier::new(other.path(), "test-epoch")
            .unwrap()
            .wait(PilotPhase::Ready, Duration::from_millis(20), never_cancel)
            .is_err());
    }
}
pub fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
pub fn json_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
pub fn text(path: &Path) -> Result<String> {
    Ok(path.to_str().ok_or("non-UTF8 path")?.to_owned())
}
const OUTPUT_LIMIT: usize = 1024 * 1024;

#[derive(Default)]
struct Capture {
    bytes: Vec<u8>,
    overflow: bool,
    eof: bool,
}
impl Capture {
    #[cfg(windows)]
    fn poll(
        &mut self,
        pipe: &mut (impl Read + std::os::windows::io::AsRawHandle),
    ) -> std::io::Result<bool> {
        use windows_sys::Win32::{Foundation::ERROR_BROKEN_PIPE, System::Pipes::PeekNamedPipe};
        let mut available = 0;
        // SAFETY: borrowed live anonymous-pipe read handle. Only this thread reads
        // it. Peek is nonblocking; Read below requests no more than available.
        let ok = unsafe {
            PeekNamedPipe(
                pipe.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                self.eof = true;
                return Ok(false);
            }
            return Err(error);
        }
        if available == 0 || self.eof {
            return Ok(false);
        }
        let mut buffer = [0; 16384];
        let count = pipe.read(&mut buffer[..(available as usize).min(16384)])?;
        let retained = count.min(OUTPUT_LIMIT - self.bytes.len());
        self.bytes.extend_from_slice(&buffer[..retained]);
        self.overflow |= count > retained;
        self.eof = count == 0;
        Ok(count != 0)
    }
    #[cfg(not(windows))]
    fn poll(&mut self, _pipe: &mut impl Read) -> std::io::Result<bool> {
        Err(std::io::Error::other(
            "bounded CLI capture requires Windows",
        ))
    }
}

#[cfg(test)]
thread_local! {
    // Observe only post-exit pipe draining, excluding fixture startup and evidence fsync.
    static CHILD_DRAIN_ELAPSED: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

/// Both pipes are serviced fairly on one thread, one bounded chunk per turn.
/// No reader threads, blocking EOF drain, or join can outlive the direct child.
/// After exit/cancellation, pipe draining has a 250ms budget (descendants may
/// retain writers); direct-child reap has a separate 2s budget. Only Child::kill
/// on the retained handle is permitted; incomplete shutdown fails closed.
/// Disk receives only the bounded prefixes, never a child's writable log handle.
pub fn command(
    exe: &Path,
    args: &[String],
    input: &[u8],
    directory: &Path,
    label: &str,
    timeout: Duration,
    cancelled: fn() -> bool,
) -> Result<Value> {
    command_inner(
        &CommandRequest {
            exe,
            args,
            input,
            directory,
            label,
            timeout,
            cancelled,
        },
        None,
    )
}

pub struct CommandRequest<'a> {
    pub exe: &'a Path,
    pub args: &'a [String],
    pub input: &'a [u8],
    pub directory: &'a Path,
    pub label: &'a str,
    pub timeout: Duration,
    pub cancelled: fn() -> bool,
}

/// Instrument one direct CLI child; representative admission belongs to the controller.
#[allow(dead_code)]
pub fn command_measured(
    request: &CommandRequest<'_>,
    policy: &crate::measure::SamplePolicy,
) -> Result<Value> {
    policy.validate()?;
    let argument_bytes = request
        .args
        .iter()
        .try_fold(0usize, |sum, arg| sum.checked_add(arg.len()))
        .ok_or("argument size overflow")?;
    ensure(
        request.args.len() <= 128 && argument_bytes <= 65536,
        "measured argument bound",
    )?;
    ensure(
        !request.timeout.is_zero() && request.timeout <= Duration::from_secs(45),
        "measured timeout bound",
    )?;
    ensure(
        request.input.len() <= 2 * 1024 * 1024,
        "representative stdin bound",
    )?;
    #[cfg(not(all(windows, feature = "experimental-broker")))]
    return Err("measured command requires Windows and experimental-broker".into());
    #[cfg(all(windows, feature = "experimental-broker"))]
    command_inner(request, Some(policy))
}

fn command_inner(
    request: &CommandRequest<'_>,
    policy: Option<&crate::measure::SamplePolicy>,
) -> Result<Value> {
    let CommandRequest {
        exe,
        args,
        input,
        directory,
        label,
        timeout,
        cancelled,
    } = *request;
    #[cfg(all(windows, feature = "experimental-broker"))]
    let mut sampler = policy.map(|p| crate::measure::ChildSampler::new(p, input.len() as u64));
    #[cfg(not(all(windows, feature = "experimental-broker")))]
    ensure(policy.is_none(), "unsupported measurement")?;
    ensure(
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "unsafe command label",
    )?;
    ensure(input.len() <= 8 * 1024 * 1024, "stdin bound")?;
    let prefix = directory.join(label);
    let mut intent = json!({"exe":exe,"args":args,"deadline_ms":timeout.as_millis()});
    if let Some(policy) = policy {
        intent["measurement_policy"] = serde_json::to_value(policy)?;
        ensure(
            serde_json::to_vec_pretty(&intent)?.len() < 65536,
            "measured intent bound",
        )?;
    }
    json_new(&prefix.with_extension("intent.json"), &intent)?;
    let stdin = prefix.with_extension("stdin");
    let stdout = prefix.with_extension("stdout");
    let stderr = prefix.with_extension("stderr");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stdin)?;
    f.write_all(input)?;
    drop(f);
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stdout)?;
    let mut err = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stderr)?;
    let started = Instant::now();
    // A bounded regular input file cannot block the supervisor on an unread
    // stdin pipe. Children receive the same bytes followed by EOF.
    let spawned = Command::new(exe)
        .args(args)
        .current_dir(directory)
        .stdin(Stdio::from(File::open(&stdin)?))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut stdout_capture = Capture::default();
    let mut stderr_capture = Capture::default();
    let mut timed_out = false;
    let mut stopped = false;
    let mut status = None;
    let mut capture_error = None;
    let mut kill_error = None;
    let mut wait_error = None;
    let mut spawn_error = None;
    if let Ok(mut child) = spawned {
        // Stdio::piped guarantees both handles on successful spawn.
        let mut stdout_pipe = child.stdout.take().expect("piped stdout");
        let mut stderr_pipe = child.stderr.take().expect("piped stderr");
        let mut shutdown = None;
        let mut drain_started = None;
        loop {
            #[cfg(all(windows, feature = "experimental-broker"))]
            if status.is_none() {
                if let Some(sampler) = &mut sampler {
                    sampler.poll(&child, started);
                }
            }
            let mut progress = false;
            if capture_error.is_none()
                && drain_started.is_none_or(|t: Instant| t.elapsed() < Duration::from_millis(250))
            {
                match stdout_capture.poll(&mut stdout_pipe) {
                    Ok(read) => progress |= read,
                    Err(error) => capture_error = Some(error.to_string()),
                }
                match stderr_capture.poll(&mut stderr_pipe) {
                    Ok(read) => progress |= read,
                    Err(error) => capture_error = Some(error.to_string()),
                }
            }
            if status.is_none() && wait_error.is_none() {
                match child.try_wait() {
                    Ok(value) => {
                        status = value;
                        #[cfg(all(windows, feature = "experimental-broker"))]
                        if status.is_some() {
                            if let Some(sampler) = &mut sampler {
                                sampler.exited(&child, started);
                            }
                        }
                    }
                    Err(error) => wait_error = Some(error.to_string()),
                }
            }
            if status.is_none() && shutdown.is_none() {
                stopped = cancelled();
                timed_out = started.elapsed() >= timeout;
                if timed_out
                    || stopped
                    || stdout_capture.overflow
                    || stderr_capture.overflow
                    || capture_error.is_some()
                    || wait_error.is_some()
                {
                    shutdown = Some(Instant::now());
                    // Only our retained direct-child handle; never a process tree.
                    if let Err(error) = child.kill() {
                        kill_error = Some(error.to_string());
                    }
                }
            }
            if status.is_some() || shutdown.is_some() {
                let drain = drain_started.get_or_insert_with(Instant::now);
                let drained = (stdout_capture.eof && stderr_capture.eof)
                    || capture_error.is_some()
                    || drain.elapsed() >= Duration::from_millis(250);
                let reaped = status.is_some()
                    || wait_error.is_some()
                    || shutdown.is_some_and(|t| t.elapsed() >= Duration::from_secs(2));
                if drained && reaped {
                    #[cfg(test)]
                    CHILD_DRAIN_ELAPSED.with(|elapsed| elapsed.set(Some(drain.elapsed())));
                    break;
                }
            }
            if !progress {
                thread::sleep(Duration::from_millis(2));
            }
        }
    } else if let Err(error) = spawned {
        spawn_error = Some(error.to_string());
    }
    // At most OUTPUT_LIMIT raw bytes per file, including on failure. No child
    // ever receives these writable handles. JSON escaping/lossy UTF-8 expansion
    // has a fixed bounded overhead; raw evidence is preserved in the files.
    out.write_all(&stdout_capture.bytes)?;
    err.write_all(&stderr_capture.bytes)?;
    out.sync_all()?;
    err.sync_all()?;
    let capture_complete = stdout_capture.eof && stderr_capture.eof;
    let success = status.is_some_and(|s| s.success())
        && !timed_out
        && !stopped
        && !stdout_capture.overflow
        && !stderr_capture.overflow
        && capture_complete
        && capture_error.is_none()
        && kill_error.is_none()
        && wait_error.is_none();
    let value = json!({"exe":exe,"args":args,"exit_code":status.and_then(|s| s.code()),"success":success,
        "child_exited":status.is_some(),"capture_complete":capture_complete,
        "spawn_error":spawn_error,"capture_error":capture_error,"kill_error":kill_error,"wait_error":wait_error,
        "stdout_overflow":stdout_capture.overflow,"stderr_overflow":stderr_capture.overflow,
        "timed_out":timed_out,"stop_requested":stopped,"elapsed_us":started.elapsed().as_micros(),
        "stdout":String::from_utf8_lossy(&stdout_capture.bytes),"stderr":String::from_utf8_lossy(&stderr_capture.bytes),
        "stdout_file":stdout,"stderr_file":stderr});
    #[cfg(all(windows, feature = "experimental-broker"))]
    let value = if let Some(mut sampler) = sampler {
        let mut value = value;
        sampler.evidence.command_success = success;
        value["measurement"] = serde_json::to_value(sampler.evidence)?;
        value
    } else {
        value
    };
    json_new(&prefix.with_extension("result.json"), &value)?;
    Ok(value)
}
pub fn output(value: &Value) -> Result<Value> {
    ensure(
        value["success"] == true,
        "CLI failed; see captured return code/stdout/stderr",
    )?;
    Ok(serde_json::from_str(
        value["stdout"].as_str().ok_or("missing stdout")?,
    )?)
}
pub fn never_cancel() -> bool {
    false
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::fs;
    // Explicitly invoked by the non-ignored regression tests with
    // --ignored --exact contract::tests::capture_fixture --nocapture.
    // Ignoring only this fixture prevents process::exit from ending the parent
    // test harness. No behavioral regression test is ignored.
    // This ordinary self-owned child never enters the benchmark/SCM entrypoint.
    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess fixture only"]
    fn capture_fixture() {
        let mut mode = String::new();
        std::io::stdin().read_to_string(&mut mode).unwrap();
        match mode.as_str() {
            "stdout" => std::io::stdout()
                .write_all(&vec![b'x'; 1024 * 1024 + 1])
                .unwrap(),
            "stderr" => std::io::stderr()
                .write_all(&vec![b'e'; 1024 * 1024 + 1])
                .unwrap(),
            "boundary" => std::io::stderr()
                .write_all(&vec![b'e'; 1024 * 1024])
                .unwrap(),
            "live-stdout" | "live-stderr" => {
                let mut stream: Box<dyn Write> = if mode == "live-stdout" {
                    Box::new(std::io::stdout())
                } else {
                    Box::new(std::io::stderr())
                };
                for _ in 0..2048 {
                    stream.write_all(&[b'x'; 16384]).unwrap();
                }
                fs::write("unexpected-completion", b"overflow not stopped").unwrap();
            }
            "nonzero" => std::process::exit(7),
            "descendant" => {
                // Self-terminating descendant deliberately retains both writers.
                // Its completion marker proves command() did not kill the tree.
                let _descendant = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "contract::tests::capture_sleeper",
                        "--nocapture",
                    ])
                    .stdin(Stdio::null())
                    .spawn()
                    .unwrap();
            }
            "timeout" => thread::sleep(Duration::from_secs(10)),
            _ => panic!("unknown fixture"),
        }
        std::process::exit(0);
    }

    #[cfg(windows)]
    fn fixture(mode: &str, timeout: Duration) -> (tempfile::TempDir, Value) {
        let dir = tempfile::tempdir().unwrap();
        let result = command(
            &std::env::current_exe().unwrap(),
            &[
                "--ignored".into(),
                "--exact".into(),
                "contract::tests::capture_fixture".into(),
                "--nocapture".into(),
            ],
            mode.as_bytes(),
            dir.path(),
            "capture",
            timeout,
            never_cancel,
        )
        .unwrap();
        let persisted: Value =
            serde_json::from_reader(File::open(dir.path().join("capture.result.json")).unwrap())
                .unwrap();
        assert_eq!(result, persisted);
        (dir, result)
    }

    #[test]
    fn measured_policy_and_platform_refuse_before_any_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let exe = std::env::current_exe().unwrap();
        let args = vec!["--help".into()];
        let request = CommandRequest {
            exe: &exe,
            args: &args,
            input: b"",
            directory: dir.path(),
            label: "rejected",
            timeout: Duration::from_secs(1),
            cancelled: never_cancel,
        };
        for variant in 0..7 {
            let mut policy = crate::measure::SamplePolicy::cli(1, 0);
            match variant {
                0 => policy.schema = 1,
                1 => policy.identity.epoch = 0,
                2 => policy.identity.role = crate::measure::ProcessRole::BrokerC,
                3 => policy.identity.role = crate::measure::ProcessRole::SupervisorB,
                4 => policy.operation_id = 80,
                5 => policy.max_timepoints = 0,
                _ => policy.max_timepoints = 13,
            }
            assert!(command_measured(&request, &policy).is_err());
        }
        let policy = crate::measure::SamplePolicy::cli(1, 0);
        for timeout in [Duration::ZERO, Duration::from_secs(46)] {
            assert!(command_measured(&CommandRequest { timeout, ..request }, &policy).is_err());
        }
        let oversized = vec![b'x'; 2 * 1024 * 1024 + 1];
        assert!(command_measured(
            &CommandRequest {
                input: &oversized,
                ..request
            },
            &policy
        )
        .is_err());
        #[cfg(not(all(windows, feature = "experimental-broker")))]
        assert!(command_measured(&request, &policy)
            .unwrap_err()
            .to_string()
            .contains("requires Windows"));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[cfg(all(windows, feature = "experimental-broker"))]
    #[test]
    fn measured_capture_failures_keep_final_io_and_never_become_success() {
        for (n, mode) in [
            "nonzero",
            "timeout",
            "live-stdout",
            "live-stderr",
            "descendant",
        ]
        .iter()
        .enumerate()
        {
            let dir = tempfile::tempdir().unwrap();
            let exe = std::env::current_exe().unwrap();
            let args = vec![
                "--ignored".into(),
                "--exact".into(),
                "contract::tests::capture_fixture".into(),
                "--nocapture".into(),
            ];
            let result = command_measured(
                &CommandRequest {
                    exe: &exe,
                    args: &args,
                    input: mode.as_bytes(),
                    directory: dir.path(),
                    label: "failure",
                    timeout: if *mode == "timeout" {
                        Duration::from_millis(100)
                    } else {
                        Duration::from_secs(5)
                    },
                    cancelled: never_cancel,
                },
                &crate::measure::SamplePolicy::cli(n as u64 + 1, 0),
            )
            .unwrap();
            if *mode == "descendant" {
                thread::sleep(Duration::from_millis(2200));
                assert!(dir.path().join("descendant-completed").exists());
            }
            assert_eq!(result["success"], false, "{mode}");
            let evidence: crate::measure::CommandMeasurement =
                serde_json::from_value(result["measurement"].clone()).unwrap();
            evidence.validate().unwrap();
            assert!(!evidence.command_success);
            assert!(evidence.child_exit_us.is_some());
            assert!(evidence.final_lifetime_logical_io.is_some());
            assert!(evidence.timepoints.len() <= 12);
            for stream in ["stdout", "stderr"] {
                assert!(
                    fs::metadata(dir.path().join(format!("failure.{stream}")))
                        .unwrap()
                        .len()
                        <= OUTPUT_LIMIT as u64
                );
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let result = command_measured(
            &CommandRequest {
                exe: &dir.path().join("missing.exe"),
                args: &[],
                input: b"",
                directory: dir.path(),
                label: "spawn",
                timeout: Duration::from_secs(1),
                cancelled: never_cancel,
            },
            &crate::measure::SamplePolicy::cli(1, 0),
        )
        .unwrap();
        assert_eq!(result["success"], false);
        assert!(result["measurement"]["memory"].is_null());
        assert!(result["measurement"]["final_lifetime_logical_io"].is_null());
    }

    #[cfg(all(windows, feature = "experimental-broker"))]
    #[test]
    fn measured_metadata_admission_precedes_writes_and_intent_pins_policy() {
        let dir = tempfile::tempdir().unwrap();
        let exe = std::env::current_exe().unwrap();
        let too_large = vec!["x".repeat(65537)];
        let mut request = CommandRequest {
            exe: &exe,
            args: &too_large,
            input: b"",
            directory: dir.path(),
            label: "admission",
            timeout: Duration::from_secs(2),
            cancelled: never_cancel,
        };
        let policy = crate::measure::SamplePolicy::cli(1, 0);
        assert!(command_measured(&request, &policy).is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        let args = vec!["--help".into()];
        request.args = &args;
        command_measured(&request, &policy).unwrap();
        let intent: Value =
            serde_json::from_reader(File::open(dir.path().join("admission.intent.json")).unwrap())
                .unwrap();
        assert_eq!(
            intent["measurement_policy"],
            serde_json::to_value(&policy).unwrap()
        );
        let before = fs::read(dir.path().join("admission.result.json")).unwrap();
        assert!(command_measured(&request, &policy).is_err());
        assert_eq!(
            before,
            fs::read(dir.path().join("admission.result.json")).unwrap()
        );
    }

    #[cfg(all(windows, feature = "experimental-broker"))]
    #[test]
    fn measured_command_retains_real_child_io_and_memory_without_changing_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let exe = std::env::current_exe().unwrap();
        let args = vec![
            "--ignored".into(),
            "--exact".into(),
            "contract::tests::capture_sleeper".into(),
            "--nocapture".into(),
        ];
        let policy = crate::measure::SamplePolicy::cli(7, 0);
        let result = command_measured(
            &CommandRequest {
                exe: &exe,
                args: &args,
                input: b"",
                directory: dir.path(),
                label: "measured",
                timeout: Duration::from_secs(5),
                cancelled: never_cancel,
            },
            &policy,
        )
        .unwrap();
        assert_eq!(result["success"], true);
        let evidence: crate::measure::CommandMeasurement =
            serde_json::from_value(result["measurement"].clone()).unwrap();
        assert_eq!(
            evidence.identity.role,
            crate::measure::ProcessRole::CliChild
        );
        assert_eq!(evidence.identity.epoch, 7);
        assert!(evidence.live_samples > 0);
        assert!(evidence.memory.as_ref().unwrap().sampled_private_bytes > 0);
        assert!(
            evidence
                .final_lifetime_logical_io
                .as_ref()
                .unwrap()
                .write_bytes
                > 0
        );
        assert!(evidence.child_exit_us.is_some());
        assert!(evidence.final_io_error.is_none());
        let persisted: Value =
            serde_json::from_reader(File::open(dir.path().join("measured.result.json")).unwrap())
                .unwrap();
        assert_eq!(persisted, result);
        let (_, legacy) = fixture("nonzero", Duration::from_secs(5));
        assert!(legacy.get("measurement").is_none());
    }

    #[cfg(windows)]
    #[test]
    fn bounded_capture_overflow_keeps_evidence() {
        for stream in ["stdout", "stderr"] {
            let (dir, result) = fixture(stream, Duration::from_secs(5));
            assert_eq!(result["success"], false);
            assert_eq!(result[format!("{stream}_overflow")], true);
            assert!(result[stream].as_str().unwrap().len() <= 1024 * 1024);
            assert_eq!(
                fs::metadata(dir.path().join(format!("capture.{stream}")))
                    .unwrap()
                    .len(),
                1024 * 1024
            );
            assert_eq!(result["child_exited"], true);
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess fixture only; explicitly selected with --ignored --exact"]
    fn capture_sleeper() {
        thread::sleep(Duration::from_secs(2));
        fs::write("descendant-completed", b"ok").unwrap();
        std::process::exit(0);
    }

    #[cfg(windows)]
    #[test]
    fn capture_exact_cap_is_successful() {
        let (dir, result) = fixture("boundary", Duration::from_secs(5));
        assert_eq!(result["success"], true);
        assert_eq!(result["stderr_overflow"], false);
        assert_eq!(result["stderr"].as_str().unwrap().len(), OUTPUT_LIMIT);
        assert_eq!(
            fs::metadata(dir.path().join("capture.stderr"))
                .unwrap()
                .len(),
            OUTPUT_LIMIT as u64
        );
    }

    #[cfg(windows)]
    #[test]
    fn capture_stops_live_producer_before_completion() {
        for stream in ["stdout", "stderr"] {
            let (dir, result) = fixture(&format!("live-{stream}"), Duration::from_secs(10));
            assert_eq!(result["success"], false);
            assert_eq!(result[format!("{stream}_overflow")], true);
            assert_eq!(result["timed_out"], false);
            assert_eq!(result["child_exited"], true);
            assert!(!dir.path().join("unexpected-completion").exists());
            for name in ["stdout", "stderr"] {
                assert!(
                    fs::metadata(dir.path().join(format!("capture.{name}")))
                        .unwrap()
                        .len()
                        <= OUTPUT_LIMIT as u64
                );
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn capture_timeout_retains_status_and_evidence() {
        let (_, result) = fixture("timeout", Duration::from_millis(100));
        assert_eq!(result["success"], false);
        assert_eq!(result["timed_out"], true);
        assert_eq!(result["child_exited"], true);
        assert!(result["elapsed_us"].as_u64().unwrap() < 3_000_000);
    }

    #[cfg(windows)]
    #[test]
    fn capture_nonzero_exit_is_preserved() {
        let (_, result) = fixture("nonzero", Duration::from_secs(5));
        assert_eq!(result["success"], false);
        assert_eq!(result["exit_code"], 7);
        assert_eq!(result["capture_complete"], true);
        assert_eq!(result["timed_out"], false);
    }

    #[cfg(windows)]
    #[test]
    fn capture_does_not_wait_for_or_kill_descendants() {
        CHILD_DRAIN_ELAPSED.with(|elapsed| elapsed.set(None));
        let (dir, result) = fixture("descendant", Duration::from_secs(5));
        let elapsed = CHILD_DRAIN_ELAPSED.with(|elapsed| elapsed.get().unwrap());
        // Observe finite descendant completion rather than guessing its startup
        // latency with a fixed sleep. This is outside the drain timing assertion.
        let completion_deadline = Instant::now() + Duration::from_secs(5);
        while !dir.path().join("descendant-completed").exists()
            && Instant::now() < completion_deadline
        {
            thread::sleep(Duration::from_millis(2));
        }
        assert!(dir.path().join("descendant-completed").exists());
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        assert_eq!(result["exit_code"], 0);
        assert_eq!(result["child_exited"], true);
        assert_eq!(result["capture_complete"], false);
        assert_eq!(result["success"], false);
    }

    #[cfg(windows)]
    #[test]
    fn capture_unread_stdin_cannot_block_timeout_or_cancellation() {
        for cancel in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let result = command(
                &std::env::current_exe().unwrap(),
                &[
                    "--ignored".into(),
                    "--exact".into(),
                    "contract::tests::capture_sleeper".into(),
                    "--nocapture".into(),
                ],
                &vec![b'x'; 8 * 1024 * 1024],
                dir.path(),
                "unread",
                // Cancellation is immediate; do not simultaneously trigger the
                // 100ms timeout while Windows is still starting the child.
                if cancel {
                    Duration::from_secs(5)
                } else {
                    Duration::from_millis(100)
                },
                if cancel { || true } else { never_cancel },
            )
            .unwrap();
            assert_eq!(result["success"], false);
            assert_eq!(result["child_exited"], true);
            assert_eq!(result["stop_requested"], cancel);
            assert_eq!(result["timed_out"], !cancel);
            assert!(result["elapsed_us"].as_u64().unwrap() < 3_000_000);
            let persisted: Value =
                serde_json::from_reader(File::open(dir.path().join("unread.result.json")).unwrap())
                    .unwrap();
            assert_eq!(result, persisted);
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn capture_poll_refuses_non_windows_without_reading() {
        let mut pipe = std::io::Cursor::new(b"must not be consumed");
        let mut capture = Capture::default();
        let error = capture.poll(&mut pipe).unwrap_err();
        assert_eq!(error.to_string(), "bounded CLI capture requires Windows");
        assert_eq!(pipe.position(), 0);
        assert!(capture.bytes.is_empty());
        assert!(!capture.overflow && !capture.eof);
    }

    #[cfg(not(windows))]
    #[test]
    fn command_non_windows_capture_fails_closed_with_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let result = command(
            &std::env::current_exe().unwrap(),
            &["--help".into()],
            b"",
            dir.path(),
            "unsupported",
            Duration::from_secs(5),
            never_cancel,
        )
        .unwrap();
        assert_eq!(result["success"], false);
        assert_eq!(result["capture_complete"], false);
        assert_eq!(
            result["capture_error"],
            "bounded CLI capture requires Windows"
        );
        assert!(result["spawn_error"].is_null());
        assert_eq!(result["child_exited"], true);
        assert!(output(&result).is_err());
        let persisted: Value = serde_json::from_reader(
            File::open(dir.path().join("unsupported.result.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(result, persisted);
    }

    #[test]
    fn capture_spawn_failure_retains_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let result = command(
            &dir.path().join("missing.exe"),
            &[],
            b"",
            dir.path(),
            "missing",
            Duration::from_secs(1),
            never_cancel,
        )
        .unwrap();
        assert_eq!(result["success"], false);
        assert_eq!(result["child_exited"], false);
        assert!(result["exit_code"].is_null());
        assert!(result["spawn_error"].is_string());
        let persisted: Value =
            serde_json::from_reader(File::open(dir.path().join("missing.result.json")).unwrap())
                .unwrap();
        assert_eq!(result, persisted);
    }

    #[cfg(windows)]
    #[test]
    fn command_captures_real_child_status_and_refuses_log_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let exe = std::env::current_exe().unwrap();
        let result = command(
            &exe,
            &["--help".into()],
            b"",
            dir.path(),
            "help",
            Duration::from_secs(10),
            never_cancel,
        )
        .unwrap();
        assert_eq!(result["exit_code"], 0);
        assert_eq!(result["timed_out"], false);
        assert!(result["stdout"].as_str().unwrap().contains("Usage"));
        assert!(command(
            &exe,
            &["--help".into()],
            b"",
            dir.path(),
            "help",
            Duration::from_secs(10),
            never_cancel
        )
        .is_err());
    }
}
