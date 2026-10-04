//! Separate Full20x256 barrier v1: exactly 64 operations, four phases each.
//! Ordinary files convey sequencing, NOT authentication or native proof. No Job,
//! small/pilot admission, installed command execution, or service authority here.
use crate::{
    contract::ensure,
    data::Result,
    full_manifest::{Ack, FullManifest, Operation},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Ready,
    Release,
    Done,
    ValidatedAck,
}
const PHASES: [Phase; 4] = [
    Phase::Ready,
    Phase::Release,
    Phase::Done,
    Phase::ValidatedAck,
];
impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Release => "release",
            Self::Done => "done",
            Self::ValidatedAck => "validated-ack",
        }
    }
    fn owner(self) -> Role {
        match self {
            Self::Ready | Self::Done => Role::Peer,
            _ => Role::Controller,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Peer,
    Controller,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Protocol {
    Full20x256BarrierV1,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    schema: u8,
    protocol: Protocol,
    epoch: String,
    operation_id: u32,
    cli_epoch: u64,
    phase: Phase,
    ack: Option<Ack>,
}
const MESSAGE_LIMIT: u64 = 1024;
const STEPS: usize = FullManifest::OPERATIONS as usize * 4;

/// O(1) cursor state; a closed 256-path namespace, no directory enumeration.
/// Both peers observe every phase before advancing. Paths are no-replace and
/// create-new staging is synced before hard-link publication, as in schema-2.
pub struct FullBarrier<'a> {
    root: PathBuf,
    epoch: String,
    role: Role,
    manifest: &'a FullManifest,
    next: usize,
}
impl<'a> FullBarrier<'a> {
    pub fn new(root: &Path, epoch: &str, role: Role, manifest: &'a FullManifest) -> Result<Self> {
        ensure(
            !epoch.is_empty() && epoch.len() <= 256,
            "full barrier epoch bound",
        )?;
        Ok(Self {
            root: root.into(),
            epoch: epoch.into(),
            role,
            manifest,
            next: 0,
        })
    }
    pub fn complete(&self) -> bool {
        self.next == STEPS
    }
    fn path(&self, id: u32, phase: Phase) -> PathBuf {
        let dir = if phase.owner() == Role::Peer {
            "scratch"
        } else {
            "controller"
        };
        self.root
            .join(dir)
            .join(format!("full20x256-v1-op-{id}-{}.json", phase.name()))
    }
    fn ordered(&self, id: u32, phase: Phase) -> Result<()> {
        ensure(
            id < FullManifest::OPERATIONS && self.next == id as usize * 4 + phase as usize,
            "full barrier phase out of order",
        )
    }
    fn validate_files(&self, id: u32, phase: Phase) -> Result<()> {
        self.ordered(id, phase)?;
        for step in self.next + 1..STEPS {
            ensure(
                !self
                    .path((step / 4) as u32, PHASES[step % 4])
                    .try_exists()?,
                "full barrier future publication exists",
            )?;
        }
        Ok(())
    }
    fn expected_ack(&self, id: u32) -> Result<Ack> {
        let op = self.manifest.operation(id)?;
        Ok(Ack {
            schema: 1,
            operation_id: id,
            cli_epoch: op.cli_epoch,
            payload_bytes: op.payload_bytes,
            inserted: op.inserted,
            duplicates: op.duplicates,
            sessions: op.sessions,
        })
    }
    fn validate(&self, message: &Message, id: u32, phase: Phase) -> Result<()> {
        self.ordered(id, phase)?;
        ensure(
            message.schema == 1
                && message.protocol == Protocol::Full20x256BarrierV1
                && message.epoch == self.epoch
                && message.operation_id == id
                && message.phase == phase
                && message.cli_epoch == self.manifest.operation(id)?.cli_epoch,
            "full barrier stale/invalid message",
        )?;
        let expected = if phase == Phase::ValidatedAck {
            Some(self.expected_ack(id)?)
        } else {
            None
        };
        ensure(message.ack == expected, "full barrier ACK mismatch")
    }
    fn publish_message(&mut self, id: u32, phase: Phase, ack: Option<Ack>) -> Result<()> {
        self.validate_files(id, phase)?;
        ensure(phase.owner() == self.role, "full barrier wrong publisher")?;
        let message = Message {
            schema: 1,
            protocol: Protocol::Full20x256BarrierV1,
            epoch: self.epoch.clone(),
            operation_id: id,
            cli_epoch: self.manifest.operation(id)?.cli_epoch,
            phase,
            ack,
        };
        self.validate(&message, id, phase)?;
        let destination = self.path(id, phase);
        ensure(
            !destination.try_exists()?,
            "full barrier destination exists",
        )?;
        let bytes = serde_json::to_vec(&message)?;
        ensure(
            bytes.len() as u64 <= MESSAGE_LIMIT,
            "full barrier message bound",
        )?;
        let staging = destination.with_extension("pending");
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
    pub fn publish(&mut self, id: u32, phase: Phase) -> Result<()> {
        ensure(
            phase != Phase::ValidatedAck,
            "full ACK requires complete receipt validator",
        )?;
        self.publish_message(id, phase, None)
    }
    /// Trust boundary for the next installed adapter: validator MUST authenticate
    /// executable/argv/input, case epoch/command label, exact capture paths,
    /// operation and CLI epoch, successful child exit,
    /// complete bounded stdout/stderr capture, complete measured command evidence
    /// (including final lifetime I/O), and exact semantic output from the actual
    /// persisted command receipt. Return Err on missing/failed/unknown-commit data;
    /// never retry an unknown commit. Only then return pure manifest Ack data.
    /// This generic callback is intentionally NOT a built-in native validator.
    /// A caller returning fabricated Ack data violates this contract; these files
    /// and unsigned Ack values do not establish identity, ACL custody, or proof.
    pub fn acknowledge<R>(
        &mut self,
        id: u32,
        receipt: &R,
        validate_command: impl FnOnce(&Operation, &[u8], &R) -> Result<Ack>,
        mut cancelled: impl FnMut() -> bool,
    ) -> Result<()> {
        self.ordered(id, Phase::ValidatedAck)?;
        ensure(
            self.role == Role::Controller,
            "full ACK requires controller",
        )?;
        ensure(!cancelled(), "full barrier cancelled")?;
        let op = self.manifest.operation(id)?;
        let payload = self.manifest.payload(id)?;
        let ack = validate_command(&op, &payload, receipt)?;
        ensure(ack == self.expected_ack(id)?, "full receipt ACK mismatch")?;
        ensure(!cancelled(), "full barrier cancelled")?;
        self.publish_message(id, Phase::ValidatedAck, Some(ack))
    }
    /// missing() runs ONLY after an actual NotFound observation; callers can use
    /// explicit events to prove withheld messages without sleep/startup guesses.
    /// Coordination time is separate from this bounded absolute phase deadline.
    pub fn wait(
        &mut self,
        id: u32,
        phase: Phase,
        deadline: Instant,
        mut cancelled: impl FnMut() -> bool,
        mut missing: impl FnMut(),
    ) -> Result<()> {
        let now = Instant::now();
        ensure(
            deadline > now && deadline.duration_since(now) <= Duration::from_secs(60),
            "full barrier deadline bound",
        )?;
        ensure(phase.owner() != self.role, "full barrier wrong observer")?;
        loop {
            ensure(
                !cancelled() && Instant::now() < deadline,
                "full barrier cancelled or timed out",
            )?;
            self.validate_files(id, phase)?;
            match File::open(self.path(id, phase)) {
                Ok(file) => {
                    ensure(
                        file.metadata()?.is_file() && file.metadata()?.len() <= MESSAGE_LIMIT,
                        "full barrier size/type bound",
                    )?;
                    let mut bytes = Vec::new();
                    file.take(MESSAGE_LIMIT + 1).read_to_end(&mut bytes)?;
                    ensure(
                        bytes.len() as u64 <= MESSAGE_LIMIT,
                        "full barrier message grew",
                    )?;
                    let message: Message = serde_json::from_slice(&bytes)?;
                    self.validate(&message, id, phase)?;
                    ensure(
                        !cancelled() && Instant::now() < deadline,
                        "full barrier cancelled or timed out",
                    )?;
                    self.next += 1;
                    return Ok(());
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    missing();
                    thread::sleep(Duration::from_millis(2));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}
/// Ordinary callback seam, not an installed-client adapter. execute MUST finish
/// and persist the complete command receipt for controller validation before
/// returning Ok. Err (including unknown commit) stops without Done or retry.
/// No operation N+1 callback runs until validated ACK N is consumed.
pub fn run_peer(
    root: &Path,
    epoch: &str,
    manifest: &FullManifest,
    deadline: Instant,
    mut cancelled: impl FnMut() -> bool,
    mut execute: impl FnMut(&Operation, &[u8]) -> Result<()>,
    mut missing: impl FnMut(u32, Phase),
) -> Result<()> {
    let mut peer = FullBarrier::new(root, epoch, Role::Peer, manifest)?;
    for id in 0..FullManifest::OPERATIONS {
        ensure(
            !cancelled() && Instant::now() < deadline,
            "full peer cancelled or expired",
        )?;
        let op = manifest.operation(id)?;
        let payload = manifest.payload(id)?;
        peer.publish(id, Phase::Ready)?;
        peer.wait(
            id,
            Phase::Release,
            deadline.min(Instant::now() + Duration::from_secs(60)),
            &mut cancelled,
            || missing(id, Phase::Release),
        )?;
        ensure(
            !cancelled() && Instant::now() < deadline,
            "full peer cancelled or expired",
        )?;
        execute(&op, &payload)?;
        ensure(
            !cancelled() && Instant::now() < deadline,
            "full peer cancelled or expired",
        )?;
        peer.publish(id, Phase::Done)?;
        peer.wait(
            id,
            Phase::ValidatedAck,
            deadline.min(Instant::now() + Duration::from_secs(60)),
            &mut cancelled,
            || missing(id, Phase::ValidatedAck),
        )?;
    }
    Ok(())
}
#[cfg(test)]
#[path = "full_workload_barrier_tests.rs"]
mod tests;
