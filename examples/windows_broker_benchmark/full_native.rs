//! Full-only orchestration. Ordinary injection and installed execution use the same loop.
use crate::{contract::ensure, data::Result};
use serde_json::Value;
/// Compare the entire ordered list: no filtering by name or measurement presence.
/// Disk/capture validation happens before retention and ACK, not in this comparator.
pub fn validate_final_commands(commands: &[Value], retained: &[Value]) -> Result<()> {
    ensure(
        commands.len() == 64 && retained.len() == 64 && commands == retained,
        "final full64 commands differ from complete controller retention",
    )?;
    let manifest = crate::full_manifest::FullManifest::new(
        crate::full_manifest::WorkloadSpec::full20x256_v1(),
        16,
    )?;
    for (id, value) in commands.iter().enumerate() {
        let op = manifest.operation(id as u32)?;
        let command: crate::full_workload_receipt::MeasuredCommand =
            serde_json::from_value(value.clone())?;
        crate::full_workload_receipt::validate_retained_command(&command, &op)?;
    }
    Ok(())
}

use crate::{
    contract::CommandRequest, full_manifest::FullManifest, full_workload_receipt::Adapter,
    measure::SamplePolicy,
};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    time::{Duration, Instant},
};
fn phase(deadline: Instant) -> Instant {
    deadline.min(Instant::now() + Duration::from_secs(60))
}
#[derive(Debug)]
struct AdmissionStopped;
impl std::fmt::Display for AdmissionStopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("full case cancelled/deadline")
    }
}
impl std::error::Error for AdmissionStopped {}
fn active(adapter: &Adapter<'_>, deadline: Instant) -> Result<()> {
    if (adapter.cancelled)() || Instant::now() >= deadline {
        return Err(Box::new(AdmissionStopped));
    }
    Ok(())
}
const FULL_COMMAND_LIMIT: usize = 128 * 1024;
pub(crate) fn command_bound(command: &Value) -> Result<()> {
    ensure(
        serde_json::to_vec(command)?.len() <= FULL_COMMAND_LIMIT,
        "full-only retained command bound",
    )
}
pub fn execute_peer_with_runner(
    adapter: &Adapter<'_>,
    manifest: &FullManifest,
    deadline: Instant,
    commands: &mut Vec<Value>,
    mut runner: impl FnMut(&CommandRequest<'_>, &SamplePolicy) -> Result<Value>,
) -> Result<()> {
    ensure(commands.is_empty(), "full peer retention must start empty")?;
    crate::full_workload_barrier::run_peer(
        adapter.root,
        adapter.epoch,
        manifest,
        deadline,
        adapter.cancelled,
        |op, payload| {
            let operation_deadline = phase(deadline);
            adapter.execute(manifest, op, payload, operation_deadline, &mut runner)?;
            let actual = adapter.read_validated_command(manifest, op.id)?;
            command_bound(&actual)?;
            active(adapter, operation_deadline)?;
            commands.push(actual);
            Ok(())
        },
        |_, _| {},
    )
}
/// No callback interruption guarantee: command_measured enforces the actual
/// request cancellation and direct-child timeout; late sync/drain is rejected.
#[allow(dead_code)]
pub fn execute_installed_peer(
    adapter: &Adapter<'_>,
    manifest: &FullManifest,
    deadline: Instant,
    commands: &mut Vec<Value>,
) -> Result<()> {
    execute_peer_with_runner(
        adapter,
        manifest,
        deadline,
        commands,
        crate::contract::command_measured,
    )
}

/// Hash preparation/finalization stays outside Acquire; all timestamps are owned by the shared loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FullEvent {
    BeforeRelease,
    ReleasePublishBegin,
    ReleasePublishEnd,
    DoneObserved,
    DoneMissing,
    Acquire(CadenceRole),
    IntervalFinalize,
}
fn duration_us(duration: Duration) -> Result<u64> {
    u64::try_from(duration.as_micros()).map_err(|_| "cadence duration overflow".into())
}
fn elapsed_us(origin: Instant) -> Result<u64> {
    duration_us(origin.elapsed())
}
fn attempted_read(error: Box<dyn std::error::Error>) -> Box<dyn std::error::Error> {
    if error.downcast_ref::<AbortedAcquisition>().is_some() {
        // The callback was invoked: this is an attempted query error, not the
        // intermediate-admission decision that skips C altogether.
        error.to_string().into()
    } else {
        error
    }
}
#[allow(clippy::too_many_arguments)]
fn acquire_pair(
    c: &mut Cadence,
    origin: Instant,
    slot: Option<u64>,
    baseline: bool,
    end: bool,
    adapter: &Adapter<'_>,
    deadline: Instant,
    loop_pairs: &mut u64,
    sample: &mut impl FnMut(u32, FullEvent) -> Result<Value>,
) -> Result<()> {
    transition(
        &mut c.state,
        Transition::AdmitClass(
            if baseline {
                AcquisitionClass::Baseline
            } else if end {
                AcquisitionClass::End
            } else {
                AcquisitionClass::Requested
            },
            slot,
        ),
    )?;
    let admission = operation_gate(c, adapter, deadline).and_then(|()| {
        ensure(
            *loop_pairs < 150128 && c.pair_attempts < 30002,
            "cadence sample pair ceiling",
        )
    });
    if let Err(e) = admission {
        if slot.is_some() {
            add(&mut c.unacquired_requests, 1)?;
        }
        return Err(e);
    }
    add(loop_pairs, 1)?;
    let bb = elapsed_us(origin)?;
    let b = sample(c.operation_id, FullEvent::Acquire(CadenceRole::SupervisorB))
        .and_then(|v| Ok(serde_json::from_value(v)?))
        .map_err(attempted_read);
    let be = elapsed_us(origin)?;
    // A B query fault never suppresses the one C attempt, unless cancellation/deadline dominates.
    let cb = elapsed_us(origin)?;
    let abort = active(adapter, deadline);
    let cr = if abort.is_ok() {
        sample(c.operation_id, FullEvent::Acquire(CadenceRole::BrokerC))
            .and_then(|v| Ok(serde_json::from_value(v)?))
            .map_err(attempted_read)
    } else {
        Err(Box::new(AbortedAcquisition) as Box<dyn std::error::Error>)
    };
    let ce = elapsed_us(origin)?;
    let result = c.record_pair(slot, baseline, end, [(bb, be, b), (cb, ce, cr)]);
    operation_gate(c, adapter, deadline)?;
    result
}
fn boundary_observation(c: &Cadence, end: bool) -> Result<Value> {
    let b = if end {
        &c.supervisor.end
    } else {
        &c.supervisor.baseline
    };
    let cr = if end {
        &c.broker.end
    } else {
        &c.broker.baseline
    };
    if let (Some(b), Some(cr)) = (b, cr) {
        Ok(
            serde_json::json!({"broker_epoch":1,"supervisor_epoch":2,"cli_epoch":c.cli_epoch,"broker":cr.read.sample,"supervisor":b.read.sample,
            "broker_logical_io_delta":if end {c.broker.baseline_to_end_io} else {None},
            "supervisor_logical_io_delta":if end {c.supervisor.baseline_to_end_io} else {None},
            "handshake_span_us":if end {c.observation_envelope_end_us} else {None}}),
        )
    } else {
        Ok(Value::Null)
    }
}
#[allow(clippy::too_many_arguments)]
pub fn controller_intervals(
    adapter: &Adapter<'_>,
    manifest: &FullManifest,
    projection: &Path,
    initial: u64,
    deadline: Instant,
    retained: &mut Vec<Value>,
    boundaries: &mut Vec<Value>,
    mut sample: impl FnMut(u32, FullEvent) -> Result<Value>,
) -> Result<()> {
    use crate::full_workload_barrier::{FullBarrier, Phase, Role};
    use sha2::{Digest, Sha256};
    ensure(
        retained.is_empty() && boundaries.is_empty(),
        "full controller retention must start empty",
    )?;
    let cap = (0..64).try_fold(initial, |n, id| -> Result<u64> {
        n.checked_add(manifest.operation(id)?.appended_jsonl_bytes)
            .ok_or_else(|| "full projection bound overflow".into())
    })?;
    let mut barrier = FullBarrier::new(adapter.root, adapter.epoch, Role::Controller, manifest)?;
    let mut loop_pairs = 0;
    for id in 0..64 {
        let op = manifest.operation(id)?;
        let mut c = Cadence::new(adapter.epoch, id, op.cli_epoch);
        let mut origin = Instant::now();
        boundaries.push(serde_json::json!({"operation_id":id,"cli_epoch":op.cli_epoch,"descriptor":Descriptor::from_operation(&op),"before_release":null,"after_done":null,"receipt_validated":false,"exact_append_verified":false,"cadence":c}));
        let result = (|| -> Result<()> {
            barrier.wait(id, Phase::Ready, phase(deadline), adapter.cancelled, || {})?;
            if id > 0 {
                // This controller owns a validated next-READY observation, not
                // native proof of the peer's internal ACK read or authenticity.
                let mut previous: Cadence =
                    serde_json::from_value(boundaries[id as usize - 1]["cadence"].clone())?;
                transition(&mut previous.state, Transition::PeerReady)?;
                boundaries[id as usize - 1]["cadence"] = serde_json::to_value(previous)?;
            }
            transition(
                &mut c.state,
                Transition::Stage(ControllerStage::Preparation),
            )?;
            let mut file = File::open(projection)?;
            let before = file.metadata()?.len();
            ensure(
                file.metadata()?.is_file() && before <= cap,
                "full projection initial bound/type",
            )?;
            let hash = crate::data::hash_file(projection)?;
            let release_deadline = phase(deadline);
            operation_gate(&mut c, adapter, release_deadline)?;
            sample(id, FullEvent::BeforeRelease)?; // Native snapshot hash before origin.
            operation_gate(&mut c, adapter, release_deadline)?;
            origin = Instant::now();
            transition(&mut c.state, Transition::Stage(ControllerStage::Baseline))?;
            acquire_pair(
                &mut c,
                origin,
                None,
                true,
                false,
                adapter,
                release_deadline,
                &mut loop_pairs,
                &mut sample,
            )?;
            boundaries[id as usize]["before_release"] = boundary_observation(&c, false)?;
            transition(&mut c.state, Transition::Stage(ControllerStage::Release))?;
            operation_gate(&mut c, adapter, release_deadline)?;
            sample(id, FullEvent::ReleasePublishBegin)?;
            operation_gate(&mut c, adapter, release_deadline)?;
            c.release_begin_us = Some(elapsed_us(origin)?);
            transition(&mut c.state, Transition::ReleaseAttempt)?;
            let publication = barrier.publish(id, Phase::Release);
            transition(
                &mut c.state,
                Transition::ReleaseOutcome(if publication.is_ok() {
                    Publication::Confirmed
                } else {
                    Publication::Unknown
                }),
            )?;
            publication?;
            c.release_end_us = Some(elapsed_us(origin)?);
            operation_gate(&mut c, adapter, release_deadline)?;
            sample(id, FullEvent::ReleasePublishEnd)?;
            operation_gate(&mut c, adapter, release_deadline)?;
            transition(&mut c.state, Transition::Stage(ControllerStage::Done))?;
            let done_deadline = phase(deadline);
            barrier.wait_with_poll(id, Phase::Done, done_deadline, adapter.cancelled, || {
                sample(id, FullEvent::DoneMissing)?;
                if let Some(slot) = c.due(elapsed_us(origin)?)? {
                    acquire_pair(
                        &mut c,
                        origin,
                        Some(slot),
                        false,
                        false,
                        adapter,
                        done_deadline,
                        &mut loop_pairs,
                        &mut sample,
                    )?;
                }
                Ok(())
            })?;
            transition(&mut c.state, Transition::DoneValidated)?;
            c.done_validated_us = Some(elapsed_us(origin)?);
            sample(id, FullEvent::DoneObserved)?;
            transition(&mut c.state, Transition::Stage(ControllerStage::End))?;
            acquire_pair(
                &mut c,
                origin,
                None,
                false,
                true,
                adapter,
                done_deadline,
                &mut loop_pairs,
                &mut sample,
            )?;
            transition(&mut c.state, Transition::Stage(ControllerStage::Finalize))?;
            c.finish(elapsed_us(origin)?)?;
            c.validate(adapter.epoch, id, op.cli_epoch)?;
            boundaries[id as usize]["cadence"] = serde_json::to_value(&c)?;
            boundaries[id as usize]["after_done"] = boundary_observation(&c, true)?;
            // Finalized evidence is retained before native/generic hashes or receipts.
            operation_gate(&mut c, adapter, done_deadline)?;
            sample(id, FullEvent::IntervalFinalize)?;
            operation_gate(&mut c, adapter, done_deadline)?;
            transition(&mut c.state, Transition::Stage(ControllerStage::Append))?;
            let ack_deadline = phase(deadline);
            ensure(
                file.metadata()?.len()
                    == before
                        .checked_add(op.appended_jsonl_bytes)
                        .ok_or("full append overflow")?
                    && file.metadata()?.len() <= cap,
                "full exact append length",
            )?;
            file.seek(SeekFrom::Start(0))?;
            let mut prefix = (&mut file).take(before);
            let mut digest = Sha256::new();
            let mut buffer = [0u8; 65536];
            loop {
                let n = prefix.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                digest.update(&buffer[..n]);
            }
            ensure(
                format!("{:x}", digest.finalize()) == hash,
                "full prefix changed",
            )?;
            if op.inserted > 0 {
                for record in manifest.records(id)? {
                    let mut expected = serde_json::to_vec(&record)?;
                    expected.push(b'\n');
                    let mut actual = vec![0; expected.len()];
                    file.read_exact(&mut actual)?;
                    ensure(actual == expected, "full exact append payload")?;
                }
            }
            ensure(file.read(&mut [0; 1])? == 0, "full append trailing bytes")?;
            transition(&mut c.state, Transition::AppendVerified)?;
            transition(&mut c.state, Transition::Stage(ControllerStage::Receipt))?;
            // Bound before Adapter::acknowledge can retain and publish ACK.
            command_bound(&adapter.read_validated_command(manifest, id)?)?;
            transition(&mut c.state, Transition::ReceiptValidated)?;
            operation_gate(&mut c, adapter, ack_deadline)?;
            adapter.acknowledge_observed(
                &mut barrier,
                manifest,
                id,
                retained,
                ack_deadline,
                |event| {
                    use crate::full_workload_receipt::AckEvent;
                    match event {
                        AckEvent::Validated => {
                            if !c.state.receipt_validated {
                                transition(&mut c.state, Transition::ReceiptValidated)?;
                            }
                            transition(&mut c.state, Transition::Stage(ControllerStage::Retention))
                        }
                        AckEvent::Retained => {
                            transition(&mut c.state, Transition::CommandRetained)?;
                            transition(&mut c.state, Transition::Stage(ControllerStage::Ack))
                        }
                        AckEvent::Attempt => transition(&mut c.state, Transition::AckAttempt),
                        AckEvent::Confirmed => {
                            transition(&mut c.state, Transition::AckOutcome(Publication::Confirmed))
                        }
                        AckEvent::Unknown => {
                            transition(&mut c.state, Transition::AckOutcome(Publication::Unknown))
                        }
                    }
                },
            )?;
            transition(&mut c.state, Transition::Stage(ControllerStage::PostAck))?;
            operation_gate(&mut c, adapter, ack_deadline)?;
            transition(&mut c.state, Transition::Seal)?;
            ensure(
                c.state.complete_confirmed(),
                "controller operation incomplete",
            )?;
            Ok(())
        })();
        boundaries[id as usize]["receipt_validated"] = Value::Bool(c.state.receipt_validated);
        boundaries[id as usize]["exact_append_verified"] = Value::Bool(c.state.append_verified);
        if let Err(e) = &result {
            // The admission error can dominate the first query diagnostic.
            let observation = if e.downcast_ref::<AdmissionStopped>().is_some() {
                FailureObservation::AdmissionStopped
            } else {
                FailureObservation::ReturnedError
            };
            transition(
                &mut c.state,
                Transition::PrimaryStop(CadenceFailure::new(None, &**e).text, observation),
            )?;
            c.fault(None, &**e);
        }
        if c.observation_envelope_end_us.is_none() {
            let finalization = elapsed_us(origin).and_then(|now| c.finish(now));
            if let Err(e) = finalization {
                c.fault(None, &*e);
            }
        }
        let evidence = serde_json::to_value(&c).map(|v| {
            boundaries[id as usize]["cadence"] = v;
        });
        result?;
        evidence?;
    }
    Ok(())
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullWorkloadJob {
    pub schema: u8,
    pub protocol: FullJobProtocol,
    pub case_epoch: String,
    pub fixture_spec: crate::data::FixtureSpec,
    pub workload_spec: crate::full_manifest::WorkloadSpec,
    pub seed_records: u64,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum FullJobProtocol {
    Full20x256NativeJobV1,
}
impl FullWorkloadJob {
    pub fn validate(&self, job: &crate::contract::Job) -> Result<()> {
        ensure(
            self.schema == 1
                && self.fixture_spec == crate::data::FixtureSpec::representative_6_mib()
                && self.workload_spec == crate::full_manifest::WorkloadSpec::full20x256_v1()
                && self.seed_records == job.seed_records
                && job.pilot.is_none(),
            "full protected job schema/spec/seed/mode mismatch",
        )?;
        ensure(
            !self.case_epoch.is_empty()
                && self.case_epoch.len() <= 256
                && self
                    .case_epoch
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "full case epoch bound",
        )?;
        FullManifest::new(self.workload_spec, self.seed_records).map(|_| ())
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ReportRole {
    Worker,
    Controller,
}
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FullStage {
    Warmup,
    Single,
    Batch,
    Dedup,
    UnchangedSnapshot,
    Export,
}
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub id: u32,
    pub cli_epoch: u64,
    pub stage: FullStage,
    pub records: u32,
    pub inserted: u64,
    pub duplicates: u64,
    pub replay_source: Option<u32>,
    pub payload_bytes: u64,
    pub appended_jsonl_bytes: u64,
    pub sessions: Option<u64>,
}
impl Descriptor {
    fn from_operation(op: &crate::full_manifest::Operation) -> Self {
        use crate::full_manifest::Stage;
        let stage = match op.stage {
            Stage::Warmup => FullStage::Warmup,
            Stage::Single => FullStage::Single,
            Stage::Batch => FullStage::Batch,
            Stage::Dedup => FullStage::Dedup,
            Stage::UnchangedSnapshot => FullStage::UnchangedSnapshot,
            Stage::Export => FullStage::Export,
        };
        Self {
            id: op.id,
            cli_epoch: op.cli_epoch,
            stage,
            records: op.records,
            inserted: op.inserted,
            duplicates: op.duplicates,
            replay_source: op.replay_source,
            payload_bytes: op.payload_bytes,
            appended_jsonl_bytes: op.appended_jsonl_bytes,
            sessions: op.sessions,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEvidence {
    pub logical_io: crate::measure::LogicalIo,
    pub private_bytes: u64,
    pub working_set_bytes: u64,
    pub lifetime_peak_private_bytes: u64,
    pub lifetime_peak_working_set_bytes: u64,
}

/// Full-only sequential retained-handle observation, never a simultaneous B+C total.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CadenceRole {
    SupervisorB,
    BrokerC,
}
impl CadenceRole {
    fn epoch(self) -> u64 {
        match self {
            Self::SupervisorB => 2,
            Self::BrokerC => 1,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedRead {
    pub role: CadenceRole,
    pub epoch: u64,
    pub sample: ProcessEvidence,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CadencePoint {
    ordinal: u64,
    class: AcquisitionClass,
    pub sample_begin_us: u64,
    pub sample_end_us: u64,
    pub requested_slot: Option<u64>,
    pub read: RetainedRead,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleCadence {
    pub last_attempt_span: Option<AcquisitionSpan>,
    pub max_attempt_span_us: Option<u64>,
    pub error: Option<CadenceFailure>,
    pub role: CadenceRole,
    pub epoch: u64,
    pub attempts: u64,
    pub successful_live_samples: u64,
    pub exit_observations: u64,
    pub query_errors: u64,
    pub counter_regressions: u64,
    pub not_attempted_due_to_abort: u64,
    pub forced_baseline_attempts: u64,
    pub forced_end_attempts: u64,
    pub baseline: Option<CadencePoint>,
    pub end: Option<CadencePoint>,
    pub prefix: Vec<CadencePoint>,
    pub omitted_points: u64,
    pub first_sample_us: Option<u64>,
    pub last: Option<CadencePoint>,
    pub max_consecutive_gap_us: Option<u64>,
    pub observation_max_gap_us: Option<u64>,
    pub operational_max_gap_us: Option<u64>,
    pub max_acquisition_span_us: Option<u64>,
    pub maxima: Option<ProcessEvidence>,
    pub baseline_to_end_io: Option<crate::measure::LogicalIo>,
}
fn add(n: &mut u64, amount: u64) -> Result<()> {
    *n = n.checked_add(amount).ok_or("cadence counter overflow")?;
    Ok(())
}
fn io_delta(
    a: &crate::measure::LogicalIo,
    b: &crate::measure::LogicalIo,
) -> Result<crate::measure::LogicalIo> {
    Ok(crate::measure::LogicalIo {
        read_operations: a
            .read_operations
            .checked_sub(b.read_operations)
            .ok_or("cadence IO regression")?,
        write_operations: a
            .write_operations
            .checked_sub(b.write_operations)
            .ok_or("cadence IO regression")?,
        other_operations: a
            .other_operations
            .checked_sub(b.other_operations)
            .ok_or("cadence IO regression")?,
        read_bytes: a
            .read_bytes
            .checked_sub(b.read_bytes)
            .ok_or("cadence IO regression")?,
        write_bytes: a
            .write_bytes
            .checked_sub(b.write_bytes)
            .ok_or("cadence IO regression")?,
        other_bytes: a
            .other_bytes
            .checked_sub(b.other_bytes)
            .ok_or("cadence IO regression")?,
    })
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcquisitionSpan {
    pub sample_begin_us: u64,
    pub sample_end_us: u64,
}
impl RoleCadence {
    fn attempt_span(&mut self, begin: u64, end: u64) -> Result<()> {
        let duration = end
            .checked_sub(begin)
            .ok_or("cadence attempt clock regression")?;
        self.last_attempt_span = Some(AcquisitionSpan {
            sample_begin_us: begin,
            sample_end_us: end,
        });
        self.max_attempt_span_us = Some(self.max_attempt_span_us.unwrap_or(0).max(duration));
        Ok(())
    }
    fn new(role: CadenceRole) -> Self {
        Self {
            role,
            last_attempt_span: None,
            max_attempt_span_us: None,
            error: None,
            epoch: role.epoch(),
            attempts: 0,
            successful_live_samples: 0,
            exit_observations: 0,
            query_errors: 0,
            counter_regressions: 0,
            not_attempted_due_to_abort: 0,
            forced_baseline_attempts: 0,
            forced_end_attempts: 0,
            baseline: None,
            end: None,
            prefix: Vec::new(),
            omitted_points: 0,
            first_sample_us: None,
            last: None,
            max_consecutive_gap_us: None,
            observation_max_gap_us: None,
            operational_max_gap_us: None,
            max_acquisition_span_us: None,
            maxima: None,
            baseline_to_end_io: None,
        }
    }
    fn record(&mut self, point: CadencePoint, baseline: bool, end: bool) -> Result<()> {
        self.attempt_span(point.sample_begin_us, point.sample_end_us)?;
        add(&mut self.attempts, 1)?;
        if baseline {
            add(&mut self.forced_baseline_attempts, 1)?;
        }
        if end {
            add(&mut self.forced_end_attempts, 1)?;
        }
        let checked = (|| -> Result<()> {
            ensure(
                point.read.role == self.role && point.read.epoch == self.epoch,
                "cadence role/epoch mismatch",
            )?;
            ensure(
                point.sample_begin_us <= point.sample_end_us
                    && self
                        .last
                        .as_ref()
                        .is_none_or(|p| p.sample_end_us <= point.sample_begin_us),
                "cadence acquisition clock regression",
            )?;
            let s = &point.read.sample;
            ensure(
                s.lifetime_peak_private_bytes >= s.private_bytes
                    && s.lifetime_peak_working_set_bytes >= s.working_set_bytes,
                "cadence impossible peak",
            )?;
            if let Some(previous) = &self.last {
                io_delta(&s.logical_io, &previous.read.sample.logical_io)?;
                ensure(
                    s.lifetime_peak_private_bytes
                        >= previous.read.sample.lifetime_peak_private_bytes
                        && s.lifetime_peak_working_set_bytes
                            >= previous.read.sample.lifetime_peak_working_set_bytes,
                    "cadence lifetime peak regression",
                )?;
            }
            Ok(())
        })();
        if let Err(e) = checked {
            let text = e.to_string();
            if text.contains("IO regression") || text.contains("peak") {
                add(&mut self.counter_regressions, 1)?;
            } else {
                add(&mut self.query_errors, 1)?;
            }
            self.error = Some(CadenceFailure::new(Some(self.role), &*e));
            return Err(e);
        }
        self.first_sample_us.get_or_insert(point.sample_end_us);
        let gap = self
            .last
            .as_ref()
            .map_or(0, |last| point.sample_end_us - last.sample_end_us);
        self.max_consecutive_gap_us = Some(self.max_consecutive_gap_us.unwrap_or(0).max(gap));
        self.max_acquisition_span_us = Some(
            self.max_acquisition_span_us
                .unwrap_or(0)
                .max(point.sample_end_us - point.sample_begin_us),
        );
        let sample = &point.read.sample;
        if let Some(max) = &mut self.maxima {
            max.private_bytes = max.private_bytes.max(sample.private_bytes);
            max.working_set_bytes = max.working_set_bytes.max(sample.working_set_bytes);
            max.lifetime_peak_private_bytes = max
                .lifetime_peak_private_bytes
                .max(sample.lifetime_peak_private_bytes);
            max.lifetime_peak_working_set_bytes = max
                .lifetime_peak_working_set_bytes
                .max(sample.lifetime_peak_working_set_bytes);
            max.logical_io = sample.logical_io;
        } else {
            self.maxima = Some(sample.clone());
        }
        add(&mut self.successful_live_samples, 1)?;
        if baseline {
            self.baseline = Some(point.clone());
        }
        if end {
            self.end = Some(point.clone());
        }
        if self.prefix.len() < 12 {
            self.prefix.push(point.clone());
        } else {
            add(&mut self.omitted_points, 1)?;
        }
        self.last = Some(point);
        Ok(())
    }

    fn acquire(
        &mut self,
        span: (u64, u64),
        slot: Option<u64>,
        baseline: bool,
        end: bool,
        ordinal: u64,
        read: Result<RetainedRead>,
    ) -> Result<()> {
        let (begin, end_us) = span;
        match read {
            Ok(read) => self.record(
                CadencePoint {
                    ordinal,
                    class: if baseline {
                        AcquisitionClass::Baseline
                    } else if end {
                        AcquisitionClass::End
                    } else {
                        AcquisitionClass::Requested
                    },
                    sample_begin_us: begin,
                    sample_end_us: end_us,
                    requested_slot: slot,
                    read,
                },
                baseline,
                end,
            ),
            Err(e) => {
                if e.downcast_ref::<AbortedAcquisition>().is_some() {
                    add(&mut self.not_attempted_due_to_abort, 1)?;
                    return Err(e);
                }
                self.attempt_span(begin, end_us)?;
                self.error = Some(CadenceFailure::new(Some(self.role), &*e));
                add(&mut self.attempts, 1)?;
                if baseline {
                    add(&mut self.forced_baseline_attempts, 1)?;
                }
                if end {
                    add(&mut self.forced_end_attempts, 1)?;
                }
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::BrokenPipe)
                {
                    add(&mut self.exit_observations, 1)?;
                } else {
                    add(&mut self.query_errors, 1)?;
                }
                Err(e)
            }
        }
    }

    fn validate(&self, release: Option<u64>, done: Option<u64>, envelope: u64) -> Result<()> {
        ensure(
            self.epoch == self.role.epoch() && self.prefix.len() <= 12 && self.attempts <= 30002,
            "cadence role bounds",
        )?;
        ensure(
            self.last_attempt_span.is_some() == (self.attempts > 0)
                && self.max_attempt_span_us.is_some() == (self.attempts > 0),
            "cadence attempted spans",
        )?;
        if let Some(span) = &self.last_attempt_span {
            ensure(
                span.sample_begin_us <= span.sample_end_us
                    && span.sample_end_us <= envelope
                    && self.max_attempt_span_us.is_some_and(|n| {
                        n >= span.sample_end_us - span.sample_begin_us && n <= envelope
                    }),
                "cadence attempted span bounds",
            )?;
        }
        ensure(
            self.error.is_some()
                == (self.exit_observations > 0
                    || self.query_errors > 0
                    || self.counter_regressions > 0),
            "cadence role error accounting",
        )?;
        if let Some(e) = &self.error {
            ensure(
                e.role == Some(self.role)
                    && e.text.len() <= 2048
                    && ["exit", "invalid-sample", "query"].contains(&e.kind.as_str()),
                "cadence role closed error",
            )?;
        }
        let count = self
            .successful_live_samples
            .checked_add(self.exit_observations)
            .and_then(|n| n.checked_add(self.query_errors))
            .and_then(|n| n.checked_add(self.counter_regressions))
            .ok_or("cadence attempt accounting overflow")?;
        ensure(
            self.attempts == count
                && self.successful_live_samples
                    == (self.prefix.len() as u64)
                        .checked_add(self.omitted_points)
                        .ok_or("cadence omitted overflow")?
                && self.prefix.len() as u64 == self.successful_live_samples.min(12)
                && self.forced_baseline_attempts <= 1
                && self.forced_end_attempts <= 1,
            "cadence attempt/prefix accounting",
        )?;
        if self.successful_live_samples == 0 {
            return ensure(
                self.first_sample_us.is_none()
                    && self.last.is_none()
                    && self.maxima.is_none()
                    && self.baseline.is_none()
                    && self.end.is_none()
                    && self.max_consecutive_gap_us.is_none()
                    && self.observation_max_gap_us.is_none()
                    && self.operational_max_gap_us.is_none()
                    && self.max_acquisition_span_us.is_none()
                    && self.baseline_to_end_io.is_none(),
                "cadence absent successes require nulls",
            );
        }
        let first = self.prefix.first().ok_or("cadence first missing")?;
        let last = self.last.as_ref().ok_or("cadence last missing")?;
        ensure(
            self.first_sample_us == Some(first.sample_end_us)
                && last.sample_end_us <= envelope
                && last.sample_begin_us <= last.sample_end_us,
            "cadence first/last/envelope",
        )?;
        let mut recomputed = RoleCadence::new(self.role);
        for p in &self.prefix {
            recomputed.record(p.clone(), false, false)?;
        }
        ensure(
            recomputed
                .last
                .as_ref()
                .is_some_and(|p| p.sample_end_us <= last.sample_end_us),
            "cadence last prefix order",
        )?;
        if self.omitted_points == 0 {
            ensure(self.prefix.last() == Some(last), "cadence exact last")?;
        }
        io_delta(
            &last.read.sample.logical_io,
            &recomputed
                .last
                .as_ref()
                .ok_or("cadence prefix last missing")?
                .read
                .sample
                .logical_io,
        )?;
        let max = self.maxima.as_ref().ok_or("cadence maxima missing")?;
        ensure(
            max.lifetime_peak_private_bytes == last.read.sample.lifetime_peak_private_bytes
                && max.lifetime_peak_working_set_bytes
                    == last.read.sample.lifetime_peak_working_set_bytes
                && max.private_bytes <= max.lifetime_peak_private_bytes
                && max.working_set_bytes <= max.lifetime_peak_working_set_bytes,
            "cadence lifetime maxima consistency",
        )?;
        let prefix_max = recomputed
            .maxima
            .as_ref()
            .ok_or("cadence prefix maxima missing")?;
        for sample in [prefix_max, &last.read.sample] {
            ensure(
                max.private_bytes >= sample.private_bytes
                    && max.working_set_bytes >= sample.working_set_bytes
                    && max.lifetime_peak_private_bytes >= sample.lifetime_peak_private_bytes
                    && max.lifetime_peak_working_set_bytes
                        >= sample.lifetime_peak_working_set_bytes,
                "cadence maxima below evidence",
            )?;
        }
        ensure(
            max.logical_io == last.read.sample.logical_io
                && last.read.role == self.role
                && last.read.epoch == self.epoch,
            "cadence last identity/IO",
        )?;
        let gap = self.max_consecutive_gap_us.ok_or("cadence gap missing")?;
        let span = self.max_acquisition_span_us.ok_or("cadence span missing")?;
        ensure(
            gap >= recomputed.max_consecutive_gap_us.unwrap_or(0)
                && gap <= envelope
                && span >= recomputed.max_acquisition_span_us.unwrap_or(0)
                && span >= last.sample_end_us - last.sample_begin_us
                && span <= envelope,
            "cadence online gap/span bounds",
        )?;
        let observation = first
            .sample_end_us
            .max(gap)
            .max(envelope - last.sample_end_us);
        ensure(
            self.observation_max_gap_us == Some(observation),
            "cadence observation edges",
        )?;
        if self.omitted_points == 0 {
            ensure(
                self.maxima == recomputed.maxima
                    && self.max_consecutive_gap_us == recomputed.max_consecutive_gap_us
                    && self.max_acquisition_span_us == recomputed.max_acquisition_span_us,
                "cadence exact online aggregates",
            )?;
        }
        if let Some(b) = &self.baseline {
            ensure(
                self.forced_baseline_attempts == 1
                    && b == first
                    && b.requested_slot.is_none()
                    && release.is_none_or(|r| b.sample_end_us <= r),
                "cadence baseline edge",
            )?;
        }
        if let Some(e) = &self.end {
            ensure(
                self.forced_end_attempts == 1
                    && e == last
                    && e.requested_slot.is_none()
                    && done.is_some_and(|d| e.sample_begin_us >= d),
                "cadence end edge",
            )?;
        }
        let delta = match (&self.baseline, &self.end) {
            (Some(b), Some(e)) => Some(io_delta(
                &e.read.sample.logical_io,
                &b.read.sample.logical_io,
            )?),
            _ => None,
        };
        ensure(
            self.baseline_to_end_io == delta,
            "cadence endpoint IO delta",
        )?;
        if let (Some(r), Some(d)) = (release, done) {
            let operational = self
                .operational_max_gap_us
                .ok_or("cadence operational gap missing")?;
            let mut known = first
                .sample_end_us
                .min(d)
                .saturating_sub(r)
                .max(d.saturating_sub(last.sample_end_us.max(r)));
            for points in self.prefix.windows(2) {
                known = known.max(
                    points[1]
                        .sample_end_us
                        .min(d)
                        .saturating_sub(points[0].sample_end_us.max(r)),
                );
            }
            ensure(
                operational >= known && operational <= d - r,
                "cadence operational gap bounds",
            )?;
            if self.omitted_points == 0 {
                ensure(operational == known, "cadence exact clipped gap")?;
            }
        } else {
            ensure(
                self.operational_max_gap_us.is_none() || release.is_some(),
                "cadence operational gap without Release",
            )?;
        }
        Ok(())
    }

    fn finish(&mut self, release: Option<u64>, done: Option<u64>, envelope: u64) -> Result<()> {
        if let (Some(first), Some(last)) = (self.first_sample_us, &self.last) {
            self.observation_max_gap_us = Some(
                first.max(self.max_consecutive_gap_us.unwrap_or(0)).max(
                    envelope
                        .checked_sub(last.sample_end_us)
                        .ok_or("cadence end clock")?,
                ),
            );
            if let (Some(r), Some(d)) = (release, done) {
                let first_gap = first.min(d).saturating_sub(r);
                let tail = d.saturating_sub(last.sample_end_us.max(r));
                self.operational_max_gap_us = Some(
                    first_gap
                        .max(tail)
                        .max(self.operational_max_gap_us.unwrap_or(0)),
                );
            }
        }
        if let (Some(b), Some(e)) = (&self.baseline, &self.end) {
            self.baseline_to_end_io = Some(io_delta(
                &e.read.sample.logical_io,
                &b.read.sample.logical_io,
            )?);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairCoverage {
    pub pairs: u64,
    pub supervisor_live: u64,
    pub broker_live: u64,
    pub both_live: u64,
    pub supervisor_aborted: u64,
    pub broker_aborted: u64,
}
impl PairCoverage {
    fn validate(&self) -> Result<()> {
        ensure(
            self.both_live <= self.supervisor_live
                && self.both_live <= self.broker_live
                && self
                    .supervisor_live
                    .checked_add(self.supervisor_aborted)
                    .is_some_and(|n| n <= self.pairs)
                && self
                    .broker_live
                    .checked_add(self.broker_aborted)
                    .is_some_and(|n| n <= self.pairs)
                && self
                    .supervisor_live
                    .checked_add(self.broker_live)
                    .is_some_and(|n| {
                        self.pairs
                            .checked_add(self.both_live)
                            .is_some_and(|m| n <= m)
                    }),
            "cadence coverage conservation",
        )
    }
}
// Constant-size structural authority. Raw process evidence remains bounded separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum AcquisitionClass {
    Baseline,
    Requested,
    End,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum ReadOutcome {
    Live,
    Exit,
    QueryError,
    InvalidSample,
    NotAttemptedAbort,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PairCut {
    ordinal: u64,
    class: AcquisitionClass,
    slot: Option<u64>,
    spans: [[u64; 2]; 2],
    outcomes: [ReadOutcome; 2],
    // spans delimit the sequential pair envelope; an unattempted role has
    // admission-check coordinates here, not an OS-query acquisition span.
    abort_check_span: Option<[u64; 2]>,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClockFaultCut {
    ordinal: u64,
    class: AcquisitionClass,
    slot: Option<u64>,
    spans: [[u64; 2]; 2],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum ControllerStage {
    Ready,
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
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum Publication {
    NotStarted,
    Attempted,
    Confirmed,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum PeerConsumption {
    NotObserved,
    NextReadyObserved,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum StopCause {
    AcquisitionFault,
    AdmissionStopped,
    PublicationUnknown,
    ControllerFailure,
    InvalidClock,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalCut {
    action: OperationAction,
    cause: StopCause,
    stage: ControllerStage,
    pair_count: u64,
    pending_slot: Option<u64>,
    primary: String,
}
fn required_option<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<TerminalCut>, D::Error> {
    serde::Deserialize::deserialize(d)
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkloadState {
    sealed: bool,
    primary_finalized: bool,
    post_ack_checked: bool,
    #[serde(deserialize_with = "required_action")]
    action: Option<OperationAction>,
    stage: ControllerStage,
    pairs: u64,
    classes: [u64; 3],
    last_pair: Option<PairCut>,
    clock_fault: Option<ClockFaultCut>,
    last_live: [u64; 2],
    last_attempt: [u64; 2],
    last_slot: u64,
    pending_slot: Option<u64>,
    append_verified: bool,
    receipt_validated: bool,
    command_retained: bool,
    ack: Publication,
    release: Publication,
    done_observed: bool,
    peer_consumption: PeerConsumption,
    #[serde(deserialize_with = "required_option")]
    terminal: Option<TerminalCut>,
}
impl WorkloadState {
    // A reachable intermediate prefix is not an operation completion proof.
    // Keep this authority shared by loop admission and persisted case closure.
    fn complete_confirmed(&self) -> bool {
        self.sealed
            && self.post_ack_checked
            && self.action.is_none()
            && self.stage == ControllerStage::Complete
            && self.terminal.is_none()
            && self.ack == Publication::Confirmed
            && self.release == Publication::Confirmed
            && self.done_observed
            && self.append_verified
            && self.receipt_validated
            && self.command_retained
            && self.pending_slot.is_none()
    }
    fn new() -> Self {
        Self {
            sealed: false,
            primary_finalized: false,
            post_ack_checked: false,
            action: Some(OperationAction::Phase(ControllerStage::Ready)),
            stage: ControllerStage::Ready,
            pairs: 0,
            classes: [0; 3],
            last_pair: None,
            clock_fault: None,
            last_live: [0; 2],
            last_attempt: [0; 2],
            last_slot: 0,
            pending_slot: None,
            append_verified: false,
            receipt_validated: false,
            command_retained: false,
            ack: Publication::NotStarted,
            release: Publication::NotStarted,
            done_observed: false,
            peer_consumption: PeerConsumption::NotObserved,
            terminal: None,
        }
    }
}
// Typed loop observation, never a caller-selected persisted causal label.
#[derive(Clone, Copy)]
enum FailureObservation {
    ReturnedError,
    AdmissionStopped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum OperationAction {
    Phase(ControllerStage),
    Gate(ControllerStage),
}
impl OperationAction {
    fn stage(self) -> ControllerStage {
        match self {
            Self::Phase(stage) | Self::Gate(stage) => stage,
        }
    }
}
fn required_action<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<OperationAction>, D::Error> {
    serde::Deserialize::deserialize(d)
}
fn operation_gate(c: &mut Cadence, adapter: &Adapter<'_>, deadline: Instant) -> Result<()> {
    transition(&mut c.state, Transition::BeginGate)?;
    active(adapter, deadline)?;
    transition(&mut c.state, Transition::EndGate)
}
impl WorkloadState {
    fn observed_cause(&self, observation: FailureObservation) -> Result<StopCause> {
        ensure(!self.sealed, "sealed operation has no failure authority")?;
        ensure(
            !(self.stage == ControllerStage::Ack && self.ack == Publication::Confirmed),
            "confirmed ACK action has returned; failures belong to postACK gate",
        )?;
        let action = self
            .action
            .ok_or("operation outcome without entered action")?;
        ensure(
            action.stage() == self.stage,
            "operation action stage ownership",
        )?;
        ensure(
            matches!(observation, FailureObservation::AdmissionStopped)
                == matches!(action, OperationAction::Gate(_)),
            "admission outcome requires entered gate",
        )?;
        let unknown = match self.stage {
            ControllerStage::Release => self.release == Publication::Unknown,
            ControllerStage::Ack => self.ack == Publication::Unknown,
            _ => false,
        };
        ensure(
            unknown == (self.release == Publication::Unknown || self.ack == Publication::Unknown),
            "unknown publication outside applicable phase",
        )?;
        // Publication errors return immediately: no subsequent admission can
        // replace their cause. Confirmed facts survive cancellation unchanged.
        if unknown {
            ensure(
                matches!(observation, FailureObservation::ReturnedError),
                "admission cannot follow unknown publication",
            )?;
            return Ok(StopCause::PublicationUnknown);
        }
        if matches!(observation, FailureObservation::AdmissionStopped) {
            return Ok(StopCause::AdmissionStopped);
        }
        if self.clock_fault.is_some() {
            return Ok(StopCause::InvalidClock);
        }
        if self
            .last_pair
            .as_ref()
            .is_some_and(|p| p.outcomes != [ReadOutcome::Live; 2])
        {
            return Ok(StopCause::AcquisitionFault);
        }
        ensure(
            self.stage != ControllerStage::PostAck,
            "postACK only owns an admission gate",
        )?;
        Ok(StopCause::ControllerFailure)
    }
    fn causal_boundary(&self) -> Result<()> {
        ensure(
            !self.primary_finalized || self.terminal.is_some(),
            "finalized primary missing terminal",
        )?;
        ensure(
            self.sealed == (self.stage == ControllerStage::Complete)
                && (!self.sealed || self.complete_confirmed()),
            "operation lifetime projection",
        )?;
        if let Some(stop) = &self.terminal {
            let observation = if stop.cause == StopCause::AdmissionStopped {
                FailureObservation::AdmissionStopped
            } else {
                FailureObservation::ReturnedError
            };
            ensure(
                stop.action == self.action.ok_or("terminal action missing")?
                    && stop.cause == self.observed_cause(observation)?,
                "terminal cause differs from observed outcomes",
            )?;
        } else {
            ensure(
                self.release != Publication::Unknown && self.ack != Publication::Unknown,
                "unknown publication requires operation terminal",
            )?;
        }
        Ok(())
    }
}
enum Transition {
    Seal,
    BeginGate,
    EndGate,
    AdmitPair,
    AdmitClass(AcquisitionClass, Option<u64>),
    ClockFault(ClockFaultCut),
    Reserve(u64),
    Close(PairCut),
    Stage(ControllerStage),
    AppendVerified,
    ReceiptValidated,
    CommandRetained,
    AckAttempt,
    AckOutcome(Publication),
    ReleaseAttempt,
    ReleaseOutcome(Publication),
    DoneValidated,
    PeerReady,
    Stop(String),
    PrimaryStop(String, FailureObservation),
    CausalBoundary,
}
// All operational permissions and closed-prefix projections use this reducer.
// Rejection is atomic: mutate a constant-size copy, then commit only on success.
fn transition(state: &mut WorkloadState, event: Transition) -> Result<()> {
    if let Transition::CausalBoundary = event {
        return state.causal_boundary();
    }
    ensure(
        !state.primary_finalized,
        "operation stopped; primary outcome is absorbing",
    )?;
    ensure(
        !state.sealed || matches!(event, Transition::PeerReady),
        "operation lifetime sealed",
    )?;
    if matches!(event, Transition::BeginGate | Transition::EndGate) {
        ensure(
            state.stage != ControllerStage::Complete,
            "gate outside operation lifetime",
        )?;
        if matches!(event, Transition::BeginGate) {
            ensure(
                state.action == Some(OperationAction::Phase(state.stage)),
                "gate already entered",
            )?;
            ensure(
                state.terminal.as_ref().is_none_or(|t| {
                    matches!(
                        t.cause,
                        StopCause::AcquisitionFault | StopCause::InvalidClock
                    )
                }),
                "gate after primary stop",
            )?;
            state.action = Some(OperationAction::Gate(state.stage));
        } else {
            ensure(
                state.action == Some(OperationAction::Gate(state.stage)),
                "gate outcome without entry",
            )?;
            state.action = Some(OperationAction::Phase(state.stage));
            if state.stage == ControllerStage::PostAck {
                state.post_ack_checked = true;
            }
        }
        return Ok(());
    }
    if let Transition::PrimaryStop(primary, observation) = event {
        let cause = state.observed_cause(observation)?;
        ensure(
            state.terminal.as_ref().is_none_or(|t| {
                t.primary == primary
                    || (matches!(observation, FailureObservation::AdmissionStopped)
                        && matches!(
                            t.cause,
                            StopCause::AcquisitionFault | StopCause::InvalidClock
                        ))
            }),
            "primary rewrite outside observed acquisition gate",
        )?;
        if state.terminal.is_none() {
            transition(state, Transition::Stop(primary.clone()))?;
        }
        if let Some(stop) = &mut state.terminal {
            stop.primary = primary;
            stop.cause = cause;
            stop.action = state.action.ok_or("primary outcome without action")?;
        }
        state.primary_finalized = true;
        return Ok(());
    }
    if let Transition::Stop(primary) = event {
        if state.terminal.is_none() {
            state.terminal = Some(TerminalCut {
                action: state.action.ok_or("stop without action")?,
                cause: state.observed_cause(
                    if matches!(state.action, Some(OperationAction::Gate(_))) {
                        FailureObservation::AdmissionStopped
                    } else {
                        FailureObservation::ReturnedError
                    },
                )?,
                stage: state.stage,
                pair_count: state.pairs,
                pending_slot: state.pending_slot,
                primary,
            });
        }
        return Ok(());
    }
    ensure(
        state.terminal.is_none(),
        "workload transition after terminal cut",
    )?;
    let mut next = state.clone();
    ensure(
        !matches!(state.action, Some(OperationAction::Gate(_))),
        "operational event during entered gate",
    )?;
    match event {
        Transition::Seal => {
            ensure(
                next.stage == ControllerStage::PostAck
                    && next.action == Some(OperationAction::Phase(ControllerStage::PostAck))
                    && next.post_ack_checked
                    && next.ack == Publication::Confirmed
                    && next.append_verified
                    && next.receipt_validated
                    && next.command_retained
                    && next.done_observed
                    && next.release == Publication::Confirmed
                    && next.pending_slot.is_none(),
                "operation seal prerequisites",
            )?;
            next.stage = ControllerStage::Complete;
            next.action = None;
            next.sealed = true;
        }
        Transition::AdmitPair => ensure(next.pairs < 30002, "cadence phase pair ceiling")?,
        Transition::ClockFault(cut) => {
            ensure(
                next.clock_fault.is_none() && cut.ordinal == next.pairs + 1,
                "clock fault ordinal",
            )?;
            let [[bb, be], [cb, ce]] = cut.spans;
            ensure(
                !(bb <= be
                    && be <= cb
                    && cb <= ce
                    && next.last_pair.as_ref().is_none_or(|p| p.spans[1][1] <= bb)),
                "clock diagnostic must contain actual invalid endpoints",
            )?;
            next.clock_fault = Some(cut);
            next.terminal = Some(TerminalCut {
                action: next.action.ok_or("clock fault without entered action")?,
                cause: StopCause::InvalidClock,
                stage: next.stage,
                pair_count: next.pairs,
                pending_slot: next.pending_slot,
                primary: "cadence pair clock regression".into(),
            });
        }
        Transition::AdmitClass(class, slot) => {
            ensure(
                next.pairs < 30002
                    && match class {
                        AcquisitionClass::Baseline => {
                            next.stage == ControllerStage::Baseline
                                && next.pairs == 0
                                && slot.is_none()
                        }
                        AcquisitionClass::Requested => {
                            next.stage == ControllerStage::Done
                                && !next.done_observed
                                && slot.is_some()
                                && slot == next.pending_slot
                        }
                        AcquisitionClass::End => {
                            next.stage == ControllerStage::End
                                && next.done_observed
                                && next.classes[2] == 0
                                && slot.is_none()
                                && next.pending_slot.is_none()
                        }
                    },
                "cadence acquisition phase admission",
            )?;
        }
        Transition::Reserve(slot) => {
            ensure(
                next.pending_slot.is_none() && slot > next.last_slot && next.classes[2] == 0,
                "cadence requested admission order",
            )?;
            next.pending_slot = Some(slot);
        }
        Transition::Close(cut) => {
            ensure(
                next.pairs < 30002 && cut.ordinal == next.pairs + 1,
                "cadence pair ordinal",
            )?;
            let class = match cut.class {
                AcquisitionClass::Baseline => 0,
                AcquisitionClass::Requested => 1,
                AcquisitionClass::End => 2,
            };
            ensure(
                match class {
                    0 => next.pairs == 0 && cut.slot.is_none(),
                    1 => {
                        next.classes[0] == 1
                            && next.classes[2] == 0
                            && cut.slot == next.pending_slot
                            && cut.slot.is_some()
                    }
                    _ => {
                        next.classes[0] == 1
                            && next.classes[2] == 0
                            && next.pending_slot.is_none()
                            && cut.slot.is_none()
                    }
                },
                "cadence acquisition class order",
            )?;
            ensure(
                cut.outcomes[0] != ReadOutcome::NotAttemptedAbort,
                "cadence B cannot be unattempted inside admitted pair",
            )?;
            ensure(
                cut.abort_check_span
                    == if cut.outcomes[1] == ReadOutcome::NotAttemptedAbort {
                        Some(cut.spans[1])
                    } else {
                        None
                    },
                "cadence abort check/query distinction",
            )?;
            let [[bb, be], [cb, ce]] = cut.spans;
            ensure(
                bb <= be
                    && be <= cb
                    && cb <= ce
                    && next.last_pair.as_ref().is_none_or(|p| p.spans[1][1] <= bb),
                "cadence pair clock regression",
            )?;
            next.pairs = cut.ordinal;
            next.classes[class] += 1;
            if let Some(slot) = cut.slot {
                next.last_slot = slot;
                next.pending_slot = None;
            }
            for (index, outcome) in cut.outcomes.iter().enumerate() {
                if *outcome != ReadOutcome::NotAttemptedAbort {
                    next.last_attempt[index] = cut.ordinal;
                }
                if *outcome == ReadOutcome::Live {
                    next.last_live[index] = cut.ordinal;
                }
            }
            next.last_pair = Some(cut);
        }
        Transition::Stage(stage) => {
            ensure(
                next.action == Some(OperationAction::Phase(next.stage)),
                "phase outcome with in-flight gate",
            )?;
            ensure(
                stage != ControllerStage::Complete,
                "Complete is derived only by seal",
            )?;
            let ordinal = |s: ControllerStage| s as u8;
            ensure(
                ordinal(stage) == ordinal(next.stage) + 1,
                "controller phase order",
            )?;
            ensure(
                match stage {
                    ControllerStage::Release => {
                        next.classes[0] == 1 && next.last_live == [next.pairs; 2]
                    }
                    ControllerStage::Finalize => {
                        next.classes[2] == 1 && next.last_live == [next.pairs; 2]
                    }
                    ControllerStage::Done => next.release == Publication::Confirmed,
                    ControllerStage::End => next.done_observed,
                    ControllerStage::Retention => next.receipt_validated,
                    ControllerStage::Ack => next.command_retained,
                    ControllerStage::PostAck | ControllerStage::Complete => {
                        next.ack == Publication::Confirmed
                    }
                    _ => true,
                },
                "controller phase prerequisite",
            )?;
            next.stage = stage;
            next.action = Some(OperationAction::Phase(stage));
        }
        Transition::AppendVerified => {
            ensure(
                next.stage == ControllerStage::Append && !next.append_verified,
                "append phase",
            )?;
            next.append_verified = true;
        }
        Transition::ReceiptValidated => {
            ensure(
                next.stage == ControllerStage::Receipt
                    && next.append_verified
                    && !next.receipt_validated,
                "receipt phase",
            )?;
            next.receipt_validated = true;
        }
        Transition::CommandRetained => {
            ensure(
                next.stage == ControllerStage::Retention
                    && next.receipt_validated
                    && !next.command_retained,
                "retention phase",
            )?;
            next.command_retained = true;
        }
        Transition::PeerReady => {
            ensure(
                next.complete_confirmed() && next.peer_consumption == PeerConsumption::NotObserved,
                "peer READY observation after confirmed ACK",
            )?;
            next.peer_consumption = PeerConsumption::NextReadyObserved;
        }
        Transition::ReleaseAttempt => {
            ensure(
                next.stage == ControllerStage::Release && next.release == Publication::NotStarted,
                "RELEASE admission",
            )?;
            next.release = Publication::Attempted;
        }
        Transition::ReleaseOutcome(outcome) => {
            ensure(
                next.release == Publication::Attempted
                    && matches!(outcome, Publication::Confirmed | Publication::Unknown),
                "RELEASE outcome",
            )?;
            next.release = outcome;
        }
        Transition::DoneValidated => {
            ensure(
                next.stage == ControllerStage::Done
                    && next.release == Publication::Confirmed
                    && !next.done_observed,
                "DONE validation admission",
            )?;
            next.done_observed = true;
        }
        Transition::AckAttempt => {
            ensure(
                next.stage == ControllerStage::Ack
                    && next.command_retained
                    && next.ack == Publication::NotStarted,
                "ACK admission",
            )?;
            next.ack = Publication::Attempted;
        }
        Transition::AckOutcome(outcome) => {
            ensure(
                next.ack == Publication::Attempted
                    && matches!(outcome, Publication::Confirmed | Publication::Unknown),
                "ACK outcome",
            )?;
            next.ack = outcome;
        }
        Transition::Stop(_)
        | Transition::PrimaryStop(_, _)
        | Transition::CausalBoundary
        | Transition::BeginGate
        | Transition::EndGate => {
            unreachable!()
        }
    }
    *state = next;
    Ok(())
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cadence {
    state: WorkloadState,
    pub schema: u8,
    pub case_epoch: String,
    pub operation_id: u32,
    pub cli_epoch: u64,
    pub origin_us: u64,
    pub nominal_period_us: u64,
    pub release_begin_us: Option<u64>,
    pub release_end_us: Option<u64>,
    pub done_validated_us: Option<u64>,
    pub observation_envelope_end_us: Option<u64>,
    pub accounted_slots: u64,
    pub requested_samples: u64,
    pub missed_slots: u64,
    pub pair_attempts: u64,
    pub baseline_coverage: PairCoverage,
    pub requested_coverage: PairCoverage,
    pub end_coverage: PairCoverage,
    pub unacquired_requests: u64,
    pub both_live_pairs: u64,
    pub partial_pairs: u64,
    pub max_pair_span_us: Option<u64>,
    pub last_pair_end_us: u64,
    pub supervisor: RoleCadence,
    pub broker: RoleCadence,
    pub evidence_complete: bool,
    pub cadence_target_met: bool,
    pub failure: Option<CadenceFailure>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CadenceFailure {
    pub role: Option<CadenceRole>,
    pub kind: String,
    pub os_code: Option<i32>,
    pub text: String,
}

impl CadenceFailure {
    fn new(role: Option<CadenceRole>, e: &(dyn std::error::Error + 'static)) -> Self {
        let io = e.downcast_ref::<std::io::Error>();
        let kind = if io.is_some_and(|i| i.kind() == std::io::ErrorKind::BrokenPipe) {
            "exit"
        } else if e.downcast_ref::<AbortedAcquisition>().is_some() {
            "abort"
        } else if e.to_string().contains("regression")
            || e.to_string().contains("peak")
            || e.to_string().contains("epoch")
        {
            "invalid-sample"
        } else if role.is_some() {
            "query"
        } else {
            "controller"
        };
        let text: String = e
            .to_string()
            .chars()
            .scan(0usize, |n, c| {
                // Four bounded diagnostic copies coexist with the largest raw
                // prefix. Budget encoded bytes, not just UTF-8: control bytes
                // expand sixfold in JSON. Keep the existing 32768-byte cap.
                *n += match c {
                    '"' | '\\' | '\n' | '\r' | '\t' | '\u{0008}' | '\u{000c}' => 2,
                    '\u{0000}'..='\u{001f}' => 6,
                    _ => c.len_utf8(),
                };
                (*n <= 1024).then_some(c)
            })
            .collect();
        CadenceFailure {
            role,
            kind: kind.into(),
            os_code: io.and_then(|i| i.raw_os_error()),
            text,
        }
    }
}
#[derive(Debug)]
struct AbortedAcquisition;
impl std::fmt::Display for AbortedAcquisition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cadence acquisition aborted")
    }
}
impl std::error::Error for AbortedAcquisition {}
impl Cadence {
    fn fault(&mut self, role: Option<CadenceRole>, e: &(dyn std::error::Error + 'static)) {
        if self.state.sealed {
            return;
        }
        let _ = transition(
            &mut self.state,
            Transition::Stop(CadenceFailure::new(role, e).text),
        );
        if self.failure.is_some() {
            return;
        }
        self.failure = Some(CadenceFailure::new(role, e));
        self.evidence_complete = false;
        self.cadence_target_met = false;
    }
    fn new(epoch: &str, id: u32, cli_epoch: u64) -> Self {
        Self {
            state: WorkloadState::new(),
            schema: 3,
            case_epoch: epoch.into(),
            operation_id: id,
            cli_epoch,
            origin_us: 0,
            nominal_period_us: 2000,
            release_begin_us: None,
            release_end_us: None,
            done_validated_us: None,
            observation_envelope_end_us: None,
            accounted_slots: 0,
            requested_samples: 0,
            missed_slots: 0,
            pair_attempts: 0,
            baseline_coverage: PairCoverage::default(),
            requested_coverage: PairCoverage::default(),
            end_coverage: PairCoverage::default(),
            unacquired_requests: 0,
            both_live_pairs: 0,
            partial_pairs: 0,
            max_pair_span_us: None,
            last_pair_end_us: 0,
            supervisor: RoleCadence::new(CadenceRole::SupervisorB),
            broker: RoleCadence::new(CadenceRole::BrokerC),
            evidence_complete: false,
            cadence_target_met: false,
            failure: None,
        }
    }
    fn sync_release(&mut self) -> Result<()> {
        if self.state.stage == ControllerStage::Baseline && self.release_end_us.is_some() {
            ensure(
                self.release_begin_us.is_some(),
                "cadence RELEASE begin missing",
            )?;
            transition(&mut self.state, Transition::Stage(ControllerStage::Release))?;
            transition(&mut self.state, Transition::ReleaseAttempt)?;
            transition(
                &mut self.state,
                Transition::ReleaseOutcome(Publication::Confirmed),
            )?;
            transition(&mut self.state, Transition::Stage(ControllerStage::Done))?;
        }
        Ok(())
    }
    fn due(&mut self, now: u64) -> Result<Option<u64>> {
        transition(&mut self.state, Transition::AdmitPair)?;
        self.sync_release()?;
        let start = self.release_begin_us.ok_or("cadence release missing")?;
        let slot = now.checked_sub(start).ok_or("cadence clock regression")? / 2000;
        if slot <= self.accounted_slots {
            return Ok(None);
        }
        transition(&mut self.state, Transition::Reserve(slot))?;
        add(&mut self.missed_slots, slot - self.accounted_slots - 1)?;
        add(&mut self.requested_samples, 1)?;
        self.accounted_slots = slot;
        Ok(Some(slot))
    }
    fn record_pair(
        &mut self,
        slot: Option<u64>,
        baseline: bool,
        end: bool,
        reads: [(u64, u64, Result<RetainedRead>); 2],
    ) -> Result<()> {
        transition(&mut self.state, Transition::AdmitPair)?;
        if baseline && self.state.stage == ControllerStage::Ready {
            transition(
                &mut self.state,
                Transition::Stage(ControllerStage::Preparation),
            )?;
        }
        if baseline && self.state.stage == ControllerStage::Preparation {
            transition(
                &mut self.state,
                Transition::Stage(ControllerStage::Baseline),
            )?;
        }
        if !baseline && self.state.stage == ControllerStage::Baseline {
            ensure(self.release_end_us.is_some(), "cadence pair before RELEASE")?;
            transition(&mut self.state, Transition::Stage(ControllerStage::Release))?;
            transition(&mut self.state, Transition::ReleaseAttempt)?;
            transition(
                &mut self.state,
                Transition::ReleaseOutcome(Publication::Confirmed),
            )?;
            transition(&mut self.state, Transition::Stage(ControllerStage::Done))?;
        }
        if end && self.state.stage == ControllerStage::Done {
            ensure(self.done_validated_us.is_some(), "cadence end before DONE")?;
            transition(&mut self.state, Transition::DoneValidated)?;
            transition(&mut self.state, Transition::Stage(ControllerStage::End))?;
        }
        ensure(
            self.state.stage
                == if baseline {
                    ControllerStage::Baseline
                } else if end {
                    ControllerStage::End
                } else {
                    ControllerStage::Done
                },
            "cadence acquisition phase",
        )?;
        let [(bb, be, b), (cb, ce, c)] = reads;
        let class = if baseline {
            AcquisitionClass::Baseline
        } else if end {
            AcquisitionClass::End
        } else {
            AcquisitionClass::Requested
        };
        transition(&mut self.state, Transition::AdmitClass(class, slot))?;
        ensure(
            !b.as_ref()
                .is_err_and(|e| e.downcast_ref::<AbortedAcquisition>().is_some()),
            "cadence B unattempted is unreachable",
        )?;
        let mut permission = self.state.clone();
        let permission_result = transition(
            &mut permission,
            Transition::Close(PairCut {
                ordinal: self.state.pairs + 1,
                class,
                slot,
                spans: [[bb, be], [cb, ce]],
                outcomes: [ReadOutcome::Live; 2],
                abort_check_span: None,
            }),
        );
        if let Err(error) = permission_result {
            transition(
                &mut self.state,
                Transition::ClockFault(ClockFaultCut {
                    ordinal: self.pair_attempts + 1,
                    class,
                    slot,
                    spans: [[bb, be], [cb, ce]],
                }),
            )?;
            self.fault(None, &*error);
            if slot.is_some() {
                add(&mut self.unacquired_requests, 1)?;
            }
            return Err(error);
        }
        ensure(self.pair_attempts < 30002, "cadence phase pair ceiling")?;
        ensure(
            bb >= self.last_pair_end_us && bb <= be && be <= cb && cb <= ce,
            "cadence pair clock regression",
        )?;
        add(&mut self.pair_attempts, 1)?;
        let coverage = if baseline {
            &mut self.baseline_coverage
        } else if end {
            &mut self.end_coverage
        } else {
            &mut self.requested_coverage
        };
        add(&mut coverage.pairs, 1)?;
        let previous_b = self.supervisor.last.as_ref().map(|p| p.sample_end_us);
        let previous_c = self.broker.last.as_ref().map(|p| p.sample_end_us);
        let br = self
            .supervisor
            .acquire((bb, be), slot, baseline, end, self.pair_attempts, b);
        let cr = self
            .broker
            .acquire((cb, ce), slot, baseline, end, self.pair_attempts, c);
        if let Some(r) = self.release_begin_us {
            let d = self.done_validated_us.unwrap_or(ce);
            for (role, previous, t, ok) in [
                (&mut self.supervisor, previous_b, be, br.is_ok()),
                (&mut self.broker, previous_c, ce, cr.is_ok()),
            ] {
                if ok {
                    let gap = t.min(d).saturating_sub(previous.unwrap_or(0).max(r));
                    role.operational_max_gap_us =
                        Some(role.operational_max_gap_us.unwrap_or(0).max(gap));
                }
            }
        }
        add(&mut coverage.supervisor_live, u64::from(br.is_ok()))?;
        add(&mut coverage.broker_live, u64::from(cr.is_ok()))?;
        add(&mut coverage.both_live, u64::from(br.is_ok() && cr.is_ok()))?;
        add(
            &mut coverage.supervisor_aborted,
            u64::from(
                br.as_ref()
                    .is_err_and(|e| e.downcast_ref::<AbortedAcquisition>().is_some()),
            ),
        )?;
        add(
            &mut coverage.broker_aborted,
            u64::from(
                cr.as_ref()
                    .is_err_and(|e| e.downcast_ref::<AbortedAcquisition>().is_some()),
            ),
        )?;
        if br.is_ok() && cr.is_ok() {
            add(&mut self.both_live_pairs, 1)?;
        } else {
            add(&mut self.partial_pairs, 1)?;
        }
        self.max_pair_span_us = Some(self.max_pair_span_us.unwrap_or(0).max(ce - bb));
        self.last_pair_end_us = ce;
        let classify = |r: &Result<()>, role: &RoleCadence| {
            if r.is_ok() {
                ReadOutcome::Live
            } else if r
                .as_ref()
                .is_err_and(|e| e.downcast_ref::<AbortedAcquisition>().is_some())
            {
                ReadOutcome::NotAttemptedAbort
            } else if role.exit_observations > 0 {
                ReadOutcome::Exit
            } else if role.counter_regressions > 0
                || role
                    .error
                    .as_ref()
                    .is_some_and(|e| e.kind == "invalid-sample")
            {
                ReadOutcome::InvalidSample
            } else {
                ReadOutcome::QueryError
            }
        };
        transition(
            &mut self.state,
            Transition::Close(PairCut {
                ordinal: self.pair_attempts,
                class: if baseline {
                    AcquisitionClass::Baseline
                } else if end {
                    AcquisitionClass::End
                } else {
                    AcquisitionClass::Requested
                },
                slot,
                spans: [[bb, be], [cb, ce]],
                outcomes: [classify(&br, &self.supervisor), classify(&cr, &self.broker)],
                abort_check_span: if cr
                    .as_ref()
                    .is_err_and(|e| e.downcast_ref::<AbortedAcquisition>().is_some())
                {
                    Some([cb, ce])
                } else {
                    None
                },
            }),
        )?;
        for (role, result) in [(CadenceRole::SupervisorB, br), (CadenceRole::BrokerC, cr)] {
            if let Err(e) = result {
                self.fault(Some(role), &*e);
                return Err(e);
            }
        }
        Ok(())
    }
    fn finish(&mut self, now: u64) -> Result<()> {
        if self.state.terminal.is_none() && self.state.stage == ControllerStage::End {
            transition(
                &mut self.state,
                Transition::Stage(ControllerStage::Finalize),
            )?;
        }
        self.observation_envelope_end_us = Some(now);
        if let (Some(r), Some(d)) = (self.release_begin_us, self.done_validated_us) {
            let slots = d.checked_sub(r).ok_or("cadence done clock")? / 2000;
            add(
                &mut self.missed_slots,
                slots
                    .checked_sub(self.accounted_slots)
                    .ok_or("cadence slot clock")?,
            )?;
            self.accounted_slots = slots;
        }
        self.supervisor
            .finish(self.release_begin_us, self.done_validated_us, now)?;
        self.broker
            .finish(self.release_begin_us, self.done_validated_us, now)?;
        self.evidence_complete = self.failure.is_none()
            && self.release_end_us.is_some()
            && self.done_validated_us.is_some()
            && self.supervisor.baseline.is_some()
            && self.supervisor.end.is_some()
            && self.broker.baseline.is_some()
            && self.broker.end.is_some();
        self.cadence_target_met = self.evidence_complete
            && self.missed_slots == 0
            && self
                .supervisor
                .operational_max_gap_us
                .is_some_and(|n| n <= 2000)
            && self
                .broker
                .operational_max_gap_us
                .is_some_and(|n| n <= 2000);
        Ok(())
    }
    fn validate_state(&self) -> Result<()> {
        let state = &self.state;
        // Same causal transition as the actual loop; no scalar acceptance patch.
        transition(&mut state.clone(), Transition::CausalBoundary)?;
        ensure(
            state.pairs == self.pair_attempts
                && state.classes
                    == [
                        self.baseline_coverage.pairs,
                        self.requested_coverage.pairs,
                        self.end_coverage.pairs,
                    ]
                && state.terminal.is_some() == self.failure.is_some(),
            "cadence structural authority",
        )?;
        ensure(state.pairs <= 30002, "cadence replay bound")?;
        ensure(
            (state.pairs == 0 || state.stage as u8 >= ControllerStage::Baseline as u8)
                && (state.classes[1] == 0 || state.stage as u8 >= ControllerStage::Done as u8)
                && (state.classes[2] == 0 || state.stage as u8 >= ControllerStage::End as u8)
                && state.done_observed == self.done_validated_us.is_some()
                && (state.release == Publication::Confirmed) == self.release_end_us.is_some(),
            "cadence phase/acquisition frontier",
        )?;
        let mut replay = WorkloadState::new();
        for ordinal in 1..=state.pairs {
            let class = if ordinal == 1 {
                AcquisitionClass::Baseline
            } else if ordinal <= 1 + state.classes[1] {
                AcquisitionClass::Requested
            } else {
                AcquisitionClass::End
            };
            let cut = if ordinal == state.pairs {
                state
                    .last_pair
                    .clone()
                    .ok_or("cadence closed pair missing")?
            } else {
                PairCut {
                    ordinal,
                    class,
                    slot: if class == AcquisitionClass::Requested {
                        Some(ordinal - 1)
                    } else {
                        None
                    },
                    spans: [[0, 0]; 2],
                    outcomes: [ReadOutcome::Live; 2],
                    abort_check_span: None,
                }
            };
            ensure(cut.class == class, "cadence last class frontier")?;
            if let Some(slot) = cut.slot {
                transition(&mut replay, Transition::Reserve(slot))?;
            }
            transition(&mut replay, Transition::AdmitPair)?;
            transition(&mut replay, Transition::Close(cut))?;
        }
        ensure(
            replay.classes == state.classes
                && replay.last_live == state.last_live
                && replay.last_attempt == state.last_attempt,
            "cadence role ordinal frontiers",
        )?;
        ensure(
            state.last_pair.is_some() == (state.pairs > 0),
            "cadence last pair presence",
        )?;
        if let Some(cut) = &state.last_pair {
            ensure(
                cut.ordinal == state.pairs && cut.spans[1][1] == self.last_pair_end_us,
                "cadence last pair envelope frontier",
            )?;
            let partial = cut.outcomes != [ReadOutcome::Live; 2];
            ensure(
                self.partial_pairs == u64::from(partial) && (!partial || state.terminal.is_some()),
                "cadence terminal acquisition cut",
            )?;
            if cut.class == AcquisitionClass::Requested
                && self.unacquired_requests == 0
                && self.done_validated_us.is_none()
            {
                ensure(
                    cut.slot == Some(self.accounted_slots),
                    "cadence terminal requested reservation",
                )?;
            }
            for (index, role) in [&self.supervisor, &self.broker].iter().enumerate() {
                ensure(
                    role.last.as_ref().map_or(0, |p| p.ordinal) == state.last_live[index],
                    "cadence last success at/after terminal ordinal",
                )?;
                let expected_live =
                    state.pairs - u64::from(cut.outcomes[index] != ReadOutcome::Live);
                ensure(
                    role.successful_live_samples == expected_live,
                    "cadence closed live prefix",
                )?;
                for (position, point) in role.prefix.iter().enumerate() {
                    ensure(
                        point.ordinal == position as u64 + 1,
                        "cadence retained ordinal prefix",
                    )?;
                }
                for point in role
                    .prefix
                    .iter()
                    .chain(role.last.iter())
                    .chain(role.baseline.iter())
                    .chain(role.end.iter())
                {
                    ensure(
                        point.ordinal > 0
                            && point.ordinal <= state.last_live[index]
                            && match point.class {
                                AcquisitionClass::Baseline => {
                                    point.ordinal == 1 && point.requested_slot.is_none()
                                }
                                AcquisitionClass::Requested => {
                                    point.ordinal > 1
                                        && point.ordinal <= 1 + state.classes[1]
                                        && point.requested_slot.is_some()
                                }
                                AcquisitionClass::End => {
                                    point.ordinal == state.pairs
                                        && state.classes[2] == 1
                                        && point.requested_slot.is_none()
                                }
                            },
                        "cadence point class/ordinal frontier",
                    )?;
                }
                if cut.outcomes[index] == ReadOutcome::Live {
                    let point = role
                        .last
                        .as_ref()
                        .ok_or("cadence live terminal point missing")?;
                    ensure(
                        point.ordinal == cut.ordinal
                            && point.class == cut.class
                            && point.requested_slot == cut.slot
                            && [point.sample_begin_us, point.sample_end_us] == cut.spans[index],
                        "cadence last live pair binding",
                    )?;
                } else {
                    ensure(
                        role.last.as_ref().is_none_or(|p| p.ordinal < cut.ordinal),
                        "cadence success following terminal fault",
                    )?;
                    if cut.outcomes[index] != ReadOutcome::NotAttemptedAbort {
                        let span = role
                            .last_attempt_span
                            .as_ref()
                            .ok_or("cadence failed attempt missing")?;
                        ensure(
                            [span.sample_begin_us, span.sample_end_us] == cut.spans[index],
                            "cadence terminal attempted span",
                        )?;
                    }
                }
                ensure(
                    match cut.outcomes[index] {
                        ReadOutcome::Live | ReadOutcome::NotAttemptedAbort => {
                            role.error.is_none()
                                && role.query_errors == 0
                                && role.counter_regressions == 0
                        }
                        ReadOutcome::Exit => {
                            role.error.as_ref().is_some_and(|e| e.kind == "exit")
                                && role.query_errors == 0
                                && role.counter_regressions == 0
                        }
                        ReadOutcome::QueryError => {
                            role.error.is_some()
                                && role.query_errors == 1
                                && role.counter_regressions == 0
                        }
                        ReadOutcome::InvalidSample => {
                            role.error
                                .as_ref()
                                .is_some_and(|e| e.kind == "invalid-sample")
                                && role.query_errors.checked_add(role.counter_regressions)
                                    == Some(1)
                        }
                    },
                    "cadence outcome/diagnostic counter binding",
                )?;
                ensure(
                    role.not_attempted_due_to_abort
                        == u64::from(cut.outcomes[index] == ReadOutcome::NotAttemptedAbort)
                        && role.exit_observations
                            == u64::from(cut.outcomes[index] == ReadOutcome::Exit),
                    "cadence terminal outcome counters",
                )?;
            }
        }
        if let Some(cut) = &state.clock_fault {
            transition(&mut replay, Transition::AdmitPair)?;
            transition(&mut replay, Transition::ClockFault(cut.clone()))?;
            ensure(
                state.terminal.as_ref().is_some_and(|s| {
                    matches!(
                        s.cause,
                        StopCause::InvalidClock | StopCause::AdmissionStopped
                    )
                }) && cut.slot == state.pending_slot,
                "raw clock terminal binding",
            )?;
        }
        // Replay phase permissions using only confirmed structural boundaries;
        // this is the same reducer, not a second boolean acceptance oracle.
        let mut phases = WorkloadState::new();
        let stages = [
            ControllerStage::Preparation,
            ControllerStage::Baseline,
            ControllerStage::Release,
            ControllerStage::Done,
            ControllerStage::End,
            ControllerStage::Finalize,
            ControllerStage::Append,
            ControllerStage::Receipt,
            ControllerStage::Retention,
            ControllerStage::Ack,
            ControllerStage::PostAck,
            ControllerStage::Complete,
        ];
        for stage in stages {
            if stage as u8 > state.stage as u8 {
                break;
            }
            match stage {
                ControllerStage::Release => {
                    ensure(
                        self.baseline_coverage.both_live == 1
                            && (state.release == Publication::NotStarted
                                || self.release_begin_us.is_some()),
                        "phase RELEASE evidence",
                    )?;
                    transition(
                        &mut phases,
                        Transition::Close(PairCut {
                            ordinal: 1,
                            class: AcquisitionClass::Baseline,
                            slot: None,
                            spans: [[0, 0]; 2],
                            outcomes: [ReadOutcome::Live; 2],
                            abort_check_span: None,
                        }),
                    )?;
                }
                ControllerStage::Done => ensure(
                    self.release_end_us.is_some(),
                    "phase confirmed RELEASE missing",
                )?,
                ControllerStage::End => ensure(
                    self.done_validated_us.is_some(),
                    "phase validated DONE missing",
                )?,
                ControllerStage::Finalize => {
                    ensure(
                        self.end_coverage.both_live == 1,
                        "phase completed endpoint missing",
                    )?;
                    transition(
                        &mut phases,
                        Transition::Close(PairCut {
                            ordinal: 2,
                            class: AcquisitionClass::End,
                            slot: None,
                            spans: [[0, 0]; 2],
                            outcomes: [ReadOutcome::Live; 2],
                            abort_check_span: None,
                        }),
                    )?;
                }
                _ => {}
            }
            transition(
                &mut phases,
                if stage == ControllerStage::Complete {
                    Transition::Seal
                } else {
                    Transition::Stage(stage)
                },
            )?;
            match stage {
                ControllerStage::Release if state.release != Publication::NotStarted => {
                    transition(&mut phases, Transition::ReleaseAttempt)?;
                    if state.release != Publication::Attempted {
                        transition(&mut phases, Transition::ReleaseOutcome(state.release))?;
                    }
                }
                ControllerStage::Done if state.done_observed => {
                    transition(&mut phases, Transition::DoneValidated)?
                }
                ControllerStage::Append if state.append_verified => {
                    transition(&mut phases, Transition::AppendVerified)?
                }
                ControllerStage::Receipt if state.receipt_validated => {
                    transition(&mut phases, Transition::ReceiptValidated)?
                }
                ControllerStage::Retention if state.command_retained => {
                    transition(&mut phases, Transition::CommandRetained)?
                }
                ControllerStage::Ack if state.ack != Publication::NotStarted => {
                    transition(&mut phases, Transition::AckAttempt)?;
                    if state.ack != Publication::Attempted {
                        transition(&mut phases, Transition::AckOutcome(state.ack))?;
                    }
                }
                ControllerStage::PostAck if state.post_ack_checked => {
                    transition(&mut phases, Transition::BeginGate)?;
                    transition(&mut phases, Transition::EndGate)?;
                }
                _ => {}
            }
        }
        if state.peer_consumption == PeerConsumption::NextReadyObserved {
            transition(&mut phases, Transition::PeerReady)?;
        }
        ensure(
            phases.stage == state.stage
                && phases.append_verified == state.append_verified
                && phases.receipt_validated == state.receipt_validated
                && phases.command_retained == state.command_retained
                && phases.ack == state.ack
                && phases.release == state.release
                && phases.done_observed == state.done_observed
                && phases.peer_consumption == state.peer_consumption
                && phases.sealed == state.sealed
                && phases.post_ack_checked == state.post_ack_checked,
            "cadence phase projection differs from reducer",
        )?;
        if let Some(stop) = &state.terminal {
            if matches!(stop.action, OperationAction::Gate(_)) {
                transition(&mut phases, Transition::BeginGate)?;
            }
            transition(&mut phases, Transition::Stop(stop.primary.clone()))?;
            ensure(
                stop.action == state.action.ok_or("closed terminal action missing")?
                    && stop.action.stage() == state.stage
                    && stop.stage == state.stage
                    && stop.pair_count == state.pairs
                    && stop.pending_slot == state.pending_slot
                    && !stop.primary.is_empty()
                    && stop.primary.len() <= 2048,
                "cadence closed terminal phase",
            )?;
        }
        ensure(
            state.pending_slot.is_some() == (self.unacquired_requests == 1)
                && state
                    .pending_slot
                    .is_none_or(|slot| slot == self.accounted_slots && slot > state.last_slot),
            "cadence pending reservation frontier",
        )?;
        ensure(
            state.action
                == if state.sealed {
                    None
                } else {
                    Some(
                        state
                            .terminal
                            .as_ref()
                            .map_or(OperationAction::Phase(state.stage), |t| t.action),
                    )
                },
            "operation entered action frontier",
        )?;
        Ok(())
    }
    fn validate(&self, epoch: &str, id: u32, cli_epoch: u64) -> Result<()> {
        self.validate_state()?;
        ensure(
            self.schema == 3
                && self.case_epoch == epoch
                && self.operation_id == id
                && self.cli_epoch == cli_epoch
                && self.origin_us == 0
                && self.nominal_period_us == 2000,
            "cadence correlation",
        )?;
        ensure(
            self.supervisor.role == CadenceRole::SupervisorB
                && self.broker.role == CadenceRole::BrokerC,
            "cadence roles",
        )?;
        let envelope = self
            .observation_envelope_end_us
            .ok_or("cadence envelope missing")?;
        ensure(
            self.max_pair_span_us.is_some() == (self.pair_attempts > 0),
            "cadence pair span presence",
        )?;
        if let Some(max) = self.max_pair_span_us {
            ensure(
                max <= envelope
                    && max >= self.supervisor.max_attempt_span_us.unwrap_or(0)
                    && max >= self.broker.max_attempt_span_us.unwrap_or(0),
                "cadence pair acquisition span",
            )?;
            for (b, c) in self
                .supervisor
                .prefix
                .iter()
                .zip(&self.broker.prefix)
                .chain(self.supervisor.end.iter().zip(self.broker.end.iter()))
            {
                ensure(
                    b.sample_end_us <= c.sample_begin_us
                        && max
                            >= c.sample_end_us
                                .checked_sub(b.sample_begin_us)
                                .ok_or("cadence sequential pair clock")?
                        && b.requested_slot == c.requested_slot,
                    "cadence pair skew/slot",
                )?;
            }
        }
        if let Some(end) = self.release_end_us {
            ensure(
                self.release_begin_us.is_some_and(|r| r <= end) && end <= envelope,
                "cadence Release span",
            )?;
        }
        if let Some(done) = self.done_validated_us {
            ensure(
                self.release_end_us.is_some_and(|r| r <= done) && done <= envelope,
                "cadence Done span",
            )?;
        }
        ensure(
            self.last_pair_end_us <= envelope
                && self.pair_attempts <= 30002
                && self.pair_attempts
                    == self
                        .both_live_pairs
                        .checked_add(self.partial_pairs)
                        .ok_or("cadence pairs overflow")?,
            "cadence pair accounting",
        )?;
        if let Some(release) = self.release_begin_us {
            ensure(
                self.accounted_slots
                    <= envelope
                        .checked_sub(release)
                        .ok_or("cadence Release envelope")?
                        / 2000,
                "cadence partial slot envelope",
            )?;
        }
        let classes = [
            &self.baseline_coverage,
            &self.requested_coverage,
            &self.end_coverage,
        ];
        for class in classes {
            class.validate()?;
        }
        let sum = |values: [u64; 3]| -> Result<u64> {
            values.into_iter().try_fold(0u64, |n, v| {
                n.checked_add(v)
                    .ok_or_else(|| "cadence coverage overflow".into())
            })
        };
        ensure(
            self.baseline_coverage.pairs <= 1
                && self.end_coverage.pairs <= 1
                && self.baseline_coverage.pairs == u64::from(self.pair_attempts > 0)
                && self.pair_attempts == sum(classes.map(|c| c.pairs))?
                && self.both_live_pairs == sum(classes.map(|c| c.both_live))?
                && self.requested_samples
                    == self
                        .requested_coverage
                        .pairs
                        .checked_add(self.unacquired_requests)
                        .ok_or("cadence request overflow")?
                && self.unacquired_requests <= 1
                && (self.unacquired_requests == 0
                    || (self.failure.is_some() && self.done_validated_us.is_none()))
                && (self.end_coverage.pairs == 0 || self.done_validated_us.is_some())
                && (self.release_begin_us.is_none() || self.baseline_coverage.both_live == 1)
                && (self.requested_samples == 0 || self.release_end_us.is_some()),
            "cadence acquisition class accounting",
        )?;
        for (role, supervisor) in [(&self.supervisor, true), (&self.broker, false)] {
            let live = |c: &PairCoverage| {
                if supervisor {
                    c.supervisor_live
                } else {
                    c.broker_live
                }
            };
            let aborted = |c: &PairCoverage| {
                if supervisor {
                    c.supervisor_aborted
                } else {
                    c.broker_aborted
                }
            };
            ensure(
                role.successful_live_samples == sum(classes.map(live))?
                    && role.not_attempted_due_to_abort == sum(classes.map(aborted))?
                    && role.forced_baseline_attempts
                        == self.baseline_coverage.pairs - aborted(&self.baseline_coverage)
                    && role.forced_end_attempts
                        == self.end_coverage.pairs - aborted(&self.end_coverage)
                    && u64::from(role.baseline.is_some()) == live(&self.baseline_coverage)
                    && u64::from(role.end.is_some()) == live(&self.end_coverage),
                "cadence role class coverage",
            )?;
            let mut retained_requested = 0u64;
            let mut previous = 0u64;
            for point in role
                .prefix
                .iter()
                .chain(role.last.iter().filter(|p| role.prefix.last() != Some(*p)))
            {
                match point.requested_slot {
                    Some(slot) => {
                        ensure(slot > previous, "cadence strict requested slots")?;
                        previous = slot;
                        add(&mut retained_requested, 1)?;
                    }
                    None => ensure(
                        role.baseline.as_ref() == Some(point) || role.end.as_ref() == Some(point),
                        "cadence unclassified retained sample",
                    )?,
                }
            }
            ensure(
                retained_requested <= live(&self.requested_coverage)
                    && (role.omitted_points > 0
                        || retained_requested == live(&self.requested_coverage)),
                "cadence retained requested coverage",
            )?;
            ensure(
                (role.error.is_none() && role.not_attempted_due_to_abort == 0)
                    || (self.failure.is_some() && self.partial_pairs > 0),
                "cadence hidden role failure/abort",
            )?;
        }
        for role in [&self.supervisor, &self.broker] {
            role.validate(self.release_begin_us, self.done_validated_us, envelope)?;
            let mut previous_slot = 0;
            for point in role.prefix.iter().chain(role.last.iter()) {
                if let Some(slot) = point.requested_slot {
                    let release = self
                        .release_begin_us
                        .ok_or("cadence requested slot without Release")?;
                    let latest = point
                        .sample_begin_us
                        .checked_sub(release)
                        .ok_or("cadence slot acquisition clock")?
                        / 2000;
                    ensure(
                        slot > 0
                            && slot <= self.accounted_slots
                            && slot <= latest
                            && slot >= previous_slot,
                        "cadence requested slot timing/order",
                    )?;
                    previous_slot = slot;
                }
            }
            ensure(
                role.attempts.checked_add(role.not_attempted_due_to_abort)
                    == Some(self.pair_attempts),
                "cadence role pair accounting",
            )?;
        }
        if let Some(end) = self.release_end_us {
            ensure(
                self.release_begin_us.is_some_and(|r| r <= end) && end <= envelope,
                "cadence Release span",
            )?;
        }
        if let Some(done) = self.done_validated_us {
            ensure(
                self.release_end_us.is_some_and(|r| r <= done) && done <= envelope,
                "cadence Done span",
            )?;
        }
        if let (Some(r), Some(d)) = (self.release_begin_us, self.done_validated_us) {
            ensure(
                self.accounted_slots == (d - r) / 2000,
                "cadence final slot count",
            )?;
        }
        ensure(
            self.requested_samples.checked_add(self.missed_slots) == Some(self.accounted_slots),
            "cadence missed slot accounting",
        )?;
        // A shared-loop acquisition error closes the current pair and interval.
        // Successful reads of the other role in that same pair are retained,
        // but no later acquisition class may follow the failed class.
        ensure(self.partial_pairs <= 1, "cadence first-fault pair closure")?;
        if self.partial_pairs == 1 {
            let failed = classes
                .iter()
                .position(|c| c.both_live != c.pairs)
                .ok_or("cadence terminal acquisition class missing")?;
            for (index, class) in classes.iter().enumerate() {
                ensure(
                    if index < failed {
                        class.both_live == class.pairs
                    } else if index == failed {
                        class.pairs == class.both_live + 1
                    } else {
                        class.pairs == 0
                    },
                    "cadence post-fault acquisition class",
                )?;
            }
            ensure(
                match failed {
                    0 => {
                        self.release_begin_us.is_none()
                            && self.requested_samples == 0
                            && self.done_validated_us.is_none()
                    }
                    1 => self.done_validated_us.is_none(),
                    _ => self.done_validated_us.is_some(),
                },
                "cadence post-fault phase",
            )?;
            let first_failed = [&self.supervisor, &self.broker]
                .into_iter()
                .find(|r| r.error.is_some() || r.not_attempted_due_to_abort > 0)
                .ok_or("cadence terminal role missing")?;
            let failure = self
                .failure
                .as_ref()
                .ok_or("cadence terminal fault missing")?;
            ensure(
                failure.role == Some(first_failed.role)
                    && if let Some(error) = &first_failed.error {
                        failure.kind == error.kind
                            && failure.text == error.text
                            && failure.os_code == error.os_code
                    } else {
                        failure.kind == "abort"
                    },
                "cadence primary terminal role correlation",
            )?;
        }
        for role in [&self.supervisor, &self.broker] {
            let errors = role
                .exit_observations
                .checked_add(role.query_errors)
                .and_then(|n| n.checked_add(role.counter_regressions))
                .and_then(|n| n.checked_add(role.not_attempted_due_to_abort))
                .ok_or("cadence terminal role overflow")?;
            ensure(errors <= 1, "cadence role retried after terminal error")?;
            if role.error.is_some() {
                let span = role
                    .last_attempt_span
                    .as_ref()
                    .ok_or("cadence error span missing")?;
                ensure(
                    role.last
                        .as_ref()
                        .is_none_or(|p| p.sample_end_us <= span.sample_begin_us),
                    "cadence successful sample after terminal error",
                )?;
            }
        }
        let complete = self.failure.is_none()
            && self.release_end_us.is_some()
            && self.done_validated_us.is_some()
            && self.supervisor.baseline.is_some()
            && self.supervisor.end.is_some()
            && self.broker.baseline.is_some()
            && self.broker.end.is_some()
            && self.partial_pairs == 0;
        ensure(
            self.evidence_complete == complete,
            "cadence false completeness",
        )?;
        let target = complete
            && self.missed_slots == 0
            && self
                .supervisor
                .operational_max_gap_us
                .is_some_and(|n| n <= 2000)
            && self
                .broker
                .operational_max_gap_us
                .is_some_and(|n| n <= 2000);
        ensure(
            self.cadence_target_met == target,
            "cadence target diagnostic",
        )?;
        if let Some(f) = &self.failure {
            ensure(
                f.text.len() <= 2048
                    && ["exit", "abort", "invalid-sample", "query", "controller"]
                        .contains(&f.kind.as_str()),
                "cadence closed fault",
            )?;
        }
        ensure(
            serde_json::to_vec(self)?.len() <= 32768,
            "cadence per interval serialized cap",
        )
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub broker_epoch: u64,
    pub supervisor_epoch: u64,
    pub cli_epoch: u64,
    pub broker: ProcessEvidence,
    pub supervisor: ProcessEvidence,
    pub broker_logical_io_delta: Option<crate::measure::LogicalIo>,
    pub supervisor_logical_io_delta: Option<crate::measure::LogicalIo>,
    pub handshake_span_us: Option<u64>,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundaryEvidence {
    pub operation_id: u32,
    pub cli_epoch: u64,
    pub descriptor: Descriptor,
    pub before_release: Option<Observation>,
    pub after_done: Option<Observation>,
    pub receipt_validated: bool,
    pub exact_append_verified: bool,
    pub cadence: Cadence,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileDigest {
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceOracle {
    pub source_unchanged: bool,
    pub archive_sha256: String,
    pub logical_sha256: String,
    pub records: u64,
    pub source_inventory: std::collections::BTreeMap<String, FileDigest>,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportOracle {
    pub persisted_startup_receipt: hermes_memory::logical_migration::MigrationReceipt,
    pub final_read_only_export: hermes_memory::logical_migration::MigrationReceipt,
    pub expected_final_logical_sha256: String,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionOracle {
    pub records: u64,
    pub bytes: u64,
    pub exact_records_including_metadata_verified: bool,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportFile {
    pub path: std::path::PathBuf,
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportOracle {
    pub records: u64,
    pub sessions: u64,
    pub files: Vec<ExportFile>,
    pub exact_payloads_verified: bool,
    pub snapshot_payload_verified: bool,
    pub index_sha256: String,
}

// Case finalization has separate mutation authority from sealed operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CaseAction {
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
}
impl CaseAction {
    fn cleanup(self) -> bool {
        matches!(
            self,
            Self::StopClient | Self::StopBroker | Self::WaitBrokerExit
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseActionRecord {
    action: CaseAction,
    error: Option<String>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseActions {
    operation_failure: Option<String>,
    records: Vec<CaseActionRecord>,
    entered: Option<CaseAction>,
}
enum CaseTransition {
    OperationFailed(String),
    Enter(CaseAction),
    Outcome(CaseAction, Option<String>),
}
fn case_transition(state: &mut CaseActions, event: CaseTransition) -> Result<()> {
    let mut next = state.clone();
    match event {
        CaseTransition::OperationFailed(primary) => {
            ensure(
                next.records.is_empty()
                    && next.entered.is_none()
                    && next.operation_failure.is_none()
                    && !primary.is_empty()
                    && primary.len() <= 2048,
                "case operation outcome ownership",
            )?;
            next.operation_failure = Some(primary);
        }
        CaseTransition::Enter(action) => {
            ensure(
                next.entered.is_none() && next.records.len() < 14,
                "case action already entered or ceiling",
            )?;
            let previous = next.records.last().map(|r| r.action);
            let failed =
                next.operation_failure.is_some() || next.records.iter().any(|r| r.error.is_some());
            ensure(
                !failed || action.cleanup(),
                "case action after primary failure",
            )?;
            ensure(
                if action.cleanup() {
                    previous.is_none_or(|p| (action as u8) > p as u8)
                } else {
                    match previous {
                        None => action == CaseAction::WorkerWait,
                        Some(p) => action as u8 == p as u8 + 1,
                    }
                },
                "case action order",
            )?;
            next.entered = Some(action);
        }
        CaseTransition::Outcome(action, error) => {
            ensure(
                next.entered == Some(action),
                "case outcome without matching entered action",
            )?;
            ensure(
                error
                    .as_ref()
                    .is_none_or(|e| !e.is_empty() && e.len() <= 2048),
                "case action error bound",
            )?;
            next.records.push(CaseActionRecord { action, error });
            next.entered = None;
        }
    }
    *state = next;
    Ok(())
}
impl CaseActions {
    fn validate(&self) -> Result<()> {
        ensure(
            self.entered.is_none() && self.records.len() <= 14,
            "case unfinished action",
        )?;
        let mut replay = Self::default();
        if let Some(primary) = &self.operation_failure {
            case_transition(
                &mut replay,
                CaseTransition::OperationFailed(primary.clone()),
            )?;
        }
        for record in &self.records {
            case_transition(&mut replay, CaseTransition::Enter(record.action))?;
            case_transition(
                &mut replay,
                CaseTransition::Outcome(record.action, record.error.clone()),
            )?;
        }
        ensure(replay == *self, "case action replay")
    }
    fn complete(&self) -> bool {
        self.operation_failure.is_none()
            && self.records.len() == 14
            && self.entered.is_none()
            && self.records.iter().all(|r| r.error.is_none())
    }
    fn failure(&self) -> Option<&CaseActionRecord> {
        self.records.iter().find(|r| r.error.is_some())
    }
}
// Record only actually invoked callbacks, including mandatory cleanup outcomes.
// Report publication remains outside this capsule: a failed writer cannot prove
// its own successful publication, and preserve_primary keeps its result secondary.
pub fn observed_case_action<T>(
    report: &mut Value,
    enabled: bool,
    action: CaseAction,
    callback: impl FnOnce(&mut Value) -> Result<T>,
) -> Result<T> {
    if !enabled {
        return callback(report);
    }
    let mut state: CaseActions = report
        .get("case_actions")
        .cloned()
        .map(serde_json::from_value)
        .transpose()?
        .unwrap_or_default();
    case_transition(&mut state, CaseTransition::Enter(action))?;
    report["case_actions"] = serde_json::to_value(&state)?;
    let result = callback(report);
    case_transition(
        &mut state,
        CaseTransition::Outcome(
            action,
            result
                .as_ref()
                .err()
                .map(|e| CadenceFailure::new(None, &**e).text),
        ),
    )?;
    report["case_actions"] = serde_json::to_value(state)?;
    result
}
pub fn observed_case_operation_failure(
    report: &mut Value,
    enabled: bool,
    error: Option<&(dyn std::error::Error + 'static)>,
) -> Result<()> {
    if !enabled {
        return Ok(());
    }
    if let Some(error) = error {
        let mut state: CaseActions = report
            .get("case_actions")
            .cloned()
            .map(serde_json::from_value)
            .transpose()?
            .unwrap_or_default();
        if state.records.is_empty() {
            case_transition(
                &mut state,
                CaseTransition::OperationFailed(CadenceFailure::new(None, error).text),
            )?;
            report["case_actions"] = serde_json::to_value(state)?;
        }
    }
    Ok(())
}
fn required_case_actions<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<CaseActions>, D::Error> {
    serde::Deserialize::deserialize(d)
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseStop {
    position: u32,
    acknowledged_prefix: u32,
    cause: CaseStopCause,
    primary: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum CaseStopCause {
    Operation(ControllerStage),
    ExternalObservation,
    Action(CaseAction),
}
fn required_case_stop<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<CaseStop>, D::Error> {
    serde::Deserialize::deserialize(d)
}
// One conservation authority for producer and consumer. Operation-owned primary
// dominates later cleanup; otherwise the first failed entered case callback owns
// the outcome. External errors are admitted only outside those owned boundaries.
fn case_outcome(
    operations: &[BoundaryEvidence],
    actions: Option<&CaseActions>,
    external_error: Option<&str>,
    controller: bool,
    command_count: usize,
) -> Result<Option<CaseStop>> {
    if let Some(actions) = actions {
        actions.validate()?;
    }
    let acknowledged = operations
        .iter()
        .take_while(|op| op.cadence.state.ack == Publication::Confirmed)
        .count();
    let terminal = operations
        .last()
        .and_then(|op| op.cadence.state.terminal.as_ref());
    let operation_failure = actions.and_then(|a| a.operation_failure.as_deref());
    let action_failure = actions.and_then(CaseActions::failure);
    let owned = if let Some(terminal) = terminal {
        let last = operations
            .last()
            .ok_or("case terminal operation identity")?;
        ensure(
            last.cadence.state.primary_finalized,
            "case operation primary unfinished",
        )?;
        if actions.is_some() {
            ensure(
                operation_failure == Some(terminal.primary.as_str()),
                "case operation outcome conservation",
            )?;
        }
        Some((
            last.operation_id,
            CaseStopCause::Operation(terminal.stage),
            terminal.primary.as_str(),
        ))
    } else if let Some(primary) = operation_failure {
        // Pre-operation setup/admission errors have no operation terminal. They
        // remain external observations, never an owner for a sealed full case.
        ensure(
            operations.len() < 64 && external_error == Some(primary),
            "case external operation outcome conservation",
        )?;
        Some((
            operations.len() as u32,
            CaseStopCause::ExternalObservation,
            primary,
        ))
    } else if let Some(failure) = action_failure {
        ensure(
            operations.len() == 64
                && operations
                    .iter()
                    .all(|op| op.cadence.state.complete_confirmed()),
            "case action failure requires sealed operations",
        )?;
        Some((
            64,
            CaseStopCause::Action(failure.action),
            failure
                .error
                .as_deref()
                .ok_or("case failed action primary")?,
        ))
    } else if let Some(primary) = external_error {
        ensure(
            !controller || operations.len() < 64,
            "case external error after sealed workload",
        )?;
        Some((
            if controller {
                operations.len()
            } else {
                command_count
            } as u32,
            CaseStopCause::ExternalObservation,
            primary,
        ))
    } else {
        None
    };
    owned
        .map(|(position, cause, primary)| {
            ensure(
                !primary.is_empty() && primary.len() <= 2048,
                "case primary bound",
            )?;
            Ok(CaseStop {
                position,
                acknowledged_prefix: acknowledged as u32,
                cause,
                primary: primary.to_owned(),
            })
        })
        .transpose()
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullReport {
    #[serde(deserialize_with = "required_case_actions")]
    case_actions: Option<CaseActions>,
    #[serde(deserialize_with = "required_case_stop")]
    case_stop: Option<CaseStop>,
    pub schema: u8,
    pub role: ReportRole,
    pub case: String,
    pub case_epoch: Option<String>,
    pub workload_spec: crate::full_manifest::WorkloadSpec,
    pub seed_records: Option<u64>,
    pub additions: u64,
    pub final_records: Option<u64>,
    pub sessions: u64,
    pub commands: Vec<crate::full_workload_receipt::MeasuredCommand>,
    pub controller_retained_commands: Option<Vec<crate::full_workload_receipt::MeasuredCommand>>,
    pub operations: Option<Vec<BoundaryEvidence>>,
    pub source_oracle: Option<SourceOracle>,
    pub import_oracle: Option<ImportOracle>,
    pub projection_oracle: Option<ProjectionOracle>,
    pub export_oracle: Option<ExportOracle>,
    pub correctness_complete: bool,
    pub workload_complete: bool,
    pub measurement_complete: bool,
    pub sampling_complete: bool,
    pub native_handle_verified: bool,
    pub performance_policy_status: String,
    pub performance_complete: bool,
    pub release_ready: bool,
    pub pass: bool,
    pub error: Option<String>,
    pub diagnostics: Value,
}
fn bounded_case_pairs(mut counts: impl Iterator<Item = u64>) -> Result<u64> {
    counts.try_fold(0u64, |n, count| {
        let total = n.checked_add(count).ok_or("cadence case pair overflow")?;
        ensure(total <= 150128, "cadence case pair ceiling")?;
        Ok(total)
    })
}
impl FullReport {
    pub fn from_observations(observed: &Value, controller: bool) -> Result<Self> {
        let worker = if controller {
            &observed["client"]
        } else {
            observed
        };
        let seed_records = if controller {
            observed["generation"]["seed_records"].as_u64()
        } else {
            observed["seed_records"].as_u64()
        };
        let owned_epoch = if controller {
            observed["metrics"]["case_epoch"].as_str()
        } else {
            None
        };
        if let (Some(owned), Some(worker_epoch)) = (owned_epoch, worker["case_epoch"].as_str()) {
            ensure(
                owned == worker_epoch,
                "full controller/worker epoch mismatch",
            )?;
        }
        let mut diagnostics = observed.clone();
        if let Some(object) = diagnostics.as_object_mut() {
            object.remove("commands");
            object.remove("client");
            object.remove("metrics");
            object.remove("case_actions");
        }
        let mut report = Self {
            case_actions: observed
                .get("case_actions")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            case_stop: None,
            schema: 8,
            role: if controller {
                ReportRole::Controller
            } else {
                ReportRole::Worker
            },
            case: "representative-6MiB-full20x256-v1".into(),
            case_epoch: owned_epoch
                .or_else(|| worker["case_epoch"].as_str())
                .map(str::to_owned),
            workload_spec: crate::full_manifest::WorkloadSpec::full20x256_v1(),
            seed_records,
            additions: 5142,
            final_records: seed_records.and_then(|n| n.checked_add(5143)),
            sessions: 18,
            commands: serde_json::from_value(
                worker
                    .get("commands")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!([])),
            )?,
            controller_retained_commands: if controller {
                observed["metrics"]
                    .get("controller_retained_commands")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?
            } else {
                None
            },
            operations: if controller {
                observed["metrics"]
                    .get("operations")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?
            } else {
                None
            },
            source_oracle: if controller {
                if let Some(unchanged) = observed.get("source_unchanged") {
                    let generation = &observed["generation"];
                    Some(serde_json::from_value(
                        serde_json::json!({"source_unchanged":unchanged,"archive_sha256":generation["archive_sha256"],"logical_sha256":generation["logical_sha256"],"records":generation["records"],"source_inventory":generation["source_before"]}),
                    )?)
                } else {
                    None
                }
            } else {
                None
            },
            import_oracle: if controller {
                observed
                    .get("startup_import")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?
            } else {
                None
            },
            projection_oracle: if controller {
                observed
                    .get("final_payloads")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?
            } else {
                None
            },
            export_oracle: if controller {
                observed
                    .get("export")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?
            } else {
                None
            },
            correctness_complete: controller && observed["correctness_complete"] == true,
            workload_complete: worker["workload_complete"] == true,
            measurement_complete: false,
            sampling_complete: false,
            native_handle_verified: controller
                && observed["metrics"]["native_handle_verified"] == true,
            performance_policy_status: "unapproved".into(),
            performance_complete: false,
            release_ready: false,
            pass: observed["pass"] == true,
            error: observed["error"].as_str().map(str::to_owned),
            diagnostics,
        };
        report.case_stop = case_outcome(
            report.operations.as_deref().unwrap_or(&[]),
            report.case_actions.as_ref(),
            report.error.as_deref(),
            controller,
            report.commands.len(),
        )?;
        report.validate()?;
        Ok(report)
    }
    pub fn validate(&self) -> Result<()> {
        if let Some(actions) = &self.case_actions {
            actions.validate()?;
        }
        if matches!(self.role, ReportRole::Controller) && (self.correctness_complete || self.pass) {
            ensure(
                self.case_actions
                    .as_ref()
                    .is_some_and(CaseActions::complete),
                "successful case requires observed finalization actions",
            )?;
        }
        let outcome = case_outcome(
            self.operations.as_deref().unwrap_or(&[]),
            self.case_actions.as_ref(),
            self.error.as_deref(),
            matches!(self.role, ReportRole::Controller),
            self.commands.len(),
        )?;
        ensure(
            self.case_stop == outcome
                && self.error.as_deref() == outcome.as_ref().map(|stop| stop.primary.as_str()),
            "full derived case outcome conservation",
        )?;
        if let Some(stop) = &outcome {
            ensure(
                !self.pass && stop.position <= 64 && stop.acknowledged_prefix <= 64,
                "full case primary terminal cut",
            )?;
        }
        ensure(
            self.schema == 8
                && self.case == "representative-6MiB-full20x256-v1"
                && self.workload_spec == crate::full_manifest::WorkloadSpec::full20x256_v1()
                && self.additions == 5142
                && self.sessions == 18,
            "full closed report namespace",
        )?;
        ensure(
            !self.measurement_complete
                && !self.sampling_complete
                && !self.performance_complete
                && !self.release_ready
                && self.performance_policy_status == "unapproved",
            "full incomplete measurement/release policy",
        )?;
        ensure(
            self.commands.len() <= 64
                && self
                    .controller_retained_commands
                    .as_ref()
                    .is_none_or(|v| v.len() <= 64)
                && self.operations.as_ref().is_none_or(|v| v.len() <= 64),
            "full report count bound",
        )?;
        ensure(
            self.final_records == self.seed_records.and_then(|n| n.checked_add(5143)),
            "full report seed/final records",
        )?;
        let manifest = self
            .seed_records
            .map(|seeds| FullManifest::new(self.workload_spec, seeds))
            .transpose()?;
        for commands in
            std::iter::once(&self.commands).chain(self.controller_retained_commands.iter())
        {
            for (id, command) in commands.iter().enumerate() {
                let value = serde_json::to_value(command)?;
                command_bound(&value)?;
                command.measurement.validate()?;
                ensure(
                    command.measurement.operation_id == id as u32
                        && command.measurement.identity
                            == SamplePolicy::cli(id as u64 + 3, id as u32).identity,
                    "full report ordered command identity",
                )?;
            }
        }
        if let Some(retained) = &self.controller_retained_commands {
            if !retained.is_empty() {
                let manifest = manifest
                    .as_ref()
                    .ok_or("retained receipt manifest missing")?;
                for (id, command) in retained.iter().enumerate() {
                    crate::full_workload_receipt::validate_retained_command(
                        command,
                        &manifest.operation(id as u32)?,
                    )?;
                }
            }
            for (worker, command) in self.commands.iter().zip(retained) {
                ensure(
                    serde_json::to_value(worker)? == serde_json::to_value(command)?,
                    "full exact worker/controller command overlap",
                )?;
            }
        }
        ensure(
            !self.pass
                || (self.workload_complete
                    && self.error.is_none()
                    && (!matches!(self.role, ReportRole::Controller) || self.correctness_complete)),
            "full report pass requires complete evidence",
        )?;
        if self.workload_complete {
            ensure(
                self.commands.len() == 64
                    && self.case_epoch.as_ref().is_some_and(|e| !e.is_empty())
                    && self.seed_records.is_some(),
                "full report complete worker evidence",
            )?;
        }

        if let Some(operations) = &self.operations {
            bounded_case_pairs(operations.iter().map(|op| op.cadence.pair_attempts))?;
            let epoch = self
                .case_epoch
                .as_deref()
                .ok_or("cadence case epoch missing")?;
            let mut cadence_bytes = 0usize;
            let manifest = manifest
                .as_ref()
                .ok_or("full operation manifest seed missing")?;
            let retained_count = self
                .controller_retained_commands
                .as_ref()
                .map_or(0, Vec::len);
            let retained_prefix = operations
                .iter()
                .take_while(|op| op.cadence.state.command_retained)
                .count();
            ensure(
                retained_count == retained_prefix
                    && operations
                        .iter()
                        .skip(retained_prefix)
                        .all(|op| !op.cadence.state.command_retained),
                "full exact retained effect prefix",
            )?;
            for (id, evidence) in operations.iter().enumerate() {
                ensure(
                    id == 0
                        || operations[id - 1].cadence.state.complete_confirmed()
                            && (evidence.cadence.state.stage == ControllerStage::Ready
                                || operations[id - 1].cadence.state.peer_consumption
                                    == PeerConsumption::NextReadyObserved),
                    "full next operation before prior ACK completion",
                )?;
                let op = manifest.operation(id as u32)?;
                evidence.cadence.validate(epoch, op.id, op.cli_epoch)?;
                cadence_bytes = cadence_bytes
                    .checked_add(serde_json::to_vec(&evidence.cadence)?.len())
                    .ok_or("cadence case bytes overflow")?;
                ensure(cadence_bytes <= 2097152, "cadence case serialized cap")?;
                if evidence.cadence.failure.is_some() {
                    let cadence = &evidence.cadence;
                    let retained = self
                        .controller_retained_commands
                        .as_ref()
                        .map_or(0, Vec::len);
                    let acquisition_terminal =
                        cadence.partial_pairs > 0 || cadence.unacquired_requests > 0;
                    ensure(
                        matches!(self.role, ReportRole::Controller)
                            && id + 1 == operations.len()
                            && !self.pass && !self.workload_complete
                            && !self.correctness_complete && !self.native_handle_verified
                            // Cancellation admission can dominate a completed pair's
                            // diagnostic error; preserve the loop's original error.
                            && self.error.as_ref().is_some_and(|e| !e.is_empty()),
                        "full terminal report outcome/first-fault closure",
                    )?;
                    ensure(
                        retained >= id
                            && retained <= id + 1
                            && self.commands.len()
                                <= id + usize::from(cadence.release_end_us.is_some())
                            && (retained == id
                                || (!acquisition_terminal && evidence.after_done.is_some()))
                            && (!acquisition_terminal
                                || (!evidence.receipt_validated
                                    && !evidence.exact_append_verified
                                    && evidence.after_done.is_none()))
                            && evidence.receipt_validated == cadence.state.receipt_validated
                            && evidence.exact_append_verified == cadence.state.append_verified
                            && retained == id + usize::from(cadence.state.command_retained),
                        "full terminal receipt/command prefix conservation",
                    )?;
                    ensure(
                        operations[..id].iter().all(|previous| {
                            previous.cadence.failure.is_none()
                                && previous.cadence.evidence_complete
                                && previous.receipt_validated
                                && previous.exact_append_verified
                        }),
                        "full terminal acknowledged operation prefix",
                    )?;
                    if let Some(commands) = &self.controller_retained_commands {
                        for (worker, retained) in self.commands.iter().zip(commands) {
                            ensure(
                                serde_json::to_value(worker)? == serde_json::to_value(retained)?,
                                "full terminal retained command mismatch",
                            )?;
                        }
                    }
                }
                ensure(
                    evidence.receipt_validated == evidence.cadence.state.receipt_validated
                        && evidence.exact_append_verified == evidence.cadence.state.append_verified,
                    "cadence completion requires receipt/append",
                )?;
                for (end, observation) in [
                    (false, &evidence.before_release),
                    (true, &evidence.after_done),
                ] {
                    if observation.is_some() {
                        ensure(
                            serde_json::to_value(observation)?
                                == boundary_observation(&evidence.cadence, end)?,
                            "cadence boundary sample mismatch",
                        )?;
                    } else if evidence.cadence.evidence_complete {
                        return Err("cadence complete boundary observation missing".into());
                    }
                }
                ensure(
                    evidence.operation_id == op.id
                        && evidence.cli_epoch == op.cli_epoch
                        && evidence.descriptor == Descriptor::from_operation(&op),
                    "full descriptor/boundary correlation",
                )?;
                for observation in [&evidence.before_release, &evidence.after_done]
                    .into_iter()
                    .flatten()
                {
                    ensure(
                        observation.broker_epoch == 1
                            && observation.supervisor_epoch == 2
                            && observation.cli_epoch == op.cli_epoch,
                        "full retained observation epochs",
                    )?;
                }
                if self.correctness_complete {
                    ensure(
                        evidence.receipt_validated && evidence.exact_append_verified,
                        "full boundary lacks validated receipt/append",
                    )?;
                }
                if self.native_handle_verified {
                    ensure(
                        evidence.cadence.evidence_complete,
                        "cadence full native completeness missing",
                    )?;
                    let before = evidence
                        .before_release
                        .as_ref()
                        .ok_or("full native baseline missing")?;
                    let after = evidence
                        .after_done
                        .as_ref()
                        .ok_or("full native end missing")?;
                    ensure(
                        before.broker_logical_io_delta.is_none()
                            && before.supervisor_logical_io_delta.is_none()
                            && before.handshake_span_us.is_none()
                            && after.broker_logical_io_delta.is_some()
                            && after.supervisor_logical_io_delta.is_some()
                            && after.handshake_span_us.is_some(),
                        "full native observation phase coverage",
                    )?;
                }
            }
        }
        if matches!(self.role, ReportRole::Controller)
            && (self.workload_complete || self.correctness_complete)
        {
            ensure(
                self.operations.as_ref().is_some_and(|operations| {
                    operations.len() == 64
                        && operations.iter().all(|e| {
                            e.cadence.state.complete_confirmed()
                                && e.cadence.failure.is_none()
                                && e.cadence.evidence_complete
                                && e.receipt_validated
                                && e.exact_append_verified
                        })
                }) && self
                    .controller_retained_commands
                    .as_ref()
                    .is_some_and(|c| c.len() == 64),
                "full controller workload requires terminal-free acknowledged coverage",
            )?;
        }
        if self.native_handle_verified {
            ensure(
                matches!(self.role, ReportRole::Controller)
                    && self.operations.as_ref().is_some_and(|v| v.len() == 64),
                "full native boundary coverage missing",
            )?;
        }
        if self.correctness_complete {
            let source = self
                .source_oracle
                .as_ref()
                .ok_or("full source oracle missing")?;
            let imported = self
                .import_oracle
                .as_ref()
                .ok_or("full import oracle missing")?;
            let projected = self
                .projection_oracle
                .as_ref()
                .ok_or("full projection oracle missing")?;
            let exported = self
                .export_oracle
                .as_ref()
                .ok_or("full export oracle missing")?;
            let manifest = manifest.as_ref().ok_or("full manifest seed missing")?;
            let initial = self
                .seed_records
                .and_then(|n| n.checked_add(1))
                .ok_or("full initial records overflow")?;
            let final_records = manifest.final_records();
            let hash = |value: &str| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            };
            ensure(
                source.records == initial
                    && hash(&source.archive_sha256)
                    && hash(&source.logical_sha256)
                    && !source.source_inventory.is_empty()
                    && source.source_inventory.len() <= 16
                    && source
                        .source_inventory
                        .values()
                        .all(|file| hash(&file.sha256)),
                "full source receipt identity/inventory",
            )?;
            let initial_projection = source
                .source_inventory
                .get("events.jsonl")
                .ok_or("full initial projection inventory missing")?
                .bytes;
            let bytes = (0..64).try_fold(initial_projection, |n, id| -> Result<u64> {
                n.checked_add(manifest.operation(id)?.appended_jsonl_bytes)
                    .ok_or_else(|| "full report projection bytes overflow".into())
            })?;
            ensure(
                imported.persisted_startup_receipt.records == initial
                    && imported.persisted_startup_receipt.snapshot_states == 1
                    && imported.persisted_startup_receipt.snapshot_counters == 1
                    && imported.persisted_startup_receipt.logical_sha256 == source.logical_sha256
                    && imported.final_read_only_export.records == final_records
                    && imported.final_read_only_export.snapshot_states == 1
                    && imported.final_read_only_export.snapshot_counters == 1
                    && imported.final_read_only_export.logical_sha256
                        == imported.expected_final_logical_sha256
                    && hash(&imported.expected_final_logical_sha256),
                "full import receipt counts/logical correlation",
            )?;
            ensure(
                projected.records == final_records
                    && projected.bytes == bytes
                    && projected.exact_records_including_metadata_verified,
                "full projection receipt counts/bytes",
            )?;
            ensure(
                exported.records == final_records
                    && exported.sessions == 18
                    && exported.files.len() == 18
                    && exported.exact_payloads_verified
                    && exported.snapshot_payload_verified
                    && hash(&exported.index_sha256)
                    && exported
                        .files
                        .iter()
                        .all(|file| hash(&file.sha256) && file.bytes <= 20 * 1024 * 1024),
                "full export receipt membership/counts",
            )?;
        }

        if self.correctness_complete {
            ensure(
                self.workload_complete
                    && self
                        .source_oracle
                        .as_ref()
                        .is_some_and(|v| v.source_unchanged)
                    && self.import_oracle.is_some()
                    && self.projection_oracle.is_some()
                    && self.export_oracle.is_some()
                    && self.operations.as_ref().is_some_and(|v| v.len() == 64),
                "full report complete stopped oracles",
            )?;
            let retained = self
                .controller_retained_commands
                .as_ref()
                .ok_or("full report retention missing")?;
            validate_final_commands(
                &self
                    .commands
                    .iter()
                    .map(serde_json::to_value)
                    .collect::<std::result::Result<Vec<_>, _>>()?,
                &retained
                    .iter()
                    .map(serde_json::to_value)
                    .collect::<std::result::Result<Vec<_>, _>>()?,
            )?;
        }
        Ok(())
    }
}
fn explicit_shape(raw: &Value, typed: &Value) -> bool {
    match (raw, typed) {
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(k, v)| b.get(k).is_some_and(|w| explicit_shape(v, w)))
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(v, w)| explicit_shape(v, w))
        }
        _ => true,
    }
}

/// Full-only cap. Legacy 1 MiB readers and their admission remain unchanged.
const REPORT_LIMIT: u64 = 16 * 1024 * 1024;
pub fn read_report(path: &Path) -> Result<Value> {
    use std::fs::OpenOptions;
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
        meta.is_file() && meta.len() <= REPORT_LIMIT,
        "full report bounded regular file",
    )?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure(
            meta.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                == 0,
            "full report reparse refused",
        )?;
    }
    let mut bytes = Vec::new();
    file.take(REPORT_LIMIT + 1).read_to_end(&mut bytes)?;
    ensure(
        bytes.len() as u64 <= REPORT_LIMIT,
        "full report grew beyond bound",
    )?;
    let report: FullReport = serde_json::from_slice(&bytes)?;
    let raw: Value = serde_json::from_slice(&bytes)?;
    let typed = serde_json::to_value(&report)?;
    ensure(
        explicit_shape(&raw, &typed),
        "full report requires explicit nullable fields",
    )?;
    report.validate()?;
    Ok(typed)
}
pub fn encode_report(report: &FullReport) -> Result<Vec<u8>> {
    use std::io::Write;
    struct Bounded(Vec<u8>);
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self
                .0
                .len()
                .checked_add(bytes.len())
                .is_none_or(|n| n as u64 > REPORT_LIMIT)
            {
                return Err(std::io::Error::other("full report serialization bound"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    report.validate()?;
    let mut output = Bounded(Vec::new());
    serde_json::to_writer(&mut output, report)?;
    Ok(output.0)
}
/// Reserve once before lifecycle acquisition. Keep the slot after every outcome;
/// actual bounded report publication still happens only after serialization.
pub fn reserve_report(path: &Path) -> Result<File> {
    use std::io::Write;
    ensure(
        std::fs::symlink_metadata(path)
            .err()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "full report output already exists or cannot be inspected",
    )?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.with_extension("full-attempt"))?;
    file.write_all(b"full20x256 report single attempt; outcome may be unknown\n")?;
    file.sync_all()?;
    Ok(file)
}
pub fn write_report_bounded(path: &Path, report: &FullReport) -> Result<()> {
    use std::io::Write;
    let bytes = encode_report(report)?;
    let pending = path.with_extension("pending");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::hard_link(pending, path)?;
    Ok(())
}
pub fn validate_report(report: &Value, epoch: &str, seeds: u64, retained: &[Value]) -> Result<()> {
    let typed: FullReport = serde_json::from_value(report.clone())?;
    typed.validate()?;
    ensure(
        explicit_shape(report, &serde_json::to_value(&typed)?),
        "full worker report explicit fields",
    )?;
    ensure(
        matches!(typed.role, ReportRole::Worker)
            && typed.case_epoch.as_deref() == Some(epoch)
            && typed.seed_records == Some(seeds)
            && typed.final_records == seeds.checked_add(5143)
            && typed.pass
            && typed.workload_complete
            && !typed.correctness_complete
            && !typed.native_handle_verified,
        "full worker report case/seed/role correlation",
    )?;
    validate_final_commands(
        report["commands"]
            .as_array()
            .ok_or("full report commands")?,
        retained,
    )
}
pub fn preserve_primary(primary: Result<()>, secondary: Result<()>) -> Result<()> {
    primary.and(secondary)
}
/// Bind controller identity independently of worker completion, before any fallible work.
#[allow(dead_code)]
fn bind_report_epoch(report: &mut Value, epoch: &str) -> Result<()> {
    ensure(
        !epoch.is_empty()
            && epoch.len() <= 256
            && epoch
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "full controller epoch bound",
    )?;
    ensure(
        report.is_object() && (report["metrics"].is_null() || report["metrics"].is_object()),
        "full controller report shape",
    )?;
    if let Some(bound) = report["metrics"].get("case_epoch") {
        ensure(
            bound.as_str() == Some(epoch),
            "full immutable controller epoch",
        )?;
    } else {
        report["metrics"]["case_epoch"] = Value::String(epoch.to_owned());
    }
    Ok(())
}
/// Real native caller and ordinary injected faults retain the same early-failure shape.
#[allow(dead_code, clippy::too_many_arguments)]
fn reported_controller_intervals(
    adapter: &Adapter<'_>,
    manifest: &FullManifest,
    projection: &Path,
    initial: u64,
    deadline: Instant,
    report: &mut Value,
    sample: impl FnMut(u32, FullEvent) -> Result<Value>,
) -> Result<()> {
    bind_report_epoch(report, adapter.epoch)?;
    ensure(
        report["metrics"].get("operations").is_none()
            && report["metrics"]
                .get("controller_retained_commands")
                .is_none(),
        "full controller intervals already attempted",
    )?;
    report["metrics"]["operations"] = serde_json::json!([]);
    report["metrics"]["controller_retained_commands"] = serde_json::json!([]);
    let mut retained = Vec::with_capacity(64);
    let mut boundaries = Vec::with_capacity(64);
    let result = controller_intervals(
        adapter,
        manifest,
        projection,
        initial,
        deadline,
        &mut retained,
        &mut boundaries,
        sample,
    );
    report["metrics"]["controller_retained_commands"] = serde_json::json!(retained);
    report["metrics"]["operations"] = serde_json::json!(boundaries);
    report["metrics"]["native_handle_verified"] = Value::Bool(false);
    if let Err(e) = &result {
        report["pass"] = Value::Bool(false);
        report["error"] = Value::String(CadenceFailure::new(None, &**e).text);
    }
    result
}
#[cfg(all(windows, feature = "experimental-broker"))]
fn native_process_sample(sample: crate::metrics::ProcessSnapshot) -> Value {
    serde_json::json!({"logical_io":crate::measure::LogicalIo::from(sample.logical_io),"private_bytes":sample.private_bytes,"working_set_bytes":sample.working_set_bytes,"lifetime_peak_private_bytes":sample.peak_private_bytes,"lifetime_peak_working_set_bytes":sample.peak_working_set_bytes})
}
#[cfg(all(windows, feature = "experimental-broker"))]
pub fn controller_native_intervals(
    root: &Path,
    epoch: &str,
    fixture: &crate::scm::Fixture,
    broker: &crate::scm::ObservedService,
    job: &crate::contract::Job,
    generation: &Value,
    report: &mut Value,
) -> Result<()> {
    bind_report_epoch(report, epoch)?;
    let manifest = crate::full_manifest::FullManifest::new(
        crate::full_manifest::WorkloadSpec::full20x256_v1(),
        job.seed_records,
    )?;
    let enroll = crate::contract::text(&job.enrollment)?;
    let adapter = crate::full_workload_receipt::Adapter {
        root,
        case: &job.case,
        enrollment: &enroll,
        epoch,
        timeout: Duration::from_secs(45),
        cancelled: crate::contract::never_cancel,
    };
    let projection = root.join("install-small/store/events.jsonl");
    let mut baseline = None;
    let mut identity = None;
    let result = reported_controller_intervals(
        &adapter,
        &manifest,
        &projection,
        generation["jsonl_bytes"]
            .as_u64()
            .ok_or("full initial projection size")?,
        Instant::now() + Duration::from_secs(300),
        report,
        |id, event| {
            match event {
                FullEvent::BeforeRelease => {
                    let file = crate::metrics::snapshot_jsonl(&projection)?;
                    ensure(file.length >= 6 * 1024 * 1024, "full seed below 6 MiB")?;
                    if let Some(previous) = &identity {
                        ensure(
                            file.identity == *previous,
                            "full projection identity changed",
                        )?;
                    }
                    identity = Some(file.identity.clone());
                    baseline = Some(file);
                }
                FullEvent::Acquire(role) => {
                    let snapshot = match role {
                        CadenceRole::SupervisorB => fixture.sample_client()?,
                        CadenceRole::BrokerC => broker.sample()?,
                    };
                    return Ok(
                        serde_json::json!({"role":role,"epoch":role.epoch(),"sample":native_process_sample(snapshot)}),
                    );
                }
                FullEvent::IntervalFinalize => {
                    let file = baseline.take().ok_or("full baseline missing")?;
                    let final_file = crate::metrics::verify_append(&projection, &file)?;
                    ensure(
                        final_file.length.checked_sub(file.length)
                            == Some(manifest.operation(id)?.appended_jsonl_bytes),
                        "full native exact append delta",
                    )?;
                }
                _ => {}
            }
            Ok(Value::Null)
        },
    );
    report["metrics"]["native_handle_verified"] = serde_json::json!(result.is_ok());
    result
}

#[cfg(test)]
#[path = "full_native_tests.rs"]
mod tests;
