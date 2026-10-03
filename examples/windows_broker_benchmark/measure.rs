//! Command measurement seam. No performance acceptance policy is approved.
//! Native counters come only from the retained child, never a reopened PID.
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serialized_evidence_rejects_counter_time_and_maximum_regressions() {
        let io = LogicalIo {
            read_operations: 1,
            write_operations: 1,
            other_operations: 1,
            read_bytes: 10,
            write_bytes: 10,
            other_bytes: 10,
        };
        let mut sample = CommandMeasurement::new(&SamplePolicy::cli(1, 63), 0);
        sample.live_attempts = 1;
        sample.live_samples = 1;
        sample.first_sample_us = Some(1);
        sample.last_sample_us = Some(1);
        sample.child_exit_us = Some(2);
        sample.final_lifetime_logical_io = Some(io);
        sample.memory = Some(MemoryCoverage {
            sampled_private_bytes: 10,
            sampled_working_set_bytes: 20,
            observed_lifetime_peak_private_bytes: 30,
            observed_lifetime_peak_working_set_bytes: 40,
        });
        sample.timepoints.push(Timepoint {
            since_spawn_start_us: 1,
            logical_io: io,
            private_bytes: 10,
            working_set_bytes: 20,
            lifetime_peak_private_bytes: 30,
            lifetime_peak_working_set_bytes: 40,
        });
        sample.validate().unwrap();
        for mutation in 0..5 {
            let mut bad = sample.clone();
            match mutation {
                0 => bad.final_lifetime_logical_io.as_mut().unwrap().read_bytes = 9,
                1 => bad.timepoints[0].since_spawn_start_us = 3,
                2 => bad.memory.as_mut().unwrap().sampled_private_bytes = 9,
                3 => bad.last_sample_us = Some(3),
                _ => bad.final_io_error = Some("x".repeat(2049)),
            }
            assert!(bad.validate().is_err(), "mutation {mutation}");
        }
    }
    // Synthetic wire evidence only; not benchmark acceptance evidence.
    fn retained_samples(times: &[u64]) -> CommandMeasurement {
        let mut sample = CommandMeasurement::new(&SamplePolicy::cli(1, 63), 0);
        sample.live_attempts = times.len() as u64;
        sample.live_samples = times.len() as u64;
        sample.first_sample_us = times.first().copied();
        sample.last_sample_us = times.last().copied();
        sample.max_sample_gap_us = times
            .windows(2)
            .map(|pair| pair[1] - pair[0])
            .max()
            .unwrap_or(0);
        if !times.is_empty() {
            sample.memory = Some(MemoryCoverage {
                sampled_private_bytes: 10,
                sampled_working_set_bytes: 20,
                observed_lifetime_peak_private_bytes: 30,
                observed_lifetime_peak_working_set_bytes: 40,
            });
        }
        sample.timepoints = times
            .iter()
            .map(|&time| Timepoint {
                since_spawn_start_us: time,
                logical_io: LogicalIo {
                    read_operations: 0,
                    write_operations: 0,
                    other_operations: 0,
                    read_bytes: 0,
                    write_bytes: 0,
                    other_bytes: 0,
                },
                private_bytes: 10,
                working_set_bytes: 20,
                lifetime_peak_private_bytes: 30,
                lifetime_peak_working_set_bytes: 40,
            })
            .collect();
        sample
    }

    fn wire_sample(sample: &CommandMeasurement) -> CommandMeasurement {
        serde_json::from_value(serde_json::to_value(sample).unwrap()).unwrap()
    }

    #[test]
    fn serialized_evidence_rejects_impossible_retained_prefix() {
        let mut sample = retained_samples(&[1, 2]);
        sample.validate().unwrap();
        sample.omitted_timepoints = sample.live_samples;
        sample.timepoints.clear();
        assert!(
            wire_sample(&sample).validate().is_err(),
            "live samples must retain their first point"
        );
    }

    #[test]
    fn serialized_evidence_binds_first_retained_timestamp() {
        let sample = retained_samples(&[1, 3]);
        wire_sample(&sample).validate().unwrap();
        for omitted in [0, 1] {
            let mut bad = sample.clone();
            bad.live_samples += omitted;
            bad.live_attempts += omitted;
            bad.omitted_timepoints = omitted;
            bad.first_sample_us = Some(0);
            assert!(
                wire_sample(&bad).validate().is_err(),
                "first timestamp mismatch, omitted={omitted}"
            );
        }
    }

    #[test]
    fn serialized_evidence_rejects_inconsistent_cadence_metadata() {
        for times in [&[][..], &[1][..], &[1, 1][..], &[1, 3, 8][..]] {
            let sample = retained_samples(times);
            wire_sample(&sample).validate().unwrap();
            let mut bad = sample.clone();
            bad.max_sample_gap_us += 1;
            assert!(
                wire_sample(&bad).validate().is_err(),
                "inflated full-coverage gap for {times:?}"
            );
        }
        let sample = retained_samples(&[1, 3, 8]);
        for omitted in [0, 1] {
            let mut bad = sample.clone();
            bad.live_samples += omitted;
            bad.live_attempts += omitted;
            bad.omitted_timepoints = omitted;
            bad.max_sample_gap_us = 4;
            assert!(
                wire_sample(&bad).validate().is_err(),
                "underreported retained gap, omitted={omitted}"
            );
        }
        let mut truncated = sample.clone();
        truncated.live_samples += 1;
        truncated.live_attempts += 1;
        truncated.omitted_timepoints = 1;
        truncated.last_sample_us = Some(15);
        truncated.max_sample_gap_us = 7;
        wire_sample(&truncated).validate().unwrap();
        // The omitted successful samples, not polling attempts or exit, determine cadence.
        let mut missing = retained_samples(&[]);
        missing.live_attempts = 2;
        missing.live_errors = 1;
        missing.first_live_error = Some("unavailable".into());
        missing.exit_races = 1;
        missing.child_exit_us = Some(20);
        wire_sample(&missing).validate().unwrap();
        assert!(missing.memory.is_none());
        assert_eq!(missing.max_sample_gap_us, 0);
    }

    #[cfg(all(windows, feature = "experimental-broker"))]
    #[test]
    fn exited_child_with_no_live_coverage_keeps_memory_missing() {
        use std::{
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let start = Instant::now();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--help")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        while child.try_wait().unwrap().is_none() {
            if start.elapsed() > Duration::from_secs(5) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("ordinary child deadline");
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        let mut sampler = ChildSampler::new(&SamplePolicy::cli(1, 63), 0);
        sampler.poll(&child, start);
        sampler.exited(&child, start);
        sampler.evidence.validate().unwrap();
        assert_eq!(sampler.evidence.live_samples, 0);
        assert_eq!(sampler.evidence.exit_races, 1);
        assert!(sampler.evidence.memory.is_none());
        assert!(sampler.evidence.final_lifetime_logical_io.is_some());
        let report = summarize_stage(CommandStage::Export, &[sampler.evidence]).unwrap();
        assert_eq!(report["logical_io_complete"], true);
        assert_eq!(report["sampled_memory_available"], false);
        assert!(report["samples"][0]["memory"].is_null());
    }
    #[test]
    fn closed_policy_bounds_case_wide_raw_timepoints() {
        let mut policy = SamplePolicy::cli(1, 0);
        policy.max_timepoints = 13;
        assert!(
            policy.validate().is_err(),
            "80 commands must fit 1000 points"
        );
        for limit in [1, 12] {
            policy.max_timepoints = limit;
            policy.validate().unwrap();
        }
        let mut value = serde_json::to_value(&policy).unwrap();
        value["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SamplePolicy>(value).is_err());
        let mut value = serde_json::to_value(&policy).unwrap();
        value["identity"]["pid"] = serde_json::json!(123);
        assert!(serde_json::from_value::<SamplePolicy>(value).is_err());
        let sample = CommandMeasurement::new(&policy, 0);
        let mut value = serde_json::to_value(sample).unwrap();
        value["unexpected"] = serde_json::json!(0);
        assert!(serde_json::from_value::<CommandMeasurement>(value).is_err());
    }
    #[test]
    fn summary_rejects_role_epoch_sequence_and_inconsistent_evidence() {
        let sample = CommandMeasurement::new(&SamplePolicy::cli(1, 0), 0);
        for mutation in 0..7 {
            let mut invalid = sample.clone();
            match mutation {
                0 => invalid.identity.role = ProcessRole::SupervisorB,
                1 => invalid.identity.epoch = 0,
                2 => invalid.schema = 1,
                3 => invalid.operation_id = 2,
                4 => invalid.live_samples = 1,
                5 => invalid.omitted_timepoints = u64::MAX,
                _ => invalid.payload_bytes = 2 * 1024 * 1024 + 1,
            }
            assert!(
                summarize_stage(CommandStage::Warmup, &[invalid]).is_err(),
                "mutation {mutation}"
            );
        }
        let mut next = sample.clone();
        next.operation_id = 1;
        assert!(summarize_stage(CommandStage::Warmup, &[sample.clone(), next]).is_err());
        assert!(summarize_stage(CommandStage::Dedup, &[sample]).is_err());
    }

    #[test]
    fn summary_preserves_raw_outliers_and_missing_coverage_without_thresholds() {
        // Pure synthetic input for statistics only, not benchmark evidence.
        let samples: Vec<_> = (0..20)
            .map(|n| {
                let mut e = CommandMeasurement::new(&SamplePolicy::cli(n + 1, n as u32 + 2), 2048);
                e.command_success = true;
                e.child_exit_us = Some(if n == 19 { 1_000_000 } else { n + 1 });
                e.final_lifetime_logical_io = Some(LogicalIo {
                    read_operations: 1,
                    write_operations: 2,
                    other_operations: 3,
                    read_bytes: (n + 1) * 1024,
                    write_bytes: 1_000_000_000,
                    other_bytes: 7,
                });
                e
            })
            .collect();
        let report = summarize_stage(CommandStage::SteadySingle, &samples).unwrap();
        assert_eq!(report["sample_count"], 20);
        assert_eq!(report["child_exit_us"]["p50"], 10);
        assert_eq!(report["child_exit_us"]["p95"], 19);
        assert_eq!(report["child_exit_us"]["worst"], 1_000_000);
        assert_eq!(report["logical_io_complete"], true);
        assert_eq!(report["sampled_memory_available"], false);
        assert_eq!(report["performance_policy_status"], "unapproved");
        assert!(report.get("pass").is_none());
        assert!(report.get("thresholds").is_none());
        assert_eq!(report["samples"].as_array().unwrap().len(), 20);
        assert!(report["samples"][0]["memory"].is_null());
        assert_eq!(report["logical_io"]["write_bytes"]["p50"], 1_000_000_000);
        let missing = summarize_stage(CommandStage::SteadySingle, &samples[..19]).unwrap();
        assert_eq!(missing["logical_io_complete"], false);
        assert_eq!(missing["commands_successful"], false);
    }
}
use crate::{contract::ensure, data::Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommandStage {
    Warmup,
    SteadySingle,
    SteadyBatch,
    Dedup,
    UnchangedSnapshot,
    Export,
}
impl CommandStage {
    fn operations(self) -> std::ops::Range<u32> {
        match self {
            Self::Warmup => 0..2,
            Self::SteadySingle => 2..22,
            Self::SteadyBatch => 22..42,
            Self::Dedup => 42..62,
            Self::UnchangedSnapshot => 62..63,
            Self::Export => 63..64,
        }
    }
}
fn statistics(mut values: Vec<u64>) -> Value {
    if values.is_empty() {
        return Value::Null;
    }
    values.sort_unstable();
    json!({"count": values.len(), "p50": values[(values.len()*50).div_ceil(100)-1],
        "p95": values[(values.len()*95).div_ceil(100)-1], "worst": values[values.len()-1]})
}
/// CLI evidence only. A successful child exit is NOT a validated broker receipt.
/// Missing entries stay incomplete; never impute zero IO/RAM or merge stages.
pub fn summarize_stage(stage: CommandStage, samples: &[CommandMeasurement]) -> Result<Value> {
    let operations = stage.operations();
    let expected = operations.len();
    ensure(samples.len() <= expected, "stage sample bound")?;
    let mut epochs = std::collections::BTreeSet::new(); // At most 20 handles, not corpus IDs.
    let mut retained_points = 0usize;
    for (sample, operation) in samples.iter().zip(operations) {
        sample.validate()?;
        ensure(
            sample.operation_id == operation,
            "stage operation sequence mismatch",
        )?;
        ensure(
            epochs.insert(sample.identity.epoch),
            "CLI epoch reused across invocations",
        )?;
        retained_points += sample.timepoints.len();
    }
    ensure(retained_points <= 1000, "stage retained timepoint bound")?;
    let count_complete = samples.len() == expected;
    let mut io = serde_json::Map::new();
    for (name, field) in [
        (
            "read_operations",
            (|v: &LogicalIo| v.read_operations) as fn(&LogicalIo) -> u64,
        ),
        ("write_operations", |v: &LogicalIo| v.write_operations),
        ("other_operations", |v: &LogicalIo| v.other_operations),
        ("read_bytes", |v: &LogicalIo| v.read_bytes),
        ("write_bytes", |v: &LogicalIo| v.write_bytes),
        ("other_bytes", |v: &LogicalIo| v.other_bytes),
    ] {
        io.insert(
            name.into(),
            statistics(
                samples
                    .iter()
                    .filter_map(|s| s.final_lifetime_logical_io.as_ref().map(field))
                    .collect(),
            ),
        );
    }
    Ok(
        json!({"schema":2, "stage":stage, "sample_count":samples.len(), "expected_count":expected,
        "commands_successful":count_complete && samples.iter().all(|s| s.command_success),
        "benchmark_correctness_verified":false,
        "logical_io_complete":count_complete && samples.iter().all(|s| s.child_exit_us.is_some() && s.final_lifetime_logical_io.is_some() && s.final_io_error.is_none()),
        "sampled_memory_available":count_complete && samples.iter().all(|s| s.live_samples > 0 && s.memory.is_some() && s.live_errors == 0),
        "child_exit_us":statistics(samples.iter().filter_map(|s| s.child_exit_us).collect()),
        "logical_io":io, "samples":samples, "performance_policy_status":"unapproved",
        "io_scope":"retained CLI child lifetime logical IO: files/devices/pipes/network; not physical IO or broker interval IO",
        "memory_scope":"live-sampled lower bounds; observed lifetime peaks include startup and may miss terminal allocations; absent RAM is null; no simultaneous sum",
        "latency_scope":"spawn start through observed child exit, including sampling/capture polling overhead; excludes later pipe drain, capture sync and projection/export verification",
        "timepoint_retention":"bounded prefix, with all-sample memory maxima, first/last timestamps and maximum observed gap retained online; omitted count explicit",
        "supervision_scope":"CLI only; C broker and B supervisor intervals require separate controller barriers; startup profiling not measured"}),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessRole {
    CliChild,
    BrokerC,
    SupervisorB,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub role: ProcessRole,
    /// Caller-assigned unique retained-handle epoch, not a PID.
    pub epoch: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamplePolicy {
    pub schema: u8,
    pub identity: ProcessIdentity,
    pub operation_id: u32,
    pub max_timepoints: usize,
}
impl SamplePolicy {
    pub fn cli(epoch: u64, operation_id: u32) -> Self {
        Self {
            schema: 2,
            identity: ProcessIdentity {
                role: ProcessRole::CliChild,
                epoch,
            },
            operation_id,
            max_timepoints: 12,
        }
    }
    pub fn validate(&self) -> Result<()> {
        ensure(self.schema == 2, "measurement schema must be 2")?;
        ensure(
            self.identity.role == ProcessRole::CliChild && self.identity.epoch != 0,
            "command sampling requires CLI role and nonzero retained-handle epoch",
        )?;
        ensure(self.operation_id < 80, "operation bound")?;
        ensure((1..=12).contains(&self.max_timepoints), "timepoint bound")
    }
}
/// Wire representation only; arithmetic uses the native metrics implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogicalIo {
    pub read_operations: u64,
    pub write_operations: u64,
    pub other_operations: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub other_bytes: u64,
}
#[cfg(all(windows, feature = "experimental-broker"))]
impl From<crate::metrics::LogicalIoCounters> for LogicalIo {
    fn from(v: crate::metrics::LogicalIoCounters) -> Self {
        Self {
            read_operations: v.read_operations,
            write_operations: v.write_operations,
            other_operations: v.other_operations,
            read_bytes: v.read_bytes,
            write_bytes: v.write_bytes,
            other_bytes: v.other_bytes,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryCoverage {
    pub sampled_private_bytes: u64,
    pub sampled_working_set_bytes: u64,
    pub observed_lifetime_peak_private_bytes: u64,
    pub observed_lifetime_peak_working_set_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timepoint {
    pub since_spawn_start_us: u64,
    pub logical_io: LogicalIo,
    pub private_bytes: u64,
    pub working_set_bytes: u64,
    pub lifetime_peak_private_bytes: u64,
    pub lifetime_peak_working_set_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandMeasurement {
    pub schema: u8,
    pub identity: ProcessIdentity,
    pub operation_id: u32,
    pub payload_bytes: u64,
    pub command_success: bool,
    /// Spawn start to observed exit, excludes subsequent drain/sync/verification.
    pub child_exit_us: Option<u64>,
    pub live_attempts: u64,
    pub live_samples: u64,
    pub exit_races: u64,
    pub live_errors: u64,
    pub first_live_error: Option<String>,
    pub first_sample_us: Option<u64>,
    pub last_sample_us: Option<u64>,
    pub max_sample_gap_us: u64,
    pub memory: Option<MemoryCoverage>,
    pub timepoints: Vec<Timepoint>,
    pub omitted_timepoints: u64,
    /// Complete child lifetime logical IO, NOT final-minus-first-live.
    pub final_lifetime_logical_io: Option<LogicalIo>,
    pub final_io_error: Option<String>,
}
impl CommandMeasurement {
    pub fn validate(&self) -> Result<()> {
        SamplePolicy {
            schema: self.schema,
            identity: self.identity.clone(),
            operation_id: self.operation_id,
            max_timepoints: 1,
        }
        .validate()?;
        ensure(self.payload_bytes <= 2 * 1024 * 1024, "payload bound")?;
        ensure(self.timepoints.len() <= 12, "timepoint bound")?;
        ensure(
            self.live_samples
                .checked_add(self.exit_races)
                .and_then(|n| n.checked_add(self.live_errors))
                == Some(self.live_attempts),
            "sampling attempt accounting",
        )?;
        ensure(
            (self.timepoints.len() as u64).checked_add(self.omitted_timepoints)
                == Some(self.live_samples),
            "retained sample accounting",
        )?;
        let has_samples = self.live_samples != 0;
        ensure(
            has_samples == !self.timepoints.is_empty(),
            "live samples require a retained prefix",
        )?;
        ensure(
            has_samples == self.memory.is_some()
                && has_samples == self.first_sample_us.is_some()
                && has_samples == self.last_sample_us.is_some(),
            "memory sample coverage mismatch",
        )?;
        ensure(
            self.first_sample_us <= self.last_sample_us,
            "sample timestamp regression",
        )?;
        ensure(
            self.live_errors != 0 || self.first_live_error.is_none(),
            "unexpected live error",
        )?;
        ensure(
            self.live_errors == 0 || self.first_live_error.is_some(),
            "missing live error",
        )?;
        ensure(
            self.final_lifetime_logical_io.is_none()
                || (self.child_exit_us.is_some() && self.final_io_error.is_none()),
            "final IO requires observed exit without error",
        )?;
        ensure(
            !self.command_success || self.child_exit_us.is_some(),
            "successful command without exit",
        )?;
        for error in [&self.first_live_error, &self.final_io_error]
            .into_iter()
            .flatten()
        {
            ensure(error.len() <= 2048, "measurement error bound")?;
        }
        if let (Some(last), Some(exit)) = (self.last_sample_us, self.child_exit_us) {
            ensure(last <= exit, "sample timestamp after child exit")?;
        }
        let counters = |io: LogicalIo| {
            [
                io.read_operations,
                io.write_operations,
                io.other_operations,
                io.read_bytes,
                io.write_bytes,
                io.other_bytes,
            ]
        };
        ensure(
            self.timepoints
                .first()
                .map(|point| point.since_spawn_start_us)
                == self.first_sample_us,
            "first retained timestamp mismatch",
        )?;
        let mut previous = None;
        let mut max_retained_gap_us = 0;
        for point in &self.timepoints {
            ensure(
                self.first_sample_us
                    .is_some_and(|first| first <= point.since_spawn_start_us)
                    && self
                        .last_sample_us
                        .is_some_and(|last| point.since_spawn_start_us <= last),
                "retained timestamp outside sample coverage",
            )?;
            if let Some((time, io)) = previous {
                ensure(
                    time <= point.since_spawn_start_us,
                    "retained timestamp regression",
                )?;
                max_retained_gap_us = max_retained_gap_us.max(point.since_spawn_start_us - time);
                ensure(
                    counters(point.logical_io)
                        .iter()
                        .zip(counters(io))
                        .all(|(now, before)| *now >= before),
                    "retained logical IO regression",
                )?;
            }
            if let Some(final_io) = self.final_lifetime_logical_io {
                ensure(
                    counters(final_io)
                        .iter()
                        .zip(counters(point.logical_io))
                        .all(|(final_count, live)| *final_count >= live),
                    "final logical IO regression",
                )?;
            }
            let memory = self.memory.as_ref().ok_or("missing sample memory")?;
            ensure(
                memory.sampled_private_bytes >= point.private_bytes
                    && memory.sampled_working_set_bytes >= point.working_set_bytes
                    && memory.observed_lifetime_peak_private_bytes
                        >= point.lifetime_peak_private_bytes
                    && memory.observed_lifetime_peak_working_set_bytes
                        >= point.lifetime_peak_working_set_bytes,
                "memory maximum below retained sample",
            )?;
            previous = Some((point.since_spawn_start_us, point.logical_io));
        }
        ensure(
            self.max_sample_gap_us >= max_retained_gap_us
                && (self.omitted_timepoints != 0 || self.max_sample_gap_us == max_retained_gap_us),
            "sample cadence mismatch",
        )?;
        Ok(())
    }
    pub fn new(policy: &SamplePolicy, payload_bytes: u64) -> Self {
        Self {
            schema: 2,
            identity: policy.identity.clone(),
            operation_id: policy.operation_id,
            payload_bytes,
            command_success: false,
            child_exit_us: None,
            live_attempts: 0,
            live_samples: 0,
            exit_races: 0,
            live_errors: 0,
            first_live_error: None,
            first_sample_us: None,
            last_sample_us: None,
            max_sample_gap_us: 0,
            memory: None,
            timepoints: Vec::new(),
            omitted_timepoints: 0,
            final_lifetime_logical_io: None,
            final_io_error: None,
        }
    }
}

#[cfg(all(windows, feature = "experimental-broker"))]
pub struct ChildSampler {
    pub evidence: CommandMeasurement,
    max_timepoints: usize,
    last_attempt: Option<std::time::Instant>,
    last_io: Option<crate::metrics::LogicalIoCounters>,
}
#[cfg(all(windows, feature = "experimental-broker"))]
impl ChildSampler {
    pub fn new(policy: &SamplePolicy, payload_bytes: u64) -> Self {
        Self {
            evidence: CommandMeasurement::new(policy, payload_bytes),
            max_timepoints: policy.max_timepoints,
            last_attempt: None,
            last_io: None,
        }
    }
    pub fn poll(&mut self, child: &std::process::Child, started: std::time::Instant) {
        use std::os::windows::io::AsRawHandle;
        if self
            .last_attempt
            .is_some_and(|t| t.elapsed() < std::time::Duration::from_millis(2))
        {
            return;
        }
        self.last_attempt = Some(std::time::Instant::now());
        self.evidence.live_attempts += 1;
        // SAFETY: Child retains the CreateProcess handle (including query, VM read
        // and synchronize rights) throughout this call. No PID reopen or SCM use.
        let sampled = unsafe { crate::metrics::sample_process(child.as_raw_handle()) };
        match sampled {
            Ok(s) => {
                if let Some(previous) = self.last_io {
                    if let Err(error) = s.logical_io.checked_delta(&previous) {
                        self.live_error(error);
                        return;
                    }
                }
                self.last_io = Some(s.logical_io);
                let us = started.elapsed().as_micros() as u64;
                let e = &mut self.evidence;
                e.live_samples += 1;
                e.first_sample_us.get_or_insert(us);
                if let Some(last) = e.last_sample_us.replace(us) {
                    e.max_sample_gap_us = e.max_sample_gap_us.max(us - last);
                }
                let m = e.memory.get_or_insert(MemoryCoverage {
                    sampled_private_bytes: 0,
                    sampled_working_set_bytes: 0,
                    observed_lifetime_peak_private_bytes: 0,
                    observed_lifetime_peak_working_set_bytes: 0,
                });
                m.sampled_private_bytes = m.sampled_private_bytes.max(s.private_bytes);
                m.sampled_working_set_bytes = m.sampled_working_set_bytes.max(s.working_set_bytes);
                m.observed_lifetime_peak_private_bytes = m
                    .observed_lifetime_peak_private_bytes
                    .max(s.peak_private_bytes);
                m.observed_lifetime_peak_working_set_bytes = m
                    .observed_lifetime_peak_working_set_bytes
                    .max(s.peak_working_set_bytes);
                if e.timepoints.len() < self.max_timepoints {
                    e.timepoints.push(Timepoint {
                        since_spawn_start_us: us,
                        logical_io: s.logical_io.into(),
                        private_bytes: s.private_bytes,
                        working_set_bytes: s.working_set_bytes,
                        lifetime_peak_private_bytes: s.peak_private_bytes,
                        lifetime_peak_working_set_bytes: s.peak_working_set_bytes,
                    });
                } else {
                    e.omitted_timepoints += 1;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                self.evidence.exit_races += 1
            }
            Err(error) => self.live_error(error),
        }
    }
    fn live_error(&mut self, error: std::io::Error) {
        self.evidence.live_errors += 1;
        self.evidence
            .first_live_error
            .get_or_insert_with(|| error.to_string().chars().take(512).collect());
    }
    pub fn exited(&mut self, child: &std::process::Child, started: std::time::Instant) {
        use std::os::windows::io::AsRawHandle;
        self.evidence.child_exit_us = Some(started.elapsed().as_micros() as u64);
        // SAFETY: try_wait observed exit, but Child still owns its original Windows
        // process handle. Query before dropping it; never synthesize exited RAM.
        let final_io =
            unsafe { crate::metrics::sample_exited_child_logical_io(child.as_raw_handle()) }
                .and_then(|io| {
                    if let Some(previous) = self.last_io {
                        io.checked_delta(&previous)?;
                    }
                    Ok(io)
                });
        match final_io {
            Ok(io) => self.evidence.final_lifetime_logical_io = Some(io.into()),
            Err(error) => {
                self.evidence.final_io_error = Some(error.to_string().chars().take(512).collect())
            }
        }
    }
}
