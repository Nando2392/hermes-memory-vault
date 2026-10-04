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
        let m: crate::measure::CommandMeasurement =
            serde_json::from_value(value["measurement"].clone())?;
        m.validate()?;
        ensure(
            m.operation_id == op.id
                && m.identity == crate::measure::SamplePolicy::cli(op.cli_epoch, op.id).identity
                && m.payload_bytes == op.payload_bytes
                && m.command_success,
            "full64 operation/epoch/payload mismatch",
        )?;
        let expected = if id == 63 {
            serde_json::json!({"sessions":18})
        } else {
            serde_json::json!({"inserted":op.inserted,"duplicates":op.duplicates})
        };
        ensure(
            crate::contract::output(value)? == expected,
            "full64 stage output",
        )?;
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
fn active(adapter: &Adapter<'_>, deadline: Instant) -> Result<()> {
    ensure(
        !(adapter.cancelled)() && Instant::now() < deadline,
        "full case cancelled/deadline",
    )
}
const FULL_COMMAND_LIMIT: usize = 128 * 1024;
fn command_bound(command: &Value) -> Result<()> {
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
#[allow(clippy::too_many_arguments)]
pub fn controller_intervals(
    adapter: &Adapter<'_>,
    manifest: &FullManifest,
    projection: &Path,
    initial: u64,
    deadline: Instant,
    retained: &mut Vec<Value>,
    boundaries: &mut Vec<Value>,
    mut sample: impl FnMut(u32, bool) -> Result<Value>,
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
    for id in 0..64 {
        barrier.wait(id, Phase::Ready, phase(deadline), adapter.cancelled, || {})?;
        let op = manifest.operation(id)?;
        let mut file = File::open(projection)?;
        let before = file.metadata()?.len();
        ensure(
            file.metadata()?.is_file() && before <= cap,
            "full projection initial bound/type",
        )?;
        let hash = crate::data::hash_file(projection)?; // Outside retained B/C sample bracket.
        let release_deadline = phase(deadline);
        let baseline = sample(id, false)?;
        boundaries.push(serde_json::json!({"operation_id":id,"cli_epoch":op.cli_epoch,"descriptor":Descriptor::from_operation(&op),"before_release":baseline,"after_done":null,"receipt_validated":false,"exact_append_verified":false}));
        active(adapter, release_deadline)?;
        barrier.publish(id, Phase::Release)?;
        active(adapter, release_deadline)?;
        let done_deadline = phase(deadline);
        barrier.wait(id, Phase::Done, done_deadline, adapter.cancelled, || {})?;
        let end = sample(id, true)?; // End samples precede all receipt/hash checks.
        active(adapter, done_deadline)?;
        let ack_deadline = phase(deadline);
        boundaries[id as usize]["after_done"] = end;
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
        // Bound before Adapter::acknowledge can retain and publish ACK.
        command_bound(&adapter.read_validated_command(manifest, id)?)?;
        active(adapter, ack_deadline)?;
        adapter.acknowledge(&mut barrier, manifest, id, retained, ack_deadline)?;
        active(adapter, ack_deadline)?;
        boundaries[id as usize]["receipt_validated"] = Value::Bool(true);
        boundaries[id as usize]["exact_append_verified"] = Value::Bool(true);
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
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessEvidence {
    pub logical_io: crate::measure::LogicalIo,
    pub private_bytes: u64,
    pub working_set_bytes: u64,
    pub lifetime_peak_private_bytes: u64,
    pub lifetime_peak_working_set_bytes: u64,
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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FullReport {
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
        let mut diagnostics = observed.clone();
        if let Some(object) = diagnostics.as_object_mut() {
            object.remove("commands");
            object.remove("client");
            object.remove("metrics");
        }
        let report = Self {
            schema: 5,
            role: if controller {
                ReportRole::Controller
            } else {
                ReportRole::Worker
            },
            case: "representative-6MiB-full20x256-v1".into(),
            case_epoch: worker["case_epoch"].as_str().map(str::to_owned),
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
        report.validate()?;
        Ok(report)
    }
    pub fn validate(&self) -> Result<()> {
        ensure(
            self.schema == 5
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

        let manifest = self
            .seed_records
            .map(|seeds| FullManifest::new(self.workload_spec, seeds))
            .transpose()?;
        if let Some(operations) = &self.operations {
            let manifest = manifest
                .as_ref()
                .ok_or("full operation manifest seed missing")?;
            for (id, evidence) in operations.iter().enumerate() {
                let op = manifest.operation(id as u32)?;
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
    let mut retained = Vec::with_capacity(64);
    let mut boundaries = Vec::with_capacity(64);
    let mut baseline = None;
    let mut identity = None;
    let result = crate::full_native::controller_intervals(
        &adapter,
        &manifest,
        &projection,
        generation["jsonl_bytes"]
            .as_u64()
            .ok_or("full initial projection size")?,
        Instant::now() + Duration::from_secs(300),
        &mut retained,
        &mut boundaries,
        |id, after| {
            if !after {
                let file = crate::metrics::snapshot_jsonl(&projection)?;
                ensure(file.length >= 6 * 1024 * 1024, "full seed below 6 MiB")?;
                if let Some(previous) = &identity {
                    ensure(
                        file.identity == *previous,
                        "full projection identity changed",
                    )?;
                }
                identity = Some(file.identity.clone());
                let b = fixture.sample_client()?;
                let c = broker.sample()?;
                baseline = Some((file, c, b, Instant::now()));
                Ok(
                    serde_json::json!({"broker_epoch":1,"supervisor_epoch":2,"cli_epoch":3+u64::from(id),"broker":native_process_sample(c),"supervisor":native_process_sample(b)}),
                )
            } else {
                let c = broker.sample()?;
                let b = fixture.sample_client()?;
                let (file, before_c, before_b, start) =
                    baseline.take().ok_or("full baseline missing")?;
                let cd = c.logical_io.checked_delta(&before_c.logical_io)?;
                let bd = b.logical_io.checked_delta(&before_b.logical_io)?;
                let value = serde_json::json!({"broker_epoch":1,"supervisor_epoch":2,"cli_epoch":3+u64::from(id),"broker":native_process_sample(c),"supervisor":native_process_sample(b),"broker_logical_io_delta":crate::measure::LogicalIo::from(cd),"supervisor_logical_io_delta":crate::measure::LogicalIo::from(bd),"handshake_span_us":start.elapsed().as_micros()});
                // The SAME retained process samples precede this native file/hash verification.
                let final_file = crate::metrics::verify_append(&projection, &file)?;
                ensure(
                    final_file.length.checked_sub(file.length)
                        == Some(manifest.operation(id)?.appended_jsonl_bytes),
                    "full native exact append delta",
                )?;
                Ok(value)
            }
        },
    );
    report["metrics"]["controller_retained_commands"] = serde_json::json!(retained);
    report["metrics"]["operations"] = serde_json::json!(boundaries);
    report["metrics"]["native_handle_verified"] = serde_json::json!(result.is_ok());
    result
}

#[cfg(test)]
#[path = "full_native_tests.rs"]
mod tests;
