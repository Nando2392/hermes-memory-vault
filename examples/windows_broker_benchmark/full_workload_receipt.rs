//! Full20x256 receipt v1, pure injected boundary, no native authority.
use crate::{
    contract::{ensure, CommandRequest},
    data::Result,
    full_manifest::{Ack, FullManifest, Operation, Stage},
    measure::{CommandMeasurement, SamplePolicy},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Protocol {
    Full20x256ReceiptV1,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: u8,
    pub protocol: Protocol,
    pub case_epoch: String,
    pub command_label: String,
    pub operation_id: u32,
    pub cli_epoch: u64,
    pub payload: Vec<u8>,
    pub command: MeasuredCommand,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredCommand {
    pub exe: String,
    pub args: Vec<String>,
    pub exit_code: Option<i32>,
    pub success: bool,
    pub child_exited: bool,
    pub capture_complete: bool,
    pub spawn_error: Option<String>,
    pub capture_error: Option<String>,
    pub kill_error: Option<String>,
    pub wait_error: Option<String>,
    pub stdout_overflow: bool,
    pub stderr_overflow: bool,
    pub timed_out: bool,
    pub stop_requested: bool,
    pub elapsed_us: u64,
    pub stdout: String,
    pub stderr: String,
    pub stdout_file: String,
    pub stderr_file: String,
    pub measurement: CommandMeasurement,
}
pub struct Adapter<'a> {
    pub root: &'a Path,
    pub case: &'a crate::commands::Case,
    pub enrollment: &'a str,
    pub epoch: &'a str,
    pub timeout: Duration,
    pub cancelled: fn() -> bool,
}
pub fn label(id: u32) -> String {
    format!("full20x256-v1-op-{id}")
}
impl Adapter<'_> {
    /// Narrow worker readback: revalidate the persisted receipt and all captures.
    /// Return the complete command, never a manifest reconstruction.
    pub fn read_validated_command(&self, manifest: &FullManifest, id: u32) -> Result<Value> {
        let receipt: Receipt = decode(&read_bounded(&self.receipt_path(id), RECEIPT_LIMIT)?)?;
        let op = manifest.operation(id)?;
        self.validate(manifest, &op, &manifest.payload(id)?, &receipt)?;
        Ok(serde_json::to_value(receipt.command)?)
    }
    /// Consume actual disk receipt after Done; retain the whole command inside
    /// the required validator BEFORE it can return Ack to FullBarrier. Retained
    /// values are evidence observations, not native provenance authentication.
    pub fn acknowledge(
        &self,
        barrier: &mut crate::full_workload_barrier::FullBarrier<'_>,
        manifest: &FullManifest,
        id: u32,
        retained: &mut Vec<Value>,
        deadline: Instant,
    ) -> Result<()> {
        ensure(
            id < FullManifest::OPERATIONS && retained.len() == id as usize,
            "retained command sequence",
        )?;
        let now = Instant::now();
        ensure(
            deadline > now
                && deadline.duration_since(now) <= Duration::from_secs(60)
                && !(self.cancelled)(),
            "controller receipt deadline/cancelled",
        )?;
        let receipt: Receipt = decode(&read_bounded(&self.receipt_path(id), RECEIPT_LIMIT)?)?;
        barrier.acknowledge(
            id,
            &receipt,
            |op, payload, actual| {
                let ack = self.validate(manifest, op, payload, actual)?;
                ensure(
                    Instant::now() < deadline && !(self.cancelled)(),
                    "controller receipt deadline/cancelled",
                )?;
                retained.push(serde_json::to_value(&actual.command)?);
                Ok(ack)
            },
            self.cancelled,
        )
    }
    pub fn receipt_path(&self, id: u32) -> PathBuf {
        self.root
            .join("scratch")
            .join(format!("{}-receipt.json", label(id)))
    }
    /// Cooperative runner must enforce request.timeout/cancelled itself. This
    /// adapter calls it ONCE and refuses late completion; it cannot interrupt an
    /// arbitrary injected callback. The full native caller supplies command_measured.
    pub fn execute(
        &self,
        manifest: &FullManifest,
        op: &Operation,
        payload: &[u8],
        deadline: Instant,
        runner: impl FnOnce(&CommandRequest<'_>, &SamplePolicy) -> Result<Value>,
    ) -> Result<()> {
        self.preflight(manifest, op, payload)?;
        let now = Instant::now();
        ensure(
            deadline > now
                && deadline.duration_since(now) <= Duration::from_secs(60)
                && deadline.duration_since(now) >= self.timeout,
            "adapter deadline budget",
        )?;
        let prefix = self.root.join("scratch").join(label(op.id));
        for path in [
            self.receipt_path(op.id),
            self.receipt_path(op.id).with_extension("pending"),
            prefix.with_extension("intent.json"),
            prefix.with_extension("stdin"),
            prefix.with_extension("stdout"),
            prefix.with_extension("stderr"),
            prefix.with_extension("result.json"),
        ] {
            ensure(
                std::fs::symlink_metadata(path)
                    .err()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound),
                "adapter preexisting command evidence",
            )?;
        }
        // Durable one-shot reservation: any error/unknown commit keeps it. No
        // remove/retry path, even if runner failed before producing captures.
        let mut attempt = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(prefix.with_extension("attempt"))?;
        attempt.write_all(b"full20x256-receipt-v1 single attempt; outcome may be unknown\n")?;
        attempt.sync_all()?;
        drop(attempt);
        ensure(
            !(self.cancelled)() && Instant::now() < deadline,
            "adapter cancelled/deadline",
        )?;
        let exe = self.exe();
        let args = self.args(op)?;
        let name = label(op.id);
        let directory = self.root.join("scratch");
        let request = self.request(&exe, &args, payload, &name, &directory);
        let invoked = Instant::now();
        let value = runner(&request, &SamplePolicy::cli(op.cli_epoch, op.id))?;
        ensure(
            invoked.elapsed() <= self.timeout,
            "runner exceeded timeout; unknown commit",
        )?;
        ensure(
            !(self.cancelled)() && Instant::now() < deadline,
            "adapter cancelled/deadline after runner; unknown commit",
        )?;
        let bytes = encode_bounded(&value, COMMAND_LIMIT)?;
        let command: MeasuredCommand = decode(&bytes)?;
        let receipt = Receipt {
            schema: 1,
            protocol: Protocol::Full20x256ReceiptV1,
            case_epoch: self.epoch.into(),
            command_label: name,
            operation_id: op.id,
            cli_epoch: op.cli_epoch,
            payload: payload.to_vec(),
            command,
        };
        self.validate(manifest, op, payload, &receipt)?;
        ensure(
            !(self.cancelled)() && Instant::now() < deadline,
            "adapter cancelled/deadline before receipt",
        )?;
        persist(&self.receipt_path(op.id), &receipt)?;
        ensure(
            !(self.cancelled)() && Instant::now() < deadline,
            "adapter cancelled/deadline after receipt; no Done",
        )?;
        Ok(())
    }
    fn preflight(&self, manifest: &FullManifest, op: &Operation, payload: &[u8]) -> Result<()> {
        ensure(
            !self.epoch.is_empty()
                && self.epoch.len() <= 256
                && !self.timeout.is_zero()
                && self.timeout <= Duration::from_secs(45),
            "adapter epoch/timeout bound",
        )?;
        ensure(!(self.cancelled)(), "adapter cancelled")?;
        ensure(
            *op == manifest.operation(op.id)?
                && payload == manifest.payload(op.id)?
                && payload.len() <= 2 * 1024 * 1024,
            "adapter exact operation/payload",
        )?;
        let args = self.args(op)?;
        ensure(
            args.len() <= 128
                && args.iter().map(String::len).sum::<usize>() <= 65536
                && !self.enrollment.is_empty(),
            "adapter argv/enrollment bound",
        )?;
        Ok(())
    }
    pub fn exe(&self) -> PathBuf {
        self.case.install_root.join("bin/hermes-memory-client.exe")
    }
    pub fn args(&self, op: &Operation) -> Result<Vec<String>> {
        let name = match op.stage {
            Stage::UnchangedSnapshot => "snapshot",
            Stage::Export => "export",
            _ => "ingest",
        };
        let mut args = self.case.client_args(name, self.enrollment)?;
        if op.stage == Stage::Export {
            args.extend([
                "--workspace".into(),
                crate::data::WORKSPACE.into(),
                "--vault".into(),
                crate::contract::text(&self.root.join("scratch").join("export"))?,
            ]);
        }
        Ok(args)
    }
    pub fn request<'a>(
        &self,
        exe: &'a Path,
        args: &'a [String],
        input: &'a [u8],
        label: &'a str,
        directory: &'a Path,
    ) -> CommandRequest<'a> {
        CommandRequest {
            exe,
            args,
            input,
            directory,
            label,
            timeout: self.timeout,
            cancelled: self.cancelled,
        }
    }
    pub fn validate(
        &self,
        manifest: &FullManifest,
        op: &Operation,
        payload: &[u8],
        receipt: &Receipt,
    ) -> Result<Ack> {
        self.preflight(manifest, op, payload)?;
        ensure(
            receipt.schema == 1
                && receipt.case_epoch == self.epoch
                && receipt.command_label == label(op.id)
                && receipt.operation_id == op.id
                && receipt.cli_epoch == op.cli_epoch
                && receipt.payload == payload,
            "receipt exact correlation",
        )?;
        let c = &receipt.command;
        let prefix = self.root.join("scratch").join(label(op.id));
        ensure(
            c.exe == crate::contract::text(&self.exe())?
                && c.args == self.args(op)?
                && c.stdout_file == crate::contract::text(&prefix.with_extension("stdout"))?
                && c.stderr_file == crate::contract::text(&prefix.with_extension("stderr"))?,
            "installed executable/argv/capture spelling",
        )?;
        ensure(
            c.success
                && c.exit_code == Some(0)
                && c.child_exited
                && c.capture_complete
                && !c.stdout_overflow
                && !c.stderr_overflow
                && !c.timed_out
                && !c.stop_requested
                && c.spawn_error.is_none()
                && c.capture_error.is_none()
                && c.kill_error.is_none()
                && c.wait_error.is_none(),
            "command failed/unknown commit",
        )?;
        let m = &c.measurement;
        m.validate()?;
        ensure(
            m.identity == SamplePolicy::cli(op.cli_epoch, op.id).identity
                && m.operation_id == op.id
                && m.payload_bytes == payload.len() as u64
                && m.command_success
                && m.child_exit_us
                    .is_some_and(|t| t <= c.elapsed_us && t <= self.timeout.as_micros() as u64)
                && m.final_lifetime_logical_io.is_some()
                && m.final_io_error.is_none()
                && m.live_errors == 0
                && m.live_samples > 0
                && m.memory.is_some(),
            "complete correlated measurement required",
        )?;
        let expected = if op.stage == Stage::Export {
            serde_json::json!({"sessions":op.sessions})
        } else {
            serde_json::json!({"inserted":op.inserted,"duplicates":op.duplicates})
        };
        ensure(
            semantic(&c.stdout, op.stage)? == expected,
            "exact stage output",
        )?;
        ensure(
            read_bounded(&prefix.with_extension("stdin"), 2 * 1024 * 1024)? == payload,
            "captured exact stdin",
        )?;
        for (extension, text) in [("stdout", &c.stdout), ("stderr", &c.stderr)] {
            let bytes = read_bounded(&prefix.with_extension(extension), 1024 * 1024)?;
            ensure(
                String::from_utf8(bytes)? == text.as_str(),
                "captured bytes differ from producer text",
            )?;
        }
        let actual: MeasuredCommand = decode(&read_bounded(
            &prefix.with_extension("result.json"),
            COMMAND_LIMIT,
        )?)?;
        ensure(
            serde_json::to_value(actual)? == serde_json::to_value(c)?,
            "full measured result differs",
        )?;
        let intent: Intent = decode(&read_bounded(&prefix.with_extension("intent.json"), 65536)?)?;
        ensure(
            intent.exe == c.exe
                && intent.args == c.args
                && intent.deadline_ms == self.timeout.as_millis() as u64
                && serde_json::to_value(intent.measurement_policy)?
                    == serde_json::to_value(SamplePolicy::cli(op.cli_epoch, op.id))?,
            "exact measured intent",
        )?;
        ensure(!(self.cancelled)(), "adapter cancelled")?;
        Ok(Ack {
            schema: 1,
            operation_id: op.id,
            cli_epoch: op.cli_epoch,
            payload_bytes: payload.len() as u64,
            inserted: op.inserted,
            duplicates: op.duplicates,
            sessions: op.sessions,
        })
    }
}

/// Serialize fully before create_new; sync owned staging then no-replace link.
/// Retain pending on every outcome; never delete somebody else's evidence.
fn persist(path: &Path, receipt: &Receipt) -> Result<()> {
    let bytes = encode_bounded(receipt, RECEIPT_LIMIT)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.with_extension("pending"))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::hard_link(path.with_extension("pending"), path)?;
    Ok(())
}

fn encode_bounded(value: &impl Serialize, cap: u64) -> Result<Vec<u8>> {
    struct Capped {
        bytes: Vec<u8>,
        cap: u64,
    }
    impl Write for Capped {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if (self.bytes.len() as u64)
                .checked_add(bytes.len() as u64)
                .is_none_or(|size| size > self.cap)
            {
                return Err(std::io::Error::other("serialization cap"));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Capped {
        bytes: Vec::new(),
        cap,
    };
    serde_json::to_writer(&mut output, value)?;
    Ok(output.bytes)
}
const COMMAND_LIMIT: u64 = 16 * 1024 * 1024;
const RECEIPT_LIMIT: u64 = 24 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    exe: String,
    args: Vec<String>,
    deadline_ms: u64,
    measurement_policy: SamplePolicy,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Counts {
    inserted: u64,
    duplicates: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sessions {
    sessions: u64,
}
fn semantic(text: &str, stage: Stage) -> Result<Value> {
    if stage == Stage::Export {
        Ok(serde_json::to_value(serde_json::from_str::<Sessions>(
            text,
        )?)?)
    } else {
        Ok(serde_json::to_value(serde_json::from_str::<Counts>(text)?)?)
    }
}
/// Typed raw decode rejects duplicate/unknown/type drift; exact recursive key
/// shape also requires Option fields explicitly present, including nulls.
fn decode<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let typed: T = serde_json::from_slice(bytes)?;
    let raw: Value = serde_json::from_slice(bytes)?;
    fn shape(a: &Value, b: &Value) -> bool {
        match (a, b) {
            (Value::Object(a), Value::Object(b)) => {
                a.len() == b.len() && a.iter().all(|(k, v)| b.get(k).is_some_and(|w| shape(v, w)))
            }
            (Value::Array(a), Value::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(v, w)| shape(v, w))
            }
            _ => true,
        }
    }
    ensure(
        shape(&raw, &serde_json::to_value(&typed)?),
        "missing receipt/command/measurement field",
    )?;
    Ok(typed)
}
/// One regular-file handle for metadata and cap+1 read. Ordinary cooperative
/// roots only: no parent-path/ACL custody or native acquisition attestation.
fn read_bounded(path: &Path, cap: u64) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    ensure(
        meta.is_file() && meta.len() <= cap,
        "bounded regular receipt/capture required",
    )?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure(
            meta.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                == 0,
            "reparse receipt/capture refused",
        )?;
    }
    read_capped(file, cap)
}
fn read_capped(reader: impl Read, cap: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(cap.checked_add(1).ok_or("read cap overflow")?)
        .read_to_end(&mut bytes)?;
    ensure(
        bytes.len() as u64 <= cap,
        "receipt/capture grew beyond bound",
    )?;
    Ok(bytes)
}

#[cfg(test)]
#[path = "full_workload_receipt_tests.rs"]
mod tests;
