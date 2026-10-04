//! Dedicated native two-warmup contract; legacy Job/PilotJob stay unchanged.
use crate::{
    contract::{self, ensure},
    data::{self, Result},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwoWarmupJob {
    pub schema: u8,
    pub epoch: String,
    pub fixture_spec: data::FixtureSpec,
}
impl TwoWarmupJob {
    pub fn validate(&self) -> Result<()> {
        ensure(
            self.schema == 4 && self.fixture_spec == data::FixtureSpec::representative_6_mib(),
            "only native representative two-warmup 6 MiB case admitted",
        )?;
        ensure(
            !self.epoch.is_empty() && self.epoch.len() <= 256,
            "two-warmup case epoch bound",
        )
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReceipt {
    pub schema: u8,
    pub case_epoch: String,
    pub command_label: String,
    pub warmup: contract::WarmupReceipt,
    pub command: Value,
}
impl NativeReceipt {
    pub fn validate(&self, epoch: &str, id: u32) -> Result<()> {
        ensure(
            self.schema == 4
                && self.case_epoch == epoch
                && self.command_label == format!("warmup-op-{id}"),
            "native warmup command correlation mismatch",
        )?;
        self.warmup.validate(id)?;
        crate::controller::validate_warmup_command(&self.command, id)
    }
}
/// One measured invocation only. Never retry unknown commit, failure or bad stdout.
pub fn measured_insert(
    request: &contract::CommandRequest<'_>,
    epoch: &str,
    id: u32,
) -> Result<NativeReceipt> {
    let manifest = data::TwoWarmupManifest;
    ensure(
        request.input == manifest.payload(id)?,
        "native warmup exact payload mismatch",
    )?;
    ensure(
        !epoch.is_empty() && epoch.len() <= 256 && request.label == format!("warmup-op-{id}"),
        "native warmup command correlation mismatch",
    )?;
    let command = contract::command_measured(
        request,
        &crate::measure::SamplePolicy::cli(manifest.cli_epoch(id)?, id),
    )?;
    crate::controller::validate_warmup_command(&command, id)?;
    let receipt = NativeReceipt {
        schema: 4,
        case_epoch: epoch.into(),
        command_label: request.label.into(),
        warmup: contract::WarmupReceipt {
            schema: 3,
            operation_id: id,
            cli_epoch: manifest.cli_epoch(id)?,
            payload: request.input.to_vec(),
            inserted: 1,
            duplicates: 0,
        },
        command,
    };
    receipt.validate(epoch, id)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_job_refuses_schema_epoch_and_larger_fixture() {
        let job = TwoWarmupJob {
            schema: 4,
            epoch: "case".into(),
            fixture_spec: crate::data::FixtureSpec::representative_6_mib(),
        };
        job.validate().unwrap();
        for n in 0..3 {
            let mut value = serde_json::to_value(&job).unwrap();
            match n {
                0 => value["schema"] = serde_json::json!(1),
                1 => value["epoch"] = serde_json::json!(""),
                _ => {
                    value["fixture_spec"]["target_jsonl_bytes"] =
                        serde_json::json!(600 * 1024 * 1024)
                }
            }
            assert!(serde_json::from_value::<TwoWarmupJob>(value)
                .unwrap()
                .validate()
                .is_err());
        }
    }
    #[test]
    fn receipt_correlation_refuses_case_label_payload_and_unknown_fields() {
        // Wire-validator fixture only: never emitted as native execution evidence.
        let payload = data::TwoWarmupManifest.payload(0).unwrap();
        let mut measurement = crate::measure::CommandMeasurement::new(
            &crate::measure::SamplePolicy::cli(3, 0),
            payload.len() as u64,
        );
        measurement.command_success = true;
        measurement.child_exit_us = Some(1);
        let receipt = NativeReceipt {
            schema: 4,
            case_epoch: "case".into(),
            command_label: "warmup-op-0".into(),
            warmup: contract::WarmupReceipt {
                schema: 3,
                operation_id: 0,
                cli_epoch: 3,
                payload,
                inserted: 1,
                duplicates: 0,
            },
            command: serde_json::json!({"success":true,"stdout":"{\"inserted\":1,\"duplicates\":0}","measurement":measurement}),
        };
        receipt.validate("case", 0).unwrap();
        assert!(receipt.validate("other-case", 0).is_err());
        assert!(receipt.validate("case", 1).is_err());
        let original = serde_json::to_value(&receipt).unwrap();
        for n in 0..5 {
            let mut value = original.clone();
            match n {
                0 => value["command_label"] = serde_json::json!("warmup-op-1"),
                1 => value["warmup"]["payload"][0] = serde_json::json!(0),
                2 => value["schema"] = serde_json::json!(3),
                3 => value["command"]["measurement"]["operation_id"] = serde_json::json!(1),
                _ => value["unknown"] = serde_json::json!(true),
            }
            match serde_json::from_value::<NativeReceipt>(value) {
                Ok(bad) => assert!(bad.validate("case", 0).is_err()),
                Err(_) => assert_eq!(n, 4),
            }
        }
    }
    #[test]
    fn wrapper_refuses_payload_before_clobber_or_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("warmup-op-0.intent.json");
        std::fs::write(&path, b"keep me\n").unwrap();
        let exe = std::env::current_exe().unwrap();
        let request = crate::contract::CommandRequest {
            exe: &exe,
            args: &[],
            input: b"wrong",
            directory: dir.path(),
            label: "warmup-op-0",
            timeout: std::time::Duration::from_secs(1),
            cancelled: crate::contract::never_cancel,
        };
        assert!(measured_insert(&request, "case", 0)
            .unwrap_err()
            .to_string()
            .contains("payload"));
        assert_eq!(std::fs::read(path).unwrap(), b"keep me\n");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
    #[cfg(all(windows, feature = "experimental-broker"))]
    #[test]
    fn actual_measured_wrong_executable_cannot_publish_receipt_or_clobber_capture() {
        let dir = tempfile::tempdir().unwrap();
        let exe = std::env::current_exe().unwrap();
        let args = vec!["--help".into()];
        let payload = crate::data::TwoWarmupManifest.payload(0).unwrap();
        let request = crate::contract::CommandRequest {
            exe: &exe,
            args: &args,
            input: &payload,
            directory: dir.path(),
            label: "warmup-op-0",
            timeout: std::time::Duration::from_secs(5),
            cancelled: crate::contract::never_cancel,
        };
        assert!(measured_insert(&request, "case", 0).is_err());
        let result = dir.path().join("warmup-op-0.result.json");
        let bytes = std::fs::read(&result).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value.get("measurement").is_some());
        assert!(measured_insert(&request, "case", 0).is_err());
        assert_eq!(std::fs::read(result).unwrap(), bytes);
        assert!(!dir.path().join("warmup-op-0-native.json").exists());
    }
}
