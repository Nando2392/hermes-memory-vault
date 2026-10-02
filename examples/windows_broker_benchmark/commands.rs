use crate::data::{Result, WORKSPACE};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub legacy_root: PathBuf,
    pub install_root: PathBuf,
    pub service_name: String,
    pub client_sid: String,
    pub broker_source: PathBuf,
    pub client_source: PathBuf,
    pub broker_sha256: String,
    pub client_sha256: String,
    pub release_sha256: String,
    pub default_enrollment: bool,
}
impl Case {
    pub fn prepare_args(&self) -> Result<Vec<String>> {
        for hash in [
            &self.broker_sha256,
            &self.client_sha256,
            &self.release_sha256,
        ] {
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err("expected lowercase SHA256 pin".into());
            }
        }
        let mut args = vec!["prepare".into(), "--allow-machine-provision".into()];
        for (key, value) in [
            (
                "--legacy-root",
                self.legacy_root.to_str().ok_or("legacy root encoding")?,
            ),
            ("--client-sid", &self.client_sid),
            ("--workspace", WORKSPACE),
            ("--service-name", &self.service_name),
            (
                "--broker-source",
                self.broker_source.to_str().ok_or("broker path encoding")?,
            ),
            ("--broker-sha256", &self.broker_sha256),
            (
                "--client-source",
                self.client_source.to_str().ok_or("client path encoding")?,
            ),
            ("--client-sha256", &self.client_sha256),
            ("--release-sha256", &self.release_sha256),
        ] {
            args.extend([key.into(), value.into()]);
        }
        if !self.default_enrollment {
            args.extend([
                "--install-root".into(),
                self.install_root
                    .to_str()
                    .ok_or("install root encoding")?
                    .into(),
            ]);
        }
        Ok(args)
    }
    pub fn client_args(&self, operation: &str, enrollment: &str) -> Result<Vec<String>> {
        if !matches!(operation, "ingest" | "snapshot" | "search" | "export") {
            return Err("unknown client operation".into());
        }
        let mut args = Vec::new();
        if !self.default_enrollment {
            args.extend(["--enrollment".into(), enrollment.into()]);
        }
        args.extend([
            operation.into(),
            "--root".into(),
            self.legacy_root
                .to_str()
                .ok_or("legacy root encoding")?
                .into(),
        ]);
        Ok(args)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_prepare_and_default_lookup_use_actual_cli_contract() {
        let mut case = Case {
            legacy_root: "C:/fixture/small/source".into(),
            install_root: "C:/HermesMemoryVault".into(),
            service_name: "HMVBenchmark-small".into(),
            client_sid: "S-1-5-80-1-2-3-4-5".into(),
            broker_source: "C:/fixture/broker.exe".into(),
            client_source: "C:/fixture/client.exe".into(),
            broker_sha256: "a".repeat(64),
            client_sha256: "b".repeat(64),
            release_sha256: "c".repeat(64),
            default_enrollment: true,
        };
        let args = case.prepare_args().unwrap();
        assert_eq!(args[0], "prepare");
        assert!(args.contains(&"--allow-machine-provision".into()));
        assert!(!args.contains(&"--install-root".into()));
        let args = case.client_args("ingest", "protected.json").unwrap();
        assert_eq!(args, ["ingest", "--root", "C:/fixture/small/source"]);
        case.default_enrollment = false;
        assert!(case
            .prepare_args()
            .unwrap()
            .contains(&"--install-root".into()));
        assert_eq!(
            &case.client_args("snapshot", "protected.json").unwrap()[..2],
            ["--enrollment", "protected.json"]
        );
        assert!(case.client_args("unknown", "protected.json").is_err());
        case.broker_sha256 = "bad".into();
        assert!(case.prepare_args().is_err());
    }
}
