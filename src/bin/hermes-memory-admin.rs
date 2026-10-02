//! Explicit administrator entry point. No auto-elevation, downloads or shell calls.
use clap::{Args, Parser, Subcommand};
use std::{io, path::PathBuf};
#[derive(Parser)]
#[command(
    name = "hermes-memory-admin",
    version,
    about = "Experimental initial Windows machine provisioning; independent review and hosted CI required"
)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Explicitly authorize machine operations; also requires an elevated Administrators token"
    )]
    allow_machine_provision: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(Args)]
struct Payload {
    #[arg(
        long,
        help = "Exact old CLI --root, normally <HERMES_HOME>/memory-vault; NEVER read"
    )]
    legacy_root: String,
    #[arg(long, help = "Canonical SID of the intended client's TokenUser")]
    client_sid: String,
    #[arg(long, help = "Exactly one fixed allowed workspace")]
    workspace: String,
    #[arg(
        long,
        help = "Fresh absolute physical NTFS namespace; defaults to system-drive/HermesMemoryVault"
    )]
    install_root: Option<String>,
    #[arg(long)]
    service_name: Option<String>,
    #[arg(long)]
    broker_source: String,
    #[arg(long)]
    broker_sha256: String,
    #[arg(long)]
    client_source: String,
    #[arg(long)]
    client_sha256: String,
    #[arg(long, help = "Externally reviewed release manifest SHA-256 metadata")]
    release_sha256: String,
}
#[derive(Subcommand)]
enum Command {
    /// Read-only validation and source hashing; no administrator token required.
    Plan(Payload),
    /// First installation only; refuses any existing install root or service. Never starts.
    Prepare(Payload),
    /// Stage an externally pinned logical archive, then start the owned service.
    Activate {
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        archive_source: PathBuf,
        #[arg(long)]
        archive_sha256: String,
        #[arg(long)]
        expected_logical_sha256: String,
    },
    /// Check owned service configuration and actual running TokenUser, not client health.
    Status {
        #[arg(long)]
        receipt: PathBuf,
    },
    /// Bounded stop of the receipt-owned service only. Never deletes canonical data.
    Stop {
        #[arg(long)]
        receipt: PathBuf,
    },
}
#[cfg(windows)]
impl Payload {
    fn inputs(self) -> io::Result<hermes_memory::windows_provision::Inputs> {
        use hermes_memory::windows_provision::{default_install_root, Inputs};
        Ok(Inputs {
            legacy_root: self.legacy_root,
            client_sid: self.client_sid,
            workspace: self.workspace,
            install_root: match self.install_root {
                Some(p) => p,
                None => default_install_root()?,
            },
            service_name: self.service_name,
            broker_source: self.broker_source,
            broker_sha256: self.broker_sha256,
            client_source: self.client_source,
            client_sha256: self.client_sha256,
            release_sha256: self.release_sha256,
        })
    }
}
#[cfg(windows)]
fn run(cli: Cli) -> io::Result<serde_json::Value> {
    use hermes_memory::windows_provision as provision;
    let allow = cli.allow_machine_provision;
    match cli.command {
        Command::Plan(payload) => {
            serde_json::to_value(provision::checked_plan(&payload.inputs()?)?)
                .map_err(io::Error::other)
        }
        Command::Prepare(payload) => {
            serde_json::to_value(provision::prepare(&payload.inputs()?, allow)?)
                .map_err(io::Error::other)
        }
        Command::Activate {
            receipt,
            archive_source,
            archive_sha256,
            expected_logical_sha256,
        } => provision::activate(
            &receipt,
            &archive_source,
            &archive_sha256,
            &expected_logical_sha256,
            allow,
        ),
        Command::Status { receipt } => provision::status(&receipt, allow),
        Command::Stop { receipt } => provision::stop(&receipt, allow),
    }
}
#[cfg(not(windows))]
fn run(_cli: Cli) -> io::Result<serde_json::Value> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows machine provisioning unsupported on this platform",
    ))
}
fn main() {
    match run(Cli::parse()).and_then(|v| serde_json::to_string_pretty(&v).map_err(io::Error::other))
    {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("machine provisioning refused/failed: {error}");
            std::process::exit(1);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_requires_receipt_and_opt_in_is_never_default() {
        use clap::Parser;
        assert!(Cli::try_parse_from(["admin", "status"]).is_err());
        let cli = Cli::try_parse_from(["admin", "status", "--receipt", "C:/fixture/receipt.json"])
            .unwrap();
        assert!(!cli.allow_machine_provision);
        let cli = Cli::try_parse_from([
            "admin",
            "stop",
            "--receipt",
            "C:/fixture/receipt.json",
            "--allow-machine-provision",
        ])
        .unwrap();
        assert!(cli.allow_machine_provision);
    }
}
