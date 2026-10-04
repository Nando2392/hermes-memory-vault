//! Small, disposable-host end-to-end broker fixture. Help/tests never provision.
// Portable help/refusal builds retain shared pure fixture helpers.
#![cfg_attr(
    not(all(windows, feature = "experimental-broker")),
    allow(dead_code, unused_imports)
)]
#[path = "windows_broker_benchmark/client.rs"]
mod client;
#[path = "windows_broker_benchmark/commands.rs"]
mod commands;
#[path = "windows_broker_benchmark/contract.rs"]
mod contract;
#[path = "windows_broker_benchmark/controller.rs"]
mod controller;
#[path = "windows_broker_benchmark/data.rs"]
mod data;
#[path = "windows_broker_benchmark/fixtures.rs"]
mod fixtures;
#[path = "windows_broker_benchmark/full_manifest.rs"]
#[allow(dead_code)] // Retain the separately tested pure continuation helpers.
mod full_manifest;
#[path = "windows_broker_benchmark/full_workload_barrier.rs"]
#[allow(dead_code)] // Full-only protocol; admission remains in controller/worker.
mod full_workload_barrier;
#[path = "windows_broker_benchmark/full_workload_receipt.rs"]
#[allow(dead_code)] // Shared receipt validation for installed and injected runners.
mod full_workload_receipt;
#[path = "windows_broker_benchmark/policy.rs"]
mod hosted_policy;
#[cfg(test)]
#[path = "windows_broker_benchmark/owned_fixture_export.rs"]
mod owned_fixture_export;
#[path = "windows_broker_benchmark/two_warmup.rs"]
mod two_warmup;
mod policy {
    pub use crate::hosted_policy::hosted_gate;
    pub fn disposable_gates(
        services: bool,
        virtual_accounts: bool,
        acl_mutation: bool,
        reviewed: bool,
    ) -> crate::data::Result<()> {
        crate::contract::ensure(
            services && virtual_accounts && acl_mutation,
            "all three disposable consents required",
        )?;
        hosted_gate(services, reviewed, &std::env::vars().collect())
    }
}
#[cfg(all(windows, feature = "experimental-broker"))]
#[path = "windows_broker_benchmark/scm.rs"]
mod scm;
// Historical small mode remains unmeasured; the explicit pilot uses this seam.
#[path = "windows_broker_benchmark/measure.rs"]
#[allow(dead_code)]
mod measure;
use clap::Parser;
#[cfg(all(windows, feature = "experimental-broker"))]
use scm::metrics;
#[derive(Debug, Parser)]
#[command(
    about = "6 MiB real broker case; hosted disposable Windows CI only. No default execution."
)]
pub struct Options {
    #[arg(long)]
    run: bool,
    #[arg(long)]
    allow_disposable_services: bool,
    #[arg(long)]
    allow_virtual_accounts: bool,
    #[arg(long)]
    allow_acl_mutation: bool,
    #[arg(long)]
    reviewed: bool,
    #[arg(long)]
    result: Option<std::path::PathBuf>,
    #[arg(long)]
    broker_exe: Option<std::path::PathBuf>,
    #[arg(long)]
    client_exe: Option<std::path::PathBuf>,
    #[arg(long)]
    admin_exe: Option<std::path::PathBuf>,
    /// One measured representative-v2 insert; incomplete pilot, not steady-state evidence.
    #[arg(long)]
    representative_small_pilot: bool,
    /// Two measured deterministic warmups only; not the full steady-state workload.
    #[arg(long, conflicts_with = "representative_small_pilot")]
    representative_two_warmup: bool,
    /// Exactly Full20x256V1 with a representative 6 MiB seed; no performance approval.
    #[arg(long, conflicts_with_all = ["representative_small_pilot", "representative_two_warmup"])]
    representative_full_workload: bool,
    /// Unsupported by this small-case controller; never silently ignored.
    #[arg(long)]
    large_mib: Option<u64>,
}
#[path = "windows_broker_benchmark/full_native.rs"]
mod full_native;
#[path = "windows_broker_benchmark/full_oracles.rs"]
mod full_oracles;
fn main() {
    if let Err(error) = entry() {
        eprintln!("benchmark refused/failed: {error}");
        std::process::exit(1);
    }
}
fn entry() -> data::Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_some_and(|a| a == "--service-client") {
        #[cfg(all(windows, feature = "experimental-broker"))]
        {
            contract::ensure(args.len() == 4, "service-client requires exactly NAME ROOT")?;
            return scm::dispatch_client(
                args[2].to_str().ok_or("service name encoding")?,
                std::path::Path::new(&args[3]),
                client::worker,
            );
        }
        #[cfg(not(all(windows, feature = "experimental-broker")))]
        return Err("SCM worker unsupported".into());
    }
    controller::run(Options::parse())
}
