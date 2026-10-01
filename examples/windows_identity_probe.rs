//! Disposable SCM identity/storage/pipe experiment, NOT a production broker.
//! Never run on a workstation. Default and --help perform no provisioning.
#[cfg(windows)]
#[path = "windows_identity_probe/native.rs"]
mod native;
// Native adapter consumes these helpers; non-Windows builds retain harmless CLI admission only.
#[cfg_attr(not(windows), allow(dead_code))]
#[path = "windows_identity_probe/policy.rs"]
mod policy;

fn main() {
    if let Err(error) = entry() {
        eprintln!("windows-identity-probe: {error}");
        std::process::exit(1);
    }
}

fn entry() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--help"] {
        println!(
            "Disposable Windows SCM identity + SQLite ACL + local pipe probe (not a broker).\n\
            --run --allow-disposable-services\n\
            Requires elevated GitHub-hosted Windows runner; creates two transient\n\
            virtual-account own-process services and one fresh protected volume-root fixture.\n\
            No remote-network, symlink, full matrix, or crash-recovery claim.\n\
            Local use is limited to --help and pure helper tests."
        );
        return Ok(());
    }
    #[cfg(windows)]
    if args.first().map(String::as_str) == Some("--service") {
        return native::dispatch(&args);
    }
    let consent = args == ["--run", "--allow-disposable-services"];
    if !policy::admitted(
        cfg!(windows),
        &std::env::var("GITHUB_ACTIONS").unwrap_or_default(),
        &std::env::var("RUNNER_ENVIRONMENT").unwrap_or_default(),
        consent,
    ) {
        return Err("refused: exact --run --allow-disposable-services and disposable Windows CI gates required".into());
    }
    #[cfg(windows)]
    return native::run();
    #[cfg(not(windows))]
    Err("Windows only".into())
}
