use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[cfg(any(target_os = "linux", test))]
mod broker;
#[derive(Parser)]
#[command(
    name = "hermes-memory-broker",
    version,
    about = "Experimental Linux separate-identity sandbox broker; export unsupported"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Serve {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        allowed_uid: u32,
        #[arg(long)]
        workspace: String,
    },
    Request {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        server_uid: u32,
    },
}
#[cfg(not(target_os = "linux"))]
fn run(_command: Command) -> Result<(), &'static str> {
    Err("unsupported")
}
#[cfg(target_os = "linux")]
fn run(command: Command) -> Result<(), &'static str> {
    match command {
        Command::Serve {
            root,
            socket,
            allowed_uid,
            workspace,
        } => broker::linux::serve(&root, &socket, allowed_uid, &workspace),
        Command::Request { socket, server_uid } => broker::linux::request(&socket, server_uid),
    }
}
fn main() {
    if let Err(code) = run(Cli::parse().command) {
        eprintln!("{code}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn help_exposes_only_sandbox_commands() {
        let e = Cli::try_parse_from(["broker", "--help"]).err().unwrap();
        assert_eq!(e.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(e.to_string().contains("serve"));
        assert!(e.to_string().contains("request"));
        assert!(Cli::try_parse_from(["broker", "request", "--socket", "a"]).is_err());
    }
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform_never_opens_store_or_socket() {
        assert_eq!(
            run(Command::Serve {
                root: "nonexistent".into(),
                socket: "nonexistent".into(),
                allowed_uid: 2,
                workspace: "sandbox".into()
            }),
            Err("unsupported")
        );
        assert_eq!(
            run(Command::Request {
                socket: "nonexistent".into(),
                server_uid: 1
            }),
            Err("unsupported")
        );
    }
}
