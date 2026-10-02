use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[cfg(any(target_os = "linux", windows, test))]
mod broker;
#[derive(Parser)]
#[command(
    name = "hermes-memory-broker",
    version,
    about = "Experimental Linux/Windows separate-identity sandbox broker; export unsupported"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Service {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        temp_dir: PathBuf,
        #[arg(long)]
        bootstrap_config: Option<PathBuf>,
        #[arg(long)]
        pipe: String,
        #[arg(long)]
        server_sid: String,
        #[arg(long)]
        client_sid: String,
        #[arg(long)]
        workspace: String,
        #[arg(long)]
        service_name: String,
    },
    RequestWindows {
        #[arg(long)]
        pipe: String,
        #[arg(long)]
        server_sid: String,
    },
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
#[cfg(not(any(target_os = "linux", windows)))]
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
        _ => Err("unsupported"),
    }
}
#[cfg(windows)]
fn run(command: Command) -> Result<(), &'static str> {
    match command {
        Command::Service {
            root,
            temp_dir,
            bootstrap_config,
            pipe,
            server_sid,
            client_sid,
            workspace,
            service_name,
        } => broker::windows::service(broker::windows::Config {
            root,
            temp_dir,
            bootstrap_config,
            pipe,
            server_sid,
            client_sid,
            workspace,
            service_name,
        }),
        Command::RequestWindows { pipe, server_sid } => {
            broker::windows::request(&pipe, &server_sid)
        }
        _ => Err("unsupported"),
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
    fn service_requires_private_temp() {
        let args = [
            "broker",
            "service",
            "--root",
            "C:/sandbox",
            "--pipe",
            r"\\.\pipe\HermesMemory.test",
            "--server-sid",
            "S-1-5-80-1-2-3-4-5",
            "--client-sid",
            "S-1-5-21-1-2-3-1001",
            "--workspace",
            "sandbox",
            "--service-name",
            "HermesMemoryTest",
        ];
        assert!(Cli::try_parse_from(args).is_err());
        let mut args = args.to_vec();
        args.extend([
            "--temp-dir",
            "C:/private-temp",
            "--bootstrap-config",
            "C:/admin/bootstrap.json",
        ]);
        assert!(Cli::try_parse_from(args).is_ok());
    }
    #[test]
    fn windows_commands_require_explicit_pinned_identity() {
        assert!(Cli::try_parse_from([
            "broker",
            "request-windows",
            "--pipe",
            r"\\.\pipe\HermesMemory.test",
            "--server-sid",
            "S-1-5-80-1-2-3-4-5"
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["broker", "request-windows", "--pipe", "x"]).is_err());
        assert!(Cli::try_parse_from([
            "broker",
            "service",
            "--root",
            "C:/sandbox",
            "--temp-dir",
            "C:/private-temp",
            "--pipe",
            r"\\.\pipe\HermesMemory.test",
            "--server-sid",
            "S-1-5-80-1-2-3-4-5",
            "--client-sid",
            "S-1-5-21-1-2-3-1001",
            "--workspace",
            "sandbox",
            "--service-name",
            "HermesMemoryTest"
        ])
        .is_ok());
    }
    #[cfg(windows)]
    #[test]
    fn windows_runtime_rejects_invalid_arguments_before_any_io() {
        assert_eq!(
            run(Command::RequestWindows {
                pipe: "remote".into(),
                server_sid: "bad".into()
            }),
            Err("invalid_request")
        );
        assert_eq!(
            run(Command::Service {
                root: "relative".into(),
                temp_dir: "C:/private-temp".into(),
                bootstrap_config: None,
                pipe: "remote".into(),
                server_sid: "bad".into(),
                client_sid: "bad".into(),
                workspace: "*".into(),
                service_name: "bad".into()
            }),
            Err("invalid_request")
        );
    }
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
