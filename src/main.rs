use clap::{Parser, Subcommand};
use hermes_memory::{
    validate_export_destination, MemoryRecord, MemoryStore, SearchRequest, SnapshotRequest,
};
use serde_json::json;
use std::error::Error;
use std::io::{self, Read};
use std::path::PathBuf;

const MAX_STDIN_BYTES: usize = 8 * 1024 * 1024;

#[derive(Parser)]
#[command(name = "hermes-memory")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Ingest {
        #[arg(long)]
        root: PathBuf,
    },
    Snapshot {
        #[arg(long)]
        root: PathBuf,
    },
    Search {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        query: String,
        #[arg(long)]
        workspace: Option<String>,
        #[arg(long)]
        session_id: Option<String>,
        #[arg(long, default_value_t = 8)]
        limit: usize,
        #[arg(long, default_value_t = 4096)]
        max_bytes: usize,
    },
    Export {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        vault: PathBuf,
        #[arg(long)]
        workspace: Option<String>,
    },
}

fn parse_records(input: &str) -> Result<Vec<MemoryRecord>, Box<dyn Error>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("ingest requires one JSON object, array, or JSONL on stdin".into());
    }
    if trimmed.starts_with('[') {
        return Ok(serde_json::from_str(trimmed)?);
    }
    if let Ok(record) = serde_json::from_str::<MemoryRecord>(trimmed) {
        return Ok(vec![record]);
    }
    trimmed
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<MemoryRecord>(line).map_err(Into::into))
        .collect()
}

fn read_bounded_utf8(reader: impl Read, max_bytes: usize) -> io::Result<String> {
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024));
    reader
        .take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "stdin exceeds maximum size",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "stdin is not valid UTF-8"))
}

enum ValidatedCommand {
    Ingest(Vec<MemoryRecord>),
    Snapshot(SnapshotRequest),
    Search(SearchRequest),
    Export {
        vault: PathBuf,
        workspace: Option<String>,
    },
}

fn run() -> Result<(), Box<dyn Error>> {
    let (root, command) = match Cli::try_parse()?.command {
        Command::Ingest { root } => {
            let input = read_bounded_utf8(io::stdin().lock(), MAX_STDIN_BYTES)?;
            let records = parse_records(&input)?;
            for record in &records {
                record.validate()?;
            }
            (root, ValidatedCommand::Ingest(records))
        }
        Command::Snapshot { root } => {
            let input = read_bounded_utf8(io::stdin().lock(), MAX_STDIN_BYTES)?;
            let request: SnapshotRequest = serde_json::from_str(&input)?;
            request.validate()?;
            (root, ValidatedCommand::Snapshot(request))
        }
        Command::Search {
            root,
            query,
            workspace,
            session_id,
            limit,
            max_bytes,
        } => {
            let request = SearchRequest {
                query,
                workspace,
                session_id,
                limit,
                max_bytes,
            };
            request.validate()?;
            (root, ValidatedCommand::Search(request))
        }
        Command::Export {
            root,
            vault,
            workspace,
        } => {
            validate_export_destination(&vault)?;
            (root, ValidatedCommand::Export { vault, workspace })
        }
    };
    let store = MemoryStore::open(root)?;
    match command {
        ValidatedCommand::Ingest(records) => {
            let (inserted, duplicates) = store.ingest_many(&records)?;
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "inserted": inserted,
                    "duplicates": duplicates,
                }))?
            );
        }
        ValidatedCommand::Snapshot(request) => {
            let (inserted, duplicates) = store.ingest_snapshot(&request)?;
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "inserted": inserted,
                    "duplicates": duplicates,
                }))?
            );
        }
        ValidatedCommand::Search(request) => {
            println!("{}", serde_json::to_string(&store.search(&request)?)?);
        }
        ValidatedCommand::Export { vault, workspace } => {
            let sessions = store.export_markdown(vault, workspace.as_deref())?;
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "sessions": sessions,
                }))?
            );
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        if let Some(argument_error) = error.downcast_ref::<clap::Error>() {
            let is_display = matches!(
                argument_error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            );
            let _ = argument_error.print();
            if is_display {
                return;
            }
        } else {
            eprintln!("hermes-memory: operation failed");
        }
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::read_bounded_utf8;

    #[test]
    fn bounded_stdin_accepts_exact_limit_and_rejects_oversize_or_invalid_utf8() {
        assert_eq!(
            read_bounded_utf8(&b"1234"[..], 4).expect("exact limit"),
            "1234"
        );
        assert!(read_bounded_utf8(&b"12345"[..], 4).is_err());
        assert!(read_bounded_utf8(&[0xff][..], 4).is_err());
    }
}
