//! Broker-only compatibility client. No database or subprocess fallback.
// Non-Windows keeps pure protocol/validation code testable, but run() rejects
// before stdin, enrollment or filesystem I/O. Native-only paths are unused there.
#![cfg_attr(not(windows), allow(dead_code))]
use clap::{Parser, Subcommand};
use hermes_memory::{MemoryRecord, SearchRequest, SnapshotRequest};
use serde_json::{json, Value};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
};
const MAX_FRAME: usize = 8 * 1024 * 1024;
#[derive(Debug, thiserror::Error)]
enum ClientError {
    #[error("invalid_request: {0}")]
    Invalid(&'static str),
    #[error("resource_limit")]
    ResourceLimit,
    #[error("unauthorized")]
    Unauthorized,
    #[error("unavailable")]
    Unavailable,
    #[error("outcome_unknown; mutation must not be automatically retried")]
    OutcomeUnknown,
    #[cfg(not(windows))]
    #[error("unsupported: Windows broker client required")]
    Unsupported,
    #[error("broker rejected request: {0}")]
    Rejected(String),
    #[error(transparent)]
    Store(#[from] hermes_memory::MemoryError),
}
#[derive(Parser)]
#[command(name = "hermes-memory", version)]
struct Cli {
    #[arg(long, global = true)]
    enrollment: Option<PathBuf>,
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
struct Prepared {
    root: PathBuf,
    workspace: String,
    operation: Operation,
}
enum Operation {
    Request { op: &'static str, body: Value },
    Export { vault: PathBuf },
}
fn bounded_input(input: impl Read) -> Result<String, ClientError> {
    let mut bytes = Vec::new();
    input
        .take((MAX_FRAME + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ClientError::Invalid("stdin read failed"))?;
    if bytes.len() > MAX_FRAME {
        return Err(ClientError::ResourceLimit);
    }
    String::from_utf8(bytes).map_err(|_| ClientError::Invalid("stdin is not UTF-8"))
}
fn text(value: &str, max: usize) -> Result<(), ClientError> {
    if value.trim().is_empty() {
        return Err(ClientError::Invalid("blank field"));
    }
    if value.len() > max {
        return Err(ClientError::ResourceLimit);
    }
    Ok(())
}
fn timestamp(value: f64) -> Result<(), ClientError> {
    if !value.is_finite() || !(0.0..=253402300799.0).contains(&value) {
        return Err(ClientError::Invalid("timestamp"));
    }
    Ok(())
}
fn prepare(command: Command, input: impl Read) -> Result<Prepared, ClientError> {
    let (root, workspace, operation) = match command {
        Command::Ingest { root } => {
            let input = bounded_input(input)?;
            let trimmed = input.trim();
            if trimmed.is_empty() {
                return Err(ClientError::Invalid(
                    "ingest requires JSON object, array or JSONL",
                ));
            }
            let records: Vec<MemoryRecord> = if trimmed.starts_with('[') {
                serde_json::from_str(trimmed).map_err(|_| ClientError::Invalid("ingest JSON"))?
            } else if let Ok(record) = serde_json::from_str::<MemoryRecord>(trimmed) {
                vec![record]
            } else {
                trimmed
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(serde_json::from_str)
                    .collect::<Result<_, _>>()
                    .map_err(|_| ClientError::Invalid("ingest JSONL"))?
            };
            if records.len() > 1024 {
                return Err(ClientError::ResourceLimit);
            }
            let workspace = records
                .first()
                .ok_or(ClientError::Invalid("ingest requires records"))?
                .workspace
                .clone();
            for r in &records {
                if r.workspace != workspace {
                    return Err(ClientError::Invalid("mixed workspace ingest is not atomic"));
                }
                for s in [&r.id, &r.session_id, &r.kind] {
                    text(s, 256)?;
                }
                if r.content.len() > 1024 * 1024 {
                    return Err(ClientError::ResourceLimit);
                }
                timestamp(r.timestamp)?;
                r.validate()?;
            }
            (
                root,
                workspace,
                Operation::Request {
                    op: "ingest",
                    body: json!({"records":records}),
                },
            )
        }
        Command::Snapshot { root } => {
            let request: SnapshotRequest = serde_json::from_str(&bounded_input(input)?)
                .map_err(|_| ClientError::Invalid("snapshot JSON"))?;
            request.validate()?;
            text(&request.session_id, 256)?;
            if request.items.len() > 1024 {
                return Err(ClientError::ResourceLimit);
            }
            for item in &request.items {
                text(&item.kind, 256)?;
                timestamp(item.timestamp)?;
                if item.content.len() > 1024 * 1024 {
                    return Err(ClientError::ResourceLimit);
                }
            }
            (
                root,
                request.workspace.clone(),
                Operation::Request {
                    op: "snapshot",
                    body: json!({"session_id":request.session_id,"workspace":request.workspace,"items":request.items.iter().map(|i|json!({"kind":i.kind,"content":i.content,"timestamp":i.timestamp,"metadata":i.metadata})).collect::<Vec<_>>()}),
                },
            )
        }
        Command::Search {
            root,
            query,
            workspace,
            session_id,
            limit,
            max_bytes,
        } => {
            let workspace = workspace.ok_or(ClientError::Invalid("search requires --workspace"))?;
            text(&query, 4096)?;
            if let Some(s) = &session_id {
                text(s, 256)?;
            }
            if !(1..=20).contains(&limit) || !(1..=65536).contains(&max_bytes) {
                return Err(ClientError::ResourceLimit);
            }
            let request = SearchRequest {
                query,
                workspace: Some(workspace.clone()),
                session_id,
                limit,
                max_bytes,
            };
            request.validate()?;
            (
                root,
                workspace,
                Operation::Request {
                    op: "search",
                    body: json!({"query":request.query,"workspace":request.workspace,"session_id":request.session_id,"limit":request.limit,"max_bytes":request.max_bytes}),
                },
            )
        }
        Command::Export {
            root,
            vault,
            workspace,
        } => {
            let workspace = workspace.ok_or(ClientError::Invalid("export requires --workspace"))?;
            // Filesystem path validation happens after authentication, before writes.
            (root, workspace, Operation::Export { vault })
        }
    };
    text(&workspace, 256)?;
    Ok(Prepared {
        root,
        workspace,
        operation,
    })
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    protocol: u32,
    request_id: String,
    ok: bool,
    result: Option<Value>,
    error: Option<WireError>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WireError {
    code: String,
}
fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, ClientError> {
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| ClientError::OutcomeUnknown)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(ClientError::OutcomeUnknown);
    }
    let mut payload = vec![0; length];
    stream
        .read_exact(&mut payload)
        .map_err(|_| ClientError::OutcomeUnknown)?;
    Ok(payload)
}
fn legacy_result(op: &str, value: Value) -> Result<Value, ClientError> {
    match op {
        "ingest" | "snapshot" => {
            let inserted = value
                .get("inserted")
                .and_then(Value::as_u64)
                .ok_or(ClientError::OutcomeUnknown)?;
            let duplicates = value
                .get("duplicates")
                .and_then(Value::as_u64)
                .ok_or(ClientError::OutcomeUnknown)?;
            if value.get("durable") != Some(&Value::Bool(true))
                || value.get("projection_ready") != Some(&Value::Bool(true))
            {
                return Err(ClientError::OutcomeUnknown);
            }
            Ok(json!({"inserted":inserted,"duplicates":duplicates}))
        }
        "search" => {
            if value.get("trust").and_then(Value::as_str) != Some("untrusted") {
                return Err(ClientError::OutcomeUnknown);
            }
            let hits = value
                .get("hits")
                .and_then(Value::as_array)
                .ok_or(ClientError::OutcomeUnknown)?;
            for hit in hits {
                let _: MemoryRecord =
                    serde_json::from_value(hit.clone()).map_err(|_| ClientError::OutcomeUnknown)?;
            }
            Ok(Value::Array(hits.clone()))
        }
        "export_page" => {
            let _: hermes_memory::broker_export::ExportPage =
                serde_json::from_value(value.clone()).map_err(|_| ClientError::OutcomeUnknown)?;
            Ok(value)
        }
        _ => Err(ClientError::Invalid("unknown operation")),
    }
}
fn exchange(
    stream: &mut (impl Read + Write),
    bytes: &[u8],
    id: &str,
    op: &str,
) -> Result<Value, ClientError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(ClientError::ResourceLimit);
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(bytes))
        .map_err(|_| ClientError::OutcomeUnknown)?;
    let payload = read_frame(stream)?;
    let response: Response =
        serde_json::from_slice(&payload).map_err(|_| ClientError::OutcomeUnknown)?;
    if response.protocol != 1
        || response.request_id != id
        || (response.ok && (response.error.is_some() || response.result.is_none()))
        || (!response.ok && (response.error.is_none() || response.result.is_some()))
    {
        return Err(ClientError::OutcomeUnknown);
    }
    let result = if response.ok {
        legacy_result(op, response.result.ok_or(ClientError::OutcomeUnknown)?)?
    } else {
        let error = response.error.ok_or(ClientError::OutcomeUnknown)?;
        if ![
            "invalid_request",
            "unsupported_version",
            "unauthorized",
            "resource_limit",
            "unavailable",
            "outcome_unknown",
            "unsupported",
        ]
        .contains(&error.code.as_str())
        {
            return Err(ClientError::OutcomeUnknown);
        }
        stream
            .write_all(b"HMACK001")
            .map_err(|_| ClientError::OutcomeUnknown)?;
        return Err(match error.code.as_str() {
            "unauthorized" => ClientError::Unauthorized,
            "unavailable" => ClientError::Unavailable,
            "outcome_unknown" => ClientError::OutcomeUnknown,
            "resource_limit" => ClientError::ResourceLimit,
            _ => ClientError::Rejected(error.code),
        });
    };
    // The current runtime requires this eight-byte ACK after full validation.
    stream
        .write_all(b"HMACK001")
        .map_err(|_| ClientError::OutcomeUnknown)?;
    Ok(result)
}
fn request_bytes(op: &str, body: &Value) -> Result<Vec<u8>, ClientError> {
    // One request per authenticated connection; fixed ID remains unambiguous.
    let bytes =
        serde_json::to_vec(&json!({"protocol":1,"request_id":"client","op":op,"body":body}))
            .map_err(|_| ClientError::Invalid("serialization"))?;
    if bytes.len() > MAX_FRAME {
        return Err(ClientError::ResourceLimit);
    }
    Ok(bytes)
}
#[cfg(windows)]
fn admission_error(error: io::Error) -> ClientError {
    if error.kind() == io::ErrorKind::PermissionDenied {
        ClientError::Unauthorized
    } else {
        ClientError::Unavailable
    }
}
#[cfg(windows)]
fn run(cli: Cli) -> Result<Value, ClientError> {
    let prepared = prepare(cli.command, io::stdin().lock())?;
    if let Operation::Request { op, body } = &prepared.operation {
        request_bytes(op, body)?;
    }
    let enrollment = match cli.enrollment {
        Some(path) => {
            hermes_memory::windows_enrollment::load_from_enrollment(&path, &prepared.root)
        }
        None => hermes_memory::windows_enrollment::load_for_root(&prepared.root),
    }
    .map_err(admission_error)?;
    if !enrollment.workspaces.contains(&prepared.workspace) {
        return Err(ClientError::Unauthorized);
    }
    execute(prepared, |op, body| {
        let bytes = request_bytes(op, &body)?;
        let mut stream = hermes_memory::windows_pipe::connect_authenticated(
            &enrollment.pipe,
            &enrollment.server_sid,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .map_err(admission_error)?;
        exchange(&mut stream, &bytes, "client", op)
    })
}
fn execute(
    prepared: Prepared,
    mut send: impl FnMut(&str, Value) -> Result<Value, ClientError>,
) -> Result<Value, ClientError> {
    match prepared.operation {
        Operation::Request { op, body } => send(op, body),
        Operation::Export { vault } => {
            let sessions = hermes_memory::client_export::render_markdown(
                &vault,
                &prepared.workspace,
                |request| {
                    let value = send("export_page", json!(request)).map_err(|error| {
                        hermes_memory::MemoryError::Io(io::Error::other(error.to_string()))
                    })?;
                    serde_json::from_value(value).map_err(Into::into)
                },
            )?;
            Ok(json!({"sessions":sessions}))
        }
    }
}
#[cfg(not(windows))]
fn run(_cli: Cli) -> Result<Value, ClientError> {
    Err(ClientError::Unsupported)
}
fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let display = matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            );
            let _ = error.print();
            std::process::exit(if display { 0 } else { 1 });
        }
    };
    match run(cli) {
        Ok(result) => {
            let mut stdout = io::stdout().lock();
            if serde_json::to_writer(&mut stdout, &result).is_err()
                || stdout.write_all(b"\n").is_err()
            {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("hermes-memory: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_results_preserve_legacy_stdout_and_ack_only_validated_replies() {
        struct Wire {
            input: io::Cursor<Vec<u8>>,
            written: Vec<u8>,
        }
        impl Read for Wire {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.input.read(b)
            }
        }
        impl Write for Wire {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.written.extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        for (op, result, expected) in [
            (
                "ingest",
                json!({"inserted":1,"duplicates":0,"durable":true,"projection_ready":true}),
                json!({"inserted":1,"duplicates":0}),
            ),
            (
                "snapshot",
                json!({"inserted":0,"duplicates":1,"durable":true,"projection_ready":true}),
                json!({"inserted":0,"duplicates":1}),
            ),
            ("search", json!({"hits":[],"trust":"untrusted"}), json!([])),
        ] {
            let payload = serde_json::to_vec(
                &json!({"protocol":1,"request_id":"r","ok":true,"result":result}),
            )
            .unwrap();
            let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
            bytes.extend(payload);
            let mut stream = Wire {
                input: io::Cursor::new(bytes),
                written: vec![],
            };
            let output = exchange(&mut stream, b"{}", "r", op).unwrap();
            assert_eq!(output, expected);
            assert!(stream.written.ends_with(b"HMACK001"));
        }
        for reply in [
            json!({"protocol":1,"request_id":"wrong","ok":true,"result":{}}),
            json!({"protocol":1,"request_id":"r","ok":true,"result":{"inserted":"bad"}}),
        ] {
            let payload = serde_json::to_vec(&reply).unwrap();
            let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
            bytes.extend(payload);
            let mut stream = Wire {
                input: io::Cursor::new(bytes),
                written: vec![],
            };
            assert!(exchange(&mut stream, b"{}", "r", "ingest").is_err());
            assert!(!stream.written.ends_with(b"HMACK001"));
        }
    }
    #[cfg(windows)]
    #[test]
    fn native_same_token_fixture_ingest_snapshot_search_export() {
        // Disposable same-token pipe: NOT SCM/protected-enrollment integration proof.
        use hermes_memory::windows_pipe::{bind, connect_authenticated};
        use std::time::{Duration, Instant};
        let output = std::process::Command::new("whoami.exe")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let sid = text
            .split('"')
            .find(|s| s.starts_with("S-1-"))
            .unwrap()
            .to_owned();
        let name = format!(r"\\.\pipe\HermesMemory.client-test-{}", std::process::id());
        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("server-store");
        let (tx, rx) = std::sync::mpsc::channel();
        let server_name = name.clone();
        let server_sid = sid.clone();
        let server = std::thread::spawn(move || {
            let store = hermes_memory::MemoryStore::open(db).unwrap();
            store.prepare_export_index().unwrap();
            let mut listener = bind(&server_name, &server_sid, &server_sid).unwrap();
            tx.send(()).unwrap();
            for _ in 0..4 {
                let mut stream = listener
                    .accept_authenticated(Instant::now() + Duration::from_secs(5))
                    .unwrap();
                let request: Value =
                    serde_json::from_slice(&read_frame(&mut stream).unwrap()).unwrap();
                let body = request["body"].clone();
                let result = match request["op"].as_str().unwrap() {
                    "ingest" => {
                        let records: Vec<MemoryRecord> =
                            serde_json::from_value(body["records"].clone()).unwrap();
                        let (inserted, duplicates) = store.ingest_many(&records).unwrap();
                        json!({"inserted":inserted,"duplicates":duplicates,"durable":true,"projection_ready":true})
                    }
                    "snapshot" => {
                        let request: SnapshotRequest = serde_json::from_value(body).unwrap();
                        let (inserted, duplicates) = store.ingest_snapshot(&request).unwrap();
                        json!({"inserted":inserted,"duplicates":duplicates,"durable":true,"projection_ready":true})
                    }
                    "search" => {
                        let request = SearchRequest {
                            query: body["query"].as_str().unwrap().into(),
                            workspace: body["workspace"].as_str().map(str::to_owned),
                            session_id: body["session_id"].as_str().map(str::to_owned),
                            limit: body["limit"].as_u64().unwrap() as usize,
                            max_bytes: body["max_bytes"].as_u64().unwrap() as usize,
                        };
                        json!({"hits":store.search(&request).unwrap(),"trust":"untrusted"})
                    }
                    "export_page" => {
                        let request = serde_json::from_value(body).unwrap();
                        json!(store.export_page(&request, "client").unwrap())
                    }
                    _ => panic!("unexpected fixture operation"),
                };
                let response=serde_json::to_vec(&json!({"protocol":1,"request_id":request["request_id"],"ok":true,"result":result})).unwrap();
                stream
                    .write_all(&(response.len() as u32).to_be_bytes())
                    .unwrap();
                stream.write_all(&response).unwrap();
                let mut ack = [0; 8];
                stream.read_exact(&mut ack).unwrap();
                assert_eq!(&ack, b"HMACK001");
            }
        });
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut send = |op: &str, body: Value| {
            let bytes = request_bytes(op, &body)?;
            let mut stream =
                connect_authenticated(&name, &sid, Instant::now() + Duration::from_secs(5))
                    .map_err(admission_error)?;
            exchange(&mut stream, &bytes, "client", op)
        };
        let client_root = temp.path().join("client-must-not-open");
        let ingest=prepare(Command::Ingest {root:client_root.clone()},br#"{"id":"a","session_id":"session","workspace":"work","kind":"user","content":"hello world","timestamp":1}"#.as_slice()).unwrap();
        assert_eq!(
            execute(ingest, &mut send).unwrap(),
            json!({"inserted":1,"duplicates":0})
        );
        let snapshot=prepare(Command::Snapshot {root:client_root.clone()},br#"{"session_id":"session","workspace":"work","items":[{"kind":"assistant","content":"hello again","timestamp":2}]}"#.as_slice()).unwrap();
        assert_eq!(
            execute(snapshot, &mut send).unwrap(),
            json!({"inserted":1,"duplicates":0})
        );
        let search = prepare(
            Command::Search {
                root: client_root.clone(),
                query: "hello".into(),
                workspace: Some("work".into()),
                session_id: None,
                limit: 8,
                max_bytes: 4096,
            },
            io::empty(),
        )
        .unwrap();
        assert_eq!(
            execute(search, &mut send)
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let vault = temp.path().join("vault");
        let export = prepare(
            Command::Export {
                root: client_root.clone(),
                vault: vault.clone(),
                workspace: Some("work".into()),
            },
            io::empty(),
        )
        .unwrap();
        assert_eq!(execute(export, &mut send).unwrap(), json!({"sessions":1}));
        assert!(vault.join("Index.md").is_file());
        assert!(!client_root.exists());
        server.join().unwrap();
    }
    #[test]
    fn bounded_stdin_and_mixed_scope_reject_before_any_dispatch() {
        assert_eq!(
            bounded_input(io::repeat(b'x').take(MAX_FRAME as u64))
                .unwrap()
                .len(),
            MAX_FRAME
        );
        assert!(matches!(
            bounded_input(io::repeat(b'x').take((MAX_FRAME + 1) as u64)),
            Err(ClientError::ResourceLimit)
        ));
        assert!(bounded_input([255].as_slice()).is_err());
        let input=br#"[{"id":"a","session_id":"s","workspace":"a","kind":"user","content":"hello","timestamp":1},{"id":"b","session_id":"s","workspace":"b","kind":"user","content":"hello","timestamp":1}]"#;
        assert!(matches!(
            prepare(
                Command::Ingest {
                    root: "never-open".into()
                },
                input.as_slice()
            ),
            Err(ClientError::Invalid("mixed workspace ingest is not atomic"))
        ));
    }
    #[test]
    fn legacy_commands_validate_before_connecting() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("never-created");
        for op in ["ingest", "snapshot"] {
            let args = ["hermes-memory", op, "--root", missing.to_str().unwrap()];
            let cli = Cli::try_parse_from(args).unwrap();
            assert!(prepare(cli.command, b"not JSON".as_slice()).is_err());
        }
        let cli = Cli::try_parse_from([
            "hermes-memory",
            "search",
            "--root",
            missing.to_str().unwrap(),
            "--query",
            "x",
        ])
        .unwrap();
        assert!(prepare(cli.command, std::io::empty()).is_err());
        assert!(!missing.exists());
        let args = [
            "hermes-memory",
            "--enrollment",
            "enrollment.json",
            "search",
            "--root",
            missing.to_str().unwrap(),
            "--query",
            "x",
            "--workspace",
            "work",
        ];
        let cli = Cli::try_parse_from(args).unwrap();
        assert_eq!(
            cli.enrollment.unwrap(),
            std::path::PathBuf::from("enrollment.json")
        );
        assert!(prepare(cli.command, std::io::empty()).is_ok());
    }
}
