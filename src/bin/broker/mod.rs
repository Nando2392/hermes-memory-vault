use std::io::{self, Read, Write};
pub const MAX_FRAME: usize = 8 * 1024 * 1024;
fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    r.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "resource_limit"));
    }
    let mut bytes = vec![0; length];
    r.read_exact(&mut bytes)?;
    Ok(bytes)
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    protocol: u32,
    request_id: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<WireError>,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WireError {
    code: ErrorCode,
}
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ErrorCode {
    InvalidRequest,
    ReservedWorkspace,
    UnsupportedVersion,
    Unauthorized,
    ResourceLimit,
    Unavailable,
    OutcomeUnknown,
    Unsupported,
}
impl ErrorCode {
    fn from_code(code: &str) -> Self {
        match code {
            "invalid_request" => Self::InvalidRequest,
            "reserved_workspace" => Self::ReservedWorkspace,
            "unsupported_version" => Self::UnsupportedVersion,
            "unauthorized" => Self::Unauthorized,
            "resource_limit" => Self::ResourceLimit,
            "outcome_unknown" => Self::OutcomeUnknown,
            "unsupported" => Self::Unsupported,
            _ => Self::Unavailable,
        }
    }
}
fn failure(id: String, code: &str) -> Response {
    Response {
        protocol: 1,
        request_id: id,
        ok: false,
        result: None,
        error: Some(WireError {
            code: ErrorCode::from_code(code),
        }),
    }
}
fn rejection(bytes: &[u8], code: &str) -> Response {
    // Correlation only: this value can never reach storage dispatch.
    let id = serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|v| {
            v.get("request_id")
                .and_then(|id| id.as_str())
                .filter(|id| id.len() <= 128)
                .map(str::to_owned)
        })
        .unwrap_or_default();
    failure(id, code)
}
fn dispatch(store: &hermes_memory::MemoryStore, request: protocol::Validated) -> Response {
    use protocol::Operation;
    use serde_json::json;
    let result = match request.operation {
        Operation::Ping => Ok(json!({"sqlite_version":rusqlite::version(),"sqlite_version_number":rusqlite::version_number(),"export_supported":false,"export_page_supported":true})),
        Operation::Ingest(records) => store.ingest_many(&records).map(|(inserted,duplicates)|json!({"inserted":inserted,"duplicates":duplicates,"durable":true,"projection_ready":true})).map_err(|_| "outcome_unknown"),
        Operation::Snapshot(snapshot) => store.ingest_snapshot(&snapshot).map(|(inserted,duplicates)|json!({"inserted":inserted,"duplicates":duplicates,"durable":true,"projection_ready":true})).map_err(|_| "outcome_unknown"),
        Operation::ExportPage(page) => store.export_page(&page, &request.request_id).map_err(|error| match error {
            hermes_memory::broker_export::ExportError::InvalidRequest => "invalid_request",
            hermes_memory::broker_export::ExportError::ResourceLimit => "resource_limit",
            _ => "unavailable",
        }).and_then(|page| serde_json::to_value(page).map_err(|_| "unavailable")),
        Operation::Search(search) => store.search(&search).map(|hits|json!({"hits":hits,"trust":"untrusted"})).map_err(|_| "unavailable"),
    };
    match result {
        Ok(result) => Response {
            protocol: 1,
            request_id: request.request_id,
            ok: true,
            result: Some(result),
            error: None,
        },
        Err(code) => failure(request.request_id, code),
    }
}
fn write_frame(w: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "resource_limit"));
    }
    w.write_all(&(bytes.len() as u32).to_be_bytes())?;
    w.write_all(bytes)
}
#[cfg(any(target_os = "linux", test))]
fn authenticate(peer: u32, expected: u32) -> Result<(), &'static str> {
    if peer == expected {
        Ok(())
    } else {
        Err("unauthorized")
    }
}
#[cfg(any(target_os = "linux", test))]
fn receive_authenticated(
    r: &mut impl Read,
    peer: u32,
    expected: u32,
) -> Result<Vec<u8>, &'static str> {
    authenticate(peer, expected)?;
    read_frame(r).map_err(|e| {
        if e.kind() == io::ErrorKind::InvalidData {
            "resource_limit"
        } else {
            "invalid_request"
        }
    })
}
#[cfg(any(target_os = "linux", test))]
fn send_authenticated(
    w: &mut impl Write,
    peer: u32,
    expected: u32,
    bytes: &[u8],
) -> Result<(), &'static str> {
    authenticate(peer, expected)?;
    write_frame(w, bytes).map_err(|_| "outcome_unknown")
}
#[cfg(any(target_os = "linux", test))]
fn service_identity(service: u32, client: u32) -> Result<(), &'static str> {
    if service == 0 || service == client || client == 0 {
        Err("unauthorized")
    } else {
        Ok(())
    }
}
#[cfg(any(target_os = "linux", test))]
fn protected_directory(
    owner: u32,
    mode: u32,
    service: u32,
    sticky_ancestor: bool,
) -> Result<(), &'static str> {
    if owner != 0 && owner != service {
        return Err("unauthorized");
    }
    if mode & 0o022 != 0 && !(sticky_ancestor && owner == 0 && mode & 0o1000 != 0) {
        return Err("unauthorized");
    }
    Ok(())
}
#[cfg(any(target_os = "linux", test))]
mod deadline;
#[cfg(target_os = "linux")]
pub mod linux;
mod protocol;
#[cfg(windows)]
pub mod windows;
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_store(root: &std::path::Path) -> hermes_memory::MemoryStore {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
            hermes_memory::MemoryStore::open_broker(root).unwrap()
        }
        #[cfg(not(target_os = "linux"))]
        {
            // No production fallback: only the portable business-method fixture.
            hermes_memory::MemoryStore::open(root).unwrap()
        }
    }
    #[test]
    fn store_dispatch_preserves_ingest_snapshot_search() {
        let dir = tempfile::tempdir().unwrap();
        let store = fixture_store(dir.path());
        let call = |op, body| {
            serde_json::to_value(dispatch(
                &store,
                protocol::decode(
                    &serde_json::to_vec(
                        &serde_json::json!({"protocol":1,"request_id":"r","op":op,"body":body}),
                    )
                    .unwrap(),
                    "sandbox",
                )
                .unwrap(),
            ))
            .unwrap()
        };
        let ingest = serde_json::json!({"records":[{"id":"a","session_id":"s","workspace":"sandbox","kind":"event","content":"tracerbullet","timestamp":1}]});
        assert_eq!(call("ingest", ingest.clone())["result"]["inserted"], 1);
        assert_eq!(call("ingest", ingest)["result"]["duplicates"], 1);
        let snapshot = serde_json::json!({"session_id":"snap","workspace":"sandbox","items":[{"kind":"message","content":"tracerbullet","timestamp":2}]});
        assert_eq!(call("snapshot", snapshot.clone())["result"]["inserted"], 1);
        assert_eq!(call("snapshot", snapshot)["result"]["inserted"], 0);
        assert_eq!(call("search",serde_json::json!({"query":"tracerbullet","workspace":"sandbox","limit":20,"max_bytes":4096}))["result"]["hits"].as_array().unwrap().len(),2);
        assert_eq!(
            call("ping", serde_json::json!({}))["result"]["sqlite_version"],
            rusqlite::version()
        );
    }
    #[test]
    fn export_page_dispatch_exact_envelope_and_scope() {
        let dir = tempfile::tempdir().unwrap();
        let store = fixture_store(dir.path());
        store.prepare_export_index().unwrap();
        for (id, workspace) in [("a", "sandbox"), ("b", "other")] {
            store
                .ingest(&hermes_memory::MemoryRecord {
                    id: id.into(),
                    session_id: "s".into(),
                    workspace: workspace.into(),
                    kind: "event".into(),
                    content: "雪\nquoted".into(),
                    timestamp: 1.0,
                    metadata: serde_json::json!({"nested":[true, 1]}),
                })
                .unwrap();
        }
        let id = "\"\n雪";
        let mut body =
            serde_json::json!({"workspace":"sandbox","max_records":256,"max_bytes":MAX_FRAME});
        let call = |body: serde_json::Value| {
            let bytes = serde_json::to_vec(
                &serde_json::json!({"protocol":1,"request_id":id,"op":"export_page","body":body}),
            )
            .unwrap();
            match protocol::decode(&bytes, "sandbox") {
                Ok(request) => dispatch(&store, request),
                Err(code) => rejection(&bytes, code),
            }
        };
        let response = call(body.clone());
        assert!(response.ok, "{response:?}");
        let wire = serde_json::to_vec(&response).unwrap();
        let result = response.result.unwrap();
        assert_eq!(result["records"].as_array().unwrap().len(), 1);
        assert_eq!(result["records"][0]["id"], "a");
        body["max_bytes"] = wire.len().into();
        assert_eq!(serde_json::to_vec(&call(body.clone())).unwrap(), wire);
        body["max_bytes"] = (wire.len() - 1).into();
        assert_eq!(
            serde_json::to_value(call(body.clone())).unwrap()["error"]["code"],
            "resource_limit"
        );
        body["workspace"] = "other".into();
        assert_eq!(
            serde_json::to_value(call(body)).unwrap()["error"]["code"],
            "unauthorized"
        );
    }
    #[test]
    fn export_page_dispatch_large_records_continuations_and_physical_limit() {
        let dir = tempfile::tempdir().unwrap();
        let store = fixture_store(dir.path());
        store.prepare_export_index().unwrap();
        let records: Vec<_> = (0..3)
            .map(|i| hermes_memory::MemoryRecord {
                id: format!("large{i}"),
                session_id: "s".into(),
                workspace: "sandbox".into(),
                kind: "event".into(),
                content: "x".repeat(1024 * 1024 + 1),
                timestamp: i as f64,
                metadata: serde_json::json!({"payload":"y".repeat(1024 * 1024 + 1)}),
            })
            .collect();
        store.ingest_many(&records).unwrap();
        let mut body =
            serde_json::json!({"workspace":"sandbox","max_records":256,"max_bytes":3*1024*1024});
        let call = |body: &serde_json::Value| {
            let bytes = serde_json::to_vec(&serde_json::json!({"protocol":1,"request_id":"large","op":"export_page","body":body})).unwrap();
            dispatch(&store, protocol::decode(&bytes, "sandbox").unwrap())
        };
        let projection = std::fs::read(dir.path().join("events.jsonl")).unwrap();
        let mut actual = Vec::new();
        loop {
            let response = call(&body);
            assert!(response.ok, "{response:?}");
            let bytes = serde_json::to_vec(&response).unwrap();
            assert!(bytes.len() <= body["max_bytes"].as_u64().unwrap() as usize);
            let mut frame = Vec::new();
            write_frame(&mut frame, &bytes).unwrap();
            let decoded: Response =
                serde_json::from_slice(&read_frame(&mut &frame[..]).unwrap()).unwrap();
            let page: hermes_memory::broker_export::ExportPage =
                serde_json::from_value(decoded.result.unwrap()).unwrap();
            assert_eq!(page.records.len(), 1);
            actual.extend(page.records);
            body["high_water"] = page.high_water.into();
            body["after"] = serde_json::to_value(&page.next).unwrap();
            if page.next.is_none() {
                break;
            }
        }
        assert_eq!(actual, records);
        assert_eq!(
            std::fs::read(dir.path().join("events.jsonl")).unwrap(),
            projection
        );
        body["after"] = serde_json::json!({"session_id":"other","timestamp":0,"rowid":1});
        assert_eq!(
            serde_json::to_value(call(&body)).unwrap()["error"]["code"],
            "invalid_request"
        );
        // A legacy-admitted row can fit raw storage but not its escaped wire envelope.
        let mut oversized = records[0].clone();
        oversized.id = "oversized".into();
        oversized.workspace = "oversized".into();
        oversized.content = "\n".repeat(MAX_FRAME / 2);
        oversized.metadata = serde_json::Value::Null;
        store.ingest(&oversized).unwrap();
        let bytes = serde_json::to_vec(&serde_json::json!({"protocol":1,"request_id":"r","op":"export_page","body":{"workspace":"oversized","max_records":256,"max_bytes":MAX_FRAME}})).unwrap();
        let response = dispatch(&store, protocol::decode(&bytes, "oversized").unwrap());
        assert_eq!(
            serde_json::to_value(response).unwrap()["error"]["code"],
            "resource_limit"
        );
    }
    #[test]
    fn export_page_capability_and_startup_preparation_contract() {
        let dir = tempfile::tempdir().unwrap();
        let store = fixture_store(dir.path());
        let ping = protocol::decode(
            br#"{"protocol":1,"request_id":"p","op":"ping","body":{}}"#,
            "sandbox",
        )
        .unwrap();
        let response = serde_json::to_value(dispatch(&store, ping)).unwrap();
        assert_eq!(response["result"]["export_supported"], false);
        assert_eq!(response["result"]["export_page_supported"], true);
        // Static startup ordering check complements CI real-service readiness proof.
        for (source, listener) in [
            (include_str!("windows.rs"), "let mut listener ="),
            (
                include_str!("linux.rs"),
                "let listener = UnixListener::bind",
            ),
        ] {
            let admission = source
                .find("let store = hermes_memory::MemoryStore::open_broker")
                .unwrap();
            let startup = &source[admission..];
            let prepare = startup
                .find("store.prepare_export_index()")
                .expect("startup must prepare before binding");
            assert!(prepare < startup.find(listener).unwrap());
            assert_eq!(source.matches("store.prepare_export_index()").count(), 1);
        }
    }
    #[test]
    fn export_page_rejects_malformed_and_never_prepares_on_dispatch() {
        let dir = tempfile::tempdir().unwrap();
        let store = fixture_store(dir.path());
        let valid =
            serde_json::json!({"workspace":"sandbox","max_records":1,"max_bytes":MAX_FRAME});
        let mut cases = vec![(valid.clone(), "unavailable")];
        for field in ["sql", "path", "root", "output"] {
            let mut body = valid.clone();
            body[field] = "forbidden".into();
            cases.push((body, "invalid_request"));
        }
        let mut body = valid.clone();
        body["workspace"] = "other".into();
        cases.push((body, "unauthorized"));
        let mut body = valid.clone();
        body["max_bytes"] = (MAX_FRAME + 1).into();
        cases.push((body, "resource_limit"));
        let mut body = valid.clone();
        body["max_records"] = 257.into();
        cases.push((body, "resource_limit"));
        let mut body = valid;
        body["after"] = serde_json::json!({"session_id":"s","timestamp":1,"rowid":1,"sql":"x"});
        cases.push((body, "invalid_request"));
        for (body, code) in cases {
            let bytes = serde_json::to_vec(
                &serde_json::json!({"protocol":1,"request_id":"r","op":"export_page","body":body}),
            )
            .unwrap();
            let response = match protocol::decode(&bytes, "sandbox") {
                Ok(request) => dispatch(&store, request),
                Err(code) => rejection(&bytes, code),
            };
            let response = serde_json::to_value(response).unwrap();
            assert_eq!(response["error"]["code"], code);
            assert!(response.get("result").is_none());
        }
        let db = rusqlite::Connection::open(dir.path().join("memory.db")).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='records_export_order'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
    #[test]
    fn writes_bounded_big_endian_frame() {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"ping").unwrap();
        assert_eq!(wire, b"\0\0\0\x04ping");
        assert!(write_frame(&mut wire, &vec![0; MAX_FRAME + 1]).is_err());
    }
    #[test]
    fn authenticates_before_any_wire_io_both_directions() {
        struct Never;
        impl Read for Never {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("unauthorized read");
            }
        }
        impl Write for Never {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                panic!("unauthorized write");
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(
            receive_authenticated(&mut Never, 3, 2).unwrap_err(),
            "unauthorized"
        );
        assert_eq!(
            send_authenticated(&mut Never, 3, 2, b"secret").unwrap_err(),
            "unauthorized"
        );
        let mut wire = Vec::new();
        send_authenticated(&mut wire, 2, 2, b"ping").unwrap();
        assert_eq!(
            receive_authenticated(&mut &wire[..], 2, 2).unwrap(),
            b"ping"
        );
    }
    #[test]
    fn rejects_unprotected_service_identity_and_namespace() {
        assert!(service_identity(0, 2).is_err());
        assert!(service_identity(2, 2).is_err());
        assert!(service_identity(1, 2).is_ok());
        assert!(protected_directory(2, 0o755, 1, false).is_err());
        assert!(protected_directory(1, 0o777, 1, false).is_err());
        assert!(protected_directory(0, 0o1777, 1, false).is_err());
        assert!(protected_directory(0, 0o1777, 1, true).is_ok());
        assert!(protected_directory(1, 0o755, 1, false).is_ok());
    }
    #[test]
    fn projection_failure_reports_unknown_without_claiming_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let store = fixture_store(dir.path());
        // The canonical transaction commits before the existing projection lock opens.
        std::fs::remove_file(dir.path().join("events.jsonl.lock")).unwrap();
        std::fs::create_dir(dir.path().join("events.jsonl.lock")).unwrap();
        let request=protocol::decode(br#"{"protocol":1,"request_id":"r","op":"ingest","body":{"records":[{"id":"postcommit","session_id":"s","workspace":"sandbox","kind":"event","content":"committedtracer","timestamp":1}]}}"#,"sandbox").unwrap();
        let result = serde_json::to_value(dispatch(&store, request)).unwrap();
        assert_eq!(result["error"]["code"], "outcome_unknown");
        assert_eq!(result["ok"], false);
        assert!(result.get("result").is_none());
        let hits = store
            .search(&hermes_memory::SearchRequest {
                query: "committedtracer".into(),
                workspace: Some("sandbox".into()),
                session_id: None,
                limit: 1,
                max_bytes: 4096,
            })
            .unwrap();
        assert_eq!(hits.len(), 1);
    }
    #[test]
    fn invalid_envelope_keeps_only_bounded_correlation_id() {
        let bytes = br#"{"protocol":1,"request_id":"r1","op":"ping","body":{},"root":"forbidden"}"#;
        assert!(protocol::decode(bytes, "sandbox").is_err());
        let response = serde_json::to_value(rejection(bytes, "invalid_request")).unwrap();
        assert_eq!(response["request_id"], "r1");
        assert_eq!(response["error"]["code"], "invalid_request");
        assert!(!response.to_string().contains("forbidden"));
    }
    #[test]
    fn truncated_frames_never_return_partial_payload() {
        for bytes in [&b"\0\0"[..], &b"\0\0\0\x04pi"[..]] {
            assert_eq!(
                read_frame(&mut &bytes[..]).unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }
    #[test]
    fn authenticated_oversized_frame_has_resource_limit_code() {
        let header = ((MAX_FRAME + 1) as u32).to_be_bytes();
        assert_eq!(
            receive_authenticated(&mut &header[..], 2, 2).unwrap_err(),
            "resource_limit"
        );
    }
    #[test]
    fn oversized_header_rejected_before_payload_read() {
        let bytes = ((MAX_FRAME + 1) as u32).to_be_bytes();
        assert_eq!(
            read_frame(&mut &bytes[..]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    #[test]
    fn reads_big_endian_frame() {
        assert_eq!(read_frame(&mut &b"\0\0\0\x04ping"[..]).unwrap(), b"ping");
    }
}
