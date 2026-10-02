use serde::Deserialize;
use serde_json::Value;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: u32,
    pub request_id: String,
    pub op: String,
    pub body: Value,
}
#[derive(Debug)]
pub struct Validated {
    pub request_id: String,
    pub operation: Operation,
}
#[derive(Debug)]
pub enum Operation {
    Ping,
    ExportPage(hermes_memory::broker_export::ExportPageRequest),
    Ingest(Vec<hermes_memory::MemoryRecord>),
    Snapshot(hermes_memory::SnapshotRequest),
    Search(hermes_memory::SearchRequest),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Records {
    records: Vec<Record>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    id: String,
    session_id: String,
    workspace: String,
    kind: String,
    content: String,
    timestamp: f64,
    #[serde(default)]
    metadata: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Search {
    query: String,
    workspace: String,
    session_id: Option<String>,
    limit: usize,
    max_bytes: usize,
}
fn typed<T: serde::de::DeserializeOwned>(body: Value) -> Result<T, &'static str> {
    serde_json::from_value(body).map_err(|_| "invalid_request")
}
fn text(s: &str, max: usize) -> Result<(), &'static str> {
    if s.trim().is_empty() {
        Err("invalid_request")
    } else if s.len() > max {
        Err("resource_limit")
    } else {
        Ok(())
    }
}
fn scope(actual: &str, expected: &str) -> Result<(), &'static str> {
    if actual == expected {
        Ok(())
    } else {
        Err("unauthorized")
    }
}
fn timestamp(t: f64) -> Result<(), &'static str> {
    if t.is_finite() && (0.0..=253402300799.0).contains(&t) {
        Ok(())
    } else {
        Err("invalid_request")
    }
}
pub fn decode(bytes: &[u8], workspace: &str) -> Result<Validated, &'static str> {
    if bytes.len() > super::MAX_FRAME {
        return Err("resource_limit");
    }
    let r: Request = serde_json::from_slice(bytes).map_err(|_| "invalid_request")?;
    if r.protocol != 1 {
        return Err("unsupported_version");
    }
    text(&r.request_id, 128)?;
    let operation = match r.op.as_str() {
        "ping" => {
            let _: Empty = typed(r.body)?;
            Operation::Ping
        }
        "ingest" => {
            let records: Records = typed(r.body)?;
            if records.records.len() > 1024 {
                return Err("resource_limit");
            }
            let mut validated = Vec::new();
            for r in records.records {
                scope(&r.workspace, workspace)?;
                for s in [&r.id, &r.session_id, &r.kind] {
                    text(s, 256)?;
                }
                if r.content.len() > 1024 * 1024 {
                    return Err("resource_limit");
                }
                timestamp(r.timestamp)?;
                validated.push(hermes_memory::MemoryRecord {
                    id: r.id,
                    session_id: r.session_id,
                    workspace: r.workspace,
                    kind: r.kind,
                    content: r.content,
                    timestamp: r.timestamp,
                    metadata: r.metadata,
                });
            }
            Operation::Ingest(validated)
        }
        "snapshot" => {
            let s: hermes_memory::SnapshotRequest = typed(r.body)?;
            scope(&s.workspace, workspace)?;
            text(&s.session_id, 256)?;
            if s.items.len() > 1024 {
                return Err("resource_limit");
            }
            for item in &s.items {
                text(&item.kind, 256)?;
                timestamp(item.timestamp)?;
                if item.content.len() > 1024 * 1024 {
                    return Err("resource_limit");
                }
            }
            Operation::Snapshot(s)
        }
        "search" => {
            let s: Search = typed(r.body)?;
            scope(&s.workspace, workspace)?;
            text(&s.query, 4096)?;
            if let Some(ref session) = s.session_id {
                text(session, 256)?;
            }
            if !(1..=20).contains(&s.limit) || !(1..=65536).contains(&s.max_bytes) {
                return Err("resource_limit");
            }
            Operation::Search(hermes_memory::SearchRequest {
                query: s.query,
                workspace: Some(s.workspace),
                session_id: s.session_id,
                limit: s.limit,
                max_bytes: s.max_bytes,
            })
        }
        "export_page" => {
            let page: hermes_memory::broker_export::ExportPageRequest = typed(r.body)?;
            scope(&page.workspace, workspace)?;
            Operation::ExportPage(page)
        }
        "export" => return Err("unsupported"),
        _ => return Err("invalid_request"),
    };
    Ok(Validated {
        request_id: r.request_id,
        operation,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_typed_scoped_operation_contract() {
        for (op, body, code) in [
            ("export", serde_json::json!({}), "unsupported"),
            ("ping", serde_json::json!({"sql":"x"}), "invalid_request"),
            (
                "search",
                serde_json::json!({"query":"x","workspace":"other","limit":1,"max_bytes":10}),
                "unauthorized",
            ),
            (
                "search",
                serde_json::json!({"query":"x","workspace":"sandbox","limit":21,"max_bytes":10}),
                "resource_limit",
            ),
            (
                "ingest",
                serde_json::json!({"records":[{"id":"a","session_id":"s","workspace":"sandbox","kind":"event","content":"c","timestamp":0,"sql":"x"}]}),
                "invalid_request",
            ),
            (
                "ingest",
                serde_json::json!({"records":[{"id":"a","session_id":"s","workspace":"sandbox","kind":"event","content":"c","timestamp":-1}]}),
                "invalid_request",
            ),
        ] {
            let bytes = serde_json::to_vec(
                &serde_json::json!({"protocol":1,"request_id":"r","op":op,"body":body}),
            )
            .unwrap();
            assert_eq!(decode(&bytes, "sandbox").unwrap_err(), code);
        }
        assert_eq!(
            decode(
                br#"{"protocol":2,"request_id":"r","op":"ping","body":{}}"#,
                "sandbox"
            )
            .unwrap_err(),
            "unsupported_version"
        );
        assert!(decode(
            br#"{"protocol":1,"request_id":"r","op":"ping","body":{}}"#,
            "sandbox"
        )
        .is_ok());
    }
    #[test]
    fn rejects_unknown_envelope_fields() {
        assert!(decode(
            br#"{"protocol":1,"request_id":"r","op":"ping","body":{},"root":"evil"}"#,
            "sandbox"
        )
        .is_err());
    }
}
