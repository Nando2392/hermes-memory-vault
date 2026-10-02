use hermes_memory::workspace_policy::{valid_root_key, validate_workspace, Policy, ScopeMode};
use serde::Deserialize;
use serde_json::Value;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: u32,
    pub request_id: String,
    pub op: String,
    pub body: Value,
    #[serde(default)]
    pub policy: Option<Policy>,
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
fn scope(actual: &str, expected: &str, mode: ScopeMode) -> Result<(), &'static str> {
    hermes_memory::workspace_policy::validate_workspace(actual)?;
    if mode == ScopeMode::VaultOwner || actual == expected {
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
#[cfg(any(target_os = "linux", test))]
pub fn decode(bytes: &[u8], workspace: &str) -> Result<Validated, &'static str> {
    decode_with_policy(bytes, workspace, ScopeMode::Fixed, None)
}
pub fn decode_with_policy(
    bytes: &[u8],
    workspace: &str,
    mode: ScopeMode,
    key: Option<&str>,
) -> Result<Validated, &'static str> {
    validate_workspace(workspace)?;
    if key.is_some_and(|k| !valid_root_key(k)) || (mode == ScopeMode::VaultOwner && key.is_none()) {
        return Err("unauthorized");
    }
    if bytes.len() > super::MAX_FRAME {
        return Err("resource_limit");
    }
    let r: Request = serde_json::from_slice(bytes).map_err(|_| "invalid_request")?;
    if r.protocol != 1 {
        return Err("unsupported_version");
    }
    match (key, r.policy.as_ref()) {
        (None, None) if mode == ScopeMode::Fixed => {}
        (Some(expected), Some(pin))
            if pin.scope_mode == mode && pin.legacy_root_key == expected => {}
        _ => return Err("unauthorized"),
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
            let first = records
                .records
                .first()
                .ok_or("invalid_request")?
                .workspace
                .clone();
            let mut validated = Vec::new();
            for r in records.records {
                scope(&r.workspace, workspace, mode)?;
                if r.workspace != first {
                    return Err("unauthorized");
                }
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
            scope(&s.workspace, workspace, mode)?;
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
            scope(&s.workspace, workspace, mode)?;
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
            scope(&page.workspace, workspace, mode)?;
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
    fn every_operation_retains_fixed_boundary_and_owner_explicit_scope() {
        for workspace in ["plain".to_owned(), "🌍".repeat(128)] {
            for (op, body) in [
                (
                    "ingest",
                    serde_json::json!({"records":[{"id":"a","session_id":"s","workspace":workspace,"kind":"event","content":"x","timestamp":0}]}),
                ),
                (
                    "snapshot",
                    serde_json::json!({"session_id":"s","workspace":workspace,"items":[]}),
                ),
                (
                    "search",
                    serde_json::json!({"workspace":workspace,"query":"x","limit":1,"max_bytes":100}),
                ),
                (
                    "export_page",
                    serde_json::json!({"workspace":workspace,"max_records":1,"max_bytes":10000}),
                ),
            ] {
                let request =
                    serde_json::json!({"protocol":1,"request_id":"r","op":op,"body":body});
                let bytes = serde_json::to_vec(&request).unwrap();
                assert!(decode(&bytes, &workspace).is_ok());
                assert_eq!(decode(&bytes, "different").unwrap_err(), "unauthorized");
                let mut pinned = request.clone();
                pinned["policy"] = serde_json::json!({"scope_mode":"vault-owner","legacy_root_key":"a".repeat(64)});
                assert!(decode_with_policy(
                    &serde_json::to_vec(&pinned).unwrap(),
                    "initial",
                    ScopeMode::VaultOwner,
                    Some(&"a".repeat(64))
                )
                .is_ok());
                assert!(
                    decode(&serde_json::to_vec(&pinned).unwrap(), &workspace).is_err(),
                    "request cannot widen legacy fixed"
                );
                for field in ["root", "sql", "path", "scope_mode"] {
                    let mut bad = pinned.clone();
                    bad["body"][field] = serde_json::json!("evil");
                    assert!(decode_with_policy(
                        &serde_json::to_vec(&bad).unwrap(),
                        "initial",
                        ScopeMode::VaultOwner,
                        Some(&"a".repeat(64))
                    )
                    .is_err());
                }
            }
        }
    }
    #[test]
    fn owner_requires_matching_pins_and_one_explicit_workspace() {
        use hermes_memory::workspace_policy::ScopeMode;
        let key = "a".repeat(64);
        let policy = Policy {
            scope_mode: ScopeMode::VaultOwner,
            legacy_root_key: key.clone(),
        };
        let mut request = serde_json::json!({"protocol":1,"request_id":"r","op":"search","policy":{"scope_mode":"vault-owner","legacy_root_key":key},"body":{"workspace":"🌍".repeat(128),"query":"x","limit":1,"max_bytes":100}});
        let decode_owner = |r: &Value| {
            decode_with_policy(
                &serde_json::to_vec(r).unwrap(),
                "initial",
                ScopeMode::VaultOwner,
                Some(&policy.legacy_root_key),
            )
        };
        assert!(decode_owner(&request).is_ok());
        for field in ["scope_mode", "legacy_root_key"] {
            let mut bad = request.clone();
            bad["policy"].as_object_mut().unwrap().remove(field);
            assert!(decode_owner(&bad).is_err());
        }
        for pin in [
            serde_json::Value::Null,
            serde_json::json!({"scope_mode":"fixed","legacy_root_key":key}),
            serde_json::json!({"scope_mode":"vault-owner","legacy_root_key":"b".repeat(64)}),
            serde_json::json!({"scope_mode":"unknown","legacy_root_key":key}),
        ] {
            let mut bad = request.clone();
            bad["policy"] = pin;
            assert!(decode_owner(&bad).is_err());
        }
        for workspace in [
            "",
            "*",
            "a/b",
            "redacted-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            request["body"]["workspace"] = serde_json::json!(workspace);
            assert!(decode_owner(&request).is_err());
        }
        request["body"]["workspace"] = serde_json::json!("beta");
        request["body"]["scope_mode"] = serde_json::json!("vault-owner");
        assert!(decode_owner(&request).is_err());
        request["body"]
            .as_object_mut()
            .unwrap()
            .remove("scope_mode");
        assert!(decode_with_policy(
            &serde_json::to_vec(&request).unwrap(),
            "initial",
            ScopeMode::Fixed,
            Some(&key)
        )
        .is_err());
        assert!(decode_with_policy(
            &serde_json::to_vec(&request).unwrap(),
            "initial",
            ScopeMode::VaultOwner,
            None
        )
        .is_err());
        request["op"] = serde_json::json!("ingest");
        request["body"] = serde_json::json!({"records":[{"id":"a","session_id":"s","workspace":"a","kind":"event","content":"x","timestamp":0},{"id":"b","session_id":"s","workspace":"b","kind":"event","content":"x","timestamp":0}]});
        assert!(decode_owner(&request).is_err());
    }
    #[test]
    fn reserved_canonical_workspace_cannot_alias_raw_secret() {
        let secret = "token=abcdefghijklmnopqrstuvwxyz123456";
        use sha2::{Digest, Sha256};
        let canonical = format!("redacted-{:x}", Sha256::digest(secret.as_bytes()));
        assert!(canonical.starts_with("redacted-"));
        for workspace in [
            canonical,
            "*".into(),
            "a/b".into(),
            " a".into(),
            "x".repeat(129),
        ] {
            let bytes = serde_json::to_vec(&serde_json::json!({"protocol":1,"request_id":"r","op":"search","body":{"workspace":workspace,"query":"x","limit":1,"max_bytes":10}})).unwrap();
            assert!(
                decode(&bytes, &workspace).is_err(),
                "must reject {workspace}"
            );
        }
        for workspace in [secret.to_string(), "🌍".repeat(128), "alpha".into()] {
            let bytes = serde_json::to_vec(&serde_json::json!({"protocol":1,"request_id":"r","op":"search","body":{"workspace":workspace,"query":"x","limit":1,"max_bytes":10}})).unwrap();
            assert!(decode(&bytes, &workspace).is_ok());
        }
    }
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
