mod support;

use hermes_memory::{
    broker_export::{ExportCursor, ExportPage},
    client_export::render_markdown,
    MemoryRecord,
};

fn record(id: &str, session: &str, timestamp: f64) -> MemoryRecord {
    MemoryRecord {
        id: id.into(),
        session_id: session.into(),
        workspace: "work".into(),
        kind: "user".into(),
        content: "你好\n[redacted]\n# untrusted".into(),
        timestamp,
        metadata: serde_json::json!({"preserved":"but not rendered"}),
    }
}
fn cursor(session: &str, timestamp: f64, rowid: i64) -> ExportCursor {
    ExportCursor {
        session_id: session.into(),
        timestamp,
        rowid,
    }
}
fn files(root: &std::path::Path) -> std::collections::BTreeMap<std::path::PathBuf, String> {
    fn collect(
        root: &std::path::Path,
        current: &std::path::Path,
        out: &mut std::collections::BTreeMap<std::path::PathBuf, String>,
    ) {
        for entry in std::fs::read_dir(current).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(root, &path, out);
            } else if path.extension().is_some_and(|v| v == "md") {
                out.insert(
                    path.strip_prefix(root).unwrap().into(),
                    std::fs::read_to_string(path).unwrap(),
                );
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    collect(root, root, &mut out);
    out
}
#[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
#[test]
fn multiple_pages_spanning_sessions_match_legacy_bytes() {
    let temp = tempfile::tempdir().unwrap();
    // Synthetic local store is only an oracle for the legacy format, not used by the client.
    let store = support::open_store(temp.path().join("oracle")).unwrap();
    let records = vec![
        record("a", "s[一]", 1.0),
        record("b", "s[一]", 2.0),
        record("c", "z", 3.0),
    ];
    store.ingest_many(&records).unwrap();
    store
        .export_markdown(temp.path().join("expected"), Some("work"))
        .unwrap();
    let mut pages = vec![
        ExportPage {
            records: vec![records[0].clone()],
            next: Some(cursor("s[一]", 1.0, 1)),
            high_water: 3,
        },
        ExportPage {
            records: vec![records[1].clone()],
            next: Some(cursor("s[一]", 2.0, 2)),
            high_water: 3,
        },
        ExportPage {
            records: vec![records[2].clone()],
            next: None,
            high_water: 3,
        },
    ]
    .into_iter();
    let mut call = 0;
    assert_eq!(
        render_markdown(&temp.path().join("actual"), "work", |req| {
            if call > 0 {
                assert_eq!(req.high_water, Some(3));
                assert_eq!(req.after, Some(cursor("s[一]", call as f64, call)));
            }
            call += 1;
            Ok(pages.next().unwrap())
        })
        .unwrap(),
        2
    );
    assert_eq!(call, 3);
    assert_eq!(
        files(&temp.path().join("actual")),
        files(&temp.path().join("expected"))
    );
}

#[test]
fn invalid_continuation_never_publishes_partial_session_or_index() {
    for case in [
        "high_water",
        "cursor",
        "empty_loop",
        "scope",
        "order",
        "source_error",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let vault = temp.path().join("vault");
        std::fs::create_dir(&vault).unwrap();
        std::fs::write(vault.join("Index.md"), "old index").unwrap();
        let mut calls = 0;
        let result = render_markdown(&vault, "work", |_| {
            calls += 1;
            if calls == 1 {
                return Ok(ExportPage {
                    records: vec![record("a", "s", 1.0)],
                    next: Some(cursor("s", 1.0, 1)),
                    high_water: 3,
                });
            }
            if case == "source_error" {
                return Err(std::io::Error::other("fixture unavailable").into());
            }
            let mut page = ExportPage {
                records: vec![record("b", "s", 2.0)],
                next: None,
                high_water: 3,
            };
            match case {
                "high_water" => page.high_water = 2,
                "cursor" => page.next = Some(cursor("s", 1.0, 1)),
                "empty_loop" => {
                    page.records.clear();
                    page.next = Some(cursor("s", 1.0, 1));
                }
                "scope" => page.records[0].workspace = "other".into(),
                "order" => page.records[0].timestamp = 0.0,
                _ => unreachable!(),
            }
            assert!(calls < 4, "invalid cursor loop must be rejected");
            Ok(page)
        });
        assert!(result.is_err(), "{case} must fail");
        let output = files(&vault);
        assert_eq!(output.len(), 1, "{case}: incomplete session published");
        assert_eq!(output.values().next().unwrap(), "old index");
    }
}

#[cfg(feature = "experimental-broker")]
#[test]
fn binary_missing_enrollment_fails_closed_without_creating_store() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("missing-root");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_hermes-memory-client"))
        .args([
            "search",
            "--root",
            root.to_str().unwrap(),
            "--query",
            "hello",
            "--workspace",
            "work",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
    assert!(!root.exists());
}

#[test]
fn capability_output_never_follows_hardlinked_destination() {
    let temp = tempfile::tempdir().unwrap();
    let vault = temp.path().join("vault");
    std::fs::create_dir(&vault).unwrap();
    let external = temp.path().join("external.md");
    std::fs::write(&external, "untouched").unwrap();
    std::fs::hard_link(&external, vault.join("Index.md")).unwrap();
    render_markdown(&vault, "work", |_| {
        Ok(ExportPage {
            records: vec![],
            next: None,
            high_water: 0,
        })
    })
    .unwrap();
    assert_eq!(std::fs::read_to_string(external).unwrap(), "untouched");
    assert!(std::fs::read_to_string(vault.join("Index.md"))
        .unwrap()
        .contains("No sessions"));
}

#[cfg(any(windows, unix))]
#[test]
fn capability_output_rejects_symlink_directory() {
    let temp = tempfile::tempdir().unwrap();
    let vault = temp.path().join("vault");
    std::fs::create_dir(&vault).unwrap();
    let external = temp.path().join("external");
    std::fs::create_dir(&external).unwrap();
    #[cfg(windows)]
    {
        // Same unprivileged junction fixture as the existing memory tests.
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(vault.join("Sessions"))
            .arg(&external)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&external, vault.join("Sessions")).unwrap();
    assert!(render_markdown(&vault, "work", |_| Ok(ExportPage {
        records: vec![record("a", "s", 1.0)],
        next: None,
        high_water: 1
    }))
    .is_err());
    assert_eq!(std::fs::read_dir(external).unwrap().count(), 0);
}

#[cfg(all(windows, feature = "experimental-broker"))]
#[test]
fn binary_custom_enrollment_has_no_ordinary_user_trust_bypass() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("no-store");
    let enrollment = temp.path().join("unprotected.json");
    std::fs::write(&enrollment, b"{}").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_hermes-memory-client"))
        .args([
            "export",
            "--root",
            root.to_str().unwrap(),
            "--vault",
            temp.path().join("no-vault").to_str().unwrap(),
            "--workspace",
            "work",
            "--enrollment",
            enrollment.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!root.exists());
    assert!(!temp.path().join("no-vault").exists());
}

#[test]
fn zero_high_water_with_records_is_rejected_before_output() {
    let temp = tempfile::tempdir().unwrap();
    let vault = temp.path().join("absent");
    assert!(render_markdown(&vault, "work", |_| Ok(ExportPage {
        records: vec![record("a", "s", 1.0)],
        next: None,
        high_water: 0
    }))
    .is_err());
    assert!(!vault.exists());
}

#[cfg(feature = "experimental-broker")]
#[test]
fn binary_mutations_never_fall_back_to_local_store() {
    use std::io::Write;
    for (op, input) in [
        (
            "ingest",
            r#"{"id":"a","session_id":"s","workspace":"work","kind":"user","content":"hello","timestamp":1}"#,
        ),
        (
            "snapshot",
            r#"{"session_id":"s","workspace":"work","items":[{"kind":"user","content":"hello","timestamp":1}]}"#,
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("absent");
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_hermes-memory-client"))
            .args([op, "--root", root.to_str().unwrap()])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert!(result.stdout.is_empty());
        assert!(!root.exists());
    }
}

#[test]
fn empty_export_streams_legacy_index() {
    let temp = tempfile::tempdir().unwrap();
    let vault = temp.path().join("vault");
    let count = render_markdown(&vault, "work", |request| {
        assert_eq!(request.workspace, "work");
        assert!(request.high_water.is_none());
        assert!(request.after.is_none());
        assert_eq!(request.max_records, 256);
        assert_eq!(request.max_bytes, 8 * 1024 * 1024);
        Ok(ExportPage {
            records: vec![],
            next: None,
            high_water: 0,
        })
    })
    .unwrap();
    assert_eq!(count, 0);
    assert_eq!(
        std::fs::read_to_string(vault.join("Index.md")).unwrap(),
        "# Hermes Memory Vault\n\n_No sessions indexed._\n"
    );
}
