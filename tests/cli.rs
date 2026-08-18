use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn run_with_stdin(args: &[&str], input: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hermes-memory"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hermes-memory");
    let write_result = child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes());
    if let Err(error) = write_result {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe,
            "write stdin: {error}"
        );
    }
    child.wait_with_output().expect("wait for hermes-memory")
}

#[test]
fn cli_help_exits_successfully() {
    for args in [&["--help"][..], &["search", "--help"][..]] {
        let output = Command::new(env!("CARGO_BIN_EXE_hermes-memory"))
            .args(args)
            .output()
            .expect("run help");
        assert!(
            output.status.success(),
            "help failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
    }
}

#[test]
fn cli_version_exits_successfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_hermes-memory"))
        .arg("--version")
        .output()
        .expect("run version");

    assert!(
        output.status.success(),
        "version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        concat!("hermes-memory ", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn cli_ingest_and_search_exchange_json() {
    let temp = tempdir().expect("temp dir");
    let root = temp.path().to_string_lossy().to_string();
    let record = json!({
        "id": "cli-1",
        "session_id": "session-cli",
        "workspace": "repo-cli",
        "kind": "assistant",
        "content": "Rust CLI bridge remembers this",
        "timestamp": 1787000000.0,
        "metadata": {"surface": "desktop"}
    });
    let ingest = run_with_stdin(&["ingest", "--root", &root], &record.to_string());
    assert!(
        ingest.status.success(),
        "{}",
        String::from_utf8_lossy(&ingest.stderr)
    );
    let ingest_json: Value = serde_json::from_slice(&ingest.stdout).expect("ingest JSON");
    assert_eq!(ingest_json["inserted"], 1);

    let search = Command::new(env!("CARGO_BIN_EXE_hermes-memory"))
        .args([
            "search",
            "--root",
            &root,
            "--query",
            "CLI remembers",
            "--workspace",
            "repo-cli",
            "--limit",
            "5",
            "--max-bytes",
            "2048",
        ])
        .output()
        .expect("search");
    assert!(
        search.status.success(),
        "{}",
        String::from_utf8_lossy(&search.stderr)
    );
    let hits: Value = serde_json::from_slice(&search.stdout).expect("search JSON");
    assert_eq!(hits.as_array().expect("array").len(), 1);
    assert_eq!(hits[0]["id"], "cli-1");
}

#[test]
fn cli_rejects_missing_required_arguments_without_partial_write() {
    let temp = tempdir().expect("temp dir");
    for (index, command, expected) in [
        (0, "search", "--query"),
        (1, "export", "--vault"),
        (2, "unknown", "unrecognized subcommand"),
    ] {
        let root_path = temp.path().join(format!("store-{index}"));
        let root = root_path.to_string_lossy().to_string();
        let output = Command::new(env!("CARGO_BIN_EXE_hermes-memory"))
            .args([command, "--root", &root])
            .output()
            .expect("invalid command");
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
        assert!(!root_path.exists(), "invalid {command} created the store");
    }

    for (index, input) in [
        (3, "not-json".to_owned()),
        (
            4,
            json!([
                {
                    "id": "would-be-partial",
                    "session_id": "session-invalid",
                    "workspace": "repo-invalid",
                    "kind": "user",
                    "content": "must not persist",
                    "timestamp": 1.0
                },
                {
                    "id": "",
                    "session_id": "session-invalid",
                    "workspace": "repo-invalid",
                    "kind": "user",
                    "content": "invalid empty id",
                    "timestamp": 2.0
                }
            ])
            .to_string(),
        ),
    ] {
        let root_path = temp.path().join(format!("store-{index}"));
        let root = root_path.to_string_lossy().to_string();
        let output = run_with_stdin(&["ingest", "--root", &root], &input);
        assert!(!output.status.success());
        assert!(!root_path.exists(), "invalid ingest created the store");
    }
}

#[test]
fn cli_rejects_ambiguous_or_unsafe_arguments_before_opening_store() {
    let temp = tempdir().expect("temp dir");
    let invalid_export_target = temp.path().join("vault-is-a-file");
    std::fs::write(&invalid_export_target, b"not a directory").expect("write invalid vault");
    let valid_record = json!({
        "id": "valid-id",
        "session_id": "valid-session",
        "workspace": "valid-workspace",
        "kind": "user",
        "content": "valid content",
        "timestamp": 1.0
    })
    .to_string();
    let invalid_snapshot = json!({
        "session_id": "valid-session",
        "workspace": "valid-workspace",
        "items": [{
            "fingerprint": "caller-controlled",
            "kind": "user",
            "content": "valid content",
            "timestamp": 1.0
        }]
    })
    .to_string();

    for (index, extra_args, stdin) in [
        (0, vec!["search", "--query", "x", "--bogus", "y"], ""),
        (1, vec!["search", "--root", "duplicate", "--query", "x"], ""),
        (2, vec!["search", "--query", "x", "--limit"], ""),
        (3, vec!["ingest", "stray"], valid_record.as_str()),
        (4, vec!["snapshot"], invalid_snapshot.as_str()),
        (
            5,
            vec![
                "export",
                "--vault",
                invalid_export_target.to_str().expect("UTF-8 temp path"),
            ],
            "",
        ),
    ] {
        let root_path = temp.path().join(format!("strict-store-{index}"));
        let root = root_path.to_string_lossy().to_string();
        let mut args = vec![extra_args[0], "--root", root.as_str()];
        args.extend_from_slice(&extra_args[1..]);
        let output = run_with_stdin(&args, stdin);
        assert!(!output.status.success(), "invalid case {index} succeeded");
        assert!(!root_path.exists(), "invalid case {index} opened the store");
        if index == 5 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!stderr.contains(&root));
            assert!(!stderr.contains(invalid_export_target.to_str().expect("UTF-8 temp path")));
        }
    }
}

#[test]
fn cli_rejects_oversized_stdin_before_opening_store() {
    let temp = tempdir().expect("temp dir");
    let root_path = temp.path().join("oversized-store");
    let root = root_path.to_string_lossy().to_string();
    let oversized = "x".repeat(8 * 1024 * 1024 + 1);

    let output = run_with_stdin(&["ingest", "--root", &root], &oversized);

    assert!(!output.status.success());
    assert!(!root_path.exists());
}

#[test]
fn cli_rejects_empty_search_query_before_opening_store() {
    let temp = tempdir().expect("temp dir");
    let root_path = temp.path().join("empty-query-store");
    let root = root_path.to_string_lossy().to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_hermes-memory"))
        .args(["search", "--root", &root, "--query", "   "])
        .output()
        .expect("empty query");

    assert!(!output.status.success());
    assert!(!root_path.exists());
}
