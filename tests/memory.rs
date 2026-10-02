#![cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]

mod support;

use hermes_memory::{
    MemoryError, MemoryRecord, MemoryStore as ProductMemoryStore, SearchRequest, SnapshotItem,
    SnapshotRequest,
};
use serde_json::json;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::time::Duration;
use support::open_store;
use tempfile::tempdir;

struct MemoryStore;

impl MemoryStore {
    fn open(root: impl AsRef<Path>) -> Result<ProductMemoryStore, MemoryError> {
        open_store(root)
    }
}

#[cfg(unix)]
fn link_directory(target: &std::path::Path, link: &std::path::Path) {
    std::os::unix::fs::symlink(target, link).expect("create directory symlink");
}

#[cfg(windows)]
fn link_directory(target: &std::path::Path, link: &std::path::Path) {
    let output = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .expect("run mklink junction");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(windows)]
fn link_file(target: &std::path::Path, link: &std::path::Path) {
    std::fs::hard_link(target, link).expect("create file hardlink");
}

fn record(id: &str, workspace: &str, content: &str) -> MemoryRecord {
    MemoryRecord {
        id: id.to_owned(),
        session_id: "session-1".to_owned(),
        workspace: workspace.to_owned(),
        kind: "user".to_owned(),
        content: content.to_owned(),
        timestamp: 1_787_000_000.0,
        metadata: json!({"provider": "local"}),
    }
}

fn read_projection(root: &std::path::Path) -> Vec<MemoryRecord> {
    std::fs::read_to_string(root.join("events.jsonl"))
        .expect("read event projection")
        .lines()
        .map(|line| serde_json::from_str::<MemoryRecord>(line).expect("valid JSONL record"))
        .collect()
}

#[test]
fn cross_workspace_snapshot_id_conflict_does_not_advance_state() {
    let reference_dir = tempdir().unwrap();
    let reference = MemoryStore::open(reference_dir.path()).unwrap();
    let snapshot = SnapshotRequest {
        session_id: "session-1".into(),
        workspace: "beta".into(),
        items: vec![SnapshotItem {
            kind: "checkpoint".into(),
            content: "snapshotmarker".into(),
            timestamp: 0.0,
            metadata: json!({}),
        }],
    };
    reference.ingest_snapshot(&snapshot).unwrap();
    let generated = read_projection(reference_dir.path()).remove(0);
    let temp = tempdir().unwrap();
    let store = MemoryStore::open(temp.path()).unwrap();
    store
        .ingest(&record(&generated.id, "alpha", "blocker"))
        .unwrap();
    assert!(store.ingest_snapshot(&snapshot).is_err());
    assert_eq!(read_projection(temp.path()).len(), 1);
    assert!(
        store.ingest_snapshot(&snapshot).is_err(),
        "conflict must not advance snapshot counter/state"
    );
}

#[test]
fn cross_workspace_duplicate_id_rolls_back_entire_batch() {
    let temp = tempdir().unwrap();
    let store = MemoryStore::open(temp.path()).unwrap();
    assert!(store.ingest(&record("shared", "alpha", "first")).unwrap());
    assert_eq!(
        store
            .ingest_many(&[record("shared", "alpha", "retry")])
            .unwrap(),
        (0, 1)
    );
    let before = std::fs::read(temp.path().join("events.jsonl")).unwrap();
    let result = store.ingest_many(&[
        record("fresh", "beta", "must roll back"),
        record("shared", "beta", "must conflict"),
    ]);
    assert!(
        result.is_err(),
        "cross-workspace ID reuse must not count as duplicate"
    );
    assert_eq!(
        before,
        std::fs::read(temp.path().join("events.jsonl")).unwrap()
    );
    assert!(store
        .ingest(&record("fresh", "beta", "rollback proved"))
        .unwrap());
}

#[test]
fn ingest_is_append_only_searchable_and_idempotent() {
    let temp = tempdir().expect("temp dir");
    let store = MemoryStore::open(temp.path()).expect("open store");

    let inserted = store
        .ingest(&record(
            "evt-1",
            "repo-a",
            "Use SQLite FTS5 for durable recall",
        ))
        .expect("ingest");
    let duplicate = store
        .ingest(&record("evt-1", "repo-a", "duplicate must not land"))
        .expect("duplicate ingest");

    assert!(inserted);
    assert!(!duplicate);
    let hits = store
        .search(&SearchRequest {
            query: "SQLite durable".to_owned(),
            workspace: Some("repo-a".to_owned()),
            session_id: None,
            limit: 10,
            max_bytes: 4096,
        })
        .expect("search");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, "evt-1");

    let event_log =
        std::fs::read_to_string(temp.path().join("events.jsonl")).expect("read append log");
    assert_eq!(event_log.lines().count(), 1);
    assert!(event_log.contains("evt-1"));
}

#[test]
fn snapshots_derive_identity_and_reconcile_repetitions_across_reopen() {
    let temp = tempdir().expect("temp dir");
    let repeated = || SnapshotItem {
        kind: "user".to_owned(),
        content: "same legitimate message".to_owned(),
        timestamp: 10.0,
        metadata: json!({"tool_call_id": null}),
    };
    let request = |items| SnapshotRequest {
        session_id: "session-repeated".to_owned(),
        workspace: "workspace-repeated".to_owned(),
        items,
    };

    let store = MemoryStore::open(temp.path()).expect("open store one");
    assert_eq!(
        store
            .ingest_snapshot(&request(vec![repeated(), repeated()]))
            .expect("initial snapshot"),
        (2, 0)
    );
    drop(store);
    let store = MemoryStore::open(temp.path()).expect("open store two");
    assert_eq!(
        store
            .ingest_snapshot(&request(vec![repeated()]))
            .expect("compressed suffix"),
        (0, 0)
    );
    drop(store);
    let store = MemoryStore::open(temp.path()).expect("open store three");
    assert_eq!(
        store
            .ingest_snapshot(&request(vec![repeated(), repeated()]))
            .expect("new repetition"),
        (1, 0)
    );
    let lines = std::fs::read_to_string(temp.path().join("events.jsonl"))
        .expect("read projection")
        .lines()
        .count();
    assert_eq!(lines, 3);
}

#[test]
fn search_never_crosses_workspace_scope() {
    let temp = tempdir().expect("temp dir");
    let store = MemoryStore::open(temp.path()).expect("open store");
    store
        .ingest(&record("a", "repo-a", "private alpha decision"))
        .expect("ingest a");
    store
        .ingest(&record("b", "repo-b", "private alpha decision"))
        .expect("ingest b");
    let mut other_session = record("c", "repo-a", "private alpha decision");
    other_session.session_id = "session-2".to_owned();
    store.ingest(&other_session).expect("ingest other session");

    let hits = store
        .search(&SearchRequest {
            query: "alpha decision".to_owned(),
            workspace: Some("repo-a".to_owned()),
            session_id: Some("session-1".to_owned()),
            limit: 10,
            max_bytes: 4096,
        })
        .expect("search");
    assert_eq!(
        hits.iter().map(|hit| hit.id.as_str()).collect::<Vec<_>>(),
        vec!["a"]
    );
    let historical = store
        .search(&SearchRequest {
            query: "alpha decision".to_owned(),
            workspace: Some("repo-a".to_owned()),
            session_id: None,
            limit: 10,
            max_bytes: 4096,
        })
        .expect("cross-session search");
    assert_eq!(historical.len(), 2);
}

#[test]
fn search_rejects_empty_query() {
    let temp = tempdir().expect("temp dir");
    let store = MemoryStore::open(temp.path().join("store")).expect("open store");

    assert!(store
        .search(&SearchRequest {
            query: "   ".to_owned(),
            workspace: None,
            session_id: None,
            limit: 5,
            max_bytes: 1024,
        })
        .is_err());
}

#[test]
fn ingest_redacts_common_inline_credentials_before_disk() {
    let temp = tempdir().expect("temp dir");
    let store = MemoryStore::open(temp.path()).expect("open store");
    let secrets = [
        ("basic", "Authorization: Basic ***"),
        ("cookie", "Cookie: session=abc123"),
        (
            "json",
            r#"{"accessToken":"json-secret","refresh_token":"refresh-secret"}"#,
        ),
        ("url-query", "https://x.test/?token=url-secret&safe=yes"),
        ("github", "ghp_ab...7890"),
        ("private-key", "[REDACTED PRIVATE KEY]"),
        ("jwt", "eyJhbG...rial"),
        (
            "url-userinfo",
            "https://alice:password-secret@example.test/path",
        ),
    ];
    for (id, content) in secrets {
        store
            .ingest(&record(id, "repo-a", content))
            .expect("ingest secret family");
    }
    let mut metadata_secret = record("metadata", "repo-a", "structured metadata");
    metadata_secret.metadata = json!({"accessToken": "metadata-secret"});
    store
        .ingest(&metadata_secret)
        .expect("ingest structured secret");

    let event_log =
        std::fs::read_to_string(temp.path().join("events.jsonl")).expect("read append log");
    assert!(!event_log.contains("dXNlcjpwYXNz"));
    assert!(!event_log.contains("abc123"));
    assert!(!event_log.contains("json-secret"));
    assert!(!event_log.contains("refresh-secret"));
    assert!(!event_log.contains("url-secret"));
    assert!(!event_log.contains("ghp_ab...wxyz"));
    assert!(!event_log.contains("private-material"));
    assert!(!event_log.contains("eyJhbG...NiJ9"));
    assert!(!event_log.contains("password-secret"));
    assert!(!event_log.contains("metadata-secret"));
    assert!(event_log.contains("[REDACTED]"));
    let json_record = event_log
        .lines()
        .map(|line| serde_json::from_str::<MemoryRecord>(line).expect("valid event JSON"))
        .find(|record| record.id == "json")
        .expect("JSON credential record");
    serde_json::from_str::<serde_json::Value>(&json_record.content)
        .expect("redacted JSON content remains valid JSON");
}

#[test]
fn ingest_redacts_credentials_from_every_persisted_field_and_preserves_json() {
    let temp = tempdir().expect("temp dir");
    let store = MemoryStore::open(temp.path()).expect("open store");
    let secrets = [
        "id-secret=alpha-secret-value",
        "session-token=beta-secret-value",
        "workspace-password=gamma-secret-value",
        "kind-api_key=delta-secret-value",
        "json-secret-value",
        "metadata-secret-value",
    ];
    let record = MemoryRecord {
        id: secrets[0].to_owned(),
        session_id: secrets[1].to_owned(),
        workspace: secrets[2].to_owned(),
        kind: secrets[3].to_owned(),
        content: format!(r#"{{"token":"{}","safe":"kept"}}"#, secrets[4]),
        timestamp: 7.0,
        metadata: json!({"password": secrets[5], "safe": "kept"}),
    };

    assert!(store.ingest(&record).expect("ingest record"));
    let line =
        std::fs::read_to_string(temp.path().join("events.jsonl")).expect("read projected event");
    for secret in secrets {
        assert!(!line.contains(secret), "secret persisted: {secret}");
    }
    let persisted: serde_json::Value = serde_json::from_str(line.trim()).expect("event JSON");
    let content = persisted["content"].as_str().expect("content string");
    let content_json: serde_json::Value = serde_json::from_str(content).expect("content JSON");
    assert_eq!(content_json["token"], "[REDACTED]");
    assert_eq!(content_json["safe"], "kept");
    assert_eq!(persisted["metadata"]["password"], "[REDACTED]");
    let hits = store
        .search(&SearchRequest {
            query: "kept".to_owned(),
            workspace: Some(secrets[2].to_owned()),
            session_id: None,
            limit: 4,
            max_bytes: 4096,
        })
        .expect("search redacted workspace");
    assert_eq!(hits.len(), 1);
    let vault = temp.path().join("vault-redacted-scope");
    assert_eq!(
        store
            .export_markdown(&vault, Some(secrets[2]))
            .expect("export redacted workspace"),
        1
    );
}

#[test]
fn search_respects_total_byte_budget() {
    let temp = tempdir().expect("temp dir");
    let store = MemoryStore::open(temp.path()).expect("open store");
    for index in 0..5 {
        store
            .ingest(&record(
                &format!("evt-{index}"),
                "repo-a",
                &format!("budget marker {}", "x".repeat(100)),
            ))
            .expect("ingest");
    }

    let hits = store
        .search(&SearchRequest {
            query: "budget marker".to_owned(),
            workspace: Some("repo-a".to_owned()),
            session_id: None,
            limit: 10,
            max_bytes: 180,
        })
        .expect("search");
    let bytes = serde_json::to_vec(&hits).expect("serialize hits").len();
    assert!(bytes <= 180, "serialized hits used {bytes} bytes");
    assert!(!hits.is_empty());
}

#[test]
fn search_skips_unfit_hit_and_returns_later_hit_that_fits_budget() {
    let temp = tempdir().expect("temp dir");
    let store = MemoryStore::open(temp.path()).expect("open store");
    let mut oversized = record(&"x".repeat(600), "repo-a", "budget marker");
    oversized.session_id = "s".repeat(600);
    oversized.timestamp = 2.0;
    store.ingest(&oversized).expect("ingest oversized envelope");
    let mut small = record("small", "repo-a", "budget marker");
    small.timestamp = 1.0;
    store.ingest(&small).expect("ingest small envelope");

    let hits = store
        .search(&SearchRequest {
            query: "budget marker".to_owned(),
            workspace: Some("repo-a".to_owned()),
            session_id: None,
            limit: 10,
            max_bytes: 256,
        })
        .expect("budgeted search");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].id, "small");
}

#[test]
fn export_markdown_creates_human_editable_session_notes_and_index() {
    let temp = tempdir().expect("temp dir");
    let store = MemoryStore::open(temp.path().join("store")).expect("open store");
    store
        .ingest(&record("evt-1", "repo-a", "First durable decision"))
        .expect("ingest");

    let exported = store
        .export_markdown(temp.path().join("vault"), Some("repo-a"))
        .expect("export vault");

    assert_eq!(exported, 1);
    let workspace_dirs = std::fs::read_dir(temp.path().join("vault").join("Sessions"))
        .expect("workspace dirs")
        .collect::<Result<Vec<_>, _>>()
        .expect("workspace entries");
    assert_eq!(workspace_dirs.len(), 1);
    let notes = std::fs::read_dir(workspace_dirs[0].path())
        .expect("session notes")
        .collect::<Result<Vec<_>, _>>()
        .expect("session entries");
    assert_eq!(notes.len(), 1);
    let note = std::fs::read_to_string(notes[0].path()).expect("read session note");
    assert!(note.contains("workspace: repo-a"));
    assert!(note.contains("First durable decision"));
    assert!(note.contains("id: evt-1"));
    let index =
        std::fs::read_to_string(temp.path().join("vault").join("Index.md")).expect("read index");
    assert!(index.contains("[[Sessions/repo-a-"));
}

#[test]
fn export_markdown_contains_untrusted_values_without_structure_injection() {
    let temp = tempdir().expect("temp dir");
    let store = MemoryStore::open(temp.path().join("store")).expect("open store");
    let record = MemoryRecord {
        id: "id\n# injected id heading".to_owned(),
        session_id: "session\n---\n# injected session heading".to_owned(),
        workspace: "workspace-safe".to_owned(),
        kind: "assistant\n# injected kind heading".to_owned(),
        content: "# injected content heading\n---\n```\nraw fence".to_owned(),
        timestamp: 8.0,
        metadata: json!({}),
    };
    store.ingest(&record).expect("ingest hostile markdown");
    let vault = temp.path().join("vault");
    store
        .export_markdown(&vault, Some("workspace-safe"))
        .expect("export vault");
    let workspace_dir = std::fs::read_dir(vault.join("Sessions"))
        .expect("read workspace root")
        .next()
        .expect("one workspace")
        .expect("workspace entry")
        .path();
    let note_path = std::fs::read_dir(workspace_dir)
        .expect("read workspace notes")
        .next()
        .expect("one note")
        .expect("note entry")
        .path();
    let note = std::fs::read_to_string(note_path).expect("read note");
    let headings = note
        .lines()
        .filter(|line| line.starts_with('#'))
        .collect::<Vec<_>>();
    assert_eq!(
        headings.len(),
        3,
        "unexpected injected heading: {headings:?}"
    );
    assert!(headings[0].starts_with("# Session "));
    assert!(headings[1].starts_with("## assistant # injected kind heading"));
    assert_eq!(headings[2], "### Content");
    assert!(note.contains("> # injected content heading\n> ---\n> ```\n> raw fence"));
}

#[test]
fn export_paths_cannot_traverse_or_collide_after_sanitization() {
    let temp = tempdir().expect("temp dir");
    let store = MemoryStore::open(temp.path().join("store")).expect("open store");
    let mut traversal = record("one", "..", "traversal marker");
    traversal.session_id = "..".to_owned();
    let mut slash = record("two", "a/b", "slash marker");
    slash.session_id = "same/name".to_owned();
    let mut underscore = record("three", "a_b", "underscore marker");
    underscore.session_id = "same_name".to_owned();
    store.ingest(&traversal).expect("ingest traversal");
    store.ingest(&slash).expect("ingest slash");
    store.ingest(&underscore).expect("ingest underscore");

    let vault = temp.path().join("vault");
    assert_eq!(store.export_markdown(&vault, None).expect("export"), 3);
    assert!(!temp.path().join("Sessions").exists());
    let index = std::fs::read_to_string(vault.join("Index.md")).expect("index");
    let links = index
        .lines()
        .filter(|line| line.starts_with("- [["))
        .collect::<Vec<_>>();
    assert_eq!(links.len(), 3);
    assert_ne!(links[1], links[2]);
    assert!(!links.iter().any(|link| link.contains("/../")));
}

#[test]
fn export_rejects_symlink_or_junction_that_escapes_vault() {
    let temp = tempdir().expect("temp dir");
    let store = MemoryStore::open(temp.path().join("store")).expect("open store");
    store
        .ingest(&record("escape", "repo-a", "must stay inside vault"))
        .expect("ingest");
    let vault = temp.path().join("vault");
    let outside = temp.path().join("outside");
    std::fs::create_dir_all(&vault).expect("vault root");
    std::fs::create_dir_all(&outside).expect("outside root");
    link_directory(&outside, &vault.join("Sessions"));

    assert!(store.export_markdown(&vault, None).is_err());
    assert!(std::fs::read_dir(&outside)
        .expect("outside directory")
        .next()
        .is_none());
}

#[cfg(windows)]
#[test]
fn store_open_rejects_symlink_or_junction_root_without_writing_outside() {
    let temp = tempdir().expect("temp dir");
    let outside = temp.path().join("outside-store");
    let redirected_root = temp.path().join("memory-vault");
    std::fs::create_dir_all(&outside).expect("outside root");
    link_directory(&outside, &redirected_root);

    assert!(MemoryStore::open(&redirected_root).is_err());
    assert!(std::fs::read_dir(&outside)
        .expect("outside directory")
        .next()
        .is_none());
}

#[cfg(windows)]
#[test]
fn store_open_rejects_hardlinked_database_without_modifying_target() {
    let temp = tempdir().expect("temp dir");
    let root = temp.path().join("store");
    let outside = temp.path().join("outside.db");
    std::fs::create_dir_all(&root).expect("store root");
    std::fs::write(&outside, b"").expect("outside file");
    link_file(&outside, &root.join("memory.db"));

    assert!(MemoryStore::open(&root).is_err());
    assert!(std::fs::read(&outside).expect("outside target").is_empty());
}

#[cfg(windows)]
#[test]
fn store_open_rejects_hardlinked_sqlite_sidecars() {
    for sidecar in ["memory.db-wal", "memory.db-shm"] {
        let temp = tempdir().expect("temp dir");
        let root = temp.path().join("store");
        let outside = temp.path().join("outside-sidecar");
        std::fs::create_dir_all(&root).expect("store root");
        std::fs::write(&outside, b"").expect("outside file");
        link_file(&outside, &root.join(sidecar));

        assert!(MemoryStore::open(&root).is_err(), "accepted {sidecar}");
        assert!(std::fs::read(&outside).expect("outside target").is_empty());
    }
}

#[cfg(windows)]
#[test]
fn store_open_rejects_hardlinked_initialization_lock() {
    let temp = tempdir().expect("temp dir");
    let root = temp.path().join("store");
    let outside = temp.path().join("outside.lock");
    std::fs::create_dir_all(&root).expect("store root");
    std::fs::write(&outside, b"outside sentinel").expect("outside file");
    link_file(&outside, &root.join("memory.init.lock"));

    assert!(MemoryStore::open(&root).is_err());
}

#[cfg(windows)]
#[test]
fn store_open_rejects_hardlinked_jsonl_projection() {
    let temp = tempdir().expect("temp dir");
    let root = temp.path().join("store");
    let store = MemoryStore::open(&root).expect("create store");
    store
        .ingest(&record("projection", "repo-a", "projection marker"))
        .expect("ingest");
    drop(store);
    let outside = temp.path().join("outside.jsonl");
    std::fs::rename(root.join("events.jsonl"), &outside).expect("move projection");
    link_file(&outside, &root.join("events.jsonl"));

    assert!(MemoryStore::open(&root).is_err());
}

#[cfg(windows)]
#[test]
fn live_store_guards_root_and_database_against_path_swaps() {
    let temp = tempdir().expect("temp dir");
    let root = temp.path().join("store");
    let _store = MemoryStore::open(&root).expect("open store");

    assert!(std::fs::rename(&root, temp.path().join("swapped-store")).is_err());
    assert!(std::fs::rename(root.join("memory.db"), root.join("swapped.db")).is_err());
}

#[test]
fn capability_export_atomically_replaces_existing_files() {
    let temp = tempdir().expect("temp dir");
    let store = MemoryStore::open(temp.path().join("store")).expect("open store");
    store
        .ingest(&record("first", "repo-a", "first export marker"))
        .expect("ingest first");
    let vault = temp.path().join("vault");
    store.export_markdown(&vault, None).expect("first export");

    store
        .ingest(&record("second", "repo-a", "second export marker"))
        .expect("ingest second");
    store.export_markdown(&vault, None).expect("second export");

    let workspace_dir = std::fs::read_dir(vault.join("Sessions"))
        .expect("workspace directories")
        .next()
        .expect("workspace directory")
        .expect("workspace entry")
        .path();
    let note_path = std::fs::read_dir(workspace_dir)
        .expect("session notes")
        .next()
        .expect("session note")
        .expect("session entry")
        .path();
    let note = std::fs::read_to_string(note_path).expect("updated note");
    assert!(note.contains("first export marker"));
    assert!(note.contains("second export marker"));
    assert!(vault.join("Index.md").is_file());
}

// This shared-connection test covers the Linux single-broker model; it is not
// a substitute for Windows independent connections below.
#[test]
fn concurrent_ingest_projects_complete_parseable_jsonl() {
    let temp = tempdir().expect("temp dir");
    let root = temp.path().join("store");
    let store = Arc::new(MemoryStore::open(&root).expect("open one store"));
    let (start_tx, start_rx) = mpsc::sync_channel::<()>(0);
    let start_rx = Arc::new(std::sync::Mutex::new(start_rx));
    let (result_tx, result_rx) = mpsc::sync_channel(2);
    let handles = (0..2)
        .map(|index| {
            let store = Arc::clone(&store);
            let start_rx = Arc::clone(&start_rx);
            let result_tx = result_tx.clone();
            std::thread::spawn(move || {
                let result = start_rx
                    .lock()
                    .map_err(|_| "start lock poisoned".to_owned())?
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|error| error.to_string())
                    .and_then(|()| {
                        store
                            .ingest(&record(
                                &format!("concurrent-{index}"),
                                "repo-a",
                                "concurrent projection marker",
                            ))
                            .map_err(|error| error.to_string())
                            .and_then(|inserted| {
                                inserted.then_some(()).ok_or_else(|| "duplicate".to_owned())
                            })
                    });
                result_tx.send((index, result)).expect("report result");
                Ok::<(), String>(())
            })
        })
        .collect::<Vec<_>>();
    for _ in 0..2 {
        start_tx.send(()).expect("release writer");
    }
    let mut outcomes = Vec::new();
    for _ in 0..2 {
        outcomes.push(
            result_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("bounded writer result"),
        );
    }
    assert!(
        outcomes.iter().all(|(_, result)| result.is_ok()),
        "{outcomes:?}"
    );
    for handle in handles {
        handle
            .join()
            .expect("join ingest")
            .expect("worker completion");
    }
    let lines = std::fs::read_to_string(root.join("events.jsonl")).expect("event projection");
    let records = lines
        .lines()
        .map(|line| serde_json::from_str::<MemoryRecord>(line).expect("valid JSONL record"))
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|record| record.id == "concurrent-0"));
    assert!(records.iter().any(|record| record.id == "concurrent-1"));
    drop(store);
    let reopened = MemoryStore::open(&root).expect("reopen broker store");
    for id in ["concurrent-0", "concurrent-1"] {
        let hits = reopened
            .search(&SearchRequest {
                query: "concurrent projection marker".to_owned(),
                workspace: Some("repo-a".to_owned()),
                session_id: None,
                limit: 10,
                max_bytes: 4096,
            })
            .expect("search reopened store");
        assert!(hits.iter().any(|record| record.id == id));
    }
}

#[cfg(windows)]
#[test]
fn windows_independent_open_concurrent_ingest_projects_complete_jsonl() {
    let temp = tempdir().expect("temp dir");
    let root = temp.path().join("store");
    let bound = Duration::from_secs(5);
    let (ready_tx, ready_rx) = mpsc::sync_channel(2);
    let (result_tx, result_rx) = mpsc::sync_channel(2);
    let mut starts = Vec::new();
    let mut handles = Vec::new();
    for index in 0..2 {
        let root = root.clone();
        let ready_tx = ready_tx.clone();
        let result_tx = result_tx.clone();
        let (start_tx, start_rx) = mpsc::sync_channel(1);
        starts.push(start_tx);
        handles.push(std::thread::spawn(move || {
            // Direct product entrypoint, one independently owned connection per
            // worker. Both must be open simultaneously before either ingests.
            let opened = ProductMemoryStore::open(&root).map_err(|error| error.to_string());
            let readiness = opened.as_ref().map(|_| ()).map_err(Clone::clone);
            let _ = ready_tx.send((index, readiness));
            let result = opened.and_then(|store| {
                // No Barrier: failed open/parent assertion drops the start sender,
                // and even a missing release cannot orphan this worker forever.
                start_rx
                    .recv_timeout(bound)
                    .map_err(|error| error.to_string())?;
                store
                    .ingest(&record(
                        &format!("independent-{index}"),
                        "repo-a",
                        "independent projection marker",
                    ))
                    .map_err(|error| error.to_string())
                    .and_then(|inserted| {
                        inserted.then_some(()).ok_or_else(|| "duplicate".to_owned())
                    })
            }); // Drop the connection before reporting completion.
            let _ = result_tx.send((index, result));
        }));
    }
    drop(ready_tx);
    drop(result_tx);
    let ready = (0..2)
        .map(|_| {
            ready_rx
                .recv_timeout(bound)
                .expect("bounded independent open")
        })
        .collect::<Vec<_>>();
    assert!(ready.iter().all(|(_, result)| result.is_ok()), "{ready:?}");
    for start in starts {
        start.send(()).expect("release independent writer");
    }
    let outcomes = (0..2)
        .map(|_| {
            result_rx
                .recv_timeout(bound)
                .expect("bounded independent ingest")
        })
        .collect::<Vec<_>>();
    assert!(
        outcomes.iter().all(|(_, result)| result.is_ok()),
        "{outcomes:?}"
    );
    for handle in handles {
        handle.join().expect("independent writer completion");
    }
    let records = read_projection(&root);
    assert_eq!(records.len(), 2);
    for id in ["independent-0", "independent-1"] {
        assert_eq!(records.iter().filter(|record| record.id == id).count(), 1);
    }
    let reopened = ProductMemoryStore::open(&root).expect("reopen independent store");
    let hits = reopened
        .search(&SearchRequest {
            query: "independent projection marker".to_owned(),
            workspace: Some("repo-a".to_owned()),
            session_id: None,
            limit: 10,
            max_bytes: 4096,
        })
        .expect("search independent committed records");
    assert_eq!(hits.len(), 2);
    for id in ["independent-0", "independent-1"] {
        assert!(hits.iter().any(|record| record.id == id));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn broker_second_instance_rejected_without_mutation() {
    let temp = tempdir().expect("temp dir");
    let root = temp.path().join("store");
    let store = MemoryStore::open(&root).expect("open broker store");
    store
        .ingest(&record("live", "repo-a", "unchanged marker"))
        .expect("ingest sentinel");
    let before = std::fs::read(root.join("events.jsonl")).expect("read sentinel projection");
    assert!(MemoryStore::open(&root).is_err());
    assert_eq!(
        std::fs::read(root.join("events.jsonl")).expect("reread projection"),
        before
    );
}

#[test]
fn monotonic_ingest_appends_to_existing_projection_file() {
    let temp = tempdir().expect("temp dir");
    let root = temp.path().join("store");
    let store = MemoryStore::open(&root).expect("open store");
    let mut first = record("append-first", "repo-a", "first projection record");
    first.timestamp = 1.0;
    store.ingest(&first).expect("ingest first");

    #[cfg(windows)]
    let mut observer = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x00000001 | 0x00000002 | 0x00000004)
            .open(root.join("events.jsonl"))
            .expect("open projection observer")
    };
    #[cfg(not(windows))]
    let mut observer =
        std::fs::File::open(root.join("events.jsonl")).expect("open projection observer");

    let mut second = record("append-second", "repo-a", "second projection record");
    second.timestamp = 2.0;
    store.ingest(&second).expect("ingest second");

    observer.seek(SeekFrom::Start(0)).expect("rewind observer");
    let mut observed = String::new();
    observer
        .read_to_string(&mut observed)
        .expect("read observed projection");
    assert!(
        observed.contains("append-second"),
        "monotonic projection replaced the file instead of appending to it"
    );
}

#[test]
fn out_of_order_ingest_rebuilds_projection_in_timestamp_order() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("store");
    let store = MemoryStore::open(&root).expect("open store");
    let mut later = record("later", "repo-a", "later record");
    later.timestamp = 10.0;
    store.ingest(&later).expect("ingest later record");

    #[cfg(windows)]
    let mut observer = {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x00000001 | 0x00000002 | 0x00000004)
            .open(root.join("events.jsonl"))
            .expect("open projection observer")
    };
    #[cfg(not(windows))]
    let mut observer =
        std::fs::File::open(root.join("events.jsonl")).expect("open projection observer");

    let mut earlier = record("earlier", "repo-a", "earlier record");
    earlier.timestamp = 1.0;
    store.ingest(&earlier).expect("ingest earlier record");

    observer.seek(SeekFrom::Start(0)).expect("rewind observer");
    let mut old_projection = String::new();
    observer
        .read_to_string(&mut old_projection)
        .expect("read old projection");
    assert!(!old_projection.contains("earlier"));

    let records = read_projection(&root);
    assert_eq!(
        records
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        vec!["earlier", "later"]
    );
}

#[test]
fn store_open_recovers_interrupted_projection_state_migration() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("store");
    drop(MemoryStore::open(&root).expect("create current store"));

    let connection = rusqlite::Connection::open(root.join("memory.db")).expect("open sqlite");
    connection
        .execute_batch("PRAGMA user_version=1;")
        .expect("simulate interruption before schema version update");
    drop(connection);

    drop(MemoryStore::open(&root).expect("resume interrupted migration"));
    let connection = rusqlite::Connection::open(root.join("memory.db")).expect("reopen sqlite");
    let version = connection
        .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .expect("read schema version");
    assert_eq!(version, 2);
}

#[test]
fn store_open_truncates_uncheckpointed_projection_tail() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("store");
    let store = MemoryStore::open(&root).expect("open store");
    store
        .ingest(&record("checkpointed", "repo-a", "canonical"))
        .expect("ingest canonical record");
    drop(store);

    let projection = root.join("events.jsonl");
    let canonical = std::fs::read(&projection).expect("read checkpointed projection");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&projection)
        .expect("open projection for simulated crash tail");
    file.write_all(b"{\"id\":\"uncheckpointed\"}\n")
        .expect("append simulated crash tail");
    file.sync_all().expect("sync simulated crash tail");
    drop(file);

    drop(MemoryStore::open(&root).expect("recover projection tail"));
    assert_eq!(
        std::fs::read(&projection).expect("read recovered projection"),
        canonical
    );
}

#[test]
fn store_open_rebuilds_projection_when_checkpoint_hash_is_not_hex() {
    let temp = tempdir().expect("temp dir");
    let root = temp.path().join("store");
    let store = MemoryStore::open(&root).expect("store");
    store
        .ingest(&record("invalid-checkpoint-hash", "repo-a", "canonical"))
        .expect("ingest");
    drop(store);

    let connection = rusqlite::Connection::open(root.join("memory.db")).expect("open database");
    connection
        .execute(
            "UPDATE projection_state SET projected_sha256 = ?1 WHERE singleton = 1",
            rusqlite::params!["z".repeat(64)],
        )
        .expect("corrupt checkpoint hash");
    drop(connection);

    drop(MemoryStore::open(&root).expect("repair invalid checkpoint hash"));
    let connection = rusqlite::Connection::open(root.join("memory.db")).expect("open database");
    let repaired: String = connection
        .query_row(
            "SELECT projected_sha256 FROM projection_state WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .expect("checkpoint hash");
    assert_eq!(repaired.len(), 64);
    assert!(repaired.bytes().all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn store_open_replays_committed_delta_after_partial_projection_append() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path().join("store");
    let store = MemoryStore::open(&root).expect("open store");
    let mut first = record("first", "repo-a", "first record");
    first.timestamp = 1.0;
    store.ingest(&first).expect("ingest first record");
    drop(store);

    let connection = rusqlite::Connection::open(root.join("memory.db")).expect("open sqlite");
    connection
        .execute(
            "INSERT INTO records
             (id, session_id, workspace, kind, content, timestamp, metadata_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                "second",
                "session-1",
                "repo-a",
                "user",
                "second record",
                2.0,
                "{}"
            ],
        )
        .expect("commit canonical delta");
    drop(connection);

    let projection = root.join("events.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&projection)
        .expect("open projection for partial append");
    file.write_all(b"{\"id\":\"sec")
        .expect("write partial projection line");
    file.sync_all().expect("sync partial projection line");
    drop(file);

    drop(MemoryStore::open(&root).expect("recover committed delta"));
    let records = read_projection(&root);
    assert_eq!(
        records
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
        vec!["first", "second"]
    );
}

#[test]
fn store_open_recovers_only_orphaned_jsonl_projection_temps() {
    let temp = tempdir().expect("temp dir");
    let root = temp.path().join("store");
    let store = MemoryStore::open(&root).expect("open store");
    store
        .ingest(&record("one", "repo-a", "first"))
        .expect("ingest");
    drop(store);

    let canonical = std::fs::read(root.join("events.jsonl")).expect("read canonical projection");
    let unrelated = root.join("unrelated.tmp");
    for sequence in 0..32 {
        std::fs::write(
            root.join(format!(".events.jsonl.424242.{sequence}.tmp")),
            b"partial derived projection",
        )
        .expect("write orphan");
    }
    std::fs::write(&unrelated, b"must be preserved").expect("write unrelated temp");

    drop(MemoryStore::open(&root).expect("reopen store"));

    assert_eq!(
        std::fs::read(root.join("events.jsonl")).expect("read recovered projection"),
        canonical,
        "orphan recovery changed the canonical projection"
    );
    assert_eq!(
        std::fs::read_dir(&root)
            .expect("read store")
            .filter_map(Result::ok)
            .filter(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with(".events.jsonl."))
            .count(),
        0,
        "projection orphan growth was not bounded"
    );
    assert!(unrelated.exists(), "unrelated temporary was removed");
}

#[cfg(windows)]
#[test]
fn store_open_skips_locked_projection_temp_until_a_later_recovery() {
    use std::os::windows::fs::OpenOptionsExt;

    let temp = tempdir().expect("temp dir");
    let root = temp.path().join("store");
    drop(MemoryStore::open(&root).expect("create store"));
    let orphan = root.join(".events.jsonl.424242.8.tmp");
    std::fs::write(&orphan, b"partial derived projection").expect("write orphan");
    let guard = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x00000001 | 0x00000002)
        .open(&orphan)
        .expect("lock orphan against delete");

    drop(MemoryStore::open(&root).expect("locked orphan must not block the store"));
    assert!(orphan.exists(), "locked orphan was unexpectedly removed");

    drop(guard);
    drop(MemoryStore::open(&root).expect("recover unlocked orphan"));
    assert!(!orphan.exists(), "unlocked orphan was not recovered");
}

#[test]
fn open_rebuilds_missing_corrupt_or_stale_jsonl_from_sqlite() {
    let temp = tempdir().expect("temp dir");
    let root = temp.path().join("store");
    let store = MemoryStore::open(&root).expect("open store");
    store
        .ingest(&record("one", "repo-a", "first"))
        .expect("first");
    store
        .ingest(&record("two", "repo-a", "second"))
        .expect("second");
    drop(store);

    let log = root.join("events.jsonl");
    std::fs::remove_file(&log).expect("remove projection");
    drop(MemoryStore::open(&root).expect("rebuild missing projection"));
    assert_eq!(
        std::fs::read_to_string(&log)
            .expect("missing rebuilt")
            .lines()
            .count(),
        2
    );

    std::fs::write(&log, "not-json\n").expect("corrupt projection");
    drop(MemoryStore::open(&root).expect("rebuild corrupt projection"));
    assert_eq!(
        std::fs::read_to_string(&log)
            .expect("corrupt rebuilt")
            .lines()
            .count(),
        2
    );

    std::fs::write(&log, [0xff, 0xfe, b'\n']).expect("invalid UTF-8 projection");
    drop(MemoryStore::open(&root).expect("rebuild invalid UTF-8 projection"));
    assert_eq!(
        std::fs::read_to_string(&log)
            .expect("invalid UTF-8 rebuilt")
            .lines()
            .count(),
        2
    );

    let first = std::fs::read_to_string(&log)
        .expect("full projection")
        .lines()
        .next()
        .expect("first line")
        .to_owned();
    std::fs::write(&log, format!("{first}\n")).expect("stale projection");
    drop(MemoryStore::open(&root).expect("rebuild stale projection"));
    assert_eq!(
        std::fs::read_to_string(&log)
            .expect("stale rebuilt")
            .lines()
            .count(),
        2
    );

    let mut records = std::fs::read_to_string(&log)
        .expect("complete projection")
        .lines()
        .map(|line| serde_json::from_str::<MemoryRecord>(line).expect("record"))
        .collect::<Vec<_>>();
    records[0].content = "tampered-content".to_owned();
    let tampered = records
        .iter()
        .map(|record| serde_json::to_string(record).expect("serialize"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(&log, tampered).expect("tamper projection without changing IDs");
    drop(MemoryStore::open(&root).expect("rebuild content-tampered projection"));
    assert!(!std::fs::read_to_string(&log)
        .expect("content rebuilt")
        .contains("tampered-content"));
}
