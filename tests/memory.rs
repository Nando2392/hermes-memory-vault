use hermes_memory::{MemoryRecord, MemoryStore, SearchRequest, SnapshotItem, SnapshotRequest};
use serde_json::json;
use std::sync::{Arc, Barrier};
use tempfile::tempdir;

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

#[test]
fn concurrent_ingest_projects_complete_parseable_jsonl() {
    let temp = tempdir().expect("temp dir");
    let root = temp.path().join("store");
    let barrier = Arc::new(Barrier::new(2));
    let handles = (0..2)
        .map(|index| {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let store = MemoryStore::open(root).expect("open concurrent store");
                barrier.wait();
                store
                    .ingest(&record(
                        &format!("concurrent-{index}"),
                        "repo-a",
                        "concurrent projection marker",
                    ))
                    .expect("concurrent ingest");
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle.join().expect("join ingest");
    }
    let lines = std::fs::read_to_string(root.join("events.jsonl")).expect("event projection");
    let records = lines
        .lines()
        .map(|line| serde_json::from_str::<MemoryRecord>(line).expect("valid JSONL record"))
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    assert!(records.iter().any(|record| record.id == "concurrent-0"));
    assert!(records.iter().any(|record| record.id == "concurrent-1"));
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
