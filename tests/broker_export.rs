use hermes_memory::broker_export::{ExportError, ExportPageRequest, MAX_EXPORT_BYTES};
use hermes_memory::{MemoryRecord, MemoryStore};
use serde_json::json;
use tempfile::tempdir;

fn request(workspace: &str) -> ExportPageRequest {
    ExportPageRequest {
        workspace: workspace.into(),
        high_water: None,
        after: None,
        max_records: 256,
        max_bytes: MAX_EXPORT_BYTES,
    }
}

fn record(id: &str, scope: &str, session: &str, timestamp: f64) -> MemoryRecord {
    MemoryRecord {
        id: id.into(),
        workspace: scope.into(),
        session_id: session.into(),
        timestamp,
        kind: "user".into(),
        content: "雪🦀\n\"quoted\"".into(),
        metadata: json!({"nested": [{"text": "é"}, [1, true, null]]}),
    }
}

fn envelope_len(page: &hermes_memory::broker_export::ExportPage, id: &str) -> usize {
    serde_json::to_vec(&json!({"protocol":1,"request_id":id,"ok":true,"result":page}))
        .unwrap()
        .len()
}

#[test]
fn exact_full_envelope_budget_and_oversized_record_are_not_truncated() {
    let root = tempdir().unwrap();
    let store = MemoryStore::open(root.path()).unwrap();
    store.ingest(&record("a", "scope", "session", 1.0)).unwrap();
    store.prepare_export_index().unwrap();
    let id = "\"\n雪";
    let mut req = request("scope");
    let page = store.export_page(&req, id).unwrap();
    req.max_bytes = envelope_len(&page, id);
    assert_eq!(store.export_page(&req, id).unwrap().records.len(), 1);
    req.max_bytes -= 1;
    assert!(matches!(
        store.export_page(&req, id),
        Err(ExportError::ResourceLimit)
    ));
    req = request("missing");
    req.max_bytes = 1;
    assert!(matches!(
        store.export_page(&req, id),
        Err(ExportError::ResourceLimit)
    ));
}

#[test]
fn byte_packing_reserves_next_cursor_and_keeps_all_records() {
    let root = tempdir().unwrap();
    let store = MemoryStore::open(root.path()).unwrap();
    let records: Vec<_> = (0..6)
        .map(|i| record(&format!("r{i}"), "scope", "session", i as f64))
        .collect();
    store.ingest_many(&records).unwrap();
    store.prepare_export_index().unwrap();
    let mut req = request("scope");
    req.max_records = 1;
    let first = store.export_page(&req, "test").unwrap();
    req.max_bytes = envelope_len(&first, "test");
    req.max_records = 256;
    let mut got = Vec::new();
    loop {
        let page = store.export_page(&req, "test").unwrap();
        assert!(envelope_len(&page, "test") <= req.max_bytes);
        assert!(!page.records.is_empty());
        got.extend(page.records);
        req.high_water = Some(page.high_water);
        req.after = page.next;
        if req.after.is_none() {
            break;
        }
    }
    assert_eq!(got, records);
}

#[test]
fn sql_lengths_guard_large_content_and_metadata_before_decoding() {
    for column in ["content", "metadata_json", "id", "session_id", "kind"] {
        let root = tempdir().unwrap();
        let store = MemoryStore::open(root.path()).unwrap();
        store.ingest(&record("a", "scope", "s", 1.0)).unwrap();
        store.prepare_export_index().unwrap();
        let db = rusqlite::Connection::open(root.path().join("memory.db")).unwrap();
        // Deliberately invalid, enormous metadata proves the length guard wins
        // before JSON parsing. SQL and column names are fixed test fixtures.
        db.execute_batch(&format!(
            "UPDATE records SET {column}=printf('%.*c',9000000,'x')"
        ))
        .unwrap();
        let mut req = request("scope");
        req.max_bytes = 512;
        assert!(
            matches!(
                store.export_page(&req, "test"),
                Err(ExportError::ResourceLimit)
            ),
            "{column}"
        );
    }
}

#[test]
fn many_scopes_indexed_order_and_page_reads_do_not_write() {
    let root = tempdir().unwrap();
    let store = MemoryStore::open(root.path()).unwrap();
    let records: Vec<_> = (0..1800)
        .map(|i| {
            record(
                &format!("r{i:04}"),
                &format!("scope{}", i % 5),
                &format!("s{}", i % 7),
                (i % 13) as f64,
            )
        })
        .collect();
    store.ingest_many(&records).unwrap();
    store.prepare_export_index().unwrap();
    let db = rusqlite::Connection::open(root.path().join("memory.db")).unwrap();
    let schema_before: i64 = db
        .query_row("PRAGMA schema_version", [], |r| r.get(0))
        .unwrap();
    let data_before: i64 = db
        .query_row("PRAGMA data_version", [], |r| r.get(0))
        .unwrap();
    let projection = std::fs::read(root.path().join("events.jsonl")).unwrap();
    for scope in 0..5 {
        let scope = format!("scope{scope}");
        let mut expected: Vec<_> = records
            .iter()
            .filter(|r| r.workspace == scope)
            .cloned()
            .collect();
        expected.sort_by(|a, b| {
            a.session_id
                .cmp(&b.session_id)
                .then(a.timestamp.total_cmp(&b.timestamp))
        });
        let mut req = request(&scope);
        let mut actual = Vec::new();
        loop {
            let page = store.export_page(&req, "test").unwrap();
            assert!(page.records.len() <= 256);
            actual.extend(page.records);
            req.after = page.next;
            req.high_water = Some(page.high_water);
            if req.after.is_none() {
                break;
            }
        }
        assert_eq!(actual, expected);
    }
    for sql in [
        "EXPLAIN QUERY PLAN SELECT rowid FROM records INDEXED BY records_export_order WHERE workspace='scope0' AND rowid<=1800 ORDER BY session_id,timestamp,rowid LIMIT 257",
        "EXPLAIN QUERY PLAN SELECT rowid FROM records INDEXED BY records_export_order WHERE workspace='scope0' AND rowid<=1800 AND (session_id,timestamp,rowid)>('s0',1,5) ORDER BY session_id,timestamp,rowid LIMIT 257",
    ] {
        let plan: Vec<String> = db.prepare(sql).unwrap().query_map([], |r| r.get(3)).unwrap().collect::<Result<_,_>>().unwrap();
        assert!(plan.iter().any(|p| p.contains("COVERING INDEX records_export_order")), "{plan:?}");
        assert!(!plan.iter().any(|p| p.contains("TEMP B-TREE")), "{plan:?}");
    }
    assert_eq!(
        db.query_row("PRAGMA schema_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        schema_before
    );
    assert_eq!(
        db.query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        data_before
    );
    assert_eq!(
        std::fs::read(root.path().join("events.jsonl")).unwrap(),
        projection
    );
}

#[test]
fn future_schema_is_rejected_before_index_writes() {
    let root = tempdir().unwrap();
    let store = MemoryStore::open(root.path()).unwrap();
    let db = rusqlite::Connection::open(root.path().join("memory.db")).unwrap();
    db.execute_batch("PRAGMA user_version=99").unwrap();
    let before: i64 = db
        .query_row("PRAGMA data_version", [], |r| r.get(0))
        .unwrap();
    assert!(store.prepare_export_index().is_err());
    assert!(store.export_page(&request("scope"), "test").is_err());
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name='records_export_order'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("PRAGMA data_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        before
    );
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        99
    );
}

#[test]
fn sanitized_scope_and_injection_text_remain_parameter_bound() {
    let root = tempdir().unwrap();
    let store = MemoryStore::open(root.path()).unwrap();
    let scope = "password=synthetic-secret";
    let mut rec = record("a", scope, "s' OR 1=1 --", 1.0);
    rec.content = "password=synthetic-secret".into();
    store.ingest(&rec).unwrap();
    store.prepare_export_index().unwrap();
    let page = store.export_page(&request(scope), "test").unwrap();
    assert_eq!(page.records.len(), 1);
    assert_ne!(page.records[0].workspace, scope);
    assert!(!page.records[0].content.contains("synthetic-secret"));
    assert!(store
        .export_page(&request("' OR 1=1 --"), "test")
        .unwrap()
        .records
        .is_empty());
}

#[test]
fn content_and_metadata_over_one_mib_export_complete_pages() {
    let root = tempdir().unwrap();
    let store = MemoryStore::open(root.path()).unwrap();
    let mut records = Vec::new();
    for i in 0..3 {
        let mut r = record(&format!("large{i}"), "scope", "s", i as f64);
        r.content = "x".repeat(1024 * 1024 + 1);
        r.metadata = json!({"payload":"y".repeat(1024 * 1024 + 1)});
        records.push(r);
    }
    store.ingest_many(&records).unwrap();
    store.prepare_export_index().unwrap();
    let mut req = request("scope");
    req.max_bytes = 3 * 1024 * 1024;
    let mut actual = Vec::new();
    loop {
        let page = store.export_page(&req, "large").unwrap();
        assert_eq!(page.records.len(), 1);
        assert!(envelope_len(&page, "large") <= req.max_bytes);
        actual.extend(page.records);
        req.high_water = Some(page.high_water);
        req.after = page.next;
        if req.after.is_none() {
            break;
        }
    }
    assert_eq!(actual, records);
}

#[test]
fn hard_field_caps_apply_even_with_full_frame_budget() {
    for column in ["content", "metadata_json", "id", "session_id", "kind"] {
        let root = tempdir().unwrap();
        let store = MemoryStore::open(root.path()).unwrap();
        store.ingest(&record("a", "scope", "s", 1.0)).unwrap();
        store.prepare_export_index().unwrap();
        let db = rusqlite::Connection::open(root.path().join("memory.db")).unwrap();
        let length = if ["content", "metadata_json"].contains(&column) {
            MAX_EXPORT_BYTES + 1
        } else {
            4097
        };
        db.execute_batch(&format!(
            "UPDATE records SET {column}=printf('%.*c',{length},'x')"
        ))
        .unwrap();
        assert!(
            matches!(
                store.export_page(&request("scope"), "test"),
                Err(ExportError::ResourceLimit)
            ),
            "{column}"
        );
    }
}

#[test]
fn serialized_cursor_roundtrips_real_timestamp_keys() {
    let root = tempdir().unwrap();
    let store = MemoryStore::open(root.path()).unwrap();
    let records: Vec<_> = [
        1.2345678901234567,
        0.845_512_408_225_570_1,
        1.0000000000000002,
        1787000000.000001,
        f64::MIN_POSITIVE,
    ]
    .iter()
    .enumerate()
    .map(|(i, t)| record(&format!("r{i}"), "scope", "s", *t))
    .collect();
    store.ingest_many(&records).unwrap();
    store.prepare_export_index().unwrap();
    let mut req = request("scope");
    req.max_records = 1;
    let mut count = 0;
    loop {
        let page = store.export_page(&req, "test").unwrap();
        count += page.records.len();
        req.after = page.next;
        req.high_water = Some(page.high_water);
        if req.after.is_none() {
            break;
        }
        req = serde_json::from_slice(&serde_json::to_vec(&req).unwrap()).unwrap();
    }
    assert_eq!(count, records.len());
}

#[test]
fn oversized_later_record_is_never_silently_skipped() {
    let root = tempdir().unwrap();
    let store = MemoryStore::open(root.path()).unwrap();
    let first = record("a", "scope", "s", 1.0);
    let mut second = record("b", "scope", "s", 2.0);
    second.content = "x".repeat(4096);
    store.ingest_many(&[first.clone(), second]).unwrap();
    store.prepare_export_index().unwrap();
    let mut req = request("scope");
    req.max_bytes = 512;
    let page = store.export_page(&req, "test").unwrap();
    assert_eq!(page.records, vec![first]);
    assert!(page.next.is_some());
    req.after = page.next;
    req.high_water = Some(page.high_water);
    assert!(matches!(
        store.export_page(&req, "test"),
        Err(ExportError::ResourceLimit)
    ));
}

#[test]
fn invalid_cursor_and_limits_fail_closed() {
    use hermes_memory::broker_export::ExportCursor;
    let root = tempdir().unwrap();
    let store = MemoryStore::open(root.path()).unwrap();
    store
        .ingest_many(&[
            record("a", "scope", "a", 1.0),
            record("b", "other", "b", 2.0),
        ])
        .unwrap();
    store.prepare_export_index().unwrap();
    for scope in ["", " \n"] {
        assert!(matches!(
            store.export_page(&request(scope), "test"),
            Err(ExportError::InvalidRequest)
        ));
    }
    for h in [-1, 3, i64::MAX] {
        let mut req = request("scope");
        req.high_water = Some(h);
        assert!(matches!(
            store.export_page(&req, "test"),
            Err(ExportError::InvalidRequest)
        ));
    }
    for (session, timestamp, rowid, high_water) in [
        ("a", 1.0, 1, None),
        ("b", 2.0, 2, Some(2)),
        ("a' OR 1=1 --", 1.0, 1, Some(2)),
        ("a", f64::NAN, 1, Some(2)),
        ("a", f64::INFINITY, 1, Some(2)),
        ("a", 1.0, -1, Some(2)),
        ("a", 0.0, 1, Some(2)),
        ("a", 1.0, 1, Some(0)),
    ] {
        let mut req = request("scope");
        req.high_water = high_water;
        req.after = Some(ExportCursor {
            session_id: session.into(),
            timestamp,
            rowid,
        });
        assert!(
            matches!(
                store.export_page(&req, "test"),
                Err(ExportError::InvalidRequest)
            ),
            "{req:?}"
        );
    }
    for count in [0, 257, usize::MAX] {
        let mut req = request("scope");
        req.max_records = count;
        assert!(matches!(
            store.export_page(&req, "test"),
            Err(ExportError::ResourceLimit)
        ));
    }
    for bytes in [0, MAX_EXPORT_BYTES + 1, usize::MAX] {
        let mut req = request("scope");
        req.max_bytes = bytes;
        assert!(matches!(
            store.export_page(&req, "test"),
            Err(ExportError::ResourceLimit)
        ));
    }
    assert!(
        serde_json::from_value::<ExportPageRequest>(json!({"max_records":1,"max_bytes":100}))
            .is_err()
    );
    assert!(serde_json::from_value::<ExportPageRequest>(
        json!({"workspace":"scope","max_records":1,"max_bytes":100,"path":"arbitrary"})
    )
    .is_err());
}

#[test]
fn stable_keyset_pages_preserve_duplicates_and_exclude_new_late_records() {
    let root = tempdir().unwrap();
    let store = MemoryStore::open(root.path()).unwrap();
    store
        .ingest_many(&[
            record("b", "scope", "z", 2.0),
            record("a2", "scope", "a", 2.0),
            record("a1", "scope", "a", 1.0),
            record("a3", "scope", "a", 2.0),
            record("other", "elsewhere", "a", 0.0),
        ])
        .unwrap();
    store.prepare_export_index().unwrap();
    let mut req = request("scope");
    req.max_records = 2;
    let first = store.export_page(&req, "test").unwrap();
    assert_eq!(
        first
            .records
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        ["a1", "a2"]
    );
    assert_eq!(first.records[0], record("a1", "scope", "a", 1.0));
    assert_eq!(first.high_water, 5);
    store
        .ingest_many(&[
            record("late", "scope", "a", 1.5),
            record("new", "scope", "zz", 5.0),
        ])
        .unwrap();
    req.high_water = Some(first.high_water);
    req.after = first.next;
    let second = store.export_page(&req, "test").unwrap();
    assert_eq!(
        second
            .records
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        ["a3", "b"]
    );
    assert_eq!(second.high_water, 5);
    assert!(second.next.is_none());
}

#[test]
fn explicit_preparation_is_required_and_empty_page_is_read_only() {
    let root = tempdir().unwrap();
    let store = MemoryStore::open(root.path()).unwrap();
    assert!(matches!(
        store.export_page(&request("scope"), "test"),
        Err(ExportError::Unprepared)
    ));
    store.prepare_export_index().unwrap();
    store.prepare_export_index().unwrap();
    let page = store.export_page(&request("scope"), "test").unwrap();
    assert!(page.records.is_empty());
    assert!(page.next.is_none());
    assert_eq!(page.high_water, 0);
}
