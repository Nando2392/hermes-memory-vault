use super::*;

#[cfg(windows)]
#[test]
fn tiny_ordinary_import_traverses_all_operations_and_exact_stopped_projection_and_export() {
    use std::io::{BufRead, Read};
    let temp = tempfile::tempdir().unwrap();
    let generation = data::generate_with_spec(
        &temp.path().join("seed"),
        &data::FixtureSpec {
            shape: data::FixtureShape::RepresentativeV2,
            target_jsonl_bytes: 32768,
        },
    )
    .unwrap();
    let seeds = generation["seed_records"].as_u64().unwrap();
    assert_eq!(seeds, 16);
    let m = FullManifest::new(WorkloadSpec::full20x256_v1(), seeds).unwrap();
    let root = temp.path().join("ordinary");
    let store = hermes_memory::MemoryStore::open(&root).unwrap();
    store
        .import_logical_archive_once(
            std::io::BufReader::new(
                std::fs::File::open(temp.path().join("seed/archive.jsonl")).unwrap(),
            ),
            generation["logical_sha256"].as_str().unwrap(),
        )
        .unwrap();
    let snapshot_line =
        std::io::BufReader::new(std::fs::File::open(root.join("events.jsonl")).unwrap())
            .lines()
            .next()
            .unwrap()
            .unwrap();
    let snapshot: hermes_memory::MemoryRecord = serde_json::from_str(&snapshot_line).unwrap();
    let item = &data::snapshot().items[0];
    assert_eq!(snapshot.content, item.content);
    assert_eq!(snapshot.metadata, item.metadata);
    let mut cursor = m.continuation();
    let mut exported = false;
    while let Some(op) = cursor.next_operation().unwrap() {
        let bytes_before = std::fs::metadata(root.join("events.jsonl")).unwrap().len();
        let hash_before = if op.id >= 42 {
            Some(data::hash_file(&root.join("events.jsonl")).unwrap())
        } else {
            None
        };
        let (inserted, duplicates, sessions) = match op.stage {
            Stage::UnchangedSnapshot => {
                let (i, d) = store.ingest_snapshot(&data::snapshot()).unwrap();
                (i as u64, d as u64, None)
            }
            Stage::Export => {
                use hermes_memory::broker_export::ExportPageRequest;
                store.prepare_export_index().unwrap();
                let mut request = ExportPageRequest {
                    workspace: data::WORKSPACE.into(),
                    high_water: None,
                    after: None,
                    max_records: 128,
                    max_bytes: 1024 * 1024,
                };
                let mut counts = [0u64; 18];
                let mut last_session = String::new();
                loop {
                    let page = store.export_page(&request, "ordinary-full-test").unwrap();
                    for record in &page.records {
                        assert!(record.session_id >= last_session);
                        last_session.clone_from(&record.session_id);
                        let (slot, expected) = if record.session_id == "benchmark-client" {
                            (
                                16,
                                FullManifest::addition_record(counts[16] as u32).unwrap(),
                            )
                        } else if record.session_id == "benchmark-snapshot" {
                            (17, snapshot.clone())
                        } else {
                            let slot: usize = record
                                .session_id
                                .strip_prefix("benchmark-seed-")
                                .unwrap()
                                .parse()
                                .unwrap();
                            (
                                slot,
                                data::representative_record(slot as u64 + counts[slot] * 16)
                                    .unwrap(),
                            )
                        };
                        assert_eq!(*record, expected);
                        counts[slot] += 1;
                    }
                    request.high_water = Some(page.high_water);
                    request.after = page.next;
                    if request.after.is_none() {
                        break;
                    }
                }
                assert_eq!(&counts[..16], &[1; 16]);
                assert_eq!(counts[16], m.expected_additions());
                assert_eq!(counts[17], 1);
                assert_eq!(counts.iter().sum::<u64>(), m.final_records());
                exported = true;
                (0, 0, Some(18))
            }
            _ => {
                let (i, d) = store.ingest_many(&m.records(op.id).unwrap()).unwrap();
                (i as u64, d as u64, None)
            }
        };
        assert_eq!(
            std::fs::metadata(root.join("events.jsonl")).unwrap().len(),
            bytes_before + op.appended_jsonl_bytes
        );
        if let Some(hash) = hash_before {
            assert_eq!(hash, data::hash_file(&root.join("events.jsonl")).unwrap());
        }
        cursor
            .acknowledge(
                &Ack {
                    schema: 1,
                    operation_id: op.id,
                    cli_epoch: op.cli_epoch,
                    payload_bytes: op.payload_bytes,
                    inserted,
                    duplicates,
                    sessions,
                },
                &m.payload(op.id).unwrap(),
            )
            .unwrap();
    }
    assert!(cursor.complete() && exported);
    drop(store);
    let database = root.join("memory.db");
    for suffix in ["-wal", "-shm"] {
        assert!(!std::path::PathBuf::from(format!("{}{suffix}", database.display())).exists());
    }
    let receipt = hermes_memory::logical_migration::export_from_staged_sqlite_copy(
        &database,
        std::io::sink(),
    )
    .unwrap();
    assert_eq!(receipt.records, m.final_records());
    assert_eq!((receipt.snapshot_states, receipt.snapshot_counters), (1, 1));
    let connection = rusqlite::Connection::open_with_flags(
        &database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM snapshot_state", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT next_occurrence FROM snapshot_counters", [], |r| r
                .get::<_, u64>(
                0
            ))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row("SELECT record_id FROM snapshot_state", [], |r| r
                .get::<_, String>(0))
            .unwrap(),
        snapshot.id
    );
    let source_path = temp
        .path()
        .join("seed/source/memory.db")
        .to_string_lossy()
        .replace('\\', "/");
    let mut source_uri = String::from("file:");
    for byte in source_path.bytes() {
        if byte.is_ascii_alphanumeric() || b"/:._-".contains(&byte) {
            source_uri.push(byte as char);
        } else {
            source_uri.push_str(&format!("%{byte:02X}"));
        }
    }
    source_uri.push_str("?mode=ro&immutable=1");
    let source_connection = rusqlite::Connection::open_with_flags(
        source_uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .unwrap();
    for sql in [
        "SELECT json_array(session_id,workspace,position,fingerprint,record_id) FROM snapshot_state",
        "SELECT json_array(session_id,workspace,fingerprint,next_occurrence) FROM snapshot_counters",
    ] {
        let original: String = source_connection.query_row(sql, [], |r| r.get(0)).unwrap();
        let final_state: String = connection.query_row(sql, [], |r| r.get(0)).unwrap();
        assert_eq!(final_state, original);
    }
    drop(source_connection);
    let imported: String = connection
        .query_row(
            "SELECT receipt_json FROM broker_migrations WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let imported: serde_json::Value = serde_json::from_str(&imported).unwrap();
    for key in [
        "records",
        "snapshot_states",
        "snapshot_counters",
        "logical_sha256",
    ] {
        assert_eq!(imported[key], generation[key]);
    }
    let mut reader =
        std::io::BufReader::new(std::fs::File::open(root.join("events.jsonl")).unwrap());
    let mut rows = connection.prepare("SELECT id,session_id,workspace,kind,content,timestamp,metadata_json FROM records ORDER BY timestamp,id").unwrap();
    let mut rows = rows.query([]).unwrap();
    for expected in std::iter::once(Ok(snapshot)).chain(m.expected_seed_and_addition_records()) {
        let expected = expected.unwrap();
        let mut line = Vec::new();
        (&mut reader)
            .take(4097)
            .read_until(b'\n', &mut line)
            .unwrap();
        assert!(line.len() <= 4096 && line.last() == Some(&b'\n'));
        assert_eq!(
            serde_json::from_slice::<hermes_memory::MemoryRecord>(&line).unwrap(),
            expected
        );
        let row = rows.next().unwrap().unwrap();
        let actual = hermes_memory::MemoryRecord {
            id: row.get(0).unwrap(),
            session_id: row.get(1).unwrap(),
            workspace: row.get(2).unwrap(),
            kind: row.get(3).unwrap(),
            content: row.get(4).unwrap(),
            timestamp: row.get(5).unwrap(),
            metadata: serde_json::from_str(&row.get::<_, String>(6).unwrap()).unwrap(),
        };
        assert_eq!(actual, expected);
    }
    assert!(rows.next().unwrap().is_none());
    assert_eq!(reader.read(&mut [0]).unwrap(), 0);
    assert_eq!(
        data::inventory(&temp.path().join("seed/source")).unwrap(),
        generation["source_before"]
    );
}

#[test]
fn continuation_advances_only_after_exact_matching_ack() {
    let m = FullManifest::new(WorkloadSpec::full20x256_v1(), 16).unwrap();
    let mut cursor = m.continuation();
    for id in 0..64 {
        let op = cursor.next_operation().unwrap().unwrap();
        assert_eq!(op.id, id);
        let payload = m.payload(id).unwrap();
        let ack = Ack {
            schema: 1,
            operation_id: id,
            cli_epoch: op.cli_epoch,
            payload_bytes: op.payload_bytes,
            inserted: op.inserted,
            duplicates: op.duplicates,
            sessions: op.sessions,
        };
        for field in 0..7 {
            let mut wrong = ack.clone();
            match field {
                0 => wrong.schema += 1,
                1 => wrong.operation_id += 1,
                2 => wrong.cli_epoch += 1,
                3 => wrong.payload_bytes += 1,
                4 => wrong.inserted += 1,
                5 => wrong.duplicates += 1,
                _ => wrong.sessions = Some(99),
            }
            assert!(cursor.acknowledge(&wrong, &payload).is_err());
            assert_eq!(cursor.next_operation().unwrap().unwrap().id, id);
        }
        let mut bad_payload = payload.clone();
        if bad_payload.is_empty() {
            bad_payload.push(b'x');
        } else {
            bad_payload[0] ^= 1;
        }
        assert!(cursor.acknowledge(&ack, &bad_payload).is_err());
        cursor.acknowledge(&ack, &payload).unwrap();
        assert!(cursor.acknowledge(&ack, &payload).is_err());
    }
    assert!(cursor.next_operation().unwrap().is_none());
    assert!(cursor.complete());
}

#[test]
fn expected_records_stream_without_materializing_the_corpus() {
    let m = FullManifest::new(WorkloadSpec::full20x256_v1(), 16).unwrap();
    let mut expected = m.expected_seed_and_addition_records();
    for i in 0..16 {
        assert_eq!(
            expected.next().unwrap().unwrap(),
            data::representative_record(i).unwrap()
        );
    }
    for id in 0..42 {
        for record in m.records(id).unwrap() {
            assert_eq!(expected.next().unwrap().unwrap(), record);
        }
    }
    assert!(expected.next().is_none());
    let large = FullManifest::new(WorkloadSpec::full20x256_v1(), data::MAX_SEED_RECORDS).unwrap();
    assert_eq!(
        large.expected_seed_and_addition_records().take(2).count(),
        2
    );
}

#[test]
fn payloads_are_exact_bounded_case_independent_and_replays_are_byte_identical() {
    let m = FullManifest::new(WorkloadSpec::full20x256_v1(), 16).unwrap();
    let large = FullManifest::new(WorkloadSpec::full20x256_v1(), data::MAX_SEED_RECORDS).unwrap();
    let mut previous = data::representative_record(data::MAX_SEED_RECORDS - 1)
        .unwrap()
        .timestamp;
    let mut ids = std::collections::BTreeSet::new();
    let mut additions = 0;
    for id in 0..64 {
        let op = m.operation(id).unwrap();
        let payload = m.payload(id).unwrap();
        assert_eq!(payload, large.payload(id).unwrap());
        assert_eq!(op.payload_bytes, payload.len() as u64);
        assert!(payload.len() < 2 * 1024 * 1024);
        let records = m.records(id).unwrap();
        assert_eq!(records.len(), op.records as usize);
        if id < 42 {
            assert_eq!(
                serde_json::from_slice::<Vec<hermes_memory::MemoryRecord>>(&payload).unwrap(),
                records
            );
            let jsonl_bytes: u64 = records
                .iter()
                .map(|r| serde_json::to_vec(r).unwrap().len() as u64 + 1)
                .sum();
            assert_eq!(op.appended_jsonl_bytes, jsonl_bytes);
            for r in records {
                assert!(ids.insert(r.id.clone()));
                assert!(r.timestamp.is_finite() && r.timestamp > previous);
                assert_eq!(r.content.len(), 2048);
                assert!(r.content.is_ascii());
                assert_ne!(r.id, data::TwoWarmupManifest.record(0).unwrap().id);
                previous = r.timestamp;
                additions += 1;
            }
        } else {
            assert_eq!(op.appended_jsonl_bytes, 0);
            if id < 62 {
                assert_eq!(payload, m.payload(id - 20).unwrap());
            }
        }
    }
    assert_eq!(additions, m.expected_additions());
    let s = data::snapshot();
    let i = &s.items[0];
    assert_eq!(m.payload(62).unwrap(), serde_json::to_vec(&serde_json::json!({"session_id":s.session_id,"workspace":s.workspace,"items":[{"kind":i.kind,"content":i.content,"timestamp":i.timestamp,"metadata":i.metadata}]})).unwrap());
    assert!(m.payload(63).unwrap().is_empty());
    assert_eq!(m.operation(63).unwrap().sessions, Some(18));
    assert!(m.records(64).is_err());
    assert!(m.payload(u32::MAX).is_err());
}

#[test]
fn invalid_manifests_fail_closed_before_generation() {
    for schema in [0, 2, 255] {
        let spec = WorkloadSpec {
            schema,
            kind: WorkloadKind::Full20x256V1,
        };
        assert!(FullManifest::new(spec, 16).is_err());
    }
    for seeds in [0, 1, 15, data::MAX_SEED_RECORDS + 1, u64::MAX] {
        assert!(FullManifest::new(WorkloadSpec::full20x256_v1(), seeds).is_err());
    }
    for wire in [
        r#"{"schema":1,"kind":"unknown"}"#,
        r#"{"schema":1,"kind":"Full20x256V1","count":64}"#,
        r#"{"schema":1}"#,
        r#"{"schema":256,"kind":"Full20x256V1"}"#,
    ] {
        assert!(serde_json::from_str::<WorkloadSpec>(wire).is_err());
    }
    let maximum = FullManifest::new(WorkloadSpec::full20x256_v1(), data::MAX_SEED_RECORDS).unwrap();
    assert_eq!(maximum.final_records(), data::MAX_SEED_RECORDS + 5143);
}

#[test]
fn closed_schedule_has_exact_counts_ids_epochs_and_replay_sources() {
    let manifest = FullManifest::new(WorkloadSpec::full20x256_v1(), 16).unwrap();
    assert_eq!(FullManifest::OPERATIONS, 64);
    assert_eq!(manifest.expected_additions(), 5142);
    assert_eq!(manifest.final_records(), 5159);
    let mut epochs = std::collections::BTreeSet::new();
    let mut counts = [0; 6];
    for id in 0..64 {
        let op = manifest.operation(id).unwrap();
        assert_eq!(op.id, id);
        assert!(epochs.insert(op.cli_epoch));
        assert_eq!(op.cli_epoch, 3 + u64::from(id));
        counts[op.stage as usize] += 1;
        match id {
            0..=21 => assert_eq!((op.records, op.inserted, op.duplicates), (1, 1, 0)),
            22..=41 => assert_eq!((op.records, op.inserted, op.duplicates), (256, 256, 0)),
            42..=61 => {
                assert_eq!((op.records, op.inserted, op.duplicates), (256, 0, 256));
                assert_eq!(op.replay_source, Some(id - 20));
            }
            _ => assert_eq!((op.records, op.inserted, op.duplicates), (0, 0, 0)),
        }
    }
    assert_eq!(counts, [2, 20, 20, 20, 1, 1]);
    assert!(manifest.operation(64).is_err());
}

#[test]
fn wire_rejection_matrix_preserves_continuation() {
    use serde_json::json;
    let m = FullManifest::new(WorkloadSpec::full20x256_v1(), 16).unwrap();
    let op = m.operation(0).unwrap();
    let ack = Ack {
        schema: 1,
        operation_id: 0,
        cli_epoch: op.cli_epoch,
        payload_bytes: op.payload_bytes,
        inserted: 1,
        duplicates: 0,
        sessions: None,
    };
    let original = serde_json::to_value(&ack).unwrap();
    let mut wires = vec![
        "{".to_owned(),
        "[]".to_owned(),
        format!(
            "{},\"schema\":1}}",
            serde_json::to_string(&ack).unwrap().trim_end_matches('}')
        ),
    ];
    for field in [
        "schema",
        "operation_id",
        "cli_epoch",
        "payload_bytes",
        "inserted",
        "duplicates",
        "sessions",
    ] {
        for value in [json!(true), json!("1"), json!(1.5), json!(-1)] {
            let mut bad = original.clone();
            bad[field] = value;
            wires.push(serde_json::to_string(&bad).unwrap());
        }
        if field != "sessions" {
            let mut bad = original.clone();
            bad[field] = json!(null);
            wires.push(serde_json::to_string(&bad).unwrap());
            let mut bad = original.clone();
            bad.as_object_mut().unwrap().remove(field);
            wires.push(serde_json::to_string(&bad).unwrap());
        }
        let limit = match field {
            "schema" => "256",
            "operation_id" => "4294967296",
            _ => "18446744073709551616",
        };
        let mut overflow = original.clone();
        overflow[field] = json!("OVERFLOW_VALUE");
        wires.push(
            serde_json::to_string(&overflow)
                .unwrap()
                .replace("\"OVERFLOW_VALUE\"", limit),
        );
    }
    let mut unknown = original.clone();
    unknown["unknown"] = json!(0);
    wires.push(serde_json::to_string(&unknown).unwrap());
    let mut cursor = m.continuation();
    for wire in wires {
        assert!(serde_json::from_str::<Ack>(&wire).is_err(), "{wire}");
    }
    let mut future = ack;
    future.operation_id = u32::MAX;
    assert!(cursor.acknowledge(&future, &m.payload(0).unwrap()).is_err());
    assert_eq!(cursor.next_operation().unwrap().unwrap().id, 0);
    for field in ["schema", "kind"] {
        for value in [json!(true), json!("1"), json!(1.5), json!(null), json!(-1)] {
            let mut bad = serde_json::to_value(WorkloadSpec::full20x256_v1()).unwrap();
            bad[field] = value;
            assert!(serde_json::from_value::<WorkloadSpec>(bad).is_err());
        }
    }
    for wire in [
        r#"{"schema":1,"schema":1,"kind":"Full20x256V1"}"#,
        r#"{"schema":18446744073709551616,"kind":"Full20x256V1"}"#,
        "{",
        "null",
    ] {
        assert!(serde_json::from_str::<WorkloadSpec>(wire).is_err());
    }
}
