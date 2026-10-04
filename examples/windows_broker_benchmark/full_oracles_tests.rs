//! Ordinary SQLite/JSONL/renderer mutation probes; not native execution evidence.
#[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
use super::*;
#[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
use std::io::{Seek, SeekFrom, Write};

#[test]
fn stopped_streaming_oracles_bind_same_count_fields_order_state_and_notes() {
    #[cfg(not(any(windows, all(target_os = "linux", feature = "experimental-broker"))))]
    {
        crate::data::assert_owned_store_refusal(32768, "seed", "store");
    }
    #[cfg(any(windows, all(target_os = "linux", feature = "experimental-broker")))]
    {
        let temp = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
        let root = temp.path();
        let generation = data::generate_with_spec_for_owned_store(
            &root.join("seed"),
            &data::FixtureSpec {
                shape: data::FixtureShape::RepresentativeV2,
                target_jsonl_bytes: 32768,
            },
        )
        .unwrap();
        let manifest =
            FullManifest::new(crate::full_manifest::WorkloadSpec::full20x256_v1(), 16).unwrap();
        let store = data::open_owned_fixture_store(&root.join("store")).unwrap();
        store
            .import_logical_archive_once(
                BufReader::new(File::open(root.join("seed/archive.jsonl")).unwrap()),
                generation["logical_sha256"].as_str().unwrap(),
            )
            .unwrap();
        for id in 0..62 {
            store.ingest_many(&manifest.records(id).unwrap()).unwrap();
        }
        assert_eq!(store.ingest_snapshot(&data::snapshot()).unwrap(), (0, 0));
        store.prepare_export_index().unwrap();
        let mut counts = [0u64; 18];
        let mut processed = 0u64;
        let mut last_session = String::new();
        let mut pages = 0;
        let snapshot = snapshot(&root.join("seed/source/events.jsonl")).unwrap();
        let mut expected_additions = manifest.expected_seed_and_addition_records().skip(16);
        let sessions = hermes_memory::client_export::render_markdown(
            &root.join("export"),
            WORKSPACE,
            |request| {
                let page = store.export_page(request, "ordinary-oracle").unwrap();
                assert_eq!(page.high_water, manifest.final_records() as i64);
                assert!(page.records.len() <= request.max_records && request.max_records <= 256);
                assert!(
                serde_json::to_vec(
                    &json!({"protocol":1,"request_id":"ordinary-oracle","ok":true,"result":page})
                )
                .unwrap()
                .len()
                    <= request.max_bytes
            );
                let mut expected_cursor = None;
                for actual in &page.records {
                    assert!(actual.session_id >= last_session);
                    last_session.clone_from(&actual.session_id);
                    let (slot, expected, rowid) = if actual.session_id == "benchmark-client" {
                        let ordinal = counts[16] as usize;
                        let expected = expected_additions.next().unwrap().unwrap();
                        (16, expected, 18 + ordinal as i64)
                    } else if actual.session_id == "benchmark-snapshot" {
                        (17, snapshot.clone(), 1)
                    } else {
                        let slot: usize = actual
                            .session_id
                            .strip_prefix("benchmark-seed-")
                            .unwrap()
                            .parse()
                            .unwrap();
                        assert!(slot < 16);
                        let ordinal = slot as u64 + counts[slot] * 16;
                        (
                            slot,
                            data::representative_record(ordinal).unwrap(),
                            ordinal as i64 + 2,
                        )
                    };
                    assert_eq!(*actual, expected);
                    expected_cursor = Some(hermes_memory::broker_export::ExportCursor {
                        session_id: expected.session_id,
                        timestamp: expected.timestamp,
                        rowid,
                    });
                    counts[slot] += 1;
                    processed += 1;
                }
                assert_eq!(page.next.is_some(), processed < manifest.final_records());
                if page.next.is_some() {
                    assert_eq!(page.next, expected_cursor);
                }
                pages += 1;
                Ok(page)
            },
        )
        .unwrap();
        assert_eq!(sessions, 18);
        assert_eq!(processed, manifest.final_records());
        assert_eq!(counts[16], 5142);
        assert_eq!(counts[17], 1);
        assert!(pages > 1);
        drop(store);
        let database = root.join("store/memory.db");
        let projection = root.join("store/events.jsonl");
        let source = root.join("seed/source/events.jsonl");
        let vault = root.join("export");
        verify_stopped_sqlite(&database, &generation, &manifest).unwrap();
        verify_projection(&projection, &source, &manifest).unwrap();
        verify_export(&vault, &source, &manifest).unwrap();
        assert!(fs::metadata(&projection).unwrap().len() > 8 * 1024 * 1024);

        // Same row count; unchanged projection/receipt cannot mask SQLite drift.
        for (table, column, key, value) in [
            (
                "records",
                "content",
                "id='benchmark-full20x256-v1-000000'",
                "same-count changed content",
            ),
            (
                "records",
                "metadata_json",
                "id='benchmark-full20x256-v1-000000'",
                "{\"ordinal\":0,\"workload\":\"changed\"}",
            ),
            (
                "snapshot_state",
                "record_id",
                "position=0",
                "different-identity",
            ),
        ] {
            let connection = rusqlite::Connection::open(&database).unwrap();
            let original: String = connection
                .query_row(
                    &format!("SELECT {column} FROM {table} WHERE {key}"),
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            connection
                .execute(
                    &format!("UPDATE {table} SET {column}=?1 WHERE {key}"),
                    [value],
                )
                .unwrap();
            drop(connection);
            assert!(verify_stopped_sqlite(&database, &generation, &manifest).is_err());
            let connection = rusqlite::Connection::open(&database).unwrap();
            connection
                .execute(
                    &format!("UPDATE {table} SET {column}=?1 WHERE {key}"),
                    [original],
                )
                .unwrap();
            drop(connection);
        }
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute("UPDATE snapshot_counters SET next_occurrence=2", [])
            .unwrap();
        drop(connection);
        assert!(verify_stopped_sqlite(&database, &generation, &manifest).is_err());
        let connection = rusqlite::Connection::open(&database).unwrap();
        connection
            .execute("UPDATE snapshot_counters SET next_occurrence=1", [])
            .unwrap();
        drop(connection);

        // Swap two complete, equal-length JSONL additions without changing size/count.
        let offset = generation["jsonl_bytes"].as_u64().unwrap();
        let mut first = serde_json::to_vec(&manifest.records(0).unwrap()[0]).unwrap();
        first.push(b'\n');
        let mut second = serde_json::to_vec(&manifest.records(1).unwrap()[0]).unwrap();
        second.push(b'\n');
        assert_eq!(first.len(), second.len());
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&projection)
            .unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&second).unwrap();
        file.write_all(&first).unwrap();
        file.sync_all().unwrap();
        assert!(verify_projection(&projection, &source, &manifest).is_err());
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(&first).unwrap();
        file.write_all(&second).unwrap();
        file.sync_all().unwrap();
        for field in ["metadata", "content", "id"] {
            let mut changed: Value = serde_json::from_slice(&first).unwrap();
            if field == "metadata" {
                changed[field]["workload"] = json!("Xull20x256-v1");
            } else {
                let text = changed[field].as_str().unwrap();
                changed[field] = json!(format!("X{}", &text[1..]));
            }
            let mut bytes = serde_json::to_vec(&changed).unwrap();
            bytes.push(b'\n');
            assert_eq!(bytes.len(), first.len());
            // Keep a valid same-size, same-count JSONL stream.
            file.seek(SeekFrom::Start(offset)).unwrap();
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
            assert!(verify_projection(&projection, &source, &manifest).is_err());
            file.seek(SeekFrom::Start(offset)).unwrap();
            file.write_all(&first).unwrap();
            file.sync_all().unwrap();
        }
        drop(file);
        verify_projection(&projection, &source, &manifest).unwrap();
        let index = vault.join("Index.md");
        let original = fs::read(&index).unwrap();
        fs::write(&index, b"# Hermes Memory Vault\n\n").unwrap();
        assert!(verify_export(&vault, &source, &manifest).is_err());
        fs::write(&index, original).unwrap();
        let note = vault
            .join("Sessions")
            .join(full_segment(WORKSPACE))
            .join(format!("{}.md", full_segment("benchmark-client")));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&note)
            .unwrap();
        let mut prefix = vec![0; 4096];
        file.read_exact(&mut prefix).unwrap();
        let offset = prefix
            .windows(b"ordinary".len())
            .position(|w| w == b"ordinary")
            .unwrap() as u64;
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(b"X").unwrap();
        file.sync_all().unwrap();
        assert!(verify_export(&vault, &source, &manifest).is_err());
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(b"o").unwrap();
        file.sync_all().unwrap();
        drop(file);
        verify_export(&vault, &source, &manifest).unwrap();
        verify_stopped_sqlite(&database, &generation, &manifest).unwrap();
    }
}
