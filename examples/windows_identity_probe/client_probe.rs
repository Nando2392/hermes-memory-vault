//! Compatibility executable proof within the existing owned SCM fixture.
use super::*;

fn enrollment(root: &Path, config: &Config, service: &str, hash: &str) -> Value {
    json!({"schema":1,"profile_root":root.join("compat-legacy-root"),"service_name":service,"server_sid":config.server,"client_sid":config.client,"pipe":config.pipe,"workspaces":[WORKSPACE],"release_sha256":hash})
}

// The parent owns all newly-created paths; no inherited source ACLs or overwrites.
pub(super) fn prepare(
    root: &Path,
    config: &Config,
    service: &str,
    broker_hash: &str,
    release: &Path,
) -> Result<Value> {
    let source = release.join("hermes-memory-client.exe");
    let target = root.join("bin/hermes-memory-client.exe");
    let hash = copy_new(&source, &target)?;
    let value = enrollment(root, config, service, broker_hash);
    write_report(root, "compat-enrollment.json", &value)?;
    let mut wrong_server = value.clone();
    wrong_server["server_sid"] = json!(config.client);
    write_report(root, "compat-wrong-server.json", &wrong_server)?;
    Ok(
        json!({"source":source,"executable":target,"sha256":hash,"enrollment":value,"enrollment_path":root.join("compat-enrollment.json"),"release_sha256_provenance":"actual compiled broker fixture hash; NOT a published release"}),
    )
}

fn launch(
    executable: &Path,
    dir: &Path,
    label: &str,
    args: &[String],
    input: &[u8],
    expected_user: &str,
) -> Result<Value> {
    use std::io::Write;
    use std::os::windows::io::AsRawHandle;
    use std::process::{Command, Stdio};
    let create = |extension: &str| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(format!("{label}.{extension}")))
    };
    let mut stdin = create("stdin")?;
    stdin.write_all(input)?;
    drop(stdin);
    let mut child = Command::new(executable)
        .args(args)
        .stdin(Stdio::from(fs::File::open(
            dir.join(format!("{label}.stdin")),
        )?))
        .stdout(Stdio::from(create("stdout")?))
        .stderr(Stdio::from(create("stderr")?))
        .spawn()?;
    let token = identity_of(child.as_raw_handle().cast());
    let status = wait_child(&mut child, Instant::now() + Duration::from_secs(20))?;
    let token = token?;
    ensure(
        token["user"] == expected_user,
        "compatibility child TokenUser is not B",
    )?;
    let read = |extension: &str| -> Result<String> {
        let path = dir.join(format!("{label}.{extension}"));
        ensure(
            fs::metadata(&path)?.len() <= 65536,
            "oversized compatibility process receipt",
        )?;
        Ok(fs::read_to_string(path)?)
    };
    let stdout = read("stdout")?;
    let stderr = read("stderr")?;
    let response = serde_json::from_str::<Value>(&stdout).ok();
    Ok(
        json!({"executable":executable,"args":args,"exit":status.code(),"stdout":stdout,"stderr":stderr,"response":response,"child_identity":token}),
    )
}

// Only the gated hosted B worker calls this; unit tests never provision services.
pub(super) fn run(root: &Path, config: &Config, before_seed: &Value) -> Result<Value> {
    let profile = root.join("compat-legacy-root");
    let enrollment = root.join("compat-enrollment.json");
    let scratch = root.join("scratch");
    ensure(
        !profile.try_exists()?,
        "compatibility profile existed before request",
    )?;
    let invoke =
        |label: &str, enrollment: &Path, profile: &Path, op: &str, extra: &[&str], input: &[u8]| {
            launch(
                &root.join("bin/hermes-memory-client.exe"),
                &scratch,
                label,
                &arguments(enrollment, profile, op, extra),
                input,
                &config.client,
            )
        };
    let good = |label: &str, op: &str, extra: &[&str], input: &[u8]| -> Result<Value> {
        let receipt = invoke(label, &enrollment, &profile, op, extra, input)?;
        ensure(
            receipt["exit"] == 0 && receipt["stderr"] == "",
            &format!("compatibility CLI failed: {receipt}"),
        )?;
        Ok(receipt)
    };
    let fixture = read_report(&root.join("migration"), "fixture.json", deadline())?;
    let migration = bootstrap_probe::verify_client(&fixture, good)?;
    let duplicate = good(
        "compat-duplicate",
        "ingest",
        &[],
        &serde_json::to_vec(&record())?,
    )?;
    ensure(
        duplicate["response"] == json!({"inserted":0,"duplicates":1}),
        "legacy duplicate stdout differs",
    )?;
    let overlap = good(
        "compat-overlap",
        "snapshot",
        &[],
        &serde_json::to_vec(&snapshot())?,
    )?;
    ensure(
        overlap["response"] == json!({"inserted":0,"duplicates":0}),
        "legacy snapshot overlap stdout differs",
    )?;
    let search = good(
        "compat-search",
        "search",
        &[
            "--query",
            "quince",
            "--workspace",
            WORKSPACE,
            "--limit",
            "20",
            "--max-bytes",
            "65536",
        ],
        b"",
    )?;
    let original = before_seed["response"]["result"]["hits"]
        .as_array()
        .ok_or("original records missing")?;
    ensure(
        search["response"] == json!(original),
        "compatibility Unicode/metadata/search shape differs",
    )?;

    // Do not mutate either ACL; opening with the exact mutation right must fail.
    let positive = scratch.join("compat-owned-control");
    fs::write(&positive, b"B owns this scratch file")?;
    let mut acl = Vec::new();
    for (target, path, rights, expected) in [
        (
            "owned_scratch",
            positive,
            vec![("write", GENERIC_WRITE), ("WRITE_DAC", WRITE_DAC)],
            0,
        ),
        (
            "protected_enrollment",
            enrollment.clone(),
            vec![("write", GENERIC_WRITE), ("WRITE_DAC", WRITE_DAC)],
            ERROR_ACCESS_DENIED,
        ),
        (
            "canonical_storage",
            root.join("runtime-store/memory.db"),
            vec![
                ("read", GENERIC_READ),
                ("write", GENERIC_WRITE),
                ("WRITE_DAC", WRITE_DAC),
            ],
            ERROR_ACCESS_DENIED,
        ),
    ] {
        for (operation, access) in rights {
            let code = access_code(&path, access);
            ensure(
                code == expected,
                &format!("compatibility ACL {target} {operation}: {code}"),
            )?;
            acl.push(json!({"target":target,"operation":operation,"win32_error":code}));
        }
    }
    let counterfeit = scratch.join("compat-counterfeit.json");
    let bytes = fs::read(&enrollment)?;
    use std::io::Write;
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&counterfeit)?
        .write_all(&bytes)?;
    ensure(
        fs::read(&counterfeit)? == bytes,
        "counterfeit control bytes differ",
    )?;
    let mut poison = record();
    poison["id"] = json!("compat-negative-must-not-be-stored");
    let poison = serde_json::to_vec(&poison)?;
    let counterfeit_receipt = invoke(
        "compat-counterfeit",
        &counterfeit,
        &profile,
        "ingest",
        &[],
        &poison,
    )?;
    denied(&counterfeit_receipt, "unauthorized")?;
    let wrong_root = scratch.join("compat-wrong-root");
    let root_receipt = invoke(
        "compat-wrong-root",
        &enrollment,
        &wrong_root,
        "ingest",
        &[],
        &poison,
    )?;
    denied(&root_receipt, "unauthorized")?;
    ensure(!wrong_root.try_exists()?, "wrong root was created")?;
    let scope_receipt = invoke(
        "compat-wrong-scope",
        &enrollment,
        &profile,
        "search",
        &["--query", "quince", "--workspace", "other"],
        b"",
    )?;
    denied(&scope_receipt, "unauthorized")?;
    let server_receipt = invoke(
        "compat-wrong-server",
        &root.join("compat-wrong-server.json"),
        &profile,
        "ingest",
        &[],
        &poison,
    )?;
    denied(&server_receipt, "unauthorized")?;

    // Earlier two-row/restart checks are already complete. One real CLI ingest
    // now crosses the renderer's 256-record boundary within a single session.
    let seed_records = paged_records();
    let seed = good(
        "compat-seed",
        "ingest",
        &[],
        &serde_json::to_vec(&seed_records)?,
    )?;
    ensure(
        seed["response"] == json!({"inserted":260,"duplicates":0}),
        "compatibility seed counts differ",
    )?;
    let mut expected = original.clone();
    expected.extend(
        fixture["expected_records"]
            .as_array()
            .ok_or("migration expected records missing")?
            .iter()
            .cloned(),
    );
    expected.extend(seed_records);
    ensure(expected.len() == 264, "expected canonical count differs")?;
    let pages = verify_pages(&expected, |index, body| {
        call(
            root,
            config,
            &format!("compat-page-{index}"),
            "export_page",
            body,
            None,
        )
    })?;
    let scope_page = call(
        root,
        config,
        "compat-page-scope-denied",
        "export_page",
        json!({"workspace":"other","high_water":null,"after":null,"max_records":1,"max_bytes":60000}),
        Some("unauthorized"),
    )?;
    let vault = scratch.join("compat-vault");
    let export = good(
        "compat-export",
        "export",
        &[
            "--vault",
            vault.to_str().ok_or("vault path is not UTF-8")?,
            "--workspace",
            WORKSPACE,
        ],
        b"",
    )?;
    ensure(
        export["response"] == json!({"sessions":5}),
        "actual export did not report five sessions",
    )?;
    let markdown = verify_markdown(&vault, &expected)?;
    ensure(
        !profile.try_exists()?,
        "compatibility CLI created legacy storage root",
    )?;
    Ok(
        json!({"migration":migration,"duplicate":duplicate,"snapshot_overlap":overlap,"search":search,"acl":acl,"counterfeit":counterfeit_receipt,"wrong_root":root_receipt,"wrong_scope":scope_receipt,"wrong_server":server_receipt,"seed":seed,"pages":pages,"page_wrong_scope":scope_page,"export":export,"markdown":markdown,"profile_root_absent":true,"default_enrollment_path":"NOT_TESTED; explicit --enrollment uses same trust checker"}),
    )
}

pub(super) fn after_stop(root: &Path, config: &Config) -> Result<Value> {
    let profile = root.join("compat-legacy-root");
    let vault = root.join("scratch/compat-stopped-vault");
    let args = arguments(
        &root.join("compat-enrollment.json"),
        &profile,
        "export",
        &[
            "--vault",
            vault.to_str().ok_or("vault path is not UTF-8")?,
            "--workspace",
            WORKSPACE,
        ],
    );
    let receipt = launch(
        &root.join("bin/hermes-memory-client.exe"),
        &root.join("scratch"),
        "compat-stopped",
        &args,
        b"",
        &config.client,
    )?;
    denied(&receipt, "I/O error: unavailable")?;
    ensure(
        !profile.try_exists()? && !vault.try_exists()?,
        "stopped broker caused local storage/export fallback",
    )?;
    Ok(
        json!({"client":receipt,"profile_root_absent":true,"export_destination_absent":true,"stage":"after real C STOPPED and pinned process exited"}),
    )
}

fn arguments(enrollment: &Path, profile: &Path, op: &str, extra: &[&str]) -> Vec<String> {
    let mut args = vec![
        "--enrollment".into(),
        enrollment.to_string_lossy().into_owned(),
        op.into(),
        "--root".into(),
        profile.to_string_lossy().into_owned(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    args
}

fn access_code(path: &Path, access: u32) -> u32 {
    use std::os::windows::fs::OpenOptionsExt;
    error_code(
        fs::OpenOptions::new()
            .access_mode(access)
            .open(path)
            .map(drop),
    )
}

fn denied(receipt: &Value, error: &str) -> Result<()> {
    ensure(
        receipt["exit"] == 1
            && receipt["stdout"] == ""
            && receipt["stderr"]
                .as_str()
                .is_some_and(|s| s.trim() == format!("hermes-memory: {error}")),
        &format!("compatibility negative failed: {receipt}"),
    )
}

fn verify_pages(
    expected: &[Value],
    mut fetch: impl FnMut(usize, Value) -> Result<Value>,
) -> Result<Value> {
    use hermes_memory::broker_export::{ExportCursor, ExportPage};
    let mut pages = Vec::new();
    let mut records = Vec::new();
    let mut after: Option<ExportCursor> = None;
    let mut high_water: Option<i64> = None;
    loop {
        ensure(pages.len() < 4, "export pagination did not terminate")?;
        let receipt = fetch(
            pages.len(),
            json!({"workspace":WORKSPACE,"high_water":high_water,"after":after,"max_records":128,"max_bytes":60000}),
        )?;
        let page: ExportPage = serde_json::from_value(receipt["response"]["result"].clone())?;
        ensure(
            page.high_water > 0 && high_water.is_none_or(|h| h == page.high_water),
            "export high-water changed",
        )?;
        ensure(
            !page.records.is_empty() && page.records.len() <= 128,
            "invalid export page size",
        )?;
        if let Some(next) = &page.next {
            ensure(
                next.rowid > 0
                    && next.rowid <= page.high_water
                    && page.records.last().is_some_and(|r| {
                        r.session_id == next.session_id && r.timestamp == next.timestamp
                    }),
                "cursor does not bind last record",
            )?;
            if let Some(previous) = &after {
                ensure(
                    (next.session_id.as_str(), next.timestamp, next.rowid)
                        > (
                            previous.session_id.as_str(),
                            previous.timestamp,
                            previous.rowid,
                        ),
                    "cursor failed to advance",
                )?;
            }
        }
        records.extend(
            page.records
                .into_iter()
                .map(serde_json::to_value)
                .collect::<std::result::Result<Vec<_>, _>>()?,
        );
        high_water = Some(page.high_water);
        after = page.next;
        pages.push(receipt);
        if after.is_none() {
            break;
        }
    }
    let mut expected = expected.to_vec();
    expected.sort_by(|a, b| {
        a["session_id"]
            .as_str()
            .cmp(&b["session_id"].as_str())
            .then_with(|| {
                a["timestamp"]
                    .as_f64()
                    .partial_cmp(&b["timestamp"].as_f64())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });
    ensure(
        records == expected && pages.len() == 3,
        "paged full records/metadata differ from admitted records",
    )?;
    Ok(json!({"records":records.len(),"high_water":high_water,"pages":pages}))
}

fn paged_records() -> Vec<Value> {
    (0..260).map(|i| json!({"id":format!("compat-paged-{i:03}"),"session_id":"compat-paged-session","workspace":WORKSPACE,"kind":"note","content":format!("compat pagination {i:03} 日本語 ñ 🔐"),"timestamp":1000.0 + f64::from(i),"metadata":{"page_fixture":i,"nested":[true,"ñ"]}})).collect()
}

fn verify_markdown(vault: &Path, expected: &[Value]) -> Result<Value> {
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    let mut sessions = BTreeMap::<String, Vec<&Value>>::new();
    for record in expected {
        sessions
            .entry(
                record["session_id"]
                    .as_str()
                    .ok_or("missing session")?
                    .into(),
            )
            .or_default()
            .push(record);
    }
    let segment = |s: &str| {
        format!(
            "{s}-{}",
            &format!("{:x}", Sha256::digest(s.as_bytes()))[..16]
        )
    };
    let mut index = "# Hermes Memory Vault\n\n".to_string();
    let mut files = Vec::new();
    for (session, records) in &mut sessions {
        records.sort_by(|a, b| {
            a["timestamp"]
                .as_f64()
                .partial_cmp(&b["timestamp"].as_f64())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let relative = format!("Sessions/{}/{}", segment(WORKSPACE), segment(session));
        index.push_str(&format!("- [[{relative}]]\n"));
        let text = fs::read_to_string(vault.join(format!("{relative}.md")))?;
        ensure(
            text.contains(&format!("session_id: {session}\n")),
            "Markdown session mismatch",
        )?;
        ensure(
            text.matches("\n## ").count() == records.len(),
            "Markdown record count mismatch",
        )?;
        let mut previous = 0;
        for record in records.iter() {
            let id = record["id"].as_str().ok_or("missing id")?;
            let content = record["content"].as_str().ok_or("missing content")?;
            let position = text
                .find(&format!("- id: {id}\n"))
                .ok_or("Markdown missing record id")?;
            ensure(position >= previous, "Markdown record ordering mismatch")?;
            let end = text[position..]
                .find("\n## ")
                .map_or(text.len(), |n| position + n);
            ensure(
                text[position..end].contains(&format!("> {content}\n")),
                "Markdown content lost across page boundary",
            )?;
            previous = end;
        }
        files.push(json!({"path":format!("{relative}.md"),"records":records.len(),"bytes":text.len(),"sha256":format!("{:x}",Sha256::digest(text.as_bytes()))}));
    }
    ensure(
        fs::read_to_string(vault.join("Index.md"))? == index,
        "Markdown index differs from actual sessions",
    )?;
    Ok(
        json!({"sessions":sessions.len(),"records":expected.len(),"index_sha256":format!("{:x}",Sha256::digest(index.as_bytes())),"files":files}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compatibility_arguments_keep_global_enrollment_and_original_cli() {
        let root = Path::new("C:/owned-fixture/compat-legacy-root");
        let enroll = Path::new("C:/owned-fixture/compat-enrollment.json");
        let args = arguments(
            enroll,
            root,
            "search",
            &["--query", "quince", "--workspace", WORKSPACE],
        );
        assert_eq!(
            args,
            vec![
                "--enrollment",
                "C:/owned-fixture/compat-enrollment.json",
                "search",
                "--root",
                "C:/owned-fixture/compat-legacy-root",
                "--query",
                "quince",
                "--workspace",
                WORKSPACE
            ]
        );
    }
    #[test]
    fn acl_access_controls_succeed_on_owned_scratch() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("owned");
        fs::write(&path, b"positive").unwrap();
        assert_eq!(access_code(&path, GENERIC_WRITE), 0);
        assert_eq!(access_code(&path, WRITE_DAC), 0);
        assert_eq!(fs::read(path).unwrap(), b"positive");
    }
    #[test]
    fn page_proof_compares_all_fields_and_continuation_to_real_store() {
        let temp = tempfile::tempdir().unwrap();
        let store = hermes_memory::MemoryStore::open(temp.path()).unwrap();
        let records = paged_records();
        let typed = records
            .iter()
            .cloned()
            .map(serde_json::from_value)
            .collect::<std::result::Result<Vec<hermes_memory::MemoryRecord>, _>>()
            .unwrap();
        store.ingest_many(&typed).unwrap();
        store.prepare_export_index().unwrap();
        let receipt = verify_pages(&records, |_, body| {
            let page = store
                .export_page(&serde_json::from_value(body).unwrap(), "proof")
                .unwrap();
            Ok(json!({"response":{"result":page}}))
        })
        .unwrap();
        assert_eq!(receipt["records"], 260);
        assert_eq!(receipt["pages"].as_array().unwrap().len(), 3);
        assert!(verify_pages(&records, |_, mut body| {
            body["max_records"] = json!(80);
            let page = store
                .export_page(&serde_json::from_value(body).unwrap(), "proof")
                .unwrap();
            Ok(json!({"response":{"result":page}}))
        })
        .is_err());
        assert!(verify_pages(&records, |_, body| {
            let mut page = serde_json::to_value(
                store
                    .export_page(&serde_json::from_value(body).unwrap(), "proof")
                    .unwrap(),
            )
            .unwrap();
            page["records"][0]["metadata"] = json!({"counterfeit":true});
            Ok(json!({"response":{"result":page}}))
        })
        .is_err());
    }
    #[test]
    fn negative_receipts_require_exact_error_not_generic_failure() {
        assert!(denied(
            &json!({"exit":1,"stdout":"","stderr":"hermes-memory: unauthorized\n"}),
            "unauthorized"
        )
        .is_ok());
        assert!(denied(
            &json!({"exit":1,"stdout":"","stderr":"hermes-memory: unavailable\n"}),
            "unauthorized"
        )
        .is_err());
        assert!(denied(
            &json!({"exit":0,"stdout":"","stderr":"hermes-memory: unauthorized\n"}),
            "unauthorized"
        )
        .is_err());
    }
    #[test]
    fn compatibility_child_receipt_is_real_bounded_and_identity_pinned() {
        let temp = tempfile::tempdir().unwrap();
        let user = identity().unwrap()["user"].as_str().unwrap().to_string();
        let receipt = launch(
            &std::env::current_exe().unwrap(),
            temp.path(),
            "child",
            &["--list".into()],
            b"",
            &user,
        )
        .unwrap();
        assert_eq!(receipt["exit"], 0);
        assert_eq!(receipt["child_identity"]["user"], user);
        assert!(receipt["stdout"]
            .as_str()
            .unwrap()
            .contains("compatibility_child_receipt"));
        assert!(launch(
            &std::env::current_exe().unwrap(),
            temp.path(),
            "wrong-pin",
            &["--list".into()],
            b"",
            "S-1-0-0"
        )
        .is_err());
    }
    #[test]
    fn enrollment_fixture_binds_existing_service_profile_and_digest() {
        let config = Config {
            server: "S-1-5-80-1-2-3-4-5".into(),
            client: "S-1-5-80-6-7-8-9-10".into(),
            pipe: r"\\.\pipe\HermesMemory.fixture".into(),
        };
        let root = Path::new("C:/owned-fixture");
        let value = enrollment(root, &config, "fixture", &"ab".repeat(32));
        assert_eq!(
            value["profile_root"],
            json!(root.join("compat-legacy-root"))
        );
        assert_eq!(value["client_sid"], config.client);
        assert_eq!(value["server_sid"], config.server);
        assert_eq!(value["pipe"], config.pipe);
        assert_eq!(value["release_sha256"], "ab".repeat(32));
        assert_eq!(value["workspaces"], json!([WORKSPACE]));
    }
    #[test]
    fn compatibility_export_checks_actual_pages_and_markdown_not_counts() {
        let temp = tempfile::tempdir().unwrap();
        let store = hermes_memory::MemoryStore::open(temp.path().join("store")).unwrap();
        let mut expected = paged_records();
        expected.push(record());
        let mut snap = record();
        snap["id"] = json!("snapshot-id");
        snap["session_id"] = json!("production-snapshot");
        snap["content"] = snapshot()["items"][0]["content"].clone();
        expected.push(snap);
        let source = temp.path().join("legacy");
        fs::create_dir(&source).unwrap();
        let (archive, fixture) = bootstrap_probe::build_fixture(&source).unwrap();
        store
            .import_logical_archive_once(
                std::io::Cursor::new(archive),
                fixture["receipt"]["logical_sha256"].as_str().unwrap(),
            )
            .unwrap();
        expected.extend(
            fixture["expected_records"]
                .as_array()
                .unwrap()
                .iter()
                .cloned(),
        );
        let records = expected
            .iter()
            .cloned()
            .map(serde_json::from_value)
            .collect::<std::result::Result<Vec<hermes_memory::MemoryRecord>, _>>()
            .unwrap();
        store.ingest_many(&records).unwrap();
        store.prepare_export_index().unwrap();
        let vault = temp.path().join("vault");
        assert_eq!(
            hermes_memory::client_export::render_markdown(&vault, WORKSPACE, |r| Ok(store
                .export_page(r, "test")
                .unwrap()))
            .unwrap(),
            5
        );
        let pages = verify_pages(&expected, |_, body| {
            let page = store
                .export_page(&serde_json::from_value(body).unwrap(), "proof")
                .unwrap();
            Ok(json!({"response":{"result":page}}))
        })
        .unwrap();
        assert_eq!(pages["records"], 264);
        let receipt = verify_markdown(&vault, &expected).unwrap();
        assert_eq!(receipt["records"], 264);
        let index = vault.join("Index.md");
        fs::write(&index, "# Hermes Memory Vault\n\n- [[fake]]\n").unwrap();
        assert!(verify_markdown(&vault, &expected).is_err());
    }
}
