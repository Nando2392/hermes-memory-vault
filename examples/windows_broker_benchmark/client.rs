//! Runs only as the SCM-dispatched virtual-account B worker.
use crate::{
    contract::{self, ensure, Job},
    data::{self, Result, WORKSPACE},
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader},
    path::Path,
    time::Duration,
};
fn snapshot_bytes() -> Result<Vec<u8>> {
    let s = data::snapshot();
    let items: Vec<_> = s.items.iter().map(|i| json!({"kind":i.kind,"content":i.content,"timestamp":i.timestamp,"metadata":i.metadata})).collect();
    Ok(serde_json::to_vec(
        &json!({"session_id":s.session_id,"workspace":s.workspace,"items":items}),
    )?)
}
pub fn known_record() -> hermes_memory::MemoryRecord {
    let mut r = data::record(9_000_000);
    r.session_id = "benchmark-client".into();
    r.content = "hmvsmallcanary actual broker client durable record".into();
    r
}
/// Enumerate only the fresh export tree; verify actual Markdown IDs and payloads.
pub fn verify_export(vault: &Path, seeds: u64) -> Result<Value> {
    ensure(seeds <= 100_000, "small export count bound")?;
    let index = fs::read_to_string(vault.join("Index.md"))?;
    ensure(
        index.starts_with("# Hermes Memory Vault\n"),
        "missing export index",
    )?;
    let mut ids = BTreeSet::new();
    let mut known = false;
    let mut snapshot = false;
    let mut files = Vec::new();
    for workspace in fs::read_dir(vault.join("Sessions"))? {
        let workspace = workspace?;
        ensure(
            workspace.file_type()?.is_dir(),
            "export workspace must be directory",
        )?;
        for entry in fs::read_dir(workspace.path())? {
            let entry = entry?;
            ensure(entry.file_type()?.is_file(), "export note must be regular")?;
            for line in BufReader::new(File::open(entry.path())?).lines() {
                let line = line?;
                if let Some(id) = line.strip_prefix("- id: ") {
                    ensure(ids.insert(id.to_owned()), "duplicate Markdown record")?;
                }
                known |= line == format!("> {}", known_record().content);
                snapshot |= line == "> snapshot benchmark reference";
            }
            files.push(json!({"path":entry.path(),"bytes":entry.metadata()?.len(),"sha256":data::hash_file(&entry.path())?}));
        }
    }
    for n in 0..seeds {
        ensure(ids.contains(&data::record(n).id), "seed absent from export")?;
    }
    ensure(
        ids.contains(&known_record().id) && known && snapshot,
        "export missing exact known/snapshot payload",
    )?;
    ensure(
        ids.len() as u64 == seeds + 2 && files.len() == 3,
        "export record/session count mismatch",
    )?;
    Ok(
        json!({"records":ids.len(),"sessions":files.len(),"files":files,"index_sha256":data::hash_file(&vault.join("Index.md"))?,"known_payload_verified":known,"snapshot_payload_verified":snapshot}),
    )
}
#[cfg(all(windows, feature = "experimental-broker"))]
pub fn worker(root: &Path) -> Result<()> {
    let scratch = root.join("scratch");
    let mut report = json!({"schema":1,"pass":false,"commands":[]});
    let result = execute(root, &mut report);
    if let Err(ref e) = result {
        report["error"] = json!(e.to_string());
    }
    report["pass"] = json!(result.is_ok());
    // Completion marker is separate: controller never consumes partially written JSON.
    contract::json_new(&scratch.join("client-result.json"), &report)?;
    contract::json_new(&scratch.join("client-done.json"), &json!({"complete":true}))?;
    result
}
#[cfg(all(windows, feature = "experimental-broker"))]
fn execute(root: &Path, report: &mut Value) -> Result<()> {
    let reader =
        hermes_memory::windows_enrollment::open_admin_owned_file(&root.join("job.json"), 65536)?;
    let job: Job = serde_json::from_reader(reader)?;
    ensure(
        job.case.install_root == root.join("install-small")
            && job.case.legacy_root == root.join("small/source"),
        "job outside fixture",
    )?;
    ensure(
        job.client == job.case.install_root.join("bin/hermes-memory-client.exe"),
        "client outside installed pinned payload",
    )?;
    ensure(
        data::hash_file(&job.client)? == job.case.client_sha256,
        "client executable pin changed",
    )?;
    let enrollment = hermes_memory::windows_enrollment::load_from_enrollment(
        &job.enrollment,
        &job.case.legacy_root,
    )?;
    ensure(
        enrollment.client_sid == job.case.client_sid,
        "B TokenUser/enrollment SID mismatch",
    )?;
    report["enrollment"] = json!({"client_sid":enrollment.client_sid,"server_sid":enrollment.server_sid,"pipe":enrollment.pipe,"scope_mode":enrollment.scope_mode,"legacy_root_key":enrollment.legacy_root_key});
    // Query-only write-access request: do not actually write even if policy fails.
    let denied = OpenOptions::new()
        .write(true)
        .open(job.case.legacy_root.join("memory.db"));
    ensure(
        denied
            .as_ref()
            .err()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied),
        "B unexpectedly has local SQLite write access",
    )?;
    report["local_sqlite_write_denied"] = json!(true);
    let before = data::inventory(&job.case.legacy_root)?;
    let scratch = root.join("scratch");
    let enroll = contract::text(&job.enrollment)?;
    let call = |label: &str,
                operation: &str,
                extra: &[&str],
                input: Vec<u8>,
                report: &mut Value|
     -> Result<Value> {
        ensure(!crate::scm::stop_requested(), "B stop requested")?;
        let mut args = job.case.client_args(operation, &enroll)?;
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        let observation = contract::command(
            &job.client,
            &args,
            &input,
            &scratch,
            label,
            Duration::from_secs(45),
            crate::scm::stop_requested,
        )?;
        report["commands"]
            .as_array_mut()
            .ok_or("commands array")?
            .push(observation.clone());
        Ok(observation)
    };
    let ping = call(
        "scoped-search",
        "search",
        &["--query", "ordinary", "--workspace", WORKSPACE],
        vec![],
        report,
    )?;
    let hits = contract::output(&ping)?;
    ensure(
        hits.as_array().is_some_and(|hits| {
            !hits.is_empty() && hits.iter().all(|h| h["workspace"] == WORKSPACE)
        }),
        "scoped search failed",
    )?;
    let ingest = call(
        "ingest",
        "ingest",
        &[],
        serde_json::to_vec(&known_record())?,
        report,
    )?;
    ensure(
        contract::output(&ingest)? == json!({"inserted":1,"duplicates":0}),
        "known ingest acknowledgement",
    )?;
    let duplicate = call(
        "duplicate",
        "ingest",
        &[],
        serde_json::to_vec(&known_record())?,
        report,
    )?;
    ensure(
        contract::output(&duplicate)? == json!({"inserted":0,"duplicates":1}),
        "duplicate retransmission acknowledgement",
    )?;
    let snapshot = call(
        "unchanged-snapshot",
        "snapshot",
        &[],
        snapshot_bytes()?,
        report,
    )?;
    ensure(
        contract::output(&snapshot)? == json!({"inserted":0,"duplicates":0}),
        "imported unchanged snapshot replay",
    )?;
    let found = call(
        "known-search",
        "search",
        &["--query", "hmvsmallcanary", "--workspace", WORKSPACE],
        vec![],
        report,
    )?;
    let found = contract::output(&found)?;
    let expected_record = serde_json::to_value(known_record())?;
    ensure(
        found
            .as_array()
            .is_some_and(|hits| hits.len() == 1 && hits[0] == expected_record),
        "known search exact record mismatch",
    )?;
    let wrong = call(
        "wrong-workspace",
        "search",
        &["--query", "ordinary", "--workspace", "not-authorized"],
        vec![],
        report,
    )?;
    denial(&wrong)?;
    // Correct protected enrollment, wrong lexical root: must fail before fallback.
    let mut wrong_case = job.case.clone();
    wrong_case.legacy_root = root.join("absent-wrong-root");
    let mut args = wrong_case.client_args("search", &enroll)?;
    args.extend([
        "--query".into(),
        "ordinary".into(),
        "--workspace".into(),
        WORKSPACE.into(),
    ]);
    let wrong = contract::command(
        &job.client,
        &args,
        b"",
        &scratch,
        "wrong-root",
        Duration::from_secs(15),
        crate::scm::stop_requested,
    )?;
    report["commands"]
        .as_array_mut()
        .ok_or("commands array")?
        .push(wrong.clone());
    denial(&wrong)?;
    ensure(
        !wrong_case.legacy_root.exists(),
        "wrong configuration created local fallback root",
    )?;
    let wrong_enrollment = root.join("wrong-server-enrollment.json");
    let admitted_wrong = hermes_memory::windows_enrollment::load_from_enrollment(
        &wrong_enrollment,
        &job.case.legacy_root,
    )?;
    ensure(
        admitted_wrong.server_sid != enrollment.server_sid,
        "negative server pin is not different",
    )?;
    let mut args = job
        .case
        .client_args("search", &contract::text(&wrong_enrollment)?)?;
    args.extend([
        "--query".into(),
        "ordinary".into(),
        "--workspace".into(),
        WORKSPACE.into(),
    ]);
    let wrong = contract::command(
        &job.client,
        &args,
        b"",
        &scratch,
        "wrong-server-pin",
        Duration::from_secs(15),
        crate::scm::stop_requested,
    )?;
    report["commands"]
        .as_array_mut()
        .ok_or("commands array")?
        .push(wrong.clone());
    denial(&wrong)?;
    report["wrong_server_enrollment_admitted_but_pipe_peer_denied"] = json!(true);
    let vault = scratch.join("export");
    let vault_text = contract::text(&vault)?;
    let export = call(
        "export",
        "export",
        &["--workspace", WORKSPACE, "--vault", &vault_text],
        vec![],
        report,
    )?;
    ensure(
        contract::output(&export)? == json!({"sessions":3}),
        "export session count",
    )?;
    report["export"] = verify_export(&vault, job.seed_records)?;
    ensure(
        before == data::inventory(&job.case.legacy_root)?,
        "client altered local source",
    )?;
    report["source_unchanged"] = json!(true);
    Ok(())
}
fn denial(value: &Value) -> Result<()> {
    ensure(
        value["exit_code"].as_i64().is_some_and(|c| c != 0)
            && value["timed_out"] == false
            && value["stop_requested"] == false
            && value["stderr"]
                .as_str()
                .is_some_and(|s| s.contains("unauthorized")),
        "wrong configuration was not explicitly denied",
    )
}
