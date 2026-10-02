//! Actual executable SCM gate; never invoked by unit tests.
use super::*;
#[path = "client_probe.rs"]
mod client_probe;

fn checked_response(v: &Value, id: &str, error: Option<&str>) -> Result<()> {
    ensure(
        v["protocol"] == 1 && v["request_id"] == id,
        "response correlation failed",
    )?;
    ensure(
        match error {
            None => v["ok"] == true && v.get("result").is_some() && v.get("error").is_none(),
            Some(code) => {
                v["ok"] == false && v["error"]["code"] == code && v.get("result").is_none()
            }
        },
        "unexpected response (no unknown-outcome mutation retries)",
    )
}
fn wait_child(child: &mut std::process::Child, end: Instant) -> Result<std::process::ExitStatus> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= end {
            child.kill()?;
            // try_wait rather than an unbounded wait, even after termination.
            let drain = Instant::now() + Duration::from_secs(3);
            while child.try_wait()?.is_none() {
                ensure(Instant::now() < drain, "owned request child failed to exit")?;
                thread::sleep(Duration::from_millis(25));
            }
            return Err("request deadline expired; outcome unknown; no retry".into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}
const WORKSPACE: &str = "production-sandbox";
const CONTENT: &str = "quince 日本語 ñ 🔐";
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct Config {
    server: String,
    client: String,
    pipe: String,
}
impl Config {
    fn read(root: &Path) -> Result<Self> {
        Ok(serde_json::from_value(read_report(
            root,
            "production-config.json",
            deadline(),
        )?)?)
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(90)
}
fn envelope(id: &str, op: &str, body: Value) -> Value {
    json!({"protocol":1,"request_id":id,"op":op,"body":body})
}
fn record() -> Value {
    json!({"id":"production-ingest-one","session_id":"production-session","workspace":WORKSPACE,"kind":"note","content":CONTENT,"timestamp":2.0,"metadata":{"source":"actual-executable","nested":[1,true,"ñ"]}})
}
fn snapshot() -> Value {
    json!({"session_id":"production-snapshot","workspace":WORKSPACE,"items":[{"kind":"note","content":"quince snapshot 日本語 ñ 🔐","timestamp":3.0,"metadata":{"source":"actual-snapshot","nested":[2,false,"ñ"]}}]})
}
fn copy_new(source: &Path, target: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    let bytes = fs::read(source)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    ensure(fs::read(target)? == bytes, "broker copy differs")?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}
/// Called only after C's newly created registration is retained by the parent.
pub(super) fn prepare(
    root: &Path,
    service: &ScHandle,
    name: &str,
    client: &str,
) -> Result<(String, Value)> {
    let server = service_sid(name)?;
    ensure(server != client, "C and B identities overlap")?;
    let config = Config {
        server: server.clone(),
        client: client.into(),
        pipe: format!(r"\\.\pipe\HermesMemory.{name}"),
    };
    mkdir(
        &root.join("runtime-store"),
        &format!("(A;OICI;FA;;;{server})"),
    )?;
    mkdir(&root.join("admin-client"), "")?;
    let audit = audit_dir(&root.join("runtime-store"), &[&server], &[], false)?;
    let source = std::env::current_exe()?
        .parent()
        .and_then(Path::parent)
        .ok_or("example must be in target/release/examples")?
        .join("hermes-memory-broker.exe");
    let target = root.join("bin/hermes-memory-broker.exe");
    let hash = copy_new(&source, &target)?;
    let compatibility = client_probe::prepare(
        root,
        &config,
        name,
        &hash,
        source.parent().ok_or("missing release directory")?,
    )?;
    write_report(
        root,
        "production-config.json",
        &serde_json::to_value(&config)?,
    )?;
    let command = format!("\"{}\" service --root \"{}\" --pipe \"{}\" --server-sid {} --client-sid {} --workspace {} --service-name {}", target.display(), root.join("runtime-store").display(), config.pipe, server, client, WORKSPACE, name);
    // SAFETY: retained owned service; all strings remain live for this synchronous configuration call.
    win(unsafe {
        ChangeServiceConfigW(
            service.0,
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            wide(&command).as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
            null(),
        )
    })?;
    Ok((
        server,
        json!({"source":source,"executable":target,"sha256":hash,"command":command,"storage_acl":audit,"compatibility":compatibility}),
    ))
}
/// Files instead of pipe-backed stdio prevent child-output deadlock. Only this
/// directly spawned request child can be killed; no PID lookup or mutation retry.
fn execute(
    root: &Path,
    config: &Config,
    dir: &Path,
    label: &str,
    request: &Value,
) -> Result<Value> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let input_path = dir.join(format!("{label}.stdin"));
    let output_path = dir.join(format!("{label}.stdout"));
    let error_path = dir.join(format!("{label}.stderr"));
    let mut input = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&input_path)?;
    input.write_all(&serde_json::to_vec(request)?)?;
    drop(input);
    let output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)?;
    let error = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&error_path)?;
    let mut child = Command::new(root.join("bin/hermes-memory-broker.exe"))
        .args([
            "request-windows",
            "--pipe",
            &config.pipe,
            "--server-sid",
            &config.server,
        ])
        .stdin(Stdio::from(fs::File::open(&input_path)?))
        .stdout(Stdio::from(output))
        .stderr(Stdio::from(error))
        .spawn()?;
    // Keep the directly returned process object, not a PID lookup. Verification
    // is deferred until after bounded drain so a token-query failure cannot leak a child.
    use std::os::windows::io::AsRawHandle;
    let child_identity = identity_of(child.as_raw_handle().cast());
    let end = Instant::now() + Duration::from_secs(12);
    let status = wait_child(&mut child, end)?;
    ensure(
        fs::metadata(&output_path)?.len() <= 65536 && fs::metadata(&error_path)?.len() <= 65536,
        "oversized process output",
    )?;
    let stdout = fs::read_to_string(output_path)?;
    let stderr = fs::read_to_string(error_path)?;
    let child_identity = child_identity?;
    ensure(
        child_identity["user"] == identity()?["user"],
        "request child changed identity",
    )?;
    let response = serde_json::from_str::<Value>(&stdout).ok();
    Ok(
        json!({"exit":status.code(),"response":response,"stdout":stdout,"stderr":stderr,"stdin":request,"child_identity":child_identity}),
    )
}
fn call(
    root: &Path,
    config: &Config,
    id: &str,
    op: &str,
    body: Value,
    error: Option<&str>,
) -> Result<Value> {
    let proof = execute(
        root,
        config,
        &root.join("scratch"),
        id,
        &envelope(id, op, body),
    )?;
    ensure(
        proof["exit"] == 0,
        &format!("actual request failed: {proof}"),
    )?;
    checked_response(&proof["response"], id, error)?;
    Ok(proof)
}
fn mutation(v: &Value, inserted: u64, duplicates: u64) -> Result<()> {
    let r = &v["response"]["result"];
    ensure(
        r["inserted"] == inserted
            && r["duplicates"] == duplicates
            && r["durable"] == true
            && r["projection_ready"] == true,
        &format!("mutation counts/durability mismatch: expected inserted={inserted} duplicates={duplicates}; actual result={r}"),
    )
}
fn snapshot_replay(v: &Value) -> Result<()> {
    // An identical snapshot is consumed by the overlap path, not by INSERT OR IGNORE.
    mutation(v, 0, 0)
}
fn search(root: &Path, config: &Config, stage: &str) -> Result<Value> {
    let v = call(
        root,
        config,
        &format!("{stage}-search"),
        "search",
        json!({"query":"quince","workspace":WORKSPACE,"limit":20,"max_bytes":65536}),
        None,
    )?;
    let hits = v["response"]["result"]["hits"]
        .as_array()
        .ok_or("search hits missing")?;
    ensure(hits.len() == 2, "expected exactly two durable records")?;
    ensure(
        hits.iter().any(|hit| *hit == record()),
        "ingest Unicode/metadata/full record mismatch",
    )?;
    let expected = snapshot();
    let item = &expected["items"][0];
    ensure(
        hits.iter().any(|hit| {
            hit["session_id"] == expected["session_id"]
                && hit["workspace"] == WORKSPACE
                && hit["kind"] == item["kind"]
                && hit["content"] == item["content"]
                && hit["timestamp"] == item["timestamp"]
                && hit["metadata"] == item["metadata"]
                && hit["id"].as_str().is_some_and(|s| !s.is_empty())
        }),
        "snapshot Unicode/metadata mismatch",
    )?;
    Ok(v)
}
/// Existing B remains the worker; this invokes the production CLI, not library IPC.
pub(super) fn client(root: &Path) -> Result<()> {
    let config = Config::read(root)?;
    ensure(
        identity()?["user"] == config.client,
        "production client not B",
    )?;
    read_report(root, "production-go.json", deadline())?;
    let ping = call(root, &config, "first-ping", "ping", json!({}), None)?;
    ensure(
        ping["response"]["result"]["export_supported"] == false
            && ping["response"]["result"]["export_page_supported"] == true
            && ping["response"]["result"]["sqlite_version"].is_string(),
        "not a production ping",
    )?;
    let ingest = call(
        root,
        &config,
        "first-ingest",
        "ingest",
        json!({"records":[record()]}),
        None,
    )?;
    mutation(&ingest, 1, 0)?;
    let duplicate = call(
        root,
        &config,
        "first-ingest-duplicate",
        "ingest",
        json!({"records":[record()]}),
        None,
    )?;
    mutation(&duplicate, 0, 1)?;
    let snap = call(
        root,
        &config,
        "first-snapshot",
        "snapshot",
        snapshot(),
        None,
    )?;
    mutation(&snap, 1, 0)?;
    let snap_duplicate = call(
        root,
        &config,
        "first-snapshot-duplicate",
        "snapshot",
        snapshot(),
        None,
    )?;
    snapshot_replay(&snap_duplicate)?;
    let found = search(root, &config, "first")?;
    let scope = call(
        root,
        &config,
        "scope-denied",
        "search",
        json!({"query":"quince","workspace":"other","limit":20,"max_bytes":65536}),
        Some("unauthorized"),
    )?;
    // Valid envelope with malformed body reaches actual server decode (not CLI prevalidation).
    let malformed = call(
        root,
        &config,
        "malformed-body",
        "ping",
        json!({"unexpected":true}),
        Some("invalid_request"),
    )?;
    let export = call(
        root,
        &config,
        "export-unsupported",
        "export",
        json!({}),
        Some("unsupported"),
    )?;
    write_report(
        &root.join("result-b"),
        "production-first.json",
        &json!({"ping":ping,"ingest":ingest,"duplicate":duplicate,"snapshot":snap,"snapshot_duplicate":snap_duplicate,"search":found,"scope":scope,"malformed":malformed,"export":export}),
    )?;
    read_report(root, "production-restarted.json", deadline())?;
    let found = search(root, &config, "restart")?;
    let ingest = call(
        root,
        &config,
        "restart-ingest-duplicate",
        "ingest",
        json!({"records":[record()]}),
        None,
    )?;
    mutation(&ingest, 0, 1)?;
    let snap = call(
        root,
        &config,
        "restart-snapshot-duplicate",
        "snapshot",
        snapshot(),
        None,
    )?;
    snapshot_replay(&snap)?;
    let final_search = search(root, &config, "final")?;
    ensure(
        found["response"]["result"] == final_search["response"]["result"],
        "replay changed durable rows",
    )?;
    let compatibility = client_probe::run(root, &config, &final_search)?;
    write_report(
        &root.join("result-b"),
        "production-final.json",
        &json!({"search":found,"ingest_duplicate":ingest,"snapshot_duplicate":snap,"final_search":final_search,"compatibility":compatibility}),
    )?;
    read_report(root, "production-stopped.json", deadline())?;
    let no_fallback = client_probe::after_stop(root, &config)?;
    write_report(
        &root.join("result-b"),
        "production-no-fallback.json",
        &no_fallback,
    )
}
pub(super) fn start(service: &ScHandle, sid: &str, processes: &mut Vec<Handle>) -> Result<Value> {
    // SAFETY: exclusively our fresh registration, configured before start.
    win(unsafe { StartServiceW(service.0, 0, null()) })?;
    let (process, observation) = track(service, sid)?;
    processes.push(process);
    let token = &observation["token"];
    let privileges = token["privileges"]
        .as_array()
        .ok_or("C privileges missing")?
        .iter()
        .map(|v| v["name"].as_str().ok_or("C privilege missing"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure(
        token["elevated"] == false && policy::ipc_privileges(&privileges),
        "C effective privilege policy failed",
    )?;
    Ok(observation)
}
pub(super) fn stopped(service: &ScHandle, process: &Handle) -> Result<Value> {
    stop(service, Instant::now() + Duration::from_secs(20))?;
    // SAFETY: live pinned process handle from track, never a recycled PID.
    ensure(
        unsafe { WaitForSingleObject(process.0, 15000) } == WAIT_OBJECT_0,
        "C process did not exit gracefully",
    )?;
    let mut exit = 0;
    // SAFETY: queried only after the owned process handle was signalled.
    win(unsafe { GetExitCodeProcess(process.0, &mut exit) })?;
    let status = query(service)?;
    ensure(
        exit == 0 && status.dwServiceSpecificExitCode == 0,
        "C process/service exit was nonzero",
    )?;
    Ok(
        json!({"state":"STOPPED","process_exit":exit,"win32_exit":status.dwWin32ExitCode,"service_exit":status.dwServiceSpecificExitCode}),
    )
}
pub(super) fn admin_denial(root: &Path) -> Result<Value> {
    let config = Config::read(root)?;
    let proof = execute(
        root,
        &config,
        &root.join("admin-client"),
        "admin-denied",
        &envelope("admin-denied", "ping", json!({})),
    )?;
    // This CLI maps only PermissionDenied at connect_authenticated to unauthorized.
    // A successful dispatch, unsupported implementation or generic unavailable fails.
    ensure(
        proof["exit"] == 1
            && proof["stdout"] == ""
            && proof["stderr"]
                .as_str()
                .is_some_and(|s| s.trim() == "unauthorized"),
        &format!("admin was not rejected before exchange: {proof}"),
    )?;
    Ok(proof)
}
pub(super) fn integrity(root: &Path) -> Result<Value> {
    let db = Connection::open_with_flags(
        root.join("runtime-store/memory.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let check: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    ensure(check == "ok", "production source integrity failed")?;
    let rows: u64 = db.query_row("SELECT count(*) FROM records", [], |r| r.get(0))?;
    ensure(rows == 262, "production source has extra or missing rows")?;
    Ok(
        json!({"integrity_check":check,"source_rows":rows,"performed":"administrator after C stopped and process exited","mode":"read-only"}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn final_integrity_requires_all_262_compatibility_rows() {
        let root = tempfile::tempdir().unwrap();
        let store = hermes_memory::MemoryStore::open(root.path().join("runtime-store")).unwrap();
        let records = (0..262)
            .map(|i| {
                let mut value = record();
                value["id"] = json!(format!("proof-{i}"));
                serde_json::from_value(value).unwrap()
            })
            .collect::<Vec<hermes_memory::MemoryRecord>>();
        store.ingest_many(&records).unwrap();
        drop(store);
        assert_eq!(integrity(root.path()).unwrap()["source_rows"], 262);
    }
    #[test]
    fn snapshot_replay_matches_actual_store_overlap_semantics_across_reopen() {
        let root = tempfile::tempdir().unwrap();
        let request: hermes_memory::SnapshotRequest = serde_json::from_value(snapshot()).unwrap();
        {
            let store = hermes_memory::MemoryStore::open(root.path()).unwrap();
            assert_eq!(store.ingest_snapshot(&request).unwrap(), (1, 0));
        }
        let store = hermes_memory::MemoryStore::open(root.path()).unwrap();
        let (inserted, duplicates) = store.ingest_snapshot(&request).unwrap();
        snapshot_replay(&json!({"response":{"result":{
            "inserted":inserted,"duplicates":duplicates,"durable":true,"projection_ready":true
        }}}))
        .unwrap();
    }
    #[test]
    fn bounded_child_wait_reaps_a_real_unprivileged_child() {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--list")
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        assert!(
            wait_child(&mut child, Instant::now() + Duration::from_secs(5))
                .unwrap()
                .success()
        );
    }
    #[test]
    fn response_checks_correlation_and_never_accepts_unsupported_as_auth_denial() {
        assert!(checked_response(
            &json!({"protocol":1,"request_id":"wrong","ok":true,"result":{}}),
            "r",
            None
        )
        .is_err());
        assert!(checked_response(
            &json!({"protocol":1,"request_id":"r","ok":false,"error":{"code":"unsupported"}}),
            "r",
            Some("unauthorized")
        )
        .is_err());
    }
}
