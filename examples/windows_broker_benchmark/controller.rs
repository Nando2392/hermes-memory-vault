//! Controller for exactly one 6 MiB staged-legacy case, not a 600 MiB benchmark.
use crate::{
    contract::{self, ensure},
    data::{self, Result},
    Options,
};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
fn validate(o: &Options) -> Result<()> {
    ensure(
        o.large_mib.is_none(),
        "--large-mib is unsupported; this controller executes ONLY the real 6 MiB case",
    )?;
    ensure(
        o.run
            && o.allow_disposable_services
            && o.allow_virtual_accounts
            && o.allow_acl_mutation
            && o.reviewed,
        "requires --run and all three explicit consents plus --reviewed",
    )?;
    ensure(
        o.result.is_some()
            && o.broker_exe.is_some()
            && o.client_exe.is_some()
            && o.admin_exe.is_some(),
        "requires --result --broker-exe --client-exe --admin-exe",
    )
}
fn executable(path: &Path) -> Result<PathBuf> {
    ensure(
        path.is_absolute()
            && path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("exe")),
        "provide absolute .exe paths",
    )?;
    ensure(
        fs::symlink_metadata(path)?.is_file(),
        "executable must be regular",
    )?;
    let canonical = fs::canonicalize(path)?;
    let text = contract::text(&canonical)?;
    Ok(PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text)))
}
pub fn run(options: Options) -> Result<()> {
    validate(&options)?;
    #[cfg(not(all(windows, feature = "experimental-broker")))]
    {
        Err("requires Windows and --features experimental-broker".into())
    }
    #[cfg(all(windows, feature = "experimental-broker"))]
    {
        // No file writes, ACLs or SCM mutations before all deployment/native gates.
        crate::policy::disposable_gates(
            options.allow_disposable_services,
            options.allow_virtual_accounts,
            options.allow_acl_mutation,
            options.reviewed,
        )?;
        let administrator = crate::scm::administrator()?;
        let broker = executable(options.broker_exe.as_deref().ok_or("broker path")?)?;
        let client = executable(options.client_exe.as_deref().ok_or("client path")?)?;
        let admin = executable(options.admin_exe.as_deref().ok_or("admin path")?)?;
        ensure(
            broker != client && broker != admin && client != admin,
            "executable roles must be distinct",
        )?;
        let pins = json!({"broker":data::hash_file(&broker)?,"client":data::hash_file(&client)?,"admin":data::hash_file(&admin)?});
        let mut result_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(options.result.as_deref().ok_or("result path")?)?;
        let mut report = json!({"schema":1,"case":"small-6MiB","pass":false,"administrator":administrator,"executable_sha256":pins,"commands":[],"metrics":{"measured":false,"reason":"small correctness case; no 600 MiB or process-IO claim"},"fixture_disposal":"retained for hosted VM disposal; no recursive cleanup"});
        let outcome = small(&broker, &client, &admin, &mut report);
        if let Err(ref e) = outcome {
            report["error"] = json!(e.to_string());
        }
        report["pass"] = json!(outcome.is_ok());
        serde_json::to_writer_pretty(&mut result_file, &report)?;
        result_file.write_all(b"\n")?;
        result_file.sync_all()?;
        outcome
    }
}
#[cfg(all(windows, feature = "experimental-broker"))]
fn small(broker: &Path, client: &Path, admin_source: &Path, report: &mut Value) -> Result<()> {
    let mut fixture = crate::scm::Fixture::create(true, true)?;
    let root = fixture.root().to_owned();
    report["fixture"] = json!({"root":root,"client_service":fixture.client_name(),"client_sid":fixture.client_sid()});
    let logs = root.join("controller");
    fs::create_dir(&logs)?;
    let admin = root.join("bin/hermes-memory-admin.exe");
    let mut source = File::open(admin_source)?;
    let mut copied = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&admin)?;
    std::io::copy(&mut source, &mut copied)?;
    copied.sync_all()?;
    drop(copied);
    ensure(
        data::hash_file(&admin)? == report["executable_sha256"]["admin"],
        "admin copy pin mismatch",
    )?;
    // Retain protected admin/ancestor handles through all helper invocations.
    let _admin_pin = hermes_memory::windows_enrollment::open_admin_owned_file(&admin, 1 << 30)?;
    let install = root.join("install-small");
    let receipt = install.join("receipt.json");
    let mut prepared = false;
    let mut observed = None;
    let mut generation = Value::Null;
    let operation = (|| -> Result<()> {
        generation = data::generate(&root.join("small"), 6 * 1024 * 1024)?;
        report["generation"] = generation.clone();
        let manifest = json!({"kind":"benchmark-generated-executable-pins-not-a-vendor-release", "broker_sha256":report["executable_sha256"]["broker"],"client_sha256":report["executable_sha256"]["client"],"admin_sha256":report["executable_sha256"]["admin"]});
        contract::json_new(&root.join("release-manifest.json"), &manifest)?;
        let case = crate::commands::Case {
            legacy_root: root.join("small/source"),
            install_root: install.clone(),
            service_name: fixture.broker_name("small")?,
            client_sid: fixture.client_sid().into(),
            broker_source: broker.into(),
            client_source: client.into(),
            broker_sha256: data::hash_file(broker)?,
            client_sha256: data::hash_file(client)?,
            release_sha256: data::hash_file(&root.join("release-manifest.json"))?,
            default_enrollment: false,
        };
        ensure(
            case.broker_sha256 == report["executable_sha256"]["broker"]
                && case.client_sha256 == report["executable_sha256"]["client"],
            "payload changed after preflight hash",
        )?;
        let mut plan_args = case.prepare_args()?;
        plan_args[0] = "plan".into();
        plan_args.remove(1); // plan is read-only and does not receive mutation consent.
        let plan = admin_call(&admin, &plan_args, &logs, "plan", report)?;
        report["plan"] = plan.clone();
        let enrollment = PathBuf::from(plan["enrollment"].as_str().ok_or("plan enrollment")?);
        let actual_receipt = admin_call(&admin, &case.prepare_args()?, &logs, "prepare", report)?;
        prepared = true;
        report["receipt"] = actual_receipt;
        // Read-only native file/ancestor admission; production prepare creates only fresh NTFS roots.
        let _receipt_pin =
            hermes_memory::windows_enrollment::open_admin_owned_file(&receipt, 65536)?;
        let args = vec![
            "activate".into(),
            "--allow-machine-provision".into(),
            "--receipt".into(),
            contract::text(&receipt)?,
            "--archive-source".into(),
            generation["archive"].as_str().ok_or("archive path")?.into(),
            "--archive-sha256".into(),
            generation["archive_sha256"]
                .as_str()
                .ok_or("archive pin")?
                .into(),
            "--expected-logical-sha256".into(),
            generation["logical_sha256"]
                .as_str()
                .ok_or("logical pin")?
                .into(),
        ];
        report["activation"] = admin_call(&admin, &args, &logs, "activate", report)?;
        report["status"] = admin_call(
            &admin,
            &receipt_args("status", &receipt)?,
            &logs,
            "status",
            report,
        )?;
        let tracked = fixture.observe_broker(&receipt, "small")?;
        report["broker_before"] = tracked.observation()?;
        observed = Some(tracked);
        let job = contract::Job {
            case,
            enrollment,
            client: install.join("bin/hermes-memory-client.exe"),
            seed_records: generation["seed_records"].as_u64().ok_or("seed count")?,
        };
        // Deliberately wrong server pin in a separately protected enrollment.
        // It is not a forged success: B must admit the config then reject the real pipe peer.
        let mut wrong: Value = serde_json::from_reader(
            hermes_memory::windows_enrollment::open_admin_owned_file(&job.enrollment, 65536)?,
        )?;
        let candidates = [
            "S-1-5-80-1-2-3-4-5",
            "S-1-5-80-1-2-3-4-6",
            "S-1-5-80-1-2-3-4-7",
        ];
        let wrong_sid = candidates
            .into_iter()
            .find(|sid| wrong["server_sid"] != *sid && wrong["client_sid"] != *sid)
            .ok_or("wrong SID candidate")?;
        wrong["server_sid"] = json!(wrong_sid);
        contract::json_new(&root.join("wrong-server-enrollment.json"), &wrong)?;
        contract::json_new(&root.join("job.json"), &job)?;
        report["client_start"] = fixture.start_client()?;
        let deadline = Instant::now() + Duration::from_secs(360);
        while !root.join("scratch/client-done.json").exists() {
            ensure(
                Instant::now() < deadline,
                "B worker completion deadline; evidence retained",
            )?;
            let current = fixture.observe_client()?;
            ensure(
                current["process"]["exited"] != true,
                "B exited before completion",
            )?;
            std::thread::sleep(Duration::from_millis(100));
        }
        let file = File::open(root.join("scratch/client-result.json"))?;
        ensure(file.metadata()?.len() < 1024 * 1024, "B report size bound")?;
        report["client"] = serde_json::from_reader(file)?;
        report["client_observation"] = fixture.observe_client()?;
        ensure(
            report["client"]["pass"] == true,
            "B client validation failed; see nested report",
        )?;
        ensure(
            data::inventory(&root.join("small/source"))? == generation["source_before"],
            "source changed during broker/client operations",
        )?;
        report["source_unchanged"] = json!(true);
        Ok(())
    })();
    // Always attempt bounded cooperative stops using only owned service capabilities.
    let b_stop = fixture.stop_client();
    report["client_stop"] = match &b_stop {
        Ok(v) => v.clone(),
        Err(e) => json!({"error":e.to_string()}),
    };
    let c_stop = if prepared {
        admin_call(
            &admin,
            &receipt_args("stop", &receipt)?,
            &logs,
            "stop",
            report,
        )
        .map(Some)
    } else {
        Ok(None)
    };
    report["broker_stop"] = match &c_stop {
        Ok(v) => json!(v),
        Err(e) => json!({"error":e.to_string()}),
    };
    let c_exit = if let Some(tracked) = &observed {
        tracked.wait_exit(Duration::from_secs(30)).map(Some)
    } else {
        Ok(None)
    };
    report["broker_exit"] = match &c_exit {
        Ok(v) => json!(v),
        Err(e) => json!({"error":e.to_string()}),
    };
    operation?;
    b_stop?;
    c_stop?;
    c_exit?;
    ensure(
        report["client_stop"]["process"]["exited"] == true
            && report["client_stop"]["process"]["exit_code"] == 0
            && report["client_stop"]["scm_exit_code"] == 0,
        "B did not stop cleanly",
    )?;
    ensure(
        report["broker_exit"]["exited"] == true && report["broker_exit"]["exit_code"] == 0,
        "C did not stop cleanly",
    )?;
    report["startup_import"] =
        crate::fixtures::verify_stopped_import(&install.join("store/memory.db"), &generation)?;
    ensure(
        data::inventory(&root.join("small/source"))? == generation["source_before"],
        "source changed after shutdown",
    )?;
    report["broker_after"] = observed
        .as_ref()
        .ok_or("no broker observation")?
        .observation()?;
    // Delete only the retained stopped B registration; files and C remain for VM disposal.
    fixture.delete_client()?;
    report["client_registration_deleted"] = json!(true);
    Ok(())
}
#[cfg(all(windows, feature = "experimental-broker"))]
fn receipt_args(operation: &str, receipt: &Path) -> Result<Vec<String>> {
    Ok(vec![
        operation.into(),
        "--allow-machine-provision".into(),
        "--receipt".into(),
        contract::text(receipt)?,
    ])
}
#[cfg(all(windows, feature = "experimental-broker"))]
fn admin_call(
    exe: &Path,
    args: &[String],
    logs: &Path,
    label: &str,
    report: &mut Value,
) -> Result<Value> {
    let value = contract::command(
        exe,
        args,
        b"",
        logs,
        label,
        Duration::from_secs(90),
        contract::never_cancel,
    )?;
    report["commands"]
        .as_array_mut()
        .ok_or("commands array")?
        .push(value.clone());
    contract::output(&value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[test]
    fn small_case_requires_every_opt_in_and_rejects_large() {
        let args = [
            "benchmark",
            "--run",
            "--allow-disposable-services",
            "--allow-virtual-accounts",
            "--allow-acl-mutation",
            "--reviewed",
            "--result",
            "result.json",
            "--broker-exe",
            "broker.exe",
            "--client-exe",
            "client.exe",
            "--admin-exe",
            "admin.exe",
        ];
        let mut options = Options::try_parse_from(args).unwrap();
        assert!(validate(&options).is_ok());
        options.large_mib = Some(600);
        assert!(validate(&options).is_err());
        options.large_mib = None;
        options.allow_virtual_accounts = false;
        assert!(validate(&options).is_err());
        options.allow_virtual_accounts = true;
        options.allow_acl_mutation = false;
        assert!(validate(&options).is_err());
        options.allow_acl_mutation = true;
        options.allow_disposable_services = false;
        assert!(validate(&options).is_err());
        options.allow_disposable_services = true;
        options.reviewed = false;
        assert!(validate(&options).is_err());
        assert!(validate(&Options::try_parse_from(["benchmark"]).unwrap()).is_err());
    }
}
