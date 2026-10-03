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
const CLIENT_REPORT_LIMIT: u64 = 1024 * 1024;

#[cfg(windows)]
fn open_client_report(path: &Path) -> Result<File> {
    use std::os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileType, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_TYPE_DISK,
    };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    // Check the opened handle, not a path that B can replace. Reject pipes/devices
    // before any read; OPEN_REPARSE_POINT prevents following a replaced leaf.
    // SAFETY: file owns the live handle throughout this query and the later read.
    ensure(
        unsafe { GetFileType(file.as_raw_handle()) } == FILE_TYPE_DISK,
        "B report must be a regular non-reparse disk file",
    )?;
    let metadata = file.metadata()?;
    ensure(
        metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "B report must be a regular non-reparse disk file",
    )?;
    ensure(metadata.len() < CLIENT_REPORT_LIMIT, "B report size bound")?;
    Ok(file)
}

fn read_client_report(file: &mut File) -> Result<Value> {
    use std::io::Read;
    // B retains write access: metadata is only an early rejection, not a read bound.
    let mut bytes = Vec::new();
    file.take(CLIENT_REPORT_LIMIT + 1).read_to_end(&mut bytes)?;
    ensure(
        bytes.len() < CLIENT_REPORT_LIMIT as usize,
        "B report size bound",
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn validate_pilot_receipt(value: &Value) -> Result<()> {
    ensure(
        contract::output(value)? == json!({"inserted":1,"duplicates":0}),
        "pilot exact acknowledgement",
    )?;
    let measurement: crate::measure::CommandMeasurement =
        serde_json::from_value(value["measurement"].clone())?;
    measurement.validate()?;
    let policy = crate::measure::SamplePolicy::cli(3, 0);
    ensure(
        measurement.identity == policy.identity
            && measurement.operation_id == policy.operation_id
            && measurement.command_success
            && measurement.payload_bytes
                == serde_json::to_vec(&crate::client::known_record())?.len() as u64,
        "pilot measurement identity/payload mismatch",
    )
}
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
        if options.representative_small_pilot {
            report["schema"] = json!(2);
            report["case"] = json!("representative-6MiB-pilot");
            report["metrics"] = json!({"measured":false,"sampling_complete":false,"performance_policy_status":"unapproved","workload":"one first-warmup insert; NOT full warmup/20-sample steady workload"});
        }
        let outcome = small(
            &broker,
            &client,
            &admin,
            &mut report,
            options.representative_small_pilot,
        );
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
fn small(
    broker: &Path,
    client: &Path,
    admin_source: &Path,
    report: &mut Value,
    pilot: bool,
) -> Result<()> {
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
        generation = if pilot {
            data::generate_with_spec(
                &root.join("small"),
                &data::FixtureSpec::representative_6_mib(),
            )?
        } else {
            data::generate(&root.join("small"), 6 * 1024 * 1024)?
        };
        report["generation"] = generation.clone();
        let manifest = json!({"kind":"benchmark-generated-executable-pins-not-a-vendor-release", "broker_sha256":report["executable_sha256"]["broker"],"client_sha256":report["executable_sha256"]["client"],"admin_sha256":report["executable_sha256"]["admin"]});
        contract::json_new(&root.join("release-manifest.json"), &manifest)?;
        let case = small_case(
            &root,
            broker,
            client,
            fixture.broker_name("small")?,
            fixture.client_sid(),
        )?;
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
            pilot: if pilot {
                Some(contract::PilotJob {
                    schema: 1,
                    fixture_spec: data::FixtureSpec::representative_6_mib(),
                    epoch: fixture.client_name().to_owned(),
                })
            } else {
                None
            },
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
        if let Some(pilot_job) = &job.pilot {
            pilot_interval(
                &root,
                pilot_job,
                &fixture,
                observed.as_ref().ok_or("missing retained C")?,
                report,
            )?;
        }
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
        let mut file = open_client_report(&root.join("scratch/client-result.json"))?;
        report["client"] = read_client_report(&mut file)?;
        report["client_observation"] = fixture.observe_client()?;
        if pilot {
            let commands = report["client"]["commands"]
                .as_array()
                .ok_or("pilot commands missing")?;
            let measured: Vec<_> = commands
                .iter()
                .filter(|v| v.get("measurement").is_some())
                .collect();
            ensure(
                measured.len() == 1,
                "pilot requires exactly one measured command",
            )?;
            validate_pilot_receipt(measured[0])?;
        }
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
    report["startup_import"] = if pilot {
        crate::fixtures::verify_stopped_import_with_expected(
            &install.join("store/memory.db"),
            &generation,
            1,
        )?
    } else {
        crate::fixtures::verify_stopped_import(&install.join("store/memory.db"), &generation)?
    };
    ensure(
        data::inventory(&root.join("small/source"))? == generation["source_before"],
        "source changed after shutdown",
    )?;
    if pilot {
        report["final_payloads"] = crate::client::verify_pilot_projection(
            &install.join("store/events.jsonl"),
            &root.join("small/source/events.jsonl"),
            generation["seed_records"].as_u64().ok_or("seed count")?,
        )?;
    }
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
fn process_sample(sample: crate::metrics::ProcessSnapshot) -> Value {
    json!({"logical_io":crate::measure::LogicalIo::from(sample.logical_io),"private_bytes":sample.private_bytes,"working_set_bytes":sample.working_set_bytes,"lifetime_peak_private_bytes":sample.peak_private_bytes,"lifetime_peak_working_set_bytes":sample.peak_working_set_bytes})
}
#[cfg(all(windows, feature = "experimental-broker"))]
fn pilot_interval(
    root: &Path,
    job: &contract::PilotJob,
    fixture: &crate::scm::Fixture,
    broker: &crate::scm::ObservedService,
    report: &mut Value,
) -> Result<()> {
    use contract::PilotPhase;
    use std::io::{Read, Seek, SeekFrom};
    job.validate()?;
    let mut barrier = contract::PilotBarrier::new(root, &job.epoch)?;
    barrier.wait(
        PilotPhase::Ready,
        Duration::from_secs(60),
        contract::never_cancel,
    )?;
    let projection = root.join("install-small/store/events.jsonl");
    // Quiescent full-prefix scan BEFORE baseline: explicitly warm-cache evidence.
    let before_file = crate::metrics::snapshot_jsonl(&projection)?;
    ensure(
        before_file.length >= 6 * 1024 * 1024,
        "broker representative corpus below 6 MiB",
    )?;
    let before_b = fixture.sample_client()?;
    let before_c = broker.sample()?;
    let start = Instant::now();
    report["metrics"]["pilot_interval"] = json!({"schema":1,"operation_id":0,"stage":"pilot-first-warmup-only","case_epoch":job.epoch,"broker_epoch":1,"supervisor_epoch":2,"cli_epoch":3,"broker_before":process_sample(before_c),"supervisor_before":process_sample(before_b),"coverage":"two boundary samples only; no cadence or interval peak claim","logical_io_semantics":"process logical IO, not physical disk or broker-store-only IO","memory_semantics":"sampled lower bounds; lifetime peaks include startup; no sum of peaks","hashing":"outside measured interval; warm-cache evidence"});
    barrier.publish(PilotPhase::Release)?;
    barrier.wait(
        PilotPhase::Done,
        Duration::from_secs(60),
        contract::never_cancel,
    )?;
    let after_c = broker.sample()?; // SAME retained receipt-admitted handle; no PID reopen.
    let span = start.elapsed().as_micros();
    let after_b = fixture.sample_client()?;
    let c_delta = after_c.logical_io.checked_delta(&before_c.logical_io)?;
    let b_delta = after_b.logical_io.checked_delta(&before_b.logical_io)?;
    let evidence = &mut report["metrics"]["pilot_interval"];
    evidence["broker_after"] = process_sample(after_c);
    evidence["supervisor_after"] = process_sample(after_b);
    evidence["broker_logical_io_delta"] = json!(crate::measure::LogicalIo::from(c_delta));
    evidence["supervisor_logical_io_delta"] = json!(crate::measure::LogicalIo::from(b_delta));
    evidence["handshake_span_us"] = json!(span);
    // Done is quiescent until ACK; corpus hashing and projection/export verification
    // are outside C interval. B harness serialization/capture remains supervisor overhead.
    let after_file = crate::metrics::verify_append(&projection, &before_file)?;
    let mut expected = serde_json::to_vec(&crate::client::known_record())?;
    expected.push(b'\n');
    ensure(
        after_file.length.checked_sub(before_file.length) == Some(expected.len() as u64),
        "pilot exact append length",
    )?;
    let mut file = File::open(&projection)?;
    file.seek(SeekFrom::Start(before_file.length))?;
    let mut actual = vec![0; expected.len()];
    file.read_exact(&mut actual)?;
    ensure(actual == expected, "pilot exact appended payload")?;
    evidence["projection"] = json!({"before_bytes":before_file.length,"after_bytes":after_file.length,"before_sha256":before_file.prefix_sha256,"after_sha256":after_file.prefix_sha256,"volume_serial_number":after_file.identity.volume_serial_number,"file_id":after_file.identity.file_id,"same_identity":true,"exact_append_verified":true});
    report["metrics"]["measured"] = json!(true);
    barrier.publish(PilotPhase::Acknowledged)?;
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

#[cfg(all(windows, feature = "experimental-broker"))]
fn small_case(
    root: &Path,
    broker: &Path,
    client: &Path,
    service_name: String,
    client_sid: &str,
) -> Result<crate::commands::Case> {
    let broker_copy = root.join("bin/hermes-memory-broker.exe");
    let client_copy = root.join("bin/hermes-memory-client.exe");
    // Build outputs can have hardlink aliases. Fresh files inherit the fixture's
    // protected bin policy, not the source ACLs or build-cache link identity.
    for (source, destination) in [(broker, &broker_copy), (client, &client_copy)] {
        let mut input = File::open(source)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
    }
    Ok(crate::commands::Case {
        legacy_root: root.join("small/source"),
        install_root: root.join("install-small"),
        service_name,
        client_sid: client_sid.into(),
        broker_sha256: data::hash_file(&broker_copy)?,
        client_sha256: data::hash_file(&client_copy)?,
        broker_source: broker_copy,
        client_source: client_copy,
        release_sha256: data::hash_file(&root.join("release-manifest.json"))?,
        default_enrollment: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn client_report_enforces_consumed_boundary_and_json_eof() {
        use std::io::{Seek, SeekFrom};
        let mut file = tempfile::tempfile().unwrap();
        for length in [
            CLIENT_REPORT_LIMIT - 1,
            CLIENT_REPORT_LIMIT,
            CLIENT_REPORT_LIMIT + 1,
            CLIENT_REPORT_LIMIT * 2,
        ] {
            let mut bytes = vec![b' '; length as usize];
            bytes[..2].copy_from_slice(b"{}");
            file.set_len(0).unwrap();
            file.rewind().unwrap();
            file.write_all(&bytes).unwrap();
            file.rewind().unwrap();
            let outcome = read_client_report(&mut file);
            assert_eq!(
                file.stream_position().unwrap(),
                length.min(CLIENT_REPORT_LIMIT + 1)
            );
            if length < CLIENT_REPORT_LIMIT {
                assert_eq!(outcome.unwrap(), json!({}));
            } else {
                assert_eq!(outcome.unwrap_err().to_string(), "B report size bound");
            }
        }
        for bytes in [b"{".as_slice(), b"{}{}", b"{} trailing", b"", b"\xff"] {
            file.set_len(0).unwrap();
            file.rewind().unwrap();
            file.write_all(bytes).unwrap();
            file.rewind().unwrap();
            let error = read_client_report(&mut file).unwrap_err();
            assert!(error.downcast_ref::<serde_json::Error>().is_some());
            assert_eq!(file.seek(SeekFrom::End(0)).unwrap(), bytes.len() as u64);
        }
        // An invalid first byte must not reach serde when the file is oversized.
        file.set_len(CLIENT_REPORT_LIMIT * 2).unwrap();
        file.rewind().unwrap();
        file.write_all(b"!").unwrap();
        file.rewind().unwrap();
        assert_eq!(
            read_client_report(&mut file).unwrap_err().to_string(),
            "B report size bound"
        );
        assert_eq!(file.stream_position().unwrap(), CLIENT_REPORT_LIMIT + 1);
    }

    #[cfg(windows)]
    #[test]
    fn client_report_open_rejects_oversize_and_retains_the_admitted_handle() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client-result.json");
        fs::write(&path, b"{\"pass\":true}").unwrap();
        let mut file = open_client_report(&path).unwrap();
        let retained = temp.path().join("retained.json");
        fs::rename(&path, &retained).unwrap();
        let replacement = File::create(&path).unwrap();
        replacement.set_len(CLIENT_REPORT_LIMIT).unwrap();
        assert_eq!(
            open_client_report(&path).unwrap_err().to_string(),
            "B report size bound"
        );
        assert_eq!(read_client_report(&mut file).unwrap(), json!({"pass":true}));
        assert_eq!(fs::read(&retained).unwrap(), b"{\"pass\":true}");
        assert_eq!(replacement.metadata().unwrap().len(), CLIENT_REPORT_LIMIT);
    }

    #[cfg(windows)]
    #[test]
    fn client_report_rejects_nonregular_and_reparse_handles() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("directory");
        fs::create_dir(&directory).unwrap();
        let junction = temp.path().join("junction");
        // Directory junctions need no symlink privilege or ACL mutation.
        let output = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&directory)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(fs::symlink_metadata(&junction)
            .unwrap()
            .file_type()
            .is_symlink());
        for path in [directory.as_path(), junction.as_path(), Path::new("NUL")] {
            assert_eq!(
                open_client_report(path).unwrap_err().to_string(),
                "B report must be a regular non-reparse disk file",
                "{path:?}"
            );
        }
        fs::remove_dir(&junction).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn client_report_growth_after_metadata_is_bounded_before_json() {
        use std::io::Seek;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("client-result.json");
        fs::write(&path, b"\"").unwrap();
        // The production open has already observed and accepted the short file.
        let mut file = open_client_report(&path).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 1);
        let mut writer = OpenOptions::new().append(true).open(&path).unwrap();
        writer
            .write_all(&vec![b'x'; (CLIENT_REPORT_LIMIT * 2) as usize])
            .unwrap();
        writer.write_all(b"\"").unwrap();
        writer.sync_all().unwrap();
        let outcome = read_client_report(&mut file);
        let consumed = file.stream_position().unwrap();
        assert!(
            consumed <= CLIENT_REPORT_LIMIT + 1,
            "consumed {consumed} bytes"
        );
        assert_eq!(consumed, CLIENT_REPORT_LIMIT + 1);
        assert_eq!(outcome.unwrap_err().to_string(), "B report size bound");
    }

    #[cfg(all(windows, feature = "experimental-broker"))]
    #[test]
    fn small_plan_owns_single_link_payloads_from_hardlinked_build_outputs() {
        use hermes_memory::windows_provision::{checked_plan, Inputs};
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("fixture");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("release-manifest.json"), b"synthetic manifest").unwrap();
        let broker = temp.path().join("broker.exe");
        let client = temp.path().join("client.exe");
        for path in [&broker, &client] {
            fs::write(path, b"synthetic payload, never executed").unwrap();
            fs::hard_link(path, path.with_extension("alias")).unwrap();
        }
        let case = small_case(
            &root,
            &broker,
            &client,
            "HMVBenchmark-synthetic".into(),
            "S-1-5-80-1-2-3-4-5",
        )
        .unwrap();
        let args = case.prepare_args().unwrap();
        let value = |key: &str| args[args.iter().position(|v| v == key).unwrap() + 1].clone();
        let inputs = Inputs {
            legacy_root: value("--legacy-root"),
            client_sid: value("--client-sid"),
            workspace: value("--workspace"),
            scope_mode: Default::default(),
            install_root: value("--install-root"),
            service_name: Some(value("--service-name")),
            broker_source: value("--broker-source"),
            broker_sha256: value("--broker-sha256"),
            client_source: value("--client-source"),
            client_sha256: value("--client-sha256"),
            release_sha256: value("--release-sha256"),
        };
        let mut original = inputs.clone();
        original.broker_source = contract::text(&broker).unwrap();
        original.client_source = contract::text(&client).unwrap();
        assert_eq!(
            checked_plan(&original).unwrap_err().to_string(),
            "source must be bounded regular non-reparse single-link disk file"
        );
        checked_plan(&inputs).expect("fixture-owned copies must pass strict source admission");
        assert_eq!(
            case.broker_source,
            root.join("bin/hermes-memory-broker.exe")
        );
        assert_eq!(
            case.client_source,
            root.join("bin/hermes-memory-client.exe")
        );
        for (source, copy) in [
            (&broker, &case.broker_source),
            (&client, &case.client_source),
        ] {
            assert_eq!(
                data::hash_file(source).unwrap(),
                data::hash_file(copy).unwrap()
            );
        }
        assert!(!root.join("install-small").exists());
        // A second attempt must not overwrite any fixture payload.
        assert!(small_case(
            &root,
            &broker,
            &client,
            "HMVBenchmark-synthetic".into(),
            "S-1-5-80-1-2-3-4-5"
        )
        .is_err());
    }

    #[test]
    fn pilot_receipt_rejects_wrong_epoch_payload_and_ack() {
        let mut measurement = crate::measure::CommandMeasurement::new(
            &crate::measure::SamplePolicy::cli(3, 0),
            serde_json::to_vec(&crate::client::known_record())
                .unwrap()
                .len() as u64,
        );
        measurement.command_success = true;
        measurement.child_exit_us = Some(1);
        let value = json!({"success":true,"stdout":"{\"inserted\":1,\"duplicates\":0}","measurement":measurement});
        validate_pilot_receipt(&value).unwrap(); // Synthetic no-memory sample stays incomplete.
        for (field, replacement) in [
            ("operation_id", json!(2)),
            ("payload_bytes", json!(1)),
            ("command_success", json!(false)),
        ] {
            let mut bad = value.clone();
            bad["measurement"][field] = replacement;
            assert!(validate_pilot_receipt(&bad).is_err());
        }
        let mut bad = value.clone();
        bad["measurement"]["identity"]["epoch"] = json!(4);
        assert!(validate_pilot_receipt(&bad).is_err());
        let mut bad = value;
        bad["stdout"] = json!("{\"inserted\":0,\"duplicates\":1}");
        assert!(validate_pilot_receipt(&bad).is_err());
    }
    #[test]
    fn representative_pilot_requires_all_consents_and_still_refuses_600() {
        let args = [
            "benchmark",
            "--representative-small-pilot",
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
        let options = Options::try_parse_from(args).expect("explicit pilot parser");
        assert!(validate(&options).is_ok());
        for missing in [
            "--run",
            "--allow-disposable-services",
            "--allow-virtual-accounts",
            "--allow-acl-mutation",
            "--reviewed",
        ] {
            let reduced: Vec<_> = args.iter().filter(|a| **a != missing).copied().collect();
            assert!(validate(&Options::try_parse_from(reduced).unwrap()).is_err());
        }
        let mut options = options;
        options.large_mib = Some(600);
        assert!(validate(&options).is_err());
    }
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
