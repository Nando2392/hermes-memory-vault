//! Shared bounded CLI capture. Only direct children are terminated on deadline;
//! SCM processes are stopped cooperatively by the owning adapter, never killed.
use crate::data::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub case: crate::commands::Case,
    pub enrollment: PathBuf,
    pub client: PathBuf,
    pub seed_records: u64,
}
pub fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
pub fn json_new(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}
pub fn text(path: &Path) -> Result<String> {
    Ok(path.to_str().ok_or("non-UTF8 path")?.to_owned())
}
const OUTPUT_LIMIT: usize = 1024 * 1024;

#[derive(Default)]
struct Capture {
    bytes: Vec<u8>,
    overflow: bool,
    eof: bool,
}
impl Capture {
    #[cfg(windows)]
    fn poll(
        &mut self,
        pipe: &mut (impl Read + std::os::windows::io::AsRawHandle),
    ) -> std::io::Result<bool> {
        use windows_sys::Win32::{Foundation::ERROR_BROKEN_PIPE, System::Pipes::PeekNamedPipe};
        let mut available = 0;
        // SAFETY: borrowed live anonymous-pipe read handle. Only this thread reads
        // it. Peek is nonblocking; Read below requests no more than available.
        let ok = unsafe {
            PeekNamedPipe(
                pipe.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                self.eof = true;
                return Ok(false);
            }
            return Err(error);
        }
        if available == 0 || self.eof {
            return Ok(false);
        }
        let mut buffer = [0; 16384];
        let count = pipe.read(&mut buffer[..(available as usize).min(16384)])?;
        let retained = count.min(OUTPUT_LIMIT - self.bytes.len());
        self.bytes.extend_from_slice(&buffer[..retained]);
        self.overflow |= count > retained;
        self.eof = count == 0;
        Ok(count != 0)
    }
    #[cfg(not(windows))]
    fn poll(&mut self, _pipe: &mut impl Read) -> std::io::Result<bool> {
        Err(std::io::Error::other(
            "bounded CLI capture requires Windows",
        ))
    }
}

/// Both pipes are serviced fairly on one thread, one bounded chunk per turn.
/// No reader threads, blocking EOF drain, or join can outlive the direct child.
/// After exit/cancellation, pipe draining has a 250ms budget (descendants may
/// retain writers); direct-child reap has a separate 2s budget. Only Child::kill
/// on the retained handle is permitted; incomplete shutdown fails closed.
/// Disk receives only the bounded prefixes, never a child's writable log handle.
pub fn command(
    exe: &Path,
    args: &[String],
    input: &[u8],
    directory: &Path,
    label: &str,
    timeout: Duration,
    cancelled: fn() -> bool,
) -> Result<Value> {
    ensure(
        !label.is_empty()
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "unsafe command label",
    )?;
    ensure(input.len() <= 8 * 1024 * 1024, "stdin bound")?;
    let prefix = directory.join(label);
    json_new(
        &prefix.with_extension("intent.json"),
        &json!({"exe":exe,"args":args,"deadline_ms":timeout.as_millis()}),
    )?;
    let stdin = prefix.with_extension("stdin");
    let stdout = prefix.with_extension("stdout");
    let stderr = prefix.with_extension("stderr");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stdin)?;
    f.write_all(input)?;
    drop(f);
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stdout)?;
    let mut err = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stderr)?;
    let started = Instant::now();
    // A bounded regular input file cannot block the supervisor on an unread
    // stdin pipe. Children receive the same bytes followed by EOF.
    let spawned = Command::new(exe)
        .args(args)
        .current_dir(directory)
        .stdin(Stdio::from(File::open(&stdin)?))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut stdout_capture = Capture::default();
    let mut stderr_capture = Capture::default();
    let mut timed_out = false;
    let mut stopped = false;
    let mut status = None;
    let mut capture_error = None;
    let mut kill_error = None;
    let mut wait_error = None;
    let mut spawn_error = None;
    if let Ok(mut child) = spawned {
        // Stdio::piped guarantees both handles on successful spawn.
        let mut stdout_pipe = child.stdout.take().expect("piped stdout");
        let mut stderr_pipe = child.stderr.take().expect("piped stderr");
        let mut shutdown = None;
        let mut drain_started = None;
        loop {
            let mut progress = false;
            if capture_error.is_none()
                && drain_started.is_none_or(|t: Instant| t.elapsed() < Duration::from_millis(250))
            {
                match stdout_capture.poll(&mut stdout_pipe) {
                    Ok(read) => progress |= read,
                    Err(error) => capture_error = Some(error.to_string()),
                }
                match stderr_capture.poll(&mut stderr_pipe) {
                    Ok(read) => progress |= read,
                    Err(error) => capture_error = Some(error.to_string()),
                }
            }
            if status.is_none() && wait_error.is_none() {
                match child.try_wait() {
                    Ok(value) => status = value,
                    Err(error) => wait_error = Some(error.to_string()),
                }
            }
            if status.is_none() && shutdown.is_none() {
                stopped = cancelled();
                timed_out = started.elapsed() >= timeout;
                if timed_out
                    || stopped
                    || stdout_capture.overflow
                    || stderr_capture.overflow
                    || capture_error.is_some()
                    || wait_error.is_some()
                {
                    shutdown = Some(Instant::now());
                    // Only our retained direct-child handle; never a process tree.
                    if let Err(error) = child.kill() {
                        kill_error = Some(error.to_string());
                    }
                }
            }
            if status.is_some() || shutdown.is_some() {
                let drain = drain_started.get_or_insert_with(Instant::now);
                let drained = (stdout_capture.eof && stderr_capture.eof)
                    || capture_error.is_some()
                    || drain.elapsed() >= Duration::from_millis(250);
                let reaped = status.is_some()
                    || wait_error.is_some()
                    || shutdown.is_some_and(|t| t.elapsed() >= Duration::from_secs(2));
                if drained && reaped {
                    break;
                }
            }
            if !progress {
                thread::sleep(Duration::from_millis(2));
            }
        }
    } else if let Err(error) = spawned {
        spawn_error = Some(error.to_string());
    }
    // At most OUTPUT_LIMIT raw bytes per file, including on failure. No child
    // ever receives these writable handles. JSON escaping/lossy UTF-8 expansion
    // has a fixed bounded overhead; raw evidence is preserved in the files.
    out.write_all(&stdout_capture.bytes)?;
    err.write_all(&stderr_capture.bytes)?;
    out.sync_all()?;
    err.sync_all()?;
    let capture_complete = stdout_capture.eof && stderr_capture.eof;
    let success = status.is_some_and(|s| s.success())
        && !timed_out
        && !stopped
        && !stdout_capture.overflow
        && !stderr_capture.overflow
        && capture_complete
        && capture_error.is_none()
        && kill_error.is_none()
        && wait_error.is_none();
    let value = json!({"exe":exe,"args":args,"exit_code":status.and_then(|s| s.code()),"success":success,
        "child_exited":status.is_some(),"capture_complete":capture_complete,
        "spawn_error":spawn_error,"capture_error":capture_error,"kill_error":kill_error,"wait_error":wait_error,
        "stdout_overflow":stdout_capture.overflow,"stderr_overflow":stderr_capture.overflow,
        "timed_out":timed_out,"stop_requested":stopped,"elapsed_us":started.elapsed().as_micros(),
        "stdout":String::from_utf8_lossy(&stdout_capture.bytes),"stderr":String::from_utf8_lossy(&stderr_capture.bytes),
        "stdout_file":stdout,"stderr_file":stderr});
    json_new(&prefix.with_extension("result.json"), &value)?;
    Ok(value)
}
pub fn output(value: &Value) -> Result<Value> {
    ensure(
        value["success"] == true,
        "CLI failed; see captured return code/stdout/stderr",
    )?;
    Ok(serde_json::from_str(
        value["stdout"].as_str().ok_or("missing stdout")?,
    )?)
}
pub fn never_cancel() -> bool {
    false
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::fs;
    // Explicitly invoked by the non-ignored regression tests with
    // --ignored --exact contract::tests::capture_fixture --nocapture.
    // Ignoring only this fixture prevents process::exit from ending the parent
    // test harness. No behavioral regression test is ignored.
    // This ordinary self-owned child never enters the benchmark/SCM entrypoint.
    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess fixture only"]
    fn capture_fixture() {
        let mut mode = String::new();
        std::io::stdin().read_to_string(&mut mode).unwrap();
        match mode.as_str() {
            "stdout" => std::io::stdout()
                .write_all(&vec![b'x'; 1024 * 1024 + 1])
                .unwrap(),
            "stderr" => std::io::stderr()
                .write_all(&vec![b'e'; 1024 * 1024 + 1])
                .unwrap(),
            "boundary" => std::io::stderr()
                .write_all(&vec![b'e'; 1024 * 1024])
                .unwrap(),
            "live-stdout" | "live-stderr" => {
                let mut stream: Box<dyn Write> = if mode == "live-stdout" {
                    Box::new(std::io::stdout())
                } else {
                    Box::new(std::io::stderr())
                };
                for _ in 0..2048 {
                    stream.write_all(&[b'x'; 16384]).unwrap();
                }
                fs::write("unexpected-completion", b"overflow not stopped").unwrap();
            }
            "nonzero" => std::process::exit(7),
            "descendant" => {
                // Self-terminating descendant deliberately retains both writers.
                // Its completion marker proves command() did not kill the tree.
                let _descendant = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "contract::tests::capture_sleeper",
                        "--nocapture",
                    ])
                    .stdin(Stdio::null())
                    .spawn()
                    .unwrap();
            }
            "timeout" => thread::sleep(Duration::from_secs(10)),
            _ => panic!("unknown fixture"),
        }
        std::process::exit(0);
    }

    #[cfg(windows)]
    fn fixture(mode: &str, timeout: Duration) -> (tempfile::TempDir, Value) {
        let dir = tempfile::tempdir().unwrap();
        let result = command(
            &std::env::current_exe().unwrap(),
            &[
                "--ignored".into(),
                "--exact".into(),
                "contract::tests::capture_fixture".into(),
                "--nocapture".into(),
            ],
            mode.as_bytes(),
            dir.path(),
            "capture",
            timeout,
            never_cancel,
        )
        .unwrap();
        let persisted: Value =
            serde_json::from_reader(File::open(dir.path().join("capture.result.json")).unwrap())
                .unwrap();
        assert_eq!(result, persisted);
        (dir, result)
    }

    #[cfg(windows)]
    #[test]
    fn bounded_capture_overflow_keeps_evidence() {
        for stream in ["stdout", "stderr"] {
            let (dir, result) = fixture(stream, Duration::from_secs(5));
            assert_eq!(result["success"], false);
            assert_eq!(result[format!("{stream}_overflow")], true);
            assert!(result[stream].as_str().unwrap().len() <= 1024 * 1024);
            assert_eq!(
                fs::metadata(dir.path().join(format!("capture.{stream}")))
                    .unwrap()
                    .len(),
                1024 * 1024
            );
            assert_eq!(result["child_exited"], true);
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess fixture only; explicitly selected with --ignored --exact"]
    fn capture_sleeper() {
        thread::sleep(Duration::from_secs(2));
        fs::write("descendant-completed", b"ok").unwrap();
        std::process::exit(0);
    }

    #[cfg(windows)]
    #[test]
    fn capture_exact_cap_is_successful() {
        let (dir, result) = fixture("boundary", Duration::from_secs(5));
        assert_eq!(result["success"], true);
        assert_eq!(result["stderr_overflow"], false);
        assert_eq!(result["stderr"].as_str().unwrap().len(), OUTPUT_LIMIT);
        assert_eq!(
            fs::metadata(dir.path().join("capture.stderr"))
                .unwrap()
                .len(),
            OUTPUT_LIMIT as u64
        );
    }

    #[cfg(windows)]
    #[test]
    fn capture_stops_live_producer_before_completion() {
        for stream in ["stdout", "stderr"] {
            let (dir, result) = fixture(&format!("live-{stream}"), Duration::from_secs(10));
            assert_eq!(result["success"], false);
            assert_eq!(result[format!("{stream}_overflow")], true);
            assert_eq!(result["timed_out"], false);
            assert_eq!(result["child_exited"], true);
            assert!(!dir.path().join("unexpected-completion").exists());
            for name in ["stdout", "stderr"] {
                assert!(
                    fs::metadata(dir.path().join(format!("capture.{name}")))
                        .unwrap()
                        .len()
                        <= OUTPUT_LIMIT as u64
                );
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn capture_timeout_retains_status_and_evidence() {
        let (_, result) = fixture("timeout", Duration::from_millis(100));
        assert_eq!(result["success"], false);
        assert_eq!(result["timed_out"], true);
        assert_eq!(result["child_exited"], true);
        assert!(result["elapsed_us"].as_u64().unwrap() < 3_000_000);
    }

    #[cfg(windows)]
    #[test]
    fn capture_nonzero_exit_is_preserved() {
        let (_, result) = fixture("nonzero", Duration::from_secs(5));
        assert_eq!(result["success"], false);
        assert_eq!(result["exit_code"], 7);
        assert_eq!(result["capture_complete"], true);
        assert_eq!(result["timed_out"], false);
    }

    #[cfg(windows)]
    #[test]
    fn capture_does_not_wait_for_or_kill_descendants() {
        let started = Instant::now();
        let (dir, result) = fixture("descendant", Duration::from_secs(5));
        let elapsed = started.elapsed();
        // Wait for the finite fixture even if assertions below fail.
        thread::sleep(Duration::from_millis(2200));
        assert!(dir.path().join("descendant-completed").exists());
        assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
        assert_eq!(result["exit_code"], 0);
        assert_eq!(result["child_exited"], true);
        assert_eq!(result["capture_complete"], false);
        assert_eq!(result["success"], false);
    }

    #[cfg(windows)]
    #[test]
    fn capture_unread_stdin_cannot_block_timeout_or_cancellation() {
        for cancel in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let result = command(
                &std::env::current_exe().unwrap(),
                &[
                    "--ignored".into(),
                    "--exact".into(),
                    "contract::tests::capture_sleeper".into(),
                    "--nocapture".into(),
                ],
                &vec![b'x'; 8 * 1024 * 1024],
                dir.path(),
                "unread",
                Duration::from_millis(100),
                if cancel { || true } else { never_cancel },
            )
            .unwrap();
            assert_eq!(result["success"], false);
            assert_eq!(result["child_exited"], true);
            assert_eq!(result["stop_requested"], cancel);
            assert_eq!(result["timed_out"], !cancel);
            assert!(result["elapsed_us"].as_u64().unwrap() < 3_000_000);
            let persisted: Value =
                serde_json::from_reader(File::open(dir.path().join("unread.result.json")).unwrap())
                    .unwrap();
            assert_eq!(result, persisted);
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn capture_poll_refuses_non_windows_without_reading() {
        let mut pipe = std::io::Cursor::new(b"must not be consumed");
        let mut capture = Capture::default();
        let error = capture.poll(&mut pipe).unwrap_err();
        assert_eq!(error.to_string(), "bounded CLI capture requires Windows");
        assert_eq!(pipe.position(), 0);
        assert!(capture.bytes.is_empty());
        assert!(!capture.overflow && !capture.eof);
    }

    #[cfg(not(windows))]
    #[test]
    fn command_non_windows_capture_fails_closed_with_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let result = command(
            &std::env::current_exe().unwrap(),
            &["--help".into()],
            b"",
            dir.path(),
            "unsupported",
            Duration::from_secs(5),
            never_cancel,
        )
        .unwrap();
        assert_eq!(result["success"], false);
        assert_eq!(result["capture_complete"], false);
        assert_eq!(
            result["capture_error"],
            "bounded CLI capture requires Windows"
        );
        assert!(result["spawn_error"].is_null());
        assert_eq!(result["child_exited"], true);
        assert!(output(&result).is_err());
        let persisted: Value = serde_json::from_reader(
            File::open(dir.path().join("unsupported.result.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(result, persisted);
    }

    #[test]
    fn capture_spawn_failure_retains_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let result = command(
            &dir.path().join("missing.exe"),
            &[],
            b"",
            dir.path(),
            "missing",
            Duration::from_secs(1),
            never_cancel,
        )
        .unwrap();
        assert_eq!(result["success"], false);
        assert_eq!(result["child_exited"], false);
        assert!(result["exit_code"].is_null());
        assert!(result["spawn_error"].is_string());
        let persisted: Value =
            serde_json::from_reader(File::open(dir.path().join("missing.result.json")).unwrap())
                .unwrap();
        assert_eq!(result, persisted);
    }

    #[cfg(windows)]
    #[test]
    fn command_captures_real_child_status_and_refuses_log_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let exe = std::env::current_exe().unwrap();
        let result = command(
            &exe,
            &["--help".into()],
            b"",
            dir.path(),
            "help",
            Duration::from_secs(10),
            never_cancel,
        )
        .unwrap();
        assert_eq!(result["exit_code"], 0);
        assert_eq!(result["timed_out"], false);
        assert!(result["stdout"].as_str().unwrap().contains("Usage"));
        assert!(command(
            &exe,
            &["--help".into()],
            b"",
            dir.path(),
            "help",
            Duration::from_secs(10),
            never_cancel
        )
        .is_err());
    }
}
