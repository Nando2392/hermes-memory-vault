//! Windows adapter for the experimental, fixed-workspace broker.
use super::*;
use std::path::PathBuf;
const ACK: &[u8; 8] = b"HMACK001";
fn exchange(
    stream: &mut (impl Read + Write),
    bytes: &[u8],
    id: &str,
) -> Result<Response, &'static str> {
    write_frame(stream, bytes).map_err(|_| "outcome_unknown")?;
    let reply = read_frame(stream).map_err(|_| "outcome_unknown")?;
    let response: Response = serde_json::from_slice(&reply).map_err(|_| "outcome_unknown")?;
    if response.protocol != 1
        || response.request_id != id
        || (response.ok && (response.result.is_none() || response.error.is_some()))
        || (!response.ok && (response.error.is_none() || response.result.is_some()))
    {
        return Err("outcome_unknown");
    }
    stream.write_all(ACK).map_err(|_| "outcome_unknown")?;
    Ok(response)
}

fn respond(stream: &mut (impl Read + Write), response: &Response) -> Result<(), &'static str> {
    let bytes = serde_json::to_vec(response).map_err(|_| "outcome_unknown")?;
    write_frame(stream, &bytes).map_err(|_| "outcome_unknown")?;
    let mut ack = [0; 8];
    stream.read_exact(&mut ack).map_err(|_| "outcome_unknown")?;
    if &ack != ACK {
        return Err("outcome_unknown");
    }
    Ok(())
}

trait PeerStream: Read + Write {
    fn reauthenticate(&mut self) -> io::Result<()>;
}
fn serve_one(
    stream: &mut impl PeerStream,
    store: &hermes_memory::MemoryStore,
    workspace: &str,
) -> Result<(), &'static str> {
    stream.reauthenticate().map_err(|_| "unauthorized")?;
    let bytes = read_frame(stream).map_err(|_| "invalid_request")?;
    stream.reauthenticate().map_err(|_| "unauthorized")?;
    let response = match protocol::decode(&bytes, workspace) {
        Ok(request) => dispatch(store, request),
        Err(code) => rejection(&bytes, code),
    };
    respond(stream, &response)
}

fn request_from<S: Read + Write>(
    input: impl Read,
    connect: impl FnOnce() -> Result<S, &'static str>,
) -> Result<Response, &'static str> {
    let mut bytes = Vec::new();
    input
        .take((MAX_FRAME + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "invalid_request")?;
    if bytes.len() > MAX_FRAME {
        return Err("resource_limit");
    }
    let request: protocol::Request = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(_) => return Ok(rejection(&bytes, "invalid_request")),
    };
    if request.protocol != 1 {
        return Err("unsupported_version");
    }
    if request.request_id.trim().is_empty() || request.request_id.len() > 128 {
        return Err("invalid_request");
    }
    exchange(&mut connect()?, &bytes, &request.request_id)
}

pub fn request(pipe: &str, server_sid: &str) -> Result<(), &'static str> {
    endpoint(pipe, server_sid)?;
    let response = request_from(io::stdin().lock(), || {
        hermes_memory::windows_pipe::connect_authenticated(
            pipe,
            server_sid,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                "unauthorized"
            } else {
                "unavailable"
            }
        })
    })?;
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &response).map_err(|_| "outcome_unknown")?;
    stdout.write_all(b"\n").map_err(|_| "outcome_unknown")
}
fn service_with(
    config: Config,
    start: impl FnOnce(Config) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    validate(&config)?;
    start(config)
}
pub fn service(config: Config) -> Result<(), &'static str> {
    service_with(config, start_scm)
}

// Thin Win32 adapters below require the external SCM binary gate,
// never by local unit tests (which use the same supervisor/control functions).
struct Runtime {
    config: Config,
    stop: AtomicBool,
    result: std::sync::Mutex<Option<Result<(), &'static str>>>,
}
static RUNTIME: std::sync::OnceLock<Runtime> = std::sync::OnceLock::new();
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn start_scm(config: Config) -> Result<(), &'static str> {
    let mut name = wide(&config.service_name);
    RUNTIME
        .set(Runtime {
            config,
            stop: AtomicBool::new(false),
            result: std::sync::Mutex::new(None),
        })
        .map_err(|_| "service_already_started")?;
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: table is sentinel terminated; name/table remain live throughout
    // dispatcher execution; callbacks have the exact system ABI and static state.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        eprintln!("SCM dispatcher: {}", io::Error::last_os_error());
        return Err("scm_dispatcher_failed");
    }
    let runtime = RUNTIME.get().ok_or("scm_dispatcher_failed")?;
    runtime
        .result
        .lock()
        .map_err(|_| "service_panicked")?
        .take()
        .ok_or("service_not_started")?
}
unsafe extern "system" fn control_handler(
    code: u32,
    _: u32,
    _: *mut std::ffi::c_void,
    _: *mut std::ffi::c_void,
) -> u32 {
    match RUNTIME.get() {
        Some(runtime) => control(code, &runtime.stop),
        None => windows_sys::Win32::Foundation::ERROR_SERVICE_NOT_ACTIVE,
    }
}
unsafe extern "system" fn service_main(_: u32, _: *mut *mut u16) {
    let Some(runtime) = RUNTIME.get() else {
        return;
    };
    // No Rust unwind may cross the SCM ABI boundary.
    let result =
        std::panic::catch_unwind(|| service_main_inner(runtime)).unwrap_or(Err("service_panicked"));
    runtime.stop.store(true, Ordering::Release);
    match runtime.result.lock() {
        Ok(mut slot) => *slot = Some(result),
        Err(_) => {
            eprintln!("service_panicked");
            std::process::exit(1);
        }
    }
    // A failed SetServiceStatus may leave SCM believing the service is still
    // active, so the dispatcher need not return. Fail THIS dedicated process
    // after the supervisor's bounded drain rather than hang awaiting SCM.
    if let Err(code) = result {
        eprintln!("{code}");
        std::process::exit(1);
    }
}
fn report_status(
    handle: SERVICE_STATUS_HANDLE,
    state: u32,
    checkpoint: u32,
    exit: u32,
) -> Result<(), &'static str> {
    let status = status(state, checkpoint, exit);
    // SAFETY: SCM supplies the live registered status handle; status is a valid
    // immutable ABI object for the synchronous call. SCM owns the handle.
    if unsafe { SetServiceStatus(handle, &status) } == 0 {
        eprintln!("SCM status: {}", io::Error::last_os_error());
        Err("scm_status_failed")
    } else {
        Ok(())
    }
}
fn service_main_inner(runtime: &'static Runtime) -> Result<(), &'static str> {
    // SAFETY: validated terminated name, static handler and no context pointer.
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(
            wide(&runtime.config.service_name).as_ptr(),
            Some(control_handler),
            std::ptr::null(),
        )
    };
    if handle.is_null() {
        eprintln!("SCM handler: {}", io::Error::last_os_error());
        return Err("scm_handler_failed");
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let spawn = std::thread::Builder::new()
        .name("broker-store".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(|| {
                worker(&runtime.config, &runtime.stop, || {
                    tx.send(Event::Ready).map_err(|_| "supervisor_exited")
                })
            })
            .unwrap_or(Err("worker_panicked"));
            // Store and pipe handles have already dropped before Done is sent.
            let _ = tx.send(Event::Done(result));
        });
    let thread = match spawn {
        Ok(thread) => thread,
        Err(_) => {
            report_status(handle, SERVICE_STOPPED, 0, 1)?;
            return Err("worker_start_failed");
        }
    };
    let result = supervise(
        || match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(event) => event,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Event::Tick,
            Err(_) => Event::Done(Err("worker_exited")),
        },
        &runtime.stop,
        |state, checkpoint, exit| report_status(handle, state, checkpoint, exit),
        Duration::from_secs(30),
        Duration::from_secs(15),
    );
    runtime.stop.store(true, Ordering::Release);
    // Never perform an unbounded join after a deadline. On timeout the SCM
    // callback/dispatcher returns Err to main, which exits THIS own process.
    // No PID lookup, TerminateProcess, service-account mutation or foreign kill.
    if thread.is_finished() {
        thread.join().map_err(|_| "worker_panicked")?;
    }
    result
}

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Services::*;
enum Event {
    Tick,
    Ready,
    Done(Result<(), &'static str>),
}
fn supervise(
    mut receive: impl FnMut() -> Event,
    stop: &AtomicBool,
    mut report: impl FnMut(u32, u32, u32) -> Result<(), &'static str>,
    start_budget: Duration,
    stop_budget: Duration,
) -> Result<(), &'static str> {
    let mut state = SERVICE_START_PENDING;
    let mut checkpoint: u32 = 1;
    let started = Instant::now();
    let mut stopping = None;
    let mut error = report(state, checkpoint, 0).err();
    loop {
        if error.is_some() {
            stop.store(true, Ordering::Release);
        }
        if stop.load(Ordering::Acquire) && stopping.is_none() {
            stopping = Some(Instant::now());
            state = SERVICE_STOP_PENDING;
        }
        let event = receive();
        if state == SERVICE_START_PENDING && started.elapsed() >= start_budget {
            error.get_or_insert("service_timeout");
            stop.store(true, Ordering::Release);
        }
        match event {
            Event::Done(result) => {
                let result = error.map_or_else(
                    || {
                        if result.is_ok() && !stop.load(Ordering::Acquire) {
                            Err("worker_exited")
                        } else {
                            result
                        }
                    },
                    Err,
                );
                report(SERVICE_STOPPED, 0, u32::from(result.is_err()))?;
                return result;
            }
            Event::Ready if !stop.load(Ordering::Acquire) => {
                state = SERVICE_RUNNING;
            }
            _ => (),
        }
        if stop.load(Ordering::Acquire) && stopping.is_none() {
            stopping = Some(Instant::now());
            state = SERVICE_STOP_PENDING;
        }
        if stopping.is_some_and(|t| t.elapsed() >= stop_budget) {
            report(SERVICE_STOPPED, 0, 1)?;
            return Err(error.unwrap_or("service_timeout"));
        }
        checkpoint = checkpoint.saturating_add(1);
        if let Err(code) = report(
            state,
            if state == SERVICE_RUNNING {
                0
            } else {
                checkpoint
            },
            0,
        ) {
            error.get_or_insert(code);
        }
    }
}

fn control(code: u32, stop: &AtomicBool) -> u32 {
    match code {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            stop.store(true, Ordering::Release);
            0
        }
        SERVICE_CONTROL_INTERROGATE => 0,
        _ => windows_sys::Win32::Foundation::ERROR_CALL_NOT_IMPLEMENTED,
    }
}
fn status(state: u32, checkpoint: u32, exit: u32) -> SERVICE_STATUS {
    let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
    SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: if exit == 0 {
            0
        } else {
            windows_sys::Win32::Foundation::ERROR_SERVICE_SPECIFIC_ERROR
        },
        dwServiceSpecificExitCode: exit,
        dwCheckPoint: if pending { checkpoint } else { 0 },
        dwWaitHint: if pending { 5000 } else { 0 },
    }
}

// Shared production ordering seam; callbacks isolate native gates for negative tests.
// The returned guard must outlive store/listener. On failure locals drop in reverse order.
#[allow(clippy::too_many_arguments)] // Explicit security gates, not optional configuration.
fn startup_with<G, S, L>(
    token: impl FnOnce() -> Result<(), &'static str>,
    temp: impl FnOnce() -> Result<G, &'static str>,
    open: impl FnOnce() -> Result<S, &'static str>,
    verify: impl FnOnce(&G, &S) -> Result<(), &'static str>,
    bootstrap: impl FnOnce(&S) -> Result<(), &'static str>,
    prepare: impl FnOnce(&S) -> Result<(), &'static str>,
    bind: impl FnOnce() -> Result<L, &'static str>,
    ready: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(G, S, L), &'static str> {
    token()?;
    let guard = temp()?;
    let store = open()?;
    verify(&guard, &store)?;
    bootstrap(&store)?;
    prepare(&store)?;
    let listener = bind()?;
    ready()?;
    Ok((guard, store, listener))
}

fn worker(
    config: &Config,
    stop: &AtomicBool,
    ready: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    validate(config)?;
    if stop.load(Ordering::Acquire) {
        return Ok(());
    }
    // SCM/control/this worker thread already exist. Native Windows environment
    // setters are thread-safe; this dedicated process has no other SQLite users
    // or environment mutators. Admission is before SQLite/database work, NOT
    // before OS SCM threads. Never restore or mutate TEMP/TMP after admission.
    let startup = startup_with(
        || {
            if process_sid()? == config.server_sid {
                Ok(())
            } else {
                Err("unauthorized")
            }
        },
        || hermes_memory::admit_broker_temp(&config.temp_dir).map_err(|_| "temp_admission_failed"),
        || {
            let store = hermes_memory::MemoryStore::open_broker(&config.root)
                .map_err(|_| "store_admission_failed")?;
            Ok(store)
        },
        |guard, store| {
            guard
                .verify_store(store)
                .map_err(|_| "temp_selection_failed")
        },
        |store| {
            if let Some(path) = &config.bootstrap_config {
                hermes_memory::windows_bootstrap::bootstrap_from_config(store, path).map_err(
                    |error| match error {
                        hermes_memory::windows_bootstrap::BootstrapError::InvalidConfig => {
                            "bootstrap_config_invalid"
                        }
                        hermes_memory::windows_bootstrap::BootstrapError::SourceAdmission => {
                            "bootstrap_source_admission_failed"
                        }
                        hermes_memory::windows_bootstrap::BootstrapError::Import => {
                            "bootstrap_import_failed"
                        }
                    },
                )?;
            }
            Ok(())
        },
        |store| store.prepare_export_index().map_err(|_| "unavailable"),
        || {
            if stop.load(Ordering::Acquire) {
                return Err("startup_cancelled");
            }
            hermes_memory::windows_pipe::bind(&config.pipe, &config.server_sid, &config.client_sid)
                .map_err(|_| "pipe_bind_failed")
        },
        ready,
    );
    // Declaration order keeps the namespace pinned until listener and store drop.
    let (_temp_guard, store, listener) = match startup {
        Err("startup_cancelled") => return Ok(()),
        other => other?,
    };
    let mut listener = listener;
    while !stop.load(Ordering::Acquire) {
        // The primitive fixes the absolute deadline at accept; do not shorten
        // it to a 250ms poll and accidentally leave no budget for an 8MiB frame.
        // An idle accept is bounded by five seconds (+ cancellation grace).
        match listener.accept_authenticated(Instant::now() + Duration::from_secs(5)) {
            Ok(mut stream) => {
                if !stop.load(Ordering::Acquire) {
                    // A connection failure is never retried and never stops the
                    // whole service. The authenticated stream bounds final ACK.
                    let _ = serve_one(&mut stream, &store, &config.workspace);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::PermissionDenied
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                ) => {}
            Err(_) => return Err("pipe_accept_failed"),
        }
        // Bound hostile immediate-failure churn as well as idle accept waits.
        std::thread::sleep(Duration::from_millis(25));
    }
    Ok(())
}
impl PeerStream for hermes_memory::windows_pipe::AuthenticatedStream<'_> {
    fn reauthenticate(&mut self) -> io::Result<()> {
        self.authenticate_peer_again()
    }
}

fn process_sid() -> Result<String, &'static str> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::{Security::*, System::Threading::*};
    let mut raw = std::ptr::null_mut();
    // SAFETY: valid current-process pseudo handle and writable token output.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err("unauthorized");
    }
    // SAFETY: successful OpenProcessToken transfers this nonnull owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut size = 0;
    // SAFETY: sizing call with null zero-size buffer; output size is valid.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut size,
        );
    }
    if size == 0 || size > 65536 {
        return Err("unauthorized");
    }
    let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: aligned storage of the OS-requested size; token remains live.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err("unauthorized");
    }
    // SAFETY: successful TokenUser information contains a valid TOKEN_USER SID
    // backed by buffer; conversion produces LocalAlloc-owned terminated text.
    unsafe {
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut text = std::ptr::null_mut();
        if Authorization::ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
            return Err("unauthorized");
        }
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let result =
            String::from_utf16(std::slice::from_raw_parts(text, len)).map_err(|_| "unauthorized");
        windows_sys::Win32::Foundation::LocalFree(text.cast());
        result
    }
}

#[derive(Clone)]
pub struct Config {
    pub root: PathBuf,
    pub temp_dir: PathBuf,
    pub bootstrap_config: Option<PathBuf>,
    pub pipe: String,
    pub server_sid: String,
    pub client_sid: String,
    pub workspace: String,
    pub service_name: String,
}
fn numeric_sid(s: &str) -> bool {
    let parts: Vec<_> = s.split('-').collect();
    parts.len() >= 4
        && parts.len() <= 18
        && parts[0] == "S"
        && parts[1] == "1"
        && parts[2].parse::<u64>().is_ok_and(|v| v < (1u64 << 48))
        && parts[2..].iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
        && parts[3..].iter().all(|p| p.parse::<u32>().is_ok())
}
fn endpoint(pipe: &str, sid: &str) -> Result<(), &'static str> {
    if !numeric_sid(sid)
        || !pipe
            .strip_prefix(r"\\.\pipe\HermesMemory.")
            .is_some_and(|p| {
                !p.is_empty()
                    && p.len() <= 80
                    && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
    {
        return Err("invalid_request");
    }
    Ok(())
}
fn validate(config: &Config) -> Result<(), &'static str> {
    endpoint(&config.pipe, &config.server_sid)?;
    for path in std::iter::once(&config.temp_dir).chain(config.bootstrap_config.iter()) {
        hermes_memory::windows_enrollment::canonical_profile_key(path)
            .map_err(|_| "invalid_request")?;
    }
    let root = config.root.to_str().ok_or("invalid_request")?;
    if !config.root.is_absolute()
        || root.contains('\0')
        || root.split(['/', '\\']).any(|p| p == "." || p == "..")
        || !config.server_sid.starts_with("S-1-5-80-")
        || config.server_sid.split('-').count() != 9
        || !numeric_sid(&config.client_sid)
        || config.client_sid == config.server_sid
        || config.workspace.trim().is_empty()
        || config.workspace.len() > 256
        || config.workspace.contains(['*', '\0'])
        || config.service_name.is_empty()
        || config.service_name.len() > 80
        || !config
            .service_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("invalid_request");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Duplex {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Duplex {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.input.read(b)
        }
    }
    impl Write for Duplex {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.output.write(b)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn client_correlates_response_then_acknowledges_without_retry() {
        for reply in [
            br#"{"protocol":1,"request_id":"r","ok":true,"result":{}}"#.as_slice(),
            br#"{"protocol":1,"request_id":"other","ok":true,"result":{}}"#,
            br#"{"protocol":2,"request_id":"r","ok":true,"result":{}}"#,
            br#"{"protocol":1,"request_id":"r","ok":false,"result":{}}"#,
            b"truncated",
        ] {
            let mut input = Vec::new();
            write_frame(&mut input, reply).unwrap();
            let mut stream = Duplex {
                input: io::Cursor::new(input),
                ..Default::default()
            };
            let result = exchange(&mut stream, b"request", "r");
            let good = reply == br#"{"protocol":1,"request_id":"r","ok":true,"result":{}}"#;
            assert_eq!(result.is_ok(), good);
            let mut expected = Vec::new();
            write_frame(&mut expected, b"request").unwrap();
            if good {
                expected.extend_from_slice(ACK);
            } else {
                assert_eq!(result.unwrap_err(), "outcome_unknown");
            }
            assert_eq!(stream.output, expected);
        }
    }
    #[test]
    fn server_requires_fixed_ack_before_disconnect() {
        for ack in [ACK.as_slice(), b"wrongACK", b""] {
            let mut stream = Duplex {
                input: io::Cursor::new(ack.to_vec()),
                ..Default::default()
            };
            assert_eq!(
                respond(&mut stream, &failure("r".into(), "unsupported")).is_ok(),
                ack == ACK
            );
            let reply = read_frame(&mut stream.output.as_slice()).unwrap();
            assert_eq!(
                serde_json::from_slice::<Response>(&reply)
                    .unwrap()
                    .request_id,
                "r"
            );
            assert_eq!(stream.input.position() as usize, ack.len());
        }
    }
    impl PeerStream for Duplex {
        fn reauthenticate(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn authenticated_server_reuses_dispatch_and_workspace_gate() {
        let dir = tempfile::tempdir().unwrap();
        let store = hermes_memory::MemoryStore::open(dir.path()).unwrap();
        for (op, body, code) in [
            ("ping", serde_json::json!({}), None),
            ("export", serde_json::json!({}), Some("unsupported")),
            (
                "search",
                serde_json::json!({"query":"x","workspace":"other","limit":1,"max_bytes":4096}),
                Some("unauthorized"),
            ),
        ] {
            let bytes = serde_json::to_vec(
                &serde_json::json!({"protocol":1,"request_id":"r","op":op,"body":body}),
            )
            .unwrap();
            let mut input = Vec::new();
            write_frame(&mut input, &bytes).unwrap();
            input.extend_from_slice(ACK);
            let mut stream = Duplex {
                input: io::Cursor::new(input),
                ..Default::default()
            };
            serve_one(&mut stream, &store, "sandbox").unwrap();
            let reply: serde_json::Value =
                serde_json::from_slice(&read_frame(&mut stream.output.as_slice()).unwrap())
                    .unwrap();
            assert_eq!(reply["ok"], code.is_none());
            if let Some(code) = code {
                assert_eq!(reply["error"]["code"], code);
            } else {
                assert_eq!(reply["result"]["export_supported"], false);
            }
        }
    }
    #[test]
    fn revoked_peer_never_dispatches_even_after_complete_frame() {
        struct Revoked(Duplex, usize);
        impl Read for Revoked {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.0.read(b)
            }
        }
        impl Write for Revoked {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                panic!("unauthorized response")
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl PeerStream for Revoked {
            fn reauthenticate(&mut self) -> io::Result<()> {
                self.1 += 1;
                if self.1 == 1 {
                    Ok(())
                } else {
                    Err(io::ErrorKind::PermissionDenied.into())
                }
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let store = hermes_memory::MemoryStore::open(dir.path()).unwrap();
        let mut input = Vec::new();
        write_frame(
            &mut input,
            br#"{"protocol":1,"request_id":"r","op":"ping","body":{}}"#,
        )
        .unwrap();
        let mut stream = Revoked(
            Duplex {
                input: io::Cursor::new(input),
                ..Default::default()
            },
            0,
        );
        assert_eq!(
            serve_one(&mut stream, &store, "sandbox"),
            Err("unauthorized")
        );
        assert_eq!(stream.1, 2);
    }
    #[test]
    fn stdin_is_bounded_and_validated_before_connect() {
        for (input, code) in [
            (vec![b' '; MAX_FRAME + 1], "resource_limit"),
            (b"invalid".to_vec(), "invalid_request"),
            (
                br#"{"protocol":2,"request_id":"r","op":"ping","body":{}}"#.to_vec(),
                "unsupported_version",
            ),
            (
                br#"{"protocol":1,"request_id":"","op":"ping","body":{}}"#.to_vec(),
                "invalid_request",
            ),
        ] {
            let result =
                request_from::<Duplex>(input.as_slice(), || panic!("connect before validation"));
            match result {
                Err(actual) => assert_eq!(actual, code),
                Ok(response) => assert_eq!(
                    serde_json::to_value(response).unwrap()["error"]["code"],
                    code
                ),
            }
        }
        let mut reply = Vec::new();
        write_frame(
            &mut reply,
            br#"{"protocol":1,"request_id":"r","ok":true,"result":{}}"#,
        )
        .unwrap();
        let response = request_from(
            br#"{"protocol":1,"request_id":"r","op":"ping","body":{}}"#.as_slice(),
            || {
                Ok(Duplex {
                    input: io::Cursor::new(reply),
                    ..Default::default()
                })
            },
        )
        .unwrap();
        assert!(response.ok);
    }
    #[test]
    fn scm_supervisor_reports_running_stop_pending_stopped() {
        let stop = AtomicBool::new(false);
        let mut states = Vec::new();
        let mut n = 0;
        let result = supervise(
            || {
                n += 1;
                match n {
                    1 => Event::Ready,
                    2 => {
                        stop.store(true, Ordering::Release);
                        Event::Tick
                    }
                    _ => Event::Done(Ok(())),
                }
            },
            &stop,
            |state, checkpoint, exit| {
                states.push((state, checkpoint, exit));
                Ok(())
            },
            Duration::from_secs(30),
            Duration::from_secs(15),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(
            states.iter().map(|s| s.0).collect::<Vec<_>>(),
            [
                SERVICE_START_PENDING,
                SERVICE_RUNNING,
                SERVICE_STOP_PENDING,
                SERVICE_STOPPED
            ]
        );
        assert!(states[0].1 > 0);
        assert_eq!(states[1].1, 0);
        assert!(states[2].1 > 0);
        assert_eq!(states[3], (SERVICE_STOPPED, 0, 0));
    }
    #[test]
    fn scm_timeouts_and_status_failures_stop_worker_and_fail_process() {
        let stop = AtomicBool::new(false);
        let mut states = Vec::new();
        let result = supervise(
            || Event::Done(Ok(())),
            &stop,
            |s, _, _| {
                states.push(s);
                Ok(())
            },
            Duration::ZERO,
            Duration::ZERO,
        );
        assert!(result.is_err(), "unexpected worker exit cannot be success");
        let stop = AtomicBool::new(false);
        let mut polls = 0;
        let result = supervise(
            || {
                polls += 1;
                assert!(polls < 4, "unbounded startup");
                Event::Tick
            },
            &stop,
            |_, _, _| Ok(()),
            Duration::ZERO,
            Duration::ZERO,
        );
        assert_eq!(result, Err("service_timeout"));
        assert!(stop.load(Ordering::Acquire));
        let stop = AtomicBool::new(false);
        let mut reports = 0;
        let result = supervise(
            || Event::Done(Ok(())),
            &stop,
            |_, _, _| {
                reports += 1;
                if reports == 1 {
                    Err("scm_status_failed")
                } else {
                    Ok(())
                }
            },
            Duration::from_secs(30),
            Duration::from_secs(15),
        );
        assert_eq!(result, Err("scm_status_failed"));
        assert!(stop.load(Ordering::Acquire));
        assert!(reports >= 2);
    }
    #[test]
    fn service_entry_validates_then_propagates_dispatcher_failure() {
        assert_eq!(
            service_with(config(), |_| Err("scm_dispatcher_failed")),
            Err("scm_dispatcher_failed")
        );
        let mut c = config();
        c.workspace = "*".into();
        assert_eq!(
            service_with(c, |_| panic!("SCM entered for invalid config")),
            Err("invalid_request")
        );
    }
    #[test]
    fn scm_control_is_nonblocking_and_status_is_own_process() {
        let stop = AtomicBool::new(false);
        assert_eq!(control(SERVICE_CONTROL_INTERROGATE, &stop), 0);
        assert!(!stop.load(Ordering::Acquire));
        assert_ne!(control(SERVICE_CONTROL_PAUSE, &stop), 0);
        assert!(!stop.load(Ordering::Acquire));
        assert_eq!(control(SERVICE_CONTROL_STOP, &stop), 0);
        assert!(stop.load(Ordering::Acquire));
        let running = status(SERVICE_RUNNING, 0, 0);
        assert_eq!(running.dwServiceType, SERVICE_WIN32_OWN_PROCESS);
        assert_eq!(
            running.dwControlsAccepted,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        );
        let pending = status(SERVICE_STOP_PENDING, 7, 0);
        assert_eq!(pending.dwControlsAccepted, 0);
        assert_eq!(pending.dwCheckPoint, 7);
        assert!(pending.dwWaitHint >= 1000);
        let failed = status(SERVICE_STOPPED, 0, 1);
        assert_eq!(
            failed.dwWin32ExitCode,
            windows_sys::Win32::Foundation::ERROR_SERVICE_SPECIFIC_ERROR
        );
        assert_eq!(failed.dwServiceSpecificExitCode, 1);
    }
    #[test]
    fn startup_order_stops_at_every_failed_gate() {
        use std::cell::RefCell;
        let names = [
            "token",
            "temp",
            "store",
            "vfscheck",
            "bootstrap",
            "prepareindex",
            "bind",
            "READY",
        ];
        for fail in 0..=8 {
            let seen = RefCell::new(Vec::new());
            let step = |i| {
                seen.borrow_mut().push(names[i]);
                if i == fail {
                    Err("blocked")
                } else {
                    Ok(())
                }
            };
            let result = startup_with(
                || step(0),
                || step(1),
                || step(2),
                |_, _| step(3),
                |_| step(4),
                |_| step(5),
                || step(6),
                || step(7),
            );
            assert_eq!(result.is_ok(), fail == 8);
            assert_eq!(*seen.borrow(), names[..(fail + 1).min(8)]);
        }
    }
    #[test]
    fn failed_native_temp_setup_prevents_sqlite_writes() {
        let dir = tempfile::tempdir().unwrap();
        let result = startup_with(
            || Ok(()),
            || hermes_memory::admit_broker_temp(dir.path()).map_err(|_| "temp_admission_failed"),
            || hermes_memory::MemoryStore::open(dir.path()).map_err(|_| "store"),
            |guard, store| guard.verify_store(store).map_err(|_| "vfs"),
            |_| Ok(()),
            |_| Ok(()),
            || Ok(()),
            || panic!("READY after rejection"),
        );
        assert!(matches!(result, Err("temp_admission_failed")));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    #[test]
    fn startup_paths_require_explicit_strict_absolute_names() {
        let mut c = config();
        c.temp_dir = "relative".into();
        assert!(validate(&c).is_err());
        c = config();
        c.bootstrap_config = Some("C:/admin/../config.json".into());
        assert!(validate(&c).is_err());
    }
    #[test]
    fn worker_stop_before_start_never_opens_store_or_pipe() {
        let stop = AtomicBool::new(true);
        assert_eq!(
            worker(&config(), &stop, || panic!("ready after stop")),
            Ok(())
        );
        let mut c = config();
        c.workspace = "*".into();
        assert_eq!(
            worker(&c, &stop, || panic!("ready invalid config")),
            Err("invalid_request")
        );
    }
    #[test]
    fn same_token_pipe_runs_real_frames_dispatch_and_final_ack() {
        let sid = process_sid().unwrap();
        assert!(numeric_sid(&sid));
        let name = format!(r"\\.\pipe\HermesMemory.runtime-{}", std::process::id());
        let server_name = name.clone();
        let server_sid = sid.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let dir = tempfile::tempdir().unwrap();
            // Portable business-method fixture, NOT service storage admission.
            let store = hermes_memory::MemoryStore::open(dir.path()).unwrap();
            let mut listener =
                hermes_memory::windows_pipe::bind(&server_name, &server_sid, &server_sid).unwrap();
            ready_tx.send(()).unwrap();
            let mut stream = listener
                .accept_authenticated(Instant::now() + Duration::from_secs(5))
                .unwrap();
            serve_one(&mut stream, &store, "sandbox").unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let response = request_from(
            br#"{"protocol":1,"request_id":"real-pipe","op":"ping","body":{}}"#.as_slice(),
            || {
                hermes_memory::windows_pipe::connect_authenticated(
                    &name,
                    &sid,
                    Instant::now() + Duration::from_secs(5),
                )
                .map_err(|_| "unauthorized")
            },
        )
        .unwrap();
        assert!(response.ok);
        assert_eq!(response.request_id, "real-pipe");
        assert_eq!(response.result.unwrap()["export_supported"], false);
        server.join().unwrap();
    }
    #[test]
    fn wrong_pinned_token_is_rejected_before_store_admission() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = config();
        c.root = dir.path().to_owned();
        assert_ne!(process_sid().unwrap(), c.server_sid);
        assert_eq!(
            worker(&c, &AtomicBool::new(false), || panic!(
                "ready with wrong TokenUser"
            )),
            Err("unauthorized")
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    #[test]
    fn scm_ready_after_start_deadline_cannot_report_running() {
        let stop = AtomicBool::new(false);
        let mut states = Vec::new();
        let result = supervise(
            || Event::Ready,
            &stop,
            |s, _, _| {
                states.push(s);
                assert!(states.len() < 4, "startup deadline ignored");
                Ok(())
            },
            Duration::ZERO,
            Duration::ZERO,
        );
        assert_eq!(result, Err("service_timeout"));
        assert!(!states.contains(&SERVICE_RUNNING));
    }
    fn config() -> Config {
        Config {
            root: "C:/sandbox".into(),
            temp_dir: "C:/private-temp".into(),
            bootstrap_config: None,
            pipe: r"\\.\pipe\HermesMemory.test".into(),
            server_sid: "S-1-5-80-1-2-3-4-5".into(),
            client_sid: "S-1-5-21-1-2-3-1001".into(),
            workspace: "sandbox".into(),
            service_name: "HermesMemoryTest".into(),
        }
    }
    #[test]
    fn validates_complete_service_configuration_before_io() {
        assert_eq!(validate(&config()), Ok(()));
        let mut c = config();
        c.workspace = "*".into();
        assert!(validate(&c).is_err());
        let mut c = config();
        c.root = "relative".into();
        assert!(validate(&c).is_err());
        let mut c = config();
        c.root = "C:/sandbox/../escape".into();
        assert!(validate(&c).is_err());
        let mut c = config();
        c.server_sid = "S-1-5-18".into();
        assert!(validate(&c).is_err());
        let mut c = config();
        c.client_sid = c.server_sid.clone();
        assert!(validate(&c).is_err());
        let mut c = config();
        c.client_sid = "S-1-5-21-1;D:(A;;GA;;;WD)".into();
        assert!(validate(&c).is_err());
        let mut c = config();
        c.pipe = r"\\remote\pipe\HermesMemory.test".into();
        assert!(validate(&c).is_err());
        let mut c = config();
        c.service_name = "bad\0name".into();
        assert!(validate(&c).is_err());
    }
}
