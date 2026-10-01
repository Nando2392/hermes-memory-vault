//! Disposable SCM-only IPC proof. Unit tests never provision identities or ACLs.
use super::*;
use hermes_memory::{windows_pipe, MemoryRecord, MemoryStore, SearchRequest};
use std::io::{Read, Write};
use windows_sys::Win32::System::{Pipes::*, IO::*};

const MAX_FRAME: usize = 16384;
const ACK: &[u8; 4] = b"ACK1";
const CLIENT_RIGHTS: u32 = 0x120083;
fn budget() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn coordination_budget() -> Instant {
    Instant::now() + Duration::from_secs(25)
}
fn read_frame(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut size = [0; 4];
    reader.read_exact(&mut size)?;
    let size = u32::from_le_bytes(size) as usize;
    ensure(size > 0 && size <= MAX_FRAME, "invalid IPC frame length")?;
    let mut bytes = vec![0; size];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> Result<()> {
    ensure(
        !bytes.is_empty() && bytes.len() <= MAX_FRAME,
        "invalid IPC frame length",
    )?;
    writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
    writer.write_all(bytes)?;
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct Config {
    pub a: String,
    pub b: String,
    pub main: String,
    pub witness: String,
    pub counterfeit: String,
    pub forged: String,
}
impl Config {
    pub fn new(a: &str, b: &str, nonce: &str) -> Self {
        let prefix = format!(r"\\.\pipe\HermesMemory.{}", nonce.replace('_', "-"));
        Self {
            a: a.into(),
            b: b.into(),
            main: format!("{prefix}-main"),
            witness: format!("{prefix}-pin"),
            counterfeit: format!("{prefix}-fake"),
            forged: format!("{prefix}-forged"),
        }
    }
    fn read(root: &Path) -> Result<Self> {
        Ok(serde_json::from_value(read_report(
            root,
            "ipc-config.json",
            coordination_budget(),
        )?)?)
    }
}
fn record() -> MemoryRecord {
    MemoryRecord {
        id: "authenticated-pipe-one".into(),
        session_id: "pipe-session".into(),
        workspace: "sandbox".into(),
        kind: "note".into(),
        content: "quince 日本語 ñ 🔐".into(),
        timestamp: 2.0,
        metadata: json!({"source":"real-distinct-token-pipe","nested":[1,true,"ñ"]}),
    }
}
fn no_thread_token() -> Result<()> {
    let mut token = null_mut();
    // SAFETY: borrowed current thread pseudo handle, initialized output storage.
    unsafe {
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) != 0 {
            drop(handle(token)?);
            return Err("IPC left an impersonation token installed".into());
        }
        ensure(
            GetLastError() == ERROR_NO_TOKEN,
            "thread token query failed",
        )
    }
}

// The raw controls intentionally bypass library admission, but never authorization
// for storage. Every pending IRP is drained before its buffer/OVERLAPPED is freed.
fn drain(pipe: HANDLE, op: &mut OVERLAPPED) {
    // SAFETY: live pipe and pinned operation; cancellation is not completion.
    unsafe {
        CancelIoEx(pipe, op);
        if WaitForSingleObject(op.hEvent, 1000) != WAIT_OBJECT_0 {
            std::process::abort();
        }
        let mut count = 0;
        let ok = GetOverlappedResult(pipe, op, &mut count, 0);
        if ok == 0 && GetLastError() == ERROR_IO_INCOMPLETE {
            std::process::abort();
        }
    }
}
fn completion(pipe: HANDLE, op: &mut OVERLAPPED, deadline: Instant) -> io::Result<u32> {
    let ms = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(5000) as u32;
    // SAFETY: caller keeps operation and event live; waits are bounded, no freeing pending IRP.
    unsafe {
        if WaitForSingleObject(op.hEvent, ms) != WAIT_OBJECT_0 {
            drain(pipe, op);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "raw witness I/O deadline",
            ));
        }
        let mut count = 0;
        if GetOverlappedResult(pipe, op, &mut count, 0) == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_IO_INCOMPLETE as i32) {
                drain(pipe, op);
            }
            return Err(error);
        }
        Ok(count)
    }
}
fn raw_io(pipe: HANDLE, start: impl FnOnce(*mut OVERLAPPED) -> i32) -> Result<u32> {
    // SAFETY: new unnamed manual reset event, uniquely owned by guard.
    let event = handle(unsafe { CreateEventW(null(), 1, 0, null()) })?;
    let mut op = OVERLAPPED {
        hEvent: event.0,
        ..Default::default()
    };
    if start(&mut op) == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            return Err(error.into());
        }
    }
    Ok(completion(pipe, &mut op, budget())?)
}

fn raw_create(name: &str, owner: &str, client: &str, first: bool) -> Result<Handle> {
    let sd = descriptor(&format!("O:{owner}D:P(A;;0x1f01ff;;;{owner})(A;;0x1f01ff;;;SY)(A;;0x1f01ff;;;BA)(A;;0x120083;;;{client})"))
        .map_err(|error| format!("descriptor preparation failed; CreateNamedPipeW not called: {error}"))?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    // SAFETY: public fixture names/SIDs originate only in admin-created config;
    // descriptor lives through syscall. Max 2 permits the second-instance attack
    // to reach the DACL rather than fail solely because a one-instance limit hit.
    handle(unsafe {
        CreateNamedPipeW(
            wide(name).as_ptr(),
            PIPE_ACCESS_DUPLEX
                | FILE_FLAG_OVERLAPPED
                | if first {
                    FILE_FLAG_FIRST_PIPE_INSTANCE
                } else {
                    0
                },
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            2,
            65536,
            65536,
            0,
            &attributes,
        )
    })
}
struct Witness {
    pipe: Handle,
    op: Box<OVERLAPPED>,
    _event: Handle,
    pending: bool,
}
impl Witness {
    fn new(name: &str, owner: &str, client: &str) -> Result<Self> {
        let pipe = raw_create(name, owner, client, true)?;
        // SAFETY: new owned unnamed event. Heap OVERLAPPED address stays fixed.
        let event = handle(unsafe { CreateEventW(null(), 1, 0, null()) })?;
        let mut op = Box::new(OVERLAPPED {
            hEvent: event.0,
            ..Default::default()
        });
        // Arm connect BEFORE publishing readiness; an immediate client close must
        // not be mistaken for absence of a connection or discarded preface bytes.
        let ok = unsafe { ConnectNamedPipe(pipe.0, &mut *op) };
        let error = unsafe { GetLastError() };
        let pending = ok == 0 && error == ERROR_IO_PENDING;
        if ok == 0 && !pending && error != ERROR_PIPE_CONNECTED {
            return Err(io::Error::from_raw_os_error(error as i32).into());
        }
        Ok(Self {
            pipe,
            op,
            _event: event,
            pending,
        })
    }
    fn observe_zero_bytes(&mut self) -> Result<Value> {
        if self.pending {
            let result = completion(self.pipe.0, &mut self.op, budget());
            self.pending = false;
            result?;
        }
        let mut byte = [0];
        // SAFETY: single-byte buffer lives through completion/cancellation drain.
        let result = raw_io(self.pipe.0, |op| unsafe {
            ReadFile(self.pipe.0, byte.as_mut_ptr(), 1, null_mut(), op)
        });
        match result {
            Ok(0) => Ok(json!({"connected":true,"bytes_received":0,"eof":"zero_read"})),
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32)) =>
            {
                Ok(json!({"connected":true,"bytes_received":0,"win32_error":ERROR_BROKEN_PIPE}))
            }
            Ok(count) => {
                Err(format!("server pin failure leaked {count} preface/application bytes").into())
            }
            Err(error) => Err(error),
        }
    }
}
impl Drop for Witness {
    fn drop(&mut self) {
        if self.pending {
            drain(self.pipe.0, &mut self.op);
        }
    }
}

pub(super) struct Server {
    config: Config,
    main: windows_pipe::PipeListener,
    witness: Witness,
}
impl Server {
    pub fn prepare(root: &Path) -> Result<Self> {
        let config = Config::read(root)?;
        let main = windows_pipe::bind(&config.main, &config.a, &config.b)?;
        let witness = Witness::new(&config.witness, &config.a, &config.b)?;
        Ok(Self {
            config,
            main,
            witness,
        })
    }
    pub fn run(&mut self, root: &Path) -> Result<Value> {
        let config = &self.config;
        read_report(root, "ipc-admin-go.json", coordination_budget())?;
        let mut dispatches = 0u32;
        let denial = match self.main.accept_authenticated(budget()) {
            Ok(_) => {
                return Err(
                    "unauthorized admin received authenticated stream; trust falsified".into(),
                )
            }
            Err(error) => error,
        };
        ensure(
            denial.kind() == io::ErrorKind::PermissionDenied
                && denial.to_string() == "client TokenUser mismatch",
            &format!("wrong rejection reason: {denial}"),
        )?;
        no_thread_token()?;
        let admin = json!({"rejected":true,"reason":denial.to_string(),"storage_dispatches":dispatches,"thread_token_absent":true});
        write_report(&root.join("result-a"), "ipc-admin.json", &admin)?;
        read_report(root, "ipc-client-go.json", coordination_budget())?;
        let mut stream = self.main.accept_authenticated(budget())?;
        let bytes = read_frame(&mut stream)?;
        let received: MemoryRecord = serde_json::from_slice(&bytes)?;
        ensure(
            serde_json::to_value(&received)? == serde_json::to_value(record())?,
            "authenticated request fields mismatch",
        )?;
        stream.authenticate_peer_again()?;
        no_thread_token()?;
        // Storage is reached ONLY through a returned authenticated stream and
        // successful per-frame reauthentication. Admin control has already failed.
        dispatches += 1;
        let store = MemoryStore::open_broker(root.join("broker-store"))?;
        ensure(
            store.ingest(&received)?,
            "IPC record unexpectedly duplicated",
        )?;
        let hits = store.search(&SearchRequest {
            query: "quince".into(),
            workspace: Some("sandbox".into()),
            session_id: Some("pipe-session".into()),
            limit: 10,
            max_bytes: MAX_FRAME,
        })?;
        ensure(hits.len() == 1, "IPC search result missing/duplicated")?;
        let response = serde_json::to_vec(&hits[0])?;
        ensure(
            serde_json::from_slice::<Value>(&response)? == serde_json::to_value(&received)?,
            "IPC stored roundtrip changed fields",
        )?;
        write_frame(&mut stream, &response)?;
        let mut ack = [0; 4];
        stream.read_exact(&mut ack)?;
        ensure(&ack == ACK, "missing final client response ACK")?;
        // Disconnect only AFTER the client has read the complete response.
        drop(stream);
        drop(store);
        no_thread_token()?;
        let wrong_pin = self.witness.observe_zero_bytes()?;
        let receipt = json!({"admin":admin,"allowed_client_sid":config.b,"server_sid":config.a,"storage_dispatches":dispatches,"unicode_roundtrip":true,"request_bytes":bytes.len(),"response_bytes":response.len(),"ack_before_disconnect":true,"thread_token_absent":true,"wrong_server_pin":wrong_pin,"remote_policy":{"creation_flag":PIPE_REJECT_REMOTE_CLIENTS,"local_connections_exercised":true,"remote_network_test":"NOT_PERFORMED"}});
        write_report(&root.join("result-a"), "ipc.json", &receipt)?;
        Ok(receipt)
    }
}

pub(super) fn admin_attempt(root: &Path, config: &Config) -> Result<Value> {
    write_report(root, "ipc-admin-go.json", &json!({"start":true}))?;
    // SAFETY: intentionally adversarial client bypasses the library's descriptor
    // check; Identification SQOS allows server-side TokenUser denial to be tested.
    let client = handle(unsafe {
        CreateFileW(
            wide(&config.main).as_ptr(),
            CLIENT_RIGHTS,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED
                | SECURITY_SQOS_PRESENT
                | SECURITY_IDENTIFICATION
                | SECURITY_EFFECTIVE_ONLY,
            null_mut(),
        )
    })?;
    let request = b"HMPIPE01UNAUTHORIZED-STORAGE-REQUEST";
    let count = raw_io(client.0, |op| unsafe {
        WriteFile(
            client.0,
            request.as_ptr(),
            request.len() as u32,
            null_mut(),
            op,
        )
    })?;
    ensure(
        count as usize == request.len(),
        "admin control write was incomplete",
    )?;
    let receipt = read_report(
        &root.join("result-a"),
        "ipc-admin.json",
        coordination_budget(),
    )?;
    ensure(
        receipt["rejected"] == true && receipt["storage_dispatches"] == 0,
        "unauthorized storage dispatch",
    )?;
    drop(client);
    Ok(json!({"request_bytes_written":count,"server":receipt}))
}

fn denial_code(result: Result<Handle>) -> Result<u32> {
    match result {
        Ok(created) => {
            drop(created);
            Ok(0)
        }
        Err(error) => error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error)
            .map(|code| code as u32)
            .ok_or_else(|| format!("control failed without raw OS evidence: {error}").into()),
    }
}
fn pin_rejection(name: &str, pin: &str) -> Result<Value> {
    match windows_pipe::connect_authenticated(name, pin, budget()) {
        Ok(_) => Err("counterfeit/wrong-pin server authenticated; trust falsified".into()),
        Err(error) => {
            ensure(
                error.kind() == io::ErrorKind::PermissionDenied
                    && error.to_string() == "pipe owner is not pinned service SID",
                &format!("wrong pin control failed for wrong reason: {error}"),
            )?;
            Ok(json!({"rejected":true,"kind":"PermissionDenied","reason":error.to_string()}))
        }
    }
}
pub(super) fn client(root: &Path) -> Result<Value> {
    let config = Config::read(root)?;
    // Raw CreateNamedPipeW rather than bind(): this MUST exercise Windows owner
    // assignment, not merely the library's process-user precheck.
    let forged = denial_code(raw_create(&config.forged, &config.a, &config.b, true))?;
    write_report(
        &root.join("result-b"),
        "ipc-owner-attempt.json",
        &json!({"requested_owner":config.a,"actual_creator":config.b,"win32_error":forged,"succeeded":forged == 0}),
    )?;
    ensure(
        policy::pipe_owner_denied(forged),
        &format!("owner-A forgery trust falsified or inconclusive: raw Win32 {forged}"),
    )?;
    // No FIRST_PIPE_INSTANCE on attack and matching max_instances=2: the owner-A
    // witness has a free second slot, so ERROR_ACCESS_DENIED tests create rights.
    let second = denial_code(raw_create(&config.witness, &config.b, &config.b, false))?;
    ensure(
        second == ERROR_ACCESS_DENIED,
        &format!("second-instance DACL denial missing: raw Win32 {second}"),
    )?;
    let mut fake = Witness::new(&config.counterfeit, &config.b, &config.b)?;
    // Positive syscall control: identical second-instance flags/limit work when
    // the same caller actually owns the pipe. Close only that new second slot.
    drop(raw_create(
        &config.counterfeit,
        &config.b,
        &config.b,
        false,
    )?);
    let fake_pin = pin_rejection(&config.counterfeit, &config.a)?;
    let fake_bytes = fake.observe_zero_bytes()?;
    write_report(
        &root.join("result-b"),
        "ipc-client-ready.json",
        &json!({"controls_completed":true,"owner_forgery_error":forged,"second_instance_error":second}),
    )?;
    // Parent releases both endpoints only after SCM startup and B's negative
    // controls finish; they do not consume the library's five-second I/O budget.
    read_report(root, "ipc-client-go.json", coordination_budget())?;
    let mut stream = windows_pipe::connect_authenticated(&config.main, &config.a, budget())?;
    let sent = serde_json::to_vec(&record())?;
    write_frame(&mut stream, &sent)?;
    let response = read_frame(&mut stream)?;
    ensure(
        serde_json::from_slice::<Value>(&response)? == serde_json::to_value(record())?,
        "client full-field Unicode response mismatch",
    )?;
    stream.write_all(ACK)?;
    drop(stream);
    let wrong_pin = pin_rejection(&config.witness, &config.b)?;
    no_thread_token()?;
    Ok(
        json!({"owner_forgery":{"win32_error":forged,"succeeded":false},"second_instance":{"win32_error":second,"max_instances":2,"first_instance_flag_on_attack":false,"own_B_positive_control":true},"counterfeit":{"client":fake_pin,"server":fake_bytes},"wrong_server_pin":wrong_pin,"unicode_roundtrip":true,"response_ack_sent":true,"response_bytes":response.len(),"thread_token_absent":true}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_witness_detects_even_one_leaked_byte_after_client_close() {
        // Only our new evidence collector is exercised here, not another copy of
        // the library's same-token handshake test. No SCM or filesystem ACL use.
        let sid = identity().unwrap()["user"].as_str().unwrap().to_owned();
        for leak in [false, true] {
            let name = format!(
                r"\\.\pipe\HermesMemory.witness-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                u8::from(leak)
            );
            let mut witness = Witness::new(&name, &sid, &sid).unwrap();
            drop(raw_create(&name, &sid, &sid, false).unwrap());
            // SAFETY: a unique test-owned local pipe and a single owned handle.
            let client = handle(unsafe {
                CreateFileW(
                    wide(&name).as_ptr(),
                    CLIENT_RIGHTS,
                    0,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    null_mut(),
                )
            })
            .unwrap();
            if leak {
                let byte = [b'H'];
                // SAFETY: byte remains live until helper proves I/O completion.
                assert_eq!(
                    raw_io(client.0, |op| unsafe {
                        WriteFile(client.0, byte.as_ptr(), 1, null_mut(), op)
                    })
                    .unwrap(),
                    1
                );
            }
            drop(client);
            let evidence = witness.observe_zero_bytes();
            if leak {
                assert!(evidence.unwrap_err().to_string().contains("leaked 1"));
            } else {
                assert_eq!(evidence.unwrap()["bytes_received"], 0);
            }
        }
    }

    #[test]
    fn raw_witness_drop_cancels_a_never_connected_operation() {
        let sid = identity().unwrap()["user"].as_str().unwrap().to_owned();
        let name = format!(
            r"\\.\pipe\HermesMemory.cancel-witness-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let start = Instant::now();
        drop(Witness::new(&name, &sid, &sid).unwrap());
        assert!(start.elapsed() < Duration::from_secs(2));
        // Drop really released the first-instance handle, not just its buffers.
        drop(Witness::new(&name, &sid, &sid).unwrap());
    }

    #[test]
    fn framing_rejects_unbounded_lengths_without_reading_body() {
        let mut input = std::io::Cursor::new(u32::MAX.to_le_bytes());
        assert!(read_frame(&mut input).is_err());
        assert_eq!(input.position(), 4);
    }
    #[test]
    fn framing_preserves_unicode_and_does_not_consume_ack() {
        let body = "quince 日本語 ñ 🔐".as_bytes();
        let mut input = Vec::from((body.len() as u32).to_le_bytes());
        input.extend_from_slice(body);
        input.extend_from_slice(b"ACK1");
        let mut input = std::io::Cursor::new(input);
        assert_eq!(read_frame(&mut input).unwrap(), body);
        let mut ack = [0; 4];
        input.read_exact(&mut ack).unwrap();
        assert_eq!(&ack, b"ACK1");
    }
}
