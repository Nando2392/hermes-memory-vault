//! Experimental handle-authenticated local Windows named pipes.

fn valid_name(name: &str) -> bool {
    name.strip_prefix(r"\\.\pipe\HermesMemory.")
        .is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= 80
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn ace_sid_bytes(ace: &[u8]) -> Option<&[u8]> {
    let sid = ace.get(8..)?;
    if sid.len() < 8 || sid[0] != 1 || sid[1] > 15 || sid.len() != 8 + 4 * sid[1] as usize {
        return None;
    }
    Some(sid)
}

const CLIENT_RIGHTS: u32 =
    FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
const SERVER_RIGHTS: u32 = FILE_ALL_ACCESS;
fn allowed_ace(
    sid: &[u8],
    mask: u32,
    service: &[u8],
    client: &[u8],
    system: &[u8],
    admins: &[u8],
) -> bool {
    (mask == SERVER_RIGHTS && [service, system, admins].contains(&sid))
        || (mask == CLIENT_RIGHTS && sid == client)
}

use std::io::{self, Read, Write};
use std::time::Instant;

use std::ffi::c_void;
use std::marker::PhantomData;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::time::Duration;
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Pipes::*, Threading::*, IO::*},
};

const PREFACE: &[u8; 8] = b"HMPIPE01";
const MAX_BUDGET: Duration = Duration::from_secs(5);
// Cancellation is not completion. If the kernel cannot drain within this grace,
// fail-stop rather than free buffers still referenced by an outstanding IRP.
const CANCEL_GRACE_MS: u32 = 1000;

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn bool_result(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn own_handle(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: caller passes a newly allocated owned Win32 handle, checked above.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: these pointers originate only in LocalAlloc-backed Win32 APIs.
        unsafe {
            LocalFree(self.0);
        }
    }
}

#[derive(Clone)]
struct Sid(Vec<u8>);
impl Sid {
    fn parse(text: &str) -> io::Result<Self> {
        // Also prevents SDDL injection when building the initial descriptor.
        if !text.starts_with("S-1-")
            || text.len() > 184
            || !text[2..].bytes().all(|b| b.is_ascii_digit() || b == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected numeric SID",
            ));
        }
        let mut raw = null_mut();
        // SAFETY: terminated UTF-16 input and writable output; allocation is owned.
        unsafe {
            bool_result(ConvertStringSidToSidW(wide(text).as_ptr(), &mut raw))?;
            let _allocation = Local(raw);
            Self::copy_raw(raw)
        }
    }
    // SAFETY: raw must point at an OS-validated SID in a live allocation.
    unsafe fn copy_raw(raw: PSID) -> io::Result<Self> {
        if raw.is_null() || IsValidSid(raw) == 0 {
            return Err(denied("invalid SID"));
        }
        Ok(Self(
            std::slice::from_raw_parts(raw.cast::<u8>(), GetLengthSid(raw) as usize).to_vec(),
        ))
    }
}

fn token_data(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<usize>> {
    let mut size = 0;
    // SAFETY: live token, probing size with a null zero-length buffer.
    unsafe {
        GetTokenInformation(token, class, null_mut(), 0, &mut size);
    }
    if size == 0 || size > 65536 {
        return Err(io::Error::last_os_error());
    }
    let mut data = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: usize allocation provides TOKEN_USER alignment and requested capacity.
    unsafe {
        bool_result(GetTokenInformation(
            token,
            class,
            data.as_mut_ptr().cast(),
            size,
            &mut size,
        ))?;
    }
    Ok(data)
}
fn token_user(token: HANDLE) -> io::Result<Sid> {
    let data = token_data(token, TokenUser)?;
    if std::mem::size_of_val(data.as_slice()) < std::mem::size_of::<TOKEN_USER>() {
        return Err(denied("short token user"));
    }
    // SAFETY: successful kernel TokenUser query into aligned allocation, still live.
    unsafe { Sid::copy_raw((*(data.as_ptr().cast::<TOKEN_USER>())).User.Sid) }
}
fn process_user() -> io::Result<Sid> {
    let mut token = null_mut();
    // SAFETY: pseudo process handle valid; output token is uniquely owned.
    unsafe {
        bool_result(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token,
        ))?;
    }
    token_user(own_handle(token)?.as_raw_handle())
}
fn no_thread_token() -> io::Result<()> {
    let mut token = null_mut();
    // SAFETY: current thread pseudo handle and valid output pointer.
    unsafe {
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) != 0 {
            drop(own_handle(token)?);
            return Err(denied("caller is already impersonating"));
        }
        if GetLastError() != ERROR_NO_TOKEN {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

// Non-Send/Sync, never escapes this synchronous stack or an OS thread.
struct RevertGuard {
    active: bool,
    _thread: PhantomData<Rc<()>>,
}
impl RevertGuard {
    fn finish(&mut self) {
        if self.active {
            // SAFETY: only constructed immediately following successful impersonation.
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
            self.active = false;
            if no_thread_token().is_err() {
                std::process::abort();
            }
        }
    }
}
impl Drop for RevertGuard {
    fn drop(&mut self) {
        self.finish();
    }
}
fn authenticate_client(pipe: HANDLE, expected: &Sid) -> io::Result<()> {
    no_thread_token()?;
    // SAFETY: live server pipe; checked result before any token inspection.
    unsafe {
        bool_result(ImpersonateNamedPipeClient(pipe))?;
    }
    let mut guard = RevertGuard {
        active: true,
        _thread: PhantomData,
    };
    let result = (|| {
        let mut token = null_mut();
        // SAFETY: same OS thread as impersonation; no fallback to process token.
        unsafe {
            bool_result(OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY,
                1,
                &mut token,
            ))?;
        }
        let token = own_handle(token)?;
        let kind = token_data(token.as_raw_handle(), TokenType)?;
        let level = token_data(token.as_raw_handle(), TokenImpersonationLevel)?;
        // SAFETY: successful fixed-size i32 token queries into aligned live allocations.
        if unsafe { *kind.as_ptr().cast::<i32>() } != TokenImpersonation
            || unsafe { *level.as_ptr().cast::<i32>() } != SecurityIdentification
        {
            return Err(denied("Identification-level client token required"));
        }
        if token_user(token.as_raw_handle())?.0 != expected.0 {
            return Err(denied("client TokenUser mismatch"));
        }
        Ok(())
    })();
    guard.finish();
    result
}

fn validate_security(pipe: HANDLE, service: &Sid, client: &Sid) -> io::Result<()> {
    let (mut owner, mut acl, mut descriptor) = (null_mut(), null_mut(), null_mut());
    // SAFETY: live connected pipe handle, writable outputs; descriptor owns pointers.
    let status = unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _descriptor = Local(descriptor);
    let system = Sid::parse("S-1-5-18")?;
    let admins = Sid::parse("S-1-5-32-544")?;
    // SAFETY: GetSecurityInfo supplies OS-validated descriptor pointers which remain
    // allocated for this scope. GetAce and IsValidAcl bound ACE traversal.
    unsafe {
        if Sid::copy_raw(owner)?.0 != service.0 {
            return Err(denied("pipe owner is not pinned service SID"));
        }
        if acl.is_null() || IsValidAcl(acl) == 0 || (*acl).AceCount != 4 {
            return Err(denied("pipe requires exact four-ACE DACL"));
        }
        let (mut control, mut revision) = (0, 0);
        bool_result(GetSecurityDescriptorControl(
            descriptor,
            &mut control,
            &mut revision,
        ))?;
        if control & SE_DACL_PROTECTED == 0 {
            return Err(denied("pipe DACL must be protected"));
        }
        let expected = [
            (&service.0, SERVER_RIGHTS),
            (&system.0, SERVER_RIGHTS),
            (&admins.0, SERVER_RIGHTS),
            (&client.0, CLIENT_RIGHTS),
        ];
        let mut seen = [false; 4];
        for i in 0..4 {
            let mut raw = null_mut();
            bool_result(GetAce(acl, i, &mut raw))?;
            let header = &*raw.cast::<ACE_HEADER>();
            // ACCESS_ALLOWED_ACE_TYPE = 0; no inherited/object/callback/deny ACEs.
            if header.AceType != 0 || header.AceFlags != 0 || header.AceSize < 16 {
                return Err(denied("unexpected ACE kind"));
            }
            let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
            let bytes = std::slice::from_raw_parts(raw.cast::<u8>(), header.AceSize as usize);
            let sid = ace_sid_bytes(bytes).ok_or_else(|| denied("invalid bounded ACE SID"))?;
            if !allowed_ace(sid, ace.Mask, &service.0, &client.0, &system.0, &admins.0) {
                return Err(denied("unexpected pipe ACE rights"));
            }
            let slot = expected
                .iter()
                .enumerate()
                .position(|(index, (s, m))| !seen[index] && s.as_slice() == sid && *m == ace.Mask)
                .ok_or_else(|| denied("duplicate pipe ACE"))?;
            seen[slot] = true;
        }
    }
    Ok(())
}

fn remaining_ms(deadline: Instant) -> io::Result<u32> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
    Ok(left
        .as_millis()
        .saturating_add(1)
        .min((u32::MAX - 1) as u128) as u32)
}
fn bounded(deadline: Instant) -> Instant {
    deadline.min(Instant::now() + MAX_BUDGET)
}

// All operations are serialized. The OVERLAPPED, event and caller's buffer remain
// at stable addresses until completion is observed, including on timeout/error.
fn overlapped(
    pipe: HANDLE,
    deadline: Instant,
    start: impl FnOnce(*mut OVERLAPPED) -> i32,
    connect: bool,
) -> io::Result<usize> {
    remaining_ms(deadline)?;
    // SAFETY: unnamed noninheritable manual-reset event with no external users.
    let event = own_handle(unsafe { CreateEventW(null(), 1, 0, null()) })?;
    let mut operation = OVERLAPPED {
        hEvent: event.as_raw_handle(),
        ..Default::default()
    };
    let success = start(&mut operation);
    // SAFETY: capture last error immediately after submitting the I/O operation.
    let error = if success == 0 {
        unsafe { GetLastError() }
    } else {
        ERROR_SUCCESS
    };
    if connect && error == ERROR_PIPE_CONNECTED {
        return Ok(0);
    }
    if success == 0 && error != ERROR_IO_PENDING {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    let wait = remaining_ms(deadline);
    // SAFETY: live event and stable OVERLAPPED; wait is finite.
    let ready = match wait {
        Ok(ms) => unsafe { WaitForSingleObject(event.as_raw_handle(), ms) == WAIT_OBJECT_0 },
        Err(_) => false,
    };
    let mut transferred = 0;
    if ready {
        // SAFETY: event reports completion; output count is valid writable memory.
        if unsafe { GetOverlappedResult(pipe, &operation, &mut transferred, 0) } != 0 {
            remaining_ms(deadline)?;
            return Ok(transferred as usize);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_IO_INCOMPLETE as i32) {
            return Err(error);
        }
    }
    // SAFETY: cancel exactly this operation, then drain before any local or caller
    // storage can be released. ERROR_NOT_FOUND is a normal completion race.
    unsafe {
        let cancelled = CancelIoEx(pipe, &operation);
        let cancel_error = if cancelled == 0 {
            GetLastError()
        } else {
            ERROR_SUCCESS
        };
        if cancel_error != ERROR_SUCCESS && cancel_error != ERROR_NOT_FOUND {
            std::process::abort();
        }
        if WaitForSingleObject(event.as_raw_handle(), CANCEL_GRACE_MS) != WAIT_OBJECT_0 {
            std::process::abort();
        }
        if GetOverlappedResult(pipe, &operation, &mut transferred, 0) == 0
            && GetLastError() == ERROR_IO_INCOMPLETE
        {
            std::process::abort();
        }
    }
    Err(io::ErrorKind::TimedOut.into())
}

/// Retains the one FIRST_PIPE_INSTANCE handle across serial clients.
/// This primitive permits same-SID test controls; the deployment layer MUST pin
/// a distinct dedicated service TokenUser and an unprivileged client identity.
pub struct PipeListener {
    handle: OwnedHandle,
    client: Sid,
}
enum Endpoint<'a> {
    Server(&'a mut PipeListener),
    Client(OwnedHandle),
}
/// Authenticated connection with a fixed, at-most-five-second absolute budget.
/// No raw handle access, cloning, buffering, or deadline extension is exposed.
/// Errors must cause the caller to drop the connection, never retry a request.
/// Before dropping the server stream after a response, the application protocol
/// must read a final client acknowledgment under this same deadline: disconnect
/// discards unread pipe bytes. `flush` is not an acknowledgment and never calls
/// the unbounded Windows `FlushFileBuffers` API. No application framing is added.
pub struct AuthenticatedStream<'a> {
    endpoint: Endpoint<'a>,
    deadline: Instant,
    failed: bool,
}

/// Create the local endpoint with its final protected owner and exact DACL.
/// Numeric SID strings only; names must match `\\\\.\\pipe\\HermesMemory.<id>`.
pub fn bind(name: &str, service_sid: &str, client_sid: &str) -> io::Result<PipeListener> {
    if !valid_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid local pipe namespace",
        ));
    }
    no_thread_token()?;
    let service = Sid::parse(service_sid)?;
    let client = Sid::parse(client_sid)?;
    if process_user()?.0 != service.0 {
        return Err(denied("service must run as pinned TokenUser"));
    }
    let sddl = wide(&format!("O:{service_sid}D:P(A;;0x{SERVER_RIGHTS:x};;;{service_sid})(A;;0x{SERVER_RIGHTS:x};;;SY)(A;;0x{SERVER_RIGHTS:x};;;BA)(A;;0x{CLIENT_RIGHTS:x};;;{client_sid})"));
    let mut sd = null_mut();
    // SAFETY: validated numeric SID interpolation, terminated input, owned output.
    unsafe {
        bool_result(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut sd,
            null_mut(),
        ))?;
    }
    let _sd = Local(sd);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    // SAFETY: name and explicit SD live through creation; no inheritance or gap.
    let handle = own_handle(unsafe {
        CreateNamedPipeW(
            wide(name).as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            0,
            &attributes,
        )
    })
    .map_err(|e| io::Error::new(e.kind(), format!("CreateNamedPipeW: {e}")))?;
    validate_security(handle.as_raw_handle(), &service, &client)
        .map_err(|e| io::Error::new(e.kind(), format!("server GetSecurityInfo/policy: {e}")))?;
    Ok(PipeListener { handle, client })
}
impl PipeListener {
    /// Read only the public preface, inspect Identification TokenUser, and revert
    /// before returning. Authentication errors disconnect but retain the instance.
    pub fn accept_authenticated(
        &mut self,
        deadline: Instant,
    ) -> io::Result<AuthenticatedStream<'_>> {
        no_thread_token()?;
        let deadline = bounded(deadline);
        let handle = self.handle.as_raw_handle();
        // Construct the disconnect guard before any connection/authentication path.
        let mut stream = AuthenticatedStream {
            endpoint: Endpoint::Server(self),
            deadline,
            failed: false,
        };
        // SAFETY: live server handle; overlapped helper retains operation until done.
        overlapped(
            handle,
            deadline,
            |op| unsafe { ConnectNamedPipe(handle, op) },
            true,
        )?;
        let mut preface = [0; 8];
        // Read implementation reauthenticates every completed chunk before exposing it.
        stream.read_exact(&mut preface)?;
        if &preface != PREFACE {
            return Err(denied("invalid public pipe preface"));
        }
        stream.authenticate_peer_again()?;
        Ok(stream)
    }
}

/// Open only the fixed local namespace. Authenticate owner/creator ACL on this
/// connected handle BEFORE sending even the public preface. No PID authorization.
pub fn connect_authenticated(
    name: &str,
    expected_service_sid: &str,
    deadline: Instant,
) -> io::Result<AuthenticatedStream<'static>> {
    if !valid_name(name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid local pipe namespace",
        ));
    }
    no_thread_token()?;
    let deadline = bounded(deadline);
    let service = Sid::parse(expected_service_sid)?;
    let client = process_user()?;
    let name = wide(name);
    let handle = loop {
        remaining_ms(deadline)?;
        // SAFETY: fixed local name, exact rights exclude CREATE_PIPE_INSTANCE;
        // static Identification SQOS, no inheritable attributes.
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
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
        };
        if raw != INVALID_HANDLE_VALUE {
            break own_handle(raw)?;
        }
        let error = io::Error::last_os_error();
        if !matches!(error.raw_os_error(), Some(e) if e == ERROR_PIPE_BUSY as i32 || e == ERROR_FILE_NOT_FOUND as i32)
        {
            return Err(error);
        }
        std::thread::sleep(Duration::from_millis(remaining_ms(deadline)?.min(5) as u64));
    };
    validate_security(handle.as_raw_handle(), &service, &client)?;
    let mut stream = AuthenticatedStream {
        endpoint: Endpoint::Client(handle),
        deadline,
        failed: false,
    };
    stream.write_all(PREFACE)?;
    Ok(stream)
}
impl AuthenticatedStream<'_> {
    fn handle(&self) -> HANDLE {
        match &self.endpoint {
            Endpoint::Server(s) => s.handle.as_raw_handle(),
            Endpoint::Client(h) => h.as_raw_handle(),
        }
    }
    fn usable(&self) -> io::Result<()> {
        if self.failed {
            return Err(denied("connection previously failed"));
        }
        remaining_ms(self.deadline).map(|_| ())
    }
    /// Server-side last-read context check, including checked reversion. Read also
    /// does this automatically on every chunk, preventing unauthenticated bytes
    /// from being returned even if a hostile client uses dynamic security tracking.
    pub fn authenticate_peer_again(&mut self) -> io::Result<()> {
        self.usable()?;
        let result = match &self.endpoint {
            Endpoint::Server(s) => authenticate_client(s.handle.as_raw_handle(), &s.client)
                .and_then(|()| remaining_ms(self.deadline).map(|_| ())),
            Endpoint::Client(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "server-side authentication only",
            )),
        };
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}
impl Read for AuthenticatedStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.usable()?;
        if buf.is_empty() {
            return Ok(0);
        }
        let handle = self.handle();
        let len = buf.len().min(u32::MAX as usize) as u32;
        // SAFETY: buffer exclusively borrowed and lives through completed/cancelled IRP.
        let result = overlapped(
            handle,
            self.deadline,
            |op| unsafe { ReadFile(handle, buf.as_mut_ptr(), len, null_mut(), op) },
            false,
        );
        if result.is_err() {
            self.failed = true;
        }
        let count = result?;
        if count > 0 && matches!(self.endpoint, Endpoint::Server(_)) {
            if let Err(error) = self.authenticate_peer_again() {
                buf[..count].fill(0);
                return Err(error);
            }
        }
        Ok(count)
    }
}
impl Write for AuthenticatedStream<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.usable()?;
        if buf.is_empty() {
            return Ok(0);
        }
        let handle = self.handle();
        let len = buf.len().min(u32::MAX as usize) as u32;
        // SAFETY: immutable borrowed buffer lives until completion or cancellation drain.
        let result = overlapped(
            handle,
            self.deadline,
            |op| unsafe { WriteFile(handle, buf.as_ptr(), len, null_mut(), op) },
            false,
        );
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    // No user-space buffering. FlushFileBuffers would block on a hostile reader.
    fn flush(&mut self) -> io::Result<()> {
        self.usable()
    }
}
impl Drop for AuthenticatedStream<'_> {
    fn drop(&mut self) {
        if let Endpoint::Server(server) = &self.endpoint {
            // SAFETY: every operation drained synchronously before drop; keep the
            // first instance handle alive. A disconnected/unconnected pipe is fine.
            unsafe {
                DisconnectNamedPipe(server.handle.as_raw_handle());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn own_sid_text() -> String {
        let output = std::process::Command::new("whoami.exe")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .expect("whoami");
        assert!(output.status.success());
        String::from_utf8(output.stdout)
            .unwrap()
            .split('"')
            .find(|s| s.starts_with("S-1-"))
            .unwrap()
            .to_owned()
    }
    #[test]
    fn same_token_roundtrip_and_retained_listener() {
        let sid = own_sid_text();
        let name = format!(r"\\.\pipe\HermesMemory.local-test-{}", std::process::id());
        let mut listener = bind(&name, &sid, &sid).expect("create owned scratch pipe");
        assert!(bind(&name, &sid, &sid).is_err());
        for _ in 0..2 {
            std::thread::scope(|scope| {
                let peer = scope.spawn(|| {
                    let mut client = connect_authenticated(
                        &name,
                        &sid,
                        Instant::now() + std::time::Duration::from_secs(3),
                    )
                    .unwrap();
                    client.write_all(b"ping").unwrap();
                    let mut response = [0; 4];
                    client.read_exact(&mut response).unwrap();
                    assert_eq!(&response, b"pong");
                    client.write_all(b"done").unwrap();
                });
                let mut server = listener
                    .accept_authenticated(Instant::now() + std::time::Duration::from_secs(3))
                    .unwrap();
                let mut request = [0; 4];
                server.read_exact(&mut request).unwrap();
                assert_eq!(&request, b"ping");
                server.write_all(b"pong").unwrap();
                server.read_exact(&mut request).unwrap();
                assert_eq!(&request, b"done");
                peer.join().unwrap();
            });
        }
    }

    #[test]
    fn cancellation_drains_connect_read_and_write() {
        let sid = own_sid_text();
        let name = format!(r"\\.\pipe\HermesMemory.cancel-test-{}", std::process::id());
        let mut listener = bind(&name, &sid, &sid).unwrap();
        for _ in 0..3 {
            let started = Instant::now();
            let error = listener
                .accept_authenticated(started + Duration::from_millis(30))
                .err()
                .expect("connect must time out");
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(started.elapsed() < Duration::from_secs(1));
        }
        for write in [false, true] {
            std::thread::scope(|scope| {
                let (ready_tx, ready_rx) = std::sync::mpsc::channel();
                let (done_tx, done_rx) = std::sync::mpsc::channel();
                let (name, sid) = (&name, &sid);
                let peer = scope.spawn(move || {
                    let _client =
                        connect_authenticated(name, sid, Instant::now() + Duration::from_secs(2))
                            .unwrap();
                    ready_tx.send(()).unwrap();
                    done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                });
                let started = Instant::now();
                let mut server = listener
                    .accept_authenticated(started + Duration::from_millis(100))
                    .unwrap();
                ready_rx.recv_timeout(Duration::from_secs(1)).unwrap();
                let error = if write {
                    server.write_all(&vec![42; 2 * 1024 * 1024]).unwrap_err()
                } else {
                    server.read_exact(&mut [0; 1]).unwrap_err()
                };
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                assert!(started.elapsed() < Duration::from_secs(1));
                assert!(server.write(b"must-not-retry").is_err());
                done_tx.send(()).unwrap();
                peer.join().unwrap();
            });
        }
    }

    #[test]
    fn wrong_server_owner_rejected_before_preface() {
        let sid = own_sid_text();
        let name = format!(r"\\.\pipe\HermesMemory.owner-test-{}", std::process::id());
        let listener = bind(&name, &sid, &sid).unwrap();
        std::thread::scope(|scope| {
            let peer = scope.spawn(|| {
                let error = connect_authenticated(
                    &name,
                    "S-1-5-18",
                    Instant::now() + Duration::from_secs(1),
                )
                .err()
                .expect("wrong owner rejected");
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            });
            let h = listener.handle.as_raw_handle();
            let deadline = Instant::now() + Duration::from_secs(1);
            // SAFETY: test-owned first instance and stable overlapped helper.
            overlapped(h, deadline, |op| unsafe { ConnectNamedPipe(h, op) }, true).unwrap();
            let mut byte = [0];
            // SAFETY: buffer remains live through completed/drained read.
            let result = overlapped(
                h,
                deadline,
                |op| unsafe { ReadFile(h, byte.as_mut_ptr(), 1, null_mut(), op) },
                false,
            );
            assert!(
                matches!(result, Ok(0))
                    || result
                        .as_ref()
                        .err()
                        .is_some_and(|e| e.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32))
            );
            peer.join().unwrap();
        });
    }

    #[test]
    fn wrong_client_token_rejected_and_reverted() {
        let sid = own_sid_text();
        let name = format!(r"\\.\pipe\HermesMemory.token-test-{}", std::process::id());
        let mut listener = bind(&name, &sid, &sid).unwrap();
        // Keep the real admission DACL, vary only the pinned post-read identity.
        listener.client = Sid::parse("S-1-5-18").unwrap();
        std::thread::scope(|scope| {
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let (name, sid) = (&name, &sid);
            let peer = scope.spawn(move || {
                let _client =
                    connect_authenticated(name, sid, Instant::now() + Duration::from_secs(1))
                        .unwrap();
                done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            });
            let error = listener
                .accept_authenticated(Instant::now() + Duration::from_secs(1))
                .err()
                .expect("wrong TokenUser must reject");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            no_thread_token().unwrap();
            done_tx.send(()).unwrap();
            peer.join().unwrap();
        });
    }

    #[test]
    fn anonymous_or_wrong_preface_never_returns_stream() {
        let sid = own_sid_text();
        for (suffix, sqos, preface) in [
            ("anonymous", SECURITY_ANONYMOUS, *PREFACE),
            ("preface", SECURITY_IDENTIFICATION, *b"BADMAGIC"),
            ("impersonation", SECURITY_IMPERSONATION, *PREFACE),
        ] {
            let name = format!(
                r"\\.\pipe\HermesMemory.reject-{suffix}-{}",
                std::process::id()
            );
            let mut listener = bind(&name, &sid, &sid).unwrap();
            std::thread::scope(|scope| {
                let (done_tx, done_rx) = std::sync::mpsc::channel();
                let name = &name;
                let peer = scope.spawn(move || {
                    // SAFETY: test-owned fixed namespace; real same-token client,
                    // intentionally selecting rejected SQOS for this negative test.
                    let handle = own_handle(unsafe {
                        CreateFileW(
                            wide(name).as_ptr(),
                            CLIENT_RIGHTS,
                            0,
                            null(),
                            OPEN_EXISTING,
                            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | sqos,
                            null_mut(),
                        )
                    })
                    .unwrap();
                    let h = handle.as_raw_handle();
                    // SAFETY: stable public fixed buffer, completion drained by helper.
                    overlapped(
                        h,
                        Instant::now() + Duration::from_secs(1),
                        |op| unsafe { WriteFile(h, preface.as_ptr(), 8, null_mut(), op) },
                        false,
                    )
                    .unwrap();
                    done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                });
                assert!(listener
                    .accept_authenticated(Instant::now() + Duration::from_secs(1))
                    .is_err());
                no_thread_token().unwrap();
                done_tx.send(()).unwrap();
                peer.join().unwrap();
            });
        }
    }

    #[test]
    fn ace_sid_copy_is_bounded_by_ace_not_untrusted_subauthority_count() {
        let mut ace = [0; 20];
        ace[8] = 1;
        ace[9] = 1;
        assert_eq!(ace_sid_bytes(&ace), Some(&ace[8..]));
        ace[9] = 15;
        assert!(ace_sid_bytes(&ace).is_none());
        ace[9] = 1;
        ace[8] = 2;
        assert!(ace_sid_bytes(&ace).is_none());
        assert!(ace_sid_bytes(&ace[..7]).is_none());
        assert!(ace_sid_bytes(&ace[..16]).is_none());
    }

    #[test]
    fn exact_rights_reject_creator_and_owner_escalation() {
        let (s, c, y, a) = (
            &b"service"[..],
            &b"client"[..],
            &b"system"[..],
            &b"admins"[..],
        );
        assert!(allowed_ace(c, 0x120083, s, c, y, a));
        assert!(allowed_ace(s, 0x1f01ff, s, c, y, a));
        for mask in [0x120087, 0x160083, 0x1a0083, 0x40000000, 0x120089, 0x1f01ff] {
            assert!(!allowed_ace(c, mask, s, c, y, a));
        }
        assert!(!allowed_ace(b"everyone", 0x120083, s, c, y, a));
    }
    #[test]
    fn namespace_is_local_fixed_and_bounded() {
        assert!(valid_name(r"\\.\pipe\HermesMemory.test-42"));
        for bad in [
            r"\\remote\pipe\HermesMemory.x",
            r"\\.\pipe\other",
            r"\\.\pipe\HermesMemory.",
            r"\\.\pipe\HermesMemory.a\b",
            "\\\\.\\pipe\\HermesMemory.x\0",
        ] {
            assert!(!valid_name(bad));
        }
        assert!(!valid_name(&format!(
            r"\\.\pipe\HermesMemory.{}",
            "a".repeat(81)
        )));
    }
}
