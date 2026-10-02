//! Linux adapter. The UID is obtained from the kernel, never the request body.
//! Native tests require the separate-identity CI fixture; portable tests cover
//! the shared framing, authentication gate, dispatch, and absolute deadline.
use super::deadline::{Deadline, TimedIo};
use super::*;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path};
use std::time::{Duration, Instant};
const BUDGET: Duration = Duration::from_secs(5);
impl TimedIo for UnixStream {
    fn timeout(&self, remaining: Duration) -> io::Result<()> {
        self.set_read_timeout(Some(remaining))?;
        self.set_write_timeout(Some(remaining))
    }
}
fn peer_uid(stream: &UnixStream) -> Result<u32, &'static str> {
    // SAFETY: credentials and length are valid writable objects of the exact
    // Linux SO_PEERCRED ABI; the borrowed stream keeps its descriptor alive.
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 || len as usize != std::mem::size_of::<libc::ucred>() {
        return Err("unauthorized");
    }
    Ok(credentials.uid)
}
fn namespace(socket: &Path, service: u32) -> Result<(), &'static str> {
    if !socket.is_absolute()
        || socket
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("invalid_request");
    }
    let parent = socket.parent().ok_or("invalid_request")?;
    for path in parent.ancestors() {
        let m = fs::symlink_metadata(path).map_err(|_| "unauthorized")?;
        if !m.is_dir() || m.file_type().is_symlink() {
            return Err("unauthorized");
        }
        // Sticky root-owned /tmp may be an ancestor, never the socket parent.
        protected_directory(m.uid(), m.mode(), service, path != parent)?;
    }
    Ok(())
}
fn connect(socket: &Path, end: Instant) -> Result<UnixStream, &'static str> {
    let bytes = socket.as_os_str().as_bytes();
    // SAFETY: zero is a valid initial representation for sockaddr_un.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err("invalid_request");
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (to, from) in address.sun_path.iter_mut().zip(bytes) {
        *to = *from as libc::c_char;
    }
    // SAFETY: socket has no pointer arguments. Successful fd is immediately
    // owned and closed on every error path; CLOEXEC prevents inheritance.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err("unavailable");
    }
    // SAFETY: fd is a fresh successful socket descriptor, uniquely owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: address is fully initialized and its complete size is supplied.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if rc != 0 {
        let errno = io::Error::last_os_error().raw_os_error();
        if errno != Some(libc::EINPROGRESS) {
            return Err("unavailable");
        }
        loop {
            let remaining = end
                .checked_duration_since(Instant::now())
                .ok_or("unavailable")?;
            let mut poll = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: poll points to one valid initialized pollfd.
            let rc =
                unsafe { libc::poll(&mut poll, 1, remaining.as_millis().clamp(1, 5000) as i32) };
            if rc < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if rc <= 0 {
                return Err("unavailable");
            }
            let mut error: libc::c_int = 0;
            let mut len = std::mem::size_of_val(&error) as libc::socklen_t;
            // SAFETY: error and len are writable correctly-sized ABI objects.
            let rc = unsafe {
                libc::getsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    (&mut error as *mut libc::c_int).cast(),
                    &mut len,
                )
            };
            if rc != 0 || error != 0 {
                return Err("unavailable");
            }
            break;
        }
    }
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(false).map_err(|_| "unavailable")?;
    Ok(stream)
}
pub fn serve(
    root: &Path,
    socket: &Path,
    allowed_uid: u32,
    workspace: &str,
) -> Result<(), &'static str> {
    // SAFETY: geteuid has no arguments or memory preconditions.
    let uid = unsafe { libc::geteuid() };
    service_identity(uid, allowed_uid)?;
    if workspace.trim().is_empty() || workspace.len() > 256 {
        return Err("invalid_request");
    }
    namespace(socket, uid)?;
    // The service is single-threaded; restrict all newly created files before
    // SQLite opens. Socket permissions are explicitly relaxed only after bind.
    // SAFETY: umask has no memory preconditions; startup is single-threaded.
    unsafe { libc::umask(0o077) };
    match fs::symlink_metadata(socket) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        _ => return Err("unavailable"),
    }
    let store = hermes_memory::MemoryStore::open_broker(root).map_err(|_| "unavailable")?;
    store.prepare_export_index().map_err(|_| "unavailable")?;
    let listener = UnixListener::bind(socket).map_err(|_| "unavailable")?;
    // Never unlink supplied endpoints, including on startup failure or exit.
    fs::set_permissions(socket, fs::Permissions::from_mode(0o666)).map_err(|_| "unavailable")?;
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("unavailable"),
        };
        let end = Instant::now() + BUDGET;
        let peer = match peer_uid(&stream) {
            Ok(uid) => uid,
            Err(_) => continue,
        };
        let mut stream = Deadline { inner: stream, end };
        // Unauthorized connections are dropped without reading even the header.
        if authenticate(peer, allowed_uid).is_err() {
            continue;
        }
        let response = match receive_authenticated(&mut stream, peer, allowed_uid) {
            Ok(bytes) => match protocol::decode(&bytes, workspace) {
                Ok(request) => dispatch(&store, request),
                Err(code) => rejection(&bytes, code),
            },
            Err(code) => failure(String::new(), code),
        };
        if let Ok(bytes) = serde_json::to_vec(&response) {
            let _ = write_frame(&mut stream, &bytes);
        }
    }
    Ok(())
}
pub fn request(socket: &Path, server_uid: u32) -> Result<(), &'static str> {
    // SAFETY: geteuid has no arguments or memory preconditions.
    service_identity(server_uid, unsafe { libc::geteuid() })?;
    namespace(socket, server_uid)?;
    let metadata = fs::symlink_metadata(socket).map_err(|_| "unavailable")?;
    if !metadata.file_type().is_socket() || metadata.uid() != server_uid {
        return Err("unauthorized");
    }
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take((MAX_FRAME + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "invalid_request")?;
    if bytes.len() > MAX_FRAME {
        return Err("resource_limit");
    }
    let request: protocol::Request = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(_) => return emit(&rejection(&bytes, "invalid_request")),
    };
    if request.protocol != 1 {
        return Err("unsupported_version");
    }
    if request.request_id.is_empty() || request.request_id.len() > 128 {
        return Err("invalid_request");
    }
    let end = Instant::now() + BUDGET;
    let socket = connect(socket, end)?;
    let peer = peer_uid(&socket)?;
    let mut socket = Deadline { inner: socket, end };
    send_authenticated(&mut socket, peer, server_uid, &bytes)?;
    // From the first attempted send onward, loss of reply may hide a commit.
    let reply = read_frame(&mut socket).map_err(|_| "outcome_unknown")?;
    let response: Response = serde_json::from_slice(&reply).map_err(|_| "outcome_unknown")?;
    if response.protocol != 1
        || response.request_id != request.request_id
        || (response.ok && (response.result.is_none() || response.error.is_some()))
        || (!response.ok && (response.error.is_none() || response.result.is_some()))
    {
        return Err("outcome_unknown");
    }
    emit(&response)
}
fn emit(response: &Response) -> Result<(), &'static str> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, response).map_err(|_| "outcome_unknown")?;
    stdout.write_all(b"\n").map_err(|_| "outcome_unknown")?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_store_does_not_leave_socket() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = dir.path().join("broker.sock");
        let uid = unsafe { libc::geteuid() };
        assert_ne!(uid, 0, "run as an unprivileged CI user");
        let client = if uid == 61002 { 61003 } else { 61002 };
        assert!(serve(&dir.path().join("missing"), &socket, client, "sandbox").is_err());
        assert!(!socket.exists(), "invalid store left a stale socket");
    }
    #[test]
    fn actual_socket_pair_reports_kernel_peer_uid() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), unsafe { libc::geteuid() });
    }
}
