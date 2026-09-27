//! Linux SQLite VFS that never resolves persistent files through ambient paths.
//!
//! The VFS is process-global, but each database name contains an unguessable-in-process
//! registry token. The registry holds only a weak reference after `xOpen` consumes the
//! caller's prevalidated database descriptor, and the final `xClose` removes the entry.
//! All persistent opens are relative to an owned `cap_std::fs::Dir` and use no-follow.

use cap_fs_ext::OpenOptionsFollowExt as _;
use cap_primitives::fs::{FollowSymlinks, MetadataExt as _};
use cap_std::fs::{Dir, File as CapFile, OpenOptions as CapOpenOptions};
use rusqlite::{ffi, Connection, OpenFlags};
use std::collections::HashMap;
use std::ffi::CStr;
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd, RawFd};
use std::os::raw::{c_char, c_int, c_void};
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock, Weak};

const VFS_NAME: &str = "hermes-cap-linux-v1";
const VFS_NAME_C: &[u8] = b"hermes-cap-linux-v1\0";
const MAIN_NAME: &str = "memory.db";
const WAL_NAME: &str = "memory.db-wal";
const SHM_NAME: &str = "memory.db-shm";
const JOURNAL_NAME: &str = "memory.db-journal";

const PENDING_BYTE: libc::off_t = 0x4000_0000;
const RESERVED_BYTE: libc::off_t = PENDING_BYTE + 1;
const SHARED_FIRST: libc::off_t = PENDING_BYTE + 2;
const SHARED_SIZE: libc::off_t = 510;
const SHM_LOCK_BASE: libc::off_t = 120;
const SHM_LOCK_COUNT: c_int = 8;
const SHM_DMS: libc::off_t = 128;

const NO_LOCK: c_int = 0;
const SHARED_LOCK: c_int = 1;
const RESERVED_LOCK: c_int = 2;
const PENDING_LOCK: c_int = 3;
const EXCLUSIVE_LOCK: c_int = 4;

static REGISTER: Once = Once::new();
static REGISTER_RESULT: AtomicI32 = AtomicI32::new(ffi::SQLITE_ERROR);
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);
static REGISTRY: OnceLock<Mutex<HashMap<String, RegistryEntry>>> = OnceLock::new();

enum RegistryEntry {
    Pending(Arc<Context>),
    Live(Weak<Context>),
}

struct Context {
    token: String,
    root: Dir,
    main: Mutex<Option<CapFile>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileKind {
    Main,
    Wal,
    Journal,
}

impl FileKind {
    fn name(self) -> &'static str {
        match self {
            Self::Main => MAIN_NAME,
            Self::Wal => WAL_NAME,
            Self::Journal => JOURNAL_NAME,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    dev: u64,
    ino: u64,
}

#[repr(C)]
struct VfsFile {
    base: ffi::sqlite3_file,
    state: MaybeUninit<FileState>,
}

struct FileState {
    context: Arc<Context>,
    file: std::fs::File,
    kind: FileKind,
    lock_level: c_int,
    shm: Option<Shm>,
}

struct Mapping {
    address: *mut c_void,
    length: usize,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: each Mapping is created by a successful mmap and is dropped once.
        unsafe {
            libc::munmap(self.address, self.length);
        }
    }
}

struct Shm {
    file: std::fs::File,
    identity: Identity,
    page_size: usize,
    mappings: Vec<Option<Mapping>>,
    shared_mask: u16,
    exclusive_mask: u16,
}

impl Context {
    fn open_nofollow(&self, name: &str, create: bool) -> io::Result<CapFile> {
        if !is_allowed_name(name) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SQLite requested a non-allowlisted persistent file",
            ));
        }
        let mut options = CapOpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(create)
            .follow(FollowSymlinks::No);
        let file = self.root.open_with(name, &options)?;
        validate_regular_single_link(&file)?;
        Ok(file)
    }

    fn consume_main(&self) -> io::Result<CapFile> {
        let main = self
            .main
            .lock()
            .map_err(|_| io::Error::other("SQLite VFS main-file lock poisoned"))?
            .take()
            .ok_or_else(|| io::Error::other("SQLite opened the main database twice"))?;
        validate_regular_single_link(&main)?;

        // This is the consumer-boundary check. The namespace entry is opened no-follow
        // after the test hook/attacker had an opportunity to replace it, and SQLite gets
        // the already validated descriptor rather than the path-opened descriptor.
        let current = self.open_nofollow(MAIN_NAME, false)?;
        if identity(&main)? != identity(&current)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "main database namespace entry changed before SQLite consumed it",
            ));
        }
        Ok(main)
    }

    fn validate_live(&self, name: &str, file: &std::fs::File) -> io::Result<()> {
        validate_std_regular_single_link(file)?;
        let current = self.open_nofollow(name, false)?;
        if identity_std(file)? != identity(&current)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SQLite persistent namespace entry was replaced",
            ));
        }
        Ok(())
    }

    fn remove_if_identity(&self, name: &str, expected: Identity, sync_dir: bool) -> io::Result<()> {
        match self.open_nofollow(name, false) {
            Ok(current) => {
                if identity(&current)? != expected {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "refusing to delete a replaced SQLite file",
                    ));
                }
                drop(current);
                #[cfg(test)]
                tests::before_unlink();
                match self.root.remove_file(name) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
                if sync_dir {
                    self.root.try_clone()?.into_std_file().sync_all()?;
                }
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Opens `database` through a descriptor-only Linux VFS scoped to `root`.
///
/// `database` must already be a no-follow, single-link, read/write handle for
/// `root/memory.db`. The handle is cloned here and consumed exactly once by xOpen.
pub(super) fn open(root: &Dir, database: &CapFile) -> Result<Connection, crate::MemoryError> {
    ensure_registered()?;
    validate_regular_single_link(database)?;

    let sequence = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
    let token = format!("{:x}-{:x}", std::process::id(), sequence);
    let context = Arc::new(Context {
        token: token.clone(),
        root: root.try_clone()?,
        main: Mutex::new(Some(database.try_clone()?)),
    });
    registry_lock()?.insert(token.clone(), RegistryEntry::Pending(context));

    let logical_name = format!("hermes-{token}/{MAIN_NAME}");
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let opened = Connection::open_with_flags_and_vfs(Path::new(&logical_name), flags, VFS_NAME);
    let connection = match opened {
        Ok(connection) => connection,
        Err(error) => {
            remove_registry_token(&token);
            return Err(error.into());
        }
    };

    // Named temporary files are intentionally unsupported by this VFS. This makes
    // SQLite keep sorter/temp-table storage in memory instead of asking xOpen for an
    // ambient or attacker-selected filename.
    if let Err(error) = connection.execute_batch("PRAGMA temp_store=MEMORY;") {
        drop(connection);
        remove_registry_token(&token);
        return Err(error.into());
    }
    Ok(connection)
}

fn ensure_registered() -> io::Result<()> {
    REGISTER.call_once(|| {
        let vfs = Box::new(ffi::sqlite3_vfs {
            iVersion: 3,
            szOsFile: mem::size_of::<VfsFile>() as c_int,
            mxPathname: 128,
            pNext: ptr::null_mut(),
            zName: VFS_NAME_C.as_ptr().cast(),
            pAppData: ptr::null_mut(),
            xOpen: Some(vfs_open),
            xDelete: Some(vfs_delete),
            xAccess: Some(vfs_access),
            xFullPathname: Some(vfs_full_pathname),
            xDlOpen: None,
            xDlError: None,
            xDlSym: None,
            xDlClose: None,
            xRandomness: Some(vfs_randomness),
            xSleep: Some(vfs_sleep),
            xCurrentTime: Some(vfs_current_time),
            xGetLastError: Some(vfs_last_error),
            xCurrentTimeInt64: Some(vfs_current_time_i64),
            xSetSystemCall: None,
            xGetSystemCall: None,
            xNextSystemCall: None,
        });
        // The registration is process-lifetime by SQLite contract. Only this one fixed
        // VFS object is leaked; per-store roots live in the weak registry described above.
        let raw = Box::into_raw(vfs);
        // SAFETY: `raw` remains valid for the process lifetime and registration is once-only.
        let result = unsafe { ffi::sqlite3_vfs_register(raw, 0) };
        REGISTER_RESULT.store(result, Ordering::Release);
    });
    let result = REGISTER_RESULT.load(Ordering::Acquire);
    if result == ffi::SQLITE_OK {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "sqlite3_vfs_register failed with code {result}"
        )))
    }
}

fn registry() -> &'static Mutex<HashMap<String, RegistryEntry>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn registry_lock() -> io::Result<std::sync::MutexGuard<'static, HashMap<String, RegistryEntry>>> {
    registry()
        .lock()
        .map_err(|_| io::Error::other("SQLite VFS registry poisoned"))
}

fn acquire_context(token: &str) -> io::Result<Arc<Context>> {
    let mut entries = registry_lock()?;
    let entry = entries.get_mut(token).ok_or_else(|| {
        io::Error::new(io::ErrorKind::PermissionDenied, "unknown SQLite VFS token")
    })?;
    match entry {
        RegistryEntry::Pending(context) => {
            let context = Arc::clone(context);
            *entry = RegistryEntry::Live(Arc::downgrade(&context));
            Ok(context)
        }
        RegistryEntry::Live(context) => context
            .upgrade()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "expired SQLite VFS token")),
    }
}

fn remove_registry_token(token: &str) {
    if let Ok(mut entries) = registry().lock() {
        entries.remove(token);
    }
}

fn parse_name(pointer: *const c_char) -> io::Result<(String, FileKind)> {
    if pointer.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "named SQLite temporary files are disabled",
        ));
    }
    // SAFETY: SQLite promises that VFS filename arguments point to NUL-terminated strings.
    let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes();
    let text = std::str::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 SQLite filename"))?;
    let rest = text.strip_prefix("hermes-").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid SQLite VFS namespace",
        )
    })?;
    let (token, basename) = rest.split_once('/').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid SQLite VFS filename",
        )
    })?;
    if token.is_empty() || token.contains('/') || basename.contains('/') {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid SQLite VFS filename components",
        ));
    }
    let kind = match basename {
        MAIN_NAME => FileKind::Main,
        WAL_NAME => FileKind::Wal,
        JOURNAL_NAME => FileKind::Journal,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "non-allowlisted SQLite filename",
            ))
        }
    };
    Ok((token.to_owned(), kind))
}

fn parse_any_name(pointer: *const c_char) -> io::Result<(String, &'static str)> {
    if pointer.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "null SQLite filename",
        ));
    }
    // SAFETY: SQLite promises a NUL-terminated filename.
    let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes();
    let text = std::str::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 SQLite filename"))?;
    let rest = text.strip_prefix("hermes-").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid SQLite VFS namespace",
        )
    })?;
    let (token, basename) = rest.split_once('/').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid SQLite VFS filename",
        )
    })?;
    if token.is_empty()
        || token.contains('/')
        || basename.contains('/')
        || !is_allowed_name(basename)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "non-allowlisted SQLite filename",
        ));
    }
    let stable = match basename {
        MAIN_NAME => MAIN_NAME,
        WAL_NAME => WAL_NAME,
        SHM_NAME => SHM_NAME,
        JOURNAL_NAME => JOURNAL_NAME,
        _ => unreachable!("allowlist and stable-name match must agree"),
    };
    Ok((token.to_owned(), stable))
}

fn is_allowed_name(name: &str) -> bool {
    matches!(name, MAIN_NAME | WAL_NAME | SHM_NAME | JOURNAL_NAME)
}

fn validate_regular_single_link(file: &CapFile) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SQLite file is not a single-link regular file",
        ));
    }
    Ok(())
}

fn validate_std_regular_single_link(file: &std::fs::File) -> io::Result<()> {
    let metadata = file.metadata()?;
    use std::os::unix::fs::MetadataExt as _;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SQLite file is not a single-link regular file",
        ));
    }
    Ok(())
}

fn identity(file: &CapFile) -> io::Result<Identity> {
    let metadata = file.metadata()?;
    Ok(Identity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

fn identity_std(file: &std::fs::File) -> io::Result<Identity> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = file.metadata()?;
    Ok(Identity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

fn io_error_code(error: &io::Error, operation: c_int) -> c_int {
    match error.kind() {
        io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput => ffi::SQLITE_PERM,
        io::ErrorKind::NotFound => ffi::SQLITE_CANTOPEN,
        io::ErrorKind::OutOfMemory => ffi::SQLITE_NOMEM,
        _ => operation,
    }
}

fn with_ffi_result(function: impl FnOnce() -> c_int) -> c_int {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(function)).unwrap_or(ffi::SQLITE_IOERR)
}

unsafe extern "C" fn vfs_open(
    _vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    output: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    with_ffi_result(|| {
        if output.is_null() {
            return ffi::SQLITE_MISUSE;
        }
        let (token, kind) = match parse_name(name) {
            Ok(parsed) => parsed,
            Err(error) => return io_error_code(&error, ffi::SQLITE_CANTOPEN),
        };
        let expected_flag = match kind {
            FileKind::Main => ffi::SQLITE_OPEN_MAIN_DB,
            FileKind::Wal => ffi::SQLITE_OPEN_WAL,
            FileKind::Journal => ffi::SQLITE_OPEN_MAIN_JOURNAL,
        };
        if flags & expected_flag == 0 || flags & ffi::SQLITE_OPEN_READONLY != 0 {
            return ffi::SQLITE_CANTOPEN;
        }
        let context = match acquire_context(&token) {
            Ok(context) => context,
            Err(error) => return io_error_code(&error, ffi::SQLITE_CANTOPEN),
        };
        let file = match kind {
            FileKind::Main => context.consume_main(),
            FileKind::Wal | FileKind::Journal => context.open_nofollow(kind.name(), true),
        };
        let file = match file {
            Ok(file) => file.into_std(),
            Err(error) => return io_error_code(&error, ffi::SQLITE_CANTOPEN),
        };
        let state = FileState {
            context,
            file,
            kind,
            lock_level: NO_LOCK,
            shm: None,
        };
        let file_output = output.cast::<VfsFile>();
        // SAFETY: SQLite allocated szOsFile bytes with suitable alignment. xOpen owns the
        // uninitialized tail until it publishes pMethods, and xClose drops it exactly once.
        unsafe {
            ptr::write(
                ptr::addr_of_mut!((*file_output).state),
                MaybeUninit::new(state),
            );
            (*file_output).base.pMethods = &IO_METHODS;
            if !out_flags.is_null() {
                *out_flags = flags;
            }
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn vfs_delete(
    _vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    sync_dir: c_int,
) -> c_int {
    with_ffi_result(|| {
        let (token, basename) = match parse_any_name(name) {
            Ok(parsed) => parsed,
            Err(error) => return io_error_code(&error, ffi::SQLITE_IOERR_DELETE),
        };
        let context = match acquire_context(&token) {
            Ok(context) => context,
            Err(error) => return io_error_code(&error, ffi::SQLITE_IOERR_DELETE),
        };
        let current = match context.open_nofollow(basename, false) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return ffi::SQLITE_OK,
            Err(error) => return io_error_code(&error, ffi::SQLITE_IOERR_DELETE),
        };
        let expected = match identity(&current) {
            Ok(identity) => identity,
            Err(error) => return io_error_code(&error, ffi::SQLITE_IOERR_DELETE),
        };
        drop(current);
        match context.remove_if_identity(basename, expected, sync_dir != 0) {
            Ok(()) => ffi::SQLITE_OK,
            Err(error) => io_error_code(&error, ffi::SQLITE_IOERR_DELETE),
        }
    })
}

unsafe extern "C" fn vfs_access(
    _vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    _flags: c_int,
    result: *mut c_int,
) -> c_int {
    with_ffi_result(|| {
        if result.is_null() {
            return ffi::SQLITE_MISUSE;
        }
        let (token, basename) = match parse_any_name(name) {
            Ok(parsed) => parsed,
            Err(error) => return io_error_code(&error, ffi::SQLITE_IOERR_ACCESS),
        };
        let context = match acquire_context(&token) {
            Ok(context) => context,
            Err(error) => return io_error_code(&error, ffi::SQLITE_IOERR_ACCESS),
        };
        let exists = match context.open_nofollow(basename, false) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return io_error_code(&error, ffi::SQLITE_IOERR_ACCESS),
        };
        // SAFETY: SQLite supplied a writable result pointer.
        unsafe { *result = c_int::from(exists) };
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn vfs_full_pathname(
    _vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    output_len: c_int,
    output: *mut c_char,
) -> c_int {
    with_ffi_result(|| {
        if name.is_null() || output.is_null() || output_len <= 0 {
            return ffi::SQLITE_CANTOPEN;
        }
        // Validate before reflecting the logical capability name. No ambient canonicalization
        // is performed or permitted.
        if parse_any_name(name).is_err() {
            return ffi::SQLITE_CANTOPEN;
        }
        // SAFETY: name is a SQLite C string and output advertises output_len writable bytes.
        let bytes = unsafe { CStr::from_ptr(name) }.to_bytes_with_nul();
        if bytes.len() > output_len as usize {
            return ffi::SQLITE_CANTOPEN;
        }
        // SAFETY: the non-overlapping destination was checked for sufficient length.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), output.cast(), bytes.len()) };
        ffi::SQLITE_OK
    })
}

unsafe fn state_mut<'a>(file: *mut ffi::sqlite3_file) -> &'a mut FileState {
    // SAFETY: all io callbacks are invoked only after xOpen published IO_METHODS.
    unsafe { &mut *(*file.cast::<VfsFile>()).state.as_mut_ptr() }
}

unsafe extern "C" fn file_close(file: *mut ffi::sqlite3_file) -> c_int {
    with_ffi_result(|| {
        if file.is_null() {
            return ffi::SQLITE_MISUSE;
        }
        // Stop SQLite from dispatching through a partially closed object first.
        // SAFETY: file points to the VfsFile initialized by xOpen.
        unsafe { (*file).pMethods = ptr::null() };
        // SAFETY: xClose is called exactly once for an xOpen-successful object.
        let state = unsafe { ptr::read((*file.cast::<VfsFile>()).state.as_ptr()) };
        let token = state.context.token.clone();
        let context = Arc::clone(&state.context);
        drop(state);
        if Arc::strong_count(&context) == 1 {
            remove_registry_token(&token);
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn file_read(
    file: *mut ffi::sqlite3_file,
    buffer: *mut c_void,
    amount: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    with_ffi_result(|| {
        if file.is_null() || buffer.is_null() || amount < 0 || offset < 0 {
            return ffi::SQLITE_IOERR_READ;
        }
        // SAFETY: callback object and output buffer are supplied by SQLite.
        let state = unsafe { state_mut(file) };
        let mut done = 0usize;
        while done < amount as usize {
            // SAFETY: buffer has amount writable bytes and arithmetic stays within it.
            let result = unsafe {
                libc::pread(
                    state.file.as_raw_fd(),
                    buffer.cast::<u8>().add(done).cast(),
                    amount as usize - done,
                    offset as libc::off_t + done as libc::off_t,
                )
            };
            if result > 0 {
                done += result as usize;
            } else if result == 0 {
                // SQLite requires unread bytes to be zeroed on short read.
                // SAFETY: done..amount is the checked remainder of SQLite's buffer.
                unsafe {
                    ptr::write_bytes(buffer.cast::<u8>().add(done), 0, amount as usize - done)
                };
                return ffi::SQLITE_IOERR_SHORT_READ;
            } else if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return ffi::SQLITE_IOERR_READ;
            }
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn file_write(
    file: *mut ffi::sqlite3_file,
    buffer: *const c_void,
    amount: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    with_ffi_result(|| {
        if file.is_null() || buffer.is_null() || amount < 0 || offset < 0 {
            return ffi::SQLITE_IOERR_WRITE;
        }
        // SAFETY: callback object is initialized and buffer is valid for amount bytes.
        let state = unsafe { state_mut(file) };
        if state
            .context
            .validate_live(state.kind.name(), &state.file)
            .is_err()
        {
            return ffi::SQLITE_IOERR_WRITE;
        }
        let mut done = 0usize;
        while done < amount as usize {
            // SAFETY: buffer arithmetic remains inside SQLite's amount-byte input.
            let result = unsafe {
                libc::pwrite(
                    state.file.as_raw_fd(),
                    buffer.cast::<u8>().add(done).cast(),
                    amount as usize - done,
                    offset as libc::off_t + done as libc::off_t,
                )
            };
            if result > 0 {
                done += result as usize;
            } else if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
            {
                continue;
            } else {
                return ffi::SQLITE_IOERR_WRITE;
            }
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn file_truncate(
    file: *mut ffi::sqlite3_file,
    size: ffi::sqlite3_int64,
) -> c_int {
    with_ffi_result(|| {
        if file.is_null() || size < 0 {
            return ffi::SQLITE_IOERR_TRUNCATE;
        }
        // SAFETY: file is an initialized callback object.
        let state = unsafe { state_mut(file) };
        if state
            .context
            .validate_live(state.kind.name(), &state.file)
            .is_err()
        {
            return ffi::SQLITE_IOERR_TRUNCATE;
        }
        // SAFETY: ftruncate operates on the owned descriptor.
        if unsafe { libc::ftruncate(state.file.as_raw_fd(), size as libc::off_t) } == 0 {
            ffi::SQLITE_OK
        } else {
            ffi::SQLITE_IOERR_TRUNCATE
        }
    })
}

unsafe extern "C" fn file_sync(file: *mut ffi::sqlite3_file, flags: c_int) -> c_int {
    with_ffi_result(|| {
        if file.is_null() {
            return ffi::SQLITE_IOERR_FSYNC;
        }
        // SAFETY: file is initialized.
        let state = unsafe { state_mut(file) };
        if state
            .context
            .validate_live(state.kind.name(), &state.file)
            .is_err()
        {
            return ffi::SQLITE_IOERR_FSYNC;
        }
        let result = if flags & ffi::SQLITE_SYNC_DATAONLY != 0 {
            // SAFETY: fd is owned and live.
            unsafe { libc::fdatasync(state.file.as_raw_fd()) }
        } else {
            // SAFETY: fd is owned and live.
            unsafe { libc::fsync(state.file.as_raw_fd()) }
        };
        if result == 0 {
            ffi::SQLITE_OK
        } else {
            ffi::SQLITE_IOERR_FSYNC
        }
    })
}

unsafe extern "C" fn file_size(
    file: *mut ffi::sqlite3_file,
    output: *mut ffi::sqlite3_int64,
) -> c_int {
    with_ffi_result(|| {
        if file.is_null() || output.is_null() {
            return ffi::SQLITE_IOERR_FSTAT;
        }
        // SAFETY: callback object and output pointer are valid by SQLite's VFS contract.
        let state = unsafe { state_mut(file) };
        match state.file.metadata() {
            Ok(metadata) => {
                unsafe { *output = metadata.len() as ffi::sqlite3_int64 };
                ffi::SQLITE_OK
            }
            Err(_) => ffi::SQLITE_IOERR_FSTAT,
        }
    })
}

fn ofd_lock(
    fd: RawFd,
    lock_type: libc::c_short,
    start: libc::off_t,
    len: libc::off_t,
) -> io::Result<()> {
    let mut lock: libc::flock = unsafe { mem::zeroed() };
    lock.l_type = lock_type;
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    lock.l_start = start;
    lock.l_len = len;
    // SAFETY: flock points to a fully initialized structure for this fcntl command.
    if unsafe { libc::fcntl(fd, libc::F_OFD_SETLK, &lock) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn ofd_conflicting_lock(
    fd: RawFd,
    lock_type: libc::c_short,
    start: libc::off_t,
    len: libc::off_t,
) -> io::Result<libc::c_short> {
    let mut lock: libc::flock = unsafe { mem::zeroed() };
    lock.l_type = lock_type;
    lock.l_whence = libc::SEEK_SET as libc::c_short;
    lock.l_start = start;
    lock.l_len = len;
    // SAFETY: kernel reads and writes the initialized flock structure.
    if unsafe { libc::fcntl(fd, libc::F_OFD_GETLK, &mut lock) } == 0 {
        Ok(lock.l_type)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn lock_result(error: io::Error, io_code: c_int) -> c_int {
    match error.raw_os_error() {
        Some(libc::EACCES | libc::EAGAIN) => ffi::SQLITE_BUSY,
        _ => io_code,
    }
}

unsafe extern "C" fn file_lock(file: *mut ffi::sqlite3_file, requested: c_int) -> c_int {
    with_ffi_result(|| {
        if file.is_null() || !(SHARED_LOCK..=EXCLUSIVE_LOCK).contains(&requested) {
            return ffi::SQLITE_IOERR_LOCK;
        }
        // SAFETY: initialized callback object.
        let state = unsafe { state_mut(file) };
        if state.kind != FileKind::Main
            || state.context.validate_live(MAIN_NAME, &state.file).is_err()
        {
            return ffi::SQLITE_IOERR_LOCK;
        }
        if state.lock_level >= requested {
            return ffi::SQLITE_OK;
        }
        let fd = state.file.as_raw_fd();
        let result = match requested {
            SHARED_LOCK => {
                let pending = ofd_lock(fd, libc::F_RDLCK as _, PENDING_BYTE, 1);
                if let Err(error) = pending {
                    Err(error)
                } else {
                    let shared = ofd_lock(fd, libc::F_RDLCK as _, SHARED_FIRST, SHARED_SIZE);
                    let release = ofd_lock(fd, libc::F_UNLCK as _, PENDING_BYTE, 1);
                    shared.and(release)
                }
            }
            RESERVED_LOCK if state.lock_level == SHARED_LOCK => {
                ofd_lock(fd, libc::F_WRLCK as _, RESERVED_BYTE, 1)
            }
            EXCLUSIVE_LOCK if state.lock_level >= SHARED_LOCK => {
                if state.lock_level == RESERVED_LOCK {
                    if let Err(error) = ofd_lock(fd, libc::F_WRLCK as _, PENDING_BYTE, 1) {
                        return lock_result(error, ffi::SQLITE_IOERR_LOCK);
                    }
                    state.lock_level = PENDING_LOCK;
                }
                ofd_lock(fd, libc::F_WRLCK as _, SHARED_FIRST, SHARED_SIZE)
            }
            _ => return ffi::SQLITE_IOERR_LOCK,
        };
        match result {
            Ok(()) => {
                state.lock_level = requested;
                ffi::SQLITE_OK
            }
            Err(error) => lock_result(error, ffi::SQLITE_IOERR_LOCK),
        }
    })
}

unsafe extern "C" fn file_unlock(file: *mut ffi::sqlite3_file, requested: c_int) -> c_int {
    with_ffi_result(|| {
        if file.is_null() || !(NO_LOCK..=SHARED_LOCK).contains(&requested) {
            return ffi::SQLITE_IOERR_UNLOCK;
        }
        // SAFETY: initialized callback object.
        let state = unsafe { state_mut(file) };
        if state.kind != FileKind::Main || state.lock_level <= requested {
            return ffi::SQLITE_OK;
        }
        let fd = state.file.as_raw_fd();
        let result = if requested == SHARED_LOCK {
            ofd_lock(fd, libc::F_RDLCK as _, SHARED_FIRST, SHARED_SIZE)
                .and_then(|_| ofd_lock(fd, libc::F_UNLCK as _, PENDING_BYTE, 2))
        } else {
            ofd_lock(fd, libc::F_UNLCK as _, 0, 0)
        };
        match result {
            Ok(()) => {
                state.lock_level = requested;
                ffi::SQLITE_OK
            }
            Err(_) => ffi::SQLITE_IOERR_UNLOCK,
        }
    })
}

unsafe extern "C" fn file_check_reserved(
    file: *mut ffi::sqlite3_file,
    output: *mut c_int,
) -> c_int {
    with_ffi_result(|| {
        if file.is_null() || output.is_null() {
            return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
        }
        // SAFETY: initialized callback object and writable output.
        let state = unsafe { state_mut(file) };
        if state.kind != FileKind::Main {
            return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
        }
        let reserved = if state.lock_level > SHARED_LOCK {
            true
        } else {
            match ofd_conflicting_lock(state.file.as_raw_fd(), libc::F_WRLCK as _, RESERVED_BYTE, 1)
            {
                Ok(kind) => kind != libc::F_UNLCK as libc::c_short,
                Err(_) => return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK,
            }
        };
        unsafe { *output = c_int::from(reserved) };
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn file_control(
    file: *mut ffi::sqlite3_file,
    operation: c_int,
    argument: *mut c_void,
) -> c_int {
    with_ffi_result(|| {
        if file.is_null() {
            return ffi::SQLITE_NOTFOUND;
        }
        // SAFETY: initialized callback object.
        let state = unsafe { state_mut(file) };
        match operation {
            ffi::SQLITE_FCNTL_LOCKSTATE if !argument.is_null() => {
                unsafe { *argument.cast::<c_int>() = state.lock_level };
                ffi::SQLITE_OK
            }
            ffi::SQLITE_FCNTL_HAS_MOVED if !argument.is_null() => {
                let moved = state
                    .context
                    .validate_live(state.kind.name(), &state.file)
                    .is_err();
                unsafe { *argument.cast::<c_int>() = c_int::from(moved) };
                ffi::SQLITE_OK
            }
            _ => ffi::SQLITE_NOTFOUND,
        }
    })
}

unsafe extern "C" fn file_sector_size(_file: *mut ffi::sqlite3_file) -> c_int {
    4096
}

unsafe extern "C" fn file_device_characteristics(_file: *mut ffi::sqlite3_file) -> c_int {
    0
}

impl Shm {
    fn open(context: &Context) -> Result<Self, c_int> {
        let cap_file = context
            .open_nofollow(SHM_NAME, true)
            .map_err(|_| ffi::SQLITE_CANTOPEN)?;
        let identity = identity(&cap_file).map_err(|_| ffi::SQLITE_IOERR_SHMOPEN)?;
        let file = cap_file.into_std();
        let fd = file.as_raw_fd();
        let conflict = ofd_conflicting_lock(fd, libc::F_WRLCK as _, SHM_DMS, 1)
            .map_err(|_| ffi::SQLITE_IOERR_LOCK)?;
        if conflict == libc::F_UNLCK as libc::c_short {
            ofd_lock(fd, libc::F_WRLCK as _, SHM_DMS, 1)
                .map_err(|error| lock_result(error, ffi::SQLITE_IOERR_LOCK))?;
            context
                .validate_live(SHM_NAME, &file)
                .map_err(|_| ffi::SQLITE_IOERR_SHMOPEN)?;
            // SQLite's deadman protocol uses three bytes as a recognizable initialized-by-
            // recovery marker, then downgrades the DMS lock without an unlocked window.
            if unsafe { libc::ftruncate(fd, 3) } != 0 {
                return Err(ffi::SQLITE_IOERR_SHMOPEN);
            }
        } else if conflict == libc::F_WRLCK as libc::c_short {
            return Err(ffi::SQLITE_BUSY);
        }
        ofd_lock(fd, libc::F_RDLCK as _, SHM_DMS, 1)
            .map_err(|error| lock_result(error, ffi::SQLITE_IOERR_LOCK))?;
        Ok(Self {
            file,
            identity,
            page_size: 0,
            mappings: Vec::new(),
            shared_mask: 0,
            exclusive_mask: 0,
        })
    }

    fn validate(&self, context: &Context) -> Result<(), c_int> {
        context
            .validate_live(SHM_NAME, &self.file)
            .map_err(|_| ffi::SQLITE_IOERR_SHMOPEN)
    }

    fn map(
        &mut self,
        context: &Context,
        page: c_int,
        page_size: c_int,
        extend: c_int,
    ) -> Result<*mut c_void, c_int> {
        if page < 0 || page_size <= 0 {
            return Err(ffi::SQLITE_IOERR_SHMMAP);
        }
        self.validate(context)?;
        let page_size = page_size as usize;
        if self.page_size == 0 {
            self.page_size = page_size;
        } else if self.page_size != page_size {
            return Err(ffi::SQLITE_IOERR_SHMMAP);
        }
        let page = page as usize;
        if let Some(Some(mapping)) = self.mappings.get(page) {
            return Ok(mapping.address);
        }
        let required = (page + 1)
            .checked_mul(page_size)
            .ok_or(ffi::SQLITE_IOERR_SHMSIZE)?;
        let current = self
            .file
            .metadata()
            .map_err(|_| ffi::SQLITE_IOERR_SHMSIZE)?
            .len() as usize;
        if current < required {
            if extend == 0 {
                return Ok(ptr::null_mut());
            }
            self.validate(context)?;
            let system_page = 4096usize;
            let first = current / system_page;
            let last = required.div_ceil(system_page);
            for index in first..last {
                self.validate(context)?;
                let byte = [0u8; 1];
                let offset = index
                    .checked_mul(system_page)
                    .and_then(|value| value.checked_add(system_page - 1))
                    .ok_or(ffi::SQLITE_IOERR_SHMSIZE)?;
                // SAFETY: pwrite reads one byte and the descriptor is validated immediately
                // before each allocation-forcing write.
                if unsafe {
                    libc::pwrite(
                        self.file.as_raw_fd(),
                        byte.as_ptr().cast(),
                        1,
                        offset as libc::off_t,
                    )
                } != 1
                {
                    return Err(ffi::SQLITE_IOERR_SHMSIZE);
                }
            }
        }
        self.validate(context)?;
        // SAFETY: the descriptor is a validated regular single-link file, length was made
        // sufficient, offset is SQLite's page-aligned SHM region offset, and Mapping owns it.
        let address = unsafe {
            libc::mmap(
                ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                self.file.as_raw_fd(),
                (page * page_size) as libc::off_t,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(ffi::SQLITE_IOERR_SHMMAP);
        }
        if self.mappings.len() <= page {
            self.mappings.resize_with(page + 1, || None);
        }
        self.mappings[page] = Some(Mapping {
            address,
            length: page_size,
        });
        Ok(address)
    }

    fn lock(&mut self, context: &Context, offset: c_int, count: c_int, flags: c_int) -> c_int {
        if offset < 0 || count < 1 || offset + count > SHM_LOCK_COUNT {
            return ffi::SQLITE_IOERR_SHMLOCK;
        }
        if self.validate(context).is_err() {
            return ffi::SQLITE_IOERR_SHMLOCK;
        }
        let mask = (((1u32 << count) - 1) << offset) as u16;
        let unlock = flags & ffi::SQLITE_SHM_UNLOCK != 0;
        let shared = flags & ffi::SQLITE_SHM_SHARED != 0;
        let exclusive = flags & ffi::SQLITE_SHM_EXCLUSIVE != 0;
        if shared == exclusive || (!unlock && flags & ffi::SQLITE_SHM_LOCK == 0) {
            return ffi::SQLITE_IOERR_SHMLOCK;
        }
        let lock_type = if unlock {
            libc::F_UNLCK
        } else if shared {
            libc::F_RDLCK
        } else {
            libc::F_WRLCK
        } as libc::c_short;
        match ofd_lock(
            self.file.as_raw_fd(),
            lock_type,
            SHM_LOCK_BASE + offset as libc::off_t,
            count as libc::off_t,
        ) {
            Ok(()) => {
                if unlock {
                    self.shared_mask &= !mask;
                    self.exclusive_mask &= !mask;
                } else if shared {
                    self.shared_mask |= mask;
                } else {
                    self.exclusive_mask |= mask;
                }
                ffi::SQLITE_OK
            }
            Err(error) => lock_result(error, ffi::SQLITE_IOERR_SHMLOCK),
        }
    }
}

unsafe extern "C" fn file_shm_map(
    file: *mut ffi::sqlite3_file,
    page: c_int,
    page_size: c_int,
    extend: c_int,
    output: *mut *mut c_void,
) -> c_int {
    with_ffi_result(|| {
        if file.is_null() || output.is_null() {
            return ffi::SQLITE_IOERR_SHMMAP;
        }
        // SAFETY: initialized main-file callback object and writable output.
        let state = unsafe { state_mut(file) };
        if state.kind != FileKind::Main {
            return ffi::SQLITE_IOERR_SHMMAP;
        }
        if state.shm.is_none() {
            match Shm::open(&state.context) {
                Ok(shm) => state.shm = Some(shm),
                Err(code) => return code,
            }
        }
        let result = state.shm.as_mut().expect("SHM was initialized above").map(
            &state.context,
            page,
            page_size,
            extend,
        );
        match result {
            Ok(address) => {
                unsafe { *output = address };
                ffi::SQLITE_OK
            }
            Err(code) => code,
        }
    })
}

unsafe extern "C" fn file_shm_lock(
    file: *mut ffi::sqlite3_file,
    offset: c_int,
    count: c_int,
    flags: c_int,
) -> c_int {
    with_ffi_result(|| {
        if file.is_null() {
            return ffi::SQLITE_IOERR_SHMLOCK;
        }
        // SAFETY: initialized callback object.
        let state = unsafe { state_mut(file) };
        match state.shm.as_mut() {
            Some(shm) => shm.lock(&state.context, offset, count, flags),
            None => ffi::SQLITE_IOERR_SHMLOCK,
        }
    })
}

unsafe extern "C" fn file_shm_barrier(_file: *mut ffi::sqlite3_file) {
    // SQLite requires a compiler/CPU barrier between SHM readers and writers.
    std::sync::atomic::fence(Ordering::SeqCst);
}

unsafe extern "C" fn file_shm_unmap(file: *mut ffi::sqlite3_file, delete: c_int) -> c_int {
    with_ffi_result(|| {
        if file.is_null() {
            return ffi::SQLITE_IOERR_SHMOPEN;
        }
        // SAFETY: initialized callback object.
        let state = unsafe { state_mut(file) };
        let Some(shm) = state.shm.take() else {
            return ffi::SQLITE_OK;
        };
        let identity = shm.identity;
        drop(shm); // munmap and close release OFD locks before optional unlink.
        if delete != 0 {
            match state.context.remove_if_identity(SHM_NAME, identity, false) {
                Ok(()) => ffi::SQLITE_OK,
                Err(_) => ffi::SQLITE_IOERR_DELETE,
            }
        } else {
            ffi::SQLITE_OK
        }
    })
}

unsafe extern "C" fn file_fetch(
    _file: *mut ffi::sqlite3_file,
    _offset: ffi::sqlite3_int64,
    _amount: c_int,
    output: *mut *mut c_void,
) -> c_int {
    with_ffi_result(|| {
        if !output.is_null() {
            // SAFETY: SQLite supplied this output pointer.
            unsafe { *output = ptr::null_mut() };
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn file_unfetch(
    _file: *mut ffi::sqlite3_file,
    _offset: ffi::sqlite3_int64,
    _pointer: *mut c_void,
) -> c_int {
    ffi::SQLITE_OK
}

static IO_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 3,
    xClose: Some(file_close),
    xRead: Some(file_read),
    xWrite: Some(file_write),
    xTruncate: Some(file_truncate),
    xSync: Some(file_sync),
    xFileSize: Some(file_size),
    xLock: Some(file_lock),
    xUnlock: Some(file_unlock),
    xCheckReservedLock: Some(file_check_reserved),
    xFileControl: Some(file_control),
    xSectorSize: Some(file_sector_size),
    xDeviceCharacteristics: Some(file_device_characteristics),
    xShmMap: Some(file_shm_map),
    xShmLock: Some(file_shm_lock),
    xShmBarrier: Some(file_shm_barrier),
    xShmUnmap: Some(file_shm_unmap),
    xFetch: Some(file_fetch),
    xUnfetch: Some(file_unfetch),
};

unsafe extern "C" fn vfs_randomness(
    _vfs: *mut ffi::sqlite3_vfs,
    amount: c_int,
    output: *mut c_char,
) -> c_int {
    with_ffi_result(|| {
        if amount <= 0 || output.is_null() {
            return 0;
        }
        let mut done = 0usize;
        while done < amount as usize {
            // SAFETY: output has amount writable bytes and getrandom retains no pointer.
            let result = unsafe {
                libc::getrandom(
                    output.cast::<u8>().add(done).cast(),
                    amount as usize - done,
                    0,
                )
            };
            if result > 0 {
                done += result as usize;
            } else if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
            {
                continue;
            } else {
                break;
            }
        }
        done as c_int
    })
}

unsafe extern "C" fn vfs_sleep(_vfs: *mut ffi::sqlite3_vfs, microseconds: c_int) -> c_int {
    with_ffi_result(|| {
        if microseconds <= 0 {
            return 0;
        }
        let duration = std::time::Duration::from_micros(microseconds as u64);
        std::thread::sleep(duration);
        microseconds
    })
}

fn unix_time_millis() -> io::Result<i64> {
    let mut time: libc::timespec = unsafe { mem::zeroed() };
    // SAFETY: time is a valid writable timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(time.tv_sec.saturating_mul(1000) + time.tv_nsec / 1_000_000)
}

unsafe extern "C" fn vfs_current_time(_vfs: *mut ffi::sqlite3_vfs, output: *mut f64) -> c_int {
    with_ffi_result(|| {
        if output.is_null() {
            return ffi::SQLITE_IOERR;
        }
        match unix_time_millis() {
            Ok(milliseconds) => {
                // SAFETY: SQLite supplied a writable f64 pointer.
                unsafe { *output = 2_440_587.5 + milliseconds as f64 / 86_400_000.0 };
                ffi::SQLITE_OK
            }
            Err(_) => ffi::SQLITE_IOERR,
        }
    })
}

unsafe extern "C" fn vfs_current_time_i64(
    _vfs: *mut ffi::sqlite3_vfs,
    output: *mut ffi::sqlite3_int64,
) -> c_int {
    with_ffi_result(|| {
        if output.is_null() {
            return ffi::SQLITE_IOERR;
        }
        match unix_time_millis() {
            Ok(milliseconds) => {
                // Julian epoch to Unix epoch is exactly 2440587.5 days.
                unsafe { *output = milliseconds.saturating_add(210_866_760_000_000) };
                ffi::SQLITE_OK
            }
            Err(_) => ffi::SQLITE_IOERR,
        }
    })
}

unsafe extern "C" fn vfs_last_error(
    _vfs: *mut ffi::sqlite3_vfs,
    length: c_int,
    output: *mut c_char,
) -> c_int {
    if length > 0 && !output.is_null() {
        // SAFETY: SQLite supplied at least length writable bytes.
        unsafe { *output = 0 };
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        static BEFORE_UNLINK: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    }

    pub(super) fn before_unlink() {
        let hook = BEFORE_UNLINK.with(|slot| slot.borrow_mut().take());
        if let Some(hook) = hook {
            hook();
        }
    }

    #[test]
    fn concurrent_sidecar_removal_is_idempotent() {
        let temporary = tempfile::tempdir().expect("synthetic directory");
        let root = Dir::open_ambient_dir(temporary.path(), cap_std::ambient_authority())
            .expect("test capability");
        let context = Context {
            token: "test-unlink".into(),
            root,
            main: Mutex::new(None),
        };
        let file = context.open_nofollow(WAL_NAME, true).expect("test sidecar");
        let expected = identity(&file).expect("sidecar identity");
        drop(file);
        let competing_root = context.root.try_clone().expect("competing capability");
        BEFORE_UNLINK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                competing_root
                    .remove_file(WAL_NAME)
                    .expect("competing removal");
            }));
        });
        context
            .remove_if_identity(WAL_NAME, expected, false)
            .expect("already removed sidecar must not fail a concurrent open");
    }
}
