//! Native disposable-runner adapter. Local IPC proof, not a production broker.
#[path = "pipe_probe.rs"]
mod pipe_probe;
#[path = "production_probe.rs"]
mod production_probe;
// All provisioning is reachable only after the public admission + elevation gates.
use super::policy;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::{
    ffi::c_void,
    fs, io,
    mem::size_of,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Services::*, Threading::*},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}
fn win(ok: i32) -> Result<()> {
    if ok != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}
fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: sole owner of a valid kernel handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct ScHandle(SC_HANDLE);
impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: sole owner of an SCM handle.
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: these allocations come only from LocalAlloc-backed Win32 APIs.
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn handle(raw: HANDLE) -> Result<Handle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    Ok(Handle(raw))
}
fn sc(raw: SC_HANDLE) -> Result<ScHandle> {
    if raw.is_null() {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(ScHandle(raw))
    }
}

// SAFETY: caller supplies a valid SID owned by a live token/SD/buffer.
unsafe fn sid_text(sid: PSID) -> Result<String> {
    let mut text = null_mut();
    win(unsafe { ConvertSidToStringSidW(sid, &mut text) })?;
    let _allocation = Local(text.cast());
    let mut n = 0;
    while unsafe { *text.add(n) } != 0 {
        n += 1;
    }
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(text, n)
    }))
}
fn token_info(token: &Handle, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<usize>> {
    let mut needed = 0;
    // SAFETY: live handle, initial null buffer is the documented sizing call.
    unsafe {
        GetTokenInformation(token.0, class, null_mut(), 0, &mut needed);
    }
    ensure(needed > 0 && needed <= 65536, "invalid token info length")?;
    let mut data = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    // SAFETY: usize allocation is aligned and at least needed bytes long; remains live for all readers.
    win(unsafe {
        GetTokenInformation(
            token.0,
            class,
            data.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    })?;
    Ok(data)
}
fn identity() -> Result<Value> {
    // SAFETY: process pseudo handle is valid, borrowed, and must not be closed.
    identity_of(unsafe { GetCurrentProcess() })
}
fn identity_of(process: HANDLE) -> Result<Value> {
    let mut raw = null_mut();
    // SAFETY: caller keeps queried process handle alive; output storage is initialized.
    win(unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) })?;
    let token = handle(raw)?;
    let user = token_info(&token, TokenUser)?;
    let owner = token_info(&token, TokenOwner)?;
    let elevation = token_info(&token, TokenElevation)?;
    let integrity = token_info(&token, TokenIntegrityLevel)?;
    let groups = token_info(&token, TokenGroups)?;
    let privileges = token_info(&token, TokenPrivileges)?;
    // SAFETY: GetTokenInformation returned the requested, aligned structures; flexible arrays bounded by its counts.
    unsafe {
        let user = sid_text((*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid)?;
        let owner = sid_text((*(owner.as_ptr().cast::<TOKEN_OWNER>())).Owner)?;
        let elevated = (*(elevation.as_ptr().cast::<TOKEN_ELEVATION>())).TokenIsElevated != 0;
        let integrity = sid_text(
            (*(integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()))
                .Label
                .Sid,
        )?;
        let g = &*groups.as_ptr().cast::<TOKEN_GROUPS>();
        let mut gs = Vec::new();
        for item in std::slice::from_raw_parts(g.Groups.as_ptr(), g.GroupCount as usize) {
            gs.push(json!({"sid":sid_text(item.Sid)?, "attributes":item.Attributes}));
        }
        let p = &*privileges.as_ptr().cast::<TOKEN_PRIVILEGES>();
        let mut ps = Vec::new();
        for item in std::slice::from_raw_parts(p.Privileges.as_ptr(), p.PrivilegeCount as usize) {
            let mut name = [0u16; 256];
            let mut len = name.len() as u32;
            win(LookupPrivilegeNameW(
                null(),
                &item.Luid,
                name.as_mut_ptr(),
                &mut len,
            ))?;
            ps.push(json!({"name":String::from_utf16_lossy(&name[..len as usize]), "attributes":item.Attributes}));
        }
        Ok(
            json!({"user":user,"owner":owner,"elevated":elevated,"integrity_sid":integrity,"groups":gs,"privileges":ps}),
        )
    }
}
fn service_sid(name: &str) -> Result<String> {
    let account = wide(format!("NT SERVICE\\{name}"));
    let mut sid = [0usize; 32];
    let mut sid_len = size_of_val(&sid) as u32;
    let mut domain = [0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut usage = 0;
    // SAFETY: fixed sufficiently sized output buffers; all input strings NUL terminated.
    win(unsafe {
        LookupAccountNameW(
            null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut usage,
        )
    })?;
    unsafe { sid_text(sid.as_mut_ptr().cast()) }
}
fn descriptor(sddl: &str) -> Result<Local> {
    let mut sd = null_mut();
    // SAFETY: API allocates descriptor; Local guard releases it.
    win(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(sddl).as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        )
    })?;
    Ok(Local(sd))
}
fn mkdir(path: &Path, extra: &str) -> Result<()> {
    let sd = descriptor(&format!(
        "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA){extra}"
    ))?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    // SAFETY: SD and path live through creation. Existing directories are never adopted.
    win(unsafe { CreateDirectoryW(wide(path).as_ptr(), &sa) })
}
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
fn trusted(sid: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-32-544") || sid == TRUSTED_INSTALLER
}
fn audit_dir(path: &Path, writers: &[&str], readers: &[&str], ancestor: bool) -> Result<Value> {
    // SAFETY: open no-follow directory handle; sharing allows only trusted mutations after validation.
    let h = handle(unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    })?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    let mut owner = null_mut();
    let mut acl = null_mut();
    let mut sd = null_mut();
    // SAFETY: live handle and valid output storage. Returned pointers are inside allocated SD.
    unsafe {
        win(GetFileInformationByHandle(h.0, &mut info))?;
        ensure(
            info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
            "reparse/non-directory ancestor",
        )?;
        let error = GetSecurityInfo(
            h.0,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut acl,
            null_mut(),
            &mut sd,
        );
        ensure(error == 0, &format!("GetSecurityInfo error {error}"))?;
        let _sd = Local(sd);
        ensure(!owner.is_null() && !acl.is_null(), "null owner/DACL")?;
        let owner = sid_text(owner)?;
        ensure(trusted(&owner), "directory not administrator/system owned")?;
        let mut control = 0;
        let mut revision = 0;
        win(GetSecurityDescriptorControl(
            sd,
            &mut control,
            &mut revision,
        ))?;
        ensure(
            ancestor || control & SE_DACL_PROTECTED != 0,
            "unprotected fixture DACL",
        )?;
        let mut entries = Vec::new();
        for index in 0..(*acl).AceCount {
            let mut raw = null_mut();
            win(GetAce(acl, index as u32, &mut raw))?;
            let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
            ensure(
                ace.Header.AceType == 0,
                "unknown/deny/object ACE: fail closed",
            )?;
            let sid = sid_text((&ace.SidStart as *const u32).cast_mut().cast())?;
            let applies = u32::from(ace.Header.AceFlags) & INHERIT_ONLY_ACE == 0;
            // Ancestors may allow harmless create-new-child, but never deletion/replacement of our child.
            ensure(
                if ancestor {
                    !applies || trusted(&sid) || !policy::namespace_mutation(ace.Mask, true)
                } else {
                    policy::fixture_ace_allowed(
                        trusted(&sid),
                        writers.contains(&sid.as_str()),
                        readers.contains(&sid.as_str()),
                        ace.Mask,
                    )
                },
                "unexpected namespace-mutating ACE",
            )?;
            entries.push(json!({"sid":sid,"mask":ace.Mask,"flags":ace.Header.AceFlags}));
        }
        Ok(
            json!({"path":path,"owner":owner,"control":control,"aces":entries,"volume_serial":info.dwVolumeSerialNumber,"file_index":[info.nFileIndexHigh,info.nFileIndexLow]}),
        )
    }
}
fn fixture_volume() -> Result<(PathBuf, Vec<Value>)> {
    let raw = format!("{}\\", std::env::var("SystemDrive")?);
    let bytes = raw.as_bytes();
    ensure(
        bytes.len() == 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..3] == b":\\",
        "only system drive root accepted",
    )?;
    let volume = &raw[..3];
    let mut fs_name = [0u16; 32];
    // SAFETY: NUL terminated volume root and valid fixed output buffer.
    unsafe {
        ensure(
            GetDriveTypeW(wide(volume).as_ptr()) == 3, // documented DRIVE_FIXED value
            "not local fixed volume",
        )?;
        win(GetVolumeInformationW(
            wide(volume).as_ptr(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        ))?;
    }
    ensure(
        String::from_utf16_lossy(&fs_name[..4]) == "NTFS",
        "not NTFS",
    )?;
    // ProgramData on hosted Windows grants ordinary users WRITE_EA/WRITE_ATTRIBUTES.
    // Never weaken that ancestor or the broker admission policy: create our fresh
    // protected namespace directly under the independently audited volume root.
    let audits = vec![audit_dir(Path::new(volume), &[], &[], true)?];
    Ok((PathBuf::from(raw), audits))
}
fn write_report(dir: &Path, name: &str, value: &Value) -> Result<()> {
    use std::io::Write;
    let pending = dir.join(format!("{name}.pending"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    drop(file);
    // SAFETY: both paths are live NUL-terminated strings on this fixture volume.
    // MoveFileW (unlike fs::rename) refuses to replace a completed receipt.
    win(unsafe { MoveFileW(wide(&pending).as_ptr(), wide(dir.join(name)).as_ptr()) })?;
    Ok(())
}
fn read_report(dir: &Path, name: &str, deadline: Instant) -> Result<Value> {
    loop {
        if dir.join("error.json").exists() {
            return Err(format!(
                "service failure: {}",
                fs::read_to_string(dir.join("error.json"))?
            )
            .into());
        }
        match fs::read(dir.join(name)) {
            Ok(bytes) => {
                ensure(bytes.len() < 1024 * 1024, "oversized receipt")?;
                return Ok(serde_json::from_slice(&bytes)?);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(100))
            }
            Err(error) => return Err(error.into()),
        }
    }
}
#[cfg(test)]
mod receipt_tests {
    use super::*;

    #[test]
    fn completed_receipt_cannot_be_replaced_by_later_stage() {
        let dir = tempfile::tempdir().unwrap();
        write_report(dir.path(), "ready.json", &json!({"stage":1})).unwrap();
        assert!(write_report(dir.path(), "ready.json", &json!({"stage":2})).is_err());
        assert_eq!(
            read_report(dir.path(), "ready.json", Instant::now()).unwrap()["stage"],
            1
        );
    }

    #[test]
    fn service_error_receipt_wins_over_stale_ready() {
        let dir = tempfile::tempdir().unwrap();
        write_report(dir.path(), "ready.json", &json!({"ready":true})).unwrap();
        write_report(
            dir.path(),
            "error.json",
            &json!({"error":"failed after ready"}),
        )
        .unwrap();
        assert!(read_report(dir.path(), "ready.json", Instant::now())
            .unwrap_err()
            .to_string()
            .contains("failed after ready"));
    }
}

fn records(db: &Connection) -> Result<Vec<String>> {
    Ok(db
        .prepare("SELECT value FROM proof ORDER BY id")?
        .query_map([], |row| row.get(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?)
}
const RECORDS: [&str; 2] = ["committed-by-first", "committed-by-second"];
fn configure(db: &Connection) -> Result<()> {
    db.busy_timeout(Duration::from_secs(2))?;
    db.execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY; PRAGMA wal_autocheckpoint=0;")?;
    Ok(())
}
fn sqlite_worker(root: &Path, id: &Value) -> Result<()> {
    let store = root.join("store");
    let report = root.join("result-a");
    let broker_storage = broker_storage_control(&root.join("broker-store"))?;
    let first = Connection::open(store.join("memory.db"))?;
    let mode: String = first.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
    ensure(mode == "wal", "SQLite did not enter WAL")?;
    configure(&first)?;
    first.execute_batch("CREATE TABLE proof(id INTEGER PRIMARY KEY, value TEXT NOT NULL); INSERT INTO proof VALUES(1,'committed-by-first');")?;
    let second = Connection::open(store.join("memory.db"))?;
    configure(&second)?;
    second.execute_batch("INSERT INTO proof VALUES(2,'committed-by-second');")?;
    ensure(
        records(&first)? == RECORDS && records(&second)? == RECORDS,
        "two-connection records mismatch",
    )?;
    // A genuine SQLite PERSIST rollback journal, closed before attacker starts: not a sharing-mode test.
    let rollback = Connection::open(store.join("rollback.db"))?;
    rollback.execute_batch("PRAGMA journal_mode=PERSIST; PRAGMA synchronous=FULL; CREATE TABLE closed_control(value); INSERT INTO closed_control VALUES(1);")?;
    drop(rollback);
    let files: Vec<_> = policy::TARGETS
        .iter()
        .map(|name| -> Result<Value> {
            let metadata = fs::metadata(store.join(name))?;
            ensure(
                metadata.is_file() && metadata.len() > 0,
                "missing/empty SQLite fixture",
            )?;
            Ok(json!({"name":name,"length":metadata.len(),"exists":true}))
        })
        .collect::<Result<_>>()?;
    let version: String = first.query_row("SELECT sqlite_version()", [], |r| r.get(0))?;
    let source: String = first.query_row("SELECT sqlite_source_id()", [], |r| r.get(0))?;
    let mut vfs: *mut std::ffi::c_char = null_mut();
    // SAFETY: connection remains live, SQLite writes an allocated C string and sqlite3_free owns it.
    let vfs_name = unsafe {
        let rc = rusqlite::ffi::sqlite3_file_control(
            first.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_VFSNAME,
            (&mut vfs as *mut *mut std::ffi::c_char).cast(),
        );
        ensure(
            rc == rusqlite::ffi::SQLITE_OK && !vfs.is_null(),
            "SQLite VFS query failed",
        )?;
        let name = std::ffi::CStr::from_ptr(vfs).to_string_lossy().into_owned();
        rusqlite::ffi::sqlite3_free(vfs.cast());
        name
    };
    ensure(vfs_name == "win32", "unexpected SQLite VFS")?;
    let options = first
        .prepare("PRAGMA compile_options")?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    // Publish ready only after both real IPC listeners have been created.
    let mut pipe = pipe_probe::Server::prepare(root)?;
    write_report(
        &report,
        "ready.json",
        &json!({"identity":id,"records":records(&first)?,"files":files,"sqlite_version":version,"sqlite_source_id":source,"vfs":vfs_name,"compile_options":options,"journal_mode":mode,"connections":2,"closed_rollback_journal":true,"broker_storage":broker_storage,"ipc_listeners_bound":true}),
    )?;
    let ipc = pipe.run(root)?;
    let deadline = Instant::now() + Duration::from_secs(90);
    while !STOP.load(Ordering::Acquire) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    ensure(STOP.load(Ordering::Acquire), "service lease expired")?;
    let integrity: String = first.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    ensure(
        integrity == "ok" && records(&first)? == RECORDS,
        "post-attack integrity/records mismatch",
    )?;
    write_report(
        &report,
        "final.json",
        &json!({"records":records(&first)?,"integrity_check":integrity,"ipc":ipc}),
    )?;
    Ok(())
}
fn broker_storage_control(root: &Path) -> Result<Value> {
    use hermes_memory::{MemoryRecord, MemoryStore, SearchRequest};
    let record = MemoryRecord {
        id: "broker-windows-one".into(),
        session_id: "probe-session".into(),
        workspace: "sandbox".into(),
        kind: "note".into(),
        content: "Windows durable quince Unicode ñ".into(),
        timestamp: 1.0,
        metadata: json!({"nested":{"source":"service","values":[1,true]}}),
    };
    let query = SearchRequest {
        query: "quince".into(),
        workspace: Some("sandbox".into()),
        session_id: Some("probe-session".into()),
        limit: 10,
        max_bytes: 65536,
    };
    let store = MemoryStore::open_broker(root)?;
    ensure(
        MemoryStore::open_broker(root).is_err(),
        "second broker instance was admitted",
    )?;
    ensure(store.ingest(&record)?, "broker did not insert record")?;
    ensure(!store.ingest(&record)?, "broker duplicated record")?;
    ensure(store.search(&query)?.len() == 1, "broker search failed")?;
    drop(store);
    let reopened = MemoryStore::open_broker(root)?;
    ensure(!reopened.ingest(&record)?, "reopen duplicated record")?;
    let hits = reopened.search(&query)?;
    ensure(
        hits.len() == 1 && serde_json::to_value(&hits[0])? == serde_json::to_value(&record)?,
        "broker full-field recovery failed",
    )?;
    let native = Connection::open(root.join("memory.db"))?;
    let integrity: String = native.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    ensure(integrity == "ok", "broker integrity check failed")?;
    Ok(
        json!({"exclusive_instance":true,"inserted":1,"duplicates_rejected":2,"full_field_reopen":true,"integrity_check":integrity}),
    )
}

fn error_code(result: io::Result<()>) -> u32 {
    match result {
        Ok(()) => 0,
        Err(e) => e.raw_os_error().map(|e| e as u32).unwrap_or(u32::MAX),
    }
}
fn attempt(path: &Path, scratch: &Path, op: &str) -> u32 {
    match op {
        "read" => error_code(fs::OpenOptions::new().read(true).open(path).map(drop)),
        "write" => error_code(fs::OpenOptions::new().write(true).open(path).map(drop)),
        // CREATE_ALWAYS on the actual existing target; missing-sidecar creation is not claimed.
        "create" => error_code(
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .map(drop),
        ),
        "delete" => error_code(fs::remove_file(path)),
        "rename" => error_code(fs::rename(path, scratch.join("stolen"))),
        "hardlink_out" => error_code(fs::hard_link(path, scratch.join("alias"))),
        "hardlink_in" => error_code(fs::hard_link(
            scratch.join("source"),
            path.with_file_name(format!(
                "{}-inserted",
                path.file_name().unwrap_or_default().to_string_lossy()
            )),
        )),
        _ => u32::MAX,
    }
}
fn attacker_worker(root: &Path, id: &Value) -> Result<()> {
    let ipc = pipe_probe::client(root)?;
    let scratch = root.join("scratch");
    // Positive controls under the exact attacking token, including a closed source and hardlink.
    let source = scratch.join("source");
    fs::write(&source, b"positive")?;
    ensure(fs::read(&source)? == b"positive", "scratch read failed")?;
    fs::write(&source, b"overwrite")?;
    fs::rename(&source, scratch.join("renamed"))?;
    fs::rename(scratch.join("renamed"), &source)?;
    fs::hard_link(&source, scratch.join("positive-link"))?;
    fs::remove_file(scratch.join("positive-link"))?;
    let mut cases = Vec::new();
    for name in policy::TARGETS {
        for op in policy::OPERATIONS {
            let code = attempt(&root.join("store").join(name), &scratch, op);
            cases.push(json!({"target":name,"operation":op,"win32_error":code,"acl_denied":code == ERROR_ACCESS_DENIED,"existing_target":root.join("store").join(name),"create_semantics":"CREATE_ALWAYS_existing_target","hardlink_in_destination":format!("{name}-inserted")}));
        }
    }
    write_report(
        &root.join("result-b"),
        "result.json",
        &json!({"identity":id,"positive_controls":["create","read","overwrite","rename","hardlink","delete"],"cases":cases,"ipc":ipc}),
    )?;
    production_probe::client(root)?;
    let deadline = Instant::now() + Duration::from_secs(90);
    while !STOP.load(Ordering::Acquire) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    ensure(
        STOP.load(Ordering::Acquire),
        "attacker service lease expired",
    )
}

static CONTEXT: OnceLock<(String, PathBuf, String)> = OnceLock::new();
static STOP: AtomicBool = AtomicBool::new(false);
unsafe extern "system" fn control(code: u32) {
    if code == SERVICE_CONTROL_STOP {
        STOP.store(true, Ordering::Release);
    }
}
fn status(h: SERVICE_STATUS_HANDLE, state: u32, error: u32) -> Result<()> {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP
        } else {
            0
        },
        dwWin32ExitCode: error,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    // SAFETY: callback's registration handle remains valid until service main returns.
    win(unsafe { SetServiceStatus(h, &status) })
}
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    // Never unwind through SCM's C ABI. Failure is an SCM failure and an isolated error receipt.
    let result = std::panic::catch_unwind(|| -> Result<()> {
        let (name, root, role) = CONTEXT.get().ok_or("missing SCM context")?;
        // SAFETY: stable NUL string and static callback; dispatcher invokes this function only as a service.
        let h = unsafe { RegisterServiceCtrlHandlerW(wide(name).as_ptr(), Some(control)) };
        ensure(!h.is_null(), "service control registration failed")?;
        status(h, SERVICE_RUNNING, 0)?;
        let work = (|| {
            let id = identity()?;
            ensure(
                id["user"] == service_sid(name)?,
                "TokenUser is not configured virtual account",
            )?;
            ensure(id["elevated"] == false, "service unexpectedly elevated")?;
            for group in id["groups"].as_array().ok_or("missing groups")? {
                let attributes = group["attributes"]
                    .as_u64()
                    .ok_or("missing group attributes")? as u32;
                ensure(
                    group["sid"] != "S-1-5-32-544"
                        || attributes & 0x00000004 /* SE_GROUP_ENABLED */ == 0,
                    "service has enabled administrators group",
                )?;
            }
            let privileges = id["privileges"]
                .as_array()
                .ok_or("missing privileges")?
                .iter()
                .map(|privilege| privilege["name"].as_str().ok_or("missing privilege name"))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            ensure(
                policy::ipc_privileges(&privileges),
                "service must have only SeChangeNotifyPrivilege installed",
            )?;
            if role == "a" {
                sqlite_worker(root, &id)
            } else {
                attacker_worker(root, &id)
            }
        })();
        if let Err(error) = &work {
            let dir = root.join(format!("result-{role}"));
            if let Err(report_error) =
                write_report(&dir, "error.json", &json!({"error":error.to_string()}))
            {
                eprintln!("error receipt failed: {report_error}");
            }
        }
        status(
            h,
            SERVICE_STOPPED,
            if work.is_ok() { 0 } else { ERROR_GEN_FAILURE },
        )?;
        work
    });
    if !matches!(result, Ok(Ok(()))) {
        std::process::exit(1);
    }
}
pub fn dispatch(args: &[String]) -> Result<()> {
    ensure(
        args.len() == 4
            && matches!(args[3].as_str(), "a" | "b")
            && args[1].starts_with("HMVProbe_"),
        "invalid private service mode",
    )?;
    CONTEXT
        .set((args[1].clone(), PathBuf::from(&args[2]), args[3].clone()))
        .map_err(|_| "duplicate service context")?;
    let mut name = wide(&args[1]);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: table and names live throughout blocking dispatcher. Ordinary console invocation fails
    // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT before service_main or any filesystem mutation.
    win(unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) })
}
fn create_service(manager: &ScHandle, name: &str, root: &Path, role: &str) -> Result<ScHandle> {
    let exe = root.join("bin").join("probe.exe");
    let command = format!(
        "\"{}\" --service {} \"{}\" {}",
        exe.display(),
        name,
        root.display(),
        role
    );
    let account = format!("NT SERVICE\\{name}");
    // SAFETY: all NUL terminated strings live during call. No password/account creation and no shell.
    sc(unsafe {
        CreateServiceW(
            manager.0,
            wide(name).as_ptr(),
            wide(name).as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            wide(command).as_ptr(),
            null(),
            null_mut(),
            null(),
            wide(account).as_ptr(),
            null(),
        )
    })
}
fn restrict_privileges(service: &ScHandle) -> Result<()> {
    let mut names = wide("SeChangeNotifyPrivilege");
    names.push(0);
    let required = SERVICE_REQUIRED_PRIVILEGES_INFOW {
        pmszRequiredPrivileges: names.as_mut_ptr(),
    };
    // SAFETY: MULTI_SZ ends with double NUL, struct/string live through synchronous call.
    win(unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            (&required as *const SERVICE_REQUIRED_PRIVILEGES_INFOW).cast(),
        )
    })
}
fn query(service: &ScHandle) -> Result<SERVICE_STATUS_PROCESS> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0;
    // SAFETY: properly sized typed output structure.
    win(unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    })?;
    Ok(status)
}
fn track(service: &ScHandle, sid: &str) -> Result<(Handle, Value)> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut before = query(service)?;
    while before.dwCurrentState == SERVICE_START_PENDING && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
        before = query(service)?;
    }
    ensure(
        before.dwCurrentState == SERVICE_RUNNING && before.dwProcessId != 0,
        "service not running with a PID",
    )?;
    // SAFETY: query/wait only, never terminate or authorize IPC using this PID. Handle pins object.
    let process = handle(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | 0x00100000,
            0,
            before.dwProcessId,
        )
    })?;
    let id = identity_of(process.0)?;
    ensure(
        id["user"] == sid,
        "SCM process token differs from pinned unique service SID",
    )?;
    let after = query(service)?;
    ensure(
        after.dwCurrentState == SERVICE_RUNNING && after.dwProcessId == before.dwProcessId,
        "SCM status changed during tracking",
    )?;
    Ok((
        process,
        json!({"scm_pid":before.dwProcessId,"token":id,"use":"exit-wait-only-not-IPC-authentication"}),
    ))
}
fn stop(service: &ScHandle, deadline: Instant) -> Result<()> {
    let mut current = query(service)?;
    if current.dwCurrentState != SERVICE_STOPPED {
        let mut ignored = SERVICE_STATUS::default();
        // SAFETY: only our retained, newly-created service handle, never name enumeration.
        let ok = unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut ignored) };
        let error = io::Error::last_os_error();
        if ok == 0 && query(service)?.dwCurrentState != SERVICE_STOPPED {
            return Err(error.into());
        }
    }
    while current.dwCurrentState != SERVICE_STOPPED {
        ensure(
            Instant::now() < deadline,
            "service stop deadline expired; no process kill fallback",
        )?;
        thread::sleep(Duration::from_millis(100));
        current = query(service)?;
    }
    ensure(current.dwWin32ExitCode == 0, "service reported failure")
}
pub fn run() -> Result<()> {
    let admin = identity()?;
    ensure(
        admin["elevated"] == true,
        "elevated administrator token required",
    )?;
    let (parent, ancestors) = fixture_volume()?;
    let nonce = format!(
        "{}_{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    );
    let root = parent.join(format!("HMVProbe_{nonce}"));
    let names = [
        format!("HMVProbe_{nonce}_A"),
        format!("HMVProbe_{nonce}_B"),
        format!("HMVProbe-{}-C", nonce.replace('_', "-")),
    ];
    // SAFETY: local manager only; no service enumeration or existing registration opened.
    let manager = sc(unsafe {
        OpenSCManagerW(
            null(),
            null(),
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
        )
    })?;
    let mut services = Vec::new();
    let mut processes = Vec::new();
    let mut observations = json!({});
    let mut created_root = false;
    let proof = (|| -> Result<Value> {
        // Registration precedes name-to-SID resolution. Nothing is started until all ACLs exist.
        for (name, role) in names.iter().zip(["a", "b", "c"]) {
            services.push(create_service(&manager, name, &root, role)?);
        }
        let a = service_sid(&names[0])?;
        let b = service_sid(&names[1])?;
        let c = service_sid(&names[2])?;
        for service in &services {
            restrict_privileges(service)?;
        }
        let rx = format!("(A;OICI;FRFX;;;{a})(A;OICI;FRFX;;;{b})(A;OICI;FRFX;;;{c})");
        mkdir(&root, &rx)?;
        created_root = true;
        mkdir(&root.join("bin"), &rx)?;
        mkdir(&root.join("store"), &format!("(A;OICI;FA;;;{a})"))?;
        mkdir(&root.join("broker-store"), &format!("(A;OICI;FA;;;{a})"))?;
        mkdir(&root.join("result-a"), &format!("(A;OICI;FA;;;{a})"))?;
        mkdir(&root.join("scratch"), &format!("(A;OICI;FA;;;{b})"))?;
        mkdir(&root.join("result-b"), &format!("(A;OICI;FA;;;{b})"))?;
        let mut acl_audits = vec![
            audit_dir(&root, &[], &[&a, &b, &c], false)?,
            audit_dir(&root.join("bin"), &[], &[&a, &b, &c], false)?,
        ];
        for (dir, sid) in [
            ("store", &a),
            ("broker-store", &a),
            ("result-a", &a),
            ("scratch", &b),
            ("result-b", &b),
        ] {
            acl_audits.push(audit_dir(&root.join(dir), &[sid], &[], false)?);
        }
        let (_, binary) = production_probe::prepare(&root, &services[2], &names[2], &b)?;
        observations["production_binary"] = binary;
        let ipc_config = pipe_probe::Config::new(&a, &b, &nonce);
        write_report(
            &root,
            "ipc-config.json",
            &serde_json::to_value(&ipc_config)?,
        )?;
        // Create-new destination inherits protected binary-directory SD, never the source ACL.
        let source = std::env::current_exe()?;
        let target = root.join("bin/probe.exe");
        {
            use std::io::Write;
            let bytes = fs::read(&source)?;
            let mut out = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&target)?;
            out.write_all(&bytes)?;
            out.sync_all()?;
        }
        // SAFETY: own fresh registrations, fixed no-argument service start.
        win(unsafe { StartServiceW(services[0].0, 0, null()) })?;
        let (process, observation) = track(&services[0], &a)?;
        processes.push(process);
        observations["tracked_a"] = observation;
        let ready = read_report(
            &root.join("result-a"),
            "ready.json",
            Instant::now() + Duration::from_secs(25),
        )?;
        observations["service_a"] = ready.clone();
        ensure(
            ready["ipc_listeners_bound"] == true,
            "IPC readiness missing",
        )?;
        observations["ipc_admin"] = pipe_probe::admin_attempt(&root, &ipc_config)?;
        for name in policy::TARGETS {
            ensure(
                fs::metadata(root.join("store").join(name))?.len() > 0,
                "parent missing target witness",
            )?;
        }
        win(unsafe { StartServiceW(services[1].0, 0, null()) })?;
        let (process, observation) = track(&services[1], &b)?;
        processes.push(process);
        observations["tracked_b"] = observation;
        let client_ready = read_report(
            &root.join("result-b"),
            "ipc-client-ready.json",
            Instant::now() + Duration::from_secs(25),
        )?;
        ensure(
            client_ready["controls_completed"] == true,
            "client preflight missing",
        )?;
        observations["ipc_client_ready"] = client_ready;
        write_report(&root, "ipc-client-go.json", &json!({"start":true}))?;
        let attacker = read_report(
            &root.join("result-b"),
            "result.json",
            Instant::now() + Duration::from_secs(25),
        )?;
        observations["service_b"] = attacker.clone();
        let ipc_server = read_report(
            &root.join("result-a"),
            "ipc.json",
            Instant::now() + Duration::from_secs(10),
        )?;
        observations["ipc_server"] = ipc_server.clone();
        ensure(
            ipc_server["storage_dispatches"] == 1
                && ipc_server["ack_before_disconnect"] == true
                && ipc_server["wrong_server_pin"]["bytes_received"] == 0,
            "incomplete server IPC evidence",
        )?;
        ensure(
            policy::identities_distinct(
                admin["user"].as_str().ok_or("admin SID missing")?,
                &a,
                &b,
                ready["identity"]["user"].as_str().ok_or("A SID missing")?,
                attacker["identity"]["user"]
                    .as_str()
                    .ok_or("B SID missing")?,
            ),
            "identity separation failed",
        )?;
        let cases = attacker["cases"].as_array().ok_or("missing cases")?;
        let tuples = cases
            .iter()
            .map(|case| -> Result<_> {
                Ok((
                    case["target"].as_str().ok_or("target missing")?,
                    case["operation"].as_str().ok_or("operation missing")?,
                    u32::try_from(case["win32_error"].as_u64().ok_or("error missing")?)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure(
            policy::exact_denials(&tuples),
            "missing/duplicate/non-ACL failure in attack matrix",
        )?;
        ensure(
            ready["records"] == json!(RECORDS),
            "parent record verification failed",
        )?;
        stop(&services[0], Instant::now() + Duration::from_secs(15))?;
        observations["production_start"] =
            production_probe::start(&services[2], &c, &mut processes)?;
        observations["production_admin"] = production_probe::admin_denial(&root)?;
        write_report(&root, "production-go.json", &json!({"start":true}))?;
        let first = read_report(
            &root.join("result-b"),
            "production-first.json",
            Instant::now() + Duration::from_secs(90),
        )?;
        observations["production_first"] = first.clone();
        observations["production_stop"] =
            production_probe::stopped(&services[2], processes.last().ok_or("C process missing")?)?;
        observations["production_restart"] =
            production_probe::start(&services[2], &c, &mut processes)?;
        write_report(&root, "production-restarted.json", &json!({"restart":true}))?;
        let durable = read_report(
            &root.join("result-b"),
            "production-final.json",
            Instant::now() + Duration::from_secs(90),
        )?;
        ensure(
            first["search"]["response"]["result"] == durable["search"]["response"]["result"],
            "restart changed exact records",
        )?;
        observations["production_final"] = durable;
        observations["production_final_stop"] =
            production_probe::stopped(&services[2], processes.last().ok_or("C process missing")?)?;
        observations["production_integrity"] = production_probe::integrity(&root)?;
        stop(&services[1], Instant::now() + Duration::from_secs(15))?;
        let final_report = read_report(
            &root.join("result-a"),
            "final.json",
            Instant::now() + Duration::from_secs(2),
        )?;
        ensure(
            final_report["records"] == json!(RECORDS)
                && final_report["integrity_check"] == "ok"
                && final_report["ipc"] == ipc_server,
            "final records/integrity failed",
        )?;
        Ok(
            json!({"scope":"SCM_VIRTUAL_IDENTITIES_SQLITE_ACL_AND_LOCAL_AUTHENTICATED_PIPE","admin":admin,"expected_sids":[a,b],"ancestors":ancestors,"fixture_acl":acl_audits,"service_a":ready,"service_b":attacker,"final":final_report,"attempts":tuples.len(),"exact_access_denied":tuples.iter().filter(|case| case.2 == 5).count(),"crash_recovery":"DEFERRED_NOT_ATTEMPTED","ipc_authentication":ipc_server,"symlink_reparse_matrix":"DEFERRED"}),
        )
    })();
    // Always attempt every owned registration; do not remove files if any process may remain.
    let mut cleanup_errors = Vec::new();
    let mut stopped = true;
    for service in &services {
        if let Err(e) = stop(service, Instant::now() + Duration::from_secs(15)) {
            cleanup_errors.push(e.to_string());
            stopped = false;
        }
        // SAFETY: retained handle exists only for a registration created in this invocation.
        if unsafe { DeleteService(service.0) } == 0 {
            cleanup_errors.push(io::Error::last_os_error().to_string());
        }
    }
    for process in &processes {
        // SAFETY: wait on owned pinned process object, never a recyclable numeric PID.
        if unsafe { WaitForSingleObject(process.0, 15000) } != WAIT_OBJECT_0 {
            cleanup_errors.push("tracked service process did not exit within 15s".to_string());
            stopped = false;
        }
    }
    drop(processes);
    let created_count = services.len();
    drop(services);
    for name in names.iter().take(created_count) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            // SAFETY: verify deletion of only the exact unique registration we created.
            let remaining =
                unsafe { OpenServiceW(manager.0, wide(name).as_ptr(), SERVICE_QUERY_STATUS) };
            let error = unsafe { GetLastError() };
            if remaining.is_null() && error == ERROR_SERVICE_DOES_NOT_EXIST {
                break;
            }
            if !remaining.is_null() {
                drop(ScHandle(remaining));
            }
            if Instant::now() >= deadline {
                cleanup_errors.push(format!(
                    "registration deletion unconfirmed: {name}, Win32 {error}"
                ));
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
    drop(manager);
    // Retain diagnostic evidence even if track() saw an already-failed service
    // before read_report() could surface its error.json. Capture before cleanup
    // deletes the fixture, including the raw owner-forgery syscall result.
    if created_root {
        for (role, name) in [
            ("a", "error.json"),
            ("b", "error.json"),
            ("b", "ipc-owner-attempt.json"),
            ("a", "ipc-admin.json"),
            ("a", "ipc.json"),
        ] {
            let key = format!("receipt_{role}_{name}");
            match fs::read(root.join(format!("result-{role}")).join(name)) {
                Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                    Ok(value) => observations[&key] = value,
                    Err(error) => cleanup_errors.push(format!("invalid diagnostic {key}: {error}")),
                },
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    observations[&key] = json!({"status":"NOT_WRITTEN"});
                }
                Err(error) => cleanup_errors.push(format!("read diagnostic {key}: {error}")),
            }
        }
    }
    if created_root && stopped {
        if let Err(e) = fs::remove_dir_all(&root) {
            cleanup_errors.push(e.to_string());
        }
    }
    let success = proof.is_ok() && cleanup_errors.is_empty();
    let report = match proof {
        Ok(proof) => {
            json!({"status":if success {"BOUNDED_SCOPE_COMPLETED"} else {"FAILED_CLEANUP"},"proof":proof})
        }
        Err(error) => json!({"status":"FAILED_OR_BLOCKED","error":error.to_string()}),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"report":report,"observations":observations,"fixture":root,"services":names,"cleanup_errors":cleanup_errors,"full_windows_security_proof":false,"production_broker_supported":false})
        )?
    );
    ensure(success, "probe or cleanup failed; see JSON receipt")
}
