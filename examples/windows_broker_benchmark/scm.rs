//! Bounded benchmark-owned SCM adapter. No broker implementation or C lifecycle
//! authority: production provisioning admits C receipts before read-only tracking.
//! All mutation requires the hosted consent gate plus a nonimpersonating native
//! administrator token. Failed fixtures remain for disposable-VM evidence.
pub fn valid_name(name: &str) -> bool {
    name.starts_with("HMVBenchmark-")
        && !name.ends_with('-')
        && name.len() > 13
        && name.len() <= 80
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
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

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
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
fn broker_name(nonce: &str, case: &str) -> Result<String> {
    ensure(
        !case.is_empty() && case.len() <= 12 && case.bytes().all(|b| b.is_ascii_alphanumeric()),
        "invalid broker case",
    )?;
    let name = format!("HMVBenchmark-{nonce}-{case}-C");
    ensure(valid_name(&name), "broker name too long")?;
    Ok(name)
}
fn planned_service_sid(name: &str) -> Result<String> {
    ensure(valid_name(name), "invalid planned service name")?;
    let mut name = wide(name);
    let unicode = UNICODE_STRING {
        Length: ((name.len() - 1) * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: name.as_mut_ptr(),
    };
    let mut sid = [0u32; 17];
    let mut bytes = size_of_val(&sid) as u32;
    // SAFETY: validated bounded UTF-16 string and aligned buffer with actual byte
    // capacity. Like production provisioning, derive without registration/lookup.
    unsafe {
        let status = windows_sys::Wdk::Storage::FileSystem::RtlCreateServiceSid(
            &unicode,
            sid.as_mut_ptr().cast(),
            &mut bytes,
        );
        if status < 0 {
            return Err(io::Error::from_raw_os_error(RtlNtStatusToDosError(status) as i32).into());
        }
        ensure(bytes == 32, "unexpected service SID extent")?;
        let text = sid_text(sid.as_mut_ptr().cast())?;
        ensure(
            text.starts_with("S-1-5-80-") && text.split('-').count() == 9,
            "not a virtual service SID",
        )?;
        Ok(text)
    }
}
fn root_grants(client_sid: &str, broker_sid: &str) -> Result<String> {
    ensure(client_sid != broker_sid, "service and client overlap")?;
    // C only needs to inspect this ancestor and traverse it; do not inherit this
    // grant onto B/controller artifacts. Production owns the install-small ACLs.
    // CreateFileW adds SYNCHRONIZE to the explicit ancestor-audit access request.
    let audit = READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE;
    Ok(format!(
        "(A;OICI;FRFX;;;{client_sid})(A;;0x{audit:x};;;{broker_sid})"
    ))
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
fn audit_dir(
    path: &Path,
    writers: &[&str],
    readers: &[&str],
    ancestor: bool,
) -> Result<(Handle, Value)> {
    // SAFETY: open no-follow directory handle; sharing allows only trusted mutations after validation.
    let h = handle(unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
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
                    !applies || trusted(&sid) || !namespace_mutation(ace.Mask, true)
                } else {
                    fixture_ace_allowed(
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
        Ok((
            h,
            json!({"path":path,"owner":owner,"control":control,"aces":entries,"volume_serial":info.dwVolumeSerialNumber,"file_index":[info.nFileIndexHigh,info.nFileIndexLow]}),
        ))
    }
}
fn fixture_volume() -> Result<(PathBuf, Vec<(Handle, Value)>)> {
    let raw = String::from(r"C:\");
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
        after.dwCurrentState == SERVICE_RUNNING && after.dwProcessId == before.dwProcessId
            // SAFETY: pinned process with SYNCHRONIZE, zero-time nonblocking wait.
            && unsafe { WaitForSingleObject(process.0, 0) } == WAIT_TIMEOUT,
        "SCM status changed during tracking",
    )?;
    Ok((
        process,
        json!({"scm_pid":before.dwProcessId,"token":id,"use":"exit-wait-only-not-IPC-authentication"}),
    ))
}
fn stop(service: &ScHandle, deadline: Instant) -> Result<()> {
    let mut current = query(service)?;
    if current.dwCurrentState != SERVICE_STOPPED && current.dwCurrentState != SERVICE_STOP_PENDING {
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

fn namespace_mutation(mask: u32, ancestor: bool) -> bool {
    let replacement = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;
    let forbidden = if ancestor {
        replacement
    } else {
        replacement | 0x2 | 0x4 | 0x10 | 0x100
    };
    mask & forbidden != 0
}

fn fixture_ace_allowed(trusted: bool, writer: bool, reader: bool, mask: u32) -> bool {
    trusted || writer || (reader && !namespace_mutation(mask, false))
}

/// Reject *any* thread token, including disabled/identification impersonation.
fn no_impersonation() -> Result<()> {
    let mut raw = null_mut();
    // SAFETY: borrowed current thread pseudo-handle and initialized output.
    let ok = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) };
    if ok != 0 {
        drop(handle(raw)?);
        return Err("thread impersonation is forbidden".into());
    }
    // SAFETY: captured immediately after failed OpenThreadToken.
    ensure(
        unsafe { GetLastError() } == ERROR_NO_TOKEN,
        "thread token query failed",
    )
}

/// Read-only native admission, not an auto-elevation operation.
pub fn administrator() -> Result<Value> {
    no_impersonation()?;
    let id = identity()?;
    let enabled_admin = id["groups"]
        .as_array()
        .ok_or("missing token groups")?
        .iter()
        .any(|g| {
            g["sid"] == "S-1-5-32-544" && g["attributes"].as_u64().is_some_and(|v| v & 4 != 0)
        });
    ensure(
        id["elevated"] == true && enabled_admin,
        "elevated Administrators token required",
    )?;
    Ok(id)
}
fn client_identity(id: &Value, sid: &str) -> Result<()> {
    ensure(
        id["user"] == sid && id["elevated"] == false,
        "client TokenUser/elevation mismatch",
    )?;
    let groups = id["groups"].as_array().ok_or("missing token groups")?;
    ensure(
        !groups.iter().any(|g| {
            g["sid"] == "S-1-5-32-544" && g["attributes"].as_u64().is_none_or(|v| v & 4 != 0)
        }),
        "client has enabled administrator group",
    )?;
    let privileges = id["privileges"].as_array().ok_or("missing privileges")?;
    ensure(
        privileges.len() == 1 && privileges[0]["name"] == "SeChangeNotifyPrivilege",
        "unexpected installed client privilege",
    )
}
fn valid_root(root: &Path) -> bool {
    let Some(text) = root.to_str() else {
        return false;
    };
    let Some(nonce) = text.strip_prefix(r"C:\HMVBench_") else {
        return false;
    };
    !nonce.is_empty() && nonce.len() <= 48 && nonce.bytes().all(|b| b.is_ascii_digit() || b == b'-')
}
fn bound(timeout: Duration) -> Result<u32> {
    ensure(
        !timeout.is_zero() && timeout <= Duration::from_secs(30),
        "timeout must be in (0,30s]",
    )?;
    Ok(timeout.as_nanos().div_ceil(1_000_000) as u32)
}

/// An owned namespace/registration. Dropping only closes handles; failures retain
/// evidence for VM disposal. The controller must explicitly stop/delete B.
pub struct Fixture {
    root: PathBuf,
    nonce: String,
    name: String,
    sid: String,
    service: Option<ScHandle>,
    process: Option<Handle>,
    _pins: Vec<Handle>,
    audits: Vec<Value>,
}
impl Fixture {
    pub fn create(allow: bool, reviewed: bool) -> Result<Self> {
        super::policy::hosted_gate(allow, reviewed, &std::env::vars().collect())?;
        administrator()?;
        let (parent, audited) = fixture_volume()?;
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        );
        let root = parent.join(format!("HMVBench_{nonce}"));
        let name = format!("HMVBenchmark-{nonce}-B");
        ensure(
            valid_name(&name) && valid_root(&root),
            "invalid generated namespace",
        )?;
        let broker_sid = planned_service_sid(&broker_name(&nonce, "small")?)?;
        let exe = root.join("bin/benchmark.exe");
        let command = format!(
            "\"{}\" --service-client {} \"{}\"",
            exe.display(),
            name,
            root.display()
        );
        // SAFETY: local SCM, no enumeration, terminated strings live during calls.
        let manager = sc(unsafe {
            OpenSCManagerW(
                null(),
                null(),
                SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
            )
        })?;
        let service = sc(unsafe {
            CreateServiceW(
                manager.0,
                wide(&name).as_ptr(),
                wide(&name).as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                wide(&command).as_ptr(),
                null(),
                null_mut(),
                null(),
                wide(format!("NT SERVICE\\{name}")).as_ptr(),
                null(),
            )
        })?;
        let namespace = (|| -> Result<(String, Vec<Handle>, Vec<Value>)> {
            // Registration precedes LookupAccountNameW: unregistered names need not resolve.
            let sid = service_sid(&name)?;
            let rx = format!("(A;OICI;FRFX;;;{sid})");
            // Atomic creation WITH protected DACL; never adopt an existing directory.
            mkdir(&root, &root_grants(&sid, &broker_sid)?)?;
            let mut pins = Vec::new();
            let mut audits = Vec::new();
            for (pin, audit) in audited {
                pins.push(pin);
                audits.push(audit);
            }
            let writer_acl = format!("(A;OICI;FA;;;{sid})");
            let principal = [sid.as_str()];
            let root_readers = [sid.as_str(), broker_sid.as_str()];
            for (path, writable) in [
                (&root, false),
                (&root.join("bin"), false),
                (&root.join("scratch"), true),
            ] {
                if path != &root {
                    mkdir(path, if writable { &writer_acl } else { &rx })?;
                }
                let (pin, audit) = audit_dir(
                    path,
                    if writable { &principal } else { &[] },
                    if writable {
                        &[]
                    } else if path == &root {
                        &root_readers
                    } else {
                        &principal
                    },
                    false,
                )?;
                pins.push(pin);
                audits.push(audit);
            }
            // Source ACLs are NOT copied. Fresh destination inherits root/bin policy.
            let source = std::env::current_exe()?;
            let mut input = fs::File::open(source)?;
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&exe)?;
            io::copy(&mut input, &mut output)?;
            output.sync_all()?;
            drop(output);
            Ok((sid, pins, audits))
        })();
        let (sid, pins, audits) = match namespace {
            Ok(value) => value,
            Err(error) => {
                // SAFETY: this invocation created the never-started service.
                let removed = unsafe { DeleteService(service.0) };
                return Err(format!(
                    "namespace {} ({}): {error}; fresh B deletion requested={}",
                    root.display(),
                    name,
                    removed != 0
                )
                .into());
            }
        };
        // Creation failure never opens/adopts existing service. On config failure
        // remove only this fresh registration (never started), retaining files.
        let configured = (|| -> Result<()> {
            restrict_privileges(&service)?;
            let sd = descriptor("O:BAG:BAD:P(A;;0xf01ff;;;SY)(A;;0xf01ff;;;BA)")?;
            let info = SERVICE_SID_INFO {
                dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
            };
            // SAFETY: retained fresh service and live descriptor/config structures.
            unsafe {
                win(SetServiceObjectSecurity(
                    service.0,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    sd.0,
                ))?;
                win(ChangeServiceConfig2W(
                    service.0,
                    SERVICE_CONFIG_SERVICE_SID_INFO,
                    (&info as *const SERVICE_SID_INFO).cast(),
                ))?;
            }
            Ok(())
        })();
        if let Err(error) = configured {
            // SAFETY: only freshly created never-started registration.
            let removed = unsafe { DeleteService(service.0) };
            return Err(format!(
                "configure B {} ({}): {error}; registration deletion requested={}",
                name,
                root.display(),
                removed != 0
            )
            .into());
        }
        Ok(Self {
            root,
            nonce,
            name,
            sid,
            service: Some(service),
            process: None,
            _pins: pins,
            audits,
        })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn client_name(&self) -> &str {
        &self.name
    }
    pub fn client_sid(&self) -> &str {
        &self.sid
    }
    pub fn broker_name(&self, case: &str) -> Result<String> {
        broker_name(&self.nonce, case)
    }
    fn service(&self) -> Result<&ScHandle> {
        self.service
            .as_ref()
            .ok_or_else(|| "B registration already deleted".into())
    }
    pub fn start_client(&mut self) -> Result<Value> {
        administrator()?;
        ensure(self.process.is_none(), "B may only start once per fixture")?;
        let service = self.service()?;
        ensure(
            query(service)?.dwCurrentState == SERVICE_STOPPED,
            "B not stopped",
        )?;
        // SAFETY: retained freshly created service; no caller-controlled start args.
        win(unsafe { StartServiceW(service.0, 0, null()) })?;
        let (process, observation) = track(service, &self.sid)?;
        // Retain handle before any further checks that could fail.
        self.process = Some(process);
        client_identity(&observation["token"], &self.sid)?;
        Ok(observation)
    }
    pub fn observe_client(&self) -> Result<Value> {
        let s = query(self.service()?)?;
        Ok(
            json!({"name":self.name,"sid":self.sid,"scm_state":s.dwCurrentState,"scm_pid":s.dwProcessId,"scm_exit_code":s.dwWin32ExitCode,"process":process_observation(self.process.as_ref())?,"fixture_acl":self.audits}),
        )
    }
    pub fn stop_client(&mut self) -> Result<Value> {
        administrator()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        let stopped = stop(self.service()?, deadline);
        // One shared deadline, including the pinned process wait.
        let remaining = deadline.saturating_duration_since(Instant::now());
        let exited = wait_process(
            self.process.as_ref(),
            remaining.max(Duration::from_millis(1)),
        );
        stopped?;
        exited?;
        self.observe_client()
    }
    pub fn delete_client(&mut self) -> Result<()> {
        administrator()?;
        ensure(
            query(self.service()?)?.dwCurrentState == SERVICE_STOPPED,
            "refuse deletion while B active",
        )?;
        if let Some(p) = &self.process {
            // SAFETY: retained process, never recyclable numeric PID.
            ensure(
                unsafe { WaitForSingleObject(p.0, 0) } == WAIT_OBJECT_0,
                "B process still active",
            )?;
        }
        // SAFETY: only retained fresh registration. No files are deleted.
        win(unsafe { DeleteService(self.service()?.0) })?;
        self.service.take();
        Ok(())
    }
    /// C is created/controlled ONLY by the production administrator helper.
    /// Its full receipt, namespace, hashes, service config and token admission
    /// run before this adapter opens any read-only SCM observation handle.
    #[cfg(feature = "experimental-broker")]
    pub fn observe_broker(&self, receipt: &Path, case: &str) -> Result<ObservedService> {
        administrator()?;
        let expected = self.broker_name(case)?;
        let admission = hermes_memory::windows_provision::status(receipt, true)?;
        ensure(
            admission["service_name"] == expected,
            "receipt does not own this fixture's C",
        )?;
        let mut receipt_pin =
            hermes_memory::windows_enrollment::open_admin_owned_file(receipt, 65536)?;
        let r: Value = serde_json::from_reader(&mut receipt_pin)?;
        ensure(
            r["plan"]["service_name"] == expected && r["plan"]["client_sid"] == self.sid,
            "receipt changed or belongs to another B",
        )?;
        let command = r["command"].as_str().ok_or("missing owned command")?;
        let sid = service_sid(&expected)?;
        ensure(r["server_sid"] == sid, "receipt SID mismatch")?;
        // SAFETY: only exact receipt-bound fixture name; observation rights only.
        let manager = sc(unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) })?;
        let service = sc(unsafe {
            OpenServiceW(
                manager.0,
                wide(&expected).as_ptr(),
                SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
            )
        })?;
        validate_config(&service, &expected, command)?;
        // Re-run full production admission after pinning our service handle.
        ensure(
            hermes_memory::windows_provision::status(receipt, true)?["service_name"] == expected,
            "receipt changed during observation",
        )?;
        let state = query(&service)?;
        let (process, token) = if state.dwCurrentState == SERVICE_RUNNING {
            let (p, id) = track(&service, &sid)?;
            (Some(p), id)
        } else {
            ensure(
                state.dwCurrentState == SERVICE_STOPPED && state.dwProcessId == 0,
                "C transitional; retry after helper settles",
            )?;
            (None, Value::Null)
        };
        Ok(ObservedService {
            service,
            process,
            name: expected,
            token,
            _receipt: Box::new(receipt_pin),
        })
    }
}
fn process_observation(process: Option<&Handle>) -> Result<Value> {
    let Some(p) = process else {
        return Ok(Value::Null);
    };
    // SAFETY: retained process with QUERY_LIMITED_INFORMATION and SYNCHRONIZE.
    let wait = unsafe { WaitForSingleObject(p.0, 0) };
    ensure(
        matches!(wait, WAIT_TIMEOUT | WAIT_OBJECT_0),
        "process wait failed",
    )?;
    let mut code = 0;
    win(unsafe { GetExitCodeProcess(p.0, &mut code) })?;
    Ok(
        json!({"exited":wait == WAIT_OBJECT_0,"exit_code":code,"token":if wait == WAIT_TIMEOUT { identity_of(p.0)? } else { Value::Null }}),
    )
}
fn wait_process(process: Option<&Handle>, timeout: Duration) -> Result<Value> {
    let ms = bound(timeout)?;
    if let Some(p) = process {
        // SAFETY: bounded wait on the retained object, no process termination.
        ensure(
            unsafe { WaitForSingleObject(p.0, ms) } == WAIT_OBJECT_0,
            "process exit deadline expired; VM disposal required",
        )?;
    }
    process_observation(process)
}
pub struct ObservedService {
    service: ScHandle,
    process: Option<Handle>,
    name: String,
    token: Value,
    _receipt: Box<dyn io::Read>,
}
impl ObservedService {
    pub fn observation(&self) -> Result<Value> {
        let state = query(&self.service)?;
        Ok(
            json!({"name":self.name,"scm_state":state.dwCurrentState,"scm_pid":state.dwProcessId,"scm_exit_code":state.dwWin32ExitCode,"initial_identity":self.token,"pinned_process":process_observation(self.process.as_ref())?}),
        )
    }
    pub fn wait_exit(&self, timeout: Duration) -> Result<Value> {
        ensure(self.process.is_some(), "no running C process was pinned")?;
        wait_process(self.process.as_ref(), timeout)
    }
}

type ClientWork = fn(&Path) -> Result<()>;
static CONTEXT: OnceLock<(String, PathBuf, ClientWork)> = OnceLock::new();
static STOP: AtomicBool = AtomicBool::new(false);
pub fn stop_requested() -> bool {
    STOP.load(Ordering::Acquire)
}
unsafe extern "system" fn control(code: u32) {
    if code == SERVICE_CONTROL_STOP {
        STOP.store(true, Ordering::Release);
    }
}
fn service_status(h: SERVICE_STATUS_HANDLE, state: u32, error: u32) -> Result<()> {
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
    // SAFETY: live callback registration and initialized status structure.
    win(unsafe { SetServiceStatus(h, &status) })
}
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let result = std::panic::catch_unwind(|| -> Result<()> {
        let (name, root, worker) = CONTEXT.get().ok_or("missing client context")?;
        // SAFETY: stable name/static callback; SCM invokes service_main, not CLI.
        let h = unsafe { RegisterServiceCtrlHandlerW(wide(name).as_ptr(), Some(control)) };
        ensure(!h.is_null(), "control registration failed")?;
        let work = (|| -> Result<()> {
            no_impersonation()?;
            client_identity(&identity()?, &service_sid(name)?)?;
            service_status(h, SERVICE_RUNNING, 0)?;
            // Lease watchdog can exit ONLY this own virtual-account process. It
            // never obtains/terminates another process, nor kills by numeric PID.
            thread::spawn(|| {
                let end = Instant::now() + Duration::from_secs(600);
                let mut stopping = None;
                loop {
                    if stop_requested() {
                        stopping.get_or_insert_with(Instant::now);
                    }
                    if Instant::now() >= end
                        || stopping.is_some_and(|s: Instant| s.elapsed() >= Duration::from_secs(25))
                    {
                        std::process::exit(1);
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            });
            worker(root)?;
            // Keep identity/process observable even if worker completes quickly.
            while !stop_requested() {
                thread::sleep(Duration::from_millis(50));
            }
            Ok(())
        })();
        if let Err(error) = &work {
            eprintln!("benchmark B: {error}");
        }
        service_status(
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
/// A console invocation cannot execute the worker: dispatcher must connect to SCM
/// and service_main additionally verifies exact virtual-account identity.
pub fn dispatch_client(name: &str, root: &Path, worker: ClientWork) -> Result<()> {
    ensure(
        valid_name(name) && name.ends_with("-B") && valid_root(root),
        "invalid private client invocation",
    )?;
    let nonce = root
        .to_str()
        .ok_or("root encoding")?
        .strip_prefix(r"C:\HMVBench_")
        .ok_or("root prefix")?;
    ensure(
        name == format!("HMVBenchmark-{nonce}-B"),
        "client/root namespace mismatch",
    )?;
    CONTEXT
        .set((name.to_owned(), root.to_owned(), worker))
        .map_err(|_| "duplicate service dispatch")?;
    let mut name = wide(name);
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
    // SAFETY: table/name remain live through blocking dispatcher. Ordinary local
    // console calls fail ERROR_FAILED_SERVICE_CONTROLLER_CONNECT before worker.
    win(unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) })
}

fn native_string(raw: *const u16, buffer: &[usize]) -> Result<String> {
    let start = buffer.as_ptr() as usize;
    let end = start + std::mem::size_of_val(buffer);
    let address = raw as usize;
    ensure(
        address >= start && address < end && address.is_multiple_of(2),
        "SCM string outside buffer",
    )?;
    // SAFETY: query-produced pointer bounded to live allocation before reading.
    let slice = unsafe { std::slice::from_raw_parts(raw, (end - address) / 2) };
    let n = slice
        .iter()
        .position(|v| *v == 0)
        .ok_or("unterminated SCM string")?;
    String::from_utf16(&slice[..n]).map_err(|e| e.into())
}

fn configuration_matches(
    binary: &str,
    account: &str,
    kind: u32,
    start: u32,
    expected: &str,
    expected_account: &str,
) -> bool {
    binary == expected
        && account == expected_account
        && kind == SERVICE_WIN32_OWN_PROCESS
        && start == SERVICE_DEMAND_START
}
fn validate_config(service: &ScHandle, name: &str, command: &str) -> Result<()> {
    let mut needed = 0;
    // SAFETY: first call sizes the native configuration buffer.
    unsafe {
        QueryServiceConfigW(service.0, null_mut(), 0, &mut needed);
    }
    ensure(
        needed as usize >= std::mem::size_of::<QUERY_SERVICE_CONFIGW>() && needed <= 65536,
        "SCM config size",
    )?;
    let mut buf = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: aligned adequately sized buffer, all interior strings checked below.
    unsafe {
        win(QueryServiceConfigW(
            service.0,
            buf.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ))?;
        let c = &*buf.as_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        ensure(
            configuration_matches(
                &native_string(c.lpBinaryPathName, &buf)?,
                &native_string(c.lpServiceStartName, &buf)?,
                c.dwServiceType,
                c.dwStartType,
                command,
                &format!("NT SERVICE\\{}", name),
            ),
            "registered service ownership mismatch",
        )?;
        ensure(
            c.dwErrorControl == SERVICE_ERROR_NORMAL
                && native_string(c.lpDependencies, &buf)?.is_empty(),
            "service policy mismatch",
        )?;
        let mut sid = SERVICE_SID_INFO::default();
        win(QueryServiceConfig2W(
            service.0,
            SERVICE_CONFIG_SERVICE_SID_INFO,
            (&mut sid as *mut SERVICE_SID_INFO).cast(),
            std::mem::size_of_val(&sid) as u32,
            &mut needed,
        ))?;
        ensure(
            sid.dwServiceSidType == SERVICE_SID_TYPE_UNRESTRICTED,
            "service SID policy mismatch",
        )?;
        QueryServiceConfig2W(
            service.0,
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            null_mut(),
            0,
            &mut needed,
        );
        ensure(
            needed >= std::mem::size_of::<SERVICE_REQUIRED_PRIVILEGES_INFOW>() as u32
                && needed <= 65536,
            "privilege config size",
        )?;
        let mut b = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
        win(QueryServiceConfig2W(
            service.0,
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            b.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ))?;
        let p = (*b.as_ptr().cast::<SERVICE_REQUIRED_PRIVILEGES_INFOW>()).pmszRequiredPrivileges;
        let name = native_string(p, &b)?;
        ensure(
            name == "SeChangeNotifyPrivilege"
                && native_string(p.add(name.encode_utf16().count() + 1), &b)?.is_empty(),
            "required privileges differ",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn planned_sid(name: &str) -> String {
        let mut name = wide(name);
        let unicode = UNICODE_STRING {
            Length: ((name.len() - 1) * 2) as u16,
            MaximumLength: (name.len() * 2) as u16,
            Buffer: name.as_mut_ptr(),
        };
        let mut sid = [0u32; 17];
        let mut bytes = size_of_val(&sid) as u32;
        // SAFETY: bounded live UTF-16 string and aligned output buffer; no SCM operations.
        unsafe {
            assert_eq!(
                windows_sys::Wdk::Storage::FileSystem::RtlCreateServiceSid(
                    &unicode,
                    sid.as_mut_ptr().cast(),
                    &mut bytes
                ),
                0
            );
            assert_eq!(bytes, 32);
            sid_text(sid.as_mut_ptr().cast()).unwrap()
        }
    }

    fn parsed_grants(extra: &str) -> Vec<(String, u32, u8)> {
        let sd = descriptor(&format!(
            "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA){extra}"
        ))
        .unwrap();
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = null_mut();
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: native parsed descriptor retained throughout inspection; ACE pointers belong to it.
        unsafe {
            win(GetSecurityDescriptorControl(
                sd.0,
                &mut control,
                &mut revision,
            ))
            .unwrap();
            assert_ne!(control & SE_DACL_PROTECTED, 0);
            win(GetSecurityDescriptorDacl(
                sd.0,
                &mut present,
                &mut acl,
                &mut defaulted,
            ))
            .unwrap();
            assert_ne!(present, 0);
            assert!(!acl.is_null());
            (0..(*acl).AceCount)
                .map(|index| {
                    let mut raw = null_mut();
                    win(GetAce(acl, index as u32, &mut raw)).unwrap();
                    let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
                    assert_eq!(ace.Header.AceType, 0);
                    (
                        sid_text((&ace.SidStart as *const u32).cast_mut().cast()).unwrap(),
                        ace.Mask,
                        ace.Header.AceFlags,
                    )
                })
                .collect()
        }
    }

    #[test]
    fn createfile_ancestor_open_adds_synchronize_access() {
        #[repr(C)]
        #[derive(Default)]
        struct ObjectBasicInformation {
            attributes: u32,
            granted_access: u32,
            handle_count: u32,
            pointer_count: u32,
            reserved: [u32; 10],
        }
        #[link(name = "ntdll")]
        extern "system" {
            fn NtQueryObject(
                handle: HANDLE,
                class: i32,
                information: *mut c_void,
                length: u32,
                returned: *mut u32,
            ) -> i32;
        }
        // Read-only existing directory, same access/flags as ancestor admission:
        // no fixture creation, service operations, or filesystem ACL mutation.
        let path = std::env::current_dir().unwrap();
        let requested = READ_CONTROL | FILE_READ_ATTRIBUTES;
        for extra_flags in [0, FILE_FLAG_OVERLAPPED] {
            // SAFETY: live terminated path, no output buffer, owned returned handle.
            let h = handle(unsafe {
                CreateFileW(
                    wide(&path).as_ptr(),
                    requested,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | extra_flags,
                    null_mut(),
                )
            })
            .unwrap();
            let mut info = ObjectBasicInformation::default();
            let mut returned = 0;
            // SAFETY: live handle, documented PUBLIC_OBJECT_BASIC_INFORMATION
            // layout for ObjectBasicInformation (0), correctly sized output.
            let status = unsafe {
                NtQueryObject(
                    h.0,
                    0,
                    (&mut info as *mut ObjectBasicInformation).cast(),
                    size_of::<ObjectBasicInformation>() as u32,
                    &mut returned,
                )
            };
            assert_eq!(status, 0);
            assert_eq!(info.granted_access, requested | SYNCHRONIZE);
        }
    }

    #[test]
    fn small_c_planned_ancestor_chain_has_native_audit_rights() {
        let nonce = "123-456";
        let b = planned_sid(&format!("HMVBenchmark-{nonce}-B"));
        let fixture = Fixture {
            root: PathBuf::from(r"C:\HMVBench_123-456"),
            nonce: nonce.into(),
            name: format!("HMVBenchmark-{nonce}-B"),
            sid: b.clone(),
            service: None,
            process: None,
            _pins: vec![],
            audits: vec![],
        };
        let c_name = fixture.broker_name("small").unwrap();
        assert_eq!(c_name, "HMVBenchmark-123-456-small-C");
        let c = planned_sid(&c_name);
        assert_ne!(b, c);
        assert_ne!(c, planned_sid("HMVBenchmark-123-457-small-C"));
        assert_eq!(planned_sid("TrustedInstaller"), TRUSTED_INSTALLER);
        assert_eq!(planned_service_sid(&c_name).unwrap(), c);
        assert!(root_grants(&b, &b).is_err());
        for invalid in ["", "Spooler", "HMVBenchmark-bad\0-C"] {
            assert!(planned_service_sid(invalid).is_err());
        }
        for invalid in ["", "../small", "small-C", "longerthan12chars"] {
            assert!(fixture.broker_name(invalid).is_err());
        }
        let needed = READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE;
        // Pure plan for every fixture-owned ancestor of production temp/store.
        // Volume-root access and actual C token admission remain the hosted CI gate.
        for (path, grants) in [
            (
                "outer",
                root_grants(
                    &b,
                    &planned_service_sid(&broker_name(nonce, "small").unwrap()).unwrap(),
                )
                .unwrap(),
            ),
            (
                "install-small",
                format!("(A;OICI;FRFX;;;{c})(A;OICI;FRFX;;;{b})"),
            ),
            ("install-small/temp", format!("(A;OICI;FA;;;{c})")),
            ("install-small/store", format!("(A;OICI;FA;;;{c})")),
        ] {
            let entries = parsed_grants(&grants);
            let c_entries: Vec<_> = entries.iter().filter(|(sid, _, _)| sid == &c).collect();
            assert_eq!(c_entries.len(), 1, "{path}: exact C grant missing");
            let (_, mask, flags) = c_entries[0];
            assert_eq!(mask & needed, needed, "{path}: C cannot audit/traverse");
            assert_eq!(u32::from(*flags) & INHERIT_ONLY_ACE, 0);
            if path == "outer" {
                assert_eq!(*mask, needed, "outer grant must be minimal");
                assert_eq!(*flags, 0, "C must not inherit access to B artifacts");
                assert_eq!(entries.len(), 4);
                let (_, b_mask, b_flags) = entries.iter().find(|(sid, _, _)| sid == &b).unwrap();
                assert_eq!(*b_mask, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE);
                assert_eq!(
                    u32::from(*b_flags),
                    OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
                );
                assert!(entries
                    .iter()
                    .all(|(sid, _, _)| trusted(sid) || sid == &b || sid == &c));
                assert!(!namespace_mutation(*mask, false));
                assert!(fixture_ace_allowed(false, false, true, *mask));
            }
        }
    }

    #[test]
    fn native_scm_strings_are_bounded_before_dereference() {
        let mut buffer = vec![0usize; 4];
        let raw = buffer.as_mut_ptr().cast::<u16>();
        // SAFETY: aligned live buffer has room for these UTF-16 code units.
        unsafe {
            *raw = b'x' as u16;
        }
        assert_eq!(native_string(raw, &buffer).unwrap(), "x");
        assert!(native_string(null(), &buffer).is_err());
        assert!(native_string((raw as usize + 1) as *const u16, &buffer).is_err());
        buffer.fill(usize::MAX);
        assert!(native_string(raw, &buffer).is_err());
    }

    #[test]
    fn timeout_rounds_up_and_rejects_unbounded_waits() {
        assert_eq!(bound(Duration::from_nanos(1_500_000)).unwrap(), 2);
        assert!(bound(Duration::ZERO).is_err());
        assert!(bound(Duration::from_secs(31)).is_err());
    }

    #[test]
    fn paths_masks_and_config_fail_closed() {
        assert!(valid_root(Path::new(r"C:\HMVBench_123-456")));
        for path in [
            r"C:\HMVBench_",
            r"C:\HMVBench_1\..\Windows",
            r"C:\HMVBench_1:ads",
            r"\\host\HMVBench_1",
            r"C:\HMVBench_1.",
        ] {
            assert!(!valid_root(Path::new(path)));
        }
        assert!(fixture_ace_allowed(
            false,
            false,
            true,
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
        ));
        for mask in [
            FILE_WRITE_DATA,
            FILE_APPEND_DATA,
            FILE_WRITE_EA,
            FILE_WRITE_ATTRIBUTES,
            FILE_DELETE_CHILD,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            GENERIC_ALL,
            GENERIC_WRITE,
        ] {
            assert!(!fixture_ace_allowed(false, false, true, mask));
        }
        assert!(configuration_matches(
            "cmd",
            "account",
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            "cmd",
            "account"
        ));
        assert!(!configuration_matches(
            "cmd injected",
            "account",
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            "cmd",
            "account"
        ));
        assert!(!configuration_matches(
            "cmd",
            "LocalSystem",
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_DEMAND_START,
            "cmd",
            "account"
        ));
        assert!(!configuration_matches(
            "cmd",
            "account",
            SERVICE_WIN32_SHARE_PROCESS,
            SERVICE_DEMAND_START,
            "cmd",
            "account"
        ));
    }

    #[test]
    fn readonly_native_identity_sid_and_descriptor() {
        no_impersonation().unwrap();
        let id = identity().unwrap();
        assert!(id["user"].as_str().unwrap().starts_with("S-1-"));
        assert!(client_identity(&id, "S-1-5-80-0-0-0-0-0").is_err());
        if id["elevated"] == false {
            assert!(administrator().is_err());
        }
        let sid = service_sid("TrustedInstaller").unwrap();
        assert_eq!(sid, TRUSTED_INSTALLER);
        let sd = descriptor(&format!(
            "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;{sid})"
        ))
        .unwrap();
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = null_mut();
        // SAFETY: descriptor remains live, API outputs point into it.
        unsafe {
            win(GetSecurityDescriptorDacl(
                sd.0,
                &mut present,
                &mut acl,
                &mut defaulted,
            ))
            .unwrap();
            assert_ne!(present, 0);
            assert!(!acl.is_null());
            assert_eq!((*acl).AceCount, 3);
        }
        // Real read-only process handle can be observed without administrator rights.
        let process = handle(unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | 0x00100000,
                0,
                GetCurrentProcessId(),
            )
        })
        .unwrap();
        assert_eq!(
            process_observation(Some(&process)).unwrap()["exited"],
            false
        );
        assert!(wait_process(Some(&process), Duration::from_millis(1)).is_err());
    }

    #[test]
    fn native_self_impersonation_is_rejected_and_reverted() {
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                unsafe {
                    RevertToSelf();
                }
            }
        }
        // SAFETY: impersonates only this same process on this test thread; no
        // privilege acquisition; RAII restores thread even on assertion panic.
        win(unsafe { ImpersonateSelf(SecurityImpersonation) }).unwrap();
        let guard = Revert;
        assert!(no_impersonation().is_err());
        assert!(administrator().is_err());
        drop(guard);
        no_impersonation().unwrap();
    }

    #[test]
    fn console_dispatch_never_executes_worker_or_creates_fixture() {
        fn forbidden(_: &Path) -> Result<()> {
            panic!("console entered worker")
        }
        assert!(Fixture::create(false, false).is_err());
        assert!(dispatch_client("Spooler", Path::new(r"C:\HMVBench_1-2"), forbidden).is_err());
        let error = dispatch_client(
            "HMVBenchmark-1-2-B",
            Path::new(r"C:\HMVBench_1-2"),
            forbidden,
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT as i32)
        );
    }

    #[test]
    fn source_has_no_arbitrary_kill_broker_or_service_adoption() {
        let source = include_str!("scm.rs");
        for forbidden in [
            ["Terminate", "Process("].concat(),
            ["Command::", "new("].concat(),
            ["MemoryStore", "::"].concat(),
            ["PROCESS_", "TERMINATE"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "forbidden capability {forbidden}"
            );
        }
        let observe = source.split("\n    pub fn observe_broker(").nth(1).unwrap();
        assert!(
            observe.find("windows_provision::status").unwrap()
                < observe.find("OpenServiceW").unwrap()
        );
        assert!(observe.contains("SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG"));
    }

    #[test]
    fn private_namespace_is_bounded_and_cannot_name_existing_system_services() {
        assert!(super::valid_name("HMVBenchmark-123-456-B"));
        for bad in [
            "",
            "Spooler",
            "HMVBenchmark-",
            "HMVBenchmark-a-",
            "HMVBenchmark-a b",
            "HMVBenchmark-a\"b",
        ] {
            assert!(!super::valid_name(bad));
        }
        assert!(!super::valid_name(&format!(
            "HMVBenchmark-{}",
            "x".repeat(81)
        )));
    }
}
