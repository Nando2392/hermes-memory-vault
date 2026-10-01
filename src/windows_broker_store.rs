//! Admission for preprovisioned Windows broker storage; never repairs ACLs.
use crate::MemoryError;
use std::{
    ffi::c_void,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::Threading::*,
};

fn win(ok: i32) -> Result<(), MemoryError> {
    if ok != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: allocation returned by a LocalAlloc-backed security API.
        unsafe {
            LocalFree(self.0);
        }
    }
}

// SAFETY: SID must be valid and backed by a live token or security descriptor.
unsafe fn sid_text(sid: PSID) -> Result<String, MemoryError> {
    require(
        !sid.is_null() && unsafe { IsValidSid(sid) } != 0,
        "invalid SID",
    )?;
    let mut text = null_mut();
    win(unsafe { ConvertSidToStringSidW(sid, &mut text) })?;
    let _allocation = Local(text.cast());
    let mut len = 0;
    while unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(text, len)
    }))
}

fn token_info(
    token: &OwnedHandle,
    class: TOKEN_INFORMATION_CLASS,
) -> Result<Vec<usize>, MemoryError> {
    let mut size = 0;
    // SAFETY: sizing query and aligned output allocation kept alive by the caller.
    unsafe {
        GetTokenInformation(token.as_raw_handle(), class, null_mut(), 0, &mut size);
    }
    require(size > 0 && size <= 65536, "invalid token information size")?;
    let mut data = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
    win(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            data.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    })?;
    Ok(data)
}

pub(super) fn virtual_user(sid: &str) -> bool {
    let Some(tail) = sid.strip_prefix("S-1-5-80-") else {
        return false;
    };
    tail.split('-').count() == 5
        && tail.split('-').all(|part| {
            part.parse::<u32>()
                .is_ok_and(|value| value.to_string() == part)
        })
}

pub(super) fn service_identity() -> Result<String, MemoryError> {
    let mut raw = null_mut();
    // SAFETY: pseudo handles are borrowed; output handle becomes uniquely owned.
    unsafe {
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) != 0 {
            let _thread = OwnedHandle::from_raw_handle(raw);
            return require(false, "broker storage refuses impersonation").map(|()| String::new());
        }
        require(
            GetLastError() == ERROR_NO_TOKEN,
            "cannot inspect thread identity",
        )?;
        win(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw))?;
    }
    // SAFETY: OpenProcessToken succeeded and transferred ownership.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let user = token_info(&token, TokenUser)?;
    let elevation = token_info(&token, TokenElevation)?;
    // SAFETY: buffers contain aligned structures requested from the kernel.
    let sid = unsafe { sid_text((*user.as_ptr().cast::<TOKEN_USER>()).User.Sid)? };
    let elevated = unsafe { (*elevation.as_ptr().cast::<TOKEN_ELEVATION>()).TokenIsElevated != 0 };
    require(
        virtual_user(sid.as_str()) && !elevated,
        "broker requires non-elevated SCM virtual TokenUser",
    )?;
    let groups = token_info(&token, TokenGroups)?;
    let mut service_logon = false;
    // SAFETY: kernel supplied TOKEN_GROUPS and its array in the live aligned buffer.
    unsafe {
        let g = &*groups.as_ptr().cast::<TOKEN_GROUPS>();
        for item in std::slice::from_raw_parts(g.Groups.as_ptr(), g.GroupCount as usize) {
            let group = sid_text(item.Sid)?;
            require(
                group != "S-1-5-32-544",
                "administrator service token refused",
            )?;
            service_logon |= group == "S-1-5-6" && item.Attributes & 0x4 != 0; // SE_GROUP_ENABLED
        }
    }
    require(service_logon, "broker requires service logon")?;
    Ok(sid)
}

#[derive(Clone)]
pub(super) struct Ace {
    pub sid: String,
    pub mask: u32,
    pub flags: u8,
    pub kind: u8,
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum ObjectKind {
    Ancestor,
    Root,
    File,
}

pub(super) fn acl_allowed(
    owner: &str,
    protected: bool,
    aces: &[Ace],
    service: &str,
    kind: ObjectKind,
) -> bool {
    let trusted = |sid: &str| {
        sid == service
            || matches!(sid, "S-1-5-18" | "S-1-5-32-544")
            || (kind == ObjectKind::Ancestor
                && sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
    };
    trusted(owner)
        && (kind != ObjectKind::Root
            || (protected
                && aces
                    .iter()
                    .any(|ace| ace.sid == service && ace.mask == 0x1f01ff && ace.flags & 0xf == 3)))
        && !aces.is_empty()
        && aces.iter().all(|ace| {
            ace.kind == 0
                && ace.flags & !0x1f == 0
                && ace.mask & !0xf01f01ff == 0
                && (trusted(&ace.sid)
                    || (kind == ObjectKind::Ancestor
                        && (ace.flags & 0x8 != 0 || ace.mask & !0x1200af == 0)))
        })
}

pub(super) fn metadata_allowed(attributes: u32, links: u32, kind: ObjectKind) -> bool {
    attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_READONLY)
        == 0
        && (attributes & FILE_ATTRIBUTE_DIRECTORY != 0) == (kind != ObjectKind::File)
        && (kind != ObjectKind::File || links == 1)
}

pub(super) fn ace_sid_bounded(bytes: &[u8]) -> bool {
    bytes.len() >= 8
        && bytes[0] == 1
        && bytes[1] <= 15
        && bytes.len() == 8 + usize::from(bytes[1]) * 4
}

// SAFETY: descriptor must be a live OS-validated security descriptor.
pub(super) unsafe fn audit_descriptor(
    sd: PSECURITY_DESCRIPTOR,
    service: &str,
    kind: ObjectKind,
) -> Result<(), MemoryError> {
    // SAFETY: caller guarantees a live descriptor; each queried interior pointer stays within its lifetime.
    unsafe {
        require(
            !sd.is_null() && IsValidSecurityDescriptor(sd) != 0,
            "invalid descriptor",
        )?;
        let mut owner = null_mut();
        let mut defaulted = 0;
        win(GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted))?;
        let owner = sid_text(owner)?;
        let mut acl = null_mut();
        let mut present = 0;
        win(GetSecurityDescriptorDacl(
            sd,
            &mut present,
            &mut acl,
            &mut defaulted,
        ))?;
        require(
            present != 0 && !acl.is_null() && IsValidAcl(acl) != 0,
            "missing/null/invalid DACL",
        )?;
        let mut control = 0;
        let mut revision = 0;
        win(GetSecurityDescriptorControl(
            sd,
            &mut control,
            &mut revision,
        ))?;
        let mut aces = Vec::new();
        for index in 0..(*acl).AceCount {
            let mut raw = null_mut();
            win(GetAce(acl, u32::from(index), &mut raw))?;
            let header = &*raw.cast::<ACE_HEADER>();
            require(
                header.AceType == 0
                    && usize::from(header.AceSize) >= size_of::<ACCESS_ALLOWED_ACE>(),
                "unknown or malformed ACE",
            )?;
            let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
            let sid_bytes = std::slice::from_raw_parts(
                raw.cast::<u8>().add(8),
                usize::from(header.AceSize) - 8,
            );
            require(ace_sid_bounded(sid_bytes), "ACE SID exceeds its entry")?;
            let sid = (&ace.SidStart as *const u32).cast_mut().cast();
            require(
                IsValidSid(sid) != 0
                    && GetLengthSid(sid) as usize + 8 <= usize::from(header.AceSize),
                "invalid ACE SID",
            )?;
            aces.push(Ace {
                sid: sid_text(sid)?,
                mask: ace.Mask,
                flags: header.AceFlags,
                kind: header.AceType,
            });
        }
        require(
            acl_allowed(
                &owner,
                control & SE_DACL_PROTECTED != 0,
                &aces,
                service,
                kind,
            ),
            "untrusted broker ACL",
        )
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

pub(super) fn audit_path(
    path: &Path,
    service: &str,
    kind: ObjectKind,
) -> Result<OwnedHandle, MemoryError> {
    // SAFETY: NUL-terminated path; no inheritable handle, no reparse traversal at the leaf.
    let raw = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful CreateFileW transfers a unique handle.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    audit_handle(handle.as_raw_handle(), path, service, kind)?;
    Ok(handle)
}

fn audit_handle(
    handle: HANDLE,
    path: &Path,
    service: &str,
    kind: ObjectKind,
) -> Result<(), MemoryError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    let mut sd = null_mut();
    // SAFETY: borrowed live handle, valid output storage, security descriptor guarded until all readers finish.
    unsafe {
        win(GetFileInformationByHandle(handle, &mut info))?;
        require(
            metadata_allowed(info.dwFileAttributes, info.nNumberOfLinks, kind),
            "reparse, aliased, readonly or wrong-type broker object",
        )?;
        require(
            GetFileType(handle) == FILE_TYPE_DISK,
            "broker object is not a disk file",
        )?;
        let code = GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        );
        if code != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(code as i32).into());
        }
        let _descriptor = Local(sd);
        audit_descriptor(sd, service, kind)?;
        let mut final_path = vec![0u16; 32768];
        let len =
            GetFinalPathNameByHandleW(handle, final_path.as_mut_ptr(), final_path.len() as u32, 0);
        require(
            len > 0 && (len as usize) < final_path.len(),
            "cannot resolve broker path",
        )?;
        let resolved = String::from_utf16_lossy(&final_path[..len as usize]);
        let expected = format!(r"\\?\{}", path.display());
        require(
            resolved.eq_ignore_ascii_case(&expected),
            "broker path resolves through an alias",
        )?;
    }
    Ok(())
}

pub(super) fn store_entry_allowed(name: &str) -> bool {
    if matches!(
        name,
        "memory.db"
            | "memory.db-wal"
            | "memory.db-shm"
            | "memory.db-journal"
            | "memory.broker.lock"
            | "events.jsonl"
            | "events.jsonl.lock"
    ) {
        return true;
    }
    let Some(identity) = name
        .strip_prefix(".events.jsonl.")
        .and_then(|n| n.strip_suffix(".tmp"))
    else {
        return false;
    };
    let mut parts = identity.split('.');
    let number = |part: Option<&str>| {
        part.is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
    };
    number(parts.next()) && number(parts.next()) && parts.next().is_none()
}

pub(super) fn volume_allowed(drive_type: u32, filesystem: &str) -> bool {
    drive_type == 3 && filesystem == "NTFS" // DRIVE_FIXED
}

pub(super) fn validate_namespace(root: &Path, service: &str) -> Result<(), MemoryError> {
    validate_path(root)?;
    let text = root
        .to_str()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let volume = Path::new(&text[..3]);
    let mut filesystem = [0u16; 32];
    // SAFETY: terminated validated drive-root path and fixed output buffers.
    unsafe {
        win(GetVolumeInformationW(
            wide(volume).as_ptr(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        ))?;
        let end = filesystem
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(filesystem.len());
        require(
            volume_allowed(
                GetDriveTypeW(wide(volume).as_ptr()),
                &String::from_utf16_lossy(&filesystem[..end]),
            ),
            "broker requires local fixed NTFS",
        )?;
    }
    // Audit top-down: OPEN_REPARSE_POINT only protects the final component.
    // Earlier components are safe only after their ownership and mutation ACLs pass.
    let mut current = volume.to_path_buf();
    let mut guards = vec![audit_path(&current, service, ObjectKind::Ancestor)?];
    for part in text[3..].split('\\') {
        current.push(part);
        let kind = if current == root {
            ObjectKind::Root
        } else {
            ObjectKind::Ancestor
        };
        guards.push(audit_path(&current, service, kind)?);
    }
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        require(
            entry.file_name().to_str().is_some_and(store_entry_allowed),
            "unknown or legacy broker entry",
        )?;
        // Never retain SQLite file handles: native VFS owns sidecar lifetimes.
        drop(audit_path(&entry.path(), service, ObjectKind::File)?);
    }
    Ok(())
}

pub(super) const NATIVE_VFS: &str = "win32";

pub(super) fn open(root: &Path) -> Result<crate::MemoryStore, MemoryError> {
    use crate::{
        capability_root_guard, configure_broker_connection, initialize_schema, MemoryStore,
    };
    use cap_std::{ambient_authority, fs::Dir};
    use fs2::FileExt;
    use rusqlite::{Connection, OpenFlags};
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt, sync::Mutex};

    validate_path(root)?;
    let service = service_identity()?;
    validate_namespace(root, &service)?;
    let root_dir = Dir::open_ambient_dir(root, ambient_authority())?;
    let root_guard = capability_root_guard(&root_dir)?;
    audit_handle(root_guard.as_raw_handle(), root, &service, ObjectKind::Root)?;
    // This lock is separate from SQLite. No sidecars are created or pinned here.
    let lock_path = root.join("memory.broker.lock");
    let instance_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&lock_path)?;
    audit_handle(
        instance_lock.as_raw_handle(),
        &lock_path,
        &service,
        ObjectKind::File,
    )?;
    FileExt::try_lock_exclusive(&instance_lock)?;
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let mut connection =
        Connection::open_with_flags_and_vfs(root.join("memory.db"), flags, NATIVE_VFS)?;
    configure_broker_connection(&mut connection)?;
    initialize_schema(&mut connection, &root_dir)?;
    let store = MemoryStore {
        root_dir,
        _root_guard: root_guard,
        _database_guard: None,
        _wal_guard: None,
        _shm_guard: None,
        connection: Mutex::new(connection),
        _broker_lock: Some(instance_lock),
    };
    store.project_jsonl()?;
    Ok(store)
}

fn require(ok: bool, reason: &str) -> Result<(), MemoryError> {
    if ok {
        Ok(())
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, reason).into())
    }
}

pub(super) fn validate_path(path: &Path) -> Result<(), MemoryError> {
    let text = path.to_str().unwrap_or_default();
    let b = text.as_bytes();
    require(
        b.len() > 3 && b[0].is_ascii_alphabetic() && &b[1..3] == b":\\",
        "broker root must be an absolute local drive path",
    )?;
    for component in text[3..].split('\\') {
        let stem = component
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
            || ((stem.starts_with("COM") || stem.starts_with("LPT")) && stem.len() == 4);
        require(
            !component.is_empty()
                && !component.ends_with(['.', ' '])
                && !component
                    .chars()
                    .any(|c| c.is_control() || ":/<>\"|?*~".contains(c))
                && !device,
            "broker root contains a path alias",
        )?;
    }
    Ok(())
}
