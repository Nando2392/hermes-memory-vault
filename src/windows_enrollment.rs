//! Read-only admission of administrator-protected Windows client enrollments.
use std::{io, path::Path};

fn require(ok: bool, reason: &'static str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, reason))
    }
}
pub(crate) fn normalized(root: &Path) -> io::Result<String> {
    let text = root
        .to_str()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?
        .replace('/', "\\");
    let b = text.as_bytes();
    require(
        b.len() >= 3
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && b[2] == b'\\'
            && b.len() <= 32700,
        "expected absolute drive path",
    )?;
    if b.len() > 3 {
        for part in text[3..].split('\\') {
            require(
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && !part.ends_with(['.', ' '])
                    && !part
                        .chars()
                        .any(|c| c.is_control() || "<>:\"|?*".contains(c)),
                "ambiguous path component",
            )?;
            let stem = part
                .split('.')
                .next()
                .unwrap_or("")
                .trim_end_matches(' ')
                .to_ascii_uppercase();
            require(
                !matches!(
                    stem.as_str(),
                    "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                ) && !(stem.len() == 4
                    && (stem.starts_with("COM") || stem.starts_with("LPT"))
                    && matches!(stem.as_bytes()[3], b'1'..=b'9'))
                    && !["COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"].contains(&stem.as_str()),
                "DOS device path",
            )?;
        }
    }
    Ok(text.to_ascii_lowercase())
}
/// SHA-256 of the strict drive path, slash-normalized and ASCII case-folded.
/// This is lexical only: it never opens the profile or its database.
pub fn canonical_profile_key(root: &Path) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    Ok(format!(
        "{:x}",
        Sha256::digest(normalized(root)?.as_bytes())
    ))
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientEnrollment {
    pub schema: u32,
    pub profile_root: String,
    pub service_name: String,
    pub server_sid: String,
    pub client_sid: String,
    pub pipe: String,
    pub workspaces: Vec<String>,
    #[serde(default)]
    pub scope_mode: crate::workspace_policy::ScopeMode,
    #[serde(default)]
    pub legacy_root_key: Option<String>,
    pub release_sha256: String,
}
fn parse(bytes: &[u8], root: &Path, user: &str) -> io::Result<ClientEnrollment> {
    require(bytes.len() <= 65536, "enrollment exceeds 64KiB")?;
    let c: ClientEnrollment =
        serde_json::from_slice(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    require(
        c.schema == 1
            && canonical_profile_key(Path::new(&c.profile_root))? == canonical_profile_key(root)?,
        "schema or profile mismatch",
    )?;
    require(
        match c.legacy_root_key.as_deref() {
            Some(key) => {
                crate::workspace_policy::valid_root_key(key) && key == canonical_profile_key(root)?
            }
            None => c.scope_mode == crate::workspace_policy::ScopeMode::Fixed,
        },
        "scope/root policy mismatch",
    )?;
    let tail = c.server_sid.strip_prefix("S-1-5-80-").unwrap_or("");
    require(
        tail.split('-').count() == 5
            && tail
                .split('-')
                .all(|p| p.parse::<u32>().is_ok_and(|n| n.to_string() == p))
            && !trusted(&c.server_sid)
            && c.server_sid != user
            && c.client_sid == user,
        "enrollment identity mismatch",
    )?;
    let name = |s: &str, bound| {
        !s.is_empty()
            && s.len() <= bound
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    require(
        name(&c.service_name, 256)
            && c.pipe
                .strip_prefix(r"\\.\pipe\HermesMemory.")
                .is_some_and(|s| name(s, 80)),
        "invalid service or pipe",
    )?;
    let mut seen = std::collections::HashSet::new();
    require(
        !c.workspaces.is_empty()
            && c.workspaces.len() <= 256
            && c.workspaces
                .iter()
                .all(|w| crate::workspace_policy::validate_workspace(w).is_ok() && seen.insert(w)),
        "invalid workspace allowlist",
    )?;
    require(
        c.release_sha256.len() == 64 && c.release_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid release digest",
    )?;
    Ok(c)
}

use std::{
    ffi::c_void,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::Threading::*,
};
fn win(ok: i32) -> io::Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: Local owns only allocations returned by LocalAlloc-backed APIs.
        unsafe {
            LocalFree(self.0);
        }
    }
}
// SAFETY: sid is inside a live OS-validated token or descriptor.
unsafe fn sid_text(sid: PSID) -> io::Result<String> {
    require(
        !sid.is_null() && unsafe { IsValidSid(sid) } != 0,
        "invalid SID",
    )?;
    let mut out = null_mut();
    unsafe {
        win(ConvertSidToStringSidW(sid, &mut out))?;
    }
    let _allocation = Local(out.cast());
    let mut len = 0;
    // SAFETY: successful converter returns a terminated UTF-16 allocation.
    unsafe {
        while *out.add(len) != 0 {
            len += 1;
        }
        String::from_utf16(std::slice::from_raw_parts(out, len))
            .map_err(|_| io::ErrorKind::InvalidData.into())
    }
}
fn trusted(sid: &str) -> bool {
    matches!(
        sid,
        "S-1-5-18"
            | "S-1-5-32-544"
            | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    )
}
// SAFETY: caller retains an OS-produced descriptor allocation throughout this call.
unsafe fn audit_descriptor(sd: PSECURITY_DESCRIPTOR, directory: bool) -> io::Result<()> {
    // SAFETY: native validation precedes all interior pointer queries; ACL and ACE
    // extents are checked before reading SID bodies. No pointer escapes the call.
    unsafe {
        require(
            !sd.is_null() && IsValidSecurityDescriptor(sd) != 0,
            "invalid descriptor",
        )?;
        let mut owner = null_mut();
        let mut defaulted = 0;
        win(GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted))?;
        require(trusted(&sid_text(owner)?), "untrusted enrollment owner")?;
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
        let start = acl as usize;
        let end = start + usize::from((*acl).AclSize);
        for index in 0..(*acl).AceCount {
            let mut raw = null_mut();
            win(GetAce(acl, u32::from(index), &mut raw))?;
            let address = raw as usize;
            require(
                address >= start + std::mem::size_of::<ACL>()
                    && address.checked_add(4).is_some_and(|v| v <= end),
                "ACE header out of bounds",
            )?;
            let h = &*raw.cast::<ACE_HEADER>();
            let size = usize::from(h.AceSize);
            require(
                h.AceType == 0
                    && h.AceFlags & !0x1f == 0
                    && size >= 16
                    && address.checked_add(size).is_some_and(|v| v <= end),
                "unknown or malformed ACE",
            )?;
            let bytes = std::slice::from_raw_parts(raw.cast::<u8>().add(8), size - 8);
            require(
                bytes[0] == 1 && bytes[1] <= 15 && bytes.len() == 8 + 4 * usize::from(bytes[1]),
                "ACE SID exceeds entry",
            )?;
            let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
            let sid = sid_text(raw.cast::<u8>().add(8).cast())?;
            // Inherit-only grants do not apply to this ancestor. Every existing
            // descendant is independently opened, pinned and audited before use.
            if directory && u32::from(h.AceFlags) & INHERIT_ONLY_ACE != 0 {
                continue;
            }
            let read_only =
                FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | GENERIC_READ | GENERIC_EXECUTE;
            let allowed = if trusted(&sid) {
                FILE_ALL_ACCESS | GENERIC_ALL | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE
            } else {
                // Creating a new child directory cannot replace an admitted one.
                // Never allow this bit for the enrollment file (append-data).
                read_only | if directory { FILE_ADD_SUBDIRECTORY } else { 0 }
            };
            require(
                ace.Mask & !allowed == 0,
                "non-administrator enrollment mutation",
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
fn metadata_allowed(attributes: u32, links: u32, directory: bool, size: u64) -> bool {
    metadata_allowed_bounded(attributes, links, directory, size, 65536)
}
fn metadata_allowed_bounded(
    attributes: u32,
    links: u32,
    directory: bool,
    size: u64,
    max_bytes: u64,
) -> bool {
    attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE) == 0
        && (attributes & FILE_ATTRIBUTE_DIRECTORY != 0) == directory
        && (directory || (links == 1 && size <= max_bytes))
}
fn audit_handle(handle: HANDLE, path: &str, directory: bool, max_bytes: u64) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: caller holds a live handle; outputs have the native structure layout.
    unsafe {
        win(GetFileInformationByHandle(handle, &mut info))?;
        require(
            GetFileType(handle) == FILE_TYPE_DISK
                && metadata_allowed_bounded(
                    info.dwFileAttributes,
                    info.nNumberOfLinks,
                    directory,
                    (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
                    max_bytes,
                ),
            "wrong type, reparse, hardlinked or oversized enrollment",
        )?;
        let mut sd = null_mut();
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
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        let _allocation = Local(sd);
        audit_descriptor(sd, directory)?;
        let mut final_path = vec![0u16; 32768];
        let n =
            GetFinalPathNameByHandleW(handle, final_path.as_mut_ptr(), final_path.len() as u32, 0)
                as usize;
        require(
            n > 0 && n < final_path.len(),
            "cannot resolve physical enrollment path",
        )?;
        let resolved =
            String::from_utf16(&final_path[..n]).map_err(|_| io::ErrorKind::InvalidData)?;
        require(
            resolved.eq_ignore_ascii_case(&format!(r"\\?\{path}")),
            "aliased enrollment path",
        )?;
    }
    Ok(())
}

fn process_user() -> io::Result<String> {
    let mut raw = null_mut();
    // SAFETY: pseudo handles are borrowed; successful token outputs become owned.
    unsafe {
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) != 0 {
            drop(OwnedHandle::from_raw_handle(raw));
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "impersonating caller",
            ));
        }
        require(
            GetLastError() == ERROR_NO_TOKEN,
            "cannot inspect thread token",
        )?;
        win(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw))?;
    }
    // SAFETY: OpenProcessToken succeeded, transferring unique ownership.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut size = 0;
    // SAFETY: sizing query followed by an aligned bounded allocation.
    unsafe {
        GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut size);
    }
    require(
        size as usize >= std::mem::size_of::<TOKEN_USER>() && size <= 65536,
        "invalid TokenUser size",
    )?;
    let mut data = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: buffer is sufficiently sized/aligned; kernel SID lives until return.
    unsafe {
        win(GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            data.as_mut_ptr().cast(),
            size,
            &mut size,
        ))?;
        sid_text((*data.as_ptr().cast::<TOKEN_USER>()).User.Sid)
    }
}
// SystemInformation is not enabled in this crate's windows-sys features. This
// exact kernel32 ABI avoids adding a dependency/feature and never reads env vars.
#[link(name = "kernel32")]
extern "system" {
    fn GetSystemWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
}
fn enrollment_path(root: &Path) -> io::Result<std::path::PathBuf> {
    let key = canonical_profile_key(root)?;
    let mut directory = vec![0u16; 32768];
    // SAFETY: writable UTF-16 buffer with matching capacity; no environment input.
    let n = unsafe { GetSystemWindowsDirectoryW(directory.as_mut_ptr(), directory.len() as u32) }
        as usize;
    require(
        n > 0 && n < directory.len(),
        "cannot locate system Windows directory",
    )?;
    let system = String::from_utf16(&directory[..n]).map_err(|_| io::ErrorKind::InvalidData)?;
    let system = normalized(Path::new(&system))?;
    Ok(Path::new(&system[..3])
        .join("HermesMemoryVault")
        .join("clients")
        .join(format!("{key}.json")))
}
/// Load the sole machine enrollment location. No environment override or fallback.
pub fn load_for_root(root: &Path) -> io::Result<ClientEnrollment> {
    load_from_enrollment(&enrollment_path(root)?, root)
}
fn open_audited(path: &str, directory: bool, max_bytes: u64) -> io::Result<OwnedHandle> {
    // SAFETY: validated terminated path, noninheritable synchronous disk handle.
    // Keep every ancestor open without delete sharing; the leaf also denies writers.
    let raw = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES | if directory { 0 } else { FILE_READ_DATA },
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateFileW transferred unique ownership.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    audit_handle(handle.as_raw_handle(), path, directory, max_bytes)?;
    Ok(handle)
}
fn fixed_ntfs(handle: HANDLE, volume: &str) -> io::Result<()> {
    let mut fs = [0u16; 32];
    let mut device = vec![0u16; 32768];
    // SAFETY: live audited volume-root handle, bounded native output buffers.
    unsafe {
        win(GetVolumeInformationByHandleW(
            handle,
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            fs.as_mut_ptr(),
            fs.len() as u32,
        ))?;
        require(
            GetDriveTypeW(wide(volume).as_ptr()) == 3,
            "enrollment requires fixed disk",
        )?;
        let n = QueryDosDeviceW(
            wide(&volume[..2]).as_ptr(),
            device.as_mut_ptr(),
            device.len() as u32,
        ) as usize;
        require(n > 0 && n < device.len(), "cannot resolve physical drive")?;
    }
    let end = fs
        .iter()
        .position(|c| *c == 0)
        .ok_or(io::ErrorKind::InvalidData)?;
    require(
        String::from_utf16_lossy(&fs[..end]) == "NTFS",
        "enrollment requires NTFS",
    )?;
    let end = device
        .iter()
        .position(|c| *c == 0)
        .ok_or(io::ErrorKind::InvalidData)?;
    let device = String::from_utf16(&device[..end]).map_err(|_| io::ErrorKind::InvalidData)?;
    require(
        device
            .strip_prefix(r"\Device\HarddiskVolume")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())),
        "nonphysical drive alias",
    )
}
/// Protected fixture/provisioning seam, NOT an override for production clients.
/// Every ancestor (including drive root) and the file must pass the same immutable
/// administrator ACL policy. Ordinary user temp files are deliberately rejected.
/// No file, directory, ACL, service or profile database is created or modified.
pub fn load_from_enrollment(path: &Path, root: &Path) -> io::Result<ClientEnrollment> {
    canonical_profile_key(root)?;
    let user = process_user()?;
    let bytes = bounded_read(open_admin_owned_file(path, 65536)?)?;
    parse(&bytes, root, &user)
}

/// Exact audited file plus top-down ancestor pins, with a bounded payload.
/// Native sharing denies writers/deletion for the full reader lifetime.
pub struct ProtectedReader {
    file: io::Take<std::fs::File>,
    _ancestors: Vec<OwnedHandle>,
}
impl io::Read for ProtectedReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut self.file, out)
    }
}
/// Open an immutable administrator-owned source without client TokenUser matching.
/// Trust is the native ACL/NTFS/handle-sharing contract, not the path spelling.
/// No provisioning, environment lookup, or whole-file buffering occurs here.
pub fn open_admin_owned_file(path: &Path, max_bytes: u64) -> io::Result<ProtectedReader> {
    let text = normalized(path)?;
    require(text.len() > 3, "source must be a file")?;
    let mut guards = vec![open_audited(&text[..3], true, max_bytes)?];
    fixed_ntfs(guards[0].as_raw_handle(), &text[..3])?;
    // Top-down admission: OPEN_REPARSE_POINT protects only each current leaf.
    // Previously audited ancestors stay pinned through the final bounded read.
    let mut current = text[..3].to_owned();
    let parts: Vec<_> = text[3..].split('\\').collect();
    for (index, part) in parts.iter().enumerate() {
        if current.len() > 3 {
            current.push('\\');
        }
        current.push_str(part);
        let directory = index + 1 < parts.len();
        let handle = open_audited(&current, directory, max_bytes)?;
        if directory {
            guards.push(handle);
        } else {
            // File owns the exact audited handle, not a reopen by pathname.
            let file = std::fs::File::from(handle);
            return Ok(ProtectedReader {
                file: io::Read::take(file, max_bytes),
                _ancestors: guards,
            });
        }
    }
    Err(io::ErrorKind::InvalidInput.into())
}
fn bounded_read(reader: impl io::Read) -> io::Result<Vec<u8>> {
    use io::Read;
    let mut bytes = Vec::new();
    reader.take(65537).read_to_end(&mut bytes)?;
    require(bytes.len() <= 65536, "enrollment exceeds 64KiB")?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protected_reader_rejects_user_owned_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.jsonl");
        std::fs::write(&path, b"untrusted").unwrap();
        assert!(open_admin_owned_file(&path, 1024).is_err());
        assert!(open_admin_owned_file(Path::new("relative"), 1024).is_err());
        assert!(metadata_allowed_bounded(
            FILE_ATTRIBUTE_NORMAL,
            1,
            false,
            65537,
            1 << 30
        ));
        assert!(!metadata_allowed_bounded(
            FILE_ATTRIBUTE_NORMAL,
            1,
            false,
            1025,
            1024
        ));
        assert!(!metadata_allowed_bounded(
            FILE_ATTRIBUTE_NORMAL,
            2,
            false,
            1,
            1024
        ));
    }
    #[test]
    fn reserved_device_spellings_are_not_profile_keys() {
        for bad in ["C:/COM¹", "C:/LPT².txt", "C:/CON .txt"] {
            assert!(canonical_profile_key(Path::new(bad)).is_err(), "{bad}");
        }
    }
    #[test]
    fn bounded_reader_accepts_limit_rejects_extra_byte() {
        assert_eq!(bounded_read(&vec![0; 65536][..]).unwrap().len(), 65536);
        assert!(bounded_read(&vec![0; 65537][..]).is_err());
    }
    #[test]
    fn native_identity_and_system_location_are_available() {
        assert!(process_user().unwrap().starts_with("S-1-"));
        let root = Path::new("C:/never-open-profile");
        let path = enrollment_path(root).unwrap();
        let text = normalized(&path).unwrap();
        assert!(text.ends_with(&format!(
            "\\hermesmemoryvault\\clients\\{}.json",
            canonical_profile_key(root).unwrap()
        )));
        let file = tempfile::NamedTempFile::new().unwrap();
        let err = load_from_enrollment(file.path(), root).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(load_for_root(Path::new("relative")).is_err());
    }
    #[test]
    fn metadata_rejects_aliases_wrong_types_and_oversize() {
        assert!(metadata_allowed(FILE_ATTRIBUTE_NORMAL, 1, false, 65536));
        assert!(metadata_allowed(FILE_ATTRIBUTE_DIRECTORY, 1, true, 0));
        for (attributes, links, directory, size) in [
            (FILE_ATTRIBUTE_REPARSE_POINT, 1, false, 1),
            (FILE_ATTRIBUTE_DEVICE, 1, false, 1),
            (FILE_ATTRIBUTE_DIRECTORY, 1, false, 0),
            (FILE_ATTRIBUTE_NORMAL, 1, true, 0),
            (FILE_ATTRIBUTE_NORMAL, 2, false, 1),
            (FILE_ATTRIBUTE_NORMAL, 0, false, 1),
            (FILE_ATTRIBUTE_NORMAL, 1, false, 65537),
        ] {
            assert!(!metadata_allowed(attributes, links, directory, size));
        }
    }
    #[test]
    fn user_owned_open_handle_is_rejected_without_acl_changes() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let result = audit_handle(
            file.as_file().as_raw_handle(),
            file.path().to_str().unwrap(),
            false,
            65536,
        );
        assert!(result.is_err(), "user-owned enrollment must fail admission");
    }
    fn sddl_check(sddl: &str) -> io::Result<()> {
        sddl_check_kind(sddl, false)
    }
    fn sddl_check_kind(sddl: &str, directory: bool) -> io::Result<()> {
        let mut sd = null_mut();
        // SAFETY: native parser owns output; kept alive through descriptor audit.
        unsafe {
            win(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                1,
                &mut sd,
                null_mut(),
            ))?;
            let _sd = Local(sd);
            audit_descriptor(sd, directory)
        }
    }
    #[test]
    fn directory_ancestor_allows_only_new_children_not_existing_path_mutation() {
        let root = "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:SYD:PAI(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
        assert!(sddl_check_kind(root, true).is_ok());
        assert!(sddl_check_kind(root, false).is_err());
        for right in ["0x2", "0x10", "0x40", "0x100", "0x10000", "WD", "WO", "GW"] {
            let bad = format!("O:BAD:P(A;;FA;;;BA)(A;;{right};;;BU)");
            assert!(sddl_check_kind(&bad, true).is_err(), "{right}");
        }
        assert!(sddl_check_kind("O:BAD:P(A;;FA;;;BA)(A;CI;DCLCRPCR;;;BU)", true).is_err());
    }
    #[test]
    fn descriptor_allows_admin_control_but_never_service_mutation() {
        let service = "S-1-5-80-1-2-3-4-5";
        assert!(sddl_check(&format!(
            "O:BAG:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;{service})"
        ))
        .is_ok());
        for right in [
            "FW", "FA", "WD", "WO", "DC", "0x100", "0x10", "0x2", "0x4", "0x10000", "GW", "GA",
        ] {
            assert!(
                sddl_check(&format!("O:BAG:BAD:P(A;;FA;;;BA)(A;;{right};;;{service})")).is_err(),
                "{right}"
            );
        }
        for bad in [
            "O:BUD:P(A;;FA;;;BA)",
            "O:BAD:NO_ACCESS_CONTROL",
            "O:BAD:P(D;;FW;;;BU)(A;;FA;;;BA)",
            "O:BAD:P(A;;FA;;;BU)",
            "O:BAD:P(XA;;FR;;;BU;(Exists @User.foo))",
        ] {
            assert!(sddl_check(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn strict_config_binds_identity_root_and_bounded_fields() {
        let mut owner = serde_json::json!({"schema":1,"profile_root":"C:/profile","service_name":"Hermes-1","server_sid":"S-1-5-80-1-2-3-4-5","client_sid":"S-1-5-21-1-2-3-1001","pipe":r"\\.\pipe\HermesMemory.test","workspaces":["main"],"release_sha256":"a".repeat(64),"scope_mode":"vault-owner","legacy_root_key":canonical_profile_key(Path::new("C:/profile")).unwrap()});
        assert!(parse(
            &serde_json::to_vec(&owner).unwrap(),
            Path::new("C:/profile"),
            "S-1-5-21-1-2-3-1001"
        )
        .is_ok());
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!(""),
            serde_json::json!("a".repeat(64)),
        ] {
            owner["legacy_root_key"] = invalid;
            assert!(parse(
                &serde_json::to_vec(&owner).unwrap(),
                Path::new("C:/profile"),
                "S-1-5-21-1-2-3-1001"
            )
            .is_err());
        }
        owner["legacy_root_key"] =
            serde_json::json!(canonical_profile_key(Path::new("C:/profile")).unwrap());
        owner["workspaces"] = serde_json::json!(["🌍".repeat(128), "plain"]);
        assert!(parse(
            &serde_json::to_vec(&owner).unwrap(),
            Path::new("C:/profile"),
            "S-1-5-21-1-2-3-1001"
        )
        .is_ok());
        for invalid in [
            "a/b",
            "redacted-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            owner["workspaces"] = serde_json::json!([invalid]);
            assert!(parse(
                &serde_json::to_vec(&owner).unwrap(),
                Path::new("C:/profile"),
                "S-1-5-21-1-2-3-1001"
            )
            .is_err());
        }
        owner["workspaces"] = serde_json::json!(["main"]);
        owner.as_object_mut().unwrap().remove("legacy_root_key");
        assert!(parse(
            &serde_json::to_vec(&owner).unwrap(),
            Path::new("C:/profile"),
            "S-1-5-21-1-2-3-1001"
        )
        .is_err());
        let valid = serde_json::json!({"schema":1,"profile_root":"C:/profile","service_name":"Hermes-1","server_sid":"S-1-5-80-1-2-3-4-5","client_sid":"S-1-5-21-1-2-3-1001","pipe":r"\\.\pipe\HermesMemory.test","workspaces":["main"],"release_sha256":"a".repeat(64)});
        let root = Path::new(r"C:\profile");
        let user = "S-1-5-21-1-2-3-1001";
        assert!(parse(&serde_json::to_vec(&valid).unwrap(), root, user).is_ok());
        for (field, value) in [
            ("schema", serde_json::json!(2)),
            ("profile_root", serde_json::json!("C:/other")),
            ("client_sid", serde_json::json!("S-1-5-18")),
            ("server_sid", serde_json::json!("S-1-5-80-01-2-3-4-5")),
            (
                "server_sid",
                serde_json::json!("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"),
            ),
            ("service_name", serde_json::json!("a/b")),
            ("pipe", serde_json::json!(r"\\remote\pipe\x")),
            ("workspaces", serde_json::json!(["*"])),
            ("workspaces", serde_json::json!(["main", "main"])),
            ("workspaces", serde_json::json!([])),
            ("release_sha256", serde_json::json!("g".repeat(64))),
            ("unknown", serde_json::json!(1)),
        ] {
            let mut bad = valid.clone();
            bad[field] = value;
            assert!(
                parse(&serde_json::to_vec(&bad).unwrap(), root, user).is_err(),
                "{field}"
            );
        }
        assert!(parse(&vec![b' '; 65537], root, user).is_err());
    }
    #[test]
    fn canonical_key_normalizes_only_case_and_separators() {
        let a = canonical_profile_key(Path::new(r"C:\Users\Alice\profile")).unwrap();
        assert_eq!(
            a,
            canonical_profile_key(Path::new("c:/users/alice/profile")).unwrap()
        );
        assert_eq!(a.len(), 64);
        assert_ne!(
            a,
            canonical_profile_key(Path::new(r"C:\Users\Bob\profile")).unwrap()
        );
        for bad in [
            "relative",
            "C:relative",
            r"\\host\share",
            r"\\?\C:\x",
            r"C:\x\..\y",
            r"C:\x\.\y",
            r"C:\x:ads",
            "C:\\x.",
            "C:\\x ",
            "C:\\x\0",
            r"C:\\x",
            r"C:\CON",
            r"C:\x\",
        ] {
            assert!(canonical_profile_key(Path::new(bad)).is_err(), "{bad:?}");
        }
    }
}
