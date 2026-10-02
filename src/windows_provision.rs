//! Explicit machine provisioning; never called by the normal client.
use crate::windows_enrollment::{canonical_profile_key, normalized};
use serde::{Deserialize, Serialize};
use std::{io, path::Path};
fn require(ok: bool, message: &'static str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, message))
    }
}
fn digest_valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sid_valid(s: &str) -> bool {
    let parts: Vec<_> = s.split('-').collect();
    parts.len() >= 4
        && parts.len() <= 18
        && parts[0] == "S"
        && parts[1] == "1"
        && parts[2]
            .parse::<u64>()
            .is_ok_and(|n| n < (1u64 << 48) && n.to_string() == parts[2])
        && parts[3..]
            .iter()
            .all(|p| p.parse::<u32>().is_ok_and(|n| n.to_string() == *p))
}
fn overlap(a: &str, b: &str) -> bool {
    a == b || a.starts_with(&format!("{b}\\")) || b.starts_with(&format!("{a}\\"))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inputs {
    pub legacy_root: String,
    pub client_sid: String,
    pub workspace: String,
    pub install_root: String,
    pub service_name: Option<String>,
    pub broker_source: String,
    pub broker_sha256: String,
    pub client_source: String,
    pub client_sha256: String,
    pub release_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub legacy_root: String,
    pub key: String,
    pub install_root: String,
    pub service_name: String,
    pub client_sid: String,
    pub workspace: String,
    pub enrollment: String,
    pub pipe: String,
    pub broker_sha256: String,
    pub client_sha256: String,
    pub release_sha256: String,
}
/// Lexical validation only: never touches the legacy profile or the filesystem.
pub fn plan(i: &Inputs) -> io::Result<Plan> {
    let legacy_root = normalized(Path::new(&i.legacy_root))?;
    let install_root = normalized(Path::new(&i.install_root))?;
    require(
        install_root.len() <= 2048,
        "install path exceeds bounded registration layout",
    )?;
    let broker = normalized(Path::new(&i.broker_source))?;
    let client = normalized(Path::new(&i.client_source))?;
    require(
        [&legacy_root, &broker, &client]
            .iter()
            .all(|p| p.len() <= 2048),
        "path exceeds bounded receipt layout",
    )?;
    require(
        install_root.len() > 3 && legacy_root.len() > 3 && broker.len() > 3 && client.len() > 3,
        "drive root is not a payload/profile namespace",
    )?;
    require(
        !overlap(&legacy_root, &install_root)
            && !overlap(&broker, &install_root)
            && !overlap(&client, &install_root)
            && !overlap(&legacy_root, &broker)
            && !overlap(&legacy_root, &client)
            && broker != client,
        "colliding namespaces",
    )?;
    require(
        sid_valid(&i.client_sid)
            && !matches!(
                i.client_sid.as_str(),
                "S-1-5-18" | "S-1-5-19" | "S-1-5-20" | "S-1-5-32-544"
            ),
        "invalid client TokenUser SID",
    )?;
    require(
        !i.workspace.is_empty()
            && i.workspace.len() <= 256
            && i.workspace.trim() == i.workspace
            && !i
                .workspace
                .chars()
                .any(|c| c.is_control() || matches!(c, '*' | '?')),
        "invalid single workspace",
    )?;
    require(
        [&i.broker_sha256, &i.client_sha256, &i.release_sha256]
            .iter()
            .all(|s| digest_valid(s)),
        "expected lowercase SHA-256 pins",
    )?;
    let key = canonical_profile_key(Path::new(&legacy_root))?;
    let service_name = i
        .service_name
        .clone()
        .unwrap_or_else(|| format!("HermesMemory-{key}"));
    require(
        !service_name.is_empty()
            && service_name.len() <= 80
            && service_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid service name",
    )?;
    Ok(Plan {
        enrollment: format!("{install_root}\\clients\\{key}.json"),
        pipe: format!(r"\\.\pipe\HermesMemory.{service_name}"),
        legacy_root,
        key,
        install_root,
        service_name,
        client_sid: i.client_sid.clone(),
        workspace: i.workspace.clone(),
        broker_sha256: i.broker_sha256.clone(),
        client_sha256: i.client_sha256.clone(),
        release_sha256: i.release_sha256.clone(),
    })
}
/// Windows CRT argument encoding, also used for the executable token.
pub fn quote_arg(arg: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for ch in arg.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        out.extend(std::iter::repeat_n(
            '\\',
            if ch == '"' { slashes * 2 + 1 } else { slashes },
        ));
        out.push(ch);
        slashes = 0;
    }
    out.extend(std::iter::repeat_n('\\', slashes * 2));
    out.push('"');
    out
}
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, Write},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Services::*, Threading::*},
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
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
struct Identity {
    volume: u32,
    high: u32,
    low: u32,
}
fn file_info(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: live file handle and correctly sized writable native output.
    unsafe {
        win(GetFileInformationByHandle(file.as_raw_handle(), &mut info))?;
    }
    Ok(info)
}
fn identity(info: &BY_HANDLE_FILE_INFORMATION) -> Identity {
    Identity {
        volume: info.dwVolumeSerialNumber,
        high: info.nFileIndexHigh,
        low: info.nFileIndexLow,
    }
}
struct PinnedSource {
    file: File,
    id: Identity,
    size: u64,
    expected: String,
}
impl PinnedSource {
    fn open(path: &Path, expected: &str, max: u64) -> io::Result<Self> {
        require(digest_valid(expected), "invalid content pin")?;
        normalized(path)?;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let info = file_info(&file)?;
        let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
        // SAFETY: file remains owned throughout this synchronous type query.
        require(
            unsafe { GetFileType(file.as_raw_handle()) } == FILE_TYPE_DISK
                && info.dwFileAttributes
                    & (FILE_ATTRIBUTE_REPARSE_POINT
                        | FILE_ATTRIBUTE_DIRECTORY
                        | FILE_ATTRIBUTE_DEVICE)
                    == 0
                && info.nNumberOfLinks == 1
                && size <= max,
            "source must be bounded regular non-reparse single-link disk file",
        )?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        require(
            format!("{:x}", hasher.finalize()) == expected,
            "source SHA-256 mismatch",
        )?;
        file.rewind()?;
        Ok(Self {
            file,
            id: identity(&info),
            size,
            expected: expected.into(),
        })
    }
    #[cfg(test)]
    fn copy_new(&mut self, path: &Path) -> io::Result<Identity> {
        let mut target = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)?;
        self.copy_to(&mut target)
    }
    fn copy_protected(&mut self, path: &Path, readers: &[&str]) -> io::Result<Identity> {
        self.copy_to(&mut protected_file(path, readers)?)
    }
    fn copy_to(&mut self, target: &mut File) -> io::Result<Identity> {
        self.file.rewind()?;
        let mut copied = 0u64;
        let mut hash = Sha256::new();
        let mut buf = [0u8; 65536];
        loop {
            let n = self.file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            copied += n as u64;
            require(copied <= self.size, "source grew during copy")?;
            hash.update(&buf[..n]);
            target.write_all(&buf[..n])?;
        }
        require(
            copied == self.size && format!("{:x}", hash.finalize()) == self.expected,
            "source changed during copy",
        )?;
        target.sync_all()?;
        Ok(identity(&file_info(target)?))
    }
}
/// Validate and hash both payloads without creating anything or accessing SCM.
pub fn checked_plan(inputs: &Inputs) -> io::Result<Plan> {
    let result = plan(inputs)?;
    let _broker = PinnedSource::open(
        Path::new(&inputs.broker_source),
        &inputs.broker_sha256,
        1 << 30,
    )?;
    let _client = PinnedSource::open(
        Path::new(&inputs.client_source),
        &inputs.client_sha256,
        1 << 30,
    )?;
    Ok(result)
}
struct Descriptor(PSECURITY_DESCRIPTOR);
impl Descriptor {
    fn new(sddl: &str) -> io::Result<Self> {
        let mut sd = null_mut();
        // SAFETY: terminated input and native out-pointer; allocation owned below.
        unsafe {
            win(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                1,
                &mut sd,
                null_mut(),
            ))?;
        }
        Ok(Self(sd))
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: unique LocalAlloc-backed allocation.
        unsafe {
            LocalFree(self.0);
        }
    }
}
unsafe fn sid_text(sid: PSID) -> io::Result<String> {
    let mut raw = null_mut();
    // SAFETY: caller supplies a live validated SID; converter owns output.
    unsafe {
        require(!sid.is_null() && IsValidSid(sid) != 0, "invalid SID")?;
        win(ConvertSidToStringSidW(sid, &mut raw))?;
        let _guard = Descriptor(raw.cast());
        let mut n = 0;
        while *raw.add(n) != 0 {
            n += 1;
        }
        String::from_utf16(std::slice::from_raw_parts(raw, n))
            .map_err(|_| io::ErrorKind::InvalidData.into())
    }
}
fn trusted(s: &str) -> bool {
    matches!(
        s,
        "S-1-5-18"
            | "S-1-5-32-544"
            | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    )
}
fn audit_sd(sd: PSECURITY_DESCRIPTOR, directory: bool) -> io::Result<()> {
    // SAFETY: private callers provide OS-allocated descriptors retained for this call.
    unsafe {
        require(
            !sd.is_null() && IsValidSecurityDescriptor(sd) != 0,
            "invalid descriptor",
        )?;
        let mut owner = null_mut();
        let mut defaulted = 0;
        win(GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted))?;
        require(trusted(&sid_text(owner)?), "untrusted owner")?;
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
            "null DACL",
        )?;
        let start = acl as usize;
        let end = start + usize::from((*acl).AclSize);
        for index in 0..(*acl).AceCount {
            let mut raw = null_mut();
            win(GetAce(acl, u32::from(index), &mut raw))?;
            let address = raw as usize;
            require(
                address >= start + std::mem::size_of::<ACL>()
                    && address.checked_add(4).is_some_and(|n| n <= end),
                "ACE header bounds",
            )?;
            let h = &*raw.cast::<ACE_HEADER>();
            let size = usize::from(h.AceSize);
            require(
                h.AceType == 0
                    && h.AceFlags & !0x1f == 0
                    && size >= 16
                    && address.checked_add(size).is_some_and(|n| n <= end),
                "unsupported ACE",
            )?;
            let bytes = std::slice::from_raw_parts(raw.cast::<u8>().add(8), size - 8);
            require(
                bytes[0] == 1 && bytes[1] <= 15 && bytes.len() == 8 + 4 * usize::from(bytes[1]),
                "SID bounds",
            )?;
            if directory && u32::from(h.AceFlags) & INHERIT_ONLY_ACE != 0 {
                continue;
            }
            let mask = (*raw.cast::<ACCESS_ALLOWED_ACE>()).Mask;
            let principal = sid_text(raw.cast::<u8>().add(8).cast())?;
            let allowed = if trusted(&principal) {
                FILE_ALL_ACCESS | GENERIC_ALL | GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE
            } else {
                FILE_GENERIC_READ
                    | FILE_GENERIC_EXECUTE
                    | GENERIC_READ
                    | GENERIC_EXECUTE
                    | if directory { FILE_ADD_SUBDIRECTORY } else { 0 }
            };
            require(
                mask & !allowed == 0,
                "non-administrator mutation permission",
            )?;
        }
        Ok(())
    }
}
fn audit_private_sd(sd: PSECURITY_DESCRIPTOR, service: &str) -> io::Result<()> {
    // SAFETY: descriptor comes from native conversion or GetSecurityInfo and is retained.
    unsafe {
        require(
            !sd.is_null() && IsValidSecurityDescriptor(sd) != 0,
            "invalid private descriptor",
        )?;
        let mut owner = null_mut();
        let mut defaulted = 0;
        win(GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted))?;
        require(
            matches!(sid_text(owner)?.as_str(), "S-1-5-18" | "S-1-5-32-544"),
            "private root owner",
        )?;
        let mut control = 0;
        let mut revision = 0;
        win(GetSecurityDescriptorControl(
            sd,
            &mut control,
            &mut revision,
        ))?;
        require(
            control & SE_DACL_PROTECTED != 0,
            "private root DACL must be protected",
        )?;
        let mut acl = null_mut();
        let mut present = 0;
        win(GetSecurityDescriptorDacl(
            sd,
            &mut present,
            &mut acl,
            &mut defaulted,
        ))?;
        require(
            present != 0 && !acl.is_null() && IsValidAcl(acl) != 0 && (*acl).AceCount == 3,
            "private root must have three grants",
        )?;
        let mut seen = std::collections::HashSet::new();
        for index in 0..3 {
            let mut raw = null_mut();
            win(GetAce(acl, index, &mut raw))?;
            let h = &*raw.cast::<ACE_HEADER>();
            require(
                h.AceType == 0
                    && u32::from(h.AceFlags) == OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
                    && h.AceSize >= 16,
                "private ACE type/inheritance",
            )?;
            let sid = raw.cast::<u8>().add(8).cast();
            require(
                IsValidSid(sid) != 0 && usize::from(h.AceSize) == 8 + GetLengthSid(sid) as usize,
                "private SID extent",
            )?;
            let principal = sid_text(sid)?;
            require(
                (principal == service || matches!(principal.as_str(), "S-1-5-18" | "S-1-5-32-544"))
                    && seen.insert(principal)
                    && (*raw.cast::<ACCESS_ALLOWED_ACE>()).Mask == FILE_ALL_ACCESS,
                "private root principal/mask",
            )?;
        }
    }
    Ok(())
}
fn require_consent(allow: bool) -> io::Result<()> {
    require(allow, "explicit --allow-machine-provision required")
}
fn configuration_matches(
    command: &str,
    account: &str,
    kind: u32,
    start: u32,
    expected_command: &str,
    expected_account: &str,
) -> bool {
    command == expected_command
        && account.eq_ignore_ascii_case(expected_account)
        && kind == SERVICE_WIN32_OWN_PROCESS
        && start == SERVICE_DEMAND_START
}
fn administrator(allow: bool) -> io::Result<()> {
    require_consent(allow)?;
    let mut raw = null_mut();
    // SAFETY: current pseudo handles are borrowed, token outputs owned below.
    unsafe {
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) != 0 {
            drop(OwnedHandle::from_raw_handle(raw));
            return require(false, "impersonation forbidden");
        }
        require(
            GetLastError() == ERROR_NO_TOKEN,
            "cannot inspect thread token",
        )?;
        win(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw))?;
    }
    // SAFETY: successful OpenProcessToken transferred ownership.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut elevation = TOKEN_ELEVATION::default();
    let mut size = 0;
    // SAFETY: matching native structure and output size.
    unsafe {
        win(GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of_val(&elevation) as u32,
            &mut size,
        ))?;
    }
    require(
        elevation.TokenIsElevated != 0,
        "elevated Administrators token required",
    )?;
    let mut sid = null_mut();
    let mut member = 0;
    // SAFETY: native allocation, membership uses the nonimpersonating effective token.
    unsafe {
        win(ConvertStringSidToSidW(
            wide("S-1-5-32-544").as_ptr(),
            &mut sid,
        ))?;
        let _guard = Descriptor(sid);
        win(CheckTokenMembership(null_mut(), sid, &mut member))?;
    }
    require(member != 0, "enabled Administrators membership required")
}
#[link(name = "kernel32")]
extern "system" {
    fn GetSystemWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32;
}
/// Native system drive; never trusts an environment-variable override.
pub fn default_install_root() -> io::Result<String> {
    let mut buf = vec![0u16; 32768];
    // SAFETY: native output buffer and matching capacity.
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    require(n > 3 && n < buf.len(), "cannot locate system drive")?;
    let path = String::from_utf16(&buf[..n]).map_err(|_| io::ErrorKind::InvalidData)?;
    let path = normalized(Path::new(&path))?;
    Ok(format!("{}HermesMemoryVault", &path[..3]))
}
fn service_sid(name: &str) -> io::Result<String> {
    let account = wide(&format!("NT SERVICE\\{name}"));
    let mut bytes = 0;
    let mut domain_len = 0;
    let mut use_ = 0;
    // SAFETY: sizing call followed by aligned allocation, outputs retained for SID conversion.
    unsafe {
        LookupAccountNameW(
            null(),
            account.as_ptr(),
            null_mut(),
            &mut bytes,
            null_mut(),
            &mut domain_len,
            &mut use_,
        );
        require(
            bytes > 0 && bytes <= 65536 && domain_len <= 32768,
            "service SID lookup size",
        )?;
        let mut sid = vec![0usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
        let mut domain = vec![0u16; domain_len as usize];
        win(LookupAccountNameW(
            null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut bytes,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut use_,
        ))?;
        let text = sid_text(sid.as_mut_ptr().cast())?;
        require(
            text.starts_with("S-1-5-80-") && text.split('-').count() == 9,
            "not a virtual service SID",
        )?;
        Ok(text)
    }
}
fn audit_directory(path: &str) -> io::Result<File> {
    audit_directory_policy(path, None)
}
fn audit_directory_policy(path: &str, private_sid: Option<&str>) -> io::Result<File> {
    let file = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let info = file_info(&file)?;
    require(
        info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
            && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "nonphysical ancestor",
    )?;
    let mut sd = null_mut();
    // SAFETY: live handle and native allocated descriptor retained until audit returns.
    unsafe {
        let code = GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        );
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        let _guard = Descriptor(sd);
        match private_sid {
            Some(sid) => audit_private_sd(sd, sid)?,
            None => audit_sd(sd, true)?,
        };
        let mut final_name = vec![0u16; 32768];
        let n = GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            final_name.as_mut_ptr(),
            final_name.len() as u32,
            0,
        ) as usize;
        require(n > 0 && n < final_name.len(), "cannot resolve ancestor")?;
        let final_name =
            String::from_utf16(&final_name[..n]).map_err(|_| io::ErrorKind::InvalidData)?;
        require(
            final_name.eq_ignore_ascii_case(&format!(r"\\?\{path}")),
            "aliased ancestor",
        )?;
    }
    Ok(file)
}
fn pin_parents(path: &str) -> io::Result<Vec<File>> {
    let parent = Path::new(path)
        .parent()
        .ok_or(io::ErrorKind::InvalidInput)?;
    let parent = normalized(parent)?;
    let mut pins = vec![audit_directory(&parent[..3])?];
    let mut fs = [0u16; 32];
    let mut device = vec![0u16; 32768];
    // SAFETY: live volume-root handle and bounded output buffers.
    unsafe {
        win(GetVolumeInformationByHandleW(
            pins[0].as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            fs.as_mut_ptr(),
            fs.len() as u32,
        ))?;
        require(
            GetDriveTypeW(wide(&parent[..3]).as_ptr()) == 3,
            "fixed drive required",
        )?;
        let n = QueryDosDeviceW(
            wide(&parent[..2]).as_ptr(),
            device.as_mut_ptr(),
            device.len() as u32,
        ) as usize;
        require(n > 0 && n < device.len(), "cannot resolve volume")?;
    }
    let text = |b: &[u16]| {
        String::from_utf16_lossy(&b[..b.iter().position(|v| *v == 0).unwrap_or(b.len())])
    };
    require(
        text(&fs) == "NTFS"
            && text(&device)
                .strip_prefix(r"\Device\HarddiskVolume")
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())),
        "physical NTFS required",
    )?;
    if parent.len() > 3 {
        let mut current = parent[..3].to_owned();
        for part in parent[3..].split('\\') {
            if current.len() > 3 {
                current.push('\\');
            }
            current.push_str(part);
            pins.push(audit_directory(&current)?);
        }
    }
    Ok(pins)
}
fn mkdir(path: &Path, grants: &str) -> io::Result<()> {
    let sd = Descriptor::new(&format!(
        "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA){grants}"
    ))?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let text = normalized(path)?;
    // SAFETY: CreateDirectory creates the fresh leaf atomically with its final ACL;
    // caller retains audited parent pins and never adopts an existing leaf.
    unsafe { win(CreateDirectoryW(wide(&text).as_ptr(), &attributes)) }
}
fn file_sddl(readers: &[&str]) -> String {
    let mut sddl = String::from("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)");
    for reader in readers {
        sddl.push_str(&format!("(A;;FRFX;;;{reader})"));
    }
    sddl
}
fn protected_file(path: &Path, readers: &[&str]) -> io::Result<File> {
    let sd = Descriptor::new(&file_sddl(readers))?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let text = normalized(path)?;
    // SAFETY: atomic CREATE_NEW with administrator owner and immutable consumer
    // ACL from first visibility. Caller holds audited immutable parent namespace.
    let raw = unsafe {
        CreateFileW(
            wide(&text).as_ptr(),
            GENERIC_WRITE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateFile transferred unique ownership.
    Ok(unsafe { File::from_raw_handle(raw) })
}
fn json_new(path: &Path, value: &impl Serialize) -> io::Result<()> {
    json_readers(path, value, &[])
}
fn json_readers(path: &Path, value: &impl Serialize, readers: &[&str]) -> io::Result<()> {
    let data = serde_json::to_vec_pretty(value).map_err(io::Error::other)?;
    let mut file = protected_file(path, readers)?;
    file.write_all(&data)?;
    file.sync_all()
}
struct Sc(SC_HANDLE);
impl Drop for Sc {
    fn drop(&mut self) {
        // SAFETY: owns a successful SCM API result.
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
fn manager(access: u32) -> io::Result<Sc> {
    // SAFETY: local SCM, default database, explicit rights.
    let raw = unsafe { OpenSCManagerW(null(), null(), access) };
    if raw.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(Sc(raw))
    }
}
fn command(p: &Plan, sid: &str) -> String {
    let root = &p.install_root;
    [
        format!("{root}\\bin\\hermes-memory-broker.exe"),
        "service".into(),
        "--root".into(),
        format!("{root}\\store"),
        "--temp-dir".into(),
        format!("{root}\\temp"),
        "--pipe".into(),
        p.pipe.clone(),
        "--server-sid".into(),
        sid.into(),
        "--client-sid".into(),
        p.client_sid.clone(),
        "--workspace".into(),
        p.workspace.clone(),
        "--service-name".into(),
        p.service_name.clone(),
        "--bootstrap-config".into(),
        format!("{root}\\cfg\\bootstrap.json"),
    ]
    .iter()
    .map(|s| quote_arg(s))
    .collect::<Vec<_>>()
    .join(" ")
}
const DIRECTORIES: [&str; 7] = ["", "bin", "clients", "cfg", "archive", "store", "temp"];
fn directory_path(root: &Path, name: &str) -> io::Result<String> {
    if name.is_empty() {
        normalized(root)
    } else {
        normalized(&root.join(name))
    }
}
fn directory_inventory_valid(ids: &std::collections::BTreeMap<String, Identity>) -> bool {
    ids.len() == DIRECTORIES.len() && DIRECTORIES.iter().all(|key| ids.contains_key(*key))
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    schema: u32,
    state: String,
    inputs: Inputs,
    plan: Plan,
    server_sid: String,
    command: String,
    broker_identity: Identity,
    client_identity: Identity,
    directories: std::collections::BTreeMap<String, Identity>,
    broker_source_identity: Identity,
    client_source_identity: Identity,
}
/// Fresh installation only. Failures retain the namespace and content-free intent.
/// No cleanup ever deletes canonical data, and prepare never starts the service.
pub fn prepare(inputs: &Inputs, allow: bool) -> io::Result<Receipt> {
    require_consent(allow)?;
    let p = plan(inputs)?;
    administrator(allow)?;
    let mut broker =
        PinnedSource::open(Path::new(&inputs.broker_source), &p.broker_sha256, 1 << 30)?;
    let mut client =
        PinnedSource::open(Path::new(&inputs.client_source), &p.client_sha256, 1 << 30)?;
    let _ancestors = pin_parents(&p.install_root)?;
    let scm = manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    // SAFETY: query only; existing services are NEVER adopted.
    let existing =
        unsafe { OpenServiceW(scm.0, wide(&p.service_name).as_ptr(), SERVICE_QUERY_CONFIG) };
    if !existing.is_null() {
        drop(Sc(existing));
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "service already exists",
        ));
    }
    require(
        unsafe { GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST,
        "cannot establish absent service",
    )?;
    let sid = service_sid(&p.service_name)?;
    require(sid != p.client_sid, "service and client overlap")?;
    let root_path = std::path::PathBuf::from(&p.install_root);
    let root = root_path.as_path();
    let readers = format!("(A;OICI;FRFX;;;{sid})(A;OICI;FRFX;;;{})", p.client_sid);
    mkdir(root, &readers)?;
    json_new(
        &root.join("intent.json"),
        &serde_json::json!({"schema":1,"state":"PREPARING_RETAIN_ON_FAILURE","plan":p,"server_sid":sid}),
    )?;
    let result = (|| {
        for name in ["bin", "clients"] {
            mkdir(&root.join(name), &readers)?;
        }
        for name in ["cfg", "archive"] {
            mkdir(&root.join(name), &format!("(A;OICI;FRFX;;;{sid})"))?;
        }
        for name in ["store", "temp"] {
            mkdir(&root.join(name), &format!("(A;OICI;FA;;;{sid})"))?;
        }
        let broker_identity = broker.copy_protected(
            &root.join("bin/hermes-memory-broker.exe"),
            &[&sid, &p.client_sid],
        )?;
        let client_identity = client.copy_protected(
            &root.join("bin/hermes-memory-client.exe"),
            &[&sid, &p.client_sid],
        )?;
        let mut directories = std::collections::BTreeMap::new();
        let mut directory_pins = Vec::new();
        for name in DIRECTORIES {
            let text = directory_path(root, name)?;
            let pin = audit_directory_policy(
                &text,
                if matches!(name, "store" | "temp") {
                    Some(&sid)
                } else {
                    None
                },
            )?;
            directories.insert(name.to_owned(), identity(&file_info(&pin)?));
            directory_pins.push(pin);
        }
        let cmd = command(&p, &sid);
        let receipt = Receipt {
            schema: 1,
            state: "NAMESPACE_PREPARED".into(),
            command: cmd.clone(),
            server_sid: sid.clone(),
            plan: p.clone(),
            inputs: inputs.clone(),
            broker_identity,
            client_identity,
            directories,
            broker_source_identity: broker.id,
            client_source_identity: client.id,
        };
        json_new(&root.join("receipt.json"), &receipt)?;
        let account = format!("NT SERVICE\\{}", p.service_name);
        // SAFETY: valid pinned executable, terminated strings retained during native call.
        let raw = unsafe {
            CreateServiceW(
                scm.0,
                wide(&p.service_name).as_ptr(),
                wide(&p.service_name).as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                wide(&cmd).as_ptr(),
                null(),
                null_mut(),
                null(),
                wide(&account).as_ptr(),
                null(),
            )
        };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let service = Sc(raw);
        let service_sd = Descriptor::new("O:BAG:BAD:P(A;;0xf01ff;;;SY)(A;;0xf01ff;;;BA)")?;
        let mut sid_policy = SERVICE_SID_INFO {
            dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
        };
        let mut privileges = wide("SeChangeNotifyPrivilege");
        privileges.push(0);
        let mut required = SERVICE_REQUIRED_PRIVILEGES_INFOW {
            pmszRequiredPrivileges: privileges.as_mut_ptr(),
        };
        // SAFETY: owned newly-created service and live native structures.
        unsafe {
            win(SetServiceObjectSecurity(
                service.0,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                service_sd.0,
            ))?;
            win(ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_SERVICE_SID_INFO,
                (&mut sid_policy as *mut SERVICE_SID_INFO).cast(),
            ))?;
            win(ChangeServiceConfig2W(
                service.0,
                SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
                (&mut required as *mut SERVICE_REQUIRED_PRIVILEGES_INFOW).cast(),
            ))?;
        }
        json_readers(
            Path::new(&p.enrollment),
            &serde_json::json!({"schema":1,"profile_root":p.legacy_root,"service_name":p.service_name,"server_sid":sid,"client_sid":p.client_sid,"pipe":p.pipe,"workspaces":[p.workspace],"release_sha256":p.release_sha256}),
            &[&p.client_sid],
        )?;
        json_new(
            &root.join("prepared.json"),
            &serde_json::json!({"schema":1,"state":"PREPARED_NOT_STARTED"}),
        )?;
        Ok(receipt)
    })();
    if result.is_err() {
        json_new(
            &root.join("prepare-failed.json"),
            &serde_json::json!({"schema":1,"state":"PREPARE_FAILED_RETAINED","automatic_cleanup":false}),
        )?;
    }
    result
}
fn prepared_marker_valid(value: &serde_json::Value) -> bool {
    *value == serde_json::json!({"schema":1,"state":"PREPARED_NOT_STARTED"})
}
fn protected_json<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<T> {
    serde_json::from_reader(crate::windows_enrollment::open_admin_owned_file(
        path, 65536,
    )?)
    .map_err(io::Error::other)
}
fn read_receipt(path: &Path) -> io::Result<Receipt> {
    let r: Receipt = protected_json(path)?;
    let planned = plan(&r.inputs)?;
    require(
        directory_inventory_valid(&r.directories),
        "receipt namespace inventory mismatch",
    )?;
    require(
        r.schema == 1
            && r.state == "NAMESPACE_PREPARED"
            && r.plan == planned
            && r.command == command(&planned, &r.server_sid)
            && normalized(path)? == format!("{}\\receipt.json", planned.install_root),
        "receipt schema/paths/bindings mismatch",
    )?;
    require(
        service_sid(&planned.service_name)? == r.server_sid && r.server_sid != planned.client_sid,
        "receipt service SID mismatch",
    )?;
    Ok(r)
}
fn service_status(s: &Sc) -> io::Result<SERVICE_STATUS_PROCESS> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut size = 0;
    // SAFETY: retained owned service and correctly sized native buffer.
    unsafe {
        win(QueryServiceStatusEx(
            s.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            std::mem::size_of_val(&status) as u32,
            &mut size,
        ))?;
    }
    Ok(status)
}
fn native_string(raw: *const u16, buffer: &[usize]) -> io::Result<String> {
    let start = buffer.as_ptr() as usize;
    let end = start + std::mem::size_of_val(buffer);
    let address = raw as usize;
    require(
        address >= start && address < end && address.is_multiple_of(2),
        "SCM string outside buffer",
    )?;
    // SAFETY: query-produced pointer bounded to live allocation before reading.
    let slice = unsafe { std::slice::from_raw_parts(raw, (end - address) / 2) };
    let n = slice
        .iter()
        .position(|v| *v == 0)
        .ok_or(io::ErrorKind::InvalidData)?;
    String::from_utf16(&slice[..n]).map_err(|_| io::ErrorKind::InvalidData.into())
}
fn owned_service(r: &Receipt, rights: u32) -> io::Result<Sc> {
    let scm = manager(SC_MANAGER_CONNECT)?;
    // SAFETY: receipt binds validated service name, local SCM, explicit rights.
    let raw = unsafe {
        OpenServiceW(
            scm.0,
            wide(&r.plan.service_name).as_ptr(),
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | rights,
        )
    };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let service = Sc(raw);
    let mut needed = 0;
    // SAFETY: first call sizes the native configuration buffer.
    unsafe {
        QueryServiceConfigW(service.0, null_mut(), 0, &mut needed);
    }
    require(
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
        require(
            configuration_matches(
                &native_string(c.lpBinaryPathName, &buf)?,
                &native_string(c.lpServiceStartName, &buf)?,
                c.dwServiceType,
                c.dwStartType,
                &r.command,
                &format!("NT SERVICE\\{}", r.plan.service_name),
            ),
            "registered service ownership mismatch",
        )?;
        require(
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
        require(
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
        require(
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
        require(
            name == "SeChangeNotifyPrivilege"
                && native_string(p.add(name.encode_utf16().count() + 1), &b)?.is_empty(),
            "required privileges differ",
        )?;
    }
    Ok(service)
}
struct Admission {
    receipt: Receipt,
    service: Sc,
    _parents: Vec<File>,
    _broker: PinnedSource,
    _client: PinnedSource,
}
fn admit(path: &Path, rights: u32) -> io::Result<Admission> {
    let receipt = read_receipt(path)?;
    let mut parents = pin_parents(&format!("{}\\receipt.json", receipt.plan.install_root))?;
    let root = Path::new(&receipt.plan.install_root);
    // Protected readers audit each executable and all its ancestors before the hash pins.
    let broker_audit = crate::windows_enrollment::open_admin_owned_file(
        &root.join("bin/hermes-memory-broker.exe"),
        1 << 30,
    )?;
    let client_audit = crate::windows_enrollment::open_admin_owned_file(
        &root.join("bin/hermes-memory-client.exe"),
        1 << 30,
    )?;
    let broker = PinnedSource::open(
        &root.join("bin/hermes-memory-broker.exe"),
        &receipt.plan.broker_sha256,
        1 << 30,
    )?;
    let client = PinnedSource::open(
        &root.join("bin/hermes-memory-client.exe"),
        &receipt.plan.client_sha256,
        1 << 30,
    )?;
    require(
        broker.id == receipt.broker_identity && client.id == receipt.client_identity,
        "installed payload identity mismatch",
    )?;
    for (name, expected) in &receipt.directories {
        let text = directory_path(root, name)?;
        let pin = audit_directory_policy(
            &text,
            if matches!(name.as_str(), "store" | "temp") {
                Some(&receipt.server_sid)
            } else {
                None
            },
        )?;
        require(
            identity(&file_info(&pin)?) == *expected,
            "namespace directory identity mismatch",
        )?;
        parents.push(pin);
    }
    let service = owned_service(&receipt, rights)?;
    drop((broker_audit, client_audit));
    Ok(Admission {
        receipt,
        service,
        _parents: parents,
        _broker: broker,
        _client: client,
    })
}
fn process_pin(service: &Sc, expected_sid: &str) -> io::Result<Option<OwnedHandle>> {
    let initial = service_status(service)?;
    if initial.dwProcessId == 0 {
        return Ok(None);
    }
    // SAFETY: SCM-reported PID is checked again after opening and verified by token.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            0,
            initial.dwProcessId,
        )
    };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful OpenProcess transferred ownership.
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut token = null_mut();
    // SAFETY: live process handle and token output ownership transfer.
    unsafe {
        win(OpenProcessToken(
            process.as_raw_handle(),
            TOKEN_QUERY,
            &mut token,
        ))?;
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut n = 0;
    // SAFETY: sizing query then aligned bounded allocation.
    unsafe {
        GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut n);
    }
    require(
        n as usize >= std::mem::size_of::<TOKEN_USER>() && n <= 65536,
        "process token size",
    )?;
    let mut buf = vec![0usize; (n as usize).div_ceil(std::mem::size_of::<usize>())];
    unsafe {
        win(GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buf.as_mut_ptr().cast(),
            n,
            &mut n,
        ))?;
        require(
            sid_text((*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid)? == expected_sid,
            "service process TokenUser mismatch",
        )?;
        require(
            WaitForSingleObject(process.as_raw_handle(), 0) == WAIT_TIMEOUT,
            "service process already exited",
        )?;
    }
    require(
        service_status(service)?.dwProcessId == initial.dwProcessId,
        "SCM process changed during admission",
    )?;
    Ok(Some(process))
}
fn stop_owned(service: &Sc, sid: &str) -> io::Result<()> {
    use std::time::{Duration, Instant};
    let process = process_pin(service, sid)?;
    let current = service_status(service)?;
    if current.dwCurrentState != SERVICE_STOPPED && current.dwCurrentState != SERVICE_STOP_PENDING {
        let mut output = SERVICE_STATUS::default();
        // SAFETY: retained exactly admitted service; never a name/PID-based kill.
        unsafe {
            win(ControlService(service.0, SERVICE_CONTROL_STOP, &mut output))?;
        }
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let stopped = service_status(service)?.dwCurrentState == SERVICE_STOPPED;
        // SAFETY: optional retained process object; zero-time wait cannot block.
        let exited = process
            .as_ref()
            .is_none_or(|p| unsafe { WaitForSingleObject(p.as_raw_handle(), 0) } == WAIT_OBJECT_0);
        if stopped && exited {
            return Ok(());
        }
        require(
            Instant::now() < deadline,
            "bounded stop timed out; state retained",
        )?;
        std::thread::sleep(Duration::from_millis(100));
    }
}
/// Does not assert normal-client health or import completion.
pub fn status(path: &Path, allow: bool) -> io::Result<serde_json::Value> {
    administrator(allow)?;
    let a = admit(path, 0)?;
    let s = service_status(&a.service)?;
    let state = if s.dwCurrentState == SERVICE_RUNNING {
        require(
            process_pin(&a.service, &a.receipt.server_sid)?.is_some(),
            "running service has no process",
        )?;
        "SCM_RUNNING_CLIENT_VALIDATION_PENDING"
    } else if s.dwCurrentState == SERVICE_STOPPED {
        "SCM_STOPPED"
    } else {
        "SCM_TRANSITIONAL"
    };
    Ok(
        serde_json::json!({"state":state,"scm_state":s.dwCurrentState,"service_name":a.receipt.plan.service_name,"client_health_verified":false}),
    )
}
pub fn stop(path: &Path, allow: bool) -> io::Result<serde_json::Value> {
    administrator(allow)?;
    let a = admit(path, SERVICE_STOP)?;
    stop_owned(&a.service, &a.receipt.server_sid)?;
    Ok(serde_json::json!({"state":"SCM_STOPPED","data_retained":true}))
}
/// Only the explicitly supplied logical archive is read. No legacy database opens.
pub fn activate(
    path: &Path,
    archive: &Path,
    archive_sha256: &str,
    logical_sha256: &str,
    allow: bool,
) -> io::Result<serde_json::Value> {
    administrator(allow)?;
    require(
        digest_valid(archive_sha256) && digest_valid(logical_sha256),
        "invalid archive/logical pins",
    )?;
    let a = admit(path, SERVICE_START | SERVICE_STOP)?;
    require(
        prepared_marker_valid(&protected_json::<serde_json::Value>(
            &Path::new(&a.receipt.plan.install_root).join("prepared.json"),
        )?),
        "prepare did not complete; retain namespace for recovery",
    )?;
    let source_path = normalized(archive)?;
    require(
        !overlap(&source_path, &a.receipt.plan.legacy_root)
            && !overlap(&source_path, &a.receipt.plan.install_root),
        "archive collides with protected or legacy namespace",
    )?;
    let mut source = PinnedSource::open(archive, archive_sha256, 1 << 30)?;
    let root = Path::new(&a.receipt.plan.install_root);
    // All target parent directories must remain administrator-immutable.
    let _archive_parent = audit_directory(&format!("{}\\archive", a.receipt.plan.install_root))?;
    let _cfg_parent = audit_directory(&format!("{}\\cfg", a.receipt.plan.install_root))?;
    let target = root.join("archive/bootstrap.jsonl");
    let config = root.join("cfg/bootstrap.json");
    let expected =
        serde_json::json!({"schema":1,"archive_path":target,"logical_sha256":logical_sha256});
    // Refuse divergent retries before any writes. Immutable activation pin precedes staging.
    let admission = root.join("activation.json");
    let expected_admission = serde_json::json!({"schema":1,"archive_sha256":archive_sha256,"logical_sha256":logical_sha256});
    match protected_json::<serde_json::Value>(&admission) {
        Ok(value) => require(
            value == expected_admission,
            "activation pin differs; state retained",
        )?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => json_new(&admission, &expected_admission)?,
        Err(e) => return Err(e),
    }
    let result = (|| {
        match crate::windows_enrollment::open_admin_owned_file(&target, 1 << 30) {
            Ok(_guard) => {
                let _verified = PinnedSource::open(&target, archive_sha256, 1 << 30)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                source.copy_protected(&target, &[&a.receipt.server_sid])?;
            }
            Err(e) => return Err(e),
        }
        match protected_json::<serde_json::Value>(&config) {
            Ok(value) => require(value == expected, "bootstrap config differs")?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                json_readers(&config, &expected, &[&a.receipt.server_sid])?
            }
            Err(e) => return Err(e),
        }
        let initial = service_status(&a.service)?;
        if initial.dwCurrentState == SERVICE_STOPPED {
            // SAFETY: exact owned registration, no service command-line overrides.
            unsafe {
                win(StartServiceW(a.service.0, 0, null()))?;
            }
        } else {
            require(
                initial.dwCurrentState == SERVICE_RUNNING,
                "service is transitional",
            )?;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let s = service_status(&a.service)?;
            if s.dwCurrentState == SERVICE_RUNNING {
                require(
                    process_pin(&a.service, &a.receipt.server_sid)?.is_some(),
                    "running service has no process",
                )?;
                return Ok(
                    serde_json::json!({"state":"SCM_RUNNING_CLIENT_VALIDATION_PENDING","client_health_verified":false,"logical_sha256":logical_sha256}),
                );
            }
            require(
                s.dwCurrentState != SERVICE_STOPPED && std::time::Instant::now() < deadline,
                "service failed to reach RUNNING; import outcome unknown",
            )?;
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    })();
    if result.is_err() {
        let stopped = stop_owned(&a.service, &a.receipt.server_sid).is_ok();
        // Append-only recovery markers; no database deletion or unknown-commit retry.
        let mut index = 0u32;
        loop {
            let event = root.join(format!("activation-failure-{index}.json"));
            match json_new(
                &event,
                &serde_json::json!({"schema":1,"state":"ACTIVATION_FAILED_OUTCOME_UNKNOWN","stop_confirmed":stopped,"data_retained":true,"logical_sha256":logical_sha256}),
            ) {
                Ok(()) => break,
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && index < 1000 => index += 1,
                Err(e) => return Err(e),
            }
        }
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_pin_rejects_hash_hardlinks_and_denies_write_delete() {
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("payload");
        std::fs::write(&source, b"abc").unwrap();
        let pin = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(PinnedSource::open(&source, &"0".repeat(64), 10).is_err());
        assert!(PinnedSource::open(&source, pin, 2).is_err());
        let mut pinned = PinnedSource::open(&source, pin, 10).unwrap();
        assert!(std::fs::OpenOptions::new()
            .write(true)
            .open(&source)
            .is_err());
        assert!(std::fs::remove_file(&source).is_err());
        let target = d.path().join("copy");
        pinned.copy_new(&target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"abc");
        assert!(pinned.copy_new(&target).is_err());
        drop(pinned);
        std::fs::hard_link(&source, d.path().join("alias")).unwrap();
        assert!(PinnedSource::open(&source, pin, 10).is_err());
    }
    #[test]
    fn consent_gate_precedes_any_machine_access() {
        assert!(require_consent(false).is_err());
    }
    #[test]
    fn protected_descriptors_reject_client_mutation() {
        let safe = Descriptor::new("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)")
            .unwrap();
        assert!(audit_sd(safe.0, true).is_ok());
        let unsafe_acl =
            Descriptor::new("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)").unwrap();
        assert!(audit_sd(unsafe_acl.0, true).is_err());
    }
    #[test]
    fn ownership_requires_exact_command_account_and_policy() {
        assert!(configuration_matches(
            "cmd",
            "NT SERVICE\\Fixture",
            16,
            3,
            "cmd",
            "NT SERVICE\\Fixture"
        ));
        assert!(!configuration_matches(
            "cmd extra",
            "NT SERVICE\\Fixture",
            16,
            3,
            "cmd",
            "NT SERVICE\\Fixture"
        ));
        assert!(!configuration_matches(
            "cmd",
            "LocalSystem",
            16,
            3,
            "cmd",
            "NT SERVICE\\Fixture"
        ));
        assert!(!configuration_matches(
            "cmd",
            "NT SERVICE\\Fixture",
            32,
            3,
            "cmd",
            "NT SERVICE\\Fixture"
        ));
        assert!(!configuration_matches(
            "cmd",
            "NT SERVICE\\Fixture",
            16,
            2,
            "cmd",
            "NT SERVICE\\Fixture"
        ));
    }
    #[test]
    fn lifecycle_refuses_without_opt_in_before_path_or_token_access() {
        assert_eq!(
            prepare(&inputs(), false).unwrap_err().to_string(),
            "explicit --allow-machine-provision required"
        );
        assert_eq!(
            status(Path::new("not-absolute"), false)
                .unwrap_err()
                .to_string(),
            "explicit --allow-machine-provision required"
        );
        assert_eq!(
            stop(Path::new("not-absolute"), false)
                .unwrap_err()
                .to_string(),
            "explicit --allow-machine-provision required"
        );
        assert_eq!(
            activate(
                Path::new("not-absolute"),
                Path::new("no-archive"),
                "",
                "",
                false
            )
            .unwrap_err()
            .to_string(),
            "explicit --allow-machine-provision required"
        );
    }
    #[test]
    fn plan_bounds_registration_before_writes() {
        let mut i = inputs();
        i.install_root = format!("C:\\{}", "x".repeat(3000));
        assert!(plan(&i).is_err());
        let mut i = inputs();
        i.legacy_root = format!("C:\\{}", "x".repeat(3000));
        assert!(plan(&i).is_err());
    }
    #[test]
    fn private_descriptor_excludes_client_and_preserves_service_access() {
        let server = "S-1-5-80-1-2-3-4-5";
        let safe = Descriptor::new(&format!(
            "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{server})"
        ))
        .unwrap();
        assert!(audit_private_sd(safe.0, server).is_ok());
        let bad = Descriptor::new(&format!(
            "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{server})(A;OICI;FR;;;BU)"
        ))
        .unwrap();
        assert!(audit_private_sd(bad.0, server).is_err());
    }
    #[test]
    fn new_file_descriptor_has_admin_owner_and_read_only_consumers() {
        let sd =
            Descriptor::new(&file_sddl(&["S-1-5-80-1-2-3-4-5", "S-1-5-21-1-2-3-1001"])).unwrap();
        assert!(audit_sd(sd.0, false).is_ok());
    }
    #[test]
    fn receipt_directory_inventory_is_exact_not_arbitrary_paths() {
        let mut ids = std::collections::BTreeMap::new();
        let id = Identity {
            volume: 1,
            high: 0,
            low: 1,
        };
        for name in ["", "bin", "clients", "cfg", "archive", "store", "temp"] {
            ids.insert(name.to_string(), id);
        }
        assert!(directory_inventory_valid(&ids));
        ids.insert("../other".into(), id);
        assert!(!directory_inventory_valid(&ids));
        ids.remove("../other");
        ids.remove("store");
        assert!(!directory_inventory_valid(&ids));
    }
    #[test]
    fn copying_rechecks_content_pin_on_the_retained_handle() {
        let d = tempfile::tempdir().unwrap();
        let original = d.path().join("original");
        let changed = d.path().join("changed");
        std::fs::write(&original, b"abc").unwrap();
        std::fs::write(&changed, b"xyz").unwrap();
        let mut pinned = PinnedSource::open(
            &original,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            10,
        )
        .unwrap();
        // Unit-only adapter for changed contents (e.g. a pre-existing mapping).
        // No source path is reopened by the production copy routine.
        pinned.file = File::open(changed).unwrap();
        assert!(pinned.copy_new(&d.path().join("copy")).is_err());
    }
    #[test]
    fn root_inventory_path_never_introduces_trailing_separator() {
        assert_eq!(
            directory_path(Path::new(r"C:\Owned"), "").unwrap(),
            r"c:\owned"
        );
        assert_eq!(
            directory_path(Path::new(r"C:\Owned"), "store").unwrap(),
            r"c:\owned\store"
        );
    }
    #[test]
    fn activation_requires_exact_completed_prepare_marker() {
        assert!(prepared_marker_valid(
            &serde_json::json!({"schema":1,"state":"PREPARED_NOT_STARTED"})
        ));
        assert!(!prepared_marker_valid(
            &serde_json::json!({"schema":1,"state":"PREPARING"})
        ));
        assert!(!prepared_marker_valid(
            &serde_json::json!({"schema":1,"state":"PREPARED_NOT_STARTED","extra":true})
        ));
    }
    fn inputs() -> Inputs {
        Inputs {
            legacy_root: r"C:\Users\Fixture\memory-vault".into(),
            client_sid: "S-1-5-21-1-2-3-1001".into(),
            workspace: "one".into(),
            install_root: r"C:\HermesMemoryVault".into(),
            service_name: None,
            broker_source: r"C:\release\broker.exe".into(),
            broker_sha256: "a".repeat(64),
            client_source: r"C:\release\client.exe".into(),
            client_sha256: "b".repeat(64),
            release_sha256: "c".repeat(64),
        }
    }
    #[test]
    fn plan_is_lexical_and_rejects_ambiguous_or_colliding_inputs() {
        let p = plan(&inputs()).unwrap();
        assert!(p.enrollment.ends_with(&format!("clients\\{}.json", p.key)));
        assert_eq!(p.legacy_root, r"c:\users\fixture\memory-vault");
        for bad in ["", "../bad", "bad name", "evil\"x"] {
            let mut i = inputs();
            i.service_name = Some(bad.into());
            assert!(plan(&i).is_err());
        }
        for bad in ["S-1-5-21-01", "S-1-5-18", "S-1-5-32-544", "S-01-5-21-1"] {
            let mut i = inputs();
            i.client_sid = bad.into();
            assert!(plan(&i).is_err());
        }
        let mut i = inputs();
        i.install_root = i.legacy_root.clone();
        assert!(plan(&i).is_err());
        let mut i = inputs();
        i.broker_source = r"C:\HermesMemoryVault\bin\broker.exe".into();
        assert!(plan(&i).is_err());
        let mut i = inputs();
        i.workspace = "*".into();
        assert!(plan(&i).is_err());
        let mut i = inputs();
        i.broker_sha256 = "A".repeat(64);
        assert!(plan(&i).is_err());
    }
    #[test]
    fn windows_argv_quotes_empty_spaces_quotes_and_terminal_slashes() {
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("plain"), "\"plain\"");
        assert_eq!(quote_arg("a b"), "\"a b\"");
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_arg("C:\\dir\\"), "\"C:\\dir\\\\\"");
        assert_eq!(quote_arg("a\\\"b"), "\"a\\\\\\\"b\"");
    }
}
