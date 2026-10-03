//! Native benchmark evidence. Logical process IO is NOT physical disk IO.
//! File evidence requires a quiescent writer; checks detect common concurrent
//! changes but are not an atomic filesystem snapshot or a JSONL syntax validator.
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    pub volume_serial_number: u64,
    pub file_id: [u8; 16],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsonlSnapshot {
    pub identity: FileIdentity,
    pub length: u64,
    /// Lowercase SHA256 of exactly `length` bytes, starting at offset zero.
    pub prefix_sha256: String,
}

#[cfg(windows)]
fn file_identity(file: &File) -> io::Result<FileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
    };
    // SAFETY: FILE_ID_INFO contains integer fields and a byte array only.
    let mut info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: file owns a live handle; info is a correctly sized writable buffer.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity {
        volume_serial_number: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
}

#[cfg(not(windows))]
fn file_identity(_file: &File) -> io::Result<FileIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows FILE_ID_INFO is required",
    ))
}

/// Hash exactly the first `prefix_len` bytes using a fixed 64-KiB buffer.
/// Seeks to zero and leaves the cursor at `prefix_len`. A short file is an error.
pub fn prefix_sha256(file: &mut File, prefix_len: u64) -> io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut remaining = prefix_len;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let chunk = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..chunk])?;
        digest.update(&buffer[..chunk]);
        remaining -= chunk as u64;
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn stable_file(file: &File, initial: &Metadata) -> io::Result<()> {
    let current = file.metadata()?;
    if initial.len() != current.len() || initial.modified()? != current.modified()? {
        return Err(io::Error::other("file changed while collecting evidence"));
    }
    Ok(())
}

fn open_evidence(path: &Path) -> io::Result<(File, Metadata, FileIdentity)> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "evidence must be a regular file",
        ));
    }
    let identity = file_identity(&file)?;
    Ok((file, metadata, identity))
}

fn verify_path_identity(path: &Path, identity: &FileIdentity) -> io::Result<()> {
    if file_identity(&File::open(path)?)? != *identity {
        return Err(io::Error::other("path replaced while collecting evidence"));
    }
    Ok(())
}

pub fn snapshot_jsonl(path: &Path) -> io::Result<JsonlSnapshot> {
    let (mut file, metadata, identity) = open_evidence(path)?;
    let prefix_sha256 = prefix_sha256(&mut file, metadata.len())?;
    stable_file(&file, &metadata)?;
    verify_path_identity(path, &identity)?;
    Ok(JsonlSnapshot {
        identity,
        length: metadata.len(),
        prefix_sha256,
    })
}

/// Prove identity, non-shrinking length and original-prefix preservation.
/// An unchanged file is accepted; callers requiring an append must also assert
/// `after.length > before.length`. The resulting hash covers the new length.
pub fn verify_append(path: &Path, before: &JsonlSnapshot) -> io::Result<JsonlSnapshot> {
    let (mut file, metadata, identity) = open_evidence(path)?;
    if identity != before.identity {
        return Err(io::Error::other("JSONL file identity changed"));
    }
    if metadata.len() < before.length {
        return Err(io::Error::other("JSONL file was truncated"));
    }
    if prefix_sha256(&mut file, before.length)? != before.prefix_sha256 {
        return Err(io::Error::other("JSONL original prefix changed"));
    }
    let prefix_sha256 = prefix_sha256(&mut file, metadata.len())?;
    stable_file(&file, &metadata)?;
    verify_path_identity(path, &identity)?;
    Ok(JsonlSnapshot {
        identity,
        length: metadata.len(),
        prefix_sha256,
    })
}

/// GetProcessIoCounters totals: logical IO for files, devices, pipes and network,
/// not physical disk traffic. These counters are cumulative for process lifetime.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LogicalIoCounters {
    pub read_operations: u64,
    pub write_operations: u64,
    pub other_operations: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub other_bytes: u64,
}

impl LogicalIoCounters {
    /// Both samples must belong to the same pinned process handle. Counter
    /// regression is an error, never saturated or silently treated as zero IO.
    pub fn checked_delta(&self, earlier: &Self) -> io::Result<Self> {
        let subtract = |now: u64, old: u64| {
            now.checked_sub(old)
                .ok_or_else(|| io::Error::other("logical process IO counter regressed"))
        };
        Ok(Self {
            read_operations: subtract(self.read_operations, earlier.read_operations)?,
            write_operations: subtract(self.write_operations, earlier.write_operations)?,
            other_operations: subtract(self.other_operations, earlier.other_operations)?,
            read_bytes: subtract(self.read_bytes, earlier.read_bytes)?,
            write_bytes: subtract(self.write_bytes, earlier.write_bytes)?,
            other_bytes: subtract(self.other_bytes, earlier.other_bytes)?,
        })
    }
}

/// Memory values are individual-process observations, not simultaneous totals.
/// A stage maximum of current samples is only a sampled lower bound; lifetime
/// peaks include earlier startup and live child samples can miss terminal peaks.
/// Never sum independent peaks or substitute B supervisor memory for CLI memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessSnapshot {
    pub logical_io: LogicalIoCounters,
    /// Current private commit: PROCESS_MEMORY_COUNTERS_EX::PrivateUsage.
    pub private_bytes: u64,
    /// Lifetime peak private commit: PROCESS_MEMORY_COUNTERS_EX::PeakPagefileUsage.
    /// This is NOT peak working set or a peak scoped to the benchmark interval.
    pub peak_private_bytes: u64,
    /// Current resident working set, which can include shared pages.
    pub working_set_bytes: u64,
    /// Process lifetime peak resident working set, NOT peak private commit.
    pub peak_working_set_bytes: u64,
}

/// Read actual counters from a pinned process, rejecting exit before/after reads.
/// The two API calls are sequential, not an atomic snapshot. Exit immediately
/// after the final check is inherently possible; keep checking the same handle.
///
/// # Safety
/// `handle` must remain a valid process HANDLE throughout this call, with
/// PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE access. The caller
/// owns/pins it; this function neither reopens by PID nor takes/closes ownership.
#[cfg(windows)]
pub unsafe fn sample_process(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> io::Result<ProcessSnapshot> {
    use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessIoCounters, WaitForSingleObject, IO_COUNTERS,
    };

    if handle.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "null process handle",
        ));
    }
    let ensure_running = || -> io::Result<()> {
        // SAFETY: caller guarantees the borrowed process handle remains valid.
        match unsafe { WaitForSingleObject(handle, 0) } {
            WAIT_TIMEOUT => Ok(()),
            WAIT_OBJECT_0 => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "pinned process has exited",
            )),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::Error::other("unexpected process wait result")),
        }
    };
    ensure_running()?;
    // SAFETY: these Win32 output structs contain only integer fields; zero is valid.
    let mut counters: IO_COUNTERS = unsafe { std::mem::zeroed() };
    // SAFETY: handle is borrowed and live, output buffer has exact required size.
    if unsafe { GetProcessIoCounters(handle, &mut counters) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the Win32 output struct contains only integer fields.
    let mut memory: PROCESS_MEMORY_COUNTERS_EX = unsafe { std::mem::zeroed() };
    memory.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;
    // SAFETY: the EX layout extends PROCESS_MEMORY_COUNTERS; cb explicitly tells
    // Windows the full EX allocation size. Handle and writable buffer are valid.
    if unsafe {
        GetProcessMemoryInfo(
            handle,
            (&mut memory as *mut PROCESS_MEMORY_COUNTERS_EX).cast::<PROCESS_MEMORY_COUNTERS>(),
            memory.cb,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    ensure_running()?;
    Ok(ProcessSnapshot {
        logical_io: LogicalIoCounters {
            read_operations: counters.ReadOperationCount,
            write_operations: counters.WriteOperationCount,
            other_operations: counters.OtherOperationCount,
            read_bytes: counters.ReadTransferCount,
            write_bytes: counters.WriteTransferCount,
            other_bytes: counters.OtherTransferCount,
        },
        private_bytes: memory.PrivateUsage as u64,
        peak_private_bytes: memory.PeakPagefileUsage as u64,
        working_set_bytes: memory.WorkingSetSize as u64,
        peak_working_set_bytes: memory.PeakWorkingSetSize as u64,
    })
}

/// Query final lifetime logical process IO only after a retained direct child exits.
/// Includes files/devices/pipes, NOT physical disk traffic. No memory is returned:
/// absent live samples remain missing coverage, never fabricated zero memory.
///
/// # Safety
/// `handle` must be the caller's retained direct-child process handle (or a
/// duplicate), valid throughout this call, with PROCESS_QUERY_INFORMATION and
/// SYNCHRONIZE access. No PID reopen, ownership transfer, close or termination.
/// Direct-child provenance is the caller's obligation, not inferable from HANDLE.
#[cfg(windows)]
pub unsafe fn sample_exited_child_logical_io(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> io::Result<LogicalIoCounters> {
    use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        GetProcessIoCounters, WaitForSingleObject, IO_COUNTERS,
    };
    if handle.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "null child process handle",
        ));
    }
    // SAFETY: caller pins a valid process handle with synchronization access.
    match unsafe { WaitForSingleObject(handle, 0) } {
        WAIT_OBJECT_0 => (),
        WAIT_TIMEOUT => {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "retained child is still running",
            ))
        }
        WAIT_FAILED => return Err(io::Error::last_os_error()),
        _ => return Err(io::Error::other("unexpected child process wait result")),
    }
    // SAFETY: IO_COUNTERS has only integer fields and the output buffer is valid.
    let mut counters: IO_COUNTERS = unsafe { std::mem::zeroed() };
    // SAFETY: retained exited process handle still pins the kernel process object.
    if unsafe { GetProcessIoCounters(handle, &mut counters) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(LogicalIoCounters {
        read_operations: counters.ReadOperationCount,
        write_operations: counters.WriteOperationCount,
        other_operations: counters.OtherOperationCount,
        read_bytes: counters.ReadTransferCount,
        write_bytes: counters.WriteTransferCount,
        other_bytes: counters.OtherTransferCount,
    })
}

#[cfg(all(test, windows))]
#[path = "metrics_tests.rs"]
mod tests;
