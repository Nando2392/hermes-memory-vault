use super::*;
use std::io::Write;

#[test]
#[ignore = "ordinary subprocess payload; invoked explicitly by parent test"]
fn logical_io_child_payload() {
    let root = std::path::PathBuf::from(std::env::var_os("HMV_METRICS_CHILD_DIR").unwrap());
    let mut file = File::create(root.join("payload.bin")).unwrap();
    file.write_all(&[b'x'; 65536]).unwrap();
    file.sync_all().unwrap();
    std::fs::write(root.join("ready"), b"ready").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !root.join("release").exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "parent release deadline"
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    file.write_all(&[b'y'; 65536]).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn retained_ordinary_child_final_logical_io_includes_terminal_writes() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle};
    use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
    use windows_sys::Win32::System::Threading::*;
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill(); // Retained direct child only, on test failure.
            }
            let _ = self.0.wait();
        }
    }
    struct Pin(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for Pin {
        fn drop(&mut self) {
            // SAFETY: exclusively owns the duplicated handle.
            unsafe { CloseHandle(self.0) };
        }
    }
    let root = tempfile::tempdir().unwrap();
    let test_name = format!(
        "{}::logical_io_child_payload",
        module_path!().split_once("::").unwrap().1
    );
    let mut child = ChildGuard(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", &test_name])
            .env("HMV_METRICS_CHILD_DIR", root.path())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !root.path().join("ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "payload exited before handshake"
        );
        assert!(std::time::Instant::now() < deadline, "child ready deadline");
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let duplicate = |rights| {
        let mut raw = std::ptr::null_mut();
        // SAFETY: source Child and current process handles remain valid; output is owned.
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    child.0.as_raw_handle(),
                    GetCurrentProcess(),
                    &mut raw,
                    rights,
                    0,
                    0,
                )
            },
            0
        );
        Pin(raw)
    };
    let pin = duplicate(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE);
    let final_only = duplicate(PROCESS_QUERY_INFORMATION | SYNCHRONIZE);
    let no_query = duplicate(SYNCHRONIZE);
    let no_wait = duplicate(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
    // SAFETY: all duplicated handles remain owned through every sample.
    let before = unsafe { sample_process(pin.0) }.unwrap();
    assert!(before.private_bytes > 0);
    assert_eq!(
        unsafe { sample_exited_child_logical_io(pin.0) }
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(
        unsafe { sample_exited_child_logical_io(std::ptr::null_mut()) }
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(unsafe { sample_process(no_query.0) }.is_err());
    assert!(unsafe { sample_process(no_wait.0) }.is_err());
    std::fs::write(root.path().join("release"), b"release").unwrap();
    while child.0.try_wait().unwrap().is_none() {
        assert!(std::time::Instant::now() < deadline, "child exit deadline");
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    assert!(child.0.wait().unwrap().success());
    assert_eq!(
        unsafe { sample_process(pin.0) }.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    let final_io = unsafe { sample_exited_child_logical_io(pin.0) }.unwrap();
    assert!(
        final_io
            .checked_delta(&before.logical_io)
            .unwrap()
            .write_bytes
            >= 65536
    );
    assert!(final_io.write_bytes >= 131072);
    assert_eq!(
        unsafe { sample_exited_child_logical_io(final_only.0) }.unwrap(),
        final_io
    );
    // Independent native query verifies every returned field, not just write bytes.
    let mut native = IO_COUNTERS::default();
    // SAFETY: pin still owns the exited process handle and native is writable.
    assert_ne!(unsafe { GetProcessIoCounters(pin.0, &mut native) }, 0);
    assert_eq!(
        final_io,
        LogicalIoCounters {
            read_operations: native.ReadOperationCount,
            write_operations: native.WriteOperationCount,
            other_operations: native.OtherOperationCount,
            read_bytes: native.ReadTransferCount,
            write_bytes: native.WriteTransferCount,
            other_bytes: native.OtherTransferCount,
        }
    );
    assert_eq!(
        unsafe { sample_exited_child_logical_io(child.0.as_raw_handle()) }.unwrap(),
        final_io
    );
    assert_eq!(
        unsafe { sample_exited_child_logical_io(pin.0) }.unwrap(),
        final_io
    );
    assert!(unsafe { sample_exited_child_logical_io(no_query.0) }.is_err());
    assert!(unsafe { sample_exited_child_logical_io(no_wait.0) }.is_err());
}

#[test]
fn native_current_process_counters_are_available() {
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    // SAFETY: current-process pseudo handle remains valid throughout the call.
    let before = unsafe { sample_process(GetCurrentProcess()) }.unwrap();
    let after = unsafe { sample_process(GetCurrentProcess()) }.unwrap();
    assert!(after.private_bytes > 0);
    assert!(after.peak_private_bytes >= after.private_bytes);
    assert!(after.peak_working_set_bytes >= after.working_set_bytes);
    after.logical_io.checked_delta(&before.logical_io).unwrap();
}

#[test]
fn exited_pinned_child_is_rejected() {
    use std::os::windows::io::AsRawHandle;
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--list"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    child.wait().unwrap();
    // SAFETY: Child retains the process handle after wait until it is dropped.
    let error = unsafe { sample_process(child.as_raw_handle()) }.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}

#[test]
fn logical_io_delta_rejects_counter_regression() {
    let before = LogicalIoCounters {
        read_bytes: 20,
        ..Default::default()
    };
    let after = LogicalIoCounters {
        read_bytes: 30,
        ..Default::default()
    };
    assert_eq!(after.checked_delta(&before).unwrap().read_bytes, 10);
    assert!(before.checked_delta(&after).is_err());
}

#[test]
fn replacement_with_identical_bytes_changes_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    std::fs::write(&path, b"{}\n").unwrap();
    let before = snapshot_jsonl(&path).unwrap();
    // Keep the original alive under another name to avoid filesystem ID reuse.
    std::fs::rename(&path, dir.path().join("old.jsonl")).unwrap();
    std::fs::write(&path, b"{}\n").unwrap();
    let replacement = snapshot_jsonl(&path).unwrap();
    assert_ne!(replacement.identity, before.identity);
    assert_eq!(replacement.prefix_sha256, before.prefix_sha256);
    assert!(verify_append(&path, &before).is_err());
}

#[test]
fn truncation_and_same_length_prefix_mutation_fail() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    std::fs::write(&path, b"{\"n\":1}\n").unwrap();
    let before = snapshot_jsonl(&path).unwrap();
    std::fs::write(&path, b"{\"n\":2}\n").unwrap();
    assert!(verify_append(&path, &before).is_err());
    std::fs::write(&path, b"{}\n").unwrap();
    assert!(verify_append(&path, &before).is_err());
    assert_eq!(
        prefix_sha256(&mut File::open(&path).unwrap(), before.length)
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn streaming_hash_matches_known_digest_across_chunk_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("million-a.jsonl");
    let mut file = File::create(&path).unwrap();
    // Standard SHA256 million-'a' test vector, generated without corpus allocation.
    for _ in 0..1000 {
        file.write_all(&[b'a'; 1000]).unwrap();
    }
    drop(file);
    let snapshot = snapshot_jsonl(&path).unwrap();
    assert_eq!(snapshot.length, 1_000_000);
    assert_eq!(
        snapshot.prefix_sha256,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
    assert_eq!(verify_append(&path, &snapshot).unwrap(), snapshot);
}

#[test]
fn empty_prefix_and_missing_path_are_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.jsonl");
    assert_eq!(
        snapshot_jsonl(&path).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    std::fs::write(&path, b"").unwrap();
    let snapshot = snapshot_jsonl(&path).unwrap();
    assert_eq!(snapshot.length, 0);
    assert_eq!(
        snapshot.prefix_sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn append_preserves_identity_and_original_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    std::fs::write(&path, b"{\"event\":1}\n").unwrap();
    let before = snapshot_jsonl(&path).unwrap();
    let mut writer = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    writer.write_all(b"{\"event\":2}\n").unwrap();
    writer.sync_all().unwrap();
    drop(writer);
    let after = verify_append(&path, &before).unwrap();
    assert_eq!(before.identity, after.identity);
    assert!(after.length > before.length);
    assert_eq!(
        prefix_sha256(&mut std::fs::File::open(&path).unwrap(), before.length).unwrap(),
        before.prefix_sha256
    );
}
