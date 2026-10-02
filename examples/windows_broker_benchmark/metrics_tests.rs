use super::*;
use std::io::Write;

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
