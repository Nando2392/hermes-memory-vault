use super::*;
use std::io::ErrorKind;

fn assert_unsupported(error: MemoryError) {
    assert!(
        matches!(error, MemoryError::Io(ref io) if io.kind() == ErrorKind::Unsupported),
        "unexpected direct POSIX open error: {error}"
    );
}

#[test]
fn direct_posix_open_is_unsupported_without_io() {
    let temp = tempfile::tempdir().expect("temp directory");
    let absent = temp.path().join("absent");
    let error = match MemoryStore::open(&absent) {
        Ok(_) => panic!("direct POSIX open unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_unsupported(error);
    assert!(!absent.exists(), "unsupported open created its root");

    let populated = temp.path().join("populated");
    std::fs::create_dir(&populated).expect("create populated root");
    let sentinel = populated.join("sentinel");
    std::fs::write(&sentinel, b"unchanged").expect("write sentinel");
    let before = std::fs::read_dir(&populated)
        .expect("list before")
        .map(|entry| entry.expect("entry").file_name())
        .collect::<Vec<_>>();
    let error = match MemoryStore::open(&populated) {
        Ok(_) => panic!("direct POSIX open unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_unsupported(error);
    let after = std::fs::read_dir(&populated)
        .expect("list after")
        .map(|entry| entry.expect("entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(after, before);
    assert_eq!(
        std::fs::read(sentinel).expect("read sentinel"),
        b"unchanged"
    );
}

#[cfg(unix)]
#[test]
fn direct_posix_open_rejects_aliases_before_io() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("temp directory");
    let real = temp.path().join("real");
    std::fs::create_dir(&real).expect("create real root");
    let sentinel = real.join("sentinel");
    std::fs::write(&sentinel, b"unchanged").expect("write sentinel");
    let alias = temp.path().join("alias");
    symlink(&real, &alias).expect("create alias");
    let error = match MemoryStore::open(&alias) {
        Ok(_) => panic!("direct POSIX alias open unexpectedly succeeded"),
        Err(error) => error,
    };
    assert_unsupported(error);
    assert_eq!(
        std::fs::read(sentinel).expect("read sentinel"),
        b"unchanged"
    );
}

#[cfg(unix)]
#[test]
fn direct_posix_open_preserves_hardlinked_sentinels() {
    let temp = tempfile::tempdir().expect("temp directory");
    for name in [
        "memory.db",
        "memory.db-wal",
        "memory.db-shm",
        "memory.init.lock",
        "events.jsonl",
        "events.jsonl.lock",
    ] {
        let root = temp.path().join(name.replace('.', "-"));
        std::fs::create_dir(&root).expect("create root");
        let sentinel = temp
            .path()
            .join(format!("sentinel-{}", name.replace('.', "-")));
        std::fs::write(&sentinel, b"unchanged").expect("write sentinel");
        std::fs::hard_link(&sentinel, root.join(name)).expect("create hardlink");
        let before = std::fs::read(&sentinel).expect("read before");
        let error = match MemoryStore::open(&root) {
            Ok(_) => panic!("direct POSIX open unexpectedly succeeded for {name}"),
            Err(error) => error,
        };
        assert_unsupported(error);
        assert_eq!(
            std::fs::read(&sentinel).expect("read after"),
            before,
            "{name}"
        );
        assert_eq!(
            std::fs::read_dir(&root).expect("list root").count(),
            1,
            "{name} inventory changed"
        );
    }
}
