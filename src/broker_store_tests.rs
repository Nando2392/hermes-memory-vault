use super::*;

#[cfg(feature = "experimental-broker")]
#[test]
fn broker_directory_policy_requires_trusted_nonroot_service() {
    assert!(broker_directory_trusted(1001, 0o700, 1001, true, false));
    for (owner, mode, service, is_root, is_tmp) in [
        (0, 0o700, 0, true, false),
        (0, 0o700, 1001, true, false),
        (1002, 0o700, 1001, true, false),
        (1001, 0o770, 1001, true, false),
        (1001, 0o707, 1001, true, false),
        (1001, 0o755, 1001, true, false),
        (1002, 0o755, 1001, false, false),
        (0, 0o775, 1001, false, false),
        (0, 0o1777, 1001, false, false),
        (1001, 0o1777, 1001, false, true),
        (0, 0o777, 1001, false, true),
    ] {
        assert!(!broker_directory_trusted(
            owner, mode, service, is_root, is_tmp
        ));
    }
    assert!(broker_directory_trusted(0, 0o755, 1001, false, false));
    assert!(broker_directory_trusted(1001, 0o755, 1001, false, false));
    assert!(broker_directory_trusted(0, 0o1777, 1001, false, true));
}

#[cfg(all(
    feature = "experimental-broker",
    not(any(target_os = "linux", windows))
))]
#[test]
fn broker_is_unsupported_without_creating_root() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("absent");
    assert!(
        matches!(MemoryStore::open_broker(&root), Err(MemoryError::Io(e)) if e.kind() == std::io::ErrorKind::Unsupported)
    );
    assert!(!root.exists());
}

#[cfg(all(feature = "experimental-broker", target_os = "linux"))]
mod linux {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn fixture() -> tempfile::TempDir {
        // CI must run these tests as the unprivileged trusted service identity.
        // SAFETY: geteuid takes no arguments and has no memory safety preconditions.
        assert_ne!(unsafe { libc::geteuid() }, 0, "run broker tests as nonroot");
        let temp = tempfile::Builder::new()
            .prefix("broker-store-")
            .tempdir_in("/tmp")
            .unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }

    #[test]
    fn broker_native_wal_reopen_and_exclusive_instance() {
        let temp = fixture();
        let store = MemoryStore::open_broker(temp.path()).unwrap();
        assert!(MemoryStore::open_broker(temp.path()).is_err());
        assert!(store._database_guard.is_none());
        assert!(store._wal_guard.is_none());
        assert!(store._shm_guard.is_none());
        let record = MemoryRecord {
            id: "one".into(),
            session_id: "s".into(),
            workspace: "w".into(),
            kind: "note".into(),
            content: "native broker durable".into(),
            timestamp: 1.0,
            metadata: Value::Null,
        };
        assert!(store.ingest(&record).unwrap());
        let native = Connection::open(temp.path().join("memory.db")).unwrap();
        assert_eq!(
            native
                .query_row("SELECT COUNT(*) FROM records", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        drop(native);
        drop(store);
        let reopened = MemoryStore::open_broker(temp.path()).unwrap();
        assert!(!reopened.ingest(&record).unwrap());
        let conn = reopened.connection.lock().unwrap();
        assert_eq!(
            conn.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
    }

    #[test]
    fn broker_rejects_missing_relative_symlink_and_mutable_namespace() {
        let temp = fixture();
        assert!(MemoryStore::open_broker("relative-broker-root").is_err());
        let absent = temp.path().join("absent");
        assert!(MemoryStore::open_broker(&absent).is_err());
        assert!(!absent.exists());
        let real = temp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let alias = temp.path().join("alias");
        symlink(&real, &alias).unwrap();
        assert!(MemoryStore::open_broker(&alias).is_err());
        for mode in [0o720, 0o702, 0o777] {
            std::fs::set_permissions(&real, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(MemoryStore::open_broker(&real).is_err());
        }
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(MemoryStore::open_broker(&real).is_err());
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!real.join("memory.db").exists());
    }

    #[test]
    fn broker_future_schema_leaves_database_and_projection_unchanged() {
        let temp = fixture();
        drop(MemoryStore::open_broker(temp.path()).unwrap());
        let path = temp.path().join("memory.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA user_version=99;").unwrap();
        drop(conn);
        let database = std::fs::read(&path).unwrap();
        let projection = std::fs::read(temp.path().join("events.jsonl")).unwrap();
        assert!(
            matches!(MemoryStore::open_broker(temp.path()), Err(MemoryError::Io(e)) if e.kind() == std::io::ErrorKind::Unsupported)
        );
        assert_eq!(std::fs::read(path).unwrap(), database);
        assert_eq!(
            std::fs::read(temp.path().join("events.jsonl")).unwrap(),
            projection
        );
    }

    #[test]
    fn broker_rejects_existing_database_and_sidecar_aliases() {
        for name in [
            "memory.db",
            "memory.db-wal",
            "memory.db-shm",
            "memory.db-journal",
            "memory.broker.lock",
            "events.jsonl.lock",
            "export.lock",
        ] {
            let temp = fixture();
            let external = fixture();
            let sentinel = external.path().join("sentinel");
            std::fs::write(&sentinel, b"unchanged").unwrap();
            symlink(&sentinel, temp.path().join(name)).unwrap();
            assert!(MemoryStore::open_broker(temp.path()).is_err(), "{name}");
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
            std::fs::remove_file(temp.path().join(name)).unwrap();
            std::fs::hard_link(&sentinel, temp.path().join(name)).unwrap();
            assert!(
                MemoryStore::open_broker(temp.path()).is_err(),
                "hardlink {name}"
            );
        }
    }
}

#[cfg(feature = "experimental-broker")]
#[test]
fn broker_policy_is_applied_to_every_connection() {
    let temp = tempfile::tempdir().unwrap();
    for _ in 0..2 {
        let mut connection = Connection::open(temp.path().join("policy.db")).unwrap();
        configure_broker_connection(&mut connection).unwrap();
        let mode: String = connection
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        for (pragma, expected) in [
            ("synchronous", 2),
            ("foreign_keys", 1),
            ("busy_timeout", 5000),
        ] {
            let value: i64 = connection
                .query_row(&format!("PRAGMA {pragma}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(value, expected, "{pragma}");
        }
    }
}

#[cfg(windows)]
#[test]
fn future_schema_rejected_before_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("memory.db");
    drop(MemoryStore::open(temp.path()).unwrap());
    std::fs::remove_file(temp.path().join("events.jsonl")).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch("PRAGMA user_version=99;").unwrap();
    drop(connection);
    let before = std::fs::read(&path).unwrap();
    assert!(
        MemoryStore::open(temp.path()).is_err(),
        "future schema must be rejected"
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert!(!temp.path().join("events.jsonl").exists());
}
