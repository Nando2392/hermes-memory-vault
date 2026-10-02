use super::windows_broker_store::*;
use super::*;

#[test]
fn windows_private_temp_rejects_interactive_identity_without_environment_changes() {
    let before = [std::env::var_os("TEMP"), std::env::var_os("TMP")];
    let root = tempfile::tempdir().unwrap();
    let result = admit_broker_temp(root.path());
    assert!(
        matches!(result, Err(MemoryError::Io(ref e)) if e.kind() == std::io::ErrorKind::PermissionDenied)
    );
    assert_eq!(before, [std::env::var_os("TEMP"), std::env::var_os("TMP")]);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn windows_private_temp_requires_all_three_inheritable_full_control_aces() {
    let service = "S-1-5-80-1-2-3-4-5";
    let aces = private_aces(service);
    assert!(acl_allowed(
        service,
        true,
        &aces,
        service,
        ObjectKind::TempRoot
    ));
    for index in 0..3 {
        for (mask, flags) in [(0x120089, 3), (0x1f01ff, 0), (0x1f01ff, 11)] {
            let mut bad = aces.clone();
            bad[index].mask = mask;
            bad[index].flags = flags;
            assert!(!acl_allowed(
                service,
                true,
                &bad,
                service,
                ObjectKind::TempRoot
            ));
        }
    }
    assert!(!acl_allowed(
        service,
        false,
        &aces,
        service,
        ObjectKind::TempRoot
    ));
}

#[test]
fn windows_private_temp_selection_requires_direct_nonaliased_child() {
    let root = Path::new(r"C:\Private\Temp");
    assert!(validate_temp_selection(root, r"c:\private\TEMP\etilqs_123").is_ok());
    for proposed in [
        r"C:\Private\Temp2\etilqs_123",
        r"C:\Private\Temp\sub\x",
        r"C:\Private\Temp\..\x",
        r"C:\Private\Temp\x:ads",
        r"C:\Private\Temp\x.",
        r"C:\Private\Temp\",
        r"\\?\C:\Private\Temp\x",
        "x",
    ] {
        assert!(
            validate_temp_selection(root, proposed).is_err(),
            "{proposed}"
        );
    }
}

#[test]
fn windows_private_temp_queries_real_win32_selection_without_spilling() {
    let _api: fn(&BrokerTempGuard, &MemoryStore) -> Result<(), MemoryError> =
        BrokerTempGuard::verify_store;
    let root = tempfile::tempdir().unwrap();
    let connection = Connection::open_with_flags_and_vfs(
        root.path().join("probe.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
        "win32",
    )
    .unwrap();
    let selected = sqlite_temp_selection(&connection).unwrap();
    assert!(Path::new(&selected).is_absolute());
    assert!(
        !Path::new(&selected).exists(),
        "selection must not create a spill file"
    );
    assert!(sqlite_temp_selection(&Connection::open_in_memory().unwrap()).is_err());
}

#[test]
fn windows_private_temp_path_allocations_are_bounded() {
    let oversized = format!("C:\\{}", "a".repeat(32768));
    assert!(validate_path(Path::new(&oversized)).is_err());
}

#[test]
fn windows_private_temp_native_sddl_rejects_public_reads_and_missing_inheritance() {
    let private = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-80-1-2-3-4-5)";
    assert!(descriptor_kind_admitted(private, ObjectKind::TempRoot));
    for sddl in [
        format!("{private}(A;;FR;;;WD)"),
        format!("{private}(A;;FW;;;BU)"),
        private.replace("O:BAG", "O:WDG"),
        private.replace("D:P", "D:"),
        private.replace("(A;OICI;FA;;;SY)", ""),
        private.replace("(A;OICI;FA;;;BA)", "(A;;FA;;;BA)"),
        "O:BAG:BAD:NO_ACCESS_CONTROL".to_owned(),
    ] {
        assert!(
            !descriptor_kind_admitted(&sddl, ObjectKind::TempRoot),
            "{sddl}"
        );
    }
}

#[test]
fn windows_private_temp_same_directory_requires_volume_and_full_file_id() {
    use windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION;
    let original = BY_HANDLE_FILE_INFORMATION {
        dwVolumeSerialNumber: 7,
        nFileIndexHigh: 8,
        nFileIndexLow: 9,
        ..Default::default()
    };
    assert!(same_directory(&original, &original));
    for changed in [
        BY_HANDLE_FILE_INFORMATION {
            dwVolumeSerialNumber: 1,
            ..original
        },
        BY_HANDLE_FILE_INFORMATION {
            nFileIndexHigh: 1,
            ..original
        },
        BY_HANDLE_FILE_INFORMATION {
            nFileIndexLow: 1,
            ..original
        },
    ] {
        assert!(!same_directory(&original, &changed));
    }
}

fn private_aces(service: &str) -> Vec<Ace> {
    ["S-1-5-18", "S-1-5-32-544", service]
        .into_iter()
        .map(|sid| Ace {
            sid: sid.to_owned(),
            mask: 0x1f01ff,
            flags: 3,
            kind: 0,
        })
        .collect()
}

#[test]
fn windows_broker_private_acl_accepts_only_service_system_admins() {
    let service = "S-1-5-80-1-2-3-4-5";
    let aces = private_aces(service);
    assert!(acl_allowed(
        "S-1-5-32-544",
        true,
        &aces,
        service,
        ObjectKind::Root
    ));
    assert!(acl_allowed(
        service,
        false,
        &aces,
        service,
        ObjectKind::File
    ));
    for owner in ["S-1-1-0", "S-1-5-21-1-2-3-4"] {
        assert!(!acl_allowed(owner, true, &aces, service, ObjectKind::Root));
    }
    assert!(!acl_allowed(
        service,
        false,
        &aces,
        service,
        ObjectKind::Root
    ));
    let mut broad = aces.clone();
    broad.push(Ace {
        sid: "S-1-1-0".into(),
        mask: 0x120089,
        flags: 3,
        kind: 0,
    });
    assert!(!acl_allowed(
        service,
        true,
        &broad,
        service,
        ObjectKind::Root
    ));
    assert!(!acl_allowed(
        service,
        true,
        &broad,
        service,
        ObjectKind::File
    ));
    for kind in [1, 5, 9, 17] {
        let mut unknown = aces.clone();
        unknown[0].kind = kind;
        assert!(!acl_allowed(
            service,
            true,
            &unknown,
            service,
            ObjectKind::Root
        ));
    }
}

#[test]
fn windows_broker_ancestors_forbid_attacker_replacement() {
    let service = "S-1-5-80-1-2-3-4-5";
    let mut aces = private_aces(service);
    aces.push(Ace {
        sid: "S-1-1-0".into(),
        mask: 0x1200af,
        flags: 0,
        kind: 0,
    });
    assert!(acl_allowed(
        "S-1-5-18",
        false,
        &aces,
        service,
        ObjectKind::Ancestor
    ));
    for mask in [
        0x40, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000, 0x100, 0x10, 0x2000000,
    ] {
        aces.last_mut().unwrap().mask = mask;
        assert!(
            !acl_allowed("S-1-5-18", false, &aces, service, ObjectKind::Ancestor),
            "{mask:x}"
        );
    }
    assert!(!acl_allowed(
        "S-1-1-0",
        false,
        &private_aces(service),
        service,
        ObjectKind::Ancestor
    ));
}

#[test]
fn windows_broker_root_requires_inheritable_service_control() {
    let service = "S-1-5-80-1-2-3-4-5";
    for flags in [0, 1, 2, 7, 11, 0x83] {
        let mut aces = private_aces(service);
        aces[2].flags = flags;
        assert!(
            !acl_allowed(service, true, &aces, service, ObjectKind::Root),
            "{flags:x}"
        );
    }
    let mut aces = private_aces(service);
    aces[2].mask = 0x120089;
    assert!(!acl_allowed(
        service,
        true,
        &aces,
        service,
        ObjectKind::Root
    ));
    assert!(!acl_allowed(service, true, &[], service, ObjectKind::Root));
}

#[test]
fn windows_broker_metadata_rejects_reparse_hardlinks_and_wrong_types() {
    assert!(metadata_allowed(0x10, 1, ObjectKind::Root));
    assert!(metadata_allowed(0x20, 1, ObjectKind::File));
    for attrs in [0x410, 0x400, 0x40, 0x1] {
        assert!(!metadata_allowed(attrs, 1, ObjectKind::File));
        assert!(!metadata_allowed(attrs, 1, ObjectKind::Root));
    }
    assert!(!metadata_allowed(0x10, 1, ObjectKind::File));
    assert!(!metadata_allowed(0x20, 1, ObjectKind::Root));
    for links in [0, 2, 3] {
        assert!(!metadata_allowed(0x20, links, ObjectKind::File));
    }
}

fn descriptor_admitted(sddl: &str) -> bool {
    descriptor_kind_admitted(sddl, ObjectKind::Root)
}

fn descriptor_kind_admitted(sddl: &str, kind: ObjectKind) -> bool {
    use windows_sys::Win32::{Foundation::LocalFree, Security::Authorization::*};
    let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut sd = std::ptr::null_mut();
    // SAFETY: pure in-memory descriptor conversion; no filesystem ACL is modified.
    unsafe {
        assert_ne!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut()
            ),
            0
        );
        let result = audit_descriptor(sd, "S-1-5-80-1-2-3-4-5", kind).is_ok();
        LocalFree(sd);
        result
    }
}

#[test]
fn windows_broker_native_descriptor_parser_enforces_acl_model() {
    assert!(descriptor_admitted(
        "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-80-1-2-3-4-5)"
    ));
    for sddl in [
        "O:BAG:BAD:NO_ACCESS_CONTROL",
        "O:BAG:BAD:P",
        "O:BAG:BAD:(A;OICI;FA;;;S-1-5-80-1-2-3-4-5)",
        "O:WDG:BAD:P(A;OICI;FA;;;S-1-5-80-1-2-3-4-5)",
        "O:BAG:BAD:P(A;OICI;FA;;;S-1-5-80-1-2-3-4-5)(A;;FR;;;WD)",
        "O:BAG:BAD:P(D;;FW;;;WD)(A;OICI;FA;;;S-1-5-80-1-2-3-4-5)",
    ] {
        assert!(!descriptor_admitted(sddl), "{sddl}");
    }
}

#[test]
fn windows_broker_native_audit_rejects_user_owned_root_without_mutation() {
    let root = tempfile::tempdir().unwrap();
    let error = audit_path(root.path(), "S-1-5-80-1-2-3-4-5", ObjectKind::Root).unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&root.path().display().to_string()),
        "missing audit location: {error}"
    );
    assert!(
        matches!(error, MemoryError::Io(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "{error}"
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn windows_broker_inventory_excludes_legacy_unknown_and_alias_names() {
    for name in [
        "memory.db",
        "memory.db-wal",
        "memory.db-shm",
        "memory.db-journal",
        "memory.broker.lock",
        "events.jsonl",
        "events.jsonl.lock",
        ".events.jsonl.123.0.tmp",
    ] {
        assert!(store_entry_allowed(name), "{name}");
    }
    for name in [
        "memory.init.lock",
        "export.lock",
        "other.db",
        "memory.db:stream",
        "memory.db.",
        ".events.jsonl.x.0.tmp",
        ".events.jsonl.1.2.3.tmp",
        ".events.jsonl..2.tmp",
    ] {
        assert!(!store_entry_allowed(name), "{name}");
    }
}

#[test]
fn windows_broker_requires_fixed_local_ntfs() {
    assert!(volume_allowed(3, "NTFS"));
    for drive in [0, 1, 2, 4, 5, 6] {
        assert!(!volume_allowed(drive, "NTFS"));
    }
    for fs in ["FAT32", "ReFS", "NTFSx", ""] {
        assert!(!volume_allowed(3, fs));
    }
}

#[test]
fn windows_broker_namespace_audit_does_not_create_or_repair_roots() {
    let temp = tempfile::tempdir().unwrap();
    for path in [temp.path().to_owned(), temp.path().join("missing")] {
        let error = validate_namespace(&path, "S-1-5-80-1-2-3-4-5").unwrap_err();
        assert!(
            matches!(error, MemoryError::Io(ref e) if e.kind() != std::io::ErrorKind::Unsupported),
            "{error}"
        );
    }
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
}

#[test]
fn windows_broker_pins_stock_win32_vfs() {
    assert_eq!(NATIVE_VFS, "win32");
    let name = std::ffi::CString::new(NATIVE_VFS).unwrap();
    // SAFETY: static VFS lookup, no registration or default mutation.
    let vfs = unsafe { rusqlite::ffi::sqlite3_vfs_find(name.as_ptr()) };
    assert!(!vfs.is_null());
}

#[test]
fn windows_broker_ace_sid_extent_precedes_native_sid_reads() {
    assert!(!ace_sid_bounded(&[1, 1, 0, 0]));
    assert!(!ace_sid_bounded(&[1, 15, 0, 0, 0, 0, 0, 5]));
    assert!(!ace_sid_bounded(&[1, 255, 0, 0, 0, 0, 0, 5]));
    assert!(ace_sid_bounded(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]));
}

#[test]
fn windows_broker_virtual_sid_rejects_noncanonical_subauthorities() {
    for sid in [
        "S-1-5-80-1-2-3-4-x",
        "S-1-5-80-1-2-3-4-4294967296",
        "S-1-5-80-1-2-3-4-",
        "S-1-5-80-1-2-3-4-+5",
        "S-1-5-80-1-2-3-4-05",
    ] {
        assert!(!virtual_user(sid), "{sid}");
    }
}

#[test]
fn windows_broker_requires_actual_virtual_user_sid() {
    assert!(virtual_user("S-1-5-80-1-2-3-4-5"));
    for sid in [
        "S-1-5-18",
        "S-1-5-19",
        "S-1-5-21-1-2-3-4",
        "S-1-5-80",
        "S-1-5-80-1-2-3-4",
        "S-1-5-80-1-2-3-4-5-6",
    ] {
        assert!(!virtual_user(sid), "{sid}");
    }
}

#[test]
fn windows_broker_rejects_path_aliases() {
    for path in [
        r"C:\safe\..\vault",
        r"C:\safe\.\vault",
        r"\\server\share\vault",
        r"\\?\C:\vault",
        r"C:\vault:stream",
        r"C:\vault.",
        r"C:\vault ",
        r"C:\PROGRA~1\vault",
        r"C:\NUL\vault",
        r"C:\safe\\vault",
        r"C:\",
    ] {
        assert!(validate_path(Path::new(path)).is_err(), "{path}");
    }
    assert!(validate_path(Path::new(r"C:\ProgramData\Hermes\vault")).is_ok());
}

#[test]
fn windows_broker_rejects_interactive_identity_before_writing() {
    let root = tempfile::tempdir().unwrap();
    let error = match MemoryStore::open_broker(root.path()) {
        Ok(_) => panic!("interactive identity admitted"),
        Err(error) => error,
    };
    assert!(
        matches!(error, MemoryError::Io(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "{error}"
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn windows_broker_rejects_relative_root_without_creating_it() {
    let error = match MemoryStore::open_broker("relative-broker-root") {
        Ok(_) => panic!("relative root admitted"),
        Err(error) => error,
    };
    assert!(
        matches!(error, MemoryError::Io(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "{error}"
    );
    assert!(!Path::new("relative-broker-root").exists());
}
