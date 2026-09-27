//! Deterministic namespace substitutions at the SQLite consumer boundary.
use super::*;
use std::cell::RefCell;
use tempfile::tempdir;

thread_local! {
    static BEFORE_SQLITE_OPEN: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}

pub(super) fn before_sqlite_open() {
    let hook = BEFORE_SQLITE_OPEN.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

fn assert_substitution_rejected(name: &str, symlink: bool) {
    let temp = tempdir().expect("temp directory");
    let root = temp.path().join("vault");
    let outside = temp.path().join("outside-sentinel");
    std::fs::write(&outside, []).expect("empty outside sentinel");
    let attacked_path = root.join(name);
    let outside_for_hook = outside.clone();
    BEFORE_SQLITE_OPEN.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            std::fs::remove_file(&attacked_path).expect("remove validated entry");
            if symlink {
                std::os::unix::fs::symlink(&outside_for_hook, &attacked_path)
                    .expect("install symlink after validation");
            } else {
                std::fs::hard_link(&outside_for_hook, &attacked_path)
                    .expect("install hardlink after validation");
            }
        }));
    });
    let result = MemoryStore::open(&root);
    let rejected = result.is_err();
    drop(result);
    assert!(
        std::fs::read(&outside)
            .expect("read outside sentinel")
            .is_empty(),
        "SQLite modified an outside inode after {name} substitution"
    );
    assert!(rejected, "SQLite accepted substituted {name}");
}

#[test]
fn sqlite_rejects_main_symlink_after_capability_validation() {
    assert_substitution_rejected("memory.db", true);
}

#[test]
fn sqlite_rejects_wal_hardlink_after_capability_validation() {
    assert_substitution_rejected("memory.db-wal", false);
}

#[test]
fn sqlite_rejects_shm_hardlink_after_capability_validation() {
    assert_substitution_rejected("memory.db-shm", false);
}
