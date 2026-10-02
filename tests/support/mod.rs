use hermes_memory::{MemoryError, MemoryStore};
use std::path::Path;

#[cfg(windows)]
pub fn open_store(root: impl AsRef<Path>) -> Result<MemoryStore, MemoryError> {
    MemoryStore::open(root)
}

#[cfg(all(target_os = "linux", feature = "experimental-broker"))]
pub fn open_store(root: impl AsRef<Path>) -> Result<MemoryStore, MemoryError> {
    use std::os::unix::fs::PermissionsExt;

    let root = root.as_ref();
    if !root.exists() {
        std::fs::create_dir(root)?;
    }
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
    MemoryStore::open_broker(root)
}
