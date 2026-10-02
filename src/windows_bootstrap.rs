//! Administrator-only pre-listen logical archive admission. Never an IPC operation.
use std::path::Path;

pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// Startup errors deliberately contain no source path, payload, or parser details.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("bootstrap_config_invalid")]
    InvalidConfig,
    #[error("bootstrap_source_admission_failed")]
    SourceAdmission,
    #[error("bootstrap_import_failed")]
    Import,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapConfig {
    schema: u32,
    archive_path: String,
    logical_sha256: String,
}
fn parse_config(bytes: &[u8]) -> Result<BootstrapConfig, BootstrapError> {
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(BootstrapError::InvalidConfig);
    }
    let config: BootstrapConfig =
        serde_json::from_slice(bytes).map_err(|_| BootstrapError::InvalidConfig)?;
    if config.schema != 1
        || crate::windows_enrollment::normalized(Path::new(&config.archive_path)).is_err()
        || config.archive_path.len() <= 3
        || config.logical_sha256.len() != 64
        || !config
            .logical_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BootstrapError::InvalidConfig);
    }
    Ok(config)
}

/// Administrative startup only: caller must pin actual virtual TokenUser, admit
/// private TEMP, open/recover the destination and verify its VFS before calling.
/// Both sources must be immutable admin-owned leaves, not service-writable files.
/// The externally pinned digest authenticates admission only through that trust.
pub fn bootstrap_from_config(
    store: &crate::MemoryStore,
    path: &Path,
) -> Result<crate::logical_migration::MigrationReceipt, BootstrapError> {
    bootstrap_with(
        store,
        path,
        crate::windows_enrollment::open_admin_owned_file,
    )
}
fn bootstrap_with<R: std::io::Read>(
    store: &crate::MemoryStore,
    path: &Path,
    mut open: impl FnMut(&Path, u64) -> std::io::Result<R>,
) -> Result<crate::logical_migration::MigrationReceipt, BootstrapError> {
    use std::io::Read;
    let mut config_reader =
        open(path, MAX_CONFIG_BYTES as u64).map_err(|_| BootstrapError::SourceAdmission)?;
    let mut bytes = Vec::new();
    (&mut config_reader)
        .take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BootstrapError::SourceAdmission)?;
    let config = parse_config(&bytes)?;
    let archive = open(
        Path::new(&config.archive_path),
        crate::logical_migration::MAX_ARCHIVE_BYTES,
    )
    .map_err(|_| BootstrapError::SourceAdmission)?;
    // BufReader construction does not read: same-pin receipts return immediately.
    // Keep both audited source namespaces pinned through the transaction.
    let result = store
        .import_logical_archive_once(
            std::io::BufReader::with_capacity(64 * 1024, archive),
            &config.logical_sha256,
        )
        .map_err(|_| BootstrapError::Import);
    drop(config_reader);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bootstrap_streams_pinned_archive_and_reuses_receipt() {
        use std::io::{Cursor, Read};
        let source = tempfile::tempdir().unwrap();
        let store = crate::MemoryStore::open(source.path()).unwrap();
        let mut archive = Vec::new();
        drop(store); // Closed synthetic staging fixture, never a live vault.
        let receipt = crate::logical_migration::export_from_staged_sqlite_copy(
            source.path().join("memory.db"),
            &mut archive,
        )
        .unwrap();
        let config = serde_json::to_vec(&serde_json::json!({"schema":1,
            "archive_path":"C:/admin/archive.jsonl", "logical_sha256":receipt.logical_sha256}))
        .unwrap();
        let target = tempfile::tempdir().unwrap();
        let destination = crate::MemoryStore::open(target.path()).unwrap();
        for retry in [false, true] {
            let result = bootstrap_with(
                &destination,
                Path::new("C:/admin/config.json"),
                |path, bound| {
                    let reader: Box<dyn Read> = if path.ends_with("config.json") {
                        assert_eq!(bound, 65536);
                        Box::new(Cursor::new(config.clone()))
                    } else {
                        assert_eq!(bound, crate::logical_migration::MAX_ARCHIVE_BYTES);
                        if retry {
                            Box::new(NoRead)
                        } else {
                            Box::new(Cursor::new(archive.clone()))
                        }
                    };
                    Ok(reader)
                },
            )
            .unwrap();
            assert_eq!(result.logical_sha256, receipt.logical_sha256);
        }
        struct NoRead;
        impl Read for NoRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                panic!("retry read archive")
            }
        }
        assert!(matches!(
            bootstrap_from_config(&destination, Path::new("relative")),
            Err(BootstrapError::SourceAdmission)
        ));
    }
    #[test]
    fn invalid_config_never_opens_archive_or_writes_receipt() {
        use std::io::Cursor;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::MemoryStore::open(dir.path()).unwrap();
        for bytes in [
            b"{\"secret-path\":true}".to_vec(),
            vec![b' '; MAX_CONFIG_BYTES + 1],
        ] {
            let mut opens = 0;
            let error = bootstrap_with(&store, Path::new("C:/admin/config.json"), |_, _| {
                opens += 1;
                assert_eq!(opens, 1, "archive opened after invalid config");
                Ok(Cursor::new(bytes.clone()))
            })
            .unwrap_err();
            assert!(matches!(error, BootstrapError::InvalidConfig));
            assert_eq!(error.to_string(), "bootstrap_config_invalid");
        }
        let db = rusqlite::Connection::open(dir.path().join("memory.db")).unwrap();
        let receipts: i64 = db
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='broker_migrations'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(receipts, 0);
    }
    #[test]
    fn strict_bootstrap_config() {
        let good = serde_json::json!({"schema":1,"archive_path":"C:/admin/archive.jsonl","logical_sha256":"a".repeat(64)});
        assert!(parse_config(&serde_json::to_vec(&good).unwrap()).is_ok());
        for (key, bad) in [
            ("schema", serde_json::json!(2)),
            ("archive_path", serde_json::json!("relative")),
            ("archive_path", serde_json::json!("C:/admin/../archive")),
            ("logical_sha256", serde_json::json!("A".repeat(64))),
            ("logical_sha256", serde_json::json!("a".repeat(63))),
            ("logical_sha256", serde_json::json!("g".repeat(64))),
            ("unknown", serde_json::json!(true)),
        ] {
            let mut value = good.clone();
            value[key] = bad;
            assert!(
                parse_config(&serde_json::to_vec(&value).unwrap()).is_err(),
                "{key}"
            );
        }
        assert!(parse_config(b"{}").is_err());
        assert!(parse_config(b"not json").is_err());
        let mut bytes = serde_json::to_vec(&good).unwrap();
        bytes.resize(65536, b' ');
        assert!(parse_config(&bytes).is_ok());
        bytes.push(b' ');
        assert!(parse_config(&bytes).is_err());
    }
}
