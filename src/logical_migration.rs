//! Bounded logical migration, NOT a service operation or a live-migration authorization.
//!
//! The exporter accepts ONLY an explicit, quiescent staged SQLite copy. The caller
//! must establish provenance and an exclusively protected staged namespace, with
//! no external writers or existing writable mappings. This API cannot establish
//! these preconditions or distinguish a live pathname from a staged one. Never
//! pass a live source. Windows read-only handles deny write/delete sharing and
//! remain pinned through export and SQLite close. A complete DB/WAL/SHM uses
//! mode=ro, retaining the matching WAL; missing-one or damaged sidecars fail closed.
//! Only when BOTH WAL/SHM are absent under the DB pin is immutable=1 selected.
//! Sidecar presence is rechecked before open and after export; detected changes
//! fail closed (discard all output). Standard pathname checks cannot prove that
//! sidecars were never transiently created: namespace exclusion remains the
//! caller's responsibility. Non-Windows export remains unsupported.
//! Only schema versions 1 and 2 and the three canonical logical tables are supported.
//! The optional exact broker_migrations receipt is derived deployment metadata,
//! validated but never transported or included in the logical digest.
//! FTS, projection checkpoints, physical rowids, SQL, paths and file handles are not
//! transported. Record order is retained, including timestamp ties.
//!
//! Import is one IMMEDIATE transaction into an already-open empty MemoryStore. In
//! production that store must be service-owned, with private SQLite TEMP/TMP policy.
//! FULL synchronous commit is the durability boundary. Projection is derived only
//! afterwards; OutcomeUnknown means commit succeeded but projection failed. Do not
//! use legacy import again: reopen to repair projection. Legacy import refuses
//! nonempty stores; empty legacy import is a repeatable no-op. Explicit admin-only
//! import_logical_archive_once instead pins an externally trusted lowercase SHA-256
//! and commits a singleton receipt in the SAME SQLite transaction. Same-pin retries
//! return that original receipt before reading input, including after later ingestion;
//! another pin always fails. Receipt means admission, not current-store integrity or
//! projection health. Reopen after OutcomeUnknown before retry. No merge/upsert,
//! automatic migration, admin identity check or IPC exposure is provided by this API.
//! Protect destination DB/WAL against tampering: a forged local receipt is not trusted
//! evidence. Deriving the pin from untrusted input defeats replacement protection.
//! This is not an authenticated archive:
//! SHA-256 detects corruption, not an attacker who can replace payload AND digest.
//! The digest covers the domain separator `hermes-logical-migration-v1\0` then
//! header and data JSONL bytes (including newlines), excluding the trailer. The
//! exporter emits records in original rowid order, counters by session/workspace/
//! fingerprint and states by session/workspace/position. Logical IDs, not physical
//! rowids, cross the boundary. Counter occurrence IDs are recomputed and resolved
//! against exact imported records; arbitrary direct-ingest IDs remain legal.
//! A trusted receipt or authenticated transport is required to detect replacement
//! by another internally consistent logical dataset. Archive JSON never selects
//! a destination path, SQL statement, source database handle or attachment.
//!
//! Limits: 16 MiB serialized JSONL line, 1 GiB total, one million rows per type,
//! 4096-byte identifiers, 8 MiB content/raw metadata JSON each. Ordinary CLI records
//! up to 8 MiB fit; heavily escaped fields must still fit the serialized line cap.
//! A 600 MB archive fits the total cap, but source DB size does not predict archive
//! size. These deliberately reject oversized legacy data rather than truncate. No encrypted/custom/future schemas,
//! deleted snapshot history, external references or redaction-policy changes are
//! supported. Rust memory is bounded per row, not proportional to archive size.
use crate::{MemoryError, MemoryRecord, MemoryStore};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, Write},
    path::Path,
};
use thiserror::Error;

pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_ROWS: u64 = 1_000_000;
pub const MAX_FIELD_BYTES: usize = 8 * 1024 * 1024;
const MAX_IDENTIFIER: usize = 4096;

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("invalid logical archive: {0}")]
    Invalid(&'static str),
    #[error("logical migration I/O failed")]
    Io(#[from] std::io::Error),
    #[error("logical migration SQLite operation failed")]
    Sqlite(#[from] rusqlite::Error),
    #[error("logical migration JSON is invalid")]
    Json(#[from] serde_json::Error),
    #[error("logical migration store operation failed")]
    Store(#[from] MemoryError),
    #[error("outcome_unknown: logical commit succeeded; projection requires recovery")]
    OutcomeUnknown { receipt: MigrationReceipt },
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationReceipt {
    pub records: u64,
    pub snapshot_states: u64,
    pub snapshot_counters: u64,
    pub logical_sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Entry {
    Header {
        format: u32,
        source_schema: i64,
    },
    Record {
        id: String,
        session_id: String,
        workspace: String,
        kind: String,
        content: String,
        timestamp: f64,
        metadata: serde_json::Value,
    },
    Counter {
        session_id: String,
        workspace: String,
        fingerprint: String,
        next_occurrence: i64,
    },
    State {
        session_id: String,
        workspace: String,
        position: i64,
        fingerprint: String,
        record_id: String,
    },
    Trailer {
        receipt: MigrationReceipt,
    },
}
fn invalid(message: &'static str) -> MigrationError {
    MigrationError::Invalid(message)
}
fn hash(hasher: Sha256) -> String {
    format!("{:x}", hasher.finalize())
}
fn seed() -> Sha256 {
    let mut h = Sha256::new();
    h.update(b"hermes-logical-migration-v1\0");
    h
}

/// Export ONLY a quiescent staged copy in an exclusively protected namespace,
/// never a live source. Caller must exclude external writers/writable mappings
/// and namespace changes for the entire call; this API cannot prove provenance
/// or absence of transient sidecars. DB-only uses immutable reads only if both
/// sidecars are absent; complete matching WAL/SHM uses ordinary read-only SQLite.
/// Partial output on any error is unusable; publish only after success.
pub fn export_from_staged_sqlite_copy(
    path: impl AsRef<Path>,
    mut output: impl Write,
) -> Result<MigrationReceipt, MigrationError> {
    if !cfg!(windows) {
        return Err(invalid("read-only staged WAL export requires Windows"));
    }
    let path = path.as_ref().canonicalize()?;
    let path = path
        .to_str()
        .ok_or_else(|| invalid("non-UTF8 staged path"))?;
    let path = path
        .strip_prefix(r"\\?\")
        .unwrap_or(path)
        .replace('\\', "/");
    let mut uri = String::from("file:");
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"/:._-".contains(&byte) {
            uri.push(byte as char);
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    // Keep these same handles alive through SQLite close and the final check.
    #[cfg(windows)]
    let (_guards, db_only) = {
        use std::os::windows::fs::OpenOptionsExt;
        let pin = |suffix: &str| {
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
                .open(format!("{path}{suffix}"))
        };
        let mut guards = vec![pin("")?];
        let topology = sidecar_topology(&path)?;
        let db_only = match topology {
            (false, false) => true,
            (true, true) => {
                guards.push(pin("-wal")?);
                guards.push(pin("-shm")?);
                validate_sidecar_headers(&guards[1], &guards[2])?;
                false
            }
            _ => return Err(invalid("incomplete staged sidecars")),
        };
        (guards, db_only)
    };
    #[cfg(not(windows))]
    let db_only = false;
    // ONLY the protected, quiescent, sidecar-free staged case may ignore WAL.
    // std path checks cannot exclude transient creation: namespace exclusion is
    // a caller precondition, not a capability this function can establish.
    let expected_topology = (!db_only, !db_only);
    if sidecar_topology(&path)? != expected_topology {
        return Err(invalid("staged sidecar topology changed"));
    }
    uri.push_str(if db_only {
        "?mode=ro&immutable=1"
    } else {
        "?mode=ro"
    });
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if !matches!(version, 1 | 2) {
        return Err(invalid("unsupported source schema"));
    }
    validate_schema(&connection, version)?;
    let mut digest = seed();
    let mut total = 0;
    let mut receipt = MigrationReceipt::default();
    let mut emit = |entry: Entry| -> Result<(), MigrationError> {
        validate_entry(&entry)?;
        let mut bytes = serde_json::to_vec(&entry)?;
        bytes.push(b'\n');
        total += bytes.len() as u64;
        if bytes.len() > MAX_LINE_BYTES || total > MAX_ARCHIVE_BYTES {
            return Err(invalid("archive bounds"));
        }
        digest.update(&bytes);
        output.write_all(&bytes)?;
        Ok(())
    };
    emit(Entry::Header {
        format: 1,
        source_schema: version,
    })?;
    {
        let mut statement = connection.prepare("SELECT id,session_id,workspace,kind,content,timestamp,metadata_json FROM records ORDER BY rowid")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            emit(Entry::Record {
                id: text(row, 0, MAX_IDENTIFIER)?,
                session_id: text(row, 1, MAX_IDENTIFIER)?,
                workspace: text(row, 2, MAX_IDENTIFIER)?,
                kind: text(row, 3, MAX_IDENTIFIER)?,
                content: text(row, 4, MAX_FIELD_BYTES)?,
                timestamp: row.get(5)?,
                metadata: serde_json::from_str(&text(row, 6, MAX_FIELD_BYTES)?)?,
            })?;
            receipt.records += 1;
            if receipt.records > MAX_ROWS {
                return Err(invalid("record count"));
            }
        }
    }
    {
        let mut statement = connection.prepare("SELECT session_id,workspace,fingerprint,next_occurrence FROM snapshot_counters ORDER BY session_id,workspace,fingerprint")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            emit(Entry::Counter {
                session_id: text(row, 0, MAX_IDENTIFIER)?,
                workspace: text(row, 1, MAX_IDENTIFIER)?,
                fingerprint: text(row, 2, 64)?,
                next_occurrence: row.get(3)?,
            })?;
            receipt.snapshot_counters += 1;
            if receipt.snapshot_counters > MAX_ROWS {
                return Err(invalid("counter count"));
            }
        }
    }
    {
        let mut statement = connection.prepare("SELECT session_id,workspace,position,fingerprint,record_id FROM snapshot_state ORDER BY session_id,workspace,position")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            emit(Entry::State {
                session_id: text(row, 0, MAX_IDENTIFIER)?,
                workspace: text(row, 1, MAX_IDENTIFIER)?,
                position: row.get(2)?,
                fingerprint: text(row, 3, 64)?,
                record_id: text(row, 4, MAX_IDENTIFIER)?,
            })?;
            receipt.snapshot_states += 1;
            if receipt.snapshot_states > MAX_ROWS {
                return Err(invalid("state count"));
            }
        }
    }
    receipt.logical_sha256 = hash(digest);
    let mut trailer = serde_json::to_vec(&Entry::Trailer {
        receipt: receipt.clone(),
    })?;
    trailer.push(b'\n');
    if total + trailer.len() as u64 > MAX_ARCHIVE_BYTES {
        return Err(invalid("archive bounds"));
    }
    output.write_all(&trailer)?;
    output.flush()?;
    drop(connection);
    if sidecar_topology(&path)? != expected_topology {
        return Err(invalid("staged sidecar topology changed"));
    }
    Ok(receipt)
}

#[cfg(windows)]
fn validate_sidecar_headers(
    mut wal: &std::fs::File,
    mut shm: &std::fs::File,
) -> Result<(), MigrationError> {
    use std::io::Read;
    // SQLite WalIndexHdr: two identical 48-byte native-endian headers. Refuse
    // recovery/private-index fallback, which can hide a damaged staged SHM.
    let mut index = [0u8; 96];
    let mut header = [0u8; 32];
    shm.read_exact(&mut index)?;
    wal.read_exact(&mut header)?;
    let native =
        |n: usize| u32::from_ne_bytes(index[n..n + 4].try_into().expect("fixed header range"));
    let big =
        |n: usize| u32::from_be_bytes(header[n..n + 4].try_into().expect("fixed header range"));
    let page = u16::from_ne_bytes([index[14], index[15]]);
    let page = if page == 1 { 65536u64 } else { u64::from(page) };
    let mut checksum = [0u32; 2];
    for n in (0..40).step_by(8) {
        checksum[0] = checksum[0]
            .wrapping_add(native(n))
            .wrapping_add(checksum[1]);
        checksum[1] = checksum[1]
            .wrapping_add(native(n + 4))
            .wrapping_add(checksum[0]);
    }
    if index[..48] != index[48..]
        || native(0) != 3_007_000
        || index[12] != 1
        || checksum != [native(40), native(44)]
        || !matches!(big(0), 0x377f0682 | 0x377f0683)
        || big(4) != 3_007_000
        || u64::from(big(8)) != page
        || index[13] != (big(0) & 1) as u8
        || index[32..40] != header[16..24]
        || !(512..=65536).contains(&page)
        || !page.is_power_of_two()
        || native(16) == 0
        || wal.metadata()?.len() < 32 + u64::from(native(16)) * (24 + page)
        || shm.metadata()?.len() < 32768
    {
        return Err(invalid("invalid staged WAL/SHM headers"));
    }
    Ok(())
}

fn sidecar_topology(path: &str) -> Result<(bool, bool), MigrationError> {
    let exists = |suffix: &str| -> Result<bool, MigrationError> {
        match std::fs::symlink_metadata(format!("{path}{suffix}")) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    };
    Ok((exists("-wal")?, exists("-shm")?))
}

fn text(row: &rusqlite::Row<'_>, column: usize, maximum: usize) -> Result<String, MigrationError> {
    let value = row.get_ref(column)?;
    let rusqlite::types::ValueRef::Text(bytes) = value else {
        return Err(invalid("source field type"));
    };
    if bytes.len() > maximum {
        return Err(invalid("source field bounds"));
    }
    Ok(std::str::from_utf8(bytes)
        .map_err(|_| invalid("source UTF8"))?
        .to_owned())
}
fn validate_schema(connection: &Connection, version: i64) -> Result<(), MigrationError> {
    connection.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON")?;
    // Names below are constants, never archive-controlled SQL identifiers.
    let logical = [
        (
            "records",
            vec![
                ("id", "TEXT", 0, 1),
                ("session_id", "TEXT", 1, 0),
                ("workspace", "TEXT", 1, 0),
                ("kind", "TEXT", 1, 0),
                ("content", "TEXT", 1, 0),
                ("timestamp", "REAL", 1, 0),
                ("metadata_json", "TEXT", 1, 0),
            ],
        ),
        (
            "snapshot_counters",
            vec![
                ("session_id", "TEXT", 1, 1),
                ("workspace", "TEXT", 1, 2),
                ("fingerprint", "TEXT", 1, 3),
                ("next_occurrence", "INTEGER", 1, 0),
            ],
        ),
        (
            "snapshot_state",
            vec![
                ("session_id", "TEXT", 1, 1),
                ("workspace", "TEXT", 1, 2),
                ("position", "INTEGER", 1, 3),
                ("fingerprint", "TEXT", 1, 0),
                ("record_id", "TEXT", 1, 0),
            ],
        ),
    ];
    for (table, columns) in logical {
        let ordinary: bool = connection.query_row(
            "SELECT type='table' AND sql NOT LIKE '%VIRTUAL%' FROM sqlite_schema WHERE name=?1",
            [table],
            |r| r.get(0),
        )?;
        if !ordinary {
            return Err(invalid("logical source must be ordinary tables"));
        }
        let mut s = connection.prepare(
            "SELECT name,type,[notnull],pk,hidden FROM pragma_table_xinfo(?1) ORDER BY cid",
        )?;
        let mut rows = s.query([table])?;
        for (name, ty, notnull, pk) in columns {
            let r = rows
                .next()?
                .ok_or_else(|| invalid("missing source column"))?;
            if r.get::<_, String>(0)? != name
                || r.get::<_, String>(1)? != ty
                || r.get::<_, i64>(2)? != notnull
                || r.get::<_, i64>(3)? != pk
                || r.get::<_, i64>(4)? != 0
            {
                return Err(invalid("source schema column mismatch"));
            }
        }
        if rows.next()?.is_some() {
            return Err(invalid("extra source column"));
        }
    }
    persisted_receipt(connection)?;
    let projection_columns: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('projection_state')",
        [],
        |r| r.get(0),
    )?;
    if projection_columns != if version == 1 { 5 } else { 10 } {
        return Err(invalid("projection schema version mismatch"));
    }
    let mut s = connection.prepare(
        "SELECT name,type,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
    )?;
    let mut rows = s.query([])?;
    while let Some(r) = rows.next()? {
        let name = text(r, 0, 128)?;
        let ty = text(r, 1, 32)?;
        let allowed = match ty.as_str() {
            "table" => [
                "records",
                "snapshot_state",
                "snapshot_counters",
                "projection_state",
                "broker_migrations",
                "records_fts",
                "records_fts_data",
                "records_fts_idx",
                "records_fts_docsize",
                "records_fts_config",
            ]
            .contains(&name.as_str()),
            "index" => name == "records_workspace_time"
                || (name == "records_export_order"
                    && text(r, 2, 128)? == "records"
                    // Exact persisted DDL from broker_export::prepare_export_index.
                    && text(r, 3, 256)? == "CREATE INDEX records_export_order ON records(workspace, session_id, timestamp)"),
            "trigger" => [
                "records_ai",
                "records_ad",
                "records_au",
                "projection_records_ai",
                "projection_records_ad",
                "projection_records_au",
            ]
            .contains(&name.as_str()),
            _ => false,
        };
        if !allowed {
            return Err(invalid("unrecognized source schema object"));
        }
    }
    Ok(())
}
fn identifier(value: &str) -> Result<(), MigrationError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER
        || value.chars().any(char::is_control)
        || crate::sanitize_identifier(value) != value
    {
        return Err(invalid("identifier bounds or redaction"));
    }
    Ok(())
}
fn fingerprint(value: &str) -> Result<(), MigrationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("fingerprint"));
    }
    Ok(())
}
fn validate_entry(entry: &Entry) -> Result<(), MigrationError> {
    match entry {
        Entry::Record {
            id,
            session_id,
            workspace,
            kind,
            content,
            timestamp,
            metadata,
        } => {
            for v in [id, session_id, workspace, kind] {
                identifier(v)?;
            }
            if content.len() > MAX_FIELD_BYTES
                || serde_json::to_vec(metadata)?.len() > MAX_FIELD_BYTES
                || !timestamp.is_finite()
            {
                return Err(invalid("record field bounds"));
            }
            if crate::redact_text(content) != *content || crate::redact_value(metadata) != *metadata
            {
                return Err(invalid("record is not redacted"));
            }
        }
        Entry::Counter {
            session_id,
            workspace,
            fingerprint: fp,
            next_occurrence,
        } => {
            identifier(session_id)?;
            identifier(workspace)?;
            fingerprint(fp)?;
            if *next_occurrence <= 0 || *next_occurrence > MAX_ROWS as i64 {
                return Err(invalid("counter bounds"));
            }
        }
        Entry::State {
            session_id,
            workspace,
            fingerprint: fp,
            position,
            record_id,
        } => {
            identifier(session_id)?;
            identifier(workspace)?;
            identifier(record_id)?;
            fingerprint(fp)?;
            if *position < 0 || *position >= MAX_ROWS as i64 {
                return Err(invalid("position bounds"));
            }
        }
        _ => {}
    }
    Ok(())
}

// fill_buf is inspected BEFORE extending: even a newline-free hostile stream cannot
// cause read_until's unbounded allocation. The caller owns its BufRead buffer size.
fn line(reader: &mut impl BufRead, total: &mut u64) -> Result<Vec<u8>, MigrationError> {
    let mut bytes = Vec::new();
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return if bytes.is_empty() {
                Ok(bytes)
            } else {
                Err(invalid("truncated line"))
            };
        }
        let count = buffer
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buffer.len(), |i| i + 1);
        if count > MAX_LINE_BYTES - bytes.len() || count as u64 > MAX_ARCHIVE_BYTES - *total {
            return Err(invalid("archive bounds"));
        }
        bytes.extend_from_slice(&buffer[..count]);
        reader.consume(count);
        *total += count as u64;
        if bytes.last() == Some(&b'\n') {
            return Ok(bytes);
        }
    }
}

const RECEIPT_SCHEMA: &str = "CREATE TABLE broker_migrations(singleton INTEGER PRIMARY KEY CHECK(singleton=1), receipt_json TEXT NOT NULL)";

// A receipt is deployment admission metadata, not a checksum of the current store.
// Validate it without scanning logical records (legitimate later writes are allowed).
fn persisted_receipt(connection: &Connection) -> Result<Option<MigrationReceipt>, MigrationError> {
    let schema: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='broker_migrations'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let Some(schema) = schema else {
        return Ok(None);
    };
    if schema != RECEIPT_SCHEMA {
        return Err(invalid("migration receipt schema mismatch"));
    }
    let mut statement =
        connection.prepare("SELECT singleton,receipt_json FROM broker_migrations LIMIT 2")?;
    let mut rows = statement.query([])?;
    let row = rows
        .next()?
        .ok_or_else(|| invalid("missing migration receipt"))?;
    if row.get::<_, i64>(0)? != 1 {
        return Err(invalid("migration receipt singleton"));
    }
    let receipt: MigrationReceipt = serde_json::from_str(&text(row, 1, 512)?)?;
    fingerprint(&receipt.logical_sha256)?;
    if receipt.records > MAX_ROWS
        || receipt.snapshot_states > receipt.records
        || receipt.snapshot_counters > receipt.records
        || rows.next()?.is_some()
    {
        return Err(invalid("migration receipt bounds"));
    }
    Ok(Some(receipt))
}

pub(crate) fn import(
    store: &MemoryStore,
    reader: impl BufRead,
) -> Result<MigrationReceipt, MigrationError> {
    import_inner(store, reader, None)
}

pub(crate) fn import_once(
    store: &MemoryStore,
    reader: impl BufRead,
    expected: &str,
) -> Result<MigrationReceipt, MigrationError> {
    fingerprint(expected)?;
    import_inner(store, reader, Some(expected))
}

fn import_inner(
    store: &MemoryStore,
    mut reader: impl BufRead,
    pinned: Option<&str>,
) -> Result<MigrationReceipt, MigrationError> {
    let mut connection = store
        .connection
        .lock()
        .map_err(|_| MemoryError::LockPoisoned)?;
    connection.execute_batch("PRAGMA synchronous=FULL")?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(expected) = pinned {
        if let Some(receipt) = persisted_receipt(&tx)? {
            if receipt.logical_sha256 != expected {
                return Err(invalid("destination already admitted another archive"));
            }
            return Ok(receipt);
        }
    }
    let nonempty: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM records) OR EXISTS(SELECT 1 FROM snapshot_state) OR EXISTS(SELECT 1 FROM snapshot_counters)", [], |r| r.get(0))?;
    if nonempty {
        return Err(invalid("destination is nonempty"));
    }
    let mut total = 0;
    let mut digest = seed();
    let mut receipt = MigrationReceipt::default();
    let first = line(&mut reader, &mut total)?;
    if !matches!(
        serde_json::from_slice::<Entry>(&first)?,
        Entry::Header {
            format: 1,
            source_schema: 1 | 2
        }
    ) {
        return Err(invalid("unsupported archive header"));
    }
    digest.update(&first);
    // A transient MAIN-schema table uses the same service-owned DB/WAL, not an
    // ambient temp directory. Transactional DDL disappears on rollback or commit.
    tx.execute_batch("CREATE TABLE migration_known_ids(id TEXT PRIMARY KEY, session_id TEXT NOT NULL, workspace TEXT NOT NULL, fingerprint TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0)")?;
    let mut phase = 0;
    let mut occurrences = 0u64;
    loop {
        let bytes = line(&mut reader, &mut total)?;
        if bytes.is_empty() {
            return Err(invalid("missing trailer"));
        }
        let entry: Entry = serde_json::from_slice(&bytes)?;
        validate_entry(&entry)?;
        let next_phase = match &entry {
            Entry::Record { .. } => 0,
            Entry::Counter { .. } => 1,
            Entry::State { .. } => 2,
            _ => 3,
        };
        if next_phase < phase {
            return Err(invalid("record type order"));
        }
        phase = next_phase;
        match entry {
            Entry::Header { .. } => return Err(invalid("duplicate header")),
            Entry::Record {
                id,
                session_id,
                workspace,
                kind,
                content,
                timestamp,
                metadata,
            } => {
                let record = MemoryRecord {
                    id,
                    session_id,
                    workspace,
                    kind,
                    content,
                    timestamp,
                    metadata,
                };
                tx.execute("INSERT INTO records(id,session_id,workspace,kind,content,timestamp,metadata_json) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![record.id,record.session_id,record.workspace,record.kind,record.content,record.timestamp,serde_json::to_string(&record.metadata)?])?;
                receipt.records += 1;
            }
            Entry::Counter {
                session_id,
                workspace,
                fingerprint,
                next_occurrence,
            } => {
                occurrences += next_occurrence as u64;
                if occurrences > receipt.records {
                    return Err(invalid("counter total exceeds records"));
                }
                for occurrence in 0..next_occurrence {
                    let id = crate::snapshot_record_id(
                        &session_id,
                        &workspace,
                        &fingerprint,
                        occurrence,
                    );
                    let record = tx.query_row("SELECT session_id,workspace,kind,content,timestamp,metadata_json FROM records WHERE id=?1", [&id], |r| Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,String>(2)?, r.get::<_,String>(3)?, r.get::<_,f64>(4)?, r.get::<_,String>(5)?)))?;
                    let item = crate::SnapshotItem {
                        kind: record.2,
                        content: record.3,
                        timestamp: record.4,
                        metadata: serde_json::from_str(&record.5)?,
                    };
                    if record.0 != session_id
                        || record.1 != workspace
                        || crate::snapshot_fingerprint(&item)? != fingerprint
                    {
                        return Err(invalid("counter record identity mismatch"));
                    }
                    tx.execute("INSERT INTO migration_known_ids(id,session_id,workspace,fingerprint) VALUES(?1,?2,?3,?4)", params![id,session_id,workspace,fingerprint])?;
                }
                let next_id = crate::snapshot_record_id(
                    &session_id,
                    &workspace,
                    &fingerprint,
                    next_occurrence,
                );
                let reused: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM records WHERE id=?1)",
                    [&next_id],
                    |r| r.get(0),
                )?;
                if reused {
                    return Err(invalid("counter would reuse an existing occurrence"));
                }
                tx.execute(
                    "INSERT INTO snapshot_counters VALUES(?1,?2,?3,?4)",
                    params![session_id, workspace, fingerprint, next_occurrence],
                )?;
                receipt.snapshot_counters += 1;
            }
            Entry::State {
                session_id,
                workspace,
                position,
                fingerprint,
                record_id,
            } => {
                let known = tx.execute("UPDATE migration_known_ids SET used=1 WHERE id=?1 AND session_id=?2 AND workspace=?3 AND fingerprint=?4 AND used=0", params![record_id,session_id,workspace,fingerprint])?;
                if known != 1 {
                    return Err(invalid("state reference is not an exact known occurrence"));
                }
                tx.execute(
                    "INSERT INTO snapshot_state VALUES(?1,?2,?3,?4,?5)",
                    params![session_id, workspace, position, fingerprint, record_id],
                )?;
                receipt.snapshot_states += 1;
            }
            Entry::Trailer { receipt: expected } => {
                receipt.logical_sha256 = hash(digest);
                if receipt != expected {
                    return Err(invalid("trailer mismatch"));
                }
                if !reader.fill_buf()?.is_empty() {
                    return Err(invalid("trailing data"));
                }
                let bad_positions: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM snapshot_state GROUP BY session_id,workspace HAVING MIN(position)<>0 OR MAX(position)<>COUNT(*)-1)", [], |r| r.get(0))?;
                if bad_positions {
                    return Err(invalid("incomplete snapshot history"));
                }
                if let Some(expected) = pinned {
                    if receipt.logical_sha256 != expected {
                        return Err(invalid("administrator digest pin mismatch"));
                    }
                    tx.execute_batch(RECEIPT_SCHEMA)?;
                    tx.execute(
                        "INSERT INTO broker_migrations(singleton,receipt_json) VALUES(1,?1)",
                        [serde_json::to_string(&receipt)?],
                    )?;
                }
                tx.execute_batch("DROP TABLE migration_known_ids")?;
                tx.commit()?;
                drop(connection);
                if store.project_jsonl().is_err() {
                    return Err(MigrationError::OutcomeUnknown { receipt });
                }
                return Ok(receipt);
            }
        }
        if receipt
            .records
            .max(receipt.snapshot_states)
            .max(receipt.snapshot_counters)
            > MAX_ROWS
        {
            return Err(invalid("row count"));
        }
        digest.update(&bytes);
    }
}
