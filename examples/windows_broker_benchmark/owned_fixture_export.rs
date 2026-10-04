//! Test-only logical encoder for privately reserved, closed schema-2 fixtures.
//! No staged WAL, writer exclusion, installed client, or production capability.
//! Codec/schema/redaction rules mirror the pinned production source; Windows
//! differential tests bind actual SQLite bytes and receipts, including mutations.
use hermes_memory::logical_migration::{
    MigrationError, MigrationReceipt, MAX_ARCHIVE_BYTES, MAX_FIELD_BYTES, MAX_LINE_BYTES, MAX_ROWS,
};
use regex::Regex;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path, sync::OnceLock};
const MAX_IDENTIFIER: usize = 4096;
#[path = "owned_fixture_export_tests.rs"]
mod tests;
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

pub(super) fn check_owned(database: &Path, owned_root: &Path) -> Result<(), MigrationError> {
    if !owned_root.is_absolute()
        || owned_root.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(invalid("fixture lexical alias"));
    }
    // Only a direct memory.db child of the explicitly reserved fixture root.
    if database.file_name() != Some(std::ffi::OsStr::new("memory.db"))
        || database.parent() != Some(owned_root)
    {
        return Err(invalid("outside owned fixture"));
    }
    for path in [owned_root, database] {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("fixture alias"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                != 0
            {
                return Err(invalid("fixture reparse"));
            }
        }
    }
    if !fs::symlink_metadata(owned_root)?.is_dir() || !fs::symlink_metadata(database)?.is_file() {
        return Err(invalid("fixture regular database"));
    }
    // Reject aliases anywhere in the explicit root's ancestry as well.
    for parent in owned_root.ancestors() {
        let m = fs::symlink_metadata(parent)?;
        if m.file_type().is_symlink() {
            return Err(invalid("fixture ancestor alias"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if m.file_attributes()
                & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                != 0
            {
                return Err(invalid("fixture ancestor reparse"));
            }
        }
    }
    let file = fs::File::open(database)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if file.metadata()?.nlink() != 1 {
            return Err(invalid("fixture hardlink"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        };
        // SAFETY: this output-only Windows structure contains integer fields only.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: live borrowed file handle and valid output storage.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if info.nNumberOfLinks != 1 {
            return Err(invalid("fixture hardlink"));
        }
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        match fs::symlink_metadata(format!("{}{suffix}", database.display())) {
            Ok(_) => return Err(invalid("fixture sidecar remains")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
pub(super) fn export(
    database: &Path,
    owned_root: &Path,
    mut output: impl Write,
) -> Result<MigrationReceipt, MigrationError> {
    check_owned(database, owned_root)?;
    let before =
        crate::data::inventory(owned_root).map_err(|_| invalid("fixture inventory read"))?;
    let path = database.canonicalize()?;
    let path = path
        .to_str()
        .ok_or_else(|| invalid("non UTF8 fixture path"))?;
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
    uri.push_str("?mode=ro&immutable=1");
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version != 2 {
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
    check_owned(database, owned_root)?;
    if before
        != crate::data::inventory(owned_root).map_err(|_| invalid("fixture inventory read"))?
    {
        return Err(invalid("fixture source changed"));
    }
    Ok(receipt)
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
        || sanitize_identifier(value) != value
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
            if redact_text(content) != *content || redact_value(metadata) != *metadata {
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

fn sanitize_identifier(value: &str) -> String {
    if redact_text(value) == value {
        return value.to_owned();
    }
    let mut digest = Sha256::new();
    digest.update(value.as_bytes());
    format!("redacted-{:x}", digest.finalize())
}

fn bearer_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"(?i)(authorization\s*:\s*bearer\s+)[^\s"']+"#)
            .expect("static bearer regex is valid")
    })
}

fn basic_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"(?i)(authorization\s*:\s*basic\s+)[^\s"']+"#)
            .expect("static basic auth regex is valid")
    })
}

fn cookie_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"(?i)((?:set-)?cookie\s*:\s*)[^\r\n]+"#).expect("static cookie regex is valid")
    })
}

fn json_credential_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?i)("(?:api[_-]?key|password|secret|token|authorization|cookie|access[_-]?token|refresh[_-]?token)"\s*:\s*")[^"]*(")"#,
        )
        .expect("static JSON credential regex is valid")
    })
}

fn url_credential_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"(?i)([?&](?:api[_-]?key|key|token|secret|password|sig|signature)=)[^&#\s]+"#)
            .expect("static URL credential regex is valid")
    })
}

fn known_token_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(?:sk-[a-z0-9_-]{16,}|ghp_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,}|xox[baprs]-[a-z0-9-]{16,}|AIza[a-z0-9_-]{20,})\b"#,
        )
        .expect("static known token regex is valid")
    })
}

fn private_key_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?is)-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"#,
        )
        .expect("static private key regex is valid")
    })
}

fn jwt_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b"#)
            .expect("static JWT regex is valid")
    })
}

fn url_userinfo_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r#"(?i)([a-z][a-z0-9+.-]*://[^:/@\s]+:)[^@\s/]+@"#)
            .expect("static URL userinfo regex is valid")
    })
}

fn assignment_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(api[_-]?key|password|secret|token|access[_-]?token|refresh[_-]?token)\s*[:=]\s*[^\s,"']+"#,
        )
            .expect("static credential regex is valid")
    })
}

fn redact_text(text: &str) -> String {
    let redacted = bearer_regex().replace_all(text, "${1}[REDACTED]");
    let redacted = basic_regex().replace_all(&redacted, "${1}[REDACTED]");
    let redacted = cookie_regex().replace_all(&redacted, "${1}[REDACTED]");
    let redacted = json_credential_regex().replace_all(&redacted, "${1}[REDACTED]${2}");
    let redacted = url_credential_regex().replace_all(&redacted, "${1}[REDACTED]");
    let redacted = known_token_regex().replace_all(&redacted, "[REDACTED]");
    let redacted = private_key_regex().replace_all(&redacted, "[REDACTED PRIVATE KEY]");
    let redacted = jwt_regex().replace_all(&redacted, "[REDACTED JWT]");
    let redacted = url_userinfo_regex().replace_all(&redacted, "${1}[REDACTED]@");
    assignment_regex()
        .replace_all(&redacted, "${1}=[REDACTED]")
        .into_owned()
}

fn redact_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| {
                    let normalized = key.to_ascii_lowercase().replace('-', "_");
                    let compact = normalized.replace('_', "");
                    let sensitive = matches!(
                        compact.as_str(),
                        "authorization"
                            | "cookie"
                            | "password"
                            | "secret"
                            | "token"
                            | "apikey"
                            | "accesstoken"
                            | "refreshtoken"
                    ) || normalized.ends_with("_token")
                        || normalized.ends_with("_secret")
                        || normalized.ends_with("_password")
                        || normalized.ends_with("_api_key");
                    (
                        key.clone(),
                        if sensitive {
                            Value::String("[REDACTED]".to_owned())
                        } else {
                            redact_value(value)
                        },
                    )
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(redact_value).collect()),
        Value::String(text) => Value::String(redact_text(text)),
        other => other.clone(),
    }
}

#[cfg(windows)]
#[test]
fn owned_export_rejects_parent_traversal_alias_before_output() {
    let owner = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let root = owner.path().join("store");
    let store = crate::data::open_owned_fixture_store(&root).unwrap();
    drop(store);
    let alias = root.join("../store");
    let mut bytes = Vec::new();
    assert!(export(&alias.join("memory.db"), &alias, &mut bytes).is_err());
    assert!(bytes.is_empty());
}
#[cfg(windows)]
#[test]
fn owned_final_stopped_seam_reads_actual_import_and_mutations() {
    let owner = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let generation = crate::data::generate_with_spec(
        &owner.path().join("seed"),
        &crate::data::FixtureSpec {
            shape: crate::data::FixtureShape::RepresentativeV2,
            target_jsonl_bytes: 32768,
        },
    )
    .unwrap();
    let manifest = crate::full_manifest::FullManifest::new(
        crate::full_manifest::WorkloadSpec::full20x256_v1(),
        16,
    )
    .unwrap();
    let root = owner.path().join("store");
    let store = crate::data::open_owned_fixture_store(&root).unwrap();
    store
        .import_logical_archive_once(
            std::io::BufReader::new(
                std::fs::File::open(owner.path().join("seed/archive.jsonl")).unwrap(),
            ),
            generation["logical_sha256"].as_str().unwrap(),
        )
        .unwrap();
    for id in 0..62 {
        store.ingest_many(&manifest.records(id).unwrap()).unwrap();
    }
    assert_eq!(
        store.ingest_snapshot(&crate::data::snapshot()).unwrap(),
        (0, 0)
    );
    drop(store);
    crate::full_oracles::verify_owned_stopped_sqlite(
        &owner,
        &root.join("memory.db"),
        &generation,
        &manifest,
    )
    .unwrap();
    let wrong_owner = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    assert!(
        crate::full_oracles::verify_owned_stopped_sqlite(
            &wrong_owner,
            &root.join("memory.db"),
            &generation,
            &manifest,
        )
        .is_err(),
        "a database is not owned merely because it is named memory.db"
    );
}
#[cfg(windows)]
#[test]
fn owned_closed_sqlite_bytes_match_windows_export() {
    let owner = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
    let root = owner.path().join("store");
    let store = crate::data::open_owned_fixture_store(&root).unwrap();
    store.ingest_snapshot(&crate::data::snapshot()).unwrap();
    store
        .ingest_many(&[crate::data::record(0), crate::data::record(1)])
        .unwrap();
    drop(store);
    let database = root.join("memory.db");
    let before = crate::data::inventory(&root).unwrap();
    let mut actual = Vec::new();
    let actual_receipt = export(&database, &root, &mut actual).unwrap();
    let mut expected = Vec::new();
    let expected_receipt =
        hermes_memory::logical_migration::export_from_staged_sqlite_copy(&database, &mut expected)
            .unwrap();
    assert_eq!(actual_receipt, expected_receipt);
    assert_eq!(actual, expected);
    assert_eq!(before, crate::data::inventory(&root).unwrap());
}
