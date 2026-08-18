use cap_fs_ext::OpenOptionsFollowExt as _;
#[cfg(windows)]
use cap_primitives::fs::_WindowsByHandle as _;
use cap_primitives::fs::FollowSymlinks;
#[cfg(unix)]
use cap_primitives::fs::MetadataExt as _;
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File as CapFile, OpenOptions as CapOpenOptions};
use fs2::FileExt;
use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use thiserror::Error;

#[cfg(windows)]
use cap_std::fs::OpenOptionsExt;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::AsRawFd;
#[cfg(windows)]
use std::os::windows::ffi::OsStringExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    GetFinalPathNameByHandleW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE,
};

#[derive(Debug, Error)]
pub enum MemoryError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("memory record {field} must not be empty")]
    EmptyField { field: &'static str },
    #[error("memory store lock is poisoned")]
    LockPoisoned,
    #[error("unsafe export path outside vault: {0}")]
    UnsafeExportPath(PathBuf),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct MemoryRecord {
    pub id: String,
    pub session_id: String,
    pub workspace: String,
    pub kind: String,
    pub content: String,
    pub timestamp: f64,
    #[serde(default)]
    pub metadata: Value,
}

impl MemoryRecord {
    pub fn validate(&self) -> Result<(), MemoryError> {
        self.sanitized().map(drop)
    }

    fn sanitized(&self) -> Result<Self, MemoryError> {
        for (field, value) in [
            ("id", self.id.as_str()),
            ("session_id", self.session_id.as_str()),
            ("workspace", self.workspace.as_str()),
            ("kind", self.kind.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(MemoryError::EmptyField { field });
            }
        }
        Ok(Self {
            id: sanitize_identifier(&self.id),
            session_id: sanitize_identifier(&self.session_id),
            workspace: sanitize_identifier(&self.workspace),
            kind: sanitize_identifier(&self.kind),
            content: redact_text(&self.content),
            timestamp: self.timestamp,
            metadata: redact_value(&self.metadata),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SearchHit {
    pub id: String,
    pub session_id: String,
    pub workspace: String,
    pub kind: String,
    pub content: String,
    pub timestamp: f64,
    pub metadata: Value,
}

#[derive(Clone, Debug)]
pub struct SearchRequest {
    pub query: String,
    pub workspace: Option<String>,
    pub session_id: Option<String>,
    pub limit: usize,
    pub max_bytes: usize,
}

impl SearchRequest {
    pub fn validate(&self) -> Result<(), MemoryError> {
        if self.query.trim().is_empty() {
            return Err(MemoryError::EmptyField { field: "query" });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotItem {
    pub kind: String,
    pub content: String,
    pub timestamp: f64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRequest {
    pub session_id: String,
    pub workspace: String,
    pub items: Vec<SnapshotItem>,
}

impl SnapshotRequest {
    pub fn validate(&self) -> Result<(), MemoryError> {
        for (field, value) in [
            ("session_id", self.session_id.as_str()),
            ("workspace", self.workspace.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(MemoryError::EmptyField { field });
            }
        }
        for item in &self.items {
            if item.kind.trim().is_empty() {
                return Err(MemoryError::EmptyField { field: "kind" });
            }
        }
        Ok(())
    }
}

pub struct MemoryStore {
    root_dir: Dir,
    _root_guard: CapFile,
    _database_guard: CapFile,
    _wal_guard: CapFile,
    _shm_guard: CapFile,
    connection: Mutex<Connection>,
}

pub fn validate_export_destination(path: &Path) -> Result<(), MemoryError> {
    let mut candidate = Some(path);
    while let Some(current) = candidate {
        match std::fs::symlink_metadata(current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || (current == path && !metadata.is_dir()) {
                    return Err(MemoryError::UnsafeExportPath(path.to_path_buf()));
                }
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                candidate = current.parent();
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(MemoryError::UnsafeExportPath(path.to_path_buf()))
}

impl MemoryStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, MemoryError> {
        let root = root.as_ref().to_path_buf();
        let root_dir = open_or_create_absolute_dir(&root)?;
        let root_guard = capability_root_guard(&root_dir)?;
        let stable_root = stable_root_path(&root_guard, &root)?;
        let initialization_lock = capability_lock_file(&root_dir, "memory.init.lock")?;
        initialization_lock.lock_exclusive()?;
        let database_guard = capability_data_file(&root_dir, "memory.db")?;
        let wal_guard = capability_data_file(&root_dir, "memory.db-wal")?;
        let shm_guard = capability_data_file(&root_dir, "memory.db-shm")?;
        sync_directory(&root_dir)?;
        let connection = Connection::open(stable_root.join("memory.db"))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS records (
               id TEXT PRIMARY KEY,
               session_id TEXT NOT NULL,
               workspace TEXT NOT NULL,
               kind TEXT NOT NULL,
               content TEXT NOT NULL,
               timestamp REAL NOT NULL,
               metadata_json TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS records_workspace_time
               ON records(workspace, timestamp DESC);
             CREATE TABLE IF NOT EXISTS snapshot_state (
               session_id TEXT NOT NULL,
               workspace TEXT NOT NULL,
               position INTEGER NOT NULL,
               fingerprint TEXT NOT NULL,
               record_id TEXT NOT NULL,
               PRIMARY KEY(session_id, workspace, position)
             );
             CREATE TABLE IF NOT EXISTS snapshot_counters (
               session_id TEXT NOT NULL,
               workspace TEXT NOT NULL,
               fingerprint TEXT NOT NULL,
               next_occurrence INTEGER NOT NULL,
               PRIMARY KEY(session_id, workspace, fingerprint)
             );
             CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(
               content,
               content='records',
               content_rowid='rowid',
               tokenize='unicode61'
             );
             CREATE TRIGGER IF NOT EXISTS records_ai AFTER INSERT ON records BEGIN
               INSERT INTO records_fts(rowid, content) VALUES (new.rowid, new.content);
             END;
             CREATE TRIGGER IF NOT EXISTS records_ad AFTER DELETE ON records BEGIN
               INSERT INTO records_fts(records_fts, rowid, content)
               VALUES ('delete', old.rowid, old.content);
             END;
             CREATE TRIGGER IF NOT EXISTS records_au AFTER UPDATE ON records BEGIN
               INSERT INTO records_fts(records_fts, rowid, content)
               VALUES ('delete', old.rowid, old.content);
               INSERT INTO records_fts(rowid, content) VALUES (new.rowid, new.content);
             END;",
        )?;
        sync_directory(&root_dir)?;
        let store = Self {
            root_dir,
            _root_guard: root_guard,
            _database_guard: database_guard,
            _wal_guard: wal_guard,
            _shm_guard: shm_guard,
            connection: Mutex::new(connection),
        };
        if !store.projection_is_current()? {
            store.project_jsonl()?;
        }
        Ok(store)
    }

    pub fn ingest(&self, record: &MemoryRecord) -> Result<bool, MemoryError> {
        let (inserted, _) = self.ingest_many(std::slice::from_ref(record))?;
        Ok(inserted == 1)
    }

    pub fn ingest_many(&self, records: &[MemoryRecord]) -> Result<(usize, usize), MemoryError> {
        let records = records
            .iter()
            .map(MemoryRecord::sanitized)
            .collect::<Result<Vec<_>, _>>()?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| MemoryError::LockPoisoned)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut inserted = 0usize;
        let mut duplicates = 0usize;
        for record in &records {
            let exists = transaction
                .query_row(
                    "SELECT 1 FROM records WHERE id = ?1",
                    params![record.id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if exists {
                duplicates += 1;
                continue;
            }
            transaction.execute(
                "INSERT INTO records
                 (id, session_id, workspace, kind, content, timestamp, metadata_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    record.id,
                    record.session_id,
                    record.workspace,
                    record.kind,
                    record.content,
                    record.timestamp,
                    serde_json::to_string(&record.metadata)?,
                ],
            )?;
            inserted += 1;
        }
        transaction.commit()?;
        drop(connection);
        self.project_jsonl()?;
        Ok((inserted, duplicates))
    }

    pub fn ingest_snapshot(
        &self,
        request: &SnapshotRequest,
    ) -> Result<(usize, usize), MemoryError> {
        request.validate()?;
        let session_id = sanitize_identifier(&request.session_id);
        let workspace = sanitize_identifier(&request.workspace);
        let fingerprints = request
            .items
            .iter()
            .map(snapshot_fingerprint)
            .collect::<Result<Vec<_>, _>>()?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| MemoryError::LockPoisoned)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous = {
            let mut statement = transaction.prepare(
                "SELECT fingerprint, record_id FROM snapshot_state
                 WHERE session_id = ?1 AND workspace = ?2 ORDER BY position",
            )?;
            let rows = statement
                .query_map(params![session_id, workspace], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        let maximum = previous.len().min(request.items.len());
        let overlap = (0..=maximum)
            .rev()
            .find(|length| {
                previous[previous.len() - length..]
                    .iter()
                    .map(|(fingerprint, _)| fingerprint)
                    .eq(fingerprints[..*length].iter())
            })
            .unwrap_or(0);
        let mut record_ids = previous[previous.len() - overlap..]
            .iter()
            .map(|(_, record_id)| record_id.clone())
            .collect::<Vec<_>>();
        let mut inserted = 0usize;
        let mut duplicates = 0usize;
        for (offset, item) in request.items[overlap..].iter().enumerate() {
            let fingerprint = &fingerprints[overlap + offset];
            let occurrence = transaction
                .query_row(
                    "SELECT next_occurrence FROM snapshot_counters
                     WHERE session_id = ?1 AND workspace = ?2 AND fingerprint = ?3",
                    params![session_id, workspace, fingerprint],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .unwrap_or(0);
            let record_id = snapshot_record_id(&session_id, &workspace, fingerprint, occurrence);
            let record = MemoryRecord {
                id: record_id.clone(),
                session_id: session_id.clone(),
                workspace: workspace.clone(),
                kind: item.kind.clone(),
                content: item.content.clone(),
                timestamp: item.timestamp,
                metadata: item.metadata.clone(),
            }
            .sanitized()?;
            let changed = transaction.execute(
                "INSERT OR IGNORE INTO records
                 (id, session_id, workspace, kind, content, timestamp, metadata_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    record.id,
                    record.session_id,
                    record.workspace,
                    record.kind,
                    record.content,
                    record.timestamp,
                    serde_json::to_string(&record.metadata)?,
                ],
            )?;
            if changed == 1 {
                inserted += 1;
            } else {
                duplicates += 1;
            }
            transaction.execute(
                "INSERT INTO snapshot_counters
                 (session_id, workspace, fingerprint, next_occurrence)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(session_id, workspace, fingerprint)
                 DO UPDATE SET next_occurrence = excluded.next_occurrence",
                params![session_id, workspace, fingerprint, occurrence + 1,],
            )?;
            record_ids.push(record_id);
        }
        transaction.execute(
            "DELETE FROM snapshot_state WHERE session_id = ?1 AND workspace = ?2",
            params![session_id, workspace],
        )?;
        for (position, record_id) in record_ids.iter().enumerate() {
            transaction.execute(
                "INSERT INTO snapshot_state
                 (session_id, workspace, position, fingerprint, record_id)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    session_id,
                    workspace,
                    position as i64,
                    fingerprints[position],
                    record_id,
                ],
            )?;
        }
        transaction.commit()?;
        drop(connection);
        self.project_jsonl()?;
        Ok((inserted, duplicates))
    }

    pub fn search(&self, request: &SearchRequest) -> Result<Vec<SearchHit>, MemoryError> {
        request.validate()?;
        if request.limit == 0 || request.max_bytes == 0 {
            return Ok(Vec::new());
        }
        let fts_query = to_fts_query(&request.query);
        if fts_query.is_empty() {
            return Ok(Vec::new());
        }
        let workspace = request.workspace.as_deref().map(sanitize_identifier);
        let session_id = request.session_id.as_deref().map(sanitize_identifier);
        let connection = self
            .connection
            .lock()
            .map_err(|_| MemoryError::LockPoisoned)?;
        let mut statement = connection.prepare(
            "SELECT r.id, r.session_id, r.workspace, r.kind, r.content,
                    r.timestamp, r.metadata_json
             FROM records_fts
             JOIN records r ON r.rowid = records_fts.rowid
             WHERE records_fts MATCH ?1
               AND (?2 IS NULL OR r.workspace = ?2)
               AND (?3 IS NULL OR r.session_id = ?3)
             ORDER BY bm25(records_fts), r.timestamp DESC
             LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![fts_query, workspace, session_id, request.limit as i64],
            |row| {
                let metadata_json: String = row.get(6)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, f64>(5)?,
                    metadata_json,
                ))
            },
        )?;
        let mut candidates = Vec::new();
        for row in rows {
            let (id, session_id, workspace, kind, content, timestamp, metadata_json) = row?;
            let hit = SearchHit {
                id,
                session_id,
                workspace,
                kind,
                content,
                timestamp,
                metadata: serde_json::from_str(&metadata_json)?,
            };
            candidates.push(hit);
        }
        pack_search_hits(candidates, request.max_bytes)
    }

    pub fn export_markdown(
        &self,
        vault: impl AsRef<Path>,
        workspace: Option<&str>,
    ) -> Result<usize, MemoryError> {
        let vault = vault.as_ref();
        validate_export_destination(vault)?;
        let vault_dir = open_or_create_absolute_dir(vault)?;
        let export_lock = capability_lock_file(&self.root_dir, "export.lock")?;
        sync_directory(&self.root_dir)?;
        export_lock.lock_exclusive()?;
        let workspace = workspace.map(sanitize_identifier);
        let connection = self
            .connection
            .lock()
            .map_err(|_| MemoryError::LockPoisoned)?;
        let mut statement = connection.prepare(
            "SELECT id, session_id, workspace, kind, content, timestamp, metadata_json
             FROM records
             WHERE (?1 IS NULL OR workspace = ?1)
             ORDER BY workspace, session_id, timestamp, rowid",
        )?;
        let rows = statement.query_map(params![workspace], |row| {
            Ok(SearchHit {
                id: row.get(0)?,
                session_id: row.get(1)?,
                workspace: row.get(2)?,
                kind: row.get(3)?,
                content: row.get(4)?,
                timestamp: row.get(5)?,
                metadata: serde_json::from_str::<Value>(&row.get::<_, String>(6)?)
                    .unwrap_or(Value::Null),
            })
        })?;
        let mut sessions: BTreeMap<(String, String), Vec<SearchHit>> = BTreeMap::new();
        for row in rows {
            let record = row?;
            sessions
                .entry((record.workspace.clone(), record.session_id.clone()))
                .or_default()
                .push(record);
        }

        let mut links = Vec::new();
        let sessions_dir = open_or_create_child_dir(&vault_dir, Path::new("Sessions"))?;
        for ((workspace, session_id), records) in &sessions {
            let workspace_segment = safe_segment(workspace);
            let session_segment = safe_segment(session_id);
            let workspace_dir =
                open_or_create_child_dir(&sessions_dir, Path::new(&workspace_segment))?;
            let mut note = String::new();
            note.push_str("---\n");
            note.push_str(&format!("workspace: {}\n", yaml_scalar(workspace)));
            note.push_str(&format!("session_id: {}\n", yaml_scalar(session_id)));
            note.push_str("generated_by: hermes-memory\n---\n\n");
            note.push_str(&format!("# Session {}\n\n", markdown_inline(session_id)));
            for record in records {
                note.push_str(&format!(
                    "## {} · {}\n\n- id: {}\n- timestamp: {}\n\n### Content\n\n{}\n\n",
                    markdown_inline(&record.kind),
                    markdown_inline(&record.id),
                    markdown_inline(&record.id),
                    record.timestamp,
                    markdown_quote(&record.content),
                ));
            }
            capability_atomic_write(
                &workspace_dir,
                &format!("{session_segment}.md"),
                note.as_bytes(),
            )?;
            links.push(format!(
                "- [[Sessions/{workspace_segment}/{session_segment}]]"
            ));
        }
        let mut index = String::from("# Hermes Memory Vault\n\n");
        if links.is_empty() {
            index.push_str("_No sessions indexed._\n");
        } else {
            index.push_str(&links.join("\n"));
            index.push('\n');
        }
        capability_atomic_write(&vault_dir, "Index.md", index.as_bytes())?;
        Ok(sessions.len())
    }

    fn projection_is_current(&self) -> Result<bool, MemoryError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| MemoryError::LockPoisoned)?;
        let mut statement = connection.prepare(
            "SELECT id, session_id, workspace, kind, content, timestamp, metadata_json
             FROM records ORDER BY timestamp, rowid",
        )?;
        let expected = statement
            .query_map([], |row| {
                Ok(MemoryRecord {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    workspace: row.get(2)?,
                    kind: row.get(3)?,
                    content: row.get(4)?,
                    timestamp: row.get(5)?,
                    metadata: serde_json::from_str::<Value>(&row.get::<_, String>(6)?)
                        .unwrap_or(Value::Null),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let file = match capability_existing_file(&self.root_dir, "events.jsonl") {
            Ok(file) => file,
            Err(MemoryError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        let mut actual = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = match line {
                Ok(line) => line,
                Err(_) => return Ok(false),
            };
            let record: MemoryRecord = match serde_json::from_str(&line) {
                Ok(record) => record,
                Err(_) => return Ok(false),
            };
            actual.push(record);
        }
        Ok(actual == expected)
    }

    fn project_jsonl(&self) -> Result<(), MemoryError> {
        let lock_file = capability_lock_file(&self.root_dir, "events.jsonl.lock")?;
        lock_file.lock_exclusive()?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| MemoryError::LockPoisoned)?;
        let mut statement = connection.prepare(
            "SELECT id, session_id, workspace, kind, content, timestamp, metadata_json
             FROM records ORDER BY timestamp, rowid",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(MemoryRecord {
                id: row.get(0)?,
                session_id: row.get(1)?,
                workspace: row.get(2)?,
                kind: row.get(3)?,
                content: row.get(4)?,
                timestamp: row.get(5)?,
                metadata: serde_json::from_str::<Value>(&row.get::<_, String>(6)?)
                    .unwrap_or(Value::Null),
            })
        })?;
        capability_atomic_replace(&self.root_dir, "events.jsonl", |file| {
            for row in rows {
                serde_json::to_writer(&mut *file, &row?)?;
                file.write_all(b"\n")?;
            }
            Ok(())
        })
    }
}

fn open_or_create_absolute_dir(path: &Path) -> Result<Dir, MemoryError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut anchor = PathBuf::new();
    let mut children = Vec::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => anchor.push(prefix.as_os_str()),
            Component::RootDir => anchor.push(component.as_os_str()),
            Component::Normal(name) => children.push(name.to_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(MemoryError::UnsafeExportPath(path.to_path_buf()));
            }
        }
    }
    if !anchor.is_absolute() {
        return Err(MemoryError::UnsafeExportPath(path.to_path_buf()));
    }
    let mut directory = Dir::open_ambient_dir(&anchor, ambient_authority())?;
    for child in children {
        directory = open_or_create_child_dir(&directory, Path::new(&child))?;
    }
    Ok(directory)
}

fn open_or_create_child_dir(parent: &Dir, child: &Path) -> Result<Dir, MemoryError> {
    let mut components = child.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(MemoryError::UnsafeExportPath(child.to_path_buf()));
    }
    let parent_file = parent.try_clone()?.into_std_file();
    match cap_primitives::fs::open_dir_nofollow(&parent_file, child) {
        Ok(file) => Ok(Dir::from_std_file(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match parent.create_dir(child) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            sync_directory(parent)?;
            let parent_file = parent.try_clone()?.into_std_file();
            let file = cap_primitives::fs::open_dir_nofollow(&parent_file, child)?;
            Ok(Dir::from_std_file(file))
        }
        Err(error) => Err(error.into()),
    }
}

fn capability_lock_file(directory: &Dir, name: &str) -> Result<File, MemoryError> {
    Ok(capability_data_file(directory, name)?.into_std())
}

fn capability_data_file(directory: &Dir, name: &str) -> Result<CapFile, MemoryError> {
    let mut options = CapOpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .follow(FollowSymlinks::No);
    #[cfg(windows)]
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    let file = directory.open_with(name, &options)?;
    ensure_single_link(&file)?;
    Ok(file)
}

fn capability_existing_file(directory: &Dir, name: &str) -> Result<CapFile, MemoryError> {
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(windows)]
    options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    let file = directory.open_with(name, &options)?;
    ensure_single_link(&file)?;
    Ok(file)
}

fn ensure_single_link(file: &CapFile) -> Result<(), MemoryError> {
    let metadata = file.metadata()?;
    #[cfg(windows)]
    let links = metadata.number_of_links().unwrap_or(0) as u64;
    #[cfg(unix)]
    let links = metadata.nlink();
    #[cfg(not(any(unix, windows)))]
    let links = 1;
    if links != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "memory file has unsafe link count",
        )
        .into());
    }
    Ok(())
}

#[cfg(windows)]
fn capability_root_guard(directory: &Dir) -> Result<CapFile, MemoryError> {
    let mut options = CapOpenOptions::new();
    options
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .follow(FollowSymlinks::No);
    Ok(directory.open_with(".", &options)?)
}

#[cfg(not(windows))]
fn capability_root_guard(directory: &Dir) -> Result<CapFile, MemoryError> {
    Ok(CapFile::from_std(directory.try_clone()?.into_std_file()))
}

#[cfg(windows)]
fn stable_root_path(root_guard: &CapFile, _requested: &Path) -> Result<PathBuf, MemoryError> {
    let mut buffer = vec![0u16; 32_768];
    // SAFETY: the handle remains owned by `root_guard`; `buffer` is writable for its full
    // advertised length, and the API does not retain either pointer after returning.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            root_guard.as_raw_handle() as _,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    };
    if length == 0 || length as usize >= buffer.len() {
        return Err(std::io::Error::last_os_error().into());
    }
    buffer.truncate(length as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer)))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn stable_root_path(root_guard: &CapFile, _requested: &Path) -> Result<PathBuf, MemoryError> {
    Ok(PathBuf::from(format!(
        "/proc/self/fd/{}",
        root_guard.as_raw_fd()
    )))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "android")))]
fn stable_root_path(_root_guard: &CapFile, requested: &Path) -> Result<PathBuf, MemoryError> {
    Ok(requested.to_path_buf())
}

fn capability_atomic_write(
    directory: &Dir,
    target: &str,
    payload: &[u8],
) -> Result<(), MemoryError> {
    capability_atomic_replace(directory, target, |file| {
        file.write_all(payload)?;
        Ok(())
    })
}

fn capability_atomic_replace(
    directory: &Dir,
    target: &str,
    write: impl FnOnce(&mut CapFile) -> Result<(), MemoryError>,
) -> Result<(), MemoryError> {
    let target_path = Path::new(target);
    let mut components = target_path.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(MemoryError::UnsafeExportPath(target_path.to_path_buf()));
    }
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut opened = None;
    for _ in 0..16 {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary = format!(".{target}.{}.{}.tmp", std::process::id(), sequence);
        let mut options = CapOpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(windows)]
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        match directory.open_with(&temporary, &options) {
            Ok(file) => {
                opened = Some((temporary, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let (temporary, mut file) = opened.ok_or_else(|| {
        MemoryError::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate an atomic temp file",
        ))
    })?;
    let result = (|| -> Result<(), MemoryError> {
        write(&mut file)?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        directory.rename(&temporary, directory, target_path)?;
        sync_directory(directory)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = directory.remove_file(&temporary);
    }
    result
}

#[cfg(not(windows))]
fn sync_directory(directory: &Dir) -> Result<(), MemoryError> {
    directory.try_clone()?.into_std_file().sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_directory(directory: &Dir) -> Result<(), MemoryError> {
    let mut options = CapOpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    directory.open_with(".", &options)?.sync_all()?;
    Ok(())
}

fn snapshot_record_id(
    session_id: &str,
    workspace: &str,
    fingerprint: &str,
    occurrence: i64,
) -> String {
    let mut digest = Sha256::new();
    digest.update(session_id.as_bytes());
    digest.update(b"\0");
    digest.update(workspace.as_bytes());
    digest.update(b"\0");
    digest.update(fingerprint.as_bytes());
    digest.update(b"\0");
    digest.update(occurrence.to_string().as_bytes());
    format!("msg-{:x}", digest.finalize())
}

fn snapshot_fingerprint(item: &SnapshotItem) -> Result<String, MemoryError> {
    let tool_call_id = item
        .metadata
        .get("tool_call_id")
        .map(redact_value)
        .unwrap_or(Value::Null);
    let identity = serde_json::to_vec(&(
        sanitize_identifier(&item.kind),
        redact_text(&item.content),
        tool_call_id,
    ))?;
    let mut digest = Sha256::new();
    digest.update(identity);
    Ok(format!("{:x}", digest.finalize()))
}

fn sanitize_identifier(value: &str) -> String {
    if redact_text(value) == value {
        return value.to_owned();
    }
    let mut digest = Sha256::new();
    digest.update(value.as_bytes());
    format!("redacted-{:x}", digest.finalize())
}

fn safe_segment(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|character| {
            if character.is_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .take(96)
        .collect();
    let base = if sanitized.is_empty() || matches!(sanitized.as_str(), "." | "..") {
        "item".to_owned()
    } else {
        sanitized
    };
    let digest = Sha256::digest(value.as_bytes());
    let suffix = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{base}-{suffix}")
}

fn yaml_scalar(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_alphanumeric() || matches!(character, '.' | '_' | '-'))
    {
        return value.to_owned();
    }
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

fn markdown_inline(value: &str) -> String {
    let flattened = value
        .chars()
        .map(|character| {
            if matches!(character, '\r' | '\n') {
                ' '
            } else if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect::<String>();
    let mut escaped = String::with_capacity(flattened.len());
    for character in flattened.trim().chars() {
        if matches!(
            character,
            '\\' | '*' | '_' | '`' | '[' | ']' | '<' | '>' | '|'
        ) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

fn markdown_quote(value: &str) -> String {
    if value.is_empty() {
        return ">".to_owned();
    }
    value
        .lines()
        .map(|line| format!("> {line}"))
        .collect::<Vec<_>>()
        .join("\n")
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

fn fit_hit_within_json_budget(
    existing: &[SearchHit],
    mut hit: SearchHit,
    max_bytes: usize,
) -> Result<Option<SearchHit>, MemoryError> {
    let mut candidate = existing.to_vec();
    candidate.push(hit.clone());
    if serde_json::to_vec(&candidate)?.len() <= max_bytes {
        return Ok(Some(hit));
    }
    let original = hit.content.clone();
    let mut low = 0usize;
    let mut high = original.len();
    let mut best = None;
    while low <= high {
        let middle = low + (high - low) / 2;
        hit.content = truncate_utf8(&original, middle);
        candidate.pop();
        candidate.push(hit.clone());
        if serde_json::to_vec(&candidate)?.len() <= max_bytes {
            best = Some(hit.clone());
            low = middle.saturating_add(1);
        } else if middle == 0 {
            break;
        } else {
            high = middle - 1;
        }
    }
    Ok(best.filter(|bounded| !bounded.content.is_empty()))
}

fn pack_search_hits(
    candidates: Vec<SearchHit>,
    max_bytes: usize,
) -> Result<Vec<SearchHit>, MemoryError> {
    let mut selected = Vec::new();
    let mut deferred = Vec::new();
    for hit in candidates {
        let mut candidate = selected.clone();
        candidate.push(hit.clone());
        if serde_json::to_vec(&candidate)?.len() <= max_bytes {
            selected.push(hit);
        } else {
            deferred.push(hit);
        }
    }
    for hit in deferred {
        if let Some(bounded) = fit_hit_within_json_budget(&selected, hit, max_bytes)? {
            selected.push(bounded);
            break;
        }
    }
    Ok(selected)
}

fn to_fts_query(query: &str) -> String {
    query
        .split(|character: char| {
            !character.is_alphanumeric() && character != '_' && character != '-'
        })
        .filter(|token| !token.is_empty())
        .map(|token| format!("\"{}\"", token.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" OR ")
}

fn truncate_utf8(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    text[..boundary].to_owned()
}

#[cfg(all(test, windows))]
mod windows_file_guard_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn capability_data_file_denies_delete_share_while_open() {
        let temp = tempdir().expect("temp dir");
        let directory =
            Dir::open_ambient_dir(temp.path(), ambient_authority()).expect("open temp dir");
        let _guard = capability_data_file(&directory, "guarded.lock").expect("open guard");

        assert!(std::fs::rename(
            temp.path().join("guarded.lock"),
            temp.path().join("renamed.lock")
        )
        .is_err());
    }
}

#[cfg(test)]
mod search_packing_tests {
    use super::*;

    fn hit(id: &str, content: &str) -> SearchHit {
        SearchHit {
            id: id.to_owned(),
            session_id: "session".to_owned(),
            workspace: "workspace".to_owned(),
            kind: "assistant".to_owned(),
            content: content.to_owned(),
            timestamp: 1.0,
            metadata: Value::Null,
        }
    }

    #[test]
    fn packer_keeps_later_complete_hit_before_truncation_fallback() {
        let packed = pack_search_hits(
            vec![hit("large", &"x".repeat(10_000)), hit("later", "complete")],
            1024,
        )
        .expect("pack hits");

        assert!(packed.iter().any(|item| item.id == "later"));
    }
}
