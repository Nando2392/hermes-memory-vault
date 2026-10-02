//! Read-only, bounded broker export pages. Prepare the derived ordering index
//! explicitly before readiness; ordinary store opens never build it.
//!
//! Clients must echo `high_water` and `next` unchanged for each subsequent page.
//! The high-water snapshot depends on records remaining append-only: the store's
//! ingest paths only insert, but direct SQL mutation, VACUUM, or restoring another
//! database invalidates cursors. No long-lived transaction is retained between
//! calls. The caller must enforce its authenticated workspace before calling;
//! this API scopes every query but is not itself an authorization boundary.
//!
//! Limits: 256 records, 8 MiB full success JSON envelope, 4096-byte identifiers,
//! with content and raw metadata bounded by the requested page budget. Payloads
//! are never truncated. Legacy records near 8 MiB may exceed the full envelope;
//! migration admission must check exportability rather than silently skip them.
//! The ordering index covers keys (including implicit rowid), not large payloads.
use crate::{MemoryError, MemoryRecord, MemoryStore};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_EXPORT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_EXPORT_RECORDS: usize = 256;

/// An opaque-to-clients keyset position, not an authentication token, SQL
/// expression, or filesystem capability. The row must match the requested scope.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportCursor {
    pub session_id: String,
    pub timestamp: f64,
    pub rowid: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportPageRequest {
    pub workspace: String,
    pub high_water: Option<i64>,
    pub after: Option<ExportCursor>,
    pub max_records: usize,
    pub max_bytes: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportPage {
    pub records: Vec<MemoryRecord>,
    pub next: Option<ExportCursor>,
    pub high_water: i64,
}

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("invalid_request")]
    InvalidRequest,
    #[error("resource_limit")]
    ResourceLimit,
    #[error("export index is not prepared")]
    Unprepared,
    #[error(transparent)]
    Store(#[from] MemoryError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

const INDEX_SQL: &str =
    "CREATE INDEX records_export_order ON records(workspace, session_id, timestamp)";

fn prepared(connection: &rusqlite::Connection) -> Result<bool, ExportError> {
    let sql: Option<String> = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='index' AND name='records_export_order' AND tbl_name='records'",
        [], |r| r.get(0),
    ).optional()?;
    Ok(sql.as_deref() == Some(INDEX_SQL))
}

// A counting serializer avoids allocating a second page-sized JSON buffer.
struct ByteCount(usize);
impl std::io::Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn json_size(value: &impl Serialize) -> Result<usize, ExportError> {
    let mut count = ByteCount(0);
    serde_json::to_writer(&mut count, value)?;
    Ok(count.0)
}
fn envelope_size(page: &ExportPage, request_id: &str) -> Result<usize, ExportError> {
    #[derive(Serialize)]
    struct Envelope<'a> {
        protocol: u32,
        request_id: &'a str,
        ok: bool,
        result: &'a ExportPage,
    }
    json_size(&Envelope {
        protocol: 1,
        request_id,
        ok: true,
        result: page,
    })
}

fn read_bounded_record(
    connection: &rusqlite::Connection,
    rowid: i64,
    budget: usize,
) -> Result<MemoryRecord, ExportError> {
    // Query only byte lengths first: no text field crosses into Rust until ALL
    // fields pass. octet_length reads the on-disk byte length without loading
    // the payload into SQLite memory (unlike length(CAST(text AS BLOB))).
    let lengths: [i64; 6] = connection.query_row(
        "SELECT octet_length(id),octet_length(session_id),octet_length(workspace),octet_length(kind),octet_length(content),octet_length(metadata_json) FROM records WHERE rowid=?1",
        [rowid], |r| Ok([r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?]),
    )?;
    let caps = [
        4096,
        4096,
        4096,
        4096,
        MAX_EXPORT_BYTES as i64,
        MAX_EXPORT_BYTES as i64,
    ];
    if lengths
        .iter()
        .zip(caps)
        .any(|(&n, cap)| n < 0 || n > cap || n as u64 > budget as u64)
        || lengths.iter().sum::<i64>() > budget as i64
    {
        return Err(ExportError::ResourceLimit);
    }
    let (mut record, metadata): (MemoryRecord, String) = connection.query_row(
        "SELECT id,session_id,workspace,kind,content,timestamp,metadata_json FROM records WHERE rowid=?1", [rowid], |r| {
            Ok((MemoryRecord { id:r.get(0)?, session_id:r.get(1)?, workspace:r.get(2)?, kind:r.get(3)?, content:r.get(4)?, timestamp:r.get(5)?, metadata:serde_json::Value::Null }, r.get(6)?))
        },
    )?;
    if !record.timestamp.is_finite() {
        return Err(ExportError::InvalidRequest);
    }
    record.metadata = serde_json::from_str(&metadata)?;
    Ok(record)
}

impl MemoryStore {
    /// Build the derived ordering index before service readiness. Does not change
    /// schema version; refuses future schemas before executing any DDL.
    pub fn prepare_export_index(&self) -> Result<(), ExportError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| MemoryError::LockPoisoned)?;
        crate::reject_future_schema(&connection)?;
        if !prepared(&connection)? {
            connection.execute_batch(INDEX_SQL)?;
        }
        Ok(())
    }

    /// The byte limit includes the protocol-1 success envelope and the actual
    /// JSON-escaped request ID (not the four-byte transport length prefix).
    /// The caller must serialize `{protocol:1,request_id,ok:true,result:page}`
    /// without extra fields/whitespace to retain the exact budget guarantee.
    /// A too-large next record yields a partial page first, then ResourceLimit
    /// on its continuation; it is never skipped or returned as truncated text.
    pub fn export_page(
        &self,
        request: &ExportPageRequest,
        request_id: &str,
    ) -> Result<ExportPage, ExportError> {
        if request.workspace.trim().is_empty() || request_id.trim().is_empty() {
            return Err(ExportError::InvalidRequest);
        }
        if request.workspace.len() > 4096
            || request_id.len() > 128
            || !(1..=MAX_EXPORT_RECORDS).contains(&request.max_records)
            || !(1..=MAX_EXPORT_BYTES).contains(&request.max_bytes)
        {
            return Err(ExportError::ResourceLimit);
        }
        if let Some(cursor) = &request.after {
            if request.high_water.is_none()
                || cursor.rowid <= 0
                || !cursor.timestamp.is_finite()
                || cursor.session_id.trim().is_empty()
                || cursor.session_id.len() > 4096
            {
                return Err(ExportError::InvalidRequest);
            }
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| MemoryError::LockPoisoned)?;
        crate::reject_future_schema(&connection)?;
        if !prepared(&connection)? {
            return Err(ExportError::Unprepared);
        }
        let tx = connection.transaction()?;
        let current: i64 = tx.query_row("SELECT COALESCE(MAX(rowid),0) FROM records", [], |r| {
            r.get(0)
        })?;
        let high_water = request.high_water.unwrap_or(current);
        if high_water < 0 || high_water > current {
            return Err(ExportError::InvalidRequest);
        }
        let workspace = crate::sanitize_identifier(&request.workspace);
        if let Some(cursor) = &request.after {
            let valid: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM records WHERE rowid=?1 AND rowid<=?2 AND workspace=?3 AND session_id=?4 AND timestamp=?5)",
                rusqlite::params![cursor.rowid, high_water, workspace, cursor.session_id, cursor.timestamp], |r| r.get(0),
            )?;
            if !valid {
                return Err(ExportError::InvalidRequest);
            }
        }
        let sql = if request.after.is_some() {
            "SELECT rowid FROM records INDEXED BY records_export_order WHERE workspace=?1 AND rowid<=?2 AND (session_id,timestamp,rowid)>(?3,?4,?5) ORDER BY session_id,timestamp,rowid LIMIT ?6"
        } else {
            "SELECT rowid FROM records INDEXED BY records_export_order WHERE workspace=?1 AND rowid<=?2 ORDER BY session_id,timestamp,rowid LIMIT ?6"
        };
        let mut stmt = tx.prepare(sql)?;
        let cursor = request.after.as_ref();
        stmt.raw_bind_parameter(1, &workspace)?;
        stmt.raw_bind_parameter(2, high_water)?;
        if let Some(cursor) = cursor {
            stmt.raw_bind_parameter(3, &cursor.session_id)?;
            stmt.raw_bind_parameter(4, cursor.timestamp)?;
            stmt.raw_bind_parameter(5, cursor.rowid)?;
        }
        stmt.raw_bind_parameter(6, (request.max_records + 1) as i64)?;
        let mut rows = stmt.raw_query();
        let mut page = ExportPage {
            records: Vec::new(),
            next: None,
            high_water,
        };
        if envelope_size(&page, request_id)? > request.max_bytes {
            return Err(ExportError::ResourceLimit);
        }
        let mut record_bytes = 0;
        let mut next_rowid: Option<i64> = rows.next()?.map(|r| r.get(0)).transpose()?;
        while let Some(rowid) = next_rowid {
            if page.records.len() == request.max_records {
                break;
            }
            let record = match read_bounded_record(&tx, rowid, request.max_bytes) {
                Ok(record) => record,
                Err(ExportError::ResourceLimit) if !page.records.is_empty() => break,
                Err(error) => return Err(error),
            };
            next_rowid = rows.next()?.map(|r| r.get(0)).transpose()?;
            let next = next_rowid.map(|_| ExportCursor {
                session_id: record.session_id.clone(),
                timestamp: record.timestamp,
                rowid,
            });
            let candidate = ExportPage {
                records: Vec::new(),
                next,
                high_water,
            };
            let candidate_bytes =
                record_bytes + json_size(&record)? + usize::from(!page.records.is_empty());
            if envelope_size(&candidate, request_id)? + candidate_bytes > request.max_bytes {
                if page.records.is_empty() {
                    return Err(ExportError::ResourceLimit);
                }
                break;
            }
            record_bytes = candidate_bytes;
            page.next = candidate.next;
            page.records.push(record);
        }
        Ok(page)
    }
}
