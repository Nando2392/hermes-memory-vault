//! Broker page to legacy Markdown projection; never opens the memory store.
use crate::broker_export::{ExportPage, ExportPageRequest, MAX_EXPORT_BYTES, MAX_EXPORT_RECORDS};
use crate::{
    capability_atomic_replace, markdown_inline, markdown_quote, open_or_create_absolute_dir,
    open_or_create_child_dir, safe_segment, validate_export_destination, yaml_scalar, MemoryError,
    MemoryRecord,
};
use std::{io::Write, path::Path};

fn invalid_page() -> MemoryError {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "invalid broker export page",
    )
    .into()
}

// A counting sink checks fixture/source budgets without cloning the page.
struct Count(usize);
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        if self.0 > MAX_EXPORT_BYTES {
            return Err(std::io::Error::other("export page exceeds budget"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn validate_page(page: &ExportPage, req: &ExportPageRequest) -> Result<(), MemoryError> {
    if page.high_water < 0
        || (page.high_water == 0 && !page.records.is_empty())
        || req.high_water.is_some_and(|h| h != page.high_water)
        || page.records.len() > req.max_records
        || (page.records.is_empty() && (page.next.is_some() || req.after.is_some()))
    {
        return Err(invalid_page());
    }
    serde_json::to_writer(&mut Count(0), page)?;
    let expected_workspace = crate::sanitize_identifier(&req.workspace);
    let mut previous = req
        .after
        .as_ref()
        .map(|c| (c.session_id.as_str(), c.timestamp));
    for record in &page.records {
        if record.workspace != expected_workspace
            || !record.timestamp.is_finite()
            || previous.is_some_and(|(s, t)| {
                record.session_id.as_str() < s || (record.session_id == s && record.timestamp < t)
            })
        {
            return Err(invalid_page());
        }
        previous = Some((&record.session_id, record.timestamp));
    }
    if let Some(next) = &page.next {
        if next.rowid <= 0
            || next.rowid > page.high_water
            || !next.timestamp.is_finite()
            || !page
                .records
                .last()
                .is_some_and(|r| r.session_id == next.session_id && r.timestamp == next.timestamp)
            || req.after.as_ref().is_some_and(|after| {
                (next.session_id.as_str(), next.timestamp, next.rowid)
                    <= (after.session_id.as_str(), after.timestamp, after.rowid)
            })
        {
            return Err(invalid_page());
        }
    }
    Ok(())
}

struct Records<F> {
    source: F,
    request: ExportPageRequest,
    records: std::vec::IntoIter<MemoryRecord>,
    finished: bool,
}
impl<F: FnMut(&ExportPageRequest) -> Result<ExportPage, MemoryError>> Iterator for Records<F> {
    type Item = Result<MemoryRecord, MemoryError>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(record) = self.records.next() {
            return Some(Ok(record));
        }
        if self.finished {
            return None;
        }
        match (self.source)(&self.request) {
            Err(error) => {
                self.finished = true;
                Some(Err(error))
            }
            Ok(page) => {
                if let Err(error) = validate_page(&page, &self.request) {
                    self.finished = true;
                    return Some(Err(error));
                }
                self.finished = page.next.is_none();
                self.request.high_water = Some(page.high_water);
                self.request.after = page.next;
                self.records = page.records.into_iter();
                self.next()
            }
        }
    }
}

/// Render trusted broker pages to the human-editable legacy vault layout.
/// Memory is bounded to a page and one record; session notes and the index are
/// streamed into capability-relative atomic replacements. On source failure the
/// current session and index are not published; prior complete sessions may be.
pub fn render_markdown(
    vault: &Path,
    workspace: &str,
    source: impl FnMut(&ExportPageRequest) -> Result<ExportPage, MemoryError>,
) -> Result<usize, MemoryError> {
    let request = ExportPageRequest {
        workspace: workspace.into(),
        high_water: None,
        after: None,
        max_records: MAX_EXPORT_RECORDS,
        max_bytes: MAX_EXPORT_BYTES,
    };
    let mut records = Records {
        source,
        request,
        records: Vec::new().into_iter(),
        finished: false,
    };
    // Authenticate/fetch before creating any destination directories.
    let mut current = records.next().transpose()?;
    validate_export_destination(vault)?;
    let directory = open_or_create_absolute_dir(vault)?;
    let sessions = open_or_create_child_dir(&directory, Path::new("Sessions"))?;
    let mut count = 0;
    capability_atomic_replace(&directory, "Index.md", |index| {
        index.write_all(b"# Hermes Memory Vault\n\n")?;
        while let Some(first) = current.take() {
            let session = first.session_id.clone();
            let workspace_segment = safe_segment(&first.workspace);
            let session_segment = safe_segment(&session);
            let session_dir = open_or_create_child_dir(&sessions, Path::new(&workspace_segment))?;
            capability_atomic_replace(&session_dir, &format!("{session_segment}.md"), |file| {
                write!(file,"---\nworkspace: {}\nsession_id: {}\ngenerated_by: hermes-memory\n---\n\n# Session {}\n\n",yaml_scalar(&first.workspace),yaml_scalar(&session),markdown_inline(&session))?;
                let mut record = first;
                loop {
                    write!(
                        file,
                        "## {} · {}\n\n- id: {}\n- timestamp: {}\n\n### Content\n\n{}\n\n",
                        markdown_inline(&record.kind),
                        markdown_inline(&record.id),
                        markdown_inline(&record.id),
                        record.timestamp,
                        markdown_quote(&record.content)
                    )?;
                    match records.next().transpose()? {
                        Some(next) if next.session_id == session => record = next,
                        next => {
                            current = next;
                            break;
                        }
                    }
                }
                Ok(())
            })?;
            writeln!(
                index,
                "- [[Sessions/{workspace_segment}/{session_segment}]]"
            )?;
            count += 1;
        }
        if count == 0 {
            index.write_all(b"_No sessions indexed._\n")?;
        }
        Ok(())
    })?;
    Ok(count)
}
