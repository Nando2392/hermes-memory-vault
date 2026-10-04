//! Pure Full20x256V1 schedule, independent of small/pilot/two-warmup contracts.
//! Base coverage explicitly excludes out-of-order ingestion, clean restart, and
//! damaged-projection recovery. This module admits no native case and measures nothing.
//! Only 64 descriptors persist; records and replay payloads are regenerated one
//! bounded batch at a time. The initial snapshot is pinned separately by import.
use crate::{
    contract::ensure,
    data::{self, Result},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadSpec {
    pub schema: u8,
    pub kind: WorkloadKind,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkloadKind {
    Full20x256V1,
}
impl WorkloadSpec {
    pub fn full20x256_v1() -> Self {
        Self {
            schema: 1,
            kind: WorkloadKind::Full20x256V1,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Warmup,
    Single,
    Batch,
    Dedup,
    UnchangedSnapshot,
    Export,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    pub id: u32,
    pub cli_epoch: u64,
    pub stage: Stage,
    pub records: u32,
    pub inserted: u64,
    pub duplicates: u64,
    pub replay_source: Option<u32>,
    pub payload_bytes: u64,
    pub appended_jsonl_bytes: u64,
    pub sessions: Option<u64>,
}
#[derive(Clone, Debug)]
pub struct FullManifest {
    seeds: u64,
    final_records: u64,
    operations: Vec<Operation>,
}
impl FullManifest {
    pub const OPERATIONS: u32 = 64;
    pub fn new(spec: WorkloadSpec, seeds: u64) -> Result<Self> {
        ensure(
            spec == WorkloadSpec::full20x256_v1(),
            "unsupported full workload schema/kind",
        )?;
        ensure(
            (16..=data::MAX_SEED_RECORDS).contains(&seeds),
            "full seed range",
        )?;
        let additions = 20u64
            .checked_mul(256)
            .and_then(|n| n.checked_add(22))
            .ok_or("full additions overflow")?;
        let final_records = seeds
            .checked_add(1)
            .and_then(|n| n.checked_add(additions))
            .ok_or("full row overflow")?;
        ensure(
            final_records <= hermes_memory::logical_migration::MAX_ROWS,
            "full final row bound",
        )?;
        let mut manifest = Self {
            seeds,
            final_records,
            operations: Vec::with_capacity(Self::OPERATIONS as usize),
        };
        for id in 0..Self::OPERATIONS {
            manifest.operations.push(manifest.build_operation(id)?);
        }
        Ok(manifest)
    }
    pub fn continuation(&self) -> Continuation<'_> {
        Continuation {
            manifest: self,
            next: 0,
        }
    }
    /// The pinned initial snapshot is separate; this stream excludes it.
    pub fn expected_seed_and_addition_records(
        &self,
    ) -> impl Iterator<Item = Result<hermes_memory::MemoryRecord>> + '_ {
        (0..self.seeds)
            .map(data::representative_record)
            .chain((0..5142).map(Self::addition_record))
    }
    pub fn expected_additions(&self) -> u64 {
        5142
    }
    pub fn final_records(&self) -> u64 {
        self.final_records
    }
    pub fn operation(&self, id: u32) -> Result<Operation> {
        self.operations
            .get(id as usize)
            .cloned()
            .ok_or_else(|| "full operation ID bound".into())
    }
    fn build_operation(&self, id: u32) -> Result<Operation> {
        ensure(id < Self::OPERATIONS, "full operation ID bound")?;
        let (stage, records, inserted, duplicates, replay_source) = match id {
            0..=1 => (Stage::Warmup, 1, 1, 0, None),
            2..=21 => (Stage::Single, 1, 1, 0, None),
            22..=41 => (Stage::Batch, 256, 256, 0, None),
            42..=61 => (Stage::Dedup, 256, 0, 256, Some(id - 20)),
            62 => (Stage::UnchangedSnapshot, 0, 0, 0, None),
            _ => (Stage::Export, 0, 0, 0, None),
        };
        let appended_jsonl_bytes = if inserted > 0 {
            data::validate_seed_batch(&self.records(id)?, 0)?
        } else {
            0
        };
        Ok(Operation {
            id,
            cli_epoch: 3 + u64::from(id),
            stage,
            records,
            inserted,
            duplicates,
            replay_source,
            payload_bytes: self.payload(id)?.len() as u64,
            appended_jsonl_bytes,
            sessions: (id == 63).then_some(18),
        })
    }
    pub fn records(&self, id: u32) -> Result<Vec<hermes_memory::MemoryRecord>> {
        ensure(id < Self::OPERATIONS, "full operation ID bound")?;
        let source = if (42..62).contains(&id) { id - 20 } else { id };
        let (first, count) = match source {
            0..=21 => (source, 1),
            22..=41 => (22 + (source - 22) * 256, 256),
            _ => return Ok(Vec::new()),
        };
        (first..first + count)
            .map(Self::addition_record)
            .collect::<Result<Vec<_>>>()
    }
    fn addition_record(ordinal: u32) -> Result<hermes_memory::MemoryRecord> {
        ensure(ordinal < 5142, "full addition ordinal bound")?;
        let text = format!("ordinary full20x256-v1 mutation {ordinal:06} ");
        let mut content = text.repeat(2048 / text.len() + 1);
        content.truncate(2048);
        let record = hermes_memory::MemoryRecord {
            id: format!("benchmark-full20x256-v1-{ordinal:06}"),
            session_id: "benchmark-client".into(),
            workspace: data::WORKSPACE.into(),
            kind: "user".into(),
            content,
            timestamp: 1_720_000_000.0 + f64::from(ordinal),
            metadata: serde_json::json!({"workload":"full20x256-v1", "ordinal":ordinal}),
        };
        // Every unique ordinal is validated by constructor batch preflight; replay
        // regenerates those same closed values without retaining record bodies.
        Ok(record)
    }
    /// Exact installed CLI stdin, not the protocol envelope or JSONL suffix.
    pub fn payload(&self, id: u32) -> Result<Vec<u8>> {
        ensure(id < Self::OPERATIONS, "full operation ID bound")?;
        match id {
            0..=61 => Ok(serde_json::to_vec(&self.records(id)?)?),
            62 => {
                let s = data::snapshot();
                let i = &s.items[0];
                Ok(serde_json::to_vec(
                    &serde_json::json!({"session_id":s.session_id,"workspace":s.workspace,"items":[{"kind":i.kind,"content":i.content,"timestamp":i.timestamp,"metadata":i.metadata}]}),
                )?)
            }
            _ => Ok(Vec::new()),
        }
    }
}
/// Pure continuation only: does not publish barriers or authenticate native evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub schema: u8,
    pub operation_id: u32,
    pub cli_epoch: u64,
    pub payload_bytes: u64,
    pub inserted: u64,
    pub duplicates: u64,
    pub sessions: Option<u64>,
}
pub struct Continuation<'a> {
    manifest: &'a FullManifest,
    next: u32,
}
impl Continuation<'_> {
    pub fn next_operation(&self) -> Result<Option<Operation>> {
        if self.complete() {
            Ok(None)
        } else {
            self.manifest.operation(self.next).map(Some)
        }
    }
    pub fn complete(&self) -> bool {
        self.next == FullManifest::OPERATIONS
    }
    pub fn acknowledge(&mut self, ack: &Ack, payload: &[u8]) -> Result<()> {
        ensure(
            !self.complete() && ack.schema == 1 && ack.operation_id == self.next,
            "full ACK schema/continuation mismatch",
        )?;
        let op = self.manifest.operation(self.next)?;
        ensure(
            ack.cli_epoch == op.cli_epoch
                && ack.payload_bytes == op.payload_bytes
                && ack.inserted == op.inserted
                && ack.duplicates == op.duplicates
                && ack.sessions == op.sessions,
            "full ACK counts/epoch mismatch",
        )?;
        ensure(
            payload.len() as u64 == op.payload_bytes
                && payload == self.manifest.payload(self.next)?,
            "full ACK exact payload mismatch",
        )?;
        self.next = self
            .next
            .checked_add(1)
            .ok_or("full continuation overflow")?;
        Ok(())
    }
}
#[cfg(test)]
#[path = "full_manifest_tests.rs"]
mod tests;
