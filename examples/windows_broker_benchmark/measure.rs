use crate::data::Result;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Sample {
    pub micros: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}
pub fn summary(samples: &[Sample], corpus: u64, peak: u64) -> Result<serde_json::Value> {
    if peak == 0 {
        return Err("missing/zero process peak measurement".into());
    }
    if samples.is_empty() || samples.len() > 1000 {
        return Err("requires 1..1000 bounded samples".into());
    }
    let stats = |mut values: Vec<u64>| {
        values.sort_unstable();
        serde_json::json!({"p50": values[(values.len()*50).div_ceil(100)-1],
            "p95": values[(values.len()*95).div_ceil(100)-1], "worst": values[values.len()-1]})
    };
    let latency = stats(samples.iter().map(|s| s.micros).collect());
    let reads = stats(samples.iter().map(|s| s.read_bytes).collect());
    let writes = stats(samples.iter().map(|s| s.write_bytes).collect());
    let corpus_ok = corpus >= 600 * 1024 * 1024;
    let peak_ok = peak <= 256 * 1024 * 1024;
    let io_ok = reads["p50"].as_u64().ok_or("read median")? < 6 * 1024 * 1024
        && writes["p50"].as_u64().ok_or("write median")? < 6 * 1024 * 1024;
    Ok(
        serde_json::json!({"pass": corpus_ok && peak_ok && io_ok && samples.len() >= 20,
        "corpus_bytes": corpus, "peak_private_bytes": peak, "latency_us": latency,
        "read_io_bytes": reads, "write_io_bytes": writes, "samples": samples,
        "thresholds": {"min_corpus_bytes": 600*1024*1024u64, "max_peak_private_bytes":256*1024*1024u64,
            "median_io_exclusive_bound_bytes":6*1024*1024u64,"minimum_samples":20},
        "context": "OS process IO includes FTS/checkpoint activity. No wallclock pass threshold; outliers retained. Peak limit provisional, never automatically relaxed."}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gates_fail_without_weakening_thresholds_and_keep_outliers() {
        let samples: Vec<_> = (1..=20)
            .map(|n| Sample {
                micros: if n == 20 { 1_000_000 } else { n },
                read_bytes: n * 1024,
                write_bytes: n * 2048,
            })
            .collect();
        let report = summary(&samples, 600 * 1024 * 1024, 128 * 1024 * 1024).unwrap();
        assert_eq!(report["pass"], true);
        assert_eq!(report["latency_us"]["p50"], 10);
        assert_eq!(report["latency_us"]["p95"], 19);
        assert_eq!(report["latency_us"]["worst"], 1_000_000);
        assert_eq!(
            summary(&samples, 600 * 1024 * 1024, 257 * 1024 * 1024).unwrap()["pass"],
            false
        );
        assert_eq!(
            summary(&samples, 6 * 1024 * 1024, 128 * 1024 * 1024).unwrap()["pass"],
            false
        );
        assert!(summary(&[], 600 * 1024 * 1024, 0).is_err());
        assert!(
            summary(&samples, 600 * 1024 * 1024, 0).is_err(),
            "missing process measurement must not pass"
        );
        let huge = vec![
            Sample {
                micros: 1,
                read_bytes: 600 * 1024 * 1024,
                write_bytes: 1
            };
            20
        ];
        assert_eq!(
            summary(&huge, 600 * 1024 * 1024, 128 * 1024 * 1024).unwrap()["pass"],
            false
        );
    }
}
