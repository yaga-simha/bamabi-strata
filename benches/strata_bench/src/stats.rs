//! Deterministic statistical summarization utilities for compiler and runtime benchmarks.

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Summary statistics recorded across timed iterations (in nanoseconds per operation).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchStats {
    /// Number of warmup iterations discarded before timing.
    pub warmup_iters: usize,
    /// Number of recorded timing samples.
    pub sample_iters: usize,
    /// Minimum observed latency (`ns/op`).
    pub min_ns: f64,
    /// Median (50th percentile) latency (`ns/op`).
    pub median_ns: f64,
    /// 95th-percentile latency (`ns/op`).
    pub p95_ns: f64,
    /// Arithmetic mean latency (`ns/op`).
    pub mean_ns: f64,
    /// Normalized latency per entity (`ns/entity`), if entity-scaled.
    pub ns_per_entity: Option<f64>,
    /// Throughput in millions of entities processed per second (`M ent/s`), if entity-scaled.
    pub m_entities_per_sec: Option<f64>,
}

/// Executes `warmup` unmeasured iterations followed by `samples` measured iterations and
/// computes summary statistics via [`summarize_samples`].
pub fn measure_ns(
    warmup: usize,
    samples: usize,
    entities: Option<usize>,
    mut body: impl FnMut(),
) -> BenchStats {
    for _ in 0..warmup {
        body();
    }
    let mut raw = Vec::with_capacity(samples.max(1));
    for _ in 0..samples.max(1) {
        let t0 = Instant::now();
        body();
        let elapsed = t0.elapsed();
        raw.push(duration_to_ns(elapsed));
    }
    summarize_samples(warmup, &raw, entities)
}

/// Executes batched iterations per timing sample so ultra-fast nanosecond loops clear timer
/// resolution cleanly.
pub fn measure_batched_ns(
    warmup_batches: usize,
    sample_batches: usize,
    iters_per_batch: usize,
    entities: Option<usize>,
    mut body: impl FnMut(),
) -> BenchStats {
    let divisor = iters_per_batch.max(1) as f64;
    for _ in 0..warmup_batches {
        for _ in 0..iters_per_batch.max(1) {
            body();
        }
    }
    let mut raw = Vec::with_capacity(sample_batches.max(1));
    for _ in 0..sample_batches.max(1) {
        let t0 = Instant::now();
        for _ in 0..iters_per_batch.max(1) {
            body();
        }
        let elapsed = t0.elapsed();
        raw.push(duration_to_ns(elapsed) / divisor);
    }
    summarize_samples(warmup_batches, &raw, entities)
}

#[inline]
fn duration_to_ns(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000_000_000.0
}

/// Computes `min`, `median`, `p95`, `mean`, and optional per-entity throughput from raw nanosecond
/// samples.
#[must_use]
pub fn summarize_samples(warmup: usize, raw: &[f64], entities: Option<usize>) -> BenchStats {
    if raw.is_empty() {
        return BenchStats {
            warmup_iters: warmup,
            sample_iters: 0,
            min_ns: 0.0,
            median_ns: 0.0,
            p95_ns: 0.0,
            mean_ns: 0.0,
            ns_per_entity: None,
            m_entities_per_sec: None,
        };
    }

    let mut sorted = raw.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let n = sorted.len();
    let min_ns = sorted[0];
    let median_ns = if n % 2 == 1 {
        sorted[n / 2]
    } else {
        0.5 * (sorted[n / 2 - 1] + sorted[n / 2])
    };
    let p95_idx = ((n - 1) * 95) / 100;
    let p95_ns = sorted[p95_idx];
    let mean_ns = sorted.iter().sum::<f64>() / (n as f64);

    let (ns_per_entity, m_entities_per_sec) = match entities {
        Some(e) if e > 0 && median_ns > 0.0 => {
            let ns_ent = median_ns / (e as f64);
            let m_ent_s = 1000.0 / ns_ent;
            (Some(ns_ent), Some(m_ent_s))
        }
        Some(e) if e > 0 => (Some(0.0), None),
        _ => (None, None),
    };

    BenchStats {
        warmup_iters: warmup,
        sample_iters: n,
        min_ns,
        median_ns,
        p95_ns,
        mean_ns,
        ns_per_entity,
        m_entities_per_sec,
    }
}

#[cfg(test)]
mod tests {
    use super::summarize_samples;

    /// Verifies median, P95, mean, and entity throughput calculations on exact sample arrays.
    #[test]
    fn summarize_samples_computes_exact_percentiles_and_throughput() {
        let samples = [100.0, 200.0, 300.0, 400.0, 500.0];
        let st = summarize_samples(2, &samples, Some(1000));
        assert_eq!(st.warmup_iters, 2);
        assert_eq!(st.sample_iters, 5);
        assert!((st.min_ns - 100.0).abs() < 1e-9);
        assert!((st.median_ns - 300.0).abs() < 1e-9);
        assert!((st.mean_ns - 300.0).abs() < 1e-9);
        assert!((st.p95_ns - 400.0).abs() < 1e-9);
        // 300 ns across 1000 entities = 0.3 ns/entity -> 3333.33 M ent/s
        assert!((st.ns_per_entity.unwrap() - 0.3).abs() < 1e-9);
        assert!((st.m_entities_per_sec.unwrap() - (1000.0 / 0.3)).abs() < 1e-5);
    }

    /// Verifies empty sample inputs degrade cleanly without NaN or panics.
    #[test]
    fn summarize_samples_handles_empty_input() {
        let st = summarize_samples(0, &[], Some(10));
        assert_eq!(st.sample_iters, 0);
        assert_eq!(st.median_ns, 0.0);
        assert_eq!(st.ns_per_entity, None);
    }
}
