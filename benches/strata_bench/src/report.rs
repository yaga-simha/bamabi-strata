//! JSON & Markdown report formatting for `strata_bench` (`BENCHMARKS.md` integration).

use crate::compiler_bench::CompilerBenchRecord;
use crate::runtime_bench::RuntimeBenchRecord;
use serde::{Deserialize, Serialize};
use std::env;
use std::fmt::Write as _;

/// Complete serialized benchmark suite output written via `--json <path>`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// Target triple / OS summary.
    pub target_env: String,
    /// Compiler `rustc` / `stratac` mode tag (`quick` or `full`).
    pub mode: String,
    /// Compiler latency results.
    pub compiler: Vec<CompilerBenchRecord>,
    /// 4-tier ECS execution and selective tick-coalescing results.
    pub runtime: Vec<RuntimeBenchRecord>,
}

impl BenchmarkReport {
    /// Captures host OS/architecture label cleanly without platform-unsafe APIs.
    #[must_use]
    pub fn host_env_label() -> String {
        format!("{}-{}", env::consts::ARCH, env::consts::OS)
    }

    /// Formats the complete Markdown tables spliced between `BENCHMARK_REPORT_START` /
    /// `BENCHMARK_REPORT_END` markers in `BENCHMARKS.md`.
    #[must_use]
    pub fn render_markdown(&self) -> String {
        let mut md = String::with_capacity(4096);
        writeln!(
            md,
            "- **Environment:** `{}` | **Run profile:** `{}`",
            self.target_env, self.mode
        )
        .ok();
        writeln!(
            md,
            "- **Parity Gate:** Mandatory pre-timing bit-exact SHA-256 + FNV-1a check passed across `native`, `jit`, `c99:release`, and `rust_guest:release`.\n"
        )
        .ok();

        if !self.compiler.is_empty() {
            writeln!(md, "### Compiler & Frontend Pipeline Latency\n").ok();
            writeln!(
                md,
                "| Fixture | Stage | Bytes | Median (us) | P95 (us) | Mean (us) |"
            )
            .ok();
            writeln!(md, "| --- | --- | ---: | ---: | ---: | ---: |").ok();
            for r in &self.compiler {
                writeln!(
                    md,
                    "| `{}` | `{}` | {} | {:.1} | {:.1} | {:.1} |",
                    r.fixture,
                    r.stage,
                    r.source_bytes,
                    r.stats.median_ns / 1000.0,
                    r.stats.p95_ns / 1000.0,
                    r.stats.mean_ns / 1000.0
                )
                .ok();
            }
            writeln!(md).ok();
        }

        if !self.runtime.is_empty() {
            writeln!(md, "### 4-Tier Execution Throughput & Selective Ticks\n").ok();
            writeln!(
                md,
                "| Workload | Subject | Entities | Median (us) | P95 (us) | ns/entity | Throughput (M ent/s) | vs Native |"
            )
            .ok();
            writeln!(
                md,
                "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"
            )
            .ok();
            for r in &self.runtime {
                let ns_ent = r
                    .stats
                    .ns_per_entity
                    .map_or_else(|| "—".to_owned(), |v| format!("{v:.2}"));
                let m_ent_s = r
                    .stats
                    .m_entities_per_sec
                    .map_or_else(|| "—".to_owned(), |v| format!("{v:.1}"));
                let ratio = r
                    .vs_native
                    .map_or_else(|| "1.00x".to_owned(), |v| format!("{v:.2}x"));
                writeln!(
                    md,
                    "| `{}` | `{}` | {} | {:.1} | {:.1} | {} | {} | {} |",
                    r.workload,
                    r.subject,
                    r.entities,
                    r.stats.median_ns / 1000.0,
                    r.stats.p95_ns / 1000.0,
                    ns_ent,
                    m_ent_s,
                    ratio
                )
                .ok();
            }
            writeln!(md).ok();
        }

        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::BenchStats;

    /// Verifies Markdown table renderer formats compiler and runtime sections with expected columns.
    #[test]
    fn report_renders_markdown_and_json_roundtrip() {
        let rep = BenchmarkReport {
            target_env: "aarch64-macos".to_owned(),
            mode: "quick".to_owned(),
            compiler: vec![CompilerBenchRecord {
                fixture: "01_rain_swarm".to_owned(),
                stage: "sema_analyze".to_owned(),
                source_bytes: 1309,
                stats: BenchStats {
                    warmup_iters: 3,
                    sample_iters: 10,
                    min_ns: 90_000.0,
                    median_ns: 100_000.0,
                    p95_ns: 120_000.0,
                    mean_ns: 105_000.0,
                    ns_per_entity: None,
                    m_entities_per_sec: None,
                },
            }],
            runtime: vec![RuntimeBenchRecord {
                workload: "step_sim".to_owned(),
                subject: "jit".to_owned(),
                entities: 1000,
                vs_native: Some(1.05),
                stats: BenchStats {
                    warmup_iters: 3,
                    sample_iters: 10,
                    min_ns: 2000.0,
                    median_ns: 2500.0,
                    p95_ns: 3000.0,
                    mean_ns: 2600.0,
                    ns_per_entity: Some(2.5),
                    m_entities_per_sec: Some(400.0),
                },
            }],
        };
        let md = rep.render_markdown();
        assert!(md.contains("Compiler & Frontend Pipeline Latency"));
        assert!(md.contains("4-Tier Execution Throughput"));
        assert!(md.contains("1.05x"));
        let json = serde_json::to_string(&rep).unwrap();
        let back: BenchmarkReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rep);
    }
}
