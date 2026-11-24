//! JSON & Markdown report formatting for `strata_bench` (`BENCHMARKS.md` integration).

use crate::compiler_bench::CompilerBenchRecord;
use crate::runtime_bench::RuntimeBenchRecord;
use serde::{Deserialize, Serialize};
use std::env;
use std::fmt::Write as _;

/// Per-target threshold check result for the `100k` dense `@par(chunk = 1024)` gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParTargetGate {
    /// Subject label (`"bevy_native"`, `"jit"`, `"c99:release"`, `"rust_guest:release"`).
    pub subject: String,
    /// Whether this target is required to meet the `<= 0.35 ns/entity` threshold.
    pub required: bool,
    /// Median normalized latency (`ns/entity`).
    pub ns_per_entity: f64,
    /// Minimum observed normalized latency (`ns/entity`).
    pub min_ns_per_entity: f64,
    /// Relative jitter spread `(p95 - min) / median * 100.0`.
    pub spread_pct: f64,
    /// Ratio of median latency relative to `bevy_native` (`None` for baseline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vs_native: Option<f64>,
    /// `true` iff `ns_per_entity <= threshold_ns_per_entity`.
    pub passed: bool,
}

/// Gate evaluation summary for the `100k` dense `@par(chunk = 1024)` benchmark.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParGateReport {
    /// Maximum allowed median `ns/entity` (`0.35`).
    pub threshold_ns_per_entity: f64,
    /// Entity count used for the parallel throughput gate (`100_000`).
    pub entities: usize,
    /// Logical host threads detected via `available_parallelism`.
    pub host_threads: usize,
    /// `true` when strict threshold failure fails the benchmark exit code.
    pub enforced: bool,
    /// `true` when all required targets (`bevy_native`, `c99:release`, `rust_guest:release`) pass.
    pub passed: bool,
    /// Per-target gate evaluations.
    pub targets: Vec<ParTargetGate>,
}

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
    /// Optional `100k` dense `@par(chunk = 1024)` threshold gate summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub par_gate: Option<ParGateReport>,
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

        if let Some(ref gate) = self.par_gate {
            let status = if gate.passed {
                "PASS"
            } else if gate.enforced {
                "FAIL"
            } else {
                "HOST_VARIANCE_WARN"
            };
            let parts: Vec<String> = gate
                .targets
                .iter()
                .map(|t| {
                    let ratio_s = t
                        .vs_native
                        .map_or_else(String::new, |r| format!(", vs_native {r:.2}x"));
                    format!(
                        "`{}`={:.3} ns/ent (min {:.3}, spread {:.1}%{ratio_s})",
                        t.subject, t.ns_per_entity, t.min_ns_per_entity, t.spread_pct
                    )
                })
                .collect();
            writeln!(
                md,
                "- **@par(chunk = 1024) 100k Gate (<= {:.2} ns/entity, {} threads, enforced={}):** `{status}` — {}\n",
                gate.threshold_ns_per_entity,
                gate.host_threads,
                gate.enforced,
                parts.join(", ")
            )
            .ok();
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
            par_gate: None,
        };
        let md = rep.render_markdown();
        assert!(md.contains("Compiler & Frontend Pipeline Latency"));
        assert!(md.contains("4-Tier Execution Throughput"));
        assert!(md.contains("1.05x"));
        let json = serde_json::to_string(&rep).unwrap();
        let back: BenchmarkReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rep);
    }

    /// Verifies `ParGateReport` Markdown rendering for `PASS`, `HOST_VARIANCE_WARN`, and `FAIL`.
    #[test]
    fn report_renders_par_gate_statuses_and_vs_native() {
        let make_rep = |enforced: bool, passed: bool, ns_ent: f64| BenchmarkReport {
            target_env: "aarch64-macos".to_owned(),
            mode: "full".to_owned(),
            compiler: Vec::new(),
            runtime: Vec::new(),
            par_gate: Some(ParGateReport {
                threshold_ns_per_entity: 0.35,
                entities: 100_000,
                host_threads: 14,
                enforced,
                passed,
                targets: vec![
                    ParTargetGate {
                        subject: "bevy_native".to_owned(),
                        required: true,
                        ns_per_entity: ns_ent,
                        min_ns_per_entity: ns_ent * 0.9,
                        spread_pct: 12.5,
                        vs_native: None,
                        passed,
                    },
                    ParTargetGate {
                        subject: "c99:release".to_owned(),
                        required: true,
                        ns_per_entity: ns_ent * 1.01,
                        min_ns_per_entity: ns_ent * 0.91,
                        spread_pct: 10.0,
                        vs_native: Some(1.01),
                        passed,
                    },
                ],
            }),
        };

        let warn_md = make_rep(false, false, 0.59).render_markdown();
        assert!(warn_md.contains("HOST_VARIANCE_WARN"));
        assert!(warn_md.contains("`bevy_native`=0.590 ns/ent (min 0.531, spread 12.5%)"));
        assert!(
            warn_md
                .contains("`c99:release`=0.596 ns/ent (min 0.537, spread 10.0%, vs_native 1.01x)")
        );

        let pass_md = make_rep(false, true, 0.30).render_markdown();
        assert!(pass_md.contains("`PASS`"));

        let fail_md = make_rep(true, false, 0.59).render_markdown();
        assert!(fail_md.contains("`FAIL`"));
    }
}
