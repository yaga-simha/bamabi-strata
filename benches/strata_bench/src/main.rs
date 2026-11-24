#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Binary benchmark runner (`strata_bench`) measuring compiler pipeline latency and 4-tier ECS
//! execution throughput across native Bevy `0.20`, Cranelift PIC JIT, strict ISO C99, and safe
//! Rust Guest `.cdylib` mods.

pub mod compiler_bench;
pub mod report;
pub mod runtime_bench;
pub mod stats;

use report::BenchmarkReport;
use runtime_bench::ParGatePolicy;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuiteChoice {
    All,
    Compiler,
    Runtime,
}

#[derive(Debug)]
struct BenchArgs {
    quick: bool,
    enforce_par_gate: bool,
    warn_only_par_gate: bool,
    suite: SuiteChoice,
    json_path: Option<PathBuf>,
    markdown_path: Option<PathBuf>,
    help: bool,
}

fn parse_bench_args(args: &[String]) -> Result<BenchArgs, String> {
    let mut out = BenchArgs {
        quick: false,
        enforce_par_gate: false,
        warn_only_par_gate: false,
        suite: SuiteChoice::All,
        json_path: None,
        markdown_path: None,
        help: false,
    };
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => out.help = true,
            "--quick" => out.quick = true,
            "--enforce-par-gate" => out.enforce_par_gate = true,
            "--warn-only-par-gate" => out.warn_only_par_gate = true,
            "--suite" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or("--suite requires <all|compiler|runtime>")?;
                out.suite = match v.as_str() {
                    "all" => SuiteChoice::All,
                    "compiler" => SuiteChoice::Compiler,
                    "runtime" => SuiteChoice::Runtime,
                    other => return Err(format!("unknown --suite value `{other}`")),
                };
            }
            "--json" => {
                i += 1;
                let p = args.get(i).ok_or("--json requires <path>")?;
                out.json_path = Some(PathBuf::from(p));
            }
            "--markdown" => {
                i += 1;
                let p = args.get(i).ok_or("--markdown requires <path>")?;
                out.markdown_path = Some(PathBuf::from(p));
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
        i += 1;
    }
    if out.enforce_par_gate && out.warn_only_par_gate {
        return Err(
            "--enforce-par-gate and --warn-only-par-gate are mutually exclusive".to_owned(),
        );
    }
    Ok(out)
}

fn main() -> ExitCode {
    let raw: Vec<String> = env::args().skip(1).collect();
    let cfg = match parse_bench_args(&raw) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    if cfg.help {
        println!(
            "Usage: strata_bench [--quick] [--enforce-par-gate | --warn-only-par-gate] [--suite <all|compiler|runtime>] [--json <path>] [--markdown <path>]"
        );
        return ExitCode::SUCCESS;
    }

    let compiler = if matches!(cfg.suite, SuiteChoice::All | SuiteChoice::Compiler) {
        match compiler_bench::run_compiler_suite(cfg.quick) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("compiler benchmark failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        Vec::new()
    };

    let (runtime, par_gate) = if matches!(cfg.suite, SuiteChoice::All | SuiteChoice::Runtime) {
        let host_threads = std::thread::available_parallelism().map_or(1, usize::from);
        let allow_variance = env::var("STRATA_BENCH_ALLOW_HOST_VARIANCE")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        let policy = ParGatePolicy {
            quick: cfg.quick,
            enforce_par_gate: cfg.enforce_par_gate,
            warn_only_par_gate: cfg.warn_only_par_gate || allow_variance,
            host_threads,
            in_ci: env::var("CI").is_ok(),
        };
        match runtime_bench::run_runtime_suite_with_policy(policy) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("runtime benchmark failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        (Vec::new(), None)
    };

    let report = BenchmarkReport {
        target_env: BenchmarkReport::host_env_label(),
        mode: if cfg.quick {
            "quick".to_owned()
        } else {
            "full".to_owned()
        },
        compiler,
        runtime,
        par_gate,
    };

    let md = report.render_markdown();
    print!("{md}");

    if let Some(jp) = &cfg.json_path {
        if let Some(parent) = jp.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let body = serde_json::to_string_pretty(&report).unwrap_or_default();
        if let Err(e) = fs::write(jp, body) {
            eprintln!("failed writing {}: {e}", jp.display());
            return ExitCode::FAILURE;
        }
    }
    if let Some(mp) = &cfg.markdown_path {
        if let Some(parent) = mp.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Err(e) = fs::write(mp, &md) {
            eprintln!("failed writing {}: {e}", mp.display());
            return ExitCode::FAILURE;
        }
    }

    if let Some(ref gate) = report.par_gate
        && gate.enforced
        && !gate.passed
    {
        let failed: Vec<String> = gate
            .targets
            .iter()
            .filter(|t| t.required && !t.passed)
            .map(|t| format!("{}={:.3} ns/entity", t.subject, t.ns_per_entity))
            .collect();
        eprintln!(
            "@par(chunk = 1024) 100k gate failed (threshold <= {:.2} ns/entity): {}",
            gate.threshold_ns_per_entity,
            failed.join(", ")
        );
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies `strata_bench` CLI parser accepts flags and rejects invalid suites.
    #[test]
    fn bench_cli_parser_handles_flags_and_errors() {
        let cfg = parse_bench_args(&[
            "--quick".to_owned(),
            "--enforce-par-gate".to_owned(),
            "--suite".to_owned(),
            "runtime".to_owned(),
            "--json".to_owned(),
            "out.json".to_owned(),
        ])
        .unwrap();
        assert!(cfg.quick);
        assert!(cfg.enforce_par_gate);
        assert!(!cfg.warn_only_par_gate);
        assert_eq!(cfg.suite, SuiteChoice::Runtime);
        assert_eq!(cfg.json_path, Some(PathBuf::from("out.json")));
        assert!(parse_bench_args(&["--suite".to_owned(), "bad".to_owned()]).is_err());
        assert!(
            parse_bench_args(&[
                "--enforce-par-gate".to_owned(),
                "--warn-only-par-gate".to_owned()
            ])
            .is_err()
        );
    }
}
