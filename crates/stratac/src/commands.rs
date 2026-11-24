//! Command implementations for `stratac` (`check`, `fmt`, `layout`, `explain-par`, `test`,
//! `build`, `watch`, `onboard`, `graph`).

#[path = "graph_cmd.rs"]
pub mod graph_cmd;

use crate::cli::{BuildTarget, Cli, Commands, GraphAction, OnboardTarget, OutputFormat};
use crate::exit_codes::{
    EXIT_COMPILE_ERROR, EXIT_OK, EXIT_PARITY_OR_ASSERT_FAILED, EXIT_SIM_TEST_FAILED,
};
use bamabi_manifest::ModTomlManifest;
use bamabi_sys::{
    ABI_VERSION, BAM_SCHEDULE_SET_FLAG_AFTER_WEAK, BAM_SCHEDULE_SET_FLAG_BEFORE_WEAK,
    BAM_SCHEDULE_SET_FLAG_PARALLEL, BAM_SCHEDULE_SET_FLAG_SEQUENCE,
    BAM_SCHEDULE_SET_FLAG_SEQUENCE_WEAK, ScheduleId,
};
use bamabi_trust::{
    Algorithm, BamPackBuilder, DEFAULT_BAMPACK_NAMESPACE, DEFAULT_SIGNATURE_NAMESPACE,
    ModTrustPolicy, PrivateKey, default_signature_path_for, generate_ed25519_keypair,
    sign_mod_bytes_with_key,
};
use notify_debouncer_full::notify::event::{
    AccessKind, AccessMode, CreateKind, ModifyKind, RenameMode,
};
use notify_debouncer_full::notify::{EventKind, RecursiveMode};
use notify_debouncer_full::{DebounceEventResult, DebouncedEvent, new_debouncer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use strata_codegen::{
    BevyNativeOptions, RustGuestOptions, emit_bevy_native, emit_c99, module_stem,
};
use strata_jit::{JitCompileOptions, JitOptLevel, compile_module_to_dylib};
use strata_mir::{MirFnKind, MirModule, lower_to_mir, verify_mir};
use strata_sema::access::ConcurrencyGraph;
use strata_sema::db::Setter;
use strata_sema::diagnostics::{Diagnostic, Severity, Span};
use strata_sema::hir::{HirSchedule, HirScheduleGroup};
use strata_sema::layout::SolvedLayout;
use strata_sema::{SemaDb, SourceFile, analyze_source};
use strata_syntax::ast::AstNode as _;
use strata_syntax::fmt::format_source;
use strata_syntax::{NodeOrToken, SyntaxKind, SyntaxNode, SyntaxToken, ast};

/// JSON/text report for `stratac check`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckReport {
    /// Source file path.
    pub file: String,
    /// `true` iff no Error diagnostics exist.
    pub ok: bool,
    /// Canonical module name.
    pub module_path: String,
    /// Total errors.
    pub error_count: usize,
    /// Total warnings.
    pub warning_count: usize,
    /// Full diagnostic list.
    pub diagnostics: Vec<Diagnostic>,
}

/// JSON/text report for `stratac layout`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutReport {
    /// Source file path.
    pub file: String,
    /// Canonical module name.
    pub module_path: String,
    /// Solved ABI-Pod layouts.
    pub layouts: Vec<SolvedLayout>,
}

/// JSON/text report for `stratac explain-par`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainParReport {
    /// Source file path.
    pub file: String,
    /// Canonical module name.
    pub module_path: String,
    /// Pairwise Theorem 0.1 concurrency graph & conflicts.
    pub concurrency_graph: ConcurrencyGraph,
}

/// Single `sim_test` case outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimTestCaseResult {
    /// `sim_test` identifier.
    pub name: String,
    /// True iff all assertions passed.
    pub passed: bool,
    /// Number of Bevy `FixedUpdate` frames simulated.
    pub frames_simulated: u64,
    /// Peak command buffer bytes recorded.
    pub peak_cmd_bytes: usize,
    /// Steady-state heap allocations inside `FixedUpdate`.
    pub steady_state_allocs: usize,
    /// Outcome detail (`"ok"` or assertion failure message).
    pub detail: String,
}

/// JSON/text report for `stratac test`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimTestSuiteReport {
    /// Source file path.
    pub file: String,
    /// Canonical module name.
    pub module_path: String,
    /// `true` iff all tests passed.
    pub all_passed: bool,
    /// Per-test outcomes.
    pub tests: Vec<SimTestCaseResult>,
}

/// JSON/text report for `stratac build`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildReport {
    /// Source file path.
    pub file: String,
    /// Module stem.
    pub module_stem: String,
    /// Compilation target (`jit`, `c99`, `rust-guest`).
    pub target: String,
    /// Output directory.
    pub out_dir: String,
    /// Compiled native shared library path (if produced).
    pub binary_path: Option<String>,
    /// Validated `mod.toml` path.
    pub mod_toml_path: String,
    /// Optional `.sig` sidecar path.
    pub signature_path: Option<String>,
    /// Optional signed `.bampack` path.
    pub bampack_path: Option<String>,
    /// OpenSSH Ed25519 signer fingerprint (when signed).
    pub signer_fingerprint: Option<String>,
    /// Total build duration in milliseconds.
    pub elapsed_ms: f64,
}

/// Execution mode of a schedule set inside [`ScheduleDeltaArtifact`], mirroring
/// `bamabi_host_sys::schedule::ScheduleSetMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduleDeltaMode {
    /// Unordered parallel container (`BAM_SCHEDULE_SET_FLAG_PARALLEL`).
    Parallel,
    /// Strict sequential chain (`BAM_SCHEDULE_SET_FLAG_SEQUENCE`).
    Sequence,
    /// Weak sequential chain (`BAM_SCHEDULE_SET_FLAG_SEQUENCE_WEAK`).
    SequenceWeak,
}

/// Decoupled schedule set entry inside [`ScheduleDeltaArtifact`] targeting `ModScheduleSetRewirePass`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleDeltaSet {
    /// Bare set name within the module (e.g. `"CombatSeq"` or `"__group_1"`).
    pub set_name: String,
    /// Canonical scoped set name (`"{mod_name}::{set_name}"`).
    pub canonical_name: String,
    /// Numeric `bamabi_sys::ScheduleId` raw `u32`.
    pub schedule_id: u32,
    /// Human-readable schedule label (`"FixedUpdate"`, `"Update"`, etc.).
    pub schedule_label: String,
    /// Intra-set ordering mode.
    pub mode: ScheduleDeltaMode,
    /// `BAM_SCHEDULE_SET_FLAG_*` bitflags.
    pub flags: u32,
    /// Sets ordered after this set (`before` / `before_weak`).
    pub before_sets: Vec<String>,
    /// Sets ordered before this set (`after` / `after_weak`).
    pub after_sets: Vec<String>,
    /// When `true`, `before_sets` edges use weak ordering.
    pub before_weak: bool,
    /// When `true`, `after_sets` edges use weak ordering.
    pub after_weak: bool,
    /// Ordered direct leaf systems mounted in this set.
    pub mounted_systems: Vec<String>,
}

/// Per-system schedule placement delta inside [`ScheduleDeltaArtifact`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleDeltaSystem {
    /// Bare system name.
    pub name: String,
    /// Numeric `bamabi_sys::ScheduleId` raw `u32`.
    pub schedule_id: u32,
    /// Human-readable schedule label (`"FixedUpdate"`, `"Update"`, etc.).
    pub schedule_label: String,
    /// Monotonic declaration order within the module schedules.
    pub sched_order: usize,
    /// All enclosing ancestor set names (outer to inner).
    pub in_sets: Vec<String>,
    /// Immediate parent set name(s) the system mounts into.
    pub mount_sets: Vec<String>,
    /// Systems/targets that must run before this system (`after`).
    pub after: Vec<String>,
    /// Systems/targets weakly ordered before this system (`after_weak`).
    pub after_weak: Vec<String>,
    /// Systems/targets that must run after this system (`before`).
    pub before: Vec<String>,
    /// Systems/targets weakly ordered after this system (`before_weak`).
    pub before_weak: Vec<String>,
}

/// Schedule-only incremental hot-rewire artifact targeting `ModScheduleSetRewirePass` without
/// recompiling native machine code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleDeltaArtifact {
    /// Artifact schema version (`1`).
    pub schema_version: u32,
    /// Host schedule pass targeted by this delta (`"ModScheduleSetRewirePass"`).
    pub target_pass: String,
    /// Frozen `bamabi_sys::ABI_VERSION`.
    pub abi_version: u32,
    /// Canonical module path (`a::b`).
    pub module_path: String,
    /// Module stem (`mod.toml` `[mod].id`).
    pub mod_name: String,
    /// Hex SHA-256 digest of the parsed schedule CST topology.
    pub schedule_signature: String,
    /// Sorted deduplicated `bamabi_sys::ScheduleId` values touched by this delta.
    pub touched_schedules: Vec<u32>,
    /// `true` if set membership changed relative to the previously loaded `.dylib` and requires
    /// host `ModScheduleSetRegistry` set registration in addition to rewire edges/modes.
    pub requires_set_registration: bool,
    /// Full updated set definitions.
    pub sets: Vec<ScheduleDeltaSet>,
    /// Full updated system topology entries.
    pub systems: Vec<ScheduleDeltaSystem>,
}

/// JSON/text report for `stratac watch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchReport {
    /// Source file path.
    pub file: String,
    /// Incremental Salsa layout recomputation required (`false` on body-only edits).
    pub salsa_layout_recomputed: bool,
    /// Schedule-only delta flag (`true` when JIT machine-code emission was skipped).
    pub schedule_delta_only: bool,
    /// Rebuilt (or preserved) shared library path.
    pub dylib_path: String,
    /// Path to `{stem}.schedule_delta.json` emitted on schedule-only delta cycles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_delta_path: Option<String>,
    /// Optional `.sig` sidecar path when signing is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_path: Option<String>,
    /// OpenSSH Ed25519 signer fingerprint when signing is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_fingerprint: Option<String>,
    /// Incremental emit + link (or schedule-delta) latency in milliseconds.
    pub rebuild_ms: f64,
}

/// JSON/text report for `stratac onboard`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardReport {
    /// Source file path.
    pub file: String,
    /// Destination directory.
    pub out_dir: String,
    /// Generated Cargo crate name.
    pub crate_name: String,
    /// Generated file list.
    pub files: Vec<String>,
    /// `true` if `cargo check` passed (when requested).
    pub cargo_checked: bool,
}

/// Executes a parsed [`Cli`] returning `(exit_code, formatted_stdout)`.
pub fn execute_cli(cli: Cli) -> (i32, String) {
    match cli.command {
        Commands::Check { file, format } => cmd_check(&file, format),
        Commands::Fmt { file, check } => cmd_fmt(&file, check),
        Commands::Layout { file, format } => cmd_layout(&file, format),
        Commands::ExplainPar { file, format } => cmd_explain_par(&file, format),
        Commands::Test { file, format } => cmd_test(&file, format),
        Commands::Build {
            file,
            release,
            target,
            out,
            bampack,
            sign,
            key,
            ephemeral_key,
            format,
        } => cmd_build_with_key(
            &file,
            release,
            target,
            out.as_deref(),
            bampack,
            sign,
            key.as_deref(),
            ephemeral_key,
            format,
        ),
        Commands::Watch {
            file,
            sign,
            key,
            ephemeral_key,
            once,
            format,
        } => cmd_watch_with_key(&file, sign, key.as_deref(), ephemeral_key, once, format),
        Commands::Onboard {
            file,
            target,
            out,
            static_console,
            check,
            format,
        } => cmd_onboard(&file, target, &out, static_console, check, format),
        Commands::Graph { action } => match action {
            GraphAction::Export { file, format } => graph_cmd::cmd_graph_export(&file, format),
            GraphAction::Apply {
                file,
                patch,
                format,
            } => graph_cmd::cmd_graph_apply(&file, &patch, format),
        },
    }
}

fn read_source(file: &Path) -> Result<String, (i32, String)> {
    fs::read_to_string(file).map_err(|e| {
        (
            EXIT_COMPILE_ERROR,
            format!("error reading `{}`: {e}", file.display()),
        )
    })
}

/// Executes `stratac check`.
pub fn cmd_check(file: &Path, format: OutputFormat) -> (i32, String) {
    let src = match read_source(file) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let analyzed = analyze_source(file.display().to_string(), &src);
    let mut diagnostics = analyzed.diagnostics.clone();
    if !diagnostics.iter().any(|d| d.severity == Severity::Error) {
        let mir = lower_to_mir(&analyzed);
        if let Err(errs) = verify_mir(&mir) {
            let file_str = file.display().to_string();
            for err in errs {
                diagnostics.push(Diagnostic::error(
                    "E0900_MIR_VERIFICATION_FAILED",
                    Span::from_bytes(file_str.clone(), &src, 0, 0),
                    err.to_string(),
                    None,
                ));
            }
        }
    }
    let error_count = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .count();
    let warning_count = diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Warning)
        .count();
    let ok = error_count == 0;
    let code = if ok { EXIT_OK } else { EXIT_COMPILE_ERROR };

    let report = CheckReport {
        file: file.display().to_string(),
        ok,
        module_path: analyzed.module_path,
        error_count,
        warning_count,
        diagnostics,
    };

    let text = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&report).unwrap_or_default(),
        OutputFormat::Text => {
            if ok {
                format!(
                    "OK: {} (0 errors, {} warnings)",
                    report.module_path, report.warning_count
                )
            } else {
                let mut lines = vec![format!(
                    "FAIL: {} ({} errors, {} warnings)",
                    report.module_path, report.error_count, report.warning_count
                )];
                for d in &report.diagnostics {
                    lines.push(format!("  [{}] {}", d.code, d.message));
                }
                lines.join("\n")
            }
        }
    };
    (code, text)
}

/// Executes `stratac fmt`.
pub fn cmd_fmt(file: &Path, check_only: bool) -> (i32, String) {
    let src = match read_source(file) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let formatted = match format_source(&src) {
        Ok(f) => f,
        Err(errs) => {
            return (
                EXIT_COMPILE_ERROR,
                format!(
                    "parse errors preventing formatting in `{}`: {errs:?}",
                    file.display()
                ),
            );
        }
    };
    if check_only {
        if formatted == src {
            (EXIT_OK, format!("formatted: {}", file.display()))
        } else {
            (
                EXIT_PARITY_OR_ASSERT_FAILED,
                format!(
                    "diff detected in `{}` (run without --check to format)",
                    file.display()
                ),
            )
        }
    } else if let Err(e) = fs::write(file, &formatted) {
        (
            EXIT_COMPILE_ERROR,
            format!("failed writing `{}`: {e}", file.display()),
        )
    } else {
        (EXIT_OK, format!("formatted `{}`", file.display()))
    }
}

/// Executes `stratac layout`.
pub fn cmd_layout(file: &Path, format: OutputFormat) -> (i32, String) {
    let src = match read_source(file) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let analyzed = analyze_source(file.display().to_string(), &src);
    if !analyzed.ok() {
        return (
            EXIT_COMPILE_ERROR,
            serde_json::to_string_pretty(&analyzed.diagnostics).unwrap_or_default(),
        );
    }
    let mir = lower_to_mir(&analyzed);
    let report = LayoutReport {
        file: file.display().to_string(),
        module_path: mir.module_path,
        layouts: mir.layouts,
    };
    let out = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&report).unwrap_or_default(),
        OutputFormat::Text => {
            let mut lines = vec![format!("Layouts for {}:", report.module_path)];
            for l in &report.layouts {
                lines.push(format!(
                    "  {} ({:?}): size={} align={} pad={}B uuid={} fp=0x{:016X}",
                    l.canonical_name,
                    l.item_kind,
                    l.size,
                    l.align,
                    l.explicit_pad_bytes,
                    l.uuid_hex,
                    l.schema_fingerprint
                ));
            }
            lines.join("\n")
        }
    };
    (EXIT_OK, out)
}

/// Executes `stratac explain-par`.
pub fn cmd_explain_par(file: &Path, format: OutputFormat) -> (i32, String) {
    let src = match read_source(file) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let analyzed = analyze_source(file.display().to_string(), &src);
    if !analyzed.ok() {
        return (
            EXIT_COMPILE_ERROR,
            serde_json::to_string_pretty(&analyzed.diagnostics).unwrap_or_default(),
        );
    }
    let report = ExplainParReport {
        file: file.display().to_string(),
        module_path: analyzed.module_path,
        concurrency_graph: analyzed.concurrency_graph,
    };
    let out = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&report).unwrap_or_default(),
        OutputFormat::Text => {
            let mut lines = vec![format!(
                "Theorem 0.1 Concurrency for {}:",
                report.module_path
            )];
            lines.push(format!(
                "  Analyzed systems: {}",
                report.concurrency_graph.systems.len()
            ));
            for c in &report.concurrency_graph.conflicts {
                lines.push(format!(
                    "  Conflict: {} <-> {}: {}",
                    c.system_a,
                    c.system_b,
                    c.reasons.join("; ")
                ));
            }
            lines.join("\n")
        }
    };
    (EXIT_OK, out)
}

/// Executes `stratac test`.
pub fn cmd_test(file: &Path, format: OutputFormat) -> (i32, String) {
    let src = match read_source(file) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let analyzed = analyze_source(file.display().to_string(), &src);
    if !analyzed.ok() {
        return (
            EXIT_COMPILE_ERROR,
            serde_json::to_string_pretty(&analyzed.diagnostics).unwrap_or_default(),
        );
    }
    let mir = lower_to_mir(&analyzed);
    let stem = module_stem(&mir.module_path);

    #[cfg(feature = "sim-runner")]
    let tests = {
        let mut all = crate::sim_runner::run_headless_sim_tests(&mir, &stem);
        all.extend(crate::net_sim_runner::run_headless_net_sim_tests(
            &mir, &stem,
        ));
        all
    };
    #[cfg(not(feature = "sim-runner"))]
    let tests: Vec<SimTestCaseResult> = {
        let _ = stem;
        mir.sim_tests
            .iter()
            .map(|t| &t.name)
            .chain(mir.net_sim_tests.iter().map(|t| &t.name))
            .map(|name| SimTestCaseResult {
                name: name.clone(),
                passed: false,
                frames_simulated: 0,
                peak_cmd_bytes: 0,
                steady_state_allocs: 0,
                detail: "stratac built without `sim-runner` feature".to_owned(),
            })
            .collect()
    };

    let all_passed = tests.iter().all(|t| t.passed);
    let code = if all_passed {
        EXIT_OK
    } else {
        EXIT_SIM_TEST_FAILED
    };
    let report = SimTestSuiteReport {
        file: file.display().to_string(),
        module_path: mir.module_path,
        all_passed,
        tests,
    };
    let out = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&report).unwrap_or_default(),
        OutputFormat::Text => {
            let mut lines = vec![format!(
                "sim_test {}: {}",
                report.module_path,
                if all_passed { "PASS" } else { "FAIL" }
            )];
            for t in &report.tests {
                lines.push(format!(
                    "  [{}] {} ({} frames, peak_cmd={}B, steady_allocs={}): {}",
                    if t.passed { "PASS" } else { "FAIL" },
                    t.name,
                    t.frames_simulated,
                    t.peak_cmd_bytes,
                    t.steady_state_allocs,
                    t.detail
                ));
            }
            lines.join("\n")
        }
    };
    (code, out)
}

fn resolve_signing_key(
    key_path: Option<&Path>,
    ephemeral_key: bool,
    ephemeral_comment: &str,
) -> Result<PrivateKey, (i32, String)> {
    if key_path.is_some() && ephemeral_key {
        return Err((
            EXIT_COMPILE_ERROR,
            "cannot specify both `--key <path>` and `--ephemeral-key`".to_owned(),
        ));
    }
    if let Some(path) = key_path {
        let key = PrivateKey::read_openssh_file(path).map_err(|e| {
            (
                EXIT_COMPILE_ERROR,
                format!("failed reading signing key `{}`: {e}", path.display()),
            )
        })?;
        if key.is_encrypted() {
            return Err((
                EXIT_COMPILE_ERROR,
                format!(
                    "encrypted OpenSSH signing key `{}` is unsupported without passphrase prompt",
                    path.display()
                ),
            ));
        }
        if key.algorithm() != Algorithm::Ed25519 {
            return Err((
                EXIT_COMPILE_ERROR,
                format!(
                    "signing key `{}` must use Ed25519 (found {:?})",
                    path.display(),
                    key.algorithm()
                ),
            ));
        }
        Ok(key)
    } else if ephemeral_key {
        generate_ed25519_keypair(Some(ephemeral_comment))
            .map_err(|e| (EXIT_COMPILE_ERROR, format!("keygen failed: {e}")))
    } else {
        Err((
            EXIT_COMPILE_ERROR,
            "signing/packaging requires either `--key <path>` or `--ephemeral-key`".to_owned(),
        ))
    }
}

/// Executes `stratac build` (compatibility wrapper without explicit key arguments).
pub fn cmd_build(
    file: &Path,
    release: bool,
    target: BuildTarget,
    out_dir: Option<&Path>,
    bampack: bool,
    sign: bool,
    format: OutputFormat,
) -> (i32, String) {
    cmd_build_with_key(
        file, release, target, out_dir, bampack, sign, None, false, format,
    )
}

/// Executes `stratac build` with explicit OpenSSH `--key` or `--ephemeral-key` selection.
#[allow(clippy::too_many_arguments)]
pub fn cmd_build_with_key(
    file: &Path,
    release: bool,
    target: BuildTarget,
    out_dir: Option<&Path>,
    bampack: bool,
    sign: bool,
    key_path: Option<&Path>,
    ephemeral_key: bool,
    format: OutputFormat,
) -> (i32, String) {
    let t0 = Instant::now();
    if key_path.is_some() && ephemeral_key {
        return (
            EXIT_COMPILE_ERROR,
            "cannot specify both `--key <path>` and `--ephemeral-key`".to_owned(),
        );
    }
    if !(bampack || sign) && (key_path.is_some() || ephemeral_key) {
        return (
            EXIT_COMPILE_ERROR,
            "cannot specify `--key` or `--ephemeral-key` without `--sign` or `--bampack`"
                .to_owned(),
        );
    }
    let resolved_key = if bampack || sign {
        match resolve_signing_key(key_path, ephemeral_key, "stratac-ephemeral") {
            Ok(k) => Some(k),
            Err(e) => return e,
        }
    } else {
        None
    };

    let src = match read_source(file) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let analyzed = analyze_source(file.display().to_string(), &src);
    if !analyzed.ok() {
        return (
            EXIT_COMPILE_ERROR,
            serde_json::to_string_pretty(&analyzed.diagnostics).unwrap_or_default(),
        );
    }
    let mir = lower_to_mir(&analyzed);
    if let Err(errs) = verify_mir(&mir) {
        let msg = errs
            .into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        return (
            EXIT_COMPILE_ERROR,
            format!("MIR verification failed:\n{msg}"),
        );
    }
    let stem = module_stem(&mir.module_path);

    let default_out = file
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("target_strata_{stem}"));
    let out = out_dir.unwrap_or(&default_out);
    if let Err(e) = fs::create_dir_all(out) {
        return (EXIT_COMPILE_ERROR, format!("mkdir error: {e}"));
    }

    let (prefix, ext) = strata_jit::host_dylib_prefix_ext();
    let bin_filename = format!("{prefix}{stem}.{ext}");
    let bin_path = out.join(&bin_filename);
    let lang_tag = match target {
        BuildTarget::C99 => "c99",
        BuildTarget::RustGuest => "rust",
        BuildTarget::Jit => "jit",
    };

    match target {
        BuildTarget::Jit => {
            let opt = if release {
                JitOptLevel::Speed
            } else {
                JitOptLevel::FastCompile
            };
            let res = compile_module_to_dylib(
                &mir,
                &JitCompileOptions {
                    out_dir: out.to_path_buf(),
                    module_stem: stem.clone(),
                    opt_level: opt,
                },
            );
            if let Err(e) = res {
                return (EXIT_COMPILE_ERROR, format!("JIT build failed: {e}"));
            }
        }
        BuildTarget::C99 => {
            let art = match emit_c99(&mir) {
                Ok(a) => a,
                Err(e) => return (EXIT_COMPILE_ERROR, format!("C99 emit failed: {e}")),
            };
            let mut c_file = PathBuf::new();
            for f in &art.files {
                let p = out.join(&f.path);
                if let Err(e) = fs::write(&p, &f.content) {
                    return (EXIT_COMPILE_ERROR, format!("write failed: {e}"));
                }
                if f.path.ends_with(".c") {
                    c_file = p;
                }
            }
            let cc = find_c_compiler();
            let mut cmd = Command::new(cc);
            cmd.args([
                "-std=c99",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-shared",
            ]);
            if cc != "cl" && !cc.ends_with("cl.exe") {
                cmd.arg("-ffp-contract=off");
            }
            if release {
                cmd.arg("-O2");
            }
            if !cfg!(target_os = "windows") {
                cmd.arg("-fPIC");
            }
            cmd.arg("-I").arg(out).arg(&c_file).arg("-o").arg(&bin_path);
            if !cfg!(target_os = "windows") {
                cmd.arg("-lm");
            }
            let output = match cmd.output() {
                Ok(o) => o,
                Err(e) => return (EXIT_COMPILE_ERROR, format!("failed running `{cc}`: {e}")),
            };
            if !output.status.success() {
                return (
                    EXIT_COMPILE_ERROR,
                    format!(
                        "C99 compile failed:\n{}",
                        String::from_utf8_lossy(&output.stderr)
                    ),
                );
            }
        }
        BuildTarget::RustGuest => {
            let art = match strata_codegen::emit_rust_guest_with(
                &mir,
                &RustGuestOptions {
                    crate_name: stem.clone(),
                },
            ) {
                Ok(a) => a,
                Err(e) => return (EXIT_COMPILE_ERROR, format!("RustGuest emit failed: {e}")),
            };
            let crate_dir = out.join("rust_guest_crate");
            for f in &art.files {
                let p = crate_dir.join(&f.path);
                if let Some(parent) = p.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if let Err(e) = fs::write(&p, &f.content) {
                    return (EXIT_COMPILE_ERROR, format!("write failed: {e}"));
                }
            }
            if let Err(e) = try_write_local_patch_config_with_ws(&workspace_root(), &crate_dir) {
                return (EXIT_COMPILE_ERROR, e);
            }
            let mut cmd = sanitized_cargo();
            cmd.current_dir(&crate_dir)
                .arg("build")
                .arg("--manifest-path")
                .arg(crate_dir.join("Cargo.toml"))
                .arg("--target-dir")
                .arg(shared_temp_target_dir());
            if release {
                cmd.arg("--release");
            }
            let output = match cmd.output() {
                Ok(o) => o,
                Err(e) => return (EXIT_COMPILE_ERROR, format!("cargo failed: {e}")),
            };
            if !output.status.success() {
                return (
                    EXIT_COMPILE_ERROR,
                    format!(
                        "RustGuest cargo build failed:\n{}",
                        String::from_utf8_lossy(&output.stderr)
                    ),
                );
            }
            let profile = if release { "release" } else { "debug" };
            let built = shared_temp_target_dir().join(profile).join(&bin_filename);
            if let Err(e) = fs::copy(&built, &bin_path) {
                return (
                    EXIT_COMPILE_ERROR,
                    format!(
                        "failed copying `{}` -> `{}`: {e}",
                        built.display(),
                        bin_path.display()
                    ),
                );
            }
        }
    }

    // Emit and validate `mod.toml` via `bamabi_manifest`.
    let mod_version = analyzed
        .version
        .as_ref()
        .map(|v| format!("{}.{}.{}", v.major, v.minor, v.patch))
        .unwrap_or_else(|| "0.3.0".to_owned());
    let mod_toml_path = out.join("mod.toml");
    let mod_toml_content = format!(
        "[mod]\n\
         id = \"{stem}\"\n\
         version = \"{mod_version}\"\n\
         abi_version = \"0.3.0\"\n\
         entry = \"{bin_filename}\"\n\
         language = \"{lang_tag}\"\n"
    );
    if let Err(e) = fs::write(&mod_toml_path, &mod_toml_content) {
        return (EXIT_COMPILE_ERROR, format!("write mod.toml failed: {e}"));
    }
    if let Err(e) = ModTomlManifest::from_file(&mod_toml_path) {
        return (
            EXIT_PARITY_OR_ASSERT_FAILED,
            format!("generated mod.toml validation failed: {e}"),
        );
    }

    let mut signature_path = None;
    let mut bampack_path = None;
    let mut signer_fingerprint = None;

    if let Some(key) = resolved_key {
        let pub_openssh = match key.public_key().to_openssh() {
            Ok(s) => s,
            Err(e) => return (EXIT_COMPILE_ERROR, format!("pubkey format failed: {e}")),
        };
        signer_fingerprint = Some(
            key.public_key()
                .fingerprint(bamabi_trust::HashAlg::Sha256)
                .to_string(),
        );
        let bin_bytes = match fs::read(&bin_path) {
            Ok(b) => b,
            Err(e) => return (EXIT_COMPILE_ERROR, format!("read built binary failed: {e}")),
        };
        if sign {
            match sign_mod_bytes_with_key(&key, DEFAULT_SIGNATURE_NAMESPACE, &bin_bytes) {
                Ok(pem) => {
                    let sig_p = default_signature_path_for(&bin_path);
                    if let Err(e) = fs::write(&sig_p, pem) {
                        return (EXIT_COMPILE_ERROR, format!("write .sig failed: {e}"));
                    }
                    signature_path = Some(sig_p.display().to_string());
                }
                Err(e) => return (EXIT_COMPILE_ERROR, format!("sign failed: {e}")),
            }
        }
        if bampack {
            let archive_res = BamPackBuilder::new()
                .add_entry("mod.toml", mod_toml_content.as_bytes())
                .and_then(|b| b.add_entry(bin_filename.clone(), bin_bytes))
                .and_then(|b| b.build_signed_with_key(&key, DEFAULT_BAMPACK_NAMESPACE));
            let archive_bytes = match archive_res {
                Ok(bytes) => bytes,
                Err(e) => return (EXIT_COMPILE_ERROR, format!("bampack failed: {e}")),
            };
            // Verify archive self-consistency using ModTrustPolicy before succeeding.
            let policy = match ModTrustPolicy::from_public_key_openssh(&pub_openssh)
                .and_then(|p| p.with_namespace(DEFAULT_BAMPACK_NAMESPACE))
            {
                Ok(p) => p,
                Err(e) => return (EXIT_COMPILE_ERROR, format!("trust policy failed: {e}")),
            };
            if let Err(e) = policy.verify_bampack_bytes(&archive_bytes) {
                return (
                    EXIT_PARITY_OR_ASSERT_FAILED,
                    format!("bampack verification failed: {e}"),
                );
            }
            let bp = out.join(format!("{stem}.bampack"));
            if let Err(e) = fs::write(&bp, &archive_bytes) {
                return (EXIT_COMPILE_ERROR, format!("write .bampack failed: {e}"));
            }
            bampack_path = Some(bp.display().to_string());
        }
    }

    let report = BuildReport {
        file: file.display().to_string(),
        module_stem: stem,
        target: lang_tag.to_owned(),
        out_dir: out.display().to_string(),
        binary_path: Some(bin_path.display().to_string()),
        mod_toml_path: mod_toml_path.display().to_string(),
        signature_path,
        bampack_path,
        signer_fingerprint,
        elapsed_ms: t0.elapsed().as_secs_f64() * 1000.0,
    };

    let out_str = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&report).unwrap_or_default(),
        OutputFormat::Text => format!(
            "Built `{}` ({}) -> {} ({:.2} ms)",
            report.module_stem,
            report.target,
            report.binary_path.as_deref().unwrap_or(""),
            report.elapsed_ms
        ),
    };
    (EXIT_OK, out_str)
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn collect_layouts_map(db: &SemaDb, sfile: SourceFile) -> BTreeMap<String, SolvedLayout> {
    db.resolve_layouts_arc(sfile)
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn schedule_id_for_label(label: &str) -> ScheduleId {
    match label {
        "Startup" => ScheduleId::STARTUP,
        "PreUpdate" => ScheduleId::PRE_UPDATE,
        "PostUpdate" => ScheduleId::POST_UPDATE,
        "FixedUpdate" => ScheduleId::FIXED_UPDATE,
        "Last" => ScheduleId::LAST,
        _ => ScheduleId::UPDATE,
    }
}

fn bare_schedule_target(name: &str) -> &str {
    if name.starts_with("host::") {
        name
    } else {
        name.rsplit("::").next().unwrap_or(name)
    }
}

fn collect_mir_schedule_sets_and_systems(
    mir: &MirModule,
) -> (HashSet<String>, HashMap<String, u32>) {
    fn walk(
        sched_id: u32,
        group: &HirScheduleGroup,
        sets: &mut HashSet<String>,
        scheduled: &mut HashMap<String, u32>,
        seq_counter: &mut usize,
    ) {
        if group.kind == "leaf" && !group.name.is_empty() {
            let bare = bare_schedule_target(&group.name).to_owned();
            scheduled.entry(bare).or_insert(sched_id);
            return;
        }
        if matches!(group.kind.as_str(), "set" | "seq" | "seq_weak" | "par") {
            let raw_name = if group.name.is_empty() {
                *seq_counter += 1;
                format!("__group_{seq_counter}")
            } else {
                group.name.clone()
            };
            let bare = bare_schedule_target(&raw_name).to_owned();
            sets.insert(bare);
        }
        for ch in &group.children {
            walk(sched_id, ch, sets, scheduled, seq_counter);
        }
    }

    let mut sets = HashSet::new();
    let mut scheduled = HashMap::new();
    let mut seq_counter = 0usize;
    for sched in &mir.schedules {
        let sched_id = schedule_id_for_label(&sched.label).0;
        for node in &sched.nodes {
            walk(sched_id, node, &mut sets, &mut scheduled, &mut seq_counter);
        }
    }
    (sets, scheduled)
}

fn collect_mir_known_systems(mir: &MirModule) -> (HashSet<String>, bool) {
    let mut known = HashSet::new();
    let mut has_timer_tick = false;
    for f in &mir.functions {
        if matches!(
            f.kind,
            MirFnKind::System
                | MirFnKind::SynthesizedTimeline
                | MirFnKind::SynthesizedTask
                | MirFnKind::SynthesizedFsm
                | MirFnKind::SynthesizedSpatialCsr
                | MirFnKind::SynthesizedTimerTick
        ) {
            known.insert(bare_schedule_target(&f.name).to_owned());
        }
        if matches!(f.kind, MirFnKind::SynthesizedTimerTick) {
            has_timer_tick = true;
        }
    }
    (known, has_timer_tick)
}

#[inline]
fn hash_token_non_trivia(tok: &SyntaxToken, hasher: &mut Sha256) {
    if tok.kind().is_trivia() {
        return;
    }
    hasher.update((tok.kind() as u16).to_le_bytes());
    let bytes = tok.text().as_bytes();
    hasher.update((bytes.len() as u32).to_le_bytes());
    hasher.update(bytes);
}

fn hash_cst_non_trivia(node: &SyntaxNode, hasher: &mut Sha256) {
    hasher.update([0x01u8]);
    hasher.update((node.kind() as u16).to_le_bytes());
    for el in node.descendants_with_tokens() {
        if let NodeOrToken::Token(tok) = el {
            hash_token_non_trivia(&tok, hasher);
        }
    }
    hasher.update([0x02u8]);
}

fn schedule_mod_is_run_if(node: &SyntaxNode) -> bool {
    node.children_with_tokens()
        .filter_map(|e| e.into_token())
        .any(|t| t.kind() == SyntaxKind::KwRunIf)
}

fn hash_schedule_cst_split(
    node: &SyntaxNode,
    sched_idx: u32,
    non_sched: &mut Sha256,
    sched: &mut Sha256,
) {
    for el in node.children_with_tokens() {
        match el {
            NodeOrToken::Token(tok) => hash_token_non_trivia(&tok, sched),
            NodeOrToken::Node(child) => match child.kind() {
                SyntaxKind::Attribute => {
                    non_sched.update(sched_idx.to_le_bytes());
                    hash_cst_non_trivia(&child, non_sched);
                }
                SyntaxKind::ScheduleMod => {
                    if schedule_mod_is_run_if(&child) {
                        non_sched.update(sched_idx.to_le_bytes());
                        hash_cst_non_trivia(&child, non_sched);
                    } else {
                        hash_cst_non_trivia(&child, sched);
                    }
                }
                SyntaxKind::ScheduleNode => {
                    sched.update([0x10u8]);
                    hash_schedule_cst_split(&child, sched_idx, non_sched, sched);
                    sched.update([0x11u8]);
                }
                _ => hash_cst_non_trivia(&child, sched),
            },
        }
    }
}

fn compute_watch_signatures(sf: &ast::SourceFile) -> ([u8; 32], [u8; 32]) {
    let mut non_sched = Sha256::new();
    let mut sched = Sha256::new();
    let mut sched_idx = 0u32;
    for item in sf.items() {
        if let ast::Item::Schedule(sd) = item {
            sched.update([0x20u8]);
            sched.update(sched_idx.to_le_bytes());
            hash_schedule_cst_split(sd.syntax(), sched_idx, &mut non_sched, &mut sched);
            sched.update([0x21u8]);
            sched_idx = sched_idx.saturating_add(1);
        } else {
            hash_cst_non_trivia(item.syntax(), &mut non_sched);
        }
    }
    (non_sched.finalize().into(), sched.finalize().into())
}

fn extract_before_after_mods(node: &SyntaxNode) -> Option<(Vec<String>, Vec<String>)> {
    let mut before = Vec::new();
    let mut after = Vec::new();
    for m in ast::children::<ast::ScheduleMod>(node) {
        let mut is_before = false;
        let mut is_after = false;
        for el in m.syntax().children_with_tokens() {
            if let NodeOrToken::Token(tok) = el {
                match tok.kind() {
                    SyntaxKind::KwBefore => is_before = true,
                    SyntaxKind::KwAfter => is_after = true,
                    _ => {}
                }
            }
        }
        if is_before || is_after {
            let paths: Vec<String> = ast::children::<ast::Path>(m.syntax())
                .map(|p| ast::path_text(&p))
                .collect();
            if paths.is_empty() {
                return None;
            }
            for raw in paths {
                let target = bare_schedule_target(&raw);
                if target.is_empty() {
                    return None;
                }
                if is_before {
                    before.push(target.to_owned());
                }
                if is_after {
                    after.push(target.to_owned());
                }
            }
        }
    }
    Some((before, after))
}

fn parse_cst_schedule_group(
    node: &SyntaxNode,
    mod_targets_to_validate: &mut Vec<String>,
) -> Option<HirScheduleGroup> {
    let kind = node
        .children_with_tokens()
        .filter_map(|e| e.into_token())
        .find_map(|t| match t.kind() {
            SyntaxKind::KwSeq => Some("seq".to_owned()),
            SyntaxKind::KwSeqWeak => Some("seq_weak".to_owned()),
            SyntaxKind::KwPar => Some("par".to_owned()),
            SyntaxKind::KwSet => Some("set".to_owned()),
            _ => None,
        })
        .unwrap_or_else(|| "leaf".to_owned());

    let (before, after) = extract_before_after_mods(node)?;
    mod_targets_to_validate.extend(before.iter().cloned());
    mod_targets_to_validate.extend(after.iter().cloned());

    if kind == "leaf" {
        let raw = ast::child::<ast::Path>(node).map(|p| ast::path_text(&p))?;
        let bare = bare_schedule_target(&raw);
        if bare.is_empty() {
            return None;
        }
        return Some(HirScheduleGroup {
            kind,
            name: bare.to_owned(),
            before,
            after,
            children: Vec::new(),
        });
    }

    let name = ast::first_ident(node).map_or_else(String::new, |t| t.text().to_owned());
    let mut children = Vec::new();
    for ch in ast::children::<ast::ScheduleNode>(node) {
        children.push(parse_cst_schedule_group(
            ch.syntax(),
            mod_targets_to_validate,
        )?);
    }
    Some(HirScheduleGroup {
        kind,
        name,
        before,
        after,
        children,
    })
}

fn encode_hex_32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Persistent incremental watch compiler session reusing a single [`SemaDb`], [`SourceFile`],
/// cached signing [`PrivateKey`], and CST signatures for `< 0.4 ms` schedule-only delta emission.
pub struct WatchSession {
    file: PathBuf,
    db: SemaDb,
    sfile: SourceFile,
    signing_key: Option<PrivateKey>,
    signer_fingerprint: Option<String>,
    prev_layouts: BTreeMap<String, SolvedLayout>,
    prev_non_schedule_sig: Option<[u8; 32]>,
    prev_schedule_sig: Option<[u8; 32]>,
    known_systems: HashSet<String>,
    scheduled_systems: HashMap<String, u32>,
    known_sets: HashSet<String>,
    has_timer_tick: bool,
    cached_module_path: String,
    cached_stem: String,
    cached_base_mir: Option<MirModule>,
    cached_out_dir: Option<PathBuf>,
    cached_dylib_path: Option<PathBuf>,
    cached_signature_path: Option<String>,
    initial_completed: bool,
}

impl WatchSession {
    /// Creates a new [`WatchSession`] for `file`, pre-warming Salsa layout resolution and loading
    /// (or generating) the Ed25519 signing key when `sign` is enabled.
    pub fn new(
        file: &Path,
        sign: bool,
        key_path: Option<&Path>,
        ephemeral_key: bool,
    ) -> Result<Self, (i32, String)> {
        if key_path.is_some() && ephemeral_key {
            return Err((
                EXIT_COMPILE_ERROR,
                "cannot specify both `--key <path>` and `--ephemeral-key`".to_owned(),
            ));
        }
        if !sign && (key_path.is_some() || ephemeral_key) {
            return Err((
                EXIT_COMPILE_ERROR,
                "cannot specify `--key` or `--ephemeral-key` without `--sign`".to_owned(),
            ));
        }
        let signing_key = if sign {
            Some(resolve_signing_key(
                key_path,
                ephemeral_key,
                "stratac-watch-ephemeral",
            )?)
        } else {
            None
        };
        let signer_fingerprint = signing_key.as_ref().map(|k| {
            k.public_key()
                .fingerprint(bamabi_trust::HashAlg::Sha256)
                .to_string()
        });

        let initial_src = read_source(file)?;
        let db = SemaDb::default();
        let sfile = db.new_source(file.display().to_string(), initial_src);
        let prev_layouts = collect_layouts_map(&db, sfile);
        let _ = db.take_executed_queries();

        Ok(Self {
            file: file.to_path_buf(),
            db,
            sfile,
            signing_key,
            signer_fingerprint,
            prev_layouts,
            prev_non_schedule_sig: None,
            prev_schedule_sig: None,
            known_systems: HashSet::new(),
            scheduled_systems: HashMap::new(),
            known_sets: HashSet::new(),
            has_timer_tick: false,
            cached_module_path: String::new(),
            cached_stem: String::new(),
            cached_base_mir: None,
            cached_out_dir: None,
            cached_dylib_path: None,
            cached_signature_path: None,
            initial_completed: false,
        })
    }

    /// Reads the watched `.strata` file from disk and runs one incremental rebuild cycle.
    pub fn rebuild_from_disk(&mut self) -> Result<WatchReport, (i32, String)> {
        let src = read_source(&self.file)?;
        self.rebuild_from_source(&src)
    }

    /// Rebuilds from an updated in-memory `.strata` source string, taking the `< 0.4 ms`
    /// `ModScheduleSetRewirePass` schedule-delta fast path whenever only schedule topology changed.
    pub fn rebuild_from_source(&mut self, cur_src: &str) -> Result<WatchReport, (i32, String)> {
        let t0 = Instant::now();
        if self.initial_completed {
            self.sfile.set_text(&mut self.db).to(cur_src.to_owned());
        }

        let parsed = strata_syntax::parse(cur_src);
        let sigs = if parsed.ok() {
            ast::SourceFile::cast(parsed.syntax()).map(|sf| {
                let sigs = compute_watch_signatures(&sf);
                (sf, sigs)
            })
        } else {
            None
        };

        if self.initial_completed
            && let Some((ref sf, (non_sched_sig, sched_sig))) = sigs
            && Some(non_sched_sig) == self.prev_non_schedule_sig
            && Some(sched_sig) != self.prev_schedule_sig
            && let Some(ref dylib_path) = self.cached_dylib_path
            && dylib_path.exists()
            && let Some(ref out_dir) = self.cached_out_dir
            && let Some(delta) = self.try_build_schedule_delta(sf, sched_sig)
        {
            let delta_path = out_dir.join(format!("{}.schedule_delta.json", self.cached_stem));
            let bytes = serde_json::to_vec(&delta)
                .map_err(|e| (EXIT_COMPILE_ERROR, format!("serialize delta failed: {e}")))?;
            fs::write(&delta_path, bytes).map_err(|e| {
                (
                    EXIT_COMPILE_ERROR,
                    format!("write `{}` failed: {e}", delta_path.display()),
                )
            })?;
            self.prev_schedule_sig = Some(sched_sig);
            let rebuild_ms = t0.elapsed().as_secs_f64() * 1000.0;
            return Ok(WatchReport {
                file: self.file.display().to_string(),
                salsa_layout_recomputed: false,
                schedule_delta_only: true,
                dylib_path: dylib_path.display().to_string(),
                schedule_delta_path: Some(delta_path.display().to_string()),
                signature_path: self.cached_signature_path.clone(),
                signer_fingerprint: self.signer_fingerprint.clone(),
                rebuild_ms,
            });
        }

        let analyzed = self.db.analyze_file(self.sfile);
        if !analyzed.ok() {
            let _ = self.db.take_executed_queries();
            return Err((
                EXIT_COMPILE_ERROR,
                serde_json::to_string_pretty(&analyzed.diagnostics).unwrap_or_default(),
            ));
        }
        let next_layouts = collect_layouts_map(&self.db, self.sfile);
        let executed = self.db.take_executed_queries();
        let salsa_layout_recomputed = next_layouts != self.prev_layouts
            && executed.iter().any(|q| q.contains("resolve_layouts"));

        let mir = lower_to_mir(&analyzed);
        if let Err(errs) = verify_mir(&mir) {
            let msg = errs
                .into_iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("\n");
            return Err((
                EXIT_COMPILE_ERROR,
                format!("MIR verification failed:\n{msg}"),
            ));
        }
        let stem = module_stem(&mir.module_path);
        let out_dir = self
            .file
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .join(format!("target_strata_watch_{stem}"));

        let art = compile_module_to_dylib(
            &mir,
            &JitCompileOptions {
                out_dir: out_dir.clone(),
                module_stem: stem.clone(),
                opt_level: JitOptLevel::FastCompile,
            },
        )
        .map_err(|e| (EXIT_COMPILE_ERROR, format!("JIT watch rebuild failed: {e}")))?;

        let mut signature_path = None;
        if let Some(ref key) = self.signing_key {
            let bytes = fs::read(&art.dylib_path).map_err(|e| {
                (
                    EXIT_COMPILE_ERROR,
                    format!(
                        "read rebuilt library `{}` failed: {e}",
                        art.dylib_path.display()
                    ),
                )
            })?;
            let pem = sign_mod_bytes_with_key(key, DEFAULT_SIGNATURE_NAMESPACE, &bytes)
                .map_err(|e| (EXIT_COMPILE_ERROR, format!("sign failed: {e}")))?;
            let sig_p = default_signature_path_for(&art.dylib_path);
            fs::write(&sig_p, pem).map_err(|e| {
                (
                    EXIT_COMPILE_ERROR,
                    format!("write signature `{}` failed: {e}", sig_p.display()),
                )
            })?;
            signature_path = Some(sig_p.display().to_string());
        }

        let (known_systems, has_timer_tick) = collect_mir_known_systems(&mir);
        let (known_sets, scheduled_systems) = collect_mir_schedule_sets_and_systems(&mir);
        let mut base_mir = mir.clone();
        base_mir
            .functions
            .retain(|f| !matches!(f.kind, MirFnKind::SynthesizedSpatialCsr));
        base_mir.schedules.clear();

        self.prev_layouts = next_layouts;
        self.known_systems = known_systems;
        self.scheduled_systems = scheduled_systems;
        self.known_sets = known_sets;
        self.has_timer_tick = has_timer_tick;
        self.cached_module_path = mir.module_path;
        self.cached_stem = stem;
        self.cached_base_mir = Some(base_mir);
        self.cached_out_dir = Some(out_dir);
        self.cached_dylib_path = Some(art.dylib_path.clone());
        self.cached_signature_path = signature_path.clone();
        if let Some((_, (non_sched_sig, sched_sig))) = sigs {
            self.prev_non_schedule_sig = Some(non_sched_sig);
            self.prev_schedule_sig = Some(sched_sig);
        } else if let Some(sf) = ast::SourceFile::cast(parsed.syntax()) {
            let (non_sched_sig, sched_sig) = compute_watch_signatures(&sf);
            self.prev_non_schedule_sig = Some(non_sched_sig);
            self.prev_schedule_sig = Some(sched_sig);
        }
        self.initial_completed = true;

        let rebuild_ms = t0.elapsed().as_secs_f64() * 1000.0;
        Ok(WatchReport {
            file: self.file.display().to_string(),
            salsa_layout_recomputed,
            schedule_delta_only: false,
            dylib_path: art.dylib_path.display().to_string(),
            schedule_delta_path: None,
            signature_path,
            signer_fingerprint: self.signer_fingerprint.clone(),
            rebuild_ms,
        })
    }

    fn try_build_schedule_delta(
        &self,
        sf: &ast::SourceFile,
        sched_sig: [u8; 32],
    ) -> Option<ScheduleDeltaArtifact> {
        #[allow(clippy::too_many_arguments)]
        fn walk_group(
            known_systems: &HashSet<String>,
            sched_id: u32,
            label: &str,
            group: &HirScheduleGroup,
            parent_sets: &[(usize, String)],
            sets: &mut Vec<ScheduleDeltaSet>,
            set_index_map: &mut HashMap<(u32, String), usize>,
            sys_map: &mut HashMap<String, ScheduleDeltaSystem>,
            sys_order: &mut Vec<String>,
            new_scheduled_systems: &mut HashMap<String, u32>,
            mod_name: &str,
            seq_counter: &mut usize,
            leaf_order: &mut usize,
        ) -> Option<(Vec<String>, Option<usize>)> {
            if group.kind == "leaf" {
                let bare = bare_schedule_target(&group.name);
                if bare.is_empty() || !known_systems.contains(bare) {
                    return None;
                }
                if let Some(&prev_sched) = new_scheduled_systems.get(bare) {
                    if prev_sched != sched_id {
                        return None;
                    }
                } else {
                    new_scheduled_systems.insert(bare.to_owned(), sched_id);
                }

                let entry = sys_map.entry(bare.to_owned()).or_insert_with(|| {
                    let order = *leaf_order;
                    *leaf_order += 1;
                    sys_order.push(bare.to_owned());
                    ScheduleDeltaSystem {
                        name: bare.to_owned(),
                        schedule_id: sched_id,
                        schedule_label: label.to_owned(),
                        sched_order: order,
                        in_sets: Vec::new(),
                        mount_sets: Vec::new(),
                        after: Vec::new(),
                        after_weak: Vec::new(),
                        before: Vec::new(),
                        before_weak: Vec::new(),
                    }
                });
                for (_, bare_set_name) in parent_sets {
                    if !entry.in_sets.contains(bare_set_name) {
                        entry.in_sets.push(bare_set_name.clone());
                    }
                }
                if let Some(&(parent_idx, ref parent_name)) = parent_sets.last() {
                    if !entry.mount_sets.contains(parent_name) {
                        entry.mount_sets.push(parent_name.clone());
                    }
                    let mounted = &mut sets[parent_idx].mounted_systems;
                    if !mounted.iter().any(|s| s == bare) {
                        mounted.push(bare.to_owned());
                    }
                }
                for t in &group.before {
                    let target = bare_schedule_target(t);
                    if !target.is_empty() && !entry.before.iter().any(|x| x == target) {
                        entry.before.push(target.to_owned());
                    }
                }
                for t in &group.after {
                    let target = bare_schedule_target(t);
                    if !target.is_empty() && !entry.after.iter().any(|x| x == target) {
                        entry.after.push(target.to_owned());
                    }
                }
                return Some((vec![bare.to_owned()], None));
            }

            let raw_name = if group.name.is_empty() {
                *seq_counter += 1;
                format!("__group_{seq_counter}")
            } else {
                group.name.clone()
            };
            let bare = bare_schedule_target(&raw_name).to_owned();
            let (mode, flags) = match group.kind.as_str() {
                "seq" => (ScheduleDeltaMode::Sequence, BAM_SCHEDULE_SET_FLAG_SEQUENCE),
                "seq_weak" => (
                    ScheduleDeltaMode::SequenceWeak,
                    BAM_SCHEDULE_SET_FLAG_SEQUENCE_WEAK,
                ),
                _ => (ScheduleDeltaMode::Parallel, BAM_SCHEDULE_SET_FLAG_PARALLEL),
            };

            let key = (sched_id, bare.clone());
            let own_idx = if let Some(&existing) = set_index_map.get(&key) {
                existing
            } else {
                let idx = sets.len();
                sets.push(ScheduleDeltaSet {
                    set_name: bare.clone(),
                    canonical_name: format!("{mod_name}::{bare}"),
                    schedule_id: sched_id,
                    schedule_label: label.to_owned(),
                    mode,
                    flags,
                    before_sets: Vec::new(),
                    after_sets: Vec::new(),
                    before_weak: false,
                    after_weak: false,
                    mounted_systems: Vec::new(),
                });
                set_index_map.insert(key, idx);
                idx
            };

            for t in &group.before {
                let target = bare_schedule_target(t);
                if !target.is_empty() && !sets[own_idx].before_sets.iter().any(|x| x == target) {
                    sets[own_idx].before_sets.push(target.to_owned());
                }
            }
            for t in &group.after {
                let target = bare_schedule_target(t);
                if !target.is_empty() && !sets[own_idx].after_sets.iter().any(|x| x == target) {
                    sets[own_idx].after_sets.push(target.to_owned());
                }
            }

            let mut next_parent_sets = parent_sets.to_vec();
            next_parent_sets.push((own_idx, bare));

            let is_seq = group.kind == "seq";
            let is_seq_weak = group.kind == "seq_weak";
            let mut prev_leaves: Vec<String> = Vec::new();
            let mut prev_set_idx: Option<usize> = None;
            let mut all_leaves: Vec<String> = Vec::new();

            for ch in &group.children {
                let (leaves, cur_set_idx) = walk_group(
                    known_systems,
                    sched_id,
                    label,
                    ch,
                    &next_parent_sets,
                    sets,
                    set_index_map,
                    sys_map,
                    sys_order,
                    new_scheduled_systems,
                    mod_name,
                    seq_counter,
                    leaf_order,
                )?;
                if is_seq || is_seq_weak {
                    if let (Some(p_s), Some(c_s)) = (prev_set_idx, cur_set_idx)
                        && p_s != c_s
                    {
                        let p_name = sets[p_s].set_name.clone();
                        let c_name = sets[c_s].set_name.clone();
                        if !sets[c_s].after_sets.contains(&p_name) {
                            sets[c_s].after_sets.push(p_name);
                        }
                        if !sets[p_s].before_sets.contains(&c_name) {
                            sets[p_s].before_sets.push(c_name);
                        }
                        if is_seq_weak {
                            sets[c_s].after_weak = true;
                            sets[c_s].flags |= BAM_SCHEDULE_SET_FLAG_AFTER_WEAK;
                            sets[p_s].before_weak = true;
                            sets[p_s].flags |= BAM_SCHEDULE_SET_FLAG_BEFORE_WEAK;
                        }
                    }
                    for l in &leaves {
                        if let Some(ent) = sys_map.get_mut(l) {
                            for pl in &prev_leaves {
                                if pl != l {
                                    if is_seq && !ent.after.contains(pl) {
                                        ent.after.push(pl.clone());
                                    } else if is_seq_weak && !ent.after_weak.contains(pl) {
                                        ent.after_weak.push(pl.clone());
                                    }
                                }
                            }
                        }
                    }
                }
                if !leaves.is_empty() {
                    prev_leaves = leaves.clone();
                }
                if cur_set_idx.is_some() {
                    prev_set_idx = cur_set_idx;
                } else if !leaves.is_empty() {
                    prev_set_idx = None;
                }
                all_leaves.extend(leaves);
            }

            Some((all_leaves, Some(own_idx)))
        }

        let base_mir = self.cached_base_mir.as_ref()?;
        let mut mod_targets_to_validate = Vec::new();
        let mut parsed_schedules = Vec::new();

        for item in sf.items() {
            if let ast::Item::Schedule(sd) = item {
                let label = ast::child::<ast::Path>(sd.syntax())
                    .map(|p| ast::path_text(&p))
                    .unwrap_or_else(|| "Update".to_owned());
                let (sched_before, sched_after) = extract_before_after_mods(sd.syntax())?;
                mod_targets_to_validate.extend(sched_before);
                mod_targets_to_validate.extend(sched_after);

                let mut nodes = Vec::new();
                for ch in ast::children::<ast::ScheduleNode>(sd.syntax()) {
                    nodes.push(parse_cst_schedule_group(
                        ch.syntax(),
                        &mut mod_targets_to_validate,
                    )?);
                }
                parsed_schedules.push(HirSchedule {
                    label,
                    run_if: None,
                    run_if_expr: None,
                    nodes,
                });
            }
        }

        let mut temp_mir = base_mir.clone();
        temp_mir.schedules = parsed_schedules;
        if self.has_timer_tick {
            let tick_leaf = HirScheduleGroup {
                kind: "leaf".to_owned(),
                name: "strata_timer_tick".to_owned(),
                before: Vec::new(),
                after: Vec::new(),
                children: Vec::new(),
            };
            if let Some(fixed) = temp_mir
                .schedules
                .iter_mut()
                .find(|s| s.label == "FixedUpdate")
            {
                fixed.nodes.insert(0, tick_leaf);
            } else {
                temp_mir.schedules.push(HirSchedule {
                    label: "FixedUpdate".to_owned(),
                    run_if: None,
                    run_if_expr: None,
                    nodes: vec![tick_leaf],
                });
            }
        }
        strata_mir::passes::spatial_csr::run(&mut temp_mir);

        let (new_known_systems, _) = collect_mir_known_systems(&temp_mir);
        if new_known_systems != self.known_systems {
            return None;
        }

        let effective_mod_name = if self.cached_module_path.is_empty() {
            "strata_mod".to_owned()
        } else {
            self.cached_module_path.clone()
        };

        let mut sets = Vec::new();
        let mut set_index_map = HashMap::new();
        let mut sys_map = HashMap::new();
        let mut sys_order = Vec::new();
        let mut new_scheduled_systems = HashMap::new();
        let mut seq_counter = 0usize;
        let mut leaf_order = 0usize;

        for sched in &temp_mir.schedules {
            let sched_id = schedule_id_for_label(&sched.label).0;
            for ch in &sched.nodes {
                walk_group(
                    &new_known_systems,
                    sched_id,
                    &sched.label,
                    ch,
                    &[],
                    &mut sets,
                    &mut set_index_map,
                    &mut sys_map,
                    &mut sys_order,
                    &mut new_scheduled_systems,
                    &effective_mod_name,
                    &mut seq_counter,
                    &mut leaf_order,
                )?;
            }
        }

        if new_scheduled_systems != self.scheduled_systems {
            return None;
        }

        let current_set_names: HashSet<&str> = sets.iter().map(|s| s.set_name.as_str()).collect();
        for t in &mod_targets_to_validate {
            let valid = t.starts_with("host::")
                || self.known_systems.contains(t)
                || self.known_sets.contains(t)
                || current_set_names.contains(t.as_str());
            if !valid {
                return None;
            }
        }

        if self.has_timer_tick {
            for ent in sys_map.values_mut() {
                if ent.schedule_id == ScheduleId::FIXED_UPDATE.0
                    && ent.name != "strata_timer_tick"
                    && !ent.after.iter().any(|a| a == "strata_timer_tick")
                {
                    ent.after.push("strata_timer_tick".to_owned());
                }
            }
        }

        let mut touched_schedules: Vec<u32> = sets
            .iter()
            .map(|s| s.schedule_id)
            .chain(sys_map.values().map(|s| s.schedule_id))
            .collect();
        touched_schedules.sort_unstable();
        touched_schedules.dedup();

        let requires_set_registration = sets.iter().any(|s| !self.known_sets.contains(&s.set_name))
            || sets.len() != self.known_sets.len();

        let systems = sys_order
            .into_iter()
            .filter_map(|name| sys_map.remove(&name))
            .collect();

        Some(ScheduleDeltaArtifact {
            schema_version: 1,
            target_pass: "ModScheduleSetRewirePass".to_owned(),
            abi_version: ABI_VERSION,
            module_path: self.cached_module_path.clone(),
            mod_name: effective_mod_name,
            schedule_signature: encode_hex_32(&sched_sig),
            touched_schedules,
            requires_set_registration,
            sets,
            systems,
        })
    }
}

fn format_watch_report(report: &WatchReport, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(report).unwrap_or_default(),
        OutputFormat::Text => {
            if report.schedule_delta_only {
                format!(
                    "watch pass: {} schedule-delta -> {} in {:.2} ms (layout_changed=false)",
                    report.dylib_path,
                    report.schedule_delta_path.as_deref().unwrap_or(""),
                    report.rebuild_ms
                )
            } else {
                format!(
                    "watch pass: {} rebuilt in {:.2} ms (layout_changed={})",
                    report.dylib_path, report.rebuild_ms, report.salsa_layout_recomputed
                )
            }
        }
    }
}

fn is_relevant_watch_event(ev: &DebouncedEvent) -> bool {
    matches!(
        ev.kind,
        EventKind::Create(CreateKind::File | CreateKind::Any)
            | EventKind::Modify(
                ModifyKind::Data(_)
                    | ModifyKind::Name(RenameMode::To | RenameMode::Both | RenameMode::Any)
                    | ModifyKind::Any
            )
            | EventKind::Access(AccessKind::Close(AccessMode::Write))
    )
}

fn path_matches_target(path: &Path, target_canonical: &Path) -> bool {
    if path == target_canonical {
        return true;
    }
    fs::canonicalize(path)
        .map(|p| p == target_canonical)
        .unwrap_or(false)
}

/// Executes `stratac watch` (compatibility wrapper without explicit key arguments).
pub fn cmd_watch(file: &Path, sign: bool, once: bool, format: OutputFormat) -> (i32, String) {
    cmd_watch_with_key(file, sign, None, false, once, format)
}

/// Executes `stratac watch` with explicit OpenSSH `--key` or `--ephemeral-key` selection.
pub fn cmd_watch_with_key(
    file: &Path,
    sign: bool,
    key_path: Option<&Path>,
    ephemeral_key: bool,
    once: bool,
    format: OutputFormat,
) -> (i32, String) {
    cmd_watch_bounded(
        file,
        sign,
        key_path,
        ephemeral_key,
        once,
        None,
        None,
        None,
        format,
    )
}

/// Executes `stratac watch` using `notify-debouncer-full` filesystem events, with optional
/// `max_rebuilds`, `on_ready`, and `on_cycle` test hooks for deterministic watcher testing.
#[allow(clippy::too_many_arguments)]
pub fn cmd_watch_bounded(
    file: &Path,
    sign: bool,
    key_path: Option<&Path>,
    ephemeral_key: bool,
    once: bool,
    max_rebuilds: Option<usize>,
    on_ready: Option<mpsc::Sender<()>>,
    on_cycle: Option<mpsc::Sender<WatchReport>>,
    format: OutputFormat,
) -> (i32, String) {
    let mut session = match WatchSession::new(file, sign, key_path, ephemeral_key) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let first = match session.rebuild_from_disk() {
        Ok(r) => r,
        Err(e) => return e,
    };
    let mut last_src = fs::read_to_string(file).unwrap_or_default();
    if let Some(ref tx_cycle) = on_cycle {
        let _ = tx_cycle.send(first.clone());
    }
    if once {
        return (EXIT_OK, format_watch_report(&first, format));
    }
    if max_rebuilds == Some(0) {
        if let Some(tx_ready) = on_ready {
            let _ = tx_ready.send(());
        }
        return (EXIT_OK, format_watch_report(&first, format));
    }

    let target_canonical = fs::canonicalize(file).unwrap_or_else(|_| file.to_path_buf());
    let watch_dir = target_canonical
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    let (tx, rx) = mpsc::channel::<DebounceEventResult>();
    let mut debouncer = match new_debouncer(Duration::from_millis(40), None, tx) {
        Ok(d) => d,
        Err(e) => {
            return (
                EXIT_COMPILE_ERROR,
                format!("failed creating file watcher: {e}"),
            );
        }
    };
    if let Err(e) = debouncer.watch(&watch_dir, RecursiveMode::NonRecursive) {
        return (
            EXIT_COMPILE_ERROR,
            format!("failed watching `{}`: {e}", watch_dir.display()),
        );
    }
    if let Some(tx_ready) = on_ready {
        let _ = tx_ready.send(());
    }

    let mut rebuilds = 0usize;
    let mut last_report = first;
    while let Ok(res) = rx.recv() {
        match res {
            Ok(events) => {
                let matched = events.iter().any(|ev| {
                    is_relevant_watch_event(ev)
                        && ev
                            .paths
                            .iter()
                            .any(|p| path_matches_target(p, &target_canonical))
                });
                if !matched {
                    continue;
                }
                let Ok(cur_src) = fs::read_to_string(&target_canonical) else {
                    continue;
                };
                if cur_src == last_src {
                    continue;
                }
                last_src = cur_src;
                match session.rebuild_from_source(&last_src) {
                    Ok(report) => {
                        rebuilds += 1;
                        if let Some(ref tx_cycle) = on_cycle {
                            let _ = tx_cycle.send(report.clone());
                        } else {
                            println!("{}", format_watch_report(&report, format));
                        }
                        last_report = report;
                        if max_rebuilds.is_some_and(|max| rebuilds >= max) {
                            break;
                        }
                    }
                    Err((_, diag)) => {
                        eprintln!("stratac watch rebuild error:\n{diag}");
                    }
                }
            }
            Err(errors) => {
                for err in errors {
                    eprintln!("stratac watch error: {err}");
                }
            }
        }
    }

    drop(debouncer);
    (EXIT_OK, format_watch_report(&last_report, format))
}

/// Executes `stratac onboard`.
pub fn cmd_onboard(
    file: &Path,
    _target: OnboardTarget,
    out_dir: &Path,
    static_console: bool,
    run_check: bool,
    format: OutputFormat,
) -> (i32, String) {
    let src = match read_source(file) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let analyzed = analyze_source(file.display().to_string(), &src);
    if !analyzed.ok() {
        return (
            EXIT_COMPILE_ERROR,
            serde_json::to_string_pretty(&analyzed.diagnostics).unwrap_or_default(),
        );
    }
    let mir = lower_to_mir(&analyzed);
    let stem = module_stem(&mir.module_path);
    let crate_name = format!("strata_native_{stem}");
    let native_rt_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("bamabi_native_rt")
        .display()
        .to_string();

    let art = match emit_bevy_native(
        &mir,
        &BevyNativeOptions {
            crate_name: crate_name.clone(),
            native_rt_path: Some(native_rt_path),
            static_console,
        },
    ) {
        Ok(a) => a,
        Err(e) => return (EXIT_COMPILE_ERROR, format!("onboard emit failed: {e}")),
    };

    let mut written_files = Vec::new();
    for f in &art.files {
        let p = out_dir.join(&f.path);
        if let Some(parent) = p.parent()
            && let Err(e) = fs::create_dir_all(parent)
        {
            return (EXIT_COMPILE_ERROR, format!("mkdir error: {e}"));
        }
        if let Err(e) = fs::write(&p, &f.content) {
            return (EXIT_COMPILE_ERROR, format!("write error: {e}"));
        }
        written_files.push(f.path.clone());
    }

    // Write local `.cargo/config.toml` patch overlay so standalone onboarded crate resolves local repos.
    if let Err(e) = try_write_local_patch_config_with_ws(&workspace_root(), out_dir) {
        return (EXIT_COMPILE_ERROR, e);
    }

    let mut cargo_checked = false;
    if run_check {
        let mut cmd = sanitized_cargo();
        cmd.current_dir(out_dir)
            .arg("check")
            .arg("--manifest-path")
            .arg(out_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(shared_temp_target_dir());
        let output = match cmd.output() {
            Ok(o) => o,
            Err(e) => return (EXIT_COMPILE_ERROR, format!("cargo check failed: {e}")),
        };
        if !output.status.success() {
            return (
                EXIT_COMPILE_ERROR,
                format!(
                    "onboarded crate failed cargo check:\n{}",
                    String::from_utf8_lossy(&output.stderr)
                ),
            );
        }
        cargo_checked = true;
    }

    let report = OnboardReport {
        file: file.display().to_string(),
        out_dir: out_dir.display().to_string(),
        crate_name,
        files: written_files,
        cargo_checked,
    };
    let text = match format {
        OutputFormat::Json => serde_json::to_string_pretty(&report).unwrap_or_default(),
        OutputFormat::Text => format!(
            "Onboarded `{}` -> {} (cargo_checked={})",
            report.crate_name, report.out_dir, report.cargo_checked
        ),
    };
    (EXIT_OK, text)
}

fn is_valid_git_rev(s: &str) -> bool {
    !s.is_empty() && s.len() >= 7 && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Resolves the pinned `bamabi-wire` git revision from `ws_root/abi-lock.toml` (optional
/// `wire_rev = "<rev>"` override) or falls back to `ws_root/Cargo.lock` (`bamabi_sys` or any
/// `bamabi-wire.git` package `source = "git+...#<rev>"`).
pub fn resolve_wire_rev(ws_root: &Path) -> Result<String, String> {
    let abi_lock = ws_root.join("abi-lock.toml");
    if abi_lock.is_file() {
        let content = fs::read_to_string(&abi_lock)
            .map_err(|e| format!("failed reading `{}`: {e}", abi_lock.display()))?;
        for raw_line in content.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if let Some((key, val)) = line.split_once('=')
                && key.trim() == "wire_rev"
            {
                let rev = val.trim().trim_matches('"').trim_matches('\'').trim();
                if is_valid_git_rev(rev) {
                    return Ok(rev.to_owned());
                }
                return Err(format!(
                    "invalid `wire_rev` in `{}`: `{rev}`",
                    abi_lock.display()
                ));
            }
        }
    }

    let cargo_lock = ws_root.join("Cargo.lock");
    if cargo_lock.is_file() {
        let content = fs::read_to_string(&cargo_lock)
            .map_err(|e| format!("failed reading `{}`: {e}", cargo_lock.display()))?;
        let mut in_pkg = false;
        let mut pkg_name: Option<String> = None;
        let mut pkg_source: Option<String> = None;
        let mut fallback: Option<String> = None;

        let flush_pkg = |name: Option<&str>,
                         source: Option<&str>,
                         fallback: &mut Option<String>|
         -> Option<String> {
            let src = source?;
            if !src.contains("bamabi-wire.git") {
                return None;
            }
            let rev = src.split_once('#')?.1.split(['"', '&', ' ']).next()?;
            if !is_valid_git_rev(rev) {
                return None;
            }
            if name == Some("bamabi_sys") {
                return Some(rev.to_owned());
            }
            if fallback.is_none() {
                *fallback = Some(rev.to_owned());
            }
            None
        };

        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line == "[[package]]" {
                if in_pkg
                    && let Some(found) =
                        flush_pkg(pkg_name.as_deref(), pkg_source.as_deref(), &mut fallback)
                {
                    return Ok(found);
                }
                in_pkg = true;
                pkg_name = None;
                pkg_source = None;
                continue;
            }
            if in_pkg && let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim().trim_matches('"');
                if k == "name" {
                    pkg_name = Some(v.to_owned());
                } else if k == "source" {
                    pkg_source = Some(v.to_owned());
                }
            }
        }
        if in_pkg
            && let Some(found) =
                flush_pkg(pkg_name.as_deref(), pkg_source.as_deref(), &mut fallback)
        {
            return Ok(found);
        }
        if let Some(rev) = fallback {
            return Ok(rev);
        }
    }

    let sibling_wire = ws_root.join("..").join("bamabi-wire");
    if sibling_wire.join(".git").exists()
        && let Ok(out) = Command::new("git")
            .arg("-C")
            .arg(&sibling_wire)
            .args(["rev-parse", "HEAD"])
            .output()
        && out.status.success()
    {
        let rev = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if is_valid_git_rev(&rev) {
            return Ok(rev);
        }
    }

    Err(format!(
        "unable to resolve bamabi-wire revision from `{}` or `{}`",
        abi_lock.display(),
        cargo_lock.display()
    ))
}

fn cargo_lock_has_git_wire_source(ws_root: &Path) -> bool {
    let Ok(content) = fs::read_to_string(ws_root.join("Cargo.lock")) else {
        return false;
    };
    let mut in_pkg = false;
    let mut is_sys = false;
    let mut has_git = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line == "[[package]]" {
            if in_pkg && is_sys {
                return has_git;
            }
            in_pkg = true;
            is_sys = false;
            has_git = false;
            continue;
        }
        if in_pkg && let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            let v = v.trim().trim_matches('"');
            if k == "name" && v == "bamabi_sys" {
                is_sys = true;
            } else if k == "source" && v.contains("bamabi-wire.git") {
                has_git = true;
            }
        }
    }
    in_pkg && is_sys && has_git
}

/// Writes `.cargo/config.toml` into `crate_dir` using `ws_root` to resolve the pinned
/// `bamabi-wire` revision dynamically from `abi-lock.toml` / `Cargo.lock` and preferring
/// sibling local checkouts when present.
pub fn try_write_local_patch_config_with_ws(
    ws_root: &Path,
    crate_dir: &Path,
) -> Result<(), String> {
    let wire_local = fs::canonicalize(ws_root.join("..").join("bamabi-wire")).ok();
    let tools_local = fs::canonicalize(ws_root.join("..").join("bamabi-tools")).ok();
    let core_local = fs::canonicalize(ws_root.join("..").join("bamabi-core")).ok();

    let mut cfg = String::new();
    if let Some(wire) = &wire_local {
        let w = wire.display();
        if cargo_lock_has_git_wire_source(ws_root) {
            let wire_rev = resolve_wire_rev(ws_root)?;
            cfg.push_str(&format!(
                "[patch.\"https://github.com/yaga-simha/bamabi-wire.git\"]\n\
                 bamabi_sys = {{ git = \"file://{w}\", rev = \"{wire_rev}\" }}\n\
                 bamabi_macros = {{ git = \"file://{w}\", rev = \"{wire_rev}\" }}\n\
                 bamabi_sdk_gen = {{ git = \"file://{w}\", rev = \"{wire_rev}\" }}\n\
                 bamabi_guest_sys = {{ git = \"file://{w}\", rev = \"{wire_rev}\" }}\n\
                 bamabi_guest = {{ git = \"file://{w}\", rev = \"{wire_rev}\" }}\n"
            ));
        } else {
            cfg.push_str(&format!(
                "[patch.\"https://github.com/yaga-simha/bamabi-wire.git\"]\n\
                 bamabi_sys = {{ path = \"{w}/crates/bamabi_sys\" }}\n\
                 bamabi_macros = {{ path = \"{w}/crates/bamabi_macros\" }}\n\
                 bamabi_sdk_gen = {{ path = \"{w}/crates/bamabi_sdk_gen\" }}\n\
                 bamabi_guest_sys = {{ path = \"{w}/crates/bamabi_guest_sys\" }}\n\
                 bamabi_guest = {{ path = \"{w}/crates/bamabi_guest\" }}\n"
            ));
        }
    }
    if let Some(tools) = &tools_local {
        let t = tools.display();
        cfg.push_str(&format!(
            "\n[patch.\"https://github.com/yaga-simha/bamabi-tools.git\"]\n\
             bamabi_manifest = {{ path = \"{t}/crates/bamabi_manifest\" }}\n\
             bamabi_trust = {{ path = \"{t}/crates/bamabi_trust\" }}\n"
        ));
    }
    if let Some(core) = &core_local {
        let c = core.display();
        cfg.push_str(&format!(
            "\n[patch.\"https://github.com/yaga-simha/bamabi-core.git\"]\n\
             bamabi_host_sys = {{ path = \"{c}/crates/bamabi_host_sys\" }}\n\
             bamabi_host = {{ path = \"{c}/crates/bamabi_host\" }}\n"
        ));
    }

    if !cfg.is_empty() {
        let cargo_dir = crate_dir.join(".cargo");
        fs::create_dir_all(&cargo_dir)
            .map_err(|e| format!("failed creating `{}`: {e}", cargo_dir.display()))?;
        fs::write(cargo_dir.join("config.toml"), cfg)
            .map_err(|e| format!("failed writing `.cargo/config.toml`: {e}"))?;
    } else if !crate_dir.join("Cargo.lock").exists() {
        let ws_lock = ws_root.join("Cargo.lock");
        if ws_lock.exists() {
            fs::copy(&ws_lock, crate_dir.join("Cargo.lock"))
                .map_err(|e| format!("failed copying Cargo.lock: {e}"))?;
        }
    }
    Ok(())
}

/// Writes a `.cargo/config.toml` into `crate_dir` pinning generated guest & native crates to the
/// dynamically resolved `bamabi-wire` revision (ABI `0.3.0`) and preferring sibling
/// local checkouts when present so builds work both offline and in clean CI runners.
pub fn write_local_patch_config(crate_dir: &Path) {
    if let Err(e) = try_write_local_patch_config_with_ws(&workspace_root(), crate_dir) {
        eprintln!("stratac warning: {e}");
    }
}

/// Shared target cache directory for building generated temporary crates rapidly.
#[must_use]
pub fn shared_temp_target_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target")
        .join("strata_generated_cache")
}

/// Constructs a clean `cargo` [`Command`] stripped of outer coverage / wrapper env vars.
#[must_use]
pub fn sanitized_cargo() -> Command {
    let cargo = env::var_os("CARGO")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    for var in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "LLVM_PROFILE_FILE",
        "CARGO_LLVM_COV",
        "CARGO_LLVM_COV_TARGET_DIR",
        "CARGO_LLVM_COV_BUILD_DIR",
        "RUSTC_WRAPPER",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

/// Discovers the host ISO C99 compiler driver (`clang`, `gcc`, or `cc`).
#[must_use]
pub fn find_c_compiler() -> &'static str {
    for cand in ["clang", "gcc", "cc"] {
        if let Ok(out) = Command::new(cand).arg("--version").output()
            && out.status.success()
        {
            return cand;
        }
    }
    "cc"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::OutputFormat;
    use tempfile::TempDir;

    /// Verifies `write_local_patch_config` resolves `bamabi-wire` dynamically without hardcoded
    /// revisions and either creates a valid `.cargo/config.toml` or falls back to `Cargo.lock`.
    #[test]
    fn local_patch_config_is_portable() {
        let _alloc_guard = crate::test_alloc_read_guard();
        let tmp = TempDir::new().unwrap();
        let ws = workspace_root();
        let expected_rev = resolve_wire_rev(&ws).expect("workspace resolves wire rev");
        write_local_patch_config(tmp.path());
        let cfg_path = tmp.path().join(".cargo").join("config.toml");
        if let Ok(text) = fs::read_to_string(&cfg_path) {
            if cargo_lock_has_git_wire_source(&ws) {
                assert!(text.contains(&expected_rev));
            } else {
                assert!(text.contains("bamabi-wire/crates/bamabi_sys"));
            }
        }
    }

    /// Verifies `resolve_wire_rev` resolves `abi-lock.toml` overrides, `Cargo.lock` `bamabi_sys`
    /// fallback, and rejects missing/invalid revisions.
    #[test]
    fn resolve_wire_rev_reads_abi_lock_and_cargo_lock() {
        let _alloc_guard = crate::test_alloc_read_guard();
        let tmp = TempDir::new().unwrap();

        // Missing both files fails cleanly.
        assert!(resolve_wire_rev(tmp.path()).is_err());

        // `Cargo.lock` fallback extracts `bamabi_sys` git rev even when `abi-lock.toml` omits `wire_rev`.
        fs::write(
            tmp.path().join("abi-lock.toml"),
            "[project]\nname = \"test\"\n",
        )
        .unwrap();
        fs::write(
            tmp.path().join("Cargo.lock"),
            r#"
[[package]]
name = "other_crate"
version = "0.1.0"
source = "git+https://github.com/yaga-simha/bamabi-wire.git?branch=main#0123456789abcdef0123456789abcdef01234567"

[[package]]
name = "bamabi_sys"
version = "0.3.0"
source = "git+https://github.com/yaga-simha/bamabi-wire.git?branch=main#fedcba9876543210fedcba9876543210fedcba98"
"#,
        )
        .unwrap();
        assert_eq!(
            resolve_wire_rev(tmp.path()).unwrap(),
            "fedcba9876543210fedcba9876543210fedcba98"
        );

        // Explicit `wire_rev` in `abi-lock.toml` takes precedence over `Cargo.lock`.
        fs::write(
            tmp.path().join("abi-lock.toml"),
            "[abi]\nwire_rev = \"abcdef0123456789abcdef0123456789abcdef01\"\n",
        )
        .unwrap();
        assert_eq!(
            resolve_wire_rev(tmp.path()).unwrap(),
            "abcdef0123456789abcdef0123456789abcdef01"
        );

        // Invalid `wire_rev` fails cleanly.
        fs::write(
            tmp.path().join("abi-lock.toml"),
            "[abi]\nwire_rev = \"not-hex\"\n",
        )
        .unwrap();
        assert!(resolve_wire_rev(tmp.path()).is_err());
    }

    /// Verifies `cmd_check` fails with `EXIT_COMPILE_ERROR` on invalid paths or semantic errors.
    #[test]
    fn cmd_check_reports_errors_deterministically() {
        let _alloc_guard = crate::test_alloc_read_guard();
        let (code, _) = cmd_check(Path::new("/nonexistent_file.strata"), OutputFormat::Json);
        assert_eq!(code, EXIT_COMPILE_ERROR);
    }

    /// Verifies Rust API key validation rejects missing, conflicting, nonexistent, and invalid keys
    /// for both `cmd_build_with_key` and `cmd_watch_with_key`.
    #[test]
    fn cmd_build_and_watch_signing_validation_rejects_missing_or_conflicting_keys() {
        let _alloc_guard = crate::test_alloc_read_guard();
        let tmp = TempDir::new().unwrap();
        let src_path = tmp.path().join("mini.strata");
        fs::write(
            &src_path,
            "module test::mini @version(1.0.0);\ncomponent P { x: f32 = 0.0 }\nsys step() {}\nschedule FixedUpdate { step }\n",
        )
        .unwrap();

        let kp = bamabi_trust::write_openssh_keypair(&tmp.path().join("id"), Some("test")).unwrap();

        // Missing key & `--ephemeral-key` fails when signing/packaging.
        let (c1, _) = cmd_build(
            &src_path,
            false,
            BuildTarget::Jit,
            None,
            false,
            true,
            OutputFormat::Json,
        );
        assert_eq!(c1, EXIT_COMPILE_ERROR);
        let (c2, _) = cmd_build(
            &src_path,
            false,
            BuildTarget::Jit,
            None,
            true,
            false,
            OutputFormat::Json,
        );
        assert_eq!(c2, EXIT_COMPILE_ERROR);
        let (c3, _) = cmd_watch(&src_path, true, true, OutputFormat::Json);
        assert_eq!(c3, EXIT_COMPILE_ERROR);

        // Conflict (`--key` + `--ephemeral-key`) fails even when unsigned.
        let (c4, _) = cmd_build_with_key(
            &src_path,
            false,
            BuildTarget::Jit,
            None,
            false,
            false,
            Some(&kp.private_key),
            true,
            OutputFormat::Json,
        );
        assert_eq!(c4, EXIT_COMPILE_ERROR);
        let (c5, _) = cmd_watch_with_key(
            &src_path,
            true,
            Some(&kp.private_key),
            true,
            true,
            OutputFormat::Json,
        );
        assert_eq!(c5, EXIT_COMPILE_ERROR);

        // Nonexistent key file fails cleanly.
        let missing_key = tmp.path().join("does_not_exist.key");
        let (c6, _) = cmd_build_with_key(
            &src_path,
            false,
            BuildTarget::Jit,
            None,
            false,
            true,
            Some(&missing_key),
            false,
            OutputFormat::Json,
        );
        assert_eq!(c6, EXIT_COMPILE_ERROR);

        // Corrupt key file fails cleanly.
        let bad_key = tmp.path().join("bad.key");
        fs::write(&bad_key, "not an openssh key").unwrap();
        let (c7, _) = cmd_watch_with_key(
            &src_path,
            true,
            Some(&bad_key),
            false,
            true,
            OutputFormat::Json,
        );
        assert_eq!(c7, EXIT_COMPILE_ERROR);
    }

    /// Verifies `WatchSession` Salsa `SourceFile::set_text` reuse, zero-JIT schedule-only delta
    /// emission targeting `ModScheduleSetRewirePass`, and fallback on `run_if` / body / unknown
    /// system / cross-schedule / deleted `.dylib` / syntax errors.
    #[test]
    fn watch_session_salsa_reuse_and_schedule_delta_fast_path() {
        let _alloc_guard = crate::test_alloc_read_guard();
        let tmp = TempDir::new().unwrap();
        let src_path = tmp.path().join("watch_test.strata");
        let s1 = r#"
module test::watch_delta @version(1.0.0);
component Pos { x: f32 = 0.0 }
sys sys_a() {
    for e in query(p: &mut Pos) { e.p.x += 1.0; }
}
sys sys_b() {
    for e in query(p: &mut Pos) { e.p.x += 2.0; }
}
schedule FixedUpdate {
    seq MainSeq { sys_a, sys_b }
}
"#;
        fs::write(&src_path, s1).unwrap();

        let mut session = WatchSession::new(&src_path, false, None, false).unwrap();

        // Cycle 1: initial build emits `.dylib`.
        let r1 = session.rebuild_from_source(s1).expect("cycle 1 succeeds");
        assert!(!r1.schedule_delta_only);
        assert!(!r1.salsa_layout_recomputed);
        assert!(r1.schedule_delta_path.is_none());
        let dylib_path = PathBuf::from(&r1.dylib_path);
        assert!(dylib_path.exists());
        let dylib_bytes_1 = fs::read(&dylib_path).unwrap();
        let dylib_mtime_1 = fs::metadata(&dylib_path).unwrap().modified().unwrap();

        // Cycle 2: schedule-only reorder (`seq MainSeq { sys_b, sys_a }`) skips JIT & emits delta.
        let s2 = r#"
module test::watch_delta @version(1.0.0);
component Pos { x: f32 = 0.0 }
sys sys_a() {
    for e in query(p: &mut Pos) { e.p.x += 1.0; }
}
sys sys_b() {
    for e in query(p: &mut Pos) { e.p.x += 2.0; }
}
schedule FixedUpdate {
    seq MainSeq { sys_b, sys_a }
}
"#;
        let r2 = session.rebuild_from_source(s2).expect("cycle 2 succeeds");
        assert!(r2.schedule_delta_only);
        assert!(!r2.salsa_layout_recomputed);
        assert_eq!(fs::read(&dylib_path).unwrap(), dylib_bytes_1);
        assert_eq!(
            fs::metadata(&dylib_path).unwrap().modified().unwrap(),
            dylib_mtime_1
        );
        let delta_path = PathBuf::from(r2.schedule_delta_path.as_ref().unwrap());
        assert!(delta_path.exists());
        let delta: ScheduleDeltaArtifact =
            serde_json::from_slice(&fs::read(&delta_path).unwrap()).unwrap();
        assert_eq!(delta.target_pass, "ModScheduleSetRewirePass");
        assert_eq!(delta.abi_version, ABI_VERSION);
        assert_eq!(delta.sets.len(), 1);
        assert_eq!(delta.sets[0].mode, ScheduleDeltaMode::Sequence);
        assert_eq!(delta.sets[0].flags, BAM_SCHEDULE_SET_FLAG_SEQUENCE);
        assert_eq!(delta.sets[0].mounted_systems, vec!["sys_b", "sys_a"]);
        assert!(!delta.requires_set_registration);

        // Cycle 3: mode switch (`par MainSeq { sys_b, sys_a }`) also stays on schedule-delta fast path.
        let s3 = s2.replace("seq MainSeq", "par MainSeq");
        let r3 = session.rebuild_from_source(&s3).expect("cycle 3 succeeds");
        assert!(r3.schedule_delta_only);
        assert!(!r3.salsa_layout_recomputed);
        let delta3: ScheduleDeltaArtifact =
            serde_json::from_slice(&fs::read(&delta_path).unwrap()).unwrap();
        assert_eq!(delta3.sets[0].mode, ScheduleDeltaMode::Parallel);
        assert_eq!(delta3.sets[0].flags, BAM_SCHEDULE_SET_FLAG_PARALLEL);
        if !cfg!(debug_assertions) {
            assert!(
                r3.rebuild_ms < 0.4,
                "release schedule-only delta took {:.3} ms (>= 0.4 ms)",
                r3.rebuild_ms
            );
        }

        // Cycle 4: body-only edit after schedule-only edit triggers full JIT (`schedule_delta_only == false`)
        // while keeping `salsa_layout_recomputed == false`.
        let s4 = s3.replace("e.p.x += 1.0;", "e.p.x += 3.0;");
        let r4 = session.rebuild_from_source(&s4).expect("cycle 4 succeeds");
        assert!(!r4.schedule_delta_only);
        assert!(!r4.salsa_layout_recomputed);

        // Cycle 5: second consecutive body-only edit hits Salsa early cutoff (`resolve_layouts` skipped).
        let s5 = s4.replace("e.p.x += 2.0;", "e.p.x += 4.0;");
        let r5 = session.rebuild_from_source(&s5).expect("cycle 5 succeeds");
        assert!(!r5.schedule_delta_only);
        assert!(!r5.salsa_layout_recomputed);

        // Cycle 6: component schema edit triggers Salsa layout recomputation.
        let s6 = s5.replace(
            "component Pos { x: f32 = 0.0 }",
            "component Pos { x: f32 = 0.0, y: f32 = 0.0 }",
        );
        let r6 = session.rebuild_from_source(&s6).expect("cycle 6 succeeds");
        assert!(!r6.schedule_delta_only);
        assert!(r6.salsa_layout_recomputed);

        // Cycle 7: `run_if(...)` addition/edit must trigger full JIT (`schedule_delta_only == false`).
        let s7 = s6.replace(
            "schedule FixedUpdate {",
            "schedule FixedUpdate run_if(true) {",
        );
        let r7 = session.rebuild_from_source(&s7).expect("cycle 7 succeeds");
        assert!(!r7.schedule_delta_only);

        // Cycle 8: unknown system in `schedule` falls back to full path (`schedule_delta_only == false`).
        let s8 = s7.replace(
            "par MainSeq { sys_b, sys_a }",
            "par MainSeq { sys_b, nonexistent_sys }",
        );
        let r8 = session.rebuild_from_source(&s8).expect("cycle 8 succeeds");
        assert!(!r8.schedule_delta_only);

        // Restore valid schedule for Cycle 9/10 checks.
        let r_reset = session.rebuild_from_source(&s7).expect("reset succeeds");
        assert!(!r_reset.schedule_delta_only);

        // Cycle 9: cross-schedule move falls back to full JIT (`schedule_delta_only == false`).
        let s9 = s7.replace(
            "par MainSeq { sys_b, sys_a }",
            "par MainSeq { sys_b }\n}\nschedule Update {\n    sys_a",
        );
        let r9 = session.rebuild_from_source(&s9).expect("cycle 9 succeeds");
        assert!(!r9.schedule_delta_only);

        // Cycle 10: deleted `.dylib` + schedule edit falls back to full JIT to recreate `.dylib`.
        fs::remove_file(&dylib_path).unwrap();
        let s10 = s9.replace("par MainSeq", "seq MainSeq");
        let r10 = session
            .rebuild_from_source(&s10)
            .expect("cycle 10 succeeds");
        assert!(!r10.schedule_delta_only);
        assert!(dylib_path.exists());

        // Cycle 11: syntax error returns `EXIT_COMPILE_ERROR`.
        let s11 = s10.replace("seq MainSeq { sys_b }", "seq {");
        let err = session.rebuild_from_source(&s11).unwrap_err();
        assert_eq!(err.0, EXIT_COMPILE_ERROR);
    }
}
