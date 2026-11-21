//! Command implementations for `stratac` (`check`, `fmt`, `layout`, `explain-par`, `test`,
//! `build`, `watch`, `onboard`).

use crate::cli::{BuildTarget, Cli, Commands, OnboardTarget, OutputFormat};
use crate::exit_codes::{
    EXIT_COMPILE_ERROR, EXIT_OK, EXIT_PARITY_OR_ASSERT_FAILED, EXIT_SIM_TEST_FAILED,
};
use bamabi_manifest::ModTomlManifest;
use bamabi_trust::{
    BamPackBuilder, DEFAULT_BAMPACK_NAMESPACE, DEFAULT_SIGNATURE_NAMESPACE, ModTrustPolicy,
    default_signature_path_for, generate_ed25519_keypair, sign_mod_bytes_with_key,
};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime};
use strata_codegen::{
    BevyNativeOptions, RustGuestOptions, emit_bevy_native, emit_c99, module_stem,
};
use strata_jit::{JitCompileOptions, JitOptLevel, compile_module_to_dylib};
use strata_mir::lower_to_mir;
use strata_sema::access::ConcurrencyGraph;
use strata_sema::diagnostics::{Diagnostic, Severity};
use strata_sema::layout::SolvedLayout;
use strata_sema::{SemaDb, analyze_source};
use strata_syntax::fmt::format_source;

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

/// JSON/text report for `stratac watch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchReport {
    /// Source file path.
    pub file: String,
    /// Incremental Salsa layout recomputation required (`false` on body-only edits).
    pub salsa_layout_recomputed: bool,
    /// Schedule-only delta flag.
    pub schedule_delta_only: bool,
    /// Rebuilt shared library path.
    pub dylib_path: String,
    /// Incremental emit + link latency in milliseconds.
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
            format,
        } => cmd_build(
            &file,
            release,
            target,
            out.as_deref(),
            bampack,
            sign,
            format,
        ),
        Commands::Watch {
            file,
            sign,
            once,
            format,
        } => cmd_watch(&file, sign, once, format),
        Commands::Onboard {
            file,
            target,
            out,
            static_console,
            check,
            format,
        } => cmd_onboard(&file, target, &out, static_console, check, format),
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
    let error_count = analyzed
        .diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .count();
    let warning_count = analyzed
        .diagnostics
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
        diagnostics: analyzed.diagnostics,
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
    let tests = crate::sim_runner::run_headless_sim_tests(&mir, &stem);
    #[cfg(not(feature = "sim-runner"))]
    let tests: Vec<SimTestCaseResult> = {
        let _ = stem;
        mir.sim_tests
            .iter()
            .map(|t| SimTestCaseResult {
                name: t.name.clone(),
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

/// Executes `stratac build`.
pub fn cmd_build(
    file: &Path,
    release: bool,
    target: BuildTarget,
    out_dir: Option<&Path>,
    bampack: bool,
    sign: bool,
    format: OutputFormat,
) -> (i32, String) {
    let t0 = Instant::now();
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
            write_local_patch_config(&crate_dir);
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
    let mod_toml_path = out.join("mod.toml");
    let mod_toml_content = format!(
        "[mod]\n\
         id = \"{stem}\"\n\
         version = \"0.3.0\"\n\
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

    if bampack || sign {
        let key = match generate_ed25519_keypair(Some("stratac-ephemeral")) {
            Ok(k) => k,
            Err(e) => return (EXIT_COMPILE_ERROR, format!("keygen failed: {e}")),
        };
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

/// Executes `stratac watch` (supports `--once` for incremental CI verification).
pub fn cmd_watch(file: &Path, sign: bool, once: bool, format: OutputFormat) -> (i32, String) {
    let mut db = SemaDb::default();
    let src = match read_source(file) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let sfile = db.new_source(file.display().to_string(), src.clone());
    let prev_layouts = serde_json::to_string(&db.resolve_layouts(sfile)).unwrap_or_default();
    let _ = db.take_executed_queries();

    let run_cycle = |db: &mut SemaDb,
                     cur_src: &str,
                     prev_json: &mut String|
     -> Result<WatchReport, (i32, String)> {
        let t0 = Instant::now();
        let sf = db.new_source(file.display().to_string(), cur_src.to_owned());
        let analyzed = db.analyze_file(sf);
        if !analyzed.ok() {
            return Err((
                EXIT_COMPILE_ERROR,
                serde_json::to_string_pretty(&analyzed.diagnostics).unwrap_or_default(),
            ));
        }
        let next_layouts_json = serde_json::to_string(&db.resolve_layouts(sf)).unwrap_or_default();
        let executed = db.take_executed_queries();
        let salsa_layout_recomputed = next_layouts_json != *prev_json
            && executed.iter().any(|q| q.contains("resolve_layouts_json"));
        *prev_json = next_layouts_json;

        let mir = lower_to_mir(&analyzed);
        let stem = module_stem(&mir.module_path);
        let out_dir = file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(format!("target_strata_watch_{stem}"));

        let art = compile_module_to_dylib(
            &mir,
            &JitCompileOptions {
                out_dir,
                module_stem: stem,
                opt_level: JitOptLevel::FastCompile,
            },
        )
        .map_err(|e| (EXIT_COMPILE_ERROR, format!("JIT watch rebuild failed: {e}")))?;

        if sign
            && let Ok(key) = generate_ed25519_keypair(Some("stratac-watch"))
            && let Ok(bytes) = fs::read(&art.dylib_path)
            && let Ok(pem) = sign_mod_bytes_with_key(&key, DEFAULT_SIGNATURE_NAMESPACE, &bytes)
        {
            let _ = fs::write(default_signature_path_for(&art.dylib_path), pem);
        }

        let rebuild_ms = t0.elapsed().as_secs_f64() * 1000.0;
        Ok(WatchReport {
            file: file.display().to_string(),
            salsa_layout_recomputed,
            schedule_delta_only: !salsa_layout_recomputed && mir.functions.is_empty(),
            dylib_path: art.dylib_path.display().to_string(),
            rebuild_ms,
        })
    };

    let mut prev_json = prev_layouts;
    match run_cycle(&mut db, &src, &mut prev_json) {
        Ok(first) => {
            if once {
                let text = match format {
                    OutputFormat::Json => serde_json::to_string_pretty(&first).unwrap_or_default(),
                    OutputFormat::Text => format!(
                        "watch pass: {} rebuilt in {:.2} ms (layout_changed={})",
                        first.dylib_path, first.rebuild_ms, first.salsa_layout_recomputed
                    ),
                };
                return (EXIT_OK, text);
            }
        }
        Err(e) => return e,
    }

    // Live polling loop when `--once` is omitted cleanly.
    let mut last_mtime = fs::metadata(file)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH);
    loop {
        std::thread::sleep(std::time::Duration::from_millis(120));
        if let Ok(meta) = fs::metadata(file)
            && let Ok(mt) = meta.modified()
            && mt != last_mtime
        {
            last_mtime = mt;
            if let Ok(cur_src) = fs::read_to_string(file) {
                let _ = run_cycle(&mut db, &cur_src, &mut prev_json);
            }
        }
    }
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
    write_local_patch_config(out_dir);

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

/// Writes a `.cargo/config.toml` into `crate_dir` pinning generated guest & native crates to the
/// stabilized `bamabi-wire` revision (`7a32b7bd`, 68-slot ABI `0.3.0`) and preferring sibling
/// local checkouts when present so builds work both offline and in clean CI runners.
pub fn write_local_patch_config(crate_dir: &Path) {
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let wire_local = fs::canonicalize(ws_root.join("..").join("bamabi-wire")).ok();
    let tools_local = fs::canonicalize(ws_root.join("..").join("bamabi-tools")).ok();
    let core_local = fs::canonicalize(ws_root.join("..").join("bamabi-core")).ok();

    const WIRE_REV: &str = "7a32b7bd329167c8dda82259659b3da54a5ab748";
    let mut cfg = String::new();
    if let Some(wire) = &wire_local {
        let w = wire.display();
        cfg.push_str(&format!(
            "[patch.\"https://github.com/yaga-simha/bamabi-wire.git\"]\n\
             bamabi_sys = {{ git = \"file://{w}\", rev = \"{WIRE_REV}\" }}\n\
             bamabi_macros = {{ git = \"file://{w}\", rev = \"{WIRE_REV}\" }}\n\
             bamabi_sdk_gen = {{ git = \"file://{w}\", rev = \"{WIRE_REV}\" }}\n\
             bamabi_guest_sys = {{ git = \"file://{w}\", rev = \"{WIRE_REV}\" }}\n\
             bamabi_guest = {{ git = \"file://{w}\", rev = \"{WIRE_REV}\" }}\n"
        ));
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
        let _ = fs::create_dir_all(&cargo_dir);
        let _ = fs::write(cargo_dir.join("config.toml"), cfg);
    } else if !crate_dir.join("Cargo.lock").exists() {
        let ws_lock = ws_root.join("Cargo.lock");
        if ws_lock.exists() {
            let _ = fs::copy(ws_lock, crate_dir.join("Cargo.lock"));
        }
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

    /// Verifies `write_local_patch_config` never emits machine-specific home paths and either
    /// creates a valid `.cargo/config.toml` or falls back to copying `Cargo.lock`.
    #[test]
    fn local_patch_config_is_portable() {
        let tmp = TempDir::new().unwrap();
        write_local_patch_config(tmp.path());
        let cfg_path = tmp.path().join(".cargo").join("config.toml");
        if let Ok(text) = fs::read_to_string(&cfg_path) {
            assert!(text.contains("7a32b7bd329167c8dda82259659b3da54a5ab748"));
        }
    }

    /// Verifies `cmd_check` fails with `EXIT_COMPILE_ERROR` on invalid paths or semantic errors.
    #[test]
    fn cmd_check_reports_errors_deterministically() {
        let (code, _) = cmd_check(Path::new("/nonexistent_file.strata"), OutputFormat::Json);
        assert_eq!(code, EXIT_COMPILE_ERROR);
    }
}
