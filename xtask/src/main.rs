#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Zero-external-dependency CI, verification, and benchmark runner (`cargo xtask`) for
//! `bamabi-strata`.
//!
//! Invoked directly from local development shells and `.github/workflows/{ci,nightly}.yml`.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const BEVY_FREE_CRATES: &[&str] = &[
    "strata_syntax",
    "strata_sema",
    "strata_mir",
    "strata_codegen",
    "strata_jit",
    "strata_lsp",
    "strata_docs",
    "xtask",
];

const WORKSPACE_CRATES_ENTRYPOINTS: &[(&str, &str)] = &[
    ("strata_syntax", "crates/strata_syntax/src/lib.rs"),
    ("bamabi_native_rt", "crates/bamabi_native_rt/src/lib.rs"),
    ("strata_sema", "crates/strata_sema/src/lib.rs"),
    ("strata_mir", "crates/strata_mir/src/lib.rs"),
    ("strata_codegen", "crates/strata_codegen/src/lib.rs"),
    ("strata_jit", "crates/strata_jit/src/lib.rs"),
    ("strata_lsp", "crates/strata_lsp/src/lib.rs"),
    ("strata_lsp-bin", "crates/strata_lsp/src/main.rs"),
    ("stratac", "crates/stratac/src/lib.rs"),
    ("stratac-bin", "crates/stratac/src/main.rs"),
    ("strata_docs", "crates/strata_docs/src/lib.rs"),
    ("strata_bench", "benches/strata_bench/src/main.rs"),
    ("xtask", "xtask/src/main.rs"),
];

const PROPTEST_TARGETS: &[(&str, &str)] = &[
    ("bamabi_native_rt", "proptest_native_rt"),
    ("strata_syntax", "proptest_syntax"),
    ("strata_sema", "proptest_sema"),
    ("strata_mir", "proptest_mir"),
    ("strata_lsp", "proptest_lsp"),
];

const KANI_TARGETS: &[(&str, &[&str])] = &[
    (
        "bamabi_native_rt",
        &["--no-default-features", "--features", "static-console"],
    ),
    ("strata_sema", &[]),
    ("strata_mir", &[]),
    ("strata_jit", &[]),
    ("strata_lsp", &[]),
];

const PINNED_WIRE_REV: &str = "7a32b7bd329167c8dda82259659b3da54a5ab748";
const BENCH_START: &str = "<!-- BENCHMARK_REPORT_START -->";
const BENCH_END: &str = "<!-- BENCHMARK_REPORT_END -->";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Task {
    Help,
    Fmt {
        fix: bool,
    },
    Lint,
    Test {
        unit: bool,
        integration: bool,
        proptest: bool,
        cases: u32,
        doc: bool,
        static_console: bool,
        no_default_features: bool,
    },
    Kani {
        crate_filter: Option<String>,
        timeout_secs: u64,
    },
    Bench {
        quick: bool,
        suite: String,
        write_docs: bool,
        no_write_docs: bool,
        check_docs: bool,
        json_path: Option<PathBuf>,
    },
    Audit {
        skip_typos: bool,
        skip_deny: bool,
    },
    Nightly {
        cases: u32,
    },
    Ci {
        no_bench: bool,
        full: bool,
    },
}

fn parse_args(args: &[String]) -> Result<Task, String> {
    let Some(cmd) = args.first().map(String::as_str) else {
        return Ok(Task::Help);
    };
    let rest = &args[1..];
    match cmd {
        "-h" | "--help" | "help" => Ok(Task::Help),
        "fmt" => {
            let mut fix = false;
            for a in rest {
                match a.as_str() {
                    "--fix" => fix = true,
                    other => return Err(format!("unknown flag `{other}` for `fmt`")),
                }
            }
            Ok(Task::Fmt { fix })
        }
        "lint" => {
            if !rest.is_empty() {
                return Err(format!("unknown flags for `lint`: {}", rest.join(" ")));
            }
            Ok(Task::Lint)
        }
        "test" => {
            let mut unit = false;
            let mut integration = false;
            let mut proptest = false;
            let mut cases = 256u32;
            let mut doc = false;
            let mut static_console = false;
            let mut no_default_features = false;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--unit" => unit = true,
                    "--integration" => integration = true,
                    "--proptest" => proptest = true,
                    "--doc" => doc = true,
                    "--static-console" => static_console = true,
                    "--no-default-features" => no_default_features = true,
                    "--cases" => {
                        i += 1;
                        let val = rest.get(i).ok_or("--cases requires a positive integer")?;
                        cases = val
                            .parse::<u32>()
                            .map_err(|_| format!("invalid --cases integer `{val}`"))?;
                    }
                    other => return Err(format!("unknown flag `{other}` for `test`")),
                }
                i += 1;
            }
            Ok(Task::Test {
                unit,
                integration,
                proptest,
                cases,
                doc,
                static_console,
                no_default_features,
            })
        }
        "kani" => {
            let mut crate_filter = None;
            let mut timeout_secs = 300u64;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--crate" => {
                        i += 1;
                        let v = rest.get(i).ok_or("--crate requires a crate name")?;
                        crate_filter = Some(v.clone());
                    }
                    "--timeout" => {
                        i += 1;
                        let v = rest.get(i).ok_or("--timeout requires seconds")?;
                        timeout_secs = v
                            .parse::<u64>()
                            .map_err(|_| format!("invalid --timeout `{v}`"))?;
                    }
                    other => return Err(format!("unknown flag `{other}` for `kani`")),
                }
                i += 1;
            }
            Ok(Task::Kani {
                crate_filter,
                timeout_secs,
            })
        }
        "bench" => {
            let mut quick = false;
            let mut suite = "all".to_owned();
            let mut write_docs = false;
            let mut no_write_docs = false;
            let mut check_docs = false;
            let mut json_path = None;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--quick" => quick = true,
                    "--write-docs" => write_docs = true,
                    "--no-write-docs" => no_write_docs = true,
                    "--check-docs" => check_docs = true,
                    "--suite" => {
                        i += 1;
                        let v = rest
                            .get(i)
                            .ok_or("--suite requires <all|compiler|runtime>")?;
                        if !matches!(v.as_str(), "all" | "compiler" | "runtime") {
                            return Err(format!("invalid --suite `{v}`"));
                        }
                        suite = v.clone();
                    }
                    "--json" => {
                        i += 1;
                        let p = rest.get(i).ok_or("--json requires a file path")?;
                        json_path = Some(PathBuf::from(p));
                    }
                    other => return Err(format!("unknown flag `{other}` for `bench`")),
                }
                i += 1;
            }
            if write_docs && no_write_docs {
                return Err("--write-docs and --no-write-docs are mutually exclusive".to_owned());
            }
            if check_docs && write_docs {
                return Err("--check-docs and --write-docs are mutually exclusive".to_owned());
            }
            Ok(Task::Bench {
                quick,
                suite,
                write_docs,
                no_write_docs,
                check_docs,
                json_path,
            })
        }
        "audit" => {
            let mut skip_typos = false;
            let mut skip_deny = false;
            for a in rest {
                match a.as_str() {
                    "--skip-typos" => skip_typos = true,
                    "--skip-deny" => skip_deny = true,
                    other => return Err(format!("unknown flag `{other}` for `audit`")),
                }
            }
            Ok(Task::Audit {
                skip_typos,
                skip_deny,
            })
        }
        "nightly" => {
            let mut cases = 1024u32;
            let mut i = 0usize;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--cases" => {
                        i += 1;
                        let v = rest.get(i).ok_or("--cases requires an integer")?;
                        cases = v
                            .parse::<u32>()
                            .map_err(|_| format!("invalid --cases `{v}`"))?;
                    }
                    other => return Err(format!("unknown flag `{other}` for `nightly`")),
                }
                i += 1;
            }
            Ok(Task::Nightly { cases })
        }
        "ci" => {
            let mut no_bench = false;
            let mut full = false;
            for a in rest {
                match a.as_str() {
                    "--no-bench" => no_bench = true,
                    "--full" => full = true,
                    other => return Err(format!("unknown flag `{other}` for `ci`")),
                }
            }
            Ok(Task::Ci { no_bench, full })
        }
        other => Err(format!("unknown subcommand `{other}` (run `--help`)")),
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".."))
}

fn cargo_bin() -> String {
    env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned())
}

fn run_checked(cmd: &mut Command, label: &str) -> Result<(), String> {
    println!("==> {label}");
    let status = cmd
        .status()
        .map_err(|e| format!("failed spawning `{label}`: {e}"))?;
    if !status.success() {
        return Err(format!(
            "`{label}` failed with exit code {:?}",
            status.code()
        ));
    }
    Ok(())
}

fn run_capture(cmd: &mut Command, label: &str) -> Result<String, String> {
    let out = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("failed running `{label}`: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`{label}` failed ({:?}):\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn has_non_bamabi_bevy_line(tree_output: &str) -> Option<String> {
    for line in tree_output.lines() {
        let pkg = line
            .trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
            .split(' ')
            .next()
            .unwrap_or("");
        let lower = pkg.to_ascii_lowercase();
        if lower.contains("bevy") && !lower.contains("bamabi") {
            return Some(pkg.to_owned());
        }
    }
    None
}

fn verify_benchmark_docs_str(md: &str) -> Result<(), String> {
    let start_idx = md
        .find(BENCH_START)
        .ok_or_else(|| format!("BENCHMARKS.md missing start marker `{BENCH_START}`"))?;
    let end_idx = md
        .find(BENCH_END)
        .ok_or_else(|| format!("BENCHMARKS.md missing end marker `{BENCH_END}`"))?;
    if end_idx <= start_idx {
        return Err("BENCHMARKS.md markers are out of order".to_owned());
    }
    let inner = md[start_idx + BENCH_START.len()..end_idx].trim();
    if inner.is_empty() {
        return Err("BENCHMARKS.md report block between markers is empty".to_owned());
    }
    if !inner.contains("Compiler & Frontend Pipeline Latency")
        || !inner.contains("4-Tier Execution Throughput")
    {
        return Err(
            "BENCHMARKS.md report missing required compiler/runtime summary sections".to_owned(),
        );
    }
    Ok(())
}

fn splice_benchmark_docs_str(existing: &str, report_md: &str) -> Result<String, String> {
    let start_idx = existing
        .find(BENCH_START)
        .ok_or_else(|| format!("BENCHMARKS.md missing `{BENCH_START}`"))?;
    let end_idx = existing
        .find(BENCH_END)
        .ok_or_else(|| format!("BENCHMARKS.md missing `{BENCH_END}`"))?;
    if end_idx < start_idx {
        return Err("BENCHMARKS.md markers out of order".to_owned());
    }
    let prefix = &existing[..start_idx + BENCH_START.len()];
    let suffix = &existing[end_idx..];
    Ok(format!("{prefix}\n{}\n{suffix}", report_md.trim()))
}

fn parse_quoted_kv<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(after) = trimmed.strip_prefix(key) {
            let after = after.trim_start();
            if let Some(rhs) = after.strip_prefix('=') {
                let rhs = rhs.trim();
                if let Some(quoted) = rhs.strip_prefix('"')
                    && let Some(end) = quoted.find('"')
                {
                    return Some(&quoted[..end]);
                }
            }
        }
    }
    None
}

fn cmd_fmt(ws: &Path, fix: bool) -> Result<(), String> {
    let mut cmd = Command::new(cargo_bin());
    cmd.current_dir(ws).args(["fmt", "--all"]);
    if !fix {
        cmd.args(["--", "--check"]);
    }
    run_checked(
        &mut cmd,
        if fix {
            "cargo fmt --all"
        } else {
            "cargo fmt --all -- --check"
        },
    )
}

fn cmd_lint(ws: &Path) -> Result<(), String> {
    // 1. Policy header check (`#![forbid(unsafe_code)]` & `#![warn(missing_docs)]`) across all crates.
    for &(name, rel_path) in WORKSPACE_CRATES_ENTRYPOINTS {
        let full = ws.join(rel_path);
        let src = fs::read_to_string(&full)
            .map_err(|e| format!("failed reading {rel_path} ({name}): {e}"))?;
        if !src.contains("#![forbid(unsafe_code)]") {
            return Err(format!(
                "crate `{name}` (`{rel_path}`) missing `#![forbid(unsafe_code)]`"
            ));
        }
        if !src.contains("#![warn(missing_docs)]") {
            return Err(format!(
                "crate `{name}` (`{rel_path}`) missing `#![warn(missing_docs)]`"
            ));
        }
    }

    // 2. Zero-Bevy isolation across all 8 Bevy-free crates.
    for &pkg in BEVY_FREE_CRATES {
        let mut cmd = Command::new(cargo_bin());
        cmd.current_dir(ws).args(["tree", "-p", pkg]);
        let tree = run_capture(&mut cmd, &format!("cargo tree -p {pkg}"))?;
        if let Some(bad) = has_non_bamabi_bevy_line(&tree) {
            return Err(format!(
                "zero-Bevy invariant violated: `{pkg}` transitively depends on `{bad}`"
            ));
        }
    }

    // 3. Zero dynamic-loader dependencies under `bamabi_native_rt --features static-console`.
    let mut sc_tree_cmd = Command::new(cargo_bin());
    sc_tree_cmd.current_dir(ws).args([
        "tree",
        "-p",
        "bamabi_native_rt",
        "--no-default-features",
        "--features",
        "static-console",
    ]);
    let sc_tree = run_capture(&mut sc_tree_cmd, "cargo tree static-console")?;
    if sc_tree.contains("libloading") || sc_tree.contains("bamabi_host") {
        return Err(
            "`bamabi_native_rt` static-console profile pulled in libloading/bamabi_host".to_owned(),
        );
    }

    // 4. Strict workspace clippy & rustdoc + profile feature matrix checks.
    run_checked(
        Command::new(cargo_bin()).current_dir(ws).args([
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ]),
        "cargo clippy --workspace --all-targets --all-features -- -D warnings",
    )?;
    run_checked(
        Command::new(cargo_bin())
            .current_dir(ws)
            .env("RUSTDOCFLAGS", "-D warnings")
            .args(["doc", "--workspace", "--no-deps", "--all-features"]),
        "RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --all-features",
    )?;
    run_checked(
        Command::new(cargo_bin()).current_dir(ws).args([
            "check",
            "-p",
            "bamabi_native_rt",
            "--no-default-features",
            "--features",
            "static-console",
        ]),
        "cargo check -p bamabi_native_rt --static-console",
    )?;
    run_checked(
        Command::new(cargo_bin()).current_dir(ws).args([
            "check",
            "-p",
            "stratac",
            "--no-default-features",
        ]),
        "cargo check -p stratac --no-default-features",
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_test(
    ws: &Path,
    unit: bool,
    integration: bool,
    proptest: bool,
    cases: u32,
    doc: bool,
    static_console: bool,
    no_default_features: bool,
) -> Result<(), String> {
    let filtered = unit || integration || proptest || doc || static_console || no_default_features;
    if !filtered {
        run_checked(
            Command::new(cargo_bin()).current_dir(ws).args([
                "test",
                "--workspace",
                "--all-features",
            ]),
            "cargo test --workspace --all-features",
        )?;
        run_checked(
            Command::new(cargo_bin()).current_dir(ws).args([
                "test",
                "-p",
                "bamabi_native_rt",
                "--no-default-features",
                "--features",
                "static-console",
            ]),
            "cargo test -p bamabi_native_rt --static-console",
        )?;
        run_checked(
            Command::new(cargo_bin()).current_dir(ws).args([
                "test",
                "--doc",
                "--workspace",
                "--all-features",
            ]),
            "cargo test --doc --workspace --all-features",
        )?;
        return Ok(());
    }

    if unit {
        run_checked(
            Command::new(cargo_bin()).current_dir(ws).args([
                "test",
                "--workspace",
                "--lib",
                "--bins",
                "--all-features",
            ]),
            "cargo test --workspace --lib --bins --all-features",
        )?;
    }
    if integration {
        run_checked(
            Command::new(cargo_bin()).current_dir(ws).args([
                "test",
                "--workspace",
                "--tests",
                "--all-features",
            ]),
            "cargo test --workspace --tests --all-features",
        )?;
    }
    if proptest {
        let cstr = cases.to_string();
        for &(pkg, test_name) in PROPTEST_TARGETS {
            run_checked(
                Command::new(cargo_bin())
                    .current_dir(ws)
                    .env("PROPTEST_CASES", &cstr)
                    .args(["test", "-p", pkg, "--test", test_name, "--all-features"]),
                &format!("PROPTEST_CASES={cstr} cargo test -p {pkg} --test {test_name}"),
            )?;
        }
    }
    if static_console {
        run_checked(
            Command::new(cargo_bin()).current_dir(ws).args([
                "test",
                "-p",
                "bamabi_native_rt",
                "--no-default-features",
                "--features",
                "static-console",
            ]),
            "cargo test -p bamabi_native_rt --static-console",
        )?;
    }
    if no_default_features {
        run_checked(
            Command::new(cargo_bin()).current_dir(ws).args([
                "check",
                "-p",
                "stratac",
                "--no-default-features",
            ]),
            "cargo check -p stratac --no-default-features",
        )?;
    }
    if doc {
        run_checked(
            Command::new(cargo_bin()).current_dir(ws).args([
                "test",
                "--doc",
                "--workspace",
                "--all-features",
            ]),
            "cargo test --doc --workspace --all-features",
        )?;
    }
    Ok(())
}

fn cmd_kani(ws: &Path, crate_filter: Option<&str>, timeout_secs: u64) -> Result<(), String> {
    let mut ran_any = false;
    let timeout_arg = format!("{timeout_secs}s");
    for &(pkg, extra_flags) in KANI_TARGETS {
        if let Some(f) = crate_filter
            && f != pkg
        {
            continue;
        }
        ran_any = true;
        let mut cmd = Command::new(cargo_bin());
        cmd.current_dir(ws).args([
            "kani",
            "-p",
            pkg,
            "-Z",
            "unstable-options",
            "--harness-timeout",
            &timeout_arg,
            "--output-format",
            "terse",
            "-j",
        ]);
        cmd.args(extra_flags);
        run_checked(&mut cmd, &format!("cargo kani -p {pkg}"))?;
    }
    if !ran_any {
        return Err(format!(
            "no Kani harnesses registered for `{}`",
            crate_filter.unwrap_or("")
        ));
    }
    Ok(())
}

fn cmd_bench(
    ws: &Path,
    quick: bool,
    suite: &str,
    write_docs: bool,
    no_write_docs: bool,
    check_docs: bool,
    json_path: Option<&Path>,
) -> Result<(), String> {
    let docs_path = ws.join("BENCHMARKS.md");
    if check_docs {
        let body =
            fs::read_to_string(&docs_path).map_err(|e| format!("read BENCHMARKS.md: {e}"))?;
        verify_benchmark_docs_str(&body)?;
        println!("==> BENCHMARKS.md markers and report sections valid.");
        return Ok(());
    }

    let md_out = ws.join("target").join("bench-summary.md");
    let mut cmd = Command::new(cargo_bin());
    cmd.current_dir(ws).args([
        "run",
        "--release",
        "-p",
        "strata_bench",
        "--",
        "--suite",
        suite,
        "--markdown",
    ]);
    cmd.arg(&md_out);
    if quick {
        cmd.arg("--quick");
    }
    if let Some(jp) = json_path {
        cmd.arg("--json").arg(jp);
    }
    run_checked(&mut cmd, "cargo run --release -p strata_bench")?;

    let should_write = write_docs || (!no_write_docs && !quick && suite == "all");
    if should_write {
        let report_md =
            fs::read_to_string(&md_out).map_err(|e| format!("read {}: {e}", md_out.display()))?;
        let existing = fs::read_to_string(&docs_path)
            .map_err(|e| format!("read {}: {e}", docs_path.display()))?;
        let updated = splice_benchmark_docs_str(&existing, &report_md)?;
        fs::write(&docs_path, updated).map_err(|e| format!("write BENCHMARKS.md: {e}"))?;
        println!("==> Updated BENCHMARKS.md latest benchmark report.");
    }
    Ok(())
}

fn cmd_audit(ws: &Path, skip_typos: bool, skip_deny: bool) -> Result<(), String> {
    let abi_lock =
        fs::read_to_string(ws.join("abi-lock.toml")).map_err(|e| format!("abi-lock.toml: {e}"))?;
    let ws_toml =
        fs::read_to_string(ws.join("Cargo.toml")).map_err(|e| format!("Cargo.toml: {e}"))?;
    let lock = fs::read_to_string(ws.join("Cargo.lock")).map_err(|e| format!("Cargo.lock: {e}"))?;

    for (lock_key, cargo_key) in [
        ("workspace_version", "version"),
        ("edition", "edition"),
        ("rust_version", "rust-version"),
    ] {
        let expected = parse_quoted_kv(&abi_lock, lock_key)
            .ok_or_else(|| format!("missing `{lock_key}` in abi-lock.toml"))?;
        let actual = parse_quoted_kv(&ws_toml, cargo_key)
            .ok_or_else(|| format!("missing `{cargo_key}` in Cargo.toml"))?;
        if expected != actual {
            return Err(format!(
                "abi-lock.toml mismatch: {lock_key}={expected:?} != Cargo.toml {cargo_key}={actual:?}"
            ));
        }
    }

    if !lock.contains(PINNED_WIRE_REV) {
        return Err(format!(
            "Cargo.lock does not reference pinned bamabi-wire commit `{PINNED_WIRE_REV}`"
        ));
    }
    println!("==> abi-lock.toml and Cargo.lock parity verified.");

    if !skip_typos {
        run_checked(Command::new("typos").current_dir(ws), "typos")?;
    }
    if !skip_deny {
        run_checked(
            Command::new(cargo_bin())
                .current_dir(ws)
                .args(["deny", "check"]),
            "cargo deny check",
        )?;
    }
    Ok(())
}

fn cmd_nightly(ws: &Path, cases: u32) -> Result<(), String> {
    cmd_test(ws, false, false, true, cases, false, false, false)?;
    println!("==> Running release compiler + parity smoke check for nightly validation.");
    run_checked(
        Command::new(cargo_bin()).current_dir(ws).args([
            "test",
            "-p",
            "stratac",
            "--test",
            "parity_4way",
            "--all-features",
        ]),
        "cargo test -p stratac --test parity_4way --all-features",
    )?;
    Ok(())
}

fn print_help() {
    println!(
        "bamabi-strata workspace task runner (cargo xtask)\n\n\
         USAGE:\n\
         \x20 cargo xtask <COMMAND> [OPTIONS]\n\n\
         COMMANDS:\n\
         \x20 fmt [--fix]                    Verify (or apply) rustfmt across all workspace crates\n\
         \x20 lint                           Enforce safety attributes, Bevy/static-console isolation, clippy -D warnings, and rustdoc\n\
         \x20 test [FLAGS]                   Run unit, integration, proptest (--cases N), doc, static-console, or --no-default-features checks\n\
         \x20 kani [--crate K] [--timeout S] Run Kani CBMC proofs (PO-S1..PO-S10)\n\
         \x20 bench [FLAGS]                  Run strata_bench compiler + 4-tier execution throughput benchmarks (--quick, --write-docs, --check-docs)\n\
         \x20 audit [--skip-typos] [--skip-deny] Check abi-lock.toml / Cargo.lock parity, typos, and cargo-deny\n\
         \x20 nightly [--cases N]            Extended proptest & 4-way differential parity regression suite\n\
         \x20 ci [--no-bench] [--full]       Run full local/CI pipeline (fmt, bench --check-docs, lint, test, optional bench; --full adds audit + kani)"
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let task = match parse_args(&args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    if matches!(task, Task::Help) {
        print_help();
        return ExitCode::SUCCESS;
    }

    let ws = workspace_root();
    let res = match task {
        Task::Help => Ok(()),
        Task::Fmt { fix } => cmd_fmt(&ws, fix),
        Task::Lint => cmd_lint(&ws),
        Task::Test {
            unit,
            integration,
            proptest,
            cases,
            doc,
            static_console,
            no_default_features,
        } => cmd_test(
            &ws,
            unit,
            integration,
            proptest,
            cases,
            doc,
            static_console,
            no_default_features,
        ),
        Task::Kani {
            crate_filter,
            timeout_secs,
        } => cmd_kani(&ws, crate_filter.as_deref(), timeout_secs),
        Task::Bench {
            quick,
            suite,
            write_docs,
            no_write_docs,
            check_docs,
            json_path,
        } => cmd_bench(
            &ws,
            quick,
            &suite,
            write_docs,
            no_write_docs,
            check_docs,
            json_path.as_deref(),
        ),
        Task::Audit {
            skip_typos,
            skip_deny,
        } => cmd_audit(&ws, skip_typos, skip_deny),
        Task::Nightly { cases } => cmd_nightly(&ws, cases),
        Task::Ci { no_bench, full } => (|| -> Result<(), String> {
            cmd_fmt(&ws, false)?;
            cmd_bench(&ws, false, "all", false, true, true, None)?;
            cmd_lint(&ws)?;
            cmd_test(&ws, false, false, false, 256, false, false, false)?;
            if !no_bench {
                cmd_bench(&ws, true, "all", false, true, false, None)?;
            }
            if full {
                cmd_audit(&ws, false, false)?;
                cmd_kani(&ws, None, 300)?;
            }
            Ok(())
        })(),
    };

    if let Err(e) = res {
        eprintln!("xtask failed: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_ci_and_test_flags_and_rejects_conflicts() {
        assert_eq!(
            parse_args(&["ci".into(), "--full".into(), "--no-bench".into()]).unwrap(),
            Task::Ci {
                no_bench: true,
                full: true
            }
        );
        assert_eq!(
            parse_args(&[
                "test".into(),
                "--proptest".into(),
                "--cases".into(),
                "64".into()
            ])
            .unwrap(),
            Task::Test {
                unit: false,
                integration: false,
                proptest: true,
                cases: 64,
                doc: false,
                static_console: false,
                no_default_features: false,
            }
        );
        assert!(
            parse_args(&[
                "bench".into(),
                "--write-docs".into(),
                "--no-write-docs".into()
            ])
            .is_err()
        );
        assert!(
            parse_args(&["bench".into(), "--check-docs".into(), "--write-docs".into()]).is_err()
        );
        assert!(parse_args(&["unknown".into()]).is_err());
    }

    #[test]
    fn benchmark_marker_validation_and_splicing() {
        let template = format!(
            "# Title\n\n{BENCH_START}\n### Compiler & Frontend Pipeline Latency\n\n### 4-Tier Execution Throughput\n{BENCH_END}\n"
        );
        verify_benchmark_docs_str(&template).unwrap();
        let spliced = splice_benchmark_docs_str(
            &template,
            "### Compiler & Frontend Pipeline Latency\nupdated\n### 4-Tier Execution Throughput\nfast",
        )
        .unwrap();
        verify_benchmark_docs_str(&spliced).unwrap();
        assert!(spliced.contains("updated"));

        let empty = format!("{BENCH_START}\n  \n{BENCH_END}");
        assert!(verify_benchmark_docs_str(&empty).is_err());
    }

    #[test]
    fn bevy_tree_checker_distinguishes_bamabi_from_bevy() {
        let ok_tree = "strata_sema v0.3.0\n├── bamabi_sys v0.3.0\n└── salsa v0.28.5\n";
        assert_eq!(has_non_bamabi_bevy_line(ok_tree), None);
        let bad_tree = "strata_sema v0.3.0\n└── bevy_ecs v0.20.1\n";
        assert_eq!(
            has_non_bamabi_bevy_line(bad_tree).as_deref(),
            Some("bevy_ecs")
        );
    }
}
