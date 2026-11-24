//! `clap` command-line argument grammar for `stratac`.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Structured output format flag shared across inspection subcommands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum OutputFormat {
    /// Human-readable text output.
    #[default]
    Text,
    /// Machine-readable JSON output (`--format=json`).
    Json,
}

/// Compilation backend target for `stratac build`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum BuildTarget {
    /// Strict ISO C99 shared library (`-std=c99 -Wall -Wextra -Wpedantic -Werror`).
    C99,
    /// Safe `#![forbid(unsafe_code)]` Rust Guest `.cdylib` targeting `bamabi_guest`.
    RustGuest,
    /// Native Cranelift PIC `.dylib` / `.so` (`strata_jit`).
    #[default]
    Jit,
}

/// Target profile for `stratac onboard`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum OnboardTarget {
    /// Static Tier 3 `#![forbid(unsafe_code)]` Bevy `Plugin` crate (`bamabi_native_rt`).
    #[default]
    BevyNative,
}

/// Top-level `stratac` CLI options.
#[derive(Debug, Parser)]
#[command(
    name = "stratac",
    version,
    about = "Strata v2.0 ECS gameplay compiler suite"
)]
pub struct Cli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Supported `stratac` subcommands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Type-check, verify SI units, prove Theorem 0.1 access sets, and solve AbiPod layouts.
    Check {
        /// Path to `.strata` source file.
        file: PathBuf,
        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Format a `.strata` source file deterministically (`stratafmt`).
    Fmt {
        /// Path to `.strata` source file.
        file: PathBuf,
        /// Check formatting without rewriting the file (exits 3 on diff).
        #[arg(long)]
        check: bool,
    },
    /// Dump solved `#[repr(C)]` AbiPod sizes, alignments, padding bytes, UUIDs, and fingerprints.
    Layout {
        /// Path to `.strata` source file.
        file: PathBuf,
        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Explain Theorem 0.1 parallel concurrency groups and any remaining read/write conflicts.
    ExplainPar {
        /// Path to `.strata` source file.
        file: PathBuf,
        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Compile and run embedded `sim_test` blocks inside a headless `bamabi_host` Bevy World.
    Test {
        /// Path to `.strata` source file.
        file: PathBuf,
        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Compile a `.strata` module to native shared library (`jit`, `c99`, or `rust-guest`) and optionally package/sign as `.bampack`.
    Build {
        /// Path to `.strata` source file.
        file: PathBuf,
        /// Optimization mode.
        #[arg(long)]
        release: bool,
        /// Target backend (`jit`, `c99`, `rust-guest`).
        #[arg(long, value_enum, default_value_t = BuildTarget::Jit)]
        target: BuildTarget,
        /// Output artifact directory.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Package artifacts into a signed `.bampack` archive using Ed25519 keys.
        #[arg(long, requires = "signing_key")]
        bampack: bool,
        /// Sign the built shared library / `.bampack` with Ed25519 `SSHSIG`.
        #[arg(long, requires = "signing_key")]
        sign: bool,
        /// Path to an OpenSSH Ed25519 private key file for deterministic signing.
        #[arg(
            long,
            value_name = "PATH",
            group = "signing_key",
            conflicts_with = "ephemeral_key"
        )]
        key: Option<PathBuf>,
        /// Generate and use a throwaway ephemeral Ed25519 keypair (development/testing only).
        #[arg(long, group = "signing_key", conflicts_with = "key")]
        ephemeral_key: bool,
        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Incrementally recompile via Salsa (`<35 ms` JIT rebuild) on source change.
    Watch {
        /// Path to `.strata` source file.
        file: PathBuf,
        /// Sign rebuilt `.dylib` via Ed25519.
        #[arg(long, requires = "signing_key")]
        sign: bool,
        /// Path to an OpenSSH Ed25519 private key file for deterministic signing.
        #[arg(
            long,
            value_name = "PATH",
            group = "signing_key",
            conflicts_with = "ephemeral_key"
        )]
        key: Option<PathBuf>,
        /// Generate and use a throwaway ephemeral Ed25519 keypair (development/testing only).
        #[arg(long, group = "signing_key", conflicts_with = "key")]
        ephemeral_key: bool,
        /// Run one watch/rebuild cycle immediately and exit (for CI & tests).
        #[arg(long)]
        once: bool,
        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Eject / graduate a `.strata` module into a static `#![forbid(unsafe_code)]` Bevy `Plugin` crate.
    Onboard {
        /// Path to `.strata` source file.
        file: PathBuf,
        /// Target crate kind (`bevy-native`).
        #[arg(long, value_enum, default_value_t = OnboardTarget::BevyNative)]
        target: OnboardTarget,
        /// Destination directory for the generated crate.
        #[arg(long)]
        out: PathBuf,
        /// Enable `static-console` (`dlopen`-free) as default Cargo feature.
        #[arg(long)]
        static_console: bool,
        /// Run `cargo check` inside the generated crate after emission.
        #[arg(long)]
        check: bool,
        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Export or apply visual node Graph IR JSON and `.strata.graph.json` layout sidecars.
    Graph {
        /// Graph action (`export` or `apply`).
        #[command(subcommand)]
        action: GraphAction,
    },
}

/// Subcommands for `stratac graph`.
#[derive(Debug, Subcommand)]
pub enum GraphAction {
    /// Export lossless Graph IR JSON (merging `.strata.graph.json` sidecar positions).
    Export {
        /// Path to `.strata` source file.
        file: PathBuf,
        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Apply a Graph IR document or delta patch JSON to `.strata` and `.strata.graph.json`.
    Apply {
        /// Path to `.strata` source file.
        file: PathBuf,
        /// Path to Graph IR document or delta patch JSON file.
        patch: PathBuf,
        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies `stratac` parses all 8 subcommands and flags cleanly and rejects invalid targets.
    #[test]
    fn cli_parses_subcommands_and_rejects_unknown_target() {
        let _alloc_guard = crate::test_alloc_read_guard();
        let cli = Cli::try_parse_from([
            "stratac",
            "build",
            "sim.strata",
            "--target",
            "rust-guest",
            "--release",
            "--sign",
            "--ephemeral-key",
            "--format",
            "json",
        ])
        .expect("build CLI parses");
        match cli.command {
            Commands::Build {
                target,
                release,
                sign,
                key,
                ephemeral_key,
                format,
                ..
            } => {
                assert_eq!(target, BuildTarget::RustGuest);
                assert!(release && sign && ephemeral_key);
                assert!(key.is_none());
                assert_eq!(format, OutputFormat::Json);
            }
            other => panic!("unexpected command parsed: {other:?}"),
        }

        let onboard = Cli::try_parse_from([
            "stratac",
            "onboard",
            "sim.strata",
            "--out",
            "out_crate",
            "--static-console",
            "--check",
        ])
        .expect("onboard CLI parses");
        assert!(matches!(
            onboard.command,
            Commands::Onboard {
                static_console: true,
                check: true,
                ..
            }
        ));

        assert!(
            Cli::try_parse_from(["stratac", "build", "sim.strata", "--target", "bogus"]).is_err()
        );
    }

    /// Verifies `--key <path>` and `--ephemeral-key` requirements and mutual exclusion on `build` and `watch`.
    #[test]
    fn cli_enforces_signing_key_flags_and_conflicts() {
        let _alloc_guard = crate::test_alloc_read_guard();
        // Unsigned build and watch succeed with neither flag.
        assert!(Cli::try_parse_from(["stratac", "build", "sim.strata"]).is_ok());
        assert!(Cli::try_parse_from(["stratac", "watch", "sim.strata"]).is_ok());

        // Signed/packaged build and signed watch accept `--key <path>` or `--ephemeral-key`.
        let build_key = Cli::try_parse_from([
            "stratac",
            "build",
            "sim.strata",
            "--sign",
            "--key",
            "id.ed25519",
        ])
        .expect("build --sign --key parses");
        assert!(matches!(
            build_key.command,
            Commands::Build {
                sign: true,
                key: Some(_),
                ephemeral_key: false,
                ..
            }
        ));
        assert!(
            Cli::try_parse_from([
                "stratac",
                "build",
                "sim.strata",
                "--bampack",
                "--ephemeral-key"
            ])
            .is_ok()
        );

        let watch_key = Cli::try_parse_from([
            "stratac",
            "watch",
            "sim.strata",
            "--sign",
            "--key",
            "id.ed25519",
            "--once",
        ])
        .expect("watch --sign --key --once parses");
        assert!(matches!(
            watch_key.command,
            Commands::Watch {
                sign: true,
                key: Some(_),
                ephemeral_key: false,
                once: true,
                ..
            }
        ));
        assert!(
            Cli::try_parse_from([
                "stratac",
                "watch",
                "sim.strata",
                "--sign",
                "--ephemeral-key"
            ])
            .is_ok()
        );

        // Missing key source when signing/packaging is rejected.
        assert!(Cli::try_parse_from(["stratac", "build", "sim.strata", "--sign"]).is_err());
        assert!(Cli::try_parse_from(["stratac", "build", "sim.strata", "--bampack"]).is_err());
        assert!(Cli::try_parse_from(["stratac", "watch", "sim.strata", "--sign"]).is_err());

        // Conflicting `--key` + `--ephemeral-key` is rejected on both `build` and `watch`.
        assert!(
            Cli::try_parse_from([
                "stratac",
                "build",
                "sim.strata",
                "--sign",
                "--key",
                "id.ed25519",
                "--ephemeral-key",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "stratac",
                "watch",
                "sim.strata",
                "--sign",
                "--key",
                "id.ed25519",
                "--ephemeral-key",
            ])
            .is_err()
        );
    }

    /// Verifies `stratac graph export` and `stratac graph apply` CLI parsing.
    #[test]
    fn cli_parses_graph_export_and_apply() {
        let _alloc_guard = crate::test_alloc_read_guard();

        let export_json =
            Cli::try_parse_from(["stratac", "graph", "export", "boss.strata", "--format=json"])
                .expect("graph export --format=json parses");
        match export_json.command {
            Commands::Graph {
                action: GraphAction::Export { file, format },
            } => {
                assert_eq!(file, PathBuf::from("boss.strata"));
                assert_eq!(format, OutputFormat::Json);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let apply_default =
            Cli::try_parse_from(["stratac", "graph", "apply", "boss.strata", "patch.json"])
                .expect("graph apply parses");
        match apply_default.command {
            Commands::Graph {
                action:
                    GraphAction::Apply {
                        file,
                        patch,
                        format,
                    },
            } => {
                assert_eq!(file, PathBuf::from("boss.strata"));
                assert_eq!(patch, PathBuf::from("patch.json"));
                assert_eq!(format, OutputFormat::Text);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        assert!(Cli::try_parse_from(["stratac", "graph", "apply", "boss.strata"]).is_err());
        assert!(Cli::try_parse_from(["stratac", "graph", "unknown", "boss.strata"]).is_err());
    }
}
