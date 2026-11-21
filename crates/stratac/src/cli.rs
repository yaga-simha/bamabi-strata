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
        #[arg(long)]
        bampack: bool,
        /// Sign the built shared library / `.bampack` with Ed25519 `SSHSIG`.
        #[arg(long)]
        sign: bool,
        /// Output format (`text` or `json`).
        #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Incrementally recompile via Salsa (`<35 ms` JIT rebuild) on source change.
    Watch {
        /// Path to `.strata` source file.
        file: PathBuf,
        /// Sign rebuilt `.dylib` via Ed25519.
        #[arg(long)]
        sign: bool,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies `stratac` parses all 8 subcommands and flags cleanly and rejects invalid targets.
    #[test]
    fn cli_parses_subcommands_and_rejects_unknown_target() {
        let cli = Cli::try_parse_from([
            "stratac",
            "build",
            "sim.strata",
            "--target",
            "rust-guest",
            "--release",
            "--sign",
            "--format",
            "json",
        ])
        .expect("build CLI parses");
        match cli.command {
            Commands::Build {
                target,
                release,
                sign,
                format,
                ..
            } => {
                assert_eq!(target, BuildTarget::RustGuest);
                assert!(release && sign);
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
}
