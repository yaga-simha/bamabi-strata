#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Unified compiler CLI, packager, Tier 3 onboarder, and headless `sim_test` runner (`stratac`)
//! for Strata v2.0.
//!
//! Enforces `#![forbid(unsafe_code)]`. Headless Bevy simulation (`test` subcommand) is gated
//! behind the default `sim-runner` feature.

pub mod cli;
pub mod commands;
pub mod exit_codes;
#[cfg(feature = "sim-runner")]
pub mod sim_runner;

pub use cli::{BuildTarget, Cli, Commands, OnboardTarget, OutputFormat};
pub use commands::{
    BuildReport, CheckReport, ExplainParReport, LayoutReport, OnboardReport, SimTestSuiteReport,
    WatchReport, cmd_build, cmd_check, cmd_explain_par, cmd_fmt, cmd_layout, cmd_onboard, cmd_test,
    cmd_watch, execute_cli,
};
pub use exit_codes::{
    EXIT_COMPILE_ERROR, EXIT_OK, EXIT_PARITY_OR_ASSERT_FAILED, EXIT_SIM_TEST_FAILED,
};
