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
pub mod net_sim_runner;
#[cfg(feature = "sim-runner")]
pub mod sim_runner;

pub use cli::{BuildTarget, Cli, Commands, OnboardTarget, OutputFormat};
pub use commands::{
    BuildReport, CheckReport, ExplainParReport, LayoutReport, OnboardReport, ScheduleDeltaArtifact,
    ScheduleDeltaMode, ScheduleDeltaSet, ScheduleDeltaSystem, SimTestSuiteReport, WatchReport,
    WatchSession, cmd_build, cmd_build_with_key, cmd_check, cmd_explain_par, cmd_fmt, cmd_layout,
    cmd_onboard, cmd_test, cmd_watch, cmd_watch_bounded, cmd_watch_with_key, execute_cli,
    resolve_wire_rev, try_write_local_patch_config_with_ws,
};
pub use exit_codes::{
    EXIT_COMPILE_ERROR, EXIT_OK, EXIT_PARITY_OR_ASSERT_FAILED, EXIT_SIM_TEST_FAILED,
};

#[cfg(test)]
static TEST_ALLOC_GATE: std::sync::RwLock<()> = std::sync::RwLock::new(());

#[cfg(test)]
pub(crate) fn test_alloc_read_guard() -> std::sync::RwLockReadGuard<'static, ()> {
    TEST_ALLOC_GATE.read().unwrap_or_else(|e| e.into_inner())
}

#[cfg(all(test, feature = "sim-runner"))]
pub(crate) fn test_alloc_write_guard() -> std::sync::RwLockWriteGuard<'static, ()> {
    TEST_ALLOC_GATE.write().unwrap_or_else(|e| e.into_inner())
}
