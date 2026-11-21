#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Multi-target code generators for `StrataMir` (Strict ISO C99, Safe Rust Guest `.cdylib`,
//! and Tier 3 Static Bevy Native `Plugin` crates).
//!
//! This crate enforces `#![forbid(unsafe_code)]` and has ZERO `bevy*` dependencies.

pub mod bevy_native;
pub mod c99;
pub mod expr;
pub mod rust_guest;

use serde::{Deserialize, Serialize};
use strata_mir::MirModule;
use strata_sema::layout::{SchemaItemKind, SolvedLayout};
use thiserror::Error;

/// Supported ahead-of-time source emission targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetKind {
    /// Strict ISO C99 dynamic mod targeting `include/bamabi.h`.
    C99,
    /// Safe `#![forbid(unsafe_code)]` Rust guest `.cdylib` targeting `bamabi_guest`.
    RustGuest,
    /// Static `#![forbid(unsafe_code)]` Bevy `0.20` `Plugin` crate targeting `bamabi_native_rt`.
    BevyNative,
}

/// One emitted source/manifest file within a [`GeneratedArtifact`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedFile {
    /// Relative POSIX file path within the target output directory.
    pub path: String,
    /// Complete UTF-8 file contents.
    pub content: String,
}

/// Collection of generated files produced for one target backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedArtifact {
    /// Target backend kind.
    pub target: TargetKind,
    /// Canonical module identifier (`module ...`).
    pub module_name: String,
    /// Emitted files (`src/lib.rs`, `Cargo.toml`, `<mod>.c`, `bamabi.h`, etc.).
    pub files: Vec<GeneratedFile>,
}

/// Options configuring Tier 3 `--target bevy-native` crate generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BevyNativeOptions {
    /// Cargo package name for the generated static crate.
    pub crate_name: String,
    /// Optional local filesystem path to `bamabi_native_rt` (for offline/monorepo builds).
    pub native_rt_path: Option<String>,
    /// Default feature selection (`true` -> `static-console`, `false` -> `shared-bridge`).
    pub static_console: bool,
}

impl Default for BevyNativeOptions {
    fn default() -> Self {
        Self {
            crate_name: "strata_generated_native".to_owned(),
            native_rt_path: None,
            static_console: false,
        }
    }
}

/// Options configuring Safe Rust Guest (`.cdylib`) crate generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RustGuestOptions {
    /// Cargo package / library name for the generated `.cdylib`.
    pub crate_name: String,
}

impl Default for RustGuestOptions {
    fn default() -> Self {
        Self {
            crate_name: "strata_generated_guest".to_owned(),
        }
    }
}

/// Errors returned during code generation from `StrataMir`.
#[derive(Debug, Error)]
pub enum CodegenError {
    /// Encountered an unsupported target construct.
    #[error("unsupported codegen construct in `{context}`: {detail}")]
    Unsupported {
        /// Enclosing system or declaration name.
        context: String,
        /// Human-readable reason.
        detail: String,
    },
}

/// Renders the canonical ABI `0.3.0` ISO C99 header (`bamabi.h`) directly via `bamabi_sdk_gen`.
///
/// # Panics
/// Panics if `bamabi_sdk_gen::render_c99_header` fails internally.
#[must_use]
pub fn emit_bamabi_header() -> String {
    bamabi_sdk_gen::render_c99_header().expect("bamabi_sdk_gen::render_c99_header failed")
}

/// Emits a strict ISO C99 (`-std=c99 -Wall -Wextra -Wpedantic -Werror`) source unit plus `bamabi.h`.
pub fn emit_c99(mir: &MirModule) -> Result<GeneratedArtifact, CodegenError> {
    c99::emit(mir)
}

/// Emits a safe `#![forbid(unsafe_code)]` Rust Guest `.cdylib` crate targeting `bamabi_guest`.
pub fn emit_rust_guest(mir: &MirModule) -> Result<GeneratedArtifact, CodegenError> {
    emit_rust_guest_with(mir, &RustGuestOptions::default())
}

/// Emits a safe Rust Guest `.cdylib` crate with custom package naming.
pub fn emit_rust_guest_with(
    mir: &MirModule,
    opts: &RustGuestOptions,
) -> Result<GeneratedArtifact, CodegenError> {
    rust_guest::emit(mir, opts)
}

/// Emits a Tier 3 `#![forbid(unsafe_code)]` Bevy `Plugin` crate targeting `bamabi_native_rt`.
pub fn emit_bevy_native(
    mir: &MirModule,
    opts: &BevyNativeOptions,
) -> Result<GeneratedArtifact, CodegenError> {
    bevy_native::emit(mir, opts)
}

/// Sanitizes a canonical Strata name (`"a::b::Foo"` or `"Foo"`) into a valid C/Rust identifier.
#[must_use]
pub fn sanitize_ident(raw: &str) -> String {
    let tail = raw.rsplit("::").next().unwrap_or(raw);
    let mut out = String::with_capacity(tail.len());
    for ch in tail.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out.as_bytes()[0].is_ascii_digit() {
        format!("strata_{out}")
    } else {
        out
    }
}

/// Extracts the normalized module stem (e.g. `"rain_swarm"` from `"tutorial::rain_swarm"`).
#[must_use]
pub fn module_stem(module_path: &str) -> String {
    let raw = module_path.rsplit("::").next().unwrap_or("strata_mod");
    let s: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() {
        "strata_mod".to_owned()
    } else {
        s
    }
}

/// Resolves a storage key (short name or canonical name) to its [`SolvedLayout`].
#[must_use]
pub fn find_layout<'a>(mir: &'a MirModule, key: &str) -> Option<&'a SolvedLayout> {
    let short = key.split('.').next().unwrap_or(key);
    mir.layouts.iter().find(|l| {
        l.canonical_name == short
            || l.canonical_name.rsplit("::").next() == Some(short)
            || sanitize_ident(&l.canonical_name) == sanitize_ident(short)
    })
}

/// Returns `true` when `layout` should be registered as an ECS component (vs struct/enum/resource).
#[must_use]
pub const fn is_ecs_component_kind(kind: SchemaItemKind) -> bool {
    matches!(
        kind,
        SchemaItemKind::Component
            | SchemaItemKind::SoaHot
            | SchemaItemKind::SoaCold
            | SchemaItemKind::TaskState
            | SchemaItemKind::FsmState
            | SchemaItemKind::Timeline
    )
}

/// Resolves the target schedule (`FixedUpdate`, `Update`, `Startup`, etc.) for a system name.
#[must_use]
pub fn system_schedule_label<'a>(mir: &'a MirModule, sys_name: &str) -> &'a str {
    for sched in &mir.schedules {
        if schedule_contains_name(&sched.nodes, sys_name) {
            return sched.label.as_str();
        }
    }
    "FixedUpdate"
}

fn schedule_contains_name(nodes: &[strata_sema::hir::HirScheduleGroup], name: &str) -> bool {
    for node in nodes {
        if node.name == name || schedule_contains_name(&node.children, name) {
            return true;
        }
    }
    false
}
