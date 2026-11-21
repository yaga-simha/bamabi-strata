#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Cranelift PIC native `.dylib` / `.so` backend (`strata_jit`) for `StrataMir`.
//!
//! Emits native `bamabi_manifest`, `bamabi_init`, `bamabi_shutdown`, and system callbacks
//! targeting `bamabi` (`ABI 0.3.0`) using `cranelift-object` and links them into a host-loadable
//! shared library. Every `BamHostApi` offset and descriptor field offset is sourced dynamically
//! from `bamabi_sys` (`offsets::*` and `core::mem::offset_of!`).
//!
//! This crate enforces `#![forbid(unsafe_code)]` and has ZERO `bevy*` dependencies.

pub mod abi_offsets;
pub mod emitter;
#[cfg(kani)]
mod kani_proofs;
pub mod linker;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Instant;
use strata_mir::MirModule;
use thiserror::Error;

/// Optimization level for Cranelift PIC codegen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum JitOptLevel {
    /// Fast baseline compilation (`opt_level = "none"`) minimizing reload latency.
    FastCompile,
    /// Vector-friendly speed optimization (`opt_level = "speed"`).
    #[default]
    Speed,
}

/// Configuration for [`compile_module_to_dylib`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JitCompileOptions {
    /// Directory where the `.o` and linked shared library are written.
    pub out_dir: PathBuf,
    /// Base filename stem (without `lib` prefix or `.dylib`/`.so` extension).
    pub module_stem: String,
    /// Cranelift optimization level.
    pub opt_level: JitOptLevel,
}

/// Artifact and timing telemetry produced by [`compile_module_to_dylib`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JitBuildArtifact {
    /// Path to the relocatable PIC `.o` object emitted by `cranelift-object`.
    pub object_path: PathBuf,
    /// Path to the linked native shared library (`.dylib` / `.so` / `.dll`).
    pub dylib_path: PathBuf,
    /// Time spent emitting Cranelift IR and machine code into `.o` (milliseconds).
    pub emit_ms: f64,
    /// Time spent linking `.o` into a shared library (milliseconds).
    pub link_ms: f64,
    /// Combined emit + link time (milliseconds).
    pub total_ms: f64,
    /// Exported ABI symbol names present in the artifact.
    pub exported_symbols: Vec<String>,
}

/// Errors returned by [`compile_module_to_dylib`].
#[derive(Debug, Error)]
pub enum JitError {
    /// Cranelift ISA or settings configuration failure.
    #[error("Cranelift ISA configuration failed: {0}")]
    IsaConfig(String),
    /// Cranelift module or function compilation error.
    #[error("Cranelift emission error: {0}")]
    Codegen(String),
    /// Filesystem I/O failure.
    #[error("I/O error writing `{path}`: {detail}")]
    Io {
        /// File path.
        path: String,
        /// Underlying OS error description.
        detail: String,
    },
    /// Platform linker error.
    #[error("native linker failed: {0}")]
    LinkFailed(String),
}

/// Returns the host platform dynamic library `(prefix, ext)` tuple.
#[must_use]
pub const fn host_dylib_prefix_ext() -> (&'static str, &'static str) {
    if cfg!(target_os = "windows") {
        ("", "dll")
    } else if cfg!(target_os = "macos") {
        ("lib", "dylib")
    } else {
        ("lib", "so")
    }
}

/// Compiles `mir` into a native PIC object file via `cranelift-object` and links a loadable
/// `bamabi` shared library into `opts.out_dir`.
pub fn compile_module_to_dylib(
    mir: &MirModule,
    opts: &JitCompileOptions,
) -> Result<JitBuildArtifact, JitError> {
    std::fs::create_dir_all(&opts.out_dir).map_err(|e| JitError::Io {
        path: opts.out_dir.display().to_string(),
        detail: e.to_string(),
    })?;

    let t0 = Instant::now();
    let emitted = emitter::emit_pic_object(mir, opts)?;
    let emit_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let obj_path = opts.out_dir.join(format!("{}.o", opts.module_stem));
    std::fs::write(&obj_path, &emitted.object_bytes).map_err(|e| JitError::Io {
        path: obj_path.display().to_string(),
        detail: e.to_string(),
    })?;

    let (prefix, ext) = host_dylib_prefix_ext();
    let dylib_path = opts
        .out_dir
        .join(format!("{prefix}{}.{ext}", opts.module_stem));

    let t_link = Instant::now();
    linker::link_shared_object(&obj_path, &dylib_path)?;
    let link_ms = t_link.elapsed().as_secs_f64() * 1000.0;
    let total_ms = t0.elapsed().as_secs_f64() * 1000.0;

    Ok(JitBuildArtifact {
        object_path: obj_path,
        dylib_path,
        emit_ms,
        link_ms,
        total_ms,
        exported_symbols: emitted.exported_symbols,
    })
}

#[cfg(test)]
mod tests {
    use super::host_dylib_prefix_ext;

    /// Verifies platform shared-library naming returns expected non-empty extension.
    #[test]
    fn platform_dylib_extension_is_valid() {
        let (_prefix, ext) = host_dylib_prefix_ext();
        assert!(matches!(ext, "dylib" | "so" | "dll"));
    }
}
