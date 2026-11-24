#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # `bamabi-strata` Workspace Documentation Hub
//!
//! Zero-dependency (`#![no_std]`, `#![forbid(unsafe_code)]`, `publish = false`) rustdoc landing
//! hub aggregating architecture, testing, formal verification (`PO-S1`..`PO-S12`, `PO-S14`..`PO-S16`),
//! benchmarking, and crate index guides for **`bamabi-strata`** (`v0.3.0`, `ABI 0.3.0`).
//!
//! Run `cargo docs --open` at the workspace root to generate and browse all crate and guide pages.
//!
//! ## Workspace Guides
//!
//! - [`overview`] — Repository overview and quickstart (`README.md`)
//! - [`architecture`] — 12-crate DAG, compilation tiers, and isolation invariants (`ARCHITECTURE.md`)
//! - [`development`] — Toolchains, `cargo xtask`, and upstream ABI pinning (`DEVELOPMENT.md`)
//! - [`testing`] — 6-tier verification pyramid, `proptest`, and Kani `PO-S1`..`PO-S12`, `PO-S14`..`PO-S16` (`TESTING.md`)
//! - [`benchmarks`] — Compiler latency & 4-tier ECS throughput benchmark report (`BENCHMARKS.md`)
//! - [`changelog`] — Release changelog (`CHANGELOG.md`)
//! - [`crates`] — Direct links to every workspace crate root

#[cfg(doc)]
pub mod overview {
    #![doc = include_str!("../../../README.md")]
}

#[cfg(doc)]
pub mod architecture {
    #![doc = include_str!("../../../ARCHITECTURE.md")]
}

#[cfg(doc)]
pub mod development {
    #![doc = include_str!("../../../DEVELOPMENT.md")]
}

#[cfg(doc)]
pub mod testing {
    #![doc = include_str!("../../../TESTING.md")]
}

#[cfg(doc)]
pub mod benchmarks {
    #![doc = include_str!("../../../BENCHMARKS.md")]
}

#[cfg(doc)]
pub mod changelog {
    #![doc = include_str!("../../../CHANGELOG.md")]
}

#[cfg(doc)]
pub mod crates {
    //! Index of all 12 workspace crates in `bamabi-strata`.
    //!
    //! - [`strata_syntax`](../../strata_syntax/index.html) — Lossless `rowan` CST, `logos` lexer, LL(2)/Pratt parser, `stratafmt`, Graph IR
    //! - [`bamabi_native_rt`](../../bamabi_native_rt/index.html) — Tier 3 Bevy `0.20` adapter, `DirtyRunCoalescer`, `AbiPod` primitives
    //! - [`strata_sema`](../../strata_sema/index.html) — `salsa` incremental analysis, SI units, `AbiPod` solver, Theorem 0.1 prover, authority analysis
    //! - [`strata_mir`](../../strata_mir/index.html) — SSA CFG IR and 6 lowering passes
    //! - [`strata_codegen`](../../strata_codegen/index.html) — ISO C99, Safe Rust Guest `.cdylib`, Tier 3 `bevy-native`
    //! - [`strata_jit`](../../strata_jit/index.html) — Cranelift PIC `ObjectModule` + native shared library linker
    //! - [`strata_lsp`](../../strata_lsp/index.html) — `tower-lsp` language server and `SystemTelemetryDigest64` / BRP codec
    //! - [`stratac`](../../stratac/index.html) — Unified compiler driver, headless `sim_test`, `.bampack` builder
    //! - [`strata_docs`](../../strata_docs/index.html) — Zero-dependency rustdoc workspace documentation hub
    //! - [`strata_bench`](../../strata_bench/index.html) — Compiler & 4-tier Bevy runtime throughput benchmark harness (`benches/strata_bench`)
    //! - [`strata_profile`](../../strata_profile/index.html) — Headless Bevy `0.20` + `bamabi_host` + `hotpath-rs` stress suite (`benches/strata_profile`)
    //! - [`xtask`](../../xtask/index.html) — Workspace CI, policy/isolation lint, audit, benchmark, and Kani proof runner
}
