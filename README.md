# `bamabi-strata` (Strata v2.0)

Statically typed, zero-allocation, data-parallel ECS gameplay language, 3-tier compiler suite (`strata_jit` / ISO C99 -> Safe Rust Guest `.cdylib` -> Tier 3 `--target bevy-native`), LSP server, and verification workbench layered at **Layer 3** above [`bamabi-wire`](https://github.com/yaga-simha/bamabi-wire) (`ABI 0.3.0`, `0x0003_0000`, `73` `BamHostApi` slots, `592 B` 64-bit / `300 B` 32-bit), [`bamabi-tools`](https://github.com/yaga-simha/bamabi-tools), and [`bamabi-core`](https://github.com/yaga-simha/bamabi-core) (`bevy_ecs` / `bevy_app` / `bevy_reflect = "0.20.1"`).

---

## 1. Design Highlights

- **Universal `#![forbid(unsafe_code)]`:** Every crate in the 12-crate workspace enforces `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`. Even the Cranelift PIC machine-code backend (`strata_jit`) generates relocatable object code and links shared libraries safely in memory with zero `unsafe`.
- **8/12 Zero-Bevy Compiler & Tooling Isolation:** `strata_syntax`, `strata_sema`, `strata_mir`, `strata_codegen`, `strata_jit`, `strata_lsp`, `strata_docs`, and `xtask` have **zero** transitive `bevy*` dependencies.
- **Bit-Exact 4-Way Parity:** Cranelift PIC JIT (`strata_jit`), strict ISO C99 (`strata_codegen::c99`, `-ffp-contract=off`), Safe Rust Guest `.cdylib` (`strata_codegen::rust_guest`), and Tier 3 static Bevy Native (`strata_codegen::bevy_native` + `bamabi_native_rt`) lower directly from `StrataMir` SSA CFGs and execute identical gameplay kernels with verified SHA-256 and FNV-1a parity across hundreds of `FixedUpdate` steps, `atomic` rollbacks, 2-pass CSR spatial grids, Slot 58 `iter_up_cascade`, and live mod reloads.
- **Compile-Time Soundness & ABI Determinism:** SI unit dimensional algebra, bidirectional type inference (`infer.rs`), unified provenance-based `@authority` verification (`authority.rs`), `@soa` hot/cold stratum splitting, zero-implicit-padding `AbiPod` layout synthesis (`_strata_pad_*`), `ComponentUuid` / FNV-1a `SCHEMA_FINGERPRINT` bit-parity with `bamabi_sys` / `bamabi_macros`, Theorem 0.1 `FilteredAccessSet` archetype-disjointness proofs, and `&mut? T` selective tick coalescing.
- **Multi-Tier Verification & Benchmarks:** Unit tests, 8 cookbook fixtures (`01_rain_swarm`..`08_authoritative_multiplayer`), 4-way differential parity harness (`stratac::tests::parity_4way`), virtual multi-world networking (`net_sim_test`), property-based tests (`proptest`), 15 symbolic Kani CBMC proof harnesses (`PO-S1`..`PO-S12`, `PO-S14`..`PO-S16`), compiler + runtime + `criterion 0.8` / `hotpath-rs` profiling suites (`benches/strata_bench`, `benches/strata_profile`), and a zero-dependency `cargo xtask` CI driver.

---

## 2. Workspace Crates (12 Members)

| Crate | Policy | `bevy*` Deps | Role |
| :--- | :--- | :--- | :--- |
| `strata_syntax` | `#![forbid(unsafe_code)]` | **ZERO** | `logos` DFA lexer, lossless `rowan` CST, LL(2)/Pratt error-recovering parser, `stratafmt`, lossless Graph IR + `.strata.graph.json` sidecar (`crates/strata_syntax`) |
| `strata_sema` | `#![forbid(unsafe_code)]` | **ZERO** | Per-item `salsa` `0.28.5` DB, bidirectional inference, SI units, unified provenance `@authority`, `@soa` splitting, `AbiPod` solver, UUID/fingerprint parity, Theorem 0.1 (`crates/strata_sema`) |
| `strata_mir` | `#![forbid(unsafe_code)]` | **ZERO** | SSA CFG IR & 6 passes: `?T` chunk splitting, `&mut?` tick coalescing, `timeline`/`task`/`fsm`, 2-pass CSR spatial indices, pre-image `atomic` tx, `@deterministic` (`crates/strata_mir`) |
| `strata_codegen` | `#![forbid(unsafe_code)]` | **ZERO** | Direct MIR CFG emitters for strict ISO C99 (`c99/*`), Safe Rust Guest `.cdylib` (`rust_guest/*`), static Tier 3 `bevy-native` (`bevy_native/*`), and 184B `StrataNetPacket` (`crates/strata_codegen`) |
| `strata_jit` | `#![forbid(unsafe_code)]` | **ZERO** | Cranelift `0.135.10` PIC `ObjectModule` (`emitter/*`) + native linker deriving all 73 slots & structs from `bamabi_sys::offsets::*` (`crates/strata_jit`) |
| `strata_lsp` | `#![forbid(unsafe_code)]` | **ZERO** | `tower-lsp` language server (`strata-lsp`), diagnostics, hover cards, formatting, CodeLenses, `strata/graphTelemetry`, Layer-0 `"BAMT"` `SystemTelemetryDigest64` / BRP codec (`crates/strata_lsp`) |
| `bamabi_native_rt` | `#![forbid(unsafe_code)]` | `bevy_ecs`, `bevy_app`, `bevy_reflect` | Tier 3 native adapter (`ChunkSliceQueryExt`, `SelectiveMutSlice`, `DirtyRunCoalescer`, `SharedBridgeAppExt`, `StrataNetPacket`, `AbiPod` primitives, `static-console`) (`crates/bamabi_native_rt`) |
| `stratac` | `#![forbid(unsafe_code)]` | Optional `bevy_app`, `bevy_ecs`, `bamabi_host` | CLI driver (`check`, `fmt`, `layout`, `explain-par`, `test`, `build`, `watch`, `onboard`, `graph`), headless `sim_test` / `net_sim_test`, Ed25519 `.bampack` (`crates/stratac`) |
| `strata_docs` | `#![forbid(unsafe_code)]`, `#![no_std]` | **ZERO** | Zero-external-dependency workspace rustdoc documentation hub (`crates/strata_docs`) |
| `strata_bench` | `#![forbid(unsafe_code)]` | `bevy_app`, `bevy_ecs`, `bamabi_host` | Compiler latency & 4-tier execution throughput harness (`benches/strata_bench`) |
| `strata_profile` | `#![forbid(unsafe_code)]` | `bevy_app`, `bevy_ecs`, `bamabi_host` | Headless Bevy `0.20` + `bamabi_host` + `hotpath-rs` closed-loop profiling suite (`benches/strata_profile`) |
| `xtask` | `#![forbid(unsafe_code)]` | **ZERO** | Zero-external-dependency CI/QA runner: `fmt`, `lint`, `test`, `kani`, `bench`, `audit`, `nightly`, `ci` (`xtask`) |

---

## 3. Quickstart

```bash
# Run full local CI gate (fmt, benchmark docs check, lint/isolation/clippy/doc, unit+integration+proptest+doctests, quick bench)
cargo xtask ci

# Include security/policy audit (abi-lock, typos, cargo-deny) and all 15 Kani formal proofs (PO-S1..PO-S12, PO-S14..PO-S16)
cargo xtask ci --full

# Compile, inspect, format, or test a cookbook module
cargo run -p stratac -- check fixtures/cookbooks/05_soulslike_combat.strata
cargo run -p stratac -- explain-par fixtures/cookbooks/05_soulslike_combat.strata
cargo run -p stratac -- test fixtures/cookbooks/03_metroidvania_core.strata
cargo run -p stratac -- graph export fixtures/cookbooks/07_visual_boss_graph.strata --format=json

# Build a Tier 1 Cranelift JIT library or Tier 3 static Bevy plugin
cargo run -p stratac -- build fixtures/cookbooks/01_rain_swarm.strata --target jit --release --out target/demo
cargo run -p stratac -- onboard fixtures/cookbooks/01_rain_swarm.strata --target bevy-native --static-console --out target/demo_native --check

# Generate and view the complete rustdoc manual
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features --open
```

---

## 4. Further Reading

- Architecture & compilation pipeline: `ARCHITECTURE.md`
- Contributor toolchain, federation overlay & `cargo xtask` reference: `DEVELOPMENT.md`
- Multi-tier verification pyramid & Kani proof catalog (`PO-S1`..`PO-S16`): `TESTING.md`
- Benchmarking methodology, Criterion `0.8` & `hotpath-rs` profiling results: `BENCHMARKS.md`
- Repository invariants & policy guide: `GEMINI.md`
- Release history: `CHANGELOG.md`

## License

Dual-licensed under `MIT OR Apache-2.0` (`LICENSE-MIT`, `LICENSE-APACHE`).
