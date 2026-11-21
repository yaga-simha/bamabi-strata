# Changelog (`bamabi-strata`)

All notable changes to **`bamabi-strata`** follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions.

## [0.3.0] - 2026-11-21

### Added
- **Core Compiler & Runtime Suite (8 crates):** `strata_syntax`, `bamabi_native_rt`, `strata_sema`, `strata_mir`, `strata_codegen`, `strata_jit`, `strata_lsp`, and `stratac` aligned to `bamabi-wire` `ABI 0.3.0` (`0x0003_0000`, 68 slots) and `bevy_ecs`/`bevy_app`/`bevy_reflect = "0.20.1"`.
- **Differential Parity & Cookbook Suite:** 6 complete cookbook fixtures (`01_rain_swarm`..`06_battle_royale_server`), 4-way 500-frame + live reload parity test (`stratac/tests/parity_4way.rs`), and `-ffp-contract=off` ISO C99 parity enforcement.
- **Multi-Tier Test & Formal Verification Suite:** Co-located `#[cfg(test)]` unit tests across all crates, 5 `proptest` suites (`bamabi_native_rt`, `strata_syntax`, `strata_sema`, `strata_mir`, `strata_lsp`), and 10 Kani CBMC formal proof obligations (`PO-S1`..`PO-S10`).
- **Benchmarking Harness (`benches/strata_bench`):** Compiler latency + 4-tier ECS execution throughput (`native`, `jit`, `c99:release`, `rust_guest:release`) + `selective_mut_slice` (`1%` vs `100%` dirty) with pre-timing SHA-256 parity gating.
- **CI Task Runner (`xtask`), Documentation Hub (`crates/strata_docs`), and GitHub Actions (`.github/workflows/{ci,nightly}.yml`):** Automated formatting, safety header checks, zero-Bevy isolation (`8/11` crates), `static-console` isolation, `clippy -D warnings`, strict `rustdoc`, `typos`, `cargo deny check` (`salsa` upgraded to `0.28.5` resolving `RUSTSEC-2026-0308`), Kani, and benchmarks.
