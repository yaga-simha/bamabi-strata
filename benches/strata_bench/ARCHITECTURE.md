# Architecture: `strata_bench`

## Modules
- `src/compiler_bench.rs`: Measures `parse_format`, `sema_analyze`, `mir_lower_verify`, `codegen_all_targets`, and `jit_compile_object` latencies on cookbooks and the physics parity kernel.
- `src/runtime_bench.rs`: Builds real `.dylib` / `.so` mods for `jit`, `c99:release` (`-O2 -ffp-contract=off`), and `rust_guest:release`, validates bit-exact SHA-256 + FNV-1a world state parity across 120 `FixedUpdate` frames against `native`, measures entity-scaled throughput (`1,000` / `50,000` entities), and benchmarks `SelectiveMutSlice` at `1%` vs `100%` dirty density.
- `src/stats.rs` & `src/report.rs`: Computes `Min`, `Median`, `P95`, `Mean`, `ns/entity`, `M ent/s`, `vs_native`, JSON reports, and Markdown tables.
