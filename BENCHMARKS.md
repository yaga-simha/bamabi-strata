# Benchmarking Strategy & Recorded Results (`bamabi-strata`)

`benches/strata_bench` measures both **compiler frontend/backend latency** (parsing, Salsa/Theorem-0.1 semantics, MIR passes, three-target codegen, Cranelift PIC object emission) and **4-tier ECS execution throughput** across Native Bevy `0.20`, Cranelift PIC JIT (`strata_jit`), strict ISO C99 (`strata_codegen::c99`), and Safe Rust Guest `.cdylib` (`strata_codegen::rust_guest`).

---

## 1. Methodology & Pre-Timing Correctness Gate

- **Correctness Before Timing:** Prior to collecting any runtime timing samples, `strata_bench` boots four independent Bevy `0.20` `World`s populated with `128` entities and steps all four backends (`native`, `jit`, `c99:release`, `rust_guest:release`) for `120` `FixedUpdate` frames, verifying bit-identical SHA-256 and FNV-1a world POD state digests (`stratac::sim_runner::hash_world_pod_state`). Similarly, compiler fixtures (`step_sim_kernel` + cookbooks `01_rain_swarm`, `03_metroidvania_core`, `05_soulslike_combat`) are parse/sema/MIR-verified before timing.
- **Release Optimization:** `cargo xtask bench` always builds and executes `strata_bench` with `--release`, compiling C99 guests with `-O2 -ffp-contract=off` and Rust/JIT targets in release/speed mode.
- **Workloads:**
  - `compiler`: `parse_format`, `sema_analyze`, `mir_lower_verify`, `codegen_all_targets`, `jit_compile_object`.
  - `runtime` (`step_sim`): Per-frame ECS physics integration (`Pos`, `Vel`, `&mut? Heat` conditional mutation) across `1,000` and `50,000` entities (`--quick`: `1,000` & `10,000`).
  - `selective_mut_slice`: Compares sparse `1%` row mutation (`DirtyRunCoalescer` skipping 99% of ticks) against `100%` dense mutation.

---

## 2. Running & CI Integration

```bash
# Run full benchmark suite and auto-update BENCHMARKS.md
cargo xtask bench --write-docs --json target/bench-results.json

# Fast CI verification (quick sweep without mutating BENCHMARKS.md)
cargo xtask bench --quick --no-write-docs --json target/bench-results.json

# Validate BENCHMARKS.md markers & required sections
cargo xtask bench --check-docs
```

---

## 3. Latest Recorded Benchmark Report

<!-- BENCHMARK_REPORT_START -->
- **Environment:** `aarch64-macos` | **Run profile:** `full`
- **Parity Gate:** Mandatory pre-timing bit-exact SHA-256 + FNV-1a check passed across `native`, `jit`, `c99:release`, and `rust_guest:release`.

### Compiler & Frontend Pipeline Latency

| Fixture | Stage | Bytes | Median (us) | P95 (us) | Mean (us) |
| --- | --- | ---: | ---: | ---: | ---: |
| `step_sim_kernel` | `parse_format` | 763 | 59.9 | 62.3 | 60.5 |
| `step_sim_kernel` | `sema_analyze` | 763 | 188.5 | 245.8 | 204.2 |
| `step_sim_kernel` | `mir_lower_verify` | 763 | 3.8 | 4.0 | 3.9 |
| `step_sim_kernel` | `codegen_all_targets` | 763 | 205.3 | 251.9 | 213.9 |
| `step_sim_kernel` | `jit_compile_object` | 763 | 753.2 | 987.1 | 809.5 |
| `01_rain_swarm` | `parse_format` | 1309 | 75.9 | 82.4 | 80.8 |
| `01_rain_swarm` | `sema_analyze` | 1309 | 232.5 | 253.5 | 239.0 |
| `01_rain_swarm` | `mir_lower_verify` | 1309 | 3.0 | 3.2 | 3.1 |
| `01_rain_swarm` | `codegen_all_targets` | 1309 | 162.9 | 168.0 | 163.2 |
| `01_rain_swarm` | `jit_compile_object` | 1309 | 639.9 | 722.3 | 659.2 |
| `03_metroidvania_core` | `parse_format` | 6663 | 309.9 | 352.7 | 325.8 |
| `03_metroidvania_core` | `sema_analyze` | 6663 | 873.0 | 1048.1 | 911.0 |
| `03_metroidvania_core` | `mir_lower_verify` | 6663 | 16.2 | 16.7 | 16.5 |
| `03_metroidvania_core` | `codegen_all_targets` | 6663 | 223.1 | 244.3 | 231.3 |
| `03_metroidvania_core` | `jit_compile_object` | 6663 | 951.1 | 1123.5 | 978.7 |
| `05_soulslike_combat` | `parse_format` | 6253 | 265.8 | 363.7 | 294.4 |
| `05_soulslike_combat` | `sema_analyze` | 6253 | 856.6 | 956.5 | 886.3 |
| `05_soulslike_combat` | `mir_lower_verify` | 6253 | 15.8 | 15.9 | 15.8 |
| `05_soulslike_combat` | `codegen_all_targets` | 6253 | 265.8 | 320.2 | 274.4 |
| `05_soulslike_combat` | `jit_compile_object` | 6253 | 816.1 | 963.3 | 853.3 |

### 4-Tier Execution Throughput & Selective Ticks

| Workload | Subject | Entities | Median (us) | P95 (us) | ns/entity | Throughput (M ent/s) | vs Native |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `step_sim` | `native` | 1000 | 2.5 | 2.7 | 2.50 | 400.0 | 1.00x |
| `step_sim` | `jit` | 1000 | 4.0 | 4.3 | 4.01 | 249.4 | 1.60x |
| `step_sim` | `c99:release` | 1000 | 2.8 | 3.0 | 2.81 | 355.6 | 1.12x |
| `step_sim` | `rust_guest:release` | 1000 | 3.0 | 3.2 | 2.96 | 338.3 | 1.18x |
| `step_sim` | `native` | 50000 | 105.6 | 115.7 | 2.11 | 473.6 | 1.00x |
| `step_sim` | `jit` | 50000 | 150.5 | 162.3 | 3.01 | 332.2 | 1.43x |
| `step_sim` | `c99:release` | 50000 | 84.8 | 90.6 | 1.70 | 589.7 | 0.80x |
| `step_sim` | `rust_guest:release` | 50000 | 94.6 | 106.7 | 1.89 | 528.8 | 0.90x |
| `selective_mut_slice` | `selective_1pct` | 50000 | 2.0 | 2.0 | 0.04 | 25196.9 | 1.00x |
| `selective_mut_slice` | `selective_100pct` | 50000 | 40.8 | 60.1 | 0.82 | 1226.3 | 1.00x |
<!-- BENCHMARK_REPORT_END -->
