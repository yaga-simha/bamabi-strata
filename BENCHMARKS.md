# Benchmarking Strategy & Recorded Results (`bamabi-strata`)

`benches/strata_bench` measures both **compiler frontend/backend latency** (parsing, Salsa/Theorem-0.1 semantics, MIR passes, three-target codegen, Cranelift PIC object emission) and **4-tier ECS execution throughput** across Native Bevy `0.20`, Cranelift PIC JIT (`strata_jit`), strict ISO C99 (`strata_codegen::c99`), and Safe Rust Guest `.cdylib` (`strata_codegen::rust_guest`).

---

## 1. Methodology & Pre-Timing Correctness Gate

- **Correctness Before Timing:** Prior to collecting any runtime timing samples, `strata_bench` boots four independent Bevy `0.20` `World`s populated with `128` entities and steps all four backends (`native`, `jit`, `c99:release`, `rust_guest:release`) for `120` `FixedUpdate` frames, verifying bit-identical SHA-256 and FNV-1a world POD state digests (`stratac::sim_runner::hash_world_pod_state`). Similarly, compiler fixtures (`step_sim_kernel` + cookbooks `01_rain_swarm`, `03_metroidvania_core`, `05_soulslike_combat`) are parse/sema/MIR-verified before timing.
- **Release Optimization:** `cargo xtask bench` always builds and executes `strata_bench` with `--release`, compiling C99 guests with `-O2 -ffp-contract=off` and Rust/JIT targets in release/speed mode.
- **Workloads:**
  - `compiler`: `parse_format`, `sema_analyze`, `mir_lower_verify`, `codegen_all_targets`, `jit_compile_object`.
  - `runtime` (`step_sim`): Per-frame ECS physics integration (`Pos`, `Vel`, `&mut? Heat` conditional mutation) across `1,000` and `50,000` entities (`--quick`: `1,000` & `10,000`).
  - `runtime` (`par_100k`): Dense `100,000`-entity `@par(chunk = 1024)` physics integration (`Pos`, `Vel`) dispatched via `ComputeTaskPool` (`<= 0.35 ns/entity` threshold evaluated on `bevy_native`, `c99:release`, and `rust_guest:release`; reports `PASS` / `HOST_VARIANCE_WARN` by default, with strict exit-1 enforcement opt-in via `--enforce-par-gate`).
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
| `step_sim_kernel` | `parse_format` | 763 | 60.2 | 60.8 | 60.3 |
| `step_sim_kernel` | `sema_analyze` | 763 | 297.8 | 304.6 | 298.5 |
| `step_sim_kernel` | `mir_lower_verify` | 763 | 32.5 | 33.3 | 34.4 |
| `step_sim_kernel` | `codegen_all_targets` | 763 | 335.9 | 409.1 | 361.3 |
| `step_sim_kernel` | `jit_compile_object` | 763 | 2312.4 | 2523.2 | 2327.3 |
| `01_rain_swarm` | `parse_format` | 1309 | 76.8 | 91.9 | 81.6 |
| `01_rain_swarm` | `sema_analyze` | 1309 | 386.0 | 527.8 | 417.7 |
| `01_rain_swarm` | `mir_lower_verify` | 1309 | 31.0 | 31.4 | 31.1 |
| `01_rain_swarm` | `codegen_all_targets` | 1309 | 410.4 | 556.5 | 441.4 |
| `01_rain_swarm` | `jit_compile_object` | 1309 | 2855.2 | 3338.7 | 2941.3 |
| `03_metroidvania_core` | `parse_format` | 6663 | 316.8 | 366.5 | 330.5 |
| `03_metroidvania_core` | `sema_analyze` | 6663 | 1764.8 | 2045.1 | 1811.9 |
| `03_metroidvania_core` | `mir_lower_verify` | 6663 | 168.6 | 171.6 | 169.1 |
| `03_metroidvania_core` | `codegen_all_targets` | 6663 | 1719.6 | 1973.1 | 1753.2 |
| `03_metroidvania_core` | `jit_compile_object` | 6663 | 11760.1 | 12485.2 | 11923.1 |
| `05_soulslike_combat` | `parse_format` | 6253 | 271.6 | 274.9 | 272.3 |
| `05_soulslike_combat` | `sema_analyze` | 6253 | 1479.0 | 1808.9 | 1515.1 |
| `05_soulslike_combat` | `mir_lower_verify` | 6253 | 141.6 | 156.5 | 147.0 |
| `05_soulslike_combat` | `codegen_all_targets` | 6253 | 1608.5 | 1882.5 | 1625.2 |
| `05_soulslike_combat` | `jit_compile_object` | 6253 | 9101.2 | 9481.0 | 9098.4 |

### 4-Tier Execution Throughput & Selective Ticks

| Workload | Subject | Entities | Median (us) | P95 (us) | ns/entity | Throughput (M ent/s) | vs Native |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `step_sim` | `native` | 1000 | 2.5 | 2.7 | 2.46 | 405.9 | 1.00x |
| `step_sim` | `jit` | 1000 | 7.0 | 7.8 | 7.01 | 142.8 | 2.84x |
| `step_sim` | `c99:release` | 1000 | 4.3 | 5.3 | 4.32 | 231.7 | 1.75x |
| `step_sim` | `rust_guest:release` | 1000 | 5.6 | 6.1 | 5.57 | 179.6 | 2.26x |
| `step_sim` | `native` | 50000 | 105.8 | 115.1 | 2.12 | 472.5 | 1.00x |
| `step_sim` | `jit` | 50000 | 262.3 | 289.6 | 5.25 | 190.6 | 2.48x |
| `step_sim` | `c99:release` | 50000 | 121.1 | 155.2 | 2.42 | 412.9 | 1.14x |
| `step_sim` | `rust_guest:release` | 50000 | 133.6 | 148.0 | 2.67 | 374.4 | 1.26x |
| `selective_mut_slice` | `selective_1pct` | 50000 | 2.0 | 2.0 | 0.04 | 25533.0 | 1.00x |
| `selective_mut_slice` | `selective_100pct` | 50000 | 41.1 | 60.9 | 0.82 | 1217.3 | 1.00x |
| `par_100k` | `bevy_native` | 100000 | 82.0 | 87.8 | 0.82 | 1219.6 | 1.00x |
| `par_100k` | `jit` | 100000 | 105.9 | 111.5 | 1.06 | 944.0 | 1.29x |
| `par_100k` | `c99:release` | 100000 | 69.7 | 75.5 | 0.70 | 1434.0 | 0.85x |
| `par_100k` | `rust_guest:release` | 100000 | 70.1 | 77.2 | 0.70 | 1427.0 | 0.85x |

- **@par(chunk = 1024) 100k Gate (<= 0.35 ns/entity, 14 threads, enforced=false):** `HOST_VARIANCE_WARN` — `bevy_native`=0.820 ns/ent (min 0.737, spread 17.2%), `jit`=1.059 ns/ent (min 0.941, spread 16.4%, vs_native 1.29x), `c99:release`=0.697 ns/ent (min 0.651, spread 14.9%, vs_native 0.85x), `rust_guest:release`=0.701 ns/ent (min 0.644, spread 18.3%, vs_native 0.85x)
<!-- BENCHMARK_REPORT_END -->

---

## 4. Gate 4 `criterion 0.8` & `hotpath-rs` Profiling Suite

Workspace-wide `criterion = "0.8"` (`0.8.2`) microbenchmarks and opt-in `hotpath = "0.32"` (`0.32.1`, `criterion-0-8`) closed-loop timing, heap allocation (`hotpath-alloc`), channel queue-depth, byte-level I/O, and thread contention telemetry. Default builds keep `hotpath` features disabled (`lib_off` zero-cost stubs), and `benches/strata_profile` is isolated from `stratac/sim-runner` so its `#[global_allocator]` never conflicts with `hotpath-alloc`.

### Running Criterion Microbenches & `strata_profile`

```bash
# Run any of the 5 crate Criterion microbenchmark suites
cargo bench -p bamabi_native_rt --bench native_rt_bench
cargo bench -p strata_sema      --bench sema_bench
cargo bench -p strata_mir       --bench mir_bench
cargo bench -p strata_jit       --bench jit_bench
cargo bench -p strata_lsp       --bench lsp_bench

# Bounded allocation-profiled Criterion sweep (hotpath-alloc)
HOTPATH_METRICS_SERVER_OFF=1 HOTPATH_CRITERION_ITERATIONS=1000 \
  cargo bench -p bamabi_native_rt --bench native_rt_bench --features hotpath-alloc -- selective_mut_slice_50k/ecs_slice/1pct_dirty

# Run headless Bevy 0.20 + JIT/Native ECS stress suite (all 5 workloads)
cargo bench -p strata_profile --bench strata_profile

# Profile all 5 headless workloads with hotpath-alloc timing, alloc, channels, io, threads
HOTPATH_METRICS_SERVER_OFF=1 \
  cargo bench -p strata_profile --bench strata_profile --features hotpath-alloc

# Profile a single headless workload case (e.g. par_100k, spatial_grid, selective_50k, atomic_10k, net_sim)
HOTPATH_METRICS_SERVER_OFF=1 STRATA_PROFILE_CASE=atomic_10k \
  cargo bench -p strata_profile --bench strata_profile --features hotpath-alloc
```

### Crate Criterion `0.8` Microbench Summary (`aarch64-macos`)

| Crate / Bench | Benchmark ID | Mean Time | Throughput / Notes | `hotpath-alloc` Bytes / Iter |
| --- | --- | ---: | ---: | ---: |
| `bamabi_native_rt` (`native_rt_bench`) | `selective_mut_slice_50k/ecs_slice/0pct_clean` | `28.12 ns` | `1778.1 Gelem/s` | — |
| `bamabi_native_rt` (`native_rt_bench`) | `selective_mut_slice_50k/ecs_slice/1pct_dirty` | `1.96 µs` | `25.51 Gelem/s` (1000 iters avg `2.01 µs`, P95 `2.08 µs`) | `0 B` |
| `bamabi_native_rt` (`native_rt_bench`) | `selective_mut_slice_50k/ecs_slice/10pct_dirty` | `21.18 µs` | `2.36 Gelem/s` | — |
| `bamabi_native_rt` (`native_rt_bench`) | `selective_mut_slice_50k/ecs_slice/100pct_dirty` | `42.08 µs` | `1.19 Gelem/s` | — |
| `bamabi_native_rt` (`native_rt_bench`) | `fixed_point_batch_1024/fix32_arith_div` | `819.65 ns` | `1.25 Gelem/s` | — |
| `bamabi_native_rt` (`native_rt_bench`) | `fixed_point_batch_1024/fix64_div_i128` | `7.51 µs` | `136.29 Melem/s` | — |
| `bamabi_native_rt` (`native_rt_bench`) | `fixed_point_batch_1024/fix64_div_restoring` | `138.93 µs` | `7.37 Melem/s` | — |
| `bamabi_native_rt` (`native_rt_bench`) | `net_quantize_delta_128/encode_quantize_pack_128` | `3.35 µs` | `38.15 Melem/s` (1000 iters avg `3.36 µs`, P95 `3.46 µs`) | `0 B` |
| `bamabi_native_rt` (`native_rt_bench`) | `net_quantize_delta_128/decode_verify_unpack_128` | `2.98 µs` | `42.95 Melem/s` | — |
| `strata_sema` (`sema_bench`) | `sema_cold_cookbooks/01_rain_swarm` .. `08_authoritative_multiplayer` | `307.16 µs` – `1.54 ms` | `3.42` – `4.59 MiB/s` | — |
| `strata_sema` (`sema_bench`) | `sema_salsa_body_edit/03_metroidvania_core` | `968.34 µs` | `6.56 MiB/s` (`0` `resolve_layouts` runs; 200 iters avg `1.10 ms`) | `1.9 MB` |
| `strata_sema` (`sema_bench`) | `sema_salsa_body_edit/05_soulslike_combat` | `830.28 µs` | `7.18 MiB/s` (`0` `resolve_layouts` runs) | — |
| `strata_sema` (`sema_bench`) | `sema_authority_place_origin/08_authoritative_multiplayer` | `666.31 µs` | `4.25 MiB/s` | — |
| `strata_sema` (`sema_bench`) | `sema_authority_place_origin/synthetic_deep_place_origin` | `417.09 µs` | `2.77 MiB/s` | — |
| `strata_mir` (`mir_bench`) | `mir_lower_verify/{01..08, spatial_grid_csr}` | `24.09 µs` – `169.32 µs` | — | — |
| `strata_mir` (`mir_bench`) | `mir_spatial_csr_scaling/csr_rebuild_2pass/{1000,10000,50000}` | `4.00 / 33.42 / 172.03 µs` | `250.1 / 299.2 / 290.6 Melem/s` (`O(N)` linear) | `0 B` (`N=10k`) |
| `strata_mir` (`mir_bench`) | `mir_spatial_csr_scaling/csr_query_disc_64/{1000,10000,50000}` | `2.05 / 3.44 / 6.28 µs` | `0.49 / 2.91 / 7.97 Gelem/s` | — |
| `strata_jit` (`jit_bench`) | `jit_emit_pic_speed/01_rain_swarm` .. `08_authoritative_multiplayer` | `2.49 ms` – `12.01 ms` | `03_metroidvania_core`: `12.01 ms` (`541.6 KiB/s`) | `12.3 MB` (`03`) |
| `strata_jit` (`jit_bench`) | `jit_opt_level_compare/{fast_compile,speed,aot_emit_all}/03_metroidvania_core` | `9.11 / 11.60 / 1.55 ms` | `714.3 KiB/s` / `560.8 KiB/s` / `4.09 MiB/s` | — |
| `strata_jit` (`jit_bench`) | `jit_opt_level_compare/{fast_compile,speed,aot_emit_all}/05_soulslike_combat` | `7.15 / 8.89 / 1.46 ms` | `854.0 KiB/s` / `687.2 KiB/s` / `4.07 MiB/s` | — |
| `strata_lsp` (`lsp_bench`) | `lsp_telemetry_bamt_10k/decode_slice_10k` | `59.95 µs` | `166.79 Melem/s` | `0 B` |
| `strata_lsp` (`lsp_bench`) | `lsp_telemetry_bamt_10k/decode_and_store_10k` | `106.70 µs` | `93.72 Melem/s` | — |
| `strata_lsp` (`lsp_bench`) | `lsp_incremental_and_graph/did_change_body_edit/03_metroidvania_core` | `973.43 µs` | `6.53 MiB/s` | — |
| `strata_lsp` (`lsp_bench`) | `lsp_incremental_and_graph/graph_telemetry/05_soulslike_combat` | `260.42 µs` | `24.40 MiB/s` | — |

### Headless Stress Suite (`benches/strata_profile`) & `hotpath-alloc` Diagnosis

| Workload | Execution Summary (Default / `hotpath-alloc`) | Per-Tick Quantiles (`hotpath-alloc`) | Steady-State Allocs / Telemetry |
| --- | --- | --- | --- |
| `par_100k` | `100,000` entities × `500` ticks: Native `0.786 ns/ent`, JIT `1.188 ns/ent` (default) / `0.786 / 1.218 ns/ent` (`hotpath-alloc`) | `par_100k_native_system`: Avg `77.53 µs`, P95 `92.22 µs`; `par_100k_jit_tick`: Avg `121.66 µs`, P95 `137.34 µs` | Native `10.2 KB/call` (`bevy_tasks::ComputeTaskPool::scope` per-worker boxed futures across 6 pool threads); JIT `13.5 KB/call` (`bamabi_host_sys` 24-partition dispatch + scope boxing) |
| `spatial_grid_10k` | JIT `N=1000/5000/10000` (`50` ticks): `80.5 / 627.5 / 1771.4 µs/tick` (`4278 / 46042 / 183976` hits); Native `10k` (`500` ticks): `554.0 µs/tick` (`183976` hits) | `spatial_native_2pass_csr_system`: Avg `570.45 µs`, P50 `560.64 µs`, P95 `615.42 µs`; `spatial_jit_tick`: Avg `812.61 µs`, P50 `566.27 µs` | `spatial_native_2pass_csr_system`: **`0 B`** steady-state; `spatial_jit_tick`: **`0 B`** P50/P95 (`23.3 KB` one-time init at P99) |
| `selective_50k` | `50,000` entities × `500` ticks (`500` changed/tick = `1%`): Native `71.6 µs/tick`, JIT `208.0 µs/tick` | `selective_50k_writer_system`: Avg `49.94 µs`, P95 `55.01 µs`; `selective_50k_changed_reader`: Avg `20.23 µs`, P95 `20.59 µs` | `selective_50k_writer_system` & `selective_50k_changed_reader`: **`0 B`** steady-state |
| `atomic_10k` | `10,000` rollback ticks (`require_true(false)` pre-image undo): `19.72 ms` total (default) / `20.05 ms` standalone `hotpath-alloc`, `arena_peak <= 1024 B` | `atomic_10k_tick`: Avg `1.96 µs`, P50 `1.92 µs`, P95 `2.08 µs`, P99 `2.42 µs` | **`0 B`** at P50/P95/P99 (`80.2 KB` total over 10k calls); standalone `Max RSS = 19.5 MB` |
| `net_sim` | `1` server + `4` client Bevy worlds × `132` entities × `200` ticks (`26,400` packets): `7.42 ms` total (default) / `12.15 ms` (`hotpath-alloc`) | `net_sim_step_worlds`: Avg `60.67 µs`, P50 `58.75 µs`, P95 `67.52 µs` | `hotpath::channels!`: 4 × `6,600` msgs, Max queue `33`, send->recv P50 `8.38–38.94 µs`; `hotpath::io!`: `26,600` zero-error reads, delta decode `537.3–895.5 MB/s` |

- **Closed-Loop Profiling Diagnosis:** Steady-state runtime ECS hotpaths (`selective_mut_slice_50k`, `spatial_native_2pass_csr_system`, `csr_rebuild_2pass`, `net_quantize_delta_128`, `lsp decode_slice_10k`, and P50/P95/P99 of `atomic_10k_tick` / `selective_50k_tick`) all run with **0 B** per-iteration heap allocations. On `par_100k`, the `~55 µs` gap between ideal `<= 0.35 ns/ent` and observed `0.786 ns/ent` (native) / `1.188 ns/ent` (JIT) originates inside `ComputeTaskPool::scope` threadpool boxing (`bevy_tasks`) and `bamabi_host_sys` (`../bamabi-core`, read-only sibling repository), not inside `bamabi-strata`. No speculatively intrusive edits were required.
