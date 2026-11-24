# Tests & Benchmarks: `strata_profile`

```bash
cargo test -p strata_profile --all-features
cargo bench -p strata_profile --bench strata_profile
HOTPATH_METRICS_SERVER_OFF=1 STRATA_PROFILE_CASE=atomic_10k \
  cargo bench -p strata_profile --bench strata_profile --features hotpath-alloc
```

## Suites
1. **Unit Tests (`src/lib.rs` — 1 test):** `all_profiling_kernels_pass_sema_and_mir` verifies all 5 `.strata` profiling kernels pass `analyze_source`, `lower_to_mir`, and `verify_mir`.
2. **Headless Stress Harness (`benches/strata_profile.rs`):** Exercises `par_100k` (100k entities), `spatial_grid_10k` (2-pass CSR `1k/5k/10k` + native `0 B` steady-state), `selective_50k` (1% dirty `&mut?`), `atomic_10k` (10k rollback storm), and `net_sim` (1 server + 4 client worlds, 26,400 packets).
