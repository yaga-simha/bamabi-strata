# Architecture: `strata_profile`

`benches/strata_profile` provides closed-loop runtime & allocation profiling over real Bevy `0.20` (`MinimalPlugins`-equivalent `App` + `TaskPoolPlugin` + `AbiModPlugin`) and Cranelift JIT `.dylib` mods, intentionally decoupled from `stratac/sim-runner` so `hotpath-alloc` owns `#[global_allocator]` cleanly.

## Modules
- `src/lib.rs`: Defines the five `.strata` stress kernels (`PAR_100K_SOURCE`, `SPATIAL_GRID_SOURCE`, `SELECTIVE_50K_SOURCE`, `ATOMIC_STORM_SOURCE`, `NET_SIM_SOURCE`) and `compile_profile_jit` (`strata_sema -> strata_mir -> strata_jit`).
- `benches/strata_profile.rs`: Executes and measures 5 workloads (`par_100k`, `spatial_grid_10k`, `selective_50k`, `atomic_10k`, `net_sim`) with `#[hotpath::measure]`, `hotpath::channels!`, and `hotpath::io!`, supporting `STRATA_PROFILE_CASE` single-case filtering for standalone `Max RSS` / `hotpath-alloc` inspection.
