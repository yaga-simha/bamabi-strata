# Architecture: `stratac`

## Modules
- `src/cli.rs`: `clap` grammar defining `Cli`, `Commands` (all 9 subcommands), `GraphAction` (`export`, `apply`), `BuildTarget`, `OnboardTarget`, and `OutputFormat` (`text` / `json`).
- `src/exit_codes.rs`: Deterministic process exit codes (`0` OK, `1` compile/CLI error, `2` `sim_test` failure, `3` layout/parity/`fmt --check` failure).
- `src/commands.rs`: Subcommand implementations (`cmd_check`, `cmd_fmt`, `cmd_layout`, `cmd_explain_par`, `cmd_test`, `cmd_build`, `cmd_watch`, `cmd_onboard`), ISO C99 `-ffp-contract=off` compilation, `.bampack` Ed25519 signing via `bamabi_trust`, dynamic `resolve_wire_rev`, and `try_write_local_patch_config_with_ws` supporting both locked git revisions and local federation path overlays.
- `src/graph_cmd.rs`: `cmd_graph_export` and `cmd_graph_apply` implementing lossless Graph IR JSON export/patch application with `.strata.graph.json` layout sidecars.
- `src/sim_runner.rs` (`#[cfg(feature = "sim-runner")]`): Headless `bamabi_host` + Bevy `0.20` world harness, `sim_test` runner, `SIM_GLOBAL_ALLOC` (`#[global_allocator]`), and `hash_world_pod_state` deterministic SHA-256 + FNV-1a snapshot hasher.
- `src/net_sim_runner.rs` (`#[cfg(feature = "sim-runner")]`): Headless `net_sim_test` executing `ServerWorld` + `ClientWorld[]` with configurable `latency`, `jitter`, `loss`, reliable ARQ, and quantization-aware convergence checks.
