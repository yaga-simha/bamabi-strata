# Architecture: `stratac`

## Modules
- `src/cli.rs`: `clap` grammar defining `Cli`, `Commands`, `BuildTarget`, `OnboardTarget`, and `OutputFormat` (`text` / `json`).
- `src/exit_codes.rs`: Deterministic process exit codes (`0` OK, `1` compile/CLI error, `2` `sim_test` failure, `3` layout/parity/`--fmt --check` failure).
- `src/commands.rs`: Subcommand implementations (`cmd_check`, `cmd_fmt`, `cmd_layout`, `cmd_explain_par`, `cmd_test`, `cmd_build`, `cmd_watch`, `cmd_onboard`), ISO C99 `-ffp-contract=off` compilation, `.bampack` Ed25519 signing via `bamabi_trust`, and portable generated-crate patch helper `write_local_patch_config`.
- `src/sim_runner.rs`: Headless `bamabi_host` + Bevy `0.20` world harness, `sim_test` runner, and `hash_world_pod_state` deterministic SHA-256 + FNV-1a snapshot hasher.
