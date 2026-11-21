# Tests: `stratac`

```bash
cargo test -p stratac --all-features
cargo test -p stratac --test parity_4way --all-features
cargo check -p stratac --no-default-features
```

## Suites
1. **Unit Tests (`src/{cli,exit_codes,commands,sim_runner}.rs` — 5 tests):** CLI argument parsing & invalid target rejection, exit code distinctness, `eval_assert_expr` predicates, portable patch config checks, and deterministic error codes.
2. **CLI & Cookbook Suite (`tests/cli_and_cookbooks.rs` — 4 active + 1 ignored soak test):** Runs `check`, `layout`, `explain-par`, `fmt` on all 6 cookbooks; runs headless `sim_test`; runs 50-cycle hot-reload stability; verifies `.bampack` Ed25519 signing + `watch` + `--target bevy-native --static-console` (`cargo check`).
3. **4-Way Differential Parity Suite (`tests/parity_4way.rs` — 1 test):** Steps JIT, C99, Safe Rust Guest `.cdylib`, and Tier 3 Native across 500 `FixedUpdate` frames + live `v1 -> v2` `reload_mod_from`, asserting bit-exact SHA-256 & FNV-1a world digests.
