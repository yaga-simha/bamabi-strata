# Tests: `stratac`

```bash
cargo test -p stratac --all-features
cargo test -p stratac --test parity_4way --release --all-features
cargo check -p stratac --no-default-features
```

## Suites
1. **Unit Tests (`src/{cli,exit_codes,commands,sim_runner}.rs`):** CLI argument parsing (`build`/`watch`/`onboard`/`graph`) & key-flag validation, exit code distinctness, `eval_assert_expr` predicates, `resolve_wire_rev` & portable patch config checks, and deterministic error codes.
2. **CLI & Cookbook Suite (`tests/cli_and_cookbooks.rs`):** Runs `check`, `layout`, `explain-par`, `fmt` on all 8 cookbooks; runs headless `sim_test` and `net_sim_test`; runs 50-cycle hot-reload & `notify-debouncer-full` watch checks; verifies `.bampack` Ed25519 signing + `--target bevy-native --static-console` (`cargo check`), plus ignored 10,000-cycle soak test.
3. **Graph CLI Suite (`tests/graph_cli.rs`):** Tests `stratac graph export|apply` CLI dispatch, position-only zero-diff sidecar edits, comment preservation, and semantic error rejection.
4. **Network Simulation Suite (`tests/net_sim_tests.rs`):** Exercises headless `net_sim_test` (`ServerWorld` + `ClientWorld[]`), multi-batch POD message conservation, authority isolation, RPC delivery, reliable ARQ under partial loss vs `loss: 1.0`, quantization-aware `assert_converged`, and cookbooks `07`/`08`.
5. **4-Way Differential Parity Suite (`tests/parity_4way.rs` — 10 tests):** Steps JIT, C99, Safe Rust Guest `.cdylib`, and Tier 3 Native across 500 `FixedUpdate` frames + live `v1 -> v2` reloads, Slot 67 migrations, `atomic` rollbacks, 2-pass CSR spatial grids, Slot 58 `iter_up_cascade`, `fix64` division + mixed arithmetic + `NB-1`/`NB-2`/`NB-3`, `Option` queries, and `ParamSet` non-`@sparse` tasks + disjoint `With`/`Without` queries.
