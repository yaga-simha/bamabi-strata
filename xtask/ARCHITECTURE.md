# Architecture: `xtask`

`xtask/src/main.rs` parses CLI arguments (`parse_args` -> `Task`) using pure Rust `std` only and dispatches directly to repository verification subcommands:
- `cmd_fmt`: Runs `cargo fmt --all [-- --check]`.
- `cmd_lint`: Enforces `#![forbid(unsafe_code)]` + `#![warn(missing_docs)]` headers, zero-Bevy `cargo tree` on 8 crates, zero-`libloading`/`bamabi_host` in `bamabi_native_rt --features static-console`, strict `clippy -D warnings`, strict `RUSTDOCFLAGS="-D warnings" cargo doc`, and `--no-default-features` profile checks.
- `cmd_test` & `cmd_nightly`: Executes unit, integration, `proptest` (`PROPTEST_CASES`), `static-console`, `--no-default-features`, and doc-test targets.
- `cmd_kani`: Invokes `cargo kani` on `bamabi_native_rt` (`static-console`), `strata_sema`, `strata_mir`, `strata_jit`, and `strata_lsp`.
- `cmd_bench`: Runs `cargo run --release -p strata_bench` and verifies/splices `BENCHMARKS.md` markers.
- `cmd_audit`: Checks `abi-lock.toml` parity, `Cargo.lock` `bamabi-wire` revision pin, `typos`, and `cargo deny check`.
