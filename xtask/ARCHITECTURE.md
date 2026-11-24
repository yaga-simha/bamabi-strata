# Architecture: `xtask`

`xtask/src/main.rs` parses CLI arguments (`parse_args` -> `Task`) using pure Rust `std` only (empty `[dependencies]`) and dispatches directly to repository verification subcommands:
- `cmd_fmt`: Runs `cargo fmt --all [-- --check]`.
- `cmd_lint`: Enforces `#![forbid(unsafe_code)]` + `#![warn(missing_docs)]` headers across all 14 entrypoints (12 workspace crates), zero-Bevy `cargo tree` on 8 crates (`strata_syntax`, `strata_sema`, `strata_mir`, `strata_codegen`, `strata_jit`, `strata_lsp`, `strata_docs`, `xtask`), zero-`libloading`/`bamabi_host` in `bamabi_native_rt --features static-console`, strict `clippy -D warnings`, strict `RUSTDOCFLAGS="-D warnings" cargo doc`, and `--no-default-features` profile checks.
- `cmd_test` & `cmd_nightly`: Executes unit, integration, `proptest` (`PROPTEST_CASES`), `static-console`, `--no-default-features`, doc-test, and `parity_4way` targets.
- `cmd_kani`: Invokes `cargo kani` on `bamabi_native_rt` (`static-console`), `strata_sema`, `strata_mir`, `strata_jit`, and `strata_lsp` (`PO-S1`..`PO-S12`, `PO-S14`..`PO-S16`).
- `cmd_bench`: Runs `cargo run --release -p strata_bench` and verifies/splices `BENCHMARKS.md` markers.
- `cmd_audit`: Dynamically checks `abi-lock.toml` and `Cargo.lock` `bamabi_sys` parity (`verify_wire_lock_parity` supporting both locked GitHub revisions and active federation path overlays), `typos`, and `cargo deny check`.
