# Agent Guide: `strata_bench`

Crate guide for **`strata_bench`** (`v0.3.0`, `benches/strata_bench`) — compiler pipeline latency and 4-tier ECS execution throughput benchmark harness (`native`, `jit`, `c99:release`, `rust_guest:release`).

---

## 1. Crate Identity & Allowed Dependencies
- **Name:** `strata_bench` (`edition = "2024"`, MSRV `1.95`, `publish = false`)
- **Dependencies:** `bamabi_host`, `bamabi_native_rt`, `bamabi_sys`, `bevy_app`, `bevy_ecs` (`multi_threaded`), `serde`, `serde_json`, `strata_syntax`, `strata_sema`, `strata_mir`, `strata_codegen`, `strata_jit`, `stratac`, `tempfile`.

---

## 2. Safety Policy
- Enforces `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.

---

## 3. Owned Surface & Frozen Contracts
- **`compiler_bench.rs`:** `parse_format`, `sema_analyze`, `mir_lower_verify`, `codegen_all_targets`, and `jit_compile_object` latency benchmarks.
- **`runtime_bench.rs`:** Pre-timing bit-exact 4-way SHA-256 + FNV-1a parity gate (`120` frames), `step_sim` (`1,000` / `50,000` entities), `par_100k` (`100,000` entities `@par(chunk = 1024)`), and `selective_mut_slice` (`1%` vs `100%` dirty).
- **`stats.rs` & `report.rs`:** Summary statistics (`Median`, `P95`, `Mean`, `ns/entity`, `M ent/s`, `vs_native`), JSON output, and `BENCHMARKS.md` Markdown report generation.

---

## 4. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy -p strata_bench --all-targets --all-features -- -D warnings
cargo test -p strata_bench --all-features
cargo xtask bench --quick --no-write-docs
RUSTDOCFLAGS="-D warnings" cargo doc -p strata_bench --no-deps --all-features
```
