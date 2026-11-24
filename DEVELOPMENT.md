# Development Guide (`bamabi-strata`)

Instructions for building, testing, formally verifying, benchmarking, profiling, and synchronizing `bamabi-strata`.

---

## 1. Prerequisites

### Required Toolchain
- **Rust (`stable`):** Pinned in `rust-toolchain.toml` (`edition = "2024"`, MSRV `1.95`), with `rustfmt` and `clippy`.
- **ISO C99 Compiler & Linker:** `clang`, `gcc`, or `cc` (used by `strata_jit` shared-library linking, `strata_codegen` ISO C99 syntax checks, `stratac build --target c99`, and 4-way parity tests).

### Optional Toolchain (for `--full` CI / Extended Audits / E2E)
- **Kani Rust Verifier (`0.68.0` / CBMC `6.11.0`):** `cargo install --locked kani-verifier && cargo kani setup` (`cargo xtask kani`).
- **Spellchecker (`typos`):** `cargo install typos-cli` (`cargo xtask audit`).
- **Dependency Audit (`cargo-deny`):** `cargo install cargo-deny` (`cargo xtask audit`).
- **Python 3:** For `fixtures/e2e_phase3/run_e2e.py` and `../bamabi-dev-overlay/sync_check.py`.

---

## 2. Cargo Aliases & Workspace Commands

`.cargo/config.toml` configures portable aliases with zero machine-specific paths:

```toml
[alias]
docs = "doc --workspace --no-deps --all-features"
xtask = "run --package xtask --"
```

Common workflows via `cargo xtask`:

```bash
# Help & flag discovery
cargo xtask --help

# Format check or auto-fix
cargo xtask fmt
cargo xtask fmt --fix

# Strict workspace lints:
# - `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]` header checks on all 14 crate entrypoints (12 crates)
# - Zero-Bevy `cargo tree` check on 8 compiler/LSP/docs/xtask crates
# - Zero `libloading` / `bamabi_host` check on `bamabi_native_rt --features static-console`
# - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
# - `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features`
cargo xtask lint

# Tests (unit, integration, proptest, static-console, doc tests, --no-default-features)
cargo xtask test
cargo xtask test --unit
cargo xtask test --integration
cargo xtask test --proptest --cases 256
cargo xtask test --static-console
cargo xtask test --doc

# Formal verification (Kani PO-S1..PO-S12, PO-S14..PO-S16)
cargo xtask kani
cargo xtask kani --crate strata_sema --timeout 300

# Benchmarks (compiler pipeline + 4-tier execution throughput)
cargo xtask bench --quick
cargo xtask bench --write-docs --json target/bench-results.json
cargo xtask bench --check-docs

# Security, license, spellcheck, and abi-lock / Cargo.lock pin audit
cargo xtask audit

# Extended proptest (1024 cases) & 4-way differential parity regression run
cargo xtask nightly --cases 1024

# Complete local CI gates
cargo xtask ci              # fmt + bench --check-docs + lint + test + bench --quick
cargo xtask ci --no-bench   # Fast gate without benchmark run
cargo xtask ci --full       # Full gate + audit + Kani proofs (PO-S1..PO-S12, PO-S14..PO-S16)
```

Additional Criterion `0.8` microbenches, `hotpath-rs` profiling, and opaque-box Phase 3 E2E suites:

```bash
cargo bench --workspace --no-run
cargo bench -p strata_profile --bench strata_profile
HOTPATH_METRICS_SERVER_OFF=1 cargo bench -p strata_profile --bench strata_profile --features hotpath-alloc
cargo test -p stratac --test parity_4way --release --all-features
python3 fixtures/e2e_phase3/run_e2e.py --tier all
```

---

## 3. ABI Lockfile, Federation Overlay & Upstream Pinning

- `abi-lock.toml` pins `project.name = "bamabi-strata"`, `project.layer = 3`, `bam_abi_version = "0x0003_0000"`, `c_symbol_prefix = "bamabi"`, `workspace_version = "0.3.0"`, `bevy_version = "0.20.1"`, `rust_version = "1.95"`, and `edition = "2024"`.
- **Co-Development Federation (`bamabi-dev-overlay`):** Tracked `Cargo.toml` manifests declare canonical GitHub `branch = "main"` URLs for `bamabi-wire`, `bamabi-tools`, and `bamabi-core` with zero `[patch]`/`[replace]` sections inside this repo. Local multi-repo co-development uses the federation parent's `.cargo/config.toml` managed by `bamabi-dev-overlay`, verified across all layers with:
  ```bash
  python3 ../bamabi-dev-overlay/sync_check.py --root .. --with-strata
  ```
- **Dynamic Lock Parity (`cargo xtask audit`):** `xtask::verify_wire_lock_parity` validates `Cargo.lock`'s `bamabi_sys` entry dynamically—accepting both locked GitHub revisions (`bamabi-wire.git`) and active local path-patched overlays when `../bamabi-wire` is present—without any hardcoded commit hash constants.
- **Generated Test/Onboard Crates:** `stratac::commands::try_write_local_patch_config_with_ws` and `stratac::commands::resolve_wire_rev` inspect `Cargo.lock` (falling back to sibling `../bamabi-wire` git `HEAD` or local path overrides during active federation overlays) so generated C99, Rust Guest, and `--target bevy-native` crates build seamlessly offline and in standalone CI.
