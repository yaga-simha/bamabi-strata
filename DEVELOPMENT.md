# Development Guide (`bamabi-strata`)

Instructions for building, testing, formally verifying, benchmarking, and documenting `bamabi-strata`.

---

## 1. Prerequisites

### Required Toolchain
- **Rust (`stable`):** Pinned in `rust-toolchain.toml` (`edition = "2024"`, MSRV `1.95`), with `rustfmt` and `clippy`.
- **ISO C99 Compiler & Linker:** `clang`, `gcc`, or `cc` (used by `strata_jit` shared-library linking, `strata_codegen` ISO C99 syntax checks, `stratac build --target c99`, and 4-way parity tests).

### Optional Toolchain (for `--full` CI / Extended Audits)
- **Kani Rust Verifier (`0.68.0` / CBMC `6.11.0`):** `cargo install --locked kani-verifier && cargo kani setup` (`cargo xtask kani`).
- **Spellchecker (`typos`):** `cargo install typos-cli` (`cargo xtask audit`).
- **Dependency Audit (`cargo-deny`):** `cargo install cargo-deny` (`cargo xtask audit`).
- **GitHub CLI (`gh`):** For repo workflows.

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
# - `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]` header checks on all 11 crates
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

# Formal verification (Kani PO-S1..PO-S10)
cargo xtask kani
cargo xtask kani --crate strata_sema --timeout 300

# Benchmarks (compiler pipeline + 4-tier execution throughput)
cargo xtask bench --quick
cargo xtask bench --write-docs --json target/bench-results.json
cargo xtask bench --check-docs

# Security, license, spellcheck, and abi-lock / Cargo.lock pin audit
cargo xtask audit

# Extended proptest & parity regression run
cargo xtask nightly --cases 1024

# Complete local CI gates
cargo xtask ci              # fmt + bench --check-docs + lint + test + bench --quick
cargo xtask ci --no-bench   # Fast gate without benchmark run
cargo xtask ci --full       # Full gate + audit + Kani proofs (PO-S1..PO-S10)
```

---

## 3. ABI Lockfile & Upstream Pinning

- `abi-lock.toml` pins `bam_abi_version = "0x0003_0000"`, `c_symbol_prefix = "bamabi"`, `workspace_version = "0.3.0"`, `bevy_version = "0.20.1"`, `rust_version = "1.95"`, and `edition = "2024"`.
- `Cargo.lock` pins `bamabi_sys`, `bamabi_macros`, and `bamabi_sdk_gen` to the stabilized 68-slot ABI `0.3.0` commit (`7a32b7bd329167c8dda82259659b3da54a5ab748` on `yaga-simha/bamabi-wire`) matching `bamabi_host_sys`. When adding or updating unrelated workspace dependencies, update only targeted packages (e.g. `cargo update -p <pkg>`) so the `bamabi-wire` pin remains locked.
- Generated guest/native test crates built dynamically by `stratac::commands::write_local_patch_config` use relative sibling checkouts only when present locally and fall back transparently to public GitHub URLs in CI environments.
