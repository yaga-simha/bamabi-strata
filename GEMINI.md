# Repository Guide: `bamabi-strata`

Workspace guide for **`bamabi-strata`** (`v0.3.0`, pinned to `bamabi-wire` ABI `0x0003_0000`, `bevy_version = "0.20.1"`, Rust Edition `2024`, MSRV `1.95`).

## 1. Non-Negotiable Engineering Invariants
- **Read-Only Sibling Repositories:** NEVER modify `../bamabi-wire`, `../bamabi-tools`, `../bamabi-core`, `../bamabi-dev-overlay`, or `../bamabi-showcase`.
- **Zero-Bevy Compiler & Tooling Isolation (8 of 11 Crates):** `strata_syntax`, `strata_sema`, `strata_mir`, `strata_codegen`, `strata_jit`, `strata_lsp`, `strata_docs`, and `xtask` MUST NEVER depend on any `bevy*` crate:
  ```bash
  cargo tree -p <crate> | sed 's/ (.*//' | grep -v bamabi | grep -i bevy # MUST print NOTHING
  ```
- **Zero-External-Dependency Crates:** `xtask` and `strata_docs` MUST have empty `[dependencies]` tables.
- **Safety Policy:** All 11 workspace crates enforce `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.
- **ABI Wire Truth:** Never hardcode `BamHostApi` slot counts, byte offsets, or query limits. Always reference `bamabi_sys::offsets::*`, `bamabi_sys::BAM_HOST_API_SLOT_COUNT`, `bamabi_sys::MAX_TERMS_PER_QUERY`, `bamabi_sys::MAX_QUERIES_PER_SYSTEM`, and `bamabi_sys::ComponentUuid` / `fnv1a_64_*` primitives.

## 2. Canonical CI Verification Gate (`cargo xtask`)

```bash
cargo xtask ci              # fmt, bench --check-docs, lint (policy + isolation + clippy + rustdoc), test, bench --quick
cargo xtask ci --full       # adds audit (abi-lock + Cargo.lock + typos + cargo deny check) and kani (PO-S1..PO-S10)
```
