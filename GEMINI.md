# Repository Guide: `bamabi-strata`

Workspace guide for **`bamabi-strata`** (`v0.3.0`, Layer 3 above `bamabi-wire` ABI `0x0003_0000`, `bevy_version = "0.20.1"`, Rust Edition `2024`, MSRV `1.95`).

## 1. Non-Negotiable Engineering Invariants
- **Read-Only Sibling Repositories:** NEVER modify `../bamabi-wire`, `../bamabi-tools`, `../bamabi-core`, `../bamabi-dev-overlay`, or `../bamabi-showcase`.
- **Co-Development Federation Protocol:** Sibling checkouts may be wired locally via `bamabi-dev-overlay` at the federation root `.cargo/config.toml` (`[patch."https://github.com/yaga-simha/bamabi-*.git"]`) while tracked `Cargo.toml` manifests stay pinned to canonical GitHub `branch = "main"` URLs without `[patch]` or `[replace]` overrides. Validate cross-repo parity via:
  ```bash
  python3 ../bamabi-dev-overlay/sync_check.py --root .. --with-strata
  ```
- **Workspace Topology (12 Crates) & Zero-Bevy Isolation (8 of 12 Crates):**
  - 9 library/CLI/docs crates (`crates/strata_syntax`, `crates/bamabi_native_rt`, `crates/strata_sema`, `crates/strata_mir`, `crates/strata_codegen`, `crates/strata_jit`, `crates/strata_lsp`, `crates/stratac`, `crates/strata_docs`), 2 benchmark crates (`benches/strata_bench`, `benches/strata_profile`), and `xtask`.
  - `strata_syntax`, `strata_sema`, `strata_mir`, `strata_codegen`, `strata_jit`, `strata_lsp`, `strata_docs`, and `xtask` MUST NEVER depend on any `bevy*` crate:
    ```bash
    cargo tree -p <crate> | sed 's/ (.*//' | grep -v bamabi | grep -i bevy # MUST print NOTHING
    ```
- **Zero-External-Dependency Crates:** `xtask` and `strata_docs` MUST have empty `[dependencies]` tables.
- **Safety Policy:** All 12 workspace crates (all 14 entrypoints in `xtask`) enforce `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.
- **ABI Wire Truth (`bamabi-wire` 73-Slot Contract):** Never hardcode `BamHostApi` slot counts, byte offsets, struct layouts, or query limits. Always reference `bamabi_sys::offsets::*`, `bamabi_sys::BAM_HOST_API_SLOT_COUNT` (`73`; `offsets::SIZE_64 = 592`, `offsets::SIZE_32 = 300`), `bamabi_sys::MAX_TERMS_PER_QUERY` (`32`), `bamabi_sys::MAX_QUERIES_PER_SYSTEM` (`16`), `bamabi_sys::{BAM_TERM_FLAG_CHANGED, BAM_TERM_FLAG_ADDED}`, `BamQueryDesc::param_set_group`, `BamSystemDesc::{run_if_ctx, run_if_query, run_if_ctx_user_data}`, Slot 58 (`iter_up_cascade`), Layer-0 `bamabi_sys::telemetry::{SYSTEM_TELEMETRY_MAGIC, SystemTelemetryDigest64}` (`*b"BAMT"`), and `bamabi_sys::{ComponentUuid, fnv1a_64_*}`.

## 2. Canonical CI Verification Gate (`cargo xtask`)

```bash
cargo xtask ci              # fmt, bench --check-docs, lint (policy + isolation + clippy + rustdoc), test, bench --quick
cargo xtask ci --full       # adds audit (abi-lock + Cargo.lock + typos + cargo deny check) and kani (PO-S1..PO-S16)
```
