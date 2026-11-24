# Agent Guide: `strata_profile`

Crate guide for **`strata_profile`** (`v0.3.0`, `benches/strata_profile`) — headless Bevy `0.20` + `bamabi_host` + `hotpath-rs` (`0.32`) closed-loop profiling suite.

---

## 1. Crate Identity & Allowed Dependencies
- **Name:** `strata_profile` (`edition = "2024"`, MSRV `1.95`, `publish = false`)
- **Dependencies:** `bamabi_host`, `bamabi_native_rt`, `bamabi_sys`, `bevy_app`, `bevy_ecs` (`multi_threaded`), `hotpath` (`0.32`), `strata_jit`, `strata_mir`, `strata_sema`, `tempfile`.
- **Allocator Isolation:** MUST NOT depend on `stratac` (`sim-runner`) so `SIM_GLOBAL_ALLOC` never collides with `hotpath-alloc`'s `#[global_allocator]`.
- **Features:** `hotpath`, `hotpath-alloc`, `hotpath-cpu` (default builds keep `hotpath` disabled).

---

## 2. Safety Policy
- Enforces `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]` (use bare `#[hotpath::measure]` — never `#[hotpath::measure(label = "...")]` which expands `#[unsafe(export_name)]`).

---

## 3. Owned Surface & Frozen Contracts
- **`src/lib.rs`:** Five `.strata` profiling kernels (`PAR_100K_SOURCE`, `SPATIAL_GRID_SOURCE`, `SELECTIVE_50K_SOURCE`, `ATOMIC_STORM_SOURCE`, `NET_SIM_SOURCE`) and `compile_profile_jit`.
- **`benches/strata_profile.rs`:** Headless workloads (`par_100k`, `spatial_grid_10k`, `selective_50k`, `atomic_10k`, `net_sim`) selectable via `STRATA_PROFILE_CASE`.

---

## 4. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy -p strata_profile --all-targets --all-features -- -D warnings
cargo test -p strata_profile --all-features
cargo bench -p strata_profile --bench strata_profile
HOTPATH_METRICS_SERVER_OFF=1 cargo bench -p strata_profile --bench strata_profile --features hotpath-alloc
```
