# Agent Guide: `bamabi_native_rt`

Crate guide for **`bamabi_native_rt`** (`v0.3.0`, Bevy `0.20.1`) — zero-unsafe Tier 3 native runtime adapter and `AbiPod` gameplay primitives.

---

## 1. Crate Identity & Allowed Dependencies
- **Name:** `bamabi_native_rt` (`edition = "2024"`, MSRV `1.95`)
- **Dependencies:** `bamabi_sys`, `bevy_app`, `bevy_ecs`, `bevy_reflect`, `thiserror`, and optional `bamabi_host` (under default `shared-bridge` feature).
- **Profiles:**
  - `shared-bridge` (default): Registers static Tier 3 `ComponentUuid`s into `ModRegistry` so dynamic `.cdylib` mods interoperate seamlessly.
  - `static-console`: 100% `dlopen`-free static profile with zero `bamabi_host` / `libloading` dependencies.

---

## 2. Safety Policy
- Enforces `#![forbid(unsafe_code)]` and `#![warn(missing_docs)]`.

---

## 3. Owned Surface & Frozen Contracts
- **`ChunkSliceQueryExt` & `SelectiveMutSlice` (`slice_query.rs`):** Dense contiguous query slice iteration (`contiguous_iter`, `contiguous_par_iter_mut`) and coalesced `&mut?` tick-range marking over Bevy `0.20` `ContiguousMut`.
- **`SharedBridgeAppExt` (`bridge.rs`):** Unified static/dynamic registration on `bevy_app::App` for components, resources, buffered messages (`stream`), events, and entity events.
- **Gameplay Primitives (`primitives.rs`):** Zero-padding `#[repr(C)]` primitives (`GraceWindow`, `InputBuffer`, `TimelineCursor`, `BitSet`, `InlineStr`, `SmallVecPod`, `Fixed32`, `Fixed64`).

---

## 4. Standalone Verification Commands

```bash
cargo fmt --check
cargo clippy -p bamabi_native_rt --all-targets --all-features -- -D warnings
cargo test -p bamabi_native_rt --all-features
cargo check -p bamabi_native_rt --no-default-features --features static-console
cargo tree -p bamabi_native_rt --no-default-features --features static-console | grep -E "libloading|bamabi_host" # MUST print NOTHING
```
