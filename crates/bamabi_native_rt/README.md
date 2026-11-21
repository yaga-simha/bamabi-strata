# `bamabi_native_rt`

Tier 3 static Bevy `0.20.1` runtime adapter and zero-allocation `#[repr(C)]` `AbiPod` gameplay primitives for `bamabi-strata`.

- **Policy:** `#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`
- **Features:**
  - `shared-bridge` *(default)*: Interoperates with dynamic `.cdylib` mods via `bamabi_host`.
  - `static-console`: Completely strips `bamabi_host` and `libloading` for `dlopen`-free static builds (`--target bevy-native --static-console`).
