# `strata_codegen`

Three-backend ahead-of-time code generator transforming `StrataMir` into strict ISO C99, Safe `#![forbid(unsafe_code)]` Rust Guest `.cdylib` crates (`bamabi_guest`), and static Tier 3 Bevy `0.20` `Plugin` crates (`bamabi_native_rt`).

- **Policy:** `#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`
- **Isolation:** **ZERO** `bevy*` dependencies
