# Architecture: `strata_docs`

`src/lib.rs` (`#![no_std]`, `#![forbid(unsafe_code)]`, empty `[dependencies]`) compiles zero executable runtime code and pulls in the workspace Markdown documents solely under `#[cfg(doc)]` modules (`overview`, `architecture`, `development`, `testing`, `benchmarks`, `changelog`, and `crates`) so `cargo doc --workspace --no-deps --all-features` renders a unified manual without introducing external dependencies or `std` linkage.
