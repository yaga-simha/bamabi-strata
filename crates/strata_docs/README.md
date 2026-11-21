# `strata_docs`

Zero-dependency (`#![no_std]`, `#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`, `publish = false`) workspace documentation hub aggregating the root `README.md`, `ARCHITECTURE.md`, `DEVELOPMENT.md`, `TESTING.md`, `BENCHMARKS.md`, and `CHANGELOG.md` guides into `rustdoc` (`target/doc/strata_docs/index.html`).

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```
