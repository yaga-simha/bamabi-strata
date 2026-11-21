# Tests: `strata_docs`

```bash
RUSTDOCFLAGS="-D warnings" cargo doc -p strata_docs --no-deps --all-features
cargo test -p strata_docs --all-features
```

Verified directly by `cargo xtask lint` (strict `-D warnings` rustdoc compilation across every included Markdown guide).
