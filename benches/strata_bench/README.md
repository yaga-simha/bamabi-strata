# `strata_bench`

Compiler pipeline latency and 4-tier ECS execution throughput benchmark harness (`publish = false`, `#![forbid(unsafe_code)]`, `#![warn(missing_docs)]`) orchestrated by `cargo xtask bench`.

```bash
cargo run --release -p strata_bench -- --quick
cargo xtask bench --write-docs --json target/bench-results.json
```
