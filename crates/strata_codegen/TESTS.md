# Tests: `strata_codegen`

```bash
cargo test -p strata_codegen --all-features
```

## Suites
1. **Unit Tests (`src/net.rs`, `src/{c99,rust_guest,bevy_native}/tests.rs`):** C99 wire `BAM_STATIC_ASSERT` checks, zero-unsafe/zero-Bevy Rust Guest generation, `static-console` feature toggling, named-object array overrides & nested arrays, and `StrataNetPacket` wire invariants.
2. **Integration Tests (`tests/codegen_tests.rs`):** Compiles all 8 cookbooks + physics parity & Phase 2B kernels through strict ISO C99 (`clang/gcc/cc -std=c99 -Wall -Wextra -Wpedantic -Werror`), Safe Rust Guest (`cargo check --offline`), and live Bevy Native execution (`Startup` / `FixedUpdate` world runs verifying 2-pass CSR, `IterUpCascade`, `ArrayStore`, `OptionalWrite`, `atomic`, `Fix64` division, `NB-1`/`NB-2`/`NB-3`, and named-object arrays).
3. **Networking Codegen Tests (`tests/net_codegen_tests.rs`):** Verifies `@net` / `@quantize` / `rpc` / `StrataNetPacket` emission and schema-fingerprint parity across C99, Rust Guest, and Bevy Native.
