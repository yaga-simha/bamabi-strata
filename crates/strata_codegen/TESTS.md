# Tests: `strata_codegen`

```bash
cargo test -p strata_codegen --all-features
```

## Suites
1. **Unit Tests (`src/{expr,c99,rust_guest,bevy_native}.rs` — 5 tests):** Unit literal scaling, `extract_system_plan` resource/selective detection, C99 wire `BAM_STATIC_ASSERT` checks, zero-unsafe/zero-Bevy Rust Guest generation, and `static-console` feature toggling.
2. **Integration Tests (`tests/codegen_tests.rs` — 2 tests):** Compiles all 6 cookbooks + physics parity kernel through ISO C99 (`clang/gcc/cc -std=c99 -Wall -Wextra -Wpedantic -Werror -fsyntax-only`), Safe Rust Guest, and Bevy Native, verifying cross-target `SCHEMA_FINGERPRINT` parity.
