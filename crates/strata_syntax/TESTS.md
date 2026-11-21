# Tests: `strata_syntax`

```bash
cargo test -p strata_syntax --all-features
```

## Suites
1. **Unit Tests (`src/{syntax_kind,lexer,parser,fmt}.rs` — 7 tests):**
   - `SYNTAX_KIND_TABLE` 1-to-1 discriminant round-trip check.
   - Trivia classification exactness (`Whitespace`, `LineComment`, `BlockComment`).
   - Byte-complete lossless lexing including nested comments & invalid tokens.
   - Separation of range operators (`0..10`) from unit literals (`100_ms`, `9.81_mps2`).
   - Pratt operator precedence & CST preservation.
   - Error recovery across broken declarations.
   - Formatter normalization and idempotency.
2. **Cookbook & Integration (`tests/cookbook_cst.rs` — 4 tests):** Lossless parse & idempotent format on all 6 cookbooks (`01_rain_swarm`..`06_battle_royale_server`).
3. **Property-Based (`tests/proptest_syntax.rs` — 3 tests):** Arbitrary UTF-8 lossless lexing, panic-free arbitrary CST round-trip, and semi-structured `stratafmt` idempotency.
