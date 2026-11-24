# Tests: `strata_syntax`

```bash
cargo test -p strata_syntax --all-features
```

## Suites
1. **Unit Tests (`src/{syntax_kind,lexer,parser,fmt,graph_ir}.rs`):**
   - `SYNTAX_KIND_TABLE` 1-to-1 discriminant round-trip check.
   - Trivia classification exactness (`Whitespace`, `LineComment`, `BlockComment`).
   - Byte-complete lossless lexing including nested comments & invalid tokens.
   - Separation of range operators (`0..10`) from unit literals (`100_ms`, `9.81_mps2`).
   - Pratt operator precedence, error recovery across broken declarations, formatter idempotency, and Graph IR helper validation.
2. **Cookbook CST (`tests/cookbook_cst.rs`):** Lossless parse & idempotent format on all 8 cookbooks (`01_rain_swarm`..`08_authoritative_multiplayer`).
3. **Graph IR Round-Trip (`tests/graph_ir_roundtrip.rs`):** Lossless export/apply round-trip for all 8 node kinds (`component`, `sys`, `timeline`, `fsm`, `task`, `table`, `curve`, `schedule`), delta position updates, comment preservation, and sidecar schema-fingerprint invariance.
4. **Property-Based (`tests/proptest_syntax.rs`):** Arbitrary UTF-8 lossless lexing, panic-free arbitrary CST round-trip, and semi-structured `stratafmt` idempotency.
