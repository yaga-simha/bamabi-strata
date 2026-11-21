# Tests & Formal Verification: `bamabi_native_rt`

```bash
cargo test -p bamabi_native_rt --all-features
cargo test -p bamabi_native_rt --no-default-features --features static-console
cargo kani -p bamabi_native_rt --no-default-features --features static-console -j
```

## Suites
1. **Unit Tests (`src/{primitives,slice_query}.rs` — 8 tests):** `GraceWindow`, `InputBuffer` eviction, `TimelineCursor`, `BitSet`, UTF-8 `InlineStr` boundary truncation, `SmallVecPod` capacity cap, `Fixed32`/`Fixed64`, and `DirtyRunCoalescer` coalescing + range clamping.
2. **Integration Tests (`tests/native_rt_tests.rs` — 4 tests):** 100k-entity dense chunk iteration, selective tick-tracking, `AbiPod` semantics, and bridge registration across profiles.
3. **Property-Based (`tests/proptest_native_rt.rs` — 4 tests):** Differential oracle equivalence for `DirtyRunCoalescer` and `BitSet`, arbitrary UTF-8 `InlineStr` prefix safety, `Fixed32`/`Fixed64` round-trips.
4. **Kani Formal Proofs (`src/kani_proofs.rs` — `PO-S1`..`PO-S5`, 5 harnesses):** Symbolic non-negative countdown, `InputBuffer`/`TimelineCursor` layout & bounds, OOB/corrupt-length container safety, wrapping fixed-point arithmetic totality, and exact bitmask equivalence of `DirtyRunCoalescer`.
