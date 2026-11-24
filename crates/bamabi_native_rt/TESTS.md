# Tests & Formal Verification: `bamabi_native_rt`

```bash
cargo test -p bamabi_native_rt --all-features
cargo test -p bamabi_native_rt --no-default-features --features static-console
cargo xtask kani --crate bamabi_native_rt --timeout 120
cargo bench -p bamabi_native_rt --bench native_rt_bench
```

## Suites
1. **Unit Tests (`src/{primitives,slice_query,net}.rs`):** `GraceWindow`, `InputBuffer` eviction, `TimelineCursor`, `BitSet`, UTF-8 `InlineStr` boundary truncation, `SmallVecPod` capacity cap, `Fixed32`/`Fixed64` totality + `div_restoring`, `DirtyRunCoalescer` coalescing + range clamping, and packet bit-packing.
2. **Integration Tests (`tests/native_rt_tests.rs`, `tests/net_rt_tests.rs`):** 100k-entity dense chunk iteration, selective tick-tracking, `AbiPod` semantics, `StrataNetPacket` wire identity & quantization, and bridge registration across `shared-bridge` / `static-console` profiles.
3. **Property-Based (`tests/proptest_native_rt.rs`):** Differential oracle equivalence for `DirtyRunCoalescer` and `BitSet`, arbitrary UTF-8 `InlineStr` prefix safety, `Fixed32`/`Fixed64` round-trips.
4. **Kani Formal Proofs (`src/kani_proofs.rs` — `PO-S1`..`PO-S5`, `PO-S16`, 6 harnesses):** Symbolic non-negative countdown, `InputBuffer`/`TimelineCursor` layout & bounds, OOB/corrupt-length container safety, wrapping fixed-point arithmetic totality, exact bitmask equivalence of `DirtyRunCoalescer`, and `Fixed64` preshifted `i128` division parity with `div_restoring`.
