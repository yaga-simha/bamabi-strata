# Tests & Formal Verification: `strata_jit`

```bash
cargo test -p strata_jit --all-features
cargo kani -p strata_jit -j
```

## Suites
1. **Unit Tests (`src/{lib,abi_offsets,emitter,linker}.rs` — 5 tests):** Dynamic vtable slot offset alignment/bounds, descriptor size checks, wire access mode discriminants, linker driver detection, missing-object error handling.
2. **Integration Tests (`tests/jit_tests.rs` — 1 test):** Emits PIC `.o`, links native shared library, verifies exported ABI symbols (`bamabi_manifest`, `bamabi_init`, `bamabi_shutdown`).
3. **Kani Formal Proofs (`src/kani_proofs.rs` — `PO-S9`):** Proves pointer alignment, pairwise uniqueness, and table-capacity bounds for all Host API slots and descriptor offsets.
