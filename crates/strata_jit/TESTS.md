# Tests & Formal Verification: `strata_jit`

```bash
cargo test -p strata_jit --all-features
cargo xtask kani --crate strata_jit --timeout 120
cargo bench -p strata_jit --bench jit_bench
```

## Suites
1. **Unit Tests (`src/{lib,abi_offsets,linker}.rs`, `src/emitter/tests.rs`):** 73-slot vtable offset alignment/bounds, descriptor size checks, wire access mode discriminants, linker driver detection, and missing-object error handling.
2. **Integration & Live C99 Host Execution (`tests/jit_tests.rs`):** Emits PIC `.o`, links `.dylib`/`.so`, verifies exported ABI symbols (`bamabi_manifest`, `bamabi_init`, `bamabi_shutdown`), and executes compiled `.dylib`s via C99 vtable harnesses (`Fix64` division/coercion, `ArrayStore`, nested literals, 2-pass CSR disc & capsule segment queries, Slot 58 `IterUpCascade`, optional queries, and `atomic` rollback).
3. **Networking JIT Tests (`tests/net_jit_tests.rs`):** Verifies `BAM_TERM_KNOWN_FLAGS`, 32-byte `BamQueryDesc`, `StrataNetPacket` TX/RX emission, and live host vtable execution.
4. **Kani Formal Proofs (`src/kani_proofs.rs` — `PO-S9`, 1 harness):** Proves pointer alignment, pairwise uniqueness, and table-capacity bounds for all 73 Host API slots and descriptor offsets.
