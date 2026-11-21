# Architecture: `bamabi_native_rt`

## Modules
- `src/primitives.rs`: `#[repr(C)]` zero-implicit-padding gameplay primitives (`GraceWindow`, `InputBuffer<N>`, `TimelineCursor`, `BitSet<WORDS>`, `InlineStr<N>`, `SmallVecPod<T, N>`, `Fixed32`, `Fixed64`).
- `src/slice_query.rs`: `ChunkSliceQueryExt` (`contiguous_iter`, `contiguous_par_iter`), `DirtyRunCoalescer` pure interval-merging state machine, and `SelectiveMutSlice` for `&mut? T` change-tick coalescing.
- `src/bridge.rs`: `SharedBridgeAppExt` registering solved `AbiPod` components and resources uniformly under both `shared-bridge` and `static-console`.
- `src/kani_proofs.rs`: Symbolic Kani proofs `PO-S1`..`PO-S5` enabled under `#[cfg(kani)]`.
