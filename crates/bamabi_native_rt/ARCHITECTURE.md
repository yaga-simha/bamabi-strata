# Architecture: `bamabi_native_rt`

## Modules
- `src/primitives.rs`: `#[repr(C)]` zero-implicit-padding gameplay primitives (`GraceWindow`, `InputBuffer<N>`, `TimelineCursor`, `BitSet<WORDS>`, `InlineStr<N>`, `SmallVecPod<T, N>`, `Fixed32`, `Fixed64` including `rhs == 0 => 0` totality and `div_restoring`).
- `src/slice_query.rs`: `ChunkSliceQueryExt` (`strata_contiguous_iter`, `strata_contiguous_par_iter_mut`), `DirtyRunCoalescer` pure interval-merging state machine, and `SelectiveMutSlice` for `&mut? T` change-tick coalescing.
- `src/bridge.rs`: `SharedBridgeAppExt` registering solved `AbiPod` components and resources uniformly under both `shared-bridge` and `static-console`.
- `src/net.rs`: Canonical 184-byte `#[repr(C)]` `StrataNetPacket` (`"STNP"`) for `Messages<StrataNetPacket>` (ABI Slots 30–32), bit-packing helpers, and handshake fingerprint checks.
- `src/kani_proofs.rs`: Symbolic Kani proofs `PO-S1`..`PO-S5` and `PO-S16` enabled under `#[cfg(kani)]`.
- `benches/native_rt_bench.rs`: Criterion `0.8` (+ optional `hotpath-alloc`) microbench for `selective_mut_slice_50k`, `fixed_point_batch_1024`, and `net_quantize_delta_128`.
