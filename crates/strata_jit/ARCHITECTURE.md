# Architecture: `strata_jit`

## Modules
- `src/abi_offsets.rs`: Computes all `73` `BamHostApi` vtable byte offsets (`bamabi_sys::offsets::*`), slot/query limits (`HOST_API_SLOTS = 73`, `QUERY_TERM_CAP = 32`, `SYSTEM_QUERY_CAP = 16`), and descriptor field offsets (`core::mem::offset_of!`, including `BamQueryDesc::param_set_group` and `BamSystemDesc::run_if_ctx*`) programmatically.
- `src/emitter/{mod,rodata,init,fn_lower,inst,spatial,net,tests}.rs`: Lowers `MirModule` CFGs directly into `cranelift-object` PIC machine code exporting `bamabi_manifest`, `bamabi_init`, `bamabi_shutdown`, internal `__strata_fix64_div`, Slot 10 `IterReset`, Slot 58 6-arg `IterUpCascade`, bounds-checked `ArrayStore`, 2-pass CSR spatial grids (`SpatialCsrBegin`/`Count`/`PrefixSum`/`Scatter`), optional chunk null-safety, `ShadowWrite` pre-image preservation, `&mut? T` dirty-run coalescing, and `StrataNetPacket` codecs.
- `src/linker.rs`: Links `.o` files into native shared libraries via platform `clang`/`cc`/`gcc`.
- `src/kani_proofs.rs`: Symbolic Kani proof `PO-S9` validating alignment and bounds of all `73` ABI offsets and descriptor layouts.
- `benches/jit_bench.rs`: Criterion `0.8` (+ optional `hotpath-alloc`) microbench for `jit_emit_pic_speed` and `jit_opt_level_compare`.
