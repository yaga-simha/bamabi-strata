# Architecture: `strata_jit`

## Modules
- `src/abi_offsets.rs`: Computes every `BamHostApi` vtable byte offset (`bamabi_sys::offsets::*`), slot limit (`HOST_API_SLOTS`, `QUERY_TERM_CAP`, `SYSTEM_QUERY_CAP`), and descriptor field offset (`core::mem::offset_of!`) programmatically with compile-time assertions.
- `src/emitter.rs`: Lowers `MirModule` + `SystemPlan` into `cranelift-object` relocatable machine code exporting `bamabi_manifest`, `bamabi_init`, `bamabi_shutdown`, and system callbacks with `&mut? T` dirty-run coalescing.
- `src/linker.rs`: Links `.o` files into native shared libraries via platform `clang`/`cc`/`gcc`.
- `src/kani_proofs.rs`: Symbolic Kani proof `PO-S9` validating alignment and bounds of all emitted ABI offsets.
