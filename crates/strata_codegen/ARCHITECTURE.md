# Architecture: `strata_codegen`

Every backend consumes `MirModule` and `MirFunction` SSA CFGs directly without an intermediate `expr.rs` / `SystemPlan` layer.

## Modules
- `src/lib.rs`: Public target dispatch (`emit_c99`, `emit_rust_guest`, `emit_rust_guest_with`, `emit_bevy_native`, `emit_bamabi_header`) and shared identifier/layout helpers.
- `src/net.rs`: Canonical `StrataNetPacket` (`184 B`, `"STNP"`) constants, offsets, and bit-packed payload capacity checks shared with `strata_jit`.
- `src/c99/{mod,prelude,decls,fn_emit,inst_emit,net_emit,tests}.rs`: Strict `-std=c99 -Wall -Wextra -Wpedantic -Werror` emitter paired with `bamabi_sdk_gen`-generated `bamabi.h`, `BAM_STATIC_ASSERT` guards (`BAM_HOST_API_SLOT_COUNT`, `BAM_MAX_TERMS_PER_QUERY`, `BAM_MAX_QUERIES_PER_SYSTEM`), ISO C99 `strata_fix64_div` 96x64 restoring division, 2-pass CSR spatial queries, Slot 58 `iter_up_cascade`, and `ArrayStore`.
- `src/rust_guest/{mod,prelude,items,fn_emit,inst_emit,export_mod,tests}.rs`: Safe `#![forbid(unsafe_code)]` `bamabi_guest` `.cdylib` crate generator emitting bit-exact `ComponentUuid` / `SCHEMA_FINGERPRINT` constants, `StrataSpatialCsrFrame` CSR grids, Slot 10/58 calls, and `StrataNetPacket` codecs.
- `src/bevy_native/{mod,items,analysis,fn_emit,places_ops,tests}.rs`: Tier 3 static `#![forbid(unsafe_code)]` Bevy `0.20` `Plugin` emitter supporting `shared-bridge` and `static-console`, `SelectiveMutSlice` `OptionalWrite` / `atomic` rollback buffering, `UpCascadePlan` `ParamSet` lookups, 2-pass CSR `SynthesizedSpatialCsr` systems, and recursive named-object `ArrayLit`/`Cast` evaluation.
