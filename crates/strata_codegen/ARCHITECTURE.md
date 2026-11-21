# Architecture: `strata_codegen`

## Modules
- `src/expr.rs`: Shared `SystemPlan` extractor unifying resource reads (`Inst::ResRead`/`ResWrite`), `uniform let` hoisting, row statements, conditionals, unit literal scaling, and `&mut? T` dirty tracking across all codegen & JIT backends.
- `src/c99.rs`: Strict `-std=c99 -Wall -Wextra -Wpedantic -Werror` emitter paired with `bamabi_sdk_gen`-generated `bamabi.h` and wire ABI `BAM_STATIC_ASSERT` guards (`BAM_HOST_API_SLOT_COUNT`, `BAM_MAX_TERMS_PER_QUERY`, `BAM_MAX_QUERIES_PER_SYSTEM`).
- `src/rust_guest.rs`: Safe `#![forbid(unsafe_code)]` `bamabi_guest` `.cdylib` crate generator using `query_typed` / `resource_read` and bit-exact `ComponentUuid` / `SCHEMA_FINGERPRINT` constants.
- `src/bevy_native.rs`: Tier 3 static `#![forbid(unsafe_code)]` Bevy `0.20` `Plugin` emitter supporting both `shared-bridge` and `dlopen`-free `static-console` Cargo features.
