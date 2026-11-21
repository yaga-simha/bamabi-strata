# `strata_jit`

Cranelift `0.135.10` PIC native `.dylib` / `.so` / `.dll` backend for `StrataMir`. Generates position-independent object code in pure safe Rust (`#![forbid(unsafe_code)]`, ZERO `bevy*` deps) and links host-loadable `bamabi` shared libraries.
