#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Zero-overhead Tier 3 static Bevy `0.20` runtime adapter and `AbiPod`-layout gameplay primitives
//! for `bamabi-strata`.
//!
//! Enforces `#![forbid(unsafe_code)]` across both `shared-bridge` (interoperating with dynamic
//! `.cdylib` mods via `bamabi_host`) and `static-console` (`dlopen`-free static console builds).

pub mod bridge;
#[cfg(kani)]
mod kani_proofs;
pub mod primitives;
pub mod slice_query;

pub use bridge::{
    SharedBridgeAppExt, StrataBridgeCatalog, StrataBridgeEntry, StrataBridgeError,
    StrataBridgeHandle, StrataComponentOptions,
};
pub use primitives::{
    BitSet, Fixed32, Fixed64, GraceWindow, InlineStr, InputBuffer, InputBufferEntry, SmallVecPod,
    TimelineCursor,
};
pub use slice_query::{ChunkSliceQueryExt, DirtyRunCoalescer, SelectiveMutSlice};
