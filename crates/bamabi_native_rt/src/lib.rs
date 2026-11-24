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
pub mod net;
pub mod primitives;
pub mod slice_query;

pub use bridge::{
    SharedBridgeAppExt, StrataBridgeCatalog, StrataBridgeEntry, StrataBridgeError,
    StrataBridgeHandle, StrataComponentOptions,
};
pub use net::{
    FLAG_IS_HANDSHAKE, FLAG_IS_PREDICTED, FLAG_IS_RELIABLE, FLAG_IS_RESOURCE, FLAG_IS_RPC,
    PACKET_KIND_COMPONENT_DELTA, PACKET_KIND_HANDSHAKE, PACKET_KIND_RESOURCE_DELTA,
    PACKET_KIND_RPC, STRATA_NET_MAX_PAYLOAD_BYTES, STRATA_NET_PACKET_CANONICAL_NAME,
    STRATA_NET_PACKET_MAGIC, STRATA_NET_WIRE_VERSION, StrataNetPacket, dequantize_scalar_f64,
    pack_bits_le, quantize_scalar_f64, unpack_bits_le, verify_handshake_fingerprint,
};
pub use primitives::{
    BitSet, Fixed32, Fixed64, GraceWindow, InlineStr, InputBuffer, InputBufferEntry, SmallVecPod,
    TimelineCursor,
};
pub use slice_query::{ChunkSliceQueryExt, DirtyRunCoalescer, SelectiveMutSlice};
