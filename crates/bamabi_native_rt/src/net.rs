//! Canonical POD network transport packet (`StrataNetPacket`), bit-packed quantization
//! helpers, and schema handshake verification for Tier 3 Bevy Native (`bamabi_native_rt`).

use bamabi_macros::ModComponent;
use bevy_ecs::message::Message;

/// Canonical ABI component/message name for [`StrataNetPacket`].
pub const STRATA_NET_PACKET_CANONICAL_NAME: &str = "strata::net::StrataNetPacket";

/// 4-byte ASCII magic header (`"STNP"`) identifying [`StrataNetPacket`] frames.
pub const STRATA_NET_PACKET_MAGIC: u32 = 0x5354_4E50;

/// Current wire protocol format version for [`StrataNetPacket`].
pub const STRATA_NET_WIRE_VERSION: u16 = 1;

/// Maximum bit-packed payload capacity per [`StrataNetPacket`] in bytes (`1024` bits).
pub const STRATA_NET_MAX_PAYLOAD_BYTES: usize = 128;

/// Packet kind discriminant: connection schema handshake packet.
pub const PACKET_KIND_HANDSHAKE: u8 = 0;

/// Packet kind discriminant: ECS component quantized delta frame.
pub const PACKET_KIND_COMPONENT_DELTA: u8 = 1;

/// Packet kind discriminant: ECS singleton resource quantized delta frame.
pub const PACKET_KIND_RESOURCE_DELTA: u8 = 2;

/// Packet kind discriminant: RPC invocation payload frame.
pub const PACKET_KIND_RPC: u8 = 3;

/// Packet flag bit 0: frame carries an RPC invocation.
pub const FLAG_IS_RPC: u16 = 1 << 0;

/// Packet flag bit 1: frame requests reliable ordered delivery.
pub const FLAG_IS_RELIABLE: u16 = 1 << 1;

/// Packet flag bit 2: frame is a schema handshake message.
pub const FLAG_IS_HANDSHAKE: u16 = 1 << 2;

/// Packet flag bit 3: frame originates from/targets `@predicted` state.
pub const FLAG_IS_PREDICTED: u16 = 1 << 3;

/// Packet flag bit 4: frame carries a singleton `resource` delta.
pub const FLAG_IS_RESOURCE: u16 = 1 << 4;

/// Canonical 184-byte `#[repr(C)]` `AbiPod` transport frame carried inside
/// `Messages<StrataNetPacket>` (ABI Slots 30–32) across C99, Rust Guest, Bevy Native, and Cranelift
/// JIT hosts/guests.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Message, ModComponent)]
#[mod_component(name = "strata::net::StrataNetPacket")]
pub struct StrataNetPacket {
    /// Combined module network schema fingerprint (`MirNetHandshake::module_net_fingerprint`).
    pub module_net_fingerprint: u64,
    /// Target component or RPC schema fingerprint (or `module_net_fingerprint` for handshake).
    pub item_schema_fingerprint: u64,
    /// RPC identifier (`MirRpc::rpc_id`) or `fnv1a_64_str(canonical_name)` for components.
    pub target_id: u64,
    /// Packed `FfiEntity::to_bits()` (`0` for resources, global RPCs, and handshakes).
    pub entity_bits: u64,
    /// Wire magic header (`STRATA_NET_PACKET_MAGIC == 0x5354_4E50`).
    pub magic: u32,
    /// Simulation tick or monotonic RPC sequence counter.
    pub tick_or_seq: u32,
    /// Wire protocol version (`STRATA_NET_WIRE_VERSION == 1`).
    pub version: u16,
    /// Number of valid bit-packed payload bits in `payload` (`0..=1024`).
    pub payload_bits: u16,
    /// Packet bitflags (`FLAG_IS_*`).
    pub flags: u16,
    /// Packet kind discriminant (`PACKET_KIND_*`).
    pub kind: u8,
    /// Transport channel index (`0..=255`).
    pub channel: u8,
    /// Number of valid payload bytes in `payload` (`0..=128`).
    pub payload_bytes: u8,
    /// Origin or destination client slot (`0` = server/default).
    pub client_id: u8,
    /// Explicit 6-byte zero padding aligning `payload` to offset `56`.
    pub _pad: [u8; 6],
    /// Little-endian bit-packed quantized delta or RPC payload bytes.
    pub payload: [u8; 128],
}

const _: () = {
    assert!(STRATA_NET_MAX_PAYLOAD_BYTES == 128);
    assert!(core::mem::size_of::<StrataNetPacket>() == 184);
    assert!(core::mem::align_of::<StrataNetPacket>() == 8);
    assert!(core::mem::offset_of!(StrataNetPacket, module_net_fingerprint) == 0);
    assert!(core::mem::offset_of!(StrataNetPacket, item_schema_fingerprint) == 8);
    assert!(core::mem::offset_of!(StrataNetPacket, target_id) == 16);
    assert!(core::mem::offset_of!(StrataNetPacket, entity_bits) == 24);
    assert!(core::mem::offset_of!(StrataNetPacket, magic) == 32);
    assert!(core::mem::offset_of!(StrataNetPacket, tick_or_seq) == 36);
    assert!(core::mem::offset_of!(StrataNetPacket, version) == 40);
    assert!(core::mem::offset_of!(StrataNetPacket, payload_bits) == 42);
    assert!(core::mem::offset_of!(StrataNetPacket, flags) == 44);
    assert!(core::mem::offset_of!(StrataNetPacket, kind) == 46);
    assert!(core::mem::offset_of!(StrataNetPacket, channel) == 47);
    assert!(core::mem::offset_of!(StrataNetPacket, payload_bytes) == 48);
    assert!(core::mem::offset_of!(StrataNetPacket, client_id) == 49);
    assert!(core::mem::offset_of!(StrataNetPacket, _pad) == 50);
    assert!(core::mem::offset_of!(StrataNetPacket, payload) == 56);
};

impl Default for StrataNetPacket {
    #[inline]
    fn default() -> Self {
        Self {
            module_net_fingerprint: 0,
            item_schema_fingerprint: 0,
            target_id: 0,
            entity_bits: 0,
            magic: STRATA_NET_PACKET_MAGIC,
            tick_or_seq: 0,
            version: STRATA_NET_WIRE_VERSION,
            payload_bits: 0,
            flags: 0,
            kind: PACKET_KIND_HANDSHAKE,
            channel: 0,
            payload_bytes: 0,
            client_id: 0,
            _pad: [0; 6],
            payload: [0; STRATA_NET_MAX_PAYLOAD_BYTES],
        }
    }
}

impl StrataNetPacket {
    /// Constructs a reliable schema handshake packet carrying `module_net_fingerprint`.
    #[inline]
    #[must_use]
    pub const fn new_handshake(
        module_net_fingerprint: u64,
        client_id: u8,
        tick_or_seq: u32,
    ) -> Self {
        Self {
            module_net_fingerprint,
            item_schema_fingerprint: module_net_fingerprint,
            target_id: 0,
            entity_bits: 0,
            magic: STRATA_NET_PACKET_MAGIC,
            tick_or_seq,
            version: STRATA_NET_WIRE_VERSION,
            payload_bits: 0,
            flags: FLAG_IS_HANDSHAKE | FLAG_IS_RELIABLE,
            kind: PACKET_KIND_HANDSHAKE,
            channel: 0,
            payload_bytes: 0,
            client_id,
            _pad: [0; 6],
            payload: [0; STRATA_NET_MAX_PAYLOAD_BYTES],
        }
    }

    /// Validates that this packet is a well-formed handshake packet whose module fingerprint
    /// matches `expected_module_net_fingerprint` (and is non-zero).
    #[inline]
    #[must_use]
    pub const fn verify_handshake(&self, expected_module_net_fingerprint: u64) -> bool {
        self.magic == STRATA_NET_PACKET_MAGIC
            && self.version == STRATA_NET_WIRE_VERSION
            && self.kind == PACKET_KIND_HANDSHAKE
            && verify_handshake_fingerprint(
                expected_module_net_fingerprint,
                self.module_net_fingerprint,
            )
            && verify_handshake_fingerprint(
                expected_module_net_fingerprint,
                self.item_schema_fingerprint,
            )
    }

    /// Validates that this frame header matches the expected module network fingerprint and item
    /// schema fingerprint, and carries a valid payload byte length (`<= 128`).
    #[inline]
    #[must_use]
    pub const fn verify_item_frame(
        &self,
        expected_module_net_fingerprint: u64,
        expected_item_schema_fingerprint: u64,
    ) -> bool {
        self.magic == STRATA_NET_PACKET_MAGIC
            && self.version == STRATA_NET_WIRE_VERSION
            && (self.payload_bytes as usize) <= STRATA_NET_MAX_PAYLOAD_BYTES
            && verify_handshake_fingerprint(
                expected_module_net_fingerprint,
                self.module_net_fingerprint,
            )
            && verify_handshake_fingerprint(
                expected_item_schema_fingerprint,
                self.item_schema_fingerprint,
            )
    }
}

/// Quantizes a scalar `f64` value in `[min, max]` into an unsigned integer of `bits` (`1..=32`)
/// using `u64` arithmetic so `bits == 32` never shift-overflows.
#[must_use]
pub fn quantize_scalar_f64(val: f64, min: f64, max: f64, bits: u8, step: Option<f64>) -> u64 {
    if bits == 0 || !min.is_finite() || !max.is_finite() || min >= max {
        return 0;
    }
    let eff_bits = bits.min(32);
    let max_q = (1u64 << eff_bits) - 1;
    let eff_step = match step {
        Some(s) if s.is_finite() && s > 0.0 => s,
        _ => (max - min) / (max_q.max(1) as f64),
    };
    if !eff_step.is_finite() || eff_step <= 0.0 {
        return 0;
    }
    let clamped = if val.is_nan() {
        min
    } else {
        val.clamp(min, max)
    };
    ((clamped - min) / eff_step)
        .round()
        .clamp(0.0, max_q as f64) as u64
}

/// Dequantizes a `bits`-wide (`1..=32`) unsigned integer back into `f64` in `[min, max]`.
#[must_use]
pub fn dequantize_scalar_f64(raw: u64, min: f64, max: f64, bits: u8, step: Option<f64>) -> f64 {
    if bits == 0 || !min.is_finite() || !max.is_finite() || min >= max {
        return min;
    }
    let eff_bits = bits.min(32);
    let max_q = (1u64 << eff_bits) - 1;
    let q = raw & max_q;
    let eff_step = match step {
        Some(s) if s.is_finite() && s > 0.0 => s,
        _ => (max - min) / (max_q.max(1) as f64),
    };
    if !eff_step.is_finite() || eff_step <= 0.0 {
        return min;
    }
    (min + (q as f64) * eff_step).clamp(min, max)
}

/// Packs the lowest `bits` (`0..=64`) of `val` into `buf` starting at `bit_offset` in little-endian
/// bit order. Out-of-bounds bits beyond `buf.len() * 8` are safely ignored.
pub fn pack_bits_le(buf: &mut [u8], bit_offset: u32, bits: u8, val: u64) {
    let eff_bits = bits.min(64);
    if eff_bits == 0 {
        return;
    }
    let mask = if eff_bits == 64 {
        u64::MAX
    } else {
        (1u64 << eff_bits) - 1
    };
    let mut src = val & mask;
    let mut remaining = eff_bits;
    let mut cur_bit = bit_offset as usize;
    while remaining > 0 {
        let byte_idx = cur_bit / 8;
        if byte_idx >= buf.len() {
            break;
        }
        let bit_in_byte = cur_bit % 8;
        let take = (8 - bit_in_byte).min(remaining as usize);
        let low_mask = ((1u16 << take) - 1) as u8;
        let chunk_mask = low_mask << bit_in_byte;
        let chunk_bits = ((src & u64::from(low_mask)) as u8) << bit_in_byte;
        buf[byte_idx] = (buf[byte_idx] & !chunk_mask) | chunk_bits;
        src >>= take;
        cur_bit += take;
        remaining -= take as u8;
    }
}

/// Unpacks `bits` (`0..=64`) from `buf` starting at `bit_offset` in little-endian bit order.
/// Out-of-bounds bits beyond `buf.len() * 8` read as `0`.
#[must_use]
pub fn unpack_bits_le(buf: &[u8], bit_offset: u32, bits: u8) -> u64 {
    let eff_bits = bits.min(64);
    if eff_bits == 0 {
        return 0;
    }
    let mut remaining = eff_bits;
    let mut cur_bit = bit_offset as usize;
    let mut out = 0u64;
    let mut shift = 0u32;
    while remaining > 0 {
        let byte_idx = cur_bit / 8;
        if byte_idx >= buf.len() {
            break;
        }
        let bit_in_byte = cur_bit % 8;
        let take = (8 - bit_in_byte).min(remaining as usize);
        let low_mask = ((1u16 << take) - 1) as u8;
        let chunk = (buf[byte_idx] >> bit_in_byte) & low_mask;
        out |= u64::from(chunk) << shift;
        shift += take as u32;
        cur_bit += take;
        remaining -= take as u8;
    }
    out
}

/// Verifies a received network handshake/item schema fingerprint against `expected`.
/// Returns `false` if `expected == 0` or `expected != received`.
#[inline]
#[must_use]
pub const fn verify_handshake_fingerprint(expected: u64, received: u64) -> bool {
    expected != 0 && expected == received
}
