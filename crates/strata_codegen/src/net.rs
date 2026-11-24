//! Shared POD networking wire protocol (`StrataNetPacket`), bit-packed quantization helpers,
//! and handshake validation primitives used across AOT codegen (`c99`, `rust_guest`, `bevy_native`)
//! and Cranelift JIT (`strata_jit`).
//!
//! Zero `bevy*` dependencies and `#![forbid(unsafe_code)]`.

use crate::CodegenError;
use bamabi_sys::{
    BamFieldKind, ComponentUuid, fnv1a_64_init, fnv1a_64_update_bytes, fnv1a_64_update_u64,
};
use strata_mir::MirModule;

/// Canonical ABI component/message name for the shared POD network transport packet.
pub const STRATA_NET_PACKET_CANONICAL_NAME: &str = "strata::net::StrataNetPacket";

/// 4-byte ASCII magic header (`"STNP"`) identifying `StrataNetPacket` frames.
pub const STRATA_NET_PACKET_MAGIC: u32 = 0x5354_4E50;

/// Current wire protocol format version for `StrataNetPacket`.
pub const STRATA_NET_WIRE_VERSION: u16 = 1;

/// Maximum bit-packed payload capacity per `StrataNetPacket` in bytes (`1024` bits).
pub const STRATA_NET_MAX_PAYLOAD_BYTES: usize = 128;

/// Exact `#[repr(C)]` byte size of `StrataNetPacket` (`184` bytes, zero implicit padding).
pub const STRATA_NET_PACKET_SIZE: usize = 184;

/// Exact `#[repr(C)]` byte alignment of `StrataNetPacket` (`8` bytes).
pub const STRATA_NET_PACKET_ALIGN: usize = 8;

/// Maximum RX message batch capacity used by C99 and Cranelift JIT net RX systems (`16,384` packets).
pub const STRATA_NET_RX_BATCH_CAP: usize = 16384;

/// Deterministic 64-bit FNV-1a `SCHEMA_FINGERPRINT` of `"strata::net::StrataNetPacket"`.
pub const STRATA_NET_PACKET_SCHEMA_FINGERPRINT: u64 = 0x7835_BC96_B507_EFCE;

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

/// Byte offsets of every `#[repr(C)]` field inside `StrataNetPacket`.
pub mod packet_offsets {
    /// Byte offset of `module_net_fingerprint: u64` (`8` bytes).
    pub const MODULE_NET_FINGERPRINT: usize = 0;
    /// Byte offset of `item_schema_fingerprint: u64` (`8` bytes).
    pub const ITEM_SCHEMA_FINGERPRINT: usize = 8;
    /// Byte offset of `target_id: u64` (`8` bytes).
    pub const TARGET_ID: usize = 16;
    /// Byte offset of `entity_bits: u64` (`8` bytes).
    pub const ENTITY_BITS: usize = 24;
    /// Byte offset of `magic: u32` (`4` bytes).
    pub const MAGIC: usize = 32;
    /// Byte offset of `tick_or_seq: u32` (`4` bytes).
    pub const TICK_OR_SEQ: usize = 36;
    /// Byte offset of `version: u16` (`2` bytes).
    pub const VERSION: usize = 40;
    /// Byte offset of `payload_bits: u16` (`2` bytes).
    pub const PAYLOAD_BITS: usize = 42;
    /// Byte offset of `flags: u16` (`2` bytes).
    pub const FLAGS: usize = 44;
    /// Byte offset of `kind: u8` (`1` byte).
    pub const KIND: usize = 46;
    /// Byte offset of `channel: u8` (`1` byte).
    pub const CHANNEL: usize = 47;
    /// Byte offset of `payload_bytes: u8` (`1` byte).
    pub const PAYLOAD_BYTES: usize = 48;
    /// Byte offset of `client_id: u8` (`1` byte).
    pub const CLIENT_ID: usize = 49;
    /// Byte offset of `_pad: [u8; 6]` (`6` bytes explicit zero padding).
    pub const PAD: usize = 50;
    /// Byte offset of `payload: [u8; 128]` (`128` bytes bit-packed payload).
    pub const PAYLOAD: usize = 56;
}

/// Wire field descriptor for one field in `StrataNetPacket`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetPacketFieldSpec {
    /// Field name.
    pub name: &'static str,
    /// `bamabi_sys::BamFieldKind` wire discriminator.
    pub kind: BamFieldKind,
    /// Canonical type tag matching `bamabi_macros` / `strata_sema::layout`.
    pub type_tag: &'static str,
    /// Byte offset inside the `#[repr(C)]` struct.
    pub offset: usize,
    /// Byte size of the field.
    pub size: usize,
    /// Byte alignment of the field.
    pub align: usize,
}

/// Ordered `#[repr(C)]` field table for `"strata::net::StrataNetPacket"` (`184` bytes, align `8`,
/// zero implicit padding).
pub const STRATA_NET_PACKET_FIELDS: &[NetPacketFieldSpec] = &[
    NetPacketFieldSpec {
        name: "module_net_fingerprint",
        kind: BamFieldKind::U64,
        type_tag: "u64",
        offset: packet_offsets::MODULE_NET_FINGERPRINT,
        size: 8,
        align: 8,
    },
    NetPacketFieldSpec {
        name: "item_schema_fingerprint",
        kind: BamFieldKind::U64,
        type_tag: "u64",
        offset: packet_offsets::ITEM_SCHEMA_FINGERPRINT,
        size: 8,
        align: 8,
    },
    NetPacketFieldSpec {
        name: "target_id",
        kind: BamFieldKind::U64,
        type_tag: "u64",
        offset: packet_offsets::TARGET_ID,
        size: 8,
        align: 8,
    },
    NetPacketFieldSpec {
        name: "entity_bits",
        kind: BamFieldKind::U64,
        type_tag: "u64",
        offset: packet_offsets::ENTITY_BITS,
        size: 8,
        align: 8,
    },
    NetPacketFieldSpec {
        name: "magic",
        kind: BamFieldKind::U32,
        type_tag: "u32",
        offset: packet_offsets::MAGIC,
        size: 4,
        align: 4,
    },
    NetPacketFieldSpec {
        name: "tick_or_seq",
        kind: BamFieldKind::U32,
        type_tag: "u32",
        offset: packet_offsets::TICK_OR_SEQ,
        size: 4,
        align: 4,
    },
    NetPacketFieldSpec {
        name: "version",
        kind: BamFieldKind::U16,
        type_tag: "u16",
        offset: packet_offsets::VERSION,
        size: 2,
        align: 2,
    },
    NetPacketFieldSpec {
        name: "payload_bits",
        kind: BamFieldKind::U16,
        type_tag: "u16",
        offset: packet_offsets::PAYLOAD_BITS,
        size: 2,
        align: 2,
    },
    NetPacketFieldSpec {
        name: "flags",
        kind: BamFieldKind::U16,
        type_tag: "u16",
        offset: packet_offsets::FLAGS,
        size: 2,
        align: 2,
    },
    NetPacketFieldSpec {
        name: "kind",
        kind: BamFieldKind::U8,
        type_tag: "u8",
        offset: packet_offsets::KIND,
        size: 1,
        align: 1,
    },
    NetPacketFieldSpec {
        name: "channel",
        kind: BamFieldKind::U8,
        type_tag: "u8",
        offset: packet_offsets::CHANNEL,
        size: 1,
        align: 1,
    },
    NetPacketFieldSpec {
        name: "payload_bytes",
        kind: BamFieldKind::U8,
        type_tag: "u8",
        offset: packet_offsets::PAYLOAD_BYTES,
        size: 1,
        align: 1,
    },
    NetPacketFieldSpec {
        name: "client_id",
        kind: BamFieldKind::U8,
        type_tag: "u8",
        offset: packet_offsets::CLIENT_ID,
        size: 1,
        align: 1,
    },
    NetPacketFieldSpec {
        name: "_pad",
        kind: BamFieldKind::NESTED,
        type_tag: "[u8;6]",
        offset: packet_offsets::PAD,
        size: 6,
        align: 1,
    },
    NetPacketFieldSpec {
        name: "payload",
        kind: BamFieldKind::NESTED,
        type_tag: "[u8;128]",
        offset: packet_offsets::PAYLOAD,
        size: STRATA_NET_MAX_PAYLOAD_BYTES,
        align: 1,
    },
];

/// Computes the deterministic 128-bit [`ComponentUuid`] for `"strata::net::StrataNetPacket"`,
/// matching `strata_sema::layout::compute_wire_identity` and `bamabi_macros` bit-for-bit.
#[must_use]
pub const fn stratanet_packet_uuid() -> ComponentUuid {
    let mut schema_hash = 0u64;
    let mut i = 0;
    while i < STRATA_NET_PACKET_FIELDS.len() {
        let f = &STRATA_NET_PACKET_FIELDS[i];
        schema_hash = ComponentUuid::hash_field_schema(schema_hash, f.name, f.type_tag, f.offset);
        i += 1;
    }
    ComponentUuid::from_parts(
        STRATA_NET_PACKET_CANONICAL_NAME,
        STRATA_NET_PACKET_SIZE,
        STRATA_NET_PACKET_ALIGN,
        schema_hash,
    )
}

/// Computes the deterministic 64-bit FNV-1a `SCHEMA_FINGERPRINT` for
/// `"strata::net::StrataNetPacket"`, matching `strata_sema::layout::compute_wire_identity` and
/// `bamabi_macros` bit-for-bit.
#[must_use]
pub const fn stratanet_packet_schema_fingerprint() -> u64 {
    let mut fp = fnv1a_64_init();
    fp = fnv1a_64_update_bytes(fp, STRATA_NET_PACKET_CANONICAL_NAME.as_bytes());
    fp = fnv1a_64_update_u64(fp, STRATA_NET_PACKET_SIZE as u64);
    fp = fnv1a_64_update_u64(fp, STRATA_NET_PACKET_ALIGN as u64);
    fp = fnv1a_64_update_u64(fp, 0); // component_flags
    let mut i = 0;
    while i < STRATA_NET_PACKET_FIELDS.len() {
        let f = &STRATA_NET_PACKET_FIELDS[i];
        fp = fnv1a_64_update_u64(fp, f.kind.0 as u64);
        fp = fnv1a_64_update_bytes(fp, f.name.as_bytes());
        fp = fnv1a_64_update_bytes(fp, f.type_tag.as_bytes());
        fp = fnv1a_64_update_u64(fp, f.offset as u64);
        fp = fnv1a_64_update_u64(fp, f.size as u64);
        fp = fnv1a_64_update_u64(fp, f.align as u64);
        i += 1;
    }
    fp
}

/// Returns `true` when `mir` declares any replicated/quantized network components or RPCs.
#[must_use]
pub fn has_net_protocol(mir: &MirModule) -> bool {
    mir.net_components
        .iter()
        .any(|c| c.is_replicated || !c.quantize_specs.is_empty())
        || !mir.rpcs.is_empty()
}

/// Validates that all networked components and RPCs in `mir` fit inside
/// [`STRATA_NET_MAX_PAYLOAD_BYTES`] (`128` bytes / `1024` bits).
pub fn validate_net_packet_capacity(mir: &MirModule) -> Result<(), CodegenError> {
    for nc in &mir.net_components {
        if nc.packed_bytes as usize > STRATA_NET_MAX_PAYLOAD_BYTES {
            return Err(CodegenError::Unsupported {
                context: nc.canonical_name.clone(),
                detail: format!(
                    "packed network component size {} bytes ({} bits) exceeds StrataNetPacket capacity of {} bytes",
                    nc.packed_bytes, nc.packed_bits, STRATA_NET_MAX_PAYLOAD_BYTES
                ),
            });
        }
    }
    for rpc in &mir.rpcs {
        if rpc.packed_bytes as usize > STRATA_NET_MAX_PAYLOAD_BYTES {
            return Err(CodegenError::Unsupported {
                context: rpc.canonical_name.clone(),
                detail: format!(
                    "packed RPC payload size {} bytes ({} bits) exceeds StrataNetPacket capacity of {} bytes",
                    rpc.packed_bytes, rpc.packed_bits, STRATA_NET_MAX_PAYLOAD_BYTES
                ),
            });
        }
    }
    Ok(())
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
#[must_use]
pub const fn verify_handshake_fingerprint(expected: u64, received: u64) -> bool {
    expected != 0 && expected == received
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_mir::{MirNetComponent, MirRpc, lower_to_mir};
    use strata_sema::analyze_source;
    use strata_sema::hir::{AuthorityKind, NetDirection, NetReliability};
    use strata_sema::layout::{SolvedField, compute_wire_identity};
    use strata_sema::types::Ty;

    #[test]
    fn stratanet_packet_layout_has_zero_implicit_padding_and_matches_sema_identity() {
        let mut cursor = 0usize;
        let mut max_align = 1usize;
        for f in STRATA_NET_PACKET_FIELDS {
            assert_eq!(f.offset, cursor, "gap before field `{}`", f.name);
            assert_eq!(f.offset % f.align, 0, "misaligned field `{}`", f.name);
            cursor += f.size;
            max_align = max_align.max(f.align);
        }
        assert_eq!(cursor, STRATA_NET_PACKET_SIZE);
        assert_eq!(max_align, STRATA_NET_PACKET_ALIGN);
        assert_eq!(STRATA_NET_PACKET_SIZE % STRATA_NET_PACKET_ALIGN, 0);

        let solved_fields: Vec<SolvedField> = STRATA_NET_PACKET_FIELDS
            .iter()
            .map(|f| SolvedField {
                name: f.name.to_owned(),
                ty: Ty::Unit,
                offset: f.offset,
                size: f.size,
                align: f.align,
                is_padding: f.name == "_pad",
                bam_field_kind: f.kind.0,
                type_tag: f.type_tag.to_owned(),
            })
            .collect();
        let (sema_uuid, sema_fp) = compute_wire_identity(
            STRATA_NET_PACKET_CANONICAL_NAME,
            STRATA_NET_PACKET_SIZE,
            STRATA_NET_PACKET_ALIGN,
            0,
            true,
            &solved_fields,
        );
        assert_eq!(stratanet_packet_uuid(), sema_uuid);
        assert_eq!(stratanet_packet_schema_fingerprint(), sema_fp);
        assert_eq!(
            stratanet_packet_schema_fingerprint(),
            STRATA_NET_PACKET_SCHEMA_FINGERPRINT
        );
        assert_ne!(sema_fp, 0);
    }

    #[test]
    fn bit_packing_across_byte_boundaries_round_trips() {
        let mut buf = [0u8; 16];
        pack_bits_le(&mut buf, 0, 1, 1);
        pack_bits_le(&mut buf, 1, 12, 0xA5F);
        pack_bits_le(&mut buf, 13, 16, 0xBEEF);
        pack_bits_le(&mut buf, 29, 32, 0xCAFE_BABE);
        pack_bits_le(&mut buf, 61, 64, 0x0123_4567_89AB_CDEF);

        assert_eq!(unpack_bits_le(&buf, 0, 1), 1);
        assert_eq!(unpack_bits_le(&buf, 1, 12), 0xA5F);
        assert_eq!(unpack_bits_le(&buf, 13, 16), 0xBEEF);
        assert_eq!(unpack_bits_le(&buf, 29, 32), 0xCAFE_BABE);
        assert_eq!(unpack_bits_le(&buf, 61, 64), 0x0123_4567_89AB_CDEF);

        // Overwriting an interior slice must not corrupt neighbors.
        pack_bits_le(&mut buf, 13, 16, 0x1234);
        assert_eq!(unpack_bits_le(&buf, 0, 1), 1);
        assert_eq!(unpack_bits_le(&buf, 1, 12), 0xA5F);
        assert_eq!(unpack_bits_le(&buf, 13, 16), 0x1234);
        assert_eq!(unpack_bits_le(&buf, 29, 32), 0xCAFE_BABE);
        assert_eq!(unpack_bits_le(&buf, 61, 64), 0x0123_4567_89AB_CDEF);
    }

    #[test]
    fn quantize_dequantize_1_12_16_32_bit_round_trips() {
        // 1-bit quantization: 0 -> min, 1 -> max.
        assert_eq!(quantize_scalar_f64(-5.0, 0.0, 10.0, 1, None), 0);
        assert_eq!(quantize_scalar_f64(15.0, 0.0, 10.0, 1, None), 1);
        assert_eq!(dequantize_scalar_f64(0, 0.0, 10.0, 1, None), 0.0);
        assert_eq!(dequantize_scalar_f64(1, 0.0, 10.0, 1, None), 10.0);

        // 12-bit quantization (-100.0 .. 100.0).
        let q12 = quantize_scalar_f64(37.25, -100.0, 100.0, 12, None);
        assert!(q12 <= 4095);
        let d12 = dequantize_scalar_f64(q12, -100.0, 100.0, 12, None);
        assert!((d12 - 37.25).abs() < 0.05, "d12={d12}");

        // 16-bit quantization with explicit step.
        let q16 = quantize_scalar_f64(12.34, -50.0, 50.0, 16, Some(0.01));
        let d16 = dequantize_scalar_f64(q16, -50.0, 50.0, 16, Some(0.01));
        assert!((d16 - 12.34).abs() <= 0.01, "d16={d16}");

        // 32-bit quantization must not overflow shift or lose precision.
        let q32_max = quantize_scalar_f64(1_000_000.0, -1_000_000.0, 1_000_000.0, 32, None);
        assert_eq!(q32_max, u64::from(u32::MAX));
        let q32_mid = quantize_scalar_f64(1234.5, -1_000_000.0, 1_000_000.0, 32, None);
        let d32_mid = dequantize_scalar_f64(q32_mid, -1_000_000.0, 1_000_000.0, 32, None);
        assert!((d32_mid - 1234.5).abs() < 1e-3, "d32_mid={d32_mid}");

        // NaN / non-finite handling clamps cleanly to min.
        assert_eq!(quantize_scalar_f64(f64::NAN, -10.0, 10.0, 8, None), 0);
    }

    #[test]
    fn handshake_verification_rejects_zero_and_mismatches() {
        assert!(!verify_handshake_fingerprint(0, 0));
        assert!(!verify_handshake_fingerprint(0, 123));
        assert!(!verify_handshake_fingerprint(0xABCD, 0));
        assert!(!verify_handshake_fingerprint(0xABCD, 0xABCE));
        assert!(verify_handshake_fingerprint(0xABCD, 0xABCD));
    }

    #[test]
    fn has_net_protocol_and_capacity_validation() {
        let non_net = analyze_source(
            "non_net.strata",
            "module game::plain @version(1.0.0);\ncomponent Pos { x: f32 = 0.0 }\n",
        );
        assert!(non_net.ok(), "{:?}", non_net.diagnostics);
        let non_net_mir = lower_to_mir(&non_net);
        assert!(!has_net_protocol(&non_net_mir));
        assert!(validate_net_packet_capacity(&non_net_mir).is_ok());

        let net = analyze_source(
            "net.strata",
            r#"
module game::net @version(1.0.0);
@net(reliable, channel = 0)
@authority(server)
component Pose {
    @quantize(min = -100.0, max = 100.0, bits = 12)
    x: f32 = 0.0,
}
"#,
        );
        assert!(net.ok(), "{:?}", net.diagnostics);
        let mut net_mir = lower_to_mir(&net);
        assert!(has_net_protocol(&net_mir));
        assert!(validate_net_packet_capacity(&net_mir).is_ok());

        // Exceeding 128-byte component capacity returns CodegenError::Unsupported.
        net_mir.net_components.push(MirNetComponent {
            name: "Huge".to_owned(),
            canonical_name: "game::net::Huge".to_owned(),
            is_resource: false,
            is_replicated: true,
            reliability: NetReliability::Reliable,
            rate_hz: None,
            interval_ticks: None,
            channel: 0,
            authority: AuthorityKind::Server,
            is_predicted: false,
            schema_fingerprint: 1,
            uuid_bytes: [0; 16],
            quantize_specs: Vec::new(),
            wire_fields: Vec::new(),
            packed_bits: 129 * 8,
            packed_bytes: 129,
        });
        assert!(validate_net_packet_capacity(&net_mir).is_err());

        // Exceeding 128-byte RPC capacity also returns CodegenError::Unsupported.
        net_mir.net_components.pop();
        net_mir.rpcs.push(MirRpc {
            name: "HugeRpc".to_owned(),
            canonical_name: "game::net::HugeRpc".to_owned(),
            direction: NetDirection::ClientToServer,
            reliability: NetReliability::Reliable,
            channel: 0,
            authority: AuthorityKind::Client,
            rpc_id: 1,
            schema_fingerprint: 1,
            fields: Vec::new(),
            quantize_specs: Vec::new(),
            wire_fields: Vec::new(),
            packed_bits: 130 * 8,
            packed_bytes: 130,
            payload_bytes: 130,
        });
        assert!(validate_net_packet_capacity(&net_mir).is_err());
    }
}
