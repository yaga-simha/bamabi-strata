//! C99 networking protocol, codecs, synthesized systems, and registration emission.

use super::*;

impl<'a> EmitCtx<'a> {
    pub(super) fn emit_net_protocol_and_codecs(&mut self) -> Result<(), CodegenError> {
        let mod_fp = self.mir.net_handshake.module_net_fingerprint;
        let _ = writeln!(
            self.out,
            "\
#define STRATA_NET_PACKET_MAGIC 0x{magic:08X}u
#define STRATA_NET_WIRE_VERSION {ver}u
#define STRATA_NET_MAX_PAYLOAD_BYTES {max_p}u
#define STRATA_NET_PACKET_SIZE {pkt_sz}u
#define STRATA_NET_PACKET_ALIGN {pkt_al}u
#define STRATA_NET_MODULE_FINGERPRINT 0x{mod_fp:016X}ull
#define STRATA_NET_PACKET_SCHEMA_FINGERPRINT 0x{pkt_fp:016X}ull
#define STRATA_NET_KIND_HANDSHAKE 0u
#define STRATA_NET_KIND_COMPONENT_DELTA {k_comp}u
#define STRATA_NET_KIND_RESOURCE_DELTA {k_res}u
#define STRATA_NET_KIND_RPC {k_rpc}u
#define STRATA_NET_FLAG_RPC {f_rpc}u
#define STRATA_NET_FLAG_RELIABLE {f_rel}u
#define STRATA_NET_FLAG_HANDSHAKE 4u
#define STRATA_NET_FLAG_PREDICTED {f_pred}u
#define STRATA_NET_FLAG_RESOURCE {f_res}u

typedef struct StrataNetPacket {{
    uint64_t module_net_fingerprint;
    uint64_t item_schema_fingerprint;
    uint64_t target_id;
    uint64_t entity_bits;
    uint32_t magic;
    uint32_t tick_or_seq;
    uint16_t version;
    uint16_t payload_bits;
    uint16_t flags;
    uint8_t kind;
    uint8_t channel;
    uint8_t payload_bytes;
    uint8_t client_id;
    uint8_t _pad[6];
    uint8_t payload[{max_p}];
}} StrataNetPacket;

BAM_STATIC_ASSERT(sizeof(StrataNetPacket) == {pkt_sz}u, strata_net_packet_size);
BAM_STATIC_ASSERT(offsetof(StrataNetPacket, module_net_fingerprint) == 0u, snp_off_mod_fp);
BAM_STATIC_ASSERT(offsetof(StrataNetPacket, item_schema_fingerprint) == 8u, snp_off_item_fp);
BAM_STATIC_ASSERT(offsetof(StrataNetPacket, target_id) == 16u, snp_off_target);
BAM_STATIC_ASSERT(offsetof(StrataNetPacket, entity_bits) == 24u, snp_off_entity);
BAM_STATIC_ASSERT(offsetof(StrataNetPacket, magic) == 32u, snp_off_magic);
BAM_STATIC_ASSERT(offsetof(StrataNetPacket, version) == 40u, snp_off_version);
BAM_STATIC_ASSERT(offsetof(StrataNetPacket, payload) == 56u, snp_off_payload);

static BAM_UNUSED inline uint64_t strata_net_quantize_scalar_f64(
    double val, double min_v, double max_v, uint8_t bits, double step_v, bool has_step
) {{
    if (bits == 0u || !isfinite(min_v) || !isfinite(max_v) || min_v >= max_v) {{
        return 0ull;
    }}
    uint8_t eff_bits = (bits > 32u) ? 32u : bits;
    uint64_t max_q = (eff_bits == 32u)
        ? 0xFFFFFFFFull
        : ((eff_bits == 12u) ? 4095ull : ((1ull << eff_bits) - 1ull));
    double eff_step = (has_step && isfinite(step_v) && step_v > 0.0)
        ? step_v
        : ((max_v - min_v) / (double)(max_q > 0ull ? max_q : 1ull));
    if (!isfinite(eff_step) || eff_step <= 0.0) {{
        return 0ull;
    }}
    double clamped = isnan(val) ? min_v : ((val < min_v) ? min_v : ((val > max_v) ? max_v : val));
    double rounded = round((clamped - min_v) / eff_step);
    if (!isfinite(rounded) || rounded <= 0.0) {{
        return 0ull;
    }}
    if (rounded >= (double)max_q) {{
        return max_q;
    }}
    uint64_t q = (uint64_t)rounded;
    return (q > max_q) ? max_q : q;
}}

static BAM_UNUSED inline double strata_net_dequantize_scalar_f64(
    uint64_t raw, double min_v, double max_v, uint8_t bits, double step_v, bool has_step
) {{
    if (bits == 0u || !isfinite(min_v) || !isfinite(max_v) || min_v >= max_v) {{
        return min_v;
    }}
    uint8_t eff_bits = (bits > 32u) ? 32u : bits;
    uint64_t max_q = (eff_bits == 32u)
        ? 0xFFFFFFFFull
        : ((eff_bits == 12u) ? 4095ull : ((1ull << eff_bits) - 1ull));
    uint64_t q = raw & max_q;
    double eff_step = (has_step && isfinite(step_v) && step_v > 0.0)
        ? step_v
        : ((max_v - min_v) / (double)(max_q > 0ull ? max_q : 1ull));
    if (!isfinite(eff_step) || eff_step <= 0.0) {{
        return min_v;
    }}
    double out = min_v + ((double)q * eff_step);
    if (out < min_v) {{ return min_v; }}
    if (out > max_v) {{ return max_v; }}
    return out;
}}

static BAM_UNUSED inline void strata_net_pack_bits_le(
    uint8_t* buf, size_t buf_len, uint32_t bit_offset, uint8_t bits, uint64_t val
) {{
    uint8_t eff_bits = (bits > 64u) ? 64u : bits;
    if (eff_bits == 0u || buf == NULL) {{
        return;
    }}
    uint64_t mask = (eff_bits == 64u) ? UINT64_MAX : ((1ull << eff_bits) - 1ull);
    uint64_t src = val & mask;
    uint8_t remaining = eff_bits;
    size_t cur_bit = (size_t)bit_offset;
    while (remaining > 0u) {{
        size_t byte_idx = cur_bit / 8u;
        if (byte_idx >= buf_len) {{
            break;
        }}
        size_t bit_in_byte = cur_bit % 8u;
        size_t avail = 8u - bit_in_byte;
        size_t take = (avail < (size_t)remaining) ? avail : (size_t)remaining;
        uint8_t low_mask = (uint8_t)((1u << take) - 1u);
        uint8_t chunk_mask = (uint8_t)(low_mask << bit_in_byte);
        uint8_t chunk_bits = (uint8_t)(((uint8_t)(src & (uint64_t)low_mask)) << bit_in_byte);
        buf[byte_idx] = (uint8_t)((buf[byte_idx] & (uint8_t)(~chunk_mask)) | chunk_bits);
        src >>= take;
        cur_bit += take;
        remaining = (uint8_t)(remaining - (uint8_t)take);
    }}
}}

static BAM_UNUSED inline uint64_t strata_net_unpack_bits_le(
    const uint8_t* buf, size_t buf_len, uint32_t bit_offset, uint8_t bits
) {{
    uint8_t eff_bits = (bits > 64u) ? 64u : bits;
    if (eff_bits == 0u || buf == NULL) {{
        return 0ull;
    }}
    uint8_t remaining = eff_bits;
    size_t cur_bit = (size_t)bit_offset;
    uint64_t out = 0ull;
    uint32_t shift = 0u;
    while (remaining > 0u) {{
        size_t byte_idx = cur_bit / 8u;
        if (byte_idx >= buf_len) {{
            break;
        }}
        size_t bit_in_byte = cur_bit % 8u;
        size_t avail = 8u - bit_in_byte;
        size_t take = (avail < (size_t)remaining) ? avail : (size_t)remaining;
        uint8_t low_mask = (uint8_t)((1u << take) - 1u);
        uint8_t chunk = (uint8_t)((buf[byte_idx] >> bit_in_byte) & low_mask);
        out |= ((uint64_t)chunk) << shift;
        shift += (uint32_t)take;
        cur_bit += take;
        remaining = (uint8_t)(remaining - (uint8_t)take);
    }}
    return out;
}}

static BAM_UNUSED inline bool strata_net_verify_handshake(
    const StrataNetPacket* pkt, uint64_t expected_item_fp
) {{
    if (pkt == NULL) {{
        return false;
    }}
    if (pkt->magic != STRATA_NET_PACKET_MAGIC || pkt->version != STRATA_NET_WIRE_VERSION) {{
        return false;
    }}
    if (pkt->module_net_fingerprint != STRATA_NET_MODULE_FINGERPRINT || pkt->module_net_fingerprint == 0ull) {{
        return false;
    }}
    if (pkt->item_schema_fingerprint != expected_item_fp || expected_item_fp == 0ull) {{
        return false;
    }}
    if ((size_t)pkt->payload_bytes > STRATA_NET_MAX_PAYLOAD_BYTES) {{
        return false;
    }}
    return true;
}}
",
            magic = STRATA_NET_PACKET_MAGIC,
            ver = STRATA_NET_WIRE_VERSION,
            max_p = STRATA_NET_MAX_PAYLOAD_BYTES,
            pkt_sz = STRATA_NET_PACKET_SIZE,
            pkt_al = STRATA_NET_PACKET_ALIGN,
            pkt_fp = STRATA_NET_PACKET_SCHEMA_FINGERPRINT,
            k_comp = PACKET_KIND_COMPONENT_DELTA,
            k_res = PACKET_KIND_RESOURCE_DELTA,
            k_rpc = PACKET_KIND_RPC,
            f_rpc = FLAG_IS_RPC,
            f_rel = FLAG_IS_RELIABLE,
            f_pred = FLAG_IS_PREDICTED,
            f_res = FLAG_IS_RESOURCE,
        );

        let rpcs = self.mir.rpcs.clone();
        for rpc in &rpcs {
            self.emit_c99_rpc_struct_and_codec(rpc)?;
        }
        let ncs = self.mir.net_components.clone();
        for nc in &ncs {
            if nc.is_replicated || !nc.quantize_specs.is_empty() {
                self.emit_c99_net_component_codec(nc)?;
            }
        }
        Ok(())
    }

    pub(super) fn c_rpc_field_decl(
        &self,
        ty: &MirType,
        byte_size: u32,
        field_name: &str,
    ) -> String {
        match ty {
            MirType::Bool | MirType::U8 => format!("uint8_t {field_name}"),
            MirType::I8 => format!("int8_t {field_name}"),
            MirType::I16 => format!("int16_t {field_name}"),
            MirType::U16 => format!("uint16_t {field_name}"),
            MirType::I32 | MirType::Fix32 => format!("int32_t {field_name}"),
            MirType::U32 | MirType::Sym => format!("uint32_t {field_name}"),
            MirType::I64 | MirType::Fix64 => format!("int64_t {field_name}"),
            MirType::U64 => format!("uint64_t {field_name}"),
            MirType::F32 => format!("float {field_name}"),
            MirType::F64 => format!("double {field_name}"),
            MirType::Entity => format!("BamEntity {field_name}"),
            MirType::Vec2 => format!("StrataVec2 {field_name}"),
            MirType::Vec3 => format!("StrataVec3 {field_name}"),
            MirType::Vec4 => format!("StrataVec4 {field_name}"),
            MirType::IVec2 => format!("StrataIVec2 {field_name}"),
            MirType::IVec3 => format!("StrataIVec3 {field_name}"),
            MirType::UVec2 => format!("StrataUVec2 {field_name}"),
            MirType::Array { elem, len } => {
                let elem_sz = byte_size / ((*len).max(1) as u32);
                self.c_rpc_field_decl(elem, elem_sz, &format!("{field_name}[{len}]"))
            }
            MirType::Named(key) => {
                if let Some(l_idx) = self.find_layout_idx(key)
                    && self.layouts[l_idx].size == byte_size as usize
                {
                    format!("{} {field_name}", self.layout_c_names[l_idx])
                } else if key.starts_with("Asset<") {
                    format!("BamAssetHandle {field_name}")
                } else if key.contains("IVec2") {
                    format!("StrataIVec2 {field_name}")
                } else if key.contains("IVec3") {
                    format!("StrataIVec3 {field_name}")
                } else if key.contains("UVec2") {
                    format!("StrataUVec2 {field_name}")
                } else if key.contains("Vec3a") && byte_size == 12 {
                    format!("StrataVec3 {field_name}")
                } else if key.contains("Vec3a")
                    || key.contains("Vec4")
                    || key.contains("Quat")
                    || key.contains("Rgba")
                {
                    format!("StrataVec4 {field_name}")
                } else if byte_size == 1 {
                    format!("uint8_t {field_name}")
                } else if byte_size == 2 {
                    format!("uint16_t {field_name}")
                } else if byte_size == 4 {
                    format!("int32_t {field_name}")
                } else if byte_size == 8 {
                    format!("int64_t {field_name}")
                } else {
                    format!("uint8_t {field_name}[{}]", byte_size.max(1))
                }
            }
            _ => format!("uint8_t {field_name}[{}]", byte_size.max(1)),
        }
    }

    pub(super) fn emit_c99_wire_field_encode(
        &mut self,
        wf: &MirNetFieldSpec,
        field_c: &str,
        src_var: &str,
    ) {
        if let Some(ref q) = wf.quantize {
            let (step_v, has_step) = match q.step {
                Some(s) => (c_f64(s), true),
                None => (c_f64(0.0), false),
            };
            let min_s = c_f64(q.min);
            let max_s = c_f64(q.max);
            let bits = q.bits;
            let cast_in = |expr: &str| -> String {
                match &wf.ty {
                    MirType::Fix32 => format!("((double)({expr}) / 65536.0)"),
                    MirType::Fix64 => format!("((double)({expr}) / 4294967296.0)"),
                    _ => format!("(double)({expr})"),
                }
            };
            if q.lane_count == 1 {
                let val_s = cast_in(&format!("{src_var}->{field_c}"));
                let _ = writeln!(
                    self.out,
                    "    strata_net_pack_bits_le(out_pkt->payload, sizeof(out_pkt->payload), {}u, {bits}u, strata_net_quantize_scalar_f64({val_s}, {min_s}, {max_s}, {bits}u, {step_v}, {has_step}));",
                    wf.bit_offset
                );
            } else {
                let lanes = ["x", "y", "z", "w"];
                for (li, lane) in lanes.iter().take(q.lane_count as usize).enumerate() {
                    let boff = wf.bit_offset + (li as u32) * u32::from(bits);
                    let val_s = cast_in(&format!("{src_var}->{field_c}.{lane}"));
                    let _ = writeln!(
                        self.out,
                        "    strata_net_pack_bits_le(out_pkt->payload, sizeof(out_pkt->payload), {boff}u, {bits}u, strata_net_quantize_scalar_f64({val_s}, {min_s}, {max_s}, {bits}u, {step_v}, {has_step}));"
                    );
                }
            }
        } else if wf.byte_size > 0 {
            let n = wf.byte_size as usize;
            let boff = wf.bit_offset;
            let _ = writeln!(
                self.out,
                "    {{\n        uint8_t raw[{n}u];\n        memcpy(raw, &{src_var}->{field_c}, {n}u);\n        size_t bi;\n        for (bi = 0u; bi < {n}u; ++bi) {{\n            strata_net_pack_bits_le(out_pkt->payload, sizeof(out_pkt->payload), {boff}u + (uint32_t)(bi * 8u), 8u, (uint64_t)raw[bi]);\n        }}\n    }}"
            );
        }
    }

    pub(super) fn emit_c99_wire_field_decode(
        &mut self,
        wf: &MirNetFieldSpec,
        field_c: &str,
        dst_var: &str,
        sema_ty: Option<&Ty>,
    ) {
        if let Some(ref q) = wf.quantize {
            let (step_v, has_step) = match q.step {
                Some(s) => (c_f64(s), true),
                None => (c_f64(0.0), false),
            };
            let min_s = c_f64(q.min);
            let max_s = c_f64(q.max);
            let bits = q.bits;
            let cast_lane = |val_expr: &str| -> String {
                match (&wf.ty, sema_ty) {
                    (MirType::F64, _) | (_, Some(Ty::F64)) => val_expr.to_string(),
                    (MirType::I8, _) | (_, Some(Ty::I8)) => format!("(int8_t)round({val_expr})"),
                    (MirType::I16, _) | (_, Some(Ty::I16)) => format!("(int16_t)round({val_expr})"),
                    (MirType::Fix32, _) | (_, Some(Ty::Fix32)) => {
                        format!("(int32_t)round(({val_expr}) * 65536.0)")
                    }
                    (MirType::I32, _) | (_, Some(Ty::I32)) => {
                        format!("(int32_t)round({val_expr})")
                    }
                    (MirType::Fix64, _) | (_, Some(Ty::Fix64)) => {
                        format!("(int64_t)round(({val_expr}) * 4294967296.0)")
                    }
                    (MirType::I64, _) | (_, Some(Ty::I64)) => {
                        format!("(int64_t)round({val_expr})")
                    }
                    (MirType::U8, _) | (_, Some(Ty::U8)) => {
                        format!("(uint8_t)fmax(0.0, round({val_expr}))")
                    }
                    (MirType::U16, _) | (_, Some(Ty::U16)) => {
                        format!("(uint16_t)fmax(0.0, round({val_expr}))")
                    }
                    (MirType::U32, _) | (_, Some(Ty::U32)) => {
                        format!("(uint32_t)fmax(0.0, round({val_expr}))")
                    }
                    (MirType::U64, _) | (_, Some(Ty::U64)) => {
                        format!("(uint64_t)fmax(0.0, round({val_expr}))")
                    }
                    (MirType::IVec2 | MirType::IVec3, _) | (_, Some(Ty::IVec2 | Ty::IVec3)) => {
                        format!("(int32_t)round({val_expr})")
                    }
                    (MirType::Named(k), _) if k.contains("IVec") => {
                        format!("(int32_t)round({val_expr})")
                    }
                    (MirType::Named(k), _) if k.contains("UVec") => {
                        format!("(uint32_t)fmax(0.0, round({val_expr}))")
                    }
                    (MirType::UVec2, _) | (_, Some(Ty::UVec2)) => {
                        format!("(uint32_t)fmax(0.0, round({val_expr}))")
                    }
                    _ => format!("(float)({val_expr})"),
                }
            };
            if q.lane_count == 1 {
                let expr = format!(
                    "strata_net_dequantize_scalar_f64(strata_net_unpack_bits_le(pkt->payload, sizeof(pkt->payload), {}u, {bits}u), {min_s}, {max_s}, {bits}u, {step_v}, {has_step})",
                    wf.bit_offset
                );
                let assigned = cast_lane(&expr);
                let _ = writeln!(self.out, "    {dst_var}->{field_c} = {assigned};");
            } else {
                let lanes = ["x", "y", "z", "w"];
                for (li, lane) in lanes.iter().take(q.lane_count as usize).enumerate() {
                    let boff = wf.bit_offset + (li as u32) * u32::from(bits);
                    let expr = format!(
                        "strata_net_dequantize_scalar_f64(strata_net_unpack_bits_le(pkt->payload, sizeof(pkt->payload), {boff}u, {bits}u), {min_s}, {max_s}, {bits}u, {step_v}, {has_step})"
                    );
                    let assigned = cast_lane(&expr);
                    let _ = writeln!(self.out, "    {dst_var}->{field_c}.{lane} = {assigned};");
                }
            }
        } else if wf.byte_size > 0 {
            let n = wf.byte_size as usize;
            let boff = wf.bit_offset;
            let _ = writeln!(
                self.out,
                "    {{\n        uint8_t raw[{n}u];\n        size_t bi;\n        for (bi = 0u; bi < {n}u; ++bi) {{\n            raw[bi] = (uint8_t)strata_net_unpack_bits_le(pkt->payload, sizeof(pkt->payload), {boff}u + (uint32_t)(bi * 8u), 8u);\n        }}\n        memcpy(&{dst_var}->{field_c}, raw, {n}u);\n    }}"
            );
        }
    }

    pub(super) fn emit_c99_net_component_codec(
        &mut self,
        nc: &MirNetComponent,
    ) -> Result<(), CodegenError> {
        let Some(l_idx) = self.find_layout_idx(&nc.canonical_name) else {
            return Err(CodegenError::Unsupported {
                context: format!("c99::net_component({})", nc.canonical_name),
                detail: "missing solved layout for network component".to_owned(),
            });
        };
        let cty = self.layout_c_names[l_idx].clone();
        let ident = sanitize_ident(&nc.name);
        let fp = nc.schema_fingerprint;
        let target_id = fnv1a_64_str(&nc.canonical_name);
        let kind_expr = if nc.is_resource {
            "STRATA_NET_KIND_RESOURCE_DELTA"
        } else {
            "STRATA_NET_KIND_COMPONENT_DELTA"
        };
        let mut flags_parts = Vec::new();
        if matches!(nc.reliability, strata_sema::hir::NetReliability::Reliable) {
            flags_parts.push("STRATA_NET_FLAG_RELIABLE");
        }
        if nc.is_predicted || nc.authority == strata_sema::hir::AuthorityKind::Predicted {
            flags_parts.push("STRATA_NET_FLAG_PREDICTED");
        }
        if nc.is_resource {
            flags_parts.push("STRATA_NET_FLAG_RESOURCE");
        }
        let flags_expr = if flags_parts.is_empty() {
            "0u".to_string()
        } else {
            flags_parts.join(" | ")
        };

        let _ = writeln!(
            self.out,
            "\
static BAM_UNUSED inline void strata_net_encode_{ident}(
    const {cty}* src, uint64_t entity_bits, uint32_t tick_or_seq, uint8_t client_id, StrataNetPacket* out_pkt
) {{
    if (out_pkt == NULL) {{ return; }}
    memset(out_pkt, 0, sizeof(*out_pkt));
    out_pkt->module_net_fingerprint = STRATA_NET_MODULE_FINGERPRINT;
    out_pkt->item_schema_fingerprint = 0x{fp:016X}ull;
    out_pkt->target_id = 0x{target_id:016X}ull;
    out_pkt->entity_bits = entity_bits;
    out_pkt->magic = STRATA_NET_PACKET_MAGIC;
    out_pkt->tick_or_seq = tick_or_seq;
    out_pkt->version = STRATA_NET_WIRE_VERSION;
    out_pkt->payload_bits = {pbits}u;
    out_pkt->flags = (uint16_t)({flags_expr});
    out_pkt->kind = {kind_expr};
    out_pkt->channel = {ch}u;
    out_pkt->payload_bytes = {pbytes}u;
    out_pkt->client_id = client_id;
    if (src == NULL) {{ return; }}",
            pbits = nc.packed_bits,
            ch = nc.channel,
            pbytes = nc.packed_bytes,
        );
        let layout_fields = self.layouts[l_idx].fields.clone();
        for wf in &nc.wire_fields {
            if !layout_fields.iter().any(|sf| sf.name == wf.field_name) {
                return Err(CodegenError::Unsupported {
                    context: format!("c99::net_component({})", nc.canonical_name),
                    detail: format!(
                        "wire field `{}` missing from solved layout `{}`",
                        wf.field_name, self.layouts[l_idx].canonical_name
                    ),
                });
            }
            let fc = sanitize_c_field(&wf.field_name);
            self.emit_c99_wire_field_encode(wf, &fc, "src");
        }
        let _ = writeln!(self.out, "}}\n");

        let _ = writeln!(
            self.out,
            "\
static BAM_UNUSED inline bool strata_net_decode_{ident}(
    const StrataNetPacket* pkt, {cty}* out_val
) {{
    if (pkt == NULL || out_val == NULL) {{
        return false;
    }}
    if (!strata_net_verify_handshake(pkt, 0x{fp:016X}ull) || pkt->item_schema_fingerprint != 0x{fp:016X}ull) {{
        return false;
    }}
    if (pkt->target_id != 0x{target_id:016X}ull || pkt->kind != {kind_expr}) {{
        return false;
    }}",
        );
        if nc.packed_bytes > 0 {
            let _ = writeln!(
                self.out,
                "    if ((size_t)pkt->payload_bytes < {pbytes}u) {{\n        return false;\n    }}",
                pbytes = nc.packed_bytes,
            );
        }
        for wf in &nc.wire_fields {
            let Some(sf) = layout_fields.iter().find(|sf| sf.name == wf.field_name) else {
                return Err(CodegenError::Unsupported {
                    context: format!("c99::net_component({})", nc.canonical_name),
                    detail: format!(
                        "wire field `{}` missing from solved layout `{}`",
                        wf.field_name, self.layouts[l_idx].canonical_name
                    ),
                });
            };
            let fc = sanitize_c_field(&wf.field_name);
            let sty = sf.ty.clone();
            self.emit_c99_wire_field_decode(wf, &fc, "out_val", Some(&sty));
        }
        let _ = writeln!(self.out, "    return true;\n}}\n");
        Ok(())
    }

    pub(super) fn emit_c99_rpc_struct_and_codec(
        &mut self,
        rpc: &MirRpc,
    ) -> Result<(), CodegenError> {
        let ident = sanitize_ident(&rpc.name);
        let rty = format!("StrataRpc_{ident}");
        let _ = writeln!(self.out, "typedef struct {rty} {{");
        if rpc.fields.is_empty() {
            let _ = writeln!(self.out, "    uint8_t _zst_pad;");
        } else {
            let mut cursor: u32 = 0;
            let mut pad_idx: usize = 0;
            for (fname, mty, off, sz) in &rpc.fields {
                if *off > cursor {
                    let gap = *off - cursor;
                    let _ = writeln!(self.out, "    uint8_t _pad_{pad_idx}[{gap}];");
                    pad_idx += 1;
                }
                let fc = sanitize_c_field(fname);
                let decl = self.c_rpc_field_decl(mty, *sz, &fc);
                let _ = writeln!(self.out, "    {decl};");
                cursor = off.saturating_add(*sz);
            }
            if rpc.payload_bytes > cursor {
                let tail = rpc.payload_bytes - cursor;
                let _ = writeln!(self.out, "    uint8_t _pad_tail[{tail}];");
            }
        }
        let _ = writeln!(self.out, "}} {rty};\n");

        let fp = rpc.schema_fingerprint;
        let rpc_id = rpc.rpc_id;
        let mut flags_parts = vec!["STRATA_NET_FLAG_RPC"];
        if matches!(rpc.reliability, strata_sema::hir::NetReliability::Reliable) {
            flags_parts.push("STRATA_NET_FLAG_RELIABLE");
        }
        let flags_expr = flags_parts.join(" | ");

        let _ = writeln!(
            self.out,
            "\
static BAM_UNUSED inline void strata_net_encode_rpc_{ident}(
    const {rty}* rpc, uint32_t tick_or_seq, uint8_t client_id, StrataNetPacket* out_pkt
) {{
    if (out_pkt == NULL) {{ return; }}
    memset(out_pkt, 0, sizeof(*out_pkt));
    out_pkt->module_net_fingerprint = STRATA_NET_MODULE_FINGERPRINT;
    out_pkt->item_schema_fingerprint = 0x{fp:016X}ull;
    out_pkt->target_id = 0x{rpc_id:016X}ull;
    out_pkt->entity_bits = 0ull;
    out_pkt->magic = STRATA_NET_PACKET_MAGIC;
    out_pkt->tick_or_seq = tick_or_seq;
    out_pkt->version = STRATA_NET_WIRE_VERSION;
    out_pkt->payload_bits = {pbits}u;
    out_pkt->flags = (uint16_t)({flags_expr});
    out_pkt->kind = STRATA_NET_KIND_RPC;
    out_pkt->channel = {ch}u;
    out_pkt->payload_bytes = {pbytes}u;
    out_pkt->client_id = client_id;
    if (rpc == NULL) {{ return; }}",
            pbits = rpc.packed_bits,
            ch = rpc.channel,
            pbytes = rpc.packed_bytes,
        );
        for wf in &rpc.wire_fields {
            if !rpc.fields.iter().any(|(n, _, _, _)| n == &wf.field_name) {
                return Err(CodegenError::Unsupported {
                    context: format!("c99::rpc({})", rpc.canonical_name),
                    detail: format!("wire field `{}` missing from RPC payload", wf.field_name),
                });
            }
            let fc = sanitize_c_field(&wf.field_name);
            self.emit_c99_wire_field_encode(wf, &fc, "rpc");
        }
        let _ = writeln!(self.out, "}}\n");

        let _ = writeln!(
            self.out,
            "\
static BAM_UNUSED inline bool strata_net_decode_rpc_{ident}(
    const StrataNetPacket* pkt, {rty}* out_rpc
) {{
    if (pkt == NULL || out_rpc == NULL) {{
        return false;
    }}
    if (!strata_net_verify_handshake(pkt, 0x{fp:016X}ull) || pkt->item_schema_fingerprint != 0x{fp:016X}ull) {{
        return false;
    }}
    if (pkt->target_id != 0x{rpc_id:016X}ull || pkt->kind != STRATA_NET_KIND_RPC) {{
        return false;
    }}",
        );
        if rpc.packed_bytes > 0 {
            let _ = writeln!(
                self.out,
                "    if ((size_t)pkt->payload_bytes < {pbytes}u) {{\n        return false;\n    }}",
                pbytes = rpc.packed_bytes,
            );
        }
        for wf in &rpc.wire_fields {
            if !rpc.fields.iter().any(|(n, _, _, _)| n == &wf.field_name) {
                return Err(CodegenError::Unsupported {
                    context: format!("c99::rpc({})", rpc.canonical_name),
                    detail: format!("wire field `{}` missing from RPC payload", wf.field_name),
                });
            }
            let fc = sanitize_c_field(&wf.field_name);
            self.emit_c99_wire_field_decode(wf, &fc, "out_rpc", None);
        }
        let _ = writeln!(self.out, "    return true;\n}}\n");
        Ok(())
    }

    pub(super) fn emit_net_synthesized_systems(&mut self) {
        let rep_comps: Vec<MirNetComponent> = self
            .mir
            .net_components
            .iter()
            .filter(|nc| nc.is_replicated)
            .cloned()
            .collect();
        if rep_comps.is_empty() {
            return;
        }
        let max_per_sys = MAX_QUERIES_PER_SYSTEM.saturating_sub(1).max(1);
        for (chunk_idx, chunk) in rep_comps.chunks(max_per_sys).enumerate() {
            // RX system
            let _ = writeln!(
                self.out,
                "\
static BAM_UNUSED BamResult strata_sys_net_rx_{chunk_idx}(BamSystemCtx* sys_ctx, void* user_data) {{
    StrataModState* state = (StrataModState*)user_data;
    if (sys_ctx == NULL || state == NULL || state->api == NULL || state->net_pkt_is_msg == 0u) {{
        return BAM_RESULT_OK;
    }}
    if (state->api->sys_query == NULL || state->api->msg_read_batch == NULL || state->net_rx_buf == NULL) {{
        return BAM_RESULT_OK;
    }}
    BamIter* msg_it = NULL;
    if (state->api->sys_query(sys_ctx, 0u, &msg_it) != BAM_RESULT_OK || msg_it == NULL) {{
        return BAM_RESULT_OK;
    }}
    StrataNetPacket* pkts = state->net_rx_buf;
    size_t got = 0u;
    do {{
        got = 0u;
        if (state->api->msg_read_batch(msg_it, 0u, (uint8_t*)pkts, {STRATA_NET_RX_BATCH_CAP}u, &got) != BAM_RESULT_OK || got == 0u) {{
            break;
        }}"
            );
            let mut entity_q_idx = 1u32;
            for nc in chunk {
                let Some(c_idx) = self.find_comp_idx(&nc.canonical_name) else {
                    continue;
                };
                let Some(l_idx) = self.components[c_idx].layout_idx else {
                    continue;
                };
                let cty = self.layout_c_names[l_idx].clone();
                let is_zst = self.layouts[l_idx].size == 0;
                let ident = sanitize_ident(&nc.name);
                let target_id = fnv1a_64_str(&nc.canonical_name);
                if nc.is_resource {
                    if is_zst {
                        let _ = writeln!(
                            self.out,
                            "        if (state->res_flags[{c_idx}] == 1u) {{ /* ZST resource: skip 1-byte column read */ }}"
                        );
                    } else {
                        let _ = writeln!(
                            self.out,
                            "\
        if (state->res_flags[{c_idx}] == 1u && state->api->sys_res_mut_ptr != NULL) {{
            size_t pi;
            const StrataNetPacket* last_pkt = NULL;
            for (pi = 0u; pi < got; ++pi) {{
                if (pkts[pi].kind == STRATA_NET_KIND_RESOURCE_DELTA && pkts[pi].target_id == 0x{target_id:016X}ull) {{
                    last_pkt = &pkts[pi];
                }}
            }}
            if (last_pkt != NULL) {{
                {cty}* rptr = ({cty}*)state->api->sys_res_mut_ptr(sys_ctx, state->components[{c_idx}], NULL);
                if (rptr != NULL) {{
                    {cty} tmp = *rptr;
                    if (strata_net_decode_{ident}(last_pkt, &tmp) && memcmp(&tmp, rptr, sizeof(tmp)) != 0) {{
                        *rptr = tmp;
                    }}
                }}
            }}
        }}"
                        );
                    }
                } else {
                    let qi = entity_q_idx;
                    entity_q_idx += 1;
                    let is_sparse = (self.layouts[l_idx].component_flags
                        & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET)
                        != 0;
                    let _ = writeln!(
                        self.out,
                        "\
        {{
            bool has_match = false;
            size_t pi;
            for (pi = 0u; pi < got; ++pi) {{
                if (pkts[pi].kind == STRATA_NET_KIND_COMPONENT_DELTA && pkts[pi].target_id == 0x{target_id:016X}ull) {{
                    has_match = true;
                    break;
                }}
            }}
            if (has_match && state->api->iter_next_chunk != NULL && state->api->iter_entities != NULL) {{
                BamIter* q_it = NULL;
                if (state->api->sys_query(sys_ctx, {qi}u, &q_it) == BAM_RESULT_OK && q_it != NULL) {{
                    if (state->api->iter_reset != NULL) {{ (void)state->api->iter_reset(q_it); }}
                    size_t clen = 0u;
                    while (state->api->iter_next_chunk(q_it, &clen) != BAM_FALSE && clen > 0u) {{
                        const BamEntity* ents = state->api->iter_entities(q_it);"
                    );
                    if is_zst {
                        let _ = writeln!(
                            self.out,
                            "\
                        if (ents != NULL) {{
                            size_t row;
                            for (row = 0u; row < clen; ++row) {{
                                const StrataNetPacket* last_pkt = NULL;
                                for (pi = 0u; pi < got; ++pi) {{
                                    if (pkts[pi].kind == STRATA_NET_KIND_COMPONENT_DELTA && pkts[pi].target_id == 0x{target_id:016X}ull && pkts[pi].entity_bits == (uint64_t)ents[row]) {{
                                        last_pkt = &pkts[pi];
                                    }}
                                }}
                                if (last_pkt != NULL) {{
                                    {cty} tmp;
                                    memset(&tmp, 0, sizeof(tmp));
                                    (void)strata_net_decode_{ident}(last_pkt, &tmp);
                                }}
                            }}
                        }}"
                        );
                    } else if is_sparse {
                        let _ = writeln!(
                            self.out,
                            "\
                        {cty}* const* rows = (state->api->iter_column_rows_mutable != NULL) ? ({cty}* const*)state->api->iter_column_rows_mutable(q_it, 0u) : NULL;
                        if (ents != NULL && rows != NULL) {{
                            size_t row;
                            for (row = 0u; row < clen; ++row) {{
                                const StrataNetPacket* last_pkt = NULL;
                                for (pi = 0u; pi < got; ++pi) {{
                                    if (pkts[pi].kind == STRATA_NET_KIND_COMPONENT_DELTA && pkts[pi].target_id == 0x{target_id:016X}ull && pkts[pi].entity_bits == (uint64_t)ents[row]) {{
                                        last_pkt = &pkts[pi];
                                    }}
                                }}
                                if (last_pkt != NULL && rows[row] != NULL) {{
                                    {cty} tmp = *rows[row];
                                    if (strata_net_decode_{ident}(last_pkt, &tmp) && memcmp(&tmp, rows[row], sizeof(tmp)) != 0) {{
                                        *rows[row] = tmp;
                                        if (state->api->iter_mark_changed_range != NULL) {{
                                            (void)state->api->iter_mark_changed_range(q_it, 0u, row, 1u);
                                        }}
                                    }}
                                }}
                            }}
                        }}"
                        );
                    } else {
                        let _ = writeln!(
                            self.out,
                            "\
                        {cty}* col = (state->api->iter_column_mutable_untracked != NULL) ? ({cty}*)state->api->iter_column_mutable_untracked(q_it, 0u) : NULL;
                        if (ents != NULL && col != NULL) {{
                            size_t row;
                            for (row = 0u; row < clen; ++row) {{
                                const StrataNetPacket* last_pkt = NULL;
                                for (pi = 0u; pi < got; ++pi) {{
                                    if (pkts[pi].kind == STRATA_NET_KIND_COMPONENT_DELTA && pkts[pi].target_id == 0x{target_id:016X}ull && pkts[pi].entity_bits == (uint64_t)ents[row]) {{
                                        last_pkt = &pkts[pi];
                                    }}
                                }}
                                if (last_pkt != NULL) {{
                                    {cty} tmp = col[row];
                                    if (strata_net_decode_{ident}(last_pkt, &tmp) && memcmp(&tmp, &col[row], sizeof(tmp)) != 0) {{
                                        col[row] = tmp;
                                        if (state->api->iter_mark_changed_range != NULL) {{
                                            (void)state->api->iter_mark_changed_range(q_it, 0u, row, 1u);
                                        }}
                                    }}
                                }}
                            }}
                        }}"
                        );
                    }
                    let _ = writeln!(
                        self.out,
                        "\
                    }}
                }}
            }}
        }}"
                    );
                }
            }
            let _ = writeln!(
                self.out,
                "    }} while (got == {STRATA_NET_RX_BATCH_CAP}u);\n    return BAM_RESULT_OK;\n}}\n"
            );

            // TX system
            let _ = writeln!(
                self.out,
                "\
static BAM_UNUSED BamResult strata_sys_net_tx_{chunk_idx}(BamSystemCtx* sys_ctx, void* user_data) {{
    StrataModState* state = (StrataModState*)user_data;
    if (sys_ctx == NULL || state == NULL || state->api == NULL || state->net_pkt_is_msg == 0u) {{
        return BAM_RESULT_OK;
    }}
    if (state->api->sys_query == NULL || state->api->msg_write_batch == NULL) {{
        return BAM_RESULT_OK;
    }}
    BamIter* msg_it = NULL;
    if (state->api->sys_query(sys_ctx, 0u, &msg_it) != BAM_RESULT_OK || msg_it == NULL) {{
        return BAM_RESULT_OK;
    }}
    StrataNetPacket out_pkts[64];
    size_t out_n = 0u;"
            );
            let mut tx_q_idx = 1u32;
            for nc in chunk {
                let Some(c_idx) = self.find_comp_idx(&nc.canonical_name) else {
                    continue;
                };
                let Some(l_idx) = self.components[c_idx].layout_idx else {
                    continue;
                };
                let cty = self.layout_c_names[l_idx].clone();
                let is_zst = self.layouts[l_idx].size == 0;
                let ident = sanitize_ident(&nc.name);
                if nc.is_resource {
                    let src_arg = if is_zst { "NULL" } else { "rptr" };
                    let _ = writeln!(
                        self.out,
                        "\
    if (state->res_flags[{c_idx}] == 1u && state->api->sys_res_ptr != NULL) {{
        BamChangeTicks ticks;
        memset(&ticks, 0, sizeof(ticks));
        const {cty}* rptr = (const {cty}*)state->api->sys_res_ptr(sys_ctx, state->components[{c_idx}], &ticks);
        if (rptr != NULL && bam_ticks_is_changed(&ticks)) {{
            strata_net_encode_{ident}({src_arg}, 0ull, ticks.this_run, 0u, &out_pkts[out_n++]);
            if (out_n == 64u) {{
                (void)state->api->msg_write_batch(msg_it, 0u, (const uint8_t*)out_pkts, out_n);
                out_n = 0u;
            }}
        }}
    }}"
                    );
                } else {
                    let qi = tx_q_idx;
                    tx_q_idx += 1;
                    let is_sparse = (self.layouts[l_idx].component_flags
                        & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET)
                        != 0;
                    let _ = writeln!(
                        self.out,
                        "\
    if (state->api->iter_next_chunk != NULL && state->api->iter_entities != NULL) {{
        BamIter* q_it = NULL;
        if (state->api->sys_query(sys_ctx, {qi}u, &q_it) == BAM_RESULT_OK && q_it != NULL) {{
            if (state->api->iter_reset != NULL) {{ (void)state->api->iter_reset(q_it); }}
            size_t clen = 0u;
            while (state->api->iter_next_chunk(q_it, &clen) != BAM_FALSE && clen > 0u) {{
                const BamEntity* ents = state->api->iter_entities(q_it);"
                    );
                    if is_zst {
                        let _ = writeln!(
                            self.out,
                            "\
                if (ents != NULL) {{
                    size_t row;
                    for (row = 0u; row < clen; ++row) {{
                        strata_net_encode_{ident}(NULL, (uint64_t)ents[row], 0u, 0u, &out_pkts[out_n++]);
                        if (out_n == 64u) {{
                            (void)state->api->msg_write_batch(msg_it, 0u, (const uint8_t*)out_pkts, out_n);
                            out_n = 0u;
                        }}
                    }}
                }}"
                        );
                    } else if is_sparse {
                        let _ = writeln!(
                            self.out,
                            "\
                const {cty}* const* rows = (state->api->iter_column_rows_readonly != NULL) ? (const {cty}* const*)state->api->iter_column_rows_readonly(q_it, 0u) : NULL;
                if (ents != NULL && rows != NULL) {{
                    size_t row;
                    for (row = 0u; row < clen; ++row) {{
                        if (rows[row] != NULL) {{
                            strata_net_encode_{ident}(rows[row], (uint64_t)ents[row], 0u, 0u, &out_pkts[out_n++]);
                            if (out_n == 64u) {{
                                (void)state->api->msg_write_batch(msg_it, 0u, (const uint8_t*)out_pkts, out_n);
                                out_n = 0u;
                            }}
                        }}
                    }}
                }}"
                        );
                    } else {
                        let _ = writeln!(
                            self.out,
                            "\
                const {cty}* col = (state->api->iter_column_readonly != NULL) ? (const {cty}*)state->api->iter_column_readonly(q_it, 0u) : NULL;
                if (ents != NULL && col != NULL) {{
                    size_t row;
                    for (row = 0u; row < clen; ++row) {{
                        strata_net_encode_{ident}(&col[row], (uint64_t)ents[row], 0u, 0u, &out_pkts[out_n++]);
                        if (out_n == 64u) {{
                            (void)state->api->msg_write_batch(msg_it, 0u, (const uint8_t*)out_pkts, out_n);
                            out_n = 0u;
                        }}
                    }}
                }}"
                        );
                    }
                    let _ = writeln!(
                        self.out,
                        "\
            }}
        }}
    }}"
                    );
                }
            }
            let _ = writeln!(
                self.out,
                "    if (out_n > 0u) {{\n        (void)state->api->msg_write_batch(msg_it, 0u, (const uint8_t*)out_pkts, out_n);\n    }}\n    return BAM_RESULT_OK;\n}}\n"
            );
        }
    }

    pub(super) fn emit_net_init_checks(&mut self) {
        let ncs = self.mir.net_components.clone();
        if !ncs.is_empty() {
            let _ = writeln!(
                self.out,
                "    if (state->host_ctx != NULL && api->component_layout_info != NULL) {{"
            );
            for nc in &ncs {
                if let Some(c_idx) = self.find_comp_idx(&nc.canonical_name) {
                    let fp = nc.schema_fingerprint;
                    let _ = writeln!(
                        self.out,
                        "\
        {{
            BamLayoutInfo net_linfo;
            memset(&net_linfo, 0, sizeof(net_linfo));
            net_linfo.struct_size = (uint32_t)sizeof(BamLayoutInfo);
            if (api->component_layout_info(state->host_ctx, state->components[{c_idx}], &net_linfo) == BAM_RESULT_OK) {{
                if (net_linfo.schema_fingerprint != 0x{fp:016X}ull) {{
                    free(state);
                    *instance_out = NULL;
                    return BAM_RESULT_TYPE_MISMATCH;
                }}
            }}
        }}"
                    );
                }
            }
            let _ = writeln!(self.out, "    }}");
        }
        let pkt_name = c_escape(STRATA_NET_PACKET_CANONICAL_NAME);
        let _ = writeln!(
            self.out,
            "\
    if (state->host_ctx != NULL && api->resolve_component != NULL) {{
        BamResult np_rc = api->resolve_component(state->host_ctx, \"{pkt_name}\", NULL, &state->net_pkt_comp);
        if (np_rc == BAM_RESULT_OK) {{
            if (api->component_layout_info != NULL) {{
                BamLayoutInfo np_info;
                memset(&np_info, 0, sizeof(np_info));
                np_info.struct_size = (uint32_t)sizeof(BamLayoutInfo);
                if (api->component_layout_info(state->host_ctx, state->net_pkt_comp, &np_info) != BAM_RESULT_OK
                    || (np_info.flags & BAM_STORAGE_FLAG_MESSAGE) == 0u
                    || np_info.size != (uint32_t)sizeof(StrataNetPacket)
                    || np_info.schema_fingerprint != STRATA_NET_PACKET_SCHEMA_FINGERPRINT) {{
                    free(state);
                    *instance_out = NULL;
                    return BAM_RESULT_TYPE_MISMATCH;
                }}
            }}
            state->net_pkt_is_msg = 1u;
            state->net_rx_buf = (StrataNetPacket*)calloc({STRATA_NET_RX_BATCH_CAP}u, sizeof(StrataNetPacket));
            if (state->net_rx_buf == NULL) {{
                free(state);
                *instance_out = NULL;
                return BAM_RESULT_INTERNAL_ERROR;
            }}
        }}
    }}"
        );
    }

    pub(super) fn emit_net_sys_registration(&mut self, is_rx: bool) {
        let rep_comps: Vec<MirNetComponent> = self
            .mir
            .net_components
            .iter()
            .filter(|nc| nc.is_replicated)
            .cloned()
            .collect();
        if rep_comps.is_empty() {
            return;
        }
        let max_per_sys = MAX_QUERIES_PER_SYSTEM.saturating_sub(1).max(1);
        let chunk_count = rep_comps.chunks(max_per_sys).len();
        for (chunk_idx, chunk) in rep_comps.chunks(max_per_sys).enumerate() {
            let sys_name = if is_rx {
                format!("__strata_net_rx_{chunk_idx}")
            } else {
                format!("__strata_net_tx_{chunk_idx}")
            };
            let cb_name = if is_rx {
                format!("strata_sys_net_rx_{chunk_idx}")
            } else {
                format!("strata_sys_net_tx_{chunk_idx}")
            };
            let msg_mode = if is_rx {
                "BAM_ACCESS_MESSAGE_READ"
            } else {
                "BAM_ACCESS_MESSAGE_WRITE"
            };
            let res_mode = if is_rx {
                "BAM_ACCESS_RESOURCE_WRITE"
            } else {
                "BAM_ACCESS_RESOURCE_READ"
            };
            let comp_mode = if is_rx {
                "BAM_ACCESS_WRITE"
            } else {
                "BAM_ACCESS_CHANGED"
            };
            let _ = writeln!(self.out, "    if (state->net_pkt_is_msg != 0u) {{");
            let mut res_indices = Vec::new();
            let mut comp_indices = Vec::new();
            for nc in chunk {
                if let Some(c_idx) = self.find_comp_idx(&nc.canonical_name) {
                    if nc.is_resource {
                        res_indices.push(c_idx);
                    } else {
                        comp_indices.push(c_idx);
                    }
                }
            }
            let q0_n = 1 + res_indices.len();
            let q_total = 1 + comp_indices.len();
            let _ = writeln!(self.out, "        BamTermDesc q0_terms[{q0_n}u];");
            let _ = writeln!(
                self.out,
                "        q0_terms[0] = bam_term_desc(state->net_pkt_comp, {msg_mode}, 0u);"
            );
            let _ = writeln!(self.out, "        uint32_t q0_cnt = 1u;");
            for &r_idx in &res_indices {
                let _ = writeln!(
                    self.out,
                    "        if (state->res_flags[{r_idx}] == 1u) {{ q0_terms[q0_cnt++] = bam_term_desc(state->components[{r_idx}], {res_mode}, 0u); }}"
                );
            }
            for (ei, &c_idx) in comp_indices.iter().enumerate() {
                let qi = ei + 1;
                let _ = writeln!(
                    self.out,
                    "        BamTermDesc qe_terms_{qi}[1] = {{ bam_term_desc(state->components[{c_idx}], {comp_mode}, 0u) }};"
                );
            }
            let _ = writeln!(self.out, "        BamQueryDesc net_qdescs[{q_total}u];");
            let _ = writeln!(
                self.out,
                "        memset(net_qdescs, 0, sizeof(net_qdescs));"
            );
            let _ = writeln!(
                self.out,
                "        net_qdescs[0].struct_size = (uint32_t)sizeof(BamQueryDesc);\n        net_qdescs[0].terms = q0_terms;\n        net_qdescs[0].term_count = q0_cnt;"
            );
            for (ei, _) in comp_indices.iter().enumerate() {
                let qi = ei + 1;
                let _ = writeln!(
                    self.out,
                    "        net_qdescs[{qi}].struct_size = (uint32_t)sizeof(BamQueryDesc);\n        net_qdescs[{qi}].terms = qe_terms_{qi};\n        net_qdescs[{qi}].term_count = 1u;"
                );
            }
            let _ = writeln!(
                self.out,
                "\
        BamSystemDesc nsdesc;
        memset(&nsdesc, 0, sizeof(nsdesc));
        nsdesc.struct_size = (uint32_t)sizeof(BamSystemDesc);
        nsdesc.flags = 0u;
        nsdesc.name = \"{sys_name}\";
        nsdesc.queries = net_qdescs;
        nsdesc.query_count = {q_total}u;
        nsdesc.callback = {cb_name};
        nsdesc.user_data = state;
        nsdesc.schedule = BAM_SCHEDULE_FIXED_UPDATE;"
            );
            let mut ordered_names: Vec<String> = self
                .systems
                .iter()
                .filter(|s| s.schedule == "BAM_SCHEDULE_FIXED_UPDATE")
                .map(|s| format!("\"{}\"", c_escape(&s.reg_name)))
                .collect();
            for other_idx in 0..chunk_count {
                if is_rx {
                    ordered_names.push(format!("\"__strata_net_tx_{other_idx}\""));
                } else {
                    ordered_names.push(format!("\"__strata_net_rx_{other_idx}\""));
                }
            }
            if !ordered_names.is_empty() {
                if is_rx {
                    let _ = writeln!(
                        self.out,
                        "        static const char* const net_rx_bw_{chunk_idx}[{}] = {{ {} }};\n        nsdesc.before_weak = net_rx_bw_{chunk_idx};\n        nsdesc.before_weak_count = {}u;",
                        ordered_names.len(),
                        ordered_names.join(", "),
                        ordered_names.len(),
                    );
                } else {
                    let _ = writeln!(
                        self.out,
                        "        static const char* const net_tx_aw_{chunk_idx}[{}] = {{ {} }};\n        nsdesc.after_weak = net_tx_aw_{chunk_idx};\n        nsdesc.after_weak_count = {}u;",
                        ordered_names.len(),
                        ordered_names.join(", "),
                        ordered_names.len(),
                    );
                }
            }
            let _ = writeln!(
                self.out,
                "\
        BamResult nrc = BAM_RESULT_UNSUPPORTED;
        if (api->register_system_handle != NULL && api->mount_system_in_schedule != NULL) {{
            BamSystem net_sys = 0u;
            nrc = api->register_system_handle(load_ctx, &nsdesc, &net_sys);
            if (nrc == BAM_RESULT_OK) {{
                nrc = api->mount_system_in_schedule(load_ctx, net_sys, BAM_SCHEDULE_FIXED_UPDATE, BAM_SYSTEM_SET_INVALID);
            }}
        }} else if (api->register_system != NULL) {{
            nrc = api->register_system(load_ctx, &nsdesc);
        }}
        if (nrc != BAM_RESULT_OK) {{
            free(state->net_rx_buf);
            free(state);
            *instance_out = NULL;
            return nrc;
        }}
    }}"
            );
        }
    }
}
