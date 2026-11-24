//! Read-only manifest, layout, relation, table, and curve constant builders.

use super::*;

pub(super) fn define_manifest_data(
    module: &mut ObjectModule,
    name_id: DataId,
    ver_id: DataId,
    ptr_ty: Type,
) -> Result<DataId, JitError> {
    let id = module
        .declare_data("STRATA_JIT_MANIFEST", Linkage::Local, false, false)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let mut raw = vec![0u8; structs::MANIFEST_SIZE];
    write_u32_le(
        &mut raw,
        structs::MANIFEST_STRUCT_SIZE,
        structs::MANIFEST_SIZE as u32,
    );
    write_u32_le(&mut raw, structs::MANIFEST_ABI_VERSION, WIRE_ABI_VERSION);

    let mut desc = DataDescription::new();
    desc.define(raw.into_boxed_slice());
    desc.set_align(if ptr_ty == types::I32 { 4 } else { 8 });
    let name_gv = module.declare_data_in_data(name_id, &mut desc);
    desc.write_data_addr(structs::MANIFEST_NAME as u32, name_gv, 0);
    let ver_gv = module.declare_data_in_data(ver_id, &mut desc);
    desc.write_data_addr(structs::MANIFEST_VERSION as u32, ver_gv, 0);

    module
        .define_data(id, &desc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    Ok(id)
}

pub(super) fn define_layout_rodata(
    module: &mut ObjectModule,
    idx: usize,
    layout: &SolvedLayout,
    required_indices: Vec<usize>,
    mir: &MirModule,
    ptr_bytes: usize,
) -> Result<LayoutMetaData, JitError> {
    let ident = sanitize_ident(&layout.canonical_name);
    let name_cstr_id = define_cstring_on(
        module,
        &format!("strata_cname_{idx}_{ident}"),
        &layout.canonical_name,
    )?;

    let fields_data_id = if layout.fields.is_empty() {
        None
    } else {
        let mut fnames = Vec::with_capacity(layout.fields.len());
        let mut ftags = Vec::with_capacity(layout.fields.len());
        for (fi, f) in layout.fields.iter().enumerate() {
            fnames.push(define_cstring_on(
                module,
                &format!("strata_fn_{idx}_{fi}_{ident}"),
                &f.name,
            )?);
            ftags.push(define_cstring_on(
                module,
                &format!("strata_ft_{idx}_{fi}_{ident}"),
                &f.type_tag,
            )?);
        }

        let arr_bytes = layout.fields.len() * structs::FIELD_DESC_SIZE;
        let mut arr = vec![0u8; arr_bytes];
        for (fi, f) in layout.fields.iter().enumerate() {
            let base = fi * structs::FIELD_DESC_SIZE;
            write_u32_le(
                &mut arr,
                base + structs::FIELD_STRUCT_SIZE,
                structs::FIELD_DESC_SIZE as u32,
            );
            write_u32_le(&mut arr, base + structs::FIELD_KIND, f.bam_field_kind);
            write_usize_le(
                &mut arr,
                base + structs::FIELD_NAME + structs::STRVIEW_LEN,
                f.name.len(),
                ptr_bytes,
            );
            write_usize_le(
                &mut arr,
                base + structs::FIELD_TYPE_TAG + structs::STRVIEW_LEN,
                f.type_tag.len(),
                ptr_bytes,
            );
            write_usize_le(&mut arr, base + structs::FIELD_OFFSET, f.offset, ptr_bytes);
            write_usize_le(&mut arr, base + structs::FIELD_SIZE, f.size, ptr_bytes);
            write_usize_le(&mut arr, base + structs::FIELD_ALIGN, f.align, ptr_bytes);
        }

        let f_id = module
            .declare_data(
                &format!("strata_fields_{idx}_{ident}"),
                Linkage::Local,
                false,
                false,
            )
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        let mut f_desc = DataDescription::new();
        f_desc.define(arr.into_boxed_slice());
        f_desc.set_align(8);
        for (fi, (&fn_id, &ft_id)) in fnames.iter().zip(ftags.iter()).enumerate() {
            let base = fi * structs::FIELD_DESC_SIZE;
            let fn_gv = module.declare_data_in_data(fn_id, &mut f_desc);
            f_desc.write_data_addr(
                (base + structs::FIELD_NAME + structs::STRVIEW_PTR) as u32,
                fn_gv,
                0,
            );
            let ft_gv = module.declare_data_in_data(ft_id, &mut f_desc);
            f_desc.write_data_addr(
                (base + structs::FIELD_TYPE_TAG + structs::STRVIEW_PTR) as u32,
                ft_gv,
                0,
            );
        }
        module
            .define_data(f_id, &f_desc)
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        Some(f_id)
    };

    let mut cbytes = vec![0u8; structs::COMPONENT_DESC_SIZE];
    write_u32_le(
        &mut cbytes,
        structs::COMP_STRUCT_SIZE,
        structs::COMPONENT_DESC_SIZE as u32,
    );
    write_u32_le(
        &mut cbytes,
        structs::COMP_FLAGS,
        layout.component_flags & crate::abi_offsets::COMPONENT_KNOWN_FLAGS,
    );
    cbytes[structs::COMP_UUID..structs::COMP_UUID + 16].copy_from_slice(&layout.uuid_bytes);
    write_usize_le(&mut cbytes, structs::COMP_SIZE, layout.size, ptr_bytes);
    write_usize_le(
        &mut cbytes,
        structs::COMP_ALIGN,
        layout.align.max(1),
        ptr_bytes,
    );
    write_u64_le(
        &mut cbytes,
        structs::COMP_SCHEMA_FINGERPRINT,
        layout.schema_fingerprint,
    );
    if !layout.fields.is_empty() {
        write_usize_le(
            &mut cbytes,
            structs::COMP_FIELD_COUNT,
            layout.fields.len(),
            ptr_bytes,
        );
    }

    let comp_desc_id = module
        .declare_data(
            &format!("strata_cdesc_{idx}_{ident}"),
            Linkage::Local,
            false,
            false,
        )
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut cdesc = DataDescription::new();
    cdesc.define(cbytes.into_boxed_slice());
    cdesc.set_align(8);
    let name_gv = module.declare_data_in_data(name_cstr_id, &mut cdesc);
    cdesc.write_data_addr(structs::COMP_NAME as u32, name_gv, 0);
    if let Some(f_id) = fields_data_id {
        let fields_gv = module.declare_data_in_data(f_id, &mut cdesc);
        cdesc.write_data_addr(structs::COMP_FIELDS as u32, fields_gv, 0);
    }
    module
        .define_data(comp_desc_id, &cdesc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let default_blob_id = if layout.size > 0
        && let Some(defaults) = mir.field_defaults.get(&layout.canonical_name).or_else(|| {
            layout
                .canonical_name
                .rsplit("::")
                .next()
                .and_then(|s| mir.field_defaults.get(s))
        }) {
        let mut blob = vec![0u8; layout.size];
        for (fname, cval) in defaults {
            if let Some(sf) = layout.fields.iter().find(|f| f.name == *fname) {
                write_const_val_to_buf(&mut blob, sf, cval, mir);
            }
        }
        let bid = module
            .declare_anonymous_data(false, false)
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        let mut bd = DataDescription::new();
        bd.define(blob.into_boxed_slice());
        bd.set_align(layout.align.max(1) as u64);
        module
            .define_data(bid, &bd)
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        Some(bid)
    } else {
        None
    };

    let is_resource = matches!(
        layout.item_kind,
        SchemaItemKind::Resource | SchemaItemKind::SpatialGrid | SchemaItemKind::SpatialHistory
    );
    let is_stream = layout.item_kind == SchemaItemKind::Stream;

    Ok(LayoutMetaData {
        is_ecs_component: is_ecs_component_kind(layout.item_kind),
        is_resource,
        is_stream,
        size: layout.size,
        align: layout.align.max(1),
        required_indices,
        name_cstr_id,
        comp_desc_id,
        default_blob_id,
        mod_res_offset: 0,
        mod_res_shadow_offset: 0,
    })
}

pub(super) fn mir_const_vals_match(a: &MirConstVal, b: &MirConstVal) -> bool {
    match (a, b) {
        (MirConstVal::Unit, MirConstVal::Unit) => true,
        (MirConstVal::Bool(x), MirConstVal::Bool(y)) => x == y,
        (MirConstVal::Int(x), MirConstVal::Int(y)) => x == y,
        (MirConstVal::Float(x), MirConstVal::Float(y)) => x.to_bits() == y.to_bits(),
        (MirConstVal::Vec2(x), MirConstVal::Vec2(y)) => {
            x[0].to_bits() == y[0].to_bits() && x[1].to_bits() == y[1].to_bits()
        }
        (MirConstVal::Vec3(x), MirConstVal::Vec3(y)) => x
            .iter()
            .zip(y.iter())
            .all(|(u, v)| u.to_bits() == v.to_bits()),
        (MirConstVal::Vec4(x), MirConstVal::Vec4(y)) => x
            .iter()
            .zip(y.iter())
            .all(|(u, v)| u.to_bits() == v.to_bits()),
        (MirConstVal::String(x), MirConstVal::String(y)) => x == y,
        (MirConstVal::Array(xs), MirConstVal::Array(ys)) => {
            xs.len() == ys.len()
                && xs
                    .iter()
                    .zip(ys.iter())
                    .all(|(x, y)| mir_const_vals_match(x, y))
        }
        (
            MirConstVal::Struct {
                name: na,
                fields: fa,
            },
            MirConstVal::Struct {
                name: nb,
                fields: fb,
            },
        ) => {
            na.rsplit("::").next() == nb.rsplit("::").next()
                && fa.len() == fb.len()
                && fa
                    .iter()
                    .zip(fb.iter())
                    .all(|((ka, va), (kb, vb))| ka == kb && mir_const_vals_match(va, vb))
        }
        _ => false,
    }
}

pub(super) fn find_solved_layout<'a>(mir: &'a MirModule, key: &str) -> Option<&'a SolvedLayout> {
    mir.layouts
        .iter()
        .find(|l| l.canonical_name == key)
        .or_else(|| {
            let short = key.rsplit("::").next().unwrap_or(key);
            mir.layouts
                .iter()
                .find(|l| l.canonical_name.rsplit("::").next() == Some(short))
        })
}

pub(super) fn write_const_val_to_buf(
    buf: &mut [u8],
    field: &SolvedField,
    cval: &MirConstVal,
    mir: &MirModule,
) {
    write_const_val_to_buf_at(buf, field.offset, field.size, &field.ty, cval, mir);
}

pub(super) fn write_const_val_to_buf_at(
    buf: &mut [u8],
    off: usize,
    sz: usize,
    ty: &Ty,
    cval: &MirConstVal,
    mir: &MirModule,
) {
    if off.checked_add(sz).is_none_or(|end| end > buf.len()) {
        return;
    }
    match cval {
        MirConstVal::Bool(v) => {
            if sz >= 1 {
                buf[off] = u8::from(*v);
            }
        }
        MirConstVal::Int(v) => match ty {
            Ty::Fix32 => {
                if sz >= 4 {
                    let q = (*v).saturating_mul(65_536) as i32;
                    buf[off..off + 4].copy_from_slice(&q.to_le_bytes());
                }
            }
            Ty::Fix64 => {
                if sz >= 8 {
                    let q = v.wrapping_shl(32);
                    buf[off..off + 8].copy_from_slice(&q.to_le_bytes());
                }
            }
            Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => {
                if sz >= 4 {
                    buf[off..off + 4].copy_from_slice(&(*v as f32).to_le_bytes());
                }
            }
            Ty::F64 => {
                if sz >= 8 {
                    buf[off..off + 8].copy_from_slice(&(*v as f64).to_le_bytes());
                }
            }
            Ty::Bool => {
                if sz >= 1 {
                    buf[off] = u8::from(*v != 0);
                }
            }
            Ty::BitSet(_) => {
                let bytes = (*v as u64).to_le_bytes();
                let n = sz.min(8);
                buf[off..off + n].copy_from_slice(&bytes[..n]);
            }
            _ => match sz {
                1 => buf[off] = *v as u8,
                2 => buf[off..off + 2].copy_from_slice(&(*v as i16).to_le_bytes()),
                4 => buf[off..off + 4].copy_from_slice(&(*v as i32).to_le_bytes()),
                8 => buf[off..off + 8].copy_from_slice(&v.to_le_bytes()),
                _ => {}
            },
        },
        MirConstVal::Float(v) => match ty {
            Ty::F64 => {
                if sz >= 8 {
                    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
                }
            }
            Ty::Fix32 => {
                if sz >= 4 {
                    let q = if v.is_finite() {
                        (*v * 65_536.0).round() as i32
                    } else {
                        0
                    };
                    buf[off..off + 4].copy_from_slice(&q.to_le_bytes());
                }
            }
            Ty::Fix64 => {
                if sz >= 8 {
                    let q = if v.is_finite() {
                        (*v * 4_294_967_296.0).round() as i64
                    } else {
                        0
                    };
                    buf[off..off + 8].copy_from_slice(&q.to_le_bytes());
                }
            }
            _ => {
                if sz >= 4 {
                    buf[off..off + 4].copy_from_slice(&(*v as f32).to_le_bytes());
                }
            }
        },
        MirConstVal::Vec2(v) => match ty {
            Ty::IVec2 => {
                if sz >= 8 {
                    buf[off..off + 4].copy_from_slice(&(v[0] as i32).to_le_bytes());
                    buf[off + 4..off + 8].copy_from_slice(&(v[1] as i32).to_le_bytes());
                }
            }
            Ty::UVec2 => {
                if sz >= 8 {
                    buf[off..off + 4].copy_from_slice(&(v[0] as u32).to_le_bytes());
                    buf[off + 4..off + 8].copy_from_slice(&(v[1] as u32).to_le_bytes());
                }
            }
            _ => {
                if sz >= 8 {
                    buf[off..off + 4].copy_from_slice(&(v[0] as f32).to_le_bytes());
                    buf[off + 4..off + 8].copy_from_slice(&(v[1] as f32).to_le_bytes());
                }
            }
        },
        MirConstVal::Vec3(v) => match ty {
            Ty::IVec3 => {
                if sz >= 12 {
                    buf[off..off + 4].copy_from_slice(&(v[0] as i32).to_le_bytes());
                    buf[off + 4..off + 8].copy_from_slice(&(v[1] as i32).to_le_bytes());
                    buf[off + 8..off + 12].copy_from_slice(&(v[2] as i32).to_le_bytes());
                }
            }
            _ => {
                if sz >= 12 {
                    buf[off..off + 4].copy_from_slice(&(v[0] as f32).to_le_bytes());
                    buf[off + 4..off + 8].copy_from_slice(&(v[1] as f32).to_le_bytes());
                    buf[off + 8..off + 12].copy_from_slice(&(v[2] as f32).to_le_bytes());
                }
            }
        },
        MirConstVal::Vec4(v) => {
            if sz >= 16 {
                for (i, &val) in v.iter().enumerate() {
                    buf[off + i * 4..off + (i + 1) * 4]
                        .copy_from_slice(&(val as f32).to_le_bytes());
                }
            }
        }
        MirConstVal::Array(elems) => match ty {
            Ty::Array { elem, len } => {
                if let Some(elem_stride) = sz.checked_div(*len)
                    && elem_stride > 0
                {
                    for (idx, elem_val) in elems.iter().take(*len).enumerate() {
                        let elem_off = off + idx * elem_stride;
                        write_const_val_to_buf_at(buf, elem_off, elem_stride, elem, elem_val, mir);
                    }
                }
            }
            Ty::BitSet(bits) => {
                let words = (*bits).div_ceil(32).max(1);
                if sz >= words * 4 {
                    let mut mask_words = vec![0u32; words];
                    for item in elems {
                        if let MirConstVal::Int(bit) = item
                            && *bit >= 0
                        {
                            let b = *bit as usize;
                            if b / 32 < words {
                                mask_words[b / 32] |= 1u32 << (b % 32);
                            }
                        }
                    }
                    for (wi, w) in mask_words.iter().enumerate() {
                        buf[off + wi * 4..off + (wi + 1) * 4].copy_from_slice(&w.to_le_bytes());
                    }
                }
            }
            Ty::U8 | Ty::U16 | Ty::U32 | Ty::U64 | Ty::I8 | Ty::I16 | Ty::I32 | Ty::I64 => {
                let mut mask = 0u64;
                for item in elems {
                    if let MirConstVal::Int(bit) = item
                        && *bit >= 0
                        && (*bit as u32) < 64
                    {
                        mask |= 1u64 << (*bit as u32);
                    }
                }
                write_const_val_to_buf_at(buf, off, sz, ty, &MirConstVal::Int(mask as i64), mir);
            }
            _ => {}
        },
        MirConstVal::Struct { name, fields } => {
            if let Ty::Named(tn) = ty
                && let Some(nested) =
                    find_solved_layout(mir, tn).or_else(|| find_solved_layout(mir, name))
            {
                let sub_buf = &mut buf[off..off + sz];
                if let Some(defaults) =
                    mir.field_defaults.get(&nested.canonical_name).or_else(|| {
                        nested
                            .canonical_name
                            .rsplit("::")
                            .next()
                            .and_then(|s| mir.field_defaults.get(s))
                    })
                {
                    for (fname, dval) in defaults {
                        if let Some(sf) = nested.fields.iter().find(|f| f.name == *fname) {
                            write_const_val_to_buf(sub_buf, sf, dval, mir);
                        }
                    }
                }
                for (fname, fval) in fields {
                    if let Some(sf) = nested.fields.iter().find(|f| f.name == *fname) {
                        write_const_val_to_buf(sub_buf, sf, fval, mir);
                    }
                }
            }
        }
        MirConstVal::String(s) => {
            if let Ty::InlineStr(cap) = ty
                && sz >= 4
            {
                let mut end = s.len().min(*cap);
                while end > 0 && !s.is_char_boundary(end) {
                    end -= 1;
                }
                buf[off..off + sz].fill(0);
                buf[off..off + 4].copy_from_slice(&(end as u32).to_le_bytes());
                let copy_len = end.min(sz - 4);
                buf[off + 4..off + 4 + copy_len].copy_from_slice(&s.as_bytes()[..copy_len]);
            }
        }
        MirConstVal::Unit => {}
    }
}

pub(super) fn define_relation_rodata(
    module: &mut ObjectModule,
    idx: usize,
    rel: &HirRelation,
    ptr_bytes: usize,
) -> Result<RelationMetaData, JitError> {
    let ident = sanitize_ident(&rel.canonical_name);
    let name_cstr_id = define_cstring_on(
        module,
        &format!("strata_rel_name_{idx}_{ident}"),
        &rel.canonical_name,
    )?;
    let (data_size, data_align, uuid) = if let Some(ref pl) = rel.payload_layout {
        (pl.size, pl.align.max(1), pl.uuid_bytes)
    } else {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in rel.canonical_name.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        let mut u = [0u8; 16];
        u[0..8].copy_from_slice(&h.to_le_bytes());
        u[8..16].copy_from_slice(&(!h).to_le_bytes());
        (0, 1, u)
    };

    let mut flags = 0u32;
    for f in &rel.flags {
        match f.as_str() {
            "exclusive" => flags |= RELATION_FLAG_EXCLUSIVE,
            "cascade_despawn" | "cascade_delete" => flags |= RELATION_FLAG_CASCADE_DESPAWN,
            "symmetric" => flags |= RELATION_FLAG_SYMMETRIC,
            "acyclic" => flags |= RELATION_FLAG_ACYCLIC,
            "cleanup_remove" => flags |= RELATION_FLAG_CLEANUP_REMOVE,
            _ => {}
        }
    }

    let mut bytes = vec![0u8; structs::RELATION_DESC_SIZE];
    write_u32_le(
        &mut bytes,
        structs::REL_STRUCT_SIZE,
        structs::RELATION_DESC_SIZE as u32,
    );
    write_u32_le(&mut bytes, structs::REL_FLAGS, flags);
    bytes[structs::REL_UUID..structs::REL_UUID + 16].copy_from_slice(&uuid);
    write_usize_le(&mut bytes, structs::REL_DATA_SIZE, data_size, ptr_bytes);
    write_usize_le(&mut bytes, structs::REL_DATA_ALIGN, data_align, ptr_bytes);
    write_u32_le(&mut bytes, structs::REL_MAX_DEGREE, 0);

    let desc_id = module
        .declare_data(
            &format!("strata_rel_desc_{idx}_{ident}"),
            Linkage::Local,
            false,
            false,
        )
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut rdesc = DataDescription::new();
    rdesc.define(bytes.into_boxed_slice());
    rdesc.set_align(8);
    let ngv = module.declare_data_in_data(name_cstr_id, &mut rdesc);
    rdesc.write_data_addr(structs::REL_NAME as u32, ngv, 0);
    module
        .define_data(desc_id, &rdesc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    Ok(RelationMetaData {
        payload_size: data_size,
        desc_id,
    })
}

pub(super) fn eval_const_hir_expr(
    expr: &HirExpr,
    enums: &HashMap<String, EnumDef>,
    consts: &HashMap<String, HirConst>,
) -> Option<MirConstVal> {
    let as_f64 = |v: &MirConstVal| -> Option<f64> {
        match v {
            MirConstVal::Float(f) => Some(*f),
            MirConstVal::Int(i) => Some(*i as f64),
            _ => None,
        }
    };
    let as_i32_f64 = |v: &MirConstVal| -> Option<f64> {
        match v {
            MirConstVal::Int(i) => Some(f64::from(*i as i32)),
            MirConstVal::Float(f) => Some(f64::from(*f as i32)),
            _ => None,
        }
    };
    let as_u32_f64 = |v: &MirConstVal| -> Option<f64> {
        match v {
            MirConstVal::Int(i) => Some(f64::from(*i as u32)),
            MirConstVal::Float(f) => Some(f64::from(*f as u32)),
            _ => None,
        }
    };

    match expr {
        HirExpr::BoolLit(b) => Some(MirConstVal::Bool(*b)),
        HirExpr::IntLit { value, .. } => Some(MirConstVal::Int(*value)),
        HirExpr::FloatLit { value, .. } => Some(MirConstVal::Float(*value)),
        HirExpr::StringLit(s) => Some(MirConstVal::String(s.clone())),
        HirExpr::Tuple { elems, .. } if elems.is_empty() => Some(MirConstVal::Unit),
        HirExpr::Path { name, .. } => {
            if let Some(c) = consts
                .get(name)
                .or_else(|| name.rsplit("::").next().and_then(|s| consts.get(s)))
                && let Some(ref c_expr) = c.expr
            {
                return eval_const_hir_expr(c_expr, enums, consts);
            }
            match name.as_str() {
                "vec2::ZERO" | "ivec2::ZERO" | "uvec2::ZERO" => {
                    return Some(MirConstVal::Vec2([0.0, 0.0]));
                }
                "vec2::ONE" | "ivec2::ONE" | "uvec2::ONE" => {
                    return Some(MirConstVal::Vec2([1.0, 1.0]));
                }
                "vec2::X" | "ivec2::X" | "uvec2::X" => {
                    return Some(MirConstVal::Vec2([1.0, 0.0]));
                }
                "vec2::Y" | "ivec2::Y" | "uvec2::Y" => {
                    return Some(MirConstVal::Vec2([0.0, 1.0]));
                }
                "vec3::ZERO" | "ivec3::ZERO" => return Some(MirConstVal::Vec3([0.0, 0.0, 0.0])),
                "vec3::ONE" | "ivec3::ONE" => return Some(MirConstVal::Vec3([1.0, 1.0, 1.0])),
                "vec3::X" | "ivec3::X" => return Some(MirConstVal::Vec3([1.0, 0.0, 0.0])),
                "vec3::UP" | "vec3::Y" | "ivec3::Y" => {
                    return Some(MirConstVal::Vec3([0.0, 1.0, 0.0]));
                }
                "vec3::Z" | "ivec3::Z" => return Some(MirConstVal::Vec3([0.0, 0.0, 1.0])),
                "vec4::ZERO" => return Some(MirConstVal::Vec4([0.0, 0.0, 0.0, 0.0])),
                "vec4::ONE" => return Some(MirConstVal::Vec4([1.0, 1.0, 1.0, 1.0])),
                "vec4::X" => return Some(MirConstVal::Vec4([1.0, 0.0, 0.0, 0.0])),
                "vec4::Y" => return Some(MirConstVal::Vec4([0.0, 1.0, 0.0, 0.0])),
                "vec4::Z" => return Some(MirConstVal::Vec4([0.0, 0.0, 1.0, 0.0])),
                "vec4::W" => return Some(MirConstVal::Vec4([0.0, 0.0, 0.0, 1.0])),
                _ => {}
            }
            if let Some((enum_n, var_n)) = name.rsplit_once("::")
                && let Some(ed) = enums.get(enum_n)
                && let Some((_, d)) = ed.variants.iter().find(|(v, _)| v == var_n)
            {
                return Some(MirConstVal::Int(*d));
            }
            None
        }
        HirExpr::Unary {
            op, expr: inner, ..
        } => match (op, eval_const_hir_expr(inner, enums, consts)?) {
            (HirUnOp::Neg, MirConstVal::Int(i)) => Some(MirConstVal::Int(i.wrapping_neg())),
            (HirUnOp::Neg, MirConstVal::Float(f)) => Some(MirConstVal::Float(-f)),
            (HirUnOp::Neg, MirConstVal::Vec2([x, y])) => Some(MirConstVal::Vec2([-x, -y])),
            (HirUnOp::Neg, MirConstVal::Vec3([x, y, z])) => Some(MirConstVal::Vec3([-x, -y, -z])),
            (HirUnOp::Neg, MirConstVal::Vec4([x, y, z, w])) => {
                Some(MirConstVal::Vec4([-x, -y, -z, -w]))
            }
            (HirUnOp::Not, MirConstVal::Bool(b)) => Some(MirConstVal::Bool(!b)),
            (HirUnOp::Not, MirConstVal::Int(i)) => Some(MirConstVal::Int(!i)),
            _ => None,
        },
        HirExpr::Binary { op, lhs, rhs, .. } => {
            let l = eval_const_hir_expr(lhs, enums, consts)?;
            let r = eval_const_hir_expr(rhs, enums, consts)?;
            match (l, r) {
                (MirConstVal::Int(a), MirConstVal::Int(b)) => match op {
                    HirBinOp::Add => Some(MirConstVal::Int(a.wrapping_add(b))),
                    HirBinOp::Sub => Some(MirConstVal::Int(a.wrapping_sub(b))),
                    HirBinOp::Mul => Some(MirConstVal::Int(a.wrapping_mul(b))),
                    HirBinOp::Div if b != 0 && !(a == i64::MIN && b == -1) => {
                        Some(MirConstVal::Int(a.wrapping_div(b)))
                    }
                    HirBinOp::BitAnd => Some(MirConstVal::Int(a & b)),
                    HirBinOp::BitOr => Some(MirConstVal::Int(a | b)),
                    HirBinOp::Shl => Some(MirConstVal::Int(a.wrapping_shl(b as u32))),
                    _ => None,
                },
                (a, b) => {
                    let fa = as_f64(&a)?;
                    let fb = as_f64(&b)?;
                    match op {
                        HirBinOp::Add => Some(MirConstVal::Float(fa + fb)),
                        HirBinOp::Sub => Some(MirConstVal::Float(fa - fb)),
                        HirBinOp::Mul => Some(MirConstVal::Float(fa * fb)),
                        HirBinOp::Div => Some(MirConstVal::Float(fa / fb)),
                        HirBinOp::Rem => Some(MirConstVal::Float(fa % fb)),
                        _ => None,
                    }
                }
            }
        }
        HirExpr::Cast {
            expr: inner,
            target_ty,
        } => {
            let v = eval_const_hir_expr(inner, enums, consts)?;
            let src_fix = match inner.ty() {
                Ty::Fix32 => Some(false),
                Ty::Fix64 => Some(true),
                _ => match inner.as_ref() {
                    HirExpr::Cast {
                        target_ty: Ty::Fix32,
                        ..
                    } => Some(false),
                    HirExpr::Cast {
                        target_ty: Ty::Fix64,
                        ..
                    } => Some(true),
                    _ => None,
                },
            };
            if let Some(is_fix64) = src_fix
                && matches!(
                    target_ty,
                    Ty::I8
                        | Ty::I16
                        | Ty::I32
                        | Ty::I64
                        | Ty::U8
                        | Ty::U16
                        | Ty::U32
                        | Ty::U64
                        | Ty::Sym
                        | Ty::Rgba8
                )
            {
                let trunc: i64 = if is_fix64 {
                    let q = match v {
                        MirConstVal::Int(i) => i.wrapping_shl(32),
                        MirConstVal::Float(f) if f.is_finite() => {
                            (f * 4_294_967_296.0).round() as i64
                        }
                        MirConstVal::Float(_) => 0,
                        MirConstVal::Bool(b) => {
                            if b {
                                1i64 << 32
                            } else {
                                0
                            }
                        }
                        _ => return None,
                    };
                    q / 4_294_967_296
                } else {
                    let q = match v {
                        MirConstVal::Int(i) => i.saturating_mul(65_536) as i32,
                        MirConstVal::Float(f) if f.is_finite() => (f * 65_536.0).round() as i32,
                        MirConstVal::Float(_) => 0,
                        MirConstVal::Bool(b) => {
                            if b {
                                65_536
                            } else {
                                0
                            }
                        }
                        _ => return None,
                    };
                    i64::from(q / 65_536)
                };
                return match target_ty {
                    Ty::I8 => Some(MirConstVal::Int(i64::from(trunc as i8))),
                    Ty::I16 => Some(MirConstVal::Int(i64::from(trunc as i16))),
                    Ty::I32 => Some(MirConstVal::Int(i64::from(trunc as i32))),
                    Ty::I64 | Ty::U64 => Some(MirConstVal::Int(trunc)),
                    Ty::U8 => Some(MirConstVal::Int(i64::from(trunc as u8))),
                    Ty::U16 => Some(MirConstVal::Int(i64::from(trunc as u16))),
                    Ty::U32 | Ty::Sym | Ty::Rgba8 => {
                        Some(MirConstVal::Int(i64::from(trunc as u32)))
                    }
                    _ => None,
                };
            }
            match (v, target_ty) {
                (MirConstVal::Int(i), Ty::F32) => Some(MirConstVal::Float((i as f32) as f64)),
                (MirConstVal::Int(i), Ty::F64 | Ty::UnitScalar { .. }) => {
                    Some(MirConstVal::Float(i as f64))
                }
                (MirConstVal::Float(f), Ty::Fix32) => {
                    if f.is_finite() {
                        let q = (f * 65_536.0).round() as i32;
                        Some(MirConstVal::Float(f64::from(q) / 65_536.0))
                    } else {
                        Some(MirConstVal::Int(0))
                    }
                }
                (MirConstVal::Float(f), Ty::Fix64) => {
                    if f.is_finite() {
                        let q = (f * 4_294_967_296.0).round() as i64;
                        Some(MirConstVal::Float((q as f64) / 4_294_967_296.0))
                    } else {
                        Some(MirConstVal::Int(0))
                    }
                }
                (MirConstVal::Int(i), Ty::Fix32 | Ty::Fix64) => Some(MirConstVal::Int(i)),
                (MirConstVal::Bool(b), Ty::Fix32 | Ty::Fix64) => {
                    Some(MirConstVal::Int(i64::from(b)))
                }
                (MirConstVal::Float(f), Ty::F32) => Some(MirConstVal::Float((f as f32) as f64)),
                (MirConstVal::Float(f), Ty::I8) => Some(MirConstVal::Int(i64::from(f as i8))),
                (MirConstVal::Float(f), Ty::I16) => Some(MirConstVal::Int(i64::from(f as i16))),
                (MirConstVal::Float(f), Ty::I32) => Some(MirConstVal::Int(i64::from(f as i32))),
                (MirConstVal::Float(f), Ty::I64) => Some(MirConstVal::Int(f as i64)),
                (MirConstVal::Float(f), Ty::U8) => Some(MirConstVal::Int(i64::from(f as u8))),
                (MirConstVal::Float(f), Ty::U16) => Some(MirConstVal::Int(i64::from(f as u16))),
                (MirConstVal::Float(f), Ty::U32 | Ty::Sym | Ty::Rgba8) => {
                    Some(MirConstVal::Int(i64::from(f as u32)))
                }
                (MirConstVal::Float(f), Ty::U64) => Some(MirConstVal::Int((f as u64) as i64)),
                (MirConstVal::Int(i), Ty::I8) => Some(MirConstVal::Int(i64::from(i as i8))),
                (MirConstVal::Int(i), Ty::I16) => Some(MirConstVal::Int(i64::from(i as i16))),
                (MirConstVal::Int(i), Ty::I32) => Some(MirConstVal::Int(i64::from(i as i32))),
                (MirConstVal::Int(i), Ty::U8) => Some(MirConstVal::Int(i64::from(i as u8))),
                (MirConstVal::Int(i), Ty::U16) => Some(MirConstVal::Int(i64::from(i as u16))),
                (MirConstVal::Int(i), Ty::U32 | Ty::Sym | Ty::Rgba8) => {
                    Some(MirConstVal::Int(i64::from(i as u32)))
                }
                (other, _) => Some(other),
            }
        }
        HirExpr::Call(HirCall {
            callee, args, ty, ..
        }) => {
            let mut evaluated = Vec::with_capacity(args.len());
            for a in args {
                evaluated.push(eval_const_hir_expr(a, enums, consts)?);
            }
            match callee.rsplit("::").next().unwrap_or(callee) {
                "vec2" | "Vec2" if evaluated.len() == 2 => Some(MirConstVal::Vec2([
                    as_f64(&evaluated[0])?,
                    as_f64(&evaluated[1])?,
                ])),
                "ivec2" | "IVec2" if evaluated.len() == 2 => Some(MirConstVal::Vec2([
                    as_i32_f64(&evaluated[0])?,
                    as_i32_f64(&evaluated[1])?,
                ])),
                "uvec2" | "UVec2" if evaluated.len() == 2 => Some(MirConstVal::Vec2([
                    as_u32_f64(&evaluated[0])?,
                    as_u32_f64(&evaluated[1])?,
                ])),
                "vec3" | "Vec3" if evaluated.len() == 3 => Some(MirConstVal::Vec3([
                    as_f64(&evaluated[0])?,
                    as_f64(&evaluated[1])?,
                    as_f64(&evaluated[2])?,
                ])),
                "vec3a" | "Vec3a" if evaluated.len() == 3 => Some(MirConstVal::Vec4([
                    as_f64(&evaluated[0])?,
                    as_f64(&evaluated[1])?,
                    as_f64(&evaluated[2])?,
                    0.0,
                ])),
                "ivec3" | "IVec3" if evaluated.len() == 3 => Some(MirConstVal::Vec3([
                    as_i32_f64(&evaluated[0])?,
                    as_i32_f64(&evaluated[1])?,
                    as_i32_f64(&evaluated[2])?,
                ])),
                "vec4" | "Vec4" | "quat" | "Quat" | "rgba" | "Rgba" if evaluated.len() == 4 => {
                    Some(MirConstVal::Vec4([
                        as_f64(&evaluated[0])?,
                        as_f64(&evaluated[1])?,
                        as_f64(&evaluated[2])?,
                        as_f64(&evaluated[3])?,
                    ]))
                }
                "ivec4" if evaluated.len() == 4 => Some(MirConstVal::Vec4([
                    as_i32_f64(&evaluated[0])?,
                    as_i32_f64(&evaluated[1])?,
                    as_i32_f64(&evaluated[2])?,
                    as_i32_f64(&evaluated[3])?,
                ])),
                "uvec4" if evaluated.len() == 4 => Some(MirConstVal::Vec4([
                    as_u32_f64(&evaluated[0])?,
                    as_u32_f64(&evaluated[1])?,
                    as_u32_f64(&evaluated[2])?,
                    as_u32_f64(&evaluated[3])?,
                ])),
                "bits" => {
                    if matches!(ty, Ty::BitSet(_)) {
                        Some(MirConstVal::Array(evaluated))
                    } else {
                        let mut mask = 0u64;
                        for v in &evaluated {
                            if let MirConstVal::Int(b) = v
                                && *b >= 0
                                && (*b as u32) < 64
                            {
                                mask |= 1u64 << (*b as u32);
                            }
                        }
                        Some(MirConstVal::Int(mask as i64))
                    }
                }
                "meters" | "sec" | "ms" | "rad" | "deg" | "mps" | "mps2" | "hz" | "frames"
                    if evaluated.len() == 1 =>
                {
                    Some(evaluated.into_iter().next().unwrap_or(MirConstVal::Unit))
                }
                _ => None,
            }
        }
        HirExpr::ArrayLit { elems, .. } => {
            let mut out = Vec::with_capacity(elems.len());
            for el in elems {
                out.push(eval_const_hir_expr(el, enums, consts)?);
            }
            Some(MirConstVal::Array(out))
        }
        HirExpr::StructLit { name, fields, .. } => {
            let mut out = Vec::with_capacity(fields.len());
            for (fname, fexpr) in fields {
                out.push((fname.clone(), eval_const_hir_expr(fexpr, enums, consts)?));
            }
            Some(MirConstVal::Struct {
                name: name.clone(),
                fields: out,
            })
        }
        _ => None,
    }
}

pub(super) fn define_table_rodata(
    module: &mut ObjectModule,
    idx: usize,
    table: &HirTable,
    enums: &HashMap<String, EnumDef>,
    consts: &HashMap<String, HirConst>,
    mir: &MirModule,
    ptr_bytes: usize,
) -> Result<TableRodata, JitError> {
    let mut fields = HashMap::new();
    let mut cursor = 0usize;
    let mut ordered_fields = Vec::with_capacity(table.fields.len());
    for (fname, fty) in &table.fields {
        let mty = mir_type_from_ty(fty);
        let (sz, al) = match mty {
            MirType::Bool | MirType::U8 | MirType::I8 => (1, 1),
            MirType::U16 | MirType::I16 => (2, 2),
            MirType::U32 | MirType::I32 | MirType::F32 | MirType::Sym | MirType::Fix32 => (4, 4),
            MirType::U64 | MirType::I64 | MirType::F64 | MirType::Fix64 | MirType::Entity => (8, 8),
            MirType::Vec2 | MirType::IVec2 | MirType::UVec2 => (8, 4),
            MirType::Vec3 | MirType::IVec3 => (12, 4),
            MirType::Vec4 => (16, 4),
            _ => (ptr_bytes.max(8), 8),
        };
        cursor = align_up(cursor, al);
        fields.insert(fname.clone(), (cursor, mty.clone()));
        ordered_fields.push((fname.clone(), cursor, sz, fty.clone()));
        cursor += sz;
    }
    let row_stride = align_up(cursor.max(8), 8);
    let enum_def = enums.get(&table.key_enum);
    let mut max_idx = table.typed_rows.len().max(table.rows.len());
    if let Some(ed) = enum_def {
        for (_, d) in &ed.variants {
            if *d >= 0 {
                max_idx = max_idx.max(*d as usize + 1);
            }
        }
    }
    let row_count = max_idx.max(1);
    let mut bytes = vec![0u8; row_count * row_stride];

    for (ri, (vname, fexprs)) in table.typed_rows.iter().enumerate() {
        let row_idx = enum_def
            .and_then(|ed| {
                ed.variants
                    .iter()
                    .find(|(v, _)| v == vname)
                    .map(|(_, d)| *d as usize)
            })
            .unwrap_or(ri);
        if row_idx >= row_count {
            continue;
        }
        let base = row_idx * row_stride;
        for (fname, fexpr) in fexprs {
            if let Some((_, off, sz, fty)) = ordered_fields.iter().find(|(n, _, _, _)| n == fname)
                && let Some(cval) = eval_const_hir_expr(fexpr, enums, consts)
            {
                let sf = SolvedField {
                    name: fname.clone(),
                    ty: fty.clone(),
                    offset: *off,
                    size: *sz,
                    align: 4,
                    is_padding: false,
                    bam_field_kind: 0,
                    type_tag: String::new(),
                };
                write_const_val_to_buf(&mut bytes[base..base + row_stride], &sf, &cval, mir);
            }
        }
    }

    let data_id = module
        .declare_data(
            &format!("strata_tbl_{idx}_{}", sanitize_ident(&table.name)),
            Linkage::Local,
            false,
            false,
        )
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut desc = DataDescription::new();
    desc.define(bytes.into_boxed_slice());
    desc.set_align(8);
    module
        .define_data(data_id, &desc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    Ok(TableRodata {
        data_id,
        row_count,
        row_stride,
        fields,
    })
}

pub(super) fn define_curve_rodata(
    module: &mut ObjectModule,
    idx: usize,
    curve: &HirCurve,
) -> Result<CurveRodata, JitError> {
    let mut pts = curve.points.clone();
    pts.sort_by(|a, b| a.0.total_cmp(&b.0));
    let mut bytes = Vec::with_capacity(pts.len().max(1) * 8);
    if pts.is_empty() {
        bytes.extend_from_slice(&0.0f32.to_le_bytes());
        bytes.extend_from_slice(&0.0f32.to_le_bytes());
    } else {
        for (x, y) in &pts {
            bytes.extend_from_slice(&(*x as f32).to_le_bytes());
            bytes.extend_from_slice(&(*y as f32).to_le_bytes());
        }
    }
    let data_id = module
        .declare_data(
            &format!("strata_crv_{idx}_{}", sanitize_ident(&curve.name)),
            Linkage::Local,
            false,
            false,
        )
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut desc = DataDescription::new();
    desc.define(bytes.into_boxed_slice());
    desc.set_align(4);
    module
        .define_data(data_id, &desc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    Ok(CurveRodata {
        data_id,
        points_len: pts.len(),
    })
}
