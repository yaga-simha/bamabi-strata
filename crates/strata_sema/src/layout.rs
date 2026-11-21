//! `AbiPod` explicit-padding layout solver, `@soa` stratum splitting, and bit-exact
//! `bamabi_sys::ComponentUuid` / FNV-1a `SCHEMA_FINGERPRINT` verification.

use crate::types::Ty;
use bamabi_sys::{
    BAM_COMPONENT_FLAG_SPARSE_SET, BAM_COMPONENT_FLAG_SUMMARY_TICK, BamFieldKind, ComponentUuid,
    fnv1a_64_init, fnv1a_64_update_bytes, fnv1a_64_update_u64,
};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Kind of schema item whose C-ABI layout was solved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum SchemaItemKind {
    Struct,
    Enum,
    Component,
    SoaHot,
    SoaCold,
    Resource,
    Event,
    Stream,
    Relation,
    Timeline,
    TaskState,
    FsmState,
    SpatialGrid,
    SpatialHistory,
}

/// A single solved field (including any compiler-inserted `_strata_pad_N` field).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SolvedField {
    /// Field identifier (or `_strata_pad_N` for zero-initialized explicit padding).
    pub name: String,
    /// Strata semantic type.
    pub ty: Ty,
    /// Byte offset inside the `#[repr(C)]` struct.
    pub offset: usize,
    /// Byte size of this field.
    pub size: usize,
    /// Byte alignment of this field.
    pub align: usize,
    /// `true` iff this field is compiler-synthesized explicit padding (`[u8; K]`).
    pub is_padding: bool,
    /// Numeric `bamabi_sys::BamFieldKind` wire discriminator.
    pub bam_field_kind: u32,
    /// Canonical type tag used in `hash_field_schema` and `SCHEMA_FINGERPRINT`.
    pub type_tag: String,
}

/// Solved `#[repr(C)]` layout, explicit padding, and deterministic wire identity for one ABI item.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SolvedLayout {
    /// Canonical namespaced name (e.g. `"genres::soulslike::CombatantBody"`).
    pub canonical_name: String,
    /// Item classification.
    pub item_kind: SchemaItemKind,
    /// Ordered `#[repr(C)]` fields including synthesized `_strata_pad_N` fields.
    pub fields: Vec<SolvedField>,
    /// Total struct byte size (`size == fields.iter().map(|f| f.size).sum()`).
    pub size: usize,
    /// Total struct byte alignment.
    pub align: usize,
    /// `true` iff zero implicit padding and all fields satisfy `AbiPod`.
    pub is_abi_pod: bool,
    /// `BAM_COMPONENT_FLAG_*` bitflags (`SPARSE_SET | SUMMARY_TICK`).
    pub component_flags: u32,
    /// Deterministic 128-bit SipHash-2-4-128 component UUID matching `bamabi_sys::ComponentUuid`.
    pub uuid_bytes: [u8; 16],
    /// Hyphenated canonical UUID representation (`8-4-4-4-12`).
    pub uuid_hex: String,
    /// Deterministic 64-bit FNV-1a schema fingerprint matching `ModComponent::SCHEMA_FINGERPRINT`.
    pub schema_fingerprint: u64,
    /// Required companion component canonical names (`@require(...)` + `@soa` hot-stratum link).
    pub required_components: Vec<String>,
    /// Number of explicit `_strata_pad_*` bytes inserted by the solver.
    pub explicit_pad_bytes: usize,
}

/// Enum metadata needed for size/align lookup and enum `ComponentUuid` / `SCHEMA_FINGERPRINT`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnumDef {
    /// Enum canonical name.
    pub canonical_name: String,
    /// Ordered variants with explicit or sequential discriminants.
    pub variants: Vec<(String, i64)>,
    /// Discriminant integer width (`u8` / `u16` / `u32`).
    pub repr_bytes: usize,
}

/// Known user-defined type layouts available while solving field types.
#[derive(Debug, Clone, Default)]
pub struct LayoutEnv {
    /// Resolved struct/enum/component layouts keyed by short or canonical name.
    pub resolved: IndexMap<String, (usize, usize, bool, u32, String)>,
    /// Declared enums keyed by short name.
    pub enums: IndexMap<String, EnumDef>,
}

/// Resolves `(size, align, is_abi_pod, BamFieldKind, canonical_tag)` for a Strata [`Ty`].
pub fn resolve_ty_layout(
    ty: &Ty,
    env: &LayoutEnv,
) -> Option<(usize, usize, bool, BamFieldKind, String)> {
    let res = match ty {
        Ty::U8 => (1, 1, true, BamFieldKind::U8, ty.canonical_tag()),
        Ty::I8 => (1, 1, true, BamFieldKind::I8, ty.canonical_tag()),
        Ty::Bool => (1, 1, true, BamFieldKind::BOOL, ty.canonical_tag()),
        Ty::U16 => (2, 2, true, BamFieldKind::U16, ty.canonical_tag()),
        Ty::I16 => (2, 2, true, BamFieldKind::I16, ty.canonical_tag()),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => (4, 4, true, BamFieldKind::U32, ty.canonical_tag()),
        Ty::I32 | Ty::Fix32 => (4, 4, true, BamFieldKind::I32, ty.canonical_tag()),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => {
            (4, 4, true, BamFieldKind::F32, ty.canonical_tag())
        }
        Ty::U64 => (8, 8, true, BamFieldKind::U64, ty.canonical_tag()),
        Ty::I64 | Ty::Fix64 => (8, 8, true, BamFieldKind::I64, ty.canonical_tag()),
        Ty::F64 => (8, 8, true, BamFieldKind::F64, ty.canonical_tag()),
        Ty::Vec2 | Ty::UVec2 | Ty::IVec2 => (8, 4, true, BamFieldKind::NESTED, ty.canonical_tag()),
        Ty::Vec3 | Ty::IVec3 => (12, 4, true, BamFieldKind::NESTED, ty.canonical_tag()),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => {
            (16, 4, true, BamFieldKind::NESTED, ty.canonical_tag())
        }
        Ty::Mat3 => (36, 4, true, BamFieldKind::NESTED, ty.canonical_tag()),
        Ty::Mat4 => (64, 4, true, BamFieldKind::NESTED, ty.canonical_tag()),
        Ty::Ref(_) => (8, 8, true, BamFieldKind::NESTED, ty.canonical_tag()),
        Ty::Asset(_) => (32, 8, true, BamFieldKind::NESTED, ty.canonical_tag()),
        Ty::BitSet(bits) => {
            let words = (*bits).div_ceil(32).max(1);
            (words * 4, 4, true, BamFieldKind::NESTED, ty.canonical_tag())
        }
        Ty::InlineStr(cap) => {
            let aligned_cap = cap.div_ceil(4) * 4;
            (
                4 + aligned_cap,
                4,
                true,
                BamFieldKind::NESTED,
                ty.canonical_tag(),
            )
        }
        Ty::InputBuffer { cap, .. } => (cap * 8, 4, true, BamFieldKind::NESTED, ty.canonical_tag()),
        Ty::SmallVec { elem, cap } => {
            let (es, ea, pod, _, _) = resolve_ty_layout(elem, env)?;
            let align = ea.max(4);
            let stride = es.div_ceil(ea) * ea;
            (
                8 + stride * cap,
                align,
                pod,
                BamFieldKind::NESTED,
                ty.canonical_tag(),
            )
        }
        Ty::Array { elem, len } => {
            let (es, ea, pod, _, _) = resolve_ty_layout(elem, env)?;
            let stride = es.div_ceil(ea) * ea;
            (
                stride * len,
                ea,
                pod,
                BamFieldKind::NESTED,
                ty.canonical_tag(),
            )
        }
        Ty::Tuple(items) => {
            let mut cursor = 0usize;
            let mut max_align = 1usize;
            let mut all_pod = true;
            for it in items {
                let (s, a, pod, _, _) = resolve_ty_layout(it, env)?;
                max_align = max_align.max(a);
                cursor = cursor.div_ceil(a) * a + s;
                all_pod &= pod;
            }
            let total = cursor.div_ceil(max_align) * max_align;
            (
                total,
                max_align,
                all_pod,
                BamFieldKind::NESTED,
                ty.canonical_tag(),
            )
        }
        Ty::Unit => (0, 1, true, BamFieldKind::NESTED, "()".to_owned()),
        Ty::Named(name) => {
            if let Some(found) = env.resolved.get(name) {
                return Some((
                    found.0,
                    found.1,
                    found.2,
                    BamFieldKind(found.3),
                    found.4.clone(),
                ));
            }
            if let Some(en) = env.enums.get(name) {
                let kind = match en.repr_bytes {
                    1 => BamFieldKind::U8,
                    2 => BamFieldKind::U16,
                    _ => BamFieldKind::U32,
                };
                let tag = match en.repr_bytes {
                    1 => "u8",
                    2 => "u16",
                    _ => "u32",
                };
                return Some((en.repr_bytes, en.repr_bytes, true, kind, tag.to_owned()));
            }
            return None;
        }
        Ty::BannedWire(_) | Ty::Unknown => return None,
    };
    Some(res)
}

/// Rounds `offset` up to the next multiple of `align` (`align <= 1` returns `Some(offset)`),
/// returning `None` on `usize` arithmetic overflow.
#[inline]
#[must_use]
pub const fn align_up(offset: usize, align: usize) -> Option<usize> {
    if align <= 1 {
        return Some(offset);
    }
    let Some(bumped) = offset.checked_add(align - 1) else {
        return None;
    };
    (bumped / align).checked_mul(align)
}

/// Computes `(pad_before, aligned_offset, next_cursor)` for placing a field of size `field_size`
/// and alignment `field_align` at `cursor`, returning `None` on overflow.
#[inline]
#[must_use]
pub const fn compute_field_placement(
    cursor: usize,
    field_size: usize,
    field_align: usize,
) -> Option<(usize, usize, usize)> {
    let eff_align = if field_align == 0 { 1 } else { field_align };
    let Some(aligned_off) = align_up(cursor, eff_align) else {
        return None;
    };
    let pad_before = aligned_off - cursor;
    let Some(next_cursor) = aligned_off.checked_add(field_size) else {
        return None;
    };
    Some((pad_before, aligned_off, next_cursor))
}

/// Solves a `#[repr(C)]` struct/component layout, inserting explicit zero-padding `_strata_pad_N`
/// fields wherever alignment gaps or trailing padding occur, and computes bit-exact `ComponentUuid`
/// and `SCHEMA_FINGERPRINT` matching `bamabi_sys` + `bamabi_macros`.
#[allow(clippy::too_many_arguments)]
pub fn solve_pod_layout(
    canonical_name: impl Into<String>,
    item_kind: SchemaItemKind,
    raw_fields: &[(String, Ty)],
    component_flags: u32,
    required_components: Vec<String>,
    env: &LayoutEnv,
) -> Result<SolvedLayout, String> {
    let canonical_name = canonical_name.into();
    let mut solved_fields = Vec::new();
    let mut cursor = 0usize;
    let mut max_align = 1usize;
    let mut pad_idx = 0usize;
    let mut explicit_pad_bytes = 0usize;
    let mut is_abi_pod = true;

    for (name, ty) in raw_fields {
        let Some((f_size, f_align, f_pod, f_kind, f_tag)) = resolve_ty_layout(ty, env) else {
            return Err(format!(
                "type `{ty:?}` on field `{name}` is not a valid AbiPod wire type"
            ));
        };
        is_abi_pod &= f_pod;
        let f_align = f_align.max(1);
        max_align = max_align.max(f_align);

        let Some((pad_len, aligned_off, next_cursor)) =
            compute_field_placement(cursor, f_size, f_align)
        else {
            return Err(format!("layout size overflow on field `{name}`"));
        };
        if pad_len > 0 {
            explicit_pad_bytes += pad_len;
            solved_fields.push(SolvedField {
                name: format!("_strata_pad_{pad_idx}"),
                ty: Ty::Array {
                    elem: Box::new(Ty::U8),
                    len: pad_len,
                },
                offset: cursor,
                size: pad_len,
                align: 1,
                is_padding: true,
                bam_field_kind: BamFieldKind::NESTED.0,
                type_tag: format!("[u8;{pad_len}]"),
            });
            pad_idx += 1;
        }
        solved_fields.push(SolvedField {
            name: name.clone(),
            ty: ty.clone(),
            offset: aligned_off,
            size: f_size,
            align: f_align,
            is_padding: false,
            bam_field_kind: f_kind.0,
            type_tag: f_tag,
        });
        cursor = next_cursor;
    }

    let total_size =
        align_up(cursor, max_align).ok_or_else(|| "layout tail overflow".to_owned())?;
    if total_size > cursor {
        let pad_len = total_size - cursor;
        explicit_pad_bytes += pad_len;
        solved_fields.push(SolvedField {
            name: format!("_strata_pad_{pad_idx}"),
            ty: Ty::Array {
                elem: Box::new(Ty::U8),
                len: pad_len,
            },
            offset: cursor,
            size: pad_len,
            align: 1,
            is_padding: true,
            bam_field_kind: BamFieldKind::NESTED.0,
            type_tag: format!("[u8;{pad_len}]"),
        });
    }

    // Zero-field marker components/tags have 0 size, 1 align.
    let (uuid, schema_fingerprint) = compute_wire_identity(
        &canonical_name,
        total_size,
        max_align,
        component_flags,
        is_abi_pod,
        &solved_fields,
    );

    Ok(SolvedLayout {
        canonical_name,
        item_kind,
        fields: solved_fields,
        size: total_size,
        align: max_align,
        is_abi_pod,
        component_flags,
        uuid_bytes: *uuid.as_bytes(),
        uuid_hex: format_uuid_hex(&uuid),
        schema_fingerprint,
        required_components,
        explicit_pad_bytes,
    })
}

/// Computes deterministic [`ComponentUuid`] and 64-bit FNV-1a `SCHEMA_FINGERPRINT` matching
/// `bamabi_macros::codegen::vtable` bit-for-bit.
pub fn compute_wire_identity(
    canonical_name: &str,
    size: usize,
    align: usize,
    component_flags: u32,
    is_abi_pod: bool,
    fields: &[SolvedField],
) -> (ComponentUuid, u64) {
    let schema_hash = if is_abi_pod {
        let mut h = 0u64;
        for f in fields {
            h = ComponentUuid::hash_field_schema(h, &f.name, &f.type_tag, f.offset);
        }
        h
    } else {
        0u64
    };
    let uuid = ComponentUuid::from_parts(canonical_name, size, align, schema_hash);

    let mut fp = fnv1a_64_init();
    fp = fnv1a_64_update_bytes(fp, canonical_name.as_bytes());
    fp = fnv1a_64_update_u64(fp, size as u64);
    fp = fnv1a_64_update_u64(fp, align as u64);
    fp = fnv1a_64_update_u64(fp, component_flags as u64);
    for f in fields {
        fp = fnv1a_64_update_u64(fp, f.bam_field_kind as u64);
        fp = fnv1a_64_update_bytes(fp, f.name.as_bytes());
        fp = fnv1a_64_update_bytes(fp, f.type_tag.as_bytes());
        fp = fnv1a_64_update_u64(fp, f.offset as u64);
        fp = fnv1a_64_update_u64(fp, f.size as u64);
        fp = fnv1a_64_update_u64(fp, f.align as u64);
    }

    (uuid, fp)
}

/// Synthesizes the canonical 16-byte `@sparse` `TimelineCursor` layout for a `timeline` item.
pub fn solve_timeline_layout(
    canonical_name: impl Into<String>,
    env: &LayoutEnv,
) -> Result<SolvedLayout, String> {
    let fields = vec![
        ("cur_frame".to_owned(), Ty::U16),
        ("flags".to_owned(), Ty::U16),
        ("active_mask".to_owned(), Ty::U32),
        ("accum_sec".to_owned(), Ty::F32),
        (
            "_pad".to_owned(),
            Ty::Array {
                elem: Box::new(Ty::U8),
                len: 4,
            },
        ),
    ];
    solve_pod_layout(
        canonical_name,
        SchemaItemKind::Timeline,
        &fields,
        BAM_COMPONENT_FLAG_SPARSE_SET,
        Vec::new(),
        env,
    )
}

/// Synthesizes the `@sparse` `AbiPod` state struct for a `task` coroutine (`__pc`, `__timer`,
/// and live-across-`wait` variables).
pub fn solve_task_state_layout(
    canonical_name: impl Into<String>,
    live_vars: &[(String, Ty)],
    is_sparse: bool,
    env: &LayoutEnv,
) -> Result<SolvedLayout, String> {
    let mut fields = vec![("__pc".to_owned(), Ty::U8), ("__timer".to_owned(), Ty::F32)];
    fields.extend(live_vars.iter().cloned());
    let flags = if is_sparse {
        BAM_COMPONENT_FLAG_SPARSE_SET
    } else {
        0
    };
    solve_pod_layout(
        canonical_name,
        SchemaItemKind::TaskState,
        &fields,
        flags,
        Vec::new(),
        env,
    )
}

/// Computes `BAM_COMPONENT_FLAG_*` bitflags from Strata component attribute names.
pub fn flags_from_attr_names<'a>(attrs: impl IntoIterator<Item = &'a str>) -> (u32, bool, bool) {
    let mut is_sparse = false;
    let mut is_summary = false;
    let mut flags = 0u32;
    for a in attrs {
        match a {
            "sparse" => {
                is_sparse = true;
                flags |= BAM_COMPONENT_FLAG_SPARSE_SET;
            }
            "summary_tick" => {
                is_summary = true;
                flags |= BAM_COMPONENT_FLAG_SUMMARY_TICK;
            }
            _ => {}
        }
    }
    (flags, is_sparse, is_summary)
}

/// Formats a [`ComponentUuid`] in canonical lowercase `8-4-4-4-12` hex form.
pub fn format_uuid_hex(uuid: &ComponentUuid) -> String {
    let b = uuid.as_bytes();
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies `align_up` and `compute_field_placement` handle alignment boundaries and overflow.
    #[test]
    fn align_up_and_field_placement_edge_cases() {
        assert_eq!(align_up(0, 4), Some(0));
        assert_eq!(align_up(5, 4), Some(8));
        assert_eq!(align_up(usize::MAX, 8), None);
        assert_eq!(compute_field_placement(1, 8, 8), Some((7, 8, 16)));
        assert_eq!(compute_field_placement(usize::MAX - 2, 4, 4), None);
    }

    /// Verifies `solve_pod_layout` synthesizes zero-gap `_strata_pad_*` fields matching C-ABI size.
    #[test]
    fn solve_pod_layout_fills_all_alignment_and_tail_gaps() {
        let env = LayoutEnv::default();
        let solved = solve_pod_layout(
            "demo::Mixed",
            SchemaItemKind::Component,
            &[
                ("flag".to_owned(), Ty::Bool),
                ("big".to_owned(), Ty::F64),
                ("tail_byte".to_owned(), Ty::U8),
            ],
            0,
            Vec::new(),
            &env,
        )
        .expect("layout solves");
        assert_eq!(solved.align, 8);
        assert_eq!(solved.size, 24);
        assert_eq!(solved.explicit_pad_bytes, 14);
        let sum_sizes: usize = solved.fields.iter().map(|f| f.size).sum();
        assert_eq!(sum_sizes, solved.size);
    }
}
