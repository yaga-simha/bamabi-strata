//! Safe Rust Guest (`.cdylib`, `#![forbid(unsafe_code)]`, ZERO `bevy*` deps) code generator
//! targeting `bamabi_guest` (`ABI 0.3.0`).

use crate::net::{
    FLAG_IS_PREDICTED, FLAG_IS_RELIABLE, FLAG_IS_RESOURCE, FLAG_IS_RPC,
    PACKET_KIND_COMPONENT_DELTA, PACKET_KIND_RESOURCE_DELTA, PACKET_KIND_RPC,
    STRATA_NET_MAX_PAYLOAD_BYTES, STRATA_NET_PACKET_ALIGN, STRATA_NET_PACKET_CANONICAL_NAME,
    STRATA_NET_PACKET_FIELDS, STRATA_NET_PACKET_MAGIC, STRATA_NET_PACKET_SCHEMA_FINGERPRINT,
    STRATA_NET_PACKET_SIZE, STRATA_NET_WIRE_VERSION, has_net_protocol, stratanet_packet_uuid,
    validate_net_packet_capacity,
};
use crate::{
    CodegenError, GeneratedArtifact, GeneratedFile, RustGuestOptions, TargetKind,
    is_ecs_component_kind, module_stem, sanitize_ident, system_schedule_label,
};
use bamabi_sys::fnv1a_64_str;
use core::fmt::Write as _;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use strata_mir::{
    BasicBlock, BlockId, Inst, LocalId, MirConstVal, MirFnKind, MirFunction, MirModule,
    MirNetComponent, MirNetFieldSpec, MirQueryBinding, MirRpc, MirStreamOpKind, MirType,
    Terminator,
};
use strata_sema::access::TermAccessMode;
use strata_sema::hir::{HirExpr, HirParamKind, HirScheduleGroup};
use strata_sema::layout::{SchemaItemKind, SolvedField, SolvedLayout, compute_wire_identity};
use strata_sema::types::Ty;

mod export_mod;
mod fn_emit;
mod inst_emit;
mod items;
mod prelude;
#[cfg(test)]
mod tests;

use export_mod::*;
use fn_emit::*;
use inst_emit::*;
use items::*;
pub(crate) use items::{
    emit_read_field_from_bytes, emit_rust_wire_field_decode, emit_rust_wire_field_encode,
    emit_write_field_to_bytes, rust_abi_type_for_mir_ty,
};
use prelude::*;

/// Emits a complete `#![forbid(unsafe_code)]` Rust Guest `.cdylib` crate (`Cargo.toml`, `src/lib.rs`)
/// directly from [`MirModule`] without intermediate `expr.rs` plan extraction.
pub fn emit(mir: &MirModule, opts: &RustGuestOptions) -> Result<GeneratedArtifact, CodegenError> {
    if has_net_protocol(mir) {
        validate_net_packet_capacity(mir)?;
    }
    let stem = module_stem(&mir.module_path);
    let crate_name = if opts.crate_name.is_empty() {
        format!("strata_guest_{stem}")
    } else {
        opts.crate_name.clone()
    };

    let cargo_toml = format!(
        "[package]\n\
         name = \"{crate_name}\"\n\
         version = \"0.3.0\"\n\
         edition = \"2024\"\n\n\
         [lib]\n\
         crate-type = [\"cdylib\", \"rlib\"]\n\n\
         [dependencies]\n\
         bamabi_guest = {{ version = \"0.3.0\", git = \"https://github.com/yaga-simha/bamabi-wire.git\", branch = \"main\", features = [\"derive\"] }}\n\
         bamabi_sys = {{ version = \"0.3.0\", git = \"https://github.com/yaga-simha/bamabi-wire.git\", branch = \"main\" }}\n"
    );

    let catalog = GuestCatalog::build(mir, &stem);
    let mut lib = String::with_capacity(32768);
    emit_crate_header(&mut lib);
    emit_enums_and_consts(&mut lib, mir, &catalog);
    emit_tables_and_curves(&mut lib, mir, &catalog);
    emit_layouts_and_tags(&mut lib, mir, &catalog);
    if has_net_protocol(mir) {
        emit_net_protocol_and_codecs(&mut lib, mir, &catalog)?;
    }
    emit_runtime_core(&mut lib, mir, &catalog);
    emit_helper_functions(&mut lib, mir, &catalog);
    emit_system_functions(&mut lib, mir, &catalog);
    if has_net_protocol(mir) {
        emit_net_synthesized_systems(&mut lib, mir, &catalog);
    }
    emit_plugin_and_registration(&mut lib, mir, &catalog, &stem);

    Ok(GeneratedArtifact {
        target: TargetKind::RustGuest,
        module_name: mir.module_path.clone(),
        files: vec![
            GeneratedFile {
                path: "Cargo.toml".to_owned(),
                content: cargo_toml,
            },
            GeneratedFile {
                path: "src/lib.rs".to_owned(),
                content: lib,
            },
        ],
    })
}

pub(crate) fn scale_int_fix32(v: i64) -> i32 {
    v.saturating_mul(65_536) as i32
}

pub(crate) fn scale_float_fix32(v: f64) -> i32 {
    if v.is_finite() {
        (v * 65_536.0).round() as i32
    } else {
        0
    }
}

pub(crate) fn scale_int_fix64(v: i64) -> i64 {
    v.wrapping_shl(32)
}

pub(crate) fn scale_float_fix64(v: f64) -> i64 {
    if v.is_finite() {
        (v * 4_294_967_296.0).round() as i64
    } else {
        0
    }
}

pub(crate) fn format_fix32_i32_lit(v: i32) -> String {
    if v == i32::MIN {
        "i32::MIN".to_owned()
    } else {
        format!("{v}i32")
    }
}

pub(crate) fn format_fix64_i64_lit(v: i64) -> String {
    if v == i64::MIN {
        "i64::MIN".to_owned()
    } else {
        format!("{v}i64")
    }
}

/// Maps a [`SolvedField`] to its exact `#![forbid(unsafe_code)]` Rust ABI field type.
pub(crate) fn rust_abi_type_for_field(field: &SolvedField, mir: &MirModule) -> String {
    if field.is_padding {
        return format!("[u8; {}]", field.size.max(1));
    }
    if matches!(
        field.ty,
        Ty::Named(_) | Ty::Tuple(_) | Ty::SmallVec { .. } | Ty::InputBuffer { .. } | Ty::Unknown
    ) && !matches_enum_ty(&field.ty, mir)
    {
        return aligned_blob_type(field.size, field.align);
    }
    rust_abi_type_for_ty(&field.ty, field.size, mir)
}

/// Maps a Strata semantic [`Ty`] to its Rust ABI POD type string.
pub(crate) fn rust_abi_type_for_ty(ty: &Ty, byte_size: usize, mir: &MirModule) -> String {
    match ty {
        Ty::U8 => "u8".to_owned(),
        Ty::I8 => "i8".to_owned(),
        Ty::Bool => "FfiBool".to_owned(),
        Ty::U16 => "u16".to_owned(),
        Ty::I16 => "i16".to_owned(),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => "u32".to_owned(),
        Ty::I32 | Ty::Fix32 => "i32".to_owned(),
        Ty::U64 => "u64".to_owned(),
        Ty::I64 | Ty::Fix64 => "i64".to_owned(),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => "f32".to_owned(),
        Ty::F64 => "f64".to_owned(),
        Ty::Vec2 => "[f32; 2]".to_owned(),
        Ty::Vec3 => "[f32; 3]".to_owned(),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => "[f32; 4]".to_owned(),
        Ty::IVec2 => "[i32; 2]".to_owned(),
        Ty::IVec3 => "[i32; 3]".to_owned(),
        Ty::UVec2 => "[u32; 2]".to_owned(),
        Ty::Mat3 => "[f32; 9]".to_owned(),
        Ty::Mat4 => "[f32; 16]".to_owned(),
        Ty::Ref(_) => "FfiEntity".to_owned(),
        Ty::Asset(_) => "FfiAssetHandle".to_owned(),
        Ty::Array { elem, len } => {
            let elem_ty = rust_abi_type_for_ty(elem, byte_size / (*len).max(1), mir);
            format!("[{elem_ty}; {len}]")
        }
        Ty::BitSet(bits) => format!("[u32; {}]", (*bits).div_ceil(32).max(1)),
        Ty::Named(n) => {
            if let Some((sz, is_signed)) = find_enum_repr(n, mir) {
                return match (sz, is_signed) {
                    (1, _) => "u8".to_owned(),
                    (2, _) => "u16".to_owned(),
                    (_, true) => "i32".to_owned(),
                    _ => "u32".to_owned(),
                };
            }
            if let Some(l) = mir.layouts.iter().find(|l| {
                l.canonical_name == *n
                    || l.canonical_name.rsplit("::").next() == Some(n.as_str())
                    || sanitize_ident(&l.canonical_name) == sanitize_ident(n)
            }) {
                return aligned_blob_type(byte_size, l.align);
            }
            aligned_blob_type(byte_size, 4)
        }
        _ => aligned_blob_type(byte_size, 4),
    }
}

/// Computes the zero/canonical Rust default expression for a [`SolvedField`].
pub(crate) fn rust_default_expr_for_field(field: &SolvedField, mir: &MirModule) -> String {
    if field.is_padding {
        return format!("[0u8; {}]", field.size.max(1));
    }
    if matches!(
        field.ty,
        Ty::Named(_) | Ty::Tuple(_) | Ty::SmallVec { .. } | Ty::InputBuffer { .. } | Ty::Unknown
    ) && !matches_enum_ty(&field.ty, mir)
    {
        return aligned_blob_default(field.size, field.align);
    }
    rust_default_expr_for_ty(&field.ty, field.size, mir)
}

/// Sanitizes an arbitrary Strata identifier into a valid Rust identifier (handling keywords).
pub(crate) fn sanitize_rust_ident(raw: &str) -> String {
    let base = sanitize_ident(raw);
    match base.as_str() {
        "self" | "Self" | "super" | "crate" => format!("{base}_"),
        "type" | "match" | "loop" | "in" | "ref" | "mut" | "fn" | "let" | "if" | "else" | "for"
        | "while" | "mod" | "pub" | "struct" | "enum" | "as" | "break" | "const" | "continue"
        | "extern" | "false" | "impl" | "move" | "return" | "static" | "trait" | "true"
        | "unsafe" | "use" | "where" | "async" | "await" | "dyn" | "try" | "gen" => {
            format!("r#{base}")
        }
        _ => base,
    }
}

pub(crate) fn aligned_blob_type(byte_size: usize, align: usize) -> String {
    if byte_size == 0 {
        return "()".to_owned();
    }
    if align >= 8 && byte_size >= 8 && byte_size.is_multiple_of(8) {
        format!("[u64; {}]", byte_size / 8)
    } else if align >= 4 && byte_size >= 4 && byte_size.is_multiple_of(4) {
        format!("[u32; {}]", byte_size / 4)
    } else if align >= 2 && byte_size >= 2 && byte_size.is_multiple_of(2) {
        format!("[u16; {}]", byte_size / 2)
    } else {
        format!("[u8; {byte_size}]")
    }
}

fn aligned_blob_default(byte_size: usize, align: usize) -> String {
    if byte_size == 0 {
        return "()".to_owned();
    }
    if align >= 8 && byte_size >= 8 && byte_size.is_multiple_of(8) {
        format!("[0u64; {}]", byte_size / 8)
    } else if align >= 4 && byte_size >= 4 && byte_size.is_multiple_of(4) {
        format!("[0u32; {}]", byte_size / 4)
    } else if align >= 2 && byte_size >= 2 && byte_size.is_multiple_of(2) {
        format!("[0u16; {}]", byte_size / 2)
    } else {
        format!("[0u8; {byte_size}]")
    }
}

fn matches_enum_ty(ty: &Ty, mir: &MirModule) -> bool {
    if let Ty::Named(n) = ty {
        find_enum_layout_or_def(n, mir).is_some()
    } else {
        false
    }
}

fn find_enum_repr(name: &str, mir: &MirModule) -> Option<(usize, bool)> {
    let short = name.rsplit("::").next().unwrap_or(name);
    if let Some(ed) = mir.enums.iter().find(|e| {
        e.canonical_name == name
            || e.canonical_name.rsplit("::").next() == Some(short)
            || sanitize_ident(&e.canonical_name) == sanitize_ident(name)
    }) {
        return Some((ed.repr_bytes, ed.is_signed));
    }
    mir.layouts
        .iter()
        .find(|l| {
            l.item_kind == SchemaItemKind::Enum
                && (l.canonical_name == name
                    || l.canonical_name.rsplit("::").next() == Some(short)
                    || sanitize_ident(&l.canonical_name) == sanitize_ident(name))
        })
        .map(|en| (en.size, false))
}

fn find_enum_layout_or_def(name: &str, mir: &MirModule) -> Option<usize> {
    find_enum_repr(name, mir).map(|(sz, _)| sz)
}

fn rust_default_expr_for_ty(ty: &Ty, byte_size: usize, mir: &MirModule) -> String {
    match ty {
        Ty::U8 => "0u8".to_owned(),
        Ty::I8 => "0i8".to_owned(),
        Ty::Bool => "FfiBool::FALSE".to_owned(),
        Ty::U16 => "0u16".to_owned(),
        Ty::I16 => "0i16".to_owned(),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => "0u32".to_owned(),
        Ty::I32 | Ty::Fix32 => "0i32".to_owned(),
        Ty::U64 => "0u64".to_owned(),
        Ty::I64 | Ty::Fix64 => "0i64".to_owned(),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => "0.0f32".to_owned(),
        Ty::F64 => "0.0f64".to_owned(),
        Ty::Vec2 => "[0.0f32; 2]".to_owned(),
        Ty::Vec3 => "[0.0f32; 3]".to_owned(),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => "[0.0f32; 4]".to_owned(),
        Ty::IVec2 => "[0i32; 2]".to_owned(),
        Ty::IVec3 => "[0i32; 3]".to_owned(),
        Ty::UVec2 => "[0u32; 2]".to_owned(),
        Ty::Mat3 => "[0.0f32; 9]".to_owned(),
        Ty::Mat4 => "[0.0f32; 16]".to_owned(),
        Ty::Ref(_) => "FfiEntity::NULL".to_owned(),
        Ty::Asset(_) => "FfiAssetHandle::NONE".to_owned(),
        Ty::Array { elem, len } => {
            let inner = rust_default_expr_for_ty(elem, byte_size / (*len).max(1), mir);
            format!("[{inner}; {len}]")
        }
        Ty::BitSet(bits) => format!("[0u32; {}]", (*bits).div_ceil(32).max(1)),
        Ty::Named(n) => {
            if let Some((sz, is_signed)) = find_enum_repr(n, mir) {
                return match (sz, is_signed) {
                    (1, _) => "0u8".to_owned(),
                    (2, _) => "0u16".to_owned(),
                    (_, true) => "0i32".to_owned(),
                    _ => "0u32".to_owned(),
                };
            }
            if let Some(l) = mir.layouts.iter().find(|l| {
                l.canonical_name == *n || l.canonical_name.rsplit("::").next() == Some(n.as_str())
            }) {
                return aligned_blob_default(byte_size, l.align);
            }
            aligned_blob_default(byte_size, 4)
        }
        _ => aligned_blob_default(byte_size, 4),
    }
}

fn rust_field_kind(kind: u32) -> &'static str {
    match kind {
        1 => "BamFieldKind::BOOL",
        2 => "BamFieldKind::U8",
        3 => "BamFieldKind::I8",
        4 => "BamFieldKind::U16",
        5 => "BamFieldKind::I16",
        6 => "BamFieldKind::U32",
        7 => "BamFieldKind::I32",
        8 => "BamFieldKind::U64",
        9 => "BamFieldKind::I64",
        10 => "BamFieldKind::F32",
        11 => "BamFieldKind::F64",
        12 => "BamFieldKind::USIZE",
        13 => "BamFieldKind::ISIZE",
        17 => "BamFieldKind::NESTED",
        _ => "BamFieldKind::UNKNOWN",
    }
}

// ============================================================================
// Catalog & Deduplicated Physical Query Resolution
// ============================================================================
