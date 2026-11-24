//! BevyNative query planning, conflict analysis, type inference, and chunk loop detection.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ValTy {
    Unit,
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    Fix32,
    Fix64,
    Vec2,
    Vec3,
    Vec4,
    IVec2,
    IVec3,
    UVec2,
    Entity,
    Checkpoint,
    QueryIter,
    Array(Box<ValTy>, usize),
    Tuple(Vec<ValTy>),
    Struct(String),
    TableRow(String),
    BitSet(usize),
    InputBuf(usize),
    InlineStr(usize),
    SmallVec {
        elem: Box<ValTy>,
        cap: usize,
        elem_size: usize,
        elem_align: usize,
    },
    PtrMarker,
}

pub(super) fn aligned_blob_default_expr(byte_size: usize, align: usize) -> String {
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

pub(super) fn sema_ty_size_align(ty: &Ty, ctx: &NativeCtx<'_>) -> (usize, usize) {
    match ty {
        Ty::Bool | Ty::U8 | Ty::I8 => (1, 1),
        Ty::U16 | Ty::I16 => (2, 2),
        Ty::U32
        | Ty::I32
        | Ty::Fix32
        | Ty::F32
        | Ty::Sym
        | Ty::Rgba8
        | Ty::UnitScalar { .. }
        | Ty::GraceWindow => (4, 4),
        Ty::U64 | Ty::I64 | Ty::Fix64 | Ty::F64 | Ty::Ref(_) => (8, 8),
        Ty::Asset(_) => (32, 8),
        Ty::Vec2 | Ty::IVec2 | Ty::UVec2 => (8, 4),
        Ty::Vec3 | Ty::IVec3 => (12, 4),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => (16, 4),
        Ty::Mat3 => (36, 4),
        Ty::Mat4 => (64, 4),
        Ty::BitSet(bits) => ((*bits).div_ceil(32).max(1) * 4, 4),
        Ty::InlineStr(cap) => (4 + cap.div_ceil(4) * 4, 4),
        Ty::InputBuffer { cap, .. } => ((*cap).max(1) * 8, 4),
        Ty::Array { elem, len } => {
            let (es, ea) = sema_ty_size_align(elem, ctx);
            let ea = ea.max(1);
            let stride = es.div_ceil(ea) * ea;
            (stride * *len, ea)
        }
        Ty::SmallVec { elem, cap } => {
            let (es, ea) = sema_ty_size_align(elem, ctx);
            let ea = ea.max(1);
            let stride = es.div_ceil(ea) * ea;
            (8 + stride * *cap, ea.max(4))
        }
        Ty::Tuple(items) => {
            let mut cursor = 0usize;
            let mut max_align = 1usize;
            for it in items {
                let (s, a) = sema_ty_size_align(it, ctx);
                let a = a.max(1);
                max_align = max_align.max(a);
                cursor = cursor.div_ceil(a) * a + s;
            }
            (cursor.div_ceil(max_align) * max_align, max_align)
        }
        Ty::Named(n) => {
            if let Some(le) = ctx.find_layout_entry(n) {
                (le.layout.size, le.layout.align.max(1))
            } else if let Some(en) = ctx.enums_by_key.get(n.as_str()).or_else(|| {
                let s = n.rsplit("::").next().unwrap_or(n.as_str());
                ctx.enums_by_key.get(s)
            }) {
                let sz = en.repr_bytes.max(1);
                (sz, sz)
            } else {
                (4, 4)
            }
        }
        _ => (0, 1),
    }
}

pub(super) fn parse_mir_debug_ty(raw: &str) -> MirType {
    let s = raw.trim();
    match s {
        "Unit" | "()" => MirType::Unit,
        "Bool" | "bool" => MirType::Bool,
        "U8" | "u8" => MirType::U8,
        "U16" | "u16" => MirType::U16,
        "U32" | "u32" => MirType::U32,
        "Sym" | "sym" => MirType::Sym,
        "U64" | "u64" => MirType::U64,
        "I8" | "i8" => MirType::I8,
        "I16" | "i16" => MirType::I16,
        "I32" | "i32" => MirType::I32,
        "I64" | "i64" => MirType::I64,
        "F32" | "f32" => MirType::F32,
        "F64" | "f64" => MirType::F64,
        "Fix32" | "fix32" => MirType::Fix32,
        "Fix64" | "fix64" => MirType::Fix64,
        "Vec2" | "vec2" => MirType::Vec2,
        "Vec3" | "vec3" => MirType::Vec3,
        "Vec4" | "vec4" | "Vec3a" | "vec3a" | "Quat" | "quat" | "Rgba" | "rgba" => MirType::Vec4,
        "IVec2" | "ivec2" => MirType::IVec2,
        "IVec3" | "ivec3" => MirType::IVec3,
        "UVec2" | "uvec2" => MirType::UVec2,
        "Entity" => MirType::Entity,
        "Ptr" => MirType::Ptr,
        "MutPtr" => MirType::MutPtr,
        _ => {
            if let Some(inner) = s.strip_prefix("Named(").and_then(|r| r.strip_suffix(')')) {
                let inner = inner.trim();
                if let Some(unquoted) = inner.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
                    let unescaped = unquoted.replace("\\\"", "\"").replace("\\\\", "\\");
                    return MirType::Named(unescaped);
                }
                return MirType::Named(inner.to_owned());
            }
            if let Some(inner) = s.strip_prefix("Array {")
                && let Some(body) = inner.strip_suffix('}')
                && let Some((elem_part, len_part)) = body.rsplit_once(", len:")
                && let Some(elem_raw) = elem_part.trim().strip_prefix("elem:")
                && let Ok(len) = len_part.trim().parse::<usize>()
            {
                return MirType::Array {
                    elem: Box::new(parse_mir_debug_ty(elem_raw)),
                    len,
                };
            }
            MirType::Named(s.to_owned())
        }
    }
}

pub(super) fn sema_ty_from_mir_with_ctx(mty: &MirType, ctx: &NativeCtx<'_>) -> Ty {
    match mty {
        MirType::Bool => Ty::Bool,
        MirType::U8 => Ty::U8,
        MirType::U16 => Ty::U16,
        MirType::U32 => Ty::U32,
        MirType::Sym => Ty::Sym,
        MirType::U64 => Ty::U64,
        MirType::I8 => Ty::I8,
        MirType::I16 => Ty::I16,
        MirType::I32 => Ty::I32,
        MirType::I64 => Ty::I64,
        MirType::F32 => Ty::F32,
        MirType::F64 => Ty::F64,
        MirType::Fix32 => Ty::Fix32,
        MirType::Fix64 => Ty::Fix64,
        MirType::Vec2 => Ty::Vec2,
        MirType::Vec3 => Ty::Vec3,
        MirType::Vec4 => Ty::Vec4,
        MirType::IVec2 => Ty::IVec2,
        MirType::IVec3 => Ty::IVec3,
        MirType::UVec2 => Ty::UVec2,
        MirType::Entity => Ty::Ref("Entity".to_owned()),
        MirType::Array { elem, len } => Ty::Array {
            elem: Box::new(sema_ty_from_mir_with_ctx(elem, ctx)),
            len: *len,
        },
        MirType::Named(n) => {
            if n == "GraceWindow" {
                Ty::GraceWindow
            } else if n == "mat3" || n == "Mat3" {
                Ty::Mat3
            } else if n == "mat4" || n == "Mat4" {
                Ty::Mat4
            } else if n == "InlineStr" {
                Ty::InlineStr(64)
            } else if let Some(inner) = n
                .strip_prefix("InlineStr<")
                .and_then(|s| s.strip_suffix('>'))
            {
                Ty::InlineStr(inner.trim().parse().unwrap_or(64))
            } else if let Some(inner) = n.strip_prefix("BitSet<").and_then(|s| s.strip_suffix('>'))
            {
                Ty::BitSet(inner.trim().parse().unwrap_or(32))
            } else if let Some(inner) = n
                .strip_prefix("InputBuffer<")
                .and_then(|s| s.strip_suffix('>'))
            {
                let (act, cap_s) = inner.rsplit_once(',').unwrap_or(("u16", "4"));
                Ty::InputBuffer {
                    action: act.trim().to_owned(),
                    cap: cap_s.trim().parse().unwrap_or(4),
                }
            } else if let Some((elem_ty, cap)) = parse_mir_smallvec_parts(n, ctx) {
                Ty::SmallVec {
                    elem: Box::new(elem_ty),
                    cap,
                }
            } else if n == "IVec2" {
                Ty::IVec2
            } else if n == "IVec3" {
                Ty::IVec3
            } else if n == "UVec2" {
                Ty::UVec2
            } else if n == "Vec3a" {
                Ty::Vec3a
            } else if let Some(inner) = n.strip_prefix("Asset<").and_then(|s| s.strip_suffix('>')) {
                Ty::Asset(inner.to_owned())
            } else {
                Ty::Named(n.clone())
            }
        }
        _ => Ty::Unknown,
    }
}

pub(super) fn parse_mir_smallvec_parts(n: &str, ctx: &NativeCtx<'_>) -> Option<(Ty, usize)> {
    let inner = n.strip_prefix("SmallVec<")?.strip_suffix('>')?;
    let (elem_raw, cap_raw) = inner.rsplit_once(',')?;
    let cap: usize = cap_raw.trim().parse().ok()?;
    let elem_mir = parse_mir_debug_ty(elem_raw.trim());
    Some((sema_ty_from_mir_with_ctx(&elem_mir, ctx), cap))
}

pub(super) fn val_ty_to_sema_hint(vt: &ValTy) -> Ty {
    match vt {
        ValTy::Bool => Ty::Bool,
        ValTy::U8 => Ty::U8,
        ValTy::U16 => Ty::U16,
        ValTy::U32 => Ty::U32,
        ValTy::U64 => Ty::U64,
        ValTy::I8 => Ty::I8,
        ValTy::I16 => Ty::I16,
        ValTy::I32 => Ty::I32,
        ValTy::I64 => Ty::I64,
        ValTy::F32 => Ty::F32,
        ValTy::F64 => Ty::F64,
        ValTy::Fix32 => Ty::Fix32,
        ValTy::Fix64 => Ty::Fix64,
        ValTy::Vec2 => Ty::Vec2,
        ValTy::Vec3 => Ty::Vec3,
        ValTy::Vec4 => Ty::Vec4,
        ValTy::IVec2 => Ty::IVec2,
        ValTy::IVec3 => Ty::IVec3,
        ValTy::UVec2 => Ty::UVec2,
        ValTy::Entity => Ty::Ref("Entity".to_owned()),
        ValTy::Array(elem, len) => Ty::Array {
            elem: Box::new(val_ty_to_sema_hint(elem)),
            len: *len,
        },
        ValTy::SmallVec { elem, cap, .. } => Ty::SmallVec {
            elem: Box::new(val_ty_to_sema_hint(elem)),
            cap: *cap,
        },
        ValTy::Struct(sname) => Ty::Named(sname.clone()),
        ValTy::BitSet(b) => Ty::BitSet(*b),
        ValTy::InputBuf(c) => Ty::InputBuffer {
            action: "u16".to_owned(),
            cap: *c,
        },
        ValTy::InlineStr(c) => Ty::InlineStr(*c),
        _ => Ty::Unknown,
    }
}

impl ValTy {
    pub(super) fn from_mir(mty: &MirType, ctx: &NativeCtx<'_>) -> Self {
        match mty {
            MirType::Unit => Self::Unit,
            MirType::Bool => Self::Bool,
            MirType::U8 => Self::U8,
            MirType::U16 => Self::U16,
            MirType::U32 | MirType::Sym => Self::U32,
            MirType::U64 => Self::U64,
            MirType::I8 => Self::I8,
            MirType::I16 => Self::I16,
            MirType::I32 => Self::I32,
            MirType::I64 => Self::I64,
            MirType::F32 => Self::F32,
            MirType::F64 => Self::F64,
            MirType::Fix32 => Self::Fix32,
            MirType::Fix64 => Self::Fix64,
            MirType::Vec2 => Self::Vec2,
            MirType::Vec3 => Self::Vec3,
            MirType::Vec4 => Self::Vec4,
            MirType::IVec2 => Self::IVec2,
            MirType::IVec3 => Self::IVec3,
            MirType::UVec2 => Self::UVec2,
            MirType::Entity => Self::Entity,
            MirType::Checkpoint => Self::Checkpoint,
            MirType::QueryIter => Self::QueryIter,
            MirType::Ptr | MirType::MutPtr => Self::PtrMarker,
            MirType::Array { elem, len } => Self::Array(Box::new(Self::from_mir(elem, ctx)), *len),
            MirType::Tuple(items) => {
                Self::Tuple(items.iter().map(|t| Self::from_mir(t, ctx)).collect())
            }
            MirType::Named(n) => {
                if n == "GraceWindow" {
                    Self::F32
                } else if n == "InlineStr" {
                    Self::InlineStr(64)
                } else if let Some(inner) = n
                    .strip_prefix("InlineStr<")
                    .and_then(|s| s.strip_suffix('>'))
                {
                    Self::InlineStr(inner.parse().unwrap_or(64))
                } else if let Some(inner) =
                    n.strip_prefix("BitSet<").and_then(|s| s.strip_suffix('>'))
                {
                    Self::BitSet(inner.parse().unwrap_or(32))
                } else if let Some(inner) = n
                    .strip_prefix("InputBuffer<")
                    .and_then(|s| s.strip_suffix('>'))
                    && let Some((_, cap_s)) = inner.split_once(',')
                {
                    Self::InputBuf(cap_s.trim().parse().unwrap_or(4))
                } else if let Some(en) = ctx.enums_by_key.get(n.as_str()) {
                    match (en.repr_bytes, en.is_signed) {
                        (1, _) => Self::U8,
                        (2, _) => Self::U16,
                        (_, true) => Self::I32,
                        _ => Self::U32,
                    }
                } else if ctx.tables_by_key.contains_key(n.as_str()) {
                    Self::TableRow(n.clone())
                } else if let Some(entry) = ctx.find_layout_entry(n) {
                    Self::Struct(entry.struct_name.clone())
                } else if let Some(sname) = ctx.resolve_ecs_struct_name(n) {
                    Self::Struct(sname)
                } else if let Some((elem_ty, cap)) = parse_mir_smallvec_parts(n, ctx) {
                    let elem_vt = Self::from_sema_ty(&elem_ty, ctx);
                    let (es, ea) = sema_ty_size_align(&elem_ty, ctx);
                    Self::SmallVec {
                        elem: Box::new(elem_vt),
                        cap,
                        elem_size: es,
                        elem_align: ea.max(1),
                    }
                } else if n == "mat3" || n == "Mat3" {
                    Self::Array(Box::new(Self::F32), 9)
                } else if n == "mat4" || n == "Mat4" {
                    Self::Array(Box::new(Self::F32), 16)
                } else if n.starts_with("Asset<") {
                    Self::Struct("FfiAssetHandle".to_owned())
                } else {
                    Self::U64
                }
            }
        }
    }

    pub(super) fn from_solved_field(field: &SolvedField, ctx: &NativeCtx<'_>) -> Self {
        Self::from_sema_ty(&field.ty, ctx)
    }

    pub(super) fn from_sema_ty(ty: &Ty, ctx: &NativeCtx<'_>) -> Self {
        match ty {
            Ty::Bool => Self::Bool,
            Ty::U8 => Self::U8,
            Ty::I8 => Self::I8,
            Ty::U16 => Self::U16,
            Ty::I16 => Self::I16,
            Ty::U32 | Ty::Sym | Ty::Rgba8 => Self::U32,
            Ty::I32 => Self::I32,
            Ty::Fix32 => Self::Fix32,
            Ty::U64 => Self::U64,
            Ty::I64 => Self::I64,
            Ty::Fix64 => Self::Fix64,
            Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => Self::F32,
            Ty::F64 => Self::F64,
            Ty::Vec2 => Self::Vec2,
            Ty::Vec3 => Self::Vec3,
            Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => Self::Vec4,
            Ty::IVec2 => Self::IVec2,
            Ty::IVec3 => Self::IVec3,
            Ty::UVec2 => Self::UVec2,
            Ty::Ref(_) => Self::Entity,
            Ty::BitSet(b) => Self::BitSet(*b),
            Ty::InputBuffer { cap, .. } => Self::InputBuf(*cap),
            Ty::InlineStr(cap) => Self::InlineStr(*cap),
            Ty::Mat3 => Self::Array(Box::new(Self::F32), 9),
            Ty::Mat4 => Self::Array(Box::new(Self::F32), 16),
            Ty::Array { elem, len } => Self::Array(Box::new(Self::from_sema_ty(elem, ctx)), *len),
            Ty::SmallVec { elem, cap } => {
                let elem_vt = Self::from_sema_ty(elem, ctx);
                let (es, ea) = sema_ty_size_align(elem, ctx);
                Self::SmallVec {
                    elem: Box::new(elem_vt),
                    cap: *cap,
                    elem_size: es,
                    elem_align: ea.max(1),
                }
            }
            Ty::Tuple(items) => {
                Self::Tuple(items.iter().map(|t| Self::from_sema_ty(t, ctx)).collect())
            }
            Ty::Named(n) => Self::from_mir(&MirType::Named(n.clone()), ctx),
            _ => Self::from_mir(&MirType::Unit, ctx),
        }
    }

    pub(super) fn rust_type(&self) -> String {
        match self {
            Self::Unit | Self::PtrMarker => "()".to_owned(),
            Self::Bool => "bool".to_owned(),
            Self::U8 => "u8".to_owned(),
            Self::U16 => "u16".to_owned(),
            Self::U32 => "u32".to_owned(),
            Self::U64 => "u64".to_owned(),
            Self::I8 => "i8".to_owned(),
            Self::I16 => "i16".to_owned(),
            Self::I32 => "i32".to_owned(),
            Self::I64 => "i64".to_owned(),
            Self::F32 => "f32".to_owned(),
            Self::F64 => "f64".to_owned(),
            Self::Fix32 => "Fixed32".to_owned(),
            Self::Fix64 => "Fixed64".to_owned(),
            Self::Vec2 => "[f32; 2]".to_owned(),
            Self::Vec3 => "[f32; 3]".to_owned(),
            Self::Vec4 => "[f32; 4]".to_owned(),
            Self::IVec2 => "[i32; 2]".to_owned(),
            Self::IVec3 => "[i32; 3]".to_owned(),
            Self::UVec2 => "[u32; 2]".to_owned(),
            Self::Entity => "FfiEntity".to_owned(),
            Self::Checkpoint => "usize".to_owned(),
            Self::QueryIter => "Vec<FfiEntity>".to_owned(),
            Self::Array(e, n) => format!("[{}; {n}]", e.rust_type()),
            Self::Tuple(items) => {
                let parts: Vec<String> = items.iter().map(Self::rust_type).collect();
                format!("({})", parts.join(", "))
            }
            Self::Struct(sname) => sname.clone(),
            Self::TableRow(tname) => format!("StrataTable_{}Row", sanitize_ident(tname)),
            Self::BitSet(bits) => format!("[u32; {}]", (*bits).div_ceil(32).max(1)),
            Self::InputBuf(cap) => format!("[u32; {}]", (*cap).max(1) * 2),
            Self::InlineStr(cap) => format!("[u32; {}]", 1 + cap.div_ceil(4)),
            Self::SmallVec {
                cap,
                elem_size,
                elem_align,
                ..
            } => {
                let ea = (*elem_align).max(1);
                let stride = elem_size.div_ceil(ea) * ea;
                aligned_blob_type(8 + stride * *cap, ea.max(4))
            }
        }
    }

    pub(super) fn default_expr(&self) -> String {
        match self {
            Self::Unit | Self::PtrMarker => "()".to_owned(),
            Self::Bool => "false".to_owned(),
            Self::U8 => "0u8".to_owned(),
            Self::U16 => "0u16".to_owned(),
            Self::U32 => "0u32".to_owned(),
            Self::U64 => "0u64".to_owned(),
            Self::I8 => "0i8".to_owned(),
            Self::I16 => "0i16".to_owned(),
            Self::I32 => "0i32".to_owned(),
            Self::I64 => "0i64".to_owned(),
            Self::F32 => "0.0_f32".to_owned(),
            Self::F64 => "0.0_f64".to_owned(),
            Self::Fix32 => "Fixed32(0)".to_owned(),
            Self::Fix64 => "Fixed64(0)".to_owned(),
            Self::Vec2 => "[0.0_f32; 2]".to_owned(),
            Self::Vec3 => "[0.0_f32; 3]".to_owned(),
            Self::Vec4 => "[0.0_f32; 4]".to_owned(),
            Self::IVec2 => "[0i32; 2]".to_owned(),
            Self::IVec3 => "[0i32; 3]".to_owned(),
            Self::UVec2 => "[0u32; 2]".to_owned(),
            Self::Entity => "FfiEntity::NULL".to_owned(),
            Self::Checkpoint => "0usize".to_owned(),
            Self::QueryIter => "Vec::new()".to_owned(),
            Self::Array(e, n) => format!("[{}; {n}]", e.default_expr()),
            Self::Tuple(items) => {
                let parts: Vec<String> = items.iter().map(Self::default_expr).collect();
                format!("({})", parts.join(", "))
            }
            Self::Struct(_) | Self::TableRow(_) => "Default::default()".to_owned(),
            Self::BitSet(bits) => format!("[0u32; {}]", (*bits).div_ceil(32).max(1)),
            Self::InputBuf(cap) => format!("[0u32; {}]", (*cap).max(1) * 2),
            Self::InlineStr(cap) => format!("[0u32; {}]", 1 + cap.div_ceil(4)),
            Self::SmallVec {
                cap,
                elem_size,
                elem_align,
                ..
            } => {
                let ea = (*elem_align).max(1);
                let stride = elem_size.div_ceil(ea) * ea;
                aligned_blob_default_expr(8 + stride * *cap, ea.max(4))
            }
        }
    }

    pub(super) fn is_int(&self) -> bool {
        matches!(
            self,
            Self::U8
                | Self::U16
                | Self::U32
                | Self::U64
                | Self::I8
                | Self::I16
                | Self::I32
                | Self::I64
        )
    }

    pub(super) fn is_float(&self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }

    pub(super) fn is_vec(&self) -> Option<usize> {
        match self {
            Self::Vec2 => Some(2),
            Self::Vec3 => Some(3),
            Self::Vec4 => Some(4),
            _ => None,
        }
    }

    pub(super) fn is_ivec(&self) -> Option<usize> {
        match self {
            Self::IVec2 | Self::UVec2 => Some(2),
            Self::IVec3 => Some(3),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) enum PtrTarget {
    Resource {
        var_name: String,
    },
    QueryCol {
        query_idx: u32,
        slot_idx: usize,
        selective: bool,
        optional: bool,
        is_sparse: bool,
        projected: Option<(String, String, ValTy)>,
    },
    QueryRow {
        query_idx: u32,
        slot_idx: usize,
        row_idx_local: LocalId,
        selective: bool,
        optional: bool,
        is_sparse: bool,
        projected: Option<(String, String, ValTy)>,
    },
    EntityRow {
        query_idx: u32,
        slot_idx: usize,
        entity_local: LocalId,
        optional: bool,
        projected: Option<(String, String, ValTy)>,
    },
    EntitiesSlice {
        query_idx: u32,
    },
    QueryEntityCol {
        query_idx: u32,
    },
    QueryEntityRow {
        query_idx: u32,
        row_idx_local: LocalId,
    },
    TriggerPayload,
    ParamPtr {
        var_name: String,
        layout_key: String,
        projected: Option<(String, String, ValTy)>,
    },
    Field {
        base: Box<PtrTarget>,
        field: String,
        blob_step: Option<(String, String, &'static str, &'static str)>,
    },
    ArrayElem {
        base: Box<PtrTarget>,
        ptr_local: LocalId,
        elem_ty: Ty,
        elem_size: usize,
        elem_align: usize,
        elem_rust_ty: String,
        elem_needs_pod_unpack: bool,
        is_smallvec: bool,
        sv_cap: usize,
    },
    SlotRef {
        slot_local: LocalId,
    },
    UpCascadeDirect {
        up_local: LocalId,
        comp_struct: String,
        up_q_expr: String,
        is_mut: bool,
    },
    UpCascadeSlot {
        slot_local: LocalId,
        row_target: Option<Box<PtrTarget>>,
        comp_struct: String,
        up_q_expr: String,
        is_mut: bool,
    },
}

#[derive(Clone)]
pub(super) struct DedupTermSlot {
    pub(super) slot_idx: usize,
    pub(super) canonical: String,
    pub(super) struct_name: String,
    pub(super) mode: TermAccessMode,
    pub(super) is_untracked: bool,
}

#[derive(Clone)]
pub(super) struct UpCascadePlan {
    pub(super) canonical: String,
    pub(super) struct_name: String,
    pub(super) is_mut: bool,
    pub(super) param_name: String,
    pub(super) param_set_idx: Option<usize>,
}

pub(super) struct QueryEmitPlan {
    pub(super) query_idx: u32,
    pub(super) param_name: String,
    pub(super) param_set_idx: Option<usize>,
    pub(super) is_sparse: bool,
    pub(super) needs_entity: bool,
    pub(super) has_any_mut: bool,
    pub(super) slots: Vec<DedupTermSlot>,
    pub(super) term_to_slot: HashMap<u32, usize>,
    pub(super) with_filters: Vec<String>,
    pub(super) without_filters: Vec<String>,
    pub(super) changed_filters: Vec<String>,
    pub(super) added_filters: Vec<String>,
}

impl QueryEmitPlan {
    pub(super) fn uses_row_iter(&self) -> bool {
        self.is_sparse || !self.changed_filters.is_empty() || !self.added_filters.is_empty()
    }
}

pub(super) struct ChunkLoopInfo {
    pub(super) hdr_bb: BlockId,
    pub(super) query_idx: u32,
    pub(super) chunk_body_bb: BlockId,
    pub(super) exit_bb: BlockId,
    pub(super) is_up_cascade: bool,
    pub(super) is_pset_snap: bool,
    pub(super) loop_blocks: HashSet<BlockId>,
    pub(super) use_par: bool,
}

impl ChunkLoopInfo {
    pub(super) const fn is_1row(&self) -> bool {
        self.is_up_cascade || self.is_pset_snap
    }
}

pub(super) fn build_query_plans(
    func: &MirFunction,
    ctx: &NativeCtx<'_>,
) -> (Vec<QueryEmitPlan>, Vec<UpCascadePlan>) {
    let mut untracked_terms: HashSet<(u32, u32)> = HashSet::new();
    let mut up_plans: Vec<UpCascadePlan> = Vec::new();
    for bb in &func.blocks {
        for st in &bb.stmts {
            match &st.inst {
                Inst::IterColWriteUntracked {
                    query_idx,
                    term_idx,
                    ..
                } => {
                    untracked_terms.insert((*query_idx, *term_idx));
                }
                Inst::IterUpCascade {
                    query_idx,
                    term_idx,
                    ..
                } => {
                    if let Some(qb) = func
                        .query_bindings
                        .iter()
                        .find(|q| q.query_idx == *query_idx)
                        && let Some(term) = qb.terms.iter().find(|t| t.term_idx == *term_idx)
                        && let Some(struct_name) =
                            ctx.resolve_ecs_struct_name(&term.canonical_component)
                    {
                        let canonical = ctx
                            .find_layout_entry(&term.canonical_component)
                            .map_or_else(
                                || term.canonical_component.clone(),
                                |e| e.layout.canonical_name.clone(),
                            );
                        let is_mut = term.mode.is_mutable();
                        if let Some(existing) =
                            up_plans.iter_mut().find(|u| u.canonical == canonical)
                        {
                            existing.is_mut |= is_mut;
                        } else {
                            up_plans.push(UpCascadePlan {
                                param_name: format!("up_q_{}", sanitize_ident(&canonical)),
                                canonical,
                                struct_name,
                                is_mut,
                                param_set_idx: None,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let mut plans = Vec::with_capacity(func.query_bindings.len());
    for qb in &func.query_bindings {
        let mut slots: Vec<DedupTermSlot> = Vec::new();
        let mut term_to_slot = HashMap::new();
        let mut with_filters = Vec::new();
        let mut without_filters = Vec::new();
        let mut changed_filters = Vec::new();
        let mut added_filters = Vec::new();

        for wf in &qb.with_filters {
            if let Some(sname) = ctx.resolve_ecs_struct_name(wf)
                && !with_filters.contains(&sname)
            {
                with_filters.push(sname);
            }
        }
        for wof in &qb.without_filters {
            if let Some(sname) = ctx.resolve_ecs_struct_name(wof)
                && !without_filters.contains(&sname)
            {
                without_filters.push(sname);
            }
        }
        for ct in &func.changed_terms {
            if ct.query_idx == qb.query_idx
                && let Some(sname) = ctx.resolve_ecs_struct_name(&ct.canonical_component)
                && !changed_filters.contains(&sname)
            {
                changed_filters.push(sname);
            }
        }
        if let Some(qdesc) = func.queries.get(qb.query_idx as usize) {
            for cf in &qdesc.changed_filters {
                if let Some(sname) = ctx.resolve_ecs_struct_name(cf)
                    && !changed_filters.contains(&sname)
                {
                    changed_filters.push(sname);
                }
            }
        }
        for at in &func.added_terms {
            if at.query_idx == qb.query_idx
                && let Some(sname) = ctx.resolve_ecs_struct_name(&at.canonical_component)
                && !added_filters.contains(&sname)
            {
                added_filters.push(sname);
            }
        }
        for (qidx, af) in &func.added_filters {
            if *qidx == qb.query_idx
                && let Some(sname) = ctx.resolve_ecs_struct_name(af)
                && !added_filters.contains(&sname)
            {
                added_filters.push(sname);
            }
        }

        let mut is_sparse = false;
        for term in &qb.terms {
            match term.mode {
                TermAccessMode::With => {
                    if let Some(sname) = ctx.resolve_ecs_struct_name(&term.canonical_component) {
                        if let Some(le) = ctx.find_layout_entry(&term.canonical_component)
                            && (le.layout.component_flags
                                & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET)
                                != 0
                        {
                            is_sparse = true;
                        }
                        if !with_filters.contains(&sname) {
                            with_filters.push(sname);
                        }
                    }
                    continue;
                }
                TermAccessMode::Without => {
                    if let Some(sname) = ctx.resolve_ecs_struct_name(&term.canonical_component) {
                        if let Some(le) = ctx.find_layout_entry(&term.canonical_component)
                            && (le.layout.component_flags
                                & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET)
                                != 0
                        {
                            is_sparse = true;
                        }
                        if !without_filters.contains(&sname) {
                            without_filters.push(sname);
                        }
                    }
                    continue;
                }
                _ => {}
            }

            if term.is_sparse {
                is_sparse = true;
            }
            if let Some(le) = ctx.find_layout_entry(&term.canonical_component)
                && (le.layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET) != 0
            {
                is_sparse = true;
            }
            let Some(struct_name) = ctx.resolve_ecs_struct_name(&term.canonical_component) else {
                continue;
            };
            let canonical = ctx
                .find_layout_entry(&term.canonical_component)
                .map_or_else(
                    || term.canonical_component.clone(),
                    |e| e.layout.canonical_name.clone(),
                );

            let term_untracked = untracked_terms.contains(&(qb.query_idx, term.term_idx));
            if let Some(existing_idx) = slots.iter().position(|s| s.canonical == canonical) {
                let merged = merge_term_access_mode(slots[existing_idx].mode, term.mode);
                slots[existing_idx].mode = merged;
                slots[existing_idx].is_untracked |= term_untracked;
                term_to_slot.insert(term.term_idx, existing_idx);
            } else {
                let sidx = slots.len();
                slots.push(DedupTermSlot {
                    slot_idx: sidx,
                    canonical,
                    struct_name,
                    mode: term.mode,
                    is_untracked: term_untracked,
                });
                term_to_slot.insert(term.term_idx, sidx);
            }
        }

        // Check if Entity is referenced for this query, or if all data slots are optional / empty.
        let uses_entities = func.blocks.iter().any(|bb| {
            bb.stmts.iter().any(|s| {
                matches!(
                    s.inst,
                    Inst::IterEntities { query_idx } if query_idx == qb.query_idx
                )
            })
        });
        let all_optional_or_empty = slots.is_empty()
            || slots.iter().all(|s| {
                matches!(
                    s.mode,
                    TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                )
            });
        let needs_entity = !qb.is_point_lookup
            && (uses_entities
                || all_optional_or_empty
                || is_sparse
                || !changed_filters.is_empty()
                || !added_filters.is_empty());
        let has_any_mut = slots.iter().any(|s| s.mode.is_mutable());

        plans.push(QueryEmitPlan {
            query_idx: qb.query_idx,
            param_name: format!("q_{}", qb.query_idx),
            param_set_idx: None,
            is_sparse,
            needs_entity,
            has_any_mut,
            slots,
            term_to_slot,
            with_filters,
            without_filters,
            changed_filters,
            added_filters,
        });
    }

    // Detect conflicting queries (and up_cascade ancestor queries) in the same function (for ParamSet grouping).
    let mut conflicting = vec![false; plans.len()];
    let mut up_conflicting = vec![false; up_plans.len()];
    for i in 0..plans.len() {
        for j in (i + 1)..plans.len() {
            if queries_conflict(&plans[i], &plans[j]) {
                conflicting[i] = true;
                conflicting[j] = true;
            }
        }
        for u in 0..up_plans.len() {
            if plans[i].slots.iter().any(|s| {
                s.struct_name == up_plans[u].struct_name
                    && (s.mode.is_mutable() || up_plans[u].is_mut)
            }) {
                conflicting[i] = true;
                up_conflicting[u] = true;
            }
        }
    }
    let mut pset_idx = 0usize;
    for i in 0..plans.len() {
        if conflicting[i] {
            plans[i].param_set_idx = Some(pset_idx);
            let is_pt = func
                .query_bindings
                .iter()
                .find(|qb| qb.query_idx == plans[i].query_idx)
                .is_some_and(|qb| qb.is_point_lookup);
            if !is_pt {
                plans[i].needs_entity = true;
            }
            pset_idx += 1;
        }
    }
    for u in 0..up_plans.len() {
        if up_conflicting[u] {
            up_plans[u].param_set_idx = Some(pset_idx);
            pset_idx += 1;
        }
    }

    (plans, up_plans)
}

pub(super) fn queries_conflict(a: &QueryEmitPlan, b: &QueryEmitPlan) -> bool {
    let a_with: HashSet<&str> = a.with_filters.iter().map(String::as_str).collect();
    let a_without: HashSet<&str> = a.without_filters.iter().map(String::as_str).collect();
    let b_with: HashSet<&str> = b.with_filters.iter().map(String::as_str).collect();
    let b_without: HashSet<&str> = b.without_filters.iter().map(String::as_str).collect();
    if !a_with.is_disjoint(&b_without) || !b_with.is_disjoint(&a_without) {
        return false;
    }
    for sa in &a.slots {
        for sb in &b.slots {
            if sa.struct_name == sb.struct_name && (sa.mode.is_mutable() || sb.mode.is_mutable()) {
                return true;
            }
        }
    }
    false
}

pub(super) fn merge_term_access_mode(a: TermAccessMode, b: TermAccessMode) -> TermAccessMode {
    if a == b {
        return a;
    }
    match (a, b) {
        (TermAccessMode::Write, _) | (_, TermAccessMode::Write) => TermAccessMode::Write,
        (TermAccessMode::SelectiveWrite, _) | (_, TermAccessMode::SelectiveWrite) => {
            TermAccessMode::SelectiveWrite
        }
        (TermAccessMode::Read, _) | (_, TermAccessMode::Read) => TermAccessMode::Read,
        (TermAccessMode::OptionalWrite, _) | (_, TermAccessMode::OptionalWrite) => {
            TermAccessMode::OptionalWrite
        }
        _ => a,
    }
}

pub(super) fn query_rust_types(plan: &QueryEmitPlan) -> (String, String) {
    let mut d_parts = Vec::new();
    if plan.needs_entity {
        d_parts.push("Entity".to_owned());
    }
    for slot in &plan.slots {
        let s = match slot.mode {
            TermAccessMode::Write | TermAccessMode::SelectiveWrite => {
                format!("&'static mut {}", slot.struct_name)
            }
            TermAccessMode::Read => format!("&'static {}", slot.struct_name),
            TermAccessMode::OptionalWrite => format!("Option<&'static mut {}>", slot.struct_name),
            TermAccessMode::OptionalRead => format!("Option<&'static {}>", slot.struct_name),
            _ => continue,
        };
        d_parts.push(s);
    }
    let data_ty = if d_parts.is_empty() {
        "Entity".to_owned()
    } else {
        format!("({},)", d_parts.join(", "))
    };
    let mut f_parts = Vec::new();
    for wf in &plan.with_filters {
        f_parts.push(format!("With<{wf}>"));
    }
    for wof in &plan.without_filters {
        f_parts.push(format!("Without<{wof}>"));
    }
    for cf in &plan.changed_filters {
        f_parts.push(format!("Changed<{cf}>"));
    }
    for af in &plan.added_filters {
        f_parts.push(format!("Added<{af}>"));
    }
    let filter_ty = if f_parts.is_empty() {
        "()".to_owned()
    } else {
        format!("({},)", f_parts.join(", "))
    };
    (data_ty, filter_ty)
}

pub(super) fn resolve_spatial_name(ctx: &NativeCtx<'_>, func: &MirFunction, raw: &str) -> String {
    if ctx.spatial_by_key.contains_key(raw) {
        return raw.to_owned();
    }
    for rb in &func.resources {
        if (rb.param_name == raw || rb.resource_name == raw || rb.canonical_name == raw)
            && ctx.spatial_by_key.contains_key(rb.resource_name.as_str())
        {
            return rb.resource_name.clone();
        }
    }
    if let Some(sp) = ctx.spatial_by_key.values().find(|sp| {
        sp.resource_layout.canonical_name == raw
            || sp.resource_layout.canonical_name.rsplit("::").next() == Some(raw)
    }) {
        return sp.name.clone();
    }
    raw.to_owned()
}

pub(super) fn projected_field_for_term(
    func: &MirFunction,
    query_idx: u32,
    term_idx: u32,
    ctx: &NativeCtx<'_>,
) -> Option<(String, String, ValTy)> {
    let qb = func
        .query_bindings
        .iter()
        .find(|q| q.query_idx == query_idx)?;
    let term = qb.terms.iter().find(|t| t.term_idx == term_idx)?;
    let pf = term.field_name.as_ref()?;
    let sf = ctx.resolve_field_info(&term.canonical_component, pf)?;
    let vt = ValTy::from_solved_field(sf, ctx);
    Some((term.canonical_component.clone(), pf.clone(), vt))
}

pub(super) fn compute_reachable_blocks(func: &MirFunction) -> HashSet<BlockId> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    if let Some(entry) = func.blocks.first() {
        visited.insert(entry.id);
        queue.push_back(entry.id);
    }
    while let Some(bid) = queue.pop_front() {
        if let Some(bb) = func.blocks.iter().find(|b| b.id == bid) {
            for succ in terminator_succs(&bb.terminator) {
                if visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
    }
    visited
}

pub(super) fn helper_is_par_unsafe(
    callee: &str,
    ctx: &NativeCtx<'_>,
    visited: &mut HashSet<String>,
) -> bool {
    let Some(hf) = ctx.helpers_by_key.get(callee).copied().or_else(|| {
        let short = callee.rsplit("::").next().unwrap_or(callee);
        ctx.mir
            .fns
            .iter()
            .find(|f| f.name == callee || f.name.rsplit("::").next() == Some(short))
    }) else {
        return false;
    };
    if !visited.insert(hf.name.clone()) {
        return false;
    }
    if hf.params.iter().any(|p| p.kind == HirParamKind::ResWrite)
        || hf.resources.iter().any(|r| r.mutable)
    {
        return true;
    }
    for hbb in &hf.blocks {
        for hs in &hbb.stmts {
            match &hs.inst {
                Inst::ResWrite { .. }
                | Inst::CmdSpawn { .. }
                | Inst::CmdSpawnBatch { .. }
                | Inst::SpawnBatchBegin { .. }
                | Inst::SpawnBatchPush { .. }
                | Inst::SpawnBatchCommit { .. }
                | Inst::CmdDespawn { .. }
                | Inst::CmdDespawnAll { .. }
                | Inst::CmdInsert { .. }
                | Inst::CmdRemove { .. }
                | Inst::CmdTrigger { .. }
                | Inst::StreamEmit { .. }
                | Inst::CmdCheckpoint
                | Inst::CmdRollback { .. }
                | Inst::CmdInsertRelation { .. }
                | Inst::CmdRemoveRelation { .. }
                | Inst::EntityGet { .. }
                | Inst::EntityGetMut { .. }
                | Inst::ResolveNamedObject { .. }
                | Inst::BindNamedObject { .. }
                | Inst::IterCount { .. }
                | Inst::IterUpCascade { .. }
                | Inst::IterReset { .. }
                | Inst::IterNextChunk { .. }
                | Inst::ParForEachChunk { .. }
                | Inst::ParForEachChunkReadonly { .. }
                | Inst::SpatialRebuildCsr { .. }
                | Inst::SpatialCsrBegin { .. }
                | Inst::SpatialCsrCount { .. }
                | Inst::SpatialCsrPrefixSum { .. }
                | Inst::SpatialCsrScatter { .. }
                | Inst::SpatialQueryDisc { .. }
                | Inst::SpatialQuerySegmentAt { .. }
                | Inst::ShadowWrite { .. }
                | Inst::ShadowCommit { .. }
                | Inst::FsmDispatch { .. }
                | Inst::TaskStep { .. } => return true,
                Inst::Call { callee: nested, .. } if helper_is_par_unsafe(nested, ctx, visited) => {
                    return true;
                }
                _ => {}
            }
        }
    }
    false
}

pub(super) fn collect_chunk_loops(
    func: &MirFunction,
    ctx: &NativeCtx<'_>,
    query_plans: &[QueryEmitPlan],
    up_plans: &[UpCascadePlan],
) -> Vec<ChunkLoopInfo> {
    let reachable = compute_reachable_blocks(func);
    let mut chunk_hdr_else: HashMap<BlockId, BlockId> = HashMap::new();
    for bb in &func.blocks {
        if !reachable.contains(&bb.id) {
            continue;
        }
        let has_next = bb
            .stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::IterNextChunk { .. }));
        if has_next && let Terminator::Branch { else_bb, .. } = bb.terminator {
            chunk_hdr_else.insert(bb.id, else_bb);
        }
    }
    let mut loops = Vec::new();
    for bb in &func.blocks {
        if !reachable.contains(&bb.id) {
            continue;
        }
        let found = bb.stmts.iter().find_map(|s| match &s.inst {
            Inst::IterNextChunk { query_idx } => Some((*query_idx, s.dst)),
            _ => None,
        });
        let Some((query_idx, _)) = found else {
            continue;
        };
        let Terminator::Branch {
            then_bb, else_bb, ..
        } = bb.terminator
        else {
            continue;
        };

        let mut loop_blocks = HashSet::new();
        let mut queue = VecDeque::new();
        let mut has_nested_loop = false;
        loop_blocks.insert(then_bb);
        queue.push_back(then_bb);
        while let Some(cur) = queue.pop_front() {
            if cur != bb.id
                && let Some(&inner_exit) = chunk_hdr_else.get(&cur)
            {
                has_nested_loop = true;
                if inner_exit != bb.id && inner_exit != else_bb && loop_blocks.insert(inner_exit) {
                    queue.push_back(inner_exit);
                }
                continue;
            }
            for succ in terminator_succs(&func.blocks[cur.0 as usize].terminator) {
                if succ != bb.id && succ != else_bb && loop_blocks.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }

        // Also compute full transitive sub-blocks for ParamSet / @par safety analysis.
        let mut deep_blocks = HashSet::new();
        let mut deep_q = VecDeque::new();
        deep_blocks.insert(then_bb);
        deep_q.push_back(then_bb);
        while let Some(cur) = deep_q.pop_front() {
            for succ in terminator_succs(&func.blocks[cur.0 as usize].terminator) {
                if succ != bb.id && succ != else_bb && deep_blocks.insert(succ) {
                    deep_q.push_back(succ);
                }
            }
        }

        let plan = query_plans.iter().find(|p| p.query_idx == query_idx);
        let is_sparse = plan.is_some_and(|p| p.is_sparse);
        let has_changed =
            plan.is_some_and(|p| !p.changed_filters.is_empty() || !p.added_filters.is_empty());
        let in_param_set = plan.is_some_and(|p| p.param_set_idx.is_some());
        let has_pset_up_cascade = !up_plans.is_empty()
            && up_plans.iter().any(|u| u.param_set_idx.is_some())
            && deep_blocks.iter().any(|bid| {
                func.blocks[bid.0 as usize]
                    .stmts
                    .iter()
                    .any(|s| matches!(s.inst, Inst::IterUpCascade { .. }))
            });
        let is_pset_snap = in_param_set
            && (has_pset_up_cascade
                || deep_blocks.iter().any(|bid| {
                    func.blocks[bid.0 as usize]
                        .stmts
                        .iter()
                        .any(|s| match s.inst {
                            Inst::EntityGet { query_idx: q2, .. }
                            | Inst::EntityGetMut { query_idx: q2, .. }
                            | Inst::IterNextChunk { query_idx: q2 }
                                if q2 != query_idx =>
                            {
                                query_plans
                                    .iter()
                                    .find(|p| p.query_idx == q2)
                                    .is_some_and(|p| p.param_set_idx.is_some())
                            }
                            _ => false,
                        })
                }));
        let has_unsupported_par_write = has_non_reducible_outer_slot_write(func, &loop_blocks);
        let has_unsafe_par_inst = has_nested_loop
            || loop_blocks.iter().any(|bid| {
                func.blocks[bid.0 as usize]
                    .stmts
                    .iter()
                    .any(|s| match &s.inst {
                        Inst::ResWrite { .. }
                        | Inst::CmdCheckpoint
                        | Inst::CmdRollback { .. }
                        | Inst::CmdInsertRelation { .. }
                        | Inst::CmdRemoveRelation { .. }
                        | Inst::IterUpCascade { .. }
                        | Inst::EntityGetMut { .. }
                        | Inst::BindNamedObject { .. }
                        | Inst::SpatialRebuildCsr { .. }
                        | Inst::SpatialCsrBegin { .. }
                        | Inst::SpatialCsrCount { .. }
                        | Inst::SpatialCsrPrefixSum { .. }
                        | Inst::SpatialCsrScatter { .. }
                        | Inst::ShadowWrite { .. }
                        | Inst::ShadowCommit { .. }
                        | Inst::TaskStep { .. }
                        | Inst::FsmDispatch { .. } => true,
                        Inst::Call { callee, .. } => {
                            helper_is_par_unsafe(callee, ctx, &mut HashSet::new())
                        }
                        _ => false,
                    })
            });
        let use_par = func.par_chunk.is_some()
            && !is_sparse
            && !has_changed
            && !in_param_set
            && !has_unsupported_par_write
            && !has_unsafe_par_inst;

        loops.push(ChunkLoopInfo {
            hdr_bb: bb.id,
            query_idx,
            chunk_body_bb: then_bb,
            exit_bb: else_bb,
            is_up_cascade: false,
            is_pset_snap,
            loop_blocks,
            use_par,
        });
    }
    loops
}

pub(super) fn has_non_reducible_outer_slot_write(
    func: &MirFunction,
    loop_blocks: &HashSet<BlockId>,
) -> bool {
    let mut inner_slots = HashSet::new();
    let mut reduce_slots = HashSet::new();
    let mut reduce_locals = HashSet::new();

    for &bid in loop_blocks {
        for s in &func.blocks[bid.0 as usize].stmts {
            if let Inst::SlotAlloc { .. } = s.inst
                && let Some(d) = s.dst
            {
                inner_slots.insert(d);
            }
            if let Inst::ReduceAccum { .. } = s.inst
                && let Some(d) = s.dst
            {
                reduce_locals.insert(d);
            }
        }
    }
    for &bid in loop_blocks {
        for s in &func.blocks[bid.0 as usize].stmts {
            if let Inst::SlotStore { slot, val } = s.inst
                && !inner_slots.contains(&slot)
            {
                if reduce_locals.contains(&val) {
                    reduce_slots.insert(slot);
                } else {
                    return true;
                }
            }
        }
    }
    let _ = reduce_slots;
    false
}

pub(super) fn terminator_succs(term: &Terminator) -> Vec<BlockId> {
    match term {
        Terminator::Return(_) => Vec::new(),
        Terminator::Goto(b) => vec![*b],
        Terminator::Branch {
            then_bb, else_bb, ..
        } => vec![*then_bb, *else_bb],
        Terminator::Switch {
            cases, default_bb, ..
        } => {
            let mut out: Vec<BlockId> = cases.iter().map(|(_, b)| *b).collect();
            out.push(*default_bb);
            out
        }
    }
}

#[derive(Clone)]
pub(super) struct SpawnBatchCompSlot {
    pub(super) struct_name: String,
    pub(super) is_zst: bool,
}

#[derive(Clone)]
pub(super) struct SpawnBatchPlan {
    pub(super) id: usize,
    pub(super) dst_local: LocalId,
    pub(super) slots: Vec<SpawnBatchCompSlot>,
    pub(super) bundle_ty: String,
    pub(super) var_name: String,
    pub(super) only_chunk_loop: Option<usize>,
}

pub(super) fn is_child_of_relation(rel: &str) -> bool {
    rel == "ChildOf" || rel.rsplit("::").next() == Some("ChildOf")
}

pub(super) fn resolve_custom_relation_name<'a>(ctx: &'a NativeCtx<'a>, raw: &'a str) -> &'a str {
    let short = raw.rsplit("::").next().unwrap_or(raw);
    ctx.mir
        .relations
        .iter()
        .find(|r| r.name == raw || r.name.rsplit("::").next() == Some(short))
        .map_or(raw, |r| r.name.as_str())
}

pub(super) fn collect_helper_implicit_res(
    callee: &str,
    ctx: &NativeCtx<'_>,
    out: &mut BTreeMap<String, (String, bool, String)>,
    visited: &mut HashSet<String>,
) {
    let Some(hf) = ctx.helpers_by_key.get(callee).copied().or_else(|| {
        let short = callee.rsplit("::").next().unwrap_or(callee);
        ctx.mir
            .fns
            .iter()
            .find(|f| f.name == callee || f.name.rsplit("::").next() == Some(short))
    }) else {
        return;
    };
    if !visited.insert(hf.name.clone()) {
        return;
    }
    for hbb in &hf.blocks {
        for hs in &hbb.stmts {
            match &hs.inst {
                Inst::ResRead { resource } | Inst::ResWrite { resource } => {
                    let is_mut = matches!(hs.inst, Inst::ResWrite { .. });
                    if let Some(entry) = ctx.find_layout_entry(resource) {
                        let vname = format!("res_{}", sanitize_ident(&entry.layout.canonical_name));
                        out.entry(entry.layout.canonical_name.clone())
                            .and_modify(|v| v.1 |= is_mut)
                            .or_insert((vname, is_mut, entry.struct_name.clone()));
                    }
                }
                Inst::Call { callee: nested, .. } => {
                    collect_helper_implicit_res(nested, ctx, out, visited);
                }
                _ => {}
            }
        }
    }
}

pub(super) struct FnAnalysis {
    pub(super) val_tys: Vec<ValTy>,
    pub(super) slot_tys: HashMap<LocalId, ValTy>,
    pub(super) ptr_targets: HashMap<LocalId, PtrTarget>,
    pub(super) const_floats: HashMap<LocalId, f64>,
    pub(super) array_inits: HashMap<LocalId, Vec<LocalId>>,
    pub(super) array_ptr_locals: HashSet<LocalId>,
    pub(super) res_map: BTreeMap<String, (String, bool, String)>, // canonical -> (var_name, mutable, struct_name)
    pub(super) implicit_res_map: BTreeMap<String, (String, bool, String)>, // canonical -> (var_name, mutable, struct_name)
    pub(super) spatial_res_map: BTreeMap<String, (String, bool)>, // index_name -> (var_name, mutable)
    pub(super) relation_res_map: BTreeMap<String, (String, bool)>, // rel_name -> (var_name, mutable)
    pub(super) stream_writers: BTreeMap<String, String>,           // stream_name -> writer_var
    pub(super) stream_readers: Vec<(String, String, String)>,      // (mr_var, struct_name, arg_var)
    pub(super) needs_commands: bool,
    pub(super) needs_par_commands: bool,
    pub(super) needs_named_objects: bool,
    pub(super) named_objects_mut: bool,
    pub(super) object_queries: BTreeMap<String, (String, String)>, // obj_name -> (q_var, primary_comp_struct)
    pub(super) needs_trigger_stack: bool,
    pub(super) needs_child_of_query: bool,
    pub(super) has_checkpoint: bool,
    pub(super) sp_lim_clamp: HashMap<LocalId, LocalId>, // sp_lim ConstInt(64) -> query_iter LocalId
    pub(super) up_cascade_locals: HashSet<LocalId>,
    pub(super) up_cascade_slots: HashSet<LocalId>,
    pub(super) field_ptr_array_meta: HashMap<LocalId, (Ty, usize, usize, bool, usize)>,
    pub(super) smallvec_ptr_meta: HashMap<LocalId, (Ty, usize, usize, usize)>,
    pub(super) spawn_batches: Vec<SpawnBatchPlan>,
    pub(super) batch_sources: HashMap<LocalId, BTreeSet<usize>>,
}

pub(super) fn analyze_function(
    func: &MirFunction,
    ctx: &NativeCtx<'_>,
    query_plans: &[QueryEmitPlan],
    up_plans: &[UpCascadePlan],
    chunk_loops: &[ChunkLoopInfo],
) -> FnAnalysis {
    let mut val_tys: Vec<ValTy> = func
        .locals
        .iter()
        .map(|l| ValTy::from_mir(&l.ty, ctx))
        .collect();
    let mut slot_tys: HashMap<LocalId, ValTy> = HashMap::new();
    let mut ptr_targets: HashMap<LocalId, PtrTarget> = HashMap::new();
    let mut def_counts = vec![0usize; func.locals.len()];
    for bb in &func.blocks {
        for st in &bb.stmts {
            if let Some(d) = st.dst
                && (d.0 as usize) < def_counts.len()
            {
                def_counts[d.0 as usize] += 1;
            }
        }
    }
    let mut const_floats: HashMap<LocalId, f64> = HashMap::new();
    let mut array_inits: HashMap<LocalId, Vec<LocalId>> = HashMap::new();
    let mut const_string_locals: HashSet<LocalId> = HashSet::new();
    let mut array_ptr_locals: HashSet<LocalId> = HashSet::new();
    for _ in 0..3 {
        for bb in &func.blocks {
            for st in &bb.stmts {
                let Some(d) = st.dst else { continue };
                if (d.0 as usize) >= def_counts.len() || def_counts[d.0 as usize] != 1 {
                    continue;
                }
                match &st.inst {
                    Inst::ConstFloat { value } => {
                        const_floats.insert(d, *value);
                    }
                    Inst::ConstString { .. } => {
                        const_string_locals.insert(d);
                    }
                    Inst::UnOp { op, val } if op == "-" => {
                        if let Some(&v) = const_floats.get(val) {
                            const_floats.insert(d, -v);
                        }
                    }
                    Inst::Copy { val } => {
                        if let Some(&v) = const_floats.get(val) {
                            const_floats.insert(d, v);
                        }
                        if let Some(elems) = array_inits.get(val).cloned() {
                            array_inits.insert(d, elems);
                        }
                        if const_string_locals.contains(val) {
                            const_string_locals.insert(d);
                        }
                    }
                    Inst::ArrayInit { elems } => {
                        array_inits.insert(d, elems.clone());
                    }
                    _ => {}
                }
            }
        }
    }
    let reachable_blocks = compute_reachable_blocks(func);
    let mut spawn_batches: Vec<SpawnBatchPlan> = Vec::new();
    let mut batch_sources: HashMap<LocalId, BTreeSet<usize>> = HashMap::new();

    // Pre-populate resources, params, streams, commands.
    let mut res_map: BTreeMap<String, (String, bool, String)> = BTreeMap::new();
    let mut implicit_res_map: BTreeMap<String, (String, bool, String)> = BTreeMap::new();
    let mut spatial_res_map: BTreeMap<String, (String, bool)> = BTreeMap::new();
    let mut relation_res_map: BTreeMap<String, (String, bool)> = BTreeMap::new();
    let mut stream_writers: BTreeMap<String, String> = BTreeMap::new();
    let mut stream_readers: Vec<(String, String, String)> = Vec::new();
    let mut needs_commands = false;
    let has_par_loop = chunk_loops.iter().any(|c| c.use_par);
    let mut needs_named_objects = false;
    let mut named_objects_mut = false;
    let mut object_queries: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut needs_trigger_stack = false;
    let mut needs_child_of_query = false;
    let mut has_checkpoint = false;
    let mut up_cascade_locals: HashSet<LocalId> = HashSet::new();
    let mut up_cascade_slots: HashSet<LocalId> = HashSet::new();
    let mut field_ptr_array_meta: HashMap<LocalId, (Ty, usize, usize, bool, usize)> =
        HashMap::new();
    let mut smallvec_ptr_meta: HashMap<LocalId, (Ty, usize, usize, usize)> = HashMap::new();
    let mut slot_row_targets: HashMap<LocalId, PtrTarget> = HashMap::new();
    let mut slot_up_targets: HashMap<LocalId, (String, String, bool)> = HashMap::new();

    for rb in &func.resources {
        if let Some(entry) = ctx.find_layout_entry(&rb.canonical_name) {
            let vname = format!("res_{}", sanitize_ident(&entry.layout.canonical_name));
            let prev = res_map
                .get(&entry.layout.canonical_name)
                .map(|v| v.1)
                .unwrap_or(false);
            res_map.insert(
                entry.layout.canonical_name.clone(),
                (vname.clone(), prev || rb.mutable, entry.struct_name.clone()),
            );
            ptr_targets.insert(rb.ptr_local, PtrTarget::Resource { var_name: vname });
        }
    }

    let mut stream_read_idx = 0usize;
    for (param_idx, p) in func.params.iter().enumerate() {
        if let Some(pl) = p.local {
            match p.kind {
                HirParamKind::Ref | HirParamKind::RefMut => {
                    let layout_key = p.layout_key.clone().unwrap_or_else(|| match &p.ty {
                        MirType::Named(n) => n.clone(),
                        _ => String::new(),
                    });
                    let projected = if let Some((comp_key, field_path)) = layout_key.split_once('.')
                    {
                        ctx.resolve_field_info(comp_key, field_path).map(|sf| {
                            (
                                comp_key.to_owned(),
                                field_path.to_owned(),
                                ValTy::from_solved_field(sf, ctx),
                            )
                        })
                    } else if matches!(func.kind, MirFnKind::HelperFn) {
                        infer_projected_helper_param_ty(func, param_idx, pl, &layout_key, ctx)
                            .map(|fvt| (layout_key.clone(), "__proj".to_owned(), fvt))
                    } else {
                        None
                    };
                    ptr_targets.insert(
                        pl,
                        PtrTarget::ParamPtr {
                            var_name: format!("arg_{}", sanitize_rust_ident(&p.name)),
                            layout_key,
                            projected,
                        },
                    );
                }
                HirParamKind::StreamIn => {
                    let arg_var = format!("arg_{}", sanitize_rust_ident(&p.name));
                    let mr_var = format!("mr_{}", sanitize_rust_ident(&p.name));
                    let stream_op = func
                        .stream_ops
                        .iter()
                        .filter(|op| op.kind == MirStreamOpKind::StreamRead)
                        .nth(stream_read_idx);
                    stream_read_idx += 1;
                    let mut layout_key = match &p.ty {
                        MirType::Named(n) => n.clone(),
                        _ => String::new(),
                    };
                    if let Some(op) = stream_op
                        && let Some(entry) = ctx
                            .find_layout_entry(&op.canonical_stream)
                            .or_else(|| ctx.find_layout_entry(&op.stream))
                    {
                        layout_key = entry.layout.canonical_name.clone();
                        stream_readers.push((mr_var, entry.struct_name.clone(), arg_var.clone()));
                    } else if let Some(entry) = ctx.find_layout_entry(&layout_key) {
                        stream_readers.push((mr_var, entry.struct_name.clone(), arg_var.clone()));
                    }
                    ptr_targets.insert(
                        pl,
                        PtrTarget::ParamPtr {
                            var_name: arg_var,
                            layout_key,
                            projected: None,
                        },
                    );
                }
                HirParamKind::ResRead | HirParamKind::ResWrite => {
                    if matches!(func.kind, MirFnKind::HelperFn) {
                        ptr_targets.insert(
                            pl,
                            PtrTarget::ParamPtr {
                                var_name: format!("arg_{}", sanitize_rust_ident(&p.name)),
                                layout_key: match &p.ty {
                                    MirType::Named(n) => n.clone(),
                                    _ => String::new(),
                                },
                                projected: None,
                            },
                        );
                    }
                }
                _ => {}
            }
        }
    }

    let par_blocks: HashSet<BlockId> = chunk_loops
        .iter()
        .filter(|c| c.use_par)
        .flat_map(|c| c.loop_blocks.iter().copied())
        .collect();

    for bb in &func.blocks {
        let in_par = par_blocks.contains(&bb.id);
        for st in &bb.stmts {
            match &st.inst {
                Inst::SlotAlloc { ty } => {
                    if let Some(d) = st.dst {
                        slot_tys.insert(d, ValTy::from_mir(ty, ctx));
                        if !matches!(ty, MirType::Ptr | MirType::MutPtr) {
                            ptr_targets.insert(d, PtrTarget::SlotRef { slot_local: d });
                        }
                    }
                }
                Inst::ResRead { resource } | Inst::ResWrite { resource } => {
                    let is_mut = matches!(st.inst, Inst::ResWrite { .. });
                    if let Some(entry) = ctx.find_layout_entry(resource) {
                        let vname = format!("res_{}", sanitize_ident(&entry.layout.canonical_name));
                        let prev = res_map
                            .get(&entry.layout.canonical_name)
                            .map(|v| v.1)
                            .unwrap_or(false);
                        res_map.insert(
                            entry.layout.canonical_name.clone(),
                            (vname.clone(), prev || is_mut, entry.struct_name.clone()),
                        );
                        let prev_imp = implicit_res_map
                            .get(&entry.layout.canonical_name)
                            .map(|v| v.1)
                            .unwrap_or(false);
                        implicit_res_map.insert(
                            entry.layout.canonical_name.clone(),
                            (vname.clone(), prev_imp || is_mut, entry.struct_name.clone()),
                        );
                        if let Some(d) = st.dst {
                            ptr_targets.insert(d, PtrTarget::Resource { var_name: vname });
                        }
                    }
                }
                Inst::Call { callee, .. } => {
                    let mut hres = BTreeMap::new();
                    collect_helper_implicit_res(callee, ctx, &mut hres, &mut HashSet::new());
                    for (canon, (vname, is_mut, sname)) in hres {
                        let prev = res_map.get(&canon).map(|v| v.1).unwrap_or(false);
                        res_map.insert(
                            canon.clone(),
                            (vname.clone(), prev || is_mut, sname.clone()),
                        );
                        let prev_imp = implicit_res_map.get(&canon).map(|v| v.1).unwrap_or(false);
                        implicit_res_map.insert(canon, (vname, prev_imp || is_mut, sname));
                    }
                }
                Inst::SpatialRebuildCsr { index_name, .. }
                | Inst::SpatialCsrBegin { index_name }
                | Inst::SpatialCsrCount { index_name, .. }
                | Inst::SpatialCsrPrefixSum { index_name }
                | Inst::SpatialCsrScatter { index_name, .. } => {
                    let resolved = resolve_spatial_name(ctx, func, index_name);
                    let vname = format!("sp_res_{}", sanitize_ident(&resolved));
                    spatial_res_map.insert(resolved, (vname, true));
                }
                Inst::SpatialQueryDisc { grid_name, .. } => {
                    let resolved = resolve_spatial_name(ctx, func, grid_name);
                    let vname = format!("sp_res_{}", sanitize_ident(&resolved));
                    spatial_res_map.entry(resolved).or_insert((vname, false));
                }
                Inst::SpatialQuerySegmentAt { history_name, .. } => {
                    let resolved = resolve_spatial_name(ctx, func, history_name);
                    let vname = format!("sp_res_{}", sanitize_ident(&resolved));
                    spatial_res_map.entry(resolved).or_insert((vname, false));
                }
                Inst::CmdInsertRelation { relation, .. }
                | Inst::CmdRemoveRelation { relation, .. } => {
                    if is_child_of_relation(relation) {
                        needs_commands = true;
                    } else {
                        let resolved = resolve_custom_relation_name(ctx, relation);
                        let vname = format!("rel_res_{}", sanitize_ident(resolved));
                        relation_res_map.insert(resolved.to_owned(), (vname, true));
                        let short_r = resolved.rsplit("::").next().unwrap_or(resolved);
                        let comp_short = format!("__strata_rel_parent_{short_r}");
                        if ctx.find_layout_entry(&comp_short).is_some() {
                            needs_commands = true;
                        }
                    }
                }
                Inst::IterUpCascade {
                    query_idx,
                    relation,
                    term_idx,
                    ..
                } => {
                    if is_child_of_relation(relation) {
                        needs_child_of_query = true;
                    } else {
                        let short_rel = relation.rsplit("::").next().unwrap_or(relation.as_str());
                        if let Some(rdef) = ctx.mir.relations.iter().find(|r| {
                            r.name == *relation || r.name.rsplit("::").next() == Some(short_rel)
                        }) {
                            let vname = format!("rel_res_{}", sanitize_ident(&rdef.name));
                            relation_res_map
                                .entry(rdef.name.clone())
                                .or_insert((vname, false));
                        } else {
                            needs_child_of_query = true;
                        }
                    }
                    if let Some(d) = st.dst
                        && let Some(qb) = func
                            .query_bindings
                            .iter()
                            .find(|q| q.query_idx == *query_idx)
                        && let Some(term) = qb.terms.iter().find(|t| t.term_idx == *term_idx)
                    {
                        let canon = ctx
                            .find_layout_entry(&term.canonical_component)
                            .map_or_else(
                                || term.canonical_component.clone(),
                                |e| e.layout.canonical_name.clone(),
                            );
                        if let Some(up) = up_plans.iter().find(|u| u.canonical == canon) {
                            let up_q_expr = if let Some(pidx) = up.param_set_idx {
                                format!("q_set.p{pidx}()")
                            } else {
                                up.param_name.clone()
                            };
                            up_cascade_locals.insert(d);
                            ptr_targets.insert(
                                d,
                                PtrTarget::UpCascadeDirect {
                                    up_local: d,
                                    comp_struct: up.struct_name.clone(),
                                    up_q_expr,
                                    is_mut: up.is_mut,
                                },
                            );
                        }
                    }
                }
                Inst::StreamEmit { stream, .. } => {
                    if in_par {
                        needs_commands = true;
                    } else if let Some(entry) = ctx.find_layout_entry(stream) {
                        let mw_name = format!("mw_{}", sanitize_ident(stream));
                        stream_writers.insert(entry.layout.canonical_name.clone(), mw_name);
                    }
                }
                Inst::CmdSpawn { .. }
                | Inst::CmdSpawnBatch { .. }
                | Inst::SpawnBatchCommit { .. }
                | Inst::CmdDespawn { .. }
                | Inst::CmdDespawnAll { .. }
                | Inst::CmdInsert { .. }
                | Inst::CmdRemove { .. }
                | Inst::CmdTrigger { .. } => {
                    needs_commands = true;
                }
                Inst::SpawnBatchBegin { components, .. } => {
                    if reachable_blocks.contains(&bb.id)
                        && let Some(d) = st.dst
                    {
                        let mut slots: Vec<SpawnBatchCompSlot> = Vec::new();
                        for cname in components {
                            if let Some(sname) = ctx.resolve_ecs_struct_name(cname)
                                && !slots.iter().any(|s| s.struct_name == sname)
                            {
                                slots.push(SpawnBatchCompSlot {
                                    struct_name: sname,
                                    is_zst: ctx.is_zst_component(cname),
                                });
                            }
                        }
                        let ty_parts: Vec<String> =
                            slots.iter().map(|s| s.struct_name.clone()).collect();
                        let bundle_ty = format_bundle_tuple(&ty_parts);
                        let id = spawn_batches.len();
                        spawn_batches.push(SpawnBatchPlan {
                            id,
                            dst_local: d,
                            slots,
                            bundle_ty,
                            var_name: format!("__batch_buf_{id}"),
                            only_chunk_loop: None,
                        });
                        batch_sources.entry(d).or_default().insert(id);
                    }
                }
                Inst::CmdCheckpoint => {
                    has_checkpoint = true;
                }
                Inst::ResolveNamedObject { name } | Inst::BindNamedObject { name } => {
                    needs_named_objects = true;
                    if matches!(st.inst, Inst::BindNamedObject { .. }) {
                        named_objects_mut = true;
                    }
                    if let Some(obj) = ctx.objects_by_key.get(name.as_str())
                        && let Some(first_comp) = obj.components.first()
                        && let Some(sname) = ctx.resolve_ecs_struct_name(first_comp)
                    {
                        object_queries.insert(
                            name.clone(),
                            (format!("obj_q_{}", sanitize_ident(name)), sname),
                        );
                    }
                }
                Inst::TriggerTarget => {
                    if let MirFnKind::Observer { ref event, .. } = func.kind
                        && let Some(ev_entry) = ctx.find_layout_entry(event)
                        && !ctx.entity_events.contains(&ev_entry.layout.canonical_name)
                    {
                        needs_trigger_stack = true;
                    }
                }
                _ => {}
            }
        }
    }

    if let MirFnKind::Observer {
        ref event,
        ref target_comp,
    } = func.kind
        && target_comp.is_some()
        && let Some(ev_entry) = ctx.find_layout_entry(event)
        && !ctx.entity_events.contains(&ev_entry.layout.canonical_name)
    {
        needs_trigger_stack = true;
    }

    // Fixed-point propagation for ValTy & PtrTarget across instructions.
    for _ in 0..4 {
        for bb in &func.blocks {
            for st in &bb.stmts {
                match &st.inst {
                    Inst::Copy { val } => {
                        if let Some(d) = st.dst {
                            if matches!(
                                val_tys[d.0 as usize],
                                ValTy::Array(_, _) | ValTy::InlineStr(_) | ValTy::SmallVec { .. }
                            ) && (array_inits.contains_key(val)
                                || const_string_locals.contains(val))
                                && !matches!(
                                    val_tys[val.0 as usize],
                                    ValTy::Array(_, _)
                                        | ValTy::InlineStr(_)
                                        | ValTy::SmallVec { .. }
                                )
                            {
                                val_tys[val.0 as usize] = val_tys[d.0 as usize].clone();
                            } else if !matches!(
                                (ptr_targets.get(val), &val_tys[d.0 as usize]),
                                (Some(PtrTarget::QueryEntityRow { .. }), ValTy::Entity)
                            ) {
                                val_tys[d.0 as usize] = val_tys[val.0 as usize].clone();
                            }
                            if let Some(pt) = ptr_targets.get(val).cloned() {
                                ptr_targets.insert(d, pt);
                            }
                            if let Some(m) = field_ptr_array_meta.get(val).cloned() {
                                field_ptr_array_meta.insert(d, m);
                            }
                            if let Some(sm) = smallvec_ptr_meta.get(val).cloned() {
                                smallvec_ptr_meta.insert(d, sm);
                            }
                            if let Some(srcs) = batch_sources.get(val).cloned() {
                                batch_sources.entry(d).or_default().extend(srcs);
                            }
                        }
                    }
                    Inst::VecInsert { vec, .. } => {
                        if let Some(d) = st.dst {
                            val_tys[d.0 as usize] = val_tys[vec.0 as usize].clone();
                        }
                    }
                    Inst::SlotStore { slot, val } => {
                        if let Some(srcs) = batch_sources.get(val).cloned() {
                            batch_sources.entry(*slot).or_default().extend(srcs);
                        }
                        let vt = &val_tys[val.0 as usize];
                        let is_rich = matches!(
                            vt,
                            ValTy::TableRow(_)
                                | ValTy::Struct(_)
                                | ValTy::Array(_, _)
                                | ValTy::SmallVec { .. }
                                | ValTy::Tuple(_)
                                | ValTy::BitSet(_)
                                | ValTy::InputBuf(_)
                                | ValTy::InlineStr(_)
                                | ValTy::Entity
                                | ValTy::Vec2
                                | ValTy::Vec3
                                | ValTy::Vec4
                                | ValTy::IVec2
                                | ValTy::IVec3
                                | ValTy::UVec2
                        );
                        let cur = slot_tys.get(slot);
                        let keep_existing_arr_or_struct = matches!(
                            cur,
                            Some(
                                ValTy::Array(_, _)
                                    | ValTy::Struct(_)
                                    | ValTy::SmallVec { .. }
                                    | ValTy::InlineStr(_)
                            )
                        );
                        let should_update = (matches!(
                            cur,
                            None | Some(ValTy::Unit | ValTy::PtrMarker | ValTy::U64 | ValTy::I64)
                        ) && *vt != ValTy::Unit
                            && *vt != ValTy::PtrMarker)
                            || (matches!(cur, Some(ValTy::Vec3)) && *vt == ValTy::Vec2)
                            || (!keep_existing_arr_or_struct && is_rich && cur != Some(vt));
                        if should_update {
                            slot_tys.insert(*slot, vt.clone());
                        }
                        if let Some(target_vt @ (ValTy::Array(_, _) | ValTy::InlineStr(_))) =
                            slot_tys.get(slot).cloned()
                            && (array_inits.contains_key(val) || const_string_locals.contains(val))
                        {
                            val_tys[val.0 as usize] = target_vt;
                        }
                        if let Some(pt) = ptr_targets.get(val).cloned() {
                            match pt {
                                PtrTarget::UpCascadeDirect {
                                    comp_struct,
                                    up_q_expr,
                                    is_mut,
                                    ..
                                } => {
                                    up_cascade_slots.insert(*slot);
                                    slot_up_targets.insert(*slot, (comp_struct, up_q_expr, is_mut));
                                }
                                PtrTarget::UpCascadeSlot {
                                    row_target,
                                    comp_struct,
                                    up_q_expr,
                                    is_mut,
                                    ..
                                } => {
                                    up_cascade_slots.insert(*slot);
                                    slot_up_targets.insert(*slot, (comp_struct, up_q_expr, is_mut));
                                    if let Some(rt) = row_target {
                                        slot_row_targets.insert(*slot, *rt);
                                    }
                                }
                                other => {
                                    slot_row_targets.insert(*slot, other);
                                }
                            }
                        }
                    }
                    Inst::SlotLoad { slot } => {
                        if let Some(d) = st.dst {
                            if let Some(srcs) = batch_sources.get(slot).cloned() {
                                batch_sources.entry(d).or_default().extend(srcs);
                            }
                            if let Some(st_ty) = slot_tys.get(slot)
                                && *st_ty != ValTy::Unit
                                && *st_ty != ValTy::PtrMarker
                            {
                                val_tys[d.0 as usize] = st_ty.clone();
                            }
                            if let Some((comp_struct, up_q_expr, is_mut)) =
                                slot_up_targets.get(slot).cloned()
                            {
                                ptr_targets.insert(
                                    d,
                                    PtrTarget::UpCascadeSlot {
                                        slot_local: *slot,
                                        row_target: slot_row_targets
                                            .get(slot)
                                            .cloned()
                                            .map(Box::new),
                                        comp_struct,
                                        up_q_expr,
                                        is_mut,
                                    },
                                );
                            } else if let Some(rt) = slot_row_targets.get(slot).cloned() {
                                ptr_targets.insert(d, rt);
                            }
                        }
                    }
                    Inst::IterEntities { query_idx } => {
                        if let Some(d) = st.dst {
                            ptr_targets.insert(
                                d,
                                PtrTarget::EntitiesSlice {
                                    query_idx: *query_idx,
                                },
                            );
                        }
                    }
                    Inst::IterColRead {
                        query_idx,
                        term_idx,
                        ..
                    }
                    | Inst::IterColWrite {
                        query_idx,
                        term_idx,
                        ..
                    }
                    | Inst::IterColWriteUntracked {
                        query_idx,
                        term_idx,
                        ..
                    }
                    | Inst::IterColRowsRead {
                        query_idx,
                        term_idx,
                        ..
                    }
                    | Inst::IterColRowsWrite {
                        query_idx,
                        term_idx,
                        ..
                    } => {
                        if let Some(d) = st.dst
                            && let Some(qp) = query_plans.iter().find(|p| p.query_idx == *query_idx)
                        {
                            if let Some(&sidx) = qp.term_to_slot.get(term_idx) {
                                let slot = &qp.slots[sidx];
                                let projected =
                                    projected_field_for_term(func, *query_idx, *term_idx, ctx);
                                ptr_targets.insert(
                                    d,
                                    PtrTarget::QueryCol {
                                        query_idx: *query_idx,
                                        slot_idx: sidx,
                                        selective: slot.mode == TermAccessMode::SelectiveWrite
                                            || (slot.mode == TermAccessMode::OptionalWrite
                                                && slot.is_untracked)
                                            || matches!(
                                                st.inst,
                                                Inst::IterColWriteUntracked { .. }
                                            ),
                                        optional: matches!(
                                            slot.mode,
                                            TermAccessMode::OptionalRead
                                                | TermAccessMode::OptionalWrite
                                        ),
                                        is_sparse: qp.uses_row_iter(),
                                        projected,
                                    },
                                );
                            } else if let Some(qb) = func
                                .query_bindings
                                .iter()
                                .find(|q| q.query_idx == *query_idx)
                                && let Some(term) =
                                    qb.terms.iter().find(|t| t.term_idx == *term_idx)
                                && (term.canonical_component == "Entity"
                                    || term.storage_key == "Entity"
                                    || term.canonical_component.ends_with("::Entity"))
                            {
                                ptr_targets.insert(
                                    d,
                                    PtrTarget::QueryEntityCol {
                                        query_idx: *query_idx,
                                    },
                                );
                            }
                        }
                    }
                    Inst::RowPtr {
                        col_ptr, row_idx, ..
                    } => {
                        if let Some(d) = st.dst {
                            match ptr_targets.get(col_ptr).cloned() {
                                Some(PtrTarget::QueryCol {
                                    query_idx,
                                    slot_idx,
                                    selective,
                                    optional,
                                    is_sparse,
                                    projected,
                                }) => {
                                    ptr_targets.insert(
                                        d,
                                        PtrTarget::QueryRow {
                                            query_idx,
                                            slot_idx,
                                            row_idx_local: *row_idx,
                                            selective,
                                            optional,
                                            is_sparse,
                                            projected,
                                        },
                                    );
                                }
                                Some(PtrTarget::QueryEntityCol { query_idx }) => {
                                    ptr_targets.insert(
                                        d,
                                        PtrTarget::QueryEntityRow {
                                            query_idx,
                                            row_idx_local: *row_idx,
                                        },
                                    );
                                }
                                _ => {}
                            }
                        }
                    }
                    Inst::EntityGet {
                        query_idx,
                        term_idx,
                        entity,
                        ..
                    }
                    | Inst::EntityGetMut {
                        query_idx,
                        term_idx,
                        entity,
                        ..
                    } => {
                        if let Some(d) = st.dst {
                            val_tys[d.0 as usize] = ValTy::Bool;
                            if let Some(qp) = query_plans.iter().find(|p| p.query_idx == *query_idx)
                                && let Some(&sidx) = qp.term_to_slot.get(term_idx)
                            {
                                let slot = &qp.slots[sidx];
                                let projected =
                                    projected_field_for_term(func, *query_idx, *term_idx, ctx);
                                ptr_targets.insert(
                                    d,
                                    PtrTarget::EntityRow {
                                        query_idx: *query_idx,
                                        slot_idx: sidx,
                                        entity_local: *entity,
                                        optional: matches!(
                                            slot.mode,
                                            TermAccessMode::OptionalRead
                                                | TermAccessMode::OptionalWrite
                                        ),
                                        projected,
                                    },
                                );
                            }
                        }
                    }
                    Inst::TriggerPayload { .. } => {
                        if let Some(d) = st.dst {
                            ptr_targets.insert(d, PtrTarget::TriggerPayload);
                        }
                    }
                    Inst::MigrateSrcPtr { layout_key } => {
                        if let Some(d) = st.dst {
                            ptr_targets.insert(
                                d,
                                PtrTarget::ParamPtr {
                                    var_name: "old_row".to_owned(),
                                    layout_key: layout_key.clone(),
                                    projected: None,
                                },
                            );
                        }
                    }
                    Inst::MigrateDstPtr { layout_key } => {
                        if let Some(d) = st.dst {
                            ptr_targets.insert(
                                d,
                                PtrTarget::ParamPtr {
                                    var_name: "dst_row".to_owned(),
                                    layout_key: layout_key.clone(),
                                    projected: None,
                                },
                            );
                        }
                    }
                    Inst::FieldPtr {
                        base_ptr,
                        layout_key,
                        field,
                        ..
                    } => {
                        if let Some(d) = st.dst {
                            let mut cur_target =
                                ptr_targets
                                    .get(base_ptr)
                                    .cloned()
                                    .unwrap_or(PtrTarget::SlotRef {
                                        slot_local: *base_ptr,
                                    });
                            if layout_key == "SmallVec" && field == "data" {
                                let sv_meta =
                                    smallvec_ptr_meta.get(base_ptr).cloned().or_else(|| {
                                        let sv_vt = match &cur_target {
                                            PtrTarget::SlotRef { slot_local } => {
                                                slot_tys.get(slot_local)
                                            }
                                            _ => Some(&val_tys[base_ptr.0 as usize]),
                                        };
                                        if let Some(ValTy::SmallVec {
                                            elem,
                                            cap,
                                            elem_size,
                                            elem_align,
                                        }) = sv_vt
                                        {
                                            Some((
                                                val_ty_to_sema_hint(elem),
                                                *elem_size,
                                                *elem_align,
                                                *cap,
                                            ))
                                        } else {
                                            None
                                        }
                                    });
                                ptr_targets.insert(d, cur_target);
                                if let Some((et, es, ea, cap)) = sv_meta {
                                    field_ptr_array_meta.insert(d, (et, es, ea, true, cap));
                                }
                            } else {
                                let eff_lk = if !layout_key.is_empty() {
                                    layout_key.as_str()
                                } else if let PtrTarget::ArrayElem {
                                    elem_ty: Ty::Named(ref n),
                                    ..
                                } = cur_target
                                {
                                    n.as_str()
                                } else {
                                    ""
                                };
                                let mut cur_entry_opt = ctx.find_layout_entry(eff_lk);
                                let mut leaf_sf_opt: Option<&SolvedField> = None;
                                for part in field.split('.') {
                                    let sf_opt = cur_entry_opt.as_ref().and_then(|e| {
                                        e.layout.fields.iter().find(|f| f.name == part)
                                    });
                                    let mut next_entry_opt = None;
                                    let blob_step = sf_opt.and_then(|sf| {
                                        if let Ty::Named(ref inner_key) = sf.ty
                                            && let Some(inner_entry) =
                                                ctx.find_layout_entry(inner_key)
                                            && inner_entry.layout.item_kind != SchemaItemKind::Enum
                                            && inner_entry.layout.size > 0
                                            && !inner_entry.layout.fields.is_empty()
                                        {
                                            next_entry_opt = Some(inner_entry);
                                            let blob_ty = rust_abi_type_for_field(sf, ctx.mir);
                                            Some((
                                                sanitize_rust_ident(part),
                                                inner_entry.struct_name.clone(),
                                                blob_unpack_method_for_blob_ty(&blob_ty),
                                                blob_pack_method_for_blob_ty(&blob_ty),
                                            ))
                                        } else {
                                            None
                                        }
                                    });
                                    cur_target = PtrTarget::Field {
                                        base: Box::new(cur_target),
                                        field: part.to_owned(),
                                        blob_step,
                                    };
                                    leaf_sf_opt = sf_opt;
                                    cur_entry_opt = next_entry_opt;
                                }
                                if let Some(sf) = leaf_sf_opt {
                                    match &sf.ty {
                                        Ty::Array { elem, .. } => {
                                            let (elem_sz, elem_align) =
                                                sema_ty_size_align(elem, ctx);
                                            field_ptr_array_meta.insert(
                                                d,
                                                ((**elem).clone(), elem_sz, elem_align, false, 0),
                                            );
                                        }
                                        Ty::SmallVec { elem, cap } => {
                                            let (elem_sz, elem_align) =
                                                sema_ty_size_align(elem, ctx);
                                            smallvec_ptr_meta.insert(
                                                d,
                                                ((**elem).clone(), elem_sz, elem_align, *cap),
                                            );
                                            field_ptr_array_meta.insert(
                                                d,
                                                ((**elem).clone(), elem_sz, elem_align, true, *cap),
                                            );
                                        }
                                        _ => {}
                                    }
                                }
                                ptr_targets.insert(d, cur_target);
                            }
                        }
                    }
                    Inst::StructInit { type_name, fields } => {
                        if type_name == "tuple" {
                            if let Some(d) = st.dst
                                && let ValTy::Tuple(item_tys) = val_tys[d.0 as usize].clone()
                            {
                                for (idx, (_, flocal)) in fields.iter().enumerate() {
                                    if let Some(
                                        target_vt @ (ValTy::Array(_, _)
                                        | ValTy::InlineStr(_)
                                        | ValTy::SmallVec { .. }),
                                    ) = item_tys.get(idx)
                                        && (array_inits.contains_key(flocal)
                                            || const_string_locals.contains(flocal))
                                    {
                                        val_tys[flocal.0 as usize] = target_vt.clone();
                                    }
                                }
                            }
                        } else if let Some(entry) = ctx.find_layout_entry(type_name) {
                            for (fname, flocal) in fields {
                                if let Some(sf) =
                                    entry.layout.fields.iter().find(|f| f.name == *fname)
                                {
                                    let fvt = ValTy::from_solved_field(sf, ctx);
                                    if matches!(
                                        fvt,
                                        ValTy::Array(_, _)
                                            | ValTy::InlineStr(_)
                                            | ValTy::SmallVec { .. }
                                    ) && (array_inits.contains_key(flocal)
                                        || const_string_locals.contains(flocal))
                                    {
                                        val_tys[flocal.0 as usize] = fvt;
                                    }
                                }
                            }
                        }
                    }
                    Inst::ArrayInit { elems } => {
                        if let Some(d) = st.dst {
                            let elem_vt_opt = match val_tys[d.0 as usize].clone() {
                                ValTy::Array(ev, _) | ValTy::SmallVec { elem: ev, .. } => Some(ev),
                                _ => None,
                            };
                            if let Some(elem_vt) = elem_vt_opt
                                && matches!(
                                    *elem_vt,
                                    ValTy::Array(_, _)
                                        | ValTy::InlineStr(_)
                                        | ValTy::SmallVec { .. }
                                )
                            {
                                for el in elems {
                                    if array_inits.contains_key(el)
                                        || const_string_locals.contains(el)
                                    {
                                        val_tys[el.0 as usize] = (*elem_vt).clone();
                                    }
                                }
                            }
                        }
                    }
                    Inst::ArrayIndex { base, .. } => {
                        if let Some(d) = st.dst {
                            if matches!(
                                func.locals[d.0 as usize].ty,
                                MirType::Ptr | MirType::MutPtr
                            ) {
                                let base_target = ptr_targets
                                    .get(base)
                                    .cloned()
                                    .unwrap_or(PtrTarget::SlotRef { slot_local: *base });
                                let meta = field_ptr_array_meta
                                    .get(base)
                                    .cloned()
                                    .or_else(|| {
                                        smallvec_ptr_meta.get(base).map(|(et, es, ea, cap)| {
                                            (et.clone(), *es, *ea, true, *cap)
                                        })
                                    })
                                    .or_else(|| {
                                        let base_vt = match &base_target {
                                            PtrTarget::SlotRef { slot_local } => {
                                                slot_tys.get(slot_local)
                                            }
                                            _ => Some(&val_tys[base.0 as usize]),
                                        };
                                        match base_vt {
                                            Some(ValTy::Array(ev, _)) => {
                                                let et = val_ty_to_sema_hint(ev);
                                                let (es, ea) = sema_ty_size_align(&et, ctx);
                                                Some((et, es, ea, false, 0))
                                            }
                                            Some(ValTy::SmallVec {
                                                elem,
                                                cap,
                                                elem_size,
                                                elem_align,
                                            }) => Some((
                                                val_ty_to_sema_hint(elem),
                                                *elem_size,
                                                *elem_align,
                                                true,
                                                *cap,
                                            )),
                                            _ => None,
                                        }
                                    });
                                if let Some((elem_ty, es, ea, is_sv, sv_cap)) = meta {
                                    let (elem_rust_ty, elem_needs_pod_unpack) = match &elem_ty {
                                        Ty::Named(n) => {
                                            let short = n.rsplit("::").next().unwrap_or(n);
                                            if !ctx.enums_by_key.contains_key(n.as_str())
                                                && !ctx.enums_by_key.contains_key(short)
                                                && let Some(entry) = ctx.find_layout_entry(n)
                                                && entry.layout.size > 0
                                                && !entry.layout.fields.is_empty()
                                            {
                                                (entry.struct_name.clone(), true)
                                            } else {
                                                (rust_abi_type_for_ty(&elem_ty, es, ctx.mir), is_sv)
                                            }
                                        }
                                        Ty::SmallVec { .. }
                                        | Ty::Tuple(_)
                                        | Ty::InputBuffer { .. } => {
                                            (aligned_blob_type(es, ea), is_sv)
                                        }
                                        _ => (rust_abi_type_for_ty(&elem_ty, es, ctx.mir), is_sv),
                                    };
                                    array_ptr_locals.insert(d);
                                    ptr_targets.insert(
                                        d,
                                        PtrTarget::ArrayElem {
                                            base: Box::new(base_target),
                                            ptr_local: d,
                                            elem_ty: elem_ty.clone(),
                                            elem_size: es,
                                            elem_align: ea,
                                            elem_rust_ty,
                                            elem_needs_pod_unpack,
                                            is_smallvec: is_sv,
                                            sv_cap,
                                        },
                                    );
                                    match &elem_ty {
                                        Ty::Array { elem: ne, .. } => {
                                            let (nes, nea) = sema_ty_size_align(ne, ctx);
                                            field_ptr_array_meta
                                                .insert(d, ((**ne).clone(), nes, nea, false, 0));
                                        }
                                        Ty::SmallVec {
                                            elem: ne,
                                            cap: ncap,
                                        } => {
                                            let (nes, nea) = sema_ty_size_align(ne, ctx);
                                            smallvec_ptr_meta.insert(
                                                d,
                                                ((**ne).clone(), nes, nea.max(1), *ncap),
                                            );
                                            field_ptr_array_meta.insert(
                                                d,
                                                ((**ne).clone(), nes, nea.max(1), true, *ncap),
                                            );
                                        }
                                        _ => {}
                                    }
                                }
                            } else {
                                match &val_tys[base.0 as usize] {
                                    ValTy::Array(elem_vt, _) => {
                                        val_tys[d.0 as usize] = (**elem_vt).clone();
                                    }
                                    ValTy::SmallVec { elem, .. } => {
                                        val_tys[d.0 as usize] = (**elem).clone();
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    Inst::FieldStore {
                        layout_key,
                        field,
                        val,
                        ..
                    } => {
                        if let Some(sf) = ctx.resolve_field_info(layout_key, field) {
                            let fvt = ValTy::from_solved_field(sf, ctx);
                            if matches!(
                                fvt,
                                ValTy::Array(_, _) | ValTy::InlineStr(_) | ValTy::SmallVec { .. }
                            ) && (array_inits.contains_key(val)
                                || const_string_locals.contains(val))
                            {
                                val_tys[val.0 as usize] = fvt;
                            }
                        }
                    }
                    Inst::FieldLoad {
                        base_ptr,
                        layout_key,
                        field,
                        ..
                    } => {
                        if let Some(d) = st.dst {
                            if let Some(sf) = ctx.resolve_field_info(layout_key, field) {
                                let fvt = ValTy::from_solved_field(sf, ctx);
                                if matches!(
                                    fvt,
                                    ValTy::BitSet(_)
                                        | ValTy::InputBuf(_)
                                        | ValTy::InlineStr(_)
                                        | ValTy::SmallVec { .. }
                                        | ValTy::Array(_, _)
                                ) {
                                    val_tys[d.0 as usize] = fvt;
                                }
                            } else if let Some(tb) =
                                ctx.tables_by_key.get(layout_key.as_str()).or_else(|| {
                                    if let ValTy::TableRow(ref tn) = val_tys[base_ptr.0 as usize] {
                                        ctx.tables_by_key.get(tn.as_str())
                                    } else {
                                        None
                                    }
                                })
                            {
                                if let Some((_, fty)) =
                                    tb.fields.iter().find(|(fnm, _)| fnm == field)
                                {
                                    val_tys[d.0 as usize] = ValTy::from_sema_ty(fty, ctx);
                                } else if let Some((top, rest)) = field.split_once('.')
                                    && let Some((_, Ty::Named(nested_key))) =
                                        tb.fields.iter().find(|(fnm, _)| fnm == top)
                                    && let Some(sf) = ctx.resolve_field_info(nested_key, rest)
                                {
                                    val_tys[d.0 as usize] = ValTy::from_solved_field(sf, ctx);
                                }
                            }
                        }
                    }
                    Inst::TableLoad {
                        table_name, field, ..
                    } => {
                        if let Some(d) = st.dst
                            && let Some(tb) = ctx.tables_by_key.get(table_name.as_str())
                        {
                            if field.is_empty() {
                                val_tys[d.0 as usize] = ValTy::TableRow(table_name.clone());
                            } else if let Some((_, fty)) =
                                tb.fields.iter().find(|(fnm, _)| fnm == field)
                            {
                                val_tys[d.0 as usize] = ValTy::from_sema_ty(fty, ctx);
                            } else if let Some((top, rest)) = field.split_once('.')
                                && let Some((_, Ty::Named(nested_key))) =
                                    tb.fields.iter().find(|(fnm, _)| fnm == top)
                                && let Some(sf) = ctx.resolve_field_info(nested_key, rest)
                            {
                                val_tys[d.0 as usize] = ValTy::from_solved_field(sf, ctx);
                            }
                        }
                    }
                    Inst::BinOp { op, lhs, rhs, .. } => {
                        if let Some(d) = st.dst
                            && !matches!(op.as_str(), "==" | "!=" | "<" | "<=" | ">" | ">=")
                            && !op.starts_with("dot")
                            && !op.starts_with("length")
                            && !op.starts_with("distance")
                        {
                            let lt = val_tys[lhs.0 as usize].clone();
                            let rt = val_tys[rhs.0 as usize].clone();
                            if lt.is_ivec().is_some() && rt.is_vec().is_none() {
                                val_tys[d.0 as usize] = lt;
                            } else if rt.is_ivec().is_some() && lt.is_vec().is_none() {
                                val_tys[d.0 as usize] = rt;
                            } else if lt.is_vec().is_some() && rt.is_vec().is_none() {
                                val_tys[d.0 as usize] = lt;
                            } else if rt.is_vec().is_some() && lt.is_vec().is_none() {
                                val_tys[d.0 as usize] = rt;
                            }
                        }
                    }
                    Inst::Call { callee, .. } => {
                        if let Some(d) = st.dst {
                            let short = callee.rsplit("::").next().unwrap_or(callee.as_str());
                            let inferred = match short {
                                "mat3" | "Mat3" => Some(ValTy::Array(Box::new(ValTy::F32), 9)),
                                "mat4" | "Mat4" => Some(ValTy::Array(Box::new(ValTy::F32), 16)),
                                "vec2" | "Vec2" => Some(ValTy::Vec2),
                                "vec3" | "Vec3" => Some(ValTy::Vec3),
                                "vec3a" | "Vec3a" | "vec4" | "Vec4" | "quat" | "Quat" | "rgba"
                                | "Rgba" => Some(ValTy::Vec4),
                                "ivec2" | "IVec2" => Some(ValTy::IVec2),
                                "ivec3" | "IVec3" => Some(ValTy::IVec3),
                                "uvec2" | "UVec2" => Some(ValTy::UVec2),
                                _ if matches!(
                                    val_tys[d.0 as usize],
                                    ValTy::Unit | ValTy::PtrMarker
                                ) =>
                                {
                                    ctx.helpers_by_key
                                        .get(callee.as_str())
                                        .copied()
                                        .or_else(|| {
                                            ctx.mir.fns.iter().find(|f| {
                                                f.name == *callee
                                                    || f.name.rsplit("::").next() == Some(short)
                                            })
                                        })
                                        .filter(|hf| !matches!(hf.ret_ty, MirType::Unit))
                                        .map(|hf| ValTy::from_mir(&hf.ret_ty, ctx))
                                }
                                _ => None,
                            };
                            if let Some(ivt) = inferred {
                                val_tys[d.0 as usize] = ivt;
                            }
                        }
                    }
                    Inst::UnOp { op, val } => {
                        if let Some(d) = st.dst
                            && op == "-"
                        {
                            let vt = val_tys[val.0 as usize].clone();
                            if vt.is_ivec().is_some() || vt.is_vec().is_some() {
                                val_tys[d.0 as usize] = vt;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Detect `sp_lim` spatial loop limit constants so we don't iterate 64 empty slots.
    let mut sp_lim_clamp = HashMap::new();
    for bb in &func.blocks {
        for st in &bb.stmts {
            if let Inst::EntityAtRow { entities_ptr, .. } = st.inst
                && val_tys[entities_ptr.0 as usize] == ValTy::QueryIter
            {
                // Find the Branch in predecessors comparing against sp_lim.
                for pbb in &func.blocks {
                    if let Terminator::Branch { cond, then_bb, .. } = pbb.terminator
                        && then_bb == bb.id
                        && let Some(cmp_stmt) = pbb.stmts.iter().find(|s| s.dst == Some(cond))
                        && let Inst::BinOp { rhs, .. } = cmp_stmt.inst
                    {
                        sp_lim_clamp.insert(rhs, entities_ptr);
                    }
                }
            }
        }
    }

    let mut block_to_loop: HashMap<BlockId, usize> = HashMap::new();
    for (li, cl) in chunk_loops.iter().enumerate() {
        for &bid in &cl.loop_blocks {
            block_to_loop.insert(bid, li);
        }
    }
    for bp in &mut spawn_batches {
        let mut seen_outside = false;
        let mut loops_used: HashSet<usize> = HashSet::new();
        for bb in &func.blocks {
            if !reachable_blocks.contains(&bb.id) {
                continue;
            }
            let loop_opt = block_to_loop.get(&bb.id).copied();
            for st in &bb.stmts {
                let touches_batch = match &st.inst {
                    Inst::SpawnBatchBegin { .. } => st.dst == Some(bp.dst_local),
                    Inst::SpawnBatchPush { batch, .. } | Inst::SpawnBatchCommit { batch } => {
                        batch_sources
                            .get(batch)
                            .is_some_and(|srcs| srcs.contains(&bp.id))
                    }
                    _ => false,
                };
                if touches_batch {
                    if let Some(li) = loop_opt {
                        loops_used.insert(li);
                    } else {
                        seen_outside = true;
                    }
                }
            }
        }
        if !seen_outside && loops_used.len() == 1 {
            bp.only_chunk_loop = loops_used.into_iter().next();
        }
    }

    let needs_par_commands = needs_commands && has_par_loop;
    FnAnalysis {
        val_tys,
        slot_tys,
        ptr_targets,
        const_floats,
        array_inits,
        array_ptr_locals,
        res_map,
        implicit_res_map,
        spatial_res_map,
        relation_res_map,
        stream_writers,
        stream_readers,
        needs_commands: needs_commands && !has_par_loop,
        needs_par_commands,
        needs_named_objects,
        named_objects_mut,
        object_queries,
        needs_trigger_stack,
        needs_child_of_query,
        has_checkpoint,
        sp_lim_clamp,
        up_cascade_locals,
        up_cascade_slots,
        field_ptr_array_meta,
        smallvec_ptr_meta,
        spawn_batches,
        batch_sources,
    }
}

impl ValTy {
    pub(super) fn from_mir_ret(ty: &MirType) -> Self {
        match ty {
            MirType::Bool => ValTy::Bool,
            MirType::U8 => ValTy::U8,
            MirType::U16 => ValTy::U16,
            MirType::U32 | MirType::Sym => ValTy::U32,
            MirType::U64 => ValTy::U64,
            MirType::I8 => ValTy::I8,
            MirType::I16 => ValTy::I16,
            MirType::I32 => ValTy::I32,
            MirType::I64 => ValTy::I64,
            MirType::F32 => ValTy::F32,
            MirType::F64 => ValTy::F64,
            MirType::Fix32 => ValTy::Fix32,
            MirType::Fix64 => ValTy::Fix64,
            MirType::Vec2 => ValTy::Vec2,
            MirType::Vec3 => ValTy::Vec3,
            MirType::Vec4 => ValTy::Vec4,
            MirType::IVec2 => ValTy::IVec2,
            MirType::IVec3 => ValTy::IVec3,
            MirType::UVec2 => ValTy::UVec2,
            MirType::Entity => ValTy::Entity,
            _ => ValTy::Unit,
        }
    }
}

pub(super) fn inst_used_locals(inst: &Inst) -> Vec<LocalId> {
    match inst {
        Inst::Copy { val }
        | Inst::SlotLoad { slot: val }
        | Inst::UnOp { val, .. }
        | Inst::Cast { val, .. }
        | Inst::VecExtract { vec: val, .. }
        | Inst::VecSwizzle { vec: val, .. }
        | Inst::FieldPtr { base_ptr: val, .. }
        | Inst::FieldLoad { base_ptr: val, .. }
        | Inst::EntityGet { entity: val, .. }
        | Inst::EntityGetMut { entity: val, .. }
        | Inst::IterUpCascade { entity: val, .. }
        | Inst::SpatialCsrCount { pos: val, .. }
        | Inst::GraceIsActive { ptr: val }
        | Inst::GraceClear { ptr: val }
        | Inst::TimelineInWindow { ptr: val, .. }
        | Inst::CmdDespawn { entity: val }
        | Inst::CmdRemove { entity: val, .. }
        | Inst::StreamEmit { payload: val, .. }
        | Inst::CmdRollback { checkpoint: val }
        | Inst::CurveSample { x: val, .. }
        | Inst::TableLoad { key: val, .. }
        | Inst::OptionalChunkIsPresent { slice_ptr: val, .. }
        | Inst::ShadowCommit {
            shadow_slot: val, ..
        }
        | Inst::RequireTrue { cond: val }
        | Inst::ReduceInit { identity: val, .. }
        | Inst::SpawnBatchBegin { count: val, .. }
        | Inst::SpawnBatchCommit { batch: val } => vec![*val],

        Inst::SlotStore { slot, val }
        | Inst::VecInsert { vec: slot, val, .. }
        | Inst::FieldStore {
            base_ptr: slot,
            val,
            ..
        }
        | Inst::RowPtr {
            col_ptr: slot,
            row_idx: val,
            ..
        }
        | Inst::EntityAtRow {
            entities_ptr: slot,
            row_idx: val,
        }
        | Inst::SpatialCsrScatter {
            entity: slot,
            pos: val,
            ..
        }
        | Inst::IterMarkChangedRange {
            run_start: slot,
            run_len: val,
            ..
        }
        | Inst::ArrayIndex {
            base: slot,
            index: val,
        }
        | Inst::GraceArm {
            ptr: slot,
            duration_sec: val,
        }
        | Inst::GraceTick {
            ptr: slot,
            dt_sec: val,
        }
        | Inst::InputBufConsume {
            ptr: slot,
            action_id: val,
            ..
        }
        | Inst::InputBufPeek {
            ptr: slot,
            action_id: val,
            ..
        }
        | Inst::InputBufTick {
            ptr: slot,
            dt_sec: val,
            ..
        }
        | Inst::BitSetSet {
            ptr: slot,
            bit: val,
            ..
        }
        | Inst::BitSetGet {
            ptr: slot,
            bit: val,
            ..
        }
        | Inst::BitSetClear {
            ptr: slot,
            bit: val,
            ..
        }
        | Inst::DirtyRunInit {
            run_start: slot,
            run_len: val,
        }
        | Inst::ShadowWrite {
            shadow_slot: slot,
            val,
            ..
        }
        | Inst::TimelineAdvance {
            cursor_ptr: slot,
            dt_sec: val,
            ..
        }
        | Inst::TaskStep {
            pc_local: slot,
            timer_local: val,
            ..
        }
        | Inst::CmdRemoveRelation {
            entity: slot,
            target: val,
            ..
        }
        | Inst::BinOp {
            lhs: slot,
            rhs: val,
            ..
        } => vec![*slot, *val],

        Inst::ReduceAccum { acc, val, .. } => vec![*acc, *val],
        Inst::DirtyRunRecordRow {
            run_start,
            run_len,
            row_idx,
        }
        | Inst::ArrayStore {
            base_ptr: run_start,
            index: run_len,
            val: row_idx,
            ..
        } => vec![*run_start, *run_len, *row_idx],
        Inst::InputBufPush {
            ptr,
            action_id,
            window_sec,
            ..
        } => vec![*ptr, *action_id, *window_sec],
        Inst::SpatialQueryDisc { center, radius, .. } => vec![*center, *radius],
        Inst::SpatialQuerySegmentAt {
            start,
            end,
            radius,
            tick_offset,
            ..
        } => vec![*start, *end, *radius, *tick_offset],
        Inst::IntrinsicMath { args, .. }
        | Inst::Call { args, .. }
        | Inst::ArrayInit { elems: args } => args.clone(),
        Inst::StructInit { fields, .. } => fields.iter().map(|(_, l)| *l).collect(),
        Inst::CmdSpawn { components, .. } => components.iter().map(|(_, l)| *l).collect(),
        Inst::CmdSpawnBatch { count, components } => {
            let mut out = vec![*count];
            out.extend(components.iter().map(|(_, l)| *l));
            out
        }
        Inst::SpawnBatchPush {
            batch,
            index,
            components,
        } => {
            let mut out = vec![*batch, *index];
            out.extend(components.iter().map(|(_, l)| *l));
            out
        }
        Inst::CmdInsert { entity, data, .. } => {
            let mut out = vec![*entity];
            if let Some(d) = data {
                out.push(*d);
            }
            out
        }
        Inst::CmdTrigger {
            target, payload, ..
        } => {
            let mut out = Vec::new();
            if let Some(t) = target {
                out.push(*t);
            }
            if let Some(p) = payload {
                out.push(*p);
            }
            out
        }
        Inst::CmdInsertRelation {
            entity,
            target,
            payload,
            ..
        } => {
            let mut out = vec![*entity, *target];
            if let Some(p) = payload {
                out.push(*p);
            }
            out
        }
        _ => Vec::new(),
    }
}

pub(super) fn terminator_used_locals(term: &Terminator) -> Vec<LocalId> {
    match term {
        Terminator::Return(Some(l)) => vec![*l],
        Terminator::Branch { cond, .. } => vec![*cond],
        Terminator::Switch { scrutinee, .. } => vec![*scrutinee],
        _ => Vec::new(),
    }
}

fn infer_projected_helper_param_ty(
    func: &MirFunction,
    param_idx: usize,
    pl: LocalId,
    layout_key: &str,
    ctx: &NativeCtx<'_>,
) -> Option<ValTy> {
    let mut aliases: HashSet<LocalId> = HashSet::new();
    aliases.insert(pl);
    for _ in 0..3 {
        for bb in &func.blocks {
            for st in &bb.stmts {
                if let Inst::Copy { val } = &st.inst
                    && aliases.contains(val)
                    && let Some(d) = st.dst
                {
                    aliases.insert(d);
                }
            }
        }
    }

    // Whole-component / handle reference parameters index into fields or bit/grace/timeline APIs.
    for bb in &func.blocks {
        for st in &bb.stmts {
            match &st.inst {
                Inst::FieldLoad {
                    base_ptr,
                    layout_key: fk,
                    field,
                    ..
                }
                | Inst::FieldStore {
                    base_ptr,
                    layout_key: fk,
                    field,
                    ..
                }
                | Inst::FieldPtr {
                    base_ptr,
                    layout_key: fk,
                    field,
                    ..
                } if aliases.contains(base_ptr) => {
                    let eff_fk = if fk.is_empty() {
                        layout_key
                    } else {
                        fk.as_str()
                    };
                    if ctx.resolve_field_info(eff_fk, field).is_some() {
                        return None;
                    }
                }
                Inst::GraceIsActive { ptr }
                | Inst::GraceClear { ptr }
                | Inst::GraceArm { ptr, .. }
                | Inst::GraceTick { ptr, .. }
                | Inst::TimelineInWindow { ptr, .. }
                | Inst::TimelineAdvance {
                    cursor_ptr: ptr, ..
                }
                | Inst::InputBufPush { ptr, .. }
                | Inst::InputBufPeek { ptr, .. }
                | Inst::InputBufTick { ptr, .. }
                | Inst::InputBufConsume { ptr, .. }
                | Inst::BitSetSet { ptr, .. }
                | Inst::BitSetClear { ptr, .. }
                | Inst::BitSetGet { ptr, .. }
                    if aliases.contains(ptr) =>
                {
                    return None;
                }
                _ => {}
            }
        }
    }

    // Check call sites across the module first: projected scalar/vector args carry non-Ptr types.
    let fn_short = func.name.rsplit("::").next().unwrap_or(func.name.as_str());
    for caller in &ctx.mir.fns {
        for bb in &caller.blocks {
            for st in &bb.stmts {
                if let Inst::Call { callee, args } = &st.inst {
                    let matches_callee =
                        callee == &func.name || callee.rsplit("::").next() == Some(fn_short);
                    if matches_callee && let Some(&arg_id) = args.get(param_idx) {
                        let aty = &caller.locals[arg_id.0 as usize].ty;
                        if !matches!(aty, MirType::Ptr | MirType::MutPtr | MirType::Unit) {
                            return Some(ValTy::from_mir(aty, ctx));
                        }
                    }
                }
            }
        }
    }

    // Fallback: inspect direct value uses inside the helper itself.
    for bb in &func.blocks {
        for st in &bb.stmts {
            match &st.inst {
                Inst::BinOp { op, lhs, rhs, .. } => {
                    let other = if aliases.contains(lhs) && !aliases.contains(rhs) {
                        Some(*rhs)
                    } else if aliases.contains(rhs) && !aliases.contains(lhs) {
                        Some(*lhs)
                    } else {
                        None
                    };
                    if let Some(o) = other {
                        let oty = &func.locals[o.0 as usize].ty;
                        if !matches!(oty, MirType::Ptr | MirType::MutPtr | MirType::Unit) {
                            if op == "quat_mul_vec3" && aliases.contains(rhs) {
                                return Some(ValTy::Vec3);
                            }
                            return Some(ValTy::from_mir(oty, ctx));
                        }
                    }
                }
                Inst::UnOp { op, val } if aliases.contains(val) && op == "!" => {
                    return Some(ValTy::Bool);
                }
                Inst::FieldStore {
                    layout_key: fk,
                    field,
                    val,
                    ..
                } if aliases.contains(val) => {
                    if let Some(sf) = ctx.resolve_field_info(fk, field) {
                        return Some(ValTy::from_solved_field(sf, ctx));
                    }
                }
                Inst::ReduceAccum { acc, val, .. } if aliases.contains(val) => {
                    let aty = &func.locals[acc.0 as usize].ty;
                    if !matches!(aty, MirType::Ptr | MirType::MutPtr | MirType::Unit) {
                        return Some(ValTy::from_mir(aty, ctx));
                    }
                }
                _ => {}
            }
        }
        if let Terminator::Return(Some(rv)) = &bb.terminator
            && aliases.contains(rv)
            && !matches!(func.ret_ty, MirType::Unit | MirType::Ptr | MirType::MutPtr)
        {
            return Some(ValTy::from_mir(&func.ret_ty, ctx));
        }
    }

    None
}

// =========================================================================
// Named Object Initialization, Schedule SystemSets, run_if, & Plugin Wiring
// =========================================================================
