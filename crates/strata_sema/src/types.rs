//! Strata v2.0 static type system and SI physical unit dimensional algebra.

use crate::access::TermAccessMode;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use strata_syntax::{SyntaxKind, SyntaxNode, SyntaxToken};

/// SI physical unit exponents `(sec, meters, rad, frames)` checked at compile time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct UnitDim {
    /// Time exponent (`sec` / `ms` -> `1`, `hz` -> `-1`, `mps` -> `-1`, `mps2` -> `-2`).
    pub sec: i8,
    /// Length exponent (`meters` -> `1`, `mps` -> `1`, `mps2` -> `1`).
    pub meters: i8,
    /// Angle exponent (`rad` / `deg` -> `1`).
    pub rad: i8,
    /// Discrete simulation frame exponent (`frames` -> `1`).
    pub frames: i8,
}

impl UnitDim {
    /// Dimensionless scalar.
    pub const NONE: Self = Self {
        sec: 0,
        meters: 0,
        rad: 0,
        frames: 0,
    };
    /// Time dimension (`sec`, `ms`).
    pub const SEC: Self = Self {
        sec: 1,
        meters: 0,
        rad: 0,
        frames: 0,
    };
    /// Frequency dimension (`hz`).
    pub const HZ: Self = Self {
        sec: -1,
        meters: 0,
        rad: 0,
        frames: 0,
    };
    /// Discrete frames dimension (`frames`).
    pub const FRAMES: Self = Self {
        sec: 0,
        meters: 0,
        rad: 0,
        frames: 1,
    };
    /// Angle dimension (`rad`, `deg`).
    pub const RAD: Self = Self {
        sec: 0,
        meters: 0,
        rad: 1,
        frames: 0,
    };
    /// Distance dimension (`meters`).
    pub const METERS: Self = Self {
        sec: 0,
        meters: 1,
        rad: 0,
        frames: 0,
    };
    /// Velocity dimension (`mps`).
    pub const MPS: Self = Self {
        sec: -1,
        meters: 1,
        rad: 0,
        frames: 0,
    };
    /// Acceleration dimension (`mps2`).
    pub const MPS2: Self = Self {
        sec: -2,
        meters: 1,
        rad: 0,
        frames: 0,
    };

    /// Multiplies two physical unit dimensions (adds exponents).
    #[inline]
    pub const fn mul(self, rhs: Self) -> Self {
        Self {
            sec: self.sec + rhs.sec,
            meters: self.meters + rhs.meters,
            rad: self.rad + rhs.rad,
            frames: self.frames + rhs.frames,
        }
    }

    /// Divides two physical unit dimensions (subtracts exponents).
    #[inline]
    pub const fn div(self, rhs: Self) -> Self {
        Self {
            sec: self.sec - rhs.sec,
            meters: self.meters - rhs.meters,
            rad: self.rad - rhs.rad,
            frames: self.frames - rhs.frames,
        }
    }
}

/// Single projected or borrowed term inside a [`Ty::QueryRow`] expression type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueryRowTerm {
    /// Binding alias (`"h"` or `"v"`).
    pub alias: String,
    /// Logical component or `@soa` stratum key (`"Health"` or `"Body::hot"`).
    pub storage_key: String,
    /// Canonical layout name (`"demo::Health"`).
    pub canonical_component: String,
    /// Optional projected field name (`Some("pos")`).
    pub field_name: Option<String>,
    /// Borrow mode (`Read`, `Write`, `SelectiveWrite`, `OptionalRead`, `OptionalWrite`).
    pub mode: TermAccessMode,
    /// Resolved semantic type of this term.
    pub ty: Ty,
}

/// Static Strata v2.0 type representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Ty {
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
    Bool,
    Sym,
    UnitScalar {
        name: String,
        dim: UnitDim,
    },
    Vec2,
    Vec3,
    Vec3a,
    Vec4,
    IVec2,
    IVec3,
    UVec2,
    Quat,
    Mat3,
    Mat4,
    Rgba8,
    Rgba,
    Array {
        elem: Box<Ty>,
        len: usize,
    },
    SmallVec {
        elem: Box<Ty>,
        cap: usize,
    },
    InlineStr(usize),
    BitSet(usize),
    InputBuffer {
        action: String,
        cap: usize,
    },
    GraceWindow,
    Ref(String),
    Asset(String),
    Named(String),
    Tuple(Vec<Ty>),
    Unit,
    BannedWire(String),
    /// Optional value `Option<T>` (and `?&T` / `?&mut T` query term target).
    Option(Box<Ty>),
    /// Fallible result `Result<T, E>`.
    Result {
        ok: Box<Ty>,
        err: Box<Ty>,
    },
    /// Live borrow `&T` (`mutable: false`) or `&mut T` (`mutable: true`).
    Borrow {
        mutable: bool,
        inner: Box<Ty>,
    },
    /// Observer event trigger `Trigger<Event, Target?>`.
    Trigger {
        event: String,
        target: Option<String>,
    },
    /// Projected row type of a `query(...)` / `query_one(...)` expression.
    QueryRow(Vec<QueryRowTerm>),
    /// Anonymous structural record `{ field: ty, ... }`.
    Record(Vec<(String, Ty)>),
    Unknown,
}

impl Ty {
    /// Returns the SI unit dimension if this is a unit scalar type.
    pub fn unit_dim(&self) -> Option<UnitDim> {
        match self {
            Self::UnitScalar { dim, .. } => Some(*dim),
            _ => None,
        }
    }

    /// Returns `true` if `self` and `other` represent compatible types (including matching SI
    /// dimensions such as `sec` and `ms`, or `rad` and `deg`).
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::U8, Self::U8)
            | (Self::U16, Self::U16)
            | (Self::U32, Self::U32)
            | (Self::U64, Self::U64)
            | (Self::I8, Self::I8)
            | (Self::I16, Self::I16)
            | (Self::I32, Self::I32)
            | (Self::I64, Self::I64)
            | (Self::F32, Self::F32)
            | (Self::F64, Self::F64)
            | (Self::Bool, Self::Bool)
            | (Self::Fix32, Self::Fix32)
            | (Self::Fix64, Self::Fix64)
            | (Self::Vec2, Self::Vec2)
            | (Self::Vec3, Self::Vec3)
            | (Self::Vec3a, Self::Vec3a)
            | (Self::Vec4, Self::Vec4)
            | (Self::Quat, Self::Quat)
            | (Self::Mat3, Self::Mat3)
            | (Self::Mat4, Self::Mat4)
            | (Self::IVec2, Self::IVec2)
            | (Self::IVec3, Self::IVec3)
            | (Self::UVec2, Self::UVec2)
            | (Self::Sym, Self::Sym)
            | (Self::Rgba8, Self::Rgba8)
            | (Self::Rgba, Self::Rgba)
            | (Self::GraceWindow, Self::GraceWindow)
            | (Self::Unit, Self::Unit)
            | (Self::Unknown, Self::Unknown) => true,
            (Self::InlineStr(a), Self::InlineStr(b)) | (Self::BitSet(a), Self::BitSet(b)) => a == b,
            (
                Self::InputBuffer {
                    cap: c1,
                    action: a1,
                },
                Self::InputBuffer {
                    cap: c2,
                    action: a2,
                },
            ) => c1 == c2 && a1 == a2,
            (Self::Ref(a), Self::Ref(b))
            | (Self::Asset(a), Self::Asset(b))
            | (Self::Named(a), Self::Named(b))
            | (Self::BannedWire(a), Self::BannedWire(b)) => a == b,
            (
                Self::Trigger {
                    event: e1,
                    target: t1,
                },
                Self::Trigger {
                    event: e2,
                    target: t2,
                },
            ) => e1 == e2 && t1 == t2,
            (Self::QueryRow(a), Self::QueryRow(b)) => {
                if a.len() != b.len() {
                    return false;
                }
                let mut i = 0;
                while i < a.len() {
                    let x = &a[i];
                    let y = &b[i];
                    if x.alias != y.alias
                        || x.storage_key != y.storage_key
                        || x.canonical_component != y.canonical_component
                        || x.field_name != y.field_name
                        || x.mode != y.mode
                        || !x.ty.is_compatible_with(&y.ty)
                    {
                        return false;
                    }
                    i += 1;
                }
                true
            }
            (Self::UnitScalar { dim: a, .. }, Self::UnitScalar { dim: b, .. }) => a == b,
            (Self::Option(a), Self::Option(b))
            | (
                Self::Borrow {
                    mutable: true,
                    inner: a,
                },
                Self::Borrow {
                    mutable: true,
                    inner: b,
                },
            )
            | (
                Self::Borrow {
                    mutable: false,
                    inner: a,
                },
                Self::Borrow {
                    mutable: false,
                    inner: b,
                },
            ) => a.is_compatible_with(b),
            (Self::Array { elem: a, len: l1 }, Self::Array { elem: b, len: l2 }) if l1 == l2 => {
                a.is_compatible_with(b)
            }
            (Self::SmallVec { elem: a, cap: c1 }, Self::SmallVec { elem: b, cap: c2 })
                if c1 == c2 =>
            {
                a.is_compatible_with(b)
            }
            (Self::Result { ok: ok1, err: err1 }, Self::Result { ok: ok2, err: err2 }) => {
                ok1.is_compatible_with(ok2) && err1.is_compatible_with(err2)
            }
            (Self::Tuple(t1), Self::Tuple(t2)) => {
                if t1.len() != t2.len() {
                    return false;
                }
                let mut i = 0;
                while i < t1.len() {
                    if !t1[i].is_compatible_with(&t2[i]) {
                        return false;
                    }
                    i += 1;
                }
                true
            }
            (Self::Record(r1), Self::Record(r2)) => {
                if r1.len() != r2.len() {
                    return false;
                }
                let mut i = 0;
                while i < r1.len() {
                    if r1[i].0 != r2[i].0 || !r1[i].1.is_compatible_with(&r2[i].1) {
                        return false;
                    }
                    i += 1;
                }
                true
            }
            _ => false,
        }
    }

    /// Canonical Rust/C ABI type tag string matching `bamabi_macros::classify::canonical_field_type_tag`.
    pub fn canonical_tag(&self) -> String {
        fn push_usize(out: &mut String, mut n: usize) {
            let mut buf = [0u8; 20];
            let mut idx = buf.len();
            if n == 0 {
                out.push('0');
                return;
            }
            while n > 0 {
                idx -= 1;
                buf[idx] = b'0' + (n % 10) as u8;
                n /= 10;
            }
            if let Ok(s) = std::str::from_utf8(&buf[idx..]) {
                out.push_str(s);
            }
        }
        match self {
            Self::U8 => "u8".to_owned(),
            Self::U16 => "u16".to_owned(),
            Self::U32 | Self::Sym | Self::Rgba8 => "u32".to_owned(),
            Self::U64 => "u64".to_owned(),
            Self::I8 => "i8".to_owned(),
            Self::I16 => "i16".to_owned(),
            Self::I32 | Self::Fix32 => "i32".to_owned(),
            Self::I64 | Self::Fix64 => "i64".to_owned(),
            Self::F32 | Self::UnitScalar { .. } | Self::GraceWindow => "f32".to_owned(),
            Self::F64 => "f64".to_owned(),
            Self::Bool => "FfiBool".to_owned(),
            Self::Vec2 => "[f32;2]".to_owned(),
            Self::Vec3 => "[f32;3]".to_owned(),
            Self::Vec3a | Self::Vec4 | Self::Quat | Self::Rgba => "[f32;4]".to_owned(),
            Self::IVec2 => "[i32;2]".to_owned(),
            Self::IVec3 => "[i32;3]".to_owned(),
            Self::UVec2 => "[u32;2]".to_owned(),
            Self::Mat3 => "[f32;9]".to_owned(),
            Self::Mat4 => "[f32;16]".to_owned(),
            Self::Array { elem, len } => {
                let tag = elem.canonical_tag();
                let mut s = String::with_capacity(tag.len() + 12);
                s.push('[');
                s.push_str(&tag);
                s.push(';');
                push_usize(&mut s, *len);
                s.push(']');
                s
            }
            Self::SmallVec { elem, cap } => {
                let tag = elem.canonical_tag();
                let mut s = String::with_capacity(tag.len() + 24);
                s.push_str("SmallVecPod<");
                s.push_str(&tag);
                s.push(',');
                push_usize(&mut s, *cap);
                s.push('>');
                s
            }
            Self::InlineStr(cap) => {
                let mut s = String::with_capacity(20);
                s.push_str("InlineStr<");
                push_usize(&mut s, *cap);
                s.push('>');
                s
            }
            Self::BitSet(bits) => {
                let mut s = String::with_capacity(18);
                s.push_str("BitSet<");
                push_usize(&mut s, (*bits).div_ceil(32).max(1));
                s.push('>');
                s
            }
            Self::InputBuffer { cap, .. } => {
                let mut s = String::with_capacity(22);
                s.push_str("InputBuffer<");
                push_usize(&mut s, *cap);
                s.push('>');
                s
            }
            Self::Ref(_) => "FfiEntity".to_owned(),
            Self::Asset(_) => "FfiAssetHandle".to_owned(),
            Self::Named(n) | Self::BannedWire(n) => n.clone(),
            Self::Tuple(_) => "Tuple".to_owned(),
            Self::Unit => "()".to_owned(),
            Self::Option(inner) => {
                let tag = inner.canonical_tag();
                let mut s = String::with_capacity(8 + tag.len());
                s.push_str("Option<");
                s.push_str(&tag);
                s.push('>');
                s
            }
            Self::Result { ok, err } => {
                let ok_tag = ok.canonical_tag();
                let err_tag = err.canonical_tag();
                let mut s = String::with_capacity(9 + ok_tag.len() + err_tag.len());
                s.push_str("Result<");
                s.push_str(&ok_tag);
                s.push(',');
                s.push_str(&err_tag);
                s.push('>');
                s
            }
            Self::Borrow { mutable, inner } => {
                let tag = inner.canonical_tag();
                let prefix = if *mutable { "&mut " } else { "&" };
                let mut s = String::with_capacity(prefix.len() + tag.len());
                s.push_str(prefix);
                s.push_str(&tag);
                s
            }
            Self::Trigger { event, target } => {
                let mut s = String::with_capacity(12 + event.len());
                s.push_str("Trigger<");
                s.push_str(event);
                if let Some(t) = target {
                    s.push(',');
                    s.push_str(t);
                }
                s.push('>');
                s
            }
            Self::QueryRow(_) => "QueryRow".to_owned(),
            Self::Record(fields) => {
                let mut s = String::from("{");
                let mut i = 0;
                while i < fields.len() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str(&fields[i].0);
                    s.push(':');
                    s.push_str(&fields[i].1.canonical_tag());
                    i += 1;
                }
                s.push('}');
                s
            }
            Self::Unknown => "unknown".to_owned(),
        }
    }

    /// Splits a unit literal (e.g. `"50ms"`, `"1_000ms"`, `"20Hz"`, `"1.5s"`, `"1_000_f"`) into
    /// `(numeric_stem, canonical_unit_name, UnitDim, si_scale_factor)`.
    pub fn split_unit_literal(lit: &str) -> Option<(&str, &'static str, UnitDim, f64)> {
        const UNITS: &[(&str, &str, UnitDim, f64)] = &[
            ("frames", "frames", UnitDim::FRAMES, 1.0),
            ("meters", "meters", UnitDim::METERS, 1.0),
            ("mps2", "mps2", UnitDim::MPS2, 1.0),
            ("mps", "mps", UnitDim::MPS, 1.0),
            ("sec", "sec", UnitDim::SEC, 1.0),
            ("rad", "rad", UnitDim::RAD, 1.0),
            ("deg", "deg", UnitDim::RAD, std::f64::consts::PI / 180.0),
            ("ms", "ms", UnitDim::SEC, 0.001),
            ("hz", "hz", UnitDim::HZ, 1.0),
            ("Hz", "hz", UnitDim::HZ, 1.0),
            ("s", "sec", UnitDim::SEC, 1.0),
            ("m", "meters", UnitDim::METERS, 1.0),
            ("f", "frames", UnitDim::FRAMES, 1.0),
        ];
        for &(suf, name, dim, factor) in UNITS {
            if let Some(rest) = lit.strip_suffix(suf) {
                let stem = rest.strip_suffix('_').unwrap_or(rest);
                if !stem.is_empty() && stem.as_bytes()[0].is_ascii_digit() {
                    let cleaned: String = stem.chars().filter(|&c| c != '_').collect();
                    if cleaned.parse::<f64>().is_ok_and(f64::is_finite) {
                        return Some((stem, name, dim, factor));
                    }
                }
            }
        }
        None
    }

    /// Parses a unit scalar suffix (`ms`, `s`, `sec`, `hz`, `Hz`, `f`, `frames`, `rad`, `deg`,
    /// `m`, `meters`, `mps`, `mps2`, with optional `_` separator) into its [`UnitDim`].
    pub fn unit_from_literal(lit: &str) -> Option<Self> {
        Self::split_unit_literal(lit).map(|(_, name, dim, _)| Self::UnitScalar {
            name: name.to_owned(),
            dim,
        })
    }
}

/// Parses a CST type node (`TypeRef`, `ArrayType`, `TupleType`, `RefType`, `PtrTermType`) into a [`Ty`].
pub fn parse_type_node(node: &SyntaxNode) -> Ty {
    parse_type_node_with_user_types(node, &HashSet::new())
}

/// Parses a CST type node into a [`Ty`], honoring user-declared type names that shadow built-in
/// PascalCase aliases (`Quat`, `Rgba8`, `Option`, `Result`, `Trigger`).
pub fn parse_type_node_with_user_types(node: &SyntaxNode, user_types: &HashSet<String>) -> Ty {
    match node.kind() {
        SyntaxKind::ArrayType => {
            let child_types: Vec<_> = node
                .children()
                .filter(|c| is_type_node_kind(c.kind()))
                .collect();
            let elem = child_types.first().map_or(Ty::Unknown, |c| {
                parse_type_node_with_user_types(c, user_types)
            });
            let len = extract_array_len(node).unwrap_or(0);
            Ty::Array {
                elem: Box::new(elem),
                len,
            }
        }
        SyntaxKind::TupleType => {
            let items = node
                .children()
                .filter(|c| is_type_node_kind(c.kind()))
                .map(|c| parse_type_node_with_user_types(&c, user_types))
                .collect::<Vec<_>>();
            if items.is_empty() {
                Ty::Unit
            } else {
                Ty::Tuple(items)
            }
        }
        SyntaxKind::RefType => {
            let has_mut = node
                .children_with_tokens()
                .filter_map(|el| el.into_token())
                .any(|t| t.kind() == SyntaxKind::KwMut);
            if let Some(inner) = node.children().find(|c| is_type_node_kind(c.kind())) {
                let inner_ty = parse_type_node_with_user_types(&inner, user_types);
                Ty::Borrow {
                    mutable: has_mut,
                    inner: Box::new(inner_ty),
                }
            } else {
                Ty::Unknown
            }
        }
        SyntaxKind::PtrTermType => {
            let has_mut = node
                .children_with_tokens()
                .filter_map(|el| el.into_token())
                .any(|t| t.kind() == SyntaxKind::KwMut);
            if let Some(inner) = node.children().find(|c| is_type_node_kind(c.kind())) {
                let inner_ty = parse_type_node_with_user_types(&inner, user_types);
                Ty::Option(Box::new(Ty::Borrow {
                    mutable: has_mut,
                    inner: Box::new(inner_ty),
                }))
            } else {
                Ty::Unknown
            }
        }
        SyntaxKind::TypeRef => parse_typeref_node(node, user_types),
        _ => Ty::Unknown,
    }
}

fn is_type_node_kind(kind: SyntaxKind) -> bool {
    matches!(
        kind,
        SyntaxKind::TypeRef
            | SyntaxKind::ArrayType
            | SyntaxKind::RefType
            | SyntaxKind::PtrTermType
            | SyntaxKind::TupleType
    )
}

fn parse_typeref_node(node: &SyntaxNode, user_types: &HashSet<String>) -> Ty {
    let base_name = node
        .children()
        .find(|c| c.kind() == SyntaxKind::Path)
        .map(|p| {
            p.children_with_tokens()
                .filter_map(|e| e.into_token())
                .filter(|t| !t.kind().is_trivia())
                .map(|t| t.text().to_owned())
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_else(|| node.text().to_string().trim().to_owned());

    let gen_args = node
        .children()
        .find(|c| c.kind() == SyntaxKind::GenericArgs);

    match base_name.as_str() {
        "u8" => Ty::U8,
        "u16" => Ty::U16,
        "u32" => Ty::U32,
        "u64" => Ty::U64,
        "i8" => Ty::I8,
        "i16" => Ty::I16,
        "i32" => Ty::I32,
        "i64" => Ty::I64,
        "f32" => Ty::F32,
        "f64" => Ty::F64,
        "fix32" => Ty::Fix32,
        "fix64" => Ty::Fix64,
        "bool" => Ty::Bool,
        "sym" => Ty::Sym,
        "sec" => Ty::UnitScalar {
            name: "sec".to_owned(),
            dim: UnitDim::SEC,
        },
        "ms" => Ty::UnitScalar {
            name: "ms".to_owned(),
            dim: UnitDim::SEC,
        },
        "hz" => Ty::UnitScalar {
            name: "hz".to_owned(),
            dim: UnitDim::HZ,
        },
        "frames" => Ty::UnitScalar {
            name: "frames".to_owned(),
            dim: UnitDim::FRAMES,
        },
        "rad" => Ty::UnitScalar {
            name: "rad".to_owned(),
            dim: UnitDim::RAD,
        },
        "deg" => Ty::UnitScalar {
            name: "deg".to_owned(),
            dim: UnitDim::RAD,
        },
        "meters" => Ty::UnitScalar {
            name: "meters".to_owned(),
            dim: UnitDim::METERS,
        },
        "mps" => Ty::UnitScalar {
            name: "mps".to_owned(),
            dim: UnitDim::MPS,
        },
        "mps2" => Ty::UnitScalar {
            name: "mps2".to_owned(),
            dim: UnitDim::MPS2,
        },
        "vec2" => Ty::Vec2,
        "vec3" => Ty::Vec3,
        "vec3a" => Ty::Vec3a,
        "vec4" => Ty::Vec4,
        "ivec2" => Ty::IVec2,
        "ivec3" => Ty::IVec3,
        "uvec2" => Ty::UVec2,
        "quat" => Ty::Quat,
        "Quat" if !user_types.contains("Quat") => Ty::Quat,
        "mat3" => Ty::Mat3,
        "mat4" => Ty::Mat4,
        "rgba8" => Ty::Rgba8,
        "Rgba8" if !user_types.contains("Rgba8") => Ty::Rgba8,
        "rgba" => Ty::Rgba,
        "GraceWindow" => Ty::GraceWindow,
        "usize" | "isize" | "u128" | "i128" | "String" | "str" | "Vec" | "Box" | "char" => {
            Ty::BannedWire(base_name)
        }
        "Option" | "std::option::Option" if !user_types.contains("Option") => {
            let inner = gen_args
                .as_ref()
                .and_then(|g| g.children().find(|c| is_type_node_kind(c.kind())))
                .map_or(Ty::Unknown, |c| {
                    parse_type_node_with_user_types(&c, user_types)
                });
            Ty::Option(Box::new(inner))
        }
        "Result" | "std::result::Result" if !user_types.contains("Result") => {
            let type_args: Vec<_> = gen_args
                .as_ref()
                .map(|g| {
                    g.children()
                        .filter(|c| is_type_node_kind(c.kind()))
                        .collect()
                })
                .unwrap_or_default();
            let ok = type_args.first().map_or(Ty::Unknown, |c| {
                parse_type_node_with_user_types(c, user_types)
            });
            let err = type_args.get(1).map_or(Ty::Unknown, |c| {
                parse_type_node_with_user_types(c, user_types)
            });
            Ty::Result {
                ok: Box::new(ok),
                err: Box::new(err),
            }
        }
        "Trigger" if !user_types.contains("Trigger") => {
            let type_args: Vec<String> = gen_args
                .as_ref()
                .map(|g| {
                    g.children()
                        .filter(|c| is_type_node_kind(c.kind()))
                        .map(|c| c.text().to_string().trim().to_owned())
                        .collect()
                })
                .unwrap_or_default();
            let event = type_args
                .first()
                .cloned()
                .unwrap_or_else(|| "Event".to_owned());
            let target = type_args.get(1).cloned();
            Ty::Trigger { event, target }
        }
        "SmallVec" => {
            let elem = gen_args
                .as_ref()
                .and_then(|g| g.children().find(|c| is_type_node_kind(c.kind())))
                .map_or(Ty::Unknown, |c| {
                    parse_type_node_with_user_types(&c, user_types)
                });
            let cap = gen_args
                .as_ref()
                .and_then(|g| extract_generic_arg_int(g, 1))
                .unwrap_or(0);
            Ty::SmallVec {
                elem: Box::new(elem),
                cap,
            }
        }
        "InlineStr" => {
            let cap = gen_args
                .as_ref()
                .and_then(|g| extract_generic_arg_int(g, 0))
                .unwrap_or(0);
            Ty::InlineStr(cap)
        }
        "BitSet" => {
            let bits = gen_args
                .as_ref()
                .and_then(|g| extract_generic_arg_int(g, 0))
                .unwrap_or(32);
            Ty::BitSet(bits)
        }
        "InputBuffer" => {
            let action = gen_args
                .as_ref()
                .and_then(|g| g.children().find(|c| is_type_node_kind(c.kind())))
                .map_or_else(
                    || "u16".to_owned(),
                    |c| c.text().to_string().trim().to_owned(),
                );
            let cap = gen_args
                .as_ref()
                .and_then(|g| extract_generic_arg_int(g, 1))
                .unwrap_or(4);
            Ty::InputBuffer { action, cap }
        }
        "Ref" => {
            let inner = gen_args
                .as_ref()
                .and_then(|g| g.children().find(|c| is_type_node_kind(c.kind())))
                .map_or_else(
                    || "Entity".to_owned(),
                    |c| c.text().to_string().trim().to_owned(),
                );
            Ty::Ref(inner)
        }
        "Asset" => {
            let inner = gen_args
                .as_ref()
                .and_then(|g| g.children().find(|c| is_type_node_kind(c.kind())))
                .map_or_else(
                    || "Untyped".to_owned(),
                    |c| c.text().to_string().trim().to_owned(),
                );
            Ty::Asset(inner)
        }
        other => Ty::Named(other.to_owned()),
    }
}

fn parse_int_lit_i128(text: &str) -> Option<i128> {
    const SUFFIXES: [&str; 12] = [
        "usize", "isize", "u128", "i128", "u64", "i64", "u32", "i32", "u16", "i16", "u8", "i8",
    ];
    let mut base = text;
    for sfx in SUFFIXES {
        if let Some(stripped) = base.strip_suffix(sfx) {
            base = stripped;
            break;
        }
    }
    let (radix, body) = if let Some(b) = base.strip_prefix("0x").or_else(|| base.strip_prefix("0X"))
    {
        (16, b)
    } else if let Some(b) = base.strip_prefix("0b").or_else(|| base.strip_prefix("0B")) {
        (2, b)
    } else if let Some(b) = base.strip_prefix("0o").or_else(|| base.strip_prefix("0O")) {
        (8, b)
    } else {
        (10, base)
    };
    let clean: String = body.chars().filter(|&c| c != '_').collect();
    if clean.is_empty() || clean.starts_with('+') || clean.starts_with('-') {
        return None;
    }
    i128::from_str_radix(&clean, radix).ok()
}

fn parse_int_lit_token(t: &SyntaxToken) -> Option<usize> {
    let val = parse_int_lit_i128(t.text())?;
    usize::try_from(val).ok()
}

fn eval_const_int_node(node: &SyntaxNode) -> Option<i128> {
    match node.kind() {
        SyntaxKind::LiteralExpr => {
            let tok = node
                .children_with_tokens()
                .filter_map(|e| e.into_token())
                .find(|t| !t.kind().is_trivia())?;
            if tok.kind() == SyntaxKind::IntLit {
                parse_int_lit_i128(tok.text())
            } else {
                None
            }
        }
        SyntaxKind::ParenExpr => {
            let mut inner: Option<SyntaxNode> = None;
            for el in node.children_with_tokens() {
                if let Some(t) = el.as_token() {
                    if t.kind().is_trivia()
                        || matches!(t.kind(), SyntaxKind::LParen | SyntaxKind::RParen)
                    {
                        continue;
                    }
                    return None;
                } else if let Some(n) = el.as_node() {
                    if inner.is_some() {
                        return None;
                    }
                    inner = Some(n.clone());
                }
            }
            eval_const_int_node(&inner?)
        }
        SyntaxKind::PrefixExpr => {
            let mut op: Option<SyntaxKind> = None;
            let mut operand: Option<SyntaxNode> = None;
            for el in node.children_with_tokens() {
                if let Some(t) = el.as_token() {
                    if t.kind().is_trivia() {
                        continue;
                    }
                    if op.is_none() && operand.is_none() {
                        op = Some(t.kind());
                    } else {
                        return None;
                    }
                } else if let Some(n) = el.as_node() {
                    if op.is_some() && operand.is_none() {
                        operand = Some(n.clone());
                    } else {
                        return None;
                    }
                }
            }
            let val = eval_const_int_node(&operand?)?;
            match op? {
                SyntaxKind::Plus => Some(val),
                SyntaxKind::Minus => val.checked_neg(),
                _ => None,
            }
        }
        SyntaxKind::BinaryExpr => {
            let mut lhs: Option<SyntaxNode> = None;
            let mut op: Option<SyntaxKind> = None;
            let mut rhs: Option<SyntaxNode> = None;
            for el in node.children_with_tokens() {
                if let Some(t) = el.as_token() {
                    if t.kind().is_trivia() {
                        continue;
                    }
                    if lhs.is_some() && op.is_none() && rhs.is_none() {
                        op = Some(t.kind());
                    } else {
                        return None;
                    }
                } else if let Some(n) = el.as_node() {
                    if lhs.is_none() {
                        lhs = Some(n.clone());
                    } else if op.is_some() && rhs.is_none() {
                        rhs = Some(n.clone());
                    } else {
                        return None;
                    }
                }
            }
            let l = eval_const_int_node(&lhs?)?;
            let r = eval_const_int_node(&rhs?)?;
            match op? {
                SyntaxKind::Plus => l.checked_add(r),
                SyntaxKind::Minus => l.checked_sub(r),
                SyntaxKind::Star => l.checked_mul(r),
                SyntaxKind::Slash => (r != 0).then(|| l.checked_div(r)).flatten(),
                SyntaxKind::Percent => (r != 0).then(|| l.checked_rem(r)).flatten(),
                SyntaxKind::Shl => u32::try_from(r)
                    .ok()
                    .filter(|&s| s < 128)
                    .and_then(|s| l.checked_shl(s)),
                SyntaxKind::Shr => u32::try_from(r)
                    .ok()
                    .filter(|&s| s < 128)
                    .and_then(|s| l.checked_shr(s)),
                SyntaxKind::Amp => Some(l & r),
                SyntaxKind::Pipe => Some(l | r),
                SyntaxKind::Caret => Some(l ^ r),
                _ => None,
            }
        }
        SyntaxKind::TypeRef => {
            let mut tok_val: Option<i128> = None;
            let mut node_val: Option<i128> = None;
            let mut count = 0usize;
            for el in node.children_with_tokens() {
                if let Some(t) = el.as_token() {
                    if t.kind().is_trivia() {
                        continue;
                    }
                    count += 1;
                    if t.kind() == SyntaxKind::IntLit {
                        tok_val = parse_int_lit_i128(t.text());
                    } else {
                        return None;
                    }
                } else if let Some(n) = el.as_node() {
                    count += 1;
                    node_val = eval_const_int_node(n);
                }
            }
            if count == 1 {
                tok_val.or(node_val)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn extract_array_len(node: &SyntaxNode) -> Option<usize> {
    let mut after_semi = false;
    for el in node.children_with_tokens() {
        if !after_semi {
            if el.as_token().is_some_and(|t| t.kind() == SyntaxKind::Semi) {
                after_semi = true;
            }
            continue;
        }
        if let Some(t) = el.as_token() {
            if t.kind().is_trivia() {
                continue;
            }
            if t.kind() == SyntaxKind::IntLit {
                return parse_int_lit_token(t);
            }
            return None;
        } else if let Some(n) = el.as_node() {
            return eval_const_int_node(n).and_then(|v| usize::try_from(v).ok());
        }
    }
    None
}

fn extract_generic_arg_int(gen_args: &SyntaxNode, arg_index: usize) -> Option<usize> {
    let mut current_arg = 0usize;
    let mut val: Option<usize> = None;
    let mut count = 0usize;
    for el in gen_args.children_with_tokens() {
        if let Some(t) = el.as_token() {
            if t.kind().is_trivia() || matches!(t.kind(), SyntaxKind::Lt | SyntaxKind::Gt) {
                continue;
            }
            if t.kind() == SyntaxKind::Comma {
                if current_arg == arg_index {
                    return if count == 1 { val } else { None };
                }
                current_arg += 1;
                if current_arg > arg_index {
                    break;
                }
            } else if current_arg == arg_index {
                count += 1;
                if t.kind() == SyntaxKind::IntLit {
                    val = parse_int_lit_token(t);
                } else {
                    return None;
                }
            }
        } else if let Some(n) = el.as_node()
            && current_arg == arg_index
        {
            count += 1;
            val = eval_const_int_node(n).and_then(|v| usize::try_from(v).ok());
        }
    }
    if current_arg == arg_index && count == 1 {
        val
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies dimensional exponents multiply cleanly (velocity = dist / time, accel = dist / time^2).
    #[test]
    fn unit_dim_arithmetic_and_compatibility() {
        let dist = UnitDim::METERS;
        let time = UnitDim::SEC;
        let vel = dist.div(time);
        assert_eq!(vel, UnitDim::MPS);
        assert_eq!(vel.div(time), UnitDim::MPS2);
        assert_eq!(vel.mul(time), dist);

        let sec_ty = Ty::UnitScalar {
            name: "sec".to_owned(),
            dim: UnitDim::SEC,
        };
        let ms_ty = Ty::UnitScalar {
            name: "ms".to_owned(),
            dim: UnitDim::SEC,
        };
        let meters_ty = Ty::UnitScalar {
            name: "meters".to_owned(),
            dim: UnitDim::METERS,
        };
        assert!(sec_ty.is_compatible_with(&ms_ty));
        assert!(!sec_ty.is_compatible_with(&meters_ty));
    }

    /// Verifies unit-literal suffix recognizer maps physics units and rejects unknown suffixes.
    #[test]
    fn unit_from_literal_mapping() {
        assert_eq!(
            Ty::unit_from_literal("9.81_mps2"),
            Some(Ty::UnitScalar {
                name: "mps2".to_owned(),
                dim: UnitDim::MPS2,
            })
        );
        assert_eq!(
            Ty::unit_from_literal("16_ms"),
            Some(Ty::UnitScalar {
                name: "ms".to_owned(),
                dim: UnitDim::SEC,
            })
        );
        assert_eq!(Ty::unit_from_literal("42"), None);
    }

    /// Verifies integer literal radix/separator parsing and constant integer arithmetic.
    #[test]
    fn int_literal_and_const_expr_parsing() {
        assert_eq!(parse_int_lit_i128("1_024"), Some(1024));
        assert_eq!(parse_int_lit_i128("1_28"), Some(128));
        assert_eq!(parse_int_lit_i128("0x10"), Some(16));
        assert_eq!(parse_int_lit_i128("0xFF_FFu32"), Some(65535));
        assert_eq!(parse_int_lit_i128("0b100"), Some(4));
        assert_eq!(parse_int_lit_i128("0o10"), Some(8));
        assert_eq!(parse_int_lit_i128("0x"), None);
        assert_eq!(parse_int_lit_i128("0b102"), None);
    }
}
