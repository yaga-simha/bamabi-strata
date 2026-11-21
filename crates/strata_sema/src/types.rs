//! Strata v2.0 static type system and SI physical unit dimensional algebra.

use serde::{Deserialize, Serialize};
use strata_syntax::SyntaxKind;
use strata_syntax::SyntaxNode;

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
    UnitScalar { name: String, dim: UnitDim },
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
    Array { elem: Box<Ty>, len: usize },
    SmallVec { elem: Box<Ty>, cap: usize },
    InlineStr(usize),
    BitSet(usize),
    InputBuffer { action: String, cap: usize },
    GraceWindow,
    Ref(String),
    Asset(String),
    Named(String),
    Tuple(Vec<Ty>),
    Unit,
    BannedWire(String),
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
        if self == other {
            return true;
        }
        match (self, other) {
            (Self::UnitScalar { dim: a, .. }, Self::UnitScalar { dim: b, .. }) => a == b,
            _ => false,
        }
    }

    /// Canonical Rust/C ABI type tag string matching `bamabi_macros::classify::canonical_field_type_tag`.
    pub fn canonical_tag(&self) -> String {
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
            Self::Array { elem, len } => format!("[{};{}]", elem.canonical_tag(), len),
            Self::SmallVec { elem, cap } => {
                format!("SmallVecPod<{},{}>", elem.canonical_tag(), cap)
            }
            Self::InlineStr(cap) => format!("InlineStr<{cap}>"),
            Self::BitSet(bits) => format!("BitSet<{}>", (*bits).div_ceil(32).max(1)),
            Self::InputBuffer { cap, .. } => format!("InputBuffer<{cap}>"),
            Self::Ref(_) => "FfiEntity".to_owned(),
            Self::Asset(_) => "FfiAssetHandle".to_owned(),
            Self::Named(n) | Self::BannedWire(n) => n.clone(),
            Self::Tuple(_) => "Tuple".to_owned(),
            Self::Unit => "()".to_owned(),
            Self::Unknown => "unknown".to_owned(),
        }
    }

    /// Parses a unit scalar suffix (`_ms`, `_s`, `_hz`, `_f`, `_rad`, `_deg`, `_m`, `_mps`, `_mps2`)
    /// into its [`UnitDim`].
    pub fn unit_from_literal(lit: &str) -> Option<Self> {
        let (name, dim) = if lit.ends_with("_sec") || lit.ends_with("_s") {
            ("sec", UnitDim::SEC)
        } else if lit.ends_with("_ms") {
            ("ms", UnitDim::SEC)
        } else if lit.ends_with("_hz") {
            ("hz", UnitDim::HZ)
        } else if lit.ends_with("_frames") || lit.ends_with("_f") {
            ("frames", UnitDim::FRAMES)
        } else if lit.ends_with("_rad") {
            ("rad", UnitDim::RAD)
        } else if lit.ends_with("_deg") {
            ("deg", UnitDim::RAD)
        } else if lit.ends_with("_meters") || lit.ends_with("_m") {
            ("meters", UnitDim::METERS)
        } else if lit.ends_with("_mps2") {
            ("mps2", UnitDim::MPS2)
        } else if lit.ends_with("_mps") {
            ("mps", UnitDim::MPS)
        } else {
            return None;
        };
        Some(Self::UnitScalar {
            name: name.to_owned(),
            dim,
        })
    }
}

/// Parses a CST type node (`TypeRef`, `ArrayType`, `TupleType`, `RefType`, `PtrTermType`) into a [`Ty`].
pub fn parse_type_node(node: &SyntaxNode) -> Ty {
    match node.kind() {
        SyntaxKind::ArrayType => {
            let child_types: Vec<_> = node
                .children()
                .filter(|c| is_type_node_kind(c.kind()))
                .collect();
            let elem = child_types.first().map_or(Ty::Unknown, parse_type_node);
            let len = extract_first_int_in_node(node).unwrap_or(0);
            Ty::Array {
                elem: Box::new(elem),
                len,
            }
        }
        SyntaxKind::TupleType => {
            let items = node
                .children()
                .filter(|c| is_type_node_kind(c.kind()))
                .map(|c| parse_type_node(&c))
                .collect::<Vec<_>>();
            if items.is_empty() {
                Ty::Unit
            } else {
                Ty::Tuple(items)
            }
        }
        SyntaxKind::RefType | SyntaxKind::PtrTermType => {
            if let Some(inner) = node.children().find(|c| is_type_node_kind(c.kind())) {
                parse_type_node(&inner)
            } else {
                Ty::Unknown
            }
        }
        SyntaxKind::TypeRef => parse_typeref_node(node),
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

fn parse_typeref_node(node: &SyntaxNode) -> Ty {
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
        "mat3" => Ty::Mat3,
        "mat4" => Ty::Mat4,
        "rgba8" => Ty::Rgba8,
        "rgba" => Ty::Rgba,
        "GraceWindow" => Ty::GraceWindow,
        "usize" | "isize" | "u128" | "i128" | "String" | "Vec" | "Box" | "char" => {
            Ty::BannedWire(base_name)
        }
        "SmallVec" => {
            let elem = gen_args
                .as_ref()
                .and_then(|g| g.children().find(|c| is_type_node_kind(c.kind())))
                .map_or(Ty::Unknown, |c| parse_type_node(&c));
            let cap = gen_args
                .as_ref()
                .and_then(extract_first_int_in_node)
                .unwrap_or(0);
            Ty::SmallVec {
                elem: Box::new(elem),
                cap,
            }
        }
        "InlineStr" => {
            let cap = gen_args
                .as_ref()
                .and_then(extract_first_int_in_node)
                .unwrap_or(0);
            Ty::InlineStr(cap)
        }
        "BitSet" => {
            let bits = gen_args
                .as_ref()
                .and_then(extract_first_int_in_node)
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
                .and_then(extract_first_int_in_node)
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

fn extract_first_int_in_node(node: &SyntaxNode) -> Option<usize> {
    node.descendants_with_tokens()
        .filter_map(|e| e.into_token())
        .find(|t| t.kind() == SyntaxKind::IntLit)
        .and_then(|t| {
            let raw = t.text().split('_').next().unwrap_or("");
            raw.parse::<usize>().ok()
        })
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
}
