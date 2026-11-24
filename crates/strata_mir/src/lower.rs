//! Direct typed-HIR -> executable SSA CFG `StrataMir` lowering pipeline.
//!
//! Zero string-splitting or `source_body.contains(...)` heuristics; every expression, statement,
//! query, control-flow construct, primitive operation, migration, and synthesized timer tick lowers
//! to complete verifiable basic blocks and SSA registers.

use crate::ir::{
    BlockId, Inst, LocalId, MirChangedTerm, MirConstVal, MirFnKind, MirFunction, MirModule,
    MirNetComponent, MirNetFieldSpec, MirNetHandshake, MirNetSimTest, MirParam, MirQuantizeSpec,
    MirQueryBinding, MirQueryTermBinding, MirResourceBinding, MirRpc, MirStmt, MirStreamOp,
    MirStreamOpKind, MirType, Terminator,
};
use crate::passes;
use indexmap::IndexMap;
use std::collections::{BTreeSet, HashMap, HashSet};
use strata_sema::access::{QueryAccessDesc, QueryTerm, TermAccessMode, storage_keys_overlap};
use strata_sema::hir::{
    AnalyzedModule, AuthorityKind, HirAssignOp, HirBinOp, HirCall, HirCallable, HirCompInit,
    HirCurve, HirExpr, HirFn, HirFor, HirForIter, HirLValue, HirMatch, HirMigration, HirNetSimTest,
    HirParam, HirParamKind, HirPattern, HirQuantizeSpec, HirQuery, HirReduceEntry, HirRpc,
    HirSchedule, HirScheduleGroup, HirSpawn, HirStmt, HirTable, HirTimeline, HirUnOp,
    NetComponentMeta, NetDirection, NetReliability,
};
use strata_sema::layout::{EnumDef, SchemaItemKind, SolvedLayout};
use strata_sema::types::Ty;

/// Immutable module-wide symbol and layout lookup context for MIR lowering and synthesis passes.
#[derive(Clone)]
pub(crate) struct MirLowerCtx {
    pub(crate) module_path: String,
    pub(crate) is_deterministic: bool,
    pub(crate) layouts_by_key: HashMap<String, SolvedLayout>,
    pub(crate) all_layouts: Vec<SolvedLayout>,
    pub(crate) enums: IndexMap<String, EnumDef>,
    pub(crate) const_vals: HashMap<String, MirConstVal>,
    pub(crate) const_exprs: HashMap<String, HirExpr>,
    pub(crate) tables: HashMap<String, HirTable>,
    pub(crate) curves: HashMap<String, HirCurve>,
    pub(crate) timelines: HashMap<String, HirTimeline>,
    pub(crate) objects: HashSet<String>,
    pub(crate) fn_ret_tys: HashMap<String, MirType>,
    pub(crate) field_defaults: IndexMap<String, IndexMap<String, MirConstVal>>,
    pub(crate) spatial_names: HashMap<String, String>,
}

impl MirLowerCtx {
    /// Constructs a lowering context from an analyzed module.
    pub(crate) fn from_analyzed(analyzed: &AnalyzedModule) -> Self {
        let all_layouts = deduplicate_layouts(analyzed.layouts.values().cloned());
        let layouts_by_key = index_layouts(&analyzed.layouts);

        let mut const_vals = HashMap::new();
        let mut const_exprs = HashMap::new();
        for c in &analyzed.consts {
            if let Some(ref ex) = c.expr {
                const_exprs.insert(c.name.clone(), ex.clone());
                if let Some(val) = eval_hir_const_for_ty(
                    ex,
                    Some(&c.ty),
                    &const_vals,
                    &analyzed.enums,
                    &layouts_by_key,
                ) {
                    const_vals.insert(c.name.clone(), val);
                }
            }
        }

        let mut field_defaults: IndexMap<String, IndexMap<String, MirConstVal>> = IndexMap::new();
        for (layout_key, fields) in &analyzed.field_defaults {
            let layout_opt = analyzed.layouts.get(layout_key);
            let mut eval_map = IndexMap::new();
            for (fname, fexpr) in fields {
                let fty_opt = layout_opt.and_then(|l| {
                    l.fields
                        .iter()
                        .find(|sf| sf.name == *fname)
                        .map(|sf| &sf.ty)
                });
                if let Some(val) = eval_hir_const_for_ty(
                    fexpr,
                    fty_opt,
                    &const_vals,
                    &analyzed.enums,
                    &layouts_by_key,
                ) {
                    eval_map.insert(fname.clone(), val);
                }
            }
            if !eval_map.is_empty() {
                field_defaults.insert(layout_key.clone(), eval_map);
            }
        }
        for fsm in &analyzed.fsms {
            let init_idx = fsm
                .states
                .iter()
                .position(|s| s == &fsm.initial_state)
                .unwrap_or(0) as i64;
            if init_idx != 0 {
                field_defaults
                    .entry(fsm.state_layout.canonical_name.clone())
                    .or_default()
                    .insert("__state".to_owned(), MirConstVal::Int(init_idx));
            }
        }

        let tables = analyzed
            .tables
            .iter()
            .map(|t| (t.name.clone(), t.clone()))
            .collect();
        let curves = analyzed
            .curves
            .iter()
            .map(|c| (c.name.clone(), c.clone()))
            .collect();
        let timelines = analyzed
            .timelines
            .iter()
            .map(|t| (t.name.clone(), t.clone()))
            .collect();
        let objects = analyzed.objects.iter().map(|o| o.name.clone()).collect();
        let fn_ret_tys = analyzed
            .fns
            .iter()
            .map(|f| (f.name.clone(), mir_ty_from_hir(&f.ret_ty)))
            .collect();
        let mut spatial_names = HashMap::new();
        for sp in &analyzed.spatial_indices {
            spatial_names.insert(sp.name.clone(), sp.name.clone());
            spatial_names.insert(sp.resource_layout.canonical_name.clone(), sp.name.clone());
            if let Some(short) = sp.resource_layout.canonical_name.rsplit("::").next() {
                spatial_names.insert(short.to_owned(), sp.name.clone());
            }
        }

        Self {
            module_path: analyzed.module_path.clone(),
            is_deterministic: analyzed.is_deterministic,
            layouts_by_key,
            all_layouts,
            enums: analyzed.enums.clone(),
            const_vals,
            const_exprs,
            tables,
            curves,
            timelines,
            objects,
            fn_ret_tys,
            field_defaults,
            spatial_names,
        }
    }

    /// Reconstructs a lowering context from an already-partially-built [`MirModule`].
    pub(crate) fn from_module(module: &MirModule) -> Self {
        let mut enums_map = IndexMap::new();
        for en in &module.enums {
            let short = en
                .canonical_name
                .rsplit("::")
                .next()
                .unwrap_or(&en.canonical_name)
                .to_owned();
            enums_map.insert(short, en.clone());
            enums_map.insert(en.canonical_name.clone(), en.clone());
        }
        let mut raw_layouts = IndexMap::new();
        for l in &module.layouts {
            raw_layouts.insert(l.canonical_name.clone(), l.clone());
        }
        let layouts_by_key = index_layouts(&raw_layouts);
        let mut const_vals = HashMap::new();
        let mut const_exprs = HashMap::new();
        for c in &module.consts {
            if let Some(ref ex) = c.expr {
                const_exprs.insert(c.name.clone(), ex.clone());
                if let Some(val) =
                    eval_hir_const_for_ty(ex, Some(&c.ty), &const_vals, &enums_map, &layouts_by_key)
                {
                    const_vals.insert(c.name.clone(), val);
                }
            }
        }
        let tables = module
            .tables
            .iter()
            .map(|t| (t.name.clone(), t.clone()))
            .collect();
        let curves = module
            .curves
            .iter()
            .map(|c| (c.name.clone(), c.clone()))
            .collect();
        let timelines = module
            .timelines
            .iter()
            .map(|t| (t.name.clone(), t.clone()))
            .collect();
        let objects = module.objects.iter().map(|o| o.name.clone()).collect();
        let fn_ret_tys = module
            .fns
            .iter()
            .map(|f| (f.name.clone(), f.ret_ty.clone()))
            .collect();
        let mut spatial_names = HashMap::new();
        for sp in &module.spatial_indices {
            spatial_names.insert(sp.name.clone(), sp.name.clone());
            spatial_names.insert(sp.resource_layout.canonical_name.clone(), sp.name.clone());
            if let Some(short) = sp.resource_layout.canonical_name.rsplit("::").next() {
                spatial_names.insert(short.to_owned(), sp.name.clone());
            }
        }

        Self {
            module_path: module.module_path.clone(),
            is_deterministic: module.is_deterministic,
            layouts_by_key,
            all_layouts: module.layouts.clone(),
            enums: enums_map,
            const_vals,
            const_exprs,
            tables,
            curves,
            timelines,
            objects,
            fn_ret_tys,
            field_defaults: module.field_defaults.clone(),
            spatial_names,
        }
    }

    pub(crate) fn find_layout(&self, key: &str) -> Option<&SolvedLayout> {
        self.layouts_by_key.get(key).or_else(|| {
            let qualified = format!("{}::{key}", self.module_path);
            self.layouts_by_key.get(&qualified)
        })
    }

    pub(crate) fn resolve_canonical(&self, key: &str) -> String {
        if let Some(l) = self.find_layout(key) {
            return l.canonical_name.clone();
        }
        if key.contains("::") {
            key.to_owned()
        } else {
            format!("{}::{key}", self.module_path)
        }
    }

    pub(crate) fn resolve_field(&self, layout_key: &str, field_path: &str) -> (u32, MirType, Ty) {
        let Some(mut layout) = self.find_layout(layout_key) else {
            return (0, MirType::F32, Ty::F32);
        };
        let mut offset = 0usize;
        let parts: Vec<&str> = field_path.split('.').collect();
        let mut cur_ty = Ty::Unknown;
        for (i, part) in parts.iter().enumerate() {
            if let Some(sf) = layout.fields.iter().find(|f| f.name == *part) {
                offset += sf.offset;
                cur_ty = sf.ty.clone();
                if i + 1 < parts.len() {
                    if let Ty::Named(ref inner_name) = sf.ty
                        && let Some(inner_layout) = self.find_layout(inner_name)
                    {
                        layout = inner_layout;
                        continue;
                    }
                    // Vector subcomponent (e.g. `pos.xy.x` -> offset + lane*4)
                    if let Some(lane) = vec_lane_index(parts[i + 1]) {
                        offset += (lane as usize) * 4;
                        let (mty, hty) = match cur_ty {
                            Ty::IVec2 | Ty::IVec3 => (MirType::I32, Ty::I32),
                            Ty::UVec2 => (MirType::U32, Ty::U32),
                            _ => (MirType::F32, Ty::F32),
                        };
                        return (offset as u32, mty, hty);
                    }
                }
            } else {
                return (offset as u32, MirType::F32, Ty::F32);
            }
        }
        (offset as u32, mir_ty_from_hir(&cur_ty), cur_ty)
    }

    pub(crate) fn resolve_field_opt(&self, layout_key: &str, field_path: &str) -> Option<MirType> {
        let mut layout = self.find_layout(layout_key)?;
        let parts: Vec<&str> = field_path.split('.').collect();
        let mut cur_ty = Ty::Unknown;
        for (i, part) in parts.iter().enumerate() {
            let sf = layout.fields.iter().find(|f| f.name == *part)?;
            cur_ty = sf.ty.clone();
            if i + 1 < parts.len() {
                if let Ty::Named(ref inner_name) = sf.ty
                    && let Some(inner_layout) = self.find_layout(inner_name)
                {
                    layout = inner_layout;
                    continue;
                }
                if vec_lane_index(parts[i + 1]).is_some() {
                    let mty = match cur_ty {
                        Ty::IVec2 | Ty::IVec3 => MirType::I32,
                        Ty::UVec2 => MirType::U32,
                        _ => MirType::F32,
                    };
                    return Some(mty);
                }
            }
        }
        let mty = mir_ty_from_hir(&cur_ty);
        (mty != MirType::Unit).then_some(mty)
    }

    pub(crate) fn enum_discriminant(&self, path: &str) -> Option<i64> {
        let (ename, var) = path.split_once("::")?;
        let edef = self
            .enums
            .get(ename)
            .or_else(|| self.enums.get(&format!("{}::{ename}", self.module_path)))?;
        edef.variants
            .iter()
            .find(|(v, _)| v == var)
            .map(|(_, disc)| *disc)
    }

    pub(crate) fn layout_defaults(
        &self,
        layout_key: &str,
    ) -> Option<&IndexMap<String, MirConstVal>> {
        self.field_defaults
            .get(layout_key)
            .or_else(|| {
                let canon = self.resolve_canonical(layout_key);
                self.field_defaults.get(&canon)
            })
            .or_else(|| {
                let qualified = format!("{}::{layout_key}", self.module_path);
                self.field_defaults.get(&qualified)
            })
    }
}

fn deduplicate_layouts(iter: impl Iterator<Item = SolvedLayout>) -> Vec<SolvedLayout> {
    let mut layouts: Vec<SolvedLayout> = iter.collect();
    let mut seen = HashSet::new();
    layouts.retain(|l| seen.insert(l.canonical_name.clone()));
    layouts
}

fn index_layouts(raw: &IndexMap<String, SolvedLayout>) -> HashMap<String, SolvedLayout> {
    let mut map = HashMap::new();
    for (alias_key, layout) in raw {
        map.insert(alias_key.clone(), layout.clone());
        map.insert(layout.canonical_name.clone(), layout.clone());
        let short = layout
            .canonical_name
            .rsplit("::")
            .next()
            .unwrap_or(&layout.canonical_name);
        map.insert(short.to_owned(), layout.clone());
        if let Some((comp, stratum)) = short.split_once("__") {
            map.insert(format!("{comp}::{stratum}"), layout.clone());
            if let Some((mod_prefix, _)) = layout.canonical_name.rsplit_once("::") {
                map.insert(format!("{mod_prefix}::{comp}::{stratum}"), layout.clone());
            }
        } else if layout.item_kind == SchemaItemKind::SoaHot {
            map.insert(format!("{short}::hot"), layout.clone());
            map.insert(format!("{}::hot", layout.canonical_name), layout.clone());
        }
    }
    map
}

/// Converts a semantic [`Ty`] into a backend-neutral [`MirType`].
pub(crate) fn mir_ty_from_hir(ty: &Ty) -> MirType {
    match ty {
        Ty::U8 => MirType::U8,
        Ty::U16 => MirType::U16,
        Ty::U32 | Ty::Rgba8 => MirType::U32,
        Ty::U64 => MirType::U64,
        Ty::I8 => MirType::I8,
        Ty::I16 => MirType::I16,
        Ty::I32 => MirType::I32,
        Ty::I64 => MirType::I64,
        Ty::F32 | Ty::UnitScalar { .. } => MirType::F32,
        Ty::F64 => MirType::F64,
        Ty::Fix32 => MirType::Fix32,
        Ty::Fix64 => MirType::Fix64,
        Ty::Bool => MirType::Bool,
        Ty::Sym => MirType::Sym,
        Ty::Vec2 => MirType::Vec2,
        Ty::IVec2 => MirType::IVec2,
        Ty::UVec2 => MirType::UVec2,
        Ty::Vec3 => MirType::Vec3,
        Ty::IVec3 => MirType::IVec3,
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => MirType::Vec4,
        Ty::Mat3 => MirType::Named("mat3".to_owned()),
        Ty::Mat4 => MirType::Named("mat4".to_owned()),
        Ty::GraceWindow => MirType::Named("GraceWindow".to_owned()),
        Ty::InputBuffer { action, cap } => MirType::Named(format!("InputBuffer<{action},{cap}>")),
        Ty::BitSet(bits) => MirType::Named(format!("BitSet<{bits}>")),
        Ty::InlineStr(cap) => MirType::Named(format!("InlineStr<{cap}>")),
        Ty::Array { elem, len } => MirType::Array {
            elem: Box::new(mir_ty_from_hir(elem)),
            len: *len,
        },
        Ty::Tuple(items) => MirType::Tuple(items.iter().map(mir_ty_from_hir).collect()),
        Ty::Ref(_) => MirType::Entity,
        Ty::Named(n) => {
            if n == "Entity" {
                MirType::Entity
            } else {
                MirType::Named(n.clone())
            }
        }
        Ty::Asset(a) => MirType::Named(format!("Asset<{a}>")),
        Ty::SmallVec { elem, cap } => MirType::Named(format!("SmallVec<{elem:?},{cap}>")),
        Ty::Option(inner) => mir_ty_from_hir(inner),
        Ty::Borrow { mutable: true, .. } => MirType::MutPtr,
        Ty::Borrow { mutable: false, .. } => MirType::Ptr,
        Ty::Result { .. }
        | Ty::Trigger { .. }
        | Ty::QueryRow(_)
        | Ty::Record(_)
        | Ty::Unit
        | Ty::Unknown
        | Ty::BannedWire(_) => MirType::Unit,
    }
}

/// Converts a semantic [`Ty`] into a wire/RPC [`MirType`], preserving distinct integer vector
/// (`IVec2`/`IVec3`/`UVec2`) and `Vec3a` type identities for ABI struct and codec generation.
pub(crate) fn mir_wire_ty_from_hir(ty: &Ty) -> MirType {
    match ty {
        Ty::IVec2 => MirType::Named("IVec2".to_owned()),
        Ty::IVec3 => MirType::Named("IVec3".to_owned()),
        Ty::UVec2 => MirType::Named("UVec2".to_owned()),
        Ty::Vec3a => MirType::Named("Vec3a".to_owned()),
        Ty::Array { elem, len } => MirType::Array {
            elem: Box::new(mir_wire_ty_from_hir(elem)),
            len: *len,
        },
        _ => mir_ty_from_hir(ty),
    }
}

/// Evaluates a constant [`HirExpr`] into a [`MirConstVal`] with optional expected [`Ty`].
pub(crate) fn eval_hir_const_for_ty(
    expr: &HirExpr,
    expected_ty: Option<&Ty>,
    consts: &HashMap<String, MirConstVal>,
    enums: &IndexMap<String, EnumDef>,
    layouts: &HashMap<String, SolvedLayout>,
) -> Option<MirConstVal> {
    match expr {
        HirExpr::BoolLit(b) => Some(MirConstVal::Bool(*b)),
        HirExpr::IntLit { value, .. } => Some(MirConstVal::Int(*value)),
        HirExpr::FloatLit { value, .. } => Some(MirConstVal::Float(*value)),
        HirExpr::StringLit(s) => Some(MirConstVal::String(s.clone())),
        HirExpr::Tuple { elems, .. } if elems.is_empty() => Some(MirConstVal::Unit),
        HirExpr::Path { name, .. } => {
            if let Some(c) = consts.get(name) {
                return Some(c.clone());
            }
            if let Some(vc) = vec_path_constant(name) {
                return Some(vc);
            }
            if let Some((en, var)) = name.split_once("::")
                && let Some(edef) = enums.get(en)
                && let Some((_, d)) = edef.variants.iter().find(|(v, _)| v == var)
            {
                return Some(MirConstVal::Int(*d));
            }
            None
        }
        HirExpr::Unary { op, expr, .. } => {
            let v = eval_hir_const_for_ty(expr, expected_ty, consts, enums, layouts)?;
            match (op, v) {
                (HirUnOp::Neg, MirConstVal::Int(i)) => Some(MirConstVal::Int(-i)),
                (HirUnOp::Neg, MirConstVal::Float(f)) => Some(MirConstVal::Float(-f)),
                (HirUnOp::Not, MirConstVal::Bool(b)) => Some(MirConstVal::Bool(!b)),
                (HirUnOp::Not, MirConstVal::Int(i)) => Some(MirConstVal::Int(!i)),
                _ => None,
            }
        }
        HirExpr::Binary { op, lhs, rhs, .. } => {
            let l = eval_hir_const_for_ty(lhs, expected_ty, consts, enums, layouts)?;
            let r = eval_hir_const_for_ty(rhs, expected_ty, consts, enums, layouts)?;
            match (l, r) {
                (MirConstVal::Int(a), MirConstVal::Int(b)) => match op {
                    HirBinOp::Add => Some(MirConstVal::Int(a.saturating_add(b))),
                    HirBinOp::Sub => Some(MirConstVal::Int(a.saturating_sub(b))),
                    HirBinOp::Mul => Some(MirConstVal::Int(a.saturating_mul(b))),
                    HirBinOp::Div if b != 0 => Some(MirConstVal::Int(a / b)),
                    HirBinOp::BitAnd => Some(MirConstVal::Int(a & b)),
                    HirBinOp::BitOr => Some(MirConstVal::Int(a | b)),
                    HirBinOp::Shl => Some(MirConstVal::Int(a.wrapping_shl(b as u32))),
                    _ => None,
                },
                (a, b) => {
                    let fa = const_as_f64_any(&a)?;
                    let fb = const_as_f64_any(&b)?;
                    let res = match op {
                        HirBinOp::Add => fa + fb,
                        HirBinOp::Sub => fa - fb,
                        HirBinOp::Mul => fa * fb,
                        HirBinOp::Div => fa / fb,
                        _ => return None,
                    };
                    Some(MirConstVal::Float(res))
                }
            }
        }
        HirExpr::Call(call) => {
            let mut vals = Vec::with_capacity(call.args.len());
            for a in &call.args {
                vals.push(eval_hir_const_for_ty(a, None, consts, enums, layouts)?);
            }
            let short = call
                .callee
                .rsplit("::")
                .next()
                .unwrap_or(call.callee.as_str());
            match short {
                "vec2" | "Vec2" | "ivec2" | "IVec2" | "uvec2" | "UVec2" if vals.len() == 2 => {
                    Some(MirConstVal::Vec2([
                        const_as_f64(&vals[0])?,
                        const_as_f64(&vals[1])?,
                    ]))
                }
                "vec3" | "Vec3" | "ivec3" | "IVec3" if vals.len() == 3 => {
                    Some(MirConstVal::Vec3([
                        const_as_f64(&vals[0])?,
                        const_as_f64(&vals[1])?,
                        const_as_f64(&vals[2])?,
                    ]))
                }
                "vec3a" | "Vec3a" if vals.len() == 3 => Some(MirConstVal::Vec4([
                    const_as_f64(&vals[0])?,
                    const_as_f64(&vals[1])?,
                    const_as_f64(&vals[2])?,
                    0.0,
                ])),
                "vec4" | "Vec4" | "quat" | "Quat" | "rgba" | "Rgba" if vals.len() == 4 => {
                    Some(MirConstVal::Vec4([
                        const_as_f64(&vals[0])?,
                        const_as_f64(&vals[1])?,
                        const_as_f64(&vals[2])?,
                        const_as_f64(&vals[3])?,
                    ]))
                }
                "bits" => {
                    if matches!(expected_ty, Some(Ty::BitSet(_))) {
                        let bit_indices: Vec<MirConstVal> = vals
                            .into_iter()
                            .filter_map(|v| match v {
                                MirConstVal::Int(b) if b >= 0 => Some(MirConstVal::Int(b)),
                                _ => None,
                            })
                            .collect();
                        return Some(MirConstVal::Array(bit_indices));
                    }
                    let mut mask = 0u64;
                    for v in &vals {
                        if let MirConstVal::Int(b) = v
                            && *b >= 0
                            && (*b as u32) < 64
                        {
                            mask |= 1u64 << (*b as u32);
                        }
                    }
                    Some(MirConstVal::Int(mask as i64))
                }
                "meters" | "sec" | "ms" | "rad" | "deg" | "mps" | "mps2" | "hz" | "frames"
                    if vals.len() == 1 =>
                {
                    Some(vals.into_iter().next().unwrap_or(MirConstVal::Unit))
                }
                _ => None,
            }
        }
        HirExpr::ArrayLit { elems, ty } => {
            let elem_ty_opt = match expected_ty.unwrap_or(ty) {
                Ty::Array { elem, .. } | Ty::SmallVec { elem, .. }
                    if !matches!(**elem, Ty::Unknown) =>
                {
                    Some(elem.as_ref())
                }
                _ => None,
            };
            let mut out = Vec::with_capacity(elems.len());
            for it in elems {
                out.push(eval_hir_const_for_ty(
                    it,
                    elem_ty_opt,
                    consts,
                    enums,
                    layouts,
                )?);
            }
            Some(MirConstVal::Array(out))
        }
        HirExpr::StructLit { name, fields, .. } => {
            let layout_opt = layouts
                .get(name)
                .or_else(|| name.rsplit("::").next().and_then(|s| layouts.get(s)))
                .or_else(|| match expected_ty {
                    Some(Ty::Named(k)) => layouts
                        .get(k)
                        .or_else(|| k.rsplit("::").next().and_then(|s| layouts.get(s))),
                    _ => None,
                });
            let mut out = Vec::with_capacity(fields.len());
            for (fname, fexpr) in fields {
                let declared_fty = layout_opt.and_then(|l| {
                    l.fields
                        .iter()
                        .find(|sf| !sf.is_padding && sf.name == *fname)
                        .map(|sf| sf.ty.clone())
                });
                let fty = declared_fty.unwrap_or_else(|| fexpr.ty());
                let fty_opt = (!matches!(fty, Ty::Unknown)).then_some(&fty);
                out.push((
                    fname.clone(),
                    eval_hir_const_for_ty(fexpr, fty_opt, consts, enums, layouts)?,
                ));
            }
            Some(MirConstVal::Struct {
                name: name.clone(),
                fields: out,
            })
        }
        HirExpr::Cast { expr, target_ty } => {
            let v = eval_hir_const_for_ty(expr, None, consts, enums, layouts)?;
            let src_fix = match expr.ty() {
                Ty::Fix32 => Some(false),
                Ty::Fix64 => Some(true),
                _ => match expr.as_ref() {
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
            match target_ty {
                Ty::F32 | Ty::F64 => const_as_f64(&v).map(MirConstVal::Float),
                Ty::Fix32 => match v {
                    MirConstVal::Int(i) => Some(MirConstVal::Int(i)),
                    MirConstVal::Float(f) if f.is_finite() => {
                        let q = (f * 65_536.0).round() as i32;
                        Some(MirConstVal::Float(f64::from(q) / 65_536.0))
                    }
                    MirConstVal::Float(_) => Some(MirConstVal::Int(0)),
                    MirConstVal::Bool(b) => Some(MirConstVal::Int(i64::from(b))),
                    _ => None,
                },
                Ty::Fix64 => match v {
                    MirConstVal::Int(i) => Some(MirConstVal::Int(i)),
                    MirConstVal::Float(f) if f.is_finite() => {
                        let q = (f * 4_294_967_296.0).round() as i64;
                        Some(MirConstVal::Float((q as f64) / 4_294_967_296.0))
                    }
                    MirConstVal::Float(_) => Some(MirConstVal::Int(0)),
                    MirConstVal::Bool(b) => Some(MirConstVal::Int(i64::from(b))),
                    _ => None,
                },
                Ty::I8 => match v {
                    MirConstVal::Int(i) => Some(MirConstVal::Int(i64::from(i as i8))),
                    MirConstVal::Float(f) => Some(MirConstVal::Int(i64::from(f as i8))),
                    _ => None,
                },
                Ty::I16 => match v {
                    MirConstVal::Int(i) => Some(MirConstVal::Int(i64::from(i as i16))),
                    MirConstVal::Float(f) => Some(MirConstVal::Int(i64::from(f as i16))),
                    _ => None,
                },
                Ty::I32 => match v {
                    MirConstVal::Int(i) => Some(MirConstVal::Int(i64::from(i as i32))),
                    MirConstVal::Float(f) => Some(MirConstVal::Int(i64::from(f as i32))),
                    _ => None,
                },
                Ty::I64 => match v {
                    MirConstVal::Int(i) => Some(MirConstVal::Int(i)),
                    MirConstVal::Float(f) => Some(MirConstVal::Int(f as i64)),
                    _ => None,
                },
                Ty::U8 => match v {
                    MirConstVal::Int(i) => Some(MirConstVal::Int(i64::from(i as u8))),
                    MirConstVal::Float(f) => Some(MirConstVal::Int(i64::from(f as u8))),
                    _ => None,
                },
                Ty::U16 => match v {
                    MirConstVal::Int(i) => Some(MirConstVal::Int(i64::from(i as u16))),
                    MirConstVal::Float(f) => Some(MirConstVal::Int(i64::from(f as u16))),
                    _ => None,
                },
                Ty::U32 | Ty::Sym | Ty::Rgba8 => match v {
                    MirConstVal::Int(i) => Some(MirConstVal::Int(i64::from(i as u32))),
                    MirConstVal::Float(f) => Some(MirConstVal::Int(i64::from(f as u32))),
                    _ => None,
                },
                Ty::U64 => match v {
                    MirConstVal::Int(i) => Some(MirConstVal::Int(i)),
                    MirConstVal::Float(f) => Some(MirConstVal::Int((f as u64) as i64)),
                    _ => None,
                },
                _ => Some(v),
            }
        }
        _ => None,
    }
}

fn const_as_f64(v: &MirConstVal) -> Option<f64> {
    match v {
        MirConstVal::Float(f) if f.is_finite() => Some(*f),
        MirConstVal::Int(i) => Some(*i as f64),
        _ => None,
    }
}

fn const_as_f64_any(v: &MirConstVal) -> Option<f64> {
    match v {
        MirConstVal::Float(f) => Some(*f),
        MirConstVal::Int(i) => Some(*i as f64),
        _ => None,
    }
}

/// Variable / query-row / resource binding tracked while building an SSA CFG.
#[derive(Clone)]
pub(crate) enum VarSlot {
    Slot {
        slot_local: LocalId,
        ty: MirType,
    },
    Imm {
        local: LocalId,
        ty: MirType,
    },
    ResPtr {
        ptr_local: LocalId,
        layout_key: String,
    },
    RowAlias {
        entity_local: Option<LocalId>,
        terms: HashMap<String, TermAccessBinding>,
    },
    OptionalRow {
        cond_local: LocalId,
        entity_local: Option<LocalId>,
        terms: HashMap<String, TermAccessBinding>,
    },
    SingleTermPtr {
        binding: TermAccessBinding,
    },
    SpatialCandidate {
        entity: LocalId,
        pos: LocalId,
    },
    TriggerCtx {
        event: String,
    },
    EventPayloadPtr {
        ptr_local: LocalId,
        layout_key: String,
    },
    Tuple(Vec<VarSlot>),
}

enum MirPlace {
    Slot {
        name: String,
        slot_local: LocalId,
        ty: MirType,
    },
    Ptr {
        ptr_local: LocalId,
        layout_key: String,
        ty: MirType,
    },
    RowAlias {
        terms: HashMap<String, TermAccessBinding>,
    },
    TermField {
        binding: TermAccessBinding,
        field_path: String,
        field_ty: MirType,
    },
    PtrField {
        ptr_local: LocalId,
        layout_key: String,
        field_path: String,
        field_ty: MirType,
    },
    VecLane {
        inner: Box<MirPlace>,
        vec_ty: MirType,
        lane: u8,
    },
    ArrayElem {
        base: Box<MirPlace>,
        index: LocalId,
        elem_ty: MirType,
    },
}

/// Active term pointer binding for a query row or `query_one` point lookup.
#[derive(Clone)]
pub(crate) struct TermAccessBinding {
    pub(crate) canonical_layout: String,
    pub(crate) field_name: Option<String>,
    pub(crate) mode: TermAccessMode,
    pub(crate) col_ptr: LocalId,
    pub(crate) row_ptr: Option<LocalId>,
    pub(crate) present_local: Option<LocalId>,
    pub(crate) is_up_cascade: bool,
}

type OptionalEvalResult = (
    LocalId,
    Option<(Option<LocalId>, HashMap<String, TermAccessBinding>)>,
    Option<TermAccessBinding>,
);

#[derive(Clone)]
struct LoopTarget {
    continue_bb: BlockId,
    break_bb: BlockId,
}

/// Imperative SSA Control-Flow Graph builder for a single [`MirFunction`].
pub(crate) struct CfgBuilder<'a> {
    pub(crate) func: MirFunction,
    pub(crate) ctx: &'a MirLowerCtx,
    pub(crate) cur_bb: BlockId,
    pub(crate) cur_terminated: bool,
    pub(crate) vars: HashMap<String, VarSlot>,
    slot_layouts: HashMap<LocalId, String>,
    loop_stack: Vec<LoopTarget>,
    atomic_rollback_stack: Vec<(LocalId, BlockId)>,
}

impl<'a> CfgBuilder<'a> {
    pub(crate) fn new(mut func: MirFunction, ctx: &'a MirLowerCtx) -> Self {
        if func.blocks.is_empty() {
            func.alloc_block("entry", Terminator::Return(None));
        }
        Self {
            func,
            ctx,
            cur_bb: BlockId(0),
            cur_terminated: false,
            vars: HashMap::new(),
            slot_layouts: HashMap::new(),
            loop_stack: Vec::new(),
            atomic_rollback_stack: Vec::new(),
        }
    }

    pub(crate) fn new_block(&mut self, label: &str) -> BlockId {
        self.func.alloc_block(label, Terminator::Return(None))
    }

    pub(crate) fn switch_to(&mut self, bb: BlockId) {
        self.cur_bb = bb;
        self.cur_terminated = false;
    }

    pub(crate) fn emit(&mut self, dst: Option<LocalId>, inst: Inst) {
        if self.cur_terminated {
            return;
        }
        self.func.blocks[self.cur_bb.0 as usize]
            .stmts
            .push(MirStmt { dst, inst });
    }

    pub(crate) fn alloc_and_emit(&mut self, name: &str, ty: MirType, inst: Inst) -> LocalId {
        let id = self.func.alloc_local(name, ty);
        self.emit(Some(id), inst);
        id
    }

    pub(crate) fn emit_void(&mut self, inst: Inst) {
        self.emit(None, inst);
    }

    pub(crate) fn terminate(&mut self, term: Terminator) {
        if self.cur_terminated {
            return;
        }
        self.func.blocks[self.cur_bb.0 as usize].terminator = term;
        self.cur_terminated = true;
    }

    pub(crate) fn coerce_local_to_ty(
        &mut self,
        val: LocalId,
        cur_ty: MirType,
        target_ty: &MirType,
    ) -> LocalId {
        if &cur_ty == target_ty {
            return val;
        }
        if is_scalar_numeric(&cur_ty) && is_scalar_numeric(target_ty) {
            return self.alloc_and_emit(
                "cast",
                target_ty.clone(),
                Inst::Cast {
                    val,
                    target_ty: target_ty.clone(),
                },
            );
        }
        val
    }

    pub(crate) fn bind_params(&mut self, params: &[HirParam], bind_resource_insts: bool) {
        for p in params {
            let mir_ty = mir_ty_from_hir(&p.ty);
            match p.kind {
                HirParamKind::Trigger => {
                    let event = match &p.ty {
                        Ty::Named(e) => e.clone(),
                        _ => "Event".to_owned(),
                    };
                    self.vars
                        .insert(p.name.clone(), VarSlot::TriggerCtx { event });
                    self.func.params.push(MirParam {
                        name: p.name.clone(),
                        ty: MirType::Ptr,
                        kind: p.kind,
                        local: None,
                        layout_key: None,
                    });
                }
                HirParamKind::ResRead | HirParamKind::ResWrite => {
                    let mutable = p.kind == HirParamKind::ResWrite;
                    let rname = match &p.ty {
                        Ty::Named(n) => n.clone(),
                        _ => p.name.clone(),
                    };
                    let canonical = self.ctx.resolve_canonical(&rname);
                    let ptr_ty = if mutable {
                        MirType::MutPtr
                    } else {
                        MirType::Ptr
                    };
                    let ptr_local = if bind_resource_insts {
                        let inst = if mutable {
                            Inst::ResWrite {
                                resource: rname.clone(),
                            }
                        } else {
                            Inst::ResRead {
                                resource: rname.clone(),
                            }
                        };
                        self.alloc_and_emit(&format!("res_{}", p.name), ptr_ty.clone(), inst)
                    } else {
                        self.func
                            .alloc_local(format!("res_{}", p.name), ptr_ty.clone())
                    };
                    self.func.resources.push(MirResourceBinding {
                        param_name: p.name.clone(),
                        resource_name: rname,
                        canonical_name: canonical.clone(),
                        mutable,
                        ptr_local,
                    });
                    self.func.params.push(MirParam {
                        name: p.name.clone(),
                        ty: ptr_ty,
                        kind: p.kind,
                        local: Some(ptr_local),
                        layout_key: Some(canonical.clone()),
                    });
                    self.vars.insert(
                        p.name.clone(),
                        VarSlot::ResPtr {
                            ptr_local,
                            layout_key: canonical,
                        },
                    );
                }
                HirParamKind::StreamIn => {
                    let pl = self.func.alloc_local(&p.name, MirType::Ptr);
                    let stream_name = match &p.ty {
                        Ty::Named(n) => n.clone(),
                        _ => "Stream".to_owned(),
                    };
                    let layout_key = match &p.ty {
                        Ty::Named(n) => self.ctx.resolve_canonical(n),
                        _ => String::new(),
                    };
                    self.func.params.push(MirParam {
                        name: p.name.clone(),
                        ty: MirType::Ptr,
                        kind: p.kind,
                        local: Some(pl),
                        layout_key: (!layout_key.is_empty()).then_some(layout_key.clone()),
                    });
                    self.func.stream_ops.push(MirStreamOp {
                        kind: MirStreamOpKind::StreamRead,
                        stream: stream_name,
                        canonical_stream: layout_key.clone(),
                        requires_outside_par: true,
                        channel: None,
                    });
                    self.vars.insert(
                        p.name.clone(),
                        VarSlot::EventPayloadPtr {
                            ptr_local: pl,
                            layout_key,
                        },
                    );
                }
                HirParamKind::Ref | HirParamKind::RefMut => {
                    let ptr_ty = if p.kind == HirParamKind::RefMut {
                        MirType::MutPtr
                    } else {
                        MirType::Ptr
                    };
                    let pl = self.func.alloc_local(&p.name, ptr_ty.clone());
                    let layout_key = match &p.ty {
                        Ty::Named(n) | Ty::Ref(n) => self.ctx.resolve_canonical(n),
                        Ty::Borrow { inner, .. } => match inner.as_ref() {
                            Ty::Named(n) | Ty::Ref(n) => self.ctx.resolve_canonical(n),
                            _ => String::new(),
                        },
                        _ => String::new(),
                    };
                    self.func.params.push(MirParam {
                        name: p.name.clone(),
                        ty: ptr_ty,
                        kind: p.kind,
                        local: Some(pl),
                        layout_key: (!layout_key.is_empty()).then_some(layout_key.clone()),
                    });
                    self.vars.insert(
                        p.name.clone(),
                        VarSlot::ResPtr {
                            ptr_local: pl,
                            layout_key,
                        },
                    );
                }
                HirParamKind::Value => {
                    let param_local = self.func.alloc_local(&p.name, mir_ty.clone());
                    let slot_local = self.alloc_and_emit(
                        &format!("slot_{}", p.name),
                        MirType::MutPtr,
                        Inst::SlotAlloc { ty: mir_ty.clone() },
                    );
                    self.emit_void(Inst::SlotStore {
                        slot: slot_local,
                        val: param_local,
                    });
                    self.func.params.push(MirParam {
                        name: p.name.clone(),
                        ty: mir_ty.clone(),
                        kind: p.kind,
                        local: Some(param_local),
                        layout_key: None,
                    });
                    self.vars.insert(
                        p.name.clone(),
                        VarSlot::Slot {
                            slot_local,
                            ty: mir_ty,
                        },
                    );
                }
            }
        }
    }

    pub(crate) fn register_query(&mut self, hq: &HirQuery) -> u32 {
        let query_idx = self.func.query_bindings.len() as u32;
        let terms_desc: Vec<QueryTerm> = hq
            .terms
            .iter()
            .map(|t| QueryTerm {
                storage_key: t.storage_key.clone(),
                field_name: t.field_name.clone(),
                mode: t.mode,
                byte_start: 0,
                byte_end: 0,
            })
            .collect();
        let mut with_filters = std::collections::BTreeSet::new();
        for f in &hq.with_filters {
            with_filters.insert(f.clone());
        }
        let mut without_filters = BTreeSet::new();
        for f in &hq.without_filters {
            without_filters.insert(f.clone());
        }
        let mut changed_filters = BTreeSet::new();
        for f in &hq.changed_filters {
            changed_filters.insert(f.clone());
        }
        for (term_idx, t) in hq.terms.iter().enumerate() {
            let canon_comp = self.ctx.resolve_canonical(&t.canonical_component);
            let is_changed = changed_filters.iter().any(|cf| {
                storage_keys_overlap(cf, &t.storage_key)
                    || storage_keys_overlap(cf, &canon_comp)
                    || cf == &canon_comp
            });
            if is_changed {
                self.func.changed_terms.push(MirChangedTerm {
                    query_idx,
                    term_idx: term_idx as u32,
                    storage_key: t.storage_key.clone(),
                    canonical_component: canon_comp,
                });
            }
        }
        self.func.queries.push(QueryAccessDesc {
            terms: terms_desc,
            with_filters,
            without_filters,
            changed_filters,
            is_task_on_header: false,
            is_point_lookup: hq.is_point_lookup,
            byte_start: 0,
            byte_end: 0,
        });
        let bound_terms = hq
            .terms
            .iter()
            .enumerate()
            .map(|(i, t)| MirQueryTermBinding {
                term_idx: i as u32,
                alias: t.alias.clone(),
                storage_key: t.storage_key.clone(),
                canonical_component: self.ctx.resolve_canonical(&t.canonical_component),
                field_name: t.field_name.clone(),
                mode: t.mode,
                is_sparse: t.is_sparse,
            })
            .collect();
        self.func.query_bindings.push(MirQueryBinding {
            query_idx,
            terms: bound_terms,
            with_filters: hq.with_filters.clone(),
            without_filters: hq.without_filters.clone(),
            is_point_lookup: hq.is_point_lookup,
        });
        query_idx
    }

    pub(crate) fn lower_stmts(&mut self, stmts: &[HirStmt]) {
        for s in stmts {
            if self.cur_terminated {
                break;
            }
            self.lower_stmt(s);
        }
    }

    pub(crate) fn lower_stmt(&mut self, stmt: &HirStmt) {
        if self.cur_terminated {
            return;
        }
        match stmt {
            HirStmt::Let {
                pattern,
                ty,
                value,
                else_block,
                ..
            } => {
                if !else_block.is_empty() {
                    // `let Some(pat) = expr else { ... };`
                    let (cond_local, opt_terms, opt_single) = self.eval_optional_source(value);
                    let ok_bb = self.new_block("let_else_ok");
                    let fail_bb = self.new_block("let_else_fail");
                    self.terminate(Terminator::Branch {
                        cond: cond_local,
                        then_bb: ok_bb,
                        else_bb: fail_bb,
                    });
                    self.switch_to(fail_bb);
                    let saved_else_vars = self.vars.clone();
                    self.lower_stmts(else_block);
                    self.vars = saved_else_vars;
                    if !self.cur_terminated {
                        if let Some((_, rb_bb)) = self.atomic_rollback_stack.last() {
                            let rb_bb = *rb_bb;
                            self.terminate(Terminator::Goto(rb_bb));
                        } else {
                            self.terminate(Terminator::Return(None));
                        }
                    }
                    self.switch_to(ok_bb);
                    if let Some((ent, terms)) = opt_terms {
                        self.bind_pattern_to_query_row(pattern, ent, terms);
                    } else if let Some(b) = opt_single {
                        self.bind_pattern_to_single_term(pattern, b);
                    } else {
                        let (val_l, val_ty) = self.lower_expr(value);
                        self.bind_pattern_value(
                            pattern,
                            val_l,
                            val_ty,
                            ty.clone().unwrap_or_else(|| value.ty()),
                        );
                    }
                    return;
                }
                if let HirExpr::Field { base, field, .. } = value
                    && let Some(EventOrTriggerPayload::Payload(ev)) =
                        self.is_trigger_payload(base, field)
                {
                    let pl = self.alloc_and_emit(
                        "trg_payload",
                        MirType::Ptr,
                        Inst::TriggerPayload { event: ev.clone() },
                    );
                    if let HirPattern::Binding { name, .. } = pattern {
                        self.vars.insert(
                            name.clone(),
                            VarSlot::EventPayloadPtr {
                                ptr_local: pl,
                                layout_key: self.ctx.resolve_canonical(&ev),
                            },
                        );
                    }
                    return;
                }
                self.bind_pattern_to_expr(pattern, value, ty.as_ref());
            }
            HirStmt::Assign { target, op, value } => {
                self.lower_assign(target, *op, value);
            }
            HirStmt::Expr(expr) => {
                let _ = self.lower_expr(expr);
            }
            HirStmt::Return(opt_expr) => {
                let val = opt_expr.as_ref().map(|e| self.lower_expr(e).0);
                self.terminate(Terminator::Return(val));
            }
            HirStmt::Break(_) => {
                if let Some(lt) = self.loop_stack.last().cloned() {
                    self.terminate(Terminator::Goto(lt.break_bb));
                }
            }
            HirStmt::Continue => {
                if let Some(lt) = self.loop_stack.last().cloned() {
                    self.terminate(Terminator::Goto(lt.continue_bb));
                }
            }
            HirStmt::While { cond, body } => {
                let hdr_bb = self.new_block("while_hdr");
                let body_bb = self.new_block("while_body");
                let exit_bb = self.new_block("while_exit");
                self.terminate(Terminator::Goto(hdr_bb));
                self.switch_to(hdr_bb);
                let (cond_l, _) = self.lower_expr(cond);
                self.terminate(Terminator::Branch {
                    cond: cond_l,
                    then_bb: body_bb,
                    else_bb: exit_bb,
                });
                self.switch_to(body_bb);
                let saved_vars = self.vars.clone();
                self.loop_stack.push(LoopTarget {
                    continue_bb: hdr_bb,
                    break_bb: exit_bb,
                });
                self.lower_stmts(body);
                self.loop_stack.pop();
                self.vars = saved_vars;
                if !self.cur_terminated {
                    self.terminate(Terminator::Goto(hdr_bb));
                }
                self.switch_to(exit_bb);
            }
            HirStmt::Loop { body } => {
                let body_bb = self.new_block("loop_body");
                let exit_bb = self.new_block("loop_exit");
                self.terminate(Terminator::Goto(body_bb));
                self.switch_to(body_bb);
                let saved_vars = self.vars.clone();
                self.loop_stack.push(LoopTarget {
                    continue_bb: body_bb,
                    break_bb: exit_bb,
                });
                self.lower_stmts(body);
                self.loop_stack.pop();
                self.vars = saved_vars;
                if !self.cur_terminated {
                    self.terminate(Terminator::Goto(body_bb));
                }
                self.switch_to(exit_bb);
            }
            HirStmt::Atomic(at) => {
                let ckpt = self.alloc_and_emit("tx_ckpt", MirType::Checkpoint, Inst::CmdCheckpoint);
                let body_bb = self.new_block("atomic_body");
                let rollback_bb = self.new_block("atomic_rollback");
                let merge_bb = self.new_block("atomic_merge");
                self.terminate(Terminator::Goto(body_bb));
                self.switch_to(body_bb);
                let saved_vars = self.vars.clone();
                self.atomic_rollback_stack.push((ckpt, rollback_bb));
                self.lower_stmts(&at.body);
                self.atomic_rollback_stack.pop();
                self.vars = saved_vars.clone();
                if !self.cur_terminated {
                    self.terminate(Terminator::Goto(merge_bb));
                }
                self.switch_to(rollback_bb);
                self.emit_void(Inst::CmdRollback { checkpoint: ckpt });
                self.lower_stmts(&at.on_rollback);
                self.vars = saved_vars;
                if !self.cur_terminated {
                    self.terminate(Terminator::Goto(merge_bb));
                }
                self.switch_to(merge_bb);
            }
            HirStmt::RequireTrue(cond) => {
                let (cond_l, _) = self.lower_expr(cond);
                self.emit_void(Inst::RequireTrue { cond: cond_l });
                if let Some((_, rollback_bb)) = self.atomic_rollback_stack.last().cloned() {
                    let cont_bb = self.new_block("tx_ok");
                    self.terminate(Terminator::Branch {
                        cond: cond_l,
                        then_bb: cont_bb,
                        else_bb: rollback_bb,
                    });
                    self.switch_to(cont_bb);
                }
            }
            HirStmt::Trigger {
                target,
                event,
                propagate,
            } => {
                let mut tgt_l = target.as_ref().map(|t| self.lower_expr(t).0);
                let ev_name = event_name_of_expr(event);
                let (payload_l, payload_ty) = self.lower_expr(event);
                if tgt_l.is_none() {
                    let layout_key = self.ctx.resolve_canonical(&ev_name);
                    if let Some(layout) = self.ctx.find_layout(&layout_key)
                        && let Some(sf) = layout.fields.iter().find(|f| {
                            !f.is_padding
                                && f.name == "entity"
                                && (matches!(f.ty, Ty::Ref(_))
                                    || matches!(&f.ty, Ty::Named(n) if n == "Entity"))
                        })
                    {
                        let ent_off = sf.offset as u32;
                        let base_key = match &payload_ty {
                            MirType::Named(n) => self.ctx.resolve_canonical(n),
                            _ => layout_key,
                        };
                        tgt_l = Some(self.alloc_and_emit(
                            "ev_target",
                            MirType::Entity,
                            Inst::FieldLoad {
                                base_ptr: payload_l,
                                layout_key: base_key,
                                field: "entity".to_owned(),
                                offset_bytes: ent_off,
                                field_ty: MirType::Entity,
                            },
                        ));
                    }
                }
                self.emit_void(Inst::CmdTrigger {
                    event: ev_name,
                    target: tgt_l,
                    payload: Some(payload_l),
                    propagate: *propagate,
                });
            }
            HirStmt::Emit(ev) => {
                let sname = event_name_of_expr(ev);
                let canon_stream = self.ctx.resolve_canonical(&sname);
                self.func.stream_ops.push(MirStreamOp {
                    kind: MirStreamOpKind::StreamSend,
                    stream: sname.clone(),
                    canonical_stream: canon_stream,
                    requires_outside_par: false,
                    channel: None,
                });
                let pl = self.lower_expr(ev).0;
                self.emit_void(Inst::StreamEmit {
                    stream: sname,
                    payload: pl,
                });
            }
            HirStmt::Despawn(ent) => {
                let ent_l = self.lower_expr(ent).0;
                self.emit_void(Inst::CmdDespawn { entity: ent_l });
            }
            HirStmt::InsertRelation {
                relation,
                entity,
                target,
                payload,
            } => {
                let e = self.lower_expr(entity).0;
                let t = self.lower_expr(target).0;
                let p = payload.as_ref().map(|pe| self.lower_expr(pe).0);
                self.emit_void(Inst::CmdInsertRelation {
                    relation: relation.clone(),
                    entity: e,
                    target: t,
                    payload: p,
                });
            }
            HirStmt::RemoveRelation {
                relation,
                entity,
                target,
            } => {
                let e = self.lower_expr(entity).0;
                let t = self.lower_expr(target).0;
                self.emit_void(Inst::CmdRemoveRelation {
                    relation: relation.clone(),
                    entity: e,
                    target: t,
                });
            }
            // Task suspension primitives outside `state_machines` synthesis evaluate directly as fallbacks
            HirStmt::AbortIf { cond, cleanup } => {
                let (c, _) = self.lower_expr(cond);
                let abort_bb = self.new_block("abort_cleanup");
                let cont_bb = self.new_block("abort_cont");
                self.terminate(Terminator::Branch {
                    cond: c,
                    then_bb: abort_bb,
                    else_bb: cont_bb,
                });
                self.switch_to(abort_bb);
                self.lower_stmts(cleanup);
                if !self.cur_terminated {
                    self.terminate(Terminator::Return(None));
                }
                self.switch_to(cont_bb);
            }
            HirStmt::Wait(d) => {
                let _ = self.lower_expr(d);
            }
            HirStmt::WaitUntil(c) => {
                let _ = self.lower_expr(c);
            }
            HirStmt::YieldTick => {}
            HirStmt::Race { branches } => {
                for b in branches {
                    self.lower_stmts(b);
                }
            }
        }
    }

    pub(crate) fn lower_expr(&mut self, expr: &HirExpr) -> (LocalId, MirType) {
        match expr {
            HirExpr::BoolLit(b) => {
                let l = self.alloc_and_emit("b", MirType::Bool, Inst::ConstBool { value: *b });
                (l, MirType::Bool)
            }
            HirExpr::IntLit { value, ty } => {
                let mty = mir_ty_from_hir(ty);
                let mty = if mty == MirType::Unit {
                    MirType::I64
                } else {
                    mty
                };
                let l = self.alloc_and_emit("i", mty.clone(), Inst::ConstInt { value: *value });
                (l, mty)
            }
            HirExpr::FloatLit { value, ty } => {
                let mty = mir_ty_from_hir(ty);
                let mty = if mty == MirType::Unit {
                    MirType::F32
                } else {
                    mty
                };
                let l = self.alloc_and_emit("f", mty.clone(), Inst::ConstFloat { value: *value });
                (l, mty)
            }
            HirExpr::StringLit(s) => {
                let l = self.alloc_and_emit(
                    "s",
                    MirType::Named("InlineStr".to_owned()),
                    Inst::ConstString { value: s.clone() },
                );
                (l, MirType::Named("InlineStr".to_owned()))
            }
            HirExpr::CharLit(c) => {
                let l =
                    self.alloc_and_emit("ch", MirType::U32, Inst::ConstInt { value: *c as i64 });
                (l, MirType::U32)
            }
            HirExpr::Path { name, ty } => self.lower_path(name, ty),
            HirExpr::Unary { op, expr, ty } => {
                let (inner_l, inner_ty) = self.lower_expr(expr);
                let op_s = match op {
                    HirUnOp::Neg => "-",
                    HirUnOp::Not => {
                        if matches!(
                            inner_ty,
                            MirType::U8
                                | MirType::U16
                                | MirType::U32
                                | MirType::U64
                                | MirType::I8
                                | MirType::I16
                                | MirType::I32
                                | MirType::I64
                        ) {
                            "~"
                        } else {
                            "!"
                        }
                    }
                    HirUnOp::BitNot => "~",
                    HirUnOp::Ref => "&",
                    HirUnOp::RefMut => "&mut",
                };
                let res_ty = if *ty != Ty::Unknown && *ty != Ty::Unit {
                    mir_ty_from_hir(ty)
                } else {
                    inner_ty
                };
                let l = self.alloc_and_emit(
                    "un",
                    res_ty.clone(),
                    Inst::UnOp {
                        op: op_s.to_owned(),
                        val: inner_l,
                    },
                );
                (l, res_ty)
            }
            HirExpr::Binary { op, lhs, rhs, ty } => {
                if *op == HirBinOp::And {
                    return self.lower_short_circuit(true, lhs, rhs);
                }
                if *op == HirBinOp::Or {
                    return self.lower_short_circuit(false, lhs, rhs);
                }
                let (mut l_id, l_ty) = self.lower_expr(lhs);
                let (mut r_id, r_ty) = self.lower_expr(rhs);
                let op_s = binop_str(*op);
                let res_ty = if is_cmp_binop(*op) {
                    MirType::Bool
                } else if *ty != Ty::Unknown && *ty != Ty::Unit {
                    mir_ty_from_hir(ty)
                } else if is_vec_mir_ty(&l_ty) {
                    l_ty.clone()
                } else if is_vec_mir_ty(&r_ty) {
                    r_ty.clone()
                } else if is_scalar_numeric(&l_ty) && is_scalar_numeric(&r_ty) {
                    unify_mir_scalar(&l_ty, &r_ty)
                } else {
                    l_ty.clone()
                };
                if is_vec_mir_ty(&l_ty) && is_scalar_numeric(&r_ty) {
                    let lane_ty = vec_lane_mir_ty(&l_ty);
                    r_id = self.coerce_local_to_ty(r_id, r_ty, &lane_ty);
                } else if is_vec_mir_ty(&r_ty) && is_scalar_numeric(&l_ty) {
                    let lane_ty = vec_lane_mir_ty(&r_ty);
                    l_id = self.coerce_local_to_ty(l_id, l_ty, &lane_ty);
                } else if !is_vec_mir_ty(&res_ty) {
                    let unified;
                    let op_ty: Option<&MirType> = if is_cmp_binop(*op) {
                        if is_scalar_numeric(&l_ty) && is_scalar_numeric(&r_ty) {
                            unified = unify_mir_scalar(&l_ty, &r_ty);
                            Some(&unified)
                        } else {
                            None
                        }
                    } else if is_scalar_numeric(&res_ty) {
                        Some(&res_ty)
                    } else if is_scalar_numeric(&l_ty) && is_scalar_numeric(&r_ty) {
                        unified = unify_mir_scalar(&l_ty, &r_ty);
                        Some(&unified)
                    } else {
                        None
                    };
                    if let Some(op_ty) = op_ty {
                        l_id = self.coerce_local_to_ty(l_id, l_ty, op_ty);
                        r_id = self.coerce_local_to_ty(r_id, r_ty, op_ty);
                    }
                }
                let allow_fma = !self.ctx.is_deterministic
                    && !self.func.is_deterministic
                    && matches!(res_ty, MirType::F32 | MirType::F64);
                let id = self.alloc_and_emit(
                    "bin",
                    res_ty.clone(),
                    Inst::BinOp {
                        op: op_s.to_owned(),
                        lhs: l_id,
                        rhs: r_id,
                        allow_fma,
                    },
                );
                (id, res_ty)
            }
            HirExpr::Cast { expr, target_ty } => {
                let (val, _) = self.lower_expr(expr);
                let mty = mir_ty_from_hir(target_ty);
                let id = self.alloc_and_emit(
                    "cast",
                    mty.clone(),
                    Inst::Cast {
                        val,
                        target_ty: mty.clone(),
                    },
                );
                (id, mty)
            }
            HirExpr::Field { base, field, ty } => self.lower_field_read(base, field, ty),
            HirExpr::Index { base, index, ty } => {
                if let HirExpr::Path { name, .. } = base.as_ref()
                    && self.ctx.tables.contains_key(name)
                {
                    let (key_l, _) = self.lower_expr(index);
                    let rty = mir_ty_from_hir(ty);
                    let rty = if rty == MirType::Unit {
                        MirType::Named(name.clone())
                    } else {
                        rty
                    };
                    let id = self.alloc_and_emit(
                        &format!("tbl_{name}"),
                        rty.clone(),
                        Inst::TableLoad {
                            table_name: name.clone(),
                            key: key_l,
                            field: String::new(),
                        },
                    );
                    return (id, rty);
                }
                let (base_l, _) = self.lower_expr(base);
                let (idx_l, _) = self.lower_expr(index);
                let mty = mir_ty_from_hir(ty);
                let id = self.alloc_and_emit(
                    "idx",
                    mty.clone(),
                    Inst::ArrayIndex {
                        base: base_l,
                        index: idx_l,
                    },
                );
                (id, mty)
            }
            HirExpr::StructLit { name, fields, ty } => {
                let flocs = self.build_comp_fields(name, fields);
                let rty = mir_ty_from_hir(ty);
                let rty = if rty == MirType::Unit {
                    MirType::Named(name.clone())
                } else {
                    rty
                };
                let id = self.alloc_and_emit(
                    &format!("init_{name}"),
                    rty.clone(),
                    Inst::StructInit {
                        type_name: name.clone(),
                        fields: flocs,
                    },
                );
                (id, rty)
            }
            HirExpr::RecordLit { fields, ty } => {
                let mut flocs = Vec::with_capacity(fields.len());
                for (fname, fexpr) in fields {
                    flocs.push((fname.clone(), self.lower_expr(fexpr).0));
                }
                let rty = mir_ty_from_hir(ty);
                let rty_name = match &rty {
                    MirType::Named(n) => n.clone(),
                    _ => "record".to_owned(),
                };
                let id = self.alloc_and_emit(
                    "rec",
                    rty.clone(),
                    Inst::StructInit {
                        type_name: rty_name,
                        fields: flocs,
                    },
                );
                (id, rty)
            }
            HirExpr::BundleLit { components } => {
                let mut f = Vec::with_capacity(components.len());
                for ci in components {
                    let fl = self.build_comp_fields(&ci.component, &ci.fields);
                    let sl = self.alloc_and_emit(
                        &format!("bndl_{}", ci.component),
                        MirType::Named(ci.component.clone()),
                        Inst::StructInit {
                            type_name: ci.component.clone(),
                            fields: fl,
                        },
                    );
                    f.push((ci.component.clone(), sl));
                }
                let ty = MirType::Named("Bundle".to_owned());
                let id = self.alloc_and_emit(
                    "bundle",
                    ty.clone(),
                    Inst::StructInit {
                        type_name: "Bundle".to_owned(),
                        fields: f,
                    },
                );
                (id, ty)
            }
            HirExpr::ArrayLit { elems, ty } => {
                let mut lowered = Vec::with_capacity(elems.len());
                for it in elems {
                    lowered.push(self.lower_expr(it));
                }
                let expected_elem_ty = match ty {
                    Ty::Array { elem, .. } | Ty::SmallVec { elem, .. } if **elem != Ty::Unknown => {
                        let m = mir_ty_from_hir(elem);
                        (m != MirType::Unit).then_some(m)
                    }
                    _ => None,
                };
                let elem_ty = if let Some(exp) = expected_elem_ty {
                    exp
                } else if let Some((_, first_t)) = lowered.first() {
                    let mut acc = first_t.clone();
                    for (_, t) in &lowered[1..] {
                        if is_scalar_numeric(&acc) && is_scalar_numeric(t) {
                            acc = unify_mir_scalar(&acc, t);
                        }
                    }
                    acc
                } else {
                    MirType::F32
                };
                let mut elem_ids = Vec::with_capacity(lowered.len());
                for (l, t) in lowered {
                    elem_ids.push(self.coerce_local_to_ty(l, t, &elem_ty));
                }
                let arr_ty = MirType::Array {
                    elem: Box::new(elem_ty),
                    len: elem_ids.len(),
                };
                let id =
                    self.alloc_and_emit("arr", arr_ty.clone(), Inst::ArrayInit { elems: elem_ids });
                (id, arr_ty)
            }
            HirExpr::Tuple { elems, .. } => {
                if elems.is_empty() {
                    let u = self.alloc_and_emit(
                        "unit",
                        MirType::Unit,
                        Inst::ConstBool { value: false },
                    );
                    return (u, MirType::Unit);
                }
                let mut f = Vec::with_capacity(elems.len());
                let mut ts = Vec::with_capacity(elems.len());
                for (i, it) in elems.iter().enumerate() {
                    let (l, t) = self.lower_expr(it);
                    f.push((format!("_{i}"), l));
                    ts.push(t);
                }
                let tty = MirType::Tuple(ts);
                let id = self.alloc_and_emit(
                    "tup",
                    tty.clone(),
                    Inst::StructInit {
                        type_name: "tuple".to_owned(),
                        fields: f,
                    },
                );
                (id, tty)
            }
            HirExpr::Call(call) => {
                if let Some(ref recv) = call.receiver {
                    self.lower_method_call(recv, &call.callee, &call.args, &call.ty)
                } else {
                    self.lower_call(call)
                }
            }
            HirExpr::Query(hq) => self.lower_query_expr(hq),
            HirExpr::Spawn(sp) => self.lower_spawn(sp),
            HirExpr::DespawnAll { filters } => {
                let id = self.alloc_and_emit(
                    "despawn_all",
                    MirType::Unit,
                    Inst::CmdDespawnAll {
                        filter: filters.join(","),
                    },
                );
                (id, MirType::Unit)
            }
            HirExpr::Insert {
                if_new,
                entity,
                value,
            } => {
                let (ent_l, _) = self.lower_expr(entity);
                self.lower_insert_value(ent_l, *if_new, value);
                let u =
                    self.alloc_and_emit("unit", MirType::Unit, Inst::ConstBool { value: false });
                (u, MirType::Unit)
            }
            HirExpr::Remove { component, entity } => {
                let (ent_l, _) = self.lower_expr(entity);
                self.emit_void(Inst::CmdRemove {
                    entity: ent_l,
                    component: component.clone(),
                });
                let u =
                    self.alloc_and_emit("unit", MirType::Unit, Inst::ConstBool { value: false });
                (u, MirType::Unit)
            }
            HirExpr::Block { stmts, tail, ty } => {
                let saved_vars = self.vars.clone();
                self.lower_stmts(stmts);
                let out = if let Some(t) = tail {
                    self.lower_expr(t)
                } else {
                    let rty = mir_ty_from_hir(ty);
                    let u = self.alloc_and_emit(
                        "blk_unit",
                        rty.clone(),
                        Inst::ConstBool { value: false },
                    );
                    (u, rty)
                };
                self.vars = saved_vars;
                out
            }
            HirExpr::If {
                let_pat,
                cond,
                then_stmts,
                then_tail,
                else_stmts,
                else_tail,
                ty,
            } => self.lower_if(
                let_pat.as_ref(),
                cond,
                then_stmts,
                then_tail.as_deref(),
                else_stmts,
                else_tail.as_deref(),
                ty,
            ),
            HirExpr::Match(hm) => self.lower_match(hm),
            HirExpr::For(hf) => self.lower_for(hf),
        }
    }

    fn lower_short_circuit(
        &mut self,
        is_and: bool,
        lhs: &HirExpr,
        rhs: &HirExpr,
    ) -> (LocalId, MirType) {
        let slot = self.alloc_and_emit(
            "sc_slot",
            MirType::MutPtr,
            Inst::SlotAlloc { ty: MirType::Bool },
        );
        let (l_id, _) = self.lower_expr(lhs);
        let rhs_bb = self.new_block("sc_rhs");
        let short_bb = self.new_block("sc_short");
        let merge_bb = self.new_block("sc_merge");
        if is_and {
            self.terminate(Terminator::Branch {
                cond: l_id,
                then_bb: rhs_bb,
                else_bb: short_bb,
            });
        } else {
            self.terminate(Terminator::Branch {
                cond: l_id,
                then_bb: short_bb,
                else_bb: rhs_bb,
            });
        }
        self.switch_to(short_bb);
        let sc_v = self.alloc_and_emit(
            "sc_const",
            MirType::Bool,
            Inst::ConstBool { value: !is_and },
        );
        self.emit_void(Inst::SlotStore { slot, val: sc_v });
        self.terminate(Terminator::Goto(merge_bb));

        self.switch_to(rhs_bb);
        let (r_id, _) = self.lower_expr(rhs);
        self.emit_void(Inst::SlotStore { slot, val: r_id });
        if !self.cur_terminated {
            self.terminate(Terminator::Goto(merge_bb));
        }
        self.switch_to(merge_bb);
        let res = self.alloc_and_emit("sc_res", MirType::Bool, Inst::SlotLoad { slot });
        (res, MirType::Bool)
    }

    fn lower_path(&mut self, name: &str, ty: &Ty) -> (LocalId, MirType) {
        // Bound variables in scope
        if let Some(slot) = self.vars.get(name).cloned() {
            return match slot {
                VarSlot::Slot { slot_local, ty, .. } => {
                    let l =
                        self.alloc_and_emit(name, ty.clone(), Inst::SlotLoad { slot: slot_local });
                    (l, ty)
                }
                VarSlot::Imm { local, ty, .. } => (local, ty),
                VarSlot::ResPtr { ptr_local, .. } | VarSlot::EventPayloadPtr { ptr_local, .. } => {
                    (ptr_local, MirType::Ptr)
                }
                VarSlot::RowAlias {
                    entity_local: Some(e),
                    ..
                } => (e, MirType::Entity),
                VarSlot::RowAlias { terms, .. } => {
                    if let Some(first) = terms.values().next() {
                        (first.row_ptr.unwrap_or(first.col_ptr), MirType::Ptr)
                    } else {
                        let e = self.alloc_and_emit(
                            "ent",
                            MirType::Entity,
                            Inst::ConstInt { value: 0 },
                        );
                        (e, MirType::Entity)
                    }
                }
                VarSlot::SingleTermPtr { binding } => {
                    if let Some(ref proj) = binding.field_name {
                        return self.emit_term_field_load(&binding, proj);
                    }
                    let p = binding.row_ptr.unwrap_or(binding.col_ptr);
                    (p, MirType::Ptr)
                }
                VarSlot::SpatialCandidate { entity, .. } => (entity, MirType::Entity),
                VarSlot::TriggerCtx { .. } => {
                    let l = self.alloc_and_emit("trg_ent", MirType::Entity, Inst::TriggerTarget);
                    (l, MirType::Entity)
                }
                VarSlot::OptionalRow { cond_local, .. } => (cond_local, MirType::Bool),
                VarSlot::Tuple(_) => {
                    let e = self.alloc_and_emit(
                        "tup_unit",
                        MirType::Unit,
                        Inst::ConstBool { value: false },
                    );
                    (e, MirType::Unit)
                }
            };
        }

        // Vector constants (`vec2::ZERO`, `vec3::ZERO`, `ivec2::ZERO`, ...)
        if let Some(vec_c) = vec_path_constant(name) {
            return match vec_c {
                MirConstVal::Vec2(v) => {
                    let vty = if name.starts_with("ivec2::") {
                        MirType::IVec2
                    } else if name.starts_with("uvec2::") {
                        MirType::UVec2
                    } else {
                        MirType::Vec2
                    };
                    (
                        self.alloc_and_emit(
                            "vec2_c",
                            vty.clone(),
                            Inst::ConstVec {
                                dims: 2,
                                values: [v[0], v[1], 0.0, 0.0],
                            },
                        ),
                        vty,
                    )
                }
                MirConstVal::Vec3(v) => {
                    let vty = if name.starts_with("ivec3::") {
                        MirType::IVec3
                    } else {
                        MirType::Vec3
                    };
                    (
                        self.alloc_and_emit(
                            "vec3_c",
                            vty.clone(),
                            Inst::ConstVec {
                                dims: 3,
                                values: [v[0], v[1], v[2], 0.0],
                            },
                        ),
                        vty,
                    )
                }
                MirConstVal::Vec4(v) => (
                    self.alloc_and_emit(
                        "vec4_c",
                        MirType::Vec4,
                        Inst::ConstVec { dims: 4, values: v },
                    ),
                    MirType::Vec4,
                ),
                _ => unreachable!(),
            };
        }

        // Module `const`
        if let Some(cv) = self.ctx.const_vals.get(name) {
            return self.materialize_const_val(name, cv, mir_ty_from_hir(ty));
        }
        if let Some(cexpr) = self.ctx.const_exprs.get(name).cloned() {
            return self.lower_expr(&cexpr);
        }

        // Enum discriminant (`CombatAction::DodgeRoll`)
        if let Some(disc) = self.ctx.enum_discriminant(name) {
            let mty = mir_ty_from_hir(ty);
            let mty = if mty == MirType::Unit {
                MirType::I32
            } else {
                mty
            };
            let id = self.alloc_and_emit("enum_v", mty.clone(), Inst::ConstInt { value: disc });
            return (id, mty);
        }

        // Named `object` entity handle (`PlayerHero`, `CampaignProgress`)
        if self.ctx.objects.contains(name) {
            let id = self.alloc_and_emit(
                &format!("obj_{name}"),
                MirType::Entity,
                Inst::ResolveNamedObject {
                    name: name.to_owned(),
                },
            );
            return (id, MirType::Entity);
        }

        // Unresolved path -> symbolic fallback constant
        let mty = mir_ty_from_hir(ty);
        let id = self.alloc_and_emit(
            name,
            mty.clone(),
            Inst::InternSymbol {
                symbol: name.to_owned(),
            },
        );
        (id, mty)
    }

    fn materialize_const_val(
        &mut self,
        hint: &str,
        cv: &MirConstVal,
        preferred_ty: MirType,
    ) -> (LocalId, MirType) {
        match cv {
            MirConstVal::Unit => (
                self.alloc_and_emit(hint, MirType::Unit, Inst::ConstBool { value: false }),
                MirType::Unit,
            ),
            MirConstVal::Bool(b) => (
                self.alloc_and_emit(hint, MirType::Bool, Inst::ConstBool { value: *b }),
                MirType::Bool,
            ),
            MirConstVal::Int(i) => {
                if let Some(bits) = bitset_bits_from_mir_ty(&preferred_ty) {
                    let words = bits.div_ceil(32).max(1);
                    let mask = *i as u64;
                    let mut elem_ids = Vec::with_capacity(words);
                    for w in 0..words {
                        let word = if w < 2 {
                            ((mask >> (w * 32)) & 0xFFFF_FFFF) as u32
                        } else {
                            0
                        };
                        elem_ids.push(self.alloc_and_emit(
                            hint,
                            MirType::U32,
                            Inst::ConstInt {
                                value: i64::from(word),
                            },
                        ));
                    }
                    let aty = MirType::Array {
                        elem: Box::new(MirType::U32),
                        len: words,
                    };
                    return (
                        self.alloc_and_emit(hint, aty.clone(), Inst::ArrayInit { elems: elem_ids }),
                        aty,
                    );
                }
                let ty = if preferred_ty != MirType::Unit {
                    preferred_ty
                } else {
                    MirType::I64
                };
                (
                    self.alloc_and_emit(hint, ty.clone(), Inst::ConstInt { value: *i }),
                    ty,
                )
            }
            MirConstVal::Float(f) => {
                let ty = if preferred_ty != MirType::Unit {
                    preferred_ty
                } else {
                    MirType::F32
                };
                (
                    self.alloc_and_emit(hint, ty.clone(), Inst::ConstFloat { value: *f }),
                    ty,
                )
            }
            MirConstVal::Vec2(v) => {
                let ty = if matches!(preferred_ty, MirType::IVec2 | MirType::UVec2) {
                    preferred_ty
                } else {
                    MirType::Vec2
                };
                (
                    self.alloc_and_emit(
                        hint,
                        ty.clone(),
                        Inst::ConstVec {
                            dims: 2,
                            values: [v[0], v[1], 0.0, 0.0],
                        },
                    ),
                    ty,
                )
            }
            MirConstVal::Vec3(v) => {
                let ty = if matches!(preferred_ty, MirType::IVec3) {
                    MirType::IVec3
                } else {
                    MirType::Vec3
                };
                (
                    self.alloc_and_emit(
                        hint,
                        ty.clone(),
                        Inst::ConstVec {
                            dims: 3,
                            values: [v[0], v[1], v[2], 0.0],
                        },
                    ),
                    ty,
                )
            }
            MirConstVal::Vec4(v) => (
                self.alloc_and_emit(
                    hint,
                    MirType::Vec4,
                    Inst::ConstVec {
                        dims: 4,
                        values: *v,
                    },
                ),
                MirType::Vec4,
            ),
            MirConstVal::String(s) => {
                let ty = MirType::Named("InlineStr".to_owned());
                (
                    self.alloc_and_emit(hint, ty.clone(), Inst::ConstString { value: s.clone() }),
                    ty,
                )
            }
            MirConstVal::Array(elems) => {
                if let Some(bits) = bitset_bits_from_mir_ty(&preferred_ty) {
                    let words = bits.div_ceil(32).max(1);
                    let mut packed = vec![0u32; words];
                    for e in elems {
                        if let MirConstVal::Int(b) = e
                            && *b >= 0
                            && (*b as usize) < bits
                        {
                            let bi = *b as usize;
                            packed[bi / 32] |= 1u32 << (bi % 32);
                        }
                    }
                    let mut elem_ids = Vec::with_capacity(words);
                    for w in packed {
                        elem_ids.push(self.alloc_and_emit(
                            hint,
                            MirType::U32,
                            Inst::ConstInt {
                                value: i64::from(w),
                            },
                        ));
                    }
                    let aty = MirType::Array {
                        elem: Box::new(MirType::U32),
                        len: words,
                    };
                    return (
                        self.alloc_and_emit(hint, aty.clone(), Inst::ArrayInit { elems: elem_ids }),
                        aty,
                    );
                }
                let elem_pref = match &preferred_ty {
                    MirType::Array { elem, .. } => elem.as_ref().clone(),
                    _ => MirType::Unit,
                };
                let mut ids = Vec::with_capacity(elems.len());
                let mut ety = if elem_pref != MirType::Unit {
                    elem_pref.clone()
                } else {
                    MirType::F32
                };
                for e in elems {
                    let (id, t) = self.materialize_const_val(hint, e, elem_pref.clone());
                    if elem_pref == MirType::Unit {
                        ety = t;
                    }
                    ids.push(id);
                }
                let aty = MirType::Array {
                    elem: Box::new(ety),
                    len: ids.len(),
                };
                (
                    self.alloc_and_emit(hint, aty.clone(), Inst::ArrayInit { elems: ids }),
                    aty,
                )
            }
            MirConstVal::Struct { name, fields } => {
                let layout = self.ctx.find_layout(name).cloned();
                let mut fl = Vec::with_capacity(fields.len());
                let mut seen = HashSet::new();
                for (fnm, fv) in fields {
                    seen.insert(fnm.clone());
                    let f_pref = layout
                        .as_ref()
                        .and_then(|l| l.fields.iter().find(|sf| sf.name == *fnm))
                        .map_or(MirType::Unit, |sf| mir_ty_from_hir(&sf.ty));
                    let (fid, _) = self.materialize_const_val(fnm, fv, f_pref);
                    fl.push((fnm.clone(), fid));
                }
                if let Some(defs) = self.ctx.layout_defaults(name).cloned() {
                    for (dfname, dval) in defs {
                        if seen.insert(dfname.clone()) {
                            let f_pref = layout
                                .as_ref()
                                .and_then(|l| l.fields.iter().find(|sf| sf.name == dfname))
                                .map_or(MirType::Unit, |sf| mir_ty_from_hir(&sf.ty));
                            let (fid, _) = self.materialize_const_val(&dfname, &dval, f_pref);
                            fl.push((dfname, fid));
                        }
                    }
                }
                let ty = MirType::Named(name.clone());
                (
                    self.alloc_and_emit(
                        hint,
                        ty.clone(),
                        Inst::StructInit {
                            type_name: name.clone(),
                            fields: fl,
                        },
                    ),
                    ty,
                )
            }
        }
    }

    fn lower_spawn(&mut self, sp: &HirSpawn) -> (LocalId, MirType) {
        if !sp.is_batch {
            let comps = self.build_spawn_components(&sp.components);
            let id = self.alloc_and_emit(
                "spawned",
                MirType::Entity,
                Inst::CmdSpawn {
                    persistent: sp.is_persistent,
                    components: comps,
                },
            );
            return (id, MirType::Entity);
        }

        let Some(ref bv) = sp.batch_var else {
            let cnt_l = if let Some(ref cnt_expr) = sp.count {
                self.lower_expr(cnt_expr).0
            } else {
                self.alloc_and_emit("cnt", MirType::U32, Inst::ConstInt { value: 1 })
            };
            let saved_vars = self.vars.clone();
            self.lower_stmts(&sp.preamble);
            let comps = self.build_spawn_components(&sp.components);
            self.vars = saved_vars;
            let id = self.alloc_and_emit(
                "batch_spawn",
                MirType::Unit,
                Inst::CmdSpawnBatch {
                    count: cnt_l,
                    components: comps,
                },
            );
            return (id, MirType::Unit);
        };

        let cnt_l = self.lower_spawn_batch_count(sp.count.as_deref());
        let comp_names: Vec<String> = sp
            .components
            .iter()
            .map(|ci| ci.component.clone())
            .collect();
        let batch_l = self.alloc_and_emit(
            "spawn_batch",
            MirType::U64,
            Inst::SpawnBatchBegin {
                count: cnt_l,
                components: comp_names,
            },
        );
        let idx_slot = self.alloc_and_emit(
            "batch_idx_slot",
            MirType::MutPtr,
            Inst::SlotAlloc { ty: MirType::U32 },
        );
        let zero = self.alloc_and_emit("batch_zero", MirType::U32, Inst::ConstInt { value: 0 });
        self.emit_void(Inst::SlotStore {
            slot: idx_slot,
            val: zero,
        });

        let hdr_bb = self.new_block("spawn_batch_hdr");
        let body_bb = self.new_block("spawn_batch_body");
        let exit_bb = self.new_block("spawn_batch_exit");
        self.terminate(Terminator::Goto(hdr_bb));

        self.switch_to(hdr_bb);
        let i_val = self.alloc_and_emit("batch_i", MirType::U32, Inst::SlotLoad { slot: idx_slot });
        let cond = self.alloc_and_emit(
            "batch_cond",
            MirType::Bool,
            Inst::BinOp {
                op: "<".to_owned(),
                lhs: i_val,
                rhs: cnt_l,
                allow_fma: false,
            },
        );
        self.terminate(Terminator::Branch {
            cond,
            then_bb: body_bb,
            else_bb: exit_bb,
        });

        self.switch_to(body_bb);
        let saved_vars = self.vars.clone();
        self.vars.insert(
            bv.clone(),
            VarSlot::Imm {
                local: i_val,
                ty: MirType::U32,
            },
        );
        self.lower_stmts(&sp.preamble);
        if !self.cur_terminated {
            let comps = self.build_spawn_components(&sp.components);
            self.emit_void(Inst::SpawnBatchPush {
                batch: batch_l,
                index: i_val,
                components: comps,
            });
            let one = self.alloc_and_emit("batch_one", MirType::U32, Inst::ConstInt { value: 1 });
            let next_i = self.alloc_and_emit(
                "batch_next_i",
                MirType::U32,
                Inst::BinOp {
                    op: "+".to_owned(),
                    lhs: i_val,
                    rhs: one,
                    allow_fma: false,
                },
            );
            self.emit_void(Inst::SlotStore {
                slot: idx_slot,
                val: next_i,
            });
            self.terminate(Terminator::Goto(hdr_bb));
        }
        self.vars = saved_vars;

        self.switch_to(exit_bb);
        self.emit_void(Inst::SpawnBatchCommit { batch: batch_l });
        let u = self.alloc_and_emit("unit", MirType::Unit, Inst::ConstBool { value: false });
        (u, MirType::Unit)
    }

    fn lower_spawn_batch_count(&mut self, count: Option<&HirExpr>) -> LocalId {
        let Some(cnt_expr) = count else {
            return self.alloc_and_emit("batch_cnt", MirType::U32, Inst::ConstInt { value: 1 });
        };
        if let HirExpr::IntLit { value, .. } = cnt_expr {
            let clamped = (*value).clamp(0, i64::from(u32::MAX));
            return self.alloc_and_emit(
                "batch_cnt",
                MirType::U32,
                Inst::ConstInt { value: clamped },
            );
        }
        let (raw_cnt, raw_ty) = self.lower_expr(cnt_expr);
        if raw_ty == MirType::U32 {
            return raw_cnt;
        }
        if matches!(
            raw_ty,
            MirType::I8 | MirType::I16 | MirType::I32 | MirType::I64
        ) {
            let cnt_slot = self.alloc_and_emit(
                "batch_cnt_slot",
                MirType::MutPtr,
                Inst::SlotAlloc { ty: MirType::U32 },
            );
            let z_cnt =
                self.alloc_and_emit("batch_cnt_z", MirType::U32, Inst::ConstInt { value: 0 });
            self.emit_void(Inst::SlotStore {
                slot: cnt_slot,
                val: z_cnt,
            });
            let z_raw = self.alloc_and_emit("raw_zero", raw_ty, Inst::ConstInt { value: 0 });
            let pos = self.alloc_and_emit(
                "batch_cnt_pos",
                MirType::Bool,
                Inst::BinOp {
                    op: ">".to_owned(),
                    lhs: raw_cnt,
                    rhs: z_raw,
                    allow_fma: false,
                },
            );
            let pos_bb = self.new_block("batch_cnt_pos");
            let cont_bb = self.new_block("batch_cnt_cont");
            self.terminate(Terminator::Branch {
                cond: pos,
                then_bb: pos_bb,
                else_bb: cont_bb,
            });
            self.switch_to(pos_bb);
            let cast_cnt = self.alloc_and_emit(
                "batch_cnt_cast",
                MirType::U32,
                Inst::Cast {
                    val: raw_cnt,
                    target_ty: MirType::U32,
                },
            );
            self.emit_void(Inst::SlotStore {
                slot: cnt_slot,
                val: cast_cnt,
            });
            self.terminate(Terminator::Goto(cont_bb));
            self.switch_to(cont_bb);
            return self.alloc_and_emit(
                "batch_cnt",
                MirType::U32,
                Inst::SlotLoad { slot: cnt_slot },
            );
        }
        self.alloc_and_emit(
            "batch_cnt",
            MirType::U32,
            Inst::Cast {
                val: raw_cnt,
                target_ty: MirType::U32,
            },
        )
    }

    fn lower_insert_value(&mut self, ent_l: LocalId, if_new: bool, value: &HirExpr) {
        match value {
            HirExpr::StructLit { name, fields, .. } => {
                let canon = self.ctx.resolve_canonical(name);
                let is_zst =
                    fields.is_empty() && self.ctx.find_layout(&canon).is_some_and(|l| l.size == 0);
                let data = if is_zst {
                    None
                } else {
                    let fl = self.build_comp_fields(name, fields);
                    Some(self.alloc_and_emit(
                        &format!("ins_{name}"),
                        MirType::Named(name.clone()),
                        Inst::StructInit {
                            type_name: name.clone(),
                            fields: fl,
                        },
                    ))
                };
                self.emit_void(Inst::CmdInsert {
                    entity: ent_l,
                    component: name.clone(),
                    data,
                    if_new,
                });
            }
            HirExpr::BundleLit { components } => {
                for ci in components {
                    let canon = self.ctx.resolve_canonical(&ci.component);
                    let is_zst = ci.fields.is_empty()
                        && self.ctx.find_layout(&canon).is_some_and(|l| l.size == 0);
                    let data = if is_zst {
                        None
                    } else {
                        let fl = self.build_comp_fields(&ci.component, &ci.fields);
                        Some(self.alloc_and_emit(
                            &format!("ins_{}", ci.component),
                            MirType::Named(ci.component.clone()),
                            Inst::StructInit {
                                type_name: ci.component.clone(),
                                fields: fl,
                            },
                        ))
                    };
                    self.emit_void(Inst::CmdInsert {
                        entity: ent_l,
                        component: ci.component.clone(),
                        data,
                        if_new,
                    });
                }
            }
            HirExpr::Block { stmts, tail, .. } => {
                self.lower_stmts(stmts);
                if let Some(t) = tail {
                    self.lower_insert_value(ent_l, if_new, t);
                }
            }
            HirExpr::If {
                let_pat,
                cond,
                then_stmts,
                then_tail,
                else_stmts,
                else_tail,
                ..
            } => {
                let mut opt_row = None;
                let mut opt_single = None;
                let cond_l = if let Some(_pat) = let_pat {
                    let (c, r, s) = self.eval_optional_source(cond);
                    opt_row = r;
                    opt_single = s;
                    c
                } else {
                    self.lower_expr(cond).0
                };
                let then_bb = self.new_block("ins_if_then");
                let else_bb = self.new_block("ins_if_else");
                let merge_bb = self.new_block("ins_if_merge");
                self.terminate(Terminator::Branch {
                    cond: cond_l,
                    then_bb,
                    else_bb,
                });

                self.switch_to(then_bb);
                if let Some(pat) = let_pat {
                    if let Some((ent, terms)) = opt_row {
                        self.bind_pattern_to_query_row(pat, ent, terms);
                    } else if let Some(tb) = opt_single {
                        self.bind_pattern_to_single_term(pat, tb);
                    }
                }
                self.lower_stmts(then_stmts);
                if let Some(tt) = then_tail {
                    self.lower_insert_value(ent_l, if_new, tt);
                }
                let then_falls = !self.cur_terminated;
                if then_falls {
                    self.terminate(Terminator::Goto(merge_bb));
                }

                self.switch_to(else_bb);
                self.lower_stmts(else_stmts);
                if let Some(et) = else_tail {
                    self.lower_insert_value(ent_l, if_new, et);
                }
                let else_falls = !self.cur_terminated;
                if else_falls {
                    self.terminate(Terminator::Goto(merge_bb));
                }

                self.switch_to(merge_bb);
                if !then_falls && !else_falls {
                    self.terminate(Terminator::Return(None));
                }
            }
            HirExpr::Match(hm) => {
                let (scrut_l, scrut_ty) = self.lower_expr(&hm.scrutinee);
                let merge_bb = self.new_block("ins_match_merge");
                let can_switch = !hm.arms.is_empty()
                    && hm.arms.iter().all(|a| {
                        a.guard.is_none() && self.arm_const_disc(&a.pattern).is_some()
                            || matches!(
                                a.pattern,
                                HirPattern::Wildcard | HirPattern::Binding { .. }
                            ) && a.guard.is_none()
                    });
                if can_switch {
                    let dispatch_bb = self.cur_bb;
                    let mut cases = Vec::new();
                    let mut default_bb = None;
                    for (idx, arm) in hm.arms.iter().enumerate() {
                        let arm_bb = self.new_block(&format!("ins_arm_{idx}"));
                        if let Some(disc) = self.arm_const_disc(&arm.pattern) {
                            cases.push((disc as u32, arm_bb));
                        } else if default_bb.is_none() {
                            default_bb = Some(arm_bb);
                        }
                        self.switch_to(arm_bb);
                        self.bind_pattern_value(
                            &arm.pattern,
                            scrut_l,
                            scrut_ty.clone(),
                            hm.scrutinee.ty(),
                        );
                        self.lower_insert_value(ent_l, if_new, &arm.body);
                        if !self.cur_terminated {
                            self.terminate(Terminator::Goto(merge_bb));
                        }
                    }
                    let def = default_bb.unwrap_or(merge_bb);
                    self.switch_to(dispatch_bb);
                    self.terminate(Terminator::Switch {
                        scrutinee: scrut_l,
                        cases,
                        default_bb: def,
                    });
                    self.switch_to(merge_bb);
                } else {
                    for (idx, arm) in hm.arms.iter().enumerate() {
                        let arm_bb = self.new_block(&format!("ins_arm_{idx}"));
                        let next_bb = if idx + 1 == hm.arms.len() {
                            merge_bb
                        } else {
                            self.new_block(&format!("ins_next_{idx}"))
                        };
                        let pat_cond = self.eval_pattern_cond(&arm.pattern, scrut_l);
                        let cond = if let Some(ref g) = arm.guard {
                            let g_bb = self.new_block(&format!("ins_guard_{idx}"));
                            self.terminate(Terminator::Branch {
                                cond: pat_cond,
                                then_bb: g_bb,
                                else_bb: next_bb,
                            });
                            self.switch_to(g_bb);
                            self.bind_pattern_value(
                                &arm.pattern,
                                scrut_l,
                                scrut_ty.clone(),
                                hm.scrutinee.ty(),
                            );
                            self.lower_expr(g).0
                        } else {
                            pat_cond
                        };
                        self.terminate(Terminator::Branch {
                            cond,
                            then_bb: arm_bb,
                            else_bb: next_bb,
                        });
                        self.switch_to(arm_bb);
                        self.bind_pattern_value(
                            &arm.pattern,
                            scrut_l,
                            scrut_ty.clone(),
                            hm.scrutinee.ty(),
                        );
                        self.lower_insert_value(ent_l, if_new, &arm.body);
                        if !self.cur_terminated {
                            self.terminate(Terminator::Goto(merge_bb));
                        }
                        self.switch_to(next_bb);
                    }
                    if !self.cur_terminated && self.cur_bb != merge_bb {
                        self.terminate(Terminator::Goto(merge_bb));
                    }
                    self.switch_to(merge_bb);
                }
            }
            other => {
                let cname = match other.ty() {
                    Ty::Named(n) | Ty::Ref(n) => n,
                    _ => "Component".to_owned(),
                };
                let canon = self.ctx.resolve_canonical(&cname);
                let is_zst = self.ctx.find_layout(&canon).is_some_and(|l| l.size == 0);
                let dl = self.lower_expr(other).0;
                self.emit_void(Inst::CmdInsert {
                    entity: ent_l,
                    component: cname,
                    data: if is_zst { None } else { Some(dl) },
                    if_new,
                });
            }
        }
    }

    fn build_spawn_components(&mut self, components: &[HirCompInit]) -> Vec<(String, LocalId)> {
        let mut comps = Vec::with_capacity(components.len());
        for ci in components {
            let fl = self.build_comp_fields(&ci.component, &ci.fields);
            let sl = self.alloc_and_emit(
                &format!("comp_{}", ci.component),
                MirType::Named(ci.component.clone()),
                Inst::StructInit {
                    type_name: ci.component.clone(),
                    fields: fl,
                },
            );
            comps.push((ci.component.clone(), sl));
        }
        comps
    }

    fn build_comp_fields(
        &mut self,
        comp_name: &str,
        explicit: &[(String, HirExpr)],
    ) -> Vec<(String, LocalId)> {
        let layout = self.ctx.find_layout(comp_name).cloned();
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for (fname, fexpr) in explicit {
            seen.insert(fname.clone());
            let sf_ty = layout
                .as_ref()
                .and_then(|l| l.fields.iter().find(|sf| sf.name == *fname))
                .map(|sf| sf.ty.clone());
            let (fl, _) = if let HirExpr::Call(call) = fexpr
                && call.receiver.is_none()
                && call.callee.rsplit("::").next() == Some("bits")
            {
                self.lower_bits_call(call, sf_ty.as_ref())
            } else {
                self.lower_expr(fexpr)
            };
            out.push((fname.clone(), fl));
        }
        if let Some(defs) = self.ctx.layout_defaults(comp_name).cloned() {
            for (dfname, dval) in defs {
                if seen.insert(dfname.clone()) {
                    let f_pref = layout
                        .as_ref()
                        .and_then(|l| l.fields.iter().find(|sf| sf.name == dfname))
                        .map_or(MirType::Unit, |sf| mir_ty_from_hir(&sf.ty));
                    let (fl, _) = self.materialize_const_val(&dfname, &dval, f_pref);
                    out.push((dfname, fl));
                }
            }
        }
        out
    }

    fn is_trigger_payload(&self, base: &HirExpr, field: &str) -> Option<EventOrTriggerPayload> {
        if let HirExpr::Path { name, .. } = base
            && let Some(VarSlot::TriggerCtx { event }) = self.vars.get(name)
        {
            if field == "payload" {
                return Some(EventOrTriggerPayload::Payload(event.clone()));
            }
            if field == "target" || field == "entity" {
                return Some(EventOrTriggerPayload::Target);
            }
        }
        None
    }

    fn lower_field_read(&mut self, base: &HirExpr, field: &str, ty: &Ty) -> (LocalId, MirType) {
        if let Some((entity_local, terms)) = self.lower_point_lookup_unwrap_expr(base) {
            if (field == "entity" || field == "id")
                && let Some(ent) = entity_local
            {
                return (ent, MirType::Entity);
            }
            if let Some(tb) = terms.get(field) {
                if let Some(ref projected_field) = tb.field_name {
                    return self.emit_term_field_load(tb, projected_field);
                }
                if matches!(
                    tb.mode,
                    TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                ) && let Some(p) = tb.present_local
                {
                    return (p, MirType::Bool);
                }
                return (tb.row_ptr.unwrap_or(tb.col_ptr), MirType::Ptr);
            }
        }

        // 1. Direct query row / resource / payload / trigger dereferences
        if let HirExpr::Path { name, .. } = base
            && let Some(slot) = self.vars.get(name).cloned()
        {
            match slot {
                VarSlot::TriggerCtx { event } => {
                    if field == "target" || field == "entity" {
                        let l =
                            self.alloc_and_emit("trg_target", MirType::Entity, Inst::TriggerTarget);
                        return (l, MirType::Entity);
                    }
                    if field == "payload" {
                        let pl = self.alloc_and_emit(
                            "trg_payload",
                            MirType::Ptr,
                            Inst::TriggerPayload { event },
                        );
                        return (pl, MirType::Ptr);
                    }
                }
                VarSlot::SpatialCandidate { entity, pos } => {
                    if field == "id" || field == "entity" {
                        return (entity, MirType::Entity);
                    }
                    return (pos, MirType::Vec3);
                }
                VarSlot::RowAlias {
                    entity_local,
                    terms,
                } => {
                    if (field == "entity" || field == "id")
                        && let Some(ent) = entity_local
                    {
                        return (ent, MirType::Entity);
                    }
                    if let Some(tb) = terms.get(field) {
                        if let Some(ref projected_field) = tb.field_name {
                            // Term already projected to a scalar/vec field (e.g. `xy: &Pos2D.xy`, `face: &Facing.dir_x`).
                            return self.emit_term_field_load(tb, projected_field);
                        }
                        if matches!(
                            tb.mode,
                            TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                        ) && let Some(p) = tb.present_local
                        {
                            return (p, MirType::Bool);
                        }
                        return (tb.row_ptr.unwrap_or(tb.col_ptr), MirType::Ptr);
                    }
                }
                VarSlot::SingleTermPtr { binding } => {
                    if let Some(ref prefix) = binding.field_name {
                        let (base_v, base_ty) = self.emit_term_field_load(&binding, prefix);
                        if is_vec_mir_ty(&base_ty) && is_vec_swizzle(field) {
                            return self.extract_vec_field(base_v, field);
                        }
                        let fpath = format!("{prefix}.{field}");
                        return self.emit_term_field_load(&binding, &fpath);
                    }
                    return self.emit_term_field_load(&binding, field);
                }
                VarSlot::ResPtr {
                    ptr_local,
                    layout_key,
                    ..
                }
                | VarSlot::EventPayloadPtr {
                    ptr_local,
                    layout_key,
                } => {
                    let (offset, fty, _) = self.ctx.resolve_field(&layout_key, field);
                    let id = self.alloc_and_emit(
                        &format!("fld_{field}"),
                        fty.clone(),
                        Inst::FieldLoad {
                            base_ptr: ptr_local,
                            layout_key,
                            field: field.to_owned(),
                            offset_bytes: offset,
                            field_ty: fty.clone(),
                        },
                    );
                    return (id, fty);
                }
                _ => {}
            }
        }

        // 2. Two-level query row component field: `row.comp.field`
        if let HirExpr::Field {
            base: inner_base,
            field: term_alias,
            ..
        } = base
        {
            let inner_terms = if let HirExpr::Path { name: row_name, .. } = inner_base.as_ref()
                && let Some(VarSlot::RowAlias { terms, .. }) = self.vars.get(row_name).cloned()
            {
                Some(terms)
            } else {
                self.lower_point_lookup_unwrap_expr(inner_base)
                    .map(|(_, terms)| terms)
            };
            if let Some(terms) = inner_terms
                && let Some(tb) = terms.get(term_alias)
            {
                if let Some(ref projected_field) = tb.field_name {
                    // `hero.vel.y` where `vel: &Vel2D.dxy`: load vec field then extract lane
                    let (vec_l, vec_ty) = self.emit_term_field_load(tb, projected_field);
                    if is_vec_mir_ty(&vec_ty) {
                        return self.extract_vec_field(vec_l, field);
                    }
                    let nested = format!("{projected_field}.{field}");
                    return self.emit_term_field_load(tb, &nested);
                }
                // Normal `row.comp.field`
                return self.emit_term_field_load(tb, field);
            }
        }

        // 3. `trg.payload.field`
        if let HirExpr::Field {
            base: inner_base,
            field: payload_kw,
            ..
        } = base
            && let Some(EventOrTriggerPayload::Payload(ev)) =
                self.is_trigger_payload(inner_base, payload_kw)
        {
            let pl = self.alloc_and_emit(
                "trg_payload",
                MirType::Ptr,
                Inst::TriggerPayload { event: ev.clone() },
            );
            let layout_key = self.ctx.resolve_canonical(&ev);
            let (offset, fty, _) = self.ctx.resolve_field(&layout_key, field);
            let id = self.alloc_and_emit(
                &format!("ev_{field}"),
                fty.clone(),
                Inst::FieldLoad {
                    base_ptr: pl,
                    layout_key,
                    field: field.to_owned(),
                    offset_bytes: offset,
                    field_ty: fty.clone(),
                },
            );
            return (id, fty);
        }

        // 4. General base expression (vector swizzles `.x`/`.xz`, nested struct fields, etc.)
        let (base_l, base_ty) = self.lower_expr(base);
        if is_vec_mir_ty(&base_ty) && is_vec_swizzle(field) {
            return self.extract_vec_field(base_l, field);
        }
        if base_ty == MirType::Ptr || base_ty == MirType::MutPtr {
            let mut layout_key = match base.ty() {
                Ty::Named(n) | Ty::Ref(n) => self.ctx.resolve_canonical(&n),
                Ty::Borrow { inner, .. } => match inner.as_ref() {
                    Ty::Named(n) | Ty::Ref(n) => self.ctx.resolve_canonical(n),
                    _ => String::new(),
                },
                _ => String::new(),
            };
            if layout_key.is_empty()
                && let HirExpr::Path { name, .. } = base
                && let Some(VarSlot::Slot { slot_local, .. }) = self.vars.get(name)
                && let Some(lk) = self.slot_layouts.get(slot_local)
            {
                layout_key = lk.clone();
            }
            let (offset, fty, _) = self.ctx.resolve_field(&layout_key, field);
            let id = self.alloc_and_emit(
                &format!("fld_{field}"),
                fty.clone(),
                Inst::FieldLoad {
                    base_ptr: base_l,
                    layout_key,
                    field: field.to_owned(),
                    offset_bytes: offset,
                    field_ty: fty.clone(),
                },
            );
            return (id, fty);
        }
        // Table cell field (`CropSpec[key].growth_ticks`)
        if matches!(base, HirExpr::Index { .. })
            && let MirType::Named(ref tname) = base_ty
            && let Some(last_stmt) = self.func.blocks[self.cur_bb.0 as usize].stmts.last_mut()
            && let Inst::TableLoad {
                ref table_name,
                field: ref mut tf,
                ..
            } = last_stmt.inst
            && let bare_tname = tname
                .strip_prefix("__table_row::")
                .unwrap_or(tname.as_str())
            && table_name == bare_tname
            && tf.is_empty()
        {
            *tf = field.to_owned();
            let fty = self
                .ctx
                .tables
                .get(bare_tname)
                .and_then(|t| t.fields.iter().find(|(fnm, _)| fnm == field))
                .map_or_else(|| mir_ty_from_hir(ty), |(_, ft)| mir_ty_from_hir(ft));
            let fty = if fty == MirType::Unit {
                MirType::F32
            } else {
                fty
            };
            if let Some(dst) = last_stmt.dst {
                self.func.locals[dst.0 as usize].ty = fty.clone();
                return (dst, fty);
            }
        }
        if let MirType::Named(ref n) = base_ty {
            let layout_key = self.ctx.resolve_canonical(n);
            if self.ctx.find_layout(&layout_key).is_some()
                && self.ctx.resolve_field_opt(&layout_key, field).is_some()
            {
                let (offset, fty, _) = self.ctx.resolve_field(&layout_key, field);
                let id = self.alloc_and_emit(
                    &format!("fld_{field}"),
                    fty.clone(),
                    Inst::FieldLoad {
                        base_ptr: base_l,
                        layout_key,
                        field: field.to_owned(),
                        offset_bytes: offset,
                        field_ty: fty.clone(),
                    },
                );
                return (id, fty);
            }
        }
        let mty = mir_ty_from_hir(ty);
        let id = self.alloc_and_emit(
            &format!("fld_{field}"),
            mty.clone(),
            Inst::FieldLoad {
                base_ptr: base_l,
                layout_key: match base_ty {
                    MirType::Named(n) => self.ctx.resolve_canonical(&n),
                    _ => String::new(),
                },
                field: field.to_owned(),
                offset_bytes: 0,
                field_ty: mty.clone(),
            },
        );
        (id, mty)
    }

    fn emit_term_field_load(&mut self, tb: &TermAccessBinding, field: &str) -> (LocalId, MirType) {
        let base_ptr = tb.row_ptr.unwrap_or(tb.col_ptr);
        let (offset, fty, _) = self.ctx.resolve_field(&tb.canonical_layout, field);
        let id = self.alloc_and_emit(
            &format!("t_{field}"),
            fty.clone(),
            Inst::FieldLoad {
                base_ptr,
                layout_key: tb.canonical_layout.clone(),
                field: field.to_owned(),
                offset_bytes: offset,
                field_ty: fty.clone(),
            },
        );
        (id, fty)
    }

    fn extract_vec_field(&mut self, vec_l: LocalId, swizzle: &str) -> (LocalId, MirType) {
        let vec_ty = self.func.locals[vec_l.0 as usize].ty.clone();
        let lanes: Vec<u8> = swizzle.chars().filter_map(vec_char_lane).collect();
        if lanes.len() == 1 {
            let lane_ty = vec_lane_mir_ty(&vec_ty);
            let l = self.alloc_and_emit(
                &format!("v_{swizzle}"),
                lane_ty.clone(),
                Inst::VecExtract {
                    vec: vec_l,
                    lane: lanes[0],
                },
            );
            (l, lane_ty)
        } else {
            let vty = vec_swizzle_mir_ty(&vec_ty, lanes.len());
            let l = self.alloc_and_emit(
                &format!("swiz_{swizzle}"),
                vty.clone(),
                Inst::VecSwizzle { vec: vec_l, lanes },
            );
            (l, vty)
        }
    }

    fn lower_assign(&mut self, target: &HirLValue, op: HirAssignOp, value: &HirExpr) {
        if let HirLValue::Local { name, .. } = target
            && op == HirAssignOp::Set
            && let HirExpr::Path { name: src_name, .. } = value
            && let Some(slot) = self.vars.get(src_name).cloned()
        {
            match &slot {
                VarSlot::RowAlias { .. } | VarSlot::Tuple(_) => {
                    self.vars.insert(name.clone(), slot);
                    return;
                }
                VarSlot::SingleTermPtr { binding }
                    if binding.field_name.is_none() || binding.present_local.is_some() =>
                {
                    self.vars.insert(name.clone(), slot);
                    return;
                }
                _ => {}
            }
        }
        let place = self.resolve_lvalue_place(target);
        let (rhs_l, rhs_ty) = if op == HirAssignOp::Set
            && let HirExpr::Call(call) = value
            && call.receiver.is_none()
            && call.callee.rsplit("::").next() == Some("bits")
        {
            let target_bs = place.as_ref().and_then(|p| match p {
                MirPlace::Slot { ty, .. }
                | MirPlace::TermField { field_ty: ty, .. }
                | MirPlace::PtrField { field_ty: ty, .. }
                | MirPlace::ArrayElem { elem_ty: ty, .. } => {
                    bitset_bits_from_mir_ty(ty).map(Ty::BitSet)
                }
                _ => None,
            });
            self.lower_bits_call(call, target_bs.as_ref())
        } else {
            self.lower_expr(value)
        };
        if let Some(place) = place {
            self.write_place(&place, op, rhs_l, rhs_ty);
        }
    }

    fn resolve_lvalue_place(&mut self, target: &HirLValue) -> Option<MirPlace> {
        match target {
            HirLValue::Local { name, .. } => self.resolve_local_place(name),
            HirLValue::ResourceAccess { resource, .. } => {
                let layout_key = self.ctx.resolve_canonical(resource);
                let ptr_local = self.alloc_and_emit(
                    &format!("res_mut_{resource}"),
                    MirType::MutPtr,
                    Inst::ResWrite {
                        resource: resource.clone(),
                    },
                );
                Some(MirPlace::Ptr {
                    ptr_local,
                    layout_key,
                    ty: MirType::MutPtr,
                })
            }
            HirLValue::Field { base, field, ty } => {
                let base_place = self.resolve_lvalue_place(base)?;
                self.resolve_field_place(base_place, field, ty)
            }
            HirLValue::Index { base, index, ty } => {
                let base_place = self.resolve_lvalue_place(base)?;
                let idx_l = self.lower_expr(index).0;
                Some(self.resolve_index_place(base_place, idx_l, ty))
            }
            HirLValue::Expr(expr) => self.resolve_expr_place(expr),
        }
    }

    fn resolve_local_place(&self, name: &str) -> Option<MirPlace> {
        let slot = self.vars.get(name)?.clone();
        match slot {
            VarSlot::Slot { slot_local, ty } => Some(MirPlace::Slot {
                name: name.to_owned(),
                slot_local,
                ty,
            }),
            VarSlot::ResPtr {
                ptr_local,
                layout_key,
            } => Some(MirPlace::Ptr {
                ptr_local,
                layout_key,
                ty: MirType::MutPtr,
            }),
            VarSlot::RowAlias { terms, .. } => Some(MirPlace::RowAlias { terms }),
            VarSlot::SingleTermPtr { binding } => {
                if let Some(ref proj) = binding.field_name {
                    let (_, fty, _) = self.ctx.resolve_field(&binding.canonical_layout, proj);
                    Some(MirPlace::TermField {
                        binding: binding.clone(),
                        field_path: proj.clone(),
                        field_ty: fty,
                    })
                } else {
                    Some(MirPlace::Ptr {
                        ptr_local: binding.row_ptr.unwrap_or(binding.col_ptr),
                        layout_key: binding.canonical_layout,
                        ty: MirType::MutPtr,
                    })
                }
            }
            _ => None,
        }
    }

    fn resolve_expr_place(&mut self, expr: &HirExpr) -> Option<MirPlace> {
        match expr {
            HirExpr::Block { stmts, tail, .. } => {
                self.lower_stmts(stmts);
                tail.as_deref().and_then(|t| self.resolve_expr_place(t))
            }
            HirExpr::Path { name, .. } => self.resolve_local_place(name),
            HirExpr::Field { base, field, ty } => {
                let base_place = self.resolve_expr_place(base)?;
                self.resolve_field_place(base_place, field, ty)
            }
            HirExpr::Index { base, index, ty } => {
                let base_place = self.resolve_expr_place(base)?;
                let idx_l = self.lower_expr(index).0;
                Some(self.resolve_index_place(base_place, idx_l, ty))
            }
            other => {
                if let Some((_, terms)) = self.lower_point_lookup_unwrap_expr(other) {
                    return Some(MirPlace::RowAlias { terms });
                }
                let (ptr_l, mty) = self.lower_expr(other);
                let layout_key = match other.ty() {
                    Ty::Named(n) | Ty::Ref(n) => self.ctx.resolve_canonical(&n),
                    Ty::Borrow { inner, .. } => match inner.as_ref() {
                        Ty::Named(n) | Ty::Ref(n) => self.ctx.resolve_canonical(n),
                        _ => String::new(),
                    },
                    _ => match &mty {
                        MirType::Named(n) => self.ctx.resolve_canonical(n),
                        _ => String::new(),
                    },
                };
                Some(MirPlace::Ptr {
                    ptr_local: ptr_l,
                    layout_key,
                    ty: mty,
                })
            }
        }
    }

    fn resolve_field_place(&mut self, base: MirPlace, field: &str, _ty: &Ty) -> Option<MirPlace> {
        match base {
            MirPlace::RowAlias { terms } => {
                let tb = terms.get(field)?.clone();
                if let Some(proj_field) = tb.field_name.clone() {
                    let (_, fty, _) = self.ctx.resolve_field(&tb.canonical_layout, &proj_field);
                    Some(MirPlace::TermField {
                        binding: tb,
                        field_path: proj_field,
                        field_ty: fty,
                    })
                } else {
                    Some(MirPlace::Ptr {
                        ptr_local: tb.row_ptr.unwrap_or(tb.col_ptr),
                        layout_key: tb.canonical_layout,
                        ty: MirType::MutPtr,
                    })
                }
            }
            MirPlace::TermField {
                binding,
                field_path,
                field_ty,
            } => {
                if is_vec_mir_ty(&field_ty)
                    && let Some(lane) = vec_lane_index(field)
                {
                    return Some(MirPlace::VecLane {
                        inner: Box::new(MirPlace::TermField {
                            binding,
                            field_path,
                            field_ty: field_ty.clone(),
                        }),
                        vec_ty: field_ty,
                        lane,
                    });
                }
                let nested = if field_path.is_empty() {
                    field.to_owned()
                } else {
                    format!("{field_path}.{field}")
                };
                let (_, fty, _) = self.ctx.resolve_field(&binding.canonical_layout, &nested);
                Some(MirPlace::TermField {
                    binding,
                    field_path: nested,
                    field_ty: fty,
                })
            }
            MirPlace::Ptr {
                ptr_local,
                layout_key,
                ..
            } => {
                let (_, fty, _) = self.ctx.resolve_field(&layout_key, field);
                Some(MirPlace::PtrField {
                    ptr_local,
                    layout_key,
                    field_path: field.to_owned(),
                    field_ty: fty,
                })
            }
            MirPlace::PtrField {
                ptr_local,
                layout_key,
                field_path,
                field_ty,
            } => {
                if is_vec_mir_ty(&field_ty)
                    && let Some(lane) = vec_lane_index(field)
                {
                    return Some(MirPlace::VecLane {
                        inner: Box::new(MirPlace::PtrField {
                            ptr_local,
                            layout_key,
                            field_path,
                            field_ty: field_ty.clone(),
                        }),
                        vec_ty: field_ty,
                        lane,
                    });
                }
                let nested = format!("{field_path}.{field}");
                let (_, fty, _) = self.ctx.resolve_field(&layout_key, &nested);
                Some(MirPlace::PtrField {
                    ptr_local,
                    layout_key,
                    field_path: nested,
                    field_ty: fty,
                })
            }
            MirPlace::Slot {
                name,
                slot_local,
                ty,
            } => {
                if is_vec_mir_ty(&ty)
                    && let Some(lane) = vec_lane_index(field)
                {
                    return Some(MirPlace::VecLane {
                        inner: Box::new(MirPlace::Slot {
                            name,
                            slot_local,
                            ty: ty.clone(),
                        }),
                        vec_ty: ty,
                        lane,
                    });
                }
                let layout_key = match &ty {
                    MirType::Named(n) => self.ctx.resolve_canonical(n),
                    _ => self
                        .slot_layouts
                        .get(&slot_local)
                        .cloned()
                        .unwrap_or_default(),
                };
                let ptr = if matches!(ty, MirType::Ptr | MirType::MutPtr) {
                    self.alloc_and_emit(&name, MirType::MutPtr, Inst::SlotLoad { slot: slot_local })
                } else {
                    slot_local
                };
                let (_, fty, _) = self.ctx.resolve_field(&layout_key, field);
                Some(MirPlace::PtrField {
                    ptr_local: ptr,
                    layout_key,
                    field_path: field.to_owned(),
                    field_ty: fty,
                })
            }
            MirPlace::ArrayElem {
                base,
                index,
                elem_ty,
            } => {
                if is_vec_mir_ty(&elem_ty)
                    && let Some(lane) = vec_lane_index(field)
                {
                    return Some(MirPlace::VecLane {
                        inner: Box::new(MirPlace::ArrayElem {
                            base,
                            index,
                            elem_ty: elem_ty.clone(),
                        }),
                        vec_ty: elem_ty,
                        lane,
                    });
                }
                None
            }
            MirPlace::VecLane { .. } => None,
        }
    }

    fn resolve_index_place(&self, base: MirPlace, index: LocalId, ty: &Ty) -> MirPlace {
        let base_elem = match &base {
            MirPlace::Slot {
                ty: MirType::Array { elem, .. },
                ..
            }
            | MirPlace::TermField {
                field_ty: MirType::Array { elem, .. },
                ..
            }
            | MirPlace::PtrField {
                field_ty: MirType::Array { elem, .. },
                ..
            } => Some((**elem).clone()),
            _ => None,
        };
        let elem_ty = base_elem.unwrap_or_else(|| {
            let m = mir_ty_from_hir(ty);
            if m == MirType::Unit { MirType::F32 } else { m }
        });
        MirPlace::ArrayElem {
            base: Box::new(base),
            index,
            elem_ty,
        }
    }

    fn read_place(&mut self, place: &MirPlace) -> (LocalId, MirType) {
        match place {
            MirPlace::Slot {
                name,
                slot_local,
                ty,
            } => {
                let v = self.alloc_and_emit(name, ty.clone(), Inst::SlotLoad { slot: *slot_local });
                (v, ty.clone())
            }
            MirPlace::TermField {
                binding,
                field_path,
                ..
            } => self.emit_term_field_load(binding, field_path),
            MirPlace::PtrField {
                ptr_local,
                layout_key,
                field_path,
                ..
            } => {
                let (offset, fty, _) = self.ctx.resolve_field(layout_key, field_path);
                let v = self.alloc_and_emit(
                    field_path,
                    fty.clone(),
                    Inst::FieldLoad {
                        base_ptr: *ptr_local,
                        layout_key: layout_key.clone(),
                        field: field_path.clone(),
                        offset_bytes: offset,
                        field_ty: fty.clone(),
                    },
                );
                (v, fty)
            }
            MirPlace::VecLane {
                inner,
                vec_ty,
                lane,
            } => {
                let (vec_cur, _) = self.read_place(inner);
                let lane_ty = vec_lane_mir_ty(vec_ty);
                let cur_lane = self.alloc_and_emit(
                    "lane_cur",
                    lane_ty.clone(),
                    Inst::VecExtract {
                        vec: vec_cur,
                        lane: *lane,
                    },
                );
                (cur_lane, lane_ty)
            }
            MirPlace::ArrayElem {
                base,
                index,
                elem_ty,
            } => {
                let (arr_val, _) = self.read_place(base);
                let el = self.alloc_and_emit(
                    "arr_elem",
                    elem_ty.clone(),
                    Inst::ArrayIndex {
                        base: arr_val,
                        index: *index,
                    },
                );
                (el, elem_ty.clone())
            }
            MirPlace::Ptr { ptr_local, ty, .. } => (*ptr_local, ty.clone()),
            MirPlace::RowAlias { .. } => {
                let u =
                    self.alloc_and_emit("unit", MirType::Unit, Inst::ConstBool { value: false });
                (u, MirType::Unit)
            }
        }
    }

    fn write_place(&mut self, place: &MirPlace, op: HirAssignOp, rhs_l: LocalId, rhs_ty: MirType) {
        match place {
            MirPlace::Slot {
                name,
                slot_local,
                ty,
            } => {
                let coerced_rhs = self.coerce_local_to_ty(rhs_l, rhs_ty, ty);
                let final_val = if op == HirAssignOp::Set {
                    coerced_rhs
                } else {
                    let cur =
                        self.alloc_and_emit(name, ty.clone(), Inst::SlotLoad { slot: *slot_local });
                    let allow_fma = !self.ctx.is_deterministic
                        && !self.func.is_deterministic
                        && matches!(ty, MirType::F32 | MirType::F64);
                    self.alloc_and_emit(
                        "upd",
                        ty.clone(),
                        Inst::BinOp {
                            op: assign_op_str(op).to_owned(),
                            lhs: cur,
                            rhs: coerced_rhs,
                            allow_fma,
                        },
                    )
                };
                self.emit_void(Inst::SlotStore {
                    slot: *slot_local,
                    val: final_val,
                });
            }
            MirPlace::TermField {
                binding,
                field_path,
                ..
            } => {
                if !field_path.is_empty() {
                    self.store_term_field(binding, field_path, op, rhs_l, rhs_ty);
                }
            }
            MirPlace::PtrField {
                ptr_local,
                layout_key,
                field_path,
                ..
            } => {
                self.store_ptr_field(*ptr_local, layout_key, field_path, op, rhs_l, rhs_ty);
            }
            MirPlace::VecLane {
                inner,
                vec_ty,
                lane,
            } => {
                let (vec_cur, _) = self.read_place(inner);
                let lane_ty = vec_lane_mir_ty(vec_ty);
                let coerced_rhs = self.coerce_local_to_ty(rhs_l, rhs_ty, &lane_ty);
                let scalar_val = if op == HirAssignOp::Set {
                    coerced_rhs
                } else {
                    let cur_lane = self.alloc_and_emit(
                        "lane_cur",
                        lane_ty.clone(),
                        Inst::VecExtract {
                            vec: vec_cur,
                            lane: *lane,
                        },
                    );
                    self.alloc_and_emit(
                        "lane_upd",
                        lane_ty,
                        Inst::BinOp {
                            op: assign_op_str(op).to_owned(),
                            lhs: cur_lane,
                            rhs: coerced_rhs,
                            allow_fma: !self.ctx.is_deterministic
                                && !self.func.is_deterministic
                                && !matches!(
                                    vec_ty,
                                    MirType::IVec2 | MirType::IVec3 | MirType::UVec2
                                ),
                        },
                    )
                };
                let new_vec = self.alloc_and_emit(
                    "vec_ins",
                    vec_ty.clone(),
                    Inst::VecInsert {
                        vec: vec_cur,
                        lane: *lane,
                        val: scalar_val,
                    },
                );
                self.write_place(inner, HirAssignOp::Set, new_vec, vec_ty.clone());
            }
            MirPlace::ArrayElem {
                base,
                index,
                elem_ty,
            } => {
                let coerced_rhs = self.coerce_local_to_ty(rhs_l, rhs_ty, elem_ty);
                let final_val = if op == HirAssignOp::Set {
                    coerced_rhs
                } else {
                    let (cur_el, _) = self.read_place(place);
                    let allow_fma = !self.ctx.is_deterministic
                        && !self.func.is_deterministic
                        && matches!(elem_ty, MirType::F32 | MirType::F64);
                    self.alloc_and_emit(
                        "arr_upd",
                        elem_ty.clone(),
                        Inst::BinOp {
                            op: assign_op_str(op).to_owned(),
                            lhs: cur_el,
                            rhs: coerced_rhs,
                            allow_fma,
                        },
                    )
                };
                if let Some(arr_ptr) = self.resolve_array_base_ptr(base) {
                    self.emit_void(Inst::ArrayStore {
                        base_ptr: arr_ptr,
                        index: *index,
                        val: final_val,
                        elem_ty: elem_ty.clone(),
                    });
                }
            }
            MirPlace::Ptr { .. } | MirPlace::RowAlias { .. } => {}
        }
    }

    fn resolve_array_base_ptr(&mut self, base: &MirPlace) -> Option<LocalId> {
        match base {
            MirPlace::Slot { slot_local, .. } => Some(*slot_local),
            MirPlace::Ptr { ptr_local, .. } => Some(*ptr_local),
            MirPlace::TermField {
                binding,
                field_path,
                ..
            } => {
                let base_ptr = binding.row_ptr.unwrap_or(binding.col_ptr);
                let (offset, _, _) = self
                    .ctx
                    .resolve_field(&binding.canonical_layout, field_path);
                Some(self.alloc_and_emit(
                    &format!("arr_ptr_{field_path}"),
                    MirType::MutPtr,
                    Inst::FieldPtr {
                        base_ptr,
                        layout_key: binding.canonical_layout.clone(),
                        field: field_path.clone(),
                        offset_bytes: offset,
                    },
                ))
            }
            MirPlace::PtrField {
                ptr_local,
                layout_key,
                field_path,
                ..
            } => {
                let (offset, _, _) = self.ctx.resolve_field(layout_key, field_path);
                Some(self.alloc_and_emit(
                    &format!("arr_ptr_{field_path}"),
                    MirType::MutPtr,
                    Inst::FieldPtr {
                        base_ptr: *ptr_local,
                        layout_key: layout_key.clone(),
                        field: field_path.clone(),
                        offset_bytes: offset,
                    },
                ))
            }
            _ => None,
        }
    }

    fn store_term_field(
        &mut self,
        tb: &TermAccessBinding,
        field: &str,
        op: HirAssignOp,
        rhs_l: LocalId,
        rhs_ty: MirType,
    ) {
        let base_ptr = tb.row_ptr.unwrap_or(tb.col_ptr);
        self.store_ptr_field(base_ptr, &tb.canonical_layout, field, op, rhs_l, rhs_ty);
    }

    fn store_ptr_field(
        &mut self,
        base_ptr: LocalId,
        layout_key: &str,
        field: &str,
        op: HirAssignOp,
        rhs_l: LocalId,
        rhs_ty: MirType,
    ) {
        let (offset, fty, _) = self.ctx.resolve_field(layout_key, field);
        let coerced_rhs = self.coerce_local_to_ty(rhs_l, rhs_ty, &fty);
        let final_val = if op == HirAssignOp::Set {
            coerced_rhs
        } else {
            let cur = self.alloc_and_emit(
                field,
                fty.clone(),
                Inst::FieldLoad {
                    base_ptr,
                    layout_key: layout_key.to_owned(),
                    field: field.to_owned(),
                    offset_bytes: offset,
                    field_ty: fty.clone(),
                },
            );
            let allow_fma = !self.ctx.is_deterministic
                && !self.func.is_deterministic
                && matches!(fty, MirType::F32 | MirType::F64);
            self.alloc_and_emit(
                &format!("{field}_upd"),
                fty,
                Inst::BinOp {
                    op: assign_op_str(op).to_owned(),
                    lhs: cur,
                    rhs: coerced_rhs,
                    allow_fma,
                },
            )
        };
        self.emit_void(Inst::FieldStore {
            base_ptr,
            layout_key: layout_key.to_owned(),
            field: field.to_owned(),
            offset_bytes: offset,
            val: final_val,
        });
    }

    fn arg_or_float(&mut self, args: &[HirExpr], idx: usize, default: f64) -> LocalId {
        if let Some(a) = args.get(idx) {
            self.lower_expr(a).0
        } else {
            self.alloc_and_emit("f_def", MirType::F32, Inst::ConstFloat { value: default })
        }
    }

    fn arg_or_int(&mut self, args: &[HirExpr], idx: usize, default: i64, ty: MirType) -> LocalId {
        if let Some(a) = args.get(idx) {
            if let HirExpr::IntLit { value, .. } = a {
                return self.alloc_and_emit("i_arg", ty, Inst::ConstInt { value: *value });
            }
            let (id, actual_ty) = self.lower_expr(a);
            if actual_ty != ty {
                return self.alloc_and_emit(
                    "i_cast",
                    ty.clone(),
                    Inst::Cast {
                        val: id,
                        target_ty: ty,
                    },
                );
            }
            id
        } else {
            self.alloc_and_emit("i_def", ty, Inst::ConstInt { value: default })
        }
    }

    fn lower_call(&mut self, call: &HirCall) -> (LocalId, MirType) {
        let short_callee = call
            .callee
            .rsplit("::")
            .next()
            .unwrap_or(call.callee.as_str());
        match short_callee {
            "res" => {
                let rname = call.generic_args.first().cloned().unwrap_or_default();
                let id = self.alloc_and_emit(
                    &format!("res_{rname}"),
                    MirType::Ptr,
                    Inst::ResRead { resource: rname },
                );
                return (id, MirType::Ptr);
            }
            "res_mut" => {
                let rname = call.generic_args.first().cloned().unwrap_or_default();
                let id = self.alloc_and_emit(
                    &format!("res_mut_{rname}"),
                    MirType::MutPtr,
                    Inst::ResWrite { resource: rname },
                );
                return (id, MirType::MutPtr);
            }
            "vec2" | "Vec2" => {
                let x = self.arg_or_float(&call.args, 0, 0.0);
                let y = self.arg_or_float(&call.args, 1, 0.0);
                let id = self.alloc_and_emit(
                    "v2",
                    MirType::Vec2,
                    Inst::IntrinsicMath {
                        name: "vec2".to_owned(),
                        args: vec![x, y],
                        deterministic: true,
                    },
                );
                return (id, MirType::Vec2);
            }
            "vec3" | "Vec3" => {
                let x = self.arg_or_float(&call.args, 0, 0.0);
                let y = self.arg_or_float(&call.args, 1, 0.0);
                let z = self.arg_or_float(&call.args, 2, 0.0);
                let id = self.alloc_and_emit(
                    "v3",
                    MirType::Vec3,
                    Inst::IntrinsicMath {
                        name: "vec3".to_owned(),
                        args: vec![x, y, z],
                        deterministic: true,
                    },
                );
                return (id, MirType::Vec3);
            }
            "vec3a" | "Vec3a" => {
                let x = self.arg_or_float(&call.args, 0, 0.0);
                let y = self.arg_or_float(&call.args, 1, 0.0);
                let z = self.arg_or_float(&call.args, 2, 0.0);
                let w = self.alloc_and_emit("v3a_w", MirType::F32, Inst::ConstFloat { value: 0.0 });
                let id = self.alloc_and_emit(
                    "v3a",
                    MirType::Vec4,
                    Inst::IntrinsicMath {
                        name: "vec3a".to_owned(),
                        args: vec![x, y, z, w],
                        deterministic: true,
                    },
                );
                return (id, MirType::Vec4);
            }
            "vec4" | "Vec4" | "quat" | "Quat" | "rgba" | "Rgba" => {
                let x = self.arg_or_float(&call.args, 0, 0.0);
                let y = self.arg_or_float(&call.args, 1, 0.0);
                let z = self.arg_or_float(&call.args, 2, 0.0);
                let w = self.arg_or_float(&call.args, 3, 0.0);
                let id = self.alloc_and_emit(
                    "v4",
                    MirType::Vec4,
                    Inst::IntrinsicMath {
                        name: "vec4".to_owned(),
                        args: vec![x, y, z, w],
                        deterministic: true,
                    },
                );
                return (id, MirType::Vec4);
            }
            "ivec2" | "IVec2" => {
                let x = self.arg_or_int(&call.args, 0, 0, MirType::I32);
                let y = self.arg_or_int(&call.args, 1, 0, MirType::I32);
                let id = self.alloc_and_emit(
                    "iv2",
                    MirType::IVec2,
                    Inst::IntrinsicMath {
                        name: "ivec2".to_owned(),
                        args: vec![x, y],
                        deterministic: true,
                    },
                );
                return (id, MirType::IVec2);
            }
            "ivec3" | "IVec3" => {
                let x = self.arg_or_int(&call.args, 0, 0, MirType::I32);
                let y = self.arg_or_int(&call.args, 1, 0, MirType::I32);
                let z = self.arg_or_int(&call.args, 2, 0, MirType::I32);
                let id = self.alloc_and_emit(
                    "iv3",
                    MirType::IVec3,
                    Inst::IntrinsicMath {
                        name: "ivec3".to_owned(),
                        args: vec![x, y, z],
                        deterministic: true,
                    },
                );
                return (id, MirType::IVec3);
            }
            "uvec2" | "UVec2" => {
                let x = self.arg_or_int(&call.args, 0, 0, MirType::U32);
                let y = self.arg_or_int(&call.args, 1, 0, MirType::U32);
                let id = self.alloc_and_emit(
                    "uv2",
                    MirType::UVec2,
                    Inst::IntrinsicMath {
                        name: "uvec2".to_owned(),
                        args: vec![x, y],
                        deterministic: true,
                    },
                );
                return (id, MirType::UVec2);
            }
            "bits" => {
                return self.lower_bits_call(call, None);
            }
            "meters" | "sec" | "ms" | "rad" | "deg" | "mps" | "mps2" | "hz" | "frames" => {
                if let Some(a0) = call.args.first() {
                    return self.lower_expr(a0);
                }
            }
            "sin" | "cos" | "tan" | "atan2" | "sqrt" | "abs" | "min" | "max" | "clamp"
            | "floor" | "ceil" | "round" | "pow" | "exp" | "ln" | "lerp" | "dot" | "length"
            | "distance" | "normalize" | "cross" => {
                let mut arg_ids = Vec::with_capacity(call.args.len());
                for a in &call.args {
                    arg_ids.push(self.lower_expr(a).0);
                }
                let rty = mir_ty_from_hir(&call.ty);
                let rty = if rty == MirType::Unit {
                    MirType::F32
                } else {
                    rty
                };
                let id = self.alloc_and_emit(
                    &call.callee,
                    rty.clone(),
                    Inst::IntrinsicMath {
                        name: call.callee.clone(),
                        args: arg_ids,
                        deterministic: self.ctx.is_deterministic || self.func.is_deterministic,
                    },
                );
                return (id, rty);
            }
            _ => {}
        }

        let mut arg_ids = Vec::with_capacity(call.args.len());
        for a in &call.args {
            arg_ids.push(self.lower_expr(a).0);
        }
        let rty = self
            .ctx
            .fn_ret_tys
            .get(&call.callee)
            .cloned()
            .unwrap_or_else(|| mir_ty_from_hir(&call.ty));
        let id = self.alloc_and_emit(
            "call_res",
            rty.clone(),
            Inst::Call {
                callee: call.callee.clone(),
                args: arg_ids,
            },
        );
        (id, rty)
    }

    fn lower_method_call(
        &mut self,
        receiver: &HirExpr,
        method: &str,
        args: &[HirExpr],
        ty: &Ty,
    ) -> (LocalId, MirType) {
        match method {
            "as_secs" | "raw" => return self.lower_expr(receiver),
            "sample" => {
                if let HirExpr::Path { name, .. } = receiver
                    && self.ctx.curves.contains_key(name)
                {
                    let x = self.arg_or_float(args, 0, 0.0);
                    let rty = mir_ty_from_hir(ty);
                    let rty = if rty == MirType::Unit {
                        MirType::F32
                    } else {
                        rty
                    };
                    let id = self.alloc_and_emit(
                        &format!("sample_{name}"),
                        rty.clone(),
                        Inst::CurveSample {
                            curve_name: name.clone(),
                            x,
                        },
                    );
                    return (id, rty);
                }
            }
            "query_disc" => {
                let raw_name = receiver_resource_name(receiver);
                let grid_name = self.resolve_spatial_resource_name(&raw_name);
                let center = if let Some(a) = args.first() {
                    self.lower_expr(a).0
                } else {
                    self.alloc_and_emit(
                        "c",
                        MirType::Vec2,
                        Inst::ConstVec {
                            dims: 2,
                            values: [0.0; 4],
                        },
                    )
                };
                let radius = self.arg_or_float(args, 1, 1.0);
                let id = self.alloc_and_emit(
                    "disc_iter",
                    MirType::QueryIter,
                    Inst::SpatialQueryDisc {
                        grid_name,
                        center,
                        radius,
                    },
                );
                return (id, MirType::QueryIter);
            }
            "query_segment_at" => {
                let raw_name = receiver_resource_name(receiver);
                let history_name = self.resolve_spatial_resource_name(&raw_name);
                let zero_v = self.alloc_and_emit(
                    "zv",
                    MirType::Vec3,
                    Inst::ConstVec {
                        dims: 3,
                        values: [0.0; 4],
                    },
                );
                let start = if let Some(a) = args.first() {
                    self.lower_expr(a).0
                } else {
                    zero_v
                };
                let end = if let Some(a) = args.get(1) {
                    self.lower_expr(a).0
                } else {
                    zero_v
                };
                let radius = self.arg_or_float(args, 2, 1.0);
                let tick_offset = self.arg_or_int(args, 3, 0, MirType::U32);
                let id = self.alloc_and_emit(
                    "seg_iter",
                    MirType::QueryIter,
                    Inst::SpatialQuerySegmentAt {
                        history_name,
                        start,
                        end,
                        radius,
                        tick_offset,
                    },
                );
                return (id, MirType::QueryIter);
            }
            "arm" => {
                let ptr = self.lower_primitive_field_ptr(receiver);
                let dur = self.arg_or_float(args, 0, 0.0);
                self.emit_void(Inst::GraceArm {
                    ptr,
                    duration_sec: dur,
                });
                let u =
                    self.alloc_and_emit("unit", MirType::Unit, Inst::ConstBool { value: false });
                return (u, MirType::Unit);
            }
            "is_active" => {
                let ptr = self.lower_primitive_field_ptr(receiver);
                let id =
                    self.alloc_and_emit("grace_active", MirType::Bool, Inst::GraceIsActive { ptr });
                return (id, MirType::Bool);
            }
            "clear" => {
                let ptr = self.lower_primitive_field_ptr(receiver);
                if args.is_empty() {
                    self.emit_void(Inst::GraceClear { ptr });
                } else {
                    let words = match receiver.ty() {
                        Ty::BitSet(b) => b.div_ceil(32).max(1) as u32,
                        _ => 1,
                    };
                    let bit = self.lower_expr(&args[0]).0;
                    self.emit_void(Inst::BitSetClear { ptr, words, bit });
                }
                let u =
                    self.alloc_and_emit("unit", MirType::Unit, Inst::ConstBool { value: false });
                return (u, MirType::Unit);
            }
            "push" => {
                let ptr = self.lower_primitive_field_ptr(receiver);
                let cap = input_buf_cap(receiver);
                let action_id = self.arg_or_int(args, 0, 0, MirType::U16);
                let window_sec = self.arg_or_float(args, 1, 0.1);
                self.emit_void(Inst::InputBufPush {
                    ptr,
                    capacity: cap,
                    action_id,
                    window_sec,
                });
                let u =
                    self.alloc_and_emit("unit", MirType::Unit, Inst::ConstBool { value: false });
                return (u, MirType::Unit);
            }
            "consume" => {
                let ptr = self.lower_primitive_field_ptr(receiver);
                let cap = input_buf_cap(receiver);
                let action_id = self.arg_or_int(args, 0, 0, MirType::U16);
                let id = self.alloc_and_emit(
                    "consumed",
                    MirType::Bool,
                    Inst::InputBufConsume {
                        ptr,
                        capacity: cap,
                        action_id,
                    },
                );
                return (id, MirType::Bool);
            }
            "peek" => {
                let ptr = self.lower_primitive_field_ptr(receiver);
                let cap = input_buf_cap(receiver);
                let action_id = self.arg_or_int(args, 0, 0, MirType::U16);
                let id = self.alloc_and_emit(
                    "peeked",
                    MirType::Bool,
                    Inst::InputBufPeek {
                        ptr,
                        capacity: cap,
                        action_id,
                    },
                );
                return (id, MirType::Bool);
            }
            "set" => {
                let ptr = self.lower_primitive_field_ptr(receiver);
                let words = bitset_words(receiver);
                let bit = self.arg_or_int(args, 0, 0, MirType::U32);
                self.emit_void(Inst::BitSetSet { ptr, words, bit });
                let u =
                    self.alloc_and_emit("unit", MirType::Unit, Inst::ConstBool { value: false });
                return (u, MirType::Unit);
            }
            "get" => {
                let ptr = self.lower_primitive_field_ptr(receiver);
                let words = bitset_words(receiver);
                let bit = self.arg_or_int(args, 0, 0, MirType::U32);
                let id = self.alloc_and_emit(
                    "bit_get",
                    MirType::Bool,
                    Inst::BitSetGet { ptr, words, bit },
                );
                return (id, MirType::Bool);
            }
            "in" => {
                let ptr = self.lower_primitive_field_ptr(receiver);
                let window_bit = resolve_timeline_window_bit(self.ctx, receiver, args.first());
                let id = self.alloc_and_emit(
                    "in_win",
                    MirType::Bool,
                    Inst::TimelineInWindow { ptr, window_bit },
                );
                return (id, MirType::Bool);
            }
            "is_some" => {
                if let Some((tb, present)) = self.resolve_optional_term_binding(receiver) {
                    let eff = self.emit_optional_present_check(&tb, present);
                    return (eff, MirType::Bool);
                }
                if let Some((cond, _, _)) = self.try_lower_optional_row_binding(receiver) {
                    return (cond, MirType::Bool);
                }
            }
            "is_none" => {
                if let Some((tb, present)) = self.resolve_optional_term_binding(receiver) {
                    let eff = self.emit_optional_present_check(&tb, present);
                    let neg = self.alloc_and_emit(
                        "opt_is_none",
                        MirType::Bool,
                        Inst::UnOp {
                            op: "!".to_owned(),
                            val: eff,
                        },
                    );
                    return (neg, MirType::Bool);
                }
                if let Some((cond, _, _)) = self.try_lower_optional_row_binding(receiver) {
                    let neg = self.alloc_and_emit(
                        "opt_is_none",
                        MirType::Bool,
                        Inst::UnOp {
                            op: "!".to_owned(),
                            val: cond,
                        },
                    );
                    return (neg, MirType::Bool);
                }
            }
            "unwrap" | "expect" => {
                if let Some((tb, _)) = self.resolve_optional_term_binding(receiver) {
                    if let Some(ref f) = tb.field_name {
                        return self.emit_term_field_load(&tb, f);
                    }
                    let ptr_ty = if tb.mode.is_mutable() {
                        MirType::MutPtr
                    } else {
                        MirType::Ptr
                    };
                    return (tb.row_ptr.unwrap_or(tb.col_ptr), ptr_ty);
                }
                return self.lower_expr(receiver);
            }
            _ => {}
        }

        let mut call_args = vec![self.lower_expr(receiver).0];
        for a in args {
            call_args.push(self.lower_expr(a).0);
        }
        let rty = mir_ty_from_hir(ty);
        let id = self.alloc_and_emit(
            method,
            rty.clone(),
            Inst::Call {
                callee: method.to_owned(),
                args: call_args,
            },
        );
        (id, rty)
    }

    fn resolve_optional_term_binding(
        &self,
        receiver: &HirExpr,
    ) -> Option<(TermAccessBinding, LocalId)> {
        match receiver {
            HirExpr::Field { base, field, .. } => {
                if let HirExpr::Path { name: row_name, .. } = base.as_ref()
                    && let Some(VarSlot::RowAlias { terms, .. }) = self.vars.get(row_name)
                    && let Some(tb) = terms.get(field)
                    && let Some(p) = tb.present_local
                {
                    return Some((tb.clone(), p));
                }
                None
            }
            HirExpr::Path { name, .. } => {
                if let Some(VarSlot::SingleTermPtr { binding }) = self.vars.get(name)
                    && let Some(p) = binding.present_local
                {
                    return Some((binding.clone(), p));
                }
                None
            }
            _ => None,
        }
    }

    fn lower_primitive_field_ptr(&mut self, receiver: &HirExpr) -> LocalId {
        if let HirExpr::Path { name, .. } = receiver
            && let Some(VarSlot::SingleTermPtr { binding }) = self.vars.get(name).cloned()
            && let Some(ref f) = binding.field_name
        {
            let base_ptr = binding.row_ptr.unwrap_or(binding.col_ptr);
            let (offset, _, _) = self.ctx.resolve_field(&binding.canonical_layout, f);
            return self.alloc_and_emit(
                &format!("ptr_{f}"),
                MirType::MutPtr,
                Inst::FieldPtr {
                    base_ptr,
                    layout_key: binding.canonical_layout,
                    field: f.clone(),
                    offset_bytes: offset,
                },
            );
        }
        if let HirExpr::Field { base, field, .. } = receiver {
            // `p.body.coyote_grace` or `p.actions` or `roll.tl`
            if let HirExpr::Field {
                base: rbase,
                field: talias,
                ..
            } = base.as_ref()
                && let HirExpr::Path { name: rname, .. } = rbase.as_ref()
                && let Some(VarSlot::RowAlias { terms, .. }) = self.vars.get(rname).cloned()
                && let Some(tb) = terms.get(talias)
            {
                let base_ptr = tb.row_ptr.unwrap_or(tb.col_ptr);
                let fpath = match tb.field_name {
                    Some(ref p) => format!("{p}.{field}"),
                    None => field.clone(),
                };
                let (offset, _, _) = self.ctx.resolve_field(&tb.canonical_layout, &fpath);
                return self.alloc_and_emit(
                    &format!("ptr_{field}"),
                    MirType::MutPtr,
                    Inst::FieldPtr {
                        base_ptr,
                        layout_key: tb.canonical_layout.clone(),
                        field: fpath,
                        offset_bytes: offset,
                    },
                );
            }
            if let HirExpr::Path { name, .. } = base.as_ref()
                && let Some(slot) = self.vars.get(name).cloned()
            {
                match slot {
                    VarSlot::RowAlias { terms, .. } => {
                        if let Some(tb) = terms.get(field) {
                            return tb.row_ptr.unwrap_or(tb.col_ptr);
                        }
                    }
                    VarSlot::SingleTermPtr { binding } => {
                        let base_ptr = binding.row_ptr.unwrap_or(binding.col_ptr);
                        let fpath = match binding.field_name {
                            Some(ref p) => format!("{p}.{field}"),
                            None => field.clone(),
                        };
                        let (offset, _, _) =
                            self.ctx.resolve_field(&binding.canonical_layout, &fpath);
                        return self.alloc_and_emit(
                            &format!("ptr_{field}"),
                            MirType::MutPtr,
                            Inst::FieldPtr {
                                base_ptr,
                                layout_key: binding.canonical_layout,
                                field: fpath,
                                offset_bytes: offset,
                            },
                        );
                    }
                    VarSlot::ResPtr {
                        ptr_local,
                        layout_key,
                        ..
                    } => {
                        let (offset, _, _) = self.ctx.resolve_field(&layout_key, field);
                        return self.alloc_and_emit(
                            &format!("ptr_{field}"),
                            MirType::MutPtr,
                            Inst::FieldPtr {
                                base_ptr: ptr_local,
                                layout_key,
                                field: field.clone(),
                                offset_bytes: offset,
                            },
                        );
                    }
                    _ => {}
                }
            }
        }
        self.lower_expr(receiver).0
    }

    fn lower_query_expr(&mut self, hq: &HirQuery) -> (LocalId, MirType) {
        if hq.is_count {
            let qi = self.register_query(hq);
            let Some(ref pred) = hq.where_pred else {
                let id =
                    self.alloc_and_emit("cnt", MirType::U32, Inst::IterCount { query_idx: qi });
                return (id, MirType::U32);
            };
            // Filtered count loop: evaluate `.where(...)` predicate per row cleanly
            let cnt_slot = self.alloc_and_emit(
                "cnt_slot",
                MirType::MutPtr,
                Inst::SlotAlloc { ty: MirType::U32 },
            );
            let zero = self.alloc_and_emit("z", MirType::U32, Inst::ConstInt { value: 0 });
            self.emit_void(Inst::SlotStore {
                slot: cnt_slot,
                val: zero,
            });
            self.lower_query_chunk_loop(qi, hq, &HirPattern::Wildcard, &[], Some((cnt_slot, pred)));
            let final_cnt =
                self.alloc_and_emit("cnt_res", MirType::U32, Inst::SlotLoad { slot: cnt_slot });
            return (final_cnt, MirType::U32);
        }

        if hq.is_point_lookup {
            let (cond, ent_opt, terms) = self.emit_query_one_lookup(hq);
            let _ = (ent_opt, terms);
            return (cond, MirType::Bool);
        }

        let qi = self.register_query(hq);
        let c = self.alloc_and_emit("q_cnt", MirType::U32, Inst::IterCount { query_idx: qi });
        (c, MirType::U32)
    }

    fn emit_query_one_lookup(
        &mut self,
        hq: &HirQuery,
    ) -> (LocalId, Option<LocalId>, HashMap<String, TermAccessBinding>) {
        let qi = self.register_query(hq);
        let ent_l = if let Some(ref on_expr) = hq.on_target {
            self.lower_expr(on_expr).0
        } else {
            self.alloc_and_emit("ent0", MirType::Entity, Inst::ConstInt { value: 0 })
        };

        let mut term_map = HashMap::new();
        let mut present_check: Option<LocalId> = None;
        for (ti, term) in hq.terms.iter().enumerate() {
            let ti = ti as u32;
            let canonical_layout = self.ctx.resolve_canonical(&term.canonical_component);
            let is_opt = matches!(
                term.mode,
                TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
            );
            let ptr_ty = if term.mode.is_mutable() {
                MirType::MutPtr
            } else {
                MirType::Ptr
            };
            let inst = if term.mode.is_mutable() {
                Inst::EntityGetMut {
                    query_idx: qi,
                    term_idx: ti,
                    entity: ent_l,
                    storage_key: term.storage_key.clone(),
                }
            } else {
                Inst::EntityGet {
                    query_idx: qi,
                    term_idx: ti,
                    entity: ent_l,
                    storage_key: term.storage_key.clone(),
                }
            };
            let ptr_l = self.alloc_and_emit(&format!("get_{}", term.alias), ptr_ty, inst);
            let pres_l = if is_opt {
                Some(self.alloc_and_emit(
                    &format!("opt_{}", term.alias),
                    MirType::Bool,
                    Inst::OptionalChunkIsPresent {
                        storage_key: term.storage_key.clone(),
                        slice_ptr: ptr_l,
                    },
                ))
            } else {
                None
            };
            if !is_opt {
                let null_l =
                    self.alloc_and_emit("null_p", MirType::Ptr, Inst::ConstInt { value: 0 });
                let term_chk = self.alloc_and_emit(
                    "has_term",
                    MirType::Bool,
                    Inst::BinOp {
                        op: "!=".to_owned(),
                        lhs: ptr_l,
                        rhs: null_l,
                        allow_fma: false,
                    },
                );
                present_check = Some(match present_check {
                    Some(prev) => self.alloc_and_emit(
                        "has_row",
                        MirType::Bool,
                        Inst::BinOp {
                            op: "&&".to_owned(),
                            lhs: prev,
                            rhs: term_chk,
                            allow_fma: false,
                        },
                    ),
                    None => term_chk,
                });
            }
            term_map.insert(
                term.alias.clone(),
                TermAccessBinding {
                    canonical_layout,
                    field_name: term.field_name.clone(),
                    mode: term.mode,
                    col_ptr: ptr_l,
                    row_ptr: Some(ptr_l),
                    present_local: pres_l,
                    is_up_cascade: false,
                },
            );
        }
        let cond = present_check.unwrap_or_else(|| {
            self.alloc_and_emit("has_row", MirType::Bool, Inst::ConstBool { value: true })
        });
        (cond, Some(ent_l), term_map)
    }

    fn resolve_spatial_resource_name(&self, raw: &str) -> String {
        if let Some(name) = self.ctx.spatial_names.get(raw) {
            return name.clone();
        }
        for rb in &self.func.resources {
            if rb.param_name == raw || rb.resource_name == raw || rb.canonical_name == raw {
                if let Some(name) = self
                    .ctx
                    .spatial_names
                    .get(&rb.resource_name)
                    .or_else(|| self.ctx.spatial_names.get(&rb.canonical_name))
                {
                    return name.clone();
                }
                return rb.resource_name.clone();
            }
        }
        raw.to_owned()
    }

    fn emit_optional_present_check(
        &mut self,
        tb: &TermAccessBinding,
        fallback: LocalId,
    ) -> LocalId {
        if tb.is_up_cascade
            && let Some(rp) = tb.row_ptr
        {
            let null_p =
                self.alloc_and_emit("up_null_p", MirType::Ptr, Inst::ConstInt { value: 0 });
            return self.alloc_and_emit(
                "up_opt_present",
                MirType::Bool,
                Inst::BinOp {
                    op: "!=".to_owned(),
                    lhs: rp,
                    rhs: null_p,
                    allow_fma: false,
                },
            );
        }
        fallback
    }

    fn emit_default_val_for_mir_ty(&mut self, ty: &MirType) -> LocalId {
        match ty {
            MirType::Bool => self.alloc_and_emit(
                "default_bool",
                MirType::Bool,
                Inst::ConstBool { value: false },
            ),
            MirType::F32 | MirType::F64 => {
                self.alloc_and_emit("default_flt", ty.clone(), Inst::ConstFloat { value: 0.0 })
            }
            MirType::Vec2 | MirType::IVec2 | MirType::UVec2 => self.alloc_and_emit(
                "default_v2",
                ty.clone(),
                Inst::ConstVec {
                    dims: 2,
                    values: [0.0; 4],
                },
            ),
            MirType::Vec3 | MirType::IVec3 => self.alloc_and_emit(
                "default_v3",
                ty.clone(),
                Inst::ConstVec {
                    dims: 3,
                    values: [0.0; 4],
                },
            ),
            MirType::Vec4 => self.alloc_and_emit(
                "default_v4",
                ty.clone(),
                Inst::ConstVec {
                    dims: 4,
                    values: [0.0; 4],
                },
            ),
            MirType::I8
            | MirType::I16
            | MirType::I32
            | MirType::I64
            | MirType::U8
            | MirType::U16
            | MirType::U32
            | MirType::U64
            | MirType::Fix32
            | MirType::Fix64
            | MirType::Sym
            | MirType::Entity
            | MirType::Checkpoint
            | MirType::Ptr
            | MirType::MutPtr
            | MirType::QueryIter => {
                self.alloc_and_emit("default_int", ty.clone(), Inst::ConstInt { value: 0 })
            }
            _ => {
                let slot = self.alloc_and_emit(
                    "default_slot",
                    MirType::MutPtr,
                    Inst::SlotAlloc { ty: ty.clone() },
                );
                self.alloc_and_emit("default_val", ty.clone(), Inst::SlotLoad { slot })
            }
        }
    }

    fn emit_guard_on_cond(&mut self, cond: LocalId) {
        let ok_bb = self.new_block("q1_unwrap_ok");
        let fail_bb = self.new_block("q1_unwrap_fail");
        self.terminate(Terminator::Branch {
            cond,
            then_bb: ok_bb,
            else_bb: fail_bb,
        });
        self.switch_to(fail_bb);
        if let Some((_, rb_bb)) = self.atomic_rollback_stack.last().copied() {
            self.terminate(Terminator::Goto(rb_bb));
        } else if self.func.ret_ty == MirType::Unit {
            self.terminate(Terminator::Return(None));
        } else {
            let ret_ty = self.func.ret_ty.clone();
            let fallback = self.emit_default_val_for_mir_ty(&ret_ty);
            self.terminate(Terminator::Return(Some(fallback)));
        }
        self.switch_to(ok_bb);
    }

    fn emit_guarded_query_one_lookup(
        &mut self,
        hq: &HirQuery,
    ) -> (Option<LocalId>, HashMap<String, TermAccessBinding>) {
        let (cond, ent_opt, terms) = self.emit_query_one_lookup(hq);
        self.emit_guard_on_cond(cond);
        (ent_opt, terms)
    }

    fn is_optional_row_expr(&self, expr: &HirExpr) -> bool {
        match expr {
            HirExpr::Query(hq) => hq.is_point_lookup && !hq.is_unwrap,
            HirExpr::Path { name, .. } => {
                matches!(self.vars.get(name), Some(VarSlot::OptionalRow { .. }))
            }
            HirExpr::Call(call)
                if call.receiver.is_none()
                    && matches!(call.callee.as_str(), "Some" | "Option::Some")
                    && call.args.len() == 1 =>
            {
                let inner = &call.args[0];
                matches!(
                    inner,
                    HirExpr::Path { name, .. }
                        if matches!(self.vars.get(name), Some(VarSlot::RowAlias { .. }))
                ) || matches!(inner, HirExpr::Query(hq) if hq.is_point_lookup && hq.is_unwrap)
                    || matches!(inner.ty(), Ty::QueryRow(_))
            }
            HirExpr::Block {
                tail: Some(tail),
                ty,
                ..
            } => {
                matches!(ty, Ty::Option(inner) if matches!(inner.as_ref(), Ty::QueryRow(_)))
                    || self.is_optional_row_expr(tail)
            }
            _ => false,
        }
    }

    fn try_lower_optional_row_binding(
        &mut self,
        expr: &HirExpr,
    ) -> Option<(LocalId, Option<LocalId>, HashMap<String, TermAccessBinding>)> {
        match expr {
            HirExpr::Query(hq) if hq.is_point_lookup && !hq.is_unwrap => {
                Some(self.emit_query_one_lookup(hq))
            }
            HirExpr::Path { name, .. } => {
                if let Some(VarSlot::OptionalRow {
                    cond_local,
                    entity_local,
                    terms,
                }) = self.vars.get(name).cloned()
                {
                    Some((cond_local, entity_local, terms))
                } else {
                    None
                }
            }
            HirExpr::Call(call)
                if call.receiver.is_none()
                    && matches!(call.callee.as_str(), "Some" | "Option::Some")
                    && call.args.len() == 1 =>
            {
                let inner = &call.args[0];
                if let HirExpr::Path { name, .. } = inner
                    && let Some(VarSlot::RowAlias {
                        entity_local,
                        terms,
                    }) = self.vars.get(name).cloned()
                {
                    let ctrue = self.alloc_and_emit(
                        "some_row",
                        MirType::Bool,
                        Inst::ConstBool { value: true },
                    );
                    return Some((ctrue, entity_local, terms));
                }
                if let Some((ent, terms)) = self.lower_point_lookup_unwrap_expr(inner) {
                    let ctrue = self.alloc_and_emit(
                        "some_row",
                        MirType::Bool,
                        Inst::ConstBool { value: true },
                    );
                    return Some((ctrue, ent, terms));
                }
                None
            }
            HirExpr::Block {
                stmts,
                tail: Some(tail),
                ty,
                ..
            } if matches!(ty, Ty::Option(inner) if matches!(inner.as_ref(), Ty::QueryRow(_)))
                || self.is_optional_row_expr(tail) =>
            {
                let saved = self.vars.clone();
                self.lower_stmts(stmts);
                let res = self.try_lower_optional_row_binding(tail);
                self.vars = saved;
                res
            }
            _ => None,
        }
    }

    fn lower_point_lookup_unwrap_expr(
        &mut self,
        expr: &HirExpr,
    ) -> Option<(Option<LocalId>, HashMap<String, TermAccessBinding>)> {
        match expr {
            HirExpr::Query(hq) if hq.is_point_lookup && hq.is_unwrap => {
                Some(self.emit_guarded_query_one_lookup(hq))
            }
            HirExpr::Block {
                stmts,
                tail: Some(tail),
                ..
            } if matches!(
                tail.as_ref(),
                HirExpr::Query(hq) if hq.is_point_lookup && hq.is_unwrap
            ) =>
            {
                let saved = self.vars.clone();
                self.lower_stmts(stmts);
                let HirExpr::Query(hq) = tail.as_ref() else {
                    unreachable!();
                };
                let res = self.emit_guarded_query_one_lookup(hq);
                self.vars = saved;
                Some(res)
            }
            HirExpr::Call(call)
                if matches!(
                    call.callee.as_str(),
                    "unwrap" | "expect" | "Option::unwrap" | "Option::expect"
                ) =>
            {
                let recv = call.receiver.as_deref().or_else(|| call.args.first())?;
                if let Some((cond, ent_opt, terms)) = self.try_lower_optional_row_binding(recv) {
                    self.emit_guard_on_cond(cond);
                    return Some((ent_opt, terms));
                }
                match recv {
                    HirExpr::Query(hq) if hq.is_point_lookup => {
                        Some(self.emit_guarded_query_one_lookup(hq))
                    }
                    HirExpr::Block {
                        stmts,
                        tail: Some(tail),
                        ..
                    } if matches!(tail.as_ref(), HirExpr::Query(hq) if hq.is_point_lookup) => {
                        let saved = self.vars.clone();
                        self.lower_stmts(stmts);
                        let HirExpr::Query(hq) = tail.as_ref() else {
                            unreachable!();
                        };
                        let res = self.emit_guarded_query_one_lookup(hq);
                        self.vars = saved;
                        Some(res)
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn eval_optional_source(&mut self, expr: &HirExpr) -> OptionalEvalResult {
        if let Some((cond, ent, terms)) = self.try_lower_optional_row_binding(expr) {
            return (cond, Some((ent, terms)), None);
        }
        match expr {
            HirExpr::Query(hq) if hq.is_point_lookup => {
                let (cond, ent, terms) = self.emit_query_one_lookup(hq);
                (cond, Some((ent, terms)), None)
            }
            HirExpr::Block {
                stmts,
                tail: Some(tail),
                ..
            } if matches!(tail.as_ref(), HirExpr::Query(hq) if hq.is_point_lookup) => {
                let saved = self.vars.clone();
                self.lower_stmts(stmts);
                let HirExpr::Query(hq) = tail.as_ref() else {
                    unreachable!();
                };
                let (cond, ent, terms) = self.emit_query_one_lookup(hq);
                self.vars = saved;
                (cond, Some((ent, terms)), None)
            }
            _ => {
                if let Some((tb, pres)) = self.resolve_optional_term_binding(expr) {
                    let eff = self.emit_optional_present_check(&tb, pres);
                    return (eff, None, Some(tb));
                }
                let (l, _) = self.lower_expr(expr);
                (l, None, None)
            }
        }
    }

    fn bind_pattern_to_query_row(
        &mut self,
        pat: &HirPattern,
        entity_local: Option<LocalId>,
        terms: HashMap<String, TermAccessBinding>,
    ) {
        let name = extract_some_inner_binding(pat).unwrap_or_else(|| "row".to_owned());
        if terms.len() == 1 {
            // Wait: in `query_one(wallet: &mut FarmerWallet)`, user writes `w.wallet.coins` (RowAlias)!
            // Whereas in `task(on (b: &mut Body))`, user writes `b.hp` (SingleTermPtr).
            // So `query_one` / `query` binds RowAlias!
        }
        self.vars.insert(
            name,
            VarSlot::RowAlias {
                entity_local,
                terms,
            },
        );
    }

    fn bind_pattern_to_single_term(&mut self, pat: &HirPattern, mut binding: TermAccessBinding) {
        binding.present_local = None;
        if let Some(name) = extract_some_inner_binding(pat) {
            self.vars.insert(name, VarSlot::SingleTermPtr { binding });
        }
    }

    fn bind_pattern_to_expr(
        &mut self,
        pat: &HirPattern,
        value: &HirExpr,
        explicit_ty: Option<&Ty>,
    ) {
        if let HirExpr::Block {
            stmts,
            tail: Some(tail),
            ..
        } = value
            && (matches!(pat, HirPattern::Tuple(_))
                || matches!(tail.as_ref(), HirExpr::Tuple { .. }))
        {
            let saved_vars = self.vars.clone();
            self.lower_stmts(stmts);
            let evaluated = self.eval_expr_to_var_slot(tail, explicit_ty);
            self.vars = saved_vars;
            self.bind_pattern_to_var_slot(pat, evaluated);
            return;
        }
        if let HirPattern::Tuple(pat_items) = pat
            && let HirExpr::Tuple { elems, .. } = value
            && pat_items.len() == elems.len()
        {
            let elem_tys: Vec<Ty> = match explicit_ty {
                Some(Ty::Tuple(ts)) => ts.clone(),
                _ => match value.ty() {
                    Ty::Tuple(ts) => ts,
                    _ => Vec::new(),
                },
            };
            let mut evaluated = Vec::with_capacity(elems.len());
            for (i, sub_val) in elems.iter().enumerate() {
                evaluated.push(self.eval_expr_to_var_slot(sub_val, elem_tys.get(i)));
            }
            for (sub_pat, ev) in pat_items.iter().zip(evaluated) {
                self.bind_pattern_to_var_slot(sub_pat, ev);
            }
            return;
        }
        let evaluated = self.eval_expr_to_var_slot(value, explicit_ty);
        self.bind_pattern_to_var_slot(pat, evaluated);
    }

    fn eval_expr_to_var_slot(&mut self, expr: &HirExpr, explicit_ty: Option<&Ty>) -> EvaluatedSlot {
        if let HirExpr::Field { base, field, .. } = expr
            && let Some(EventOrTriggerPayload::Payload(ev)) = self.is_trigger_payload(base, field)
        {
            let pl = self.alloc_and_emit(
                "trg_payload",
                MirType::Ptr,
                Inst::TriggerPayload { event: ev.clone() },
            );
            return EvaluatedSlot::Handle(VarSlot::EventPayloadPtr {
                ptr_local: pl,
                layout_key: self.ctx.resolve_canonical(&ev),
            });
        }
        if let Some((ent_opt, terms)) = self.lower_point_lookup_unwrap_expr(expr) {
            return EvaluatedSlot::Handle(VarSlot::RowAlias {
                entity_local: ent_opt,
                terms,
            });
        }
        if let Some((cond_local, entity_local, terms)) = self.try_lower_optional_row_binding(expr) {
            return EvaluatedSlot::Handle(VarSlot::OptionalRow {
                cond_local,
                entity_local,
                terms,
            });
        }
        if let HirExpr::Path { name: src_name, .. } = expr
            && let Some(slot) = self.vars.get(src_name).cloned()
        {
            match &slot {
                VarSlot::RowAlias { .. }
                | VarSlot::OptionalRow { .. }
                | VarSlot::Tuple(_)
                | VarSlot::EventPayloadPtr { .. } => {
                    return EvaluatedSlot::Handle(slot);
                }
                VarSlot::SingleTermPtr { binding }
                    if binding.field_name.is_none() || binding.present_local.is_some() =>
                {
                    return EvaluatedSlot::Handle(slot);
                }
                _ => {}
            }
        }
        if let HirExpr::Field { base, field, .. } = expr {
            if let Some((tb, _)) = self.resolve_optional_term_binding(expr) {
                return EvaluatedSlot::Handle(VarSlot::SingleTermPtr { binding: tb });
            }
            if let HirExpr::Path { name: row_name, .. } = base.as_ref()
                && let Some(VarSlot::RowAlias { terms, .. }) = self.vars.get(row_name)
                && let Some(tb) = terms.get(field)
                && tb.field_name.is_none()
            {
                return EvaluatedSlot::Handle(VarSlot::SingleTermPtr {
                    binding: tb.clone(),
                });
            }
        }
        if let HirExpr::Call(call) = expr
            && matches!(
                call.callee.as_str(),
                "unwrap" | "expect" | "Option::unwrap" | "Option::expect"
            )
            && let Some(recv) = call.receiver.as_deref().or_else(|| call.args.first())
            && let Some((tb, _)) = self.resolve_optional_term_binding(recv)
            && tb.field_name.is_none()
        {
            return EvaluatedSlot::Handle(VarSlot::SingleTermPtr { binding: tb });
        }
        if let HirExpr::Block {
            stmts,
            tail: Some(tail),
            ..
        } = expr
        {
            let saved_vars = self.vars.clone();
            self.lower_stmts(stmts);
            let res = self.eval_expr_to_var_slot(tail, explicit_ty);
            self.vars = saved_vars;
            return res;
        }
        if let HirExpr::Tuple { elems, .. } = expr {
            let elem_tys: Vec<Ty> = match explicit_ty {
                Some(Ty::Tuple(ts)) => ts.clone(),
                _ => match expr.ty() {
                    Ty::Tuple(ts) => ts,
                    _ => Vec::new(),
                },
            };
            let mut sub_evals = Vec::with_capacity(elems.len());
            let mut has_handle = false;
            for (i, el) in elems.iter().enumerate() {
                let ev = self.eval_expr_to_var_slot(el, elem_tys.get(i));
                if matches!(ev, EvaluatedSlot::Handle(_)) {
                    has_handle = true;
                }
                sub_evals.push(ev);
            }
            if has_handle {
                let slots = sub_evals
                    .into_iter()
                    .map(|ev| match ev {
                        EvaluatedSlot::Handle(s) => s,
                        EvaluatedSlot::Value {
                            local,
                            mir_ty,
                            hir_ty,
                        } => {
                            let resolved_ty = if mir_ty != MirType::Unit {
                                mir_ty
                            } else {
                                mir_ty_from_hir(&hir_ty)
                            };
                            let slot_local = self.alloc_and_emit(
                                "tup_el",
                                MirType::MutPtr,
                                Inst::SlotAlloc {
                                    ty: resolved_ty.clone(),
                                },
                            );
                            self.emit_void(Inst::SlotStore {
                                slot: slot_local,
                                val: local,
                            });
                            VarSlot::Slot {
                                slot_local,
                                ty: resolved_ty,
                            }
                        }
                    })
                    .collect();
                return EvaluatedSlot::Handle(VarSlot::Tuple(slots));
            }
            let mut f = Vec::with_capacity(sub_evals.len());
            let mut ts = Vec::with_capacity(sub_evals.len());
            for (i, ev) in sub_evals.into_iter().enumerate() {
                let EvaluatedSlot::Value { local, mir_ty, .. } = ev else {
                    unreachable!();
                };
                f.push((format!("_{i}"), local));
                ts.push(mir_ty);
            }
            let tty = MirType::Tuple(ts);
            let id = self.alloc_and_emit(
                "tup",
                tty.clone(),
                Inst::StructInit {
                    type_name: "tuple".to_owned(),
                    fields: f,
                },
            );
            return EvaluatedSlot::Value {
                local: id,
                mir_ty: tty,
                hir_ty: explicit_ty.cloned().unwrap_or_else(|| expr.ty()),
            };
        }
        let (local, mir_ty) = if matches!(explicit_ty, Some(Ty::BitSet(_)))
            && let HirExpr::Call(call) = expr
            && call.receiver.is_none()
            && call.callee.rsplit("::").next() == Some("bits")
        {
            self.lower_bits_call(call, explicit_ty)
        } else {
            self.lower_expr(expr)
        };
        let resolved_ty = explicit_ty
            .map(mir_ty_from_hir)
            .filter(|t| *t != MirType::Unit)
            .unwrap_or(mir_ty);
        EvaluatedSlot::Value {
            local,
            mir_ty: resolved_ty,
            hir_ty: explicit_ty.cloned().unwrap_or_else(|| expr.ty()),
        }
    }

    fn bind_pattern_to_var_slot(&mut self, pat: &HirPattern, evaluated: EvaluatedSlot) {
        match (pat, evaluated) {
            (HirPattern::Wildcard, _) => {}
            (HirPattern::Tuple(pat_items), EvaluatedSlot::Handle(VarSlot::Tuple(slots)))
                if pat_items.len() == slots.len() =>
            {
                for (sub_pat, sub_slot) in pat_items.iter().zip(slots) {
                    self.bind_pattern_to_var_slot(sub_pat, EvaluatedSlot::Handle(sub_slot));
                }
            }
            (HirPattern::Binding { name, .. }, EvaluatedSlot::Handle(slot)) => {
                if let VarSlot::Slot { slot_local, ty } = slot {
                    let loaded =
                        self.alloc_and_emit(name, ty.clone(), Inst::SlotLoad { slot: slot_local });
                    let new_slot = self.alloc_and_emit(
                        &format!("slot_{name}"),
                        MirType::MutPtr,
                        Inst::SlotAlloc { ty: ty.clone() },
                    );
                    self.emit_void(Inst::SlotStore {
                        slot: new_slot,
                        val: loaded,
                    });
                    self.vars.insert(
                        name.clone(),
                        VarSlot::Slot {
                            slot_local: new_slot,
                            ty,
                        },
                    );
                } else {
                    self.vars.insert(name.clone(), slot);
                }
            }
            (other_pat, EvaluatedSlot::Handle(VarSlot::Slot { slot_local, ty })) => {
                let loaded =
                    self.alloc_and_emit("tup_v", ty.clone(), Inst::SlotLoad { slot: slot_local });
                self.bind_pattern_value(other_pat, loaded, ty, Ty::Unknown);
            }
            (other_pat, EvaluatedSlot::Handle(_)) => {
                if let Some(name) = extract_some_inner_binding(other_pat) {
                    let u = self.alloc_and_emit(
                        "unit",
                        MirType::Unit,
                        Inst::ConstBool { value: false },
                    );
                    self.bind_pattern_value(
                        &HirPattern::Binding {
                            name,
                            mutable: false,
                        },
                        u,
                        MirType::Unit,
                        Ty::Unit,
                    );
                }
            }
            (
                other_pat,
                EvaluatedSlot::Value {
                    local,
                    mir_ty,
                    hir_ty,
                },
            ) => {
                let resolved_ty = if mir_ty != MirType::Unit {
                    mir_ty
                } else {
                    mir_ty_from_hir(&hir_ty)
                };
                self.bind_pattern_value(other_pat, local, resolved_ty, hir_ty);
            }
        }
    }

    fn resolve_const_bit_arg(&self, expr: &HirExpr) -> Option<i64> {
        match expr {
            HirExpr::IntLit { value, .. } => Some(*value),
            HirExpr::Path { name, .. } => {
                if let Some(MirConstVal::Int(i)) = self.ctx.const_vals.get(name) {
                    Some(*i)
                } else {
                    self.ctx.enum_discriminant(name)
                }
            }
            _ => None,
        }
    }

    fn lower_bits_call(&mut self, call: &HirCall, target_ty: Option<&Ty>) -> (LocalId, MirType) {
        if let Some(Ty::BitSet(bits)) = target_ty {
            let words = (*bits).div_ceil(32).max(1);
            if call
                .args
                .iter()
                .all(|a| self.resolve_const_bit_arg(a).is_some())
            {
                let mut packed = vec![0u32; words];
                for a in &call.args {
                    if let Some(b) = self.resolve_const_bit_arg(a)
                        && b >= 0
                        && (b as usize) < *bits
                    {
                        let bi = b as usize;
                        packed[bi / 32] |= 1u32 << (bi % 32);
                    }
                }
                let mut elem_ids = Vec::with_capacity(words);
                for w in packed {
                    elem_ids.push(self.alloc_and_emit(
                        "bs_w",
                        MirType::U32,
                        Inst::ConstInt {
                            value: i64::from(w),
                        },
                    ));
                }
                let arr_ty = MirType::Array {
                    elem: Box::new(MirType::U32),
                    len: words,
                };
                let arr = self.alloc_and_emit(
                    "bs_arr",
                    arr_ty.clone(),
                    Inst::ArrayInit { elems: elem_ids },
                );
                return (arr, arr_ty);
            }
            let mut word_slots = Vec::with_capacity(words);
            for w in 0..words {
                let slot = self.alloc_and_emit(
                    &format!("bs_w{w}"),
                    MirType::MutPtr,
                    Inst::SlotAlloc { ty: MirType::U32 },
                );
                let z = self.alloc_and_emit("bs_z", MirType::U32, Inst::ConstInt { value: 0 });
                self.emit_void(Inst::SlotStore { slot, val: z });
                word_slots.push(slot);
            }
            let mask31 = self.alloc_and_emit("m31", MirType::U32, Inst::ConstInt { value: 31 });
            let one = self.alloc_and_emit("u1", MirType::U32, Inst::ConstInt { value: 1 });
            for a in &call.args {
                let (b_raw, b_ty) = self.lower_expr(a);
                let b_u32 = self.coerce_local_to_ty(b_raw, b_ty, &MirType::U32);
                let bit_in_word = self.alloc_and_emit(
                    "biw",
                    MirType::U32,
                    Inst::BinOp {
                        op: "&".to_owned(),
                        lhs: b_u32,
                        rhs: mask31,
                        allow_fma: false,
                    },
                );
                let bit_mask = self.alloc_and_emit(
                    "bmask",
                    MirType::U32,
                    Inst::BinOp {
                        op: "<<".to_owned(),
                        lhs: one,
                        rhs: bit_in_word,
                        allow_fma: false,
                    },
                );
                for (w, &slot) in word_slots.iter().enumerate() {
                    let lo = self.alloc_and_emit(
                        "wlo",
                        MirType::U32,
                        Inst::ConstInt {
                            value: (w * 32) as i64,
                        },
                    );
                    let hi = self.alloc_and_emit(
                        "whi",
                        MirType::U32,
                        Inst::ConstInt {
                            value: ((w + 1) * 32) as i64,
                        },
                    );
                    let ge_lo = self.alloc_and_emit(
                        "ge_lo",
                        MirType::Bool,
                        Inst::BinOp {
                            op: ">=".to_owned(),
                            lhs: b_u32,
                            rhs: lo,
                            allow_fma: false,
                        },
                    );
                    let lt_hi = self.alloc_and_emit(
                        "lt_hi",
                        MirType::Bool,
                        Inst::BinOp {
                            op: "<".to_owned(),
                            lhs: b_u32,
                            rhs: hi,
                            allow_fma: false,
                        },
                    );
                    let in_word = self.alloc_and_emit(
                        "in_w",
                        MirType::Bool,
                        Inst::BinOp {
                            op: "&&".to_owned(),
                            lhs: ge_lo,
                            rhs: lt_hi,
                            allow_fma: false,
                        },
                    );
                    let then_bb = self.new_block("bs_set");
                    let skip_bb = self.new_block("bs_skip");
                    self.terminate(Terminator::Branch {
                        cond: in_word,
                        then_bb,
                        else_bb: skip_bb,
                    });
                    self.switch_to(then_bb);
                    let cur = self.alloc_and_emit("w_cur", MirType::U32, Inst::SlotLoad { slot });
                    let nxt = self.alloc_and_emit(
                        "w_nxt",
                        MirType::U32,
                        Inst::BinOp {
                            op: "|".to_owned(),
                            lhs: cur,
                            rhs: bit_mask,
                            allow_fma: false,
                        },
                    );
                    self.emit_void(Inst::SlotStore { slot, val: nxt });
                    self.terminate(Terminator::Goto(skip_bb));
                    self.switch_to(skip_bb);
                }
            }
            let mut elem_ids = Vec::with_capacity(words);
            for slot in word_slots {
                elem_ids.push(self.alloc_and_emit("bs_w", MirType::U32, Inst::SlotLoad { slot }));
            }
            let arr_ty = MirType::Array {
                elem: Box::new(MirType::U32),
                len: words,
            };
            let arr = self.alloc_and_emit(
                "bs_arr",
                arr_ty.clone(),
                Inst::ArrayInit { elems: elem_ids },
            );
            return (arr, arr_ty);
        }

        if call
            .args
            .iter()
            .all(|a| self.resolve_const_bit_arg(a).is_some())
        {
            let mut mask = 0u64;
            for a in &call.args {
                if let Some(b) = self.resolve_const_bit_arg(a)
                    && b >= 0
                    && (b as u32) < 64
                {
                    mask |= 1u64 << (b as u32);
                }
            }
            let id = self.alloc_and_emit(
                "bits_mask",
                MirType::U64,
                Inst::ConstInt { value: mask as i64 },
            );
            return (id, MirType::U64);
        }
        let mask_slot = self.alloc_and_emit(
            "bits_slot",
            MirType::MutPtr,
            Inst::SlotAlloc { ty: MirType::U64 },
        );
        let z = self.alloc_and_emit("bits_z", MirType::U64, Inst::ConstInt { value: 0 });
        self.emit_void(Inst::SlotStore {
            slot: mask_slot,
            val: z,
        });
        let one = self.alloc_and_emit("bits_1", MirType::U64, Inst::ConstInt { value: 1 });
        let lim = self.alloc_and_emit("bits_64", MirType::U64, Inst::ConstInt { value: 64 });
        for a in &call.args {
            let (b_raw, b_ty) = self.lower_expr(a);
            let b_u64 = self.coerce_local_to_ty(b_raw, b_ty, &MirType::U64);
            let lt64 = self.alloc_and_emit(
                "lt64",
                MirType::Bool,
                Inst::BinOp {
                    op: "<".to_owned(),
                    lhs: b_u64,
                    rhs: lim,
                    allow_fma: false,
                },
            );
            let then_bb = self.new_block("bits_set");
            let skip_bb = self.new_block("bits_skip");
            self.terminate(Terminator::Branch {
                cond: lt64,
                then_bb,
                else_bb: skip_bb,
            });
            self.switch_to(then_bb);
            let sh = self.alloc_and_emit(
                "sh",
                MirType::U64,
                Inst::BinOp {
                    op: "<<".to_owned(),
                    lhs: one,
                    rhs: b_u64,
                    allow_fma: false,
                },
            );
            let cur =
                self.alloc_and_emit("m_cur", MirType::U64, Inst::SlotLoad { slot: mask_slot });
            let nxt = self.alloc_and_emit(
                "m_nxt",
                MirType::U64,
                Inst::BinOp {
                    op: "|".to_owned(),
                    lhs: cur,
                    rhs: sh,
                    allow_fma: false,
                },
            );
            self.emit_void(Inst::SlotStore {
                slot: mask_slot,
                val: nxt,
            });
            self.terminate(Terminator::Goto(skip_bb));
            self.switch_to(skip_bb);
        }
        let out = self.alloc_and_emit("bits_out", MirType::U64, Inst::SlotLoad { slot: mask_slot });
        (out, MirType::U64)
    }

    fn bind_pattern_value(
        &mut self,
        pat: &HirPattern,
        val_local: LocalId,
        val_ty: MirType,
        hir_ty: Ty,
    ) {
        match pat {
            HirPattern::Binding { name, .. } => {
                let slot_local = self.alloc_and_emit(
                    &format!("slot_{name}"),
                    MirType::MutPtr,
                    Inst::SlotAlloc { ty: val_ty.clone() },
                );
                self.emit_void(Inst::SlotStore {
                    slot: slot_local,
                    val: val_local,
                });
                let layout_name = match &hir_ty {
                    Ty::Named(n) | Ty::Ref(n) => Some(n.as_str()),
                    Ty::Borrow { inner, .. } | Ty::Option(inner) => match inner.as_ref() {
                        Ty::Named(n) | Ty::Ref(n) => Some(n.as_str()),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(ln) = layout_name {
                    let canon = self.ctx.resolve_canonical(ln);
                    if self.ctx.find_layout(&canon).is_some() {
                        self.slot_layouts.insert(slot_local, canon);
                    }
                }
                self.vars.insert(
                    name.clone(),
                    VarSlot::Slot {
                        slot_local,
                        ty: val_ty,
                    },
                );
            }
            HirPattern::Tuple(items) => {
                let elem_mir = match val_ty {
                    MirType::Tuple(ts) => ts,
                    _ => Vec::new(),
                };
                let elem_hir = match hir_ty {
                    Ty::Tuple(ts) => ts,
                    _ => Vec::new(),
                };
                for (i, sub) in items.iter().enumerate() {
                    let et = elem_mir.get(i).cloned().unwrap_or(MirType::F32);
                    let eh = elem_hir.get(i).cloned().unwrap_or(Ty::Unknown);
                    let f = self.alloc_and_emit(
                        &format!("tup_{i}"),
                        et.clone(),
                        Inst::FieldLoad {
                            base_ptr: val_local,
                            layout_key: "tuple".to_owned(),
                            field: format!("_{i}"),
                            offset_bytes: (i as u32) * 8,
                            field_ty: et.clone(),
                        },
                    );
                    self.bind_pattern_value(sub, f, et, eh);
                }
            }
            HirPattern::TupleStruct { fields, .. } => {
                for f in fields {
                    self.bind_pattern_value(f, val_local, val_ty.clone(), hir_ty.clone());
                }
            }
            HirPattern::Wildcard | HirPattern::Literal(_) | HirPattern::Path(_) => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn lower_if(
        &mut self,
        let_pat: Option<&HirPattern>,
        cond: &HirExpr,
        then_stmts: &[HirStmt],
        then_tail: Option<&HirExpr>,
        else_stmts: &[HirStmt],
        else_tail: Option<&HirExpr>,
        ty: &Ty,
    ) -> (LocalId, MirType) {
        let mut opt_row = None;
        let mut opt_single = None;
        let cond_l = if let Some(_pat) = let_pat {
            let (c, r, s) = self.eval_optional_source(cond);
            opt_row = r;
            opt_single = s;
            c
        } else {
            self.lower_expr(cond).0
        };

        let result_ty = mir_ty_from_hir(ty);
        let needs_result = result_ty != MirType::Unit || then_tail.is_some() || else_tail.is_some();
        let res_slot = if needs_result && result_ty != MirType::Unit {
            Some(self.alloc_and_emit(
                "if_res",
                MirType::MutPtr,
                Inst::SlotAlloc {
                    ty: result_ty.clone(),
                },
            ))
        } else {
            None
        };

        let then_bb = self.new_block("if_then");
        let else_bb = self.new_block("if_else");
        let merge_bb = self.new_block("if_merge");

        self.terminate(Terminator::Branch {
            cond: cond_l,
            then_bb,
            else_bb,
        });

        let saved_vars = self.vars.clone();
        self.switch_to(then_bb);
        if let Some(pat) = let_pat {
            if let Some((ent, terms)) = opt_row {
                self.bind_pattern_to_query_row(pat, ent, terms);
            } else if let Some(tb) = opt_single {
                self.bind_pattern_to_single_term(pat, tb);
            }
        }
        self.lower_stmts(then_stmts);
        if let Some(tt) = then_tail {
            let (tl, _) = self.lower_expr(tt);
            if let Some(slot) = res_slot {
                self.emit_void(Inst::SlotStore { slot, val: tl });
            }
        }
        let then_falls_through = !self.cur_terminated;
        if then_falls_through {
            self.terminate(Terminator::Goto(merge_bb));
        }

        self.vars = saved_vars.clone();
        self.switch_to(else_bb);
        self.lower_stmts(else_stmts);
        if let Some(et) = else_tail {
            let (el, _) = self.lower_expr(et);
            if let Some(slot) = res_slot {
                self.emit_void(Inst::SlotStore { slot, val: el });
            }
        }
        let else_falls_through = !self.cur_terminated;
        if else_falls_through {
            self.terminate(Terminator::Goto(merge_bb));
        }

        self.vars = saved_vars;
        self.switch_to(merge_bb);
        if !then_falls_through && !else_falls_through {
            self.terminate(Terminator::Return(None));
        }
        if let Some(slot) = res_slot {
            let out = self.alloc_and_emit("if_val", result_ty.clone(), Inst::SlotLoad { slot });
            (out, result_ty)
        } else {
            let u = self.alloc_and_emit("unit", MirType::Unit, Inst::ConstBool { value: false });
            (u, MirType::Unit)
        }
    }

    fn lower_match(&mut self, hm: &HirMatch) -> (LocalId, MirType) {
        let is_opt_match = self.is_optional_row_expr(&hm.scrutinee)
            || matches!(
                hm.scrutinee.as_ref(),
                HirExpr::Query(hq) if hq.is_point_lookup
            )
            || matches!(
                hm.scrutinee.as_ref(),
                HirExpr::Block { tail: Some(t), .. } if matches!(t.as_ref(), HirExpr::Query(hq) if hq.is_point_lookup)
            )
            || self.resolve_optional_term_binding(&hm.scrutinee).is_some();
        if is_opt_match {
            let (eff, opt_row, opt_single) = self.eval_optional_source(&hm.scrutinee);
            let res_ty = mir_ty_from_hir(&hm.ty);
            let res_slot = (res_ty != MirType::Unit).then(|| {
                self.alloc_and_emit(
                    "match_res",
                    MirType::MutPtr,
                    Inst::SlotAlloc { ty: res_ty.clone() },
                )
            });
            let merge_bb = self.new_block("match_merge");
            for (idx, arm) in hm.arms.iter().enumerate() {
                let arm_bb = self.new_block(&format!("match_arm_{idx}"));
                let next_bb = if idx + 1 == hm.arms.len() {
                    merge_bb
                } else {
                    self.new_block(&format!("match_next_{idx}"))
                };
                let saved_vars = self.vars.clone();
                let pat_cond = match &arm.pattern {
                    HirPattern::TupleStruct { path, .. }
                        if path == "Some" || path.ends_with("::Some") =>
                    {
                        eff
                    }
                    HirPattern::Path(p) if p == "None" || p.ends_with("::None") => self
                        .alloc_and_emit(
                            "opt_is_none",
                            MirType::Bool,
                            Inst::UnOp {
                                op: "!".to_owned(),
                                val: eff,
                            },
                        ),
                    HirPattern::Binding { name, .. } if name == "None" => self.alloc_and_emit(
                        "opt_is_none",
                        MirType::Bool,
                        Inst::UnOp {
                            op: "!".to_owned(),
                            val: eff,
                        },
                    ),
                    HirPattern::Wildcard | HirPattern::Binding { .. } => self.alloc_and_emit(
                        "p_true",
                        MirType::Bool,
                        Inst::ConstBool { value: true },
                    ),
                    _ => self.eval_pattern_cond(&arm.pattern, eff),
                };
                let bind_arm_opt = |this: &mut Self| {
                    if matches!(arm.pattern, HirPattern::TupleStruct { ref path, .. } if path == "Some" || path.ends_with("::Some"))
                    {
                        if let Some((ent, ref terms)) = opt_row {
                            this.bind_pattern_to_query_row(&arm.pattern, ent, terms.clone());
                        } else if let Some(ref tb) = opt_single {
                            this.bind_pattern_to_single_term(&arm.pattern, tb.clone());
                        }
                    } else if let HirPattern::Binding { ref name, .. } = arm.pattern
                        && name != "None"
                    {
                        if let Some((ent, ref terms)) = opt_row {
                            this.vars.insert(
                                name.clone(),
                                VarSlot::RowAlias {
                                    entity_local: ent,
                                    terms: terms.clone(),
                                },
                            );
                        } else if let Some(ref tb) = opt_single {
                            let mut tb = tb.clone();
                            tb.present_local = None;
                            this.vars
                                .insert(name.clone(), VarSlot::SingleTermPtr { binding: tb });
                        }
                    }
                };
                let cond = if let Some(ref g) = arm.guard {
                    let g_bb = self.new_block(&format!("match_guard_{idx}"));
                    self.terminate(Terminator::Branch {
                        cond: pat_cond,
                        then_bb: g_bb,
                        else_bb: next_bb,
                    });
                    self.switch_to(g_bb);
                    bind_arm_opt(self);
                    self.lower_expr(g).0
                } else {
                    pat_cond
                };
                self.terminate(Terminator::Branch {
                    cond,
                    then_bb: arm_bb,
                    else_bb: next_bb,
                });
                self.vars = saved_vars.clone();
                self.switch_to(arm_bb);
                bind_arm_opt(self);
                let (aval, _) = self.lower_expr(&arm.body);
                if let Some(slot) = res_slot {
                    self.emit_void(Inst::SlotStore { slot, val: aval });
                }
                if !self.cur_terminated {
                    self.terminate(Terminator::Goto(merge_bb));
                }
                self.vars = saved_vars;
                self.switch_to(next_bb);
            }
            if !self.cur_terminated && self.cur_bb != merge_bb {
                self.terminate(Terminator::Goto(merge_bb));
            }
            self.switch_to(merge_bb);
            return if let Some(slot) = res_slot {
                let out = self.alloc_and_emit("match_val", res_ty.clone(), Inst::SlotLoad { slot });
                (out, res_ty)
            } else {
                let u =
                    self.alloc_and_emit("unit", MirType::Unit, Inst::ConstBool { value: false });
                (u, MirType::Unit)
            };
        }

        let (scrut_l, scrut_ty) = self.lower_expr(&hm.scrutinee);
        let res_ty = mir_ty_from_hir(&hm.ty);
        let res_slot = (res_ty != MirType::Unit).then(|| {
            self.alloc_and_emit(
                "match_res",
                MirType::MutPtr,
                Inst::SlotAlloc { ty: res_ty.clone() },
            )
        });
        let merge_bb = self.new_block("match_merge");

        // Try emitting `Terminator::Switch` if arms are pure constant integer/enum discriminants
        let can_switch = !hm.arms.is_empty()
            && hm.arms.iter().all(|a| {
                a.guard.is_none() && self.arm_const_disc(&a.pattern).is_some()
                    || matches!(a.pattern, HirPattern::Wildcard | HirPattern::Binding { .. })
                        && a.guard.is_none()
            });

        if can_switch {
            let dispatch_bb = self.cur_bb;
            let mut cases = Vec::new();
            let mut default_bb = None;
            let saved_vars = self.vars.clone();
            for (idx, arm) in hm.arms.iter().enumerate() {
                let arm_bb = self.new_block(&format!("match_arm_{idx}"));
                if let Some(disc) = self.arm_const_disc(&arm.pattern) {
                    cases.push((disc as u32, arm_bb));
                } else if default_bb.is_none() {
                    default_bb = Some(arm_bb);
                }
                self.vars = saved_vars.clone();
                self.switch_to(arm_bb);
                self.bind_pattern_value(&arm.pattern, scrut_l, scrut_ty.clone(), hm.scrutinee.ty());
                let (aval, _) = self.lower_expr(&arm.body);
                if let Some(slot) = res_slot {
                    self.emit_void(Inst::SlotStore { slot, val: aval });
                }
                if !self.cur_terminated {
                    self.terminate(Terminator::Goto(merge_bb));
                }
            }
            self.vars = saved_vars;
            let def = default_bb.unwrap_or(merge_bb);
            self.switch_to(dispatch_bb);
            self.terminate(Terminator::Switch {
                scrutinee: scrut_l,
                cases,
                default_bb: def,
            });
            self.switch_to(merge_bb);
        } else {
            for (idx, arm) in hm.arms.iter().enumerate() {
                let arm_bb = self.new_block(&format!("match_arm_{idx}"));
                let next_bb = if idx + 1 == hm.arms.len() {
                    merge_bb
                } else {
                    self.new_block(&format!("match_next_{idx}"))
                };
                let saved_vars = self.vars.clone();
                let pat_cond = self.eval_pattern_cond(&arm.pattern, scrut_l);
                let cond = if let Some(ref g) = arm.guard {
                    let g_bb = self.new_block(&format!("match_guard_{idx}"));
                    self.terminate(Terminator::Branch {
                        cond: pat_cond,
                        then_bb: g_bb,
                        else_bb: next_bb,
                    });
                    self.switch_to(g_bb);
                    self.bind_pattern_value(
                        &arm.pattern,
                        scrut_l,
                        scrut_ty.clone(),
                        hm.scrutinee.ty(),
                    );
                    self.lower_expr(g).0
                } else {
                    pat_cond
                };
                self.terminate(Terminator::Branch {
                    cond,
                    then_bb: arm_bb,
                    else_bb: next_bb,
                });
                self.vars = saved_vars.clone();
                self.switch_to(arm_bb);
                self.bind_pattern_value(&arm.pattern, scrut_l, scrut_ty.clone(), hm.scrutinee.ty());
                let (aval, _) = self.lower_expr(&arm.body);
                if let Some(slot) = res_slot {
                    self.emit_void(Inst::SlotStore { slot, val: aval });
                }
                if !self.cur_terminated {
                    self.terminate(Terminator::Goto(merge_bb));
                }
                self.vars = saved_vars;
                self.switch_to(next_bb);
            }
            if !self.cur_terminated && self.cur_bb != merge_bb {
                self.terminate(Terminator::Goto(merge_bb));
            }
            self.switch_to(merge_bb);
        }

        if let Some(slot) = res_slot {
            let out = self.alloc_and_emit("match_val", res_ty.clone(), Inst::SlotLoad { slot });
            (out, res_ty)
        } else {
            let u = self.alloc_and_emit("unit", MirType::Unit, Inst::ConstBool { value: false });
            (u, MirType::Unit)
        }
    }

    fn arm_const_disc(&self, pat: &HirPattern) -> Option<i64> {
        match pat {
            HirPattern::Literal(e) => match e.as_ref() {
                HirExpr::IntLit { value, .. } => Some(*value),
                _ => None,
            },
            HirPattern::Path(p) => self.ctx.enum_discriminant(p),
            _ => None,
        }
    }

    fn eval_pattern_cond(&mut self, pat: &HirPattern, scrut: LocalId) -> LocalId {
        match pat {
            HirPattern::Wildcard | HirPattern::Binding { .. } => {
                self.alloc_and_emit("p_true", MirType::Bool, Inst::ConstBool { value: true })
            }
            HirPattern::Literal(e) => {
                let (lit_l, _) = self.lower_expr(e);
                self.alloc_and_emit(
                    "p_eq",
                    MirType::Bool,
                    Inst::BinOp {
                        op: "==".to_owned(),
                        lhs: scrut,
                        rhs: lit_l,
                        allow_fma: false,
                    },
                )
            }
            HirPattern::Path(p) => {
                let val_l = if let Some(d) = self.ctx.enum_discriminant(p) {
                    self.alloc_and_emit("disc", MirType::I32, Inst::ConstInt { value: d })
                } else {
                    self.alloc_and_emit(p, MirType::Sym, Inst::InternSymbol { symbol: p.clone() })
                };
                self.alloc_and_emit(
                    "p_eq",
                    MirType::Bool,
                    Inst::BinOp {
                        op: "==".to_owned(),
                        lhs: scrut,
                        rhs: val_l,
                        allow_fma: false,
                    },
                )
            }
            HirPattern::TupleStruct { .. } | HirPattern::Tuple(_) => {
                self.alloc_and_emit("p_ts", MirType::Bool, Inst::ConstBool { value: true })
            }
        }
    }

    fn lower_for(&mut self, hf: &HirFor) -> (LocalId, MirType) {
        match &hf.iter {
            HirForIter::Query(hq) => {
                let qi = self.register_query(hq);
                if !hf.reduce.is_empty() {
                    return self.lower_reduce_query_loop(qi, hq, &hf.binding, &hf.reduce);
                }
                self.lower_query_chunk_loop(qi, hq, &hf.binding, &hf.body, None);
                let u =
                    self.alloc_and_emit("unit", MirType::Unit, Inst::ConstBool { value: false });
                (u, MirType::Unit)
            }
            HirForIter::Range {
                start,
                end,
                inclusive,
            } => {
                let (s_l, s_ty) = self.lower_expr(start);
                let (e_l, _) = self.lower_expr(end);
                let idx_ty = if s_ty == MirType::Unit {
                    MirType::I64
                } else {
                    s_ty
                };
                let idx_slot = self.alloc_and_emit(
                    "for_idx_slot",
                    MirType::MutPtr,
                    Inst::SlotAlloc { ty: idx_ty.clone() },
                );
                self.emit_void(Inst::SlotStore {
                    slot: idx_slot,
                    val: s_l,
                });
                let hdr_bb = self.new_block("for_range_hdr");
                let body_bb = self.new_block("for_range_body");
                let inc_bb = self.new_block("for_range_inc");
                let exit_bb = self.new_block("for_range_exit");
                self.terminate(Terminator::Goto(hdr_bb));

                self.switch_to(hdr_bb);
                let cur_i =
                    self.alloc_and_emit("i_cur", idx_ty.clone(), Inst::SlotLoad { slot: idx_slot });
                let cmp_op = if *inclusive { "<=" } else { "<" };
                let cond = self.alloc_and_emit(
                    "range_cond",
                    MirType::Bool,
                    Inst::BinOp {
                        op: cmp_op.to_owned(),
                        lhs: cur_i,
                        rhs: e_l,
                        allow_fma: false,
                    },
                );
                self.terminate(Terminator::Branch {
                    cond,
                    then_bb: body_bb,
                    else_bb: exit_bb,
                });

                self.switch_to(body_bb);
                let saved_vars = self.vars.clone();
                self.bind_pattern_value(&hf.binding, cur_i, idx_ty.clone(), start.ty());
                self.loop_stack.push(LoopTarget {
                    continue_bb: inc_bb,
                    break_bb: exit_bb,
                });
                self.lower_stmts(&hf.body);
                self.loop_stack.pop();
                self.vars = saved_vars;
                if !self.cur_terminated {
                    self.terminate(Terminator::Goto(inc_bb));
                }

                self.switch_to(inc_bb);
                let one = self.alloc_and_emit("one", idx_ty.clone(), Inst::ConstInt { value: 1 });
                let cur_for_inc = self.alloc_and_emit(
                    "i_pre_inc",
                    idx_ty.clone(),
                    Inst::SlotLoad { slot: idx_slot },
                );
                let next_i = self.alloc_and_emit(
                    "i_next",
                    idx_ty,
                    Inst::BinOp {
                        op: "+".to_owned(),
                        lhs: cur_for_inc,
                        rhs: one,
                        allow_fma: false,
                    },
                );
                self.emit_void(Inst::SlotStore {
                    slot: idx_slot,
                    val: next_i,
                });
                self.terminate(Terminator::Goto(hdr_bb));

                self.switch_to(exit_bb);
                let u =
                    self.alloc_and_emit("unit", MirType::Unit, Inst::ConstBool { value: false });
                (u, MirType::Unit)
            }
            HirForIter::SpatialDisc {
                grid,
                center,
                radius,
            } => {
                let grid_name = self.resolve_spatial_resource_name(grid);
                let c_l = self.lower_expr(center).0;
                let r_l = self.lower_expr(radius).0;
                let sp_l = self.alloc_and_emit(
                    "disc_iter",
                    MirType::QueryIter,
                    Inst::SpatialQueryDisc {
                        grid_name,
                        center: c_l,
                        radius: r_l,
                    },
                );
                self.lower_spatial_candidate_loop(sp_l, &hf.binding, &hf.body)
            }
            HirForIter::SpatialSegmentAt {
                history,
                tick,
                p0,
                p1,
            } => {
                let history_name = self.resolve_spatial_resource_name(history);
                let tick_l = self.lower_expr(tick).0;
                let s_l = self.lower_expr(p0).0;
                let e_l = self.lower_expr(p1).0;
                let r_l =
                    self.alloc_and_emit("r_def", MirType::F32, Inst::ConstFloat { value: 0.5 });
                let sp_l = self.alloc_and_emit(
                    "seg_iter",
                    MirType::QueryIter,
                    Inst::SpatialQuerySegmentAt {
                        history_name,
                        start: s_l,
                        end: e_l,
                        radius: r_l,
                        tick_offset: tick_l,
                    },
                );
                self.lower_spatial_candidate_loop(sp_l, &hf.binding, &hf.body)
            }
            HirForIter::Expr(other) => {
                let (it_l, it_ty) = self.lower_expr(other);
                if it_ty == MirType::QueryIter {
                    return self.lower_spatial_candidate_loop(it_l, &hf.binding, &hf.body);
                }
                let hdr_bb = self.new_block("iter_body");
                let exit_bb = self.new_block("iter_exit");
                self.terminate(Terminator::Goto(hdr_bb));
                self.switch_to(hdr_bb);
                let saved_vars = self.vars.clone();
                self.loop_stack.push(LoopTarget {
                    continue_bb: hdr_bb,
                    break_bb: exit_bb,
                });
                self.lower_stmts(&hf.body);
                self.loop_stack.pop();
                self.vars = saved_vars;
                self.terminate(Terminator::Goto(exit_bb));
                self.switch_to(exit_bb);
                let u =
                    self.alloc_and_emit("unit", MirType::Unit, Inst::ConstBool { value: false });
                (u, MirType::Unit)
            }
        }
    }

    fn lower_spatial_candidate_loop(
        &mut self,
        sp_l: LocalId,
        binding: &HirPattern,
        body: &[HirStmt],
    ) -> (LocalId, MirType) {
        let max_l = self.alloc_and_emit("sp_lim", MirType::U32, Inst::ConstInt { value: 64 });
        let idx_slot = self.alloc_and_emit(
            "sp_idx",
            MirType::MutPtr,
            Inst::SlotAlloc { ty: MirType::U32 },
        );
        let zero = self.alloc_and_emit("z", MirType::U32, Inst::ConstInt { value: 0 });
        self.emit_void(Inst::SlotStore {
            slot: idx_slot,
            val: zero,
        });
        let hdr_bb = self.new_block("spatial_hdr");
        let body_bb = self.new_block("spatial_body");
        let inc_bb = self.new_block("spatial_inc");
        let exit_bb = self.new_block("spatial_exit");
        self.terminate(Terminator::Goto(hdr_bb));

        self.switch_to(hdr_bb);
        let i_l = self.alloc_and_emit("sp_i", MirType::U32, Inst::SlotLoad { slot: idx_slot });
        let cond = self.alloc_and_emit(
            "sp_cond",
            MirType::Bool,
            Inst::BinOp {
                op: "<".to_owned(),
                lhs: i_l,
                rhs: max_l,
                allow_fma: false,
            },
        );
        self.terminate(Terminator::Branch {
            cond,
            then_bb: body_bb,
            else_bb: exit_bb,
        });

        self.switch_to(body_bb);
        let ent_l = self.alloc_and_emit(
            "cand_ent",
            MirType::Entity,
            Inst::EntityAtRow {
                entities_ptr: sp_l,
                row_idx: i_l,
            },
        );
        let null_ent =
            self.alloc_and_emit("null_ent", MirType::Entity, Inst::ConstInt { value: 0 });
        let has_ent = self.alloc_and_emit(
            "has_cand_ent",
            MirType::Bool,
            Inst::BinOp {
                op: "!=".to_owned(),
                lhs: ent_l,
                rhs: null_ent,
                allow_fma: false,
            },
        );
        let hit_body_bb = self.new_block("spatial_hit");
        self.terminate(Terminator::Branch {
            cond: has_ent,
            then_bb: hit_body_bb,
            else_bb: exit_bb,
        });

        self.switch_to(hit_body_bb);
        let saved_vars = self.vars.clone();
        if let HirPattern::Binding { name, .. } = binding {
            self.vars.insert(
                name.clone(),
                VarSlot::SpatialCandidate {
                    entity: ent_l,
                    pos: sp_l,
                },
            );
        }
        self.loop_stack.push(LoopTarget {
            continue_bb: inc_bb,
            break_bb: exit_bb,
        });
        self.lower_stmts(body);
        self.loop_stack.pop();
        self.vars = saved_vars;
        if !self.cur_terminated {
            self.terminate(Terminator::Goto(inc_bb));
        }

        self.switch_to(inc_bb);
        let one = self.alloc_and_emit("one", MirType::U32, Inst::ConstInt { value: 1 });
        let cur = self.alloc_and_emit("sp_i2", MirType::U32, Inst::SlotLoad { slot: idx_slot });
        let nxt = self.alloc_and_emit(
            "sp_nxt",
            MirType::U32,
            Inst::BinOp {
                op: "+".to_owned(),
                lhs: cur,
                rhs: one,
                allow_fma: false,
            },
        );
        self.emit_void(Inst::SlotStore {
            slot: idx_slot,
            val: nxt,
        });
        self.terminate(Terminator::Goto(hdr_bb));

        self.switch_to(exit_bb);
        let u = self.alloc_and_emit("unit", MirType::Unit, Inst::ConstBool { value: false });
        (u, MirType::Unit)
    }

    fn lower_query_chunk_loop(
        &mut self,
        qi: u32,
        hq: &HirQuery,
        pat: &HirPattern,
        body: &[HirStmt],
        filtered_count: Option<(LocalId, &HirExpr)>,
    ) {
        if let Some(chunk) = self.func.par_chunk {
            let has_mut = hq.terms.iter().any(|t| t.mode.is_mutable());
            if self.func.par_read_only || !has_mut {
                self.emit_void(Inst::ParForEachChunkReadonly {
                    query_idx: qi,
                    chunk_size: chunk,
                    deterministic_order: self.ctx.is_deterministic || self.func.is_deterministic,
                });
            } else {
                self.emit_void(Inst::ParForEachChunk {
                    query_idx: qi,
                    chunk_size: chunk,
                });
            }
        }

        let chunk_hdr = self.new_block(&format!("q{qi}_chunk_hdr"));
        let chunk_body = self.new_block(&format!("q{qi}_chunk_body"));
        let row_hdr = self.new_block(&format!("q{qi}_row_hdr"));
        let row_body = self.new_block(&format!("q{qi}_row_body"));
        let row_inc = self.new_block(&format!("q{qi}_row_inc"));
        let chunk_exit = self.new_block(&format!("q{qi}_chunk_exit"));

        self.terminate(Terminator::Goto(chunk_hdr));
        self.switch_to(chunk_hdr);

        let has_chunk = self.alloc_and_emit(
            "has_chunk",
            MirType::Bool,
            Inst::IterNextChunk { query_idx: qi },
        );
        self.terminate(Terminator::Branch {
            cond: has_chunk,
            then_bb: chunk_body,
            else_bb: chunk_exit,
        });

        self.switch_to(chunk_body);
        let chunk_len = self.alloc_and_emit(
            "chunk_len",
            MirType::U32,
            Inst::IterChunkLen { query_idx: qi },
        );
        let entities_ptr = self.alloc_and_emit(
            "entities",
            MirType::Ptr,
            Inst::IterEntities { query_idx: qi },
        );

        // Column borrows hoisted cleanly at chunk header
        let mut col_bindings = Vec::new();
        for (ti, term) in hq.terms.iter().enumerate() {
            let ti = ti as u32;
            if matches!(term.mode, TermAccessMode::With | TermAccessMode::Without) {
                continue;
            }
            let canonical_layout = self.ctx.resolve_canonical(&term.canonical_component);
            let is_opt = matches!(
                term.mode,
                TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
            );
            let ptr_ty = if term.mode.is_mutable() {
                MirType::MutPtr
            } else {
                MirType::Ptr
            };
            let inst = if term.is_sparse {
                if term.mode.is_mutable() {
                    Inst::IterColRowsWrite {
                        query_idx: qi,
                        term_idx: ti,
                        storage_key: term.storage_key.clone(),
                    }
                } else {
                    Inst::IterColRowsRead {
                        query_idx: qi,
                        term_idx: ti,
                        storage_key: term.storage_key.clone(),
                    }
                }
            } else if term.mode.is_mutable() {
                Inst::IterColWrite {
                    query_idx: qi,
                    term_idx: ti,
                    storage_key: term.storage_key.clone(),
                }
            } else {
                Inst::IterColRead {
                    query_idx: qi,
                    term_idx: ti,
                    storage_key: term.storage_key.clone(),
                }
            };
            let col_ptr = self.alloc_and_emit(&format!("col_{}", term.alias), ptr_ty, inst);
            let present_local = if is_opt {
                Some(self.alloc_and_emit(
                    &format!("opt_{}_present", term.alias),
                    MirType::Bool,
                    Inst::OptionalChunkIsPresent {
                        storage_key: term.storage_key.clone(),
                        slice_ptr: col_ptr,
                    },
                ))
            } else {
                None
            };
            col_bindings.push((ti, term, canonical_layout, col_ptr, present_local));
        }

        let row_idx_slot = self.alloc_and_emit(
            "row_idx_slot",
            MirType::MutPtr,
            Inst::SlotAlloc { ty: MirType::U32 },
        );
        let zero = self.alloc_and_emit("r0", MirType::U32, Inst::ConstInt { value: 0 });
        self.emit_void(Inst::SlotStore {
            slot: row_idx_slot,
            val: zero,
        });
        self.terminate(Terminator::Goto(row_hdr));

        // Row header
        self.switch_to(row_hdr);
        let row_idx = self.alloc_and_emit(
            "row_idx",
            MirType::U32,
            Inst::SlotLoad { slot: row_idx_slot },
        );
        let rcond = self.alloc_and_emit(
            "row_cond",
            MirType::Bool,
            Inst::BinOp {
                op: "<".to_owned(),
                lhs: row_idx,
                rhs: chunk_len,
                allow_fma: false,
            },
        );
        self.terminate(Terminator::Branch {
            cond: rcond,
            then_bb: row_body,
            else_bb: chunk_hdr,
        });

        // Row body
        self.switch_to(row_body);
        let row_ent = self.alloc_and_emit(
            "row_ent",
            MirType::Entity,
            Inst::EntityAtRow {
                entities_ptr,
                row_idx,
            },
        );
        let has_optional_term = hq.terms.iter().any(|t| {
            matches!(
                t.mode,
                TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
            )
        });
        let mut terms_map = HashMap::new();
        for (ti, term, canonical_layout, col_ptr, present_local) in col_bindings {
            let stride = self
                .ctx
                .find_layout(&canonical_layout)
                .map_or(16, |l| l.size as u32);
            let rptr_ty = if term.mode.is_mutable() {
                MirType::MutPtr
            } else {
                MirType::Ptr
            };
            let is_up_cascade = hq.up_relation.is_some() && present_local.is_some();
            let row_ptr = if let Some(ref rel) = hq.up_relation {
                if let Some(p_local) = present_local {
                    let slot = self.alloc_and_emit(
                        &format!("up_slot_{}", term.alias),
                        MirType::MutPtr,
                        Inst::SlotAlloc {
                            ty: rptr_ty.clone(),
                        },
                    );
                    let loc_bb = self.new_block(&format!("q{qi}_t{ti}_local"));
                    let up_bb = self.new_block(&format!("q{qi}_t{ti}_up"));
                    let join_bb = self.new_block(&format!("q{qi}_t{ti}_join"));
                    self.terminate(Terminator::Branch {
                        cond: p_local,
                        then_bb: loc_bb,
                        else_bb: up_bb,
                    });
                    self.switch_to(loc_bb);
                    let lr = self.alloc_and_emit(
                        &format!("row_{}", term.alias),
                        rptr_ty.clone(),
                        Inst::RowPtr {
                            col_ptr,
                            row_idx,
                            stride_bytes: stride,
                            is_sparse: term.is_sparse,
                        },
                    );
                    self.emit_void(Inst::SlotStore { slot, val: lr });
                    self.terminate(Terminator::Goto(join_bb));

                    self.switch_to(up_bb);
                    let ur = self.alloc_and_emit(
                        &format!("up_{}", term.alias),
                        rptr_ty.clone(),
                        Inst::IterUpCascade {
                            query_idx: qi,
                            relation: rel.clone(),
                            entity: row_ent,
                            term_idx: ti,
                        },
                    );
                    self.emit_void(Inst::SlotStore { slot, val: ur });
                    self.terminate(Terminator::Goto(join_bb));

                    self.switch_to(join_bb);
                    self.alloc_and_emit(
                        &format!("eff_row_{}", term.alias),
                        rptr_ty,
                        Inst::SlotLoad { slot },
                    )
                } else if !has_optional_term {
                    self.alloc_and_emit(
                        &format!("up_{}", term.alias),
                        rptr_ty,
                        Inst::IterUpCascade {
                            query_idx: qi,
                            relation: rel.clone(),
                            entity: row_ent,
                            term_idx: ti,
                        },
                    )
                } else {
                    self.alloc_and_emit(
                        &format!("row_{}", term.alias),
                        rptr_ty,
                        Inst::RowPtr {
                            col_ptr,
                            row_idx,
                            stride_bytes: stride,
                            is_sparse: term.is_sparse,
                        },
                    )
                }
            } else {
                self.alloc_and_emit(
                    &format!("row_{}", term.alias),
                    rptr_ty,
                    Inst::RowPtr {
                        col_ptr,
                        row_idx,
                        stride_bytes: stride,
                        is_sparse: term.is_sparse,
                    },
                )
            };
            terms_map.insert(
                term.alias.clone(),
                TermAccessBinding {
                    canonical_layout,
                    field_name: term.field_name.clone(),
                    mode: term.mode,
                    col_ptr,
                    row_ptr: Some(row_ptr),
                    present_local,
                    is_up_cascade,
                },
            );
        }

        let saved_vars = self.vars.clone();
        if let HirPattern::Binding { name, .. } = pat {
            if hq.terms.len() == 1
                && let Some((alias, tb)) = terms_map.iter().next()
                && (tb.field_name.is_some()
                    || matches!(
                        tb.mode,
                        TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                    ))
                && alias == name
            {
                // Single projected term (`c: &Pos.cell`) or single optional term (`sh: Option<&Shield>`)
                self.vars.insert(
                    name.clone(),
                    VarSlot::SingleTermPtr {
                        binding: tb.clone(),
                    },
                );
            } else {
                self.vars.insert(
                    name.clone(),
                    VarSlot::RowAlias {
                        entity_local: Some(row_ent),
                        terms: terms_map.clone(),
                    },
                );
            }
        }
        // Also bind bare projected aliases inside `.where(c == req.cell)` cleanly
        for (alias, tb) in &terms_map {
            self.vars
                .entry(alias.clone())
                .or_insert_with(|| VarSlot::SingleTermPtr {
                    binding: tb.clone(),
                });
        }

        self.loop_stack.push(LoopTarget {
            continue_bb: row_inc,
            break_bb: chunk_exit,
        });

        if let Some((cnt_slot, pred)) = filtered_count {
            let (pl, _) = self.lower_expr(pred);
            let match_bb = self.new_block(&format!("q{qi}_where_hit"));
            self.terminate(Terminator::Branch {
                cond: pl,
                then_bb: match_bb,
                else_bb: row_inc,
            });
            self.switch_to(match_bb);
            let one = self.alloc_and_emit("one", MirType::U32, Inst::ConstInt { value: 1 });
            let prev =
                self.alloc_and_emit("c_prev", MirType::U32, Inst::SlotLoad { slot: cnt_slot });
            let nxt = self.alloc_and_emit(
                "c_nxt",
                MirType::U32,
                Inst::BinOp {
                    op: "+".to_owned(),
                    lhs: prev,
                    rhs: one,
                    allow_fma: false,
                },
            );
            self.emit_void(Inst::SlotStore {
                slot: cnt_slot,
                val: nxt,
            });
        } else {
            self.lower_stmts(body);
        }
        self.loop_stack.pop();
        if !self.cur_terminated {
            self.terminate(Terminator::Goto(row_inc));
        }

        self.switch_to(row_inc);
        let r_prev = self.alloc_and_emit(
            "r_prev",
            MirType::U32,
            Inst::SlotLoad { slot: row_idx_slot },
        );
        let one = self.alloc_and_emit("r1", MirType::U32, Inst::ConstInt { value: 1 });
        let r_nxt = self.alloc_and_emit(
            "r_nxt",
            MirType::U32,
            Inst::BinOp {
                op: "+".to_owned(),
                lhs: r_prev,
                rhs: one,
                allow_fma: false,
            },
        );
        self.emit_void(Inst::SlotStore {
            slot: row_idx_slot,
            val: r_nxt,
        });
        self.terminate(Terminator::Goto(row_hdr));

        self.switch_to(chunk_exit);
        self.vars = saved_vars;
    }

    fn lower_reduce_query_loop(
        &mut self,
        qi: u32,
        hq: &HirQuery,
        pat: &HirPattern,
        reduce: &[HirReduceEntry],
    ) -> (LocalId, MirType) {
        let mut acc_slots = Vec::with_capacity(reduce.len());
        let mut acc_tys = Vec::with_capacity(reduce.len());
        for entry in reduce {
            let (id_val, id_ty) = self.lower_expr(&entry.identity);
            let ty = if entry.ty != Ty::Unknown && entry.ty != Ty::Unit {
                mir_ty_from_hir(&entry.ty)
            } else {
                id_ty
            };
            let init_l = self.alloc_and_emit(
                &format!("red_init_{}", entry.name),
                ty.clone(),
                Inst::ReduceInit {
                    op: entry.op.clone(),
                    identity: id_val,
                },
            );
            let slot = self.alloc_and_emit(
                &format!("red_slot_{}", entry.name),
                MirType::MutPtr,
                Inst::SlotAlloc { ty: ty.clone() },
            );
            self.emit_void(Inst::SlotStore { slot, val: init_l });
            acc_slots.push((entry, slot, ty.clone()));
            acc_tys.push(ty);
        }

        // Emit `ParForEachChunkReadonly`
        let chunk_size = self.func.par_chunk.unwrap_or(512);
        self.emit_void(Inst::ParForEachChunkReadonly {
            query_idx: qi,
            chunk_size,
            deterministic_order: self.ctx.is_deterministic || self.func.is_deterministic,
        });

        let chunk_hdr = self.new_block(&format!("red{qi}_chunk_hdr"));
        let chunk_body = self.new_block(&format!("red{qi}_chunk_body"));
        let row_hdr = self.new_block(&format!("red{qi}_row_hdr"));
        let row_body = self.new_block(&format!("red{qi}_row_body"));
        let chunk_exit = self.new_block(&format!("red{qi}_exit"));

        self.terminate(Terminator::Goto(chunk_hdr));
        self.switch_to(chunk_hdr);
        let has_chunk = self.alloc_and_emit(
            "has_chunk",
            MirType::Bool,
            Inst::IterNextChunk { query_idx: qi },
        );
        self.terminate(Terminator::Branch {
            cond: has_chunk,
            then_bb: chunk_body,
            else_bb: chunk_exit,
        });

        self.switch_to(chunk_body);
        let chunk_len = self.alloc_and_emit(
            "chunk_len",
            MirType::U32,
            Inst::IterChunkLen { query_idx: qi },
        );
        let mut col_bindings = Vec::new();
        for (ti, term) in hq.terms.iter().enumerate() {
            let col_ptr = self.alloc_and_emit(
                &format!("col_{}", term.alias),
                MirType::Ptr,
                Inst::IterColRead {
                    query_idx: qi,
                    term_idx: ti as u32,
                    storage_key: term.storage_key.clone(),
                },
            );
            col_bindings.push((
                ti as u32,
                term,
                self.ctx.resolve_canonical(&term.canonical_component),
                col_ptr,
            ));
        }
        let rslot = self.alloc_and_emit(
            "red_ridx",
            MirType::MutPtr,
            Inst::SlotAlloc { ty: MirType::U32 },
        );
        let z = self.alloc_and_emit("rz", MirType::U32, Inst::ConstInt { value: 0 });
        self.emit_void(Inst::SlotStore {
            slot: rslot,
            val: z,
        });
        self.terminate(Terminator::Goto(row_hdr));

        self.switch_to(row_hdr);
        let ridx = self.alloc_and_emit("ridx", MirType::U32, Inst::SlotLoad { slot: rslot });
        let rcond = self.alloc_and_emit(
            "rcond",
            MirType::Bool,
            Inst::BinOp {
                op: "<".to_owned(),
                lhs: ridx,
                rhs: chunk_len,
                allow_fma: false,
            },
        );
        self.terminate(Terminator::Branch {
            cond: rcond,
            then_bb: row_body,
            else_bb: chunk_hdr,
        });

        self.switch_to(row_body);
        let saved_vars = self.vars.clone();
        let mut terms_map = HashMap::new();
        for (_ti, term, canon, col_ptr) in col_bindings {
            let stride = self.ctx.find_layout(&canon).map_or(16, |l| l.size as u32);
            let rp = self.alloc_and_emit(
                &format!("rptr_{}", term.alias),
                MirType::Ptr,
                Inst::RowPtr {
                    col_ptr,
                    row_idx: ridx,
                    stride_bytes: stride,
                    is_sparse: term.is_sparse,
                },
            );
            terms_map.insert(
                term.alias.clone(),
                TermAccessBinding {
                    canonical_layout: canon,
                    field_name: term.field_name.clone(),
                    mode: term.mode,
                    col_ptr,
                    row_ptr: Some(rp),
                    present_local: None,
                    is_up_cascade: false,
                },
            );
        }
        if let HirPattern::Binding { name, .. } = pat {
            if hq.terms.len() == 1
                && let Some((alias, tb)) = terms_map.iter().next()
                && (tb.field_name.is_some()
                    || matches!(
                        tb.mode,
                        TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                    ))
                && alias == name
            {
                self.vars.insert(
                    name.clone(),
                    VarSlot::SingleTermPtr {
                        binding: tb.clone(),
                    },
                );
            } else {
                self.vars.insert(
                    name.clone(),
                    VarSlot::RowAlias {
                        entity_local: None,
                        terms: terms_map.clone(),
                    },
                );
            }
        }
        for (alias, tb) in &terms_map {
            self.vars
                .entry(alias.clone())
                .or_insert_with(|| VarSlot::SingleTermPtr {
                    binding: tb.clone(),
                });
        }
        for (entry, slot, ty) in &acc_slots {
            let (val_l, _) = self.lower_expr(&entry.value);
            let cur = self.alloc_and_emit("acc_cur", ty.clone(), Inst::SlotLoad { slot: *slot });
            let nxt = self.alloc_and_emit(
                "acc_nxt",
                ty.clone(),
                Inst::ReduceAccum {
                    acc: cur,
                    op: entry.op.clone(),
                    val: val_l,
                },
            );
            self.emit_void(Inst::SlotStore {
                slot: *slot,
                val: nxt,
            });
        }
        let one = self.alloc_and_emit("r1", MirType::U32, Inst::ConstInt { value: 1 });
        let nxt_i = self.alloc_and_emit(
            "rnxt",
            MirType::U32,
            Inst::BinOp {
                op: "+".to_owned(),
                lhs: ridx,
                rhs: one,
                allow_fma: false,
            },
        );
        self.emit_void(Inst::SlotStore {
            slot: rslot,
            val: nxt_i,
        });
        self.terminate(Terminator::Goto(row_hdr));

        self.switch_to(chunk_exit);
        self.vars = saved_vars;
        if acc_slots.len() == 1 {
            let (_, slot, ty) = &acc_slots[0];
            let final_l =
                self.alloc_and_emit("red_out", ty.clone(), Inst::SlotLoad { slot: *slot });
            (final_l, ty.clone())
        } else {
            let mut fields = Vec::with_capacity(acc_slots.len());
            for (i, (_, slot, ty)) in acc_slots.iter().enumerate() {
                let fl = self.alloc_and_emit(
                    &format!("red_out_{i}"),
                    ty.clone(),
                    Inst::SlotLoad { slot: *slot },
                );
                fields.push((format!("_{i}"), fl));
            }
            let tty = MirType::Tuple(acc_tys);
            let out = self.alloc_and_emit(
                "red_tup",
                tty.clone(),
                Inst::StructInit {
                    type_name: "tuple".to_owned(),
                    fields,
                },
            );
            (out, tty)
        }
    }

    pub(crate) fn finish(self) -> MirFunction {
        self.func
    }
}

enum EvaluatedSlot {
    Handle(VarSlot),
    Value {
        local: LocalId,
        mir_ty: MirType,
        hir_ty: Ty,
    },
}

fn bitset_bits_from_mir_ty(ty: &MirType) -> Option<usize> {
    if let MirType::Named(n) = ty {
        n.strip_prefix("BitSet<")
            .and_then(|s| s.strip_suffix('>'))
            .and_then(|s| s.parse::<usize>().ok())
    } else {
        None
    }
}

enum EventOrTriggerPayload {
    Payload(String),
    Target,
}

fn event_name_of_expr(expr: &HirExpr) -> String {
    match expr {
        HirExpr::StructLit { name, .. } => name.clone(),
        _ => match expr.ty() {
            Ty::Named(n) => n,
            _ => "Event".to_owned(),
        },
    }
}

fn receiver_resource_name(expr: &HirExpr) -> String {
    match expr {
        HirExpr::Path { name, .. } => name.clone(),
        HirExpr::Call(c) if matches!(c.callee.as_str(), "res" | "res_mut") => {
            c.generic_args.first().cloned().unwrap_or_default()
        }
        _ => match expr.ty() {
            Ty::Named(n) => n,
            _ => "SpatialIndex".to_owned(),
        },
    }
}

fn resolve_timeline_window_bit(
    ctx: &MirLowerCtx,
    receiver: &HirExpr,
    arg: Option<&HirExpr>,
) -> u32 {
    let Some(HirExpr::Path { name: wname, .. }) = arg else {
        return 0;
    };
    if let Ty::Named(ref tname) = receiver.ty()
        && let Some(tl) = ctx.timelines.get(tname)
        && let Some((_, _, _, bit)) = tl.windows.iter().find(|(wn, _, _, _)| wn == wname)
    {
        return u32::from(*bit);
    }
    for tl in ctx.timelines.values() {
        if let Some((_, _, _, bit)) = tl.windows.iter().find(|(wn, _, _, _)| wn == wname) {
            return u32::from(*bit);
        }
    }
    0
}

fn input_buf_cap(expr: &HirExpr) -> u32 {
    match expr.ty() {
        Ty::InputBuffer { cap, .. } => cap as u32,
        _ => 4,
    }
}

fn bitset_words(expr: &HirExpr) -> u32 {
    match expr.ty() {
        Ty::BitSet(bits) => bits.div_ceil(32).max(1) as u32,
        _ => 1,
    }
}

fn extract_some_inner_binding(pat: &HirPattern) -> Option<String> {
    match pat {
        HirPattern::Binding { name, .. } => Some(name.clone()),
        HirPattern::TupleStruct { fields, .. } => {
            fields.iter().find_map(extract_some_inner_binding)
        }
        _ => None,
    }
}

fn is_vec_mir_ty(ty: &MirType) -> bool {
    matches!(
        ty,
        MirType::Vec2
            | MirType::Vec3
            | MirType::Vec4
            | MirType::IVec2
            | MirType::IVec3
            | MirType::UVec2
    )
}

fn vec_lane_mir_ty(ty: &MirType) -> MirType {
    match ty {
        MirType::IVec2 | MirType::IVec3 => MirType::I32,
        MirType::UVec2 => MirType::U32,
        _ => MirType::F32,
    }
}

fn vec_swizzle_mir_ty(base_ty: &MirType, len: usize) -> MirType {
    match (base_ty, len) {
        (MirType::IVec2 | MirType::IVec3, 2) => MirType::IVec2,
        (MirType::IVec2 | MirType::IVec3, 3) => MirType::IVec3,
        (MirType::UVec2, 2) => MirType::UVec2,
        (_, 2) => MirType::Vec2,
        (_, 3) => MirType::Vec3,
        _ => MirType::Vec4,
    }
}

fn vec_path_constant(name: &str) -> Option<MirConstVal> {
    match name {
        "vec2::ZERO" | "ivec2::ZERO" | "uvec2::ZERO" => Some(MirConstVal::Vec2([0.0, 0.0])),
        "vec2::ONE" | "ivec2::ONE" | "uvec2::ONE" => Some(MirConstVal::Vec2([1.0, 1.0])),
        "vec2::X" | "ivec2::X" | "uvec2::X" => Some(MirConstVal::Vec2([1.0, 0.0])),
        "vec2::Y" | "ivec2::Y" | "uvec2::Y" => Some(MirConstVal::Vec2([0.0, 1.0])),
        "vec3::ZERO" | "ivec3::ZERO" => Some(MirConstVal::Vec3([0.0, 0.0, 0.0])),
        "vec3::ONE" | "ivec3::ONE" => Some(MirConstVal::Vec3([1.0, 1.0, 1.0])),
        "vec3::UP" | "vec3::Y" | "ivec3::Y" => Some(MirConstVal::Vec3([0.0, 1.0, 0.0])),
        "vec3::X" | "ivec3::X" => Some(MirConstVal::Vec3([1.0, 0.0, 0.0])),
        "vec3::Z" | "ivec3::Z" => Some(MirConstVal::Vec3([0.0, 0.0, 1.0])),
        "vec4::ZERO" => Some(MirConstVal::Vec4([0.0, 0.0, 0.0, 0.0])),
        "vec4::ONE" => Some(MirConstVal::Vec4([1.0, 1.0, 1.0, 1.0])),
        "vec4::X" => Some(MirConstVal::Vec4([1.0, 0.0, 0.0, 0.0])),
        "vec4::Y" => Some(MirConstVal::Vec4([0.0, 1.0, 0.0, 0.0])),
        "vec4::Z" => Some(MirConstVal::Vec4([0.0, 0.0, 1.0, 0.0])),
        "vec4::W" => Some(MirConstVal::Vec4([0.0, 0.0, 0.0, 1.0])),
        _ => None,
    }
}

fn vec_char_lane(c: char) -> Option<u8> {
    match c {
        'x' | 'r' => Some(0),
        'y' | 'g' => Some(1),
        'z' | 'b' => Some(2),
        'w' | 'a' => Some(3),
        _ => None,
    }
}

fn vec_lane_index(field: &str) -> Option<u8> {
    match field {
        "x" | "r" => Some(0),
        "y" | "g" => Some(1),
        "z" | "b" => Some(2),
        "w" | "a" => Some(3),
        _ => None,
    }
}

fn is_vec_swizzle(field: &str) -> bool {
    !field.is_empty() && field.len() <= 4 && field.chars().all(|c| vec_char_lane(c).is_some())
}

fn binop_str(op: HirBinOp) -> &'static str {
    match op {
        HirBinOp::Add => "+",
        HirBinOp::Sub => "-",
        HirBinOp::Mul => "*",
        HirBinOp::Div => "/",
        HirBinOp::Rem => "%",
        HirBinOp::BitAnd => "&",
        HirBinOp::BitOr => "|",
        HirBinOp::BitXor => "^",
        HirBinOp::Shl => "<<",
        HirBinOp::Shr => ">>",
        HirBinOp::Eq => "==",
        HirBinOp::Ne => "!=",
        HirBinOp::Lt => "<",
        HirBinOp::Le => "<=",
        HirBinOp::Gt => ">",
        HirBinOp::Ge => ">=",
        HirBinOp::And => "&&",
        HirBinOp::Or => "||",
        HirBinOp::Range => "..",
        HirBinOp::RangeInclusive => "..=",
    }
}

fn is_cmp_binop(op: HirBinOp) -> bool {
    matches!(
        op,
        HirBinOp::Eq | HirBinOp::Ne | HirBinOp::Lt | HirBinOp::Le | HirBinOp::Gt | HirBinOp::Ge
    )
}

fn is_scalar_numeric(ty: &MirType) -> bool {
    matches!(
        ty,
        MirType::I8
            | MirType::I16
            | MirType::I32
            | MirType::I64
            | MirType::U8
            | MirType::U16
            | MirType::U32
            | MirType::U64
            | MirType::F32
            | MirType::F64
            | MirType::Fix32
            | MirType::Fix64
    )
}

fn numeric_rank(ty: &MirType) -> u8 {
    match ty {
        MirType::Fix64 => 12,
        MirType::Fix32 => 11,
        MirType::F64 => 10,
        MirType::F32 => 9,
        MirType::I64 => 8,
        MirType::U64 => 7,
        MirType::I32 => 6,
        MirType::U32 => 5,
        MirType::I16 => 4,
        MirType::U16 => 3,
        MirType::I8 => 2,
        MirType::U8 => 1,
        _ => 0,
    }
}

fn unify_mir_scalar(a: &MirType, b: &MirType) -> MirType {
    if numeric_rank(a) >= numeric_rank(b) {
        a.clone()
    } else {
        b.clone()
    }
}

fn assign_op_str(op: HirAssignOp) -> &'static str {
    match op {
        HirAssignOp::Set => "=",
        HirAssignOp::AddAssign => "+",
        HirAssignOp::SubAssign => "-",
        HirAssignOp::MulAssign => "*",
        HirAssignOp::DivAssign => "/",
        HirAssignOp::RemAssign => "%",
        HirAssignOp::BitAndAssign => "&",
        HirAssignOp::BitOrAssign => "|",
        HirAssignOp::BitXorAssign => "^",
        HirAssignOp::ShlAssign => "<<",
        HirAssignOp::ShrAssign => ">>",
    }
}

/// Lowers a verified [`AnalyzedModule`] into [`MirModule`] and runs all 6 MIR optimization and
/// synthesis passes in canonical order.
pub fn lower_to_mir(analyzed: &AnalyzedModule) -> MirModule {
    let ctx = MirLowerCtx::from_analyzed(analyzed);
    let mut fns = Vec::with_capacity(analyzed.fns.len());
    for hf in &analyzed.fns {
        fns.push(lower_helper_fn(&ctx, hf));
    }

    let mut functions = Vec::new();
    for callable in &analyzed.callables {
        functions.push(lower_callable(&ctx, callable));
    }
    for mig in &analyzed.migrations {
        functions.push(lower_migration(&ctx, mig));
    }

    let mut schedules = analyzed.schedules.clone();
    synthesize_timer_tick_system(&ctx, &mut functions, &mut schedules);

    let net_components = lower_net_components(&ctx, &analyzed.net_components);
    let rpcs = lower_rpcs(&analyzed.rpcs);
    let net_sim_tests = lower_net_sim_tests(&analyzed.net_sim_tests);
    let net_handshake = build_net_handshake(
        &analyzed.module_path,
        analyzed.net_schema_fingerprint,
        &net_components,
        &rpcs,
    );
    let net_stream_ops = build_net_stream_ops(&analyzed.module_path, &net_components, &rpcs);

    let mut mir = MirModule {
        module_path: analyzed.module_path.clone(),
        is_deterministic: analyzed.is_deterministic,
        layouts: ctx.all_layouts.clone(),
        enums: analyzed.enums.values().cloned().collect(),
        consts: analyzed.consts.clone(),
        tables: analyzed.tables.clone(),
        curves: analyzed.curves.clone(),
        relations: analyzed.relations.clone(),
        spatial_indices: analyzed.spatial_indices.clone(),
        timelines: analyzed.timelines.clone(),
        tasks: analyzed.tasks.clone(),
        fsms: analyzed.fsms.clone(),
        objects: analyzed.objects.clone(),
        migrations: analyzed.migrations.clone(),
        fns,
        functions,
        schedules,
        sim_tests: analyzed.sim_tests.clone(),
        field_defaults: ctx.field_defaults.clone(),
        rpcs,
        net_components,
        net_sim_tests,
        net_handshake,
        net_stream_ops,
    };

    // Canonical pass pipeline:
    // 1. State machines (`timeline`, `task`, `fsm`)
    passes::state_machines::run(&mut mir);
    // 2. Spatial CSR synthesis + pre-reader schedule ordering
    passes::spatial_csr::run(&mut mir);
    // 3. Per-function CFG passes (`optional_split`, `tick_coalesce`, `atomic_tx`)
    for func in &mut mir.functions {
        passes::optional_split::run(func);
        passes::tick_coalesce::run(func);
        passes::atomic_tx::run_with_ctx(func, &ctx);
    }
    // 4. Deterministic math & reduction order enforcement
    passes::determinism::run(&mut mir);

    mir
}

fn lower_helper_fn(ctx: &MirLowerCtx, hf: &HirFn) -> MirFunction {
    let mut func = MirFunction::new(&hf.name, MirFnKind::HelperFn);
    func.ret_ty = mir_ty_from_hir(&hf.ret_ty);
    func.is_deterministic = ctx.is_deterministic;
    func.is_node_pure = hf.is_node_pure;
    func.node_group = hf.node_group.clone();
    let mut b = CfgBuilder::new(func, ctx);
    b.bind_params(&hf.params, false);
    b.lower_stmts(&hf.body);
    if !b.cur_terminated {
        if let Some(ref tail) = hf.tail {
            let (tl, _) = b.lower_expr(tail);
            b.terminate(Terminator::Return(Some(tl)));
        } else {
            b.terminate(Terminator::Return(None));
        }
    }
    b.finish()
}

fn lower_callable(ctx: &MirLowerCtx, c: &HirCallable) -> MirFunction {
    let kind = if c.is_observer {
        MirFnKind::Observer {
            event: c
                .trigger_event
                .clone()
                .unwrap_or_else(|| "Event".to_owned()),
            target_comp: c.trigger_target_comp.clone(),
        }
    } else {
        MirFnKind::System
    };
    let mut func = MirFunction::new(&c.name, kind);
    func.par_chunk = c.par_chunk;
    func.par_read_only = c.par_read_only;
    func.is_deterministic = ctx.is_deterministic;
    func.authority = c.authority;
    func.is_predicted = c.is_predicted;
    func.node_group = c.node_group.clone();
    func.source_body = c.body_source.clone();

    let mut b = CfgBuilder::new(func, ctx);
    b.bind_params(&c.params, true);
    b.lower_stmts(&c.body);
    if !b.cur_terminated {
        b.terminate(Terminator::Return(None));
    }
    let mut finished = b.finish();
    // Preserve any non-body access metadata when a stub/empty test body exists
    if finished.queries.is_empty() && !c.access.queries.is_empty() {
        finished.queries = c.access.queries.clone();
    }
    finished
}

fn lower_migration(ctx: &MirLowerCtx, mig: &HirMigration) -> MirFunction {
    let fname = format!(
        "{}__migrate_{}_to_{}",
        mig.component,
        mig.from_ver.replace('.', "_"),
        mig.to_ver.replace('.', "_")
    );
    let src_key = match &mig.from_type {
        Ty::Named(n) | Ty::Ref(n) => ctx.resolve_canonical(n),
        _ => ctx.resolve_canonical(&format!("{}V1", mig.component)),
    };
    let dst_key = match &mig.to_type {
        Ty::Named(n) => ctx.resolve_canonical(n),
        _ => ctx.resolve_canonical(&mig.component),
    };
    let mut func = MirFunction::new(
        fname,
        MirFnKind::Migration {
            component: mig.component.clone(),
            from_ver: mig.from_ver.clone(),
            to_ver: mig.to_ver.clone(),
            src_layout: src_key.clone(),
            dst_layout: dst_key.clone(),
        },
    );
    func.is_deterministic = ctx.is_deterministic;
    func.source_body = mig.body_source.clone();

    let mut b = CfgBuilder::new(func, ctx);
    let src_ptr = b.alloc_and_emit(
        &mig.param_name,
        MirType::Ptr,
        Inst::MigrateSrcPtr {
            layout_key: src_key.clone(),
        },
    );
    let dst_ptr = b.alloc_and_emit(
        "dst_row",
        MirType::MutPtr,
        Inst::MigrateDstPtr {
            layout_key: dst_key.clone(),
        },
    );
    b.vars.insert(
        mig.param_name.clone(),
        VarSlot::ResPtr {
            ptr_local: src_ptr,
            layout_key: src_key,
        },
    );
    b.lower_stmts(&mig.body);

    if let Some(ref tail) = mig.tail {
        match tail {
            HirExpr::StructLit { name, fields, .. } => {
                let flocs = b.build_comp_fields(name, fields);
                for (fname, flocal) in flocs {
                    let (offset, _, _) = ctx.resolve_field(&dst_key, &fname);
                    b.emit_void(Inst::FieldStore {
                        base_ptr: dst_ptr,
                        layout_key: dst_key.clone(),
                        field: fname,
                        offset_bytes: offset,
                        val: flocal,
                    });
                }
            }
            other => {
                let (val_l, _) = b.lower_expr(other);
                b.emit_void(Inst::FieldStore {
                    base_ptr: dst_ptr,
                    layout_key: dst_key,
                    field: "_value".to_owned(),
                    offset_bytes: 0,
                    val: val_l,
                });
            }
        }
    }

    if !b.cur_terminated {
        b.terminate(Terminator::Return(None));
    }
    b.finish()
}

fn synthesize_timer_tick_system(
    ctx: &MirLowerCtx,
    functions: &mut Vec<MirFunction>,
    schedules: &mut Vec<HirSchedule>,
) {
    // Identify singleton clock resource carrying `dt`
    let Some((clock_layout, dt_offset)) = ctx.all_layouts.iter().find_map(|l| {
        if l.item_kind != SchemaItemKind::Resource {
            return None;
        }
        l.fields
            .iter()
            .find(|f| f.name == "dt")
            .map(|f| (l, f.offset as u32))
    }) else {
        return;
    };

    // Identify every component / `@soa` stratum layout with `GraceWindow` or `InputBuffer` fields
    let mut timer_targets: Vec<(&SolvedLayout, Vec<(String, u32, TimerFieldKind)>)> = Vec::new();
    for l in &ctx.all_layouts {
        if !matches!(
            l.item_kind,
            SchemaItemKind::Component | SchemaItemKind::SoaHot | SchemaItemKind::SoaCold
        ) {
            continue;
        }
        let mut fields = Vec::new();
        for f in &l.fields {
            match &f.ty {
                Ty::GraceWindow => {
                    fields.push((f.name.clone(), f.offset as u32, TimerFieldKind::Grace));
                }
                Ty::InputBuffer { cap, .. } => {
                    fields.push((
                        f.name.clone(),
                        f.offset as u32,
                        TimerFieldKind::InputBuf(*cap as u32),
                    ));
                }
                _ => {}
            }
        }
        if !fields.is_empty() {
            timer_targets.push((l, fields));
        }
    }

    if timer_targets.is_empty() {
        return;
    }

    let clock_short = clock_layout
        .canonical_name
        .rsplit("::")
        .next()
        .unwrap_or(&clock_layout.canonical_name)
        .to_owned();

    let mut func = MirFunction::new("strata_timer_tick", MirFnKind::SynthesizedTimerTick);
    func.is_deterministic = ctx.is_deterministic;

    let mut b = CfgBuilder::new(func, ctx);
    let clk_ptr = b.alloc_and_emit(
        "clk",
        MirType::Ptr,
        Inst::ResRead {
            resource: clock_short.clone(),
        },
    );
    b.func.resources.push(MirResourceBinding {
        param_name: "clk".to_owned(),
        resource_name: clock_short,
        canonical_name: clock_layout.canonical_name.clone(),
        mutable: false,
        ptr_local: clk_ptr,
    });
    let dt_sec = b.alloc_and_emit(
        "dt",
        MirType::F32,
        Inst::FieldLoad {
            base_ptr: clk_ptr,
            layout_key: clock_layout.canonical_name.clone(),
            field: "dt".to_owned(),
            offset_bytes: dt_offset,
            field_ty: MirType::F32,
        },
    );

    for (qi, (comp_layout, timer_fields)) in timer_targets.into_iter().enumerate() {
        let qi = qi as u32;
        let short_comp = comp_layout
            .canonical_name
            .rsplit("::")
            .next()
            .unwrap_or(&comp_layout.canonical_name)
            .to_owned();
        let storage_key = if let Some((comp, strat)) = short_comp.split_once("__") {
            format!("{comp}::{strat}")
        } else {
            short_comp.clone()
        };
        let is_sparse =
            (comp_layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET) != 0;

        b.func.queries.push(QueryAccessDesc {
            terms: vec![QueryTerm {
                storage_key: storage_key.clone(),
                field_name: None,
                mode: TermAccessMode::Write,
                byte_start: 0,
                byte_end: 0,
            }],
            ..Default::default()
        });
        b.func.query_bindings.push(MirQueryBinding {
            query_idx: qi,
            terms: vec![MirQueryTermBinding {
                term_idx: 0,
                alias: "c".to_owned(),
                storage_key: storage_key.clone(),
                canonical_component: comp_layout.canonical_name.clone(),
                field_name: None,
                mode: TermAccessMode::Write,
                is_sparse,
            }],
            with_filters: Vec::new(),
            without_filters: Vec::new(),
            is_point_lookup: false,
        });

        let chunk_hdr = b.new_block(&format!("tmr{qi}_chunk_hdr"));
        let chunk_body = b.new_block(&format!("tmr{qi}_chunk_body"));
        let row_hdr = b.new_block(&format!("tmr{qi}_row_hdr"));
        let row_body = b.new_block(&format!("tmr{qi}_row_body"));
        let next_comp = b.new_block(&format!("tmr{qi}_done"));

        b.terminate(Terminator::Goto(chunk_hdr));
        b.switch_to(chunk_hdr);
        let has_chunk = b.alloc_and_emit(
            "has_chunk",
            MirType::Bool,
            Inst::IterNextChunk { query_idx: qi },
        );
        b.terminate(Terminator::Branch {
            cond: has_chunk,
            then_bb: chunk_body,
            else_bb: next_comp,
        });

        b.switch_to(chunk_body);
        let chunk_len = b.alloc_and_emit(
            "chunk_len",
            MirType::U32,
            Inst::IterChunkLen { query_idx: qi },
        );
        let col_ptr = b.alloc_and_emit(
            "col",
            MirType::MutPtr,
            if is_sparse {
                Inst::IterColRowsWrite {
                    query_idx: qi,
                    term_idx: 0,
                    storage_key: storage_key.clone(),
                }
            } else {
                Inst::IterColWrite {
                    query_idx: qi,
                    term_idx: 0,
                    storage_key: storage_key.clone(),
                }
            },
        );
        let rslot = b.alloc_and_emit(
            "ridx_slot",
            MirType::MutPtr,
            Inst::SlotAlloc { ty: MirType::U32 },
        );
        let zero = b.alloc_and_emit("z", MirType::U32, Inst::ConstInt { value: 0 });
        b.emit_void(Inst::SlotStore {
            slot: rslot,
            val: zero,
        });
        b.terminate(Terminator::Goto(row_hdr));

        b.switch_to(row_hdr);
        let ridx = b.alloc_and_emit("ridx", MirType::U32, Inst::SlotLoad { slot: rslot });
        let cond = b.alloc_and_emit(
            "rcond",
            MirType::Bool,
            Inst::BinOp {
                op: "<".to_owned(),
                lhs: ridx,
                rhs: chunk_len,
                allow_fma: false,
            },
        );
        b.terminate(Terminator::Branch {
            cond,
            then_bb: row_body,
            else_bb: chunk_hdr,
        });

        b.switch_to(row_body);
        let rptr = b.alloc_and_emit(
            "rptr",
            MirType::MutPtr,
            Inst::RowPtr {
                col_ptr,
                row_idx: ridx,
                stride_bytes: comp_layout.size as u32,
                is_sparse,
            },
        );
        for (fname, foff, kind) in timer_fields {
            let fptr = b.alloc_and_emit(
                &format!("fptr_{fname}"),
                MirType::MutPtr,
                Inst::FieldPtr {
                    base_ptr: rptr,
                    layout_key: comp_layout.canonical_name.clone(),
                    field: fname,
                    offset_bytes: foff,
                },
            );
            match kind {
                TimerFieldKind::Grace => b.emit_void(Inst::GraceTick { ptr: fptr, dt_sec }),
                TimerFieldKind::InputBuf(cap) => b.emit_void(Inst::InputBufTick {
                    ptr: fptr,
                    capacity: cap,
                    dt_sec,
                }),
            }
        }
        let one = b.alloc_and_emit("one", MirType::U32, Inst::ConstInt { value: 1 });
        let nxt = b.alloc_and_emit(
            "r_nxt",
            MirType::U32,
            Inst::BinOp {
                op: "+".to_owned(),
                lhs: ridx,
                rhs: one,
                allow_fma: false,
            },
        );
        b.emit_void(Inst::SlotStore {
            slot: rslot,
            val: nxt,
        });
        b.terminate(Terminator::Goto(row_hdr));

        b.switch_to(next_comp);
    }

    if !b.cur_terminated {
        b.terminate(Terminator::Return(None));
    }
    functions.push(b.finish());

    let tick_leaf = HirScheduleGroup {
        kind: "leaf".to_owned(),
        name: "strata_timer_tick".to_owned(),
        children: Vec::new(),
    };
    if let Some(fixed) = schedules.iter_mut().find(|s| s.label == "FixedUpdate") {
        fixed.nodes.insert(0, tick_leaf);
    } else {
        schedules.push(HirSchedule {
            label: "FixedUpdate".to_owned(),
            run_if: None,
            run_if_expr: None,
            nodes: vec![tick_leaf],
        });
    }
}

enum TimerFieldKind {
    Grace,
    InputBuf(u32),
}

fn quantize_lane_count(ty: &Ty) -> u8 {
    match ty {
        Ty::Vec2 | Ty::IVec2 | Ty::UVec2 => 2,
        Ty::Vec3 | Ty::Vec3a | Ty::IVec3 => 3,
        Ty::Vec4 | Ty::Quat => 4,
        _ => 1,
    }
}

fn pack_quantized_fields(
    fields: &[strata_sema::layout::SolvedField],
    specs: &[HirQuantizeSpec],
    cursor_bits: &mut u32,
    quantize_specs: &mut Vec<MirQuantizeSpec>,
    wire_fields: &mut Vec<MirNetFieldSpec>,
) {
    let wildcard_spec = specs.iter().find(|q| q.field_name == "*");
    for field in fields {
        if field.is_padding {
            continue;
        }
        let mir_ty = mir_wire_ty_from_hir(&field.ty);
        let spec_opt = specs
            .iter()
            .find(|q| q.field_name == field.name)
            .or(wildcard_spec);
        if let Some(spec) = spec_opt {
            let lane_count = quantize_lane_count(&field.ty);
            let total_bits = u32::from(spec.bits) * u32::from(lane_count);
            let bit_offset = *cursor_bits;
            *cursor_bits += total_bits;
            let mq = MirQuantizeSpec {
                field_name: field.name.clone(),
                lane_count,
                bits: spec.bits,
                min: spec.min,
                max: spec.max,
                step: spec.step,
                bit_offset,
                total_bits,
                field_byte_offset: field.offset as u32,
                field_ty: mir_ty.clone(),
            };
            quantize_specs.push(mq.clone());
            wire_fields.push(MirNetFieldSpec {
                field_name: field.name.clone(),
                byte_offset: field.offset as u32,
                byte_size: field.size as u32,
                ty: mir_ty,
                quantize: Some(mq),
                bit_offset,
                total_bits,
            });
        } else {
            let total_bits = (field.size as u32) * 8;
            let bit_offset = *cursor_bits;
            *cursor_bits += total_bits;
            wire_fields.push(MirNetFieldSpec {
                field_name: field.name.clone(),
                byte_offset: field.offset as u32,
                byte_size: field.size as u32,
                ty: mir_ty,
                quantize: None,
                bit_offset,
                total_bits,
            });
        }
    }
}

fn lower_net_components(ctx: &MirLowerCtx, metas: &[NetComponentMeta]) -> Vec<MirNetComponent> {
    let mut out = Vec::new();
    for nc in metas {
        let Some(layout) = ctx.find_layout(&nc.canonical_name) else {
            continue;
        };
        let mut cursor_bits = 0u32;
        let mut quantize_specs = Vec::new();
        let mut wire_fields = Vec::new();

        pack_quantized_fields(
            &layout.fields,
            &nc.quantized_fields,
            &mut cursor_bits,
            &mut quantize_specs,
            &mut wire_fields,
        );
        if layout.item_kind == SchemaItemKind::SoaHot {
            let cold_prefix = format!("{}__", nc.canonical_name);
            for l in &ctx.all_layouts {
                if l.item_kind == SchemaItemKind::SoaCold
                    && l.canonical_name.starts_with(&cold_prefix)
                    && l.required_components.first() == Some(&nc.canonical_name)
                {
                    pack_quantized_fields(
                        &l.fields,
                        &nc.quantized_fields,
                        &mut cursor_bits,
                        &mut quantize_specs,
                        &mut wire_fields,
                    );
                }
            }
        }

        let packed_bits = cursor_bits;
        let packed_bytes = packed_bits.div_ceil(8);
        let (reliability, rate_hz, interval_ticks, channel) = if let Some(ref cfg) = nc.net_config {
            (
                cfg.reliability,
                cfg.rate_hz,
                cfg.interval_ticks,
                cfg.channel,
            )
        } else {
            (NetReliability::Reliable, None, None, 0)
        };

        out.push(MirNetComponent {
            name: nc.short_name.clone(),
            canonical_name: nc.canonical_name.clone(),
            is_resource: nc.is_resource,
            is_replicated: nc.is_replicated,
            reliability,
            rate_hz,
            interval_ticks,
            channel,
            authority: nc.authority,
            is_predicted: nc.is_predicted,
            schema_fingerprint: layout.schema_fingerprint,
            uuid_bytes: layout.uuid_bytes,
            quantize_specs,
            wire_fields,
            packed_bits,
            packed_bytes,
        });
    }
    out
}

fn lower_rpcs(rpcs: &[HirRpc]) -> Vec<MirRpc> {
    use bamabi_sys::{fnv1a_64_init, fnv1a_64_update_bytes, fnv1a_64_update_u64};

    let mut out = Vec::new();
    for rpc in rpcs {
        let mut fields = Vec::new();
        for f in &rpc.payload_layout.fields {
            if f.is_padding {
                continue;
            }
            fields.push((
                f.name.clone(),
                mir_wire_ty_from_hir(&f.ty),
                f.offset as u32,
                f.size as u32,
            ));
        }

        let mut cursor_bits = 0u32;
        let mut quantize_specs = Vec::new();
        let mut wire_fields = Vec::new();
        pack_quantized_fields(
            &rpc.payload_layout.fields,
            &rpc.quantized_fields,
            &mut cursor_bits,
            &mut quantize_specs,
            &mut wire_fields,
        );
        let packed_bits = cursor_bits;
        let packed_bytes = packed_bits.div_ceil(8);

        let mut fp = fnv1a_64_init();
        fp = fnv1a_64_update_bytes(fp, b"strata_rpc_v1:");
        fp = fnv1a_64_update_bytes(fp, rpc.canonical_name.as_bytes());
        fp = fnv1a_64_update_u64(fp, rpc.payload_layout.schema_fingerprint);
        fp = fnv1a_64_update_u64(
            fp,
            match rpc.direction {
                NetDirection::ClientToServer => 0,
                NetDirection::ServerToClient => 1,
                NetDirection::Bidirectional => 2,
            },
        );
        fp = fnv1a_64_update_u64(
            fp,
            match rpc.reliability {
                NetReliability::Reliable => 0,
                NetReliability::Unreliable => 1,
            },
        );
        fp = fnv1a_64_update_u64(fp, u64::from(rpc.channel));
        fp = fnv1a_64_update_u64(fp, u64::from(rpc.is_marker));
        let auth_tag: u64 = match rpc.authority {
            AuthorityKind::Unspecified => 0,
            AuthorityKind::Server => 1,
            AuthorityKind::Client => 2,
            AuthorityKind::Predicted => 3,
            AuthorityKind::Shared => 4,
        };
        fp = fnv1a_64_update_u64(fp, auth_tag);
        fp = fnv1a_64_update_u64(fp, rpc.quantized_fields.len() as u64);
        for q in &rpc.quantized_fields {
            fp = fnv1a_64_update_bytes(fp, q.field_name.as_bytes());
            fp = fnv1a_64_update_u64(fp, q.min.to_bits());
            fp = fnv1a_64_update_u64(fp, q.max.to_bits());
            fp = fnv1a_64_update_u64(fp, u64::from(q.bits));
            fp = fnv1a_64_update_u64(fp, q.step.map_or(0, f64::to_bits));
        }

        out.push(MirRpc {
            name: rpc.name.clone(),
            canonical_name: rpc.canonical_name.clone(),
            direction: rpc.direction,
            reliability: rpc.reliability,
            channel: rpc.channel,
            authority: rpc.authority,
            rpc_id: rpc.rpc_id,
            schema_fingerprint: fp.max(1),
            fields,
            quantize_specs,
            wire_fields,
            packed_bits,
            packed_bytes,
            payload_bytes: rpc.payload_layout.size as u32,
        });
    }
    out
}

fn lower_net_sim_tests(tests: &[HirNetSimTest]) -> Vec<MirNetSimTest> {
    tests
        .iter()
        .map(|t| MirNetSimTest {
            name: t.name.clone(),
            latency_ms: t.latency_ms,
            jitter_ms: t.jitter_ms,
            loss: t.loss,
            seed: t.seed,
            clients: t.clients,
            body: t.body.clone(),
            body_source: t.body_source.clone(),
        })
        .collect()
}

fn hash_quantize_specs(mut fp: u64, specs: &[MirQuantizeSpec]) -> u64 {
    use bamabi_sys::{fnv1a_64_update_bytes, fnv1a_64_update_u64};

    fp = fnv1a_64_update_u64(fp, specs.len() as u64);
    for q in specs {
        fp = fnv1a_64_update_bytes(fp, q.field_name.as_bytes());
        fp = fnv1a_64_update_u64(fp, u64::from(q.lane_count));
        fp = fnv1a_64_update_u64(fp, u64::from(q.bits));
        fp = fnv1a_64_update_u64(fp, q.min.to_bits());
        fp = fnv1a_64_update_u64(fp, q.max.to_bits());
        fp = fnv1a_64_update_u64(fp, q.step.map_or(0, f64::to_bits));
        fp = fnv1a_64_update_u64(fp, u64::from(q.bit_offset));
        fp = fnv1a_64_update_u64(fp, u64::from(q.total_bits));
        fp = fnv1a_64_update_u64(fp, u64::from(q.field_byte_offset));
    }
    fp
}

fn build_net_handshake(
    module_path: &str,
    net_schema_fingerprint: u64,
    net_components: &[MirNetComponent],
    rpcs: &[MirRpc],
) -> MirNetHandshake {
    use bamabi_sys::{fnv1a_64_init, fnv1a_64_update_bytes, fnv1a_64_update_u64};

    let mut component_fingerprints: Vec<(String, u64)> = net_components
        .iter()
        .map(|c| (c.canonical_name.clone(), c.schema_fingerprint))
        .collect();
    component_fingerprints.sort_by(|a, b| a.0.cmp(&b.0));

    let mut rpc_fingerprints: Vec<(String, u64)> = rpcs
        .iter()
        .map(|r| (r.canonical_name.clone(), r.schema_fingerprint))
        .collect();
    rpc_fingerprints.sort_by(|a, b| a.0.cmp(&b.0));

    let module_net_fingerprint = if component_fingerprints.is_empty() && rpc_fingerprints.is_empty()
    {
        0
    } else {
        let mut sorted_comps: Vec<&MirNetComponent> = net_components.iter().collect();
        sorted_comps.sort_by(|a, b| a.canonical_name.cmp(&b.canonical_name));
        let mut sorted_rpcs: Vec<&MirRpc> = rpcs.iter().collect();
        sorted_rpcs.sort_by(|a, b| a.canonical_name.cmp(&b.canonical_name));

        let mut fp = fnv1a_64_init();
        fp = fnv1a_64_update_bytes(fp, b"strata_net_handshake_v1:");
        fp = fnv1a_64_update_bytes(fp, module_path.as_bytes());
        fp = fnv1a_64_update_u64(fp, net_schema_fingerprint);
        fp = fnv1a_64_update_u64(fp, sorted_comps.len() as u64);
        for c in sorted_comps {
            fp = fnv1a_64_update_bytes(fp, c.canonical_name.as_bytes());
            fp = fnv1a_64_update_u64(fp, c.schema_fingerprint);
            fp = fnv1a_64_update_u64(fp, u64::from(c.is_resource));
            fp = fnv1a_64_update_u64(fp, u64::from(c.is_replicated));
            fp = fnv1a_64_update_u64(
                fp,
                match c.reliability {
                    NetReliability::Reliable => 0,
                    NetReliability::Unreliable => 1,
                },
            );
            fp = fnv1a_64_update_u64(fp, c.rate_hz.map_or(0, f64::to_bits));
            fp = fnv1a_64_update_u64(fp, u64::from(c.interval_ticks.unwrap_or(0)));
            fp = fnv1a_64_update_u64(fp, u64::from(c.channel));
            fp = fnv1a_64_update_u64(
                fp,
                match c.authority {
                    AuthorityKind::Unspecified => 0,
                    AuthorityKind::Server => 1,
                    AuthorityKind::Client => 2,
                    AuthorityKind::Predicted => 3,
                    AuthorityKind::Shared => 4,
                },
            );
            fp = fnv1a_64_update_u64(fp, u64::from(c.is_predicted));
            fp = fnv1a_64_update_u64(fp, u64::from(c.packed_bits));
            fp = fnv1a_64_update_u64(fp, u64::from(c.packed_bytes));
            fp = hash_quantize_specs(fp, &c.quantize_specs);
        }
        fp = fnv1a_64_update_u64(fp, sorted_rpcs.len() as u64);
        for r in sorted_rpcs {
            fp = fnv1a_64_update_bytes(fp, r.canonical_name.as_bytes());
            fp = fnv1a_64_update_u64(fp, r.schema_fingerprint);
            fp = fnv1a_64_update_u64(fp, u64::from(r.packed_bits));
            fp = fnv1a_64_update_u64(fp, u64::from(r.packed_bytes));
            fp = hash_quantize_specs(fp, &r.quantize_specs);
        }
        fp.max(1)
    };

    MirNetHandshake {
        module_net_fingerprint,
        component_fingerprints,
        rpc_fingerprints,
    }
}

fn build_net_stream_ops(
    module_path: &str,
    net_components: &[MirNetComponent],
    rpcs: &[MirRpc],
) -> Vec<MirStreamOp> {
    let has_net = net_components
        .iter()
        .any(|c| c.is_replicated || !c.quantize_specs.is_empty())
        || !rpcs.is_empty();
    if !has_net {
        return Vec::new();
    }
    let mut channels = BTreeSet::new();
    for nc in net_components {
        if nc.is_replicated {
            channels.insert(nc.channel);
        }
    }
    for rpc in rpcs {
        channels.insert(rpc.channel);
    }
    if channels.is_empty() {
        channels.insert(0);
    }
    let canonical_stream = format!("{module_path}::StrataNetPacket");
    let mut ops = Vec::new();
    for ch in channels {
        ops.push(MirStreamOp {
            kind: MirStreamOpKind::StreamRead,
            stream: "StrataNetPacket".to_owned(),
            canonical_stream: canonical_stream.clone(),
            requires_outside_par: true,
            channel: Some(ch),
        });
        ops.push(MirStreamOp {
            kind: MirStreamOpKind::StreamWriteBatch,
            stream: "StrataNetPacket".to_owned(),
            canonical_stream: canonical_stream.clone(),
            requires_outside_par: true,
            channel: Some(ch),
        });
    }
    ops
}
