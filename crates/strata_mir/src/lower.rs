//! Direct typed-HIR -> executable SSA CFG `StrataMir` lowering pipeline.
//!
//! Zero string-splitting or `source_body.contains(...)` heuristics; every expression, statement,
//! query, control-flow construct, primitive operation, migration, and synthesized timer tick lowers
//! to complete verifiable basic blocks and SSA registers.

use crate::ir::{
    BlockId, Inst, LocalId, MirConstVal, MirFnKind, MirFunction, MirModule, MirParam,
    MirQueryBinding, MirQueryTermBinding, MirResourceBinding, MirStmt, MirType, Terminator,
};
use crate::passes;
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use strata_sema::access::{QueryAccessDesc, QueryTerm, TermAccessMode};
use strata_sema::hir::{
    AnalyzedModule, HirAssignOp, HirBinOp, HirCall, HirCallable, HirCompInit, HirCurve, HirExpr,
    HirFn, HirFor, HirForIter, HirLValue, HirMatch, HirMigration, HirParam, HirParamKind,
    HirPattern, HirQuery, HirReduceEntry, HirSchedule, HirScheduleGroup, HirSpawn, HirStmt,
    HirTable, HirTimeline, HirUnOp,
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
    pub(crate) tables: HashMap<String, HirTable>,
    pub(crate) curves: HashMap<String, HirCurve>,
    pub(crate) timelines: HashMap<String, HirTimeline>,
    pub(crate) objects: HashSet<String>,
    pub(crate) fn_ret_tys: HashMap<String, MirType>,
    pub(crate) field_defaults: IndexMap<String, IndexMap<String, MirConstVal>>,
}

impl MirLowerCtx {
    /// Constructs a lowering context from an analyzed module.
    pub(crate) fn from_analyzed(analyzed: &AnalyzedModule) -> Self {
        let mut const_vals = HashMap::new();
        for c in &analyzed.consts {
            if let Some(ref ex) = c.expr
                && let Some(val) = eval_hir_const(ex, &const_vals, &analyzed.enums)
            {
                const_vals.insert(c.name.clone(), val);
            }
        }

        let mut field_defaults: IndexMap<String, IndexMap<String, MirConstVal>> = IndexMap::new();
        for (layout_key, fields) in &analyzed.field_defaults {
            let mut eval_map = IndexMap::new();
            for (fname, fexpr) in fields {
                if let Some(val) = eval_hir_const(fexpr, &const_vals, &analyzed.enums) {
                    eval_map.insert(fname.clone(), val);
                }
            }
            if !eval_map.is_empty() {
                field_defaults.insert(layout_key.clone(), eval_map);
            }
        }

        let all_layouts = deduplicate_layouts(analyzed.layouts.values().cloned());
        let layouts_by_key = index_layouts(&analyzed.layouts);

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

        Self {
            module_path: analyzed.module_path.clone(),
            is_deterministic: analyzed.is_deterministic,
            layouts_by_key,
            all_layouts,
            enums: analyzed.enums.clone(),
            const_vals,
            tables,
            curves,
            timelines,
            objects,
            fn_ret_tys,
            field_defaults,
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
        let mut const_vals = HashMap::new();
        for c in &module.consts {
            if let Some(ref ex) = c.expr
                && let Some(val) = eval_hir_const(ex, &const_vals, &enums_map)
            {
                const_vals.insert(c.name.clone(), val);
            }
        }
        let mut raw_layouts = IndexMap::new();
        for l in &module.layouts {
            raw_layouts.insert(l.canonical_name.clone(), l.clone());
        }
        let layouts_by_key = index_layouts(&raw_layouts);
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

        Self {
            module_path: module.module_path.clone(),
            is_deterministic: module.is_deterministic,
            layouts_by_key,
            all_layouts: module.layouts.clone(),
            enums: enums_map,
            const_vals,
            tables,
            curves,
            timelines,
            objects,
            fn_ret_tys,
            field_defaults: module.field_defaults.clone(),
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
                        return (offset as u32, MirType::F32, Ty::F32);
                    }
                }
            } else {
                return (offset as u32, MirType::F32, Ty::F32);
            }
        }
        (offset as u32, mir_ty_from_hir(&cur_ty), cur_ty)
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
        Ty::Vec2 | Ty::IVec2 | Ty::UVec2 => MirType::Vec2,
        Ty::Vec3 | Ty::Vec3a | Ty::IVec3 => MirType::Vec3,
        Ty::Vec4 | Ty::Quat | Ty::Rgba => MirType::Vec4,
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
        Ty::Unit | Ty::Unknown | Ty::BannedWire(_) => MirType::Unit,
    }
}

/// Evaluates a constant [`HirExpr`] into a [`MirConstVal`].
pub(crate) fn eval_hir_const(
    expr: &HirExpr,
    consts: &HashMap<String, MirConstVal>,
    enums: &IndexMap<String, EnumDef>,
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
            match name.as_str() {
                "vec2::ZERO" => Some(MirConstVal::Vec2([0.0, 0.0])),
                "vec2::ONE" => Some(MirConstVal::Vec2([1.0, 1.0])),
                "vec3::ZERO" => Some(MirConstVal::Vec3([0.0, 0.0, 0.0])),
                "vec3::ONE" => Some(MirConstVal::Vec3([1.0, 1.0, 1.0])),
                "vec3::UP" | "vec3::Y" => Some(MirConstVal::Vec3([0.0, 1.0, 0.0])),
                "vec3::X" => Some(MirConstVal::Vec3([1.0, 0.0, 0.0])),
                "vec3::Z" => Some(MirConstVal::Vec3([0.0, 0.0, 1.0])),
                "vec4::ZERO" => Some(MirConstVal::Vec4([0.0, 0.0, 0.0, 0.0])),
                "vec4::ONE" => Some(MirConstVal::Vec4([1.0, 1.0, 1.0, 1.0])),
                _ => {
                    if let Some((en, var)) = name.split_once("::")
                        && let Some(edef) = enums.get(en)
                        && let Some((_, d)) = edef.variants.iter().find(|(v, _)| v == var)
                    {
                        return Some(MirConstVal::Int(*d));
                    }
                    None
                }
            }
        }
        HirExpr::Unary { op, expr, .. } => {
            let v = eval_hir_const(expr, consts, enums)?;
            match (op, v) {
                (HirUnOp::Neg, MirConstVal::Int(i)) => Some(MirConstVal::Int(-i)),
                (HirUnOp::Neg, MirConstVal::Float(f)) => Some(MirConstVal::Float(-f)),
                (HirUnOp::Not, MirConstVal::Bool(b)) => Some(MirConstVal::Bool(!b)),
                (HirUnOp::Not, MirConstVal::Int(i)) => Some(MirConstVal::Int(!i)),
                _ => None,
            }
        }
        HirExpr::Binary { op, lhs, rhs, .. } => {
            let l = eval_hir_const(lhs, consts, enums)?;
            let r = eval_hir_const(rhs, consts, enums)?;
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
                    let fa = const_as_f64(&a)?;
                    let fb = const_as_f64(&b)?;
                    let res = match op {
                        HirBinOp::Add => fa + fb,
                        HirBinOp::Sub => fa - fb,
                        HirBinOp::Mul => fa * fb,
                        HirBinOp::Div if fb != 0.0 => fa / fb,
                        _ => return None,
                    };
                    res.is_finite().then_some(MirConstVal::Float(res))
                }
            }
        }
        HirExpr::Call(call) => {
            let mut vals = Vec::with_capacity(call.args.len());
            for a in &call.args {
                vals.push(eval_hir_const(a, consts, enums)?);
            }
            match call.callee.as_str() {
                "vec2" if vals.len() == 2 => Some(MirConstVal::Vec2([
                    const_as_f64(&vals[0])?,
                    const_as_f64(&vals[1])?,
                ])),
                "vec3" if vals.len() == 3 => Some(MirConstVal::Vec3([
                    const_as_f64(&vals[0])?,
                    const_as_f64(&vals[1])?,
                    const_as_f64(&vals[2])?,
                ])),
                "vec4" if vals.len() == 4 => Some(MirConstVal::Vec4([
                    const_as_f64(&vals[0])?,
                    const_as_f64(&vals[1])?,
                    const_as_f64(&vals[2])?,
                    const_as_f64(&vals[3])?,
                ])),
                "bits" | "meters" | "sec" | "rad" | "deg" | "mps" | "mps2" | "hz" | "frames"
                    if vals.len() == 1 =>
                {
                    Some(vals.into_iter().next().unwrap_or(MirConstVal::Unit))
                }
                _ => None,
            }
        }
        HirExpr::ArrayLit { elems, .. } => {
            let mut out = Vec::with_capacity(elems.len());
            for it in elems {
                out.push(eval_hir_const(it, consts, enums)?);
            }
            Some(MirConstVal::Array(out))
        }
        HirExpr::StructLit { name, fields, .. } => {
            let mut out = Vec::with_capacity(fields.len());
            for (fname, fexpr) in fields {
                out.push((fname.clone(), eval_hir_const(fexpr, consts, enums)?));
            }
            Some(MirConstVal::Struct {
                name: name.clone(),
                fields: out,
            })
        }
        HirExpr::Cast { expr, target_ty } => {
            let v = eval_hir_const(expr, consts, enums)?;
            match target_ty {
                Ty::F32 | Ty::F64 => const_as_f64(&v).map(MirConstVal::Float),
                Ty::U8 | Ty::U16 | Ty::U32 | Ty::U64 | Ty::I8 | Ty::I16 | Ty::I32 | Ty::I64 => {
                    match v {
                        MirConstVal::Int(i) => Some(MirConstVal::Int(i)),
                        MirConstVal::Float(f) if f.is_finite() => Some(MirConstVal::Int(f as i64)),
                        _ => None,
                    }
                }
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
                    self.func.params.push(MirParam {
                        name: p.name.clone(),
                        ty: MirType::Ptr,
                        kind: p.kind,
                        local: Some(pl),
                    });
                    self.vars.insert(
                        p.name.clone(),
                        VarSlot::EventPayloadPtr {
                            ptr_local: pl,
                            layout_key: match &p.ty {
                                Ty::Named(n) => self.ctx.resolve_canonical(n),
                                _ => String::new(),
                            },
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
                    self.func.params.push(MirParam {
                        name: p.name.clone(),
                        ty: ptr_ty,
                        kind: p.kind,
                        local: Some(pl),
                    });
                    let layout_key = match &p.ty {
                        Ty::Named(n) | Ty::Ref(n) => self.ctx.resolve_canonical(n),
                        _ => String::new(),
                    };
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
        let mut without_filters = std::collections::BTreeSet::new();
        for f in &hq.without_filters {
            without_filters.insert(f.clone());
        }
        self.func.queries.push(QueryAccessDesc {
            terms: terms_desc,
            with_filters,
            without_filters,
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
                    self.lower_stmts(else_block);
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
                let (val_l, val_ty) = self.lower_expr(value);
                let resolved_ty = ty
                    .as_ref()
                    .map(mir_ty_from_hir)
                    .filter(|t| *t != MirType::Unit)
                    .unwrap_or(val_ty);
                let resolved_hir = ty.clone().unwrap_or_else(|| value.ty());
                self.bind_pattern_value(pattern, val_l, resolved_ty, resolved_hir);
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
                self.loop_stack.push(LoopTarget {
                    continue_bb: hdr_bb,
                    break_bb: exit_bb,
                });
                self.lower_stmts(body);
                self.loop_stack.pop();
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
                self.loop_stack.push(LoopTarget {
                    continue_bb: body_bb,
                    break_bb: exit_bb,
                });
                self.lower_stmts(body);
                self.loop_stack.pop();
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
                self.atomic_rollback_stack.push((ckpt, rollback_bb));
                self.lower_stmts(&at.body);
                self.atomic_rollback_stack.pop();
                if !self.cur_terminated {
                    self.terminate(Terminator::Goto(merge_bb));
                }
                self.switch_to(rollback_bb);
                self.emit_void(Inst::CmdRollback { checkpoint: ckpt });
                self.lower_stmts(&at.on_rollback);
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
                let tgt_l = self.lower_expr(target).0;
                let ev_name = event_name_of_expr(event);
                let payload_l = self.lower_expr(event).0;
                self.emit_void(Inst::CmdTrigger {
                    event: ev_name,
                    target: Some(tgt_l),
                    payload: Some(payload_l),
                    propagate: *propagate,
                });
            }
            HirStmt::Emit(ev) => {
                let sname = event_name_of_expr(ev);
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
                let (l_id, l_ty) = self.lower_expr(lhs);
                let (r_id, r_ty) = self.lower_expr(rhs);
                let op_s = binop_str(*op);
                let res_ty = if is_cmp_binop(*op) {
                    MirType::Bool
                } else if *ty != Ty::Unknown && *ty != Ty::Unit {
                    mir_ty_from_hir(ty)
                } else if matches!(l_ty, MirType::Vec2 | MirType::Vec3 | MirType::Vec4) {
                    l_ty
                } else if matches!(r_ty, MirType::Vec2 | MirType::Vec3 | MirType::Vec4) {
                    r_ty
                } else {
                    l_ty
                };
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
            HirExpr::ArrayLit { elems, .. } => {
                let mut elem_ids = Vec::with_capacity(elems.len());
                let mut elem_ty = MirType::F32;
                for it in elems {
                    let (l, t) = self.lower_expr(it);
                    elem_ty = t;
                    elem_ids.push(l);
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
                let (component, data_l) = match value.as_ref() {
                    HirExpr::StructLit { name, fields, .. } => {
                        let fl = self.build_comp_fields(name, fields);
                        let dl = self.alloc_and_emit(
                            &format!("ins_{name}"),
                            MirType::Named(name.clone()),
                            Inst::StructInit {
                                type_name: name.clone(),
                                fields: fl,
                            },
                        );
                        (name.clone(), dl)
                    }
                    other => {
                        let cname = match other.ty() {
                            Ty::Named(n) => n,
                            _ => "Component".to_owned(),
                        };
                        let dl = self.lower_expr(other).0;
                        (cname, dl)
                    }
                };
                self.emit_void(Inst::CmdInsert {
                    entity: ent_l,
                    component,
                    data: Some(data_l),
                    if_new: *if_new,
                });
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
                self.lower_stmts(stmts);
                if let Some(t) = tail {
                    self.lower_expr(t)
                } else {
                    let rty = mir_ty_from_hir(ty);
                    let u = self.alloc_and_emit(
                        "blk_unit",
                        rty.clone(),
                        Inst::ConstBool { value: false },
                    );
                    (u, rty)
                }
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
                    let p = binding.row_ptr.unwrap_or(binding.col_ptr);
                    (p, MirType::Ptr)
                }
                VarSlot::SpatialCandidate { entity, .. } => (entity, MirType::Entity),
                VarSlot::TriggerCtx { .. } => {
                    let l = self.alloc_and_emit("trg_ent", MirType::Entity, Inst::TriggerTarget);
                    (l, MirType::Entity)
                }
            };
        }

        // Vector constants (`vec2::ZERO`, `vec3::ZERO`, `vec3::UP`, ...)
        if let Some(vec_c) = vec_path_constant(name) {
            return match vec_c {
                MirConstVal::Vec2(v) => (
                    self.alloc_and_emit(
                        "vec2_c",
                        MirType::Vec2,
                        Inst::ConstVec {
                            dims: 2,
                            values: [v[0], v[1], 0.0, 0.0],
                        },
                    ),
                    MirType::Vec2,
                ),
                MirConstVal::Vec3(v) => (
                    self.alloc_and_emit(
                        "vec3_c",
                        MirType::Vec3,
                        Inst::ConstVec {
                            dims: 3,
                            values: [v[0], v[1], v[2], 0.0],
                        },
                    ),
                    MirType::Vec3,
                ),
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
            MirConstVal::Vec2(v) => (
                self.alloc_and_emit(
                    hint,
                    MirType::Vec2,
                    Inst::ConstVec {
                        dims: 2,
                        values: [v[0], v[1], 0.0, 0.0],
                    },
                ),
                MirType::Vec2,
            ),
            MirConstVal::Vec3(v) => (
                self.alloc_and_emit(
                    hint,
                    MirType::Vec3,
                    Inst::ConstVec {
                        dims: 3,
                        values: [v[0], v[1], v[2], 0.0],
                    },
                ),
                MirType::Vec3,
            ),
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
                let mut ids = Vec::with_capacity(elems.len());
                let mut ety = MirType::F32;
                for e in elems {
                    let (id, t) = self.materialize_const_val(hint, e, MirType::Unit);
                    ety = t;
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
                let mut fl = Vec::with_capacity(fields.len());
                for (fnm, fv) in fields {
                    let (fid, _) = self.materialize_const_val(fnm, fv, MirType::Unit);
                    fl.push((fnm.clone(), fid));
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
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for (fname, fexpr) in explicit {
            seen.insert(fname.clone());
            let (fl, _) = self.lower_expr(fexpr);
            out.push((fname.clone(), fl));
        }
        if let Some(defs) = self.ctx.layout_defaults(comp_name).cloned() {
            for (dfname, dval) in defs {
                if seen.insert(dfname.clone()) {
                    let (fl, _) = self.materialize_const_val(&dfname, &dval, MirType::Unit);
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
                    let fpath = match binding.field_name {
                        Some(ref prefix) => format!("{prefix}.{field}"),
                        None => field.to_owned(),
                    };
                    return self.emit_term_field_load(&binding, &fpath);
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
            && let HirExpr::Path { name: row_name, .. } = inner_base.as_ref()
            && let Some(VarSlot::RowAlias { terms, .. }) = self.vars.get(row_name).cloned()
            && let Some(tb) = terms.get(term_alias)
        {
            if let Some(ref projected_field) = tb.field_name {
                // `hero.vel.y` where `vel: &Vel2D.dxy`: load vec field then extract lane
                let (vec_l, vec_ty) = self.emit_term_field_load(tb, projected_field);
                if matches!(vec_ty, MirType::Vec2 | MirType::Vec3 | MirType::Vec4) {
                    return self.extract_vec_field(vec_l, field);
                }
                let nested = format!("{projected_field}.{field}");
                return self.emit_term_field_load(tb, &nested);
            }
            // Normal `row.comp.field`
            return self.emit_term_field_load(tb, field);
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
        if matches!(base_ty, MirType::Vec2 | MirType::Vec3 | MirType::Vec4) && is_vec_swizzle(field)
        {
            return self.extract_vec_field(base_l, field);
        }
        if base_ty == MirType::Ptr || base_ty == MirType::MutPtr {
            let layout_key = match base.ty() {
                Ty::Named(n) | Ty::Ref(n) => self.ctx.resolve_canonical(&n),
                _ => String::new(),
            };
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
        if let MirType::Named(ref tname) = base_ty
            && let Some(last_stmt) = self.func.blocks[self.cur_bb.0 as usize].stmts.last_mut()
            && let Inst::TableLoad {
                ref table_name,
                field: ref mut tf,
                ..
            } = last_stmt.inst
            && table_name == tname
            && tf.is_empty()
        {
            *tf = field.to_owned();
            let fty = self
                .ctx
                .tables
                .get(tname)
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
        let lanes: Vec<u8> = swizzle.chars().filter_map(vec_char_lane).collect();
        if lanes.len() == 1 {
            let l = self.alloc_and_emit(
                &format!("v_{swizzle}"),
                MirType::F32,
                Inst::VecExtract {
                    vec: vec_l,
                    lane: lanes[0],
                },
            );
            (l, MirType::F32)
        } else {
            let vty = match lanes.len() {
                2 => MirType::Vec2,
                3 => MirType::Vec3,
                _ => MirType::Vec4,
            };
            let l = self.alloc_and_emit(
                &format!("swiz_{swizzle}"),
                vty.clone(),
                Inst::VecSwizzle { vec: vec_l, lanes },
            );
            (l, vty)
        }
    }

    fn lower_assign(&mut self, target: &HirLValue, op: HirAssignOp, value: &HirExpr) {
        let (rhs_l, _) = self.lower_expr(value);
        match target {
            HirLValue::Local { name, .. } => {
                if let Some(VarSlot::Slot { slot_local, ty, .. }) = self.vars.get(name).cloned() {
                    let final_val = if op == HirAssignOp::Set {
                        rhs_l
                    } else {
                        let cur = self.alloc_and_emit(
                            name,
                            ty.clone(),
                            Inst::SlotLoad { slot: slot_local },
                        );
                        let allow_fma = !self.ctx.is_deterministic
                            && !self.func.is_deterministic
                            && matches!(ty, MirType::F32 | MirType::F64);
                        self.alloc_and_emit(
                            "upd",
                            ty,
                            Inst::BinOp {
                                op: assign_op_str(op).to_owned(),
                                lhs: cur,
                                rhs: rhs_l,
                                allow_fma,
                            },
                        )
                    };
                    self.emit_void(Inst::SlotStore {
                        slot: slot_local,
                        val: final_val,
                    });
                }
            }
            HirLValue::Field { base, field, .. } => match base.as_ref() {
                HirLValue::ResourceAccess { resource, .. } => {
                    let layout_key = self.ctx.resolve_canonical(resource);
                    let ptr = self.alloc_and_emit(
                        &format!("res_mut_{resource}"),
                        MirType::MutPtr,
                        Inst::ResWrite {
                            resource: resource.clone(),
                        },
                    );
                    self.store_ptr_field(ptr, &layout_key, field, op, rhs_l);
                }
                HirLValue::Local { name, .. } => {
                    if let Some(slot) = self.vars.get(name).cloned() {
                        match slot {
                            VarSlot::RowAlias { terms, .. } => {
                                if let Some(tb) = terms.get(field)
                                    && let Some(ref proj_field) = tb.field_name
                                {
                                    self.store_term_field(tb, proj_field, op, rhs_l);
                                }
                            }
                            VarSlot::SingleTermPtr { binding } => {
                                let fpath = match binding.field_name {
                                    Some(ref p) => format!("{p}.{field}"),
                                    None => field.clone(),
                                };
                                self.store_term_field(&binding, &fpath, op, rhs_l);
                            }
                            VarSlot::ResPtr {
                                ptr_local,
                                layout_key,
                                ..
                            } => {
                                self.store_ptr_field(ptr_local, &layout_key, field, op, rhs_l);
                            }
                            VarSlot::Slot { slot_local, ty, .. }
                                if matches!(ty, MirType::Vec2 | MirType::Vec3 | MirType::Vec4) =>
                            {
                                if let Some(lane) = vec_lane_index(field) {
                                    let vec_cur = self.alloc_and_emit(
                                        name,
                                        ty.clone(),
                                        Inst::SlotLoad { slot: slot_local },
                                    );
                                    let scalar_val = if op == HirAssignOp::Set {
                                        rhs_l
                                    } else {
                                        let cur_lane = self.alloc_and_emit(
                                            field,
                                            MirType::F32,
                                            Inst::VecExtract { vec: vec_cur, lane },
                                        );
                                        self.alloc_and_emit(
                                            "vupd",
                                            MirType::F32,
                                            Inst::BinOp {
                                                op: assign_op_str(op).to_owned(),
                                                lhs: cur_lane,
                                                rhs: rhs_l,
                                                allow_fma: !self.ctx.is_deterministic
                                                    && !self.func.is_deterministic,
                                            },
                                        )
                                    };
                                    let new_vec = self.alloc_and_emit(
                                        "vins",
                                        ty,
                                        Inst::VecInsert {
                                            vec: vec_cur,
                                            lane,
                                            val: scalar_val,
                                        },
                                    );
                                    self.emit_void(Inst::SlotStore {
                                        slot: slot_local,
                                        val: new_vec,
                                    });
                                }
                            }
                            VarSlot::Slot { slot_local, ty, .. } => {
                                let layout_key = match &ty {
                                    MirType::Named(n) => self.ctx.resolve_canonical(n),
                                    _ => String::new(),
                                };
                                let ptr = self.alloc_and_emit(
                                    name,
                                    MirType::MutPtr,
                                    Inst::SlotLoad { slot: slot_local },
                                );
                                self.store_ptr_field(ptr, &layout_key, field, op, rhs_l);
                            }
                            _ => {}
                        }
                    }
                }
                HirLValue::Field {
                    base: inner_base,
                    field: term_alias,
                    ..
                } => match inner_base.as_ref() {
                    HirLValue::Local { name: row_name, .. } => {
                        if let Some(VarSlot::RowAlias { terms, .. }) =
                            self.vars.get(row_name).cloned()
                            && let Some(tb) = terms.get(term_alias)
                        {
                            if let Some(ref proj_field) = tb.field_name {
                                if let Some(lane) = vec_lane_index(field) {
                                    self.store_term_vec_lane(tb, proj_field, lane, op, rhs_l);
                                } else {
                                    let nested = format!("{proj_field}.{field}");
                                    self.store_term_field(tb, &nested, op, rhs_l);
                                }
                            } else {
                                self.store_term_field(tb, field, op, rhs_l);
                            }
                        } else if let Some(VarSlot::SingleTermPtr { binding }) =
                            self.vars.get(row_name).cloned()
                        {
                            let full = match binding.field_name {
                                Some(ref p) => format!("{p}.{term_alias}.{field}"),
                                None => format!("{term_alias}.{field}"),
                            };
                            self.store_term_field(&binding, &full, op, rhs_l);
                        }
                    }
                    HirLValue::Field {
                        base: r_base,
                        field: t_alias,
                        ..
                    } => {
                        if let HirLValue::Local { name: r_name, .. } = r_base.as_ref()
                            && let Some(VarSlot::RowAlias { terms, .. }) =
                                self.vars.get(r_name).cloned()
                            && let Some(tb) = terms.get(t_alias)
                        {
                            if let Some(lane) = vec_lane_index(field) {
                                self.store_term_vec_lane(tb, term_alias, lane, op, rhs_l);
                            } else {
                                let nested = format!("{term_alias}.{field}");
                                self.store_term_field(tb, &nested, op, rhs_l);
                            }
                        }
                    }
                    _ => {}
                },
                _ => {}
            },
            HirLValue::Index { base: _, index, .. } => {
                let _ = self.lower_expr(index);
            }
            HirLValue::ResourceAccess { resource, .. } => {
                let _ = self.alloc_and_emit(
                    &format!("res_mut_{resource}"),
                    MirType::MutPtr,
                    Inst::ResWrite {
                        resource: resource.clone(),
                    },
                );
            }
        }
    }

    fn store_term_field(
        &mut self,
        tb: &TermAccessBinding,
        field: &str,
        op: HirAssignOp,
        rhs_l: LocalId,
    ) {
        let base_ptr = tb.row_ptr.unwrap_or(tb.col_ptr);
        self.store_ptr_field(base_ptr, &tb.canonical_layout, field, op, rhs_l);
    }

    fn store_term_vec_lane(
        &mut self,
        tb: &TermAccessBinding,
        vec_field: &str,
        lane: u8,
        op: HirAssignOp,
        rhs_l: LocalId,
    ) {
        let base_ptr = tb.row_ptr.unwrap_or(tb.col_ptr);
        let (offset, fty, _) = self.ctx.resolve_field(&tb.canonical_layout, vec_field);
        let vec_cur = self.alloc_and_emit(
            vec_field,
            fty.clone(),
            Inst::FieldLoad {
                base_ptr,
                layout_key: tb.canonical_layout.clone(),
                field: vec_field.to_owned(),
                offset_bytes: offset,
                field_ty: fty,
            },
        );
        let scalar_val = if op == HirAssignOp::Set {
            rhs_l
        } else {
            let cur_lane = self.alloc_and_emit(
                "lane_cur",
                MirType::F32,
                Inst::VecExtract { vec: vec_cur, lane },
            );
            self.alloc_and_emit(
                "lane_upd",
                MirType::F32,
                Inst::BinOp {
                    op: assign_op_str(op).to_owned(),
                    lhs: cur_lane,
                    rhs: rhs_l,
                    allow_fma: !self.ctx.is_deterministic && !self.func.is_deterministic,
                },
            )
        };
        let new_vec = self.alloc_and_emit(
            "vec_ins",
            MirType::Vec3,
            Inst::VecInsert {
                vec: vec_cur,
                lane,
                val: scalar_val,
            },
        );
        self.emit_void(Inst::FieldStore {
            base_ptr,
            layout_key: tb.canonical_layout.clone(),
            field: vec_field.to_owned(),
            offset_bytes: offset,
            val: new_vec,
        });
    }

    fn store_ptr_field(
        &mut self,
        base_ptr: LocalId,
        layout_key: &str,
        field: &str,
        op: HirAssignOp,
        rhs_l: LocalId,
    ) {
        let (offset, fty, _) = self.ctx.resolve_field(layout_key, field);
        let final_val = if op == HirAssignOp::Set {
            rhs_l
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
                    rhs: rhs_l,
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
            self.lower_expr(a).0
        } else {
            self.alloc_and_emit("i_def", ty, Inst::ConstInt { value: default })
        }
    }

    fn lower_call(&mut self, call: &HirCall) -> (LocalId, MirType) {
        match call.callee.as_str() {
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
            "vec2" => {
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
            "vec3" => {
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
            "vec4" => {
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
            "bits" | "meters" | "sec" | "ms" | "rad" | "deg" | "mps" | "mps2" | "hz" | "frames" => {
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
            "as_secs" | "raw" | "unwrap" => return self.lower_expr(receiver),
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
                let grid_name = receiver_resource_name(receiver);
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
                let history_name = receiver_resource_name(receiver);
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

    fn lower_primitive_field_ptr(&mut self, receiver: &HirExpr) -> LocalId {
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
                        let (offset, _, _) =
                            self.ctx.resolve_field(&binding.canonical_layout, field);
                        return self.alloc_and_emit(
                            &format!("ptr_{field}"),
                            MirType::MutPtr,
                            Inst::FieldPtr {
                                base_ptr,
                                layout_key: binding.canonical_layout,
                                field: field.clone(),
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
            if !is_opt && present_check.is_none() {
                let null_l =
                    self.alloc_and_emit("null_p", MirType::Ptr, Inst::ConstInt { value: 0 });
                present_check = Some(self.alloc_and_emit(
                    "has_row",
                    MirType::Bool,
                    Inst::BinOp {
                        op: "!=".to_owned(),
                        lhs: ptr_l,
                        rhs: null_l,
                        allow_fma: false,
                    },
                ));
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
                },
            );
        }
        let cond = present_check.unwrap_or_else(|| {
            self.alloc_and_emit("has_row", MirType::Bool, Inst::ConstBool { value: true })
        });
        (cond, Some(ent_l), term_map)
    }

    fn eval_optional_source(&mut self, expr: &HirExpr) -> OptionalEvalResult {
        match expr {
            HirExpr::Query(hq) if hq.is_point_lookup => {
                let (cond, ent, terms) = self.emit_query_one_lookup(hq);
                (cond, Some((ent, terms)), None)
            }
            HirExpr::Field { base, field, .. } => {
                if let HirExpr::Path { name: row_name, .. } = base.as_ref()
                    && let Some(VarSlot::RowAlias { terms, .. }) = self.vars.get(row_name).cloned()
                    && let Some(tb) = terms.get(field)
                    && let Some(pres) = tb.present_local
                {
                    return (pres, None, Some(tb.clone()));
                }
                let (l, _) = self.lower_expr(expr);
                (l, None, None)
            }
            _ => {
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

    fn bind_pattern_to_single_term(&mut self, pat: &HirPattern, binding: TermAccessBinding) {
        if let Some(name) = extract_some_inner_binding(pat) {
            self.vars.insert(name, VarSlot::SingleTermPtr { binding });
        }
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
            for (idx, arm) in hm.arms.iter().enumerate() {
                let arm_bb = self.new_block(&format!("match_arm_{idx}"));
                if let Some(disc) = self.arm_const_disc(&arm.pattern) {
                    cases.push((disc as u32, arm_bb));
                } else if default_bb.is_none() {
                    default_bb = Some(arm_bb);
                }
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
                self.switch_to(arm_bb);
                self.bind_pattern_value(&arm.pattern, scrut_l, scrut_ty.clone(), hm.scrutinee.ty());
                let (aval, _) = self.lower_expr(&arm.body);
                if let Some(slot) = res_slot {
                    self.emit_void(Inst::SlotStore { slot, val: aval });
                }
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
                self.bind_pattern_value(&hf.binding, cur_i, idx_ty.clone(), start.ty());
                self.loop_stack.push(LoopTarget {
                    continue_bb: inc_bb,
                    break_bb: exit_bb,
                });
                self.lower_stmts(&hf.body);
                self.loop_stack.pop();
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
                let c_l = self.lower_expr(center).0;
                let r_l = self.lower_expr(radius).0;
                let sp_l = self.alloc_and_emit(
                    "disc_iter",
                    MirType::QueryIter,
                    Inst::SpatialQueryDisc {
                        grid_name: grid.clone(),
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
                let tick_l = self.lower_expr(tick).0;
                let s_l = self.lower_expr(p0).0;
                let e_l = self.lower_expr(p1).0;
                let r_l =
                    self.alloc_and_emit("r_def", MirType::F32, Inst::ConstFloat { value: 0.5 });
                let sp_l = self.alloc_and_emit(
                    "seg_iter",
                    MirType::QueryIter,
                    Inst::SpatialQuerySegmentAt {
                        history_name: history.clone(),
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
                self.loop_stack.push(LoopTarget {
                    continue_bb: hdr_bb,
                    break_bb: exit_bb,
                });
                self.lower_stmts(&hf.body);
                self.loop_stack.pop();
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

        let has_chunk = if let Some(ref rel) = hq.up_relation {
            self.alloc_and_emit(
                "has_chunk",
                MirType::Bool,
                Inst::IterUpCascade {
                    query_idx: qi,
                    relation: rel.clone(),
                },
            )
        } else {
            self.alloc_and_emit(
                "has_chunk",
                MirType::Bool,
                Inst::IterNextChunk { query_idx: qi },
            )
        };
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
        let mut terms_map = HashMap::new();
        for (_ti, term, canonical_layout, col_ptr, present_local) in col_bindings {
            let stride = self
                .ctx
                .find_layout(&canonical_layout)
                .map_or(16, |l| l.size as u32);
            let rptr_ty = if term.mode.is_mutable() {
                MirType::MutPtr
            } else {
                MirType::Ptr
            };
            let row_ptr = self.alloc_and_emit(
                &format!("row_{}", term.alias),
                rptr_ty,
                Inst::RowPtr {
                    col_ptr,
                    row_idx,
                    stride_bytes: stride,
                    is_sparse: term.is_sparse,
                },
            );
            terms_map.insert(
                term.alias.clone(),
                TermAccessBinding {
                    canonical_layout,
                    field_name: term.field_name.clone(),
                    mode: term.mode,
                    col_ptr,
                    row_ptr: Some(row_ptr),
                    present_local,
                },
            );
        }

        if let HirPattern::Binding { name, .. } = pat {
            if hq.terms.len() == 1
                && let Some((alias, tb)) = terms_map.iter().next()
                && tb.field_name.is_some()
                && alias == name
            {
                // Single `.where(c == req.cell)` where binding name is `c`
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
                },
            );
        }
        if let HirPattern::Binding { name, .. } = pat {
            self.vars.insert(
                name.clone(),
                VarSlot::RowAlias {
                    entity_local: None,
                    terms: terms_map,
                },
            );
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

fn vec_path_constant(name: &str) -> Option<MirConstVal> {
    match name {
        "vec2::ZERO" => Some(MirConstVal::Vec2([0.0, 0.0])),
        "vec2::ONE" => Some(MirConstVal::Vec2([1.0, 1.0])),
        "vec3::ZERO" => Some(MirConstVal::Vec3([0.0, 0.0, 0.0])),
        "vec3::ONE" => Some(MirConstVal::Vec3([1.0, 1.0, 1.0])),
        "vec3::UP" | "vec3::Y" => Some(MirConstVal::Vec3([0.0, 1.0, 0.0])),
        "vec3::X" => Some(MirConstVal::Vec3([1.0, 0.0, 0.0])),
        "vec3::Z" => Some(MirConstVal::Vec3([0.0, 0.0, 1.0])),
        "vec4::ZERO" => Some(MirConstVal::Vec4([0.0, 0.0, 0.0, 0.0])),
        "vec4::ONE" => Some(MirConstVal::Vec4([1.0, 1.0, 1.0, 1.0])),
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
        passes::atomic_tx::run(func);
    }
    // 4. Deterministic math & reduction order enforcement
    passes::determinism::run(&mut mir);

    mir
}

fn lower_helper_fn(ctx: &MirLowerCtx, hf: &HirFn) -> MirFunction {
    let mut func = MirFunction::new(&hf.name, MirFnKind::HelperFn);
    func.ret_ty = mir_ty_from_hir(&hf.ret_ty);
    func.is_deterministic = ctx.is_deterministic;
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
