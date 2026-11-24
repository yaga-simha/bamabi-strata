//! Unified provenance-based network authority checker (`E0501`) for Strata v2.0 HIR.
//!
//! Replaces all legacy parallel type/shape/value simulators with a single sound & precise
//! `Provenance` abstract interpreter over lowered HIR:
//! - Storage constructors (`let`, `Some`, `[...]`, `(...)`, `Struct { ... }`, `{ ... }`, by-value
//!   call arguments) decay rvalue provenance to `TempValue` **iff** the constructed value type is a
//!   copy-scalar (`is_copy_scalar_ty`).
//! - Transparent combinators (`if`, `match`, `block`, `(expr)`, `.unwrap()`, `.expect()`,
//!   `.unwrap_or(...)`, `.as_ref()`, `.as_mut()`, `.take()`, `.field`, `[index]`) preserve and join
//!   provenance without prematurely decaying copy-scalars.
//! - Helper `fn`s are summarized via fixed-point iteration over transitive server writes,
//!   mutated parameter indices, and symbolic parameter-to-return provenance flow.

use crate::diagnostics::{Diagnostic, Span, codes};
use crate::hir::{
    AuthorityKind, HirAssignOp, HirCall, HirCompInit, HirExpr, HirFn, HirForIter, HirFsm,
    HirLValue, HirObject, HirParamKind, HirPattern, HirQuery, HirQueryTerm, HirStmt, HirTask,
    HirTimeline, HirUnOp,
};
use crate::layout::{EnumDef, SolvedLayout};
use crate::types::Ty;
use indexmap::IndexMap;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Bitmask tracking which authority domains may originate or influence a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(dead_code)]
pub(crate) struct AuthoritySet(pub(crate) u8);

#[allow(dead_code)]
impl AuthoritySet {
    /// Empty authority set (`TempValue` / purely local computation).
    pub(crate) const EMPTY: Self = Self(0);
    /// Value originates from or aliases a `@authority(server)` ECS place.
    pub(crate) const SERVER: Self = Self(1 << 0);
    /// Value originates from or aliases a `@authority(client)` / `@predicted` ECS place.
    pub(crate) const CLIENT: Self = Self(1 << 1);

    /// Lattice least upper bound (`join`).
    #[inline]
    pub(crate) const fn join(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Returns `true` iff `self` is less than or equal to `other` in the subset order.
    #[inline]
    pub(crate) const fn is_subset_of(self, other: Self) -> bool {
        (self.0 & other.0) == self.0
    }

    /// Returns `true` iff `SERVER` authority is present.
    #[inline]
    pub(crate) const fn contains_server(self) -> bool {
        (self.0 & Self::SERVER.0) != 0
    }

    /// Returns `true` iff `CLIENT` authority is present.
    #[inline]
    #[allow(dead_code)]
    pub(crate) const fn contains_client(self) -> bool {
        (self.0 & Self::CLIENT.0) != 0
    }
}

/// Abstract place origin used to verify copy-vs-borrow provenance soundness and precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum PlaceOrigin {
    /// Purely local temporary or copied scalar value.
    TempValue,
    /// Borrow or non-scalar aggregate referencing an ECS place with authority `AuthoritySet`.
    EcsPlace(AuthoritySet),
}

#[allow(dead_code)]
impl PlaceOrigin {
    /// Decays an rvalue origin to [`PlaceOrigin::TempValue`] across a storage-constructor copy iff
    /// `is_copy_scalar` is `true`; otherwise preserves `self`.
    #[inline]
    pub(crate) const fn decay_on_storage_copy(self, is_copy_scalar: bool) -> Self {
        if is_copy_scalar {
            Self::TempValue
        } else {
            self
        }
    }

    /// Lattice least upper bound across control-flow branches.
    #[inline]
    pub(crate) const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::TempValue, o) | (o, Self::TempValue) => o,
            (Self::EcsPlace(a), Self::EcsPlace(b)) => Self::EcsPlace(a.join(b)),
        }
    }

    /// Returns the underlying [`AuthoritySet`].
    #[inline]
    pub(crate) const fn authority(self) -> AuthoritySet {
        match self {
            Self::TempValue => AuthoritySet::EMPTY,
            Self::EcsPlace(a) => a,
        }
    }
}

/// Structured provenance tree tracking direct ECS places, container elements/fields, `QueryRow`
/// terms, and symbolic helper-function parameter origins.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Provenance {
    /// Server-authoritative components directly rooted at this expression/place.
    direct: BTreeSet<String>,
    /// True when this value represents a multi-term or unprojected `QueryRow` (fat row handle).
    is_query_row: bool,
    /// True when this value represents a single-term projected ECS borrow (`&T` / `&mut T`).
    is_ecs_borrow: bool,
    /// Named fields (`QueryRow` term aliases, `StructLit`, `RecordLit`, `BundleLit`).
    fields: BTreeMap<String, Provenance>,
    /// Positional tuple elements.
    elems: Vec<Provenance>,
    /// Inner payload provenance for `Option<T>` / `query_one(...)`.
    opt_inner: Option<Box<Provenance>>,
    /// Joined element provenance for arrays / `SmallVec`.
    elem_join: Option<Box<Provenance>>,
    /// Symbolic 0-based helper `fn` parameter indices flowing into this value directly.
    param_origins: BTreeSet<usize>,
    /// `@authority(server)` component keys present on entities flowing into this value
    /// (for catching `despawn(e)` on server-authoritative entities without tainting `direct`).
    server_entity_comps: BTreeSet<String>,
    /// Symbolic 0-based helper `fn` parameter indices flowing into an `Entity` value for `despawn`.
    entity_param_origins: BTreeSet<usize>,
}

impl Provenance {
    fn empty() -> Self {
        Self::default()
    }

    fn direct_server(comp: impl Into<String>, is_ecs_borrow: bool) -> Self {
        let mut direct = BTreeSet::new();
        direct.insert(comp.into());
        Self {
            direct,
            is_ecs_borrow,
            ..Self::default()
        }
    }

    fn param(idx: usize) -> Self {
        let mut param_origins = BTreeSet::new();
        param_origins.insert(idx);
        let mut entity_param_origins = BTreeSet::new();
        entity_param_origins.insert(idx);
        Self {
            param_origins,
            entity_param_origins,
            ..Self::default()
        }
    }

    fn is_empty(&self) -> bool {
        self.direct.is_empty()
            && !self.is_query_row
            && !self.is_ecs_borrow
            && self.fields.is_empty()
            && self.elems.is_empty()
            && self.opt_inner.is_none()
            && self.elem_join.is_none()
            && self.param_origins.is_empty()
            && self.server_entity_comps.is_empty()
            && self.entity_param_origins.is_empty()
    }

    fn is_pure_leaf(&self) -> bool {
        !self.is_query_row
            && self.elems.is_empty()
            && self.opt_inner.is_none()
            && self.elem_join.is_none()
            && self.fields.is_empty()
    }

    fn collect_direct_and_deep_comps(&self, out: &mut BTreeSet<String>) {
        out.extend(self.direct.iter().cloned());
        for v in self.fields.values() {
            v.collect_direct_and_deep_comps(out);
        }
        for e in &self.elems {
            e.collect_direct_and_deep_comps(out);
        }
        if let Some(ref inner) = self.opt_inner {
            inner.collect_direct_and_deep_comps(out);
        }
        if let Some(ref elem) = self.elem_join {
            elem.collect_direct_and_deep_comps(out);
        }
    }

    fn deep_comps(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        self.collect_direct_and_deep_comps(&mut out);
        out
    }

    fn collect_deep_params(&self, out: &mut BTreeSet<usize>) {
        out.extend(self.param_origins.iter().copied());
        for v in self.fields.values() {
            v.collect_deep_params(out);
        }
        for e in &self.elems {
            e.collect_deep_params(out);
        }
        if let Some(ref inner) = self.opt_inner {
            inner.collect_deep_params(out);
        }
        if let Some(ref elem) = self.elem_join {
            elem.collect_deep_params(out);
        }
    }

    fn deep_params(&self) -> BTreeSet<usize> {
        let mut out = BTreeSet::new();
        self.collect_deep_params(&mut out);
        out
    }

    fn join(&self, other: &Self) -> Self {
        if self.is_empty() {
            return other.clone();
        }
        if other.is_empty() {
            return self.clone();
        }
        let mut direct = self.direct.clone();
        direct.extend(other.direct.iter().cloned());

        let mut param_origins = self.param_origins.clone();
        param_origins.extend(other.param_origins.iter().copied());

        let mut fields = self.fields.clone();
        for (k, v) in &other.fields {
            fields
                .entry(k.clone())
                .and_modify(|existing| *existing = existing.join(v))
                .or_insert_with(|| v.clone());
        }

        let mut elem_join = match (&self.elem_join, &other.elem_join) {
            (Some(a), Some(b)) => Some(Box::new(a.join(b))),
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        };

        let elems = if self.elems.is_empty() {
            other.elems.clone()
        } else if other.elems.is_empty() {
            self.elems.clone()
        } else if self.elems.len() == other.elems.len() {
            self.elems
                .iter()
                .zip(other.elems.iter())
                .map(|(a, b)| a.join(b))
                .collect()
        } else {
            let mut merged = elem_join.take().map(|b| *b).unwrap_or_default();
            for e in self.elems.iter().chain(other.elems.iter()) {
                merged = merged.join(e);
            }
            if !merged.is_empty() {
                elem_join = Some(Box::new(merged));
            }
            Vec::new()
        };

        let opt_inner = match (&self.opt_inner, &other.opt_inner) {
            (Some(a), Some(b)) => Some(Box::new(a.join(b))),
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        };

        let mut server_entity_comps = self.server_entity_comps.clone();
        server_entity_comps.extend(other.server_entity_comps.iter().cloned());

        let mut entity_param_origins = self.entity_param_origins.clone();
        entity_param_origins.extend(other.entity_param_origins.iter().copied());

        Self {
            direct,
            is_query_row: self.is_query_row || other.is_query_row,
            is_ecs_borrow: self.is_ecs_borrow || other.is_ecs_borrow,
            fields,
            elems,
            opt_inner,
            elem_join,
            param_origins,
            server_entity_comps,
            entity_param_origins,
        }
    }

    fn proj_field(&self, field: &str) -> Self {
        if self.is_query_row && matches!(field, "id" | "entity") {
            return Self {
                server_entity_comps: self.server_entity_comps.clone(),
                entity_param_origins: self.entity_param_origins.clone(),
                ..Self::default()
            };
        }
        if let Some(fp) = self.fields.get(field) {
            let mut out = fp.clone();
            if !self.is_query_row {
                out.direct.extend(self.direct.iter().cloned());
                out.param_origins.extend(self.param_origins.iter().copied());
            } else if matches!(field, "id" | "entity") {
                out.server_entity_comps
                    .extend(self.server_entity_comps.iter().cloned());
                out.entity_param_origins
                    .extend(self.entity_param_origins.iter().copied());
            }
            return out;
        }
        if !self.direct.is_empty() || !self.param_origins.is_empty() {
            return Self {
                direct: self.direct.clone(),
                param_origins: self.param_origins.clone(),
                ..Self::default()
            };
        }
        Self::empty()
    }

    fn proj_index(&self, idx_opt: Option<usize>) -> Self {
        if !self.elems.is_empty()
            && let Some(idx) = idx_opt
            && let Some(e) = self.elems.get(idx)
        {
            return e.clone();
        }
        if let Some(ref ej) = self.elem_join {
            let mut out = (**ej).clone();
            out.direct.extend(self.direct.iter().cloned());
            out.param_origins.extend(self.param_origins.iter().copied());
            return out;
        }
        if !self.direct.is_empty() || !self.param_origins.is_empty() {
            return Self {
                direct: self.direct.clone(),
                param_origins: self.param_origins.clone(),
                ..Self::default()
            };
        }
        Self::empty()
    }

    fn unwrap_opt(&self) -> Self {
        let mut out = self
            .opt_inner
            .as_deref()
            .cloned()
            .unwrap_or_else(Self::empty);
        out.direct.extend(self.direct.iter().cloned());
        out.param_origins.extend(self.param_origins.iter().copied());
        out.is_ecs_borrow |= self.is_ecs_borrow;
        out
    }

    fn instantiate(&self, arg_provs: &[Self], depth: u8) -> Self {
        if depth > 6 {
            return Self::empty();
        }
        let mut out = Self {
            direct: self.direct.clone(),
            is_query_row: self.is_query_row,
            is_ecs_borrow: self.is_ecs_borrow,
            fields: self
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), v.instantiate(arg_provs, depth + 1)))
                .collect(),
            elems: self
                .elems
                .iter()
                .map(|e| e.instantiate(arg_provs, depth + 1))
                .collect(),
            opt_inner: self
                .opt_inner
                .as_ref()
                .map(|b| Box::new(b.instantiate(arg_provs, depth + 1))),
            elem_join: self
                .elem_join
                .as_ref()
                .map(|b| Box::new(b.instantiate(arg_provs, depth + 1))),
            param_origins: BTreeSet::new(),
            server_entity_comps: self.server_entity_comps.clone(),
            entity_param_origins: BTreeSet::new(),
        };
        for &p in &self.param_origins {
            if let Some(ap) = arg_provs.get(p) {
                out = out.join(ap);
            }
        }
        for &p in &self.entity_param_origins {
            if let Some(ap) = arg_provs.get(p) {
                out.server_entity_comps
                    .extend(ap.server_entity_comps.iter().cloned());
                out.entity_param_origins
                    .extend(ap.entity_param_origins.iter().copied());
            }
        }
        out
    }

    fn instantiate_with_remap(&self, arg_provs: &[Self]) -> Self {
        self.instantiate(arg_provs, 0)
    }
}

/// Returns `true` iff values of `ty` are trivially copyable scalars (`f32`, `i32`, `bool`, enums,
/// unit scalars, entity refs, `Option<Scalar>`), which safely detach from ECS place provenance
/// when copied across a storage constructor.
pub(crate) fn is_copy_scalar_ty(ty: &Ty, enums: &IndexMap<String, EnumDef>) -> bool {
    match ty {
        Ty::U8
        | Ty::U16
        | Ty::U32
        | Ty::U64
        | Ty::I8
        | Ty::I16
        | Ty::I32
        | Ty::I64
        | Ty::F32
        | Ty::F64
        | Ty::Fix32
        | Ty::Fix64
        | Ty::Bool
        | Ty::Unit
        | Ty::Sym
        | Ty::UnitScalar { .. }
        | Ty::Rgba8
        | Ty::Asset(_) => true,
        Ty::Ref(s) | Ty::Named(s) if s == "Entity" => true,
        Ty::Named(s) => enums.values().any(|e| {
            e.canonical_name == *s || e.canonical_name.rsplit("::").next() == Some(s.as_str())
        }),
        Ty::Option(inner) => is_copy_scalar_ty(inner, enums),
        Ty::Ref(_)
        | Ty::Vec2
        | Ty::Vec3
        | Ty::Vec3a
        | Ty::Vec4
        | Ty::IVec2
        | Ty::IVec3
        | Ty::UVec2
        | Ty::Quat
        | Ty::Mat3
        | Ty::Mat4
        | Ty::Rgba
        | Ty::BitSet(_)
        | Ty::Array { .. }
        | Ty::SmallVec { .. }
        | Ty::Tuple(_)
        | Ty::Record(_)
        | Ty::QueryRow(_)
        | Ty::Borrow { .. }
        | Ty::Result { .. }
        | Ty::Trigger { .. }
        | Ty::InlineStr(_)
        | Ty::BannedWire(_)
        | Ty::InputBuffer { .. }
        | Ty::GraceWindow
        | Ty::Unknown => false,
    }
}

fn is_decayable_copy_ty(ty: &Ty, enums: &IndexMap<String, EnumDef>) -> bool {
    match ty {
        Ty::Borrow {
            mutable: false,
            inner,
        } => is_copy_scalar_ty(inner, enums),
        Ty::Option(inner) => is_decayable_copy_ty(inner, enums),
        _ => is_copy_scalar_ty(ty, enums),
    }
}

fn decay_storage_copy(prov: Provenance, ty: &Ty, enums: &IndexMap<String, EnumDef>) -> Provenance {
    let can_decay = prov.is_pure_leaf() || prov.is_ecs_borrow;
    if can_decay && is_decayable_copy_ty(ty, enums) {
        if matches!(ty, Ty::Ref(s) | Ty::Named(s) if s == "Entity") {
            Provenance {
                server_entity_comps: prov.server_entity_comps,
                entity_param_origins: prov.entity_param_origins,
                ..Provenance::default()
            }
        } else {
            Provenance::empty()
        }
    } else {
        prov
    }
}

fn is_server_authoritative_key(key: &str, authorities: &IndexMap<String, AuthorityKind>) -> bool {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return false;
    }
    if let Some(auth) = authorities.get(trimmed) {
        return *auth == AuthorityKind::Server;
    }
    if let Some((prefix, suffix)) = trimmed.rsplit_once("::") {
        if let Some(auth) = authorities.get(prefix) {
            return *auth == AuthorityKind::Server;
        }
        if let Some(auth) = authorities.get(suffix) {
            return *auth == AuthorityKind::Server;
        }
    }
    if let Some((base, _)) = trimmed.split_once("__")
        && let Some(auth) = authorities.get(base)
    {
        return *auth == AuthorityKind::Server;
    }
    false
}

fn extract_filter_target_component(filter: &str) -> Option<&str> {
    let f = filter.trim();
    if f.is_empty() {
        return None;
    }
    if let Some(inner) = f
        .strip_prefix("With<")
        .or_else(|| f.strip_prefix("Without<"))
        .or_else(|| f.strip_prefix("Changed<"))
        && let Some(core) = inner.strip_suffix('>')
    {
        return Some(core.trim());
    }
    Some(f)
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct AuthScope {
    frames: Vec<HashMap<String, Provenance>>,
}

impl AuthScope {
    fn new() -> Self {
        Self {
            frames: vec![HashMap::new()],
        }
    }

    fn push(&mut self) {
        self.frames.push(HashMap::new());
    }

    fn pop(&mut self) {
        if self.frames.len() > 1 {
            self.frames.pop();
        }
    }

    fn insert(&mut self, name: impl Into<String>, prov: Provenance) {
        if let Some(top) = self.frames.last_mut() {
            top.insert(name.into(), prov);
        }
    }

    fn assign(&mut self, name: &str, prov: Provenance) {
        for frame in self.frames.iter_mut().rev() {
            if frame.contains_key(name) {
                frame.insert(name.to_owned(), prov);
                return;
            }
        }
        self.insert(name, prov);
    }

    fn get(&self, name: &str) -> Option<&Provenance> {
        for frame in self.frames.iter().rev() {
            if let Some(p) = frame.get(name) {
                return Some(p);
            }
        }
        None
    }

    fn get_mut(&mut self, name: &str) -> Option<&mut Provenance> {
        for frame in self.frames.iter_mut().rev() {
            if frame.contains_key(name) {
                return frame.get_mut(name);
            }
        }
        None
    }

    fn snapshot(&self) -> Vec<HashMap<String, Provenance>> {
        self.frames.clone()
    }

    fn merge_from(
        &mut self,
        pre_frames: &[HashMap<String, Provenance>],
        branch_frames: &[Vec<HashMap<String, Provenance>>],
    ) {
        let mut merged = pre_frames.to_vec();
        for (depth, frame) in merged.iter_mut().enumerate() {
            let keys: Vec<String> = frame.keys().cloned().collect();
            for k in keys {
                let mut acc = Provenance::empty();
                for bf in branch_frames {
                    if let Some(bmap) = bf.get(depth)
                        && let Some(p) = bmap.get(&k)
                    {
                        acc = acc.join(p);
                    }
                }
                frame.insert(k, acc);
            }
        }
        self.frames = merged;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct FnSummary {
    direct_server_writes: BTreeSet<String>,
    mutated_params: BTreeSet<usize>,
    despawned_entity_params: BTreeSet<usize>,
    triggered_events: BTreeSet<String>,
    started_workflows: BTreeSet<String>,
    uses_server_res: bool,
    return_prov: Provenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct WorkflowSummary {
    server_writes: BTreeSet<String>,
    triggered_events: BTreeSet<String>,
    started_workflows: BTreeSet<String>,
    uses_server_res: bool,
}

struct AuthEnv<'a> {
    module_path: &'a str,
    authorities: &'a IndexMap<String, AuthorityKind>,
    layouts: &'a IndexMap<String, SolvedLayout>,
    enums: &'a IndexMap<String, EnumDef>,
    item_fields: &'a IndexMap<String, Vec<(String, Ty)>>,
    fn_summaries: &'a HashMap<String, FnSummary>,
    fn_params: &'a HashMap<String, Vec<(HirParamKind, Ty)>>,
    workflow_names: &'a HashSet<String>,
    object_server_comps: &'a HashMap<String, BTreeSet<String>>,
}

impl<'a> AuthEnv<'a> {
    fn is_server(&self, key: &str) -> bool {
        is_server_authoritative_key(key, self.authorities)
    }

    fn find_fields(&self, name: &str) -> Option<Vec<(String, Ty)>> {
        let canon = format!("{}::{name}", self.module_path);
        if let Some(fs) = self
            .item_fields
            .get(&canon)
            .or_else(|| self.item_fields.get(name))
            .or_else(|| {
                self.item_fields
                    .iter()
                    .find(|(k, _)| k.rsplit("::").next() == Some(name) || *k == name)
                    .map(|(_, v)| v)
            })
        {
            return Some(fs.clone());
        }
        self.layouts
            .get(&canon)
            .or_else(|| self.layouts.get(name))
            .or_else(|| {
                self.layouts
                    .iter()
                    .find(|(k, _)| k.rsplit("::").next() == Some(name) || *k == name)
                    .map(|(_, v)| v)
            })
            .map(|l| {
                l.fields
                    .iter()
                    .map(|f| (f.name.clone(), f.ty.clone()))
                    .collect()
            })
    }

    fn schema_type_provenance(&self, ty: &Ty, visited: &mut HashSet<String>) -> Provenance {
        match ty {
            Ty::Borrow { inner, .. } => self.schema_type_provenance(inner, visited),
            Ty::Option(inner) => {
                let ip = self.schema_type_provenance(inner, visited);
                if ip.is_empty() {
                    Provenance::empty()
                } else {
                    Provenance {
                        opt_inner: Some(Box::new(ip)),
                        ..Provenance::default()
                    }
                }
            }
            Ty::Array { elem, .. } | Ty::SmallVec { elem, .. } => {
                let ep = self.schema_type_provenance(elem, visited);
                if ep.is_empty() {
                    Provenance::empty()
                } else {
                    Provenance {
                        elem_join: Some(Box::new(ep)),
                        ..Provenance::default()
                    }
                }
            }
            Ty::Tuple(ts) => {
                let elems: Vec<_> = ts
                    .iter()
                    .map(|t| self.schema_type_provenance(t, visited))
                    .collect();
                if elems.iter().all(Provenance::is_empty) {
                    Provenance::empty()
                } else {
                    Provenance {
                        elems,
                        ..Provenance::default()
                    }
                }
            }
            Ty::Record(fs) => {
                let mut fields = BTreeMap::new();
                for (fname, fty) in fs {
                    let fp = self.schema_type_provenance(fty, visited);
                    if !fp.is_empty() {
                        fields.insert(fname.clone(), fp);
                    }
                }
                if fields.is_empty() {
                    Provenance::empty()
                } else {
                    Provenance {
                        fields,
                        ..Provenance::default()
                    }
                }
            }
            Ty::Named(name) | Ty::Ref(name) => {
                let mod_prefix = format!("{}::", self.module_path);
                let without_mod = name.strip_prefix(&mod_prefix).unwrap_or(name);
                let base_name = without_mod
                    .split("::")
                    .next()
                    .unwrap_or(without_mod)
                    .split("__")
                    .next()
                    .unwrap_or(without_mod);
                let mut direct = BTreeSet::new();
                if self.is_server(name) {
                    direct.insert(base_name.to_owned());
                }
                let mut fields = BTreeMap::new();
                if visited.insert(name.clone()) {
                    if let Some(item_fs) = self.find_fields(name) {
                        for (fname, fty) in item_fs {
                            let fp = self.schema_type_provenance(&fty, visited);
                            if !fp.is_empty() {
                                fields.insert(fname, fp);
                            }
                        }
                    }
                    visited.remove(name);
                }
                if direct.is_empty() && fields.is_empty() {
                    Provenance::empty()
                } else {
                    Provenance {
                        direct,
                        fields,
                        ..Provenance::default()
                    }
                }
            }
            _ => Provenance::empty(),
        }
    }

    fn query_term_prov(&self, term: &HirQueryTerm) -> Provenance {
        let mut p =
            if self.is_server(&term.storage_key) || self.is_server(&term.canonical_component) {
                let short = term
                    .storage_key
                    .split("::")
                    .next()
                    .unwrap_or(&term.storage_key)
                    .to_owned();
                Provenance::direct_server(short, term.field_name.is_some())
            } else {
                Provenance::empty()
            };
        if let Some(ref fname) = term.field_name {
            if let Some(fs) = self
                .find_fields(&term.canonical_component)
                .or_else(|| self.find_fields(&term.storage_key))
                && let Some((_, fty)) = fs.iter().find(|(n, _)| n == fname)
            {
                let fp = self.schema_type_provenance(fty, &mut HashSet::new());
                p = p.join(&fp);
            }
        } else if term.storage_key != "Entity" {
            let sp = self
                .schema_type_provenance(&Ty::Named(term.storage_key.clone()), &mut HashSet::new());
            p = p.join(&sp);
        }
        p
    }

    fn query_server_entity_comps(&self, q: &HirQuery) -> BTreeSet<String> {
        let mut server_comps = BTreeSet::new();
        for t in &q.terms {
            if self.is_server(&t.storage_key) || self.is_server(&t.canonical_component) {
                let short = t
                    .storage_key
                    .split("::")
                    .next()
                    .unwrap_or(&t.storage_key)
                    .to_owned();
                server_comps.insert(short);
            }
        }
        for f in q.with_filters.iter().chain(q.has_filters.iter()) {
            let comp = extract_filter_target_component(f).unwrap_or(f.as_str());
            if self.is_server(comp) {
                let short = comp.rsplit("::").next().unwrap_or(comp).to_owned();
                server_comps.insert(short);
            }
        }
        server_comps
    }

    fn query_row_prov_for_query(&self, q: &HirQuery, pat_name: Option<&str>) -> Provenance {
        let server_entity_comps = self.query_server_entity_comps(q);
        let terms = &q.terms;
        let mut out = if terms.len() == 1 && pat_name == Some(terms[0].alias.as_str()) {
            let tp = self.query_term_prov(&terms[0]);
            let mut fields = BTreeMap::new();
            fields.insert(terms[0].alias.clone(), tp.clone());
            Provenance {
                direct: tp.direct,
                is_query_row: terms[0].field_name.is_none(),
                is_ecs_borrow: terms[0].field_name.is_some(),
                fields,
                server_entity_comps: server_entity_comps.clone(),
                ..Provenance::default()
            }
        } else {
            let mut fields = BTreeMap::new();
            for t in terms {
                let mut tp = self.query_term_prov(t);
                if t.storage_key == "Entity" {
                    tp.server_entity_comps
                        .extend(server_entity_comps.iter().cloned());
                }
                fields.insert(t.alias.clone(), tp);
            }
            Provenance {
                is_query_row: true,
                fields,
                server_entity_comps: server_entity_comps.clone(),
                ..Provenance::default()
            }
        };
        if !server_entity_comps.is_empty() {
            for ent_key in ["id", "entity"] {
                out.fields
                    .entry(ent_key.to_owned())
                    .and_modify(|p| {
                        p.server_entity_comps
                            .extend(server_entity_comps.iter().cloned())
                    })
                    .or_insert_with(|| Provenance {
                        server_entity_comps: server_entity_comps.clone(),
                        ..Provenance::default()
                    });
            }
        }
        out
    }

    fn query_prov(&self, q: &HirQuery) -> Provenance {
        if q.is_count {
            return Provenance::empty();
        }
        let row = self.query_row_prov_for_query(q, None);
        if q.is_point_lookup && !q.is_unwrap {
            Provenance {
                opt_inner: Some(Box::new(row)),
                ..Provenance::default()
            }
        } else {
            row
        }
    }
}

fn first_hir_pattern_binding(pat: &HirPattern) -> Option<&str> {
    match pat {
        HirPattern::Binding { name, .. } => Some(name.as_str()),
        _ => None,
    }
}

fn is_irrefutable_hir_pattern(pat: &HirPattern) -> bool {
    match pat {
        HirPattern::Wildcard => true,
        HirPattern::Binding { name, .. } => name != "None",
        HirPattern::Tuple(items) => items.iter().all(is_irrefutable_hir_pattern),
        HirPattern::TupleStruct { .. } | HirPattern::Literal(_) | HirPattern::Path(_) => false,
    }
}

struct ExecCtx<'a> {
    env: &'a AuthEnv<'a>,
    emit_violations: bool,
    server_writes_seen: BTreeSet<String>,
    mutated_params_seen: BTreeSet<usize>,
    despawned_entity_params_seen: BTreeSet<usize>,
    triggered_events_seen: BTreeSet<String>,
    started_workflows_seen: BTreeSet<String>,
    uses_server_res: bool,
    return_prov: Provenance,
    diagnostics: Vec<(String, String)>,
    flow_exited: bool,
    loop_continues: Vec<Vec<HashMap<String, Provenance>>>,
    loop_breaks: Vec<Vec<HashMap<String, Provenance>>>,
}

impl<'a> ExecCtx<'a> {
    fn new(env: &'a AuthEnv<'a>, emit_violations: bool) -> Self {
        Self {
            env,
            emit_violations,
            server_writes_seen: BTreeSet::new(),
            mutated_params_seen: BTreeSet::new(),
            despawned_entity_params_seen: BTreeSet::new(),
            triggered_events_seen: BTreeSet::new(),
            started_workflows_seen: BTreeSet::new(),
            uses_server_res: false,
            return_prov: Provenance::empty(),
            diagnostics: Vec::new(),
            flow_exited: false,
            loop_continues: Vec::new(),
            loop_breaks: Vec::new(),
        }
    }

    fn record_server_violation(&mut self, comp: &str, msg: String) {
        self.server_writes_seen.insert(comp.to_owned());
        if self.emit_violations {
            self.diagnostics.push((comp.to_owned(), msg));
        }
    }

    fn record_prov_mutation(
        &mut self,
        comps: &BTreeSet<String>,
        params: &BTreeSet<usize>,
        ctx: &str,
    ) {
        for c in comps {
            self.record_server_violation(
                c,
                format!("non-server callable mutates `@authority(server)` component `{c}` ({ctx})"),
            );
        }
        self.mutated_params_seen.extend(params.iter().copied());
    }

    fn bind_query_pattern(&self, pat: &HirPattern, prov: Provenance, scope: &mut AuthScope) {
        match pat {
            HirPattern::Binding { name, .. } => {
                scope.insert(name.clone(), prov);
            }
            HirPattern::Tuple(items) => {
                for (idx, p) in items.iter().enumerate() {
                    self.bind_query_pattern(p, prov.proj_index(Some(idx)), scope);
                }
            }
            HirPattern::TupleStruct { path, fields } => {
                if matches!(path.as_str(), "Some" | "Option::Some") && fields.len() == 1 {
                    self.bind_query_pattern(&fields[0], prov.unwrap_opt(), scope);
                } else {
                    for f in fields {
                        self.bind_query_pattern(f, Provenance::empty(), scope);
                    }
                }
            }
            HirPattern::Wildcard | HirPattern::Literal(_) | HirPattern::Path(_) => {}
        }
    }

    fn bind_pattern(&self, pat: &HirPattern, prov: Provenance, scope: &mut AuthScope, ty: &Ty) {
        match pat {
            HirPattern::Binding { name, .. } => {
                let stored = decay_storage_copy(prov, ty, self.env.enums);
                scope.insert(name.clone(), stored);
            }
            HirPattern::Tuple(items) => {
                let item_tys = match ty {
                    Ty::Tuple(ts) => ts.as_slice(),
                    _ => &[],
                };
                for (idx, p) in items.iter().enumerate() {
                    let eprov = prov.proj_index(Some(idx));
                    let ety = item_tys.get(idx).unwrap_or(&Ty::Unknown);
                    self.bind_pattern(p, eprov, scope, ety);
                }
            }
            HirPattern::TupleStruct { path, fields } => {
                if matches!(path.as_str(), "Some" | "Option::Some") && fields.len() == 1 {
                    let inner_prov = prov.unwrap_opt();
                    let inner_ty = match ty {
                        Ty::Option(inner) => inner.as_ref(),
                        _ => &Ty::Unknown,
                    };
                    self.bind_pattern(&fields[0], inner_prov, scope, inner_ty);
                } else {
                    for f in fields {
                        self.bind_pattern(f, Provenance::empty(), scope, &Ty::Unknown);
                    }
                }
            }
            HirPattern::Wildcard | HirPattern::Literal(_) | HirPattern::Path(_) => {}
        }
    }

    fn eval_stmts(&mut self, stmts: &[HirStmt], scope: &mut AuthScope) {
        for stmt in stmts {
            if self.flow_exited {
                // Once control has exited (`return`/`break`/`continue`), keep scanning direct
                // violations (e.g. `res_mut`) in an isolated dead scope so dead assignments
                // never taint reachable variables.
                let mut dead_scope = AuthScope::new();
                let mut dead_ctx = ExecCtx::new(self.env, self.emit_violations);
                dead_ctx.eval_stmt(stmt, &mut dead_scope);
                self.server_writes_seen.extend(dead_ctx.server_writes_seen);
                self.mutated_params_seen
                    .extend(dead_ctx.mutated_params_seen);
                self.despawned_entity_params_seen
                    .extend(dead_ctx.despawned_entity_params_seen);
                self.triggered_events_seen
                    .extend(dead_ctx.triggered_events_seen);
                self.started_workflows_seen
                    .extend(dead_ctx.started_workflows_seen);
                self.uses_server_res |= dead_ctx.uses_server_res;
                self.diagnostics.extend(dead_ctx.diagnostics);
            } else {
                self.eval_stmt(stmt, scope);
            }
        }
    }

    fn eval_stmt(&mut self, stmt: &HirStmt, scope: &mut AuthScope) {
        match stmt {
            HirStmt::Let {
                pattern,
                ty,
                value,
                else_block,
                ..
            } => {
                let val_prov = self.eval_expr(value, scope);
                let bound_ty = ty.as_ref().filter(|t| **t != Ty::Unknown);
                let val_ty = value.ty();
                let eff_ty = bound_ty.unwrap_or(&val_ty);
                let stored = decay_storage_copy(val_prov, eff_ty, self.env.enums);
                self.bind_pattern(pattern, stored, scope, eff_ty);
                if !else_block.is_empty() {
                    let saved = scope.snapshot();
                    let saved_exit = self.flow_exited;
                    self.flow_exited = false;
                    scope.push();
                    self.eval_stmts(else_block, scope);
                    scope.pop();
                    scope.frames = saved;
                    self.flow_exited = saved_exit;
                }
            }
            HirStmt::Assign { target, op, value } => {
                // Evaluate target index subexpressions & check if `target` diverges before the
                // assignment executes (e.g. `arr[{ return; 0 }].hp = 0.0`).
                let base_or_target_prov = match target {
                    HirLValue::Field { base, .. } | HirLValue::Index { base, .. } => {
                        let bp = self.eval_lvalue_place(base, scope);
                        if let HirLValue::Index { index, .. } = target
                            && !self.flow_exited
                        {
                            self.eval_expr(index, scope);
                        }
                        Some(bp)
                    }
                    HirLValue::Local { .. }
                    | HirLValue::Expr(_)
                    | HirLValue::ResourceAccess { .. } => None,
                };
                if self.flow_exited {
                    return;
                }
                let rhs_prov = self.eval_expr(value, scope);
                if self.flow_exited {
                    return;
                }
                let rhs_ty = value.ty();
                self.check_and_apply_assign(
                    target,
                    *op,
                    rhs_prov,
                    &rhs_ty,
                    base_or_target_prov,
                    scope,
                );
            }
            HirStmt::Despawn(e) => {
                let ep = self.eval_expr(e, scope);
                for comp in &ep.server_entity_comps {
                    self.record_server_violation(
                        comp,
                        format!(
                            "non-server callable despawns entity with `@authority(server)` component `{comp}`"
                        ),
                    );
                }
                self.despawned_entity_params_seen
                    .extend(ep.entity_param_origins.iter().copied());
            }
            HirStmt::Expr(e)
            | HirStmt::Wait(e)
            | HirStmt::WaitUntil(e)
            | HirStmt::Emit(e)
            | HirStmt::RequireTrue(e) => {
                self.eval_expr(e, scope);
            }
            HirStmt::Return(opt) => {
                if let Some(e) = opt {
                    let p = self.eval_expr(e, scope);
                    self.return_prov = self.return_prov.join(&p);
                }
                self.flow_exited = true;
            }
            HirStmt::Break(opt) => {
                if let Some(e) = opt {
                    let p = self.eval_expr(e, scope);
                    self.return_prov = self.return_prov.join(&p);
                }
                self.loop_breaks.push(scope.snapshot());
                self.flow_exited = true;
            }
            HirStmt::Continue => {
                self.loop_continues.push(scope.snapshot());
                self.flow_exited = true;
            }
            HirStmt::YieldTick => {}
            HirStmt::While { cond, body } => {
                self.eval_loop_cfg(Some(cond), body, true, scope);
            }
            HirStmt::Loop { body } => {
                self.eval_loop_cfg(None, body, false, scope);
            }
            HirStmt::Atomic(at) => {
                let pre = scope.snapshot();
                scope.push();
                self.eval_stmts(&at.body, scope);
                scope.pop();
                let body_snap = scope.snapshot();
                scope.frames = pre.clone();
                scope.push();
                self.eval_stmts(&at.on_rollback, scope);
                scope.pop();
                let rb_snap = scope.snapshot();
                scope.merge_from(&pre, &[body_snap, rb_snap]);
            }
            HirStmt::AbortIf { cond, cleanup } => {
                self.eval_expr(cond, scope);
                let pre = scope.snapshot();
                scope.push();
                self.eval_stmts(cleanup, scope);
                scope.pop();
                scope.frames = pre;
            }
            HirStmt::Race { branches } => {
                let pre = scope.snapshot();
                let mut snaps = Vec::with_capacity(branches.len());
                for br in branches {
                    scope.frames = pre.clone();
                    self.flow_exited = false;
                    scope.push();
                    self.eval_stmts(br, scope);
                    scope.pop();
                    if !self.flow_exited {
                        snaps.push(scope.snapshot());
                    }
                }
                self.flow_exited = false;
                if snaps.is_empty() {
                    scope.frames = pre;
                } else {
                    scope.merge_from(&pre, &snaps);
                }
            }
            HirStmt::Trigger { target, event, .. } => {
                if let Some(t) = target {
                    self.eval_expr(t, scope);
                }
                self.eval_expr(event, scope);
                let ev_name = match event.as_ref() {
                    HirExpr::StructLit { name, .. } => {
                        Some(name.rsplit("::").next().unwrap_or(name).to_owned())
                    }
                    _ => match event.ty() {
                        Ty::Named(n) => Some(n.rsplit("::").next().unwrap_or(&n).to_owned()),
                        _ => None,
                    },
                };
                if let Some(ev) = ev_name {
                    self.triggered_events_seen.insert(ev);
                }
            }
            HirStmt::InsertRelation {
                relation,
                entity,
                target,
                payload,
            } => {
                self.eval_expr(entity, scope);
                self.eval_expr(target, scope);
                if let Some(p) = payload {
                    self.eval_expr(p, scope);
                }
                if self.env.is_server(relation) {
                    self.record_server_violation(
                        relation,
                        format!(
                            "non-server callable inserts `@authority(server)` relation `{relation}`"
                        ),
                    );
                }
            }
            HirStmt::RemoveRelation {
                relation,
                entity,
                target,
            } => {
                self.eval_expr(entity, scope);
                self.eval_expr(target, scope);
                if self.env.is_server(relation) {
                    self.record_server_violation(
                        relation,
                        format!(
                            "non-server callable removes `@authority(server)` relation `{relation}`"
                        ),
                    );
                }
            }
        }
    }

    fn check_comp_init(&mut self, ci: &HirCompInit, verb: &str, scope: &mut AuthScope) {
        let short_comp = ci.component.rsplit("::").next().unwrap_or(&ci.component);
        if self.env.workflow_names.contains(short_comp) {
            self.started_workflows_seen.insert(short_comp.to_owned());
        }
        if self.env.is_server(&ci.component) {
            self.record_server_violation(
                &ci.component,
                format!(
                    "non-server callable cannot {verb} `@authority(server)` component `{}`",
                    ci.component
                ),
            );
        }
        for (_, fexpr) in &ci.fields {
            let fp = self.eval_expr(fexpr, scope);
            let decayed = decay_storage_copy(fp, &fexpr.ty(), self.env.enums);
            if decayed.is_ecs_borrow {
                let comps = decayed.deep_comps();
                let params = decayed.deep_params();
                if !comps.is_empty() || !params.is_empty() {
                    let action = if verb == "spawn" {
                        "spawning server component"
                    } else {
                        "inserting server component"
                    };
                    self.record_prov_mutation(&comps, &params, action);
                }
            }
        }
    }

    fn eval_lvalue_place(&mut self, lv: &HirLValue, scope: &mut AuthScope) -> Provenance {
        match lv {
            HirLValue::Local { name, .. } => {
                scope.get(name).cloned().unwrap_or_else(Provenance::empty)
            }
            HirLValue::Field { base, field, .. } => {
                self.eval_lvalue_place(base, scope).proj_field(field)
            }
            HirLValue::Index { base, index, .. } => {
                self.eval_expr(index, scope);
                self.eval_lvalue_place(base, scope).proj_index(None)
            }
            HirLValue::Expr(e) => self.eval_expr(e, scope),
            HirLValue::ResourceAccess {
                resource,
                client_id,
                ..
            } => {
                if let Some(cid) = client_id {
                    self.eval_expr(cid, scope);
                }
                self.env
                    .schema_type_provenance(&Ty::Named(resource.clone()), &mut HashSet::new())
            }
        }
    }

    fn apply_nested_lvalue_store(lv: &HirLValue, stored: Provenance, scope: &mut AuthScope) {
        #[derive(Clone)]
        enum Step<'b> {
            Field(&'b str),
            Index,
        }
        let mut steps = Vec::new();
        let mut cur = lv;
        loop {
            match cur {
                HirLValue::Local { name, .. } => {
                    let Some(root_p) = scope.get_mut(name) else {
                        return;
                    };
                    let mut p_ref = root_p;
                    let mut saw_index = false;
                    let len = steps.len();
                    for (idx, step) in steps.into_iter().rev().enumerate() {
                        let is_last = idx + 1 == len;
                        match step {
                            Step::Field(f) => {
                                p_ref = p_ref.fields.entry(f.to_owned()).or_default();
                                if is_last {
                                    *p_ref = if saw_index {
                                        p_ref.join(&stored)
                                    } else {
                                        stored
                                    };
                                    return;
                                }
                            }
                            Step::Index => {
                                saw_index = true;
                                p_ref = p_ref
                                    .elem_join
                                    .get_or_insert_with(|| Box::new(Provenance::empty()));
                                if is_last {
                                    *p_ref = p_ref.join(&stored);
                                    return;
                                }
                            }
                        }
                    }
                    return;
                }
                HirLValue::Field { base, field, .. } => {
                    steps.push(Step::Field(field.as_str()));
                    cur = base.as_ref();
                }
                HirLValue::Index { base, .. } => {
                    steps.push(Step::Index);
                    cur = base.as_ref();
                }
                HirLValue::Expr(_) | HirLValue::ResourceAccess { .. } => return,
            }
        }
    }

    fn check_and_apply_assign(
        &mut self,
        target: &HirLValue,
        op: HirAssignOp,
        rhs_prov: Provenance,
        rhs_ty: &Ty,
        pre_eval_base: Option<Provenance>,
        scope: &mut AuthScope,
    ) {
        match target {
            HirLValue::Local { name, .. } => {
                let existing = scope.get(name).cloned().unwrap_or_else(Provenance::empty);
                let must_check_existing = op != HirAssignOp::Set
                    || existing.is_ecs_borrow
                    || existing.is_query_row
                    || !existing.param_origins.is_empty();
                if must_check_existing
                    && (!existing.direct.is_empty() || !existing.param_origins.is_empty())
                {
                    self.record_prov_mutation(
                        &existing.direct,
                        &existing.param_origins,
                        &format!("assigning `{name}`"),
                    );
                }
                if op == HirAssignOp::Set {
                    let stored = decay_storage_copy(rhs_prov, rhs_ty, self.env.enums);
                    scope.assign(name, stored);
                }
            }
            HirLValue::Field { base, field, .. } => {
                let base_prov =
                    pre_eval_base.unwrap_or_else(|| self.eval_lvalue_place(base, scope));
                if self.flow_exited {
                    return;
                }
                if base_prov.is_query_row {
                    let term_prov = base_prov.proj_field(field);
                    let comps = term_prov.deep_comps();
                    let params = term_prov.deep_params();
                    if !comps.is_empty() || !params.is_empty() {
                        self.record_prov_mutation(
                            &comps,
                            &params,
                            &format!("mutating query field `{field}`"),
                        );
                    }
                } else {
                    if !base_prov.direct.is_empty() || !base_prov.param_origins.is_empty() {
                        self.record_prov_mutation(
                            &base_prov.direct,
                            &base_prov.param_origins,
                            &format!("mutating field `{field}`"),
                        );
                    }
                    if op == HirAssignOp::Set {
                        let stored = decay_storage_copy(rhs_prov, rhs_ty, self.env.enums);
                        if let HirLValue::Local { name, .. } = base.as_ref()
                            && let Some(local_p) = scope.get_mut(name)
                        {
                            if stored.is_empty() {
                                local_p.fields.remove(field);
                            } else {
                                local_p.fields.insert(field.clone(), stored);
                            }
                        } else {
                            Self::apply_nested_lvalue_store(target, stored, scope);
                        }
                    }
                }
            }
            HirLValue::Index { base, index, .. } => {
                let base_prov = match pre_eval_base {
                    Some(bp) => bp,
                    None => {
                        let bp = self.eval_lvalue_place(base, scope);
                        if !self.flow_exited {
                            self.eval_expr(index, scope);
                        }
                        bp
                    }
                };
                if self.flow_exited {
                    return;
                }
                if !base_prov.direct.is_empty() || !base_prov.param_origins.is_empty() {
                    self.record_prov_mutation(
                        &base_prov.direct,
                        &base_prov.param_origins,
                        "mutating indexed slot",
                    );
                }
                if op == HirAssignOp::Set {
                    let stored = decay_storage_copy(rhs_prov, rhs_ty, self.env.enums);
                    Self::apply_nested_lvalue_store(target, stored, scope);
                }
            }
            HirLValue::Expr(inner) => {
                let p = self.eval_expr(inner, scope);
                if self.flow_exited {
                    return;
                }
                let (comps, params) = if op == HirAssignOp::Set {
                    (p.direct, p.param_origins)
                } else {
                    (p.deep_comps(), p.deep_params())
                };
                if !comps.is_empty() || !params.is_empty() {
                    self.record_prov_mutation(&comps, &params, "mutating place expression");
                }
            }
            HirLValue::ResourceAccess {
                resource,
                client_id,
                ..
            } => {
                if let Some(cid) = client_id {
                    self.eval_expr(cid, scope);
                }
                if self.flow_exited {
                    return;
                }
                if self.env.is_server(resource) {
                    self.record_server_violation(
                        resource,
                        format!(
                            "non-server callable mutates `@authority(server)` resource `{resource}`"
                        ),
                    );
                }
            }
        }
    }

    fn check_inserted_value_authority(&mut self, value: &HirExpr, scope: &mut AuthScope) {
        match value {
            HirExpr::StructLit { name, fields, .. } => {
                let short_name = name.rsplit("::").next().unwrap_or(name);
                if self.env.workflow_names.contains(short_name) {
                    self.started_workflows_seen.insert(short_name.to_owned());
                }
                if self.env.is_server(name) {
                    self.record_server_violation(
                        name,
                        format!(
                            "non-server callable inserts `@authority(server)` component `{name}`"
                        ),
                    );
                }
                for (_, fe) in fields {
                    let fp = self.eval_expr(fe, scope);
                    let decayed = decay_storage_copy(fp, &fe.ty(), self.env.enums);
                    if decayed.is_ecs_borrow {
                        let comps = decayed.deep_comps();
                        let params = decayed.deep_params();
                        if !comps.is_empty() || !params.is_empty() {
                            self.record_prov_mutation(
                                &comps,
                                &params,
                                "inserting server component",
                            );
                        }
                    }
                }
            }
            HirExpr::BundleLit { components } => {
                for ci in components {
                    self.check_comp_init(ci, "insert", scope);
                }
            }
            HirExpr::RecordLit { fields, .. } => {
                for (_, fe) in fields {
                    let fp = self.eval_expr(fe, scope);
                    let decayed = decay_storage_copy(fp, &fe.ty(), self.env.enums);
                    if decayed.is_ecs_borrow {
                        let comps = decayed.deep_comps();
                        let params = decayed.deep_params();
                        if !comps.is_empty() || !params.is_empty() {
                            self.record_prov_mutation(
                                &comps,
                                &params,
                                "inserting server component",
                            );
                        }
                    }
                }
            }
            HirExpr::Block { stmts, tail, .. } => {
                scope.push();
                self.eval_stmts(stmts, scope);
                if let Some(t) = tail {
                    self.check_inserted_value_authority(t, scope);
                }
                scope.pop();
            }
            _ => {
                let p = self.eval_expr(value, scope);
                let comps = p.deep_comps();
                let params = p.deep_params();
                if !comps.is_empty() || !params.is_empty() {
                    self.record_prov_mutation(&comps, &params, "inserting server component");
                }
            }
        }
    }

    fn eval_expr(&mut self, expr: &HirExpr, scope: &mut AuthScope) -> Provenance {
        match expr {
            HirExpr::IntLit { .. }
            | HirExpr::FloatLit { .. }
            | HirExpr::BoolLit(_)
            | HirExpr::StringLit(_)
            | HirExpr::CharLit(_) => Provenance::empty(),

            HirExpr::Path { name, .. } => scope.get(name).cloned().unwrap_or_else(|| {
                if let Some(comps) = self.env.object_server_comps.get(name) {
                    Provenance {
                        server_entity_comps: comps.clone(),
                        ..Provenance::default()
                    }
                } else {
                    Provenance::empty()
                }
            }),

            HirExpr::Field { base, field, .. } => self.eval_expr(base, scope).proj_field(field),

            HirExpr::Index { base, index, .. } => {
                let base_prov = self.eval_expr(base, scope);
                self.eval_expr(index, scope);
                let idx_const = match index.as_ref() {
                    HirExpr::IntLit { value, .. } if *value >= 0 => usize::try_from(*value).ok(),
                    _ => None,
                };
                base_prov.proj_index(idx_const)
            }

            HirExpr::Cast { expr: inner, .. } => self.eval_expr(inner, scope),

            HirExpr::Unary {
                op, expr: inner, ..
            } => {
                let inner_prov = self.eval_expr(inner, scope);
                if matches!(op, HirUnOp::RefMut) {
                    let comps = inner_prov.deep_comps();
                    let params = inner_prov.deep_params();
                    if !comps.is_empty() || !params.is_empty() {
                        self.record_prov_mutation(&comps, &params, "taking `&mut` borrow");
                    }
                }
                match op {
                    HirUnOp::Ref | HirUnOp::RefMut => inner_prov,
                    _ => Provenance::empty(),
                }
            }

            HirExpr::Binary { lhs, rhs, .. } => {
                self.eval_expr(lhs, scope);
                self.eval_expr(rhs, scope);
                Provenance::empty()
            }

            HirExpr::Tuple { elems, .. } => {
                let mut out_elems = Vec::with_capacity(elems.len());
                for e in elems {
                    let ep = self.eval_expr(e, scope);
                    out_elems.push(decay_storage_copy(ep, &e.ty(), self.env.enums));
                }
                Provenance {
                    elems: out_elems,
                    ..Provenance::default()
                }
            }

            HirExpr::ArrayLit { elems, ty } => {
                let elem_ty = match ty {
                    Ty::Array { elem, .. } => elem.as_ref(),
                    _ => &Ty::Unknown,
                };
                let mut joined = Provenance::empty();
                for e in elems {
                    let ep = self.eval_expr(e, scope);
                    let eff_ty = if *elem_ty == Ty::Unknown {
                        e.ty()
                    } else {
                        elem_ty.clone()
                    };
                    let decayed = decay_storage_copy(ep, &eff_ty, self.env.enums);
                    joined = joined.join(&decayed);
                }
                if joined.is_empty() {
                    Provenance::empty()
                } else {
                    Provenance {
                        elem_join: Some(Box::new(joined)),
                        ..Provenance::default()
                    }
                }
            }

            HirExpr::StructLit { name, fields, .. } => {
                let mut schema_p = self
                    .env
                    .schema_type_provenance(&Ty::Named(name.clone()), &mut HashSet::new());
                for (fname, fexpr) in fields {
                    let fp = self.eval_expr(fexpr, scope);
                    let stored = decay_storage_copy(fp, &fexpr.ty(), self.env.enums);
                    if stored.is_empty() {
                        schema_p.fields.remove(fname);
                    } else {
                        schema_p.fields.insert(fname.clone(), stored);
                    }
                }
                schema_p
            }

            HirExpr::RecordLit { fields, .. } => {
                let mut field_provs = BTreeMap::new();
                for (fname, fexpr) in fields {
                    let fp = self.eval_expr(fexpr, scope);
                    let stored = decay_storage_copy(fp, &fexpr.ty(), self.env.enums);
                    if !stored.is_empty() {
                        field_provs.insert(fname.clone(), stored);
                    }
                }
                Provenance {
                    fields: field_provs,
                    ..Provenance::default()
                }
            }

            HirExpr::BundleLit { components } => {
                let mut fields = BTreeMap::new();
                for ci in components {
                    let mut comp_p = self.env.schema_type_provenance(
                        &Ty::Named(ci.component.clone()),
                        &mut HashSet::new(),
                    );
                    let mut cfields = BTreeMap::new();
                    for (fname, fexpr) in &ci.fields {
                        let fp = self.eval_expr(fexpr, scope);
                        let stored = decay_storage_copy(fp, &fexpr.ty(), self.env.enums);
                        if !stored.is_empty() {
                            cfields.insert(fname.clone(), stored);
                        }
                    }
                    if !cfields.is_empty() {
                        comp_p = comp_p.join(&Provenance {
                            fields: cfields,
                            ..Provenance::default()
                        });
                    }
                    if !comp_p.is_empty() {
                        fields.insert(ci.component.clone(), comp_p);
                    }
                }
                Provenance {
                    fields,
                    ..Provenance::default()
                }
            }

            HirExpr::Query(q) => {
                self.eval_query_clauses(q, scope);
                self.env.query_prov(q)
            }

            HirExpr::Block { stmts, tail, .. } => {
                scope.push();
                self.eval_stmts(stmts, scope);
                let out = tail
                    .as_deref()
                    .map_or_else(Provenance::empty, |t| self.eval_expr(t, scope));
                scope.pop();
                out
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
                let cond_prov = self.eval_expr(cond, scope);
                let pre = scope.snapshot();

                scope.push();
                self.flow_exited = false;
                if let Some(pat) = let_pat {
                    self.bind_pattern(pat, cond_prov, scope, &cond.ty());
                }
                self.eval_stmts(then_stmts, scope);
                let then_prov = if self.flow_exited {
                    Provenance::empty()
                } else {
                    then_tail
                        .as_deref()
                        .map_or_else(Provenance::empty, |t| self.eval_expr(t, scope))
                };
                scope.pop();
                let then_exited = self.flow_exited;
                let then_frames = scope.snapshot();

                scope.frames = pre.clone();
                scope.push();
                self.flow_exited = false;
                self.eval_stmts(else_stmts, scope);
                let else_prov = if self.flow_exited {
                    Provenance::empty()
                } else {
                    else_tail
                        .as_deref()
                        .map_or_else(Provenance::empty, |t| self.eval_expr(t, scope))
                };
                scope.pop();
                let else_exited = self.flow_exited;
                let else_frames = scope.snapshot();

                let mut live_frames = Vec::with_capacity(2);
                let mut out_prov = Provenance::empty();
                if !then_exited {
                    live_frames.push(then_frames);
                    out_prov = out_prov.join(&then_prov);
                }
                if !else_exited {
                    live_frames.push(else_frames);
                    out_prov = out_prov.join(&else_prov);
                }
                if live_frames.is_empty() {
                    self.flow_exited = true;
                    scope.frames = pre;
                } else {
                    self.flow_exited = false;
                    scope.merge_from(&pre, &live_frames);
                }
                out_prov
            }

            HirExpr::Match(m) => {
                let scrut_prov = self.eval_expr(&m.scrutinee, scope);
                let scrut_ty = m.scrutinee.ty();
                let mut cur_pre = scope.snapshot();
                let mut arm_frames = Vec::with_capacity(m.arms.len() + 1);
                let mut out_prov = Provenance::empty();
                let mut cutoff = false;
                for arm in &m.arms {
                    scope.frames = cur_pre.clone();
                    scope.push();
                    self.flow_exited = false;
                    self.bind_pattern(&arm.pattern, scrut_prov.clone(), scope, &scrut_ty);
                    if let Some(ref g) = arm.guard {
                        self.eval_expr(g, scope);
                    }
                    let guard_exited = self.flow_exited;
                    if guard_exited {
                        scope.pop();
                        if is_irrefutable_hir_pattern(&arm.pattern) {
                            cutoff = true;
                            break;
                        }
                        continue;
                    }
                    // On guard failure, guard mutations remain visible to subsequent arms!
                    let after_guard_outer = {
                        let mut next_scope = scope.clone();
                        next_scope.pop();
                        next_scope.snapshot()
                    };
                    let arm_prov = self.eval_expr(&arm.body, scope);
                    let arm_exited = self.flow_exited;
                    scope.pop();
                    if !arm_exited {
                        out_prov = out_prov.join(&arm_prov);
                        arm_frames.push(scope.snapshot());
                    }
                    cur_pre = after_guard_outer;
                }
                if m.arms.is_empty() {
                    scope.frames = cur_pre;
                } else {
                    if !cutoff && !crate::hir_lower::match_arms_have_catch_all(&m.arms) {
                        arm_frames.push(cur_pre.clone());
                    }
                    if arm_frames.is_empty() {
                        self.flow_exited = true;
                        scope.frames = cur_pre;
                    } else {
                        self.flow_exited = false;
                        scope.merge_from(&cur_pre, &arm_frames);
                    }
                }
                out_prov
            }

            HirExpr::For(f) => {
                let pat_name = first_hir_pattern_binding(&f.binding).map(str::to_owned);
                let (iter_prov, pat_ty, is_query) = match &f.iter {
                    HirForIter::Query(q) => {
                        self.eval_query_clauses(q, scope);
                        (
                            self.env.query_row_prov_for_query(q, pat_name.as_deref()),
                            Ty::Ref("Entity".to_owned()),
                            true,
                        )
                    }
                    HirForIter::Range { start, end, .. } => {
                        self.eval_expr(start, scope);
                        self.eval_expr(end, scope);
                        (Provenance::empty(), start.ty(), false)
                    }
                    HirForIter::Expr(e) => {
                        let ep = self.eval_expr(e, scope);
                        let mut ety = e.ty();
                        while let Ty::Borrow { inner, .. } = ety {
                            ety = *inner;
                        }
                        let elem_ty = match ety {
                            Ty::Array { elem, .. } | Ty::SmallVec { elem, .. } => *elem,
                            _ => Ty::Unknown,
                        };
                        (ep.proj_index(None), elem_ty, false)
                    }
                    HirForIter::SpatialDisc { center, radius, .. } => {
                        self.eval_expr(center, scope);
                        self.eval_expr(radius, scope);
                        (Provenance::empty(), Ty::Ref("Entity".to_owned()), false)
                    }
                    HirForIter::SpatialSegmentAt {
                        tick,
                        p0,
                        p1,
                        radius,
                        ..
                    } => {
                        self.eval_expr(tick, scope);
                        self.eval_expr(p0, scope);
                        self.eval_expr(p1, scope);
                        if let Some(r) = radius {
                            self.eval_expr(r, scope);
                        }
                        (Provenance::empty(), Ty::Ref("Entity".to_owned()), false)
                    }
                };

                // Bounded fixed-point iteration over loop body (silent), followed by single
                // diagnostic-emitting pass if `emit_violations == true`.
                for red in &f.reduce {
                    self.eval_expr(&red.identity, scope);
                }
                let outer_continues = std::mem::take(&mut self.loop_continues);
                let outer_breaks = std::mem::take(&mut self.loop_breaks);

                let mut loop_scope = scope.clone();
                for _ in 0..16 {
                    let prev_scope = loop_scope.clone();
                    let mut body_scope = loop_scope.clone();
                    body_scope.push();
                    let mut silent = ExecCtx::new(self.env, false);
                    if is_query {
                        silent.bind_query_pattern(&f.binding, iter_prov.clone(), &mut body_scope);
                        if let HirForIter::Query(q) = &f.iter {
                            for t in &q.terms {
                                if t.storage_key == "Entity"
                                    && pat_name.as_deref() != Some(t.alias.as_str())
                                    && !iter_prov.server_entity_comps.is_empty()
                                {
                                    body_scope.insert(
                                        t.alias.clone(),
                                        Provenance {
                                            server_entity_comps: iter_prov
                                                .server_entity_comps
                                                .clone(),
                                            ..Provenance::default()
                                        },
                                    );
                                }
                            }
                        }
                    } else {
                        silent.bind_pattern(
                            &f.binding,
                            iter_prov.clone(),
                            &mut body_scope,
                            &pat_ty,
                        );
                    }
                    silent.eval_stmts(&f.body, &mut body_scope);
                    for red in &f.reduce {
                        silent.eval_expr(&red.value, &mut body_scope);
                    }
                    body_scope.pop();
                    let mut back_edges = vec![prev_scope.frames.clone()];
                    if !silent.flow_exited {
                        back_edges.push(body_scope.frames);
                    }
                    back_edges.extend(silent.loop_continues);
                    loop_scope.merge_from(&prev_scope.frames, &back_edges);
                    if loop_scope == prev_scope {
                        break;
                    }
                }

                // Final pass on converged `loop_scope` collecting diagnostics / writes / returns.
                self.flow_exited = false;
                loop_scope.push();
                if is_query {
                    self.bind_query_pattern(&f.binding, iter_prov.clone(), &mut loop_scope);
                    if let HirForIter::Query(q) = &f.iter {
                        for t in &q.terms {
                            if t.storage_key == "Entity"
                                && pat_name.as_deref() != Some(t.alias.as_str())
                                && !iter_prov.server_entity_comps.is_empty()
                            {
                                loop_scope.insert(
                                    t.alias.clone(),
                                    Provenance {
                                        server_entity_comps: iter_prov.server_entity_comps.clone(),
                                        ..Provenance::default()
                                    },
                                );
                            }
                        }
                    }
                } else {
                    self.bind_pattern(&f.binding, iter_prov, &mut loop_scope, &pat_ty);
                }
                self.eval_stmts(&f.body, &mut loop_scope);
                for red in &f.reduce {
                    self.eval_expr(&red.value, &mut loop_scope);
                }
                loop_scope.pop();
                let mut exit_edges = vec![scope.snapshot()];
                if !self.flow_exited {
                    exit_edges.push(loop_scope.frames);
                }
                exit_edges.extend(std::mem::replace(&mut self.loop_breaks, outer_breaks));
                self.loop_continues = outer_continues;
                self.flow_exited = false;
                scope.merge_from(&scope.snapshot(), &exit_edges);
                Provenance::empty()
            }

            HirExpr::Spawn(sp) => {
                if let Some(ref cnt) = sp.count {
                    self.eval_expr(cnt, scope);
                }
                if !sp.preamble.is_empty() {
                    let outer_continues = std::mem::take(&mut self.loop_continues);
                    let outer_breaks = std::mem::take(&mut self.loop_breaks);

                    let run_preamble_once =
                        |ctx: &mut ExecCtx<'_>, cur_scope: &mut AuthScope, check_tail: bool| {
                            ctx.flow_exited = false;
                            cur_scope.push();
                            if let Some(ref bv) = sp.batch_var {
                                cur_scope.insert(bv.clone(), Provenance::empty());
                            }
                            if check_tail
                                && sp.is_batch
                                && sp.components.is_empty()
                                && let Some(HirStmt::Expr(tail_expr)) = sp.preamble.last()
                            {
                                ctx.eval_stmts(&sp.preamble[..sp.preamble.len() - 1], cur_scope);
                                let tp = ctx.eval_expr(tail_expr, cur_scope);
                                let comps = tp.deep_comps();
                                let params = tp.deep_params();
                                if !comps.is_empty() || !params.is_empty() {
                                    ctx.record_prov_mutation(
                                        &comps,
                                        &params,
                                        "spawning server bundle",
                                    );
                                }
                            } else {
                                ctx.eval_stmts(&sp.preamble, cur_scope);
                                for ci in &sp.components {
                                    ctx.check_comp_init(ci, "spawn", cur_scope);
                                }
                            }
                            cur_scope.pop();
                        };

                    let mut loop_scope = scope.clone();
                    for _ in 0..16 {
                        let prev_scope = loop_scope.clone();
                        let mut body_scope = loop_scope.clone();
                        let mut silent = ExecCtx::new(self.env, false);
                        run_preamble_once(&mut silent, &mut body_scope, false);
                        let mut back_edges = vec![prev_scope.frames.clone()];
                        if !silent.flow_exited {
                            back_edges.push(body_scope.frames);
                        }
                        back_edges.extend(silent.loop_continues);
                        loop_scope.merge_from(&prev_scope.frames, &back_edges);
                        if loop_scope == prev_scope {
                            break;
                        }
                    }

                    let header_frames = loop_scope.frames.clone();
                    run_preamble_once(self, &mut loop_scope, true);
                    let mut exit_edges = vec![header_frames];
                    exit_edges.extend(std::mem::replace(&mut self.loop_breaks, outer_breaks));
                    self.loop_continues = outer_continues;
                    self.flow_exited = false;
                    scope.merge_from(&scope.snapshot(), &exit_edges);
                } else {
                    for ci in &sp.components {
                        self.check_comp_init(ci, "spawn", scope);
                    }
                }
                let mut spawned_srv = BTreeSet::new();
                for ci in &sp.components {
                    if self.env.is_server(&ci.component) {
                        let short = ci.component.rsplit("::").next().unwrap_or(&ci.component);
                        spawned_srv.insert(short.to_owned());
                    }
                }
                Provenance {
                    server_entity_comps: spawned_srv,
                    ..Provenance::default()
                }
            }

            HirExpr::DespawnAll { filters } => {
                for f in filters {
                    if let Some(comp) = extract_filter_target_component(f)
                        && self.env.is_server(comp)
                    {
                        self.record_server_violation(
                            comp,
                            format!(
                                "non-server callable despawns entities with `@authority(server)` component `{comp}`"
                            ),
                        );
                    }
                }
                Provenance::empty()
            }

            HirExpr::Insert { entity, value, .. } => {
                self.eval_expr(entity, scope);
                self.check_inserted_value_authority(value, scope);
                Provenance::empty()
            }

            HirExpr::Remove { entity, component } => {
                self.eval_expr(entity, scope);
                if self.env.is_server(component) {
                    self.record_server_violation(
                        component,
                        format!(
                            "non-server callable removes `@authority(server)` component `{component}`"
                        ),
                    );
                }
                Provenance::empty()
            }

            HirExpr::Call(c) => self.eval_call(c, scope),
        }
    }

    fn eval_call(&mut self, c: &HirCall, scope: &mut AuthScope) -> Provenance {
        let recv_prov = c.receiver.as_deref().map(|r| self.eval_expr(r, scope));
        let mut arg_provs = Vec::with_capacity(c.args.len());
        for a in &c.args {
            if self.flow_exited {
                return Provenance::empty();
            }
            arg_provs.push(self.eval_expr(a, scope));
        }
        if self.flow_exited {
            return Provenance::empty();
        }

        // Handle Option combinators transparently (and flag in-place mutators like `as_mut`/`take`).
        if let Some(ref recv) = recv_prov {
            match c.callee.as_str() {
                "id" if !recv.server_entity_comps.is_empty()
                    || !recv.entity_param_origins.is_empty() =>
                {
                    return Provenance {
                        server_entity_comps: recv.server_entity_comps.clone(),
                        entity_param_origins: recv.entity_param_origins.clone(),
                        ..Provenance::default()
                    };
                }
                "unwrap" | "expect" | "as_ref" => {
                    return recv.unwrap_opt();
                }
                "unwrap_or" => {
                    let mut joined = recv.unwrap_opt();
                    if let Some(fb) = arg_provs.first() {
                        joined = joined.join(fb);
                    }
                    return joined;
                }
                "as_mut" | "take" => {
                    let comps = recv.deep_comps();
                    let params = recv.deep_params();
                    if !comps.is_empty() || !params.is_empty() {
                        self.record_prov_mutation(
                            &comps,
                            &params,
                            &format!("calling mutating method `{}`", c.callee),
                        );
                    }
                    return recv.unwrap_opt();
                }
                "arm" | "clear" | "push" | "consume" | "set" => {
                    let comps = recv.deep_comps();
                    let params = recv.deep_params();
                    if !comps.is_empty() || !params.is_empty() {
                        self.record_prov_mutation(
                            &comps,
                            &params,
                            &format!("calling mutating method `{}`", c.callee),
                        );
                    }
                    return Provenance::empty();
                }
                _ => {}
            }
        } else {
            match c.callee.as_str() {
                "Some" | "Option::Some" => {
                    let inner_ty = c.args.first().map_or(Ty::Unknown, HirExpr::ty);
                    let inner_prov = arg_provs
                        .into_iter()
                        .next()
                        .unwrap_or_else(Provenance::empty);
                    let stored = decay_storage_copy(inner_prov, &inner_ty, self.env.enums);
                    return Provenance {
                        opt_inner: Some(Box::new(stored)),
                        ..Provenance::default()
                    };
                }
                "Option::unwrap" | "Option::expect" | "Option::as_ref" => {
                    return arg_provs
                        .first()
                        .map_or_else(Provenance::empty, Provenance::unwrap_opt);
                }
                "Option::unwrap_or" => {
                    let mut joined = arg_provs
                        .first()
                        .map_or_else(Provenance::empty, Provenance::unwrap_opt);
                    if let Some(fb) = arg_provs.get(1) {
                        joined = joined.join(fb);
                    }
                    return joined;
                }
                "Option::as_mut" | "Option::take" => {
                    if let Some(first) = arg_provs.first() {
                        let comps = first.deep_comps();
                        let params = first.deep_params();
                        if !comps.is_empty() || !params.is_empty() {
                            self.record_prov_mutation(
                                &comps,
                                &params,
                                &format!("calling `{}`", c.callee),
                            );
                        }
                        return first.unwrap_opt();
                    }
                    return Provenance::empty();
                }
                "res" | "client_res" => {
                    if let Some(rname) = c.generic_args.first() {
                        return self.env.schema_type_provenance(
                            &Ty::Named(rname.clone()),
                            &mut HashSet::new(),
                        );
                    }
                    return Provenance::empty();
                }
                "server_res" => {
                    self.uses_server_res = true;
                    if let Some(rname) = c.generic_args.first() {
                        if self.env.is_server(rname) {
                            self.record_server_violation(
                                rname,
                                format!(
                                    "non-server callable calls `server_res<{rname}>()` on `@authority(server)` resource"
                                ),
                            );
                        }
                        return self.env.schema_type_provenance(
                            &Ty::Named(rname.clone()),
                            &mut HashSet::new(),
                        );
                    }
                    return Provenance::empty();
                }
                "play" => {
                    for a in &c.args {
                        let wf = match a {
                            HirExpr::Path { name, .. } | HirExpr::StructLit { name, .. } => {
                                Some(name.rsplit("::").next().unwrap_or(name).to_owned())
                            }
                            _ => match a.ty() {
                                Ty::Named(n) => {
                                    Some(n.rsplit("::").next().unwrap_or(&n).to_owned())
                                }
                                _ => None,
                            },
                        };
                        if let Some(w) = wf {
                            self.started_workflows_seen.insert(w);
                        }
                    }
                    return Provenance::empty();
                }
                "despawn" => {
                    if let Some(ep) = arg_provs.first() {
                        for comp in &ep.server_entity_comps {
                            self.record_server_violation(
                                comp,
                                format!(
                                    "non-server callable despawns entity with `@authority(server)` component `{comp}`"
                                ),
                            );
                        }
                        self.despawned_entity_params_seen
                            .extend(ep.entity_param_origins.iter().copied());
                    }
                    return Provenance::empty();
                }
                "res_mut" => {
                    if let Some(rname) = c.generic_args.first() {
                        if self.env.is_server(rname) {
                            self.record_server_violation(
                                rname,
                                format!(
                                    "non-server callable calls `res_mut<{rname}>()` on `@authority(server)` resource"
                                ),
                            );
                        }
                        return self.env.schema_type_provenance(
                            &Ty::Named(rname.clone()),
                            &mut HashSet::new(),
                        );
                    }
                    return Provenance::empty();
                }
                "server_query" | "client_query" => {
                    let mut fields = BTreeMap::new();
                    for (name_opt, arg) in c.arg_names.iter().zip(c.args.iter()) {
                        let Some(alias) = name_opt else { continue };
                        let (is_mut, inner) = match arg {
                            HirExpr::Unary {
                                op: HirUnOp::RefMut,
                                expr,
                                ..
                            } => (true, expr.as_ref()),
                            HirExpr::Unary { expr, .. } => (false, expr.as_ref()),
                            other => (false, other),
                        };
                        let comp = match inner {
                            HirExpr::Path { name, .. } => name.as_str(),
                            HirExpr::Field { base, .. } => match base.as_ref() {
                                HirExpr::Path { name, .. } => name.as_str(),
                                _ => "",
                            },
                            _ => "",
                        };
                        if !comp.is_empty() && self.env.is_server(comp) {
                            if is_mut {
                                self.record_server_violation(
                                    comp,
                                    format!(
                                        "non-server callable requests mutable query term on `@authority(server)` component `{comp}`"
                                    ),
                                );
                            }
                            fields.insert(
                                alias.clone(),
                                Provenance::direct_server(comp.to_owned(), true),
                            );
                        }
                    }
                    return Provenance {
                        is_query_row: true,
                        fields,
                        ..Provenance::default()
                    };
                }
                _ => {}
            }
        }

        // Transitive helper `fn` invocation check and provenance substitution.
        if c.receiver.is_none() {
            if let Some(prefix) = c.callee.strip_suffix("::start") {
                let short_wf = prefix.rsplit("::").next().unwrap_or(prefix).to_owned();
                self.started_workflows_seen.insert(short_wf);
                return Provenance::empty();
            }
            let short_callee = c.callee.rsplit("::").next().unwrap_or(&c.callee);
            if let Some(summary) = self
                .env
                .fn_summaries
                .get(&c.callee)
                .or_else(|| self.env.fn_summaries.get(short_callee))
            {
                for srv_comp in &summary.direct_server_writes {
                    self.record_server_violation(
                        srv_comp,
                        format!(
                            "non-server callable invokes helper `fn {}` which mutates `@authority(server)` `{srv_comp}`",
                            c.callee
                        ),
                    );
                }
                self.triggered_events_seen
                    .extend(summary.triggered_events.iter().cloned());
                self.started_workflows_seen
                    .extend(summary.started_workflows.iter().cloned());
                if summary.uses_server_res {
                    self.uses_server_res = true;
                }
                for &p_idx in &summary.despawned_entity_params {
                    if let Some(ap) = arg_provs.get(p_idx) {
                        for comp in &ap.server_entity_comps {
                            self.record_server_violation(
                                comp,
                                format!(
                                    "non-server callable passes server entity `{comp}` to helper `fn {}` which despawns it",
                                    c.callee
                                ),
                            );
                        }
                        self.despawned_entity_params_seen
                            .extend(ap.entity_param_origins.iter().copied());
                    }
                }
                let callee_params = self
                    .env
                    .fn_params
                    .get(&c.callee)
                    .or_else(|| self.env.fn_params.get(short_callee));
                for &p_idx in &summary.mutated_params {
                    if let Some(ap) = arg_provs.get(p_idx) {
                        let comps = ap.deep_comps();
                        let params = ap.deep_params();
                        if !comps.is_empty() || !params.is_empty() {
                            self.record_prov_mutation(
                                &comps,
                                &params,
                                &format!("passing server place to helper `fn {}`", c.callee),
                            );
                        } else if let Some((kind, pty)) = callee_params.and_then(|ps| ps.get(p_idx))
                            && *kind == HirParamKind::RefMut
                        {
                            let scomps = self
                                .env
                                .schema_type_provenance(pty, &mut HashSet::new())
                                .deep_comps();
                            if !scomps.is_empty() {
                                self.record_prov_mutation(
                                    &scomps,
                                    &BTreeSet::new(),
                                    &format!("passing `&mut` container with server field to helper `fn {}`", c.callee),
                                );
                            }
                        }
                    }
                }
                let instantiated = summary.return_prov.instantiate_with_remap(&arg_provs);
                return decay_storage_copy(instantiated, &c.ty, self.env.enums);
            }
        }

        // Unknown / builtin free function: pass-by-value copy-scalar arguments already can't mutate.
        Provenance::empty()
    }

    fn eval_loop_cfg(
        &mut self,
        cond: Option<&HirExpr>,
        body: &[HirStmt],
        can_skip_initial: bool,
        scope: &mut AuthScope,
    ) {
        let outer_continues = std::mem::take(&mut self.loop_continues);
        let outer_breaks = std::mem::take(&mut self.loop_breaks);

        let mut loop_scope = scope.clone();
        for _ in 0..16 {
            let prev_scope = loop_scope.clone();
            let mut body_scope = loop_scope.clone();
            let mut silent = ExecCtx::new(self.env, false);
            if let Some(c) = cond {
                silent.eval_expr(c, &mut body_scope);
            }
            body_scope.push();
            silent.eval_stmts(body, &mut body_scope);
            body_scope.pop();
            let mut back_edges = vec![prev_scope.frames.clone()];
            if !silent.flow_exited {
                back_edges.push(body_scope.frames);
            }
            back_edges.extend(silent.loop_continues);
            loop_scope.merge_from(&prev_scope.frames, &back_edges);
            if loop_scope == prev_scope {
                break;
            }
        }

        self.flow_exited = false;
        let header_frames = loop_scope.frames.clone();
        if let Some(c) = cond {
            self.eval_expr(c, &mut loop_scope);
        }
        loop_scope.push();
        self.eval_stmts(body, &mut loop_scope);
        loop_scope.pop();

        let mut exit_edges = Vec::new();
        if can_skip_initial {
            exit_edges.push(header_frames);
        }
        exit_edges.extend(std::mem::replace(&mut self.loop_breaks, outer_breaks));
        self.loop_continues = outer_continues;
        if exit_edges.is_empty() {
            self.flow_exited = true;
        } else {
            self.flow_exited = false;
            scope.merge_from(&scope.snapshot(), &exit_edges);
        }
    }

    fn eval_query_clauses(&mut self, q: &HirQuery, scope: &mut AuthScope) {
        for t in &q.terms {
            if t.mode.is_mutable()
                && (self.env.is_server(&t.storage_key)
                    || self.env.is_server(&t.canonical_component))
            {
                let short = t.storage_key.split("::").next().unwrap_or(&t.storage_key);
                self.record_server_violation(
                    short,
                    format!(
                        "non-server callable requests mutable query term on `@authority(server)` component `{short}`"
                    ),
                );
            }
        }
        if let Some(ref pred) = q.where_pred {
            let pre = scope.snapshot();
            scope.push();
            for t in &q.terms {
                scope.insert(t.alias.clone(), self.env.query_term_prov(t));
            }
            self.eval_expr(pred, scope);
            scope.pop();
            scope.frames = pre;
        }
        if let Some(ref on_tgt) = q.on_target {
            self.eval_expr(on_tgt, scope);
        }
    }
}

/// Computes fixed-point summaries across all helper `fn`, `obs`, `task`, `fsm`, and `timeline`
/// declarations and enforces `E0501` authority isolation across all `@authority(client)` /
/// `@predicted` / `@authority(shared)` callables in the module.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_module_authority(
    file: &str,
    src: &str,
    module_path: &str,
    authorities: &IndexMap<String, AuthorityKind>,
    layouts: &IndexMap<String, SolvedLayout>,
    enums: &IndexMap<String, EnumDef>,
    item_fields: &IndexMap<String, Vec<(String, Ty)>>,
    fns: &[HirFn],
    callables: &[crate::hir::HirCallable],
    tasks: &[HirTask],
    fsms: &[HirFsm],
    timelines: &[HirTimeline],
    objects: &[HirObject],
    server_res_items: &HashSet<String>,
    diags: &mut Vec<Diagnostic>,
) {
    let mut workflow_names = HashSet::new();
    for t in tasks {
        workflow_names.insert(t.name.rsplit("::").next().unwrap_or(&t.name).to_owned());
    }
    for f in fsms {
        workflow_names.insert(f.name.rsplit("::").next().unwrap_or(&f.name).to_owned());
    }
    for tl in timelines {
        workflow_names.insert(tl.name.rsplit("::").next().unwrap_or(&tl.name).to_owned());
    }

    let mut object_server_comps: HashMap<String, BTreeSet<String>> = HashMap::new();
    for obj in objects {
        let mut srv = BTreeSet::new();
        for ci in &obj.inits {
            if is_server_authoritative_key(&ci.component, authorities) {
                let short = ci.component.rsplit("::").next().unwrap_or(&ci.component);
                srv.insert(short.to_owned());
            }
        }
        if !srv.is_empty() {
            let short = obj.name.rsplit("::").next().unwrap_or(&obj.name);
            object_server_comps.insert(obj.name.clone(), srv.clone());
            object_server_comps.insert(short.to_owned(), srv);
        }
    }

    // 1. Fixed-point computation of helper `fn` summaries (direct server writes, mutated params,
    //    despawned entity params, triggered events, started workflows, server_res, and returns).
    let mut fn_summaries: HashMap<String, FnSummary> = HashMap::new();
    let mut fn_params: HashMap<String, Vec<(HirParamKind, Ty)>> = HashMap::new();
    for hf in fns {
        fn_summaries.insert(hf.name.clone(), FnSummary::default());
        fn_params.insert(
            hf.name.clone(),
            hf.params.iter().map(|p| (p.kind, p.ty.clone())).collect(),
        );
    }

    for _ in 0..16 {
        let mut changed = false;
        let next_env = AuthEnv {
            module_path,
            authorities,
            layouts,
            enums,
            item_fields,
            fn_summaries: &fn_summaries,
            fn_params: &fn_params,
            workflow_names: &workflow_names,
            object_server_comps: &object_server_comps,
        };
        let mut updated = fn_summaries.clone();
        for hf in fns {
            let mut scope = AuthScope::new();
            let mut ctx = ExecCtx::new(&next_env, false);
            let f_short = hf.name.rsplit("::").next().unwrap_or(&hf.name);
            if server_res_items.contains(&hf.name) || server_res_items.contains(f_short) {
                ctx.uses_server_res = true;
            }
            for (idx, p) in hf.params.iter().enumerate() {
                if let Some(ref def_expr) = p.default {
                    ctx.eval_expr(def_expr, &mut scope);
                }
                scope.insert(p.name.clone(), Provenance::param(idx));
            }
            ctx.eval_stmts(&hf.body, &mut scope);
            if let Some(ref tail) = hf.tail {
                let tp = ctx.eval_expr(tail, &mut scope);
                ctx.return_prov = ctx.return_prov.join(&tp);
            }
            let summary = FnSummary {
                direct_server_writes: ctx.server_writes_seen,
                mutated_params: ctx.mutated_params_seen,
                despawned_entity_params: ctx.despawned_entity_params_seen,
                triggered_events: ctx.triggered_events_seen,
                started_workflows: ctx.started_workflows_seen,
                uses_server_res: ctx.uses_server_res,
                return_prov: decay_storage_copy(ctx.return_prov, &hf.ret_ty, enums),
            };
            if updated.get(&hf.name) != Some(&summary) {
                updated.insert(hf.name.clone(), summary);
                changed = true;
            }
        }
        fn_summaries = updated;
        if !changed {
            break;
        }
    }

    let auth_env = AuthEnv {
        module_path,
        authorities,
        layouts,
        enums,
        item_fields,
        fn_summaries: &fn_summaries,
        fn_params: &fn_params,
        workflow_names: &workflow_names,
        object_server_comps: &object_server_comps,
    };

    // 2. Collect per-observer and per-workflow (`task`/`fsm`/`timeline`) server-write summaries.
    let mut obs_summaries: Vec<(String, String, WorkflowSummary)> = Vec::new();
    for c in callables.iter().filter(|c| c.is_observer) {
        let mut ws = WorkflowSummary::default();
        let c_short = c.name.rsplit("::").next().unwrap_or(&c.name);
        if server_res_items.contains(&c.name) || server_res_items.contains(c_short) {
            ws.uses_server_res = true;
        }
        for q in &c.access.queries {
            for t in &q.terms {
                if t.mode.is_mutable() && is_server_authoritative_key(&t.storage_key, authorities) {
                    let short = t.storage_key.split("::").next().unwrap_or(&t.storage_key);
                    ws.server_writes.insert(short.to_owned());
                }
            }
        }
        let mut scope = AuthScope::new();
        for p in &c.params {
            let schema_p = auth_env.schema_type_provenance(&p.ty, &mut HashSet::new());
            match p.kind {
                HirParamKind::ResWrite => {
                    if let Ty::Named(ref r) | Ty::Ref(ref r) = p.ty
                        && is_server_authoritative_key(r, authorities)
                    {
                        ws.server_writes.insert(r.clone());
                    }
                    if !schema_p.is_empty() {
                        scope.insert(p.name.clone(), schema_p);
                    }
                }
                HirParamKind::RefMut => {
                    ws.server_writes.extend(schema_p.deep_comps());
                    if !schema_p.is_empty() {
                        scope.insert(p.name.clone(), schema_p);
                    }
                }
                _ => {
                    if !schema_p.is_empty() {
                        scope.insert(p.name.clone(), schema_p);
                    }
                }
            }
        }
        let mut ctx = ExecCtx::new(&auth_env, false);
        ctx.eval_stmts(&c.body, &mut scope);
        ws.server_writes.extend(ctx.server_writes_seen);
        ws.triggered_events.extend(ctx.triggered_events_seen);
        ws.started_workflows.extend(ctx.started_workflows_seen);
        ws.uses_server_res |= ctx.uses_server_res;
        if let Some(ref ev) = c.trigger_event {
            let ev_short = ev.rsplit("::").next().unwrap_or(ev).to_owned();
            obs_summaries.push((c.name.clone(), ev_short, ws));
        }
    }

    let mut wf_summaries: HashMap<String, WorkflowSummary> = HashMap::new();
    for task in tasks {
        let mut ws = WorkflowSummary::default();
        let t_short = task
            .name
            .rsplit("::")
            .next()
            .unwrap_or(&task.name)
            .to_owned();
        if server_res_items.contains(&task.name) || server_res_items.contains(&t_short) {
            ws.uses_server_res = true;
        }
        let mut scope = AuthScope::new();
        for t in &task.typed_on_terms {
            if t.mode.is_mutable() && is_server_authoritative_key(&t.storage_key, authorities) {
                let short = t.storage_key.split("::").next().unwrap_or(&t.storage_key);
                ws.server_writes.insert(short.to_owned());
            }
            let tp = auth_env.query_term_prov(t);
            if !tp.is_empty() {
                scope.insert(t.alias.clone(), tp);
            }
        }
        let mut ctx = ExecCtx::new(&auth_env, false);
        for p in &task.typed_params {
            if let Some(ref def) = p.default {
                ctx.eval_expr(def, &mut scope);
            }
            let sp = auth_env.schema_type_provenance(&p.ty, &mut HashSet::new());
            if !sp.is_empty() {
                scope.insert(p.name.clone(), sp);
            }
        }
        for p in &task.typed_using_params {
            if p.kind == HirParamKind::ResWrite
                && let Ty::Named(ref r) | Ty::Ref(ref r) = p.ty
                && is_server_authoritative_key(r, authorities)
            {
                ws.server_writes.insert(r.clone());
            }
            let sp = auth_env.schema_type_provenance(&p.ty, &mut HashSet::new());
            if !sp.is_empty() {
                scope.insert(p.name.clone(), sp);
            }
        }
        ctx.eval_stmts(&task.body, &mut scope);
        ws.server_writes.extend(ctx.server_writes_seen);
        ws.triggered_events.extend(ctx.triggered_events_seen);
        ws.started_workflows.extend(ctx.started_workflows_seen);
        ws.uses_server_res |= ctx.uses_server_res;
        wf_summaries.insert(t_short, ws);
    }

    for fsm in fsms {
        let mut ws = WorkflowSummary::default();
        let f_short = fsm.name.rsplit("::").next().unwrap_or(&fsm.name).to_owned();
        if server_res_items.contains(&fsm.name) || server_res_items.contains(&f_short) {
            ws.uses_server_res = true;
        }
        let mut base_scope = AuthScope::new();
        for p in &fsm.params {
            if p.kind == HirParamKind::ResWrite
                && let Ty::Named(ref r) | Ty::Ref(ref r) = p.ty
                && is_server_authoritative_key(r, authorities)
            {
                ws.server_writes.insert(r.clone());
            }
            let sp = auth_env.schema_type_provenance(&p.ty, &mut HashSet::new());
            if !sp.is_empty() {
                base_scope.insert(p.name.clone(), sp);
            }
        }
        let mut ctx = ExecCtx::new(&auth_env, false);
        for st in &fsm.state_hooks {
            let mut st_scope = base_scope.clone();
            for (_, _, def) in &st.fields {
                if let Some(d) = def {
                    ctx.eval_expr(d, &mut st_scope);
                }
            }
            ctx.eval_stmts(&st.on_enter, &mut st_scope);
            ctx.eval_stmts(&st.on_tick, &mut st_scope);
            ctx.eval_stmts(&st.on_exit, &mut st_scope);
        }
        for tr in &fsm.typed_transitions {
            let mut tr_scope = base_scope.clone();
            ctx.eval_expr(&tr.guard, &mut tr_scope);
            for (_, v) in &tr.target_args {
                ctx.eval_expr(v, &mut tr_scope);
            }
        }
        ws.server_writes.extend(ctx.server_writes_seen);
        ws.triggered_events.extend(ctx.triggered_events_seen);
        ws.started_workflows.extend(ctx.started_workflows_seen);
        ws.uses_server_res |= ctx.uses_server_res;
        wf_summaries.insert(f_short, ws);
    }

    for tl in timelines {
        let mut ws = WorkflowSummary::default();
        let tl_short = tl.name.rsplit("::").next().unwrap_or(&tl.name).to_owned();
        if server_res_items.contains(&tl.name) || server_res_items.contains(&tl_short) {
            ws.uses_server_res = true;
        }
        let mut ctx = ExecCtx::new(&auth_env, false);
        for (_, stmts) in &tl.typed_triggers {
            let mut scope = AuthScope::new();
            ctx.eval_stmts(stmts, &mut scope);
        }
        ws.server_writes.extend(ctx.server_writes_seen);
        ws.triggered_events.extend(ctx.triggered_events_seen);
        ws.started_workflows.extend(ctx.started_workflows_seen);
        ws.uses_server_res |= ctx.uses_server_res;
        wf_summaries.insert(tl_short, ws);
    }

    // Bounded fixed-point closure across observers and workflows (`trigger -> obs`, `play/start -> task/fsm/timeline`).
    for _ in 0..16 {
        let mut changed = false;
        let obs_snap = obs_summaries.clone();
        let wf_snap = wf_summaries.clone();
        let propagate = |ws: &mut WorkflowSummary| -> bool {
            let mut c = false;
            let evs: Vec<String> = ws.triggered_events.iter().cloned().collect();
            for ev in evs {
                for (_, obs_ev, obs_ws) in &obs_snap {
                    if *obs_ev == ev {
                        for w in &obs_ws.server_writes {
                            c |= ws.server_writes.insert(w.clone());
                        }
                        for e in &obs_ws.triggered_events {
                            c |= ws.triggered_events.insert(e.clone());
                        }
                        for sf in &obs_ws.started_workflows {
                            c |= ws.started_workflows.insert(sf.clone());
                        }
                        if obs_ws.uses_server_res && !ws.uses_server_res {
                            ws.uses_server_res = true;
                            c = true;
                        }
                    }
                }
            }
            let wfs: Vec<String> = ws.started_workflows.iter().cloned().collect();
            for wname in wfs {
                if let Some(target_ws) = wf_snap.get(&wname) {
                    for w in &target_ws.server_writes {
                        c |= ws.server_writes.insert(w.clone());
                    }
                    for e in &target_ws.triggered_events {
                        c |= ws.triggered_events.insert(e.clone());
                    }
                    for sf in &target_ws.started_workflows {
                        c |= ws.started_workflows.insert(sf.clone());
                    }
                    if target_ws.uses_server_res && !ws.uses_server_res {
                        ws.uses_server_res = true;
                        c = true;
                    }
                }
            }
            c
        };
        for (_, _, ws) in &mut obs_summaries {
            changed |= propagate(ws);
        }
        for ws in wf_summaries.values_mut() {
            changed |= propagate(ws);
        }
        if !changed {
            break;
        }
    }

    // 3. Enforce E0501 on every non-server callable (`@authority(client)` / `@predicted` / `@authority(shared)`).
    for callable in callables {
        let is_client_restricted = matches!(
            callable.authority,
            AuthorityKind::Client | AuthorityKind::Predicted | AuthorityKind::Shared
        ) || callable.is_predicted;
        if !is_client_restricted {
            continue;
        }

        let callable_span =
            Span::from_bytes(file, src, callable.byte_range.0, callable.byte_range.1);

        // 2a. Check query term declarations directly via exact source byte spans.
        for q in &callable.access.queries {
            for t in &q.terms {
                if t.mode.is_mutable() && is_server_authoritative_key(&t.storage_key, authorities) {
                    let short = t.storage_key.split("::").next().unwrap_or(&t.storage_key);
                    diags.push(Diagnostic::error(
                        codes::E0501_AUTHORITY_VIOLATION,
                        Span::from_bytes(file, src, t.byte_start, t.byte_end),
                        format!(
                            "`{}` requests mutable query access `&mut {short}` which is `@authority(server)`",
                            callable.name
                        ),
                        None,
                    ));
                }
            }
        }

        // 2b. Check callable parameters (`ResWrite` / `ResRead` / `Value` / `Ref` / `RefMut`).
        let mut scope = AuthScope::new();
        for param in &callable.params {
            let schema_p = auth_env.schema_type_provenance(&param.ty, &mut HashSet::new());
            match &param.kind {
                HirParamKind::ResWrite => {
                    let rname = param
                        .ty
                        .canonical_tag()
                        .rsplit("::")
                        .next()
                        .unwrap_or(&param.name)
                        .to_owned();
                    let rkey = match &param.ty {
                        Ty::Named(n) | Ty::Ref(n) => n.clone(),
                        _ => rname,
                    };
                    if is_server_authoritative_key(&rkey, authorities) {
                        diags.push(Diagnostic::error(
                            codes::E0501_AUTHORITY_VIOLATION,
                            callable_span.clone(),
                            format!(
                                "`{}` takes mutable resource `&mut res {rkey}` which is `@authority(server)`",
                                callable.name
                            ),
                            None,
                        ));
                    }
                    if !schema_p.is_empty() {
                        scope.insert(param.name.clone(), schema_p);
                    } else if is_server_authoritative_key(&rkey, authorities) {
                        scope.insert(param.name.clone(), Provenance::direct_server(rkey, true));
                    }
                }
                HirParamKind::ResRead => {
                    let rkey = match &param.ty {
                        Ty::Named(n) | Ty::Ref(n) => n.clone(),
                        _ => String::new(),
                    };
                    if !schema_p.is_empty() {
                        scope.insert(param.name.clone(), schema_p);
                    } else if is_server_authoritative_key(&rkey, authorities) {
                        scope.insert(param.name.clone(), Provenance::direct_server(rkey, true));
                    }
                }
                HirParamKind::RefMut => {
                    let comps = schema_p.deep_comps();
                    if !comps.is_empty() {
                        diags.push(Diagnostic::error(
                            codes::E0501_AUTHORITY_VIOLATION,
                            callable_span.clone(),
                            format!(
                                "`{}` takes mutable `&mut` parameter `{}` containing `@authority(server)` component `{}`",
                                callable.name,
                                param.name,
                                comps.iter().next().cloned().unwrap_or_default()
                            ),
                            None,
                        ));
                    }
                    if !schema_p.is_empty() {
                        scope.insert(param.name.clone(), schema_p);
                    }
                }
                HirParamKind::Trigger => {
                    let mut tp = if !schema_p.is_empty() {
                        schema_p
                    } else {
                        Provenance::empty()
                    };
                    if let Some(ref tc) = callable.trigger_target_comp
                        && is_server_authoritative_key(tc, authorities)
                    {
                        let short = tc.rsplit("::").next().unwrap_or(tc).to_owned();
                        tp.fields.insert(
                            "target".to_owned(),
                            Provenance {
                                server_entity_comps: BTreeSet::from([short]),
                                ..Provenance::default()
                            },
                        );
                    }
                    if !tp.is_empty() {
                        scope.insert(param.name.clone(), tp);
                    }
                }
                _ => {
                    if !schema_p.is_empty() {
                        scope.insert(param.name.clone(), schema_p);
                    }
                }
            }
        }

        // 2c. Abstract-interpret callable body using unified provenance lattice.
        let mut ctx = ExecCtx::new(&auth_env, true);
        let c_short = callable.name.rsplit("::").next().unwrap_or(&callable.name);
        if server_res_items.contains(&callable.name) || server_res_items.contains(c_short) {
            ctx.uses_server_res = true;
        }
        ctx.eval_stmts(&callable.body, &mut scope);
        for (_comp, msg) in ctx.diagnostics {
            diags.push(Diagnostic::error(
                codes::E0501_AUTHORITY_VIOLATION,
                callable_span.clone(),
                msg,
                None,
            ));
        }
        if ctx.uses_server_res {
            diags.push(Diagnostic::error(
                codes::E0501_AUTHORITY_VIOLATION,
                callable_span.clone(),
                format!(
                    "non-server callable `{}` uses `server_res<...>()` to access server-side resource",
                    callable.name
                ),
                None,
            ));
        }
        for ev in &ctx.triggered_events_seen {
            for (obs_name, obs_ev, obs_ws) in &obs_summaries {
                if obs_ev == ev && (!obs_ws.server_writes.is_empty() || obs_ws.uses_server_res) {
                    let writes: Vec<&str> =
                        obs_ws.server_writes.iter().map(String::as_str).collect();
                    let detail = if writes.is_empty() {
                        "server_res".to_owned()
                    } else {
                        writes.join(", ")
                    };
                    diags.push(Diagnostic::error(
                        codes::E0501_AUTHORITY_VIOLATION,
                        callable_span.clone(),
                        format!(
                            "non-server callable `{}` triggers `{ev}` handled by observer `{obs_name}` which mutates `@authority(server)` state ({detail})",
                            callable.name
                        ),
                        None,
                    ));
                }
            }
        }
        for wf in &ctx.started_workflows_seen {
            if let Some(wf_ws) = wf_summaries.get(wf)
                && (!wf_ws.server_writes.is_empty() || wf_ws.uses_server_res)
            {
                let writes: Vec<&str> = wf_ws.server_writes.iter().map(String::as_str).collect();
                let detail = if writes.is_empty() {
                    "server_res".to_owned()
                } else {
                    writes.join(", ")
                };
                diags.push(Diagnostic::error(
                    codes::E0501_AUTHORITY_VIOLATION,
                    callable_span.clone(),
                    format!(
                        "non-server callable `{}` starts/plays `{wf}` which mutates `@authority(server)` state ({detail})",
                        callable.name
                    ),
                    None,
                ));
            }
        }
    }
}
