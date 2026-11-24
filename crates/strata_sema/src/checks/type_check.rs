//! Type mismatch (`E0111`) and query/field resolution (`E0301`) validation over lowered HIR.

use crate::access::TermAccessMode;
use crate::diagnostics::{Diagnostic, Span, codes};
use crate::hir::{
    HirCallable, HirCompInit, HirConst, HirExpr, HirFn, HirFor, HirForIter, HirFsm, HirLValue,
    HirNetSimTest, HirObject, HirPattern, HirQuery, HirQueryTerm, HirSimTest, HirStmt, HirTask,
    HirTimeline,
};
use crate::hir_lower::LowerEnv;
use crate::infer::check_array_or_smallvec_mismatch;
use crate::types::Ty;
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use strata_syntax::TextRange;
use strata_syntax::ast::{self, AstNode, SourceFile};

/// Validates array/SmallVec literal lengths, field defaults/inits, and query/field resolution.
#[allow(clippy::too_many_arguments)]
pub(super) fn validate_module_types(
    file: &str,
    src: &str,
    sf: &SourceFile,
    lower_env: &LowerEnv<'_>,
    consts: &[HirConst],
    objects: &[HirObject],
    field_defaults: &IndexMap<String, IndexMap<String, HirExpr>>,
    fns: &[HirFn],
    callables: &[HirCallable],
    tasks: &[HirTask],
    fsms: &[HirFsm],
    timelines: &[HirTimeline],
    sim_tests: &[HirSimTest],
    net_sim_tests: &[HirNetSimTest],
    diags: &mut Vec<Diagnostic>,
) {
    let fallback_span = Span::from_range(file, src, TextRange::empty(0.into()));
    let spans = collect_item_spans(file, src, sf);
    let fn_map: HashMap<String, &HirFn> = fns
        .iter()
        .flat_map(|f| {
            let short = f.name.rsplit("::").next().unwrap_or(&f.name).to_owned();
            [(f.name.clone(), f), (short, f)]
        })
        .collect();

    let mut ctx = CheckCtx {
        env: lower_env,
        fns: &fn_map,
        diags,
    };

    for hc in consts {
        let span = spans.get(&hc.name).unwrap_or(&fallback_span);
        if let Some(ref expr) = hc.expr {
            let expected = (hc.ty != Ty::Unknown).then_some(&hc.ty);
            let mut scope = LocalScope::default();
            ctx.check_expr(expr, expected, None, &mut scope, span);
        }
    }

    for (owner, defs) in field_defaults {
        let short_owner = owner.rsplit("::").next().unwrap_or(owner);
        let span = spans
            .get(owner)
            .or_else(|| spans.get(short_owner))
            .unwrap_or(&fallback_span);
        let fields_schema = lower_env
            .find_item_fields(owner)
            .or_else(|| lower_env.find_item_fields(short_owner));
        for (fname, def_expr) in defs {
            let expected =
                fields_schema.and_then(|fs| fs.iter().find(|(k, _)| k == fname).map(|(_, ty)| ty));
            let mut scope = LocalScope::default();
            ctx.check_expr(def_expr, expected, None, &mut scope, span);
        }
    }

    for obj in objects {
        let short = obj.name.rsplit("::").next().unwrap_or(&obj.name);
        let span = spans
            .get(&obj.name)
            .or_else(|| spans.get(short))
            .unwrap_or(&fallback_span);
        let mut scope = LocalScope::default();
        for ci in &obj.inits {
            ctx.check_comp_init(ci, &mut scope, span);
        }
    }

    for hf in fns {
        let short = hf.name.rsplit("::").next().unwrap_or(&hf.name);
        let span = Span::from_range(
            file,
            src,
            TextRange::new(hf.byte_range.0.into(), hf.byte_range.1.into()),
        );
        let mut scope = LocalScope::default();
        for p in &hf.params {
            scope.bind_var(&p.name, p.ty.clone());
        }
        let ret_ty = (hf.ret_ty != Ty::Unknown && hf.ret_ty != Ty::Unit).then_some(&hf.ret_ty);
        for stmt in &hf.body {
            ctx.check_stmt(stmt, ret_ty, &mut scope, &span);
        }
        if let Some(ref tail) = hf.tail {
            ctx.check_expr(tail, ret_ty, ret_ty, &mut scope, &span);
        }
        let _ = spans.get(short);
    }

    for c in callables {
        let span = Span::from_range(
            file,
            src,
            TextRange::new(c.byte_range.0.into(), c.byte_range.1.into()),
        );
        let mut scope = LocalScope::default();
        for p in &c.params {
            scope.bind_var(&p.name, p.ty.clone());
        }
        for stmt in &c.body {
            ctx.check_stmt(stmt, None, &mut scope, &span);
        }
    }

    for task in tasks {
        let short = task.name.rsplit("::").next().unwrap_or(&task.name);
        let span = spans
            .get(&task.name)
            .or_else(|| spans.get(short))
            .unwrap_or(&fallback_span);
        let mut scope = LocalScope::default();
        for (pname, pty) in &task.params {
            scope.bind_var(pname, pty.clone());
        }
        for p in &task.typed_params {
            scope.bind_var(&p.name, p.ty.clone());
            if let Some(ref def) = p.default {
                ctx.check_expr(def, Some(&p.ty), None, &mut scope, span);
            }
        }
        for p in &task.typed_using_params {
            scope.bind_var(&p.name, p.ty.clone());
        }
        for term in &task.typed_on_terms {
            scope.bind_var(&term.alias, Ty::Named(term.storage_key.clone()));
        }
        for stmt in &task.body {
            ctx.check_stmt(stmt, None, &mut scope, span);
        }
    }

    for fsm in fsms {
        let short = fsm.name.rsplit("::").next().unwrap_or(&fsm.name);
        let span = spans
            .get(&fsm.name)
            .or_else(|| spans.get(short))
            .unwrap_or(&fallback_span);
        let mut base_scope = LocalScope::default();
        for p in &fsm.params {
            base_scope.bind_var(&p.name, p.ty.clone());
        }
        for st in &fsm.state_hooks {
            let mut st_scope = base_scope.clone();
            for (fname, fty, def) in &st.fields {
                st_scope.bind_var(fname, fty.clone());
                if let Some(d) = def {
                    ctx.check_expr(d, Some(fty), None, &mut st_scope, span);
                }
            }
            for stmt in st
                .on_enter
                .iter()
                .chain(st.on_tick.iter())
                .chain(st.on_exit.iter())
            {
                ctx.check_stmt(stmt, None, &mut st_scope, span);
            }
        }
        for tr in &fsm.typed_transitions {
            let mut tr_scope = base_scope.clone();
            ctx.check_expr(&tr.guard, None, None, &mut tr_scope, span);
            for (_, arg) in &tr.target_args {
                ctx.check_expr(arg, None, None, &mut tr_scope, span);
            }
        }
    }

    for tl in timelines {
        let short = tl.name.rsplit("::").next().unwrap_or(&tl.name);
        let span = spans
            .get(&tl.name)
            .or_else(|| spans.get(short))
            .unwrap_or(&fallback_span);
        for (_, stmts) in &tl.typed_triggers {
            let mut scope = LocalScope::default();
            for stmt in stmts {
                ctx.check_stmt(stmt, None, &mut scope, span);
            }
        }
    }

    for st in sim_tests {
        let short = st.name.rsplit("::").next().unwrap_or(&st.name);
        let span = spans
            .get(&st.name)
            .or_else(|| spans.get(short))
            .unwrap_or(&fallback_span);
        let mut scope = LocalScope::default();
        for stmt in &st.body {
            ctx.check_stmt(stmt, None, &mut scope, span);
        }
    }

    for nst in net_sim_tests {
        let short = nst.name.rsplit("::").next().unwrap_or(&nst.name);
        let span = spans
            .get(&nst.name)
            .or_else(|| spans.get(short))
            .unwrap_or(&fallback_span);
        let mut scope = LocalScope::default();
        for (_, pe) in &nst.params {
            ctx.check_expr(pe, None, None, &mut scope, span);
        }
        for stmt in &nst.body {
            ctx.check_stmt(stmt, None, &mut scope, span);
        }
    }
}

fn collect_item_spans(file: &str, src: &str, sf: &SourceFile) -> HashMap<String, Span> {
    let mut map = HashMap::new();
    for item in sf.items() {
        let node = match item {
            ast::Item::Const(n) => n.syntax().clone(),
            ast::Item::Struct(n) => n.syntax().clone(),
            ast::Item::Component(n) => n.syntax().clone(),
            ast::Item::Resource(n) => n.syntax().clone(),
            ast::Item::Event(n) => n.syntax().clone(),
            ast::Item::Stream(n) => n.syntax().clone(),
            ast::Item::Object(n) => n.syntax().clone(),
            ast::Item::Timeline(n) => n.syntax().clone(),
            ast::Item::Task(n) => n.syntax().clone(),
            ast::Item::Fsm(n) => n.syntax().clone(),
            ast::Item::Sys(n) => n.syntax().clone(),
            ast::Item::Obs(n) => n.syntax().clone(),
            ast::Item::Fn(n) => n.syntax().clone(),
            ast::Item::SimTest(n) => n.syntax().clone(),
            ast::Item::NetSimTest(n) => n.syntax().clone(),
            _ => continue,
        };
        if let Some(ident) = ast::first_ident(&node) {
            map.insert(
                ident.text().to_owned(),
                Span::from_range(file, src, node.text_range()),
            );
        }
    }
    map
}

#[derive(Default, Clone)]
struct LocalScope {
    vars: HashSet<String>,
    var_tys: HashMap<String, Ty>,
    query_rows: HashSet<String>,
    term_alias_tys: HashMap<String, Ty>,
}

impl LocalScope {
    fn bind_var(&mut self, name: &str, ty: Ty) {
        self.vars.insert(name.to_owned());
        self.term_alias_tys.remove(name);
        if ty != Ty::Unknown {
            self.var_tys.insert(name.to_owned(), ty);
        }
    }

    fn bind_pattern(&mut self, pat: &HirPattern, ty: Option<&Ty>) {
        match pat {
            HirPattern::Binding { name, .. } => {
                self.bind_var(name, ty.cloned().unwrap_or(Ty::Unknown));
            }
            HirPattern::Tuple(ps) => {
                if let Some(Ty::Tuple(ts)) = ty {
                    for (p, t) in ps.iter().zip(ts.iter()) {
                        self.bind_pattern(p, Some(t));
                    }
                    for p in ps.iter().skip(ts.len()) {
                        self.bind_pattern(p, None);
                    }
                } else {
                    for p in ps {
                        self.bind_pattern(p, None);
                    }
                }
            }
            HirPattern::TupleStruct { fields, .. } => {
                for p in fields {
                    self.bind_pattern(p, None);
                }
            }
            HirPattern::Wildcard | HirPattern::Literal(_) | HirPattern::Path(_) => {}
        }
    }
}

struct CheckCtx<'a> {
    env: &'a LowerEnv<'a>,
    fns: &'a HashMap<String, &'a HirFn>,
    diags: &'a mut Vec<Diagnostic>,
}

impl<'a> CheckCtx<'a> {
    fn check_stmt(
        &mut self,
        stmt: &HirStmt,
        ret_ty: Option<&Ty>,
        scope: &mut LocalScope,
        span: &Span,
    ) {
        match stmt {
            HirStmt::Let {
                pattern,
                ty,
                value,
                else_block,
                ..
            } => {
                self.check_expr(value, ty.as_ref(), ret_ty, scope, span);
                if !else_block.is_empty() {
                    let mut else_scope = scope.clone();
                    for s in else_block {
                        self.check_stmt(s, ret_ty, &mut else_scope, span);
                    }
                }
                let bound_ty = ty.clone().unwrap_or_else(|| value.ty());
                scope.bind_pattern(pattern, Some(&bound_ty));
                if let HirPattern::Binding { name, .. } = pattern
                    && expr_produces_query_row(value)
                {
                    scope.query_rows.insert(name.clone());
                }
            }
            HirStmt::Assign { target, op, value } => {
                self.check_lvalue(target, ret_ty, scope, span);
                let target_ty = target.ty().clone();
                let exp: Option<Ty> =
                    if *op == crate::hir::HirAssignOp::Set && target_ty != Ty::Unknown {
                        Some(target_ty)
                    } else if *op == crate::hir::HirAssignOp::Set
                        && let HirLValue::Local { name, .. } = target
                    {
                        scope.var_tys.get(name).cloned()
                    } else {
                        None
                    };
                self.check_expr(value, exp.as_ref(), ret_ty, scope, span);
            }
            HirStmt::Expr(e)
            | HirStmt::Wait(e)
            | HirStmt::WaitUntil(e)
            | HirStmt::RequireTrue(e)
            | HirStmt::Emit(e)
            | HirStmt::Despawn(e)
            | HirStmt::Break(Some(e)) => {
                self.check_expr(e, None, ret_ty, scope, span);
            }
            HirStmt::Return(Some(e)) => {
                self.check_expr(e, ret_ty, ret_ty, scope, span);
            }
            HirStmt::Return(None)
            | HirStmt::Break(None)
            | HirStmt::Continue
            | HirStmt::YieldTick => {}
            HirStmt::While { cond, body } => {
                self.check_expr(cond, None, ret_ty, scope, span);
                let mut loop_scope = scope.clone();
                for s in body {
                    self.check_stmt(s, ret_ty, &mut loop_scope, span);
                }
            }
            HirStmt::Loop { body } => {
                let mut loop_scope = scope.clone();
                for s in body {
                    self.check_stmt(s, ret_ty, &mut loop_scope, span);
                }
            }
            HirStmt::Atomic(at) => {
                let mut body_scope = scope.clone();
                for s in &at.body {
                    self.check_stmt(s, ret_ty, &mut body_scope, span);
                }
                let mut rb_scope = scope.clone();
                for s in &at.on_rollback {
                    self.check_stmt(s, ret_ty, &mut rb_scope, span);
                }
            }
            HirStmt::AbortIf { cond, cleanup } => {
                self.check_expr(cond, None, ret_ty, scope, span);
                let mut cl_scope = scope.clone();
                for s in cleanup {
                    self.check_stmt(s, ret_ty, &mut cl_scope, span);
                }
            }
            HirStmt::Race { branches } => {
                for br in branches {
                    let mut br_scope = scope.clone();
                    for s in br {
                        self.check_stmt(s, ret_ty, &mut br_scope, span);
                    }
                }
            }
            HirStmt::Trigger { target, event, .. } => {
                if let Some(t) = target {
                    self.check_expr(t, None, ret_ty, scope, span);
                }
                self.check_expr(event, None, ret_ty, scope, span);
            }
            HirStmt::InsertRelation {
                entity,
                target,
                payload,
                ..
            } => {
                self.check_expr(entity, None, ret_ty, scope, span);
                self.check_expr(target, None, ret_ty, scope, span);
                if let Some(p) = payload {
                    self.check_expr(p, None, ret_ty, scope, span);
                }
            }
            HirStmt::RemoveRelation { entity, target, .. } => {
                self.check_expr(entity, None, ret_ty, scope, span);
                self.check_expr(target, None, ret_ty, scope, span);
            }
        }
    }

    fn check_lvalue(
        &mut self,
        lv: &HirLValue,
        ret_ty: Option<&Ty>,
        scope: &mut LocalScope,
        span: &Span,
    ) {
        match lv {
            HirLValue::Local { .. } => {}
            HirLValue::Field { base, field, ty } => {
                self.check_lvalue(base, ret_ty, scope, span);
                if *ty == Ty::Unknown {
                    let is_query_row = matches!(
                        base.as_ref(),
                        HirLValue::Local { name, .. } if scope.query_rows.contains(name)
                    );
                    let base_ident = match base.as_ref() {
                        HirLValue::Local { name, .. } => Some(name.as_str()),
                        _ => None,
                    };
                    let eff_base = self.effective_lvalue_ty(base, scope);
                    self.check_unknown_field(&eff_base, base_ident, is_query_row, field, span);
                }
            }
            HirLValue::Index { base, index, .. } => {
                self.check_lvalue(base, ret_ty, scope, span);
                self.check_expr(index, None, ret_ty, scope, span);
            }
            HirLValue::ResourceAccess { client_id, .. } => {
                if let Some(cid) = client_id {
                    self.check_expr(cid, None, ret_ty, scope, span);
                }
            }
            HirLValue::Expr(e) => {
                self.check_expr(e, None, ret_ty, scope, span);
            }
        }
    }

    fn check_expr(
        &mut self,
        expr: &HirExpr,
        expected: Option<&Ty>,
        ret_ty: Option<&Ty>,
        scope: &mut LocalScope,
        span: &Span,
    ) {
        if let Some(exp) = expected
            && let Some(msg) = check_array_or_smallvec_mismatch(expr, exp)
        {
            self.diags.push(Diagnostic::error(
                codes::E0111_TYPE_MISMATCH,
                span.clone(),
                msg,
                None,
            ));
        }

        match expr {
            HirExpr::Unary { expr: inner, .. } | HirExpr::Cast { expr: inner, .. } => {
                self.check_expr(inner, None, ret_ty, scope, span);
            }
            HirExpr::Binary { lhs, rhs, .. } => {
                self.check_expr(lhs, None, ret_ty, scope, span);
                self.check_expr(rhs, None, ret_ty, scope, span);
            }
            HirExpr::Field { base, field, ty } => {
                self.check_expr(base, None, ret_ty, scope, span);
                if *ty == Ty::Unknown {
                    let is_query_row = matches!(
                        base.as_ref(),
                        HirExpr::Path { name, .. } if scope.query_rows.contains(name)
                    );
                    let base_ident = match base.as_ref() {
                        HirExpr::Path { name, .. } => Some(name.as_str()),
                        _ => None,
                    };
                    let eff_base = self.effective_expr_ty(base, scope);
                    self.check_unknown_field(&eff_base, base_ident, is_query_row, field, span);
                }
            }
            HirExpr::Index { base, index, .. } => {
                self.check_expr(base, None, ret_ty, scope, span);
                self.check_expr(index, None, ret_ty, scope, span);
            }
            HirExpr::Call(c) => {
                if let Some(ref recv) = c.receiver {
                    self.check_expr(recv, None, ret_ty, scope, span);
                }
                let matched_fn = if c.receiver.is_none() {
                    let short = c.callee.rsplit("::").next().unwrap_or(&c.callee);
                    self.fns
                        .get(&c.callee)
                        .or_else(|| self.fns.get(short))
                        .copied()
                } else {
                    None
                };
                for (i, arg) in c.args.iter().enumerate() {
                    let arg_exp = matched_fn.and_then(|hf| hf.params.get(i)).map(|p| &p.ty);
                    self.check_expr(arg, arg_exp, ret_ty, scope, span);
                }
            }
            HirExpr::StructLit { name, fields, .. } => {
                let schema = self.env.find_item_fields(name);
                for (fname, fval) in fields {
                    let fty =
                        schema.and_then(|fs| fs.iter().find(|(k, _)| k == fname).map(|(_, t)| t));
                    self.check_expr(fval, fty, ret_ty, scope, span);
                }
            }
            HirExpr::RecordLit { fields, .. } => {
                for (_, fval) in fields {
                    self.check_expr(fval, None, ret_ty, scope, span);
                }
            }
            HirExpr::BundleLit { components } => {
                for ci in components {
                    self.check_comp_init(ci, scope, span);
                }
            }
            HirExpr::ArrayLit { elems, .. } => match expected {
                Some(Ty::Array { elem, .. } | Ty::SmallVec { elem, .. }) => {
                    for e in elems {
                        self.check_expr(e, Some(elem.as_ref()), ret_ty, scope, span);
                    }
                }
                _ => {
                    if let Some(Ty::Array { len: first_len, .. }) = elems.first().map(HirExpr::ty) {
                        for e in elems.iter().skip(1) {
                            if let Ty::Array {
                                len: actual_len, ..
                            } = e.ty()
                                && actual_len != first_len
                            {
                                self.diags.push(Diagnostic::error(
                                        codes::E0111_TYPE_MISMATCH,
                                        span.clone(),
                                        format!(
                                            "inconsistent nested array literal lengths: expected {first_len} elements, found {actual_len}"
                                        ),
                                        None,
                                    ));
                            }
                        }
                    }
                    for e in elems {
                        self.check_expr(e, None, ret_ty, scope, span);
                    }
                }
            },
            HirExpr::Tuple { elems, .. } => {
                if let Some(Ty::Tuple(exp_elems)) = expected {
                    for (e, exp_t) in elems.iter().zip(exp_elems.iter()) {
                        self.check_expr(e, Some(exp_t), ret_ty, scope, span);
                    }
                    for e in elems.iter().skip(exp_elems.len()) {
                        self.check_expr(e, None, ret_ty, scope, span);
                    }
                } else {
                    for e in elems {
                        self.check_expr(e, None, ret_ty, scope, span);
                    }
                }
            }
            HirExpr::Block { stmts, tail, .. } => {
                let mut inner_scope = scope.clone();
                for s in stmts {
                    self.check_stmt(s, ret_ty, &mut inner_scope, span);
                }
                if let Some(t) = tail {
                    self.check_expr(t, expected, ret_ty, &mut inner_scope, span);
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
                self.check_expr(cond, None, ret_ty, scope, span);
                let mut then_scope = scope.clone();
                if let Some(pat) = let_pat {
                    then_scope.bind_pattern(pat, Some(&cond.ty()));
                }
                for s in then_stmts {
                    self.check_stmt(s, ret_ty, &mut then_scope, span);
                }
                if let Some(t) = then_tail {
                    self.check_expr(t, expected, ret_ty, &mut then_scope, span);
                }
                let mut else_scope = scope.clone();
                for s in else_stmts {
                    self.check_stmt(s, ret_ty, &mut else_scope, span);
                }
                if let Some(t) = else_tail {
                    self.check_expr(t, expected, ret_ty, &mut else_scope, span);
                }
            }
            HirExpr::Match(m) => {
                let scrut_ty = m.scrutinee.ty();
                self.check_expr(&m.scrutinee, None, ret_ty, scope, span);
                for arm in &m.arms {
                    let mut arm_scope = scope.clone();
                    arm_scope.bind_pattern(&arm.pattern, Some(&scrut_ty));
                    if let Some(ref g) = arm.guard {
                        self.check_expr(g, None, ret_ty, &mut arm_scope, span);
                    }
                    self.check_expr(&arm.body, expected, ret_ty, &mut arm_scope, span);
                }
            }
            HirExpr::For(f) => self.check_for(f, ret_ty, scope, span),
            HirExpr::Spawn(sp) => {
                if let Some(ref cnt) = sp.count {
                    self.check_expr(cnt, None, ret_ty, scope, span);
                }
                let mut sp_scope = scope.clone();
                if let Some(ref bv) = sp.batch_var {
                    sp_scope.bind_var(bv, Ty::U32);
                }
                for s in &sp.preamble {
                    self.check_stmt(s, ret_ty, &mut sp_scope, span);
                }
                for ci in &sp.components {
                    self.check_comp_init(ci, &mut sp_scope, span);
                }
            }
            HirExpr::Insert { entity, value, .. } => {
                self.check_expr(entity, None, ret_ty, scope, span);
                self.check_expr(value, None, ret_ty, scope, span);
            }
            HirExpr::Remove { entity, .. } => {
                self.check_expr(entity, None, ret_ty, scope, span);
            }
            HirExpr::Path { .. }
            | HirExpr::IntLit { .. }
            | HirExpr::FloatLit { .. }
            | HirExpr::BoolLit(_)
            | HirExpr::StringLit(_)
            | HirExpr::CharLit(_)
            | HirExpr::Query(_)
            | HirExpr::DespawnAll { .. } => {}
        }
    }

    fn check_for(&mut self, f: &HirFor, ret_ty: Option<&Ty>, scope: &LocalScope, span: &Span) {
        let mut loop_scope = scope.clone();
        match &f.iter {
            HirForIter::Query(_) => {}
            HirForIter::Range { start, end, .. } => {
                self.check_expr(start, None, ret_ty, &mut loop_scope, span);
                self.check_expr(end, None, ret_ty, &mut loop_scope, span);
            }
            HirForIter::SpatialDisc { center, radius, .. } => {
                self.check_expr(center, None, ret_ty, &mut loop_scope, span);
                self.check_expr(radius, None, ret_ty, &mut loop_scope, span);
            }
            HirForIter::SpatialSegmentAt {
                tick,
                p0,
                p1,
                radius,
                ..
            } => {
                self.check_expr(tick, None, ret_ty, &mut loop_scope, span);
                self.check_expr(p0, None, ret_ty, &mut loop_scope, span);
                self.check_expr(p1, None, ret_ty, &mut loop_scope, span);
                if let Some(r) = radius {
                    self.check_expr(r, None, ret_ty, &mut loop_scope, span);
                }
            }
            HirForIter::Expr(e) => {
                self.check_expr(e, None, ret_ty, &mut loop_scope, span);
            }
        }
        loop_scope.bind_pattern(&f.binding, None);
        if let HirForIter::Query(q) = &f.iter {
            if let HirPattern::Binding { name: row_name, .. } = &f.binding {
                let single_direct = q.terms.len() == 1
                    && q.terms[0].alias == *row_name
                    && (q.terms[0].field_name.is_some()
                        || matches!(
                            q.terms[0].mode,
                            TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                        ));
                if !single_direct {
                    loop_scope.query_rows.insert(row_name.clone());
                }
            }
            for t in &q.terms {
                if !loop_scope.vars.contains(&t.alias) {
                    let tty = self.resolve_term_ty(t);
                    if tty != Ty::Unknown {
                        loop_scope.term_alias_tys.insert(t.alias.clone(), tty);
                    }
                }
            }
        }
        for s in &f.body {
            self.check_stmt(s, ret_ty, &mut loop_scope, span);
        }
        for r in &f.reduce {
            self.check_expr(&r.identity, None, ret_ty, &mut loop_scope, span);
            self.check_expr(&r.value, None, ret_ty, &mut loop_scope, span);
        }
    }

    fn check_comp_init(&mut self, ci: &HirCompInit, scope: &mut LocalScope, span: &Span) {
        let schema = self.env.find_item_fields(&ci.component).or_else(|| {
            ci.canonical_component
                .as_deref()
                .and_then(|c| self.env.find_item_fields(c))
        });
        for (fname, fval) in &ci.fields {
            let fty = schema.and_then(|fs| fs.iter().find(|(k, _)| k == fname).map(|(_, t)| t));
            self.check_expr(fval, fty, None, scope, span);
        }
    }

    fn resolve_term_ty(&self, t: &HirQueryTerm) -> Ty {
        let base_comp = t.storage_key.split("::").next().unwrap_or(&t.storage_key);
        let core = if let Some(ref field) = t.field_name {
            self.lookup_struct_field_ty(base_comp, field)
                .unwrap_or(Ty::Unknown)
        } else if t.storage_key == "Entity" {
            Ty::Ref("Entity".to_owned())
        } else {
            Ty::Named(base_comp.to_owned())
        };
        if core == Ty::Unknown {
            return Ty::Unknown;
        }
        match t.mode {
            TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite => {
                Ty::Option(Box::new(core))
            }
            _ => core,
        }
    }

    fn lookup_struct_field_ty(&self, owner: &str, field: &str) -> Option<Ty> {
        let short = owner.rsplit("::").next().unwrap_or(owner);
        let base_name = short.split("::").next().unwrap_or(short);
        self.env
            .find_item_fields(owner)
            .or_else(|| self.env.find_item_fields(base_name))
            .and_then(|fs| {
                fs.iter()
                    .find(|(k, _)| k == field)
                    .map(|(_, ty)| ty.clone())
            })
    }

    fn effective_lvalue_ty(&self, lv: &HirLValue, scope: &LocalScope) -> Ty {
        match lv {
            HirLValue::Local { name, ty } => {
                if *ty != Ty::Unknown {
                    ty.clone()
                } else {
                    scope
                        .term_alias_tys
                        .get(name)
                        .or_else(|| scope.var_tys.get(name))
                        .cloned()
                        .unwrap_or(Ty::Unknown)
                }
            }
            HirLValue::Field { base, field, ty } => {
                if *ty != Ty::Unknown {
                    return ty.clone();
                }
                let base_ty = self.effective_lvalue_ty(base, scope);
                self.resolve_field_on_ty(&base_ty, field)
            }
            _ => lv.ty().clone(),
        }
    }

    fn effective_expr_ty(&self, expr: &HirExpr, scope: &LocalScope) -> Ty {
        match expr {
            HirExpr::Path { name, ty } => {
                if *ty != Ty::Unknown {
                    ty.clone()
                } else {
                    scope
                        .term_alias_tys
                        .get(name)
                        .or_else(|| scope.var_tys.get(name))
                        .cloned()
                        .unwrap_or(Ty::Unknown)
                }
            }
            HirExpr::Field { base, field, ty } => {
                if *ty != Ty::Unknown {
                    return ty.clone();
                }
                let base_ty = self.effective_expr_ty(base, scope);
                self.resolve_field_on_ty(&base_ty, field)
            }
            _ => expr.ty(),
        }
    }

    fn resolve_field_on_ty(&self, base_ty: &Ty, field: &str) -> Ty {
        let mut inner = base_ty;
        while let Ty::Borrow { inner: next, .. } = inner {
            inner = next.as_ref();
        }
        match inner {
            Ty::Named(n) => self.lookup_struct_field_ty(n, field).unwrap_or(Ty::Unknown),
            _ => Ty::Unknown,
        }
    }

    fn check_unknown_field(
        &mut self,
        base_ty: &Ty,
        base_ident: Option<&str>,
        is_query_row: bool,
        field: &str,
        span: &Span,
    ) {
        let mut inner = base_ty;
        while let Ty::Borrow { inner: next, .. } = inner {
            inner = next.as_ref();
        }
        if *inner == Ty::Unknown {
            return;
        }
        if is_query_row {
            let row_label = base_ident.unwrap_or("row");
            self.diags.push(Diagnostic::error(
                codes::E0301_UNRESOLVED_SYMBOL,
                span.clone(),
                format!("unknown field or query term `{field}` on query row `{row_label}`"),
                None,
            ));
            return;
        }
        let has_known_schema = match inner {
            Ty::Named(n) => {
                if self.lookup_struct_field_ty(n, field).is_some() {
                    return;
                }
                n.starts_with("__table_row::")
                    || (!self.env.enums.contains_key(n)
                        && (self.env.find_item_fields(n).is_some()
                            || self.env.find_layout(n).is_some()))
            }
            Ty::Tuple(_) | Ty::Record(_) => true,
            _ => false,
        };
        if has_known_schema {
            self.diags.push(Diagnostic::error(
                codes::E0301_UNRESOLVED_SYMBOL,
                span.clone(),
                format!("unknown field `{field}` on type `{inner:?}`"),
                None,
            ));
        }
    }
}

fn expr_produces_query_row(expr: &HirExpr) -> bool {
    match expr {
        HirExpr::Query(HirQuery {
            is_count: false, ..
        }) => true,
        HirExpr::Call(c) if c.callee == "unwrap" => {
            c.receiver.as_deref().is_some_and(expr_produces_query_row)
        }
        HirExpr::If {
            then_tail,
            else_tail,
            ..
        } => {
            then_tail.as_deref().is_some_and(expr_produces_query_row)
                || else_tail.as_deref().is_some_and(expr_produces_query_row)
        }
        HirExpr::Match(m) => m.arms.iter().any(|a| expr_produces_query_row(&a.body)),
        HirExpr::Block { tail, .. } => tail.as_deref().is_some_and(expr_produces_query_row),
        _ => false,
    }
}
