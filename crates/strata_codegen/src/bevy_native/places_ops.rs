//! BevyNative place resolution, ABI field load/store wrapping, binary ops, and intrinsics.

use super::*;

pub(super) struct PeelFieldStep {
    pub(super) rfname: String,
    pub(super) blob_step: Option<(String, String, &'static str, &'static str)>,
}

pub(super) fn peel_ptr_fields(pt: &PtrTarget) -> (&PtrTarget, String) {
    let (base, steps) = peel_ptr_field_steps(pt);
    let suffix: String = steps
        .into_iter()
        .map(|s| format!(".{}", s.rfname))
        .collect();
    (base, suffix)
}

pub(super) fn peel_ptr_field_steps(mut pt: &PtrTarget) -> (&PtrTarget, Vec<PeelFieldStep>) {
    let mut steps = Vec::new();
    while let PtrTarget::Field {
        base,
        field,
        blob_step,
    } = pt
    {
        steps.push(PeelFieldStep {
            rfname: sanitize_rust_ident(field),
            blob_step: blob_step.clone(),
        });
        pt = base;
    }
    steps.reverse();
    (pt, steps)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_place_mut(
    out: &mut String,
    ptr: LocalId,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    indent: &str,
    in_undo: bool,
    build: impl Fn(&str) -> String,
) {
    if let Some(pt) = analysis.ptr_targets.get(&ptr) {
        emit_place_mut_for_target(
            out,
            pt,
            analysis,
            query_plans,
            in_chunk,
            indent,
            in_undo,
            &build,
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_place_mut_for_target(
    out: &mut String,
    pt: &PtrTarget,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    indent: &str,
    in_undo: bool,
    build: &dyn Fn(&str) -> String,
) {
    let (base_pt, steps) = peel_ptr_field_steps(pt);
    let has_blob = steps.iter().any(|s| s.blob_step.is_some());
    let apply = |base_expr: &str| {
        if !has_blob {
            let suffix: String = steps.iter().map(|s| format!(".{}", s.rfname)).collect();
            if suffix.is_empty() {
                build(base_expr)
            } else {
                build(&format!("(&mut {base_expr}{suffix})"))
            }
        } else {
            let mut stmts = Vec::new();
            let mut cur_place = base_expr.to_owned();
            let mut bindings: Vec<(String, String, String, &'static str)> = Vec::new();
            for (idx, step) in steps.iter().enumerate() {
                if let Some((ref rfname, ref sname, unpack_fn, pack_fn)) = step.blob_step {
                    let bvar = format!("__bp_{idx}");
                    stmts.push(format!(
                        "let mut {bvar} = {sname}::{unpack_fn}(&{cur_place}.{rfname});"
                    ));
                    bindings.push((cur_place.clone(), rfname.clone(), bvar.clone(), pack_fn));
                    cur_place = bvar;
                } else {
                    cur_place = format!("{cur_place}.{}", step.rfname);
                }
            }
            stmts.push(build(&format!("(&mut {cur_place})")));
            for (parent_place, rfname, bvar, pack_fn) in bindings.into_iter().rev() {
                stmts.push(format!("{parent_place}.{rfname} = {bvar}.{pack_fn}();"));
            }
            format!("{{ {} }}", stmts.join(" "))
        }
    };
    let dirty_flag_stmt = |qi: u32, si: usize| -> String {
        if in_undo {
            String::new()
        } else if analysis.has_checkpoint {
            format!(
                "if __tx_active {{ __q{qi}_tx_dirty_{si} = true; }} else {{ __q{qi}_dirty_{si} = true; }}"
            )
        } else {
            format!("__q{qi}_dirty_{si} = true;")
        }
    };
    let dirty_row_stmt = |qi: u32, si: usize, sel_var: &str, row: LocalId| -> String {
        if in_undo {
            String::new()
        } else if analysis.has_checkpoint {
            format!(
                "if __tx_active {{ __q{qi}_tx_rows_{si}.push(__loc_{0} as usize); }} else {{ {sel_var}.mark_dirty_row(__loc_{0} as usize); }}",
                row.0
            )
        } else {
            format!("{sel_var}.mark_dirty_row(__loc_{} as usize);", row.0)
        }
    };
    match base_pt {
        PtrTarget::Resource { var_name, .. } => {
            let body = apply(&format!("(&mut *{var_name})"));
            writeln!(out, "{indent}{body}").ok();
        }
        PtrTarget::ParamPtr { var_name, .. } => {
            let body = apply(var_name);
            writeln!(out, "{indent}{body}").ok();
        }
        PtrTarget::QueryRow {
            query_idx,
            slot_idx,
            row_idx_local,
            selective,
            optional,
            is_sparse,
            ..
        } => {
            let is_1row = *is_sparse || in_chunk.is_some_and(ChunkLoopInfo::is_1row);
            let is_pset_snap = in_chunk.is_some_and(|c| c.is_pset_snap);
            if *selective && *optional {
                let d_stmt = if is_pset_snap || is_1row {
                    dirty_flag_stmt(*query_idx, *slot_idx)
                } else {
                    dirty_row_stmt(*query_idx, *slot_idx, "__opt_sel", *row_idx_local)
                };
                if is_pset_snap {
                    let body = apply("(&mut **__opt_item)");
                    writeln!(
                        out,
                        "{indent}if let Some(ref mut __opt_item) = __q{query_idx}_sel_{slot_idx} {{ {body} {d_stmt} }}"
                    )
                    .ok();
                } else if is_1row {
                    let body = apply("(&mut *__opt_sel.bypass_change_detection())");
                    writeln!(
                        out,
                        "{indent}if let Some(ref mut __opt_sel) = __q{query_idx}_sel_{slot_idx} {{ {body} {d_stmt} }}"
                    )
                    .ok();
                } else {
                    let body = apply(&format!(
                        "(&mut __opt_sel.as_mut_untracked()[__loc_{} as usize])",
                        row_idx_local.0
                    ));
                    writeln!(
                        out,
                        "{indent}if let Some(ref mut __opt_sel) = __q{query_idx}_sel_{slot_idx} {{ {body} {d_stmt} }}"
                    )
                    .ok();
                }
            } else if *selective {
                if is_pset_snap {
                    let body = apply(&format!("(&mut *__q{query_idx}_sel_{slot_idx})"));
                    let d_stmt = dirty_flag_stmt(*query_idx, *slot_idx);
                    writeln!(out, "{indent}{body}").ok();
                    if !d_stmt.is_empty() {
                        writeln!(out, "{indent}{d_stmt}").ok();
                    }
                } else if is_1row {
                    let body = apply(&format!(
                        "(&mut *__q{query_idx}_sel_{slot_idx}.bypass_change_detection())"
                    ));
                    let d_stmt = dirty_flag_stmt(*query_idx, *slot_idx);
                    writeln!(out, "{indent}{body}").ok();
                    if !d_stmt.is_empty() {
                        writeln!(out, "{indent}{d_stmt}").ok();
                    }
                } else {
                    let body = apply(&format!(
                        "(&mut __q{query_idx}_sel_{slot_idx}.as_mut_untracked()[__loc_{} as usize])",
                        row_idx_local.0
                    ));
                    let sel_var = format!("__q{query_idx}_sel_{slot_idx}");
                    let d_stmt = dirty_row_stmt(*query_idx, *slot_idx, &sel_var, *row_idx_local);
                    writeln!(out, "{indent}{body}").ok();
                    if !d_stmt.is_empty() {
                        writeln!(out, "{indent}{d_stmt}").ok();
                    }
                }
            } else if *optional {
                let body = apply("__opt_item");
                if is_1row {
                    writeln!(
                        out,
                        "{indent}if let Some(ref mut __opt_item) = __q{query_idx}_col_{slot_idx} {{ {body} }}"
                    )
                    .ok();
                } else {
                    writeln!(
                        out,
                        "{indent}if let Some(ref mut __opt_s) = __q{query_idx}_col_{slot_idx} {{ let __opt_item = &mut __opt_s[__loc_{} as usize]; {body} }}",
                        row_idx_local.0
                    )
                    .ok();
                }
            } else if is_1row {
                let body = apply(&format!("(&mut *__q{query_idx}_col_{slot_idx})"));
                writeln!(out, "{indent}{body}").ok();
            } else {
                let body = apply(&format!(
                    "(&mut __q{query_idx}_col_{slot_idx}[__loc_{} as usize])",
                    row_idx_local.0
                ));
                writeln!(out, "{indent}{body}").ok();
            }
        }
        PtrTarget::EntityRow {
            query_idx,
            slot_idx,
            entity_local,
            optional,
            ..
        } => {
            let plan = &query_plans[*query_idx as usize];
            let qa = query_access_expr(plan);
            let tup_idx = slot_idx + usize::from(plan.needs_entity);
            let body = apply("__ent_comp");
            if *optional {
                writeln!(
                    out,
                    "{indent}if let Some(__e) = Entity::try_from_bits(__loc_{}.to_bits()) {{ if let Ok(mut __row) = {qa}.get_mut(__e) {{ if let Some(mut __mc) = __row.{tup_idx} {{ let __ent_comp = &mut *__mc; {body} }} }} }}",
                    entity_local.0
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "{indent}if let Some(__e) = Entity::try_from_bits(__loc_{}.to_bits()) {{ if let Ok(mut __row) = {qa}.get_mut(__e) {{ let __ent_comp = &mut *__row.{tup_idx}; {body} }} }}",
                    entity_local.0
                )
                .ok();
            }
        }
        PtrTarget::SlotRef { slot_local, .. } => {
            let sname = if analysis.slot_tys.contains_key(slot_local) {
                format!("(&mut __slot_{})", slot_local.0)
            } else {
                format!("(&mut __loc_{})", slot_local.0)
            };
            let body = apply(&sname);
            writeln!(out, "{indent}{body}").ok();
        }
        PtrTarget::UpCascadeDirect {
            up_local,
            up_q_expr,
            is_mut,
            ..
        } => {
            if *is_mut {
                let body = apply("(&mut *__uc)");
                writeln!(
                    out,
                    "{indent}if let Some(__e) = __up_ent_{} {{ if let Ok(mut __uc) = {up_q_expr}.get_mut(__e) {{ {body} }} }}",
                    up_local.0
                )
                .ok();
            }
        }
        PtrTarget::UpCascadeSlot {
            slot_local,
            row_target,
            up_q_expr,
            is_mut,
            ..
        } => {
            writeln!(out, "{indent}if __up_flag_{} {{", slot_local.0).ok();
            if *is_mut {
                let body = apply("(&mut *__uc)");
                writeln!(
                    out,
                    "{indent}    if let Some(__e) = __up_ent_{} {{ if let Ok(mut __uc) = {up_q_expr}.get_mut(__e) {{ {body} }} }}",
                    slot_local.0
                )
                .ok();
            }
            writeln!(out, "{indent}}} else {{").ok();
            if let Some(rt) = row_target {
                let inner_indent = format!("{indent}    ");
                emit_place_mut_for_target(
                    out,
                    rt,
                    analysis,
                    query_plans,
                    in_chunk,
                    &inner_indent,
                    in_undo,
                    build,
                );
            }
            writeln!(out, "{indent}}}").ok();
        }
        _ => {}
    }
}

pub(super) fn emit_place_mut_res_expr(
    ptr: LocalId,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    in_undo: bool,
    build: impl Fn(&str) -> String,
) -> Option<String> {
    let pt = analysis.ptr_targets.get(&ptr)?;
    emit_place_mut_res_for_target(pt, analysis, query_plans, in_chunk, in_undo, &build)
}

pub(super) fn emit_place_mut_res_for_target(
    pt: &PtrTarget,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    in_undo: bool,
    build: &dyn Fn(&str) -> String,
) -> Option<String> {
    let (base_pt, suffix) = peel_ptr_fields(pt);
    let apply = |base_expr: &str| {
        if suffix.is_empty() {
            build(base_expr)
        } else {
            build(&format!("(&mut {base_expr}{suffix})"))
        }
    };
    let dirty_flag_stmt = |qi: u32, si: usize| -> String {
        if in_undo {
            String::new()
        } else if analysis.has_checkpoint {
            format!(
                "if __tx_active {{ __q{qi}_tx_dirty_{si} = true; }} else {{ __q{qi}_dirty_{si} = true; }}"
            )
        } else {
            format!("__q{qi}_dirty_{si} = true;")
        }
    };
    let dirty_row_stmt = |qi: u32, si: usize, sel_var: &str, row: LocalId| -> String {
        if in_undo {
            String::new()
        } else if analysis.has_checkpoint {
            format!(
                "if __tx_active {{ __q{qi}_tx_rows_{si}.push(__loc_{0} as usize); }} else {{ {sel_var}.mark_dirty_row(__loc_{0} as usize); }}",
                row.0
            )
        } else {
            format!("{sel_var}.mark_dirty_row(__loc_{} as usize);", row.0)
        }
    };
    match base_pt {
        PtrTarget::Resource { var_name, .. } => Some(apply(&format!("(&mut *{var_name})"))),
        PtrTarget::ParamPtr { var_name, .. } => Some(apply(var_name)),
        PtrTarget::QueryRow {
            query_idx,
            slot_idx,
            row_idx_local,
            selective,
            optional,
            is_sparse,
            ..
        } => {
            let is_1row = *is_sparse || in_chunk.is_some_and(ChunkLoopInfo::is_1row);
            let is_pset_snap = in_chunk.is_some_and(|c| c.is_pset_snap);
            if *selective && *optional {
                let d_stmt = if is_pset_snap || is_1row {
                    dirty_flag_stmt(*query_idx, *slot_idx)
                } else {
                    dirty_row_stmt(*query_idx, *slot_idx, "__opt_sel", *row_idx_local)
                };
                if is_pset_snap {
                    let b = apply("(&mut **__opt_item)");
                    Some(format!(
                        "__q{query_idx}_sel_{slot_idx}.as_mut().map_or(false, |__opt_item| {{ let __r = {b}; if __r {{ {d_stmt} }} __r }})"
                    ))
                } else if is_1row {
                    let b = apply("(&mut *__opt_sel.bypass_change_detection())");
                    Some(format!(
                        "__q{query_idx}_sel_{slot_idx}.as_mut().map_or(false, |__opt_sel| {{ let __r = {b}; if __r {{ {d_stmt} }} __r }})"
                    ))
                } else {
                    let b = apply(&format!(
                        "(&mut __opt_sel.as_mut_untracked()[__loc_{} as usize])",
                        row_idx_local.0
                    ));
                    Some(format!(
                        "__q{query_idx}_sel_{slot_idx}.as_mut().map_or(false, |__opt_sel| {{ let __r = {b}; if __r {{ {d_stmt} }} __r }})"
                    ))
                }
            } else if *selective {
                if is_pset_snap {
                    let b = apply(&format!("(&mut *__q{query_idx}_sel_{slot_idx})"));
                    let d_stmt = dirty_flag_stmt(*query_idx, *slot_idx);
                    Some(format!("{{ let __r = {b}; if __r {{ {d_stmt} }} __r }}"))
                } else if is_1row {
                    let b = apply(&format!(
                        "(&mut *__q{query_idx}_sel_{slot_idx}.bypass_change_detection())"
                    ));
                    let d_stmt = dirty_flag_stmt(*query_idx, *slot_idx);
                    Some(format!("{{ let __r = {b}; if __r {{ {d_stmt} }} __r }}"))
                } else {
                    let b = apply(&format!(
                        "(&mut __q{query_idx}_sel_{slot_idx}.as_mut_untracked()[__loc_{} as usize])",
                        row_idx_local.0
                    ));
                    let sel_var = format!("__q{query_idx}_sel_{slot_idx}");
                    let d_stmt = dirty_row_stmt(*query_idx, *slot_idx, &sel_var, *row_idx_local);
                    Some(format!("{{ let __r = {b}; if __r {{ {d_stmt} }} __r }}"))
                }
            } else if *optional {
                let b = apply("__opt_item");
                if is_1row {
                    Some(format!(
                        "__q{query_idx}_col_{slot_idx}.as_deref_mut().map_or(false, |__opt_item| {b})"
                    ))
                } else {
                    Some(format!(
                        "__q{query_idx}_col_{slot_idx}.as_mut().map_or(false, |__opt_s| {{ let __opt_item = &mut __opt_s[__loc_{} as usize]; {b} }})",
                        row_idx_local.0
                    ))
                }
            } else if is_1row {
                Some(apply(&format!("(&mut *__q{query_idx}_col_{slot_idx})")))
            } else {
                Some(apply(&format!(
                    "(&mut __q{query_idx}_col_{slot_idx}[__loc_{} as usize])",
                    row_idx_local.0
                )))
            }
        }
        PtrTarget::EntityRow {
            query_idx,
            slot_idx,
            entity_local,
            optional,
            ..
        } => {
            let plan = &query_plans[*query_idx as usize];
            let qa = query_access_expr(plan);
            let tup_idx = slot_idx + usize::from(plan.needs_entity);
            let b = apply("__ent_comp");
            if *optional {
                Some(format!(
                    "Entity::try_from_bits(__loc_{}.to_bits()).is_some_and(|__e| {qa}.get_mut(__e).ok().is_some_and(|__row| __row.{tup_idx}.is_some_and(|mut __mc| {{ let __ent_comp = &mut *__mc; {b} }})))",
                    entity_local.0
                ))
            } else {
                Some(format!(
                    "Entity::try_from_bits(__loc_{}.to_bits()).is_some_and(|__e| {qa}.get_mut(__e).ok().is_some_and(|mut __row| {{ let __ent_comp = &mut *__row.{tup_idx}; {b} }}))",
                    entity_local.0
                ))
            }
        }
        PtrTarget::SlotRef { slot_local, .. } => {
            let sname = if analysis.slot_tys.contains_key(slot_local) {
                format!("(&mut __slot_{})", slot_local.0)
            } else {
                format!("(&mut __loc_{})", slot_local.0)
            };
            Some(apply(&sname))
        }
        PtrTarget::UpCascadeDirect {
            up_local,
            up_q_expr,
            is_mut,
            ..
        } => {
            if *is_mut {
                let b = apply("(&mut *__uc)");
                Some(format!(
                    "if let Some(__e) = __up_ent_{} {{ if let Ok(mut __uc) = {up_q_expr}.get_mut(__e) {{ {b} }} else {{ false }} }} else {{ false }}",
                    up_local.0
                ))
            } else {
                None
            }
        }
        PtrTarget::UpCascadeSlot {
            slot_local,
            row_target,
            up_q_expr,
            is_mut,
            ..
        } => {
            let up_expr = if *is_mut {
                let b = apply("(&mut *__uc)");
                format!(
                    "if let Some(__e) = __up_ent_{} {{ if let Ok(mut __uc) = {up_q_expr}.get_mut(__e) {{ {b} }} else {{ false }} }} else {{ false }}",
                    slot_local.0
                )
            } else {
                "false".to_owned()
            };
            let row_expr = row_target
                .as_ref()
                .and_then(|rt| {
                    emit_place_mut_res_for_target(
                        rt,
                        analysis,
                        query_plans,
                        in_chunk,
                        in_undo,
                        build,
                    )
                })
                .unwrap_or_else(|| "false".to_owned());
            Some(format!(
                "if __up_flag_{} {{ {up_expr} }} else {{ {row_expr} }}",
                slot_local.0
            ))
        }
        _ => None,
    }
}

pub(super) fn emit_place_ref_expr(
    ptr: LocalId,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    build: impl Fn(&str) -> String,
    default_expr: &str,
) -> String {
    let Some(pt) = analysis.ptr_targets.get(&ptr) else {
        return format!("({})", build(&format!("(&__loc_{})", ptr.0)));
    };
    emit_place_ref_for_target(pt, analysis, query_plans, in_chunk, &build, default_expr)
}

pub(super) fn emit_place_ref_for_target(
    pt: &PtrTarget,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    build: &dyn Fn(&str) -> String,
    default_expr: &str,
) -> String {
    let (base_pt, steps) = peel_ptr_field_steps(pt);
    let apply = |base_expr: &str| {
        let mut cur = base_expr.to_owned();
        for step in &steps {
            if let Some((ref rfname, ref sname, unpack_fn, _pack_fn)) = step.blob_step {
                cur = format!("(&{sname}::{unpack_fn}(&{cur}.{rfname}))");
            } else {
                cur = format!("{cur}.{}", step.rfname);
            }
        }
        if steps.is_empty() || steps.last().is_some_and(|s| s.blob_step.is_some()) {
            build(&cur)
        } else {
            build(&format!("(&{cur})"))
        }
    };
    match base_pt {
        PtrTarget::Resource { var_name, .. } => apply(&format!("(&*{var_name})")),
        PtrTarget::ParamPtr { var_name, .. } => apply(var_name),
        PtrTarget::TriggerPayload => {
            if in_chunk.is_some_and(|c| c.use_par) {
                apply("(&__obs_ev_copy)")
            } else {
                apply("on.event()")
            }
        }
        PtrTarget::QueryRow {
            query_idx,
            slot_idx,
            row_idx_local,
            selective,
            optional,
            is_sparse,
            ..
        } => {
            let is_1row = *is_sparse || in_chunk.is_some_and(ChunkLoopInfo::is_1row);
            let is_pset_snap = in_chunk.is_some_and(|c| c.is_pset_snap);
            if *selective && *optional {
                let b = apply("__opt_item");
                if is_pset_snap || is_1row {
                    format!(
                        "__q{query_idx}_sel_{slot_idx}.as_deref().map_or({default_expr}, |__opt_item| {b})"
                    )
                } else {
                    format!(
                        "__q{query_idx}_sel_{slot_idx}.as_ref().map_or({default_expr}, |__opt_s| {{ let __opt_item = &__opt_s.as_slice()[__loc_{} as usize]; {b} }})",
                        row_idx_local.0
                    )
                }
            } else if *selective {
                if is_1row {
                    apply(&format!("(&*__q{query_idx}_sel_{slot_idx})"))
                } else {
                    apply(&format!(
                        "(&__q{query_idx}_sel_{slot_idx}.as_slice()[__loc_{} as usize])",
                        row_idx_local.0
                    ))
                }
            } else if *optional {
                let b = apply("__opt_item");
                if is_1row {
                    format!(
                        "__q{query_idx}_col_{slot_idx}.as_deref().map_or({default_expr}, |__opt_item| {b})"
                    )
                } else {
                    format!(
                        "__q{query_idx}_col_{slot_idx}.as_ref().map_or({default_expr}, |__opt_s| {{ let __opt_item = &__opt_s[__loc_{} as usize]; {b} }})",
                        row_idx_local.0
                    )
                }
            } else if is_1row {
                apply(&format!("(&*__q{query_idx}_col_{slot_idx})"))
            } else {
                apply(&format!(
                    "(&__q{query_idx}_col_{slot_idx}[__loc_{} as usize])",
                    row_idx_local.0
                ))
            }
        }
        PtrTarget::EntityRow {
            query_idx,
            slot_idx,
            entity_local,
            optional,
            ..
        } => {
            let plan = &query_plans[*query_idx as usize];
            let qa = query_access_expr(plan);
            let tup_idx = slot_idx + usize::from(plan.needs_entity);
            let b = apply("__ent_comp");
            if *optional {
                format!(
                    "Entity::try_from_bits(__loc_{}.to_bits()).map_or({default_expr}, |__e| {qa}.get(__e).ok().map_or({default_expr}, |__row| __row.{tup_idx}.map_or({default_expr}, |__ent_comp| {b})))",
                    entity_local.0
                )
            } else {
                format!(
                    "Entity::try_from_bits(__loc_{}.to_bits()).map_or({default_expr}, |__e| {qa}.get(__e).ok().map_or({default_expr}, |__row| {{ let __ent_comp = &*__row.{tup_idx}; {b} }}))",
                    entity_local.0
                )
            }
        }
        PtrTarget::SlotRef { slot_local, .. } => {
            if analysis.slot_tys.contains_key(slot_local) {
                apply(&format!("(&__slot_{})", slot_local.0))
            } else {
                apply(&format!("(&__loc_{})", slot_local.0))
            }
        }
        PtrTarget::UpCascadeDirect {
            up_local,
            up_q_expr,
            ..
        } => {
            let b = apply("(&*__uc)");
            format!(
                "if let Some(__e) = __up_ent_{} {{ if let Ok(__uc) = {up_q_expr}.get(__e) {{ {b} }} else {{ {default_expr} }} }} else {{ {default_expr} }}",
                up_local.0
            )
        }
        PtrTarget::UpCascadeSlot {
            slot_local,
            row_target,
            up_q_expr,
            ..
        } => {
            let b = apply("(&*__uc)");
            let up_expr = format!(
                "if let Some(__e) = __up_ent_{} {{ if let Ok(__uc) = {up_q_expr}.get(__e) {{ {b} }} else {{ {default_expr} }} }} else {{ {default_expr} }}",
                slot_local.0
            );
            let row_expr = row_target.as_ref().map_or_else(
                || default_expr.to_owned(),
                |rt| {
                    emit_place_ref_for_target(
                        rt,
                        analysis,
                        query_plans,
                        in_chunk,
                        build,
                        default_expr,
                    )
                },
            );
            format!(
                "if __up_flag_{} {{ {up_expr} }} else {{ {row_expr} }}",
                slot_local.0
            )
        }
        _ => default_expr.to_owned(),
    }
}

pub(super) struct BlobAccessStep {
    pub(super) rfname: String,
    pub(super) struct_name: String,
    pub(super) unpack_fn: &'static str,
    pub(super) pack_fn: &'static str,
}

pub(super) struct ResolvedFieldAccess<'a> {
    pub(super) steps: Vec<BlobAccessStep>,
    pub(super) leaf_chain: String,
    pub(super) sf_opt: Option<&'a SolvedField>,
    pub(super) is_vec_lane: bool,
    pub(super) is_entity_ev: bool,
}

pub(super) fn resolve_blob_field_access<'a>(
    layout_key: &str,
    field: &str,
    ctx: &'a NativeCtx<'a>,
) -> ResolvedFieldAccess<'a> {
    if let Some(mut entry) = ctx.find_layout_entry(layout_key) {
        let is_entity_ev = ctx.entity_events.contains(&entry.layout.canonical_name);
        let parts: Vec<&str> = field.split('.').collect();
        let mut steps = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            let Some(sf) = entry.layout.fields.iter().find(|f| f.name == *part) else {
                break;
            };
            if i + 1 == parts.len() {
                return ResolvedFieldAccess {
                    steps,
                    leaf_chain: sanitize_rust_ident(part),
                    sf_opt: Some(sf),
                    is_vec_lane: false,
                    is_entity_ev,
                };
            }
            if i + 2 == parts.len()
                && matches!(
                    sf.ty,
                    Ty::Vec2
                        | Ty::Vec3
                        | Ty::Vec3a
                        | Ty::Vec4
                        | Ty::Quat
                        | Ty::Rgba
                        | Ty::IVec2
                        | Ty::IVec3
                        | Ty::UVec2
                )
            {
                let lane = parts[i + 1];
                let idx = match lane {
                    "x" | "r" => Some(0),
                    "y" | "g" => Some(1),
                    "z" | "b" => Some(2),
                    "w" | "a" => Some(3),
                    _ => None,
                };
                if let Some(li) = idx {
                    return ResolvedFieldAccess {
                        steps,
                        leaf_chain: format!("{}[{li}]", sanitize_rust_ident(part)),
                        sf_opt: None,
                        is_vec_lane: true,
                        is_entity_ev: false,
                    };
                }
            }
            if let Ty::Named(ref inner_key) = sf.ty
                && let Some(next_entry) = ctx.find_layout_entry(inner_key)
                && next_entry.layout.item_kind != SchemaItemKind::Enum
                && next_entry.layout.size > 0
                && !next_entry.layout.fields.is_empty()
            {
                let blob_ty = rust_abi_type_for_field(sf, ctx.mir);
                steps.push(BlobAccessStep {
                    rfname: sanitize_rust_ident(part),
                    struct_name: next_entry.struct_name.clone(),
                    unpack_fn: blob_unpack_method_for_blob_ty(&blob_ty),
                    pack_fn: blob_pack_method_for_blob_ty(&blob_ty),
                });
                entry = next_entry;
                continue;
            }
            let rem_chain = parts[i..]
                .iter()
                .map(|p| sanitize_rust_ident(p))
                .collect::<Vec<_>>()
                .join(".");
            return ResolvedFieldAccess {
                steps,
                leaf_chain: rem_chain,
                sf_opt: Some(sf),
                is_vec_lane: false,
                is_entity_ev,
            };
        }
    }
    let field_parts: Vec<&str> = field.split('.').collect();
    let chain = field_parts
        .iter()
        .map(|p| sanitize_rust_ident(p))
        .collect::<Vec<_>>()
        .join(".");
    ResolvedFieldAccess {
        steps: Vec::new(),
        leaf_chain: chain,
        sf_opt: None,
        is_vec_lane: false,
        is_entity_ev: false,
    }
}

pub(super) fn build_field_load_from_place(
    place: &str,
    access: &ResolvedFieldAccess<'_>,
    dst_vt: &ValTy,
    ctx: &NativeCtx<'_>,
) -> String {
    let mut cur = place.to_owned();
    for step in &access.steps {
        cur = format!(
            "{}::{}(&{}.{})",
            step.struct_name, step.unpack_fn, cur, step.rfname
        );
    }
    let raw = format!("{cur}.{}", access.leaf_chain);
    if let Some(sf) = access.sf_opt {
        let raw_adj = if access.is_entity_ev && access.steps.is_empty() && sf.name == "entity" {
            format!("{raw}.0")
        } else {
            raw
        };
        unwrap_abi_field_load(&raw_adj, sf, dst_vt, ctx)
    } else if access.is_vec_lane {
        coerce_expr(&raw, &ValTy::F32, dst_vt)
    } else {
        raw
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_field_load_expr(
    base_ptr: LocalId,
    layout_key: &str,
    field: &str,
    dst_vt: &ValTy,
    _func: &MirFunction,
    ctx: &NativeCtx<'_>,
    query_plans: &[QueryEmitPlan],
    analysis: &FnAnalysis,
    in_chunk: Option<&ChunkLoopInfo>,
) -> String {
    if layout_key == "tuple" || matches!(analysis.val_tys[base_ptr.0 as usize], ValTy::Tuple(_)) {
        let idx = field.trim_start_matches('_');
        let raw = format!("__loc_{}.{idx}", base_ptr.0);
        if let ValTy::Tuple(ref elems) = analysis.val_tys[base_ptr.0 as usize]
            && let Ok(i) = idx.parse::<usize>()
            && let Some(elem_vt) = elems.get(i)
        {
            return coerce_expr(&raw, elem_vt, dst_vt);
        }
        return raw;
    }

    let access = resolve_blob_field_access(layout_key, field, ctx);

    // Value-held table row or struct in an SSA register
    if !analysis.ptr_targets.contains_key(&base_ptr) {
        let place = format!("__loc_{}", base_ptr.0);
        return build_field_load_from_place(&place, &access, dst_vt, ctx);
    }

    let def_expr = dst_vt.default_expr();

    emit_place_ref_expr(
        base_ptr,
        analysis,
        query_plans,
        in_chunk,
        |place| build_field_load_from_place(place, &access, dst_vt, ctx),
        &def_expr,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_field_store_stmt(
    out: &mut String,
    base_ptr: LocalId,
    layout_key: &str,
    field: &str,
    val: LocalId,
    ctx: &NativeCtx<'_>,
    query_plans: &[QueryEmitPlan],
    analysis: &FnAnalysis,
    indent: &str,
    in_chunk: Option<&ChunkLoopInfo>,
    in_undo: bool,
) {
    let access = resolve_blob_field_access(layout_key, field, ctx);
    if access.sf_opt.is_none() && !access.is_vec_lane && ctx.find_layout_entry(layout_key).is_some()
    {
        return;
    }

    let (src_vt, src_raw_expr) =
        effective_local_val_and_expr(val, analysis, query_plans, in_chunk, ctx);
    let local_id_opt = if analysis.val_tys[val.0 as usize] != ValTy::PtrMarker {
        Some(val)
    } else {
        None
    };
    let val_expr = if let Some(sf) = access.sf_opt {
        let target_vt = ValTy::from_solved_field(sf, ctx);
        let coerced = coerce_local_expr(local_id_opt, &src_raw_expr, &src_vt, &target_vt, analysis);
        let is_ent_ev = ctx
            .find_layout_entry(layout_key)
            .is_some_and(|e| ctx.entity_events.contains(&e.layout.canonical_name));
        wrap_abi_field_store(&coerced, sf, ctx, is_ent_ev)
    } else if access.is_vec_lane {
        coerce_local_expr(local_id_opt, &src_raw_expr, &src_vt, &ValTy::F32, analysis)
    } else {
        src_raw_expr
    };

    emit_place_mut(
        out,
        base_ptr,
        analysis,
        query_plans,
        in_chunk,
        indent,
        in_undo,
        |place| {
            if access.steps.is_empty() {
                format!("{place}.{} = {val_expr};", access.leaf_chain)
            } else {
                let mut stmts = Vec::new();
                for (idx, step) in access.steps.iter().enumerate() {
                    let src_expr = if idx == 0 {
                        format!("{place}.{}", step.rfname)
                    } else {
                        format!("__bs_{}.{}", idx - 1, step.rfname)
                    };
                    stmts.push(format!(
                        "let mut __bs_{idx} = {}::{}(&{src_expr});",
                        step.struct_name, step.unpack_fn
                    ));
                }
                let last = access.steps.len() - 1;
                stmts.push(format!("__bs_{last}.{} = {val_expr};", access.leaf_chain));
                for idx in (1..access.steps.len()).rev() {
                    let step = &access.steps[idx];
                    stmts.push(format!(
                        "__bs_{}.{} = __bs_{idx}.{}();",
                        idx - 1,
                        step.rfname,
                        step.pack_fn
                    ));
                }
                let first = &access.steps[0];
                stmts.push(format!(
                    "{place}.{} = __bs_0.{}();",
                    first.rfname, first.pack_fn
                ));
                format!("{{ {} }}", stmts.join(" "))
            }
        },
    );
}

pub(super) fn unwrap_abi_ty_load(
    raw: &str,
    ty: &Ty,
    byte_size: usize,
    align: usize,
    ctx: &NativeCtx<'_>,
    depth: usize,
) -> (String, ValTy) {
    match ty {
        Ty::Bool => (format!("({raw}).get()"), ValTy::Bool),
        Ty::Fix32 => (format!("Fixed32({raw})"), ValTy::Fix32),
        Ty::Fix64 => (format!("Fixed64({raw})"), ValTy::Fix64),
        Ty::IVec2 => (raw.to_owned(), ValTy::IVec2),
        Ty::UVec2 => (raw.to_owned(), ValTy::UVec2),
        Ty::IVec3 => (raw.to_owned(), ValTy::IVec3),
        Ty::Named(n) => {
            let short = n.rsplit("::").next().unwrap_or(n);
            if !ctx.enums_by_key.contains_key(n.as_str())
                && !ctx.enums_by_key.contains_key(short)
                && let Some(entry) = ctx.find_layout_entry(n)
                && entry.layout.size > 0
                && !entry.layout.fields.is_empty()
            {
                let blob_ty = aligned_blob_type(byte_size, align);
                let unpack_fn = blob_unpack_method_for_blob_ty(&blob_ty);
                return (
                    format!("{}::{unpack_fn}(&({raw}))", entry.struct_name),
                    ValTy::Struct(entry.struct_name.clone()),
                );
            }
            (raw.to_owned(), ValTy::from_sema_ty(ty, ctx))
        }
        Ty::Array { elem, len } => {
            let elem_sz = byte_size / (*len).max(1);
            let elem_align = if let Ty::Named(en_key) = elem.as_ref() {
                ctx.find_layout_entry(en_key)
                    .map_or(align, |e| e.layout.align)
            } else {
                align
            };
            let var = format!("__ael_{depth}");
            let (elem_expr, elem_vt) =
                unwrap_abi_ty_load(&var, elem, elem_sz, elem_align, ctx, depth + 1);
            let arr_vt = ValTy::Array(Box::new(elem_vt), *len);
            if elem_expr == var {
                (raw.to_owned(), arr_vt)
            } else {
                (format!("({raw}).map(|{var}| {elem_expr})"), arr_vt)
            }
        }
        _ => (raw.to_owned(), ValTy::from_sema_ty(ty, ctx)),
    }
}

pub(super) fn unwrap_abi_field_load(
    raw: &str,
    sf: &SolvedField,
    dst_vt: &ValTy,
    ctx: &NativeCtx<'_>,
) -> String {
    let (normalized, eff_from) = unwrap_abi_ty_load(raw, &sf.ty, sf.size, sf.align, ctx, 0);
    coerce_expr(&normalized, &eff_from, dst_vt)
}

pub(super) fn wrap_abi_ty_store(
    val_expr: &str,
    ty: &Ty,
    byte_size: usize,
    align: usize,
    ctx: &NativeCtx<'_>,
    depth: usize,
) -> String {
    match ty {
        Ty::Bool => format!("FfiBool::from_bool({val_expr})"),
        Ty::Fix32 | Ty::Fix64 => format!("({val_expr}).0"),
        Ty::Named(n) => {
            let short = n.rsplit("::").next().unwrap_or(n);
            if !ctx.enums_by_key.contains_key(n.as_str())
                && !ctx.enums_by_key.contains_key(short)
                && let Some(entry) = ctx.find_layout_entry(n)
                && entry.layout.size > 0
                && !entry.layout.fields.is_empty()
            {
                let blob_ty = aligned_blob_type(byte_size, align);
                let pack_fn = blob_pack_method_for_blob_ty(&blob_ty);
                return format!("({val_expr}).{pack_fn}()");
            }
            val_expr.to_owned()
        }
        Ty::Array { elem, len } => {
            let elem_sz = byte_size / (*len).max(1);
            let elem_align = if let Ty::Named(en_key) = elem.as_ref() {
                ctx.find_layout_entry(en_key)
                    .map_or(align, |e| e.layout.align)
            } else {
                align
            };
            let var = format!("__ael_{depth}");
            let inner = wrap_abi_ty_store(&var, elem, elem_sz, elem_align, ctx, depth + 1);
            if inner == var {
                val_expr.to_owned()
            } else {
                let elem_def = native_default_expr_for_ty(elem, elem_sz, elem_align, ctx);
                format!(
                    "{{ let __src_{depth} = {val_expr}; let mut __out_{depth} = [{elem_def}; {len}]; let mut __i_{depth} = 0usize; while __i_{depth} < {len} {{ let {var} = __src_{depth}[__i_{depth}]; __out_{depth}[__i_{depth}] = {inner}; __i_{depth} += 1; }} __out_{depth} }}"
                )
            }
        }
        _ => val_expr.to_owned(),
    }
}

pub(super) fn wrap_abi_field_store(
    val_expr: &str,
    sf: &SolvedField,
    ctx: &NativeCtx<'_>,
    is_entity_ev: bool,
) -> String {
    if is_entity_ev && sf.name == "entity" {
        return format!("StrataTargetEntity({val_expr})");
    }
    wrap_abi_ty_store(val_expr, &sf.ty, sf.size, sf.align, ctx, 0)
}

pub(super) fn coerce_local_expr(
    local: Option<LocalId>,
    expr: &str,
    from: &ValTy,
    to: &ValTy,
    analysis: &FnAnalysis,
) -> String {
    if let Some(lid) = local {
        if let Some(&fval) = analysis.const_floats.get(&lid)
            && matches!(from, ValTy::F32 | ValTy::F64)
        {
            match to {
                ValTy::Fix32 => {
                    return format!("Fixed32({})", format_fix32_i32_lit(scale_float_fix32(fval)));
                }
                ValTy::Fix64 => {
                    return format!("Fixed64({})", format_fix64_i64_lit(scale_float_fix64(fval)));
                }
                ValTy::F64 => return format_f64_lit(fval),
                _ => {}
            }
        }
        if let ValTy::Array(ref te, tlen) = *to
            && let Some(elems) = analysis.array_inits.get(&lid)
            && elems.len() == tlen
            && matches!(from, ValTy::Array(fe, flen) if *flen == tlen && fe.as_ref() != te.as_ref())
        {
            let parts: Vec<String> = elems
                .iter()
                .map(|el| {
                    coerce_local_expr(
                        Some(*el),
                        &format!("__loc_{}", el.0),
                        &analysis.val_tys[el.0 as usize],
                        te,
                        analysis,
                    )
                })
                .collect();
            return format!("[{}]", parts.join(", "));
        }
    }
    coerce_expr(expr, from, to)
}

pub(super) fn coerce_expr(expr: &str, from: &ValTy, to: &ValTy) -> String {
    coerce_expr_depth(expr, from, to, 0)
}

pub(super) fn coerce_expr_depth(expr: &str, from: &ValTy, to: &ValTy, depth: usize) -> String {
    if from == to || *to == ValTy::Unit || *to == ValTy::PtrMarker {
        return expr.to_owned();
    }
    match (from, to) {
        (ValTy::Entity, ValTy::U64) => format!("({expr}).to_bits()"),
        (ValTy::U64, ValTy::Entity) => format!("FfiEntity::from_bits({expr})"),
        (ValTy::Fix32, ValTy::F32) => format!("({expr}).to_f32()"),
        (ValTy::Fix32, ValTy::F64) => format!("(({expr}).to_f32() as f64)"),
        (ValTy::F32, ValTy::Fix32) => format!("Fixed32::from_f32({expr})"),
        (ValTy::F64, ValTy::Fix32) => format!("Fixed32::from_f32(({expr}) as f32)"),
        (ValTy::Fix64, ValTy::F64) => format!("({expr}).to_f64()"),
        (ValTy::Fix64, ValTy::F32) => format!("(({expr}).to_f64() as f32)"),
        (ValTy::F64, ValTy::Fix64) => format!("Fixed64::from_f64({expr})"),
        (ValTy::F32, ValTy::Fix64) => format!("Fixed64::from_f64(({expr}) as f64)"),
        (ValTy::Fix32, ValTy::Fix64) => format!("Fixed64((({expr}).0 as i64) << 16)"),
        (ValTy::Fix64, ValTy::Fix32) => format!("Fixed32(((({expr}).0) >> 16) as i32)"),
        (ValTy::Fix32, t) if t.is_int() => {
            format!("((({expr}).0 / 65536i32) as {})", t.rust_type())
        }
        (ValTy::Fix64, t) if t.is_int() => {
            format!("((({expr}).0 / 4294967296i64) as {})", t.rust_type())
        }
        (f, ValTy::Fix32) if f.is_int() => {
            format!("Fixed32((({expr} as i64).saturating_mul(65536)) as i32)")
        }
        (f, ValTy::Fix64) if f.is_int() => format!("Fixed64((({expr} as i64) << 32))"),
        (ValTy::Bool, ValTy::Fix32) => format!("Fixed32(if {expr} {{ 65536 }} else {{ 0 }})"),
        (ValTy::Bool, ValTy::Fix64) => {
            format!("Fixed64(if {expr} {{ 4294967296 }} else {{ 0 }})")
        }
        (ValTy::Fix32 | ValTy::Fix64, ValTy::Bool) => format!("(({expr}).0 != 0)"),
        (ValTy::Vec3, ValTy::Vec2) | (ValTy::Vec4, ValTy::Vec2) => {
            format!("[({expr})[0], ({expr})[1]]")
        }
        (ValTy::Vec2, ValTy::Vec3) => format!("[({expr})[0], ({expr})[1], 0.0_f32]"),
        (ValTy::Vec2, ValTy::Vec4) => format!("[({expr})[0], ({expr})[1], 0.0_f32, 0.0_f32]"),
        (ValTy::Vec3, ValTy::Vec4) => {
            format!("[({expr})[0], ({expr})[1], ({expr})[2], 0.0_f32]")
        }
        (ValTy::Vec4, ValTy::Vec3) => format!("[({expr})[0], ({expr})[1], ({expr})[2]]"),
        (ValTy::Array(fe, _), ValTy::BitSet(bits)) if matches!(fe.as_ref(), ValTy::U32) => {
            let words = (*bits).div_ceil(32).max(1);
            format!(
                "{{ let __s = {expr}; let mut __d = [0u32; {words}]; let __n = __s.len().min({words}); __d[..__n].copy_from_slice(&__s[..__n]); __d }}"
            )
        }
        (ValTy::BitSet(_), ValTy::Array(te, tlen)) if matches!(te.as_ref(), ValTy::U32) => {
            format!(
                "{{ let __s = {expr}; let mut __d = [0u32; {tlen}]; let __n = __s.len().min({tlen}); __d[..__n].copy_from_slice(&__s[..__n]); __d }}"
            )
        }
        (ValTy::BitSet(_), ValTy::BitSet(tb)) => {
            let words = (*tb).div_ceil(32).max(1);
            format!(
                "{{ let __s = {expr}; let mut __d = [0u32; {words}]; let __n = __s.len().min({words}); __d[..__n].copy_from_slice(&__s[..__n]); __d }}"
            )
        }
        (f, ValTy::BitSet(bits)) if f.is_int() => {
            let words = (*bits).div_ceil(32).max(1);
            format!(
                "{{ let __m = ({expr}) as u64; let mut __ws = [0u32; {words}]; if {words} > 0 {{ __ws[0] = __m as u32; }} if {words} > 1 {{ __ws[1] = (__m >> 32) as u32; }} __ws }}"
            )
        }
        (ValTy::BitSet(_), t) if t.is_int() => format!(
            "{{ let __s = {expr}; let __w0 = __s.first().copied().unwrap_or(0) as u64; let __w1 = __s.get(1).copied().unwrap_or(0) as u64; ((__w0 | (__w1 << 32)) as {}) }}",
            t.rust_type()
        ),
        (ValTy::Bool, t) if t.is_int() => format!("(({expr} as u8) as {})", t.rust_type()),
        (f, ValTy::Bool) if f.is_int() => format!("(({expr}) != 0)"),
        (f, t) if (f.is_int() || f.is_float()) && (t.is_int() || t.is_float()) => {
            format!("(({expr}) as {})", t.rust_type())
        }
        (ValTy::Array(fe, flen), ValTy::Array(te, tlen)) if flen == tlen => {
            let var = format!("__cae_{depth}");
            let inner = coerce_expr_depth(&var, fe, te, depth + 1);
            if inner == var {
                expr.to_owned()
            } else {
                format!("({expr}).map(|{var}| {inner})")
            }
        }
        _ => expr.to_owned(),
    }
}

pub(super) fn ptr_projected_field(pt: &PtrTarget) -> Option<&(String, String, ValTy)> {
    match pt {
        PtrTarget::QueryCol { projected, .. }
        | PtrTarget::QueryRow { projected, .. }
        | PtrTarget::EntityRow { projected, .. } => projected.as_ref(),
        _ => None,
    }
}

pub(super) fn effective_local_val_and_expr(
    lid: LocalId,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    ctx: &NativeCtx<'_>,
) -> (ValTy, String) {
    let vt = &analysis.val_tys[lid.0 as usize];
    if *vt == ValTy::PtrMarker
        && let Some(pt) = analysis.ptr_targets.get(&lid)
        && let Some((canon, pf, fvt)) = ptr_projected_field(pt)
    {
        let access = resolve_blob_field_access(canon, pf, ctx);
        let def_e = fvt.default_expr();
        let expr = emit_place_ref_for_target(
            pt,
            analysis,
            query_plans,
            in_chunk,
            &|place| build_field_load_from_place(place, &access, fvt, ctx),
            &def_e,
        );
        return (fvt.clone(), expr);
    }
    (vt.clone(), format!("__loc_{}", lid.0))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_binop_expr(
    op: &str,
    lhs: LocalId,
    rhs: LocalId,
    dst_vt: &ValTy,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    ctx: &NativeCtx<'_>,
) -> String {
    let (lt_val, le) = effective_local_val_and_expr(lhs, analysis, query_plans, in_chunk, ctx);
    let (rt_val, re) = effective_local_val_and_expr(rhs, analysis, query_plans, in_chunk, ctx);
    let lt = &lt_val;
    let rt = &rt_val;

    // Null pointer checks produced by `emit_query_one_lookup` or `IterUpCascade`
    let ptr_present_expr = |pid: LocalId| -> Option<String> {
        let mut pt = analysis.ptr_targets.get(&pid)?;
        while let PtrTarget::Field { base, .. } = pt {
            pt = base;
        }
        match pt {
            PtrTarget::UpCascadeDirect { up_local, .. } => {
                Some(format!("__up_ent_{}.is_some()", up_local.0))
            }
            PtrTarget::UpCascadeSlot {
                slot_local,
                row_target,
                ..
            } => {
                let local_p = match row_target.as_deref() {
                    Some(PtrTarget::QueryRow {
                        query_idx,
                        slot_idx,
                        optional: true,
                        selective,
                        ..
                    }) => {
                        if *selective {
                            format!("__q{query_idx}_sel_{slot_idx}.is_some()")
                        } else {
                            format!("__q{query_idx}_col_{slot_idx}.is_some()")
                        }
                    }
                    Some(_) => "true".to_owned(),
                    None => "false".to_owned(),
                };
                Some(format!(
                    "(if __up_flag_{0} {{ __up_ent_{0}.is_some() }} else {{ {local_p} }})",
                    slot_local.0
                ))
            }
            _ => None,
        }
    };
    if *lt == ValTy::PtrMarker && *rt == ValTy::PtrMarker {
        if let Some(pe) = ptr_present_expr(lhs)
            && !analysis.ptr_targets.contains_key(&rhs)
        {
            return match op {
                "==" => format!("(!{pe})"),
                _ => pe,
            };
        }
        if let Some(pe) = ptr_present_expr(rhs)
            && !analysis.ptr_targets.contains_key(&lhs)
        {
            return match op {
                "==" => format!("(!{pe})"),
                _ => pe,
            };
        }
    }
    if *lt == ValTy::Bool && *rt == ValTy::PtrMarker && !analysis.ptr_targets.contains_key(&rhs) {
        return match op {
            "==" => format!("(!{le})"),
            _ => le,
        };
    }
    if *rt == ValTy::Bool && *lt == ValTy::PtrMarker && !analysis.ptr_targets.contains_key(&lhs) {
        return match op {
            "==" => format!("(!{re})"),
            _ => re,
        };
    }
    if *lt == ValTy::PtrMarker || *rt == ValTy::PtrMarker {
        return match op {
            "==" => "false".to_owned(),
            _ => "true".to_owned(),
        };
    }

    // Vector binary ops
    if let (Some(d), Some(rd)) = (lt.is_ivec(), rt.is_ivec())
        && d == rd
    {
        if matches!(op, "==" | "!=") {
            let re_c = coerce_expr(&re, rt, lt);
            return format!("({le} {op} {re_c})");
        }
        let re_c = coerce_expr(&re, rt, lt);
        let meth = match op {
            "-" => "wrapping_sub",
            "*" => "wrapping_mul",
            "/" => "wrapping_div",
            _ => "wrapping_add",
        };
        let lanes: Vec<String> = (0..d)
            .map(|i| {
                if op == "/" {
                    format!(
                        "if {re_c}[{i}] == 0 {{ 0 }} else {{ ({le}[{i}]).{meth}({re_c}[{i}]) }}"
                    )
                } else {
                    format!("({le}[{i}]).{meth}({re_c}[{i}])")
                }
            })
            .collect();
        return format!("[{}]", lanes.join(", "));
    }
    match (lt.is_vec(), rt.is_vec()) {
        (Some(d), Some(_)) => {
            if matches!(op, "==" | "!=") {
                let re_c = coerce_expr(&re, rt, lt);
                return format!("({le} {op} {re_c})");
            }
            let fn_name = match (d, op) {
                (2, "+") => "strata_v2_add",
                (2, "-") => "strata_v2_sub",
                (2, "*") => "strata_v2_mul",
                (2, "/") => "strata_v2_div",
                (3, "-") => "strata_v3_sub",
                (3, "*") => "strata_v3_mul",
                (3, "/") => "strata_v3_div",
                (4, "+") => "strata_v4_add",
                (4, "-") => "strata_v4_sub",
                (4, "*") => "strata_v4_mul",
                (4, "/") => "strata_v4_div",
                _ => "strata_v3_add",
            };
            let re_c = coerce_expr(&re, rt, lt);
            return format!("{fn_name}({le}, {re_c})");
        }
        (Some(d), None) => {
            let s = coerce_expr(&re, rt, &ValTy::F32);
            let fn_name = match d {
                2 => "strata_v2_scale",
                3 => "strata_v3_scale",
                _ => "strata_v4_scale",
            };
            let expr = if op == "/" {
                format!("{fn_name}({le}, 1.0_f32 / {s})")
            } else {
                format!("{fn_name}({le}, {s})")
            };
            return coerce_expr(&expr, lt, dst_vt);
        }
        (None, Some(d)) => {
            let s = coerce_expr(&le, lt, &ValTy::F32);
            let fn_name = match d {
                2 => "strata_v2_scale",
                3 => "strata_v3_scale",
                _ => "strata_v4_scale",
            };
            return format!("{fn_name}({re}, {s})");
        }
        (None, None) => {}
    }

    // Scalar binary ops & comparisons
    let is_cmp = matches!(op, "==" | "!=" | "<" | "<=" | ">" | ">=");
    let mut common_ty = common_scalar_type(lt, rt);
    if !is_cmp
        && *dst_vt != ValTy::Unit
        && *dst_vt != ValTy::PtrMarker
        && (scalar_type_rank(dst_vt) >= scalar_type_rank(&common_ty)
            || (*lt == ValTy::I64 && *rt == ValTy::I64)
            || (*lt == ValTy::F64 && *rt == ValTy::F64 && dst_vt.is_float()))
    {
        common_ty = dst_vt.clone();
    }
    let lc = coerce_local_expr(
        (analysis.val_tys[lhs.0 as usize] != ValTy::PtrMarker).then_some(lhs),
        &le,
        lt,
        &common_ty,
        analysis,
    );
    let rc = coerce_local_expr(
        (analysis.val_tys[rhs.0 as usize] != ValTy::PtrMarker).then_some(rhs),
        &re,
        rt,
        &common_ty,
        analysis,
    );
    let expr = if op == "%" && matches!(common_ty, ValTy::Fix32 | ValTy::Fix64) {
        let rty = common_ty.rust_type();
        format!(
            "{{ let __r = ({rc}).0; if __r == 0 {{ {rty}(0) }} else {{ {rty}(({lc}).0.wrapping_rem(__r)) }} }}"
        )
    } else if matches!(op, "/" | "%") && common_ty.is_int() {
        let rty = common_ty.rust_type();
        let meth = if op == "/" {
            "wrapping_div"
        } else {
            "wrapping_rem"
        };
        format!(
            "{{ let __l: {rty} = {lc}; let __r: {rty} = {rc}; if __r == 0 {{ 0 }} else {{ __l.{meth}(__r) }} }}"
        )
    } else {
        format!("({lc} {op} {rc})")
    };
    if !is_cmp && *dst_vt != ValTy::Unit && *dst_vt != ValTy::PtrMarker && common_ty != *dst_vt {
        coerce_expr(&expr, &common_ty, dst_vt)
    } else {
        expr
    }
}

pub(super) fn scalar_type_rank(vt: &ValTy) -> u8 {
    match vt {
        ValTy::I8 | ValTy::U8 => 1,
        ValTy::I16 | ValTy::U16 => 2,
        ValTy::I32 | ValTy::U32 => 3,
        ValTy::I64 | ValTy::U64 => 4,
        ValTy::F32 => 5,
        ValTy::F64 => 6,
        ValTy::Fix32 => 7,
        ValTy::Fix64 => 8,
        _ => 0,
    }
}

pub(super) fn common_scalar_type(a: &ValTy, b: &ValTy) -> ValTy {
    if a == b {
        return a.clone();
    }
    if *a == ValTy::Entity || *b == ValTy::Entity {
        return ValTy::Entity;
    }
    if *a == ValTy::Fix64 || *b == ValTy::Fix64 {
        return ValTy::Fix64;
    }
    if *a == ValTy::Fix32 || *b == ValTy::Fix32 {
        return ValTy::Fix32;
    }
    if *a == ValTy::F64 || *b == ValTy::F64 {
        return ValTy::F64;
    }
    if *a == ValTy::F32 || *b == ValTy::F32 {
        return ValTy::F32;
    }
    if a.is_int() && b.is_int() {
        // Prefer specific non-i64 operand width when comparing against untyped IntLit (I64)
        if *a != ValTy::I64 && *b == ValTy::I64 {
            return a.clone();
        }
        if *b != ValTy::I64 && *a == ValTy::I64 {
            return b.clone();
        }
    }
    a.clone()
}

pub(super) fn emit_intrinsic_math(
    name: &str,
    args: &[LocalId],
    dst_vt: &ValTy,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    ctx: &NativeCtx<'_>,
) -> String {
    let arg_raw = |idx: usize| -> (ValTy, String) {
        if let Some(&lid) = args.get(idx) {
            effective_local_val_and_expr(lid, analysis, query_plans, in_chunk, ctx)
        } else {
            (ValTy::F32, "0.0_f32".to_owned())
        }
    };
    let arg_s = |idx: usize, expected: &ValTy| -> String {
        if args.get(idx).is_some() {
            let (vt, expr) = arg_raw(idx);
            coerce_expr(&expr, &vt, expected)
        } else {
            expected.default_expr()
        }
    };
    match name.rsplit("::").next().unwrap_or(name) {
        "vec2" | "Vec2" => format!("[{}, {}]", arg_s(0, &ValTy::F32), arg_s(1, &ValTy::F32)),
        "vec3" | "Vec3" => format!(
            "[{}, {}, {}]",
            arg_s(0, &ValTy::F32),
            arg_s(1, &ValTy::F32),
            arg_s(2, &ValTy::F32)
        ),
        "vec3a" | "Vec3a" => format!(
            "[{}, {}, {}, 0.0_f32]",
            arg_s(0, &ValTy::F32),
            arg_s(1, &ValTy::F32),
            arg_s(2, &ValTy::F32)
        ),
        "vec4" | "Vec4" | "quat" | "Quat" | "rgba" | "Rgba" => format!(
            "[{}, {}, {}, {}]",
            arg_s(0, &ValTy::F32),
            arg_s(1, &ValTy::F32),
            arg_s(2, &ValTy::F32),
            arg_s(3, &ValTy::F32)
        ),
        "ivec2" | "IVec2" => format!("[{}, {}]", arg_s(0, &ValTy::I32), arg_s(1, &ValTy::I32)),
        "ivec3" | "IVec3" => format!(
            "[{}, {}, {}]",
            arg_s(0, &ValTy::I32),
            arg_s(1, &ValTy::I32),
            arg_s(2, &ValTy::I32)
        ),
        "uvec2" | "UVec2" => format!("[{}, {}]", arg_s(0, &ValTy::U32), arg_s(1, &ValTy::U32)),
        "sin" | "cos" | "tan" | "sqrt" | "abs" | "floor" | "ceil" | "round" | "exp" | "ln" => {
            let fty = if *dst_vt == ValTy::F64 {
                ValTy::F64
            } else {
                ValTy::F32
            };
            format!("({}).{name}()", arg_s(0, &fty))
        }
        "atan2" | "pow" => {
            let fty = if *dst_vt == ValTy::F64 {
                ValTy::F64
            } else {
                ValTy::F32
            };
            let m = if name == "pow" { "powf" } else { "atan2" };
            format!("({}).{m}({})", arg_s(0, &fty), arg_s(1, &fty))
        }
        "min" | "max" => {
            let (t0, _) = arg_raw(0);
            let (t1, _) = arg_raw(1);
            let ct = if *dst_vt != ValTy::Unit {
                dst_vt.clone()
            } else {
                common_scalar_type(&t0, &t1)
            };
            format!("({}).{name}({})", arg_s(0, &ct), arg_s(1, &ct))
        }
        "clamp" => {
            let ct = if *dst_vt != ValTy::Unit {
                dst_vt.clone()
            } else {
                ValTy::F32
            };
            format!(
                "({}).clamp({}, {})",
                arg_s(0, &ct),
                arg_s(1, &ct),
                arg_s(2, &ct)
            )
        }
        "lerp" => {
            let ct = if *dst_vt != ValTy::Unit {
                dst_vt.clone()
            } else {
                ValTy::F32
            };
            let a = arg_s(0, &ct);
            let b = arg_s(1, &ct);
            let t = arg_s(2, &ValTy::F32);
            match ct.is_vec() {
                Some(2) => {
                    format!("strata_v2_add({a}, strata_v2_scale(strata_v2_sub({b}, {a}), {t}))")
                }
                Some(3) => {
                    format!("strata_v3_add({a}, strata_v3_scale(strata_v3_sub({b}, {a}), {t}))")
                }
                Some(4) => {
                    format!("strata_v4_add({a}, strata_v4_scale(strata_v4_sub({b}, {a}), {t}))")
                }
                _ => format!("({a} + ({b} - {a}) * {t})"),
            }
        }
        "dot" => {
            let (_, e0) = arg_raw(0);
            let (_, e1) = arg_raw(1);
            format!("strata_dot(&({e0}), &({e1}))")
        }
        "length" => {
            let (_, e0) = arg_raw(0);
            format!("strata_len(&({e0}))")
        }
        "distance" => {
            let (_, e0) = arg_raw(0);
            let (_, e1) = arg_raw(1);
            format!("strata_dist(&({e0}), &({e1}))")
        }
        "normalize" => {
            let (t0, e0) = arg_raw(0);
            match t0.is_vec() {
                Some(2) => format!("strata_norm_v2({e0})"),
                Some(4) => format!("strata_norm_v4({e0})"),
                _ => format!("strata_norm_v3({e0})"),
            }
        }
        "cross" => {
            let (t0, e0) = arg_raw(0);
            let (t1, e1) = arg_raw(1);
            if matches!(dst_vt, ValTy::Vec4)
                || matches!(t0, ValTy::Vec4)
                || matches!(t1, ValTy::Vec4)
            {
                let a3 = coerce_expr(&e0, &t0, &ValTy::Vec3);
                let b3 = coerce_expr(&e1, &t1, &ValTy::Vec3);
                coerce_expr(&format!("strata_cross({a3}, {b3})"), &ValTy::Vec3, dst_vt)
            } else {
                format!("strata_cross({e0}, {e1})")
            }
        }
        _ => dst_vt.default_expr(),
    }
}

pub(super) fn emit_call_expr(
    callee: &str,
    args: &[LocalId],
    dst_vt: Option<&ValTy>,
    ctx: &NativeCtx<'_>,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
) -> Result<String, CodegenError> {
    if let Some(hf) = ctx.helpers_by_key.get(callee) {
        let mut arg_strs = Vec::with_capacity(args.len());
        for (i, a) in args.iter().enumerate() {
            let arg_expr = if let Some(p) = hf.params.get(i) {
                match p.kind {
                    HirParamKind::Ref => {
                        if let Some(pt) = analysis.ptr_targets.get(a) {
                            match pt {
                                PtrTarget::Resource { var_name, .. } => format!("(&*{var_name})"),
                                PtrTarget::ParamPtr { var_name, .. } => var_name.clone(),
                                PtrTarget::SlotRef { slot_local, .. } => {
                                    if analysis.slot_tys.contains_key(slot_local) {
                                        format!("(&__slot_{})", slot_local.0)
                                    } else {
                                        format!("(&__loc_{})", slot_local.0)
                                    }
                                }
                                _ => format!("(&__loc_{})", a.0),
                            }
                        } else {
                            format!("(&__loc_{})", a.0)
                        }
                    }
                    HirParamKind::RefMut => {
                        if let Some(pt) = analysis.ptr_targets.get(a) {
                            match pt {
                                PtrTarget::Resource { var_name, .. } => {
                                    format!("(&mut *{var_name})")
                                }
                                PtrTarget::ParamPtr { var_name, .. } => var_name.clone(),
                                PtrTarget::SlotRef { slot_local, .. } => {
                                    if analysis.slot_tys.contains_key(slot_local) {
                                        format!("(&mut __slot_{})", slot_local.0)
                                    } else {
                                        format!("(&mut __loc_{})", slot_local.0)
                                    }
                                }
                                _ => format!("(&mut __loc_{})", a.0),
                            }
                        } else {
                            format!("(&mut __loc_{})", a.0)
                        }
                    }
                    _ => {
                        let target_vt = ValTy::from_mir(&p.ty, ctx);
                        let (avt, aexpr) =
                            effective_local_val_and_expr(*a, analysis, query_plans, in_chunk, ctx);
                        coerce_expr(&aexpr, &avt, &target_vt)
                    }
                }
            } else {
                effective_local_val_and_expr(*a, analysis, query_plans, in_chunk, ctx).1
            };
            arg_strs.push(arg_expr);
        }
        let fn_ident = sanitize_ident(&hf.name);
        return Ok(format!("strata_fn_{fn_ident}({})", arg_strs.join(", ")));
    }

    if let Some(item_name) = callee.strip_suffix("::start") {
        if let Some(tl) = ctx.timelines_by_key.get(item_name)
            && let Some(entry) = ctx.find_layout_entry(&tl.canonical_name)
        {
            return Ok(format!(
                "{} {{ cur_frame: 0, flags: 1, active_mask: 0, accum_sec: 0.0_f32, ..Default::default() }}",
                entry.struct_name
            ));
        }
        if let Some(tk) = ctx.tasks_by_key.get(item_name)
            && let Some(entry) = ctx.find_layout_entry(&tk.state_layout.canonical_name)
        {
            let mut inits = vec!["__pc: 0u8".to_owned(), "__timer: 0.0_f32".to_owned()];
            for (pi, tp) in tk.typed_params.iter().enumerate() {
                let pident = sanitize_rust_ident(&tp.name);
                if let Some(&arg_l) = args.get(pi) {
                    let sf = entry.layout.fields.iter().find(|f| f.name == tp.name);
                    let val_s = if let Some(sf) = sf {
                        let target_vt = ValTy::from_solved_field(sf, ctx);
                        let c = coerce_expr(
                            &format!("__loc_{}", arg_l.0),
                            &analysis.val_tys[arg_l.0 as usize],
                            &target_vt,
                        );
                        wrap_abi_field_store(&c, sf, ctx, false)
                    } else {
                        format!("__loc_{}", arg_l.0)
                    };
                    inits.push(format!("{pident}: {val_s}"));
                }
            }
            return Ok(format!(
                "{} {{ {}, ..Default::default() }}",
                entry.struct_name,
                inits.join(", ")
            ));
        }
        if let Some(fsm) = ctx.fsms_by_key.get(item_name)
            && let Some(entry) = ctx.find_layout_entry(&fsm.state_layout.canonical_name)
        {
            let init_idx = fsm
                .states
                .iter()
                .position(|s| s == &fsm.initial_state)
                .unwrap_or(0);
            return Ok(format!(
                "{} {{ __state: {init_idx}, __flags: 0, ..Default::default() }}",
                entry.struct_name
            ));
        }
    }

    match callee {
        "sqr" => {
            let a0 = args.first().copied().unwrap_or(LocalId(0));
            let vt = dst_vt.unwrap_or(&ValTy::F32);
            let (avt, ae) = effective_local_val_and_expr(a0, analysis, query_plans, in_chunk, ctx);
            let x = coerce_expr(&ae, &avt, vt);
            Ok(format!("({x} * {x})"))
        }
        "distance_sq" => {
            let a0 = args.first().copied().unwrap_or(LocalId(0));
            let a1 = args.get(1).copied().unwrap_or(LocalId(0));
            let e0 = effective_local_val_and_expr(a0, analysis, query_plans, in_chunk, ctx).1;
            let e1 = effective_local_val_and_expr(a1, analysis, query_plans, in_chunk, ctx).1;
            Ok(format!("strata_dist_sq(&({e0}), &({e1}))"))
        }
        "ivec2" | "IVec2" => {
            let x = args.first().map_or_else(
                || "0i32".to_owned(),
                |&l| {
                    let (vt, e) =
                        effective_local_val_and_expr(l, analysis, query_plans, in_chunk, ctx);
                    coerce_expr(&e, &vt, &ValTy::I32)
                },
            );
            let y = args.get(1).map_or_else(
                || "0i32".to_owned(),
                |&l| {
                    let (vt, e) =
                        effective_local_val_and_expr(l, analysis, query_plans, in_chunk, ctx);
                    coerce_expr(&e, &vt, &ValTy::I32)
                },
            );
            Ok(format!("[{x}, {y}]"))
        }
        "uvec2" | "UVec2" => {
            let x = args.first().map_or_else(
                || "0u32".to_owned(),
                |&l| {
                    let (vt, e) =
                        effective_local_val_and_expr(l, analysis, query_plans, in_chunk, ctx);
                    coerce_expr(&e, &vt, &ValTy::U32)
                },
            );
            let y = args.get(1).map_or_else(
                || "0u32".to_owned(),
                |&l| {
                    let (vt, e) =
                        effective_local_val_and_expr(l, analysis, query_plans, in_chunk, ctx);
                    coerce_expr(&e, &vt, &ValTy::U32)
                },
            );
            Ok(format!("[{x}, {y}]"))
        }
        "ivec3" | "IVec3" => {
            let x = args.first().map_or_else(
                || "0i32".to_owned(),
                |&l| {
                    let (vt, e) =
                        effective_local_val_and_expr(l, analysis, query_plans, in_chunk, ctx);
                    coerce_expr(&e, &vt, &ValTy::I32)
                },
            );
            let y = args.get(1).map_or_else(
                || "0i32".to_owned(),
                |&l| {
                    let (vt, e) =
                        effective_local_val_and_expr(l, analysis, query_plans, in_chunk, ctx);
                    coerce_expr(&e, &vt, &ValTy::I32)
                },
            );
            let z = args.get(2).map_or_else(
                || "0i32".to_owned(),
                |&l| {
                    let (vt, e) =
                        effective_local_val_and_expr(l, analysis, query_plans, in_chunk, ctx);
                    coerce_expr(&e, &vt, &ValTy::I32)
                },
            );
            Ok(format!("[{x}, {y}, {z}]"))
        }
        _ => Ok(dst_vt.map_or_else(|| "()".to_owned(), ValTy::default_expr)),
    }
}
