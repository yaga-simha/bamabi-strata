//! RustGuest plugin registration, net/object/schedule builders, and run conditions.

use super::*;

pub(super) fn emit_plugin_and_registration(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    stem: &str,
) {
    writeln!(out, "#[derive(Default)]").ok();
    writeln!(out, "pub struct StrataGuestMod;\n").ok();
    writeln!(out, "impl GuestPlugin for StrataGuestMod {{").ok();
    writeln!(out, "    const NAME: &'static CStr = c\"{stem}\";").ok();
    writeln!(out, "    const VERSION: &'static CStr = c\"0.3.0\";\n").ok();
    writeln!(
        out,
        "    fn build(&mut self, app: &mut GuestApp<'_>) -> FfiResult {{"
    )
    .ok();
    writeln!(
        out,
        "        let world_state: Arc<Mutex<StrataWorldState>> = Arc::new(Mutex::new(StrataWorldState::default()));\n\
         \x20       let mut handles = StrataHandles::default();"
    )
    .ok();
    if !mir.spatial_indices.is_empty() {
        writeln!(
            out,
            "        if let Ok(mut _w_init) = world_state.lock() {{"
        )
        .ok();
        for sp in &mir.spatial_indices {
            let esc = escape_rust_str(&sp.name);
            let frames = sp.frames.max(1) as usize;
            let cap = sp.capacity.max(1) as usize;
            let cols = sp.cols.max(1);
            let rows = sp.rows.max(1);
            let cs = fmt_f32(if sp.cell_size > 0.0 {
                sp.cell_size
            } else {
                4.0
            });
            let bmin0 = fmt_f32(sp.bounds_min[0]);
            let bmin1 = fmt_f32(sp.bounds_min[1]);
            let ax0 = sp.plane_axes[0];
            let ax1 = sp.plane_axes[1];
            writeln!(
                out,
                "            _w_init.spatial.insert(\"{esc}\".to_owned(), StrataSpatialGridState::new({frames}, {cap}, {cols}, {rows}, {cs}, [{bmin0}, {bmin1}], [{ax0}, {ax1}]));"
            )
            .ok();
        }
        writeln!(out, "        }}").ok();
    }

    // 1. Live schema migrations (`Slot 67`) BEFORE component registration
    for (idx, func) in mir.functions.iter().enumerate() {
        if let MirFnKind::Migration {
            component,
            src_layout,
            dst_layout,
            ..
        } = &func.kind
        {
            let src_comp = cat.resolve_comp(src_layout);
            let dst_comp = cat
                .resolve_comp(dst_layout)
                .or_else(|| cat.resolve_comp(component));
            if let (Some(src), Some(dst)) = (src_comp, dst_comp) {
                let fn_ident = format!("strata_sys_fn_{idx}_{}", sanitize_ident(&func.name));
                let old_s = &src.struct_name;
                let old_v = &src.variant_name;
                let new_s = &dst.struct_name;
                let new_v = &dst.variant_name;
                writeln!(
                    out,
                    "        if let Ok(_existing_h) = app.resolve_component_named(Some(<{new_s} as ModComponent>::COMPONENT_CSTR), None) {{\n\
                     \x20           let _needs_mig = app.component_layout_info(_existing_h).is_ok_and(|info| {{\n\
                     \x20               info.schema_fingerprint != <{new_s} as ModComponent>::SCHEMA_FINGERPRINT\n\
                     \x20                   || info.size != core::mem::size_of::<{new_s}>()\n\
                     \x20                   || info.align != core::mem::align_of::<{new_s}>()\n\
                     \x20           }});\n\
                     \x20           if _needs_mig {{\n\
                     \x20               let _w_mig = Arc::clone(&world_state);\n\
                     \x20               let _h_mig = handles;\n\
                     \x20               let _mig_res = app.migrate_pod_component_column::<{old_s}, {new_s}, _>(\n\
                     \x20                   _existing_h,\n\
                     \x20                   0u64,\n\
                     \x20                   <{new_s} as ModComponent>::SCHEMA_FINGERPRINT,\n\
                     \x20                   move |old: &{old_s}| -> Result<{new_s}, FfiResult> {{\n\
                     \x20                       let _res = {fn_ident}(&_w_mig, &_h_mig, StrataObj::{old_v}(*old), StrataObj::{new_v}({new_s}::default()));\n\
                     \x20                       if let StrataObj::{new_v}(new_val) = _res {{\n\
                     \x20                           Ok(new_val)\n\
                     \x20                       }} else {{\n\
                     \x20                           Ok({new_s}::default())\n\
                     \x20                       }}\n\
                     \x20                   }},\n\
                     \x20               );\n\
                     \x20               if !_mig_res.is_ok() {{\n\
                     \x20                   return _mig_res;\n\
                     \x20               }}\n\
                     \x20           }}\n\
                     \x20       }}"
                )
                .ok();
            }
        }
    }

    // 2. Register components, tags, events, streams; probe host-registered resources without calling register_dynamic_component
    writeln!(
        out,
        "        handles.bam_child_of = match app.resolve_component::<FfiChildOf>() {{\n\
         \x20           Ok(h) => h,\n\
         \x20           Err(FfiResult::NOT_FOUND) => BamComponent::INVALID,\n\
         \x20           Err(e) => return e,\n\
         \x20       }};"
    )
    .ok();
    for &cid in &cat.topo_order {
        let c = &cat.components[cid];
        if !c.register_dynamic && !c.is_resource_like() {
            continue;
        }
        let sname = &c.struct_name;
        let hfield = &c.handle_field;
        if c.canonical_name == "ChildOf" || c.canonical_name.ends_with("::ChildOf") {
            writeln!(out, "        handles.{hfield} = handles.bam_child_of;").ok();
            continue;
        }
        if c.is_resource_like() {
            writeln!(
                out,
                "        match app.resolve_component::<{sname}>().or_else(|e| {{\n\
                 \x20           if e == FfiResult::TYPE_MISMATCH {{\n\
                 \x20               app.resolve_component_named(Some(<{sname} as ModComponent>::COMPONENT_CSTR), None)\n\
                 \x20           }} else {{\n\
                 \x20               Err(e)\n\
                 \x20           }}\n\
                 \x20       }}) {{\n\
                 \x20           Ok(h) => if app.component_layout_info(h).is_ok_and(|info| {{\n\
                 \x20               (info.flags & BAM_STORAGE_FLAG_RESOURCE) != 0\n\
                 \x20                   && info.size == core::mem::size_of::<{sname}>()\n\
                 \x20                   && info.align == core::mem::align_of::<{sname}>()\n\
                 \x20           }}) {{\n\
                 \x20               handles.{hfield} = h;\n\
                 \x20               handles.is_host_res_{id} = true;\n\
                 \x20           }},\n\
                 \x20           Err(FfiResult::NOT_FOUND | FfiResult::TYPE_MISMATCH) => {{}}\n\
                 \x20           Err(e) => return e,\n\
                 \x20       }}",
                id = c.id
            )
            .ok();
        } else {
            writeln!(
                out,
                "        handles.{hfield} = match app.resolve_component::<{sname}>() {{\n\
                 \x20           Ok(h) => h,\n\
                 \x20           Err(FfiResult::NOT_FOUND) => match app.register_dynamic_component::<{sname}>() {{\n\
                 \x20               Ok(h) => h,\n\
                 \x20               Err(e) => return e,\n\
                 \x20           }},\n\
                 \x20           Err(e) => return e,\n\
                 \x20       }};"
            )
            .ok();
        }
    }

    // 3. Register relations (`register_relation`)
    for rel in &cat.relations {
        if rel.canonical_name == "ChildOf" || rel.canonical_name.ends_with("::ChildOf") {
            writeln!(
                out,
                "        handles.{} = handles.bam_child_of;",
                rel.handle_field
            )
            .ok();
            continue;
        }
        let esc = escape_rust_str(&rel.canonical_name);
        let uuid_lit = format_u8_array_16(&rel.uuid_bytes);
        let mut builder_chain = format!(
            "RelationDescBuilder::new(\"{esc}\").with_uuid(ComponentUuid::from_bytes({uuid_lit}))"
        );
        for flag in &rel.flags {
            match flag.as_str() {
                "exclusive" => builder_chain.push_str(".exclusive()"),
                "symmetric" => builder_chain.push_str(".symmetric()"),
                "acyclic" => builder_chain.push_str(".acyclic()"),
                "cascade_despawn" | "cascade_delete" => {
                    builder_chain.push_str(".cascade_despawn()")
                }
                "cleanup_remove" => builder_chain.push_str(".cleanup_remove()"),
                _ => {}
            }
        }
        if let Some(pid) = rel.payload_comp_id {
            let psname = &cat.components[pid].struct_name;
            builder_chain.push_str(&format!(".with_payload::<{psname}>()"));
        }
        writeln!(
            out,
            "        handles.{} = match app.register_relation({builder_chain}) {{\n\
             \x20           Ok(h) => h,\n\
             \x20           Err(e) => return e,\n\
             \x20       }};",
            rel.handle_field
        )
        .ok();
    }

    // 4. Register Startup named-object initializer if `mir.objects` non-empty
    if !mir.objects.is_empty() {
        emit_named_objects_startup(out, mir, cat);
    }

    // 5. Register reactive observers (`MirFnKind::Observer`)
    for (idx, func) in mir.functions.iter().enumerate() {
        let MirFnKind::Observer { event, target_comp } = &func.kind else {
            continue;
        };
        let Some(ev_comp) = cat.resolve_comp(event) else {
            continue;
        };
        let fn_ident = format!("strata_sys_fn_{idx}_{}", sanitize_ident(&func.name));
        let obs_esc = escape_rust_str(&bare_unqualified_name(&func.name));
        let ev_s = &ev_comp.struct_name;
        let ev_v = &ev_comp.variant_name;
        let phys_queries = build_physical_queries(func, cat);
        let stream_decls = collect_func_stream_decls(func, cat);
        let named_fallback_queries = collect_named_fallback_queries(mir, func, &phys_queries, cat);

        let mut obs_res_order: Vec<(usize, bool)> = Vec::new();
        for rb in &func.resources {
            if let Some(rc) = cat
                .resolve_comp(&rb.canonical_name)
                .or_else(|| cat.resolve_comp(&rb.resource_name))
            {
                if let Some((_, existing_mut)) =
                    obs_res_order.iter_mut().find(|(cid, _)| *cid == rc.id)
                {
                    *existing_mut |= rb.mutable;
                } else {
                    obs_res_order.push((rc.id, rb.mutable));
                }
            }
        }
        for bb in &func.blocks {
            for st in &bb.stmts {
                match &st.inst {
                    Inst::ResRead { resource } => {
                        if let Some(rc) = cat.resolve_comp(resource)
                            && !obs_res_order.iter().any(|(cid, _)| *cid == rc.id)
                        {
                            obs_res_order.push((rc.id, false));
                        }
                    }
                    Inst::ResWrite { resource } => {
                        if let Some(rc) = cat.resolve_comp(resource) {
                            if let Some((_, existing_mut)) =
                                obs_res_order.iter_mut().find(|(cid, _)| *cid == rc.id)
                            {
                                *existing_mut = true;
                            } else {
                                obs_res_order.push((rc.id, true));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        writeln!(out, "        {{").ok();
        writeln!(out, "            let _w_obs = Arc::clone(&world_state);").ok();
        writeln!(out, "            let _h_obs = handles;").ok();
        writeln!(out, "            let mut _obs_res_cnt: usize = 0;").ok();
        writeln!(
            out,
            "            let mut _b_obs = app.observe_event::<{ev_s}>(\"{obs_esc}\");"
        )
        .ok();
        if let Some(tc) = target_comp.as_deref()
            && let Some(tc_comp) = cat.resolve_comp(tc)
        {
            let tc_hf = &tc_comp.handle_field;
            writeln!(
                out,
                "            _b_obs = _b_obs.with_watched_handle(_h_obs.{tc_hf});"
            )
            .ok();
        }
        for (cid, is_mut) in obs_res_order {
            let rc = &cat.components[cid];
            let hf = &rc.handle_field;
            let method = if is_mut {
                "resource_write_handle"
            } else {
                "resource_read_handle"
            };
            if rc.is_resource_like() {
                writeln!(
                    out,
                    "            if _h_obs.is_host_res_{cid} {{\n\
                     \x20               _b_obs = _b_obs.{method}(_h_obs.{hf});\n\
                     \x20               _obs_res_cnt += 1;\n\
                     \x20           }}"
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "            _b_obs = _b_obs.{method}(_h_obs.{hf});\n\
                     \x20           _obs_res_cnt += 1;"
                )
                .ok();
            }
        }
        writeln!(out, "            let _res_obs = _b_obs").ok();
        for (sname, is_write) in &stream_decls {
            if let Some(sc) = cat.resolve_comp(sname) {
                if *is_write {
                    writeln!(
                        out,
                        "                .message_write::<{}>()",
                        sc.struct_name
                    )
                    .ok();
                } else {
                    writeln!(out, "                .message_read::<{}>()", sc.struct_name).ok();
                }
            }
        }
        let (pset_groups, _) = compute_guest_query_emit_plan(&phys_queries);
        let mut emitted_pset_groups: HashSet<u32> = HashSet::new();
        for (qi, pq) in phys_queries.iter().enumerate() {
            let g = pset_groups.get(qi).copied().unwrap_or(0);
            if g == 0 {
                emit_query_builder_chain(out, cat, pq, "                ", ".query", "");
            } else if emitted_pset_groups.insert(g) {
                writeln!(out, "                .param_set(|ps| {{").ok();
                for (qj, pq_member) in phys_queries.iter().enumerate() {
                    if pset_groups.get(qj).copied() == Some(g) {
                        emit_query_builder_chain(
                            out,
                            cat,
                            pq_member,
                            "                    ",
                            "ps.query",
                            ";",
                        );
                    }
                }
                writeln!(out, "                }})").ok();
            }
        }
        let mut ordered_fb: Vec<(&String, &usize)> = named_fallback_queries.iter().collect();
        ordered_fb.sort_by_key(|(_, i)| **i);
        for (obj_name, _) in ordered_fb {
            if let Some(obj) = mir.objects.iter().find(|o| o.name == *obj_name)
                && let Some(first_comp) = obj
                    .components
                    .iter()
                    .find_map(|c| cat.resolve_comp(c))
                    .or_else(|| {
                        obj.inits.iter().find_map(|ci| {
                            let cname = ci.canonical_component.as_deref().unwrap_or(&ci.component);
                            cat.resolve_comp(cname)
                        })
                    })
            {
                writeln!(
                    out,
                    "                .query(|q| q.with::<{}>())",
                    first_comp.struct_name
                )
                .ok();
            }
        }
        writeln!(
            out,
            "                .build_with_ctx(move |tgt: FfiEntity, ev: &{ev_s}, ctx: &mut SystemContext<'_>| {{\n\
             \x20                   {fn_ident}(ctx, &_w_obs, &_h_obs, _obs_res_cnt, tgt, StrataObj::{ev_v}(*ev));\n\
             \x20               }});\n\
             \x20           if let Err(e) = _res_obs {{ return e; }}\n\
             \x20       }}"
        )
        .ok();
    }

    // 6. Register scheduled systems (`SystemBuilder::register_handle`, `ScheduleSetBuilder`, `mount_system`)
    //    and direct unscheduled systems (`SystemBuilder::build`).
    let mut scheduled_names = HashSet::new();
    for sched in &mir.schedules {
        collect_schedule_leaf_names(&sched.nodes, &mut scheduled_names);
    }

    let timer_tick_name = mir
        .functions
        .iter()
        .find(|f| matches!(f.kind, MirFnKind::SynthesizedTimerTick))
        .map(|f| bare_unqualified_name(&f.name));

    if has_net_protocol(mir) {
        for nc in &mir.net_components {
            if let Some(comp) = cat.resolve_comp(&nc.canonical_name) {
                let hf = &comp.handle_field;
                let sname = &comp.struct_name;
                let guard = if comp.is_resource_like() {
                    format!("handles.is_host_res_{}", comp.id)
                } else {
                    "true".to_owned()
                };
                writeln!(
                    out,
                    "        if {guard} {{\n\
                     \x20           if let Ok(_net_info) = app.component_layout_info(handles.{hf}) {{\n\
                     \x20               if _net_info.schema_fingerprint != <{sname} as ModComponent>::SCHEMA_FINGERPRINT {{\n\
                     \x20                   return FfiResult::TYPE_MISMATCH;\n\
                     \x20               }}\n\
                     \x20           }}\n\
                     \x20       }}"
                )
                .ok();
            }
        }
        writeln!(
            out,
            "        let _net_pkt_handle: Option<BamComponent> = match app.resolve_component_named(Some(<StrataNetPacket as ModComponent>::COMPONENT_CSTR), None) {{\n\
             \x20           Ok(h) => match app.component_layout_info(h) {{\n\
             \x20               Ok(info) => {{\n\
             \x20                   if (info.flags & BAM_STORAGE_FLAG_MESSAGE) == 0\n\
             \x20                       || info.size != core::mem::size_of::<StrataNetPacket>()\n\
             \x20                       || info.schema_fingerprint != STRATA_NET_PACKET_SCHEMA_FINGERPRINT\n\
             \x20                   {{\n\
             \x20                       return FfiResult::TYPE_MISMATCH;\n\
             \x20                   }}\n\
             \x20                   Some(h)\n\
             \x20               }}\n\
             \x20               Err(e) => return e,\n\
             \x20           }},\n\
             \x20           Err(FfiResult::NOT_FOUND) => None,\n\
             \x20           Err(e) => return e,\n\
             \x20       }};"
        )
        .ok();
        emit_guest_net_sys_registration(out, mir, cat, true);
    }

    let mut sys_handle_vars: HashMap<String, String> = HashMap::new();
    let ordered_sys_indices: Vec<usize> = mir
        .functions
        .iter()
        .enumerate()
        .filter(|(_, f)| matches!(f.kind, MirFnKind::SynthesizedTimerTick))
        .map(|(i, _)| i)
        .chain(
            mir.functions
                .iter()
                .enumerate()
                .filter(|(_, f)| {
                    !matches!(
                        f.kind,
                        MirFnKind::Observer { .. }
                            | MirFnKind::Migration { .. }
                            | MirFnKind::HelperFn
                            | MirFnKind::SynthesizedTimerTick
                    )
                })
                .map(|(i, _)| i),
        )
        .collect();
    for idx in ordered_sys_indices {
        let func = &mir.functions[idx];
        let phys_queries = build_physical_queries(func, cat);
        let stream_decls = collect_func_stream_decls(func, cat);
        let named_fallback_queries = collect_named_fallback_queries(mir, func, &phys_queries, cat);
        let sched_run_if = find_schedule_run_if(mir, func);

        let sys_var = format!("_sys_h_{idx}");
        let is_scheduled = scheduled_names.contains(&func.name);
        let sched_label = system_schedule_label(mir, &func.name);
        let after_timer_tick = if !matches!(func.kind, MirFnKind::SynthesizedTimerTick)
            && sched_label == "FixedUpdate"
        {
            timer_tick_name.as_deref()
        } else {
            None
        };
        emit_system_builder_registration(
            out,
            mir,
            cat,
            func,
            idx,
            &phys_queries,
            &stream_decls,
            &named_fallback_queries,
            sched_run_if,
            sched_label,
            after_timer_tick,
            is_scheduled.then_some(sys_var.as_str()),
        );
        if is_scheduled {
            sys_handle_vars.insert(func.name.clone(), sys_var);
        }
    }

    // Configure ScheduleSetBuilder & mount systems for each `mir.schedules`
    let mut set_counter = 0usize;
    for (s_idx, sched) in mir.schedules.iter().enumerate() {
        let sched_id = schedule_id_expr(&sched.label);
        emit_schedule_nodes(
            out,
            s_idx,
            &sched.nodes,
            sched_id,
            &mut set_counter,
            &sys_handle_vars,
        );
    }

    if has_net_protocol(mir) {
        emit_guest_net_sys_registration(out, mir, cat, false);
    }

    writeln!(out, "        FfiResult::OK").ok();
    writeln!(out, "    }}").ok();
    writeln!(out, "}}\n").ok();
    writeln!(out, "export_mod!(plugin: StrataGuestMod);").ok();
}

pub(super) fn emit_guest_net_sys_registration(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    is_rx: bool,
) {
    let rep_comps: Vec<&MirNetComponent> = mir
        .net_components
        .iter()
        .filter(|nc| nc.is_replicated)
        .collect();
    if rep_comps.is_empty() {
        return;
    }
    let fixed_user_names: Vec<String> = mir
        .functions
        .iter()
        .filter(|f| {
            !matches!(
                f.kind,
                MirFnKind::Observer { .. } | MirFnKind::Migration { .. } | MirFnKind::HelperFn
            ) && (matches!(f.kind, MirFnKind::SynthesizedTimerTick)
                || system_schedule_label(mir, &f.name) == "FixedUpdate")
        })
        .map(|f| bare_unqualified_name(&f.name))
        .collect();
    let max_per_sys = bamabi_sys::MAX_QUERIES_PER_SYSTEM.saturating_sub(1).max(1);
    let chunk_count = rep_comps.chunks(max_per_sys).len();
    for (chunk_idx, chunk) in rep_comps.chunks(max_per_sys).enumerate() {
        let sys_name = if is_rx {
            format!("__strata_net_rx_{chunk_idx}")
        } else {
            format!("__strata_net_tx_{chunk_idx}")
        };
        let fn_name = if is_rx {
            format!("strata_net_rx_{chunk_idx}")
        } else {
            format!("strata_net_tx_{chunk_idx}")
        };
        writeln!(out, "        if let Some(_net_h) = _net_pkt_handle {{").ok();
        writeln!(out, "            let _w_net = Arc::clone(&world_state);").ok();
        writeln!(out, "            let _h_net = handles;").ok();
        writeln!(out, "            let mut _net_res_cnt: usize = 0;").ok();
        writeln!(
            out,
            "            let mut _nb = app.system(c\"{sys_name}\").schedule(ScheduleId::FIXED_UPDATE);"
        )
        .ok();
        for uname in &fixed_user_names {
            let esc_u = escape_rust_str(uname);
            if is_rx {
                writeln!(out, "            _nb = _nb.before_weak(c\"{esc_u}\");").ok();
            } else {
                writeln!(out, "            _nb = _nb.after_weak(c\"{esc_u}\");").ok();
            }
        }
        for other_idx in 0..chunk_count {
            if is_rx {
                writeln!(
                    out,
                    "            _nb = _nb.before_weak(c\"__strata_net_tx_{other_idx}\");"
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "            _nb = _nb.after_weak(c\"__strata_net_rx_{other_idx}\");"
                )
                .ok();
            }
        }
        for nc in chunk {
            if nc.is_resource
                && let Some(comp) = cat.resolve_comp(&nc.canonical_name)
            {
                let hf = &comp.handle_field;
                let method = if is_rx {
                    "resource_write_handle"
                } else {
                    "resource_read_handle"
                };
                writeln!(
                    out,
                    "            if _h_net.is_host_res_{cid} {{\n\
                     \x20               _nb = _nb.{method}(_h_net.{hf});\n\
                     \x20               _net_res_cnt += 1;\n\
                     \x20           }}",
                    cid = comp.id,
                )
                .ok();
            }
        }
        let msg_method = if is_rx {
            "message_read_handle"
        } else {
            "message_write_handle"
        };
        writeln!(out, "            let _net_res = _nb.{msg_method}(_net_h)").ok();
        for nc in chunk {
            if !nc.is_resource
                && let Ok(strata) = net_comp_strata(nc, cat)
                && !strata.is_empty()
            {
                if strata.len() == 1 {
                    let sname = &strata[0].1.struct_name;
                    if is_rx {
                        writeln!(out, "                .query(|q| q.write::<{sname}>())").ok();
                    } else {
                        writeln!(out, "                .query(|q| q.changed::<{sname}>())").ok();
                    }
                } else if is_rx {
                    writeln!(out, "                .query(|mut q| {{").ok();
                    for (_, comp) in &strata {
                        let sname = &comp.struct_name;
                        writeln!(out, "                    q = q.write::<{sname}>();").ok();
                    }
                    writeln!(out, "                    q\n                }})").ok();
                } else {
                    writeln!(out, "                .query(|mut q| {{").ok();
                    for (_, comp) in &strata {
                        let sname = &comp.struct_name;
                        writeln!(out, "                    q = q.read::<{sname}>();").ok();
                    }
                    writeln!(out, "                    q.or_group(1, |mut g| {{").ok();
                    for (_, comp) in &strata {
                        let sname = &comp.struct_name;
                        writeln!(out, "                        g = g.changed::<{sname}>();").ok();
                    }
                    writeln!(
                        out,
                        "                        g\n                    }})\n                }})"
                    )
                    .ok();
                }
            }
        }
        writeln!(
            out,
            "                .build(move |mut ctx| {fn_name}(&mut ctx, &_w_net, &_h_net, _net_res_cnt));\n\
             \x20           if !_net_res.is_ok() {{ return _net_res; }}\n\
             \x20       }}"
        )
        .ok();
    }
}

pub(super) fn emit_named_objects_startup(out: &mut String, mir: &MirModule, cat: &GuestCatalog) {
    writeln!(out, "        {{").ok();
    writeln!(
        out,
        "            let _w_obj = Arc::clone(&world_state);\n\
         \x20           let _h_obj = handles;\n\
         \x20           let _r = app\n\
         \x20               .system(c\"__strata_named_objects_startup\")\n\
         \x20               .schedule(ScheduleId::STARTUP)"
    )
    .ok();
    for obj in &mir.objects {
        if let Some(first_comp) = obj
            .components
            .iter()
            .find_map(|c| cat.resolve_comp(c))
            .or_else(|| {
                obj.inits.iter().find_map(|ci| {
                    let cname = ci.canonical_component.as_deref().unwrap_or(&ci.component);
                    cat.resolve_comp(cname)
                })
            })
        {
            writeln!(
                out,
                "                .query(|q| q.with::<{}>())",
                first_comp.struct_name
            )
            .ok();
        }
    }
    writeln!(
        out,
        "                .build(move |ctx: &mut SystemContext<'_>| {{"
    )
    .ok();
    for (oi, obj) in mir.objects.iter().enumerate() {
        let esc_name = escape_rust_str(&obj.name);
        writeln!(
            out,
            "                    let mut _existing_{oi} = FfiEntity::NULL;\n\
             \x20                   if let Some(it) = ctx.query_mut({oi}) {{\n\
             \x20                       if let Some(n) = it.next_chunk() {{ if n > 0 {{ _existing_{oi} = it.entities()[0]; }} }}\n\
             \x20                   }}\n\
             \x20                   let _ent_{oi} = if !_existing_{oi}.is_null() {{\n\
             \x20                       _existing_{oi}\n\
             \x20                   }} else {{"
        )
        .ok();
        let mut built_vars = Vec::new();
        // Build initialized components cleanly
        let mut covered_comps = HashSet::new();
        for (ci, init) in obj.inits.iter().enumerate() {
            let cname = init
                .canonical_component
                .as_deref()
                .unwrap_or(&init.component);
            if let Some(comp) = cat.resolve_comp(cname) {
                covered_comps.insert(comp.id);
                let sname = &comp.struct_name;
                let vname = &comp.variant_name;
                let var = format!("_init_{oi}_{ci}");
                writeln!(
                    out,
                    "                        let mut {var} = {sname}::default();"
                )
                .ok();
                if !init.fields.is_empty() {
                    writeln!(
                        out,
                        "                        let mut {var}_obj = StrataObj::{vname}({var});"
                    )
                    .ok();
                    for (fname, fexpr) in &init.fields {
                        let f_ty = comp
                            .layout
                            .fields
                            .iter()
                            .find(|f| f.name == *fname)
                            .map(|f| f.ty.clone())
                            .unwrap_or(Ty::Unknown);
                        let val_expr = hir_expr_to_strata_val(fexpr, &f_ty, mir, cat);
                        let esc_f = escape_rust_str(fname);
                        writeln!(
                            out,
                            "                        {var}_obj.set_field(0, \"{esc_f}\", {val_expr});"
                        )
                        .ok();
                    }
                    writeln!(
                        out,
                        "                        if let StrataObj::{vname}(_filled) = {var}_obj {{ {var} = _filled; }}"
                    )
                    .ok();
                }
                built_vars.push((
                    comp.handle_field.clone(),
                    var,
                    comp.layout.size == 0 || comp.layout.fields.is_empty(),
                ));
            }
        }
        for (ti, cname) in obj.components.iter().enumerate() {
            if let Some(comp) = cat.resolve_comp(cname)
                && !covered_comps.contains(&comp.id)
            {
                covered_comps.insert(comp.id);
                let sname = &comp.struct_name;
                let var = format!("_def_{oi}_{ti}");
                writeln!(
                    out,
                    "                        let {var} = {sname}::default();"
                )
                .ok();
                built_vars.push((
                    comp.handle_field.clone(),
                    var,
                    comp.layout.size == 0 || comp.layout.fields.is_empty(),
                ));
            }
        }
        writeln!(out, "                        let _ents = [").ok();
        for (hf, var, is_zst) in &built_vars {
            if *is_zst {
                writeln!(
                    out,
                    "                            SpawnEntry::marker(_h_obj.{hf}),"
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "                            SpawnEntry::new(_h_obj.{hf}, &{var}),"
                )
                .ok();
            }
        }
        let spawn_fn = if obj.is_persist {
            "spawn_persistent"
        } else {
            "spawn"
        };
        writeln!(
            out,
            "                        ];\n\
             \x20                       ctx.commands().{spawn_fn}(&_ents).unwrap_or(FfiEntity::NULL)\n\
             \x20                   }};\n\
             \x20                   if !_ent_{oi}.is_null() {{\n\
             \x20                       let _ = ctx.bind_named_object(\"{esc_name}\", _ent_{oi});\n\
             \x20                       if let Ok(mut _w) = _w_obj.lock() {{ _w.named_objects.insert(\"{esc_name}\".to_owned(), _ent_{oi}); }}\n\
             \x20                   }}"
        )
        .ok();
    }
    writeln!(
        out,
        "                    FfiResult::OK\n\
         \x20               }});\n\
         \x20           if !_r.is_ok() {{ return _r; }}\n\
         \x20       }}"
    )
    .ok();
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_system_builder_registration(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    func: &MirFunction,
    idx: usize,
    phys_queries: &[PhysicalQuery],
    stream_decls: &[(String, bool)],
    named_fallback_queries: &HashMap<String, usize>,
    run_if_expr: Option<&HirExpr>,
    sched_label: &str,
    after_timer_tick: Option<&str>,
    handle_var: Option<&str>,
) {
    let fn_ident = format!("strata_sys_fn_{idx}_{}", sanitize_ident(&func.name));
    let sys_name_esc = escape_rust_str(&bare_unqualified_name(&func.name));
    let sched_id = schedule_id_expr(sched_label);

    writeln!(out, "        let _w_s{idx} = Arc::clone(&world_state);").ok();
    writeln!(out, "        let _h_s{idx} = handles;").ok();
    writeln!(out, "        let mut _sys_res_cnt_{idx}: usize = 0;").ok();
    writeln!(
        out,
        "        let mut _b_s{idx} = app.system(c\"{sys_name_esc}\");"
    )
    .ok();
    if handle_var.is_none() {
        writeln!(out, "        _b_s{idx} = _b_s{idx}.schedule({sched_id});").ok();
    }
    if !mir.objects.is_empty() && sched_label == "Startup" {
        writeln!(
            out,
            "        _b_s{idx} = _b_s{idx}.after(c\"__strata_named_objects_startup\");"
        )
        .ok();
    }
    if let Some(tt_name) = after_timer_tick {
        let tt_esc = escape_rust_str(tt_name);
        writeln!(out, "        _b_s{idx} = _b_s{idx}.after(c\"{tt_esc}\");").ok();
    }
    if has_net_protocol(mir)
        && (matches!(func.kind, MirFnKind::SynthesizedTimerTick) || sched_label == "FixedUpdate")
    {
        let rep_count = mir
            .net_components
            .iter()
            .filter(|nc| nc.is_replicated)
            .count();
        if rep_count > 0 {
            let max_per_sys = bamabi_sys::MAX_QUERIES_PER_SYSTEM.saturating_sub(1).max(1);
            let net_chunk_count = rep_count.div_ceil(max_per_sys);
            for chunk_idx in 0..net_chunk_count {
                writeln!(
                    out,
                    "        _b_s{idx} = _b_s{idx}.after_weak(c\"__strata_net_rx_{chunk_idx}\");"
                )
                .ok();
            }
        }
    }

    // 1. Host-registered singleton resources (`func.resources` + `run_if` refs, deduplicated by `rc.id`).
    // Mod-owned resources live in `world_state.mod_res_*` and are NOT bound via SystemBuilder.
    let mut sys_res_order: Vec<(usize, bool)> = Vec::new();
    for rb in &func.resources {
        if let Some(rc) = cat
            .resolve_comp(&rb.canonical_name)
            .or_else(|| cat.resolve_comp(&rb.resource_name))
        {
            if let Some((_, existing_mut)) = sys_res_order.iter_mut().find(|(cid, _)| *cid == rc.id)
            {
                *existing_mut |= rb.mutable;
            } else {
                sys_res_order.push((rc.id, rb.mutable));
            }
        }
    }
    if let Some(rif) = run_if_expr {
        let mut rif_res_refs: Vec<String> = Vec::new();
        collect_hir_res_refs(rif, &mut rif_res_refs);
        for rname in &rif_res_refs {
            if let Some(rc) = cat.resolve_comp(rname)
                && !sys_res_order.iter().any(|(cid, _)| *cid == rc.id)
            {
                sys_res_order.push((rc.id, false));
            }
        }
    }
    for (cid, is_mut) in sys_res_order {
        let rc = &cat.components[cid];
        let hf = &rc.handle_field;
        let method = if is_mut {
            "resource_write_handle"
        } else {
            "resource_read_handle"
        };
        if rc.is_resource_like() {
            writeln!(
                out,
                "        if _h_s{idx}.is_host_res_{cid} {{\n\
                 \x20           _b_s{idx} = _b_s{idx}.{method}(_h_s{idx}.{hf});\n\
                 \x20           _sys_res_cnt_{idx} += 1;\n\
                 \x20       }}"
            )
            .ok();
        } else {
            writeln!(
                out,
                "        _b_s{idx} = _b_s{idx}.{method}(_h_s{idx}.{hf});\n\
                 \x20       _sys_res_cnt_{idx} += 1;"
            )
            .ok();
        }
    }

    if let Some(hvar) = handle_var {
        writeln!(out, "        let {hvar} = match _b_s{idx}").ok();
    } else {
        writeln!(out, "        let _res_s{idx} = _b_s{idx}").ok();
    }

    // 2. Message stream readers & writers (`StreamIn` / `StreamEmit` / `StreamWriteBatch`)
    for (sname, is_write) in stream_decls {
        if let Some(sc) = cat.resolve_comp(sname) {
            if *is_write {
                writeln!(out, "            .message_write::<{}>()", sc.struct_name).ok();
            } else {
                writeln!(out, "            .message_read::<{}>()", sc.struct_name).ok();
            }
        }
    }

    // 3. Queries (conflicting queries grouped via SystemBuilder::param_set; standalone via .query)
    let (pset_groups, _) = compute_guest_query_emit_plan(phys_queries);
    let mut emitted_pset_groups: HashSet<u32> = HashSet::new();
    for (qi, pq) in phys_queries.iter().enumerate() {
        let g = pset_groups.get(qi).copied().unwrap_or(0);
        if g == 0 {
            emit_query_builder_chain(out, cat, pq, "            ", ".query", "");
        } else if emitted_pset_groups.insert(g) {
            writeln!(out, "            .param_set(|ps| {{").ok();
            for (qj, pq_member) in phys_queries.iter().enumerate() {
                if pset_groups.get(qj).copied() == Some(g) {
                    emit_query_builder_chain(
                        out,
                        cat,
                        pq_member,
                        "                ",
                        "ps.query",
                        ";",
                    );
                }
            }
            writeln!(out, "            }})").ok();
        }
    }

    // 4. Hidden fallback queries for `ResolveNamedObject`
    let mut ordered_fb: Vec<(&String, &usize)> = named_fallback_queries.iter().collect();
    ordered_fb.sort_by_key(|(_, i)| **i);
    for (obj_name, _) in ordered_fb {
        if let Some(obj) = mir.objects.iter().find(|o| o.name == *obj_name)
            && let Some(first_comp) = obj
                .components
                .iter()
                .find_map(|c| cat.resolve_comp(c))
                .or_else(|| {
                    obj.inits.iter().find_map(|ci| {
                        let cname = ci.canonical_component.as_deref().unwrap_or(&ci.component);
                        cat.resolve_comp(cname)
                    })
                })
        {
            writeln!(
                out,
                "            .query(|q| q.with::<{}>())",
                first_comp.struct_name
            )
            .ok();
        }
    }

    // 5. Optional `schedule ... run_if(...)` predicate via `.run_if_fn`
    if let Some(rif) = run_if_expr {
        let mut res_refs: Vec<String> = Vec::new();
        collect_hir_res_refs(rif, &mut res_refs);
        let mut host_guards: Vec<String> = Vec::new();
        for rname in &res_refs {
            if let Some(rc) = cat.resolve_comp(rname) {
                let g = if rc.is_resource_like() {
                    format!("_h_rif{idx}.is_host_res_{}", rc.id)
                } else {
                    "true".to_owned()
                };
                if !host_guards.contains(&g) {
                    host_guards.push(g);
                }
            }
        }
        let cond_expr = format_run_if_hir_expr(
            rif,
            mir,
            cat,
            &format!("_w_rif{idx}"),
            &format!("_h_rif{idx}"),
            None,
        );
        let host_guard_expr = if host_guards.is_empty() {
            "false".to_owned()
        } else {
            host_guards.join(" || ")
        };
        writeln!(
            out,
            "            .run_if_fn({{\n\
             \x20               let _w_rif{idx} = Arc::clone(&_w_s{idx});\n\
             \x20               let _h_rif{idx} = _h_s{idx};\n\
             \x20               move || {{ if {host_guard_expr} {{ true }} else {{ ({cond_expr}).as_bool() }} }}\n\
             \x20           }})"
        )
        .ok();
    }

    if handle_var.is_some() {
        writeln!(
            out,
            "            .register_handle(move |mut ctx| {fn_ident}(&mut ctx, &_w_s{idx}, &_h_s{idx}, _sys_res_cnt_{idx})) {{\n\
             \x20           Ok(h) => h,\n\
             \x20           Err(e) => return e,\n\
             \x20       }};"
        )
        .ok();
    } else {
        writeln!(
            out,
            "            .build(move |mut ctx| {fn_ident}(&mut ctx, &_w_s{idx}, &_h_s{idx}, _sys_res_cnt_{idx}));\n\
             \x20       if !_res_s{idx}.is_ok() {{ return _res_s{idx}; }}"
        )
        .ok();
    }
}

pub(super) fn emit_query_builder_chain(
    out: &mut String,
    cat: &GuestCatalog,
    pq: &PhysicalQuery,
    indent: &str,
    call_prefix: &str,
    trailing_semi: &str,
) {
    writeln!(out, "{indent}{call_prefix}(|mut q| {{").ok();
    let mut post_changed: Vec<&str> = Vec::new();
    let mut post_added: Vec<&str> = Vec::new();
    for pt in &pq.terms {
        let sname = &cat.components[pt.comp_id].struct_name;
        let is_opt = matches!(
            pt.mode,
            TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
        );
        let (method, handled_changed, handled_added) = match pt.mode {
            TermAccessMode::Write | TermAccessMode::SelectiveWrite => ("write", false, false),
            TermAccessMode::OptionalRead => ("optional_read", false, false),
            TermAccessMode::OptionalWrite => ("optional_write", false, false),
            TermAccessMode::Allow => ("allow", false, false),
            TermAccessMode::Has => ("has", false, false),
            TermAccessMode::RemovedRead => ("removed", false, false),
            TermAccessMode::With => ("with", false, false),
            TermAccessMode::Without => ("without", false, false),
            _ if pt.changed_filter && !pt.added_filter => ("changed", true, false),
            _ if pt.added_filter && !pt.changed_filter => ("added", false, true),
            _ if pt.changed_filter && pt.added_filter => ("changed", true, false),
            _ => ("read", false, false),
        };
        writeln!(out, "{indent}    q = q.{method}::<{sname}>();").ok();
        if !is_opt {
            if pt.changed_filter && !handled_changed {
                post_changed.push(sname.as_str());
            }
            if pt.added_filter && !handled_added {
                post_added.push(sname.as_str());
            }
        }
    }
    for sname in post_changed {
        writeln!(out, "{indent}    q = q.changed::<{sname}>();").ok();
    }
    for sname in post_added {
        writeln!(out, "{indent}    q = q.added::<{sname}>();").ok();
    }
    for cid in &pq.with_filters {
        let sname = &cat.components[*cid].struct_name;
        writeln!(out, "{indent}    q = q.with::<{sname}>();").ok();
    }
    for cid in &pq.without_filters {
        let sname = &cat.components[*cid].struct_name;
        writeln!(out, "{indent}    q = q.without::<{sname}>();").ok();
    }
    for cid in &pq.extra_changed_filters {
        let sname = &cat.components[*cid].struct_name;
        writeln!(out, "{indent}    q = q.changed::<{sname}>();").ok();
    }
    for cid in &pq.extra_added_filters {
        let sname = &cat.components[*cid].struct_name;
        writeln!(out, "{indent}    q = q.added::<{sname}>();").ok();
    }
    writeln!(out, "{indent}    q\n{indent}}}){trailing_semi}").ok();
}

pub(super) fn emit_schedule_nodes(
    out: &mut String,
    sched_idx: usize,
    nodes: &[HirScheduleGroup],
    sched_id: &str,
    set_counter: &mut usize,
    sys_handles: &HashMap<String, String>,
) {
    struct ScheduleSetPlan {
        idx: usize,
        set_name: String,
        var_name: String,
        kind: String,
        leaf_sys_var: Option<String>,
        parent_idx: Option<usize>,
        after_deps: Vec<(usize, bool)>,
        raw_before: Vec<String>,
        raw_after: Vec<String>,
        raw_names: Vec<String>,
    }

    fn collect_refs(nodes: &[HirScheduleGroup], out: &mut HashSet<String>) {
        for n in nodes {
            for b in &n.before {
                out.insert(b.clone());
                out.insert(bare_unqualified_name(b));
            }
            for a in &n.after {
                out.insert(a.clone());
                out.insert(bare_unqualified_name(a));
            }
            collect_refs(&n.children, out);
        }
    }

    fn flatten_nodes(
        nodes: &[HirScheduleGroup],
        sched_idx: usize,
        parent_idx: Option<usize>,
        parent_is_seq: bool,
        parent_is_weak: bool,
        referenced_names: &HashSet<String>,
        set_counter: &mut usize,
        sys_handles: &HashMap<String, String>,
        plans: &mut Vec<ScheduleSetPlan>,
        unwrapped_leaves: &mut Vec<(String, Option<usize>)>,
    ) {
        let mut prev_sibling: Option<usize> = None;
        for node in nodes {
            let bare_node = bare_unqualified_name(&node.name);
            let is_refd = !node.name.is_empty()
                && (referenced_names.contains(&node.name) || referenced_names.contains(&bare_node));
            if node.kind == "leaf" {
                let Some(sys_var) = sys_handles.get(&node.name) else {
                    continue;
                };
                if parent_is_seq || !node.before.is_empty() || !node.after.is_empty() || is_refd {
                    let k = *set_counter;
                    *set_counter += 1;
                    let idx = plans.len();
                    let raw_name = if node.name.trim().is_empty() {
                        format!("sched_{sched_idx}_leaf_{k}")
                    } else {
                        format!("sched_{sched_idx}_leaf_{}_{k}", sanitize_ident(&bare_node))
                    };
                    let mut after_deps = Vec::new();
                    if parent_is_seq && let Some(prev) = prev_sibling {
                        after_deps.push((prev, parent_is_weak));
                    }
                    let mut raw_names = vec![node.name.clone()];
                    if bare_node != node.name {
                        raw_names.push(bare_node);
                    }
                    plans.push(ScheduleSetPlan {
                        idx,
                        set_name: raw_name,
                        var_name: format!("_set_{k}"),
                        kind: "leaf".to_owned(),
                        leaf_sys_var: Some(sys_var.clone()),
                        parent_idx,
                        after_deps,
                        raw_before: node.before.clone(),
                        raw_after: node.after.clone(),
                        raw_names,
                    });
                    if parent_is_seq {
                        prev_sibling = Some(idx);
                    }
                } else {
                    unwrapped_leaves.push((sys_var.clone(), parent_idx));
                }
                continue;
            }

            let k = *set_counter;
            *set_counter += 1;
            let idx = plans.len();
            let raw_name = if node.name.trim().is_empty() {
                format!("sched_{sched_idx}_{}_{k}", sanitize_ident(&node.kind))
            } else {
                format!("sched_{sched_idx}_{}_{k}", sanitize_ident(&bare_node))
            };
            let mut after_deps = Vec::new();
            if parent_is_seq && let Some(prev) = prev_sibling {
                after_deps.push((prev, parent_is_weak));
            }
            let mut raw_names = Vec::new();
            if !node.name.trim().is_empty() {
                raw_names.push(node.name.clone());
                if bare_node != node.name {
                    raw_names.push(bare_node);
                }
            }
            plans.push(ScheduleSetPlan {
                idx,
                set_name: raw_name,
                var_name: format!("_set_{k}"),
                kind: node.kind.clone(),
                leaf_sys_var: None,
                parent_idx,
                after_deps,
                raw_before: node.before.clone(),
                raw_after: node.after.clone(),
                raw_names,
            });
            if parent_is_seq {
                prev_sibling = Some(idx);
            }

            let child_is_seq = matches!(node.kind.as_str(), "seq" | "seq_weak");
            let child_is_weak = node.kind == "seq_weak";
            flatten_nodes(
                &node.children,
                sched_idx,
                Some(idx),
                child_is_seq,
                child_is_weak,
                referenced_names,
                set_counter,
                sys_handles,
                plans,
                unwrapped_leaves,
            );
        }
    }

    let mut referenced_names = HashSet::new();
    collect_refs(nodes, &mut referenced_names);
    let mut plans = Vec::new();
    let mut unwrapped_leaves = Vec::new();
    flatten_nodes(
        nodes,
        sched_idx,
        None,
        false,
        false,
        &referenced_names,
        set_counter,
        sys_handles,
        &mut plans,
        &mut unwrapped_leaves,
    );

    let mut name_to_idxs: HashMap<String, Vec<usize>> = HashMap::new();
    for p in &plans {
        for nm in &p.raw_names {
            name_to_idxs.entry(nm.clone()).or_default().push(p.idx);
        }
    }

    let before_edges: Vec<(usize, String)> = plans
        .iter()
        .flat_map(|p| p.raw_before.iter().map(move |tgt| (p.idx, tgt.clone())))
        .collect();
    for (src_idx, tgt_name) in before_edges {
        let targets = name_to_idxs
            .get(&tgt_name)
            .or_else(|| name_to_idxs.get(&bare_unqualified_name(&tgt_name)))
            .cloned()
            .unwrap_or_default();
        for t_idx in targets {
            if t_idx != src_idx {
                plans[t_idx].after_deps.push((src_idx, false));
            }
        }
    }
    let raw_afters: Vec<Vec<String>> = plans.iter().map(|p| p.raw_after.clone()).collect();
    for (idx, after_names) in raw_afters.into_iter().enumerate() {
        for dep_name in after_names {
            let deps = name_to_idxs
                .get(&dep_name)
                .or_else(|| name_to_idxs.get(&bare_unqualified_name(&dep_name)))
                .cloned()
                .unwrap_or_default();
            for d_idx in deps {
                if d_idx != idx {
                    plans[idx].after_deps.push((d_idx, false));
                }
            }
        }
    }

    // Propagate parent group ordering onto nested sets/leaves since ABI v0.3 `ScheduleSetBuilder`
    // has `.before`/`.after` without `.in_set`.
    let n = plans.len();
    let mut children_of: Vec<Vec<usize>> = vec![Vec::new(); n];
    for p in &plans {
        if let Some(par) = p.parent_idx {
            children_of[par].push(p.idx);
        }
    }
    let mut descendants_of: Vec<Vec<usize>> = vec![Vec::new(); n];
    for idx in (0..n).rev() {
        let mut desc = Vec::new();
        for &c in &children_of[idx] {
            desc.push(c);
            desc.extend_from_slice(&descendants_of[c]);
        }
        descendants_of[idx] = desc;
    }
    let parent_idxs: Vec<Option<usize>> = plans.iter().map(|p| p.parent_idx).collect();
    for (idx, par_opt) in parent_idxs.into_iter().enumerate() {
        if let Some(par) = par_opt {
            let par_deps = plans[par].after_deps.clone();
            for (dep, is_weak) in par_deps {
                if dep != idx && !descendants_of[idx].contains(&dep) {
                    plans[idx].after_deps.push((dep, is_weak));
                }
            }
        }
    }
    let all_after_deps: Vec<Vec<(usize, bool)>> =
        plans.iter().map(|p| p.after_deps.clone()).collect();
    for (idx, cur_deps) in all_after_deps.into_iter().enumerate() {
        for (dep, is_weak) in cur_deps {
            for &d_child in &descendants_of[dep] {
                if d_child != idx
                    && !descendants_of[idx].contains(&d_child)
                    && !descendants_of[d_child].contains(&idx)
                {
                    plans[idx].after_deps.push((d_child, is_weak));
                }
            }
        }
    }

    // Kahn's topological order so `.after(_set_d)` only references declared sets.
    let mut indeg = vec![0usize; n];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];
    for p in &plans {
        let mut prereqs = Vec::new();
        if let Some(par) = p.parent_idx {
            prereqs.push(par);
        }
        for &(dep, _) in &p.after_deps {
            prereqs.push(dep);
        }
        prereqs.sort_unstable();
        prereqs.dedup();
        for pr in prereqs {
            if pr != p.idx {
                dependents[pr].push(p.idx);
                indeg[p.idx] += 1;
            }
        }
    }
    let mut queue: Vec<usize> = (0..n).filter(|&i| indeg[i] == 0).collect();
    let mut q_head = 0usize;
    let mut order = Vec::with_capacity(n);
    let mut in_order = vec![false; n];
    while q_head < queue.len() {
        let cur = queue[q_head];
        q_head += 1;
        if in_order[cur] {
            continue;
        }
        in_order[cur] = true;
        order.push(cur);
        for &nxt in &dependents[cur] {
            indeg[nxt] = indeg[nxt].saturating_sub(1);
            if indeg[nxt] == 0 {
                queue.push(nxt);
            }
        }
    }
    for (i, &seen) in in_order.iter().enumerate() {
        if !seen {
            order.push(i);
        }
    }

    let mut emitted_sets = HashSet::new();
    for &idx in &order {
        let p = &plans[idx];
        let esc_set = escape_rust_str(&p.set_name);
        let set_var = &p.var_name;
        let mode_call = match p.kind.as_str() {
            "seq" => ".sequence()",
            "seq_weak" => ".sequence_weak()",
            "par" => ".parallel()",
            _ => "",
        };
        let mut chain =
            format!("ScheduleSetBuilder::new(\"{esc_set}\").schedule({sched_id}){mode_call}");
        let mut seen_after = HashSet::new();
        for &(dep, is_weak) in &p.after_deps {
            if emitted_sets.contains(&dep) && seen_after.insert(dep) {
                let method = if is_weak { "after_weak" } else { "after" };
                chain.push_str(&format!(".{method}({})", plans[dep].var_name));
            }
        }
        writeln!(
            out,
            "        let {set_var} = match app.configure_schedule_set(\n\
             \x20           {chain}\n\
             \x20       ) {{\n\
             \x20           Ok(s) => s,\n\
             \x20           Err(e) => return e,\n\
             \x20       }};"
        )
        .ok();
        emitted_sets.insert(idx);
    }
    for p in &plans {
        if let Some(ref sys_var) = p.leaf_sys_var {
            let set_var = &p.var_name;
            writeln!(
                out,
                "        let _mnt = app.mount_system({sys_var}, {sched_id}, {set_var});\n\
                 \x20       if !_mnt.is_ok() {{ return _mnt; }}"
            )
            .ok();
        }
    }
    for (sys_var, par_opt) in unwrapped_leaves {
        let par_expr = par_opt.map_or("BamSystemSet::INVALID", |pi| plans[pi].var_name.as_str());
        writeln!(
            out,
            "        let _mnt = app.mount_system({sys_var}, {sched_id}, {par_expr});\n\
             \x20       if !_mnt.is_ok() {{ return _mnt; }}"
        )
        .ok();
    }
}

pub(super) fn collect_schedule_leaf_names(nodes: &[HirScheduleGroup], out: &mut HashSet<String>) {
    for n in nodes {
        if n.kind == "leaf" {
            out.insert(n.name.clone());
        } else {
            collect_schedule_leaf_names(&n.children, out);
        }
    }
}

pub(super) fn schedule_id_expr(label: &str) -> &'static str {
    match label {
        "Startup" => "ScheduleId::STARTUP",
        "PreUpdate" => "ScheduleId::PRE_UPDATE",
        "Update" => "ScheduleId::UPDATE",
        "PostUpdate" => "ScheduleId::POST_UPDATE",
        "Last" => "ScheduleId::LAST",
        "PreStartup" => "BevySchedules::DEFAULT.pre_startup()",
        "PostStartup" => "BevySchedules::DEFAULT.post_startup()",
        "First" => "BevySchedules::DEFAULT.first()",
        "FixedFirst" => "BevySchedules::DEFAULT.fixed_first()",
        "FixedPreUpdate" => "BevySchedules::DEFAULT.fixed_pre_update()",
        "FixedPostUpdate" => "BevySchedules::DEFAULT.fixed_post_update()",
        "FixedLast" => "BevySchedules::DEFAULT.fixed_last()",
        "SpawnScene" => "BevySchedules::DEFAULT.spawn_scene()",
        _ => "ScheduleId::FIXED_UPDATE",
    }
}

// ============================================================================
// HIR Constant / Run-If / Table Expression Formatting Helpers
// ============================================================================

pub(super) fn bare_unqualified_name(raw: &str) -> String {
    let trimmed = raw.trim();
    let tail = trimmed.rsplit("::").next().unwrap_or(trimmed);
    if tail.is_empty() {
        "unnamed".to_owned()
    } else {
        tail.replace("::", "_")
    }
}

pub(super) fn collect_hir_res_refs(expr: &HirExpr, out: &mut Vec<String>) {
    match expr {
        HirExpr::Call(c) => {
            if (c.callee == "res" || c.callee == "res_mut")
                && let Some(r) = c.generic_args.first()
                && !out.contains(r)
            {
                out.push(r.clone());
            }
            if let Some(ref r) = c.receiver {
                collect_hir_res_refs(r, out);
            }
            for a in &c.args {
                collect_hir_res_refs(a, out);
            }
        }
        HirExpr::Field { base, .. }
        | HirExpr::Unary { expr: base, .. }
        | HirExpr::Cast { expr: base, .. } => {
            collect_hir_res_refs(base, out);
        }
        HirExpr::Binary { lhs, rhs, .. } => {
            collect_hir_res_refs(lhs, out);
            collect_hir_res_refs(rhs, out);
        }
        HirExpr::Index { base, index, .. } => {
            collect_hir_res_refs(base, out);
            collect_hir_res_refs(index, out);
        }
        _ => {}
    }
}

pub(super) fn format_run_if_res_access(
    rc: &ComponentEntry,
    field_esc: &str,
    world_var: &str,
    handles_var: &str,
    ctx_var: Option<&str>,
) -> String {
    let sname = &rc.struct_name;
    let hf = &rc.handle_field;
    let id = rc.id;
    let host_expr = if let Some(ctx) = ctx_var {
        format!(
            "{ctx}.res_by_handle::<{sname}>({handles_var}.{hf}).map_or(StrataVal::Unit, |r| r.strata_get(0, \"{field_esc}\"))"
        )
    } else {
        "StrataVal::Unit".to_owned()
    };
    if rc.is_resource_like() {
        format!(
            "if {handles_var}.is_host_res_{id} {{ {host_expr} }} else {{ {world_var}.lock().map_or(StrataVal::Unit, |w| w.mod_res_{id}.strata_get(0, \"{field_esc}\")) }}"
        )
    } else {
        host_expr
    }
}

pub(super) fn format_run_if_hir_expr(
    expr: &HirExpr,
    mir: &MirModule,
    cat: &GuestCatalog,
    world_var: &str,
    handles_var: &str,
    ctx_var: Option<&str>,
) -> String {
    match expr {
        HirExpr::BoolLit(b) => format!("StrataVal::Bool({b})"),
        HirExpr::IntLit { value, .. } => format!("StrataVal::I32({}i32)", *value as i32),
        HirExpr::FloatLit { value, .. } => format!("StrataVal::F32({})", fmt_f32(*value as f32)),
        HirExpr::Unary { op, expr, .. } => {
            let op_s = match op {
                strata_sema::hir::HirUnOp::Neg => "-",
                strata_sema::hir::HirUnOp::Not => "!",
                strata_sema::hir::HirUnOp::BitNot => "~",
                _ => "",
            };
            let inner = format_run_if_hir_expr(expr, mir, cat, world_var, handles_var, ctx_var);
            format!("strata_unop(\"{op_s}\", &{inner})")
        }
        HirExpr::Binary { op, lhs, rhs, .. } => {
            let op_s = hir_binop_str(*op);
            let l = format_run_if_hir_expr(lhs, mir, cat, world_var, handles_var, ctx_var);
            let r = format_run_if_hir_expr(rhs, mir, cat, world_var, handles_var, ctx_var);
            format!("strata_binop(\"{op_s}\", &{l}, &{r}, false)")
        }
        HirExpr::Call(c) => {
            if (c.callee == "res" || c.callee == "res_mut")
                && let Some(rname) = c.generic_args.first()
                && let Some(rc) = cat.resolve_comp(rname)
            {
                return format_run_if_res_access(rc, "", world_var, handles_var, ctx_var);
            }
            "StrataVal::Unit".to_owned()
        }
        HirExpr::Field { base, field, .. } => {
            let esc = escape_rust_str(field);
            if let HirExpr::Call(c) = base.as_ref()
                && (c.callee == "res" || c.callee == "res_mut")
                && let Some(rname) = c.generic_args.first()
                && let Some(rc) = cat.resolve_comp(rname)
            {
                return format_run_if_res_access(rc, &esc, world_var, handles_var, ctx_var);
            }
            let base_expr = format_run_if_hir_expr(base, mir, cat, world_var, handles_var, ctx_var);
            format!(
                "match {base_expr} {{ StrataVal::Obj(_o) => _o.get_field(0, \"{esc}\"), _ => StrataVal::Unit }}"
            )
        }
        HirExpr::Path { name, .. } => {
            if let Some(disc) = lookup_enum_path_disc(name, mir) {
                format!("StrataVal::I32({disc}i32)")
            } else {
                "StrataVal::Bool(true)".to_owned()
            }
        }
        _ => "StrataVal::Bool(true)".to_owned(),
    }
}

pub(super) fn hir_binop_str(op: strata_sema::hir::HirBinOp) -> &'static str {
    use strata_sema::hir::HirBinOp as B;
    match op {
        B::Add => "+",
        B::Sub => "-",
        B::Mul => "*",
        B::Div => "/",
        B::Rem => "%",
        B::BitAnd => "&",
        B::BitOr => "|",
        B::BitXor => "^",
        B::Shl => "<<",
        B::Shr => ">>",
        B::Ne => "!=",
        B::Lt => "<",
        B::Le => "<=",
        B::Gt => ">",
        B::Ge => ">=",
        B::And => "&&",
        B::Or => "||",
        _ => "==",
    }
}

pub(super) fn format_hir_expr_rust(
    expr: &HirExpr,
    target_ty: &Ty,
    mir: &MirModule,
    _cat: &GuestCatalog,
) -> String {
    match expr {
        HirExpr::BoolLit(b) => {
            if matches!(target_ty, Ty::Bool) {
                format!("{b}")
            } else {
                format!("FfiBool::from_bool({b})")
            }
        }
        HirExpr::IntLit { value, .. } => match target_ty {
            Ty::U8 => format!("{value}i64 as u8"),
            Ty::I8 => format!("{value}i64 as i8"),
            Ty::U16 => format!("{value}i64 as u16"),
            Ty::I16 => format!("{value}i64 as i16"),
            Ty::U32 | Ty::Sym | Ty::Rgba8 => format!("{value}i64 as u32"),
            Ty::U64 => format!("{value}i64 as u64"),
            Ty::I64 => format!("{value}i64"),
            Ty::Fix32 => format_fix32_i32_lit(scale_int_fix32(*value)),
            Ty::Fix64 => format_fix64_i64_lit(scale_int_fix64(*value)),
            Ty::F32 | Ty::UnitScalar { .. } => format!("{}f32", *value as f32),
            Ty::F64 => format!("{}f64", *value as f64),
            _ => format!("{value}i64 as i32"),
        },
        HirExpr::FloatLit { value, ty } => match target_ty {
            Ty::F64 => fmt_f64(*value),
            Ty::Fix32 => format_fix32_i32_lit(scale_float_fix32(*value)),
            Ty::Fix64 => format_fix64_i64_lit(scale_float_fix64(*value)),
            _ if matches!(ty, Ty::F64) => fmt_f64(*value),
            _ => fmt_f32(*value as f32),
        },
        HirExpr::StringLit(s) => {
            if let Ty::InlineStr(cap) = target_ty {
                let words = 1 + cap.div_ceil(4);
                let mut out_words = vec![0u32; words];
                let mut end = s.len().min(*cap);
                while end > 0 && !s.is_char_boundary(end) {
                    end -= 1;
                }
                out_words[0] = end as u32;
                for (wi, chunk) in s.as_bytes()[..end].chunks(4).enumerate() {
                    let mut arr = [0u8; 4];
                    arr[..chunk.len()].copy_from_slice(chunk);
                    out_words[1 + wi] = u32::from_le_bytes(arr);
                }
                let parts: Vec<String> = out_words.iter().map(|w| format!("{w}u32")).collect();
                format!("[{}]", parts.join(", "))
            } else {
                format!("\"{}\"", escape_rust_str(s))
            }
        }
        HirExpr::Path { name, .. } => {
            if let Some(vec_expr) = rust_vec_path_const(name) {
                vec_expr.to_owned()
            } else if let Some(disc) = lookup_enum_path_disc(name, mir) {
                match find_enum_repr_by_path(name, mir) {
                    (1, _) => format!("{disc}i64 as u8"),
                    (2, _) => format!("{disc}i64 as u16"),
                    (_, true) => format!("{disc}i64 as i32"),
                    _ => format!("{disc}i64 as u32"),
                }
            } else if let Some(c) = mir.consts.iter().find(|c| {
                let seg = name.rsplit("::").next().unwrap_or(name.as_str());
                c.name == *name || c.name.rsplit("::").next() == Some(seg)
            }) && let Some(ref inner) = c.expr
            {
                format_hir_expr_rust(inner, target_ty, mir, _cat)
            } else {
                "0".to_owned()
            }
        }
        HirExpr::Call(c) if c.callee.rsplit("::").next().unwrap_or(c.callee.as_str()) == "bits" => {
            if let Ty::BitSet(bits) = target_ty {
                let words = (*bits).div_ceil(32).max(1);
                let mut mask_words = vec![0u32; words];
                for arg in &c.args {
                    let bit_opt = match arg {
                        HirExpr::IntLit { value, .. } if *value >= 0 => Some(*value as usize),
                        HirExpr::Path { name, .. } => {
                            lookup_enum_path_disc(name, mir).map(|v| v.max(0) as usize)
                        }
                        _ => None,
                    };
                    if let Some(b) = bit_opt
                        && b / 32 < words
                    {
                        mask_words[b / 32] |= 1u32 << (b % 32);
                    }
                }
                let parts: Vec<String> = mask_words.iter().map(|w| format!("{w}u32")).collect();
                format!("[{}]", parts.join(", "))
            } else {
                let mut mask = 0u64;
                for arg in &c.args {
                    let bit_opt = match arg {
                        HirExpr::IntLit { value, .. } if *value >= 0 => Some(*value as u32),
                        HirExpr::Path { name, .. } => lookup_enum_path_disc(name, mir)
                            .and_then(|v| (v >= 0).then_some(v as u32)),
                        _ => None,
                    };
                    if let Some(b) = bit_opt
                        && b < 64
                    {
                        mask |= 1u64 << b;
                    }
                }
                if let Some(rs_ty) = rust_scalar_str_for_hir_ty(target_ty) {
                    format!("0x{mask:X}u64 as {rs_ty}")
                } else {
                    format!("0x{mask:X}u64")
                }
            }
        }
        HirExpr::Call(c)
            if matches!(
                c.callee.rsplit("::").next().unwrap_or(c.callee.as_str()),
                "vec2"
                    | "Vec2"
                    | "vec3"
                    | "Vec3"
                    | "vec4"
                    | "Vec4"
                    | "quat"
                    | "Quat"
                    | "rgba"
                    | "Rgba"
            ) =>
        {
            let vals: Vec<String> = c
                .args
                .iter()
                .map(|a| format_hir_expr_rust(a, &Ty::F32, mir, _cat))
                .collect();
            format!("[{}]", vals.join(", "))
        }
        HirExpr::Call(c)
            if matches!(
                c.callee.rsplit("::").next().unwrap_or(c.callee.as_str()),
                "vec3a" | "Vec3a"
            ) =>
        {
            let a0 = c.args.first().map_or_else(
                || "0.0f32".to_owned(),
                |a| format_hir_expr_rust(a, &Ty::F32, mir, _cat),
            );
            let a1 = c.args.get(1).map_or_else(
                || "0.0f32".to_owned(),
                |a| format_hir_expr_rust(a, &Ty::F32, mir, _cat),
            );
            let a2 = c.args.get(2).map_or_else(
                || "0.0f32".to_owned(),
                |a| format_hir_expr_rust(a, &Ty::F32, mir, _cat),
            );
            if matches!(target_ty, Ty::Vec3a) {
                format!("[{a0}, {a1}, {a2}, 0.0f32]")
            } else {
                format!("[{a0}, {a1}, {a2}]")
            }
        }
        HirExpr::Call(c)
            if matches!(
                c.callee.rsplit("::").next().unwrap_or(c.callee.as_str()),
                "ivec2" | "IVec2" | "ivec3" | "IVec3"
            ) =>
        {
            let vals: Vec<String> = c
                .args
                .iter()
                .map(|a| format!("({}) as i32", format_hir_expr_rust(a, &Ty::I32, mir, _cat)))
                .collect();
            format!("[{}]", vals.join(", "))
        }
        HirExpr::Call(c)
            if matches!(
                c.callee.rsplit("::").next().unwrap_or(c.callee.as_str()),
                "uvec2" | "UVec2"
            ) =>
        {
            let vals: Vec<String> = c
                .args
                .iter()
                .map(|a| format!("({}) as u32", format_hir_expr_rust(a, &Ty::U32, mir, _cat)))
                .collect();
            format!("[{}]", vals.join(", "))
        }
        HirExpr::Call(c)
            if matches!(
                c.callee.rsplit("::").next().unwrap_or(c.callee.as_str()),
                "mat3" | "Mat3"
            ) =>
        {
            if c.args.len() >= 9 {
                let vals: Vec<String> = c
                    .args
                    .iter()
                    .take(9)
                    .map(|a| format_hir_expr_rust(a, &Ty::F32, mir, _cat))
                    .collect();
                format!("[{}]", vals.join(", "))
            } else if c.args.len() == 3 {
                let mut cols = Vec::with_capacity(9);
                for a in &c.args {
                    let v = format_hir_expr_rust(a, &Ty::Vec3, mir, _cat);
                    cols.push(format!("({v})[0]"));
                    cols.push(format!("({v})[1]"));
                    cols.push(format!("({v})[2]"));
                }
                format!("[{}]", cols.join(", "))
            } else {
                let d = c.args.first().map_or_else(
                    || "1.0f32".to_owned(),
                    |a| format_hir_expr_rust(a, &Ty::F32, mir, _cat),
                );
                format!("[{d}, 0.0f32, 0.0f32, 0.0f32, {d}, 0.0f32, 0.0f32, 0.0f32, {d}]")
            }
        }
        HirExpr::Call(c)
            if matches!(
                c.callee.rsplit("::").next().unwrap_or(c.callee.as_str()),
                "mat4" | "Mat4"
            ) =>
        {
            if c.args.len() >= 16 {
                let vals: Vec<String> = c
                    .args
                    .iter()
                    .take(16)
                    .map(|a| format_hir_expr_rust(a, &Ty::F32, mir, _cat))
                    .collect();
                format!("[{}]", vals.join(", "))
            } else if c.args.len() == 4 {
                let mut cols = Vec::with_capacity(16);
                for a in &c.args {
                    let v = format_hir_expr_rust(a, &Ty::Vec4, mir, _cat);
                    cols.push(format!("({v})[0]"));
                    cols.push(format!("({v})[1]"));
                    cols.push(format!("({v})[2]"));
                    cols.push(format!("({v})[3]"));
                }
                format!("[{}]", cols.join(", "))
            } else {
                let d = c.args.first().map_or_else(
                    || "1.0f32".to_owned(),
                    |a| format_hir_expr_rust(a, &Ty::F32, mir, _cat),
                );
                format!(
                    "[{d}, 0.0f32, 0.0f32, 0.0f32, 0.0f32, {d}, 0.0f32, 0.0f32, 0.0f32, 0.0f32, {d}, 0.0f32, 0.0f32, 0.0f32, 0.0f32, {d}]"
                )
            }
        }
        HirExpr::Call(c)
            if matches!(
                c.callee.rsplit("::").next().unwrap_or(c.callee.as_str()),
                "meters" | "sec" | "ms" | "rad" | "deg" | "mps" | "mps2" | "hz" | "frames"
            ) =>
        {
            if let Some(a0) = c.args.first() {
                format_hir_expr_rust(a0, target_ty, mir, _cat)
            } else {
                table_field_default(target_ty, mir)
            }
        }
        HirExpr::StructLit { name, fields, .. } => {
            let comp_opt = _cat.resolve_comp(name).or_else(|| match target_ty {
                Ty::Named(n) => _cat.resolve_comp(n),
                _ => None,
            });
            if let Some(comp) = comp_opt {
                if comp.layout.size == 0 || comp.layout.fields.is_empty() {
                    comp.struct_name.clone()
                } else {
                    fn format_abi_field_val(
                        expr: &HirExpr,
                        fty: &Ty,
                        mir: &MirModule,
                        cat: &GuestCatalog,
                    ) -> String {
                        match fty {
                            Ty::Bool => {
                                if let HirExpr::BoolLit(b) = expr {
                                    format!("FfiBool::from_bool({b})")
                                } else {
                                    format!(
                                        "FfiBool::from_bool({})",
                                        format_hir_expr_rust(expr, &Ty::Bool, mir, cat)
                                    )
                                }
                            }
                            Ty::Array { elem, .. } => match expr {
                                HirExpr::ArrayLit { elems, .. } => {
                                    let items: Vec<String> = elems
                                        .iter()
                                        .map(|e| format_abi_field_val(e, elem, mir, cat))
                                        .collect();
                                    format!("[{}]", items.join(", "))
                                }
                                HirExpr::Path { name, .. } => {
                                    if let Some(c) = mir.consts.iter().find(|c| {
                                        let seg = name.rsplit("::").next().unwrap_or(name.as_str());
                                        c.name == *name || c.name.rsplit("::").next() == Some(seg)
                                    }) && let Some(ref inner) = c.expr
                                    {
                                        format_abi_field_val(inner, fty, mir, cat)
                                    } else {
                                        format_hir_expr_rust(expr, fty, mir, cat)
                                    }
                                }
                                _ => format_hir_expr_rust(expr, fty, mir, cat),
                            },
                            _ => format_hir_expr_rust(expr, fty, mir, cat),
                        }
                    }
                    let mut field_inits = Vec::with_capacity(fields.len());
                    for (fname, fexpr) in fields {
                        if let Some(sf) = comp
                            .layout
                            .fields
                            .iter()
                            .find(|sf| !sf.is_padding && sf.name == *fname)
                        {
                            let rf = sanitize_rust_ident(fname);
                            let fv = format_abi_field_val(fexpr, &sf.ty, mir, _cat);
                            field_inits.push(format!("{rf}: {fv}"));
                        }
                    }
                    let sname = &comp.struct_name;
                    if field_inits.is_empty() {
                        format!("{sname}::strata_const_default()")
                    } else {
                        format!(
                            "{sname} {{ {}, ..{sname}::strata_const_default() }}",
                            field_inits.join(", ")
                        )
                    }
                }
            } else {
                table_field_default(target_ty, mir)
            }
        }
        HirExpr::ArrayLit { elems, .. } => {
            if let Ty::SmallVec { elem, cap } = target_ty {
                let (sv_sz, sv_al) =
                    crate::rust_guest::items::guest_ty_abi_size_align(target_ty, mir);
                let elem_exprs: Vec<String> = elems
                    .iter()
                    .take(*cap)
                    .map(|e| {
                        if **elem == Ty::Bool {
                            if let HirExpr::BoolLit(b) = e {
                                format!("FfiBool::from_bool({b})")
                            } else {
                                format!(
                                    "FfiBool::from_bool({})",
                                    format_hir_expr_rust(e, &Ty::Bool, mir, _cat)
                                )
                            }
                        } else {
                            format_hir_expr_rust(e, elem, mir, _cat)
                        }
                    })
                    .collect();
                crate::rust_guest::items::emit_const_pack_smallvec_expr(
                    &elem_exprs,
                    elem,
                    sv_sz,
                    sv_al,
                    *cap,
                    mir,
                    _cat,
                )
            } else {
                let elem_ty = match target_ty {
                    Ty::Array { elem, .. } => elem.as_ref(),
                    _ => &Ty::I32,
                };
                let vals: Vec<String> = elems
                    .iter()
                    .map(|e| format_hir_expr_rust(e, elem_ty, mir, _cat))
                    .collect();
                format!("[{}]", vals.join(", "))
            }
        }
        HirExpr::Tuple { elems, .. } => {
            if elems.is_empty() {
                "()".to_owned()
            } else if let Ty::Tuple(item_tys) = target_ty {
                let parts: Vec<String> = elems
                    .iter()
                    .enumerate()
                    .map(|(i, e)| {
                        let ety = item_tys.get(i).unwrap_or(&Ty::Unknown);
                        format_hir_expr_rust(e, ety, mir, _cat)
                    })
                    .collect();
                format!("({})", parts.join(", "))
            } else {
                let parts: Vec<String> = elems
                    .iter()
                    .map(|e| {
                        let ety = infer_const_hir_expr_ty(e, mir);
                        format_hir_expr_rust(e, &ety, mir, _cat)
                    })
                    .collect();
                format!("({})", parts.join(", "))
            }
        }
        HirExpr::Unary {
            op: strata_sema::hir::HirUnOp::Neg,
            expr,
            ..
        } => {
            if let HirExpr::IntLit { value, .. } = &**expr {
                let neg = value.wrapping_neg();
                match target_ty {
                    Ty::Fix32 => return format_fix32_i32_lit(scale_int_fix32(neg)),
                    Ty::Fix64 => return format_fix64_i64_lit(scale_int_fix64(neg)),
                    Ty::I8 => return format!("({neg}i64 as i8)"),
                    Ty::I16 => return format!("({neg}i64 as i16)"),
                    Ty::I32 => return format_fix32_i32_lit(neg as i32),
                    Ty::I64 => return format_fix64_i64_lit(neg),
                    Ty::U8 => return format!("{}u8", neg as u8),
                    Ty::U16 => return format!("{}u16", neg as u16),
                    Ty::U32 | Ty::Sym | Ty::Rgba8 => return format!("{}u32", neg as u32),
                    Ty::U64 => return format!("{}u64", neg as u64),
                    _ => {}
                }
            }
            if let HirExpr::FloatLit { value, .. } = &**expr {
                let neg = -*value;
                match target_ty {
                    Ty::Fix32 => return format_fix32_i32_lit(scale_float_fix32(neg)),
                    Ty::Fix64 => return format_fix64_i64_lit(scale_float_fix64(neg)),
                    _ => {}
                }
            }
            let inferred_inner = infer_const_hir_expr_ty(expr, mir);
            let inner_ty = if matches!(inferred_inner, Ty::F32 | Ty::F64 | Ty::UnitScalar { .. }) {
                &inferred_inner
            } else if matches!(
                target_ty,
                Ty::U8 | Ty::U16 | Ty::U32 | Ty::U64 | Ty::Sym | Ty::Rgba8
            ) {
                &Ty::I64
            } else {
                target_ty
            };
            let inner = format_hir_expr_rust(expr, inner_ty, mir, _cat);
            let inner_is_float =
                matches!(inferred_inner, Ty::F32 | Ty::F64 | Ty::UnitScalar { .. })
                    || matches!(inner_ty, Ty::F32 | Ty::F64 | Ty::UnitScalar { .. });
            let neg_expr = if !inner_is_float
                && matches!(
                    inner_ty,
                    Ty::Fix32 | Ty::Fix64 | Ty::I8 | Ty::I16 | Ty::I32 | Ty::I64
                ) {
                format!("({inner}).wrapping_neg()")
            } else if inner.starts_with('-') {
                format!("-({inner})")
            } else {
                format!("-{inner}")
            };
            match target_ty {
                Ty::U8 => format!("({neg_expr}) as u8"),
                Ty::U16 => format!("({neg_expr}) as u16"),
                Ty::U32 | Ty::Sym | Ty::Rgba8 => format!("({neg_expr}) as u32"),
                Ty::U64 => format!("({neg_expr}) as u64"),
                _ => neg_expr,
            }
        }
        HirExpr::Binary { op, lhs, rhs, ty } => {
            use strata_sema::hir::HirBinOp as B;
            let eff = if !matches!(target_ty, Ty::Unknown) {
                target_ty
            } else if !matches!(ty, Ty::Unknown) {
                ty
            } else {
                &Ty::I64
            };
            let l = format_hir_expr_rust(lhs, eff, mir, _cat);
            let r = format_hir_expr_rust(rhs, eff, mir, _cat);
            match eff {
                Ty::Fix32 => match op {
                    B::Add => format!("({l}).wrapping_add({r})"),
                    B::Sub => format!("({l}).wrapping_sub({r})"),
                    B::Mul => format!("((((({l}) as i64) * (({r}) as i64)) >> 16) as i32)"),
                    B::Div => format!(
                        "(if ({r}) == 0 {{ 0 }} else {{ ((((({l}) as i64) << 16) / (({r}) as i64)) as i32) }})"
                    ),
                    B::Rem => {
                        format!("(if ({r}) == 0 {{ 0 }} else {{ ({l}).wrapping_rem({r}) }})")
                    }
                    _ => format!("(({l}) {} ({r}))", hir_binop_str(*op)),
                },
                Ty::Fix64 => match op {
                    B::Add => format!("({l}).wrapping_add({r})"),
                    B::Sub => format!("({l}).wrapping_sub({r})"),
                    B::Mul => format!("((((({l}) as i128) * (({r}) as i128)) >> 32) as i64)"),
                    B::Div => format!(
                        "(if ({r}) == 0 {{ 0 }} else {{ ((((({l}) as i128) << 32) / (({r}) as i128)) as i64) }})"
                    ),
                    B::Rem => {
                        format!("(if ({r}) == 0 {{ 0 }} else {{ ({l}).wrapping_rem({r}) }})")
                    }
                    _ => format!("(({l}) {} ({r}))", hir_binop_str(*op)),
                },
                Ty::U8
                | Ty::U16
                | Ty::U32
                | Ty::U64
                | Ty::I8
                | Ty::I16
                | Ty::I32
                | Ty::I64
                | Ty::Sym
                | Ty::Rgba8 => match op {
                    B::Add => format!("({l}).wrapping_add({r})"),
                    B::Sub => format!("({l}).wrapping_sub({r})"),
                    B::Mul => format!("({l}).wrapping_mul({r})"),
                    B::Div => {
                        format!("(if ({r}) == 0 {{ 0 }} else {{ ({l}).wrapping_div({r}) }})")
                    }
                    B::Rem => {
                        format!("(if ({r}) == 0 {{ 0 }} else {{ ({l}).wrapping_rem({r}) }})")
                    }
                    _ => format!("(({l}) {} ({r}))", hir_binop_str(*op)),
                },
                _ => format!("(({l}) {} ({r}))", hir_binop_str(*op)),
            }
        }
        HirExpr::Cast {
            expr,
            target_ty: cast_ty,
        } => {
            let expr_ty = expr.ty();
            let inferred_src = if !matches!(expr_ty, Ty::Unknown) {
                expr_ty
            } else {
                infer_const_hir_expr_ty(expr, mir)
            };
            let src_ty = if !matches!(inferred_src, Ty::Unknown) {
                inferred_src
            } else if matches!(
                cast_ty,
                Ty::U8 | Ty::U16 | Ty::U32 | Ty::U64 | Ty::Sym | Ty::Rgba8
            ) {
                Ty::I64
            } else {
                cast_ty.clone()
            };
            let mid_expr = if matches!(cast_ty, Ty::Fix32 | Ty::Fix64) {
                if matches!(
                    expr.as_ref(),
                    HirExpr::IntLit { .. } | HirExpr::FloatLit { .. }
                ) || matches!(
                    expr.as_ref(),
                    HirExpr::Unary {
                        op: strata_sema::hir::HirUnOp::Neg,
                        expr: inner,
                        ..
                    } if matches!(inner.as_ref(), HirExpr::IntLit { .. } | HirExpr::FloatLit { .. })
                ) {
                    format_hir_expr_rust(expr, cast_ty, mir, _cat)
                } else {
                    let inner_s = format_hir_expr_rust(expr, &src_ty, mir, _cat);
                    let is_float = matches!(src_ty, Ty::F32 | Ty::F64 | Ty::UnitScalar { .. });
                    match (&src_ty, cast_ty, is_float) {
                        (Ty::Fix32, Ty::Fix32, _) => format!("(({inner_s}) as i32)"),
                        (Ty::Fix64, Ty::Fix64, _) => format!("(({inner_s}) as i64)"),
                        (Ty::Fix32, Ty::Fix64, _) => format!("((({inner_s}) as i32 as i64) << 16)"),
                        (Ty::Fix64, Ty::Fix32, _) => format!(
                            "(((({inner_s}) as i64) >> 16).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32)"
                        ),
                        (Ty::Bool, Ty::Fix32, _) => {
                            format!("(if ({inner_s}) {{ 65536_i32 }} else {{ 0_i32 }})")
                        }
                        (Ty::Bool, Ty::Fix64, _) => {
                            format!("(if ({inner_s}) {{ 4294967296_i64 }} else {{ 0_i64 }})")
                        }
                        (_, Ty::Fix32, true) => {
                            format!(
                                "{{ let __v = ({inner_s}) as f64; if __v.is_finite() {{ let __x = __v * 65536.0_f64; (if __x >= 0.0_f64 {{ __x + 0.5_f64 }} else {{ __x - 0.5_f64 }}) as i32 }} else {{ 0 }} }}"
                            )
                        }
                        (_, Ty::Fix32, false) => {
                            format!(
                                "((({inner_s}) as i64).saturating_mul(65536).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32)"
                            )
                        }
                        (_, Ty::Fix64 | _, true) => {
                            format!(
                                "{{ let __v = ({inner_s}) as f64; if __v.is_finite() {{ let __x = __v * 4294967296.0_f64; (if __x >= 0.0_f64 {{ __x + 0.5_f64 }} else {{ __x - 0.5_f64 }}) as i64 }} else {{ 0 }} }}"
                            )
                        }
                        (_, _, false) => format!("((({inner_s}) as i64).wrapping_shl(32))"),
                    }
                }
            } else {
                let inner_s = format_hir_expr_rust(expr, &src_ty, mir, _cat);
                match (&src_ty, cast_ty) {
                    (Ty::Fix32, Ty::F32 | Ty::F64 | Ty::UnitScalar { .. }) => {
                        let rs = rust_scalar_str_for_hir_ty(cast_ty).unwrap_or("f32");
                        format!("((({inner_s}) as f64 / 65536.0) as {rs})")
                    }
                    (Ty::Fix64, Ty::F32 | Ty::F64 | Ty::UnitScalar { .. }) => {
                        let rs = rust_scalar_str_for_hir_ty(cast_ty).unwrap_or("f64");
                        format!("((({inner_s}) as f64 / 4294967296.0) as {rs})")
                    }
                    (
                        Ty::Fix32,
                        Ty::I8
                        | Ty::I16
                        | Ty::I32
                        | Ty::I64
                        | Ty::U8
                        | Ty::U16
                        | Ty::U32
                        | Ty::U64
                        | Ty::Sym
                        | Ty::Rgba8,
                    ) => {
                        let rs = rust_scalar_str_for_hir_ty(cast_ty).unwrap_or("i32");
                        format!("((({inner_s}) / 65536i32) as {rs})")
                    }
                    (
                        Ty::Fix64,
                        Ty::I8
                        | Ty::I16
                        | Ty::I32
                        | Ty::I64
                        | Ty::U8
                        | Ty::U16
                        | Ty::U32
                        | Ty::U64
                        | Ty::Sym
                        | Ty::Rgba8,
                    ) => {
                        let rs = rust_scalar_str_for_hir_ty(cast_ty).unwrap_or("i64");
                        format!("((({inner_s}) / 4294967296i64) as {rs})")
                    }
                    (Ty::Fix32 | Ty::Fix64, Ty::Bool) => format!("(({inner_s}) != 0)"),
                    _ => match rust_scalar_str_for_hir_ty(cast_ty) {
                        Some(rs) => format!("(({inner_s}) as {rs})"),
                        None => inner_s,
                    },
                }
            };
            if cast_ty == target_ty || matches!(target_ty, Ty::Unknown) {
                return mid_expr;
            }
            match target_ty {
                Ty::Fix32 => match cast_ty {
                    Ty::Fix32 => mid_expr,
                    Ty::Fix64 => format!("((({mid_expr}) >> 16) as i32)"),
                    Ty::F32 | Ty::F64 | Ty::UnitScalar { .. } => {
                        format!(
                            "{{ let __v = ({mid_expr}) as f64; if __v.is_finite() {{ let __x = __v * 65536.0_f64; (if __x >= 0.0_f64 {{ __x + 0.5_f64 }} else {{ __x - 0.5_f64 }}) as i32 }} else {{ 0 }} }}"
                        )
                    }
                    _ => format!("((({mid_expr}) as i64).saturating_mul(65536) as i32)"),
                },
                Ty::Fix64 => match cast_ty {
                    Ty::Fix64 => mid_expr,
                    Ty::Fix32 => format!("((({mid_expr}) as i64).wrapping_shl(16))"),
                    Ty::F32 | Ty::F64 | Ty::UnitScalar { .. } => {
                        format!(
                            "{{ let __v = ({mid_expr}) as f64; if __v.is_finite() {{ let __x = __v * 4294967296.0_f64; (if __x >= 0.0_f64 {{ __x + 0.5_f64 }} else {{ __x - 0.5_f64 }}) as i64 }} else {{ 0 }} }}"
                        )
                    }
                    _ => format!("((({mid_expr}) as i64).wrapping_shl(32))"),
                },
                _ => {
                    let Some(dst_rs) = rust_scalar_str_for_hir_ty(target_ty) else {
                        return mid_expr;
                    };
                    let dst_is_float =
                        matches!(target_ty, Ty::F32 | Ty::F64 | Ty::UnitScalar { .. });
                    match (cast_ty, dst_is_float) {
                        (Ty::Fix32, true) => {
                            format!("((({mid_expr}) as f64 / 65536.0) as {dst_rs})")
                        }
                        (Ty::Fix32, false) => format!("((({mid_expr}) / 65536i32) as {dst_rs})"),
                        (Ty::Fix64, true) => {
                            format!("((({mid_expr}) as f64 / 4294967296.0) as {dst_rs})")
                        }
                        (Ty::Fix64, false) => {
                            format!("((({mid_expr}) / 4294967296i64) as {dst_rs})")
                        }
                        _ => format!("(({mid_expr}) as {dst_rs})"),
                    }
                }
            }
        }
        _ => table_field_default(target_ty, mir),
    }
}

fn rust_vec_path_const(name: &str) -> Option<&'static str> {
    match name {
        "vec2::ZERO" => Some("[0.0f32, 0.0f32]"),
        "vec2::ONE" => Some("[1.0f32, 1.0f32]"),
        "vec2::X" => Some("[1.0f32, 0.0f32]"),
        "vec2::Y" => Some("[0.0f32, 1.0f32]"),
        "vec3::ZERO" => Some("[0.0f32, 0.0f32, 0.0f32]"),
        "vec3::ONE" => Some("[1.0f32, 1.0f32, 1.0f32]"),
        "vec3::X" => Some("[1.0f32, 0.0f32, 0.0f32]"),
        "vec3::Y" | "vec3::UP" => Some("[0.0f32, 1.0f32, 0.0f32]"),
        "vec3::Z" => Some("[0.0f32, 0.0f32, 1.0f32]"),
        "vec4::ZERO" => Some("[0.0f32, 0.0f32, 0.0f32, 0.0f32]"),
        "vec4::ONE" => Some("[1.0f32, 1.0f32, 1.0f32, 1.0f32]"),
        "vec4::X" => Some("[1.0f32, 0.0f32, 0.0f32, 0.0f32]"),
        "vec4::Y" => Some("[0.0f32, 1.0f32, 0.0f32, 0.0f32]"),
        "vec4::Z" => Some("[0.0f32, 0.0f32, 1.0f32, 0.0f32]"),
        "vec4::W" => Some("[0.0f32, 0.0f32, 0.0f32, 1.0f32]"),
        "ivec2::ZERO" => Some("[0i32, 0i32]"),
        "ivec2::ONE" => Some("[1i32, 1i32]"),
        "ivec2::X" => Some("[1i32, 0i32]"),
        "ivec2::Y" => Some("[0i32, 1i32]"),
        "ivec3::ZERO" => Some("[0i32, 0i32, 0i32]"),
        "ivec3::ONE" => Some("[1i32, 1i32, 1i32]"),
        "ivec3::X" => Some("[1i32, 0i32, 0i32]"),
        "ivec3::Y" => Some("[0i32, 1i32, 0i32]"),
        "ivec3::Z" => Some("[0i32, 0i32, 1i32]"),
        "uvec2::ZERO" => Some("[0u32, 0u32]"),
        "uvec2::ONE" => Some("[1u32, 1u32]"),
        "uvec2::X" => Some("[1u32, 0u32]"),
        "uvec2::Y" => Some("[0u32, 1u32]"),
        _ => None,
    }
}

fn infer_const_hir_expr_ty(expr: &HirExpr, mir: &MirModule) -> Ty {
    let cur_ty = expr.ty();
    if !matches!(cur_ty, Ty::Unknown) {
        return cur_ty;
    }
    match expr {
        HirExpr::BoolLit(_) => Ty::Bool,
        HirExpr::IntLit { .. } => Ty::I64,
        HirExpr::FloatLit { .. } => Ty::F32,
        HirExpr::Unary { expr: inner, .. } => infer_const_hir_expr_ty(inner, mir),
        HirExpr::Cast { target_ty, .. } => target_ty.clone(),
        HirExpr::Binary { lhs, rhs, .. } => {
            let lt = infer_const_hir_expr_ty(lhs, mir);
            let rt = infer_const_hir_expr_ty(rhs, mir);
            if matches!(lt, Ty::F64) || matches!(rt, Ty::F64) {
                Ty::F64
            } else if matches!(lt, Ty::F32 | Ty::UnitScalar { .. })
                || matches!(rt, Ty::F32 | Ty::UnitScalar { .. })
            {
                Ty::F32
            } else if matches!(lt, Ty::Fix64) || matches!(rt, Ty::Fix64) {
                Ty::Fix64
            } else if matches!(lt, Ty::Fix32) || matches!(rt, Ty::Fix32) {
                Ty::Fix32
            } else if lt != Ty::Unknown {
                lt
            } else {
                rt
            }
        }
        HirExpr::Path { name, .. } => {
            if let Some(c) = mir.consts.iter().find(|c| {
                let seg = name.rsplit("::").next().unwrap_or(name.as_str());
                c.name == *name || c.name.rsplit("::").next() == Some(seg)
            }) {
                return c.ty.clone();
            }
            Ty::Unknown
        }
        HirExpr::Call(c) => match c.callee.rsplit("::").next().unwrap_or(c.callee.as_str()) {
            "vec2" | "Vec2" => Ty::Vec2,
            "vec3" | "Vec3" => Ty::Vec3,
            "vec3a" | "Vec3a" => Ty::Vec3a,
            "vec4" | "Vec4" => Ty::Vec4,
            "ivec2" | "IVec2" => Ty::IVec2,
            "ivec3" | "IVec3" => Ty::IVec3,
            "uvec2" | "UVec2" => Ty::UVec2,
            "quat" | "Quat" => Ty::Quat,
            "rgba" | "Rgba" => Ty::Rgba,
            "mat3" | "Mat3" => Ty::Mat3,
            "mat4" | "Mat4" => Ty::Mat4,
            "bits" => Ty::BitSet(32),
            "meters" | "sec" | "ms" | "rad" | "deg" | "mps" | "mps2" | "hz" | "frames" => Ty::F32,
            _ => Ty::Unknown,
        },
        _ => Ty::Unknown,
    }
}

fn rust_scalar_str_for_hir_ty(ty: &Ty) -> Option<&'static str> {
    match ty {
        Ty::U8 => Some("u8"),
        Ty::I8 => Some("i8"),
        Ty::U16 => Some("u16"),
        Ty::I16 => Some("i16"),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => Some("u32"),
        Ty::I32 | Ty::Fix32 => Some("i32"),
        Ty::U64 => Some("u64"),
        Ty::I64 | Ty::Fix64 => Some("i64"),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => Some("f32"),
        Ty::F64 => Some("f64"),
        _ => None,
    }
}

pub(super) fn hir_expr_to_strata_val(
    expr: &HirExpr,
    ty: &Ty,
    mir: &MirModule,
    cat: &GuestCatalog,
) -> String {
    if let HirExpr::Path { name, .. } = expr
        && lookup_enum_path_disc(name, mir).is_none()
        && let Some(c) = mir.consts.iter().find(|c| {
            let seg = name.rsplit("::").next().unwrap_or(name.as_str());
            c.name == *name || c.name.rsplit("::").next() == Some(seg)
        })
        && let Some(ref inner) = c.expr
    {
        return hir_expr_to_strata_val(inner, ty, mir, cat);
    }
    match ty {
        Ty::BitSet(_) => {
            let r = format_hir_expr_rust(expr, ty, mir, cat);
            return format!("StrataVal::Words({r}.to_vec())");
        }
        Ty::SmallVec { elem, .. } => {
            if let HirExpr::ArrayLit { elems, .. } = expr {
                let parts: Vec<String> = elems
                    .iter()
                    .map(|e| hir_expr_to_strata_val(e, elem, mir, cat))
                    .collect();
                return format!("StrataVal::Arr(vec![{}])", parts.join(", "));
            }
            let r = format_hir_expr_rust(expr, ty, mir, cat);
            return format!(
                "{{ let _tmp = {r}; let mut _raw = Vec::new(); for _w in &_tmp {{ strata_push_le_into(&mut _raw, *_w); }} StrataVal::Bytes(_raw) }}"
            );
        }
        Ty::Mat3 | Ty::Mat4 => {
            let r = format_hir_expr_rust(expr, ty, mir, cat);
            return format!("StrataVal::Arr(({r}).iter().map(|_x| StrataVal::F32(*_x)).collect())");
        }
        Ty::Tuple(item_tys) => {
            if let HirExpr::Tuple { elems, .. } = expr {
                let parts: Vec<String> = elems
                    .iter()
                    .enumerate()
                    .map(|(i, e)| {
                        let ety = item_tys.get(i).unwrap_or(&Ty::Unknown);
                        hir_expr_to_strata_val(e, ety, mir, cat)
                    })
                    .collect();
                return format!("StrataVal::Tuple(vec![{}])", parts.join(", "));
            }
            return "StrataVal::Unit".to_owned();
        }
        Ty::InlineStr(_) => {
            let r = format_hir_expr_rust(expr, ty, mir, cat);
            return format!("StrataVal::Words(({r}).to_vec())");
        }
        Ty::Array { elem, .. } => {
            if let HirExpr::ArrayLit { elems, .. } = expr {
                let parts: Vec<String> = elems
                    .iter()
                    .map(|e| hir_expr_to_strata_val(e, elem, mir, cat))
                    .collect();
                return format!("StrataVal::Arr(vec![{}])", parts.join(", "));
            }
            return "StrataVal::Unit".to_owned();
        }
        Ty::Named(n) => {
            if let Some((_, is_signed)) = find_enum_repr(n, mir) {
                let r = format_hir_expr_rust(expr, ty, mir, cat);
                return if is_signed {
                    format!("StrataVal::I32(({r}) as i32)")
                } else {
                    format!("StrataVal::U32(({r}) as u32)")
                };
            }
            if let HirExpr::StructLit { name, fields, .. } = expr
                && let Some(nested) = cat.resolve_comp(name).or_else(|| cat.resolve_comp(n))
            {
                let vname = &nested.variant_name;
                let sname = &nested.struct_name;
                let mut stmts = vec![format!(
                    "let mut _o = StrataObj::{vname}({sname}::default());"
                )];
                for (fname, fexpr) in fields {
                    if let Some(sf) = nested
                        .layout
                        .fields
                        .iter()
                        .find(|f| !f.is_padding && f.name == *fname)
                    {
                        let esc_f = escape_rust_str(fname);
                        let fv = hir_expr_to_strata_val(fexpr, &sf.ty, mir, cat);
                        stmts.push(format!("_o.set_field(0, \"{esc_f}\", {fv});"));
                    }
                }
                stmts.push("StrataVal::Obj(_o)".to_owned());
                return format!("{{ {} }}", stmts.join(" "));
            }
            return "StrataVal::Unit".to_owned();
        }
        _ => {}
    }
    let r = format_hir_expr_rust(expr, ty, mir, cat);
    match ty {
        Ty::Bool => format!("StrataVal::Bool({r})"),
        Ty::U8 | Ty::U16 | Ty::U32 | Ty::Sym | Ty::Rgba8 => format!("StrataVal::U32(({r}) as u32)"),
        Ty::I8 | Ty::I16 | Ty::I32 => format!("StrataVal::I32(({r}) as i32)"),
        Ty::Fix32 => format!("StrataVal::Fix32(({r}) as i32)"),
        Ty::U64 => format!("StrataVal::U64(({r}) as u64)"),
        Ty::I64 => format!("StrataVal::I64(({r}) as i64)"),
        Ty::Fix64 => format!("StrataVal::Fix64(({r}) as i64)"),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => {
            format!("StrataVal::F32(({r}) as f32)")
        }
        Ty::F64 => format!("StrataVal::F64(({r}) as f64)"),
        Ty::Vec2 => format!("StrataVal::Vec2({r})"),
        Ty::Vec3 => format!("StrataVal::Vec3({r})"),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => format!("StrataVal::Vec4({r})"),
        Ty::IVec2 => format!("StrataVal::IVec2({r})"),
        Ty::IVec3 => format!("StrataVal::IVec3({r})"),
        Ty::UVec2 => format!("StrataVal::UVec2({r})"),
        _ => "StrataVal::Unit".to_owned(),
    }
}

pub(super) fn lookup_enum_variant_disc(
    enum_name: &str,
    variant: &str,
    mir: &MirModule,
) -> Option<i64> {
    let short = enum_name.rsplit("::").next().unwrap_or(enum_name);
    let en = mir.enums.iter().find(|e| {
        e.canonical_name == enum_name || e.canonical_name.rsplit("::").next() == Some(short)
    })?;
    en.variants
        .iter()
        .find(|(vn, _)| vn == variant)
        .map(|(_, d)| *d)
}

pub(super) fn lookup_enum_path_disc(path: &str, mir: &MirModule) -> Option<i64> {
    let (en, var) = path.rsplit_once("::")?;
    lookup_enum_variant_disc(en, var, mir)
}

pub(super) fn find_enum_repr_by_path(path: &str, mir: &MirModule) -> (usize, bool) {
    if let Some((en, _)) = path.rsplit_once("::") {
        find_enum_repr(en, mir).unwrap_or((4, false))
    } else {
        (4, false)
    }
}

pub(super) fn default_strata_val_for_mir_ty(ty: &MirType) -> &'static str {
    match ty {
        MirType::Bool => "StrataVal::Bool(false)",
        MirType::U8 | MirType::U16 | MirType::U32 | MirType::Sym => "StrataVal::U32(0)",
        MirType::U64 => "StrataVal::U64(0)",
        MirType::I8 | MirType::I16 | MirType::I32 => "StrataVal::I32(0)",
        MirType::Fix32 => "StrataVal::Fix32(0)",
        MirType::I64 => "StrataVal::I64(0)",
        MirType::Fix64 => "StrataVal::Fix64(0)",
        MirType::F32 => "StrataVal::F32(0.0)",
        MirType::F64 => "StrataVal::F64(0.0)",
        MirType::Vec2 => "StrataVal::Vec2([0.0; 2])",
        MirType::Vec3 => "StrataVal::Vec3([0.0; 3])",
        MirType::Vec4 => "StrataVal::Vec4([0.0; 4])",
        MirType::IVec2 => "StrataVal::IVec2([0; 2])",
        MirType::IVec3 => "StrataVal::IVec3([0; 3])",
        MirType::UVec2 => "StrataVal::UVec2([0; 2])",
        MirType::Entity => "StrataVal::Entity(FfiEntity::NULL)",
        MirType::Checkpoint => "StrataVal::Checkpoint(0)",
        _ => "StrataVal::Unit",
    }
}

pub(super) fn fmt_f32(v: f32) -> String {
    if v.is_nan() {
        "f32::NAN".to_owned()
    } else if v.is_infinite() {
        if v.is_sign_positive() {
            "f32::INFINITY".to_owned()
        } else {
            "f32::NEG_INFINITY".to_owned()
        }
    } else {
        let s = format!("{v:?}");
        if s.contains('.') || s.contains('e') || s.contains('E') {
            format!("{s}f32")
        } else {
            format!("{s}.0f32")
        }
    }
}

pub(super) fn fmt_f64(v: f64) -> String {
    if v.is_nan() {
        "f64::NAN".to_owned()
    } else if v.is_infinite() {
        if v.is_sign_positive() {
            "f64::INFINITY".to_owned()
        } else {
            "f64::NEG_INFINITY".to_owned()
        }
    } else {
        let s = format!("{v:?}");
        if s.contains('.') || s.contains('e') || s.contains('E') {
            format!("{s}f64")
        } else {
            format!("{s}.0f64")
        }
    }
}

pub(super) fn escape_rust_str(s: &str) -> String {
    s.replace('\0', "")
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

pub(super) fn format_u8_array_16(bytes: &[u8; 16]) -> String {
    let parts: Vec<String> = bytes.iter().map(|b| format!("0x{b:02X}")).collect();
    format!("[{}]", parts.join(", "))
}

// ============================================================================
// Typed Hoisted-Slice Fast Path (`TypedChunkIter` & `SelectiveWrite` `Chunk`)
// ============================================================================
