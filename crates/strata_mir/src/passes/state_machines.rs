//! Synthesizes complete executable SSA CFG tick functions for `timeline`, stackless
//! `@sparse task` coroutines, and hierarchical `fsm` declarations.

use crate::ir::{
    Inst, LocalId, MirFnKind, MirFunction, MirModule, MirQueryBinding, MirQueryTermBinding,
    MirType, Terminator,
};
use crate::lower::{CfgBuilder, MirLowerCtx, TermAccessBinding, VarSlot, mir_ty_from_hir};
use std::collections::HashMap;
use strata_sema::access::{QueryAccessDesc, QueryTerm, TermAccessMode};
use strata_sema::hir::HirStmt;
use strata_sema::layout::SchemaItemKind;

/// Lowers every `timeline`, `task`, and `fsm` in `module` into concrete `MirFunction` tick
/// systems ready for backend code generation.
pub fn run(module: &mut MirModule) {
    let ctx = MirLowerCtx::from_module(module);
    let clock_info = ctx.all_layouts.iter().find_map(|l| {
        if l.item_kind != SchemaItemKind::Resource {
            return None;
        }
        l.fields
            .iter()
            .find(|f| f.name == "dt")
            .map(|f| (l.clone(), f.offset as u32))
    });

    // 1. `timeline` -> 16B sparse cursor tick loop computing `active_mask` + lowered edge triggers.
    let timelines = module.timelines.clone();
    for tl in &timelines {
        let mut func = MirFunction::new(&tl.name, MirFnKind::SynthesizedTimeline);
        func.par_chunk = Some(256);
        func.is_deterministic = module.is_deterministic;

        let window_masks: Vec<(String, u32, u32, u32)> = tl
            .windows
            .iter()
            .map(|(wname, s, e, bit)| (wname.clone(), *s, *e, 1u32 << (*bit as u32)))
            .collect();

        let mut b = CfgBuilder::new(func, &ctx);
        b.func.queries.push(QueryAccessDesc {
            terms: vec![QueryTerm {
                storage_key: tl.name.clone(),
                field_name: None,
                mode: TermAccessMode::Write,
                byte_start: 0,
                byte_end: 0,
            }],
            ..Default::default()
        });
        b.func.query_bindings.push(MirQueryBinding {
            query_idx: 0,
            terms: vec![MirQueryTermBinding {
                term_idx: 0,
                alias: "tl".to_owned(),
                storage_key: tl.name.clone(),
                canonical_component: tl.canonical_name.clone(),
                field_name: None,
                mode: TermAccessMode::Write,
                is_sparse: true,
            }],
            with_filters: Vec::new(),
            without_filters: Vec::new(),
            is_point_lookup: false,
        });

        let dt_sec = if let Some((ref clk_layout, dt_off)) = clock_info {
            let cshort = clk_layout
                .canonical_name
                .rsplit("::")
                .next()
                .unwrap_or("SimClock")
                .to_owned();
            let cptr = b.alloc_and_emit("clk", MirType::Ptr, Inst::ResRead { resource: cshort });
            b.alloc_and_emit(
                "dt",
                MirType::F32,
                Inst::FieldLoad {
                    base_ptr: cptr,
                    layout_key: clk_layout.canonical_name.clone(),
                    field: "dt".to_owned(),
                    offset_bytes: dt_off,
                    field_ty: MirType::F32,
                },
            )
        } else {
            let hz = tl.rate_hz.max(1) as f64;
            b.alloc_and_emit("dt", MirType::F32, Inst::ConstFloat { value: 1.0 / hz })
        };

        let chunk_hdr = b.new_block("tl_chunk_hdr");
        let chunk_body = b.new_block("tl_chunk_body");
        let row_hdr = b.new_block("tl_row_hdr");
        let row_body = b.new_block("tl_row_body");
        let exit_bb = b.new_block("tl_exit");

        b.terminate(Terminator::Goto(chunk_hdr));
        b.switch_to(chunk_hdr);
        let has_chunk = b.alloc_and_emit(
            "has_chunk",
            MirType::Bool,
            Inst::IterNextChunk { query_idx: 0 },
        );
        b.terminate(Terminator::Branch {
            cond: has_chunk,
            then_bb: chunk_body,
            else_bb: exit_bb,
        });

        b.switch_to(chunk_body);
        let chunk_len = b.alloc_and_emit(
            "chunk_len",
            MirType::U32,
            Inst::IterChunkLen { query_idx: 0 },
        );
        let entities_ptr = b.alloc_and_emit(
            "entities",
            MirType::Ptr,
            Inst::IterEntities { query_idx: 0 },
        );
        let rows_ptr = b.alloc_and_emit(
            "tl_rows",
            MirType::MutPtr,
            Inst::IterColRowsWrite {
                query_idx: 0,
                term_idx: 0,
                storage_key: tl.name.clone(),
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
        let rcond = b.alloc_and_emit(
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
            cond: rcond,
            then_bb: row_body,
            else_bb: chunk_hdr,
        });

        b.switch_to(row_body);
        let row_ent = b.alloc_and_emit(
            "row_ent",
            MirType::Entity,
            Inst::EntityAtRow {
                entities_ptr,
                row_idx: ridx,
            },
        );
        b.vars.insert(
            "self".to_owned(),
            VarSlot::Imm {
                local: row_ent,
                ty: MirType::Entity,
            },
        );
        let rptr = b.alloc_and_emit(
            "cursor_ptr",
            MirType::MutPtr,
            Inst::RowPtr {
                col_ptr: rows_ptr,
                row_idx: ridx,
                stride_bytes: tl.cursor_layout.size as u32,
                is_sparse: true,
            },
        );
        let prev_frame = b.alloc_and_emit(
            "prev_frame",
            MirType::U16,
            Inst::FieldLoad {
                base_ptr: rptr,
                layout_key: tl.canonical_name.clone(),
                field: "cur_frame".to_owned(),
                offset_bytes: 0,
                field_ty: MirType::U16,
            },
        );
        let accum = b.alloc_and_emit(
            "accum_sec",
            MirType::F32,
            Inst::FieldLoad {
                base_ptr: rptr,
                layout_key: tl.canonical_name.clone(),
                field: "accum_sec".to_owned(),
                offset_bytes: 8,
                field_ty: MirType::F32,
            },
        );
        let new_accum = b.alloc_and_emit(
            "new_accum",
            MirType::F32,
            Inst::BinOp {
                op: "+".to_owned(),
                lhs: accum,
                rhs: dt_sec,
                allow_fma: false,
            },
        );
        b.emit_void(Inst::FieldStore {
            base_ptr: rptr,
            layout_key: tl.canonical_name.clone(),
            field: "accum_sec".to_owned(),
            offset_bytes: 8,
            val: new_accum,
        });
        b.emit_void(Inst::TimelineAdvance {
            timeline: tl.name.clone(),
            cursor_ptr: rptr,
            dt_sec,
            rate_hz: tl.rate_hz,
            duration_frames: tl.duration_frames,
            window_masks,
        });
        let cur_frame = b.alloc_and_emit(
            "cur_frame",
            MirType::U16,
            Inst::FieldLoad {
                base_ptr: rptr,
                layout_key: tl.canonical_name.clone(),
                field: "cur_frame".to_owned(),
                offset_bytes: 0,
                field_ty: MirType::U16,
            },
        );

        // Edge-triggered `at <frame> => <stmt>` blocks
        for (idx, (trig_frame, stmts)) in tl.typed_triggers.iter().enumerate() {
            let tf_c = b.alloc_and_emit(
                "trig_f",
                MirType::U16,
                Inst::ConstInt {
                    value: i64::from(*trig_frame),
                },
            );
            let hit_eq = b.alloc_and_emit(
                "trig_eq",
                MirType::Bool,
                Inst::BinOp {
                    op: "==".to_owned(),
                    lhs: cur_frame,
                    rhs: tf_c,
                    allow_fma: false,
                },
            );
            let prev_ne = b.alloc_and_emit(
                "prev_ne",
                MirType::Bool,
                Inst::BinOp {
                    op: "!=".to_owned(),
                    lhs: prev_frame,
                    rhs: tf_c,
                    allow_fma: false,
                },
            );
            let fire_cond = b.alloc_and_emit(
                "fire_cond",
                MirType::Bool,
                Inst::BinOp {
                    op: "&&".to_owned(),
                    lhs: hit_eq,
                    rhs: prev_ne,
                    allow_fma: false,
                },
            );
            let trig_bb = b.new_block(&format!("tl_at_{trig_frame}_{idx}"));
            let cont_bb = b.new_block(&format!("tl_after_{trig_frame}_{idx}"));
            b.terminate(Terminator::Branch {
                cond: fire_cond,
                then_bb: trig_bb,
                else_bb: cont_bb,
            });
            b.switch_to(trig_bb);
            b.lower_stmts(stmts);
            if !b.cur_terminated {
                b.terminate(Terminator::Goto(cont_bb));
            }
            b.switch_to(cont_bb);
        }

        // Remove cursor when timeline reaches duration
        let dur_c = b.alloc_and_emit(
            "dur_f",
            MirType::U16,
            Inst::ConstInt {
                value: i64::from(tl.duration_frames),
            },
        );
        let done_cond = b.alloc_and_emit(
            "tl_finished",
            MirType::Bool,
            Inst::BinOp {
                op: ">=".to_owned(),
                lhs: cur_frame,
                rhs: dur_c,
                allow_fma: false,
            },
        );
        let rem_bb = b.new_block("tl_remove");
        let row_inc = b.new_block("tl_row_inc");
        b.terminate(Terminator::Branch {
            cond: done_cond,
            then_bb: rem_bb,
            else_bb: row_inc,
        });
        b.switch_to(rem_bb);
        b.emit_void(Inst::CmdRemove {
            entity: row_ent,
            component: tl.name.clone(),
        });
        b.terminate(Terminator::Goto(row_inc));

        b.switch_to(row_inc);
        let one = b.alloc_and_emit("r1", MirType::U32, Inst::ConstInt { value: 1 });
        let r_prev = b.alloc_and_emit("rp", MirType::U32, Inst::SlotLoad { slot: rslot });
        let r_nxt = b.alloc_and_emit(
            "rn",
            MirType::U32,
            Inst::BinOp {
                op: "+".to_owned(),
                lhs: r_prev,
                rhs: one,
                allow_fma: false,
            },
        );
        b.emit_void(Inst::SlotStore {
            slot: rslot,
            val: r_nxt,
        });
        b.terminate(Terminator::Goto(row_hdr));

        b.switch_to(exit_bb);
        b.terminate(Terminator::Return(None));
        module.functions.push(b.finish());
    }

    // 2. Stackless `task` -> `__pc` switch state machine + lowered `abort_if` / `wait` / `race`.
    let tasks = module.tasks.clone();
    for task in &tasks {
        let state_is_sparse = task.is_sparse
            || (task.state_layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET) != 0;
        let mut func = MirFunction::new(&task.name, MirFnKind::SynthesizedTask);
        func.is_deterministic = module.is_deterministic;
        func.source_body = task.body_source.clone();

        let mut b = CfgBuilder::new(func, &ctx);
        b.bind_params(&task.typed_using_params, true);

        let dt_sec = if let Some((ref clk_layout, dt_off)) = clock_info {
            let cshort = clk_layout
                .canonical_name
                .rsplit("::")
                .next()
                .unwrap_or("SimClock")
                .to_owned();
            let cptr = b.alloc_and_emit("clk_t", MirType::Ptr, Inst::ResRead { resource: cshort });
            b.alloc_and_emit(
                "dt_t",
                MirType::F32,
                Inst::FieldLoad {
                    base_ptr: cptr,
                    layout_key: clk_layout.canonical_name.clone(),
                    field: "dt".to_owned(),
                    offset_bytes: dt_off,
                    field_ty: MirType::F32,
                },
            )
        } else {
            b.alloc_and_emit("dt_t", MirType::F32, Inst::ConstFloat { value: 1.0 / 60.0 })
        };

        // Build query 0 combining `on (...)` terms + task state component
        let mut q_terms = Vec::new();
        let mut qb_terms = Vec::new();
        for (i, ot) in task.typed_on_terms.iter().enumerate() {
            q_terms.push(QueryTerm {
                storage_key: ot.storage_key.clone(),
                field_name: ot.field_name.clone(),
                mode: ot.mode,
                byte_start: 0,
                byte_end: 0,
            });
            qb_terms.push(MirQueryTermBinding {
                term_idx: i as u32,
                alias: ot.alias.clone(),
                storage_key: ot.storage_key.clone(),
                canonical_component: ot.canonical_component.clone(),
                field_name: ot.field_name.clone(),
                mode: ot.mode,
                is_sparse: ot.is_sparse,
            });
        }
        let state_term_idx = q_terms.len() as u32;
        q_terms.push(QueryTerm {
            storage_key: task.name.clone(),
            field_name: None,
            mode: TermAccessMode::Write,
            byte_start: 0,
            byte_end: 0,
        });
        qb_terms.push(MirQueryTermBinding {
            term_idx: state_term_idx,
            alias: "__task_state".to_owned(),
            storage_key: task.name.clone(),
            canonical_component: task.state_layout.canonical_name.clone(),
            field_name: None,
            mode: TermAccessMode::Write,
            is_sparse: state_is_sparse,
        });
        b.func.queries.push(QueryAccessDesc {
            terms: q_terms,
            is_task_on_header: true,
            ..Default::default()
        });
        b.func.query_bindings.push(MirQueryBinding {
            query_idx: 0,
            terms: qb_terms,
            with_filters: Vec::new(),
            without_filters: Vec::new(),
            is_point_lookup: false,
        });

        // Segment task body into abort_ifs + suspension-delimited phases
        let (abort_stmts, phases) = segment_task_phases(&task.body);
        let num_states = phases.len().max(1) as u32;

        let chunk_hdr = b.new_block("task_chunk_hdr");
        let chunk_body = b.new_block("task_chunk_body");
        let row_hdr = b.new_block("task_row_hdr");
        let row_body = b.new_block("task_row_body");
        let abort_bb = b.new_block("abort_cleanup");
        let row_inc = b.new_block("task_row_inc");
        let exit_bb = b.new_block("task_exit");

        b.terminate(Terminator::Goto(chunk_hdr));
        b.switch_to(chunk_hdr);
        let has_chunk = b.alloc_and_emit(
            "has_chunk",
            MirType::Bool,
            Inst::IterNextChunk { query_idx: 0 },
        );
        b.terminate(Terminator::Branch {
            cond: has_chunk,
            then_bb: chunk_body,
            else_bb: exit_bb,
        });

        b.switch_to(chunk_body);
        let chunk_len = b.alloc_and_emit(
            "chunk_len",
            MirType::U32,
            Inst::IterChunkLen { query_idx: 0 },
        );
        let entities_ptr = b.alloc_and_emit(
            "entities",
            MirType::Ptr,
            Inst::IterEntities { query_idx: 0 },
        );
        let mut on_cols = Vec::new();
        for (i, ot) in task.typed_on_terms.iter().enumerate() {
            let ti = i as u32;
            let cptr = b.alloc_and_emit(
                &format!("col_{}", ot.alias),
                if ot.mode.is_mutable() {
                    MirType::MutPtr
                } else {
                    MirType::Ptr
                },
                if ot.is_sparse {
                    if ot.mode.is_mutable() {
                        Inst::IterColRowsWrite {
                            query_idx: 0,
                            term_idx: ti,
                            storage_key: ot.storage_key.clone(),
                        }
                    } else {
                        Inst::IterColRowsRead {
                            query_idx: 0,
                            term_idx: ti,
                            storage_key: ot.storage_key.clone(),
                        }
                    }
                } else if ot.mode.is_mutable() {
                    Inst::IterColWrite {
                        query_idx: 0,
                        term_idx: ti,
                        storage_key: ot.storage_key.clone(),
                    }
                } else {
                    Inst::IterColRead {
                        query_idx: 0,
                        term_idx: ti,
                        storage_key: ot.storage_key.clone(),
                    }
                },
            );
            on_cols.push((ti, ot.clone(), cptr));
        }
        let rows_local = b.alloc_and_emit(
            if state_is_sparse {
                "task_rows"
            } else {
                "task_col"
            },
            MirType::MutPtr,
            if state_is_sparse {
                Inst::IterColRowsWrite {
                    query_idx: 0,
                    term_idx: state_term_idx,
                    storage_key: task.name.clone(),
                }
            } else {
                Inst::IterColWrite {
                    query_idx: 0,
                    term_idx: state_term_idx,
                    storage_key: task.name.clone(),
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
        let rcond = b.alloc_and_emit(
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
            cond: rcond,
            then_bb: row_body,
            else_bb: chunk_hdr,
        });

        b.switch_to(row_body);
        let row_ent = b.alloc_and_emit(
            "row_ent",
            MirType::Entity,
            Inst::EntityAtRow {
                entities_ptr,
                row_idx: ridx,
            },
        );
        b.vars.insert(
            "self".to_owned(),
            VarSlot::Imm {
                local: row_ent,
                ty: MirType::Entity,
            },
        );
        for (_ti, ot, cptr) in &on_cols {
            let stride = ctx
                .find_layout(&ot.canonical_component)
                .map_or(16, |l| l.size as u32);
            let rptr = b.alloc_and_emit(
                &format!("on_{}", ot.alias),
                if ot.mode.is_mutable() {
                    MirType::MutPtr
                } else {
                    MirType::Ptr
                },
                Inst::RowPtr {
                    col_ptr: *cptr,
                    row_idx: ridx,
                    stride_bytes: stride,
                    is_sparse: ot.is_sparse,
                },
            );
            b.vars.insert(
                ot.alias.clone(),
                VarSlot::SingleTermPtr {
                    binding: TermAccessBinding {
                        canonical_layout: ctx.resolve_canonical(&ot.canonical_component),
                        field_name: ot.field_name.clone(),
                        mode: ot.mode,
                        col_ptr: *cptr,
                        row_ptr: Some(rptr),
                        present_local: None,
                        is_up_cascade: false,
                    },
                },
            );
        }

        let state_ptr = b.alloc_and_emit(
            "task_state_ptr",
            MirType::MutPtr,
            Inst::RowPtr {
                col_ptr: rows_local,
                row_idx: ridx,
                stride_bytes: task.state_layout.size as u32,
                is_sparse: state_is_sparse,
            },
        );
        // Bind persisted task parameters and live variables from task state struct
        for (pname, _pty) in &task.live_across_wait {
            let (foff, mty, _) = ctx.resolve_field(&task.state_layout.canonical_name, pname);
            let fl = b.alloc_and_emit(
                pname,
                mty.clone(),
                Inst::FieldLoad {
                    base_ptr: state_ptr,
                    layout_key: task.state_layout.canonical_name.clone(),
                    field: pname.clone(),
                    offset_bytes: foff,
                    field_ty: mty.clone(),
                },
            );
            let slot = b.alloc_and_emit(
                &format!("slot_{pname}"),
                MirType::MutPtr,
                Inst::SlotAlloc { ty: mty.clone() },
            );
            b.emit_void(Inst::SlotStore { slot, val: fl });
            b.vars.insert(
                pname.clone(),
                VarSlot::Slot {
                    slot_local: slot,
                    ty: mty,
                },
            );
        }

        let (pc_off, _, _) = ctx.resolve_field(&task.state_layout.canonical_name, "__pc");
        let (tmr_off, _, _) = ctx.resolve_field(&task.state_layout.canonical_name, "__timer");
        let pc_local = b.alloc_and_emit(
            "__pc",
            MirType::U8,
            Inst::FieldLoad {
                base_ptr: state_ptr,
                layout_key: task.state_layout.canonical_name.clone(),
                field: "__pc".to_owned(),
                offset_bytes: pc_off,
                field_ty: MirType::U8,
            },
        );
        let timer_local = b.alloc_and_emit(
            "__timer",
            MirType::F32,
            Inst::FieldLoad {
                base_ptr: state_ptr,
                layout_key: task.state_layout.canonical_name.clone(),
                field: "__timer".to_owned(),
                offset_bytes: tmr_off,
                field_ty: MirType::F32,
            },
        );

        let abort_cond_desc = (!abort_stmts.is_empty()).then(|| "abort_if".to_owned());
        b.emit_void(Inst::TaskStep {
            task: task.name.clone(),
            pc_local,
            timer_local,
            abort_cond: abort_cond_desc,
            num_states,
        });

        // Evaluate `abort_if` guards before dispatching `__pc`
        for (a_idx, (cond_expr, cleanup)) in abort_stmts.iter().enumerate() {
            let (ac, _) = b.lower_expr(cond_expr);
            let cleanup_bb = b.new_block(&format!("abort_guard_{a_idx}"));
            let next_chk_bb = b.new_block(&format!("abort_pass_{a_idx}"));
            b.terminate(Terminator::Branch {
                cond: ac,
                then_bb: cleanup_bb,
                else_bb: next_chk_bb,
            });
            b.switch_to(cleanup_bb);
            b.lower_stmts(cleanup);
            if !b.cur_terminated {
                b.terminate(Terminator::Goto(abort_bb));
            }
            b.switch_to(next_chk_bb);
        }

        // Allocate state blocks `state_0 .. state_{K-1}` + switch
        let dispatch_bb = b.cur_bb;
        let mut cases = Vec::with_capacity(phases.len().max(1));
        for s in 0..num_states {
            cases.push((s, b.new_block(&format!("state_{s}"))));
        }
        let default_bb = cases[0].1;
        b.switch_to(dispatch_bb);
        b.terminate(Terminator::Switch {
            scrutinee: pc_local,
            cases: cases.clone(),
            default_bb,
        });

        if phases.is_empty() {
            b.switch_to(cases[0].1);
            b.emit_void(Inst::CmdRemove {
                entity: row_ent,
                component: task.name.clone(),
            });
            b.terminate(Terminator::Goto(row_inc));
        } else {
            for (s_idx, phase) in phases.iter().enumerate() {
                b.switch_to(cases[s_idx].1);
                b.lower_stmts(&phase.pre_stmts);
                let next_state = (s_idx as u32) + 1;
                match &phase.terminator {
                    TaskSuspension::YieldTick => {
                        let nxt = b.alloc_and_emit(
                            "next_pc",
                            MirType::U8,
                            Inst::ConstInt {
                                value: i64::from(next_state),
                            },
                        );
                        b.emit_void(Inst::FieldStore {
                            base_ptr: state_ptr,
                            layout_key: task.state_layout.canonical_name.clone(),
                            field: "__pc".to_owned(),
                            offset_bytes: pc_off,
                            val: nxt,
                        });
                        b.terminate(Terminator::Goto(row_inc));
                    }
                    TaskSuspension::Wait(dur_expr) => {
                        let (dur_val, _) = b.lower_expr(dur_expr);
                        let rem = b.alloc_and_emit(
                            "wait_rem",
                            MirType::F32,
                            Inst::BinOp {
                                op: "-".to_owned(),
                                lhs: timer_local,
                                rhs: dt_sec,
                                allow_fma: false,
                            },
                        );
                        let zero_f =
                            b.alloc_and_emit("zf", MirType::F32, Inst::ConstFloat { value: 0.0 });
                        let is_done = b.alloc_and_emit(
                            "wait_done",
                            MirType::Bool,
                            Inst::BinOp {
                                op: "<=".to_owned(),
                                lhs: rem,
                                rhs: zero_f,
                                allow_fma: false,
                            },
                        );
                        let done_bb = b.new_block(&format!("wait_done_{s_idx}"));
                        let tick_bb = b.new_block(&format!("wait_tick_{s_idx}"));
                        b.terminate(Terminator::Branch {
                            cond: is_done,
                            then_bb: done_bb,
                            else_bb: tick_bb,
                        });
                        b.switch_to(done_bb);
                        let nxt = b.alloc_and_emit(
                            "next_pc",
                            MirType::U8,
                            Inst::ConstInt {
                                value: i64::from(next_state),
                            },
                        );
                        b.emit_void(Inst::FieldStore {
                            base_ptr: state_ptr,
                            layout_key: task.state_layout.canonical_name.clone(),
                            field: "__pc".to_owned(),
                            offset_bytes: pc_off,
                            val: nxt,
                        });
                        b.emit_void(Inst::FieldStore {
                            base_ptr: state_ptr,
                            layout_key: task.state_layout.canonical_name.clone(),
                            field: "__timer".to_owned(),
                            offset_bytes: tmr_off,
                            val: dur_val,
                        });
                        b.terminate(Terminator::Goto(row_inc));

                        b.switch_to(tick_bb);
                        b.emit_void(Inst::FieldStore {
                            base_ptr: state_ptr,
                            layout_key: task.state_layout.canonical_name.clone(),
                            field: "__timer".to_owned(),
                            offset_bytes: tmr_off,
                            val: rem,
                        });
                        b.terminate(Terminator::Goto(row_inc));
                    }
                    TaskSuspension::WaitUntil(cond_expr) => {
                        let (wcond, _) = b.lower_expr(cond_expr);
                        let adv_bb = b.new_block(&format!("wuntil_adv_{s_idx}"));
                        b.terminate(Terminator::Branch {
                            cond: wcond,
                            then_bb: adv_bb,
                            else_bb: row_inc,
                        });
                        b.switch_to(adv_bb);
                        let nxt = b.alloc_and_emit(
                            "next_pc",
                            MirType::U8,
                            Inst::ConstInt {
                                value: i64::from(next_state),
                            },
                        );
                        b.emit_void(Inst::FieldStore {
                            base_ptr: state_ptr,
                            layout_key: task.state_layout.canonical_name.clone(),
                            field: "__pc".to_owned(),
                            offset_bytes: pc_off,
                            val: nxt,
                        });
                        b.terminate(Terminator::Goto(row_inc));
                    }
                    TaskSuspension::Race(branches) => {
                        let winner_exit = b.new_block(&format!("race_exit_{s_idx}"));
                        for (bi, br_stmts) in branches.iter().enumerate() {
                            let br_bb = b.new_block(&format!("race_{s_idx}_b{bi}"));
                            let next_br = if bi + 1 == branches.len() {
                                row_inc
                            } else {
                                b.new_block(&format!("race_{s_idx}_chk{}", bi + 1))
                            };
                            let (fired, tail_stmts) =
                                evaluate_race_branch_trigger(&mut b, br_stmts, timer_local, dt_sec);
                            b.terminate(Terminator::Branch {
                                cond: fired,
                                then_bb: br_bb,
                                else_bb: next_br,
                            });
                            b.switch_to(br_bb);
                            b.lower_stmts(&tail_stmts);
                            if !b.cur_terminated {
                                b.terminate(Terminator::Goto(winner_exit));
                            }
                            if next_br != row_inc {
                                b.switch_to(next_br);
                            }
                        }
                        b.switch_to(winner_exit);
                        let nxt = b.alloc_and_emit(
                            "next_pc",
                            MirType::U8,
                            Inst::ConstInt {
                                value: i64::from(next_state),
                            },
                        );
                        b.emit_void(Inst::FieldStore {
                            base_ptr: state_ptr,
                            layout_key: task.state_layout.canonical_name.clone(),
                            field: "__pc".to_owned(),
                            offset_bytes: pc_off,
                            val: nxt,
                        });
                        b.terminate(Terminator::Goto(row_inc));
                    }
                    TaskSuspension::Complete => {
                        b.emit_void(Inst::CmdRemove {
                            entity: row_ent,
                            component: task.name.clone(),
                        });
                        if !b.cur_terminated {
                            b.terminate(Terminator::Goto(row_inc));
                        }
                    }
                }
            }
        }

        b.switch_to(abort_bb);
        b.emit_void(Inst::CmdRemove {
            entity: row_ent,
            component: task.name.clone(),
        });
        b.terminate(Terminator::Goto(row_inc));

        b.switch_to(row_inc);
        let one = b.alloc_and_emit("r1", MirType::U32, Inst::ConstInt { value: 1 });
        let r_prev = b.alloc_and_emit("rp", MirType::U32, Inst::SlotLoad { slot: rslot });
        let r_nxt = b.alloc_and_emit(
            "rn",
            MirType::U32,
            Inst::BinOp {
                op: "+".to_owned(),
                lhs: r_prev,
                rhs: one,
                allow_fma: false,
            },
        );
        b.emit_void(Inst::SlotStore {
            slot: rslot,
            val: r_nxt,
        });
        b.terminate(Terminator::Goto(row_hdr));

        b.switch_to(exit_bb);
        b.terminate(Terminator::Return(None));
        module.functions.push(b.finish());
    }

    // 3. `fsm` -> priority-ordered state transition dispatcher + `on_enter` / `on_tick` / `on_exit`.
    let fsms = module.fsms.clone();
    for fsm in &fsms {
        let mut sorted_transitions = fsm.transitions.clone();
        sorted_transitions.sort_by_key(|a| std::cmp::Reverse(a.3));

        let mut func = MirFunction::new(&fsm.name, MirFnKind::SynthesizedFsm);
        func.is_deterministic = module.is_deterministic;

        let mut b = CfgBuilder::new(func, &ctx);
        b.bind_params(&fsm.params, true);

        b.func.queries.push(QueryAccessDesc {
            terms: vec![QueryTerm {
                storage_key: fsm.name.clone(),
                field_name: None,
                mode: TermAccessMode::Write,
                byte_start: 0,
                byte_end: 0,
            }],
            ..Default::default()
        });
        b.func.query_bindings.push(MirQueryBinding {
            query_idx: 0,
            terms: vec![MirQueryTermBinding {
                term_idx: 0,
                alias: "fsm".to_owned(),
                storage_key: fsm.name.clone(),
                canonical_component: fsm.state_layout.canonical_name.clone(),
                field_name: None,
                mode: TermAccessMode::Write,
                is_sparse: false,
            }],
            with_filters: Vec::new(),
            without_filters: Vec::new(),
            is_point_lookup: false,
        });

        let state_index: HashMap<String, u32> = fsm
            .states
            .iter()
            .enumerate()
            .map(|(i, s)| (s.clone(), i as u32))
            .collect();

        let chunk_hdr = b.new_block("fsm_chunk_hdr");
        let chunk_body = b.new_block("fsm_chunk_body");
        let row_hdr = b.new_block("fsm_row_hdr");
        let row_body = b.new_block("fsm_row_body");
        let row_inc = b.new_block("fsm_row_inc");
        let exit_bb = b.new_block("fsm_exit");

        b.terminate(Terminator::Goto(chunk_hdr));
        b.switch_to(chunk_hdr);
        let has_chunk = b.alloc_and_emit(
            "has_chunk",
            MirType::Bool,
            Inst::IterNextChunk { query_idx: 0 },
        );
        b.terminate(Terminator::Branch {
            cond: has_chunk,
            then_bb: chunk_body,
            else_bb: exit_bb,
        });

        b.switch_to(chunk_body);
        let chunk_len = b.alloc_and_emit(
            "chunk_len",
            MirType::U32,
            Inst::IterChunkLen { query_idx: 0 },
        );
        let col_ptr = b.alloc_and_emit(
            "fsm_col",
            MirType::MutPtr,
            Inst::IterColWrite {
                query_idx: 0,
                term_idx: 0,
                storage_key: fsm.name.clone(),
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
        let rcond = b.alloc_and_emit(
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
            cond: rcond,
            then_bb: row_body,
            else_bb: chunk_hdr,
        });

        b.switch_to(row_body);
        b.emit_void(Inst::FsmDispatch {
            fsm: fsm.name.clone(),
            transitions: sorted_transitions,
        });
        let rptr = b.alloc_and_emit(
            "fsm_row",
            MirType::MutPtr,
            Inst::RowPtr {
                col_ptr,
                row_idx: ridx,
                stride_bytes: fsm.state_layout.size as u32,
                is_sparse: false,
            },
        );
        let cur_state = b.alloc_and_emit(
            "cur_state",
            MirType::U16,
            Inst::FieldLoad {
                base_ptr: rptr,
                layout_key: fsm.state_layout.canonical_name.clone(),
                field: "__state".to_owned(),
                offset_bytes: 0,
                field_ty: MirType::U16,
            },
        );

        let num_states = fsm.states.len().max(1);
        let mut state_bbs = Vec::with_capacity(num_states);
        for (i, sname) in fsm.states.iter().enumerate() {
            state_bbs.push((i as u32, b.new_block(&format!("fsm_state_{sname}"))));
        }
        if state_bbs.is_empty() {
            state_bbs.push((0, b.new_block("fsm_state_0")));
        }
        let default_bb = state_bbs[0].1;
        b.terminate(Terminator::Switch {
            scrutinee: cur_state,
            cases: state_bbs.clone(),
            default_bb,
        });

        let hooks_by_name: HashMap<&str, _> = fsm
            .state_hooks
            .iter()
            .map(|h| (h.name.as_str(), h))
            .collect();

        for (i, sname) in fsm.states.iter().enumerate() {
            b.switch_to(state_bbs[i].1);
            if let Some(hook) = hooks_by_name.get(sname.as_str()) {
                for (fnm, fty, fdef) in &hook.fields {
                    let mty = mir_ty_from_hir(fty);
                    let init_l = if let Some(def) = fdef {
                        b.lower_expr(def).0
                    } else {
                        b.alloc_and_emit("z", mty.clone(), Inst::ConstInt { value: 0 })
                    };
                    let slot = b.alloc_and_emit(
                        &format!("st_{fnm}"),
                        MirType::MutPtr,
                        Inst::SlotAlloc { ty: mty.clone() },
                    );
                    b.emit_void(Inst::SlotStore { slot, val: init_l });
                    b.vars.insert(
                        fnm.clone(),
                        VarSlot::Slot {
                            slot_local: slot,
                            ty: mty,
                        },
                    );
                }
                b.lower_stmts(&hook.on_tick);
            }

            let mut outgoing: Vec<_> = fsm
                .typed_transitions
                .iter()
                .filter(|t| t.from_state == *sname)
                .collect();
            outgoing.sort_by_key(|t| std::cmp::Reverse(t.priority));

            for (ti, tr) in outgoing.iter().enumerate() {
                let (guard_l, _) = b.lower_expr(&tr.guard);
                let take_bb = b.new_block(&format!("fsm_{sname}_to_{}_{ti}", tr.to_state));
                let skip_bb = b.new_block(&format!("fsm_{sname}_next_{ti}"));
                b.terminate(Terminator::Branch {
                    cond: guard_l,
                    then_bb: take_bb,
                    else_bb: skip_bb,
                });
                b.switch_to(take_bb);
                if let Some(from_hook) = hooks_by_name.get(sname.as_str()) {
                    b.lower_stmts(&from_hook.on_exit);
                }
                let tgt_idx = state_index.get(&tr.to_state).copied().unwrap_or(0);
                let nxt_s = b.alloc_and_emit(
                    "next_state",
                    MirType::U16,
                    Inst::ConstInt {
                        value: i64::from(tgt_idx),
                    },
                );
                b.emit_void(Inst::FieldStore {
                    base_ptr: rptr,
                    layout_key: fsm.state_layout.canonical_name.clone(),
                    field: "__state".to_owned(),
                    offset_bytes: 0,
                    val: nxt_s,
                });
                if let Some(to_hook) = hooks_by_name.get(tr.to_state.as_str()) {
                    for (anm, aexpr) in &tr.target_args {
                        let (av, _) = b.lower_expr(aexpr);
                        if let Some(VarSlot::Slot { slot_local, .. }) = b.vars.get(anm).cloned() {
                            b.emit_void(Inst::SlotStore {
                                slot: slot_local,
                                val: av,
                            });
                        }
                    }
                    b.lower_stmts(&to_hook.on_enter);
                }
                if !b.cur_terminated {
                    b.terminate(Terminator::Goto(row_inc));
                }
                b.switch_to(skip_bb);
            }
            if !b.cur_terminated {
                b.terminate(Terminator::Goto(row_inc));
            }
        }
        if fsm.states.is_empty() {
            b.switch_to(state_bbs[0].1);
            b.terminate(Terminator::Goto(row_inc));
        }

        b.switch_to(row_inc);
        let one = b.alloc_and_emit("r1", MirType::U32, Inst::ConstInt { value: 1 });
        let r_prev = b.alloc_and_emit("rp", MirType::U32, Inst::SlotLoad { slot: rslot });
        let r_nxt = b.alloc_and_emit(
            "rn",
            MirType::U32,
            Inst::BinOp {
                op: "+".to_owned(),
                lhs: r_prev,
                rhs: one,
                allow_fma: false,
            },
        );
        b.emit_void(Inst::SlotStore {
            slot: rslot,
            val: r_nxt,
        });
        b.terminate(Terminator::Goto(row_hdr));

        b.switch_to(exit_bb);
        b.terminate(Terminator::Return(None));
        module.functions.push(b.finish());
    }
}

struct TaskPhase {
    pre_stmts: Vec<HirStmt>,
    terminator: TaskSuspension,
}

enum TaskSuspension {
    YieldTick,
    Wait(strata_sema::hir::HirExpr),
    WaitUntil(strata_sema::hir::HirExpr),
    Race(Vec<Vec<HirStmt>>),
    Complete,
}

fn segment_task_phases(
    body: &[HirStmt],
) -> (
    Vec<(strata_sema::hir::HirExpr, Vec<HirStmt>)>,
    Vec<TaskPhase>,
) {
    let mut aborts = Vec::new();
    let mut phases = Vec::new();
    let mut cur = Vec::new();

    for stmt in body {
        match stmt {
            HirStmt::AbortIf { cond, cleanup } => {
                aborts.push((cond.clone(), cleanup.clone()));
            }
            HirStmt::YieldTick => {
                phases.push(TaskPhase {
                    pre_stmts: std::mem::take(&mut cur),
                    terminator: TaskSuspension::YieldTick,
                });
            }
            HirStmt::Wait(d) => {
                phases.push(TaskPhase {
                    pre_stmts: std::mem::take(&mut cur),
                    terminator: TaskSuspension::Wait(d.clone()),
                });
            }
            HirStmt::WaitUntil(c) => {
                phases.push(TaskPhase {
                    pre_stmts: std::mem::take(&mut cur),
                    terminator: TaskSuspension::WaitUntil(c.clone()),
                });
            }
            HirStmt::Race { branches } => {
                phases.push(TaskPhase {
                    pre_stmts: std::mem::take(&mut cur),
                    terminator: TaskSuspension::Race(branches.clone()),
                });
            }
            other => cur.push(other.clone()),
        }
    }
    if !cur.is_empty() || phases.is_empty() {
        phases.push(TaskPhase {
            pre_stmts: cur,
            terminator: TaskSuspension::Complete,
        });
    }
    (aborts, phases)
}

fn evaluate_race_branch_trigger(
    b: &mut CfgBuilder<'_>,
    stmts: &[HirStmt],
    timer_local: LocalId,
    dt_sec: LocalId,
) -> (LocalId, Vec<HirStmt>) {
    let mut rest = Vec::new();
    let mut cond_out = None;
    for (idx, s) in stmts.iter().enumerate() {
        match s {
            HirStmt::Wait(dur) if cond_out.is_none() => {
                let (dur_v, _) = b.lower_expr(dur);
                let elapsed = b.alloc_and_emit(
                    "race_t",
                    MirType::F32,
                    Inst::BinOp {
                        op: "+".to_owned(),
                        lhs: timer_local,
                        rhs: dt_sec,
                        allow_fma: false,
                    },
                );
                cond_out = Some(b.alloc_and_emit(
                    "race_wait_hit",
                    MirType::Bool,
                    Inst::BinOp {
                        op: ">=".to_owned(),
                        lhs: elapsed,
                        rhs: dur_v,
                        allow_fma: false,
                    },
                ));
                rest.extend(stmts[idx + 1..].iter().cloned());
                break;
            }
            HirStmt::WaitUntil(c) if cond_out.is_none() => {
                let (cv, _) = b.lower_expr(c);
                cond_out = Some(cv);
                rest.extend(stmts[idx + 1..].iter().cloned());
                break;
            }
            HirStmt::YieldTick if cond_out.is_none() => {
                cond_out = Some(b.alloc_and_emit(
                    "race_yield",
                    MirType::Bool,
                    Inst::ConstBool { value: true },
                ));
                rest.extend(stmts[idx + 1..].iter().cloned());
                break;
            }
            other => b.lower_stmt(other),
        }
    }
    let fired = cond_out.unwrap_or_else(|| {
        b.alloc_and_emit("race_imm", MirType::Bool, Inst::ConstBool { value: true })
    });
    (fired, rest)
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::ir::*;
    use crate::verify::verify_mir;
    use indexmap::IndexMap;
    use strata_sema::access::FilteredAccessSet;
    use strata_sema::hir::{HirExpr, HirFsm, HirFsmState, HirFsmTransition, HirStmt, HirTask};
    use strata_sema::layout::{
        LayoutEnv, SchemaItemKind, solve_pod_layout, solve_task_state_layout,
    };

    /// Verifies FSM synthesis orders transitions by descending explicit priority.
    #[test]
    fn fsm_synthesis_sorts_transitions_by_descending_priority() {
        let layout = solve_pod_layout(
            "fsm::BossAi",
            SchemaItemKind::FsmState,
            &[],
            0,
            Vec::new(),
            &LayoutEnv::default(),
        )
        .unwrap();
        let mut module = MirModule {
            module_path: "fsm::m".to_owned(),
            is_deterministic: false,
            layouts: Vec::new(),
            enums: Vec::new(),
            consts: Vec::new(),
            tables: Vec::new(),
            curves: Vec::new(),
            relations: Vec::new(),
            spatial_indices: Vec::new(),
            timelines: Vec::new(),
            tasks: Vec::new(),
            fsms: vec![HirFsm {
                name: "BossAi".to_owned(),
                is_persist: false,
                initial_state: "Idle".to_owned(),
                states: vec!["Idle".to_owned(), "Attack".to_owned(), "Enrage".to_owned()],
                transitions: vec![
                    (
                        "Idle".to_owned(),
                        "Attack".to_owned(),
                        "cond1".to_owned(),
                        1,
                    ),
                    (
                        "Idle".to_owned(),
                        "Enrage".to_owned(),
                        "cond2".to_owned(),
                        10,
                    ),
                ],
                params: Vec::new(),
                typed_transitions: vec![
                    HirFsmTransition {
                        from_state: "Idle".to_owned(),
                        to_state: "Attack".to_owned(),
                        guard: HirExpr::BoolLit(true),
                        priority: 1,
                        target_args: Vec::new(),
                    },
                    HirFsmTransition {
                        from_state: "Idle".to_owned(),
                        to_state: "Enrage".to_owned(),
                        guard: HirExpr::BoolLit(true),
                        priority: 10,
                        target_args: Vec::new(),
                    },
                ],
                state_hooks: vec![
                    HirFsmState {
                        name: "Idle".to_owned(),
                        fields: Vec::new(),
                        on_enter: Vec::new(),
                        on_tick: Vec::new(),
                        on_exit: Vec::new(),
                    },
                    HirFsmState {
                        name: "Attack".to_owned(),
                        fields: Vec::new(),
                        on_enter: Vec::new(),
                        on_tick: Vec::new(),
                        on_exit: Vec::new(),
                    },
                    HirFsmState {
                        name: "Enrage".to_owned(),
                        fields: Vec::new(),
                        on_enter: Vec::new(),
                        on_tick: Vec::new(),
                        on_exit: Vec::new(),
                    },
                ],
                state_layout: layout,
                access: FilteredAccessSet::default(),
            }],
            objects: Vec::new(),
            migrations: Vec::new(),
            fns: Vec::new(),
            functions: Vec::new(),
            schedules: Vec::new(),
            sim_tests: Vec::new(),
            field_defaults: IndexMap::new(),
            rpcs: Vec::new(),
            net_components: Vec::new(),
            net_sim_tests: Vec::new(),
            net_handshake: crate::ir::MirNetHandshake::default(),
            net_stream_ops: Vec::new(),
        };
        run(&mut module);
        let disp = module.functions[0]
            .blocks
            .iter()
            .flat_map(|b| &b.stmts)
            .find_map(|s| match &s.inst {
                Inst::FsmDispatch { transitions, .. } => Some(transitions),
                _ => None,
            })
            .expect("FsmDispatch synthesized");
        assert_eq!(disp[0].3, 10);
        assert_eq!(disp[1].3, 1);
    }

    /// Verifies `task` synthesis uses dense `IterColWrite` + `RowPtr { is_sparse: false }` when
    /// `@sparse` is absent and `IterColRowsWrite` + `RowPtr { is_sparse: true }` when `@sparse`.
    #[test]
    fn task_synthesis_respects_dense_vs_sparse_state_storage() {
        let env = LayoutEnv::default();
        let dense_layout = solve_task_state_layout("task_m::DenseTask", &[], false, &env).unwrap();
        let sparse_layout = solve_task_state_layout("task_m::SparseTask", &[], true, &env).unwrap();
        assert_eq!(
            dense_layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET,
            0
        );
        assert_ne!(
            sparse_layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET,
            0
        );

        let mut module = MirModule {
            module_path: "task_m".to_owned(),
            is_deterministic: false,
            layouts: vec![dense_layout.clone(), sparse_layout.clone()],
            enums: Vec::new(),
            consts: Vec::new(),
            tables: Vec::new(),
            curves: Vec::new(),
            relations: Vec::new(),
            spatial_indices: Vec::new(),
            timelines: Vec::new(),
            tasks: vec![
                HirTask {
                    name: "DenseTask".to_owned(),
                    is_sparse: false,
                    params: Vec::new(),
                    typed_params: Vec::new(),
                    on_terms: Vec::new(),
                    typed_on_terms: Vec::new(),
                    using_params: Vec::new(),
                    typed_using_params: Vec::new(),
                    live_across_wait: Vec::new(),
                    state_layout: dense_layout,
                    access: FilteredAccessSet::default(),
                    body_source: "yield_tick;".to_owned(),
                    body: vec![HirStmt::YieldTick],
                },
                HirTask {
                    name: "SparseTask".to_owned(),
                    is_sparse: true,
                    params: Vec::new(),
                    typed_params: Vec::new(),
                    on_terms: Vec::new(),
                    typed_on_terms: Vec::new(),
                    using_params: Vec::new(),
                    typed_using_params: Vec::new(),
                    live_across_wait: Vec::new(),
                    state_layout: sparse_layout,
                    access: FilteredAccessSet::default(),
                    body_source: "yield_tick;".to_owned(),
                    body: vec![HirStmt::YieldTick],
                },
            ],
            fsms: Vec::new(),
            objects: Vec::new(),
            migrations: Vec::new(),
            fns: Vec::new(),
            functions: Vec::new(),
            schedules: Vec::new(),
            sim_tests: Vec::new(),
            field_defaults: IndexMap::new(),
            rpcs: Vec::new(),
            net_components: Vec::new(),
            net_sim_tests: Vec::new(),
            net_handshake: crate::ir::MirNetHandshake::default(),
            net_stream_ops: Vec::new(),
        };

        run(&mut module);
        verify_mir(&module).expect("synthesized dense and sparse tasks must verify");

        let dense_fn = module
            .functions
            .iter()
            .find(|f| f.name == "DenseTask")
            .expect("DenseTask function");
        assert!(
            !dense_fn.query_bindings[0].terms[0].is_sparse,
            "non-@sparse task state binding must have is_sparse == false"
        );
        let dense_col_stmt = dense_fn
            .blocks
            .iter()
            .flat_map(|b| &b.stmts)
            .find(|s| matches!(s.inst, Inst::IterColWrite { term_idx: 0, .. }))
            .expect("non-@sparse task must emit IterColWrite for task state");
        assert!(
            !dense_fn
                .blocks
                .iter()
                .flat_map(|b| &b.stmts)
                .any(|s| matches!(s.inst, Inst::IterColRowsWrite { .. })),
            "non-@sparse task must not emit IterColRowsWrite"
        );
        let dense_col_local = dense_col_stmt.dst.expect("IterColWrite dst");
        assert!(
            dense_fn.blocks.iter().flat_map(|b| &b.stmts).any(|s| {
                matches!(
                    s.inst,
                    Inst::RowPtr {
                        col_ptr,
                        is_sparse: false,
                        ..
                    } if col_ptr == dense_col_local
                )
            }),
            "non-@sparse task RowPtr must have is_sparse == false"
        );

        let sparse_fn = module
            .functions
            .iter()
            .find(|f| f.name == "SparseTask")
            .expect("SparseTask function");
        assert!(
            sparse_fn.query_bindings[0].terms[0].is_sparse,
            "@sparse task state binding must have is_sparse == true"
        );
        let sparse_col_stmt = sparse_fn
            .blocks
            .iter()
            .flat_map(|b| &b.stmts)
            .find(|s| matches!(s.inst, Inst::IterColRowsWrite { term_idx: 0, .. }))
            .expect("@sparse task must emit IterColRowsWrite for task state");
        assert!(
            !sparse_fn
                .blocks
                .iter()
                .flat_map(|b| &b.stmts)
                .any(|s| matches!(s.inst, Inst::IterColWrite { .. })),
            "@sparse task must not emit dense IterColWrite"
        );
        let sparse_col_local = sparse_col_stmt.dst.expect("IterColRowsWrite dst");
        assert!(
            sparse_fn.blocks.iter().flat_map(|b| &b.stmts).any(|s| {
                matches!(
                    s.inst,
                    Inst::RowPtr {
                        col_ptr,
                        is_sparse: true,
                        ..
                    } if col_ptr == sparse_col_local
                )
            }),
            "@sparse task RowPtr must have is_sparse == true"
        );
    }
}
