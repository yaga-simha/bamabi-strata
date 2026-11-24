//! Synthesizes complete executable SSA CFG tick functions for `timeline`, stackless
//! `@sparse task` coroutines, and hierarchical `fsm` declarations.

use crate::ir::{
    BlockId, Inst, LocalId, MirFnKind, MirFunction, MirModule, MirQueryBinding,
    MirQueryTermBinding, MirStmt, MirType, Terminator,
};
use crate::lower::{CfgBuilder, MirLowerCtx, TermAccessBinding, VarSlot};
use std::collections::{HashMap, HashSet};
use strata_sema::access::{QueryAccessDesc, QueryTerm, TermAccessMode};
use strata_sema::hir::{HirExpr, HirPattern, HirStmt};
use strata_sema::layout::{
    LayoutEnv, SchemaItemKind, resolve_ty_layout, solve_pod_layout, solve_task_state_layout,
};
use strata_sema::types::Ty;

/// Lowers every `timeline`, `task`, and `fsm` in `module` into concrete `MirFunction` tick
/// systems ready for backend code generation.
pub fn run(module: &mut MirModule) {
    prepare_task_and_fsm_layouts(module);
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

        // Extract `abort_if` guards + executable task statements (preserving arbitrary nesting).
        let (abort_stmts, exec_stmts) = split_task_aborts(&task.body);

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
        // Bind persisted task parameters and live variables from task state struct, tracking
        // `(var_name, layout_field_name, field_offset, mir_ty, persist_slot)` for writeback.
        let mut persist_fields: Vec<TaskPersistField> = Vec::new();
        for (raw_name, _pty) in &task.live_across_wait {
            let var_name = raw_name
                .strip_prefix("mut ")
                .unwrap_or(raw_name)
                .trim()
                .to_owned();
            if persist_fields.iter().any(|pf| pf.var_name == var_name) {
                continue;
            }
            let (foff, mty, _) = ctx.resolve_field(&task.state_layout.canonical_name, raw_name);
            let fl = b.alloc_and_emit(
                &var_name,
                mty.clone(),
                Inst::FieldLoad {
                    base_ptr: state_ptr,
                    layout_key: task.state_layout.canonical_name.clone(),
                    field: raw_name.clone(),
                    offset_bytes: foff,
                    field_ty: mty.clone(),
                },
            );
            let slot = b.alloc_and_emit(
                &format!("slot_{var_name}"),
                MirType::MutPtr,
                Inst::SlotAlloc { ty: mty.clone() },
            );
            b.emit_void(Inst::SlotStore { slot, val: fl });
            b.vars.insert(
                var_name.clone(),
                VarSlot::Slot {
                    slot_local: slot,
                    ty: mty.clone(),
                },
            );
            persist_fields.push(TaskPersistField {
                var_name,
                field_name: raw_name.clone(),
                offset_bytes: foff,
                ty: mty,
                persist_slot: slot,
            });
        }
        let live_base_vars = b.vars.clone();

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
        let task_step_bb = b.cur_bb;
        let task_step_stmt_idx = b.func.blocks[task_step_bb.0 as usize].stmts.len();
        b.emit_void(Inst::TaskStep {
            task: task.name.clone(),
            pc_local,
            timer_local,
            abort_cond: abort_cond_desc,
            num_states: 1,
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

        // Lower task body recursively into stackless `__pc` resume states supporting suspensions
        // at top-level, inside `if`/`else` (`else if`), `while`/`loop`, and `race`.
        let dispatch_bb = b.cur_bb;
        let state0_bb = b.new_block("state_0");
        let mut tctx = TaskLowerCtx {
            resume_states: vec![state0_bb],
            cur_pc: 0,
            live_base_vars,
            persist_fields,
            state_ptr,
            row_ent,
            pc_off,
            tmr_off,
            timer_local,
            dt_sec,
            task_name: task.name.clone(),
            layout_key: task.state_layout.canonical_name.clone(),
            row_inc,
            loop_targets: Vec::new(),
            alloc_bb: dispatch_bb,
        };
        b.switch_to(state0_bb);
        lower_task_stmts(&mut b, &mut tctx, &exec_stmts);
        if !b.cur_terminated {
            b.emit_void(Inst::CmdRemove {
                entity: row_ent,
                component: task.name.clone(),
            });
            b.terminate(Terminator::Goto(row_inc));
        }

        let total_states = tctx.resume_states.len().max(1) as u32;
        if let Some(stmt) = b.func.blocks[task_step_bb.0 as usize]
            .stmts
            .get_mut(task_step_stmt_idx)
            && let Inst::TaskStep { num_states, .. } = &mut stmt.inst
        {
            *num_states = total_states;
        }
        let cases: Vec<(u32, BlockId)> = tctx
            .resume_states
            .iter()
            .enumerate()
            .map(|(i, &bb)| (i as u32, bb))
            .collect();
        let default_bb = cases[0].1;
        b.switch_to(dispatch_bb);
        b.terminate(Terminator::Switch {
            scrutinee: pc_local,
            cases,
            default_bb,
        });

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
        let flags_off_opt = ctx
            .find_layout(&fsm.state_layout.canonical_name)
            .and_then(|l| l.fields.iter().find(|f| f.name == "__flags"))
            .map(|f| f.offset as u32);

        let hooks_by_name: HashMap<&str, _> = fsm
            .state_hooks
            .iter()
            .map(|h| (h.name.as_str(), h))
            .collect();
        let base_fsm_vars = b.vars.clone();

        // Pre-allocate stack slots for every state's persistent fields in `row_body` so every
        // state handler and incoming transition dominates and shares the same slot allocation.
        let mut state_fields: Vec<Vec<FsmPersistField>> =
            Vec::with_capacity(fsm.states.len().max(1));
        for (s_idx, sname) in fsm.states.iter().enumerate() {
            let mut fields_for_state = Vec::new();
            if let Some(hook) = hooks_by_name.get(sname.as_str()) {
                for (fnm, _fty, fdef) in &hook.fields {
                    let layout_field = fsm_state_field_key(s_idx, fnm);
                    let (foff, mty, _) =
                        ctx.resolve_field(&fsm.state_layout.canonical_name, &layout_field);
                    let slot = b.alloc_and_emit(
                        &format!("st_{s_idx}_{fnm}"),
                        MirType::MutPtr,
                        Inst::SlotAlloc { ty: mty.clone() },
                    );
                    fields_for_state.push(FsmPersistField {
                        user_name: fnm.clone(),
                        layout_field,
                        offset_bytes: foff,
                        ty: mty,
                        default_expr: fdef.clone(),
                        slot_local: slot,
                    });
                }
            }
            state_fields.push(fields_for_state);
        }

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

        for (i, sname) in fsm.states.iter().enumerate() {
            b.switch_to(state_bbs[i].1);
            let hook_opt = hooks_by_name.get(sname.as_str()).copied();
            let has_enter_work =
                !state_fields[i].is_empty() || hook_opt.is_some_and(|h| !h.on_enter.is_empty());

            if let Some(flags_off) = flags_off_opt
                && has_enter_work
            {
                let cur_flags = b.alloc_and_emit(
                    "fsm_flags",
                    MirType::U16,
                    Inst::FieldLoad {
                        base_ptr: rptr,
                        layout_key: fsm.state_layout.canonical_name.clone(),
                        field: "__flags".to_owned(),
                        offset_bytes: flags_off,
                        field_ty: MirType::U16,
                    },
                );
                let one_u16 = b.alloc_and_emit("flag_1", MirType::U16, Inst::ConstInt { value: 1 });
                let zero_u16 =
                    b.alloc_and_emit("flag_0", MirType::U16, Inst::ConstInt { value: 0 });
                let bit = b.alloc_and_emit(
                    "flag_bit",
                    MirType::U16,
                    Inst::BinOp {
                        op: "&".to_owned(),
                        lhs: cur_flags,
                        rhs: one_u16,
                        allow_fma: false,
                    },
                );
                let need_init = b.alloc_and_emit(
                    "fsm_need_init",
                    MirType::Bool,
                    Inst::BinOp {
                        op: "==".to_owned(),
                        lhs: bit,
                        rhs: zero_u16,
                        allow_fma: false,
                    },
                );
                let init_bb = b.new_block(&format!("fsm_{sname}_init_enter"));
                let load_bb = b.new_block(&format!("fsm_{sname}_load"));
                let tick_bb = b.new_block(&format!("fsm_{sname}_tick"));
                b.terminate(Terminator::Branch {
                    cond: need_init,
                    then_bb: init_bb,
                    else_bb: load_bb,
                });

                b.switch_to(init_bb);
                let flags_set = b.alloc_and_emit(
                    "flags_init",
                    MirType::U16,
                    Inst::BinOp {
                        op: "|".to_owned(),
                        lhs: cur_flags,
                        rhs: one_u16,
                        allow_fma: false,
                    },
                );
                b.emit_void(Inst::FieldStore {
                    base_ptr: rptr,
                    layout_key: fsm.state_layout.canonical_name.clone(),
                    field: "__flags".to_owned(),
                    offset_bytes: flags_off,
                    val: flags_set,
                });
                bind_fsm_state_vars(&mut b, &base_fsm_vars, &state_fields[i]);
                init_fsm_state_fields(
                    &mut b,
                    rptr,
                    &fsm.state_layout.canonical_name,
                    &state_fields[i],
                );
                if let Some(hook) = hook_opt {
                    b.lower_stmts(&hook.on_enter);
                }
                if !b.cur_terminated {
                    persist_fsm_state_fields(
                        &mut b,
                        rptr,
                        &fsm.state_layout.canonical_name,
                        &state_fields[i],
                    );
                    b.terminate(Terminator::Goto(tick_bb));
                }

                b.switch_to(load_bb);
                load_fsm_state_fields(
                    &mut b,
                    rptr,
                    &fsm.state_layout.canonical_name,
                    &state_fields[i],
                );
                b.terminate(Terminator::Goto(tick_bb));

                b.switch_to(tick_bb);
            }

            bind_fsm_state_vars(&mut b, &base_fsm_vars, &state_fields[i]);
            if let Some(hook) = hook_opt {
                b.lower_stmts(&hook.on_tick);
            }
            if !b.cur_terminated {
                persist_fsm_state_fields(
                    &mut b,
                    rptr,
                    &fsm.state_layout.canonical_name,
                    &state_fields[i],
                );
            }

            let mut outgoing: Vec<_> = fsm
                .typed_transitions
                .iter()
                .filter(|t| t.from_state == *sname)
                .collect();
            outgoing.sort_by_key(|t| std::cmp::Reverse(t.priority));

            for (ti, tr) in outgoing.iter().enumerate() {
                if b.cur_terminated {
                    break;
                }
                let (guard_l, _) = b.lower_expr(&tr.guard);
                let take_bb = b.new_block(&format!("fsm_{sname}_to_{}_{ti}", tr.to_state));
                let skip_bb = b.new_block(&format!("fsm_{sname}_next_{ti}"));
                b.terminate(Terminator::Branch {
                    cond: guard_l,
                    then_bb: take_bb,
                    else_bb: skip_bb,
                });
                b.switch_to(take_bb);
                if let Some(from_hook) = hook_opt {
                    b.lower_stmts(&from_hook.on_exit);
                    if !b.cur_terminated {
                        persist_fsm_state_fields(
                            &mut b,
                            rptr,
                            &fsm.state_layout.canonical_name,
                            &state_fields[i],
                        );
                    }
                }
                if !b.cur_terminated {
                    // Evaluate target state args while `from_state` fields are still in `b.vars`.
                    let eval_args: Vec<(String, LocalId)> = tr
                        .target_args
                        .iter()
                        .map(|(anm, aexpr)| (anm.clone(), b.lower_expr(aexpr).0))
                        .collect();

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
                    if let Some(flags_off) = flags_off_opt {
                        let cur_flags = b.alloc_and_emit(
                            "tr_flags",
                            MirType::U16,
                            Inst::FieldLoad {
                                base_ptr: rptr,
                                layout_key: fsm.state_layout.canonical_name.clone(),
                                field: "__flags".to_owned(),
                                offset_bytes: flags_off,
                                field_ty: MirType::U16,
                            },
                        );
                        let one_u16 = b.alloc_and_emit(
                            "tr_flag_1",
                            MirType::U16,
                            Inst::ConstInt { value: 1 },
                        );
                        let flags_set = b.alloc_and_emit(
                            "tr_flags_set",
                            MirType::U16,
                            Inst::BinOp {
                                op: "|".to_owned(),
                                lhs: cur_flags,
                                rhs: one_u16,
                                allow_fma: false,
                            },
                        );
                        b.emit_void(Inst::FieldStore {
                            base_ptr: rptr,
                            layout_key: fsm.state_layout.canonical_name.clone(),
                            field: "__flags".to_owned(),
                            offset_bytes: flags_off,
                            val: flags_set,
                        });
                    }

                    let tgt_u = tgt_idx as usize;
                    if let Some(tgt_fields) = state_fields.get(tgt_u) {
                        bind_fsm_state_vars(&mut b, &base_fsm_vars, tgt_fields);
                        init_fsm_state_fields(
                            &mut b,
                            rptr,
                            &fsm.state_layout.canonical_name,
                            tgt_fields,
                        );
                        for (anm, av) in eval_args {
                            if let Some(pf) = tgt_fields.iter().find(|f| f.user_name == anm) {
                                b.emit_void(Inst::SlotStore {
                                    slot: pf.slot_local,
                                    val: av,
                                });
                            }
                        }
                    } else {
                        b.vars = base_fsm_vars.clone();
                    }
                    if let Some(to_hook) = hooks_by_name.get(tr.to_state.as_str()) {
                        b.lower_stmts(&to_hook.on_enter);
                    }
                    if !b.cur_terminated
                        && let Some(tgt_fields) = state_fields.get(tgt_u)
                    {
                        persist_fsm_state_fields(
                            &mut b,
                            rptr,
                            &fsm.state_layout.canonical_name,
                            tgt_fields,
                        );
                    }
                }
                if !b.cur_terminated {
                    b.terminate(Terminator::Goto(row_inc));
                }
                bind_fsm_state_vars(&mut b, &base_fsm_vars, &state_fields[i]);
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

struct TaskPersistField {
    var_name: String,
    field_name: String,
    offset_bytes: u32,
    ty: MirType,
    persist_slot: LocalId,
}

struct TaskLowerCtx {
    resume_states: Vec<BlockId>,
    cur_pc: u8,
    live_base_vars: HashMap<String, VarSlot>,
    persist_fields: Vec<TaskPersistField>,
    state_ptr: LocalId,
    row_ent: LocalId,
    pc_off: u32,
    tmr_off: u32,
    timer_local: LocalId,
    dt_sec: LocalId,
    task_name: String,
    layout_key: String,
    row_inc: BlockId,
    loop_targets: Vec<(BlockId, BlockId)>,
    alloc_bb: BlockId,
}

impl TaskLowerCtx {
    fn alloc_state(&mut self, b: &mut CfgBuilder<'_>, prefix: &str) -> (u8, BlockId) {
        let idx = self.resume_states.len() as u8;
        let bb = b.new_block(&format!("{prefix}_{idx}"));
        self.resume_states.push(bb);
        (idx, bb)
    }
}

struct FsmPersistField {
    user_name: String,
    layout_field: String,
    offset_bytes: u32,
    ty: MirType,
    default_expr: Option<HirExpr>,
    slot_local: LocalId,
}

fn fsm_state_field_key(state_idx: usize, field_name: &str) -> String {
    format!("__st_{state_idx}_{field_name}")
}

fn build_layout_env(module: &MirModule) -> LayoutEnv {
    let mut env = LayoutEnv::default();
    for e in &module.enums {
        if let Some(short) = e.canonical_name.rsplit("::").next() {
            env.enums.insert(short.to_owned(), e.clone());
        }
        env.enums.insert(e.canonical_name.clone(), e.clone());
    }
    for l in &module.layouts {
        let entry = (
            l.size,
            l.align,
            l.is_abi_pod,
            bamabi_sys::BamFieldKind::NESTED.0,
            l.canonical_name.clone(),
        );
        if let Some(short) = l.canonical_name.rsplit("::").next() {
            env.resolved
                .entry(short.to_owned())
                .or_insert_with(|| entry.clone());
        }
        env.resolved.insert(l.canonical_name.clone(), entry);
    }
    env
}

fn replace_module_layout(module: &mut MirModule, updated: &strata_sema::layout::SolvedLayout) {
    if let Some(slot) = module
        .layouts
        .iter_mut()
        .find(|l| l.canonical_name == updated.canonical_name)
    {
        *slot = updated.clone();
    } else {
        module.layouts.push(updated.clone());
    }
}

fn collect_inferred_lets_in_expr(expr: &HirExpr, out: &mut HashMap<String, Option<Ty>>) {
    match expr {
        HirExpr::Block { stmts, tail, .. } => {
            collect_inferred_lets_in_stmts(stmts, out);
            if let Some(t) = tail {
                collect_inferred_lets_in_expr(t, out);
            }
        }
        HirExpr::If {
            cond,
            then_stmts,
            then_tail,
            else_stmts,
            else_tail,
            ..
        } => {
            collect_inferred_lets_in_expr(cond, out);
            collect_inferred_lets_in_stmts(then_stmts, out);
            if let Some(t) = then_tail {
                collect_inferred_lets_in_expr(t, out);
            }
            collect_inferred_lets_in_stmts(else_stmts, out);
            if let Some(t) = else_tail {
                collect_inferred_lets_in_expr(t, out);
            }
        }
        HirExpr::Match(m) => {
            collect_inferred_lets_in_expr(&m.scrutinee, out);
            for arm in &m.arms {
                collect_inferred_lets_in_expr(&arm.body, out);
            }
        }
        _ => {}
    }
}

fn collect_inferred_lets_in_stmts(stmts: &[HirStmt], out: &mut HashMap<String, Option<Ty>>) {
    for stmt in stmts {
        match stmt {
            HirStmt::Let {
                pattern: HirPattern::Binding { name, .. },
                ty,
                value,
                else_block,
                ..
            } => {
                let bound_ty = ty.clone().unwrap_or_else(|| value.ty());
                match out.get_mut(name) {
                    None => {
                        out.insert(name.clone(), Some(bound_ty));
                    }
                    Some(Some(prev)) if *prev != bound_ty => {
                        *out.get_mut(name).unwrap() = None;
                    }
                    _ => {}
                }
                collect_inferred_lets_in_expr(value, out);
                collect_inferred_lets_in_stmts(else_block, out);
            }
            HirStmt::Expr(e) => collect_inferred_lets_in_expr(e, out),
            HirStmt::While { cond, body } => {
                collect_inferred_lets_in_expr(cond, out);
                collect_inferred_lets_in_stmts(body, out);
            }
            HirStmt::Loop { body } => collect_inferred_lets_in_stmts(body, out),
            HirStmt::Race { branches } => {
                for br in branches {
                    collect_inferred_lets_in_stmts(br, out);
                }
            }
            _ => {}
        }
    }
}

fn is_persistable_task_local_ty(ty: &Ty, env: &LayoutEnv) -> bool {
    if matches!(
        ty,
        Ty::Unknown
            | Ty::Unit
            | Ty::Borrow { .. }
            | Ty::Ref(_)
            | Ty::Option(_)
            | Ty::Tuple(_)
            | Ty::BannedWire(_)
    ) {
        return false;
    }
    resolve_ty_layout(ty, env).is_some_and(|(sz, _, is_pod, _, _)| sz > 0 && is_pod)
}

fn prepare_task_and_fsm_layouts(module: &mut MirModule) {
    let env = build_layout_env(module);

    // 1. Expand `task` state layouts for untyped `let` locals live across suspension points.
    let mut updated_task_layouts = Vec::new();
    for task in &mut module.tasks {
        if !stmts_contain_suspension(&task.body) {
            continue;
        }
        let mut let_vars = HashMap::new();
        collect_inferred_lets_in_stmts(&task.body, &mut let_vars);
        let existing: HashSet<String> = task
            .live_across_wait
            .iter()
            .map(|(n, _)| n.strip_prefix("mut ").unwrap_or(n).trim().to_owned())
            .collect();
        let mut extras: Vec<(String, Ty)> = let_vars
            .into_iter()
            .filter_map(|(nm, ty_opt)| {
                let ty = ty_opt?;
                if !existing.contains(&nm) && is_persistable_task_local_ty(&ty, &env) {
                    Some((nm, ty))
                } else {
                    None
                }
            })
            .collect();
        extras.sort_by(|a, b| a.0.cmp(&b.0));
        if !extras.is_empty() {
            task.live_across_wait.extend(extras);
            let is_sparse = task.is_sparse
                || (task.state_layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET)
                    != 0;
            let reqs = task.state_layout.required_components.clone();
            if let Ok(mut solved) = solve_task_state_layout(
                &task.state_layout.canonical_name,
                &task.live_across_wait,
                is_sparse,
                &env,
            ) {
                solved.required_components = reqs;
                task.state_layout = solved.clone();
                updated_task_layouts.push(solved);
            }
        }
    }
    for sl in &updated_task_layouts {
        replace_module_layout(module, sl);
    }

    // 2. Extend `fsm` state layouts with persisted per-state fields (`__st_{idx}_{field}`).
    let mut updated_fsm_layouts = Vec::new();
    for fsm in &mut module.fsms {
        let has_state_fields = fsm.state_hooks.iter().any(|h| !h.fields.is_empty());
        if !has_state_fields {
            continue;
        }
        let hooks_by_name: HashMap<&str, _> = fsm
            .state_hooks
            .iter()
            .map(|h| (h.name.as_str(), h))
            .collect();
        let mut fields = vec![
            ("__state".to_owned(), Ty::U16),
            ("__flags".to_owned(), Ty::U16),
        ];
        for (s_idx, sname) in fsm.states.iter().enumerate() {
            if let Some(hook) = hooks_by_name.get(sname.as_str()) {
                for (fnm, fty, _) in &hook.fields {
                    fields.push((fsm_state_field_key(s_idx, fnm), fty.clone()));
                }
            }
        }
        if let Ok(solved) = solve_pod_layout(
            &fsm.state_layout.canonical_name,
            SchemaItemKind::FsmState,
            &fields,
            fsm.state_layout.component_flags,
            fsm.state_layout.required_components.clone(),
            &env,
        ) {
            fsm.state_layout = solved.clone();
            updated_fsm_layouts.push(solved);
        }
    }
    for sl in &updated_fsm_layouts {
        replace_module_layout(module, sl);
    }
}

fn split_task_aborts(body: &[HirStmt]) -> (Vec<(HirExpr, Vec<HirStmt>)>, Vec<HirStmt>) {
    let mut aborts = Vec::new();
    let mut exec = Vec::new();
    for stmt in body {
        match stmt {
            HirStmt::AbortIf { cond, cleanup } => aborts.push((cond.clone(), cleanup.clone())),
            other => exec.push(other.clone()),
        }
    }
    (aborts, exec)
}

fn expr_contains_suspension(expr: &HirExpr) -> bool {
    match expr {
        HirExpr::If {
            then_stmts,
            then_tail,
            else_stmts,
            else_tail,
            ..
        } => {
            stmts_contain_suspension(then_stmts)
                || then_tail.as_deref().is_some_and(expr_contains_suspension)
                || stmts_contain_suspension(else_stmts)
                || else_tail.as_deref().is_some_and(expr_contains_suspension)
        }
        HirExpr::Block { stmts, tail, .. } => {
            stmts_contain_suspension(stmts) || tail.as_deref().is_some_and(expr_contains_suspension)
        }
        HirExpr::Match(m) => m.arms.iter().any(|arm| expr_contains_suspension(&arm.body)),
        _ => false,
    }
}

fn stmt_contains_suspension(stmt: &HirStmt) -> bool {
    match stmt {
        HirStmt::Wait(_) | HirStmt::WaitUntil(_) | HirStmt::YieldTick | HirStmt::Race { .. } => {
            true
        }
        HirStmt::While { body, .. } | HirStmt::Loop { body } => stmts_contain_suspension(body),
        HirStmt::Expr(e) => expr_contains_suspension(e),
        _ => false,
    }
}

fn stmts_contain_suspension(stmts: &[HirStmt]) -> bool {
    stmts.iter().any(stmt_contains_suspension)
}

fn sync_live_vars_to_persist_slots(b: &mut CfgBuilder<'_>, tctx: &TaskLowerCtx) {
    for pf in &tctx.persist_fields {
        match b.vars.get(&pf.var_name).cloned() {
            Some(VarSlot::Slot { slot_local, .. }) if slot_local != pf.persist_slot => {
                let v = b.alloc_and_emit(
                    &format!("sync_{}", pf.var_name),
                    pf.ty.clone(),
                    Inst::SlotLoad { slot: slot_local },
                );
                b.emit_void(Inst::SlotStore {
                    slot: pf.persist_slot,
                    val: v,
                });
            }
            Some(VarSlot::Imm { local, .. }) => {
                b.emit_void(Inst::SlotStore {
                    slot: pf.persist_slot,
                    val: local,
                });
            }
            _ => {}
        }
    }
}

fn emit_writeback_live_vars(b: &mut CfgBuilder<'_>, tctx: &TaskLowerCtx) {
    sync_live_vars_to_persist_slots(b, tctx);
    for pf in &tctx.persist_fields {
        let v = b.alloc_and_emit(
            &format!("wb_{}", pf.var_name),
            pf.ty.clone(),
            Inst::SlotLoad {
                slot: pf.persist_slot,
            },
        );
        b.emit_void(Inst::FieldStore {
            base_ptr: tctx.state_ptr,
            layout_key: tctx.layout_key.clone(),
            field: pf.field_name.clone(),
            offset_bytes: pf.offset_bytes,
            val: v,
        });
    }
}

fn store_pc_const(b: &mut CfgBuilder<'_>, tctx: &TaskLowerCtx, pc: u8) {
    let nxt = b.alloc_and_emit(
        "next_pc",
        MirType::U8,
        Inst::ConstInt {
            value: i64::from(pc),
        },
    );
    b.emit_void(Inst::FieldStore {
        base_ptr: tctx.state_ptr,
        layout_key: tctx.layout_key.clone(),
        field: "__pc".to_owned(),
        offset_bytes: tctx.pc_off,
        val: nxt,
    });
}

fn store_timer_zero(b: &mut CfgBuilder<'_>, tctx: &TaskLowerCtx) {
    let zf = b.alloc_and_emit("tmr_z", MirType::F32, Inst::ConstFloat { value: 0.0 });
    b.emit_void(Inst::FieldStore {
        base_ptr: tctx.state_ptr,
        layout_key: tctx.layout_key.clone(),
        field: "__timer".to_owned(),
        offset_bytes: tctx.tmr_off,
        val: zf,
    });
}

fn lower_task_suspending_expr(b: &mut CfgBuilder<'_>, tctx: &mut TaskLowerCtx, expr: &HirExpr) {
    if !expr_contains_suspension(expr) {
        let _ = b.lower_expr(expr);
        return;
    }
    match expr {
        HirExpr::Block { stmts, tail, .. } => {
            lower_task_stmts(b, tctx, stmts);
            if !b.cur_terminated
                && let Some(t) = tail
            {
                lower_task_suspending_expr(b, tctx, t);
            }
        }
        HirExpr::If {
            let_pat: None,
            cond,
            then_stmts,
            then_tail,
            else_stmts,
            else_tail,
            ..
        } => {
            let (join_pc, join_bb) = tctx.alloc_state(b, "task_if_join");
            let (cond_l, _) = b.lower_expr(cond);
            let saved_vars = b.vars.clone();
            let then_bb = b.new_block("task_if_then");
            let else_bb = b.new_block("task_if_else");
            b.terminate(Terminator::Branch {
                cond: cond_l,
                then_bb,
                else_bb,
            });

            b.switch_to(then_bb);
            b.vars = saved_vars.clone();
            lower_task_stmts(b, tctx, then_stmts);
            if !b.cur_terminated
                && let Some(tt) = then_tail
            {
                lower_task_suspending_expr(b, tctx, tt);
            }
            if !b.cur_terminated {
                sync_live_vars_to_persist_slots(b, tctx);
                store_pc_const(b, tctx, join_pc);
                b.terminate(Terminator::Goto(join_bb));
            }

            b.switch_to(else_bb);
            b.vars = saved_vars;
            lower_task_stmts(b, tctx, else_stmts);
            if !b.cur_terminated
                && let Some(et) = else_tail
            {
                lower_task_suspending_expr(b, tctx, et);
            }
            if !b.cur_terminated {
                sync_live_vars_to_persist_slots(b, tctx);
                store_pc_const(b, tctx, join_pc);
                b.terminate(Terminator::Goto(join_bb));
            }

            b.switch_to(join_bb);
            b.vars = tctx.live_base_vars.clone();
            tctx.cur_pc = join_pc;
        }
        HirExpr::Match(m) => {
            // Fallback for match arms with suspensions: lower match directly if non-suspending.
            let _ = m;
            let _ = b.lower_expr(expr);
        }
        _ => {
            let _ = b.lower_expr(expr);
        }
    }
}

fn lower_task_stmts(b: &mut CfgBuilder<'_>, tctx: &mut TaskLowerCtx, stmts: &[HirStmt]) {
    for stmt in stmts {
        if b.cur_terminated {
            return;
        }
        if !stmt_contains_suspension(stmt) {
            match stmt {
                HirStmt::Return(_) => {
                    b.emit_void(Inst::CmdRemove {
                        entity: tctx.row_ent,
                        component: tctx.task_name.clone(),
                    });
                    b.terminate(Terminator::Goto(tctx.row_inc));
                }
                HirStmt::Break(_) if !tctx.loop_targets.is_empty() => {
                    let brk = tctx.loop_targets.last().unwrap().0;
                    b.terminate(Terminator::Goto(brk));
                }
                HirStmt::Continue if !tctx.loop_targets.is_empty() => {
                    let cont = tctx.loop_targets.last().unwrap().1;
                    b.terminate(Terminator::Goto(cont));
                }
                _ => b.lower_stmt(stmt),
            }
            continue;
        }
        match stmt {
            HirStmt::YieldTick => {
                let (next_pc, next_bb) = tctx.alloc_state(b, "task_yield_resume");
                emit_writeback_live_vars(b, tctx);
                store_pc_const(b, tctx, next_pc);
                b.terminate(Terminator::Goto(tctx.row_inc));
                b.switch_to(next_bb);
                b.vars = tctx.live_base_vars.clone();
                tctx.cur_pc = next_pc;
            }
            HirStmt::Wait(dur_expr) => {
                let (wait_pc, wait_bb) = tctx.alloc_state(b, "task_wait");
                let (done_pc, done_bb) = tctx.alloc_state(b, "task_wait_done");

                // On first entry: arm `__timer = 0.0`, `__pc = wait_pc`, persist locals, and
                // suspend until next tick so `wait` never expires on entry tick (`GF-04`).
                store_timer_zero(b, tctx);
                store_pc_const(b, tctx, wait_pc);
                emit_writeback_live_vars(b, tctx);
                b.terminate(Terminator::Goto(tctx.row_inc));

                b.switch_to(wait_bb);
                b.vars = tctx.live_base_vars.clone();
                let (dur_val, _) = b.lower_expr(dur_expr);
                let elapsed = b.alloc_and_emit(
                    "wait_elapsed",
                    MirType::F32,
                    Inst::BinOp {
                        op: "+".to_owned(),
                        lhs: tctx.timer_local,
                        rhs: tctx.dt_sec,
                        allow_fma: false,
                    },
                );
                let is_done = b.alloc_and_emit(
                    "wait_done",
                    MirType::Bool,
                    Inst::BinOp {
                        op: ">=".to_owned(),
                        lhs: elapsed,
                        rhs: dur_val,
                        allow_fma: false,
                    },
                );
                let wait_done_tr_bb = b.new_block(&format!("wait_done_tr_{wait_pc}"));
                let wait_tick_bb = b.new_block(&format!("wait_tick_{wait_pc}"));
                b.terminate(Terminator::Branch {
                    cond: is_done,
                    then_bb: wait_done_tr_bb,
                    else_bb: wait_tick_bb,
                });

                b.switch_to(wait_done_tr_bb);
                store_timer_zero(b, tctx);
                store_pc_const(b, tctx, done_pc);
                b.terminate(Terminator::Goto(done_bb));

                b.switch_to(wait_tick_bb);
                b.emit_void(Inst::FieldStore {
                    base_ptr: tctx.state_ptr,
                    layout_key: tctx.layout_key.clone(),
                    field: "__timer".to_owned(),
                    offset_bytes: tctx.tmr_off,
                    val: elapsed,
                });
                emit_writeback_live_vars(b, tctx);
                b.terminate(Terminator::Goto(tctx.row_inc));

                b.switch_to(done_bb);
                b.vars = tctx.live_base_vars.clone();
                tctx.cur_pc = done_pc;
            }
            HirStmt::WaitUntil(cond_expr) => {
                let (wait_pc, wait_bb) = tctx.alloc_state(b, "task_wuntil");
                let (done_pc, done_bb) = tctx.alloc_state(b, "task_wuntil_done");

                emit_writeback_live_vars(b, tctx);
                store_pc_const(b, tctx, wait_pc);
                b.terminate(Terminator::Goto(wait_bb));

                b.switch_to(wait_bb);
                b.vars = tctx.live_base_vars.clone();
                let (wcond, _) = b.lower_expr(cond_expr);
                let adv_bb = b.new_block(&format!("wuntil_adv_{wait_pc}"));
                b.terminate(Terminator::Branch {
                    cond: wcond,
                    then_bb: adv_bb,
                    else_bb: tctx.row_inc,
                });

                b.switch_to(adv_bb);
                store_pc_const(b, tctx, done_pc);
                b.terminate(Terminator::Goto(done_bb));

                b.switch_to(done_bb);
                b.vars = tctx.live_base_vars.clone();
                tctx.cur_pc = done_pc;
            }
            HirStmt::Race { branches } => {
                let (race_pc, race_bb) = tctx.alloc_state(b, "task_race");
                let (after_pc, after_bb) = tctx.alloc_state(b, "task_race_after");
                let race_timer_slot = b
                    .func
                    .alloc_local(format!("race_tmr_{race_pc}"), MirType::MutPtr);
                b.func.blocks[tctx.alloc_bb.0 as usize].stmts.push(MirStmt {
                    dst: Some(race_timer_slot),
                    inst: Inst::SlotAlloc { ty: MirType::F32 },
                });
                let race_check_bb = b.new_block(&format!("race_chk_{race_pc}"));
                let miss_bb = b.new_block(&format!("race_miss_{race_pc}"));

                // First entry: reset persisted `__timer = 0.0`, arm `__pc = race_pc`, write back
                // live vars, and evaluate immediate triggers (`wait_until`) with `elapsed = 0.0`.
                store_timer_zero(b, tctx);
                store_pc_const(b, tctx, race_pc);
                emit_writeback_live_vars(b, tctx);
                let zero_f =
                    b.alloc_and_emit("race_z0", MirType::F32, Inst::ConstFloat { value: 0.0 });
                b.emit_void(Inst::SlotStore {
                    slot: race_timer_slot,
                    val: zero_f,
                });
                b.terminate(Terminator::Goto(race_check_bb));

                // Subsequent ticks: accumulate `timer_local + dt_sec` before checking branches.
                b.switch_to(race_bb);
                b.vars = tctx.live_base_vars.clone();
                let next_elapsed = b.alloc_and_emit(
                    "race_next_t",
                    MirType::F32,
                    Inst::BinOp {
                        op: "+".to_owned(),
                        lhs: tctx.timer_local,
                        rhs: tctx.dt_sec,
                        allow_fma: false,
                    },
                );
                b.emit_void(Inst::SlotStore {
                    slot: race_timer_slot,
                    val: next_elapsed,
                });
                b.terminate(Terminator::Goto(race_check_bb));

                b.switch_to(race_check_bb);
                if branches.is_empty() {
                    b.terminate(Terminator::Goto(miss_bb));
                } else {
                    for (bi, br_stmts) in branches.iter().enumerate() {
                        b.vars = tctx.live_base_vars.clone();
                        let cur_elapsed = b.alloc_and_emit(
                            &format!("race_el_{bi}"),
                            MirType::F32,
                            Inst::SlotLoad {
                                slot: race_timer_slot,
                            },
                        );
                        let win_bb = b.new_block(&format!("race_{race_pc}_win_{bi}"));
                        let next_chk = if bi + 1 == branches.len() {
                            miss_bb
                        } else {
                            b.new_block(&format!("race_{race_pc}_chk_{}", bi + 1))
                        };
                        let (fired, tail_stmts) =
                            evaluate_race_branch_cond(b, br_stmts, cur_elapsed);
                        b.terminate(Terminator::Branch {
                            cond: fired,
                            then_bb: win_bb,
                            else_bb: next_chk,
                        });

                        b.switch_to(win_bb);
                        b.vars = tctx.live_base_vars.clone();
                        store_timer_zero(b, tctx);
                        lower_task_stmts(b, tctx, &tail_stmts);
                        if !b.cur_terminated {
                            sync_live_vars_to_persist_slots(b, tctx);
                            store_pc_const(b, tctx, after_pc);
                            b.terminate(Terminator::Goto(after_bb));
                        }
                        if next_chk != miss_bb {
                            b.switch_to(next_chk);
                        }
                    }
                }

                // No branch fired: persist accumulated elapsed timer (`__timer`) and live vars!
                b.switch_to(miss_bb);
                b.vars = tctx.live_base_vars.clone();
                let save_el = b.alloc_and_emit(
                    "race_save_t",
                    MirType::F32,
                    Inst::SlotLoad {
                        slot: race_timer_slot,
                    },
                );
                b.emit_void(Inst::FieldStore {
                    base_ptr: tctx.state_ptr,
                    layout_key: tctx.layout_key.clone(),
                    field: "__timer".to_owned(),
                    offset_bytes: tctx.tmr_off,
                    val: save_el,
                });
                emit_writeback_live_vars(b, tctx);
                b.terminate(Terminator::Goto(tctx.row_inc));

                b.switch_to(after_bb);
                b.vars = tctx.live_base_vars.clone();
                tctx.cur_pc = after_pc;
            }
            HirStmt::Expr(expr) => lower_task_suspending_expr(b, tctx, expr),
            HirStmt::While { cond, body } => {
                let (hdr_pc, hdr_bb) = tctx.alloc_state(b, "task_while_hdr");
                let (exit_pc, exit_bb) = tctx.alloc_state(b, "task_while_exit");
                let body_bb = b.new_block(&format!("task_while_body_{hdr_pc}"));
                let leave_bb = b.new_block(&format!("task_while_leave_{hdr_pc}"));
                let break_proxy = b.new_block(&format!("task_while_brk_{hdr_pc}"));
                let cont_proxy = b.new_block(&format!("task_while_cont_{hdr_pc}"));

                sync_live_vars_to_persist_slots(b, tctx);
                store_pc_const(b, tctx, hdr_pc);
                b.terminate(Terminator::Goto(hdr_bb));

                b.switch_to(break_proxy);
                sync_live_vars_to_persist_slots(b, tctx);
                store_pc_const(b, tctx, exit_pc);
                b.terminate(Terminator::Goto(exit_bb));

                b.switch_to(cont_proxy);
                sync_live_vars_to_persist_slots(b, tctx);
                store_pc_const(b, tctx, hdr_pc);
                b.terminate(Terminator::Goto(hdr_bb));

                b.switch_to(leave_bb);
                store_pc_const(b, tctx, exit_pc);
                b.terminate(Terminator::Goto(exit_bb));

                b.switch_to(hdr_bb);
                b.vars = tctx.live_base_vars.clone();
                let (wcond, _) = b.lower_expr(cond);
                b.terminate(Terminator::Branch {
                    cond: wcond,
                    then_bb: body_bb,
                    else_bb: leave_bb,
                });

                b.switch_to(body_bb);
                b.vars = tctx.live_base_vars.clone();
                tctx.loop_targets.push((break_proxy, cont_proxy));
                lower_task_stmts(b, tctx, body);
                tctx.loop_targets.pop();
                if !b.cur_terminated {
                    b.terminate(Terminator::Goto(cont_proxy));
                }

                b.switch_to(exit_bb);
                b.vars = tctx.live_base_vars.clone();
                tctx.cur_pc = exit_pc;
            }
            HirStmt::Loop { body } => {
                let (hdr_pc, hdr_bb) = tctx.alloc_state(b, "task_loop_hdr");
                let (exit_pc, exit_bb) = tctx.alloc_state(b, "task_loop_exit");
                let break_proxy = b.new_block(&format!("task_loop_brk_{hdr_pc}"));
                let cont_proxy = b.new_block(&format!("task_loop_cont_{hdr_pc}"));

                sync_live_vars_to_persist_slots(b, tctx);
                store_pc_const(b, tctx, hdr_pc);
                b.terminate(Terminator::Goto(hdr_bb));

                b.switch_to(break_proxy);
                sync_live_vars_to_persist_slots(b, tctx);
                store_pc_const(b, tctx, exit_pc);
                b.terminate(Terminator::Goto(exit_bb));

                b.switch_to(cont_proxy);
                sync_live_vars_to_persist_slots(b, tctx);
                store_pc_const(b, tctx, hdr_pc);
                b.terminate(Terminator::Goto(hdr_bb));

                b.switch_to(hdr_bb);
                b.vars = tctx.live_base_vars.clone();
                tctx.loop_targets.push((break_proxy, cont_proxy));
                lower_task_stmts(b, tctx, body);
                tctx.loop_targets.pop();
                if !b.cur_terminated {
                    b.terminate(Terminator::Goto(cont_proxy));
                }

                b.switch_to(exit_bb);
                b.vars = tctx.live_base_vars.clone();
                tctx.cur_pc = exit_pc;
            }
            other => b.lower_stmt(other),
        }
    }
}

fn evaluate_race_branch_cond(
    b: &mut CfgBuilder<'_>,
    stmts: &[HirStmt],
    elapsed: LocalId,
) -> (LocalId, Vec<HirStmt>) {
    let mut rest = Vec::new();
    let mut cond_out = None;
    for (idx, s) in stmts.iter().enumerate() {
        match s {
            HirStmt::Wait(dur) if cond_out.is_none() => {
                let (dur_v, _) = b.lower_expr(dur);
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
            HirStmt::Loop { body } if cond_out.is_none() && stmts_contain_suspension(body) => {
                // Continuous racing loop (`loop { ...; yield_tick; }`): run non-suspending per-tick
                // body statements without infinite intra-tick looping; keep race open.
                for inner in body {
                    if !matches!(inner, HirStmt::YieldTick) && !stmt_contains_suspension(inner) {
                        b.lower_stmt(inner);
                    }
                }
                cond_out = Some(b.alloc_and_emit(
                    "race_loop_wait",
                    MirType::Bool,
                    Inst::ConstBool { value: false },
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

fn bind_fsm_state_vars(
    b: &mut CfgBuilder<'_>,
    base_vars: &HashMap<String, VarSlot>,
    fields: &[FsmPersistField],
) {
    b.vars = base_vars.clone();
    for pf in fields {
        b.vars.insert(
            pf.user_name.clone(),
            VarSlot::Slot {
                slot_local: pf.slot_local,
                ty: pf.ty.clone(),
            },
        );
    }
}

fn emit_typed_zero(b: &mut CfgBuilder<'_>, ty: &MirType) -> LocalId {
    match ty {
        MirType::Bool => b.alloc_and_emit("zf", MirType::Bool, Inst::ConstBool { value: false }),
        MirType::F32 | MirType::F64 => {
            b.alloc_and_emit("zf", ty.clone(), Inst::ConstFloat { value: 0.0 })
        }
        MirType::Vec2 | MirType::IVec2 | MirType::UVec2 => b.alloc_and_emit(
            "zv2",
            ty.clone(),
            Inst::ConstVec {
                dims: 2,
                values: [0.0; 4],
            },
        ),
        MirType::Vec3 | MirType::IVec3 => b.alloc_and_emit(
            "zv3",
            ty.clone(),
            Inst::ConstVec {
                dims: 3,
                values: [0.0; 4],
            },
        ),
        MirType::Vec4 => b.alloc_and_emit(
            "zv4",
            ty.clone(),
            Inst::ConstVec {
                dims: 4,
                values: [0.0; 4],
            },
        ),
        MirType::Array { elem, len } => {
            let mut elems = Vec::with_capacity(*len);
            for _ in 0..*len {
                elems.push(emit_typed_zero(b, elem));
            }
            b.alloc_and_emit("zarr", ty.clone(), Inst::ArrayInit { elems })
        }
        _ => b.alloc_and_emit("zi", ty.clone(), Inst::ConstInt { value: 0 }),
    }
}

fn init_fsm_state_fields(
    b: &mut CfgBuilder<'_>,
    rptr: LocalId,
    layout_key: &str,
    fields: &[FsmPersistField],
) {
    for pf in fields {
        let init_l = if let Some(def) = &pf.default_expr {
            b.lower_expr(def).0
        } else {
            emit_typed_zero(b, &pf.ty)
        };
        b.emit_void(Inst::SlotStore {
            slot: pf.slot_local,
            val: init_l,
        });
        b.emit_void(Inst::FieldStore {
            base_ptr: rptr,
            layout_key: layout_key.to_owned(),
            field: pf.layout_field.clone(),
            offset_bytes: pf.offset_bytes,
            val: init_l,
        });
    }
}

fn load_fsm_state_fields(
    b: &mut CfgBuilder<'_>,
    rptr: LocalId,
    layout_key: &str,
    fields: &[FsmPersistField],
) {
    for pf in fields {
        let loaded = b.alloc_and_emit(
            &format!("ld_{}", pf.user_name),
            pf.ty.clone(),
            Inst::FieldLoad {
                base_ptr: rptr,
                layout_key: layout_key.to_owned(),
                field: pf.layout_field.clone(),
                offset_bytes: pf.offset_bytes,
                field_ty: pf.ty.clone(),
            },
        );
        b.emit_void(Inst::SlotStore {
            slot: pf.slot_local,
            val: loaded,
        });
    }
}

fn persist_fsm_state_fields(
    b: &mut CfgBuilder<'_>,
    rptr: LocalId,
    layout_key: &str,
    fields: &[FsmPersistField],
) {
    for pf in fields {
        let cur_slot = match b.vars.get(&pf.user_name) {
            Some(VarSlot::Slot { slot_local, .. }) => *slot_local,
            _ => pf.slot_local,
        };
        let v = b.alloc_and_emit(
            &format!("st_wb_{}", pf.user_name),
            pf.ty.clone(),
            Inst::SlotLoad { slot: cur_slot },
        );
        if cur_slot != pf.slot_local {
            b.emit_void(Inst::SlotStore {
                slot: pf.slot_local,
                val: v,
            });
        }
        b.emit_void(Inst::FieldStore {
            base_ptr: rptr,
            layout_key: layout_key.to_owned(),
            field: pf.layout_field.clone(),
            offset_bytes: pf.offset_bytes,
            val: v,
        });
    }
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

    fn lower_and_verify_src(src: &str) -> MirModule {
        let sema = strata_sema::analyze_source("sm_test.strata", src);
        let errs: Vec<_> = sema
            .diagnostics
            .iter()
            .filter(|d| matches!(d.severity, strata_sema::Severity::Error))
            .collect();
        assert!(errs.is_empty(), "sema errors: {errs:?}");
        let mir = crate::lower_to_mir(&sema);
        verify_mir(&mir).expect("synthesized MIR must verify cleanly");
        mir
    }

    /// GF-04: Verifies `task` accumulates `wait` timer upward without leaking duration, persists
    /// `race { wait }` timer back to `__timer`, writes back modified `live_across_wait` params &
    /// locals before suspending, and suspends `yield_tick` inside `if` branches properly.
    #[test]
    fn task_wait_race_live_writeback_and_if_branch_yield() {
        let src = r#"
component Actor {
    flag: bool = true,
    ticks: u32 = 0,
    branch_val: i32 = 0,
    kept_param: i32 = 0,
    kept_local: i32 = 0,
    won_wait: bool = false,
}

task FullCoroutine(start_val: i32)
    on (a: &mut Actor)
{
    start_val += 10;
    let saved = 77;
    wait 0.2_s;
    if a.flag {
        a.branch_val = 10;
        yield_tick;
        a.branch_val = 20;
    }
    a.ticks += 100_u32;
    race {
        branch {
            wait 0.1_s;
            a.won_wait = true;
            a.kept_param = start_val;
            a.kept_local = saved;
        }
        branch {
            wait_until false;
            a.won_wait = false;
        }
    }
}
"#;
        let mir = lower_and_verify_src(src);
        let f = mir
            .functions
            .iter()
            .find(|f| f.name == "FullCoroutine")
            .expect("FullCoroutine task fn");

        // `saved` (unannotated `let saved = 77`) and `start_val` must both be in `TaskState` layout
        // and written back via `FieldStore` before suspending!
        let tk = mir
            .tasks
            .iter()
            .find(|t| t.name == "FullCoroutine")
            .unwrap();
        assert!(
            tk.live_across_wait.iter().any(|(n, _)| n == "saved"),
            "inferred `let saved` must persist across wait: {:?}",
            tk.live_across_wait
        );
        let state_key = &tk.state_layout.canonical_name;
        for fname in ["start_val", "saved"] {
            let writes = f
                .blocks
                .iter()
                .flat_map(|b| &b.stmts)
                .filter(|s| {
                    matches!(
                        &s.inst,
                        Inst::FieldStore {
                            layout_key,
                            field,
                            ..
                        } if layout_key == state_key && field == fname
                    )
                })
                .count();
            assert!(
                writes >= 1,
                "live variable `{fname}` must be written back to `{state_key}` before suspension"
            );
        }

        // Wait must accumulate with `+` and compare `>=` (never store `dur_val` directly into
        // `__timer` upon wait completion or subtract from `0.0`).
        let wait_bb = f
            .blocks
            .iter()
            .find(|b| b.label.starts_with("task_wait_") && !b.label.contains("done"))
            .expect("missing task_wait state");
        assert!(wait_bb.stmts.iter().any(|s| matches!(
            &s.inst,
            Inst::BinOp { op, .. } if op == "+"
        )));
        assert!(wait_bb.stmts.iter().any(|s| matches!(
            &s.inst,
            Inst::BinOp { op, .. } if op == ">="
        )));

        // `race_miss_*` must store accumulated timer back into `__timer`.
        let race_miss = f
            .blocks
            .iter()
            .find(|b| b.label.starts_with("race_miss_"))
            .expect("missing race_miss block");
        assert!(race_miss.stmts.iter().any(|s| matches!(
            &s.inst,
            Inst::FieldStore { field, .. } if field == "__timer"
        )));

        // `yield_tick` inside `if a.flag` must split `task_if_then` into separate resume state
        // before `task_if_join` (`a.ticks += 100`), rather than lowering `yield_tick` as a no-op.
        let then_bb = f
            .blocks
            .iter()
            .find(|b| b.label == "task_if_then")
            .expect("missing task_if_then");
        assert!(
            matches!(then_bb.terminator, Terminator::Goto(target) if f.blocks[target.0 as usize].label == "task_row_inc")
        );
        assert!(
            f.blocks
                .iter()
                .any(|b| b.label.starts_with("task_yield_resume_")),
            "expected dedicated resume state inside `if` branch"
        );
        assert!(
            f.blocks
                .iter()
                .any(|b| b.label.starts_with("task_if_join_")),
            "expected post-if continuation join state"
        );
    }

    /// GF-05a: FSM state-local fields persist across ticks inside `fsm.state_layout` and are
    /// initialized on state entry (`on_enter`) rather than reset on every `on_tick`.
    #[test]
    fn fsm_state_local_fields_persist_across_ticks_and_init_on_enter() {
        let src = r#"
component Marker { tag_v: i32 = 0 }
resource Out { b_timer: i32 = 0 }

fsm CounterFsm(out: &mut res Out) @require(Marker) {
    initial StateA;
    state StateA {
        to StateB when true;
    }
    state StateB {
        local_cnt: i32 = 0,
        on_enter {
            local_cnt = 10;
            out.b_timer = local_cnt;
        }
        on_tick {
            local_cnt += 1;
            out.b_timer = local_cnt;
        }
        to StateA when false;
    }
}
"#;
        let mir = lower_and_verify_src(src);
        let fsm = mir
            .fsms
            .iter()
            .find(|f| f.name == "CounterFsm")
            .expect("CounterFsm missing");
        let st_field = fsm
            .state_layout
            .fields
            .iter()
            .find(|f| f.name == "__st_1_local_cnt")
            .expect("FSM state_layout must persist StateB's `local_cnt`");
        assert!(fsm.state_layout.size >= 8);

        let fn_mir = mir
            .functions
            .iter()
            .find(|f| f.name == "CounterFsm")
            .expect("CounterFsm fn missing");
        let load_bb = fn_mir
            .blocks
            .iter()
            .find(|b| b.label == "fsm_StateB_load")
            .expect("expected StateB field reload block on subsequent ticks");
        assert!(load_bb.stmts.iter().any(|s| matches!(
            &s.inst,
            Inst::FieldLoad { field, offset_bytes, .. }
                if field == &st_field.name && *offset_bytes == st_field.offset as u32
        )));

        let tick_bb = fn_mir
            .blocks
            .iter()
            .find(|b| b.label == "fsm_StateB_tick")
            .expect("expected StateB tick block");
        assert!(tick_bb.stmts.iter().any(|s| matches!(
            &s.inst,
            Inst::FieldStore { field, offset_bytes, .. }
                if field == &st_field.name && *offset_bytes == st_field.offset as u32
        )));
    }
}
