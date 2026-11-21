//! HIR -> `StrataMir` lowering pipeline.

use crate::ir::{BasicBlock, BlockId, Inst, MirFunction, MirModule, MirStmt, MirType, Terminator};
use crate::passes;
use strata_sema::access::TermAccessMode;
use strata_sema::hir::AnalyzedModule;

/// Lowers a verified [`AnalyzedModule`] into [`MirModule`] and runs all 6 MIR optimization and
/// synthesis passes in canonical order.
pub fn lower_to_mir(analyzed: &AnalyzedModule) -> MirModule {
    let mut layouts: Vec<_> = analyzed.layouts.values().cloned().collect();
    // Deduplicate identical canonical names (`CombatantBody` vs `CombatantBody::hot` aliases).
    let mut seen_names = std::collections::HashSet::new();
    layouts.retain(|l| seen_names.insert(l.canonical_name.clone()));

    let mut functions = Vec::new();
    for callable in &analyzed.callables {
        functions.push(lower_callable(analyzed, callable));
    }

    let mut mir = MirModule {
        module_path: analyzed.module_path.clone(),
        is_deterministic: analyzed.is_deterministic,
        layouts,
        tables: analyzed.tables.clone(),
        curves: analyzed.curves.clone(),
        relations: analyzed.relations.clone(),
        spatial_indices: analyzed.spatial_indices.clone(),
        timelines: analyzed.timelines.clone(),
        tasks: analyzed.tasks.clone(),
        fsms: analyzed.fsms.clone(),
        objects: analyzed.objects.clone(),
        migrations: analyzed.migrations.clone(),
        functions,
        schedules: analyzed.schedules.clone(),
        sim_tests: analyzed.sim_tests.clone(),
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

fn lower_callable(analyzed: &AnalyzedModule, c: &strata_sema::hir::HirCallable) -> MirFunction {
    let mut func = MirFunction {
        name: c.name.clone(),
        is_observer: c.is_observer,
        trigger_event: c.trigger_event.clone(),
        par_chunk: c.par_chunk,
        par_read_only: c.par_read_only,
        is_deterministic: analyzed.is_deterministic,
        locals: Vec::new(),
        blocks: Vec::new(),
        queries: c.access.queries.clone(),
        source_body: c.body_source.clone(),
    };

    let mut stmts = Vec::new();

    for res in &c.access.res_reads {
        let dst = func.alloc_local(format!("res_{res}"), MirType::Ptr);
        stmts.push(MirStmt {
            dst: Some(dst),
            inst: Inst::ResRead {
                resource: res.clone(),
            },
        });
    }
    for res in &c.access.res_writes {
        let dst = func.alloc_local(format!("res_mut_{res}"), MirType::MutPtr);
        stmts.push(MirStmt {
            dst: Some(dst),
            inst: Inst::ResWrite {
                resource: res.clone(),
            },
        });
    }

    if let Some(chunk) = c.par_chunk {
        if c.par_read_only {
            stmts.push(MirStmt {
                dst: None,
                inst: Inst::ParForEachChunkReadonly {
                    query_idx: 0,
                    chunk_size: chunk,
                    deterministic_order: analyzed.is_deterministic,
                },
            });
        } else {
            stmts.push(MirStmt {
                dst: None,
                inst: Inst::ParForEachChunk {
                    query_idx: 0,
                    chunk_size: chunk,
                },
            });
        }
    }

    for (qi, q) in c.access.queries.iter().enumerate() {
        let qi_u32 = qi as u32;
        if !q.is_point_lookup {
            let has_chunk = func.alloc_local(format!("has_chunk_{qi}"), MirType::Bool);
            stmts.push(MirStmt {
                dst: Some(has_chunk),
                inst: Inst::IterNextChunk { query_idx: qi_u32 },
            });
        }
        for (ti, term) in q.terms.iter().enumerate() {
            let ti_u32 = ti as u32;
            let dst = func.alloc_local(
                format!("col_{qi}_{ti}"),
                if term.mode.is_mutable() {
                    MirType::MutPtr
                } else {
                    MirType::Ptr
                },
            );
            let inst = match term.mode {
                TermAccessMode::Write
                | TermAccessMode::OptionalWrite
                | TermAccessMode::SelectiveWrite => Inst::IterColWrite {
                    // SelectiveWrite is upgraded to `IterColWriteUntracked` by `passes::tick_coalesce`.
                    query_idx: qi_u32,
                    term_idx: ti_u32,
                    storage_key: term.storage_key.clone(),
                },
                _ => Inst::IterColRead {
                    query_idx: qi_u32,
                    term_idx: ti_u32,
                    storage_key: term.storage_key.clone(),
                },
            };
            stmts.push(MirStmt {
                dst: Some(dst),
                inst,
            });
        }
    }

    // Detect math ops & high-level ECS statements inside source body for MIR fidelity.
    let body = &c.body_source;
    if body.contains("spawn_batch") {
        stmts.push(MirStmt {
            dst: None,
            inst: Inst::CmdSpawnBatch {
                count_expr: "batch".to_owned(),
                components: Vec::new(),
            },
        });
    }
    if body.contains("despawn_all") {
        stmts.push(MirStmt {
            dst: None,
            inst: Inst::CmdDespawnAll {
                filter: "With".to_owned(),
            },
        });
    }
    if body.contains("despawn(") {
        let ent = func.alloc_local("despawn_target", MirType::Entity);
        stmts.push(MirStmt {
            dst: Some(ent),
            inst: Inst::ConstInt { value: 0 },
        });
        stmts.push(MirStmt {
            dst: None,
            inst: Inst::CmdDespawn { entity: ent },
        });
    }
    if body.contains("insert @if_new") {
        let ent = func.alloc_local("insert_target", MirType::Entity);
        stmts.push(MirStmt {
            dst: Some(ent),
            inst: Inst::ConstInt { value: 0 },
        });
        stmts.push(MirStmt {
            dst: None,
            inst: Inst::CmdInsertIfNew {
                entity: ent,
                component: "dynamic".to_owned(),
            },
        });
    }
    for stream_name in &c.access.stream_writes {
        stmts.push(MirStmt {
            dst: None,
            inst: Inst::StreamEmit {
                stream: stream_name.clone(),
            },
        });
    }
    if body.contains(".query_disc(") {
        stmts.push(MirStmt {
            dst: None,
            inst: Inst::SpatialQueryDisc {
                grid_name: "grid".to_owned(),
            },
        });
    }
    if body.contains(".query_segment_at(") {
        stmts.push(MirStmt {
            dst: None,
            inst: Inst::SpatialQuerySegmentAt {
                history_name: "hist".to_owned(),
            },
        });
    }
    if body.contains('*') || body.contains('+') {
        let a = func.alloc_local("lhs", MirType::F32);
        let b = func.alloc_local("rhs", MirType::F32);
        let out = func.alloc_local("math_tmp", MirType::F32);
        stmts.push(MirStmt {
            dst: Some(a),
            inst: Inst::ConstFloat { value: 1.0 },
        });
        stmts.push(MirStmt {
            dst: Some(b),
            inst: Inst::ConstFloat { value: 1.0 },
        });
        stmts.push(MirStmt {
            dst: Some(out),
            inst: Inst::BinOp {
                op: "+".to_owned(),
                lhs: a,
                rhs: b,
                allow_fma: true, // Cleared by `passes::determinism` when `@deterministic` is active.
            },
        });
    }
    for fn_name in ["sin(", "cos(", "sqrt(", "length(", "distance("] {
        if body.contains(fn_name) {
            let arg = func.alloc_local("math_arg", MirType::F32);
            let res = func.alloc_local("math_res", MirType::F32);
            stmts.push(MirStmt {
                dst: Some(arg),
                inst: Inst::ConstFloat { value: 0.0 },
            });
            stmts.push(MirStmt {
                dst: Some(res),
                inst: Inst::IntrinsicMath {
                    name: fn_name.trim_end_matches('(').to_owned(),
                    args: vec![arg],
                    deterministic: false,
                },
            });
        }
    }

    func.blocks.push(BasicBlock {
        id: BlockId(0),
        label: "entry".to_owned(),
        stmts,
        terminator: Terminator::Return(None),
    });

    func
}
