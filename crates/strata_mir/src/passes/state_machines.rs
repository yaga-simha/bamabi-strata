//! Synthesizes concrete MIR tick functions and schedule hooks for `timeline`, stackless
//! `@sparse task` coroutines, and hierarchical `fsm` declarations.

use crate::ir::{BasicBlock, BlockId, Inst, MirFunction, MirModule, MirStmt, MirType, Terminator};
use strata_sema::access::{QueryAccessDesc, QueryTerm, TermAccessMode};

/// Lowers every `timeline`, `task`, and `fsm` in `module` into concrete `MirFunction` tick
/// systems ready for backend code generation.
pub fn run(module: &mut MirModule) {
    // 1. `timeline` -> 16B sparse cursor tick function computing `active_mask` + edge triggers.
    for tl in &module.timelines {
        let mut func = MirFunction {
            name: tl.name.clone(),
            is_observer: false,
            trigger_event: None,
            par_chunk: Some(256),
            par_read_only: false,
            is_deterministic: module.is_deterministic,
            locals: Vec::new(),
            blocks: Vec::new(),
            queries: vec![QueryAccessDesc {
                terms: vec![QueryTerm {
                    storage_key: tl.name.clone(),
                    field_name: None,
                    mode: TermAccessMode::Write,
                    byte_start: 0,
                    byte_end: 0,
                }],
                ..Default::default()
            }],
            source_body: String::new(),
        };

        let rows_ptr = func.alloc_local("tl_rows", MirType::MutPtr);
        let window_masks: Vec<(String, u32, u32, u32)> = tl
            .windows
            .iter()
            .map(|(wname, s, e, bit)| (wname.clone(), *s, *e, 1u32 << (*bit as u32)))
            .collect();

        let mut stmts = vec![
            MirStmt {
                dst: Some(rows_ptr),
                inst: Inst::IterColRowsWrite {
                    query_idx: 0,
                    term_idx: 0,
                    storage_key: tl.name.clone(),
                },
            },
            MirStmt {
                dst: None,
                inst: Inst::TimelineAdvance {
                    timeline: tl.name.clone(),
                    rate_hz: tl.rate_hz,
                    duration_frames: tl.duration_frames,
                    window_masks,
                },
            },
        ];

        for (frame, stmt_src) in &tl.triggers {
            stmts.push(MirStmt {
                dst: None,
                inst: Inst::CmdTrigger {
                    event: format!("at_{frame}f:{stmt_src}"),
                    target: None,
                },
            });
        }

        func.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts,
            terminator: Terminator::Return(None),
        });
        module.functions.push(func);
    }

    // 2. Stackless `@sparse task` -> `__pc` switch state machine + `abort_if` preamble.
    for task in &module.tasks {
        let mut func = MirFunction {
            name: task.name.clone(),
            is_observer: false,
            trigger_event: None,
            par_chunk: None,
            par_read_only: false,
            is_deterministic: module.is_deterministic,
            locals: Vec::new(),
            blocks: Vec::new(),
            queries: task.access.queries.clone(),
            source_body: task.body_source.clone(),
        };

        let pc_local = func.alloc_local("__pc", MirType::U8);
        let timer_local = func.alloc_local("__timer", MirType::F32);
        let rows_local = func.alloc_local("task_rows", MirType::MutPtr);

        let abort_cond = task
            .body_source
            .lines()
            .find(|l| l.trim_start().starts_with("abort_if"))
            .map(|l| l.trim().to_owned());

        let state_count = (task.body_source.matches("wait").count()
            + task.body_source.matches("yield_tick").count()
            + 1) as u32;

        let entry_bb = func.alloc_block("entry", Terminator::Return(None));
        let abort_bb = func.alloc_block("abort_cleanup", Terminator::Return(None));
        let mut state_bbs = Vec::new();
        for s in 0..state_count {
            state_bbs.push((
                s,
                func.alloc_block(format!("state_{s}"), Terminator::Return(None)),
            ));
        }
        let default_bb = state_bbs[0].1;

        func.blocks[entry_bb.0 as usize].stmts.push(MirStmt {
            dst: Some(rows_local),
            inst: Inst::IterColRowsWrite {
                query_idx: 0,
                term_idx: 0,
                storage_key: task.name.clone(),
            },
        });
        func.blocks[entry_bb.0 as usize].stmts.push(MirStmt {
            dst: None,
            inst: Inst::TaskStep {
                task: task.name.clone(),
                pc_local,
                timer_local,
                abort_cond,
                num_states: state_count,
            },
        });
        func.blocks[entry_bb.0 as usize].terminator = Terminator::Switch {
            scrutinee: pc_local,
            cases: state_bbs.clone(),
            default_bb,
        };

        func.blocks[abort_bb.0 as usize].stmts.push(MirStmt {
            dst: None,
            inst: Inst::CmdRemove {
                entity: rows_local,
                component: task.name.clone(),
            },
        });

        module.functions.push(func);
    }

    // 3. `fsm` -> priority-ordered transition dispatcher.
    for fsm in &module.fsms {
        let mut sorted_transitions = fsm.transitions.clone();
        sorted_transitions.sort_by_key(|a| std::cmp::Reverse(a.3));

        let mut func = MirFunction {
            name: fsm.name.clone(),
            is_observer: false,
            trigger_event: None,
            par_chunk: None,
            par_read_only: false,
            is_deterministic: module.is_deterministic,
            locals: Vec::new(),
            blocks: Vec::new(),
            queries: vec![QueryAccessDesc {
                terms: vec![QueryTerm {
                    storage_key: fsm.name.clone(),
                    field_name: None,
                    mode: TermAccessMode::Write,
                    byte_start: 0,
                    byte_end: 0,
                }],
                ..Default::default()
            }],
            source_body: String::new(),
        };
        let ptr_local = func.alloc_local("fsm_col", MirType::MutPtr);
        func.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts: vec![
                MirStmt {
                    dst: Some(ptr_local),
                    inst: Inst::IterColWrite {
                        query_idx: 0,
                        term_idx: 0,
                        storage_key: fsm.name.clone(),
                    },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::FsmDispatch {
                        fsm: fsm.name.clone(),
                        transitions: sorted_transitions,
                    },
                },
            ],
            terminator: Terminator::Return(None),
        });
        module.functions.push(func);
    }
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::ir::*;
    use strata_sema::access::FilteredAccessSet;
    use strata_sema::hir::HirFsm;
    use strata_sema::layout::{LayoutEnv, SchemaItemKind, solve_pod_layout};

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
                states: vec!["Idle".to_owned(), "Enrage".to_owned()],
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
                state_layout: layout,
                access: FilteredAccessSet::default(),
            }],
            objects: Vec::new(),
            migrations: Vec::new(),
            functions: Vec::new(),
            schedules: Vec::new(),
            sim_tests: Vec::new(),
        };
        run(&mut module);
        let disp = module.functions[0].blocks[0]
            .stmts
            .iter()
            .find_map(|s| match &s.inst {
                Inst::FsmDispatch { transitions, .. } => Some(transitions),
                _ => None,
            })
            .expect("FsmDispatch synthesized");
        assert_eq!(disp[0].3, 10);
        assert_eq!(disp[1].3, 1);
    }
}
