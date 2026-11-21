//! `@deterministic` enforcement pass.
//!
//! Disables FMA contraction, enforces deterministic `libm`/fixed-point transcendentals, and locks
//! `ParForEachChunkReadonly` reductions into deterministic associative order whenever
//! `@deterministic` is active.

use crate::ir::{Inst, MirModule};

/// Enforces `@deterministic` invariants across every function in `module`.
pub fn run(module: &mut MirModule) {
    for func in &mut module.functions {
        let enforce = module.is_deterministic || func.is_deterministic;
        if !enforce {
            continue;
        }
        func.is_deterministic = true;
        for bb in &mut func.blocks {
            for stmt in &mut bb.stmts {
                match &mut stmt.inst {
                    Inst::BinOp { allow_fma, .. } => {
                        *allow_fma = false;
                    }
                    Inst::IntrinsicMath { deterministic, .. } => {
                        *deterministic = true;
                    }
                    Inst::ParForEachChunkReadonly {
                        deterministic_order,
                        ..
                    } => {
                        *deterministic_order = true;
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::ir::*;

    /// Verifies `@deterministic` clears `allow_fma`, enables deterministic math intrinsics, and
    /// locks `deterministic_order` on parallel readonly chunk iterations.
    #[test]
    fn determinism_pass_rewrites_all_nondeterministic_flags() {
        let mut func = MirFunction {
            name: "sys0".to_owned(),
            is_observer: false,
            trigger_event: None,
            par_chunk: Some(64),
            par_read_only: true,
            is_deterministic: false,
            locals: vec![MirLocal {
                id: LocalId(0),
                name: "x".to_owned(),
                ty: MirType::F32,
            }],
            blocks: vec![BasicBlock {
                id: BlockId(0),
                label: "entry".to_owned(),
                stmts: vec![
                    MirStmt {
                        dst: None,
                        inst: Inst::BinOp {
                            op: "+".to_owned(),
                            lhs: LocalId(0),
                            rhs: LocalId(0),
                            allow_fma: true,
                        },
                    },
                    MirStmt {
                        dst: None,
                        inst: Inst::IntrinsicMath {
                            name: "sin".to_owned(),
                            args: vec![LocalId(0)],
                            deterministic: false,
                        },
                    },
                    MirStmt {
                        dst: None,
                        inst: Inst::ParForEachChunkReadonly {
                            query_idx: 0,
                            chunk_size: 64,
                            deterministic_order: false,
                        },
                    },
                ],
                terminator: Terminator::Return(None),
            }],
            queries: Vec::new(),
            source_body: String::new(),
        };
        let _ = &mut func;
        let mut module = MirModule {
            module_path: "det::m".to_owned(),
            is_deterministic: true,
            layouts: Vec::new(),
            tables: Vec::new(),
            curves: Vec::new(),
            relations: Vec::new(),
            spatial_indices: Vec::new(),
            timelines: Vec::new(),
            tasks: Vec::new(),
            fsms: Vec::new(),
            objects: Vec::new(),
            migrations: Vec::new(),
            functions: vec![func],
            schedules: Vec::new(),
            sim_tests: Vec::new(),
        };
        run(&mut module);
        let stmts = &module.functions[0].blocks[0].stmts;
        assert!(matches!(
            stmts[0].inst,
            Inst::BinOp {
                allow_fma: false,
                ..
            }
        ));
        assert!(matches!(
            stmts[1].inst,
            Inst::IntrinsicMath {
                deterministic: true,
                ..
            }
        ));
        assert!(matches!(
            stmts[2].inst,
            Inst::ParForEachChunkReadonly {
                deterministic_order: true,
                ..
            }
        ));
    }
}
