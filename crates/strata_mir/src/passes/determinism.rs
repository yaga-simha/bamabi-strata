//! `@deterministic` strict-math & reduction-order enforcement pass.
//!
//! Disables hardware FMA contraction (`allow_fma = false`), routes math intrinsics to
//! deterministic software libm (`deterministic = true`), and enforces fixed tree-reduction order on
//! parallel readonly chunks across both ECS functions and helper functions.

use crate::ir::{Inst, MirFunction, MirModule};

/// Rewrites every MIR function and helper function under `@deterministic` modules to eliminate
/// hardware-dependent FMA / nondeterministic reduction ordering.
pub fn run(module: &mut MirModule) {
    for func in module.functions.iter_mut().chain(module.fns.iter_mut()) {
        if !module.is_deterministic && !func.is_deterministic {
            continue;
        }
        enforce_function_determinism(func);
    }
}

fn enforce_function_determinism(func: &mut MirFunction) {
    func.is_deterministic = true;
    for bb in &mut func.blocks {
        for stmt in &mut bb.stmts {
            match &mut stmt.inst {
                Inst::BinOp { allow_fma, .. } => *allow_fma = false,
                Inst::IntrinsicMath { deterministic, .. } => *deterministic = true,
                Inst::ParForEachChunkReadonly {
                    deterministic_order,
                    ..
                } => *deterministic_order = true,
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::ir::*;
    use indexmap::IndexMap;

    /// Verifies `@deterministic` clears `allow_fma`, enables deterministic math intrinsics, and
    /// locks `deterministic_order` on parallel readonly chunk iterations across systems & helpers.
    #[test]
    fn determinism_pass_rewrites_all_nondeterministic_flags() {
        let mut func = MirFunction::new("sys0", MirFnKind::System);
        func.par_chunk = Some(64);
        func.par_read_only = true;
        let x = func.alloc_local("x", MirType::F32);
        func.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts: vec![
                MirStmt {
                    dst: None,
                    inst: Inst::BinOp {
                        op: "+".to_owned(),
                        lhs: x,
                        rhs: x,
                        allow_fma: true,
                    },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::IntrinsicMath {
                        name: "sin".to_owned(),
                        args: vec![x],
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
        });
        let mut module = MirModule {
            module_path: "det::m".to_owned(),
            is_deterministic: true,
            layouts: Vec::new(),
            enums: Vec::new(),
            consts: Vec::new(),
            tables: Vec::new(),
            curves: Vec::new(),
            relations: Vec::new(),
            spatial_indices: Vec::new(),
            timelines: Vec::new(),
            tasks: Vec::new(),
            fsms: Vec::new(),
            objects: Vec::new(),
            migrations: Vec::new(),
            fns: Vec::new(),
            functions: vec![func],
            schedules: Vec::new(),
            sim_tests: Vec::new(),
            field_defaults: IndexMap::new(),
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
