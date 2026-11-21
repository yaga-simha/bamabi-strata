//! Structural SSA, CFG, zero-padding ABI, and `@deterministic` MIR verifier.

use crate::ir::{Inst, LocalId, MirFunction, MirModule, Terminator};
use thiserror::Error;

/// Structural invariant violation discovered in lowered `StrataMir`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MirVerifyError {
    /// Function has no entry block.
    #[error("MIR function `{function}` has no entry basic block")]
    MissingEntryBlock {
        /// Function name.
        function: String,
    },
    /// Terminator jumps to a non-existent `BlockId`.
    #[error("MIR function `{function}` block {block} branches to out-of-bounds BlockId({target})")]
    InvalidBlockTarget {
        /// Function name.
        function: String,
        /// Source block index.
        block: u32,
        /// Invalid target block index.
        target: u32,
    },
    /// Instruction or terminator references an out-of-bounds `LocalId`.
    #[error("MIR function `{function}` block {block} references undefined LocalId({local})")]
    InvalidLocalRef {
        /// Function name.
        function: String,
        /// Block index.
        block: u32,
        /// Invalid local index.
        local: u32,
    },
    /// Layout contains implicit padding (`size != sum(fields.size)`).
    #[error(
        "layout `{canonical_name}` violates zero implicit padding: size={size}, sum={field_sum}"
    )]
    ImplicitPadding {
        /// Component canonical name.
        canonical_name: String,
        /// Total struct size.
        size: usize,
        /// Sum of field sizes.
        field_sum: usize,
    },
    /// `@deterministic` function retained unconstrained FMA or non-deterministic transcendental.
    #[error("MIR function `{function}` violates @deterministic invariant: {detail}")]
    NonDeterministicOp {
        /// Function name.
        function: String,
        /// Specific violation.
        detail: String,
    },
}

/// Verifies CFG well-formedness, SSA local validity, zero-padding ABI layout invariants, and
/// `@deterministic` rules across an entire [`MirModule`].
pub fn verify_mir(module: &MirModule) -> Result<(), Vec<MirVerifyError>> {
    let mut errors = Vec::new();

    for layout in &module.layouts {
        let field_sum: usize = layout.fields.iter().map(|f| f.size).sum();
        if field_sum != layout.size {
            errors.push(MirVerifyError::ImplicitPadding {
                canonical_name: layout.canonical_name.clone(),
                size: layout.size,
                field_sum,
            });
        }
    }

    for func in &module.functions {
        verify_function(func, module.is_deterministic, &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn verify_function(func: &MirFunction, mod_det: bool, errors: &mut Vec<MirVerifyError>) {
    if func.blocks.is_empty() {
        errors.push(MirVerifyError::MissingEntryBlock {
            function: func.name.clone(),
        });
        return;
    }

    let num_blocks = func.blocks.len() as u32;
    let num_locals = func.locals.len() as u32;
    let enforce_det = mod_det || func.is_deterministic;

    let check_local = |local: LocalId, blk: u32, errs: &mut Vec<MirVerifyError>| {
        if local.0 >= num_locals {
            errs.push(MirVerifyError::InvalidLocalRef {
                function: func.name.clone(),
                block: blk,
                local: local.0,
            });
        }
    };

    for bb in &func.blocks {
        for stmt in &bb.stmts {
            if let Some(dst) = stmt.dst {
                check_local(dst, bb.id.0, errors);
            }
            for local in inst_used_locals(&stmt.inst) {
                check_local(local, bb.id.0, errors);
            }
            if enforce_det {
                match &stmt.inst {
                    Inst::BinOp {
                        allow_fma: true, ..
                    } => {
                        errors.push(MirVerifyError::NonDeterministicOp {
                            function: func.name.clone(),
                            detail: "FMA contraction (`allow_fma = true`) must be disabled under @deterministic".to_owned(),
                        });
                    }
                    Inst::IntrinsicMath {
                        name,
                        deterministic: false,
                        ..
                    } => {
                        errors.push(MirVerifyError::NonDeterministicOp {
                            function: func.name.clone(),
                            detail: format!(
                                "non-deterministic transcendental `{name}` under @deterministic"
                            ),
                        });
                    }
                    _ => {}
                }
            }
        }

        match &bb.terminator {
            Terminator::Return(Some(l)) => check_local(*l, bb.id.0, errors),
            Terminator::Return(None) => {}
            Terminator::Goto(target) => {
                if target.0 >= num_blocks {
                    errors.push(MirVerifyError::InvalidBlockTarget {
                        function: func.name.clone(),
                        block: bb.id.0,
                        target: target.0,
                    });
                }
            }
            Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } => {
                check_local(*cond, bb.id.0, errors);
                for t in [then_bb.0, else_bb.0] {
                    if t >= num_blocks {
                        errors.push(MirVerifyError::InvalidBlockTarget {
                            function: func.name.clone(),
                            block: bb.id.0,
                            target: t,
                        });
                    }
                }
            }
            Terminator::Switch {
                scrutinee,
                cases,
                default_bb,
            } => {
                check_local(*scrutinee, bb.id.0, errors);
                for (_, target) in cases {
                    if target.0 >= num_blocks {
                        errors.push(MirVerifyError::InvalidBlockTarget {
                            function: func.name.clone(),
                            block: bb.id.0,
                            target: target.0,
                        });
                    }
                }
                if default_bb.0 >= num_blocks {
                    errors.push(MirVerifyError::InvalidBlockTarget {
                        function: func.name.clone(),
                        block: bb.id.0,
                        target: default_bb.0,
                    });
                }
            }
        }
    }
}

fn inst_used_locals(inst: &Inst) -> Vec<LocalId> {
    match inst {
        Inst::BinOp { lhs, rhs, .. } => vec![*lhs, *rhs],
        Inst::UnOp { val, .. } => vec![*val],
        Inst::IntrinsicMath { args, .. } => args.clone(),
        Inst::IterMarkChangedRange {
            run_start, run_len, ..
        }
        | Inst::DirtyRunInit { run_start, run_len } => vec![*run_start, *run_len],
        Inst::DirtyRunRecordRow {
            run_start,
            run_len,
            row_idx,
        } => vec![*run_start, *run_len, *row_idx],
        Inst::EntityGet { entity, .. }
        | Inst::EntityGetMut { entity, .. }
        | Inst::CmdDespawn { entity }
        | Inst::CmdInsert { entity, .. }
        | Inst::CmdInsertIfNew { entity, .. }
        | Inst::CmdRemove { entity, .. } => vec![*entity],
        Inst::CmdTrigger {
            target: Some(t), ..
        } => vec![*t],
        Inst::CmdRollback { checkpoint } => vec![*checkpoint],
        Inst::OptionalChunkIsPresent { slice_ptr, .. } => vec![*slice_ptr],
        Inst::ShadowWrite { shadow_slot, .. } | Inst::ShadowCommit { shadow_slot, .. } => {
            vec![*shadow_slot]
        }
        Inst::RequireTrue { cond } => vec![*cond],
        Inst::TaskStep {
            pc_local,
            timer_local,
            ..
        } => vec![*pc_local, *timer_local],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BasicBlock, BlockId, Inst, LocalId, MirFunction, MirModule, MirStmt, MirType};

    fn base_module(func: MirFunction) -> MirModule {
        MirModule {
            module_path: "test::mod".to_owned(),
            is_deterministic: false,
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
        }
    }

    /// Verifies CFG verifier rejects dangling branch target blocks and undefined SSA locals.
    #[test]
    fn verify_rejects_invalid_block_target_and_undefined_local() {
        let m_bad_target = base_module(MirFunction {
            name: "bad_jump".to_owned(),
            is_observer: false,
            trigger_event: None,
            par_chunk: None,
            par_read_only: false,
            is_deterministic: false,
            locals: Vec::new(),
            blocks: vec![BasicBlock {
                id: BlockId(0),
                label: "entry".to_owned(),
                stmts: Vec::new(),
                terminator: Terminator::Goto(BlockId(99)),
            }],
            queries: Vec::new(),
            source_body: String::new(),
        });
        let errs = verify_mir(&m_bad_target).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, MirVerifyError::InvalidBlockTarget { target: 99, .. }))
        );

        let m_bad_local = base_module(MirFunction {
            name: "bad_local".to_owned(),
            is_observer: false,
            trigger_event: None,
            par_chunk: None,
            par_read_only: false,
            is_deterministic: false,
            locals: Vec::new(),
            blocks: vec![BasicBlock {
                id: BlockId(0),
                label: "entry".to_owned(),
                stmts: vec![MirStmt {
                    dst: None,
                    inst: Inst::RequireTrue { cond: LocalId(7) },
                }],
                terminator: Terminator::Return(None),
            }],
            queries: Vec::new(),
            source_body: String::new(),
        });
        let errs_local = verify_mir(&m_bad_local).unwrap_err();
        assert!(
            errs_local
                .iter()
                .any(|e| matches!(e, MirVerifyError::InvalidLocalRef { local: 7, .. }))
        );
    }

    /// Verifies `@deterministic` validator flags any function still permitting FMA after lowering.
    #[test]
    fn verify_rejects_fma_when_deterministic() {
        let mut func = MirFunction {
            name: "det".to_owned(),
            is_observer: false,
            trigger_event: None,
            par_chunk: None,
            par_read_only: false,
            is_deterministic: true,
            locals: Vec::new(),
            blocks: Vec::new(),
            queries: Vec::new(),
            source_body: String::new(),
        };
        let a = func.alloc_local("a", MirType::F32);
        let b = func.alloc_local("b", MirType::F32);
        let out = func.alloc_local("out", MirType::F32);
        func.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts: vec![MirStmt {
                dst: Some(out),
                inst: Inst::BinOp {
                    op: "+".to_owned(),
                    lhs: a,
                    rhs: b,
                    allow_fma: true,
                },
            }],
            terminator: Terminator::Return(None),
        });
        let m = base_module(func);
        let errs = verify_mir(&m).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, MirVerifyError::NonDeterministicOp { .. }))
        );
    }
}
