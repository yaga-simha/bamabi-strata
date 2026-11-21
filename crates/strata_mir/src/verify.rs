//! Structural SSA, CFG, zero-padding ABI, `@sparse`/`&mut?`, and `@deterministic` MIR verifier.

use crate::ir::{Inst, LocalId, MirFunction, MirModule, MirType, Terminator};
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
    /// Query or transaction invariant violation in lowered CFG.
    #[error("MIR function `{function}` violates CFG/ABI invariant: {detail}")]
    InvalidCfgInvariant {
        /// Function name.
        function: String,
        /// Violation detail.
        detail: String,
    },
}

/// Verifies CFG well-formedness, SSA local validity, zero-padding ABI layout invariants, sparse /
/// selective access modes, and `@deterministic` rules across an entire [`MirModule`].
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

    for func in module.functions.iter().chain(module.fns.iter()) {
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

    for (idx, loc) in func.locals.iter().enumerate() {
        if loc.id.0 != idx as u32 {
            errors.push(MirVerifyError::InvalidCfgInvariant {
                function: func.name.clone(),
                detail: format!("non-dense LocalId({}): expected {}", loc.id.0, idx),
            });
        }
    }

    let check_local = |local: LocalId, blk: u32, errs: &mut Vec<MirVerifyError>| {
        if local.0 >= num_locals {
            errs.push(MirVerifyError::InvalidLocalRef {
                function: func.name.clone(),
                block: blk,
                local: local.0,
            });
        }
    };

    for param in &func.params {
        if let Some(l) = param.local {
            check_local(l, 0, errors);
        }
    }
    for res in &func.resources {
        check_local(res.ptr_local, 0, errors);
    }

    let check_block = |target: u32, src: u32, errs: &mut Vec<MirVerifyError>| {
        if target >= num_blocks {
            errs.push(MirVerifyError::InvalidBlockTarget {
                function: func.name.clone(),
                block: src,
                target,
            });
        }
    };

    for (bb_idx, bb) in func.blocks.iter().enumerate() {
        let blk = bb_idx as u32;
        if bb.id.0 != blk {
            errors.push(MirVerifyError::InvalidCfgInvariant {
                function: func.name.clone(),
                detail: format!("non-dense BlockId({}): expected {}", bb.id.0, blk),
            });
        }

        for stmt in &bb.stmts {
            if let Some(dst) = stmt.dst {
                check_local(dst, blk, errors);
            }
            for used in inst_locals(&stmt.inst) {
                check_local(used, blk, errors);
            }

            let check_local_ty =
                |local: LocalId, expected: MirType, desc: &str, errs: &mut Vec<MirVerifyError>| {
                    if let Some(loc) = func.locals.get(local.0 as usize)
                        && loc.ty != expected
                    {
                        errs.push(MirVerifyError::InvalidCfgInvariant {
                            function: func.name.clone(),
                            detail: format!(
                                "{desc} LocalId({}) must have MirType::{expected:?}",
                                local.0
                            ),
                        });
                    }
                };

            match &stmt.inst {
                Inst::CmdRollback { checkpoint } => {
                    check_local_ty(
                        *checkpoint,
                        MirType::Checkpoint,
                        "CmdRollback checkpoint",
                        errors,
                    );
                }
                Inst::SpawnBatchBegin { count, .. } => {
                    if let Some(d) = stmt.dst {
                        check_local_ty(d, MirType::U64, "SpawnBatchBegin dst", errors);
                    } else {
                        errors.push(MirVerifyError::InvalidCfgInvariant {
                            function: func.name.clone(),
                            detail:
                                "SpawnBatchBegin requires a destination LocalId of MirType::U64"
                                    .to_owned(),
                        });
                    }
                    check_local_ty(*count, MirType::U32, "SpawnBatchBegin count", errors);
                }
                Inst::SpawnBatchPush { batch, index, .. } => {
                    check_local_ty(*batch, MirType::U64, "SpawnBatchPush batch", errors);
                    check_local_ty(*index, MirType::U32, "SpawnBatchPush index", errors);
                }
                Inst::SpawnBatchCommit { batch } => {
                    check_local_ty(*batch, MirType::U64, "SpawnBatchCommit batch", errors);
                }
                _ => {}
            }

            if enforce_det {
                match &stmt.inst {
                    Inst::BinOp {
                        allow_fma: true, ..
                    } => {
                        errors.push(MirVerifyError::NonDeterministicOp {
                            function: func.name.clone(),
                            detail: "hardware FMA contraction must be disabled".to_owned(),
                        });
                    }
                    Inst::IntrinsicMath {
                        name,
                        deterministic: false,
                        ..
                    } => {
                        errors.push(MirVerifyError::NonDeterministicOp {
                            function: func.name.clone(),
                            detail: format!("intrinsic `{name}` must use deterministic libm"),
                        });
                    }
                    Inst::ParForEachChunkReadonly {
                        deterministic_order: false,
                        ..
                    } => {
                        errors.push(MirVerifyError::NonDeterministicOp {
                            function: func.name.clone(),
                            detail: "ParForEachChunkReadonly requires deterministic_order = true"
                                .to_owned(),
                        });
                    }
                    _ => {}
                }
            }
        }

        match &bb.terminator {
            Terminator::Return(opt_l) => {
                if let Some(l) = opt_l {
                    check_local(*l, blk, errors);
                }
            }
            Terminator::Goto(dst) => check_block(dst.0, blk, errors),
            Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } => {
                check_local(*cond, blk, errors);
                check_block(then_bb.0, blk, errors);
                check_block(else_bb.0, blk, errors);
            }
            Terminator::Switch {
                scrutinee,
                cases,
                default_bb,
            } => {
                check_local(*scrutinee, blk, errors);
                for (_, dst) in cases {
                    check_block(dst.0, blk, errors);
                }
                check_block(default_bb.0, blk, errors);
            }
        }
    }

    // Verify `@sparse` terms use sparse row indirections (`IterColRows*`) rather than dense column borrows
    for qb in &func.query_bindings {
        if qb.is_point_lookup {
            continue;
        }
        for term in &qb.terms {
            if !term.is_sparse {
                continue;
            }
            let used_dense = func.blocks.iter().any(|bb| {
                bb.stmts.iter().any(|s| match &s.inst {
                    Inst::IterColRead {
                        query_idx,
                        term_idx,
                        ..
                    }
                    | Inst::IterColWrite {
                        query_idx,
                        term_idx,
                        ..
                    }
                    | Inst::IterColWriteUntracked {
                        query_idx,
                        term_idx,
                        ..
                    } => *query_idx == qb.query_idx && *term_idx == term.term_idx,
                    _ => false,
                })
            });
            if used_dense {
                errors.push(MirVerifyError::InvalidCfgInvariant {
                    function: func.name.clone(),
                    detail: format!(
                        "@sparse query {} term {} (`{}`) used dense IterCol* instead of IterColRows*",
                        qb.query_idx, term.term_idx, term.storage_key
                    ),
                });
            }
        }
    }
}

fn inst_locals(inst: &Inst) -> Vec<LocalId> {
    match inst {
        Inst::ConstInt { .. }
        | Inst::ConstFloat { .. }
        | Inst::ConstBool { .. }
        | Inst::ConstVec { .. }
        | Inst::ConstString { .. }
        | Inst::SlotAlloc { .. }
        | Inst::IterNextChunk { .. }
        | Inst::IterChunkLen { .. }
        | Inst::IterEntities { .. }
        | Inst::IterColRead { .. }
        | Inst::IterColWrite { .. }
        | Inst::IterColWriteUntracked { .. }
        | Inst::IterColRowsRead { .. }
        | Inst::IterColRowsWrite { .. }
        | Inst::IterCount { .. }
        | Inst::IterUpCascade { .. }
        | Inst::ParForEachChunk { .. }
        | Inst::ParForEachChunkReadonly { .. }
        | Inst::ResRead { .. }
        | Inst::ResWrite { .. }
        | Inst::BindNamedObject { .. }
        | Inst::ResolveNamedObject { .. }
        | Inst::InternSymbol { .. }
        | Inst::TriggerPayload { .. }
        | Inst::TriggerTarget
        | Inst::CmdDespawnAll { .. }
        | Inst::CmdCheckpoint
        | Inst::SpatialRebuildCsr { .. }
        | Inst::FsmDispatch { .. }
        | Inst::MigrateSrcPtr { .. }
        | Inst::MigrateDstPtr { .. } => Vec::new(),

        Inst::Copy { val }
        | Inst::SlotLoad { slot: val }
        | Inst::UnOp { val, .. }
        | Inst::Cast { val, .. }
        | Inst::VecExtract { vec: val, .. }
        | Inst::VecSwizzle { vec: val, .. }
        | Inst::FieldPtr { base_ptr: val, .. }
        | Inst::FieldLoad { base_ptr: val, .. }
        | Inst::EntityGet { entity: val, .. }
        | Inst::EntityGetMut { entity: val, .. }
        | Inst::GraceIsActive { ptr: val }
        | Inst::GraceClear { ptr: val }
        | Inst::TimelineInWindow { ptr: val, .. }
        | Inst::SpawnBatchBegin { count: val, .. }
        | Inst::SpawnBatchCommit { batch: val }
        | Inst::CmdDespawn { entity: val }
        | Inst::CmdRemove { entity: val, .. }
        | Inst::StreamEmit { payload: val, .. }
        | Inst::CmdRollback { checkpoint: val }
        | Inst::CurveSample { x: val, .. }
        | Inst::TableLoad { key: val, .. }
        | Inst::OptionalChunkIsPresent { slice_ptr: val, .. }
        | Inst::ShadowCommit {
            shadow_slot: val, ..
        }
        | Inst::RequireTrue { cond: val }
        | Inst::ReduceInit { identity: val, .. } => vec![*val],

        Inst::SlotStore { slot, val }
        | Inst::VecInsert { vec: slot, val, .. }
        | Inst::FieldStore {
            base_ptr: slot,
            val,
            ..
        }
        | Inst::RowPtr {
            col_ptr: slot,
            row_idx: val,
            ..
        }
        | Inst::EntityAtRow {
            entities_ptr: slot,
            row_idx: val,
        }
        | Inst::IterMarkChangedRange {
            run_start: slot,
            run_len: val,
            ..
        }
        | Inst::ArrayIndex {
            base: slot,
            index: val,
        }
        | Inst::GraceArm {
            ptr: slot,
            duration_sec: val,
        }
        | Inst::GraceTick {
            ptr: slot,
            dt_sec: val,
        }
        | Inst::InputBufConsume {
            ptr: slot,
            action_id: val,
            ..
        }
        | Inst::InputBufPeek {
            ptr: slot,
            action_id: val,
            ..
        }
        | Inst::InputBufTick {
            ptr: slot,
            dt_sec: val,
            ..
        }
        | Inst::BitSetSet {
            ptr: slot,
            bit: val,
            ..
        }
        | Inst::BitSetGet {
            ptr: slot,
            bit: val,
            ..
        }
        | Inst::BitSetClear {
            ptr: slot,
            bit: val,
            ..
        }
        | Inst::DirtyRunInit {
            run_start: slot,
            run_len: val,
        }
        | Inst::ShadowWrite {
            shadow_slot: slot,
            val,
            ..
        }
        | Inst::TimelineAdvance {
            cursor_ptr: slot,
            dt_sec: val,
            ..
        }
        | Inst::TaskStep {
            pc_local: slot,
            timer_local: val,
            ..
        }
        | Inst::CmdRemoveRelation {
            entity: slot,
            target: val,
            ..
        }
        | Inst::BinOp {
            lhs: slot,
            rhs: val,
            ..
        } => vec![*slot, *val],

        Inst::ReduceAccum { acc, val, .. } => vec![*acc, *val],

        Inst::DirtyRunRecordRow {
            run_start,
            run_len,
            row_idx,
        } => vec![*run_start, *run_len, *row_idx],

        Inst::InputBufPush {
            ptr,
            action_id,
            window_sec,
            ..
        } => vec![*ptr, *action_id, *window_sec],

        Inst::SpatialQueryDisc { center, radius, .. } => vec![*center, *radius],

        Inst::SpatialQuerySegmentAt {
            start,
            end,
            radius,
            tick_offset,
            ..
        } => vec![*start, *end, *radius, *tick_offset],

        Inst::IntrinsicMath { args, .. }
        | Inst::Call { args, .. }
        | Inst::ArrayInit { elems: args } => args.clone(),

        Inst::StructInit { fields, .. } => fields.iter().map(|(_, l)| *l).collect(),

        Inst::CmdSpawn { components, .. } => components.iter().map(|(_, l)| *l).collect(),

        Inst::CmdSpawnBatch { count, components } => {
            let mut out = vec![*count];
            out.extend(components.iter().map(|(_, l)| *l));
            out
        }

        Inst::SpawnBatchPush {
            batch,
            index,
            components,
        } => {
            let mut out = vec![*batch, *index];
            out.extend(components.iter().map(|(_, l)| *l));
            out
        }

        Inst::CmdInsert { entity, data, .. } => {
            let mut out = vec![*entity];
            if let Some(d) = data {
                out.push(*d);
            }
            out
        }

        Inst::CmdTrigger {
            target, payload, ..
        } => {
            let mut out = Vec::new();
            if let Some(t) = target {
                out.push(*t);
            }
            if let Some(p) = payload {
                out.push(*p);
            }
            out
        }

        Inst::CmdInsertRelation {
            entity,
            target,
            payload,
            ..
        } => {
            let mut out = vec![*entity, *target];
            if let Some(p) = payload {
                out.push(*p);
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        BasicBlock, BlockId, Inst, LocalId, MirFnKind, MirFunction, MirModule, MirStmt, MirType,
    };
    use indexmap::IndexMap;

    fn base_module(func: MirFunction) -> MirModule {
        MirModule {
            module_path: "test::mod".to_owned(),
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
            fsms: Vec::new(),
            objects: Vec::new(),
            migrations: Vec::new(),
            fns: Vec::new(),
            functions: vec![func],
            schedules: Vec::new(),
            sim_tests: Vec::new(),
            field_defaults: IndexMap::new(),
        }
    }

    /// Verifies CFG verifier rejects dangling branch target blocks and undefined SSA locals.
    #[test]
    fn verify_rejects_invalid_block_target_and_undefined_local() {
        let mut f_bad_target = MirFunction::new("bad_jump", MirFnKind::System);
        f_bad_target.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts: Vec::new(),
            terminator: Terminator::Goto(BlockId(99)),
        });
        let m_bad_target = base_module(f_bad_target);
        let errs = verify_mir(&m_bad_target).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, MirVerifyError::InvalidBlockTarget { target: 99, .. }))
        );

        let mut f_bad_local = MirFunction::new("bad_local", MirFnKind::System);
        f_bad_local.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts: vec![MirStmt {
                dst: None,
                inst: Inst::RequireTrue { cond: LocalId(7) },
            }],
            terminator: Terminator::Return(None),
        });
        let m_bad_local = base_module(f_bad_local);
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
        let mut func = MirFunction::new("det", MirFnKind::System);
        func.is_deterministic = true;
        let a = func.alloc_local("a", MirType::F32);
        let b = func.alloc_local("b", MirType::F32);
        let out = func.alloc_local("out", MirType::F32);
        func.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts: vec![MirStmt {
                dst: Some(out),
                inst: Inst::BinOp {
                    op: "*".to_owned(),
                    lhs: a,
                    rhs: b,
                    allow_fma: true,
                },
            }],
            terminator: Terminator::Return(None),
        });
        let errs = verify_mir(&base_module(func)).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, MirVerifyError::NonDeterministicOp { .. }))
        );
    }

    /// Verifies `SpawnBatch*` instructions require `MirType::U64` handle and `MirType::U32` counts/indices.
    #[test]
    fn verify_rejects_mismatched_spawn_batch_types() {
        let mut func = MirFunction::new("bad_batch", MirFnKind::System);
        let cnt_bad = func.alloc_local("cnt", MirType::I32);
        let batch_bad = func.alloc_local("batch", MirType::U32);
        let idx_bad = func.alloc_local("idx", MirType::I32);
        func.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts: vec![
                MirStmt {
                    dst: Some(batch_bad),
                    inst: Inst::SpawnBatchBegin {
                        count: cnt_bad,
                        components: vec!["Pos".to_owned()],
                    },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::SpawnBatchPush {
                        batch: batch_bad,
                        index: idx_bad,
                        components: Vec::new(),
                    },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::SpawnBatchCommit { batch: batch_bad },
                },
            ],
            terminator: Terminator::Return(None),
        });
        let errs = verify_mir(&base_module(func)).unwrap_err();
        assert!(errs.iter().any(|e| {
            matches!(e, MirVerifyError::InvalidCfgInvariant { detail, .. } if detail.contains("SpawnBatchBegin dst"))
        }));
        assert!(errs.iter().any(|e| {
            matches!(e, MirVerifyError::InvalidCfgInvariant { detail, .. } if detail.contains("SpawnBatchBegin count"))
        }));
        assert!(errs.iter().any(|e| {
            matches!(e, MirVerifyError::InvalidCfgInvariant { detail, .. } if detail.contains("SpawnBatchPush batch"))
        }));
        assert!(errs.iter().any(|e| {
            matches!(e, MirVerifyError::InvalidCfgInvariant { detail, .. } if detail.contains("SpawnBatchPush index"))
        }));
        assert!(errs.iter().any(|e| {
            matches!(e, MirVerifyError::InvalidCfgInvariant { detail, .. } if detail.contains("SpawnBatchCommit batch"))
        }));
    }
}
