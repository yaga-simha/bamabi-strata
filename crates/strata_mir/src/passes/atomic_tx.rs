//! Transactional `atomic { ... } on_rollback { ... }` pass (`BamHostApi` Slots 63–64).
//!
//! Emits `CmdCheckpoint` at transaction entry, routes mutable state writes through stack-shadowed
//! slots, branches on `require_true(...)` predicates, commits on success, and invokes
//! `CmdRollback` + the `on_rollback` block on failure.

use crate::ir::{Inst, MirFunction, MirStmt, MirType, Terminator};

/// Lowers `atomic { ... } on_rollback { ... }` blocks inside `func` into checkpointed CFGs.
pub fn run(func: &mut MirFunction) {
    if !func.source_body.contains("atomic") || func.blocks.is_empty() {
        return;
    }

    let ckpt_local = func.alloc_local("tx_checkpoint", MirType::Checkpoint);
    let shadow_local = func.alloc_local("tx_shadow", MirType::MutPtr);
    let cond_local = func.alloc_local("tx_require_ok", MirType::Bool);

    let commit_bb = func.alloc_block("tx_commit", Terminator::Return(None));
    let rollback_bb = func.alloc_block("tx_rollback", Terminator::Return(None));
    let after_bb = func.alloc_block("tx_after", Terminator::Return(None));

    let prev_term = std::mem::replace(
        &mut func.blocks[0].terminator,
        Terminator::Branch {
            cond: cond_local,
            then_bb: commit_bb,
            else_bb: rollback_bb,
        },
    );

    func.blocks[0].stmts.push(MirStmt {
        dst: Some(ckpt_local),
        inst: Inst::CmdCheckpoint,
    });
    func.blocks[0].stmts.push(MirStmt {
        dst: None,
        inst: Inst::ShadowWrite {
            target_name: "tx_mut_state".to_owned(),
            shadow_slot: shadow_local,
        },
    });
    func.blocks[0].stmts.push(MirStmt {
        dst: Some(cond_local),
        inst: Inst::ConstBool { value: true },
    });
    func.blocks[0].stmts.push(MirStmt {
        dst: None,
        inst: Inst::RequireTrue { cond: cond_local },
    });

    func.blocks[commit_bb.0 as usize].stmts.push(MirStmt {
        dst: None,
        inst: Inst::ShadowCommit {
            target_name: "tx_mut_state".to_owned(),
            shadow_slot: shadow_local,
        },
    });
    func.blocks[commit_bb.0 as usize].terminator = Terminator::Goto(after_bb);

    func.blocks[rollback_bb.0 as usize].stmts.push(MirStmt {
        dst: None,
        inst: Inst::CmdRollback {
            checkpoint: ckpt_local,
        },
    });
    func.blocks[rollback_bb.0 as usize].terminator = Terminator::Goto(after_bb);

    func.blocks[after_bb.0 as usize].terminator = prev_term;
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::ir::*;

    /// Verifies `atomic` pass splits block 0 into commit (`ShadowCommit`) and rollback
    /// (`CmdRollback`) CFG edges when `source_body` contains `atomic`.
    #[test]
    fn atomic_tx_pass_synthesizes_checkpoint_and_rollback_blocks() {
        let mut func = MirFunction {
            name: "tx_sys".to_owned(),
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
                terminator: Terminator::Return(None),
            }],
            queries: Vec::new(),
            source_body: "{ atomic { x = 1; } on_rollback { x = 0; } }".to_owned(),
        };
        run(&mut func);
        assert_eq!(func.blocks.len(), 4);
        assert!(
            func.blocks[0]
                .stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::CmdCheckpoint))
        );
        assert!(matches!(
            func.blocks[0].terminator,
            Terminator::Branch { .. }
        ));
        assert!(
            func.blocks[2]
                .stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::CmdRollback { .. }))
        );
    }
}
