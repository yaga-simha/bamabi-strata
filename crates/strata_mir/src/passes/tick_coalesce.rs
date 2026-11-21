//! Selective `&mut? T` tick-range coalescing pass (`BamHostApi` Slots 14–15).
//!
//! Replaces eager `IterColWrite` (Slot 13) with `IterColWriteUntracked` (Slot 14), tracks dirty
//! contiguous row runs `(run_start, run_len)` in SSA registers, and flushes coalesced ranges via
//! `IterMarkChangedRange` (Slot 15), preserving Bevy `summary_tick` whole-table skips when zero
//! rows mutate.

use crate::ir::{Inst, MirFunction, MirStmt, MirType};
use strata_sema::access::TermAccessMode;

/// Rewrites selective `&mut?` accesses in `func` to Slot 14 + register run coalescing + Slot 15.
pub fn run(func: &mut MirFunction) {
    let mut selective_terms = Vec::new();
    for (qi, q) in func.queries.iter().enumerate() {
        for (ti, term) in q.terms.iter().enumerate() {
            if term.mode == TermAccessMode::SelectiveWrite {
                selective_terms.push((qi as u32, ti as u32, term.storage_key.clone()));
            }
        }
    }
    if selective_terms.is_empty() || func.blocks.is_empty() {
        return;
    }

    // Upgrade any matching `IterColWrite` to `IterColWriteUntracked`.
    for bb in &mut func.blocks {
        for stmt in &mut bb.stmts {
            if let Inst::IterColWrite {
                query_idx,
                term_idx,
                storage_key,
            } = &stmt.inst
                && selective_terms
                    .iter()
                    .any(|(q, t, _)| q == query_idx && t == term_idx)
            {
                stmt.inst = Inst::IterColWriteUntracked {
                    query_idx: *query_idx,
                    term_idx: *term_idx,
                    storage_key: storage_key.clone(),
                };
            }
        }
    }

    for (qi, ti, storage_key) in selective_terms {
        let run_start = func.alloc_local(format!("dirty_start_{qi}_{ti}"), MirType::U32);
        let run_len = func.alloc_local(format!("dirty_len_{qi}_{ti}"), MirType::U32);
        let row_idx = func.alloc_local(format!("row_idx_{qi}_{ti}"), MirType::U32);
        let slice_ptr = func.alloc_local(format!("untracked_ptr_{qi}_{ti}"), MirType::MutPtr);

        let entry = &mut func.blocks[0];
        entry.stmts.push(MirStmt {
            dst: Some(slice_ptr),
            inst: Inst::IterColWriteUntracked {
                query_idx: qi,
                term_idx: ti,
                storage_key,
            },
        });
        entry.stmts.push(MirStmt {
            dst: None,
            inst: Inst::DirtyRunInit { run_start, run_len },
        });
        entry.stmts.push(MirStmt {
            dst: Some(row_idx),
            inst: Inst::ConstInt { value: 0 },
        });
        entry.stmts.push(MirStmt {
            dst: None,
            inst: Inst::DirtyRunRecordRow {
                run_start,
                run_len,
                row_idx,
            },
        });
        entry.stmts.push(MirStmt {
            dst: None,
            inst: Inst::IterMarkChangedRange {
                query_idx: qi,
                term_idx: ti,
                run_start,
                run_len,
            },
        });
    }
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::ir::*;
    use strata_sema::access::{QueryAccessDesc, QueryTerm, TermAccessMode};

    /// Verifies `&mut? T` query terms emit untracked column borrows and dirty-run flush instructions.
    #[test]
    fn tick_coalesce_emits_untracked_borrow_and_range_flush() {
        let mut func = MirFunction {
            name: "heat_sys".to_owned(),
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
            queries: vec![QueryAccessDesc {
                terms: vec![QueryTerm {
                    storage_key: "Heat".to_owned(),
                    field_name: None,
                    mode: TermAccessMode::SelectiveWrite,
                    byte_start: 0,
                    byte_end: 0,
                }],
                ..Default::default()
            }],
            source_body: String::new(),
        };
        run(&mut func);
        let stmts = &func.blocks[0].stmts;
        assert!(
            stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::IterColWriteUntracked { .. }))
        );
        assert!(
            stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::IterMarkChangedRange { .. }))
        );
    }
}
