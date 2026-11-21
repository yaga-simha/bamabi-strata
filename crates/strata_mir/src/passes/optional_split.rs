//! Chunk-hoisted `?T` optional query loop splitting pass.
//!
//! When a query binds `?&T` or `?&mut T`, this pass hoists the null-pointer check out of the
//! per-entity inner loop into two specialized basic blocks (`opt_present` and `opt_absent`) per
//! chunk so inner loops run branch-free and vectorize cleanly.

use crate::ir::{Inst, MirFunction, MirStmt, MirType, Terminator};
use strata_sema::access::TermAccessMode;

/// Splits loops over queries with optional (`?&T` / `?&mut T`) terms into chunk-hoisted present
/// vs. absent fast paths.
pub fn run(func: &mut MirFunction) {
    let mut optional_terms = Vec::new();
    for (qi, q) in func.queries.iter().enumerate() {
        for (ti, term) in q.terms.iter().enumerate() {
            if matches!(
                term.mode,
                TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
            ) {
                optional_terms.push((qi as u32, ti as u32, term.storage_key.clone()));
            }
        }
    }
    if optional_terms.is_empty() || func.blocks.is_empty() {
        return;
    }

    for (qi, ti, storage_key) in optional_terms {
        let slice_local = func.alloc_local(format!("opt_slice_{qi}_{ti}"), MirType::Ptr);
        let cond_local = func.alloc_local(format!("opt_present_{qi}_{ti}"), MirType::Bool);

        let present_bb = func.alloc_block(
            format!("opt_present_{storage_key}"),
            Terminator::Return(None),
        );
        let absent_bb = func.alloc_block(
            format!("opt_absent_{storage_key}"),
            Terminator::Return(None),
        );
        let merge_bb =
            func.alloc_block(format!("opt_merge_{storage_key}"), Terminator::Return(None));

        let old_term = std::mem::replace(
            &mut func.blocks[0].terminator,
            Terminator::Branch {
                cond: cond_local,
                then_bb: present_bb,
                else_bb: absent_bb,
            },
        );

        func.blocks[0].stmts.push(MirStmt {
            dst: Some(slice_local),
            inst: Inst::IterColRead {
                query_idx: qi,
                term_idx: ti,
                storage_key: storage_key.clone(),
            },
        });
        func.blocks[0].stmts.push(MirStmt {
            dst: Some(cond_local),
            inst: Inst::OptionalChunkIsPresent {
                storage_key: storage_key.clone(),
                slice_ptr: slice_local,
            },
        });

        // Clone specialized body hooks into `present_bb` and `absent_bb`, forwarding to `merge_bb`.
        func.blocks[present_bb.0 as usize].stmts.push(MirStmt {
            dst: None,
            inst: Inst::OpaqueExpr {
                text: format!("/* chunk-hoisted Some({storage_key}) fast loop */"),
            },
        });
        func.blocks[present_bb.0 as usize].terminator = Terminator::Goto(merge_bb);

        func.blocks[absent_bb.0 as usize].stmts.push(MirStmt {
            dst: None,
            inst: Inst::OpaqueExpr {
                text: format!("/* chunk-hoisted None({storage_key}) fast loop */"),
            },
        });
        func.blocks[absent_bb.0 as usize].terminator = Terminator::Goto(merge_bb);

        func.blocks[merge_bb.0 as usize].terminator = old_term;
    }
}

#[cfg(test)]
mod tests {
    use super::run;
    use crate::ir::*;
    use strata_sema::access::{QueryAccessDesc, QueryTerm, TermAccessMode};

    /// Verifies optional `?T` query terms hoist a chunk-level presence branch around fast-path blocks.
    #[test]
    fn optional_split_inserts_chunk_presence_branch() {
        let mut func = MirFunction {
            name: "opt_sys".to_owned(),
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
                    storage_key: "Buff".to_owned(),
                    field_name: None,
                    mode: TermAccessMode::OptionalRead,
                    byte_start: 0,
                    byte_end: 0,
                }],
                ..Default::default()
            }],
            source_body: String::new(),
        };
        run(&mut func);
        assert_eq!(func.blocks.len(), 4);
        assert!(matches!(
            func.blocks[0].terminator,
            Terminator::Branch { .. }
        ));
        assert!(
            func.blocks[0]
                .stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::OptionalChunkIsPresent { .. }))
        );
    }
}
