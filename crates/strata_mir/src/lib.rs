#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Backend-neutral SSA CFG Medium-Level Intermediate Representation (`StrataMir`) and lowering
//! passes for Strata v2.0.
//!
//! Enforces `#![forbid(unsafe_code)]` and has ZERO `bevy*` dependencies.

pub mod ir;
#[cfg(kani)]
mod kani_proofs;
pub mod lower;
pub mod passes;
pub mod verify;

pub use ir::{
    BasicBlock, BlockId, Inst, LocalId, MirChangedTerm, MirConstVal, MirFnKind, MirFunction,
    MirLocal, MirModule, MirNetComponent, MirNetFieldSpec, MirNetHandshake, MirNetSimTest,
    MirParam, MirQuantizeSpec, MirQueryBinding, MirQueryTermBinding, MirResourceBinding, MirRpc,
    MirStmt, MirStreamOp, MirStreamOpKind, MirType, Terminator,
};
pub use lower::lower_to_mir;
pub use passes::spatial_csr::csr_cell_range;
pub use verify::{MirVerifyError, verify_mir};
