//! Ordered `StrataMir` optimization and lowering passes.

pub mod atomic_tx;
pub mod determinism;
pub mod optional_split;
pub mod spatial_csr;
pub mod state_machines;
pub mod tick_coalesce;
