//! Backend-neutral SSA Control-Flow Graph (CFG) Intermediate Representation (`StrataMir`)
//! for Strata v2.0.
//!
//! Lowered from `strata_sema::AnalyzedModule` and consumed identically by the C99, Rust Guest,
//! Cranelift JIT, and Tier 3 `bevy-native` backends.

use serde::{Deserialize, Serialize};
use strata_sema::access::QueryAccessDesc;
use strata_sema::hir::{
    HirCurve, HirFsm, HirMigration, HirObject, HirRelation, HirSchedule, HirSimTest,
    HirSpatialIndex, HirTable, HirTask, HirTimeline,
};
use strata_sema::layout::SolvedLayout;

/// SSA local register identifier within a [`MirFunction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LocalId(pub u32);

/// Basic block identifier within a [`MirFunction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BlockId(pub u32);

/// Backend-neutral MIR scalar/pointer/ECS handle types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum MirType {
    Unit,
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    Fix32,
    Fix64,
    Vec2,
    Vec3,
    Vec4,
    Entity,
    Ptr,
    MutPtr,
    QueryIter,
    Checkpoint,
    Named(String),
}

/// Typed SSA local variable inside a [`MirFunction`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MirLocal {
    /// Local index.
    pub id: LocalId,
    /// Human-readable symbol name.
    pub name: String,
    /// Static MIR type.
    pub ty: MirType,
}

/// Wire-mapped SSA instruction inside a [`BasicBlock`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Inst {
    ConstInt {
        value: i64,
    },
    ConstFloat {
        value: f64,
    },
    ConstBool {
        value: bool,
    },
    BinOp {
        op: String,
        lhs: LocalId,
        rhs: LocalId,
        allow_fma: bool,
    },
    UnOp {
        op: String,
        val: LocalId,
    },
    IntrinsicMath {
        name: String,
        args: Vec<LocalId>,
        deterministic: bool,
    },
    /// Advances a query iterator to the next archetype chunk (`BamHostApi::iter_next_chunk`).
    IterNextChunk {
        query_idx: u32,
    },
    /// Returns the `FfiEntity*` slice for the current chunk (`BamHostApi::iter_entities`).
    IterEntities {
        query_idx: u32,
    },
    /// Borrows a read-only `BAM_RESTRICT` column pointer (`BamHostApi::iter_column_readonly`).
    IterColRead {
        query_idx: u32,
        term_idx: u32,
        storage_key: String,
    },
    /// Borrows a mutable `BAM_RESTRICT` column pointer (`BamHostApi::iter_column_mutable`).
    IterColWrite {
        query_idx: u32,
        term_idx: u32,
        storage_key: String,
    },
    /// Borrows an untracked mutable column pointer for `&mut?` (`BamHostApi::iter_column_mutable_untracked`).
    IterColWriteUntracked {
        query_idx: u32,
        term_idx: u32,
        storage_key: String,
    },
    /// Flushes a contiguous dirty row range `(start, len)` (`BamHostApi::iter_mark_changed_range`).
    IterMarkChangedRange {
        query_idx: u32,
        term_idx: u32,
        run_start: LocalId,
        run_len: LocalId,
    },
    /// Batched `@sparse` row read (`BamHostApi::iter_column_rows_readonly`).
    IterColRowsRead {
        query_idx: u32,
        term_idx: u32,
        storage_key: String,
    },
    /// Batched `@sparse` row write (`BamHostApi::iter_column_rows_mutable`).
    IterColRowsWrite {
        query_idx: u32,
        term_idx: u32,
        storage_key: String,
    },
    /// Non-destructive query entity count (`BamHostApi::iter_count`).
    IterCount {
        query_idx: u32,
    },
    /// Breadth-first hierarchy cascade (`BamHostApi::iter_up_cascade`).
    IterUpCascade {
        query_idx: u32,
        relation: String,
    },
    /// Work-stealing parallel chunk dispatch (`BamHostApi::par_for_each_chunk`).
    ParForEachChunk {
        query_idx: u32,
        chunk_size: u32,
    },
    /// Zero-arena read-only parallel reduction (`BamHostApi::par_for_each_chunk_readonly`).
    ParForEachChunkReadonly {
        query_idx: u32,
        chunk_size: u32,
        deterministic_order: bool,
    },
    /// Borrows a singleton resource pointer (`BamHostApi::res_ptr` / `sys_res_ptr`).
    ResRead {
        resource: String,
    },
    /// Borrows a mutable singleton resource pointer (`BamHostApi::res_mut_ptr` / `sys_res_mut_ptr`).
    ResWrite {
        resource: String,
    },
    /// Random-access read on one entity (`BamHostApi::sys_entity_get`).
    EntityGet {
        entity: LocalId,
        storage_key: String,
    },
    /// Random-access write on one entity (`BamHostApi::sys_entity_get_mut`).
    EntityGetMut {
        entity: LocalId,
        storage_key: String,
    },
    /// Binds a persistent named object (`BamHostApi::bind_named_object`).
    BindNamedObject {
        name: String,
    },
    /// Interns a `sym` handle (`BamHostApi::intern_symbol`).
    InternSymbol {
        symbol: String,
    },
    /// Deferred spawn (`BamHostApi::cmd_spawn`).
    CmdSpawn {
        components: Vec<String>,
    },
    /// Deferred `@persist` spawn (`BamHostApi::cmd_spawn_persistent`).
    CmdSpawnPersistent {
        components: Vec<String>,
    },
    /// SoA bulk spawn (`BamHostApi::cmd_spawn_batch`).
    CmdSpawnBatch {
        count_expr: String,
        components: Vec<String>,
    },
    /// Deferred entity despawn (`BamHostApi::cmd_despawn`).
    CmdDespawn {
        entity: LocalId,
    },
    /// Bulk zone/group despawn (`BamHostApi::cmd_despawn_all`).
    CmdDespawnAll {
        filter: String,
    },
    /// Conditional component insert (`BamHostApi::cmd_insert`).
    CmdInsert {
        entity: LocalId,
        component: String,
    },
    /// Conditional insert-if-new (`BamHostApi::cmd_insert_if_new`).
    CmdInsertIfNew {
        entity: LocalId,
        component: String,
    },
    /// Deferred component removal (`BamHostApi::cmd_remove`).
    CmdRemove {
        entity: LocalId,
        component: String,
    },
    /// Deferred observer trigger (`BamHostApi::cmd_trigger` / `cmd_trigger_ex`).
    CmdTrigger {
        event: String,
        target: Option<LocalId>,
    },
    /// Buffered message stream write (`BamHostApi::msg_send` / `msg_write_batch`).
    StreamEmit {
        stream: String,
    },
    /// Captures a LIFO transaction checkpoint (`BamHostApi::cmd_checkpoint`).
    CmdCheckpoint,
    /// Rolls back commands to checkpoint (`BamHostApi::cmd_rollback`).
    CmdRollback {
        checkpoint: LocalId,
    },
    /// Inserts a typed relation edge (`BamHostApi::cmd_insert_relation`).
    CmdInsertRelation {
        relation: String,
    },
    /// Removes a typed relation edge (`BamHostApi::cmd_remove_relation`).
    CmdRemoveRelation {
        relation: String,
    },
    /// 2-pass counting-sort CSR spatial grid / history rebuild.
    SpatialRebuildCsr {
        index_name: String,
        is_history: bool,
        frames: u32,
        over_component: String,
        by_field_path: String,
    },
    /// Broadphase disc probe over a CSR `spatial_grid`.
    SpatialQueryDisc {
        grid_name: String,
    },
    /// Lag-compensated historical segment sweep over `spatial_history`.
    SpatialQuerySegmentAt {
        history_name: String,
    },
    /// `O(1)` enum-indexed load from `.rodata` `table`.
    TableLoad {
        table_name: String,
    },
    /// Branchless piecewise-linear `curve` interpolation.
    CurveSample {
        curve_name: String,
    },
    /// Chunk-hoisted optional component presence check (`term_slice != null`).
    OptionalChunkIsPresent {
        storage_key: String,
        slice_ptr: LocalId,
    },
    /// Initializes register-held selective tick coalescing state `(run_start, run_len)`.
    DirtyRunInit {
        run_start: LocalId,
        run_len: LocalId,
    },
    /// Records one mutated row index into `(run_start, run_len)`, flushing gaps cleanly.
    DirtyRunRecordRow {
        run_start: LocalId,
        run_len: LocalId,
        row_idx: LocalId,
    },
    /// Stack-shadowed `&mut` write inside an `atomic { ... }` transaction.
    ShadowWrite {
        target_name: String,
        shadow_slot: LocalId,
    },
    /// Commits stack-shadowed writes upon transaction completion.
    ShadowCommit {
        target_name: String,
        shadow_slot: LocalId,
    },
    /// Evaluates `require_true(cond)` inside an `atomic` block.
    RequireTrue {
        cond: LocalId,
    },
    /// Advances a `timeline` 16-byte cursor and computes active window bitmasks.
    TimelineAdvance {
        timeline: String,
        rate_hz: u32,
        duration_frames: u32,
        window_masks: Vec<(String, u32, u32, u32)>,
    },
    /// Evaluates priority-ordered `fsm` state transitions.
    FsmDispatch {
        fsm: String,
        transitions: Vec<(String, String, String, i32)>,
    },
    /// Resumes a stackless `task` state machine across `wait`/`wait_until`/`yield_tick`/`race`.
    TaskStep {
        task: String,
        pc_local: LocalId,
        timer_local: LocalId,
        abort_cond: Option<String>,
        num_states: u32,
    },
    /// Preserves an un-lowered scalar expression/statement snippet for backend emission.
    OpaqueExpr {
        text: String,
    },
}

/// One SSA statement assigning an optional result [`LocalId`] to an [`Inst`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MirStmt {
    /// Destination SSA local if instruction produces a value.
    pub dst: Option<LocalId>,
    /// Instruction payload.
    pub inst: Inst,
}

/// Basic-block control-flow terminator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Terminator {
    Return(Option<LocalId>),
    Goto(BlockId),
    Branch {
        cond: LocalId,
        then_bb: BlockId,
        else_bb: BlockId,
    },
    Switch {
        scrutinee: LocalId,
        cases: Vec<(u32, BlockId)>,
        default_bb: BlockId,
    },
}

/// Single basic block in a [`MirFunction`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Block ID (`BlockId(0)` is always the entry block).
    pub id: BlockId,
    /// Diagnostic label (`"entry"`, `"chunk_loop"`, `"opt_present"`, etc.).
    pub label: String,
    /// Ordered instructions inside this block.
    pub stmts: Vec<MirStmt>,
    /// Outgoing CFG terminator.
    pub terminator: Terminator,
}

/// Lowered MIR function representing a user `sys`, `obs`, or synthesized state-machine/CSR tick.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MirFunction {
    /// Function/system name.
    pub name: String,
    /// `true` for reactive `obs`.
    pub is_observer: bool,
    /// Trigger event type if observer.
    pub trigger_event: Option<String>,
    /// `@par(chunk = N)` chunk size if parallel.
    pub par_chunk: Option<u32>,
    /// `@par(read_only, ...)` flag.
    pub par_read_only: bool,
    /// `@deterministic` enforcement active.
    pub is_deterministic: bool,
    /// SSA local declarations (`locals[id.0]`).
    pub locals: Vec<MirLocal>,
    /// Basic blocks (`blocks[id.0]`).
    pub blocks: Vec<BasicBlock>,
    /// Bound ECS query descriptors.
    pub queries: Vec<QueryAccessDesc>,
    /// Original source body retained for backend emission context.
    pub source_body: String,
}

impl MirFunction {
    /// Allocates a new typed SSA [`LocalId`].
    pub fn alloc_local(&mut self, name: impl Into<String>, ty: MirType) -> LocalId {
        let id = LocalId(self.locals.len() as u32);
        self.locals.push(MirLocal {
            id,
            name: name.into(),
            ty,
        });
        id
    }

    /// Allocates a new empty [`BasicBlock`] returning its [`BlockId`].
    pub fn alloc_block(&mut self, label: impl Into<String>, terminator: Terminator) -> BlockId {
        let id = BlockId(self.blocks.len() as u32);
        self.blocks.push(BasicBlock {
            id,
            label: label.into(),
            stmts: Vec::new(),
            terminator,
        });
        id
    }
}

/// Complete lowered module IR (`StrataMir`) ready for verification and multi-target codegen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MirModule {
    /// Module canonical path.
    pub module_path: String,
    /// Module-wide `@deterministic` flag.
    pub is_deterministic: bool,
    /// Solved ABI-Pod layouts (components, `@soa` strata, resources, events, tasks, timelines).
    pub layouts: Vec<SolvedLayout>,
    /// Static `.rodata` tables.
    pub tables: Vec<HirTable>,
    /// Piecewise-linear curves.
    pub curves: Vec<HirCurve>,
    /// Declared relations.
    pub relations: Vec<HirRelation>,
    /// Declared spatial grids and histories.
    pub spatial_indices: Vec<HirSpatialIndex>,
    /// Declared frame timelines.
    pub timelines: Vec<HirTimeline>,
    /// Declared stackless tasks.
    pub tasks: Vec<HirTask>,
    /// Declared FSMs.
    pub fsms: Vec<HirFsm>,
    /// Named objects (`bind_named_object`).
    pub objects: Vec<HirObject>,
    /// Schema migrations (`v1 -> v2`).
    pub migrations: Vec<HirMigration>,
    /// All lowered and synthesized MIR functions.
    pub functions: Vec<MirFunction>,
    /// Module schedule trees (augmented with synthesized CSR rebuild & state-machine systems).
    pub schedules: Vec<HirSchedule>,
    /// Embedded `sim_test` specs.
    pub sim_tests: Vec<HirSimTest>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies `MirFunction::alloc_local` and `alloc_block` assign dense sequential IDs matching
    /// SSA vector indices.
    #[test]
    fn alloc_local_and_block_assign_sequential_indices() {
        let mut func = MirFunction {
            name: "step".to_owned(),
            is_observer: false,
            trigger_event: None,
            par_chunk: None,
            par_read_only: false,
            is_deterministic: false,
            locals: Vec::new(),
            blocks: Vec::new(),
            queries: Vec::new(),
            source_body: String::new(),
        };
        let l0 = func.alloc_local("a", MirType::F32);
        let l1 = func.alloc_local("b", MirType::Bool);
        let b0 = func.alloc_block("entry", Terminator::Return(None));
        let b1 = func.alloc_block("exit", Terminator::Return(None));
        assert_eq!((l0.0, l1.0), (0, 1));
        assert_eq!((b0.0, b1.0), (0, 1));
    }
}
