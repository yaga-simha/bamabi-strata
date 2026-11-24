//! Backend-neutral SSA Control-Flow Graph (CFG) Intermediate Representation (`StrataMir`)
//! for Strata v2.0.
//!
//! Lowered from `strata_sema::AnalyzedModule` and consumed identically by the C99, Rust Guest,
//! Cranelift JIT, and Tier 3 `bevy-native` backends.

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use strata_sema::access::{QueryAccessDesc, TermAccessMode};
use strata_sema::hir::{
    AuthorityKind, HirConst, HirCurve, HirFsm, HirMigration, HirObject, HirParamKind, HirRelation,
    HirSchedule, HirSimTest, HirSpatialIndex, HirStmt, HirTable, HirTask, HirTimeline,
    NetDirection, NetReliability,
};
use strata_sema::layout::{EnumDef, SolvedLayout};

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
    Sym,
    Vec2,
    Vec3,
    Vec4,
    IVec2,
    IVec3,
    UVec2,
    Entity,
    Ptr,
    MutPtr,
    QueryIter,
    Checkpoint,
    Array { elem: Box<MirType>, len: usize },
    Tuple(Vec<MirType>),
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

/// Evaluable compile-time constant value stored in `MirModule::field_defaults`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MirConstVal {
    /// Unit constant.
    Unit,
    /// Boolean constant.
    Bool(bool),
    /// Signed 64-bit integer constant.
    Int(i64),
    /// Double-precision scalar constant (normalized to SI base units).
    Float(f64),
    /// 2D float vector.
    Vec2([f64; 2]),
    /// 3D float vector.
    Vec3([f64; 3]),
    /// 4D float vector.
    Vec4([f64; 4]),
    /// String / inline-str literal constant.
    String(String),
    /// Array literal constant.
    Array(Vec<MirConstVal>),
    /// Named struct or component default fields.
    Struct {
        /// Type name.
        name: String,
        /// Field values `(field_name, value)`.
        fields: Vec<(String, MirConstVal)>,
    },
}

/// Function/system classification within a [`MirModule`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MirFnKind {
    /// User-declared ECS system (`sys`).
    System,
    /// Reactive observer (`obs`).
    Observer {
        /// Event type triggering this observer.
        event: String,
        /// Optional target component filter (`Trigger<Event, Comp>`).
        target_comp: Option<String>,
    },
    /// Top-level helper function (`fn`).
    HelperFn,
    /// Schema migration (`migrate v1 -> v2`) matching `BamRowMigrateFn` (`Slot 67`).
    Migration {
        /// Component short or canonical name.
        component: String,
        /// Source SemVer.
        from_ver: String,
        /// Target SemVer.
        to_ver: String,
        /// Canonical source layout name.
        src_layout: String,
        /// Canonical destination layout name.
        dst_layout: String,
    },
    /// Synthesized `timeline` cursor & edge-trigger system.
    SynthesizedTimeline,
    /// Synthesized stackless `task` state-machine system.
    SynthesizedTask,
    /// Synthesized `fsm` transition & hook system.
    SynthesizedFsm,
    /// Synthesized spatial CSR 2-pass counting-sort rebuild system.
    SynthesizedSpatialCsr,
    /// Synthesized `GraceWindow` & `InputBuffer` timer-tick system in `FixedUpdate`.
    SynthesizedTimerTick,
}

/// Parameter descriptor on a [`MirFunction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirParam {
    /// Parameter identifier.
    pub name: String,
    /// Lowered MIR type.
    pub ty: MirType,
    /// Binding mode.
    pub kind: HirParamKind,
    /// Bound entry SSA local if applicable.
    pub local: Option<LocalId>,
    /// Canonical component/struct layout key for `&T` / `&mut T` / `&res T` parameters.
    #[serde(default)]
    pub layout_key: Option<String>,
}

/// Singleton resource borrow bound in a [`MirFunction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirResourceBinding {
    /// Parameter identifier (`clk`, `cfg`).
    pub param_name: String,
    /// Declared resource name (`SimClock`).
    pub resource_name: String,
    /// Canonical module-qualified layout name.
    pub canonical_name: String,
    /// `true` for `&mut res`, `false` for `&res`.
    pub mutable: bool,
    /// Entry-block pointer local (`Ptr` / `MutPtr`).
    pub ptr_local: LocalId,
}

/// Term-level descriptor inside [`MirQueryBinding`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirQueryTermBinding {
    /// Index within parent query's term list.
    pub term_idx: u32,
    /// Source binding alias (`p`, `h`, `x`).
    pub alias: String,
    /// Logical component or `@soa` stratum key (`CombatantBody::hot`).
    pub storage_key: String,
    /// Canonical solved layout name (`mod::CombatantBody`, `mod::CombatantBody__caps`).
    pub canonical_component: String,
    /// Optional projected field name (`Vel2D.vx` -> `Some("vx")`).
    pub field_name: Option<String>,
    /// Access mode (`Read`, `Write`, `SelectiveWrite`, `OptionalRead`, `OptionalWrite`).
    pub mode: TermAccessMode,
    /// `true` if component carries `@sparse`.
    pub is_sparse: bool,
}

/// Complete resolved binding metadata for one query inside a [`MirFunction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirQueryBinding {
    /// Query index matching `Inst::Iter* { query_idx, .. }`.
    pub query_idx: u32,
    /// Bound projection terms.
    pub terms: Vec<MirQueryTermBinding>,
    /// Positive `.with<T>()` filters.
    pub with_filters: Vec<String>,
    /// Negative `.without<T>()` filters.
    pub without_filters: Vec<String>,
    /// `true` for `query_one(...)` point lookups (`Slots 28–29`).
    pub is_point_lookup: bool,
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
    ConstVec {
        dims: u8,
        values: [f64; 4],
    },
    ConstString {
        value: String,
    },
    Copy {
        val: LocalId,
    },
    /// Allocates a mutable stack slot for local variable storage.
    SlotAlloc {
        ty: MirType,
    },
    /// Loads the current value from a [`Inst::SlotAlloc`] slot.
    SlotLoad {
        slot: LocalId,
    },
    /// Stores a value into a [`Inst::SlotAlloc`] slot.
    SlotStore {
        slot: LocalId,
        val: LocalId,
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
    Cast {
        val: LocalId,
        target_ty: MirType,
    },
    VecExtract {
        vec: LocalId,
        lane: u8,
    },
    VecInsert {
        vec: LocalId,
        lane: u8,
        val: LocalId,
    },
    VecSwizzle {
        vec: LocalId,
        lanes: Vec<u8>,
    },
    IntrinsicMath {
        name: String,
        args: Vec<LocalId>,
        deterministic: bool,
    },
    /// Calls a module helper [`MirFunction`] (`MirFnKind::HelperFn`).
    Call {
        callee: String,
        args: Vec<LocalId>,
    },
    /// Constructs an aggregate component/struct value in a temporary register.
    StructInit {
        type_name: String,
        fields: Vec<(String, LocalId)>,
    },
    /// Constructs a fixed-size array temporary.
    ArrayInit {
        elems: Vec<LocalId>,
    },
    /// Indexes an array temporary or pointer.
    ArrayIndex {
        base: LocalId,
        index: LocalId,
    },
    /// Writes `val` at element `index` of an array slot or array field pointer `base_ptr`.
    ArrayStore {
        base_ptr: LocalId,
        index: LocalId,
        val: LocalId,
        elem_ty: MirType,
    },
    /// Computes the typed pointer to a field inside a component/resource/struct pointer.
    FieldPtr {
        base_ptr: LocalId,
        layout_key: String,
        field: String,
        offset_bytes: u32,
    },
    /// Loads a field from a component/resource/struct pointer.
    FieldLoad {
        base_ptr: LocalId,
        layout_key: String,
        field: String,
        offset_bytes: u32,
        field_ty: MirType,
    },
    /// Stores a field into a component/resource/struct pointer.
    FieldStore {
        base_ptr: LocalId,
        layout_key: String,
        field: String,
        offset_bytes: u32,
        val: LocalId,
    },
    /// Computes the row pointer `base + row * stride` (or `@sparse` indirection).
    RowPtr {
        col_ptr: LocalId,
        row_idx: LocalId,
        stride_bytes: u32,
        is_sparse: bool,
    },
    /// Advances a query iterator to the next archetype chunk (`BamHostApi::iter_next_chunk`).
    IterNextChunk {
        query_idx: u32,
    },
    /// Returns the `u32` entity count for the current chunk.
    IterChunkLen {
        query_idx: u32,
    },
    /// Returns the `FfiEntity*` slice for the current chunk (`BamHostApi::iter_entities`).
    IterEntities {
        query_idx: u32,
    },
    /// Extracts the `Entity` at row index `row_idx` from `entities_ptr`.
    EntityAtRow {
        entities_ptr: LocalId,
        row_idx: LocalId,
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
    /// Borrows an untracked mutable column pointer for `&mut?` (`BamHostApi::iter_column_mutable_untracked`, Slot 14).
    IterColWriteUntracked {
        query_idx: u32,
        term_idx: u32,
        storage_key: String,
    },
    /// Flushes a contiguous dirty row range `(start, len)` (`BamHostApi::iter_mark_changed_range`, Slot 15).
    IterMarkChangedRange {
        query_idx: u32,
        term_idx: u32,
        run_start: LocalId,
        run_len: LocalId,
    },
    /// Batched `@sparse` row read (`BamHostApi::iter_column_rows_readonly`, Slot 16).
    IterColRowsRead {
        query_idx: u32,
        term_idx: u32,
        storage_key: String,
    },
    /// Batched `@sparse` row write (`BamHostApi::iter_column_rows_mutable`, Slot 17).
    IterColRowsWrite {
        query_idx: u32,
        term_idx: u32,
        storage_key: String,
    },
    /// Non-destructive query entity count (`BamHostApi::iter_count`, Slot 57).
    IterCount {
        query_idx: u32,
    },
    /// Walks ancestor relationship chain upward from `entity` for `term_idx` (`BamHostApi::iter_up_cascade`, Slot 58).
    IterUpCascade {
        query_idx: u32,
        relation: String,
        entity: LocalId,
        term_idx: u32,
    },
    /// Resets query iterator `query_idx` to chunk 0 (`BamHostApi::iter_reset`, Slot 10).
    IterReset {
        query_idx: u32,
    },
    /// Work-stealing parallel chunk dispatch (`BamHostApi::par_for_each_chunk`, Slot 27).
    ParForEachChunk {
        query_idx: u32,
        chunk_size: u32,
    },
    /// Zero-arena read-only parallel reduction (`BamHostApi::par_for_each_chunk_readonly`, Slot 59).
    ParForEachChunkReadonly {
        query_idx: u32,
        chunk_size: u32,
        deterministic_order: bool,
    },
    /// Initializes a parallel/loop reduction accumulator.
    ReduceInit {
        op: String,
        identity: LocalId,
    },
    /// Combines a per-row value into a reduction accumulator.
    ReduceAccum {
        acc: LocalId,
        op: String,
        val: LocalId,
    },
    /// Borrows a singleton resource pointer (`BamHostApi::res_ptr` / `sys_res_ptr`).
    ResRead {
        resource: String,
    },
    /// Borrows a mutable singleton resource pointer (`BamHostApi::res_mut_ptr` / `sys_res_mut_ptr`).
    ResWrite {
        resource: String,
    },
    /// Random-access read on one entity (`BamHostApi::sys_entity_get`, Slot 28).
    EntityGet {
        query_idx: u32,
        term_idx: u32,
        entity: LocalId,
        storage_key: String,
    },
    /// Random-access write on one entity (`BamHostApi::sys_entity_get_mut`, Slot 29).
    EntityGetMut {
        query_idx: u32,
        term_idx: u32,
        entity: LocalId,
        storage_key: String,
    },
    /// Binds a persistent named object (`BamHostApi::bind_named_object`, Slot 56).
    BindNamedObject {
        name: String,
    },
    /// Resolves a singleton named object entity handle (`Slot 56`).
    ResolveNamedObject {
        name: String,
    },
    /// Interns a `sym` handle (`BamHostApi::intern_symbol`).
    InternSymbol {
        symbol: String,
    },
    /// Extracts the incoming event payload inside an `obs` (`TriggerPayload`).
    TriggerPayload {
        event: String,
    },
    /// Extracts the target entity inside an `obs` (`trg.entity` / `trg.target`).
    TriggerTarget,
    /// Arms a `GraceWindow` (`remaining_sec = duration_sec`).
    GraceArm {
        ptr: LocalId,
        duration_sec: LocalId,
    },
    /// Ticks a `GraceWindow` down by `dt_sec`.
    GraceTick {
        ptr: LocalId,
        dt_sec: LocalId,
    },
    /// Returns `true` iff `GraceWindow.remaining_sec > 0.0`.
    GraceIsActive {
        ptr: LocalId,
    },
    /// Clears a `GraceWindow` (`remaining_sec = 0.0`).
    GraceClear {
        ptr: LocalId,
    },
    /// Pushes an action with validity duration into `InputBuffer<N>`.
    InputBufPush {
        ptr: LocalId,
        capacity: u32,
        action_id: LocalId,
        window_sec: LocalId,
    },
    /// Consumes a matching buffered action from `InputBuffer<N>`, returning `bool`.
    InputBufConsume {
        ptr: LocalId,
        capacity: u32,
        action_id: LocalId,
    },
    /// Peeks whether a matching buffered action exists in `InputBuffer<N>`.
    InputBufPeek {
        ptr: LocalId,
        capacity: u32,
        action_id: LocalId,
    },
    /// Ticks all active entries in `InputBuffer<N>` down by `dt_sec`.
    InputBufTick {
        ptr: LocalId,
        capacity: u32,
        dt_sec: LocalId,
    },
    /// Sets a bit index inside `BitSet<WORDS>`.
    BitSetSet {
        ptr: LocalId,
        words: u32,
        bit: LocalId,
    },
    /// Reads a bit index from `BitSet<WORDS>`.
    BitSetGet {
        ptr: LocalId,
        words: u32,
        bit: LocalId,
    },
    /// Clears a bit index inside `BitSet<WORDS>`.
    BitSetClear {
        ptr: LocalId,
        words: u32,
        bit: LocalId,
    },
    /// Tests whether a `TimelineCursor` window bit is active (`(active_mask & (1 << window_bit)) != 0`).
    TimelineInWindow {
        ptr: LocalId,
        window_bit: u32,
    },
    /// Deferred spawn (`BamHostApi::cmd_spawn` / `cmd_spawn_persistent`).
    CmdSpawn {
        persistent: bool,
        components: Vec<(String, LocalId)>,
    },
    /// SoA bulk spawn (`BamHostApi::cmd_spawn_batch`, Slot 39) for unindexed `spawn_batch(count) { ... }`.
    CmdSpawnBatch {
        count: LocalId,
        components: Vec<(String, LocalId)>,
    },
    /// Allocates an SoA batch spawn buffer of `count` (`MirType::U32`) entities for
    /// `components` and produces an opaque batch handle of type `MirType::U64`.
    SpawnBatchBegin {
        count: LocalId,
        components: Vec<String>,
    },
    /// Writes entity `index` (`MirType::U32`) initialized `components` (`(component_name, value_local)`)
    /// into the batch buffer `batch` (`MirType::U64`), producing `MirType::Unit` (`dst: None`).
    SpawnBatchPush {
        batch: LocalId,
        index: LocalId,
        components: Vec<(String, LocalId)>,
    },
    /// Commits the accumulated batch `batch` (`MirType::U64`) via ABI Slot 39 (`cmd_spawn_batch`)
    /// and frees any temporary buffers, producing `MirType::Unit` (`dst: None`).
    SpawnBatchCommit {
        batch: LocalId,
    },
    /// Deferred entity despawn (`BamHostApi::cmd_despawn`, Slot 23).
    CmdDespawn {
        entity: LocalId,
    },
    /// Bulk zone/group despawn (`BamHostApi::cmd_despawn_all`, Slot 40).
    CmdDespawnAll {
        filter: String,
    },
    /// Conditional component insert (`BamHostApi::cmd_insert` / `cmd_insert_if_new`, Slots 24/41).
    CmdInsert {
        entity: LocalId,
        component: String,
        data: Option<LocalId>,
        if_new: bool,
    },
    /// Deferred component removal (`BamHostApi::cmd_remove`, Slot 26).
    CmdRemove {
        entity: LocalId,
        component: String,
    },
    /// Deferred observer trigger (`BamHostApi::cmd_trigger` / `cmd_trigger_ex`, Slots 37/42).
    CmdTrigger {
        event: String,
        target: Option<LocalId>,
        payload: Option<LocalId>,
        propagate: bool,
    },
    /// Buffered message stream write (`BamHostApi::msg_send`, Slot 31).
    StreamEmit {
        stream: String,
        payload: LocalId,
    },
    /// Captures a LIFO transaction checkpoint (`BamHostApi::cmd_checkpoint`, Slot 63).
    CmdCheckpoint,
    /// Rolls back commands to checkpoint (`BamHostApi::cmd_rollback`, Slot 64).
    CmdRollback {
        checkpoint: LocalId,
    },
    /// Inserts a typed relation edge (`BamHostApi::cmd_insert_relation`, Slot 65).
    CmdInsertRelation {
        relation: String,
        entity: LocalId,
        target: LocalId,
        payload: Option<LocalId>,
    },
    /// Removes a typed relation edge (`BamHostApi::cmd_remove_relation`, Slot 66).
    CmdRemoveRelation {
        relation: String,
        entity: LocalId,
        target: LocalId,
    },
    /// Advances spatial ring cursor and zeroes `cell_offsets[0..=cell_count]` and `count` for active frame.
    SpatialCsrBegin {
        index_name: String,
    },
    /// Pass 1: Quantizes `pos` to `(cx, cy)` cell and increments `cell_offsets[cell + 1]`.
    SpatialCsrCount {
        index_name: String,
        pos: LocalId,
    },
    /// Computes exclusive prefix sum over `cell_offsets[0..=cell_count]` and initializes `write_cursors`.
    SpatialCsrPrefixSum {
        index_name: String,
    },
    /// Pass 2: Scatters `(entity, pos)` into `entities[slot]` & `positions[slot]` using `write_cursors[cell]++`.
    SpatialCsrScatter {
        index_name: String,
        entity: LocalId,
        pos: LocalId,
    },
    /// 2-pass counting-sort CSR spatial grid / history rebuild descriptor.
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
        center: LocalId,
        radius: LocalId,
    },
    /// Lag-compensated historical segment sweep over `spatial_history`.
    SpatialQuerySegmentAt {
        history_name: String,
        start: LocalId,
        end: LocalId,
        radius: LocalId,
        tick_offset: LocalId,
    },
    /// `O(1)` enum-indexed load from `.rodata` `table`.
    TableLoad {
        table_name: String,
        key: LocalId,
        field: String,
    },
    /// Branchless piecewise-linear `curve` interpolation.
    CurveSample {
        curve_name: String,
        x: LocalId,
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
        val: LocalId,
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
        cursor_ptr: LocalId,
        dt_sec: LocalId,
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
    /// Obtains the typed source row pointer inside a `MirFnKind::Migration` function (`Slot 67`).
    MigrateSrcPtr {
        layout_key: String,
    },
    /// Obtains the typed destination row pointer inside a `MirFnKind::Migration` function (`Slot 67`).
    MigrateDstPtr {
        layout_key: String,
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

/// Records a `.changed()` / `.changed<T>()` filter bound to a query term.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MirChangedTerm {
    /// Query index within [`MirFunction::query_bindings`].
    pub query_idx: u32,
    /// Term index within `MirQueryBinding::terms`.
    pub term_idx: u32,
    /// Logical storage key (`"Pos3D"` or `"Body::hot"`).
    pub storage_key: String,
    /// Canonical component layout name.
    pub canonical_component: String,
}

/// `Messages<M>` host ABI stream operation kind (Slots 30–32).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MirStreamOpKind {
    /// `msg_read_batch` (Slot 30).
    StreamRead,
    /// `msg_send` (Slot 31).
    StreamSend,
    /// `msg_write_batch` (Slot 32).
    StreamWriteBatch,
}

/// Host `Messages<M>` stream operation contract attached to a function or network module.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MirStreamOp {
    /// ABI stream operation kind (Slots 30–32).
    pub kind: MirStreamOpKind,
    /// Short stream or packet message name (e.g. `"StrataNetPacket"`).
    pub stream: String,
    /// Canonical stream or packet message name.
    pub canonical_stream: String,
    /// `true` when this op MUST execute outside `@par` chunk callbacks (Slots 30/32).
    pub requires_outside_par: bool,
    /// Optional network transport channel index.
    pub channel: Option<u8>,
}

/// Bit-packed quantization specification for a scalar or vector component/RPC field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MirQuantizeSpec {
    /// Field identifier.
    pub field_name: String,
    /// Number of scalar lanes (`1` for scalar, `2` for vec2, `3` for vec3, `4` for vec4).
    pub lane_count: u8,
    /// Bit width per lane (`1..=32`).
    pub bits: u8,
    /// Minimum representable value.
    pub min: f64,
    /// Maximum representable value.
    pub max: f64,
    /// Optional explicit quantization step (`> 0.0`).
    pub step: Option<f64>,
    /// Starting bit offset within the packed network wire frame.
    pub bit_offset: u32,
    /// Total packed bits for this field (`u32::from(bits) * u32::from(lane_count)`).
    pub total_bits: u32,
    /// Byte offset of this field inside the solved `#[repr(C)]` struct.
    pub field_byte_offset: u32,
    /// MIR type of the field.
    pub field_ty: MirType,
}

impl MirQuantizeSpec {
    /// Returns the maximum unsigned integer quantized level `(1u64 << bits) - 1`.
    #[must_use]
    pub fn max_quantized_u64(&self) -> u64 {
        if self.bits == 0 {
            0
        } else {
            (1u64 << self.bits.min(32)) - 1
        }
    }

    /// Returns the effective quantization step size (explicit `step` or `(max / max_level) - (min / max_level)`).
    #[must_use]
    pub fn effective_step(&self) -> f64 {
        self.step.unwrap_or_else(|| {
            let levels = self.max_quantized_u64().max(1) as f64;
            (self.max / levels) - (self.min / levels)
        })
    }
}

/// Wire field descriptor (either quantized or raw bit-packed) in a [`MirNetComponent`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MirNetFieldSpec {
    /// Field identifier.
    pub field_name: String,
    /// Byte offset in the solved `#[repr(C)]` struct.
    pub byte_offset: u32,
    /// Byte size in the solved `#[repr(C)]` struct.
    pub byte_size: u32,
    /// MIR field type.
    pub ty: MirType,
    /// Quantization specification if `@quantize(...)` applies to this field.
    pub quantize: Option<MirQuantizeSpec>,
    /// Starting bit offset within the packed network wire frame.
    pub bit_offset: u32,
    /// Total packed bit width for this field.
    pub total_bits: u32,
    /// Optional `@soa` split struct layout name (e.g. `Comp__cold_0`) when extracted from an SoA split.
    #[serde(default)]
    pub stratum_layout: Option<String>,
}

/// Lowered network replication, authority, and quantized bit-packing metadata for a component/resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MirNetComponent {
    /// Short component or resource name.
    pub name: String,
    /// Canonical namespaced name (`"mod::Comp"`).
    pub canonical_name: String,
    /// `true` for singleton `resource`, `false` for `component`.
    pub is_resource: bool,
    /// `true` when `@net(...)` is attached.
    pub is_replicated: bool,
    /// Packet reliability (`Reliable` / `Unreliable`).
    pub reliability: NetReliability,
    /// Optional send rate in Hz (`> 0.0`).
    pub rate_hz: Option<f64>,
    /// Optional send interval in ticks (`> 0`).
    pub interval_ticks: Option<u32>,
    /// Transport channel index (`0..=255`).
    pub channel: u8,
    /// Network authority ownership (`@authority(...)` / `@predicted`).
    pub authority: AuthorityKind,
    /// `true` when `@predicted` (or `@authority(predicted)`) is active.
    pub is_predicted: bool,
    /// Deterministic 64-bit FNV-1a schema fingerprint copied from `SolvedLayout`.
    pub schema_fingerprint: u64,
    /// Deterministic 128-bit `ComponentUuid` bytes copied from `SolvedLayout`.
    pub uuid_bytes: [u8; 16],
    /// Quantization specifications for quantized fields.
    pub quantize_specs: Vec<MirQuantizeSpec>,
    /// Ordered non-padding wire fields with bit offsets.
    pub wire_fields: Vec<MirNetFieldSpec>,
    /// Total packed bit count of all wire fields.
    pub packed_bits: u32,
    /// Total packed byte count (`packed_bits.div_ceil(8)`).
    pub packed_bytes: u32,
}

/// Lowered `rpc` declaration with wire ID, fingerprint, and payload field offsets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MirRpc {
    /// Short RPC name.
    pub name: String,
    /// Canonical namespaced RPC name (`"mod::MoveInput"`).
    pub canonical_name: String,
    /// RPC direction (`ClientToServer`, `ServerToClient`, `Bidirectional`).
    pub direction: NetDirection,
    /// Packet reliability (`Reliable`, `Unreliable`).
    pub reliability: NetReliability,
    /// Transport channel index (`0..=255`).
    pub channel: u8,
    /// Explicit authority classification if annotated.
    pub authority: AuthorityKind,
    /// Deterministic 64-bit FNV-1a RPC identifier.
    pub rpc_id: u64,
    /// Deterministic 64-bit FNV-1a schema fingerprint of the RPC payload and metadata.
    pub schema_fingerprint: u64,
    /// Ordered non-padding payload fields `(name, mir_ty, byte_offset, byte_size)`.
    pub fields: Vec<(String, MirType, u32, u32)>,
    /// Quantization specs for RPC fields (if any).
    pub quantize_specs: Vec<MirQuantizeSpec>,
    /// Ordered non-padding wire fields with bit offsets (quantized or raw).
    pub wire_fields: Vec<MirNetFieldSpec>,
    /// Total packed bit count of all wire fields.
    pub packed_bits: u32,
    /// Total packed byte count (`packed_bits.div_ceil(8)`).
    pub packed_bytes: u32,
    /// Total `#[repr(C)]` payload size in bytes.
    pub payload_bytes: u32,
}

/// Lowered `net_sim_test` virtual network simulation scenario.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MirNetSimTest {
    /// Test case name.
    pub name: String,
    /// Simulated one-way latency in milliseconds (`>= 0.0`).
    pub latency_ms: f64,
    /// Simulated jitter in milliseconds (`>= 0.0`).
    pub jitter_ms: f64,
    /// Packet loss probability in `0.0..=1.0`.
    pub loss: f64,
    /// Deterministic PRNG seed.
    pub seed: u64,
    /// Number of simulated clients (`>= 1`).
    pub clients: u32,
    /// Lowered test body statements.
    pub body: Vec<HirStmt>,
    /// Raw test body source text.
    pub body_source: String,
}

/// Deterministic network handshake fingerprint table emitted for connection validation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MirNetHandshake {
    /// Combined FNV-1a module network fingerprint (`0` when module has no net items/RPCs).
    pub module_net_fingerprint: u64,
    /// Sorted `(canonical_name, schema_fingerprint)` pairs for all [`MirNetComponent`]s.
    pub component_fingerprints: Vec<(String, u64)>,
    /// Sorted `(canonical_name, schema_fingerprint)` pairs for all [`MirRpc`]s.
    pub rpc_fingerprints: Vec<(String, u64)>,
}

/// Lowered MIR function representing a user `sys`, `obs`, `fn`, `migrate`, or synthesized system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MirFunction {
    /// Function/system name.
    pub name: String,
    /// Role classification (`System`, `Observer`, `HelperFn`, `Migration`, or synthesized).
    pub kind: MirFnKind,
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
    /// Function/system parameters.
    pub params: Vec<MirParam>,
    /// Return type (`MirType::Unit` for ECS systems).
    pub ret_ty: MirType,
    /// Bound resource borrows (`&res`, `&mut res`).
    pub resources: Vec<MirResourceBinding>,
    /// Resolved ECS query bindings.
    pub query_bindings: Vec<MirQueryBinding>,
    /// SSA local declarations (`locals[id.0]`).
    pub locals: Vec<MirLocal>,
    /// Basic blocks (`blocks[id.0]`).
    pub blocks: Vec<BasicBlock>,
    /// Bound ECS query access descriptors.
    pub queries: Vec<QueryAccessDesc>,
    /// Original source body retained for downstream backend compatibility.
    pub source_body: String,
    /// Explicit `@authority(...)` / `@predicted` classification.
    #[serde(default)]
    pub authority: AuthorityKind,
    /// `true` when `@predicted` (or `@authority(predicted)`) is active.
    #[serde(default)]
    pub is_predicted: bool,
    /// `true` when `@node_pure` is attached to a helper `fn`.
    #[serde(default)]
    pub is_node_pure: bool,
    /// Optional `@node_group("...")` label.
    #[serde(default)]
    pub node_group: Option<String>,
    /// `.changed()` / `.changed<T>()` filters bound to query terms.
    #[serde(default)]
    pub changed_terms: Vec<MirChangedTerm>,
    /// `.added()` / `.added<T>()` filters bound to query terms.
    #[serde(default)]
    pub added_terms: Vec<MirChangedTerm>,
    /// Raw `.added()` / `.added<T>()` filter component names keyed by query index.
    #[serde(default)]
    pub added_filters: Vec<(u32, String)>,
    /// Host `Messages<M>` stream operations used by this function.
    #[serde(default)]
    pub stream_ops: Vec<MirStreamOp>,
    /// Non-empty diagnostics collected during lowering (rejected by the MIR verifier).
    #[serde(default)]
    pub lowering_errors: Vec<String>,
}

impl MirFunction {
    /// Creates an empty [`MirFunction`] with sensible defaults.
    pub fn new(name: impl Into<String>, kind: MirFnKind) -> Self {
        let (is_observer, trigger_event) = match &kind {
            MirFnKind::Observer { event, .. } => (true, Some(event.clone())),
            _ => (false, None),
        };
        Self {
            name: name.into(),
            kind,
            is_observer,
            trigger_event,
            par_chunk: None,
            par_read_only: false,
            is_deterministic: false,
            params: Vec::new(),
            ret_ty: MirType::Unit,
            resources: Vec::new(),
            query_bindings: Vec::new(),
            locals: Vec::new(),
            blocks: Vec::new(),
            queries: Vec::new(),
            source_body: String::new(),
            authority: AuthorityKind::Unspecified,
            is_predicted: false,
            is_node_pure: false,
            node_group: None,
            changed_terms: Vec::new(),
            added_terms: Vec::new(),
            added_filters: Vec::new(),
            stream_ops: Vec::new(),
            lowering_errors: Vec::new(),
        }
    }

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
    /// Declared enums for discriminant and table-key lookup.
    pub enums: Vec<EnumDef>,
    /// Declared module constants.
    pub consts: Vec<HirConst>,
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
    /// Top-level helper functions (`MirFnKind::HelperFn`).
    pub fns: Vec<MirFunction>,
    /// All lowered and synthesized ECS systems, observers, and migrations.
    pub functions: Vec<MirFunction>,
    /// Module schedule trees (augmented with synthesized timer-tick, CSR rebuild, & state-machine systems).
    pub schedules: Vec<HirSchedule>,
    /// Embedded `sim_test` specs.
    pub sim_tests: Vec<HirSimTest>,
    /// Evaluated field defaults keyed by canonical layout name -> field name -> constant value.
    pub field_defaults: IndexMap<String, IndexMap<String, MirConstVal>>,
    /// Declared `rpc` definitions with payload layouts and wire IDs.
    #[serde(default)]
    pub rpcs: Vec<MirRpc>,
    /// Networked/authority/quantized component & resource descriptors.
    #[serde(default)]
    pub net_components: Vec<MirNetComponent>,
    /// Embedded `net_sim_test` scenarios.
    #[serde(default)]
    pub net_sim_tests: Vec<MirNetSimTest>,
    /// Deterministic handshake fingerprint table.
    #[serde(default)]
    pub net_handshake: MirNetHandshake,
    /// Module-level `Messages<StrataNetPacket>` stream contracts (Slots 30/32).
    #[serde(default)]
    pub net_stream_ops: Vec<MirStreamOp>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies `MirFunction::alloc_local` and `alloc_block` assign dense sequential IDs matching
    /// SSA vector indices.
    #[test]
    fn alloc_local_and_block_assign_sequential_indices() {
        let mut func = MirFunction::new("step", MirFnKind::System);
        let l0 = func.alloc_local("a", MirType::F32);
        let l1 = func.alloc_local("b", MirType::Bool);
        let b0 = func.alloc_block("entry", Terminator::Return(None));
        let b1 = func.alloc_block("exit", Terminator::Return(None));
        assert_eq!((l0.0, l1.0), (0, 1));
        assert_eq!((b0.0, b1.0), (0, 1));
    }
}
