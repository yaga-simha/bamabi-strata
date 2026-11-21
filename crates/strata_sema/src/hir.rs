//! Frozen `AnalyzedModule` HIR produced by `strata_sema` and consumed by `strata_mir`.

use crate::access::{ConcurrencyGraph, FilteredAccessSet, TermAccessMode};
use crate::diagnostics::Diagnostic;
use crate::layout::{EnumDef, SolvedLayout};
use crate::types::Ty;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Declared module version (`@version(x.y.z)`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SemVerInfo {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Patch version.
    pub patch: u32,
}

/// Binary arithmetic, bitwise, comparison, logical, or range operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HirBinOp {
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `%`
    Rem,
    /// `&`
    BitAnd,
    /// `|`
    BitOr,
    /// `^`
    BitXor,
    /// `<<`
    Shl,
    /// `>>`
    Shr,
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `&&`
    And,
    /// `||`
    Or,
    /// `..`
    Range,
    /// `..=`
    RangeInclusive,
}

/// Compound or plain assignment operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HirAssignOp {
    /// `=`
    Set,
    /// `+=`
    AddAssign,
    /// `-=`
    SubAssign,
    /// `*=`
    MulAssign,
    /// `/=`
    DivAssign,
    /// `%=`
    RemAssign,
    /// `&=`
    BitAndAssign,
    /// `|=`
    BitOrAssign,
    /// `^=`
    BitXorAssign,
    /// `<<=`
    ShlAssign,
    /// `>>=`
    ShrAssign,
}

/// Unary prefix operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HirUnOp {
    /// Arithmetic negation `-x`.
    Neg,
    /// Logical negation `!x`.
    Not,
    /// Bitwise negation `~x`.
    BitNot,
    /// Shared borrow `&x`.
    Ref,
    /// Mutable borrow `&mut x`.
    RefMut,
}

/// Classification of a callable or item parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HirParamKind {
    /// By-value parameter (`x: f32`).
    Value,
    /// Immutable singleton resource (`clk: &res SimClock`).
    ResRead,
    /// Mutable singleton resource (`clk: &mut res SimClock`).
    ResWrite,
    /// Observer event trigger parameter (`trg: &Trigger<Event, Target?>`).
    Trigger,
    /// Buffered stream reader (`s: stream_in<Msg>`).
    StreamIn,
    /// Shared reference parameter (`old: &HealthV1`).
    Ref,
    /// Mutable reference parameter (`x: &mut Foo`).
    RefMut,
}

/// Typed parameter on a `sys`, `obs`, `fn`, `task`, `fsm`, or `migrate`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirParam {
    /// Parameter identifier.
    pub name: String,
    /// Resolved static type (inner type for `&res R`, `&Trigger<E, T?>`, or `stream_in<S>`).
    pub ty: Ty,
    /// Parameter kind / borrow mode.
    pub kind: HirParamKind,
    /// Optional target component on `Trigger<Event, TargetComp>`.
    pub trigger_target: Option<String>,
    /// Optional default initializer expression (e.g. `speed: mps = 26.0_mps`).
    pub default: Option<HirExpr>,
}

/// Single bound query term inside a `query(...)`, `query_one(...)`, or `task on (...)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HirQueryTerm {
    /// Loop-element field alias (`xyz` in `xyz: &mut Pos3D.xyz`, or component short name).
    pub alias: String,
    /// Logical storage key (`"Pos3D"`, `"CombatantBody::hot"`, `"CombatantBody::caps"`).
    pub storage_key: String,
    /// Canonical solved layout name (`"genres::soulslike::CombatantBody"`).
    pub canonical_component: String,
    /// Optional projected field name (`Some("xyz")`).
    pub field_name: Option<String>,
    /// Borrow mode (`Read`, `Write`, `SelectiveWrite`, `OptionalRead`, `OptionalWrite`, etc.).
    pub mode: TermAccessMode,
    /// `true` when the target component uses `@sparse` storage (`SparseSet`).
    pub is_sparse: bool,
}

/// Typed `query(...)` or `query_one(...)` expression with filter/point-lookup modifiers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirQuery {
    /// `true` for `query_one(...)`, `false` for `query(...)`.
    pub is_point_lookup: bool,
    /// Ordered projected/borrowed component terms.
    pub terms: Vec<HirQueryTerm>,
    /// `.with<T>()` archetype inclusion filters.
    pub with_filters: Vec<String>,
    /// `.without<T>()` archetype exclusion filters.
    pub without_filters: Vec<String>,
    /// `.allow<T>()` disabling-filter bypasses.
    pub allow_filters: Vec<String>,
    /// `.has<T>()` presence indicators.
    pub has_filters: Vec<String>,
    /// Optional `.where(predicate)` row filter expression.
    pub where_pred: Option<Box<HirExpr>>,
    /// Optional `.on(target)` entity/object expression for `query_one(...)`.
    pub on_target: Option<Box<HirExpr>>,
    /// Optional `.up<Rel>()` / relation cascade target.
    pub up_relation: Option<String>,
    /// `true` when `.count()` is invoked on the query (`Slot 57`).
    pub is_count: bool,
    /// `true` when `.unwrap()` is invoked on `query_one(...)`.
    pub is_unwrap: bool,
    /// Matched query index in the enclosing callable's `FilteredAccessSet`.
    pub query_idx: Option<u32>,
}

/// Single component initializer (`Comp { field: expr, ... }`) in `spawn`, `spawn_batch`, or `object`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirCompInit {
    /// Component or tag short/path name (`"Pos2D"`, `"RespawnAtGrace"`).
    pub component: String,
    /// Canonical layout name if resolved.
    pub canonical_component: Option<String>,
    /// Explicit `(field_name, value_expr)` initializers.
    pub fields: Vec<(String, HirExpr)>,
}

/// Entity spawn (`spawn { ... }`, `spawn @persistent { ... }`, or `spawn_batch(n) |i| { ... }`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirSpawn {
    /// `@persistent` marker (`Slot 38`).
    pub is_persistent: bool,
    /// `true` for `spawn_batch(...)` (`Slot 39`).
    pub is_batch: bool,
    /// Batch count expression for `spawn_batch(count)`.
    pub count: Option<Box<HirExpr>>,
    /// Loop index variable name for `spawn_batch(n) |idx| { ... }`.
    pub batch_var: Option<String>,
    /// Preamble statements computed inside the `spawn_batch` closure per entity.
    pub preamble: Vec<HirStmt>,
    /// Component/tag initializers for each spawned entity.
    pub components: Vec<HirCompInit>,
}

/// Function, method, or built-in call expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirCall {
    /// Optional receiver expression for `recv.method(args)`.
    pub receiver: Option<Box<HirExpr>>,
    /// Function, path, or method identifier (`"vec3"`, `"min"`, `"BladeSlash::start"`, `"push"`).
    pub callee: String,
    /// Generic type/const arguments (`<T>`).
    pub generic_args: Vec<String>,
    /// Positional or named call arguments.
    pub args: Vec<HirExpr>,
    /// Optional argument labels parallel to `args`.
    pub arg_names: Vec<Option<String>>,
    /// Resolved return type.
    pub ty: Ty,
}

/// Assignable destination expression (`lvalue`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HirLValue {
    /// Local variable or query loop binding (`x`, `vel`).
    Local {
        /// Identifier name.
        name: String,
        /// Resolved type.
        ty: Ty,
    },
    /// Field or vector lane access (`d.dxyz.y`, `clk.hitstop_rem`, `c.caps.poise_delay_rem`).
    Field {
        /// Base lvalue.
        base: Box<HirLValue>,
        /// Field or lane name.
        field: String,
        /// Resolved field type.
        ty: Ty,
    },
    /// Array/buffer indexing (`arr[i]`).
    Index {
        /// Base lvalue.
        base: Box<HirLValue>,
        /// Index expression.
        index: Box<HirExpr>,
        /// Element type.
        ty: Ty,
    },
    /// Direct singleton resource access expression (`res_mut<PadInput>()`).
    ResourceAccess {
        /// Resource name.
        resource: String,
        /// `true` for `res_mut<R>()`, `false` for `res<R>()`.
        is_mut: bool,
        /// Resolved resource type.
        ty: Ty,
    },
}

impl HirLValue {
    /// Returns the static [`Ty`] of this lvalue.
    #[must_use]
    pub fn ty(&self) -> &Ty {
        match self {
            Self::Local { ty, .. }
            | Self::Field { ty, .. }
            | Self::Index { ty, .. }
            | Self::ResourceAccess { ty, .. } => ty,
        }
    }
}

/// Pattern in `let`, `if let`, `for`, and `match` arms.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HirPattern {
    /// Wildcard `_`.
    Wildcard,
    /// Variable binding `x` or `mut x`.
    Binding {
        /// Variable identifier.
        name: String,
        /// Mutability flag.
        mutable: bool,
    },
    /// Constant literal pattern (`0`, `-1`, `true`).
    Literal(Box<HirExpr>),
    /// Enum unit variant or path (`Season::Spring`, `None`).
    Path(String),
    /// Tuple destructuring `(a, b)`.
    Tuple(Vec<HirPattern>),
    /// Tuple-struct / enum pattern (`Some(x)`).
    TupleStruct {
        /// Path name (`"Some"`).
        path: String,
        /// Inner field patterns.
        fields: Vec<HirPattern>,
    },
}

/// Single arm inside a `match` expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirMatchArm {
    /// Arm match pattern.
    pub pattern: HirPattern,
    /// Optional `if guard` condition.
    pub guard: Option<HirExpr>,
    /// Arm body expression or block.
    pub body: HirExpr,
}

/// Typed `match` expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirMatch {
    /// Scrutinee expression.
    pub scrutinee: Box<HirExpr>,
    /// Match arms in source order.
    pub arms: Vec<HirMatchArm>,
    /// Result type of the match expression.
    pub ty: Ty,
}

/// Iteration source for `for pat in iter`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HirForIter {
    /// ECS query iteration (`for d in query(...)`).
    Query(HirQuery),
    /// Half-open or inclusive integer range (`0..10` or `0..=10`).
    Range {
        /// Inclusive start bound.
        start: Box<HirExpr>,
        /// End bound.
        end: Box<HirExpr>,
        /// `true` for `..=`, `false` for `..`.
        inclusive: bool,
    },
    /// Spatial grid broadphase disc scan (`grid.query_disc(center, radius)`).
    SpatialDisc {
        /// Spatial grid resource name.
        grid: String,
        /// Disc center expression (`vec2`/`vec3`).
        center: Box<HirExpr>,
        /// Disc radius expression.
        radius: Box<HirExpr>,
    },
    /// Spatial history lag-compensated segment sweep (`hist.query_segment_at(tick, p0, p1)`).
    SpatialSegmentAt {
        /// Spatial history resource name.
        history: String,
        /// Rewind tick expression.
        tick: Box<HirExpr>,
        /// Segment start position.
        p0: Box<HirExpr>,
        /// Segment end position.
        p1: Box<HirExpr>,
    },
    /// Fallback generic iterable expression.
    Expr(Box<HirExpr>),
}

/// Single entry in a `for ... reduce (...)` clause.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirReduceEntry {
    /// Accumulator output name (`min_hp`, `hot_cnt`, `total`).
    pub name: String,
    /// Reduction operator (`"min"`, `"max"`, `"sum"`, `"prod"`, `"any"`, `"all"`).
    pub op: String,
    /// Identity seed expression.
    pub identity: HirExpr,
    /// Per-row value expression.
    pub value: HirExpr,
    /// Resolved accumulator scalar type.
    pub ty: Ty,
}

/// Typed `for` loop or parallel reduction expression.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirFor {
    /// Loop variable pattern (`d`, `p`, `i`).
    pub binding: HirPattern,
    /// Iterator source.
    pub iter: HirForIter,
    /// Imperative loop body (empty when `reduce` is non-empty).
    pub body: Vec<HirStmt>,
    /// Optional `reduce (...)` reduction entries.
    pub reduce: Vec<HirReduceEntry>,
    /// Result type (`Ty::Unit` for imperative loops, scalar/tuple for `reduce`).
    pub ty: Ty,
}

/// Transactional `atomic { ... } on_rollback { ... }` block (`Slots 63–64`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirAtomic {
    /// Transactional body statements.
    pub body: Vec<HirStmt>,
    /// Rollback handler statements executed if `require_true` fails.
    pub on_rollback: Vec<HirStmt>,
}

/// Typed HIR expression node lowered directly from `rowan` CST.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HirExpr {
    /// Integer literal (`IntLit`).
    IntLit {
        /// Signed 64-bit integer value.
        value: i64,
        /// Resolved integer type.
        ty: Ty,
    },
    /// Float or SI-normalized unit literal (`FloatLit` / `UnitLit`).
    FloatLit {
        /// Numeric value normalized to SI base units (`_ms` -> `* 0.001`, `_deg` -> `* PI / 180.0`).
        value: f64,
        /// Resolved float or unit scalar type.
        ty: Ty,
    },
    /// Boolean literal (`true` / `false`).
    BoolLit(bool),
    /// String literal (`"..."`).
    StringLit(String),
    /// Character literal (`'a'`).
    CharLit(char),
    /// Path or variable reference (`x`, `GRAVITY`, `Action::Jump`, `vec3::ZERO`).
    Path {
        /// Full path text.
        name: String,
        /// Resolved type.
        ty: Ty,
    },
    /// Unary prefix operation.
    Unary {
        /// Unary operator.
        op: HirUnOp,
        /// Operand expression.
        expr: Box<HirExpr>,
        /// Result type.
        ty: Ty,
    },
    /// Binary operation.
    Binary {
        /// Binary operator.
        op: HirBinOp,
        /// Left-hand side.
        lhs: Box<HirExpr>,
        /// Right-hand side.
        rhs: Box<HirExpr>,
        /// Result type.
        ty: Ty,
    },
    /// Explicit type cast (`expr as Ty`).
    Cast {
        /// Source expression.
        expr: Box<HirExpr>,
        /// Target type.
        target_ty: Ty,
    },
    /// Field access or vector swizzle (`d.xyz.y`, `p.pos.xz`, `trg.payload`).
    Field {
        /// Base expression.
        base: Box<HirExpr>,
        /// Field or swizzle name.
        field: String,
        /// Resolved field type.
        ty: Ty,
    },
    /// Table lookup (`CropSpec[p.plot.crop]`) or array indexing (`arr[i]`).
    Index {
        /// Base expression.
        base: Box<HirExpr>,
        /// Index expression.
        index: Box<HirExpr>,
        /// Element/row type.
        ty: Ty,
    },
    /// Function, method, or builtin call.
    Call(HirCall),
    /// Standalone `query(...)` or `query_one(...)` expression.
    Query(HirQuery),
    /// Struct, component, event, or stream literal (`Health { hp: 100.0 }`).
    StructLit {
        /// Struct/component/event/stream name.
        name: String,
        /// Field initializer list.
        fields: Vec<(String, HirExpr)>,
        /// Resolved struct type.
        ty: Ty,
    },
    /// Anonymous record literal (`{ field: val }`).
    RecordLit {
        /// Field initializers.
        fields: Vec<(String, HirExpr)>,
        /// Resolved type.
        ty: Ty,
    },
    /// Component bundle literal (`{ CompA { ... }, CompB { ... } }`).
    BundleLit {
        /// Component initializers.
        components: Vec<HirCompInit>,
    },
    /// Array literal (`[a, b, c]`).
    ArrayLit {
        /// Element expressions.
        elems: Vec<HirExpr>,
        /// Array type.
        ty: Ty,
    },
    /// Tuple literal (`(a, b)` or `()`).
    Tuple {
        /// Element expressions.
        elems: Vec<HirExpr>,
        /// Tuple or unit type.
        ty: Ty,
    },
    /// Lexical block `{ stmts; tail? }`.
    Block {
        /// Block statements.
        stmts: Vec<HirStmt>,
        /// Optional trailing expression value.
        tail: Option<Box<HirExpr>>,
        /// Block result type.
        ty: Ty,
    },
    /// Conditional `if cond { ... } else { ... }` or `if let pat = expr { ... } else { ... }`.
    If {
        /// Optional pattern for `if let pat = cond`.
        let_pat: Option<HirPattern>,
        /// Condition expression (or scrutinee when `let_pat` is `Some`).
        cond: Box<HirExpr>,
        /// Then-branch statements.
        then_stmts: Vec<HirStmt>,
        /// Optional then-branch value expression.
        then_tail: Option<Box<HirExpr>>,
        /// Else-branch statements.
        else_stmts: Vec<HirStmt>,
        /// Optional else-branch value expression.
        else_tail: Option<Box<HirExpr>>,
        /// Unified branch result type.
        ty: Ty,
    },
    /// Pattern match expression.
    Match(HirMatch),
    /// Loop or parallel reduction expression.
    For(HirFor),
    /// Entity spawn or bulk batch spawn.
    Spawn(HirSpawn),
    /// Bulk filter-matched entity despawn (`despawn_all<With<Tag>>()`).
    DespawnAll {
        /// Filter type arguments (e.g. `"With<TransientRoomEntity>"`).
        filters: Vec<String>,
    },
    /// Conditional or unconditional component insertion (`insert(...)` / `insert @if_new(...)`).
    Insert {
        /// `true` when `@if_new` attribute is attached (`Slot 41`).
        if_new: bool,
        /// Target entity expression.
        entity: Box<HirExpr>,
        /// Component/timeline/task value expression.
        value: Box<HirExpr>,
    },
    /// Component removal (`remove<Comp>(entity)`).
    Remove {
        /// Component name to remove.
        component: String,
        /// Target entity expression.
        entity: Box<HirExpr>,
    },
}

impl HirExpr {
    /// Returns the static [`Ty`] of this expression.
    #[must_use]
    pub fn ty(&self) -> Ty {
        match self {
            Self::IntLit { ty, .. }
            | Self::FloatLit { ty, .. }
            | Self::Path { ty, .. }
            | Self::Unary { ty, .. }
            | Self::Binary { ty, .. }
            | Self::Field { ty, .. }
            | Self::Index { ty, .. }
            | Self::StructLit { ty, .. }
            | Self::RecordLit { ty, .. }
            | Self::ArrayLit { ty, .. }
            | Self::Tuple { ty, .. }
            | Self::Block { ty, .. }
            | Self::If { ty, .. } => ty.clone(),
            Self::BoolLit(_) => Ty::Bool,
            Self::StringLit(_) => Ty::InlineStr(64),
            Self::CharLit(_) => Ty::U8,
            Self::Cast { target_ty, .. } => target_ty.clone(),
            Self::Call(c) => c.ty.clone(),
            Self::Match(m) => m.ty.clone(),
            Self::For(f) => f.ty.clone(),
            Self::Query(q) => {
                if q.is_count {
                    Ty::U32
                } else {
                    Ty::Unknown
                }
            }
            Self::Spawn(_)
            | Self::BundleLit { .. }
            | Self::DespawnAll { .. }
            | Self::Insert { .. }
            | Self::Remove { .. } => Ty::Unit,
        }
    }
}

/// Typed HIR statement lowered directly from `rowan` CST.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HirStmt {
    /// `let pat [: ty] = expr [else { ... }];` or `uniform let pat [: ty] = expr;`.
    Let {
        /// Binding pattern.
        pattern: HirPattern,
        /// Explicit type annotation if present.
        ty: Option<Ty>,
        /// Initializer expression.
        value: HirExpr,
        /// `true` for `uniform let`.
        is_uniform: bool,
        /// Optional `else { ... }` diverging block (`let Some(w) = ... else { ... };`).
        else_block: Vec<HirStmt>,
    },
    /// Assignment statement (`target op= value;`).
    Assign {
        /// Destination lvalue.
        target: HirLValue,
        /// Assignment operator.
        op: HirAssignOp,
        /// Value expression.
        value: HirExpr,
    },
    /// Expression evaluated for side effects.
    Expr(HirExpr),
    /// `return expr?;`.
    Return(Option<HirExpr>),
    /// `break expr?;`.
    Break(Option<HirExpr>),
    /// `continue;`.
    Continue,
    /// `while cond { body }`.
    While {
        /// Loop condition.
        cond: HirExpr,
        /// Loop body statements.
        body: Vec<HirStmt>,
    },
    /// Infinite `loop { body }`.
    Loop {
        /// Loop body statements.
        body: Vec<HirStmt>,
    },
    /// Transactional `atomic { ... } on_rollback { ... }`.
    Atomic(HirAtomic),
    /// Task `abort_if cond { cleanup }`.
    AbortIf {
        /// Abort condition expression.
        cond: HirExpr,
        /// Cleanup statements executed on abort before removing task.
        cleanup: Vec<HirStmt>,
    },
    /// Task `wait duration;`.
    Wait(HirExpr),
    /// Task `wait_until cond;`.
    WaitUntil(HirExpr),
    /// Task `yield_tick;`.
    YieldTick,
    /// Task `race { branch { ... } ... }`.
    Race {
        /// Competing branch statement sequences.
        branches: Vec<Vec<HirStmt>>,
    },
    /// `require_true(cond);` assertion inside `atomic`.
    RequireTrue(HirExpr),
    /// `trigger(target, event)` (`Slots 37/42`).
    Trigger {
        /// Target entity or `self`.
        target: Box<HirExpr>,
        /// Event payload struct literal or expression.
        event: Box<HirExpr>,
        /// Propagation flag (`Slot 42`).
        propagate: bool,
    },
    /// `emit(stream_expr)` (`Slot 31`).
    Emit(HirExpr),
    /// `despawn(entity)` (`Slot 23`).
    Despawn(HirExpr),
    /// `insert_relation<Rel>(entity, target, payload?)` (`Slot 65`).
    InsertRelation {
        /// Relation name.
        relation: String,
        /// Source entity.
        entity: Box<HirExpr>,
        /// Target entity.
        target: Box<HirExpr>,
        /// Optional relation payload.
        payload: Option<Box<HirExpr>>,
    },
    /// `remove_relation<Rel>(entity, target)` (`Slot 66`).
    RemoveRelation {
        /// Relation name.
        relation: String,
        /// Source entity.
        entity: Box<HirExpr>,
        /// Target entity.
        target: Box<HirExpr>,
    },
}

/// Analyzed `const` declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirConst {
    /// Constant identifier.
    pub name: String,
    /// Declared static type.
    pub ty: Ty,
    /// Raw expression source text.
    pub value_expr: String,
    /// Typed constant initializer expression.
    pub expr: Option<HirExpr>,
}

/// Analyzed `table` declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirTable {
    /// Table name.
    pub name: String,
    /// Key enum name.
    pub key_enum: String,
    /// Row fields `(name, ty)`.
    pub fields: Vec<(String, Ty)>,
    /// Row entries `(variant_name, fields_source)`.
    pub rows: Vec<(String, String)>,
    /// Typed row entries `(variant_name, vec_of_(field_name, value_expr))`.
    pub typed_rows: Vec<(String, Vec<(String, HirExpr)>)>,
}

/// Analyzed `curve` declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirCurve {
    /// Curve name.
    pub name: String,
    /// Domain type.
    pub input_ty: Ty,
    /// Range type.
    pub output_ty: Ty,
    /// Ordered `(x, y)` control points (SI-normalized).
    pub points: Vec<(f64, f64)>,
}

/// Analyzed `relation` declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HirRelation {
    /// Canonical `"ns::Rel"` name.
    pub canonical_name: String,
    /// Short name.
    pub name: String,
    /// Relation flags (`exclusive`, `symmetric`, `acyclic`, `cascade_despawn`, `cleanup_remove`, `self_ok`).
    pub flags: Vec<String>,
    /// Optional edge payload layout.
    pub payload_layout: Option<SolvedLayout>,
}

/// Analyzed `spatial_grid` or `spatial_history` declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HirSpatialIndex {
    /// Index identifier.
    pub name: String,
    /// `true` for `spatial_history`, `false` for `spatial_grid`.
    pub is_history: bool,
    /// History frame ring depth (`1` for static grid).
    pub frames: u32,
    /// Over target component or tag.
    pub over_component: String,
    /// Position field path (`Pos2D.xy`, `Pos3D.xyz`).
    pub by_field_path: String,
    /// Optional cached narrowphase components.
    pub cached_components: Vec<String>,
    /// Synthesized backing resource layout.
    pub resource_layout: SolvedLayout,
}

/// Analyzed `timeline` window interval and event trigger edge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirTimeline {
    /// Canonical timeline name.
    pub canonical_name: String,
    /// Short name.
    pub name: String,
    /// Tick rate in Hz (e.g. `60` or `120`).
    pub rate_hz: u32,
    /// Total timeline duration in frames.
    pub duration_frames: u32,
    /// Named windows `(window_name, start_frame, end_frame, bit_index)`.
    pub windows: Vec<(String, u32, u32, u8)>,
    /// Edge triggers `(frame, stmt_source)`.
    pub triggers: Vec<(u32, String)>,
    /// Typed edge trigger actions `(frame, statements)`.
    pub typed_triggers: Vec<(u32, Vec<HirStmt>)>,
    /// Synthesized 16-byte `@sparse` cursor layout.
    pub cursor_layout: SolvedLayout,
}

/// Analyzed `task` coroutine declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirTask {
    /// Task name.
    pub name: String,
    /// `@sparse` marker.
    pub is_sparse: bool,
    /// Parameters `(name, ty)`.
    pub params: Vec<(String, Ty)>,
    /// Typed parameters with optional defaults.
    pub typed_params: Vec<HirParam>,
    /// Target entity query terms (`on (...)`).
    pub on_terms: Vec<String>,
    /// Typed target entity query terms (`on (...)`).
    pub typed_on_terms: Vec<HirQueryTerm>,
    /// Resource borrows (`using (...)`).
    pub using_params: Vec<String>,
    /// Typed resource parameters (`using (...)`).
    pub typed_using_params: Vec<HirParam>,
    /// Live variables crossing suspension points (`wait`/`wait_until`/`yield_tick`/`race`).
    pub live_across_wait: Vec<(String, Ty)>,
    /// Synthesized `@sparse` `AbiPod` state struct layout.
    pub state_layout: SolvedLayout,
    /// Filtered access signature for scheduling and parallelism.
    pub access: FilteredAccessSet,
    /// Raw task body source.
    pub body_source: String,
    /// Lowered task body statements.
    pub body: Vec<HirStmt>,
}

/// Typed `fsm` transition rule (`to Target when guard @priority(N);`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirFsmTransition {
    /// Source state name.
    pub from_state: String,
    /// Target state name.
    pub to_state: String,
    /// Typed guard predicate expression.
    pub guard: HirExpr,
    /// Explicit transition priority (higher evaluated first, default `0`).
    pub priority: i32,
    /// Optional state payload arguments (`to State { field: expr }`).
    pub target_args: Vec<(String, HirExpr)>,
}

/// Typed `fsm` state declaration with fields and lifecycle hooks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirFsmState {
    /// State name.
    pub name: String,
    /// State-local fields `(name, ty, default_expr)`.
    pub fields: Vec<(String, Ty, Option<HirExpr>)>,
    /// `on_enter { ... }` statements.
    pub on_enter: Vec<HirStmt>,
    /// `on_tick { ... }` statements.
    pub on_tick: Vec<HirStmt>,
    /// `on_exit { ... }` statements.
    pub on_exit: Vec<HirStmt>,
}

/// Analyzed `fsm` state machine declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirFsm {
    /// FSM name.
    pub name: String,
    /// `@persist` marker.
    pub is_persist: bool,
    /// Initial state name.
    pub initial_state: String,
    /// Declared state names.
    pub states: Vec<String>,
    /// Transitions `(from_state, to_state, guard_expr, priority)`.
    pub transitions: Vec<(String, String, String, i32)>,
    /// Typed FSM parameters (`fsm Foo(cal: &res Calendar)`).
    pub params: Vec<HirParam>,
    /// Typed state transitions.
    pub typed_transitions: Vec<HirFsmTransition>,
    /// Typed state hooks and local fields.
    pub state_hooks: Vec<HirFsmState>,
    /// Synthesized component layout.
    pub state_layout: SolvedLayout,
    /// Filtered access signature.
    pub access: FilteredAccessSet,
}

/// Declared `effects(...)` contract on a `sys` or `obs`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EffectsSpec {
    /// `reads: [...]`.
    pub reads: Vec<String>,
    /// `writes: [...]`.
    pub writes: Vec<String>,
    /// `spawns: [...]`.
    pub spawns: Vec<String>,
    /// `despawns: [...]`.
    pub despawns: Vec<String>,
    /// `triggers: [...]`.
    pub triggers: Vec<String>,
    /// `emits: [...]`.
    pub emits: Vec<String>,
}

/// Analyzed `sys` or `obs` function.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirCallable {
    /// Function name.
    pub name: String,
    /// `true` for `obs`, `false` for `sys`.
    pub is_observer: bool,
    /// Trigger event type if observer.
    pub trigger_event: Option<String>,
    /// Optional target component type for `Trigger<Event, TargetComp>`.
    pub trigger_target_comp: Option<String>,
    /// `@par(chunk = N)` chunk size if present.
    pub par_chunk: Option<u32>,
    /// `@par(read_only, ...)` flag.
    pub par_read_only: bool,
    /// `effects(...)` declaration if present.
    pub declared_effects: Option<EffectsSpec>,
    /// Verified `FilteredAccessSet` signature.
    pub access: FilteredAccessSet,
    /// Typed system/observer parameters (`clk: &res SimClock`, `trg: &Trigger<...>`).
    pub params: Vec<HirParam>,
    /// Typed body statements lowered from CST.
    pub body: Vec<HirStmt>,
    /// Body source text (retained for downstream context).
    pub body_source: String,
    /// Raw CST byte range `(start, end)` of the callable.
    pub byte_range: (u32, u32),
}

/// Analyzed top-level `fn` helper function.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirFn {
    /// Function name.
    pub name: String,
    /// Generic parameter names.
    pub generic_params: Vec<String>,
    /// Typed function parameters.
    pub params: Vec<HirParam>,
    /// Return type (`Ty::Unit` when omitted).
    pub ret_ty: Ty,
    /// Body statements.
    pub body: Vec<HirStmt>,
    /// Optional trailing expression returned by the block.
    pub tail: Option<HirExpr>,
    /// Raw CST byte range `(start, end)`.
    pub byte_range: (u32, u32),
}

/// Analyzed `schedule` tree node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HirScheduleGroup {
    /// Group mode (`seq`, `seq_weak`, `par`, `set`, `leaf`).
    pub kind: String,
    /// Group or system name.
    pub name: String,
    /// Nested children.
    pub children: Vec<HirScheduleGroup>,
}

/// Analyzed `schedule` declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirSchedule {
    /// Schedule label (`Startup`, `FixedUpdate`, `Update`).
    pub label: String,
    /// Optional `run_if(...)` condition source.
    pub run_if: Option<String>,
    /// Typed `run_if(...)` condition expression.
    pub run_if_expr: Option<HirExpr>,
    /// Schedule DAG nodes.
    pub nodes: Vec<HirScheduleGroup>,
}

/// Analyzed `object` / `@persist object` singleton entity declaration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirObject {
    /// Object name.
    pub name: String,
    /// `@persist` marker.
    pub is_persist: bool,
    /// Attached component names.
    pub components: Vec<String>,
    /// Typed component initializers preserving field values (e.g. `Pos2D { xy: vec2(0.0, 2.0) }`).
    pub inits: Vec<HirCompInit>,
}

/// Analyzed `migrate` declaration (`v1 -> v2`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirMigration {
    /// Target component name.
    pub component: String,
    /// Source SemVer string.
    pub from_ver: String,
    /// Target SemVer string.
    pub to_ver: String,
    /// Source parameter identifier (`old`).
    pub param_name: String,
    /// Source row type (`&HealthV1` / `HealthV1`).
    pub from_type: Ty,
    /// Target component type (`Health`).
    pub to_type: Ty,
    /// Lowered migration body statements.
    pub body: Vec<HirStmt>,
    /// Optional trailing migration value expression (e.g. `Health { ... }`).
    pub tail: Option<HirExpr>,
    /// Migration body source.
    pub body_source: String,
}

/// Analyzed `sim_test` headless test block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HirSimTest {
    /// Test case name.
    pub name: String,
    /// Lowered test body statements.
    pub body: Vec<HirStmt>,
    /// Test body source.
    pub body_source: String,
}

/// Complete frozen semantic output for one Strata module, consumed directly by `strata_mir`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalyzedModule {
    /// Canonical module path (`"tutorial::rain_swarm"`).
    pub module_path: String,
    /// Module `@version(...)` if specified.
    pub version: Option<SemVerInfo>,
    /// `@deterministic` module-level invariant flag.
    pub is_deterministic: bool,
    /// All solved component/stratum/struct/resource/event/stream layouts keyed by canonical name.
    pub layouts: IndexMap<String, SolvedLayout>,
    /// Mapping from `@soa` logical component short name -> stratum names (`["DroneHull", "DroneHull__telemetry"]`).
    pub soa_strata: IndexMap<String, Vec<String>>,
    /// Declared enums.
    pub enums: IndexMap<String, EnumDef>,
    /// Declared tags.
    pub tags: Vec<String>,
    /// Declared constants.
    pub consts: Vec<HirConst>,
    /// Declared tables.
    pub tables: Vec<HirTable>,
    /// Declared curves.
    pub curves: Vec<HirCurve>,
    /// Declared relations.
    pub relations: Vec<HirRelation>,
    /// Declared spatial grids & histories.
    pub spatial_indices: Vec<HirSpatialIndex>,
    /// Declared timelines.
    pub timelines: Vec<HirTimeline>,
    /// Declared stackless tasks.
    pub tasks: Vec<HirTask>,
    /// Declared FSMs.
    pub fsms: Vec<HirFsm>,
    /// Declared systems and observers.
    pub callables: Vec<HirCallable>,
    /// Declared top-level helper functions (`fn`).
    pub fns: Vec<HirFn>,
    /// Declared named objects.
    pub objects: Vec<HirObject>,
    /// Declared schema migrations.
    pub migrations: Vec<HirMigration>,
    /// Declared schedules.
    pub schedules: Vec<HirSchedule>,
    /// Declared embedded `sim_test`s.
    pub sim_tests: Vec<HirSimTest>,
    /// Default field expressions parsed from `FieldDecl` CST: `canonical_layout -> field_name -> HirExpr`.
    pub field_defaults: IndexMap<String, IndexMap<String, HirExpr>>,
    /// Pairwise Theorem 0.1 parallelism / conflict graph.
    pub concurrency_graph: ConcurrencyGraph,
    /// All semantic errors and warnings accumulated across every pass.
    pub diagnostics: Vec<Diagnostic>,
}

impl AnalyzedModule {
    /// Returns `true` iff no [`crate::diagnostics::Severity::Error`] diagnostics were emitted.
    pub fn ok(&self) -> bool {
        !self
            .diagnostics
            .iter()
            .any(|d| d.severity == crate::diagnostics::Severity::Error)
    }
}
