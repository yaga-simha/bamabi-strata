//! Frozen `AnalyzedModule` HIR produced by `strata_sema` and consumed by `strata_mir`.

use crate::access::{ConcurrencyGraph, FilteredAccessSet};
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

/// Analyzed `const` declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HirConst {
    /// Constant identifier.
    pub name: String,
    /// Declared static type.
    pub ty: Ty,
    /// Raw expression source text.
    pub value_expr: String,
}

/// Analyzed `table` declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HirTable {
    /// Table name.
    pub name: String,
    /// Key enum name.
    pub key_enum: String,
    /// Row fields `(name, ty)`.
    pub fields: Vec<(String, Ty)>,
    /// Row entries `(variant_name, fields_source)`.
    pub rows: Vec<(String, String)>,
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
    /// Ordered `(x, y)` control points.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Synthesized 16-byte `@sparse` cursor layout.
    pub cursor_layout: SolvedLayout,
}

/// Analyzed `task` coroutine declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HirTask {
    /// Task name.
    pub name: String,
    /// `@sparse` marker.
    pub is_sparse: bool,
    /// Parameters `(name, ty)`.
    pub params: Vec<(String, Ty)>,
    /// Target entity query terms (`on (...)`).
    pub on_terms: Vec<String>,
    /// Resource borrows (`using (...)`).
    pub using_params: Vec<String>,
    /// Live variables crossing suspension points (`wait`/`wait_until`/`yield_tick`/`race`).
    pub live_across_wait: Vec<(String, Ty)>,
    /// Synthesized `@sparse` `AbiPod` state struct layout.
    pub state_layout: SolvedLayout,
    /// Filtered access signature for scheduling and parallelism.
    pub access: FilteredAccessSet,
    /// Raw task body source.
    pub body_source: String,
}

/// Analyzed `fsm` state machine declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HirCallable {
    /// Function name.
    pub name: String,
    /// `true` for `obs`, `false` for `sys`.
    pub is_observer: bool,
    /// Trigger event type if observer.
    pub trigger_event: Option<String>,
    /// `@par(chunk = N)` chunk size if present.
    pub par_chunk: Option<u32>,
    /// `@par(read_only, ...)` flag.
    pub par_read_only: bool,
    /// `effects(...)` declaration if present.
    pub declared_effects: Option<EffectsSpec>,
    /// Verified `FilteredAccessSet` signature.
    pub access: FilteredAccessSet,
    /// Body source text (for MIR lowering).
    pub body_source: String,
    /// Raw CST byte range `(start, end)` of the callable.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HirSchedule {
    /// Schedule label (`Startup`, `FixedUpdate`, `Update`).
    pub label: String,
    /// Optional `run_if(...)` condition source.
    pub run_if: Option<String>,
    /// Schedule DAG nodes.
    pub nodes: Vec<HirScheduleGroup>,
}

/// Analyzed `object` / `@persist object` singleton entity declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HirObject {
    /// Object name.
    pub name: String,
    /// `@persist` marker.
    pub is_persist: bool,
    /// Attached component names.
    pub components: Vec<String>,
}

/// Analyzed `migrate` declaration (`v1 -> v2`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HirMigration {
    /// Target component name.
    pub component: String,
    /// Source SemVer string.
    pub from_ver: String,
    /// Target SemVer string.
    pub to_ver: String,
    /// Migration body source.
    pub body_source: String,
}

/// Analyzed `sim_test` headless test block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HirSimTest {
    /// Test case name.
    pub name: String,
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
    /// Declared named objects.
    pub objects: Vec<HirObject>,
    /// Declared schema migrations.
    pub migrations: Vec<HirMigration>,
    /// Declared schedules.
    pub schedules: Vec<HirSchedule>,
    /// Declared embedded `sim_test`s.
    pub sim_tests: Vec<HirSimTest>,
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
