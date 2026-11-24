//! Lossless `rowan` CST <-> Graph IR JSON serialization and hash-isolated `.strata.graph.json`
//! layout sidecar support for Strata v2.0.

use crate::ast::{
    self, AstNode, Attribute, Block, ComponentDecl, CurveDecl, FieldDecl, FnDecl, FsmDecl, Item,
    RequireClause, ScheduleDecl, ScheduleModKind, ScheduleNode, ScheduleNodeKind, SourceFile,
    TableDecl, TaskDecl, TimelineDecl,
};
use crate::syntax_kind::{SyntaxKind, SyntaxNode};
use rowan::TextRange;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// Current Graph IR document schema version.
pub const GRAPH_IR_VERSION: &str = "1.0";

/// Errors returned by Graph IR export, CST patch application, or sidecar I/O.
#[derive(Debug, thiserror::Error)]
pub enum GraphIrError {
    /// Source `.strata` input contains syntax errors.
    #[error("source contains {} parse error(s)", .0.len())]
    ParseErrors(Vec<crate::ParseError>),
    /// Patch contains duplicate canonical node IDs.
    #[error("duplicate canonical node id `{0}` in graph patch")]
    DuplicateNodeId(String),
    /// Patch node is malformed (e.g. empty name, mismatched id/name, invalid payload kind).
    #[error("invalid graph node `{id}`: {reason}")]
    InvalidNode {
        /// Canonical ID of the offending node.
        id: String,
        /// Explanation of why the node is invalid.
        reason: String,
    },
    /// Explicit delta removal referenced an unknown canonical node ID.
    #[error("cannot remove unknown node id `{0}`")]
    NodeNotFound(String),
    /// Internal edit planner detected overlapping CST ranges.
    #[error("overlapping CST replacement ranges at {0}..{1}")]
    OverlappingEdit(u32, u32),
    /// Re-parsing patched `.strata` source failed.
    #[error("patched source failed syntax validation with {} error(s)", .0.len())]
    GeneratedSyntaxInvalid(Vec<crate::ParseError>),
    /// JSON serialization or deserialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// Filesystem I/O error while reading or writing a layout sidecar.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Top-level Graph IR document matching the canonical Strata visual graph JSON schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphIrDocument {
    /// Schema version (`"1.0"`).
    pub version: String,
    /// Module path from `module ...;` or `"anonymous"`.
    pub module_path: String,
    /// Hex-formatted 64-bit schema fingerprint (`"0x..."`).
    pub schema_fingerprint: String,
    /// Exported graph nodes in declaration order.
    pub nodes: Vec<GraphIrNode>,
    /// Extracted dependency, control-flow, and scheduling edges.
    pub edges: Vec<GraphIrEdge>,
}

/// Supported Graph IR node kinds covering all 8 visual graph constructs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphNodeKind {
    /// ECS component declaration (`component Name ...`).
    Component,
    /// Pure visual graph function (`@node_pure fn name(...) -> ...`).
    #[serde(rename = "node_pure_fn")]
    NodePureFn,
    /// Frame/time-based timeline declaration (`timeline Name ...`).
    Timeline,
    /// Finite state machine declaration (`fsm Name ...`).
    Fsm,
    /// Stackless coroutine task declaration (`task Name ...`).
    Task,
    /// Keyed data table declaration (`table Name by Key ...`).
    Table,
    /// Piecewise-linear curve declaration (`curve Name(...) = [...]`).
    Curve,
    /// Execution schedule declaration (`schedule Label { ... }`).
    Schedule,
}

/// Source byte span (`[start, end)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GraphIrSpan {
    /// Inclusive start byte offset in `.strata` source.
    pub start: u32,
    /// Exclusive end byte offset in `.strata` source.
    pub end: u32,
}

/// Canvas node layout stored in `.strata.graph.json` and optionally merged into [`GraphIrNode`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct NodeLayout {
    /// Horizontal canvas coordinate.
    pub x: f64,
    /// Vertical canvas coordinate.
    pub y: f64,
    /// Whether the node is collapsed in the visual editor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collapsed: Option<bool>,
}

/// Attribute attached to an item, field, or FSM transition (`@name` or `@name(args...)`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GraphAttribute {
    /// Attribute identifier without leading `@`.
    pub name: String,
    /// Positional or `key = value` attribute arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<GraphAttrArg>,
}

/// Single attribute argument (`value` or `key = value`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GraphAttrArg {
    /// Optional argument key for `key = value` pairs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// Argument value expression or semantic version text.
    pub value: String,
}

/// Single exported or patched Graph IR node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphIrNode {
    /// Canonical symbol ID (`"{module_path}::{name}"`, or `"{module_path}::{label}#N"` for
    /// duplicate `schedule` declarations).
    pub id: String,
    /// Node construct kind.
    pub kind: GraphNodeKind,
    /// Unqualified symbol name (or schedule label path).
    pub name: String,
    /// Optional visual group from `@node_group("...")` or `@node_group(name = "...")`.
    #[serde(default)]
    pub group: Option<String>,
    /// Item attributes (excluding `@node_group`, which is normalized into `group`).
    #[serde(default)]
    pub attributes: Vec<GraphAttribute>,
    /// Structured lossless construct payload.
    pub payload: GraphNodePayload,
    /// Byte span in the `.strata` file (`None` for newly synthesized patch nodes).
    #[serde(default)]
    pub span: Option<GraphIrSpan>,
    /// Layout coordinates merged from `.strata.graph.json` (nullable).
    #[serde(default)]
    pub position: Option<NodeLayout>,
    /// Optional previous canonical ID when renaming an existing node in a patch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_id: Option<String>,
}

/// Directed edge connecting two canonical symbols or external targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GraphIrEdge {
    /// Source canonical node ID.
    pub from: String,
    /// Target canonical node ID (or external symbol path).
    pub to: String,
    /// Edge relation (`"require"`, `"schedules"`, `"before"`, `"after"`, `"reads"`, `"writes"`,
    /// `"reads_resource"`, `"writes_resource"`, `"reads_stream"`, `"key_enum"`, `"call"`,
    /// `"triggers"`, `"inserts"`, `"table_lookup"`).
    pub kind: String,
    /// Optional edge annotation (e.g. schedule modifier or projection alias).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Tagged structured payload for one of the 8 Graph IR node constructs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GraphNodePayload {
    /// Payload for [`GraphNodeKind::Component`].
    Component(ComponentPayload),
    /// Payload for [`GraphNodeKind::NodePureFn`].
    NodePureFn(FnPayload),
    /// Payload for [`GraphNodeKind::Timeline`].
    Timeline(TimelinePayload),
    /// Payload for [`GraphNodeKind::Fsm`].
    Fsm(FsmPayload),
    /// Payload for [`GraphNodeKind::Task`].
    Task(TaskPayload),
    /// Payload for [`GraphNodeKind::Table`].
    Table(TablePayload),
    /// Payload for [`GraphNodeKind::Curve`].
    Curve(CurvePayload),
    /// Payload for [`GraphNodeKind::Schedule`].
    Schedule(SchedulePayload),
}

impl GraphNodePayload {
    fn expected_kind(&self) -> GraphNodeKind {
        match self {
            Self::Component(_) => GraphNodeKind::Component,
            Self::NodePureFn(_) => GraphNodeKind::NodePureFn,
            Self::Timeline(_) => GraphNodeKind::Timeline,
            Self::Fsm(_) => GraphNodeKind::Fsm,
            Self::Task(_) => GraphNodeKind::Task,
            Self::Table(_) => GraphNodeKind::Table,
            Self::Curve(_) => GraphNodeKind::Curve,
            Self::Schedule(_) => GraphNodeKind::Schedule,
        }
    }
}

/// Payload for a `component` declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentPayload {
    /// Whether this is a semicolon-terminated unit marker component (`component Tag;`).
    pub is_unit: bool,
    /// Required components from `@require(...)`.
    #[serde(default)]
    pub requires: Vec<RequireIr>,
    /// SoA strata (`hot` / `cold <name>`) for `@soa` components.
    #[serde(default)]
    pub strata: Vec<StratumIr>,
    /// Direct fields for non-SoA components.
    #[serde(default)]
    pub fields: Vec<FieldIr>,
}

/// Payload for a `@node_pure fn` declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FnPayload {
    /// Generic parameter list entries (e.g. `T`, `T: Copy`).
    #[serde(default)]
    pub generic_params: Vec<String>,
    /// Function parameters.
    #[serde(default)]
    pub params: Vec<FnParamIr>,
    /// Optional return type text after `->`.
    #[serde(default)]
    pub return_type: Option<String>,
    /// Block body text (`{ ... }`).
    pub body: String,
}

/// Payload for a `timeline` declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelinePayload {
    /// Required components from `@require(...)`.
    #[serde(default)]
    pub requires: Vec<RequireIr>,
    /// Named `window` ranges.
    #[serde(default)]
    pub windows: Vec<TimelineWindowIr>,
    /// Timestamped `at ... => ...` event entries.
    #[serde(default)]
    pub events: Vec<TimelineEventIr>,
}

/// Payload for an `fsm` declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsmPayload {
    /// Optional system parameters on the FSM header.
    #[serde(default)]
    pub params: Vec<SysParamIr>,
    /// Required components from `@require(...)`.
    #[serde(default)]
    pub requires: Vec<RequireIr>,
    /// Initial state identifier (`initial State ...;`).
    #[serde(default)]
    pub initial: Option<String>,
    /// Optional initial state field initializer text (`{ ... }`).
    #[serde(default)]
    pub initial_args: Option<String>,
    /// Declared FSM states.
    #[serde(default)]
    pub states: Vec<FsmStateIr>,
}

/// Payload for a `task` declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskPayload {
    /// Task input parameters.
    #[serde(default)]
    pub params: Vec<FnParamIr>,
    /// Projection terms in `on (...)`.
    #[serde(default)]
    pub on_terms: Vec<String>,
    /// Filter chain clauses (`.with<T>()`, `.without<T>()`).
    #[serde(default)]
    pub chain: Vec<String>,
    /// Resource/stream parameters in `using (...)`.
    #[serde(default)]
    pub using_params: Vec<SysParamIr>,
    /// Task body block text (`{ ... }`).
    pub body: String,
}

/// Payload for a `table` declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TablePayload {
    /// Key enum path after `by`.
    pub key_enum: String,
    /// Table schema column fields.
    #[serde(default)]
    pub fields: Vec<FieldIr>,
    /// Table data rows keyed by enum variant.
    #[serde(default)]
    pub rows: Vec<TableRowIr>,
}

/// Payload for a `curve` declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurvePayload {
    /// Domain input type text.
    pub input_type: String,
    /// Range output type text.
    pub output_type: String,
    /// Control points `(x, y)`.
    #[serde(default)]
    pub points: Vec<CurvePointIr>,
}

/// Payload for a `schedule` declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulePayload {
    /// Top-level schedule modifiers (`run_if`, `before`, `after`).
    #[serde(default)]
    pub modifiers: Vec<ScheduleModIr>,
    /// Top-level schedule groups and leaf items.
    #[serde(default)]
    pub nodes: Vec<ScheduleNodeIr>,
}

/// Field declaration IR entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldIr {
    /// Field-level attributes (e.g. `@quantize(...)`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<GraphAttribute>,
    /// Field identifier.
    pub name: String,
    /// Field type text.
    pub ty: String,
    /// Optional default expression text after `=`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

/// `@require(...)` item IR entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequireIr {
    /// Required component or field path.
    pub path: String,
    /// Optional required value expression text after `=`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// SoA stratum block IR entry (`hot` or `cold <name>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StratumIr {
    /// Stratum name (`"hot"` or cold stratum identifier).
    pub name: String,
    /// `true` for the `hot` stratum.
    pub is_hot: bool,
    /// Fields inside this stratum.
    #[serde(default)]
    pub fields: Vec<FieldIr>,
}

/// Function or task parameter IR entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FnParamIr {
    /// Parameter identifier.
    pub name: String,
    /// Parameter type text.
    pub ty: String,
    /// Optional default value expression text after `=`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

/// System/FSM/`using` parameter IR entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysParamIr {
    /// Parameter identifier.
    pub name: String,
    /// Parameter type text (e.g. `&res SimClock`).
    pub ty: String,
}

/// Timeline `window` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineWindowIr {
    /// Window identifier.
    pub name: String,
    /// Range expression text (e.g. `0_f .. 4_f`).
    pub expr: String,
}

/// Timeline `at frame => action` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEventIr {
    /// Time/frame expression text.
    pub frame: String,
    /// Action statement or block text.
    pub action: String,
}

/// FSM `state` declaration IR entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsmStateIr {
    /// State identifier.
    pub name: String,
    /// State-local field declarations.
    #[serde(default)]
    pub fields: Vec<FieldIr>,
    /// Optional `on_enter` block text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_enter: Option<String>,
    /// Optional `on_tick` block text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_tick: Option<String>,
    /// Optional `on_exit` block text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_exit: Option<String>,
    /// Outgoing state transitions.
    #[serde(default)]
    pub transitions: Vec<FsmTransitionIr>,
}

/// FSM `to Target ... when cond;` transition IR entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsmTransitionIr {
    /// Target state identifier.
    pub target: String,
    /// Optional record initializer text (`{ ... }`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub init: Option<String>,
    /// Guard expression text after `when`.
    pub when: String,
    /// Optional transition attributes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<GraphAttribute>,
}

/// Table row IR entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableRowIr {
    /// Enum variant key name.
    pub variant: String,
    /// Column field initializers.
    #[serde(default)]
    pub values: Vec<FieldInitIr>,
}

/// Field initializer IR entry (`name: value` or shorthand `name`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldInitIr {
    /// Field identifier.
    pub name: String,
    /// Optional initializer expression text (absent for shorthand).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// Curve `(x, y)` control point IR entry (preserving unit literals).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurvePointIr {
    /// X coordinate expression text.
    pub x: String,
    /// Y coordinate expression text.
    pub y: String,
}

/// Schedule modifier IR entry (`run_if`, `before`, `after`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleModIr {
    /// Modifier kind (`"run_if"`, `"before"`, or `"after"`).
    pub kind: String,
    /// Condition expression or target path text.
    pub arg: String,
}

/// Recursive schedule tree node IR entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScheduleNodeIr {
    /// Schedule group (`seq`, `seq_weak`, `par`, or `set`).
    Group {
        /// Group keyword (`"seq"`, `"seq_weak"`, `"par"`, `"set"`).
        group_kind: String,
        /// Group name identifier.
        name: String,
        /// Modifiers attached to this group.
        #[serde(default)]
        modifiers: Vec<ScheduleModIr>,
        /// Child schedule nodes inside this group.
        #[serde(default)]
        children: Vec<ScheduleNodeIr>,
    },
    /// Leaf scheduled system/timeline/task/FSM path.
    Leaf {
        /// Target symbol path text.
        target: String,
        /// Modifiers attached to this leaf.
        #[serde(default)]
        modifiers: Vec<ScheduleModIr>,
    },
}

/// Input to [`apply_graph_patch`]: either a full [`GraphIrDocument`] or a surgical [`GraphIrDelta`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GraphIrPatch {
    /// Full Graph IR document (nodes omitted from `nodes` are removed from `.strata`).
    Document(GraphIrDocument),
    /// Surgical partial patch updating/adding/removing nodes or layout positions.
    Delta(GraphIrDelta),
}

/// Partial patch updating, adding, or removing nodes and/or layout positions.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphIrDelta {
    /// Nodes to update or insert.
    #[serde(default, alias = "nodes")]
    pub upsert: Vec<GraphIrNode>,
    /// Canonical node IDs to remove from `.strata`.
    #[serde(default)]
    pub remove: Vec<String>,
    /// Position-only layout updates keyed by canonical node ID.
    #[serde(default)]
    pub positions: BTreeMap<String, NodeLayout>,
}

/// Output of [`apply_graph_patch`] / [`apply_graph_document`].
#[derive(Debug, Clone, PartialEq)]
pub struct GraphApplyResult {
    /// Resulting `.strata` source text (identical to input if `source_modified == false`).
    pub source: String,
    /// `true` iff `.strata` source bytes changed.
    pub source_modified: bool,
    /// Canonical IDs of existing nodes whose `.strata` CST was updated.
    pub updated_nodes: Vec<String>,
    /// Canonical IDs of newly appended nodes.
    pub added_nodes: Vec<String>,
    /// Canonical IDs of removed nodes.
    pub removed_nodes: Vec<String>,
    /// Layout coordinate updates to write into `.strata.graph.json`.
    pub sidecar_updates: BTreeMap<String, NodeLayout>,
    /// Canonical IDs to prune from `.strata.graph.json`.
    pub sidecar_removals: Vec<String>,
}

fn default_version() -> String {
    GRAPH_IR_VERSION.to_owned()
}

/// Hash-isolated `.strata.graph.json` layout sidecar keyed by canonical symbol paths.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphLayoutSidecar {
    /// Sidecar format version (`"1.0"`).
    #[serde(default = "default_version", alias = "layout_version")]
    pub version: String,
    /// Hex-formatted 64-bit schema fingerprint (`"0x..."`).
    #[serde(default)]
    pub schema_fingerprint: String,
    /// Layout coordinates keyed by canonical symbol path (`"{module_path}::{symbol}"`).
    #[serde(default)]
    pub nodes: BTreeMap<String, NodeLayout>,
}

impl Default for GraphLayoutSidecar {
    fn default() -> Self {
        Self {
            version: GRAPH_IR_VERSION.to_owned(),
            schema_fingerprint: String::new(),
            nodes: BTreeMap::new(),
        }
    }
}

/// Exports a Strata source file into a canonical [`GraphIrDocument`].
///
/// If `schema_fingerprint` is `None`, computes [`fallback_schema_fingerprint`].
pub fn export_graph_ir(
    src: &str,
    schema_fingerprint: Option<&str>,
) -> Result<GraphIrDocument, GraphIrError> {
    export_graph_ir_with_sidecar(src, schema_fingerprint, None)
}

/// Exports a Strata source file into a canonical [`GraphIrDocument`], merging any layout positions
/// from `sidecar`.
pub fn export_graph_ir_with_sidecar(
    src: &str,
    schema_fingerprint: Option<&str>,
    sidecar: Option<&GraphLayoutSidecar>,
) -> Result<GraphIrDocument, GraphIrError> {
    let parsed = crate::parse(src);
    if !parsed.ok() {
        return Err(GraphIrError::ParseErrors(parsed.errors().to_vec()));
    }
    let root = parsed.syntax();
    let sf = SourceFile::cast(root).unwrap_or_else(|| unreachable!("root is SourceFile"));
    let module_path = extract_module_path(&sf);
    let fingerprint = schema_fingerprint
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| fallback_schema_fingerprint(src));

    let extracted = extract_items(&sf, &module_path, src);
    let mut nodes = Vec::with_capacity(extracted.len());
    let mut declared_symbols: HashMap<String, String> = HashMap::new();

    for entry in &extracted {
        declared_symbols
            .entry(entry.node.name.clone())
            .or_insert_with(|| entry.node.id.clone());
        let mut ir_node = entry.node.clone();
        if let Some(sc) = sidecar
            && let Some(pos) = sc.nodes.get(&ir_node.id)
        {
            ir_node.position = Some(*pos);
        }
        nodes.push(ir_node);
    }

    // Also index non-graph items (resources, events, streams, enums, sys, obs, etc.) by short name
    // so edge resolution yields canonical module-qualified IDs when referencing same-module items.
    collect_additional_declared_symbols(&sf, &module_path, &mut declared_symbols);

    let edges = extract_edges(&sf, &module_path, &declared_symbols);

    Ok(GraphIrDocument {
        version: GRAPH_IR_VERSION.to_owned(),
        module_path,
        schema_fingerprint: fingerprint,
        nodes,
        edges,
    })
}

/// Applies a [`GraphIrDocument`] as a full-graph patch to `src`.
pub fn apply_graph_document(
    src: &str,
    doc: &GraphIrDocument,
) -> Result<GraphApplyResult, GraphIrError> {
    apply_graph_patch(src, &GraphIrPatch::Document(doc.clone()))
}

/// Applies a [`GraphIrPatch`] (full document or delta) losslessly to `src`.
///
/// Untouched items, comments, and whitespace are preserved byte-for-byte. Position-only or
/// semantically identical patches return `source_modified: false` with `source == src` (0-byte
/// diff).
pub fn apply_graph_patch(
    src: &str,
    patch: &GraphIrPatch,
) -> Result<GraphApplyResult, GraphIrError> {
    let parsed = crate::parse(src);
    if !parsed.ok() {
        return Err(GraphIrError::ParseErrors(parsed.errors().to_vec()));
    }
    let root = parsed.syntax();
    let sf = SourceFile::cast(root).unwrap_or_else(|| unreachable!("root is SourceFile"));
    let module_path = extract_module_path(&sf);
    let existing = extract_items(&sf, &module_path, src);

    let mut existing_by_id: HashMap<String, usize> = HashMap::new();
    for (idx, item) in existing.iter().enumerate() {
        existing_by_id.insert(item.node.id.clone(), idx);
    }

    let mut edits: Vec<TextEdit> = Vec::new();
    let mut additions: Vec<String> = Vec::new();
    let mut updated_nodes: Vec<String> = Vec::new();
    let mut added_nodes: Vec<String> = Vec::new();
    let mut removed_nodes: Vec<String> = Vec::new();
    let mut sidecar_updates: BTreeMap<String, NodeLayout> = BTreeMap::new();
    let mut sidecar_removals: Vec<String> = Vec::new();

    let active_ids: BTreeSet<String> = match patch {
        GraphIrPatch::Document(doc) => {
            let mut seen_patch_ids = BTreeSet::new();
            let mut matched_existing = vec![false; existing.len()];

            for patch_node in &doc.nodes {
                validate_patch_node(&module_path, patch_node)?;
                if !seen_patch_ids.insert(patch_node.id.clone()) {
                    return Err(GraphIrError::DuplicateNodeId(patch_node.id.clone()));
                }
                if let Some(pos) = patch_node.position {
                    sidecar_updates.insert(patch_node.id.clone(), pos);
                }

                let lookup_id = patch_node
                    .previous_id
                    .as_deref()
                    .unwrap_or(patch_node.id.as_str());
                if let Some(&idx) = existing_by_id.get(lookup_id) {
                    if matched_existing[idx] {
                        return Err(GraphIrError::InvalidNode {
                            id: patch_node.id.clone(),
                            reason: format!(
                                "multiple patch nodes target existing node `{}`",
                                existing[idx].node.id
                            ),
                        });
                    }
                    matched_existing[idx] = true;
                    let cur = &existing[idx];
                    if patch_node.previous_id.is_some() && cur.node.id != patch_node.id {
                        sidecar_removals.push(cur.node.id.clone());
                    }
                    if let Some(edit) = plan_node_update(src, cur, patch_node) {
                        edits.push(edit);
                        updated_nodes.push(patch_node.id.clone());
                    }
                } else {
                    additions.push(render_node(patch_node, ""));
                    added_nodes.push(patch_node.id.clone());
                }
            }

            for (idx, cur) in existing.iter().enumerate() {
                if !matched_existing[idx] {
                    edits.push(plan_node_removal(src, cur.item_range));
                    removed_nodes.push(cur.node.id.clone());
                    sidecar_removals.push(cur.node.id.clone());
                }
            }
            seen_patch_ids
        }
        GraphIrPatch::Delta(delta) => {
            let mut seen_upsert_ids = BTreeSet::new();
            let mut removed_indices = BTreeSet::new();
            let mut upserted_indices = BTreeSet::new();

            for rem_id in &delta.remove {
                if let Some(&idx) = existing_by_id.get(rem_id) {
                    if removed_indices.insert(idx) {
                        edits.push(plan_node_removal(src, existing[idx].item_range));
                        removed_nodes.push(rem_id.clone());
                        sidecar_removals.push(rem_id.clone());
                    }
                } else {
                    return Err(GraphIrError::NodeNotFound(rem_id.clone()));
                }
            }

            for patch_node in &delta.upsert {
                validate_patch_node(&module_path, patch_node)?;
                if !seen_upsert_ids.insert(patch_node.id.clone()) {
                    return Err(GraphIrError::DuplicateNodeId(patch_node.id.clone()));
                }
                if let Some(pos) = patch_node.position {
                    sidecar_updates.insert(patch_node.id.clone(), pos);
                }

                let lookup_id = patch_node
                    .previous_id
                    .as_deref()
                    .unwrap_or(patch_node.id.as_str());
                if let Some(&idx) = existing_by_id.get(lookup_id) {
                    if removed_indices.contains(&idx) {
                        return Err(GraphIrError::InvalidNode {
                            id: patch_node.id.clone(),
                            reason: "node cannot be both removed and upserted in the same delta"
                                .to_owned(),
                        });
                    }
                    if !upserted_indices.insert(idx) {
                        return Err(GraphIrError::InvalidNode {
                            id: patch_node.id.clone(),
                            reason: format!(
                                "multiple upsert nodes target existing node `{}`",
                                existing[idx].node.id
                            ),
                        });
                    }
                    let cur = &existing[idx];
                    if patch_node.previous_id.is_some() && cur.node.id != patch_node.id {
                        sidecar_removals.push(cur.node.id.clone());
                    }
                    if let Some(edit) = plan_node_update(src, cur, patch_node) {
                        edits.push(edit);
                        updated_nodes.push(patch_node.id.clone());
                    }
                } else {
                    additions.push(render_node(patch_node, ""));
                    added_nodes.push(patch_node.id.clone());
                }
            }

            for patch_node in &delta.upsert {
                if let Some(&target_idx) = existing_by_id.get(&patch_node.id)
                    && !removed_indices.contains(&target_idx)
                    && !upserted_indices.contains(&target_idx)
                {
                    return Err(GraphIrError::InvalidNode {
                        id: patch_node.id.clone(),
                        reason: format!(
                            "target node `{}` already exists and is neither removed nor renamed in this delta",
                            patch_node.id
                        ),
                    });
                }
            }

            for (id, pos) in &delta.positions {
                if !existing_by_id.contains_key(id) && !seen_upsert_ids.contains(id) {
                    return Err(GraphIrError::InvalidNode {
                        id: id.clone(),
                        reason: format!("positions entry references unknown node id `{id}`"),
                    });
                }
                if !pos.x.is_finite() || !pos.y.is_finite() {
                    return Err(GraphIrError::InvalidNode {
                        id: id.clone(),
                        reason: "non-finite position coordinates".to_owned(),
                    });
                }
                sidecar_updates.entry(id.clone()).or_insert(*pos);
            }

            seen_upsert_ids
        }
    };

    for rem in &sidecar_removals {
        if !active_ids.contains(rem) {
            sidecar_updates.remove(rem);
        }
    }
    sidecar_removals.retain(|rem| !active_ids.contains(rem) || !sidecar_updates.contains_key(rem));

    if edits.is_empty() && additions.is_empty() {
        return Ok(GraphApplyResult {
            source: src.to_owned(),
            source_modified: false,
            updated_nodes,
            added_nodes,
            removed_nodes,
            sidecar_updates,
            sidecar_removals,
        });
    }

    // Sort descending by (start, end) and resolve/verify non-overlap.
    edits.sort_by(|a, b| b.start.cmp(&a.start).then_with(|| b.end.cmp(&a.end)));
    for i in 1..edits.len() {
        let prev = &edits[i - 1];
        let curr = &edits[i];
        if curr.end > prev.start {
            // If `curr` is a pure removal whose extended trailing newline touches `prev`, clamp it.
            if curr.replacement.is_empty() && curr.core_end <= prev.start {
                // Allowed: clamp in a second pass below.
                continue;
            }
            return Err(GraphIrError::OverlappingEdit(
                u32::try_from(curr.start).unwrap_or(u32::MAX),
                u32::try_from(curr.end).unwrap_or(u32::MAX),
            ));
        }
    }
    for i in 1..edits.len() {
        let next_start = edits[i - 1].start;
        if edits[i].end > next_start {
            edits[i].end = next_start;
        }
    }

    let mut out = src.to_owned();
    for edit in &edits {
        out.replace_range(edit.start..edit.end, &edit.replacement);
    }

    if !additions.is_empty() {
        let had_trailing_nl = out.ends_with('\n');
        let trimmed = out.trim_end_matches(['\r', '\n', ' ', '\t']).len();
        out.truncate(trimmed);
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        out.push_str(&additions.join("\n\n"));
        if had_trailing_nl || src.ends_with('\n') {
            out.push('\n');
        }
    } else if src.ends_with('\n') && !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }

    // Clean up leading/trailing blank lines if a removal deleted the very first or last item.
    let reparsed = crate::parse(&out);
    if !reparsed.ok() {
        return Err(GraphIrError::GeneratedSyntaxInvalid(
            reparsed.errors().to_vec(),
        ));
    }

    let source_modified = out != src;
    Ok(GraphApplyResult {
        source: out,
        source_modified,
        updated_nodes,
        added_nodes,
        removed_nodes,
        sidecar_updates,
        sidecar_removals,
    })
}

/// Returns the canonical layout sidecar path for a `.strata` file (`foo.strata` -> `foo.strata.graph.json`).
pub fn sidecar_path_for(strata_path: &Path) -> PathBuf {
    let mut os = strata_path.as_os_str().to_os_string();
    os.push(".graph.json");
    PathBuf::from(os)
}

/// Loads a `.strata.graph.json` layout sidecar from disk, returning `Ok(None)` if it does not exist.
pub fn load_sidecar(path: &Path) -> Result<Option<GraphLayoutSidecar>, GraphIrError> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)?;
    let sidecar: GraphLayoutSidecar = serde_json::from_str(&raw)?;
    Ok(Some(sidecar))
}

/// Persists a [`GraphLayoutSidecar`] to disk in pretty-printed JSON with a trailing newline.
pub fn save_sidecar(path: &Path, sidecar: &GraphLayoutSidecar) -> Result<(), GraphIrError> {
    let mut json = serde_json::to_string_pretty(sidecar)?;
    json.push('\n');
    std::fs::write(path, json)?;
    Ok(())
}

/// Merges `result.sidecar_updates` and `result.sidecar_removals` into an existing sidecar (or creates a new one).
pub fn merge_sidecar(
    existing: Option<GraphLayoutSidecar>,
    result: &GraphApplyResult,
    schema_fingerprint: &str,
) -> GraphLayoutSidecar {
    let mut sc = existing.unwrap_or_default();
    sc.version = GRAPH_IR_VERSION.to_owned();
    sc.schema_fingerprint = schema_fingerprint.to_owned();
    for rem in &result.sidecar_removals {
        sc.nodes.remove(rem);
    }
    for (id, layout) in &result.sidecar_updates {
        sc.nodes.insert(id.clone(), *layout);
    }
    sc
}

/// Computes a deterministic 64-bit FNV-1a schema fingerprint (`"0x..."`) directly from the CST.
///
/// Mirrors `strata_sema`'s early-cutoff rules: ignores trivia/comments, ignores visual-only
/// attributes (`@node_group`, `@pos`, `@node_pure`), ignores `sim_test` and `net_sim_test`
/// declarations, and ignores `sys`/`obs`/`fn` block bodies.
pub fn fallback_schema_fingerprint(src: &str) -> String {
    let parsed = crate::parse(src);
    let root = parsed.syntax();
    let Some(sf) = SourceFile::cast(root) else {
        return "0xCBF29CE484222325".to_owned();
    };
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for item in sf.items() {
        match item {
            Item::SimTest(_) | Item::NetSimTest(_) => {}
            Item::Sys(s) => {
                let stop = s.body().map(|b| b.syntax().text_range().start());
                hash_node_tokens(s.syntax(), stop, &mut hash);
            }
            Item::Obs(o) => {
                let stop = o.body().map(|b| b.syntax().text_range().start());
                hash_node_tokens(o.syntax(), stop, &mut hash);
            }
            Item::Fn(f) => {
                let stop = f.body().map(|b| b.syntax().text_range().start());
                hash_node_tokens(f.syntax(), stop, &mut hash);
            }
            other => {
                hash_node_tokens(other.syntax(), None, &mut hash);
            }
        }
    }
    format!("0x{hash:016X}")
}

fn fnv1a_byte(hash: &mut u64, b: u8) {
    *hash ^= u64::from(b);
    *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
}

fn is_visual_only_attribute(node: &SyntaxNode) -> bool {
    let Some(attr) = Attribute::cast(node.clone()) else {
        return false;
    };
    matches!(
        attr.name_text().as_deref(),
        Some("node_group" | "pos" | "node_pure")
    )
}

fn hash_node_tokens(node: &SyntaxNode, stop_at: Option<rowan::TextSize>, hash: &mut u64) {
    fn visit(node: &SyntaxNode, stop_at: Option<rowan::TextSize>, hash: &mut u64) -> bool {
        if let Some(limit) = stop_at
            && node.text_range().start() >= limit
        {
            return false;
        }
        if is_visual_only_attribute(node) {
            return true;
        }
        for el in node.children_with_tokens() {
            match el {
                rowan::NodeOrToken::Node(sub) => {
                    if !visit(&sub, stop_at, hash) {
                        return false;
                    }
                }
                rowan::NodeOrToken::Token(tok) => {
                    if let Some(limit) = stop_at
                        && tok.text_range().start() >= limit
                    {
                        return false;
                    }
                    if tok.kind().is_trivia() {
                        continue;
                    }
                    let raw = (tok.kind() as u16).to_le_bytes();
                    fnv1a_byte(hash, raw[0]);
                    fnv1a_byte(hash, raw[1]);
                    for &b in tok.text().as_bytes() {
                        fnv1a_byte(hash, b);
                    }
                    fnv1a_byte(hash, 0x1f);
                }
            }
        }
        true
    }
    let _ = visit(node, stop_at, hash);
    fnv1a_byte(hash, 0x1e);
}

// ---------------------------------------------------------------------------
// Internal extraction
// ---------------------------------------------------------------------------

struct ExtractedItem {
    node: GraphIrNode,
    item_range: TextRange,
    group_attr_range: Option<TextRange>,
}

struct TextEdit {
    start: usize,
    end: usize,
    core_end: usize,
    replacement: String,
}

fn extract_module_path(sf: &SourceFile) -> String {
    sf.module_decl()
        .and_then(|m| m.path())
        .map(|p| ast::path_text(&p))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "anonymous".to_owned())
}

fn canonical_id(module_path: &str, name: &str) -> String {
    format!("{module_path}::{name}")
}

fn schedule_canonical_id(
    module_path: &str,
    label: &str,
    counts: &mut HashMap<String, usize>,
) -> String {
    let count = counts.entry(label.to_owned()).or_insert(0);
    *count += 1;
    let base = canonical_id(module_path, label);
    if *count == 1 {
        base
    } else {
        format!("{base}#{count}")
    }
}

fn extract_items(sf: &SourceFile, module_path: &str, src: &str) -> Vec<ExtractedItem> {
    let mut out = Vec::new();
    let mut schedule_counts: HashMap<String, usize> = HashMap::new();
    for item in sf.items() {
        match item {
            Item::Component(c) => {
                if let Some(ext) = extract_component(&c, module_path) {
                    out.push(ext);
                }
            }
            Item::Fn(f) if f.is_node_pure() => {
                if let Some(ext) = extract_node_pure_fn(&f, module_path, src) {
                    out.push(ext);
                }
            }
            Item::Timeline(t) => {
                if let Some(ext) = extract_timeline(&t, module_path, src) {
                    out.push(ext);
                }
            }
            Item::Fsm(f) => {
                if let Some(ext) = extract_fsm(&f, module_path, src) {
                    out.push(ext);
                }
            }
            Item::Task(t) => {
                if let Some(ext) = extract_task(&t, module_path, src) {
                    out.push(ext);
                }
            }
            Item::Table(t) => {
                if let Some(ext) = extract_table(&t, module_path) {
                    out.push(ext);
                }
            }
            Item::Curve(c) => {
                if let Some(ext) = extract_curve(&c, module_path) {
                    out.push(ext);
                }
            }
            Item::Schedule(s) => {
                if let Some(ext) = extract_schedule(&s, module_path, &mut schedule_counts) {
                    out.push(ext);
                }
            }
            _ => {}
        }
    }
    out
}

fn split_attrs_and_group(
    attrs: &[Attribute],
) -> (Option<String>, Option<TextRange>, Vec<GraphAttribute>) {
    let mut group: Option<String> = None;
    let mut group_range: Option<TextRange> = None;
    let mut rest = Vec::new();

    for attr in attrs {
        let Some(name) = attr.name_text() else {
            continue;
        };
        if name == "node_group" && group.is_none() {
            group = attr.first_string_arg();
            group_range = Some(attr.text_range());
            continue;
        }
        let args = attr
            .args()
            .into_iter()
            .map(|a| GraphAttrArg {
                key: a.key().map(|k| k.text().to_owned()),
                value: a.value_text(),
            })
            .collect();
        rest.push(GraphAttribute { name, args });
    }
    (group, group_range, rest)
}

fn extract_attrs_plain(attrs: &[Attribute]) -> Vec<GraphAttribute> {
    attrs
        .iter()
        .filter_map(|attr| {
            let name = attr.name_text()?;
            let args = attr
                .args()
                .into_iter()
                .map(|a| GraphAttrArg {
                    key: a.key().map(|k| k.text().to_owned()),
                    value: a.value_text(),
                })
                .collect();
            Some(GraphAttribute { name, args })
        })
        .collect()
}

fn extract_requires(clauses: &[RequireClause]) -> Vec<RequireIr> {
    let mut out = Vec::new();
    for clause in clauses {
        for item in clause.items() {
            if let Some(path) = item.path() {
                out.push(RequireIr {
                    path: ast::path_text(&path),
                    value: item
                        .value_expr()
                        .map(|e| e.text().to_string().trim().to_owned()),
                });
            }
        }
    }
    out
}

fn extract_field(f: &FieldDecl) -> Option<FieldIr> {
    let name = f.name()?.text().to_owned();
    let ty = f
        .type_node()
        .map(|n| n.text().to_string().trim().to_owned())
        .unwrap_or_default();
    let attributes = extract_attrs_plain(&f.attributes());
    let default = f
        .default_expr()
        .map(|e| e.text().to_string().trim().to_owned());
    Some(FieldIr {
        attributes,
        name,
        ty,
        default,
    })
}

fn span_of(node: &SyntaxNode) -> GraphIrSpan {
    let r = node.text_range();
    GraphIrSpan {
        start: u32::from(r.start()),
        end: u32::from(r.end()),
    }
}

fn extract_component(c: &ComponentDecl, module_path: &str) -> Option<ExtractedItem> {
    let name = c.name()?.text().to_owned();
    let (group, group_attr_range, attributes) = split_attrs_and_group(&c.attributes());
    let requires = extract_requires(&c.require_clauses());
    let strata: Vec<StratumIr> = c
        .strata()
        .into_iter()
        .map(|s| StratumIr {
            name: s.stratum_name(),
            is_hot: s.is_hot(),
            fields: s.fields().iter().filter_map(extract_field).collect(),
        })
        .collect();
    let fields: Vec<FieldIr> = c.fields().iter().filter_map(extract_field).collect();
    let is_unit = c.is_unit_marker();

    Some(ExtractedItem {
        item_range: c.text_range(),
        group_attr_range,
        node: GraphIrNode {
            id: canonical_id(module_path, &name),
            kind: GraphNodeKind::Component,
            name,
            group,
            attributes,
            payload: GraphNodePayload::Component(ComponentPayload {
                is_unit,
                requires,
                strata,
                fields,
            }),
            span: Some(span_of(c.syntax())),
            position: None,
            previous_id: None,
        },
    })
}

fn extract_node_pure_fn(f: &FnDecl, module_path: &str, src: &str) -> Option<ExtractedItem> {
    let name = f.name()?.text().to_owned();
    let (group, group_attr_range, attributes) = split_attrs_and_group(&f.attributes());
    let generic_params = f
        .generic_params()
        .map(|gp| {
            gp.params()
                .into_iter()
                .map(|(ident, bound)| match bound {
                    Some(b) => format!("{}: {}", ident.text(), b.text().to_string().trim()),
                    None => ident.text().to_owned(),
                })
                .collect()
        })
        .unwrap_or_default();
    let params = f
        .params()
        .into_iter()
        .filter_map(|p| {
            let pname = p.name()?.text().to_owned();
            let ty = p
                .type_node()
                .map(|n| n.text().to_string().trim().to_owned())
                .unwrap_or_default();
            let default = p
                .default_expr()
                .map(|e| e.text().to_string().trim().to_owned());
            Some(FnParamIr {
                name: pname,
                ty,
                default,
            })
        })
        .collect();
    let return_type = f
        .return_type()
        .map(|n| n.text().to_string().trim().to_owned());
    let body = f
        .body()
        .map(|b| dedent_block(&b, src))
        .unwrap_or_else(|| "{}".to_owned());

    Some(ExtractedItem {
        item_range: f.text_range(),
        group_attr_range,
        node: GraphIrNode {
            id: canonical_id(module_path, &name),
            kind: GraphNodeKind::NodePureFn,
            name,
            group,
            attributes,
            payload: GraphNodePayload::NodePureFn(FnPayload {
                generic_params,
                params,
                return_type,
                body,
            }),
            span: Some(span_of(f.syntax())),
            position: None,
            previous_id: None,
        },
    })
}

fn extract_timeline(t: &TimelineDecl, module_path: &str, src: &str) -> Option<ExtractedItem> {
    let name = t.name()?.text().to_owned();
    let (group, group_attr_range, attributes) = split_attrs_and_group(&t.attributes());
    let requires = extract_requires(&t.require_clauses());
    let windows = t
        .windows()
        .into_iter()
        .filter_map(|w| {
            let wname = w.name()?.text().to_owned();
            let expr = w
                .range_expr()
                .map(|e| e.text().to_string().trim().to_owned())
                .unwrap_or_default();
            Some(TimelineWindowIr { name: wname, expr })
        })
        .collect();
    let events = t
        .at_entries()
        .into_iter()
        .filter_map(|ev| {
            let frame = ev.time_expr()?.text().to_string().trim().to_owned();
            let act_node = ev.action_node()?;
            let block_opt = Block::cast(act_node.clone()).or_else(|| {
                (act_node.kind() == SyntaxKind::ExprStmt)
                    .then(|| ast::child::<Block>(&act_node))
                    .flatten()
            });
            let action = if let Some(b) = block_opt {
                dedent_block(&b, src)
            } else {
                let raw = act_node.text().to_string();
                dedent_from_offset(raw.trim(), usize::from(act_node.text_range().start()), src)
            };
            Some(TimelineEventIr { frame, action })
        })
        .collect();

    Some(ExtractedItem {
        item_range: t.text_range(),
        group_attr_range,
        node: GraphIrNode {
            id: canonical_id(module_path, &name),
            kind: GraphNodeKind::Timeline,
            name,
            group,
            attributes,
            payload: GraphNodePayload::Timeline(TimelinePayload {
                requires,
                windows,
                events,
            }),
            span: Some(span_of(t.syntax())),
            position: None,
            previous_id: None,
        },
    })
}

fn extract_fsm(f: &FsmDecl, module_path: &str, src: &str) -> Option<ExtractedItem> {
    let name = f.name()?.text().to_owned();
    let (group, group_attr_range, attributes) = split_attrs_and_group(&f.attributes());
    let params = f
        .params()
        .into_iter()
        .filter_map(|p| {
            let pname = p.name()?.text().to_owned();
            let ty = p
                .type_node()
                .map(|n| n.text().to_string().trim().to_owned())
                .unwrap_or_default();
            Some(SysParamIr { name: pname, ty })
        })
        .collect();
    let requires = extract_requires(&f.require_clauses());
    let initial = f.initial_state().map(|t| t.text().to_owned());
    let initial_args = f
        .initial_args()
        .map(|n| n.text().to_string().trim().to_owned());
    let states = f
        .states()
        .into_iter()
        .filter_map(|st| {
            let sname = st.name()?.text().to_owned();
            let fields = st.fields().iter().filter_map(extract_field).collect();
            let on_enter = st.on_enter().map(|b| dedent_block(&b, src));
            let on_tick = st.on_tick().map(|b| dedent_block(&b, src));
            let on_exit = st.on_exit().map(|b| dedent_block(&b, src));
            let transitions = st
                .transitions()
                .into_iter()
                .filter_map(|tr| {
                    let target = tr.target_state()?.text().to_owned();
                    let init = tr
                        .target_args()
                        .map(|n| n.text().to_string().trim().to_owned());
                    let when = tr
                        .guard()
                        .map(|n| n.text().to_string().trim().to_owned())
                        .unwrap_or_else(|| "true".to_owned());
                    let tr_attrs = extract_attrs_plain(&tr.attributes());
                    Some(FsmTransitionIr {
                        target,
                        init,
                        when,
                        attributes: tr_attrs,
                    })
                })
                .collect();
            Some(FsmStateIr {
                name: sname,
                fields,
                on_enter,
                on_tick,
                on_exit,
                transitions,
            })
        })
        .collect();

    Some(ExtractedItem {
        item_range: f.text_range(),
        group_attr_range,
        node: GraphIrNode {
            id: canonical_id(module_path, &name),
            kind: GraphNodeKind::Fsm,
            name,
            group,
            attributes,
            payload: GraphNodePayload::Fsm(FsmPayload {
                params,
                requires,
                initial,
                initial_args,
                states,
            }),
            span: Some(span_of(f.syntax())),
            position: None,
            previous_id: None,
        },
    })
}

fn extract_task(t: &TaskDecl, module_path: &str, src: &str) -> Option<ExtractedItem> {
    let name = t.name()?.text().to_owned();
    let (group, group_attr_range, attributes) = split_attrs_and_group(&t.attributes());
    let params = t
        .params()
        .into_iter()
        .filter_map(|p| {
            let pname = p.name()?.text().to_owned();
            let ty = p
                .type_node()
                .map(|n| n.text().to_string().trim().to_owned())
                .unwrap_or_default();
            let default = p
                .default_expr()
                .map(|e| e.text().to_string().trim().to_owned());
            Some(FnParamIr {
                name: pname,
                ty,
                default,
            })
        })
        .collect();
    let on_terms = t
        .on_terms()
        .into_iter()
        .map(|term| term.syntax().text().to_string().trim().to_owned())
        .collect();
    let chain = t
        .on_chain_filters()
        .into_iter()
        .map(|clause| {
            let mut s = format!(".{}", clause.name.text());
            if let Some(ga) = clause.generic_args {
                s.push_str(ga.syntax().text().to_string().trim());
            }
            if let Some(al) = clause.arg_list {
                s.push_str(al.syntax().text().to_string().trim());
            }
            s
        })
        .collect();
    let using_params = t
        .using_params()
        .into_iter()
        .filter_map(|p| {
            let pname = p.name()?.text().to_owned();
            let ty = p
                .type_node()
                .map(|n| n.text().to_string().trim().to_owned())
                .unwrap_or_default();
            Some(SysParamIr { name: pname, ty })
        })
        .collect();
    let body = t
        .body()
        .map(|b| dedent_block(&b, src))
        .unwrap_or_else(|| "{}".to_owned());

    Some(ExtractedItem {
        item_range: t.text_range(),
        group_attr_range,
        node: GraphIrNode {
            id: canonical_id(module_path, &name),
            kind: GraphNodeKind::Task,
            name,
            group,
            attributes,
            payload: GraphNodePayload::Task(TaskPayload {
                params,
                on_terms,
                chain,
                using_params,
                body,
            }),
            span: Some(span_of(t.syntax())),
            position: None,
            previous_id: None,
        },
    })
}

fn extract_table(t: &TableDecl, module_path: &str) -> Option<ExtractedItem> {
    let name = t.name()?.text().to_owned();
    let (group, group_attr_range, attributes) = split_attrs_and_group(&t.attributes());
    let key_enum = t.key_enum().map(|p| ast::path_text(&p)).unwrap_or_default();
    let fields = t.fields().iter().filter_map(extract_field).collect();
    let rows = t
        .rows()
        .into_iter()
        .filter_map(|row| {
            let variant = row.variant_name()?.text().to_owned();
            let values = row
                .inits()
                .into_iter()
                .filter_map(|fi| {
                    let fname = fi.name()?.text().to_owned();
                    let value = fi
                        .value_expr()
                        .map(|e| e.text().to_string().trim().to_owned());
                    Some(FieldInitIr { name: fname, value })
                })
                .collect();
            Some(TableRowIr { variant, values })
        })
        .collect();

    Some(ExtractedItem {
        item_range: t.text_range(),
        group_attr_range,
        node: GraphIrNode {
            id: canonical_id(module_path, &name),
            kind: GraphNodeKind::Table,
            name,
            group,
            attributes,
            payload: GraphNodePayload::Table(TablePayload {
                key_enum,
                fields,
                rows,
            }),
            span: Some(span_of(t.syntax())),
            position: None,
            previous_id: None,
        },
    })
}

fn extract_curve(c: &CurveDecl, module_path: &str) -> Option<ExtractedItem> {
    let name = c.name()?.text().to_owned();
    let (group, group_attr_range, attributes) = split_attrs_and_group(&c.attributes());
    let input_type = c
        .input_type()
        .map(|n| n.text().to_string().trim().to_owned())
        .unwrap_or_default();
    let output_type = c
        .output_type()
        .map(|n| n.text().to_string().trim().to_owned())
        .unwrap_or_default();
    let points = c
        .points()
        .into_iter()
        .filter_map(|pt| {
            let x = pt.x_expr()?.text().to_string().trim().to_owned();
            let y = pt.y_expr()?.text().to_string().trim().to_owned();
            Some(CurvePointIr { x, y })
        })
        .collect();

    Some(ExtractedItem {
        item_range: c.text_range(),
        group_attr_range,
        node: GraphIrNode {
            id: canonical_id(module_path, &name),
            kind: GraphNodeKind::Curve,
            name,
            group,
            attributes,
            payload: GraphNodePayload::Curve(CurvePayload {
                input_type,
                output_type,
                points,
            }),
            span: Some(span_of(c.syntax())),
            position: None,
            previous_id: None,
        },
    })
}

fn extract_schedule_mod(m: &ast::ScheduleMod) -> Option<ScheduleModIr> {
    let kind_enum = m.kind()?;
    let (kind, arg) = match kind_enum {
        ScheduleModKind::RunIf => (
            "run_if".to_owned(),
            m.condition_expr()
                .map(|e| e.text().to_string().trim().to_owned())
                .unwrap_or_default(),
        ),
        ScheduleModKind::Before => (
            "before".to_owned(),
            m.target_path()
                .map(|p| ast::path_text(&p))
                .unwrap_or_default(),
        ),
        ScheduleModKind::After => (
            "after".to_owned(),
            m.target_path()
                .map(|p| ast::path_text(&p))
                .unwrap_or_default(),
        ),
    };
    Some(ScheduleModIr { kind, arg })
}

fn extract_schedule_node(n: &ScheduleNode) -> Option<ScheduleNodeIr> {
    let modifiers = n
        .modifiers()
        .iter()
        .filter_map(extract_schedule_mod)
        .collect();
    match n.kind() {
        ScheduleNodeKind::Leaf => {
            let target = n.path().map(|p| ast::path_text(&p))?;
            Some(ScheduleNodeIr::Leaf { target, modifiers })
        }
        kind => {
            let group_kind = match kind {
                ScheduleNodeKind::Seq => "seq",
                ScheduleNodeKind::SeqWeak => "seq_weak",
                ScheduleNodeKind::Par => "par",
                ScheduleNodeKind::Set => "set",
                ScheduleNodeKind::Leaf => unreachable!(),
            }
            .to_owned();
            let name = n.name()?.text().to_owned();
            let children = n
                .children()
                .iter()
                .filter_map(extract_schedule_node)
                .collect();
            Some(ScheduleNodeIr::Group {
                group_kind,
                name,
                modifiers,
                children,
            })
        }
    }
}

fn extract_schedule(
    s: &ScheduleDecl,
    module_path: &str,
    schedule_counts: &mut HashMap<String, usize>,
) -> Option<ExtractedItem> {
    let name = s.label_text().filter(|l| !l.is_empty())?;
    let id = schedule_canonical_id(module_path, &name, schedule_counts);
    let (group, group_attr_range, attributes) = split_attrs_and_group(&s.attributes());
    let modifiers = s
        .modifiers()
        .iter()
        .filter_map(extract_schedule_mod)
        .collect();
    let nodes = s.nodes().iter().filter_map(extract_schedule_node).collect();

    Some(ExtractedItem {
        item_range: s.text_range(),
        group_attr_range,
        node: GraphIrNode {
            id,
            kind: GraphNodeKind::Schedule,
            name,
            group,
            attributes,
            payload: GraphNodePayload::Schedule(SchedulePayload { modifiers, nodes }),
            span: Some(span_of(s.syntax())),
            position: None,
            previous_id: None,
        },
    })
}

// ---------------------------------------------------------------------------
// Edge extraction
// ---------------------------------------------------------------------------

fn collect_additional_declared_symbols(
    sf: &SourceFile,
    module_path: &str,
    map: &mut HashMap<String, String>,
) {
    for item in sf.items() {
        let short = match item {
            Item::Struct(n) => n.name(),
            Item::Enum(n) => n.name(),
            Item::Resource(n) => n.name(),
            Item::Event(n) => ast::first_ident(n.syntax()),
            Item::Stream(n) => ast::first_ident(n.syntax()),
            Item::Rpc(n) => n.name(),
            Item::Relation(n) => ast::first_ident(n.syntax()),
            Item::Sys(n) => n.name(),
            Item::Obs(n) => n.name(),
            Item::Fn(n) => n.name(),
            Item::SpatialGrid(n) => ast::first_ident(n.syntax()),
            Item::SpatialHistory(n) => ast::first_ident(n.syntax()),
            Item::HashIndex(n) => ast::first_ident(n.syntax()),
            Item::Aspect(n) => ast::first_ident(n.syntax()),
            _ => None,
        };
        if let Some(tok) = short {
            let s = tok.text().to_owned();
            map.entry(s.clone())
                .or_insert_with(|| canonical_id(module_path, &s));
        }
    }
}

fn resolve_target(
    target: &str,
    module_path: &str,
    declared_symbols: &HashMap<String, String>,
) -> String {
    let trimmed = target.trim();
    if let Some(id) = declared_symbols.get(trimmed) {
        return id.clone();
    }
    if trimmed.contains("::") {
        return trimmed.to_owned();
    }
    canonical_id(module_path, trimmed)
}

fn extract_edges(
    sf: &SourceFile,
    module_path: &str,
    declared_symbols: &HashMap<String, String>,
) -> Vec<GraphIrEdge> {
    let mut raw_edges: Vec<GraphIrEdge> = Vec::new();
    let mut seen: BTreeSet<(String, String, String, Option<String>)> = BTreeSet::new();
    let mut schedule_counts: HashMap<String, usize> = HashMap::new();

    let mut push_edge = |from: &str, to: String, kind: &str, label: Option<String>| {
        let key = (from.to_owned(), to.clone(), kind.to_owned(), label.clone());
        if seen.insert(key) {
            raw_edges.push(GraphIrEdge {
                from: from.to_owned(),
                to,
                kind: kind.to_owned(),
                label,
            });
        }
    };

    for item in sf.items() {
        match item {
            Item::Component(c) => {
                let Some(name) = c.name() else { continue };
                let from = canonical_id(module_path, name.text());
                for req in extract_requires(&c.require_clauses()) {
                    let to = resolve_target(&req.path, module_path, declared_symbols);
                    push_edge(&from, to, "require", None);
                }
            }
            Item::Fn(f) if f.is_node_pure() => {
                let Some(name) = f.name() else { continue };
                let from = canonical_id(module_path, name.text());
                if let Some(body) = f.body() {
                    scan_block_edges(
                        body.syntax(),
                        &from,
                        module_path,
                        declared_symbols,
                        &mut push_edge,
                    );
                }
            }
            Item::Timeline(t) => {
                let Some(name) = t.name() else { continue };
                let from = canonical_id(module_path, name.text());
                for req in extract_requires(&t.require_clauses()) {
                    let to = resolve_target(&req.path, module_path, declared_symbols);
                    push_edge(&from, to, "require", None);
                }
                for at in t.at_entries() {
                    if let Some(act) = at.action_node() {
                        scan_block_edges(
                            &act,
                            &from,
                            module_path,
                            declared_symbols,
                            &mut push_edge,
                        );
                    }
                }
            }
            Item::Fsm(f) => {
                let Some(name) = f.name() else { continue };
                let from = canonical_id(module_path, name.text());
                for req in extract_requires(&f.require_clauses()) {
                    let to = resolve_target(&req.path, module_path, declared_symbols);
                    push_edge(&from, to, "require", None);
                }
                for param in f.params() {
                    if let Some(ty) = param.type_node() {
                        record_sys_param_edge(
                            &ty,
                            param.name().map(|t| t.text().to_owned()),
                            &from,
                            module_path,
                            declared_symbols,
                            &mut push_edge,
                        );
                    }
                }
                for st in f.states() {
                    if let Some(b) = st.on_enter() {
                        scan_block_edges(
                            b.syntax(),
                            &from,
                            module_path,
                            declared_symbols,
                            &mut push_edge,
                        );
                    }
                    if let Some(b) = st.on_tick() {
                        scan_block_edges(
                            b.syntax(),
                            &from,
                            module_path,
                            declared_symbols,
                            &mut push_edge,
                        );
                    }
                    if let Some(b) = st.on_exit() {
                        scan_block_edges(
                            b.syntax(),
                            &from,
                            module_path,
                            declared_symbols,
                            &mut push_edge,
                        );
                    }
                    for tr in st.transitions() {
                        if let Some(guard) = tr.guard() {
                            scan_block_edges(
                                &guard,
                                &from,
                                module_path,
                                declared_symbols,
                                &mut push_edge,
                            );
                        }
                    }
                }
            }
            Item::Task(t) => {
                let Some(name) = t.name() else { continue };
                let from = canonical_id(module_path, name.text());
                for term in t.on_terms() {
                    let Some(ty) = term.type_node() else { continue };
                    let is_write = has_mut_ref(&ty);
                    if let Some(comp) = extract_base_type_ident(&ty) {
                        let to = resolve_target(&comp, module_path, declared_symbols);
                        let kind = if is_write { "writes" } else { "reads" };
                        let label = term.alias().map(|a| a.text().to_owned());
                        push_edge(&from, to, kind, label);
                    }
                }
                for param in t.using_params() {
                    if let Some(ty) = param.type_node() {
                        record_sys_param_edge(
                            &ty,
                            param.name().map(|t| t.text().to_owned()),
                            &from,
                            module_path,
                            declared_symbols,
                            &mut push_edge,
                        );
                    }
                }
                if let Some(body) = t.body() {
                    scan_block_edges(
                        body.syntax(),
                        &from,
                        module_path,
                        declared_symbols,
                        &mut push_edge,
                    );
                }
            }
            Item::Table(t) => {
                let Some(name) = t.name() else { continue };
                let from = canonical_id(module_path, name.text());
                if let Some(key_enum) = t.key_enum() {
                    let to =
                        resolve_target(&ast::path_text(&key_enum), module_path, declared_symbols);
                    push_edge(&from, to, "key_enum", None);
                }
            }
            Item::Schedule(s) => {
                let Some(label) = s.label_text().filter(|l| !l.is_empty()) else {
                    continue;
                };
                let from = schedule_canonical_id(module_path, &label, &mut schedule_counts);
                for m in s.modifiers() {
                    collect_schedule_mod_edge(
                        &m,
                        &from,
                        module_path,
                        declared_symbols,
                        &mut push_edge,
                    );
                }
                for node in s.nodes() {
                    collect_schedule_node_edges(
                        &node,
                        &from,
                        None,
                        module_path,
                        declared_symbols,
                        &mut push_edge,
                    );
                }
            }
            _ => {}
        }
    }

    raw_edges
}

fn has_mut_ref(ty: &SyntaxNode) -> bool {
    ty.descendants_with_tokens()
        .filter_map(|el| el.into_token())
        .any(|tok| tok.kind() == SyntaxKind::KwMut)
}

fn is_stream_in_ref(ty: &SyntaxNode) -> bool {
    ty.descendants_with_tokens()
        .filter_map(|el| el.into_token())
        .any(|tok| tok.kind() == SyntaxKind::KwStreamIn)
}

fn extract_base_type_ident(ty: &SyntaxNode) -> Option<String> {
    if let Some(path) = ty.descendants().find_map(ast::Path::cast) {
        let full = ast::path_text(&path);
        // Strip `::stratum` suffix if this is a stratum projection like `CombatantBody::caps`
        if let Some((base, _)) = full.split_once("::") {
            return Some(base.to_owned());
        }
        return Some(full);
    }
    None
}

fn record_sys_param_edge(
    ty: &SyntaxNode,
    label: Option<String>,
    from: &str,
    module_path: &str,
    declared_symbols: &HashMap<String, String>,
    push_edge: &mut impl FnMut(&str, String, &str, Option<String>),
) {
    if is_stream_in_ref(ty) {
        if let Some(ga) = ty.descendants().find_map(ast::GenericArgs::cast)
            && let Some(path) = ga.syntax().descendants().find_map(ast::Path::cast)
        {
            let to = resolve_target(&ast::path_text(&path), module_path, declared_symbols);
            push_edge(from, to, "reads_stream", label);
        }
        return;
    }
    let kind = if has_mut_ref(ty) {
        "writes_resource"
    } else {
        "reads_resource"
    };
    if let Some(base) = extract_base_type_ident(ty) {
        let to = resolve_target(&base, module_path, declared_symbols);
        push_edge(from, to, kind, label);
    }
}

fn postfix_direct_method(node: &SyntaxNode) -> Option<String> {
    let mut saw_dot = false;
    for el in node.children_with_tokens() {
        if let Some(tok) = el.into_token() {
            if tok.kind().is_trivia() {
                continue;
            }
            if saw_dot {
                if tok.kind() == SyntaxKind::Ident {
                    return Some(tok.text().to_owned());
                }
                return None;
            }
            if tok.kind() == SyntaxKind::Dot {
                saw_dot = true;
            }
        }
    }
    None
}

fn scan_block_edges(
    root: &SyntaxNode,
    from: &str,
    module_path: &str,
    declared_symbols: &HashMap<String, String>,
    push_edge: &mut impl FnMut(&str, String, &str, Option<String>),
) {
    for node in root.descendants() {
        match node.kind() {
            SyntaxKind::IndexExpr => {
                if let Some(first_child) = node.children().next()
                    && first_child.kind() == SyntaxKind::PathExpr
                    && let Some(path) = ast::child::<ast::Path>(&first_child)
                {
                    let name = ast::path_text(&path);
                    if declared_symbols.contains_key(&name) || name.contains("::") {
                        let to = resolve_target(&name, module_path, declared_symbols);
                        push_edge(from, to, "table_lookup", None);
                    }
                }
            }
            SyntaxKind::InsertExpr => {
                if let Some(al) = ast::child::<ast::ArgList>(&node) {
                    for sl in al
                        .syntax()
                        .descendants()
                        .filter(|n| n.kind() == SyntaxKind::StructLitExpr)
                    {
                        if let Some(path) = sl.children().find_map(ast::Path::cast).or_else(|| {
                            sl.children()
                                .find(|n| n.kind() == SyntaxKind::PathExpr)
                                .and_then(|pe| ast::child::<ast::Path>(&pe))
                        }) {
                            let to = resolve_target(
                                &ast::path_text(&path),
                                module_path,
                                declared_symbols,
                            );
                            push_edge(from, to, "inserts", None);
                        }
                    }
                }
            }
            SyntaxKind::PostfixCallExpr => {
                let Some(callee) = node.children().next() else {
                    continue;
                };
                if let Some(method) = postfix_direct_method(&node) {
                    if callee.kind() == SyntaxKind::PathExpr
                        && let Some(path) = ast::child::<ast::Path>(&callee)
                    {
                        let base = ast::path_text(&path);
                        if declared_symbols.contains_key(&base) || base.contains("::") {
                            let to = resolve_target(&base, module_path, declared_symbols);
                            if method == "sample" {
                                push_edge(from, to, "table_lookup", Some("sample".to_owned()));
                            } else {
                                push_edge(from, to, "call", Some(method));
                            }
                        }
                    } else if callee.kind() == SyntaxKind::FieldExpr
                        && method == "sample"
                        && let Some(recv) = callee.children().next()
                        && recv.kind() == SyntaxKind::PathExpr
                        && let Some(path) = ast::child::<ast::Path>(&recv)
                    {
                        let base = ast::path_text(&path);
                        if declared_symbols.contains_key(&base) || base.contains("::") {
                            let to = resolve_target(&base, module_path, declared_symbols);
                            push_edge(from, to, "table_lookup", Some("sample".to_owned()));
                        }
                    }
                } else if callee.kind() == SyntaxKind::PathExpr
                    && let Some(path) = ast::child::<ast::Path>(&callee)
                {
                    let callee_name = ast::path_text(&path);
                    if callee_name == "trigger"
                        && let Some(al) = ast::child::<ast::ArgList>(&node)
                    {
                        for sl in al
                            .syntax()
                            .children()
                            .filter(|n| n.kind() == SyntaxKind::StructLitExpr)
                        {
                            if let Some(ev_path) = sl
                                .children()
                                .find(|n| n.kind() == SyntaxKind::PathExpr)
                                .and_then(|pe| ast::child::<ast::Path>(&pe))
                            {
                                let to = resolve_target(
                                    &ast::path_text(&ev_path),
                                    module_path,
                                    declared_symbols,
                                );
                                push_edge(from, to, "triggers", None);
                            }
                        }
                    } else if callee_name == "insert"
                        && let Some(al) = ast::child::<ast::ArgList>(&node)
                    {
                        for sl in al
                            .syntax()
                            .descendants()
                            .filter(|n| n.kind() == SyntaxKind::StructLitExpr)
                        {
                            if let Some(comp_path) = sl
                                .children()
                                .find(|n| n.kind() == SyntaxKind::PathExpr)
                                .and_then(|pe| ast::child::<ast::Path>(&pe))
                            {
                                let to = resolve_target(
                                    &ast::path_text(&comp_path),
                                    module_path,
                                    declared_symbols,
                                );
                                push_edge(from, to, "inserts", None);
                            }
                        }
                    } else if let Some((base, method)) = callee_name.rsplit_once("::")
                        && method == "start"
                    {
                        let to = resolve_target(base, module_path, declared_symbols);
                        push_edge(from, to, "call", Some("start".to_owned()));
                    } else if declared_symbols.contains_key(&callee_name)
                        || callee_name.contains("::")
                    {
                        let to = resolve_target(&callee_name, module_path, declared_symbols);
                        push_edge(from, to, "call", None);
                    }
                } else if callee.kind() == SyntaxKind::FieldExpr
                    && let Some(recv) = callee.children().next()
                    && recv.kind() == SyntaxKind::PathExpr
                    && let Some(path) = ast::child::<ast::Path>(&recv)
                {
                    let base = ast::path_text(&path);
                    let method = callee
                        .children_with_tokens()
                        .filter_map(|el| el.into_token())
                        .filter(|t| t.kind() == SyntaxKind::Ident)
                        .last()
                        .map(|t| t.text().to_owned());
                    if method.as_deref() == Some("sample")
                        && (declared_symbols.contains_key(&base) || base.contains("::"))
                    {
                        let to = resolve_target(&base, module_path, declared_symbols);
                        push_edge(from, to, "table_lookup", Some("sample".to_owned()));
                    }
                }
            }
            _ => {}
        }
    }
}

fn collect_schedule_mod_edge(
    m: &ast::ScheduleMod,
    from: &str,
    module_path: &str,
    declared_symbols: &HashMap<String, String>,
    push_edge: &mut impl FnMut(&str, String, &str, Option<String>),
) {
    match m.kind() {
        Some(ScheduleModKind::Before) => {
            if let Some(p) = m.target_path() {
                let to = resolve_target(&ast::path_text(&p), module_path, declared_symbols);
                push_edge(from, to, "before", None);
            }
        }
        Some(ScheduleModKind::After) => {
            if let Some(p) = m.target_path() {
                let to = resolve_target(&ast::path_text(&p), module_path, declared_symbols);
                push_edge(from, to, "after", None);
            }
        }
        _ => {}
    }
}

fn collect_schedule_node_edges(
    node: &ScheduleNode,
    from: &str,
    enclosing_group: Option<&str>,
    module_path: &str,
    declared_symbols: &HashMap<String, String>,
    push_edge: &mut impl FnMut(&str, String, &str, Option<String>),
) {
    for m in node.modifiers() {
        collect_schedule_mod_edge(&m, from, module_path, declared_symbols, push_edge);
    }
    if node.is_leaf() {
        if let Some(p) = node.path() {
            let to = resolve_target(&ast::path_text(&p), module_path, declared_symbols);
            push_edge(
                from,
                to,
                "schedules",
                enclosing_group.map(ToOwned::to_owned),
            );
        }
    } else {
        let group_name = node.name().map(|t| t.text().to_owned());
        let next_group = group_name.as_deref().or(enclosing_group);
        for ch in node.children() {
            collect_schedule_node_edges(
                &ch,
                from,
                next_group,
                module_path,
                declared_symbols,
                push_edge,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// CST Diff, Targeted Splicing & Node Rendering
// ---------------------------------------------------------------------------

fn is_valid_schedule_id(id: &str, expected_base: &str) -> bool {
    if id == expected_base {
        return true;
    }
    let Some(rest) = id
        .strip_prefix(expected_base)
        .and_then(|s| s.strip_prefix('#'))
    else {
        return false;
    };
    rest.parse::<usize>()
        .ok()
        .is_some_and(|n| n >= 2 && rest == n.to_string())
}

fn validate_patch_node(module_path: &str, node: &GraphIrNode) -> Result<(), GraphIrError> {
    if node.id.trim().is_empty() {
        return Err(GraphIrError::InvalidNode {
            id: node.id.clone(),
            reason: "node id must not be empty".to_owned(),
        });
    }
    if node.name.trim().is_empty() {
        return Err(GraphIrError::InvalidNode {
            id: node.id.clone(),
            reason: "node name must not be empty".to_owned(),
        });
    }
    let expected_id = canonical_id(module_path, &node.name);
    let id_valid = if node.kind == GraphNodeKind::Schedule {
        is_valid_schedule_id(&node.id, &expected_id)
    } else {
        node.id == expected_id
    };
    if !id_valid {
        return Err(GraphIrError::InvalidNode {
            id: node.id.clone(),
            reason: format!(
                "node id `{}` does not match canonical id `{expected_id}` for name `{}`",
                node.id, node.name
            ),
        });
    }
    if node.payload.expected_kind() != node.kind {
        return Err(GraphIrError::InvalidNode {
            id: node.id.clone(),
            reason: format!(
                "node kind {:?} does not match payload variant {:?}",
                node.kind,
                node.payload.expected_kind()
            ),
        });
    }
    if let Some(pos) = node.position
        && (!pos.x.is_finite() || !pos.y.is_finite())
    {
        return Err(GraphIrError::InvalidNode {
            id: node.id.clone(),
            reason: "non-finite position coordinates".to_owned(),
        });
    }
    Ok(())
}

fn non_group_attrs(attrs: &[GraphAttribute]) -> Vec<&GraphAttribute> {
    attrs.iter().filter(|a| a.name != "node_group").collect()
}

fn normalized_attrs_for_compare(node: &GraphIrNode) -> Vec<GraphAttribute> {
    let mut out: Vec<GraphAttribute> = node
        .attributes
        .iter()
        .filter(|a| a.name != "node_group")
        .cloned()
        .collect();
    if node.kind == GraphNodeKind::NodePureFn && !out.iter().any(|a| a.name == "node_pure") {
        out.insert(
            0,
            GraphAttribute {
                name: "node_pure".to_owned(),
                args: Vec::new(),
            },
        );
    }
    out
}

fn plan_node_update(src: &str, cur: &ExtractedItem, next: &GraphIrNode) -> Option<TextEdit> {
    let cur_attrs = normalized_attrs_for_compare(&cur.node);
    let next_attrs = normalized_attrs_for_compare(next);
    let core_same = cur.node.kind == next.kind
        && cur.node.name == next.name
        && cur_attrs == next_attrs
        && cur.node.payload == next.payload;

    if core_same && cur.node.group == next.group {
        return None;
    }

    if core_same {
        return Some(plan_group_only_edit(
            src,
            cur.item_range,
            cur.group_attr_range,
            next.group.as_deref(),
        ));
    }

    let item_start = usize::from(cur.item_range.start());
    let item_end = usize::from(cur.item_range.end());
    let indent = line_indent_at(src, item_start);
    let rendered = render_node(next, &indent);
    Some(TextEdit {
        start: item_start,
        end: item_end,
        core_end: item_end,
        replacement: rendered,
    })
}

fn plan_group_only_edit(
    src: &str,
    item_range: TextRange,
    group_attr_range: Option<TextRange>,
    new_group: Option<&str>,
) -> TextEdit {
    let item_start = usize::from(item_range.start());
    match (group_attr_range, new_group) {
        (Some(gr), Some(g)) => {
            let s = usize::from(gr.start());
            let e = usize::from(gr.end());
            TextEdit {
                start: s,
                end: e,
                core_end: e,
                replacement: format!("@node_group(\"{}\")", escape_strata_string(g)),
            }
        }
        (Some(gr), None) => {
            let mut s = usize::from(gr.start());
            let mut e = usize::from(gr.end());
            let bytes = src.as_bytes();
            // If `@node_group(...)` occupies its own line before the item, remove the whole line.
            let line_start = src[..s].rfind('\n').map_or(0, |i| i + 1);
            let only_ws_before = src[line_start..s].bytes().all(|b| b == b' ' || b == b'\t');
            let mut after_ws = e;
            while after_ws < bytes.len() && (bytes[after_ws] == b' ' || bytes[after_ws] == b'\t') {
                after_ws += 1;
            }
            if only_ws_before && after_ws < bytes.len() && bytes[after_ws] == b'\n' {
                s = line_start;
                e = after_ws + 1;
            } else if only_ws_before
                && after_ws + 1 < bytes.len()
                && bytes[after_ws] == b'\r'
                && bytes[after_ws + 1] == b'\n'
            {
                s = line_start;
                e = after_ws + 2;
            } else if e < bytes.len() && (bytes[e] == b' ' || bytes[e] == b'\t') {
                // Inline attribute before next attribute/keyword: consume trailing spaces.
                while e < bytes.len() && (bytes[e] == b' ' || bytes[e] == b'\t') {
                    e += 1;
                }
            } else if s > line_start && bytes[s - 1] == b' ' {
                // Inline attribute after item name (`component Foo @node_group("A") {`): consume leading space.
                while s > line_start && (bytes[s - 1] == b' ' || bytes[s - 1] == b'\t') {
                    s -= 1;
                }
            }
            TextEdit {
                start: s,
                end: e,
                core_end: e,
                replacement: String::new(),
            }
        }
        (None, Some(g)) => {
            let indent = line_indent_at(src, item_start);
            TextEdit {
                start: item_start,
                end: item_start,
                core_end: item_start,
                replacement: format!("@node_group(\"{}\")\n{indent}", escape_strata_string(g)),
            }
        }
        (None, None) => unreachable!("group_only_edit called with identical None groups"),
    }
}

fn plan_node_removal(src: &str, item_range: TextRange) -> TextEdit {
    let mut start = usize::from(item_range.start());
    let core_end = usize::from(item_range.end());
    let mut end = core_end;
    let bytes = src.as_bytes();

    // Trim horizontal indent on the item's starting line if nothing precedes it on that line.
    let line_start = src[..start].rfind('\n').map_or(0, |i| i + 1);
    if src[line_start..start]
        .bytes()
        .all(|b| b == b' ' || b == b'\t')
    {
        start = line_start;
    }

    // Consume trailing horizontal spaces and up to one newline (plus one blank separator line if needed).
    while end < bytes.len() && (bytes[end] == b' ' || bytes[end] == b'\t') {
        end += 1;
    }
    if end < bytes.len() && bytes[end] == b'\r' {
        end += 1;
    }
    if end < bytes.len() && bytes[end] == b'\n' {
        end += 1;
    }
    // Consume one extra blank line if both sides would otherwise leave a double blank line.
    let mut next_end = end;
    if next_end < bytes.len() && bytes[next_end] == b'\r' {
        next_end += 1;
    }
    if next_end < bytes.len() && bytes[next_end] == b'\n' {
        end = next_end + 1;
    }

    TextEdit {
        start,
        end,
        core_end,
        replacement: String::new(),
    }
}

fn line_indent_at(src: &str, byte_pos: usize) -> String {
    let line_start = src[..byte_pos].rfind('\n').map_or(0, |i| i + 1);
    src[line_start..byte_pos]
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect()
}

fn dedent_from_offset(raw: &str, byte_start: usize, src: &str) -> String {
    let base_indent = line_indent_at(src, byte_start);
    if base_indent.is_empty() || !raw.contains('\n') {
        return raw.to_owned();
    }
    let mut lines = raw.lines();
    let Some(first) = lines.next() else {
        return raw.to_owned();
    };
    let mut out = String::from(first);
    for line in lines {
        out.push('\n');
        if let Some(stripped) = line.strip_prefix(&base_indent) {
            out.push_str(stripped);
        } else {
            out.push_str(line);
        }
    }
    out
}

fn dedent_block(block: &Block, src: &str) -> String {
    dedent_from_offset(
        &block.syntax().text().to_string(),
        usize::from(block.text_range().start()),
        src,
    )
}

fn reindent_tail_lines(text: &str, target_indent: &str) -> String {
    if target_indent.is_empty() || !text.contains('\n') {
        return text.to_owned();
    }
    let mut lines = text.lines();
    let Some(first) = lines.next() else {
        return text.to_owned();
    };
    let mut out = String::from(first);
    for line in lines {
        out.push('\n');
        if !line.trim().is_empty() {
            out.push_str(target_indent);
        }
        out.push_str(line);
    }
    out
}

fn reindent_block(block_text: &str, target_indent: &str) -> String {
    let trimmed = block_text.trim();
    let wrapped = if trimmed.starts_with('{') && trimmed.ends_with('}') {
        trimmed.to_owned()
    } else if trimmed.is_empty() {
        "{}".to_owned()
    } else {
        format!("{{\n    {trimmed}\n}}")
    };
    reindent_tail_lines(&wrapped, target_indent)
}

fn is_brace_terminated_timeline_action(trimmed: &str) -> bool {
    if trimmed.is_empty() || trimmed.ends_with(';') {
        return false;
    }
    let wrapped = format!("fn _t() {{\n{trimmed}\n}}");
    let parsed = crate::parse(&wrapped);
    let Some(sf) = SourceFile::cast(parsed.syntax()) else {
        return false;
    };
    let Some(Item::Fn(func)) = sf.items().next() else {
        return false;
    };
    let Some(block) = func.body() else {
        return false;
    };
    let mut children = block.syntax().children();
    let Some(stmt) = children.next() else {
        return false;
    };
    if children.next().is_some() {
        return false;
    }
    let node = if stmt.kind() == SyntaxKind::ExprStmt {
        stmt.children().next().unwrap_or(stmt)
    } else {
        stmt
    };
    match node.kind() {
        SyntaxKind::Block
        | SyntaxKind::WhileStmt
        | SyntaxKind::LoopStmt
        | SyntaxKind::AtomicStmt
        | SyntaxKind::AbortIfStmt
        | SyntaxKind::RaceStmt
        | SyntaxKind::IfExpr
        | SyntaxKind::MatchExpr => true,
        SyntaxKind::ForExpr => ast::child::<Block>(&node).is_some(),
        _ => false,
    }
}

fn escape_strata_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

fn render_attribute(attr: &GraphAttribute) -> String {
    if attr.args.is_empty() {
        format!("@{}", attr.name)
    } else {
        let args: Vec<String> = attr
            .args
            .iter()
            .map(|a| match &a.key {
                Some(k) => format!("{k} = {}", a.value),
                None => a.value.clone(),
            })
            .collect();
        format!("@{}({})", attr.name, args.join(", "))
    }
}

fn push_leading_attrs(out: &mut String, node: &GraphIrNode, indent: &str, ensure_node_pure: bool) {
    if let Some(group) = &node.group {
        out.push_str(&format!(
            "@node_group(\"{}\")\n{indent}",
            escape_strata_string(group)
        ));
    }
    let mut emitted_pure = false;
    for attr in non_group_attrs(&node.attributes) {
        if attr.name == "node_pure" {
            emitted_pure = true;
        }
        out.push_str(&render_attribute(attr));
        out.push('\n');
        out.push_str(indent);
    }
    if ensure_node_pure && !emitted_pure {
        out.push_str("@node_pure\n");
        out.push_str(indent);
    }
}

fn render_requires(requires: &[RequireIr]) -> String {
    if requires.is_empty() {
        return String::new();
    }
    let items: Vec<String> = requires
        .iter()
        .map(|r| match &r.value {
            Some(v) => format!("{} = {v}", r.path),
            None => r.path.clone(),
        })
        .collect();
    format!(" @require({})", items.join(", "))
}

fn render_field(f: &FieldIr, indent: &str) -> String {
    let mut s = String::new();
    for attr in &f.attributes {
        s.push_str(indent);
        s.push_str(&render_attribute(attr));
        s.push('\n');
    }
    s.push_str(indent);
    s.push_str(&format!("{}: {}", f.name, f.ty));
    if let Some(def) = &f.default {
        s.push_str(&format!(" = {def}"));
    }
    s.push(',');
    s
}

fn render_node(node: &GraphIrNode, indent: &str) -> String {
    let mut out = String::new();
    let is_pure_fn = matches!(node.kind, GraphNodeKind::NodePureFn);
    push_leading_attrs(&mut out, node, indent, is_pure_fn);

    match &node.payload {
        GraphNodePayload::Component(p) => {
            out.push_str(&format!(
                "component {}{}",
                node.name,
                render_requires(&p.requires)
            ));
            if p.is_unit && p.strata.is_empty() && p.fields.is_empty() {
                out.push(';');
                return out;
            }
            out.push_str(" {\n");
            let inner = format!("{indent}    ");
            for st in &p.strata {
                if st.is_hot {
                    out.push_str(&format!("{inner}hot {{\n"));
                } else {
                    out.push_str(&format!("{inner}cold {} {{\n", st.name));
                }
                let s_inner = format!("{inner}    ");
                for f in &st.fields {
                    out.push_str(&render_field(f, &s_inner));
                    out.push('\n');
                }
                out.push_str(&format!("{inner}}}\n"));
            }
            for f in &p.fields {
                out.push_str(&render_field(f, &inner));
                out.push('\n');
            }
            out.push_str(&format!("{indent}}}"));
        }
        GraphNodePayload::NodePureFn(p) => {
            out.push_str(&format!("fn {}", node.name));
            if !p.generic_params.is_empty() {
                out.push_str(&format!("<{}>", p.generic_params.join(", ")));
            }
            let params: Vec<String> = p
                .params
                .iter()
                .map(|param| match &param.default {
                    Some(d) => format!("{}: {} = {d}", param.name, param.ty),
                    None => format!("{}: {}", param.name, param.ty),
                })
                .collect();
            out.push_str(&format!("({})", params.join(", ")));
            if let Some(ret) = &p.return_type {
                out.push_str(&format!(" -> {ret}"));
            }
            out.push(' ');
            out.push_str(&reindent_block(&p.body, indent));
        }
        GraphNodePayload::Timeline(p) => {
            out.push_str(&format!(
                "timeline {}{} {{\n",
                node.name,
                render_requires(&p.requires)
            ));
            let inner = format!("{indent}    ");
            for w in &p.windows {
                out.push_str(&format!("{inner}window {} = {};\n", w.name, w.expr));
            }
            for ev in &p.events {
                let trimmed = ev.action.trim();
                let act = if trimmed.starts_with('{') {
                    reindent_block(&ev.action, &inner)
                } else if trimmed.ends_with(';') || is_brace_terminated_timeline_action(trimmed) {
                    reindent_tail_lines(trimmed, &inner)
                } else {
                    reindent_tail_lines(&format!("{trimmed};"), &inner)
                };
                out.push_str(&format!("{inner}at {} => {act}\n", ev.frame));
            }
            out.push_str(&format!("{indent}}}"));
        }
        GraphNodePayload::Fsm(p) => {
            out.push_str(&format!("fsm {}", node.name));
            if !p.params.is_empty() {
                let params: Vec<String> = p
                    .params
                    .iter()
                    .map(|sp| format!("{}: {}", sp.name, sp.ty))
                    .collect();
                out.push_str(&format!("({})", params.join(", ")));
            }
            out.push_str(&render_requires(&p.requires));
            out.push_str(" {\n");
            let inner = format!("{indent}    ");
            if let Some(init_state) = &p.initial {
                out.push_str(&format!("{inner}initial {init_state}"));
                if let Some(args) = &p.initial_args {
                    out.push(' ');
                    out.push_str(args);
                }
                out.push_str(";\n");
            }
            for st in &p.states {
                out.push_str(&format!("{inner}state {} {{\n", st.name));
                let s_inner = format!("{inner}    ");
                for f in &st.fields {
                    out.push_str(&render_field(f, &s_inner));
                    out.push('\n');
                }
                if let Some(b) = &st.on_enter {
                    out.push_str(&format!(
                        "{s_inner}on_enter {}\n",
                        reindent_block(b, &s_inner)
                    ));
                }
                if let Some(b) = &st.on_tick {
                    out.push_str(&format!(
                        "{s_inner}on_tick {}\n",
                        reindent_block(b, &s_inner)
                    ));
                }
                if let Some(b) = &st.on_exit {
                    out.push_str(&format!(
                        "{s_inner}on_exit {}\n",
                        reindent_block(b, &s_inner)
                    ));
                }
                for tr in &st.transitions {
                    out.push_str(&format!("{s_inner}to {}", tr.target));
                    if let Some(init) = &tr.init {
                        out.push(' ');
                        out.push_str(init);
                    }
                    out.push_str(&format!(" when {}", tr.when));
                    for attr in &tr.attributes {
                        out.push(' ');
                        out.push_str(&render_attribute(attr));
                    }
                    out.push_str(";\n");
                }
                out.push_str(&format!("{inner}}}\n"));
            }
            out.push_str(&format!("{indent}}}"));
        }
        GraphNodePayload::Task(p) => {
            let params: Vec<String> = p
                .params
                .iter()
                .map(|param| match &param.default {
                    Some(d) => format!("{}: {} = {d}", param.name, param.ty),
                    None => format!("{}: {}", param.name, param.ty),
                })
                .collect();
            out.push_str(&format!("task {}({})", node.name, params.join(", ")));
            if !p.on_terms.is_empty() {
                out.push_str(&format!(" on ({})", p.on_terms.join(", ")));
            }
            for ch in &p.chain {
                out.push(' ');
                out.push_str(ch);
            }
            if !p.using_params.is_empty() {
                let up: Vec<String> = p
                    .using_params
                    .iter()
                    .map(|sp| format!("{}: {}", sp.name, sp.ty))
                    .collect();
                out.push_str(&format!(" using ({})", up.join(", ")));
            }
            out.push(' ');
            out.push_str(&reindent_block(&p.body, indent));
        }
        GraphNodePayload::Table(p) => {
            out.push_str(&format!("table {} by {} {{\n", node.name, p.key_enum));
            let inner = format!("{indent}    ");
            for f in &p.fields {
                out.push_str(&render_field(f, &inner));
                out.push('\n');
            }
            out.push_str(&format!("{indent}}} = {{\n"));
            for row in &p.rows {
                let vals: Vec<String> = row
                    .values
                    .iter()
                    .map(|fi| match &fi.value {
                        Some(v) => format!("{}: {v}", fi.name),
                        None => fi.name.clone(),
                    })
                    .collect();
                out.push_str(&format!(
                    "{inner}{} => {{ {} }},\n",
                    row.variant,
                    vals.join(", ")
                ));
            }
            out.push_str(&format!("{indent}}};"));
        }
        GraphNodePayload::Curve(p) => {
            out.push_str(&format!(
                "curve {}({} -> {}) = [\n",
                node.name, p.input_type, p.output_type
            ));
            let inner = format!("{indent}    ");
            for pt in &p.points {
                out.push_str(&format!("{inner}({}, {}),\n", pt.x, pt.y));
            }
            out.push_str(&format!("{indent}];"));
        }
        GraphNodePayload::Schedule(p) => {
            out.push_str(&format!("schedule {}", node.name));
            for m in &p.modifiers {
                out.push_str(&format!(" {}({})", m.kind, m.arg));
            }
            out.push_str(" {\n");
            let inner = format!("{indent}    ");
            for sn in &p.nodes {
                render_schedule_node(&mut out, sn, &inner);
            }
            out.push_str(&format!("{indent}}}"));
        }
    }
    out
}

fn render_schedule_node(out: &mut String, node: &ScheduleNodeIr, indent: &str) {
    match node {
        ScheduleNodeIr::Leaf { target, modifiers } => {
            out.push_str(indent);
            out.push_str(target);
            for m in modifiers {
                out.push_str(&format!(" {}({})", m.kind, m.arg));
            }
            out.push('\n');
        }
        ScheduleNodeIr::Group {
            group_kind,
            name,
            modifiers,
            children,
        } => {
            out.push_str(&format!("{indent}{group_kind} {name}"));
            for m in modifiers {
                out.push_str(&format!(" {}({})", m.kind, m.arg));
            }
            out.push_str(" {\n");
            let inner = format!("{indent}    ");
            for ch in children {
                render_schedule_node(out, ch, &inner);
            }
            out.push_str(&format!("{indent}}}\n"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_8_FIXTURE: &str = r#"module test::graph @version(1.0.0);

enum Tier { Low = 0, High = 1 }

@node_group("Core")
component Pos2D {
    xy: vec2 = vec2::ZERO,
}

component Marker;

@node_pure
@node_group(name = "Math")
fn scale_hp(hp: f32, mult: f32) -> f32 {
    return hp * mult;
}

fn helper_not_pure(x: f32) -> f32 {
    return x + 1.0;
}

@sparse
timeline SlashTl @rate(60_hz) @duration(12_f) {
    window active = 2_f .. 8_f;
    at 2_f => trigger(self, HitEvent {});
}

fsm BossFsm @require(Pos2D) {
    initial Idle;
    state Idle {
        on_enter {
            let x = 1;
        }
        to Enraged when true;
    }
    state Enraged {
        to Idle when false;
    }
}

task DashTask(speed: f32) on (pos: &mut Pos2D) {
    pos.xy.x += speed;
}

table TierStats by Tier {
    dmg: f32,
} = {
    Low => { dmg: 10.0 },
    High => { dmg: 25.0 },
};

curve Falloff(meters -> f32) = [
    (0.0_m, 100.0),
    (50.0_m, 25.0),
];

schedule FixedUpdate {
    seq Main {
        DashTask,
        BossFsm,
    }
}
"#;

    #[test]
    fn export_covers_all_8_kinds_and_excludes_non_pure_fn() {
        let doc = export_graph_ir(ALL_8_FIXTURE, None).expect("export succeeds");
        assert_eq!(doc.version, "1.0");
        assert_eq!(doc.module_path, "test::graph");
        assert!(doc.schema_fingerprint.starts_with("0x"));
        let ids: Vec<_> = doc.nodes.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "test::graph::Pos2D",
                "test::graph::Marker",
                "test::graph::scale_hp",
                "test::graph::SlashTl",
                "test::graph::BossFsm",
                "test::graph::DashTask",
                "test::graph::TierStats",
                "test::graph::Falloff",
                "test::graph::FixedUpdate",
            ]
        );
        assert!(!ids.contains(&"test::graph::helper_not_pure"));
        assert_eq!(doc.nodes[0].group.as_deref(), Some("Core"));
        assert_eq!(doc.nodes[2].group.as_deref(), Some("Math"));
        assert_eq!(doc.nodes[2].kind, GraphNodeKind::NodePureFn);
    }

    #[test]
    fn position_only_patch_produces_zero_diff_and_same_fingerprint() {
        let mut doc = export_graph_ir(ALL_8_FIXTURE, None).expect("export");
        let fp_before = fallback_schema_fingerprint(ALL_8_FIXTURE);
        for (i, node) in doc.nodes.iter_mut().enumerate() {
            node.position = Some(NodeLayout {
                x: (i as f64) * 120.0,
                y: 80.0,
                collapsed: Some(i % 2 == 0),
            });
        }
        let res = apply_graph_document(ALL_8_FIXTURE, &doc).expect("apply");
        assert!(!res.source_modified);
        assert_eq!(res.source, ALL_8_FIXTURE);
        assert!(res.updated_nodes.is_empty());
        assert!(res.added_nodes.is_empty());
        assert!(res.removed_nodes.is_empty());
        assert_eq!(res.sidecar_updates.len(), doc.nodes.len());
        assert_eq!(fallback_schema_fingerprint(&res.source), fp_before);
    }

    #[test]
    fn group_only_patch_preserves_internal_comments_and_formatting() {
        let src = "module m;\n\n// header comment\ncomponent Hero {\n    // keep this inner comment!\n    hp:   f32 = 100.0,\n}\n";
        let mut doc = export_graph_ir(src, None).expect("export");
        doc.nodes[0].group = Some("Players".to_owned());
        let res = apply_graph_document(src, &doc).expect("apply");
        assert!(res.source_modified);
        assert!(res.source.contains("// header comment"));
        assert!(res.source.contains("// keep this inner comment!"));
        assert!(res.source.contains("hp:   f32 = 100.0,"));
        assert!(res.source.contains("@node_group(\"Players\")"));

        // Now remove the group via delta and verify comment/formatting still preserved.
        let mut doc2 = export_graph_ir(&res.source, None).expect("re-export");
        doc2.nodes[0].group = None;
        let res2 = apply_graph_document(&res.source, &doc2).expect("apply remove group");
        assert_eq!(res2.source, src);
    }
}
