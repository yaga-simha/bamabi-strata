//! Direct `StrataMir` -> Cranelift PIC native object emitter (`.o`).
//!
//! Lowers [`MirModule`] components, resources, relations, tables, curves, helpers,
//! reactive observers, ECS systems, synthesized spatial/state-machine ticks, and schema
//! migrations directly from [`MirFunction::blocks`] SSA CFGs into position-independent
//! machine code targeting ABI `0.3.0`.
//!
//! Zero dependencies on `strata_codegen::expr::*`, zero BSS mutable globals (per-world
//! heap state allocated via `calloc` in `bamabi_init` and released via `free` in
//! `bamabi_shutdown`), and strength-reduced dense column pointer iteration inside hot row loops.

use crate::abi_offsets::{
    ACCESS_MODE_CHANGED, BAM_COMPONENT_INVALID, BAM_EVENT_KIND_ADD, BAM_EVENT_KIND_CUSTOM,
    BAM_EVENT_KIND_DESPAWN, BAM_EVENT_KIND_INSERT, BAM_EVENT_KIND_READY, BAM_EVENT_KIND_REMOVE,
    BAM_SYSTEM_SET_INVALID, FFI_ENTITY_NULL, FFI_OK, FFI_TYPE_MISMATCH, QUERY_FLAG_PARAM_SET,
    QUERY_TERM_CAP, RELATION_FLAG_ACYCLIC, RELATION_FLAG_CASCADE_DESPAWN,
    RELATION_FLAG_CLEANUP_REMOVE, RELATION_FLAG_EXCLUSIVE, RELATION_FLAG_SYMMETRIC,
    SCHEDULE_SET_FLAG_PARALLEL, SCHEDULE_SET_FLAG_SEQUENCE, SCHEDULE_SET_FLAG_SEQUENCE_WEAK,
    SYSTEM_QUERY_CAP, TRIGGER_FLAG_PROPAGATE, WIRE_ABI_VERSION, api_slots, structs,
};
use crate::{JitCompileOptions, JitError, JitOptLevel};
use bamabi_sys::{
    AccessMode, BAM_COMPONENT_FLAG_SPARSE_SET, BAM_REQUIRED_FLAG_CUSTOM_BYTES,
    BamRequiredComponent, ComponentDesc, ScheduleId, fnv1a_64_str,
};
use cranelift_codegen::ir::condcodes::{FloatCC, IntCC};
use cranelift_codegen::ir::{
    AbiParam, Block, BlockArg, InstBuilder, MemFlagsData, Signature, StackSlot, StackSlotData,
    StackSlotKind, Type, Value, types,
};
use cranelift_codegen::isa::{CallConv, TargetFrontendConfig};
use cranelift_codegen::settings::{self, Configurable};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Switch, Variable};
use cranelift_module::{DataDescription, DataId, FuncId, Linkage, Module};
use cranelift_object::{ObjectBuilder, ObjectModule};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use strata_codegen::net::{
    FLAG_IS_PREDICTED, FLAG_IS_RELIABLE, FLAG_IS_RESOURCE, PACKET_KIND_COMPONENT_DELTA,
    PACKET_KIND_RESOURCE_DELTA, STRATA_NET_MAX_PAYLOAD_BYTES, STRATA_NET_PACKET_CANONICAL_NAME,
    STRATA_NET_PACKET_MAGIC, STRATA_NET_PACKET_SCHEMA_FINGERPRINT, STRATA_NET_PACKET_SIZE,
    STRATA_NET_RX_BATCH_CAP, STRATA_NET_WIRE_VERSION, has_net_protocol, packet_offsets,
    validate_net_packet_capacity,
};
use strata_mir::{
    Inst, LocalId, MirConstVal, MirFnKind, MirFunction, MirModule, MirNetComponent, MirStmt,
    MirStreamOpKind, MirType, Terminator,
};
use strata_sema::access::TermAccessMode;
use strata_sema::hir::{
    AuthorityKind, HirBinOp, HirCall, HirCompInit, HirConst, HirCurve, HirExpr, HirParamKind,
    HirRelation, HirScheduleGroup, HirSpatialIndex, HirTable, HirUnOp, NetReliability,
};
use strata_sema::layout::{
    EnumDef, SchemaItemKind, SolvedField, SolvedLayout, compute_wire_identity,
};
use strata_sema::types::Ty;
use target_lexicon::Triple;

mod fn_lower;
mod init;
mod inst;
mod net;
mod rodata;
mod spatial;
#[cfg(test)]
mod tests;

use fn_lower::*;
use init::*;
use net::*;
use rodata::*;

/// `BAM_STORAGE_FLAG_RESOURCE` bit matching `bamabi_sys::iter`.
const STORAGE_FLAG_RESOURCE: u32 = bamabi_sys::BAM_STORAGE_FLAG_RESOURCE;
/// `BAM_STORAGE_FLAG_MESSAGE` bit matching `bamabi_sys::iter`.
const STORAGE_FLAG_MESSAGE: u32 = bamabi_sys::BAM_STORAGE_FLAG_MESSAGE;

/// Programmatic `ComponentDesc` / `BamRequiredComponent` field offsets from `bamabi_sys`.
const COMP_REQUIRED_INIT_DESCS_OFF: usize =
    core::mem::offset_of!(ComponentDesc, required_init_descs);
const COMP_REQUIRED_INIT_DESC_COUNT_OFF: usize =
    core::mem::offset_of!(ComponentDesc, required_init_desc_count);
const REQ_COMP_DESC_SIZE: usize = core::mem::size_of::<BamRequiredComponent>();
const REQ_COMP_STRUCT_SIZE_OFF: usize = core::mem::offset_of!(BamRequiredComponent, struct_size);
const REQ_COMP_FLAGS_OFF: usize = core::mem::offset_of!(BamRequiredComponent, flags);
const REQ_COMP_COMPONENT_OFF: usize = core::mem::offset_of!(BamRequiredComponent, component);
const REQ_COMP_INIT_BYTES_OFF: usize = core::mem::offset_of!(BamRequiredComponent, init_bytes);
const REQ_COMP_INIT_SIZE_OFF: usize = core::mem::offset_of!(BamRequiredComponent, init_size);

/// Maximum spatial broadphase candidate entities returned on stack per query.
const MAX_SPATIAL_CANDIDATES: usize = 64;

/// In-memory relocatable PIC object bytes and symbol list produced before platform linking.
pub struct PicObjectArtifact {
    /// Target triple string embedded in the ELF/Mach-O/COFF object.
    pub target_triple: String,
    /// Raw relocatable object file bytes.
    pub object_bytes: Vec<u8>,
    /// Exported ABI symbol names present in the object.
    pub exported_symbols: Vec<String>,
}

#[derive(Clone)]
struct LayoutMetaData {
    is_ecs_component: bool,
    is_resource: bool,
    is_stream: bool,
    size: usize,
    align: usize,
    required_indices: Vec<usize>,
    name_cstr_id: DataId,
    comp_desc_id: DataId,
    default_blob_id: Option<DataId>,
    mod_res_offset: usize,
    mod_res_shadow_offset: usize,
}

#[derive(Clone)]
struct RelationMetaData {
    payload_size: usize,
    desc_id: DataId,
}

#[derive(Clone)]
struct SpatialIndexMeta {
    name: String,
    canonical_name: String,
    frames: usize,
    cols: usize,
    rows: usize,
    cell_count: usize,
    capacity: usize,
    inv_cell_size: f32,
    bounds_min: [f32; 2],
    plane_axes: [u8; 2],
    cursor_offset: usize,
    write_cursors_offset: usize,
    ring_offset: usize,
    offsets_off: usize,
    entities_off: usize,
    positions_off: usize,
    slot_bytes: usize,
}

#[derive(Clone)]
struct TableRodata {
    data_id: DataId,
    row_count: usize,
    row_stride: usize,
    fields: HashMap<String, (usize, MirType)>,
}

#[derive(Clone)]
struct CurveRodata {
    data_id: DataId,
    points_len: usize,
}

#[derive(Clone)]
struct StateLayout {
    api_off: usize,
    host_ctx_off: usize,
    comp_off: usize,
    res_flags_off: usize,
    rel_off: usize,
    obj_off: usize,
    sys_off: usize,
    set_off: usize,
    net_pkt_comp_off: usize,
    net_pkt_is_msg_off: usize,
    net_rx_buf_off: usize,
    total_bytes: usize,
}

impl StateLayout {
    fn compute(
        ptr_bytes: usize,
        layouts: &mut [LayoutMetaData],
        rel_count: usize,
        obj_count: usize,
        sys_count: usize,
        set_count: usize,
        spatial_indices: &[HirSpatialIndex],
    ) -> (Self, Vec<SpatialIndexMeta>) {
        let mut cursor = 0usize;
        let api_off = cursor;
        cursor += ptr_bytes;
        let host_ctx_off = cursor;
        cursor += ptr_bytes;

        cursor = align_up(cursor, 4);
        let comp_off = cursor;
        cursor += layouts.len().max(1) * structs::BAM_COMPONENT_SIZE;

        let res_flags_off = cursor;
        cursor += layouts.len().max(1);
        cursor = align_up(cursor, 8);

        for l in layouts.iter_mut() {
            if l.is_resource || l.is_stream {
                let sz = l.size.max(8);
                cursor = align_up(cursor, l.align.max(8));
                l.mod_res_offset = cursor;
                cursor += sz;
                if l.is_resource && l.size > 0 {
                    cursor = align_up(cursor, l.align.max(8));
                    l.mod_res_shadow_offset = cursor;
                    cursor += sz;
                }
            }
        }

        cursor = align_up(cursor, 4);
        let rel_off = cursor;
        cursor += rel_count.max(1) * structs::BAM_COMPONENT_SIZE;

        cursor = align_up(cursor, 8);
        let obj_off = cursor;
        cursor += obj_count.max(1) * structs::FFI_ENTITY_SIZE;

        cursor = align_up(cursor, 4);
        let sys_off = cursor;
        cursor += sys_count.max(1) * structs::BAM_SYSTEM_SIZE;

        cursor = align_up(cursor, 4);
        let set_off = cursor;
        cursor += set_count.max(1) * structs::BAM_SYSTEM_SET_SIZE;

        cursor = align_up(cursor, 4);
        let net_pkt_comp_off = cursor;
        cursor += structs::BAM_COMPONENT_SIZE;
        let net_pkt_is_msg_off = cursor;
        cursor += 1;
        cursor = align_up(cursor, ptr_bytes);
        let net_rx_buf_off = cursor;
        cursor += ptr_bytes;

        cursor = align_up(cursor, 8);
        let mut spatial_metas = Vec::with_capacity(spatial_indices.len());
        for sp in spatial_indices {
            let ring_frames = (sp.frames as usize).max(1);
            let cols = (sp.cols as usize).max(1);
            let rows = (sp.rows as usize).max(1);
            let cell_count = cols * rows;
            let capacity = (sp.capacity as usize).max(1);
            let cell_size = if sp.cell_size.is_finite() && sp.cell_size > 0.0 {
                sp.cell_size
            } else {
                4.0
            };
            let inv_cell_size = 1.0_f32 / cell_size;

            // Head cursor (`u32`, padded to 8 bytes)
            cursor = align_up(cursor, 8);
            let cursor_offset = cursor;
            cursor += 8;

            // Reusable CSR pass-2 write cursors: `[u32; cell_count]`
            let write_cursors_offset = cursor;
            cursor += align_up(cell_count * 4, 8);

            // Per frame slot:
            //   count:         u32 @ 0  (8 bytes padded)
            //   cell_offsets:  [u32; cell_count + 1] @ offsets_off (= 8)
            //   entities:      [u64; capacity] @ entities_off
            //   positions:     [[f32; 4]; capacity] @ positions_off
            let offsets_off = 8usize;
            let entities_off = align_up(offsets_off + (cell_count + 1) * 4, 8);
            let positions_off = entities_off + capacity * 8;
            let slot_bytes = align_up(positions_off + capacity * 16, 8);

            let ring_offset = cursor;
            cursor += ring_frames * slot_bytes;
            spatial_metas.push(SpatialIndexMeta {
                name: sp.name.clone(),
                canonical_name: sp.resource_layout.canonical_name.clone(),
                frames: ring_frames,
                cols,
                rows,
                cell_count,
                capacity,
                inv_cell_size,
                bounds_min: sp.bounds_min,
                plane_axes: sp.plane_axes,
                cursor_offset,
                write_cursors_offset,
                ring_offset,
                offsets_off,
                entities_off,
                positions_off,
                slot_bytes,
            });
        }

        let total_bytes = align_up(cursor.max(ptr_bytes), 8);
        (
            Self {
                api_off,
                host_ctx_off,
                comp_off,
                res_flags_off,
                rel_off,
                obj_off,
                sys_off,
                set_off,
                net_pkt_comp_off,
                net_pkt_is_msg_off,
                net_rx_buf_off,
                total_bytes,
            },
            spatial_metas,
        )
    }

    fn comp_slot_offset(&self, layout_idx: usize) -> usize {
        self.comp_off + layout_idx * structs::BAM_COMPONENT_SIZE
    }

    fn res_flag_offset(&self, layout_idx: usize) -> usize {
        self.res_flags_off + layout_idx
    }

    fn rel_slot_offset(&self, rel_idx: usize) -> usize {
        self.rel_off + rel_idx * structs::BAM_COMPONENT_SIZE
    }

    fn obj_slot_offset(&self, obj_idx: usize) -> usize {
        self.obj_off + obj_idx * structs::FFI_ENTITY_SIZE
    }

    fn sys_slot_offset(&self, sys_idx: usize) -> usize {
        self.sys_off + sys_idx * structs::BAM_SYSTEM_SIZE
    }

    fn set_slot_offset(&self, set_idx: usize) -> usize {
        self.set_off + set_idx * structs::BAM_SYSTEM_SET_SIZE
    }
}

/// Flattened deduplicated ECS query wire descriptor attached to a `BamSystemDesc`.
#[derive(Clone)]
struct WireTermSpec {
    layout_idx: usize,
    mode: TermAccessMode,
    changed: bool,
}

#[derive(Clone)]
struct WireQuerySpec {
    terms: Vec<WireTermSpec>,
    /// Maps `(original_term_idx) -> wire_term_idx`.
    term_map: Vec<usize>,
    with_filters: Vec<usize>,
    without_filters: Vec<usize>,
    extra_changed_filters: Vec<usize>,
    /// Mutually exclusive `ParamSet` group (`0` = independent; `1, 2, ...` = connected component).
    param_set_group: u32,
}

#[derive(Clone)]
struct ExtraObjQuery {
    obj_idx: usize,
    wire_query_idx: usize,
}

#[derive(Clone)]
struct StreamQuerySlot {
    stream_layout_idx: usize,
    is_write: bool,
}

#[derive(Clone)]
struct NetSystemChunkEntry {
    rx_func_id: FuncId,
    tx_func_id: FuncId,
    rx_name_data_id: DataId,
    tx_name_data_id: DataId,
    res_layout_indices: Vec<usize>,
    comp_layout_indices: Vec<usize>,
    tx_after_weak_names: Vec<DataId>,
}

#[derive(Clone)]
struct SystemRegistrationEntry {
    fn_idx: usize,
    func_id: FuncId,
    name_data_id: DataId,
    schedule_id: u32,
    wire_queries: Vec<WireQuerySpec>,
    resource_queries: Vec<(usize, bool, usize)>,
    extra_obj_queries: Vec<ExtraObjQuery>,
    stream_queries: Vec<StreamQuerySlot>,
    after_names: Vec<DataId>,
    after_weak_names: Vec<DataId>,
    before_names: Vec<DataId>,
    in_set_names: Vec<DataId>,
    mount_set_indices: Vec<usize>,
    sched_order: usize,
    run_if_guard: Option<(HirExpr, usize)>,
}

#[derive(Clone)]
struct ObserverRegistrationEntry {
    event_layout_idx: Option<usize>,
    event_kind: u32,
    watched_layout_idx: Option<usize>,
    sys_entry: SystemRegistrationEntry,
}

#[derive(Clone)]
struct ScheduleSetEntry {
    qualified_name_cstr: DataId,
    schedule_id: u32,
    flags: u32,
    before_set_indices: Vec<usize>,
    after_set_indices: Vec<usize>,
}

struct ModuleContext<'a> {
    mir: &'a MirModule,
    obj_mod: ObjectModule,
    triple: Triple,
    ptr_ty: Type,
    ptr_bytes: usize,
    call_conv: CallConv,
    fe_cfg: TargetFrontendConfig,
    /// Topologically sorted layout table.
    layouts: Vec<LayoutMetaData>,
    mir_layouts_sorted: Vec<SolvedLayout>,
    layout_map: HashMap<String, usize>,
    relations: Vec<RelationMetaData>,
    relation_map: HashMap<String, usize>,
    enums_by_name: HashMap<String, EnumDef>,
    consts_by_name: HashMap<String, HirConst>,
    tables: HashMap<String, TableRodata>,
    curves: HashMap<String, CurveRodata>,
    spatial_metas: Vec<SpatialIndexMeta>,
    state_layout: StateLayout,
    string_cache: HashMap<String, DataId>,
    cstring_cache: HashMap<String, DataId>,
    extern_funcs: HashMap<String, FuncId>,
    round_fn: FuncId,
    fix64_div_fn: FuncId,
    helper_funcs: HashMap<String, (FuncId, usize)>,
    migrations_by_layout: HashMap<usize, FuncId>,
    systems: Vec<SystemRegistrationEntry>,
    observers: Vec<ObserverRegistrationEntry>,
    schedule_sets: Vec<ScheduleSetEntry>,
    init_objects_fn: Option<(FuncId, DataId, Vec<(usize, usize)>)>,
    net_chunks: Vec<Vec<MirNetComponent>>,
    net_systems: Vec<NetSystemChunkEntry>,
}

/// Compiles a verified `MirModule` directly from MIR CFGs into a native PIC `.o` artifact.
pub fn emit_pic_object(
    mir: &MirModule,
    opts: &JitCompileOptions,
) -> Result<PicObjectArtifact, JitError> {
    emit_pic_object_for_triple(mir, opts, Triple::host())
}

pub(crate) fn emit_pic_object_for_triple(
    mir: &MirModule,
    opts: &JitCompileOptions,
    triple: Triple,
) -> Result<PicObjectArtifact, JitError> {
    validate_net_packet_capacity(mir).map_err(|e| JitError::Codegen(e.to_string()))?;

    let mut flag_builder = settings::builder();
    flag_builder
        .set("is_pic", "true")
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let opt_str = match opts.opt_level {
        JitOptLevel::FastCompile => "none",
        JitOptLevel::Speed => "speed",
    };
    flag_builder
        .set("opt_level", opt_str)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let isa_builder = cranelift_codegen::isa::lookup(triple.clone())
        .map_err(|e| JitError::IsaConfig(format!("native ISA lookup failed: {e}")))?;
    let isa = isa_builder
        .finish(settings::Flags::new(flag_builder))
        .map_err(|e| JitError::IsaConfig(e.to_string()))?;

    let fe_cfg = isa.frontend_config();
    let call_conv = isa.default_call_conv();
    let ptr_ty = Type::triple_pointer_type(&triple);
    let ptr_bytes = usize::from(fe_cfg.pointer_bytes());

    let obj_builder = ObjectBuilder::new(
        isa,
        "strata_jit_module",
        cranelift_module::default_libcall_names(),
    )
    .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut obj_mod = ObjectModule::new(obj_builder);

    let mod_stem = if mir.module_path.is_empty() {
        "strata_mod".to_owned()
    } else {
        mir.module_path.clone()
    };
    let mod_name_id = define_cstring_on(&mut obj_mod, "STRATA_MOD_NAME", &mod_stem)?;
    let mod_ver_id = define_cstring_on(&mut obj_mod, "STRATA_MOD_VERSION", "0.3.0")?;
    let manifest_data_id = define_manifest_data(&mut obj_mod, mod_name_id, mod_ver_id, ptr_ty)?;

    let mut ctx = build_module_context(mir, obj_mod, triple, ptr_ty, ptr_bytes, call_conv, fe_cfg)?;

    // 0. Emit internal `__strata_fix64_div` restoring division helper.
    emit_fix64_div_helper(&mut ctx)?;

    // 1. Emit helper functions (`mir.fns`).
    emit_all_helpers(&mut ctx)?;

    // 2. Emit migrations (`MirFnKind::Migration`).
    emit_all_migrations(&mut ctx)?;

    // 3. Emit reactive observers (`MirFnKind::Observer`).
    emit_all_observers(&mut ctx)?;

    // 4. Emit ECS systems & synthesized functions (`mir.functions`) + schedule `run_if_ctx`.
    emit_all_systems(&mut ctx)?;

    // 4b. Emit synthesized networking TX/RX systems (`strata_sys_net_rx_*` / `strata_sys_net_tx_*`).
    emit_all_net_systems(&mut ctx)?;

    // 5. Emit Startup named-object initializer if `mir.objects` is non-empty.
    emit_startup_object_initializer(&mut ctx)?;

    // 6. Emit ABI exports: `bamabi_manifest`, `bamabi_init`, `bamabi_shutdown`.
    emit_bamabi_manifest(&mut ctx, manifest_data_id)?;
    emit_bamabi_shutdown(&mut ctx)?;
    emit_bamabi_init(&mut ctx)?;

    let product = ctx.obj_mod.finish();
    let object_bytes = product
        .emit()
        .map_err(|e| JitError::Codegen(format!("object emission failed: {e}")))?;

    Ok(PicObjectArtifact {
        target_triple: ctx.triple.to_string(),
        object_bytes,
        exported_symbols: vec![
            "bamabi_manifest".to_owned(),
            "bamabi_init".to_owned(),
            "bamabi_shutdown".to_owned(),
        ],
    })
}

fn align_up(val: usize, align: usize) -> usize {
    let a = align.max(1);
    val.div_ceil(a) * a
}

fn sanitize_ident(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "_".to_owned()
    } else if out.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        format!("_{out}")
    } else {
        out
    }
}

fn is_ecs_component_kind(kind: SchemaItemKind) -> bool {
    matches!(
        kind,
        SchemaItemKind::Component
            | SchemaItemKind::SoaHot
            | SchemaItemKind::SoaCold
            | SchemaItemKind::Event
            | SchemaItemKind::Stream
            | SchemaItemKind::Timeline
            | SchemaItemKind::TaskState
            | SchemaItemKind::FsmState
    )
}

fn schedule_id_for(label: &str) -> u32 {
    match label {
        "Startup" => ScheduleId::STARTUP.0,
        "PreUpdate" => ScheduleId::PRE_UPDATE.0,
        "PostUpdate" => ScheduleId::POST_UPDATE.0,
        "FixedUpdate" => ScheduleId::FIXED_UPDATE.0,
        "Last" => ScheduleId::LAST.0,
        _ => ScheduleId::UPDATE.0,
    }
}

fn access_mode_u32(mode: TermAccessMode) -> u32 {
    match mode {
        TermAccessMode::Read => AccessMode::READ.0,
        TermAccessMode::Write | TermAccessMode::SelectiveWrite => AccessMode::WRITE.0,
        TermAccessMode::OptionalRead => AccessMode::OPTIONAL_READ.0,
        TermAccessMode::OptionalWrite => AccessMode::OPTIONAL_WRITE.0,
        TermAccessMode::With => AccessMode::FILTER_ONLY.0,
        TermAccessMode::Without => AccessMode::WITHOUT.0,
        TermAccessMode::Allow => AccessMode::ALLOW.0,
        TermAccessMode::Has => AccessMode::HAS.0,
        TermAccessMode::RemovedRead => AccessMode::REMOVED_READ.0,
        TermAccessMode::ResRead => AccessMode::RESOURCE_READ.0,
        TermAccessMode::ResWrite => AccessMode::RESOURCE_WRITE.0,
        TermAccessMode::StreamRead => AccessMode::MESSAGE_READ.0,
        TermAccessMode::StreamWrite => AccessMode::MESSAGE_WRITE.0,
    }
}

fn merge_access_mode(a: TermAccessMode, b: TermAccessMode) -> TermAccessMode {
    if a == TermAccessMode::Write
        || b == TermAccessMode::Write
        || a == TermAccessMode::SelectiveWrite
        || b == TermAccessMode::SelectiveWrite
    {
        TermAccessMode::Write
    } else if a == TermAccessMode::OptionalWrite || b == TermAccessMode::OptionalWrite {
        TermAccessMode::OptionalWrite
    } else if a == TermAccessMode::Read || b == TermAccessMode::Read {
        TermAccessMode::Read
    } else {
        a
    }
}

fn bare_schedule_target(name: &str) -> &str {
    if name.starts_with("host::") {
        name
    } else {
        name.rsplit("::").next().unwrap_or(name)
    }
}

fn lookup_name_ref<'a, T>(map: &'a HashMap<String, T>, key: &str) -> Option<&'a T> {
    if let Some(val) = map.get(key) {
        return Some(val);
    }
    let normalized = key.replace("::", "__");
    if let Some(val) = map.get(&normalized) {
        return Some(val);
    }
    if let Some(short) = key.rsplit("::").next()
        && let Some(val) = map.get(short)
    {
        return Some(val);
    }
    None
}

fn lookup_name_in_map(map: &HashMap<String, usize>, key: &str) -> Option<usize> {
    lookup_name_ref(map, key).copied()
}

fn register_layout_aliases(map: &mut HashMap<String, usize>, canonical: &str, idx: usize) {
    map.entry(canonical.to_owned()).or_insert(idx);
    if let Some(short) = canonical.rsplit("::").next() {
        map.entry(short.to_owned()).or_insert(idx);
        if let Some((base, stratum)) = short.split_once("__") {
            map.entry(format!("{base}::{stratum}")).or_insert(idx);
        }
    }
}

fn format_uuid_hex(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

fn collect_inst_referenced_comps(inst: &Inst, out: &mut BTreeSet<String>) {
    match inst {
        Inst::IterColRead { storage_key, .. }
        | Inst::IterColWrite { storage_key, .. }
        | Inst::IterColWriteUntracked { storage_key, .. }
        | Inst::IterColRowsRead { storage_key, .. }
        | Inst::IterColRowsWrite { storage_key, .. }
        | Inst::EntityGet { storage_key, .. }
        | Inst::EntityGetMut { storage_key, .. } => {
            out.insert(storage_key.clone());
        }
        Inst::ResRead { resource } | Inst::ResWrite { resource } => {
            out.insert(resource.clone());
        }
        Inst::CmdInsert { component, .. } | Inst::CmdRemove { component, .. } => {
            out.insert(component.clone());
        }
        Inst::CmdSpawn { components, .. }
        | Inst::CmdSpawnBatch { components, .. }
        | Inst::SpawnBatchPush { components, .. } => {
            for (c, _) in components {
                out.insert(c.clone());
            }
        }
        Inst::SpawnBatchBegin { components, .. } => {
            for c in components {
                out.insert(c.clone());
            }
        }
        Inst::CmdDespawnAll { filter } => {
            for tok in filter.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                let inner = tok
                    .strip_prefix("Without<")
                    .or_else(|| tok.strip_prefix("With<"))
                    .and_then(|r| r.strip_suffix('>'))
                    .unwrap_or(tok)
                    .trim();
                if !inner.is_empty() {
                    out.insert(inner.to_string());
                }
            }
        }
        Inst::CmdTrigger { event, .. } => {
            out.insert(event.clone());
        }
        Inst::StreamEmit { stream, .. } => {
            out.insert(stream.clone());
        }
        _ => {}
    }
}

fn collect_all_layouts_with_zst_tags(mir: &MirModule) -> Vec<SolvedLayout> {
    let mut layouts = mir.layouts.clone();
    let mut known: HashMap<String, usize> = HashMap::new();
    for (i, l) in layouts.iter().enumerate() {
        register_layout_aliases(&mut known, &l.canonical_name, i);
    }

    let mut extra_tags: BTreeSet<String> = BTreeSet::new();
    for l in &mir.layouts {
        for req in &l.required_components {
            extra_tags.insert(req.clone());
        }
    }
    for sp in &mir.spatial_indices {
        extra_tags.insert(sp.over_component.clone());
    }
    for obj in &mir.objects {
        for c in &obj.components {
            extra_tags.insert(c.clone());
        }
        for ci in &obj.inits {
            extra_tags.insert(
                ci.canonical_component
                    .clone()
                    .unwrap_or_else(|| ci.component.clone()),
            );
        }
    }
    for f in mir.functions.iter().chain(mir.fns.iter()) {
        for qb in &f.query_bindings {
            for t in &qb.terms {
                extra_tags.insert(t.canonical_component.clone());
                if !t.storage_key.is_empty() {
                    extra_tags.insert(t.storage_key.clone());
                }
            }
            for w in &qb.with_filters {
                extra_tags.insert(w.clone());
            }
            for wo in &qb.without_filters {
                extra_tags.insert(wo.clone());
            }
        }
        for r in &f.resources {
            extra_tags.insert(r.canonical_name.clone());
        }
        for op in &f.stream_ops {
            if !op.canonical_stream.is_empty() {
                extra_tags.insert(op.canonical_stream.clone());
            } else if !op.stream.is_empty() {
                extra_tags.insert(op.stream.clone());
            }
        }
        if let MirFnKind::Observer { event, target_comp } = &f.kind {
            extra_tags.insert(event.clone());
            if let Some(tc) = target_comp {
                extra_tags.insert(tc.clone());
            }
        }
        for bb in &f.blocks {
            for s in &bb.stmts {
                collect_inst_referenced_comps(&s.inst, &mut extra_tags);
            }
        }
    }

    for tag in extra_tags {
        let trimmed = tag.trim();
        if trimmed.is_empty() || lookup_name_in_map(&known, trimmed).is_some() {
            continue;
        }
        if let Some((prefix, _)) = trimmed.rsplit_once("::")
            && lookup_name_in_map(&known, prefix).is_some()
        {
            continue;
        }
        let canon = if trimmed.contains("::") || mir.module_path.is_empty() {
            trimmed.to_owned()
        } else {
            format!("{}::{trimmed}", mir.module_path)
        };
        if lookup_name_in_map(&known, &canon).is_some() {
            continue;
        }
        let (uuid, fp) = compute_wire_identity(&canon, 0, 1, 0, true, &[]);
        let uuid_bytes = *uuid.as_bytes();
        let idx = layouts.len();
        register_layout_aliases(&mut known, &canon, idx);
        layouts.push(SolvedLayout {
            canonical_name: canon,
            item_kind: SchemaItemKind::Component,
            fields: Vec::new(),
            size: 0,
            align: 1,
            is_abi_pod: true,
            component_flags: 0,
            uuid_bytes,
            uuid_hex: format_uuid_hex(&uuid_bytes),
            schema_fingerprint: fp,
            required_components: Vec::new(),
            explicit_pad_bytes: 0,
        });
    }

    topological_sort_layouts(&layouts)
}

fn topological_sort_layouts(layouts: &[SolvedLayout]) -> Vec<SolvedLayout> {
    let mut name_to_orig: HashMap<String, usize> = HashMap::new();
    for (i, l) in layouts.iter().enumerate() {
        register_layout_aliases(&mut name_to_orig, &l.canonical_name, i);
    }

    let mut visited = vec![false; layouts.len()];
    let mut visiting = vec![false; layouts.len()];
    let mut order = Vec::with_capacity(layouts.len());

    fn dfs(
        i: usize,
        layouts: &[SolvedLayout],
        map: &HashMap<String, usize>,
        visited: &mut [bool],
        visiting: &mut [bool],
        order: &mut Vec<usize>,
    ) {
        if visited[i] || visiting[i] {
            return;
        }
        visiting[i] = true;
        for req in &layouts[i].required_components {
            if let Some(dep_idx) = lookup_name_in_map(map, req) {
                dfs(dep_idx, layouts, map, visited, visiting, order);
            }
        }
        visiting[i] = false;
        visited[i] = true;
        order.push(i);
    }

    for i in 0..layouts.len() {
        dfs(
            i,
            layouts,
            &name_to_orig,
            &mut visited,
            &mut visiting,
            &mut order,
        );
    }
    order.into_iter().map(|i| layouts[i].clone()).collect()
}

fn build_module_context<'a>(
    mir: &'a MirModule,
    mut obj_mod: ObjectModule,
    triple: Triple,
    ptr_ty: Type,
    ptr_bytes: usize,
    call_conv: CallConv,
    fe_cfg: TargetFrontendConfig,
) -> Result<ModuleContext<'a>, JitError> {
    let mir_layouts_sorted = collect_all_layouts_with_zst_tags(mir);
    let mut layout_map = HashMap::new();
    for (i, l) in mir_layouts_sorted.iter().enumerate() {
        register_layout_aliases(&mut layout_map, &l.canonical_name, i);
    }

    let mut enums_by_name = HashMap::new();
    for e in &mir.enums {
        enums_by_name.insert(e.canonical_name.clone(), e.clone());
        if let Some(short) = e.canonical_name.rsplit("::").next() {
            enums_by_name
                .entry(short.to_owned())
                .or_insert_with(|| e.clone());
        }
    }

    let mut consts_by_name = HashMap::new();
    for c in &mir.consts {
        consts_by_name.insert(c.name.clone(), c.clone());
        if let Some(short) = c.name.rsplit("::").next() {
            consts_by_name
                .entry(short.to_owned())
                .or_insert_with(|| c.clone());
        }
    }

    let mut layouts = Vec::with_capacity(mir_layouts_sorted.len());
    for (idx, l) in mir_layouts_sorted.iter().enumerate() {
        let req_indices: Vec<usize> = l
            .required_components
            .iter()
            .filter_map(|r| lookup_name_in_map(&layout_map, r))
            .collect();
        let meta = define_layout_rodata(&mut obj_mod, idx, l, req_indices, mir, ptr_bytes)?;
        layouts.push(meta);
    }

    let mut relations = Vec::with_capacity(mir.relations.len());
    let mut relation_map = HashMap::new();
    for (ri, r) in mir.relations.iter().enumerate() {
        let rmeta = define_relation_rodata(&mut obj_mod, ri, r, ptr_bytes)?;
        relation_map.insert(r.canonical_name.clone(), ri);
        relation_map.insert(r.name.clone(), ri);
        relations.push(rmeta);
    }

    let mut tables = HashMap::new();
    for (ti, t) in mir.tables.iter().enumerate() {
        let tro = define_table_rodata(
            &mut obj_mod,
            ti,
            t,
            &enums_by_name,
            &consts_by_name,
            mir,
            ptr_bytes,
        )?;
        tables.insert(t.name.clone(), tro);
    }

    let mut curves = HashMap::new();
    for (ci, c) in mir.curves.iter().enumerate() {
        let cro = define_curve_rodata(&mut obj_mod, ci, c)?;
        curves.insert(c.name.clone(), cro);
    }

    let net_chunks = if has_net_protocol(mir) {
        chunk_replicated_net_components(mir, &layout_map)
    } else {
        Vec::new()
    };

    let mut sys_fn_count = 0usize;
    for f in &mir.functions {
        if !matches!(
            f.kind,
            MirFnKind::HelperFn | MirFnKind::Observer { .. } | MirFnKind::Migration { .. }
        ) {
            sys_fn_count += 1;
        }
    }
    if !mir.objects.is_empty() {
        sys_fn_count += 1;
    }
    sys_fn_count += net_chunks.len() * 2;

    let (schedule_sets, sys_sched_info) = extract_schedule_topology(&mut obj_mod, mir)?;

    let (state_layout, spatial_metas) = StateLayout::compute(
        ptr_bytes,
        &mut layouts,
        relations.len(),
        mir.objects.len(),
        sys_fn_count,
        schedule_sets.len(),
        &mir.spatial_indices,
    );

    let mut helper_funcs = HashMap::new();
    for (hi, hfn) in mir.fns.iter().enumerate() {
        let sym = format!("strata_fn_{hi}_{}", sanitize_ident(&hfn.name));
        let sig = build_helper_signature(hfn, ptr_ty, call_conv, &enums_by_name);
        let fid = obj_mod
            .declare_function(&sym, Linkage::Local, &sig)
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        helper_funcs.insert(hfn.name.clone(), (fid, hi));
        if let Some(short) = hfn.name.rsplit("::").next() {
            helper_funcs.entry(short.to_owned()).or_insert((fid, hi));
        }
    }

    let mut extern_funcs = HashMap::new();
    let round_fn = {
        let mut sig = Signature::new(call_conv);
        sig.params.push(AbiParam::new(types::F64));
        sig.returns.push(AbiParam::new(types::F64));
        let fid = obj_mod
            .declare_function("round", Linkage::Import, &sig)
            .map_err(|e| JitError::Codegen(format!("extern `round`: {e}")))?;
        extern_funcs.insert("round".to_owned(), fid);
        fid
    };
    let fix64_div_fn = {
        let mut sig = Signature::new(call_conv);
        sig.params.push(AbiParam::new(types::I64));
        sig.params.push(AbiParam::new(types::I64));
        sig.returns.push(AbiParam::new(types::I64));
        obj_mod
            .declare_function("__strata_fix64_div", Linkage::Local, &sig)
            .map_err(|e| JitError::Codegen(format!("local `__strata_fix64_div`: {e}")))?
    };

    let mut ctx = ModuleContext {
        mir,
        obj_mod,
        triple,
        ptr_ty,
        ptr_bytes,
        call_conv,
        fe_cfg,
        layouts,
        mir_layouts_sorted,
        layout_map,
        relations,
        relation_map,
        enums_by_name,
        consts_by_name,
        tables,
        curves,
        spatial_metas,
        state_layout,
        string_cache: HashMap::new(),
        cstring_cache: HashMap::new(),
        extern_funcs,
        round_fn,
        fix64_div_fn,
        helper_funcs,
        migrations_by_layout: HashMap::new(),
        systems: Vec::new(),
        observers: Vec::new(),
        schedule_sets,
        init_objects_fn: None,
        net_chunks,
        net_systems: Vec::new(),
    };

    // Build schedule system descriptors + observers.
    for (fi, f) in mir.functions.iter().enumerate() {
        match &f.kind {
            MirFnKind::HelperFn => {}
            MirFnKind::Migration { component, .. } => {
                let sym = format!("strata_mig_{fi}_{}", sanitize_ident(&f.name));
                let mut sig = Signature::new(call_conv);
                sig.params.push(AbiParam::new(ptr_ty)); // src_row
                sig.params.push(AbiParam::new(ptr_ty)); // dst_row
                sig.params.push(AbiParam::new(ptr_ty)); // user_data (state_ptr)
                sig.returns.push(AbiParam::new(types::I32));
                let fid = ctx
                    .obj_mod
                    .declare_function(&sym, Linkage::Local, &sig)
                    .map_err(|e| JitError::Codegen(e.to_string()))?;
                if let Some(lidx) = lookup_name_in_map(&ctx.layout_map, component) {
                    ctx.migrations_by_layout.insert(lidx, fid);
                }
            }
            MirFnKind::Observer { event, target_comp } => {
                let sym = format!("strata_obs_{fi}_{}", sanitize_ident(&f.name));
                let mut sig = Signature::new(call_conv);
                sig.params.push(AbiParam::new(types::I64)); // entity
                sig.params.push(AbiParam::new(ptr_ty)); // event_data
                sig.params.push(AbiParam::new(ptr_ty)); // sys_ctx
                sig.params.push(AbiParam::new(ptr_ty)); // user_data (state_ptr)
                sig.returns.push(AbiParam::new(types::I32));
                let fid = ctx
                    .obj_mod
                    .declare_function(&sym, Linkage::Local, &sig)
                    .map_err(|e| JitError::Codegen(e.to_string()))?;
                let (event_kind, event_layout_idx) =
                    classify_observer_event(&ctx.layout_map, event);
                let watched_layout_idx = target_comp
                    .as_deref()
                    .and_then(|tc| lookup_name_in_map(&ctx.layout_map, tc));
                let sys_entry =
                    build_system_registration_entry(&mut ctx, fi, f, fid, &sys_sched_info)?;
                ctx.observers.push(ObserverRegistrationEntry {
                    event_layout_idx,
                    event_kind,
                    watched_layout_idx,
                    sys_entry,
                });
            }
            MirFnKind::System
            | MirFnKind::SynthesizedTimeline
            | MirFnKind::SynthesizedTask
            | MirFnKind::SynthesizedFsm
            | MirFnKind::SynthesizedSpatialCsr
            | MirFnKind::SynthesizedTimerTick => {
                let sym = format!("strata_sys_{fi}_{}", sanitize_ident(&f.name));
                let mut sig = Signature::new(call_conv);
                sig.params.push(AbiParam::new(ptr_ty)); // sys_ctx
                sig.params.push(AbiParam::new(ptr_ty)); // user_data (state_ptr)
                sig.returns.push(AbiParam::new(types::I32));
                let fid = ctx
                    .obj_mod
                    .declare_function(&sym, Linkage::Local, &sig)
                    .map_err(|e| JitError::Codegen(e.to_string()))?;
                let entry = build_system_registration_entry(&mut ctx, fi, f, fid, &sys_sched_info)?;
                ctx.systems.push(entry);
            }
        }
    }

    if !ctx.net_chunks.is_empty() {
        let mut rx_cstrs = Vec::with_capacity(ctx.net_chunks.len());
        let mut tx_cstrs = Vec::with_capacity(ctx.net_chunks.len());
        for chunk_idx in 0..ctx.net_chunks.len() {
            rx_cstrs.push(ctx.intern_cstr(&format!("__strata_net_rx_{chunk_idx}"))?);
            tx_cstrs.push(ctx.intern_cstr(&format!("__strata_net_tx_{chunk_idx}"))?);
        }

        let mut fixed_user_names = Vec::new();
        for sys in &mut ctx.systems {
            if sys.schedule_id == ScheduleId::FIXED_UPDATE.0 {
                fixed_user_names.push(sys.name_data_id);
                for &rx_cstr in &rx_cstrs {
                    if !sys.after_weak_names.contains(&rx_cstr) {
                        sys.after_weak_names.push(rx_cstr);
                    }
                }
            }
        }

        let chunks_cloned = ctx.net_chunks.clone();
        for (chunk_idx, chunk) in chunks_cloned.iter().enumerate() {
            let rx_sym = format!("strata_sys_net_rx_{chunk_idx}");
            let tx_sym = format!("strata_sys_net_tx_{chunk_idx}");
            let mut sig = Signature::new(call_conv);
            sig.params.push(AbiParam::new(ptr_ty)); // sys_ctx
            sig.params.push(AbiParam::new(ptr_ty)); // user_data (state_ptr)
            sig.returns.push(AbiParam::new(types::I32));
            let rx_func_id = ctx
                .obj_mod
                .declare_function(&rx_sym, Linkage::Local, &sig)
                .map_err(|e| JitError::Codegen(e.to_string()))?;
            let tx_func_id = ctx
                .obj_mod
                .declare_function(&tx_sym, Linkage::Local, &sig)
                .map_err(|e| JitError::Codegen(e.to_string()))?;

            let mut res_layout_indices = Vec::new();
            let mut comp_layout_indices = Vec::new();
            for nc in chunk {
                if let Some(lidx) = lookup_name_in_map(&ctx.layout_map, &nc.canonical_name) {
                    if nc.is_resource {
                        res_layout_indices.push(lidx);
                    } else {
                        comp_layout_indices.push(lidx);
                    }
                }
            }
            let mut tx_after_weak_names = fixed_user_names.clone();
            for &rx_cstr in &rx_cstrs {
                if !tx_after_weak_names.contains(&rx_cstr) {
                    tx_after_weak_names.push(rx_cstr);
                }
            }
            ctx.net_systems.push(NetSystemChunkEntry {
                rx_func_id,
                tx_func_id,
                rx_name_data_id: rx_cstrs[chunk_idx],
                tx_name_data_id: tx_cstrs[chunk_idx],
                res_layout_indices,
                comp_layout_indices,
                tx_after_weak_names,
            });
        }
    }

    Ok(ctx)
}

fn chunk_replicated_net_components(
    mir: &MirModule,
    layout_map: &HashMap<String, usize>,
) -> Vec<Vec<MirNetComponent>> {
    let max_ecs_per_sys = SYSTEM_QUERY_CAP.saturating_sub(1).max(1);
    let max_res_per_sys = QUERY_TERM_CAP.saturating_sub(1).max(1);
    let mut chunks: Vec<Vec<MirNetComponent>> = Vec::new();
    let mut cur: Vec<MirNetComponent> = Vec::new();
    let mut cur_ecs = 0usize;
    let mut cur_res = 0usize;

    for nc in &mir.net_components {
        if !nc.is_replicated || lookup_name_in_map(layout_map, &nc.canonical_name).is_none() {
            continue;
        }
        let need_new = if nc.is_resource {
            cur_res >= max_res_per_sys
        } else {
            cur_ecs >= max_ecs_per_sys
        };
        if need_new && !cur.is_empty() {
            chunks.push(cur);
            cur = Vec::new();
            cur_ecs = 0;
            cur_res = 0;
        }
        if nc.is_resource {
            cur_res += 1;
        } else {
            cur_ecs += 1;
        }
        cur.push(nc.clone());
    }
    if !cur.is_empty() {
        chunks.push(cur);
    }
    chunks
}

fn classify_observer_event(
    layout_map: &HashMap<String, usize>,
    event: &str,
) -> (u32, Option<usize>) {
    let short = event.rsplit("::").next().unwrap_or(event);
    match short {
        "OnAdd" | "ADD" => (BAM_EVENT_KIND_ADD, None),
        "OnInsert" | "INSERT" => (BAM_EVENT_KIND_INSERT, None),
        "OnRemove" | "REMOVE" => (BAM_EVENT_KIND_REMOVE, None),
        "OnDespawn" | "DESPAWN" => (BAM_EVENT_KIND_DESPAWN, None),
        "Ready" | "READY" => (BAM_EVENT_KIND_READY, None),
        _ => (BAM_EVENT_KIND_CUSTOM, lookup_name_in_map(layout_map, event)),
    }
}

#[derive(Clone)]
struct SysSchedTopology {
    schedule_id: u32,
    after: Vec<String>,
    after_weak: Vec<String>,
    before: Vec<String>,
    in_sets: Vec<String>,
    mount_set_indices: Vec<usize>,
    sched_order: usize,
    run_if_expr: Option<HirExpr>,
}

impl Default for SysSchedTopology {
    fn default() -> Self {
        Self {
            schedule_id: 0,
            after: Vec::new(),
            after_weak: Vec::new(),
            before: Vec::new(),
            in_sets: Vec::new(),
            mount_set_indices: Vec::new(),
            sched_order: usize::MAX,
            run_if_expr: None,
        }
    }
}

fn extract_schedule_topology(
    obj_mod: &mut ObjectModule,
    mir: &MirModule,
) -> Result<(Vec<ScheduleSetEntry>, HashMap<String, SysSchedTopology>), JitError> {
    let mut sets: Vec<ScheduleSetEntry> = Vec::new();
    let mut set_index_map: HashMap<(u32, String), usize> = HashMap::new();
    let mut sys_map: HashMap<String, SysSchedTopology> = HashMap::new();

    #[allow(clippy::too_many_arguments)]
    fn walk_group(
        obj_mod: &mut ObjectModule,
        sched_id: u32,
        run_if_expr: Option<&HirExpr>,
        group: &HirScheduleGroup,
        parent_sets: &[(usize, String)],
        sets: &mut Vec<ScheduleSetEntry>,
        set_index_map: &mut HashMap<(u32, String), usize>,
        sys_map: &mut HashMap<String, SysSchedTopology>,
        seq_counter: &mut usize,
        leaf_order: &mut usize,
    ) -> Result<(Vec<String>, Option<usize>), JitError> {
        if group.kind == "leaf" && !group.name.is_empty() {
            let bare_leaf = bare_schedule_target(&group.name).to_owned();
            let entry = sys_map.entry(bare_leaf.clone()).or_default();
            entry.schedule_id = sched_id;
            if entry.sched_order == usize::MAX {
                entry.sched_order = *leaf_order;
                *leaf_order += 1;
            }
            if entry.run_if_expr.is_none() {
                entry.run_if_expr = run_if_expr.cloned();
            }
            for (_, bare_set_name) in parent_sets {
                if !entry.in_sets.contains(bare_set_name) {
                    entry.in_sets.push(bare_set_name.clone());
                }
            }
            if let Some(&(set_idx, _)) = parent_sets.last()
                && !entry.mount_set_indices.contains(&set_idx)
            {
                entry.mount_set_indices.push(set_idx);
            }
            return Ok((vec![bare_leaf], None));
        }

        let mut next_parent_sets = parent_sets.to_vec();
        let mut own_set_idx = None;
        if matches!(group.kind.as_str(), "set" | "seq" | "seq_weak" | "par") {
            let raw_name = if group.name.is_empty() {
                *seq_counter += 1;
                format!("__group_{seq_counter}")
            } else {
                group.name.clone()
            };
            let bare = bare_schedule_target(&raw_name).to_owned();
            let key = (sched_id, bare.clone());
            let idx = if let Some(&existing) = set_index_map.get(&key) {
                existing
            } else {
                let flags = match group.kind.as_str() {
                    "seq" => SCHEDULE_SET_FLAG_SEQUENCE,
                    "seq_weak" => SCHEDULE_SET_FLAG_SEQUENCE_WEAK,
                    _ => SCHEDULE_SET_FLAG_PARALLEL,
                };
                let cstr =
                    define_cstring_on(obj_mod, &format!("strata_sset_{}", sets.len()), &bare)?;
                let idx = sets.len();
                sets.push(ScheduleSetEntry {
                    qualified_name_cstr: cstr,
                    schedule_id: sched_id,
                    flags,
                    before_set_indices: Vec::new(),
                    after_set_indices: Vec::new(),
                });
                set_index_map.insert(key, idx);
                idx
            };
            // Nested parent set relationship; ordering between siblings happens below.
            own_set_idx = Some(idx);
            next_parent_sets.push((idx, bare));
        }

        let is_seq = group.kind == "seq";
        let is_seq_weak = group.kind == "seq_weak";
        let mut prev_leaves: Vec<String> = Vec::new();
        let mut prev_set_idx: Option<usize> = None;
        let mut all_leaves: Vec<String> = Vec::new();

        for ch in &group.children {
            let (leaves, cur_set_idx) = walk_group(
                obj_mod,
                sched_id,
                run_if_expr,
                ch,
                &next_parent_sets,
                sets,
                set_index_map,
                sys_map,
                seq_counter,
                leaf_order,
            )?;
            if is_seq || is_seq_weak {
                if let (Some(p_s), Some(c_s)) = (prev_set_idx, cur_set_idx)
                    && p_s != c_s
                {
                    if !sets[c_s].after_set_indices.contains(&p_s) {
                        sets[c_s].after_set_indices.push(p_s);
                    }
                    if !sets[p_s].before_set_indices.contains(&c_s) {
                        sets[p_s].before_set_indices.push(c_s);
                    }
                }
                for l in &leaves {
                    if let Some(ent) = sys_map.get_mut(l) {
                        for pl in &prev_leaves {
                            if pl != l {
                                if is_seq && !ent.after.contains(pl) {
                                    ent.after.push(pl.clone());
                                } else if is_seq_weak && !ent.after_weak.contains(pl) {
                                    ent.after_weak.push(pl.clone());
                                }
                            }
                        }
                    }
                }
            }
            if !leaves.is_empty() {
                prev_leaves = leaves.clone();
            }
            if cur_set_idx.is_some() {
                prev_set_idx = cur_set_idx;
            } else if !leaves.is_empty() {
                prev_set_idx = None;
            }
            all_leaves.extend(leaves);
        }
        Ok((all_leaves, own_set_idx))
    }

    let mut seq_counter = 0usize;
    let mut leaf_order = 0usize;
    for sched in &mir.schedules {
        let sched_id = schedule_id_for(&sched.label);
        for node in &sched.nodes {
            walk_group(
                obj_mod,
                sched_id,
                sched.run_if_expr.as_ref(),
                node,
                &[],
                &mut sets,
                &mut set_index_map,
                &mut sys_map,
                &mut seq_counter,
                &mut leaf_order,
            )?;
        }
    }

    // Also inherit default schedule for any synthesized system not listed explicitly.
    let fixed_run_if = mir
        .schedules
        .iter()
        .find(|s| s.label == "FixedUpdate")
        .and_then(|s| s.run_if_expr.as_ref());
    for f in &mir.functions {
        if matches!(
            f.kind,
            MirFnKind::SynthesizedTimeline
                | MirFnKind::SynthesizedTask
                | MirFnKind::SynthesizedFsm
                | MirFnKind::SynthesizedSpatialCsr
                | MirFnKind::SynthesizedTimerTick
        ) {
            let sys_bare = bare_schedule_target(&f.name).to_owned();
            let e = sys_map.entry(sys_bare).or_insert_with(|| SysSchedTopology {
                schedule_id: ScheduleId::FIXED_UPDATE.0,
                ..Default::default()
            });
            if e.run_if_expr.is_none()
                && e.schedule_id == ScheduleId::FIXED_UPDATE.0
                && let Some(expr) = fixed_run_if
            {
                e.run_if_expr = Some(expr.clone());
            }
        }
    }

    // Ensure synthesized `strata_timer_tick` executes before all other `FixedUpdate` systems.
    let timer_tick_name = mir
        .functions
        .iter()
        .find(|f| matches!(f.kind, MirFnKind::SynthesizedTimerTick))
        .map(|f| bare_schedule_target(&f.name).to_owned());
    if let Some(ref tt_name) = timer_tick_name {
        for f in &mir.functions {
            if matches!(
                f.kind,
                MirFnKind::System
                    | MirFnKind::SynthesizedTimeline
                    | MirFnKind::SynthesizedTask
                    | MirFnKind::SynthesizedFsm
                    | MirFnKind::SynthesizedSpatialCsr
            ) {
                let sys_bare = bare_schedule_target(&f.name);
                if sys_bare != tt_name
                    && let Some(ent) = sys_map.get_mut(sys_bare)
                    && ent.schedule_id == ScheduleId::FIXED_UPDATE.0
                    && !ent.after.contains(tt_name)
                {
                    ent.after.push(tt_name.clone());
                }
            }
        }
    }

    Ok((sets, sys_map))
}

fn wire_query_sets(
    wq: &WireQuerySpec,
) -> (
    HashSet<usize>,
    HashSet<usize>,
    HashSet<usize>,
    HashSet<usize>,
    HashSet<usize>,
    HashSet<usize>,
) {
    let mut comp_reads = HashSet::new();
    let mut comp_writes = HashSet::new();
    let mut with_set: HashSet<usize> = wq.with_filters.iter().copied().collect();
    let mut without_set: HashSet<usize> = wq.without_filters.iter().copied().collect();
    let mut res_reads = HashSet::new();
    let mut res_writes = HashSet::new();

    for t in &wq.terms {
        match t.mode {
            TermAccessMode::Read => {
                comp_reads.insert(t.layout_idx);
                with_set.insert(t.layout_idx);
            }
            TermAccessMode::Write | TermAccessMode::SelectiveWrite => {
                comp_writes.insert(t.layout_idx);
                with_set.insert(t.layout_idx);
            }
            TermAccessMode::OptionalRead => {
                comp_reads.insert(t.layout_idx);
                if t.changed {
                    with_set.insert(t.layout_idx);
                }
            }
            TermAccessMode::OptionalWrite => {
                comp_writes.insert(t.layout_idx);
                if t.changed {
                    with_set.insert(t.layout_idx);
                }
            }
            TermAccessMode::With => {
                with_set.insert(t.layout_idx);
            }
            TermAccessMode::Without => {
                without_set.insert(t.layout_idx);
            }
            TermAccessMode::ResRead | TermAccessMode::StreamRead => {
                res_reads.insert(t.layout_idx);
            }
            TermAccessMode::ResWrite | TermAccessMode::StreamWrite => {
                res_writes.insert(t.layout_idx);
            }
            TermAccessMode::Allow | TermAccessMode::Has | TermAccessMode::RemovedRead => {}
        }
    }

    for &cf in &wq.extra_changed_filters {
        with_set.insert(cf);
        if !comp_writes.contains(&cf) {
            comp_reads.insert(cf);
        }
    }

    (
        comp_reads,
        comp_writes,
        with_set,
        without_set,
        res_reads,
        res_writes,
    )
}

fn wire_queries_conflict(a: &WireQuerySpec, b: &WireQuerySpec) -> bool {
    let (a_reads, a_writes, a_with, a_without, a_res_reads, a_res_writes) = wire_query_sets(a);
    let (b_reads, b_writes, b_with, b_without, b_res_reads, b_res_writes) = wire_query_sets(b);

    if a_res_writes
        .iter()
        .any(|r| b_reads_or_writes(&b_res_reads, &b_res_writes, *r))
        || b_res_writes
            .iter()
            .any(|r| b_reads_or_writes(&a_res_reads, &a_res_writes, *r))
    {
        return true;
    }

    if !a_with.is_disjoint(&b_without) || !b_with.is_disjoint(&a_without) {
        return false;
    }

    a_writes
        .iter()
        .any(|c| b_reads_or_writes(&b_reads, &b_writes, *c))
        || b_writes
            .iter()
            .any(|c| b_reads_or_writes(&a_reads, &a_writes, *c))
}

#[inline]
fn b_reads_or_writes(reads: &HashSet<usize>, writes: &HashSet<usize>, id: usize) -> bool {
    reads.contains(&id) || writes.contains(&id)
}

fn assign_param_set_groups(wire_queries: &mut [WireQuerySpec]) {
    for q in wire_queries.iter_mut() {
        q.param_set_group = 0;
    }
    let n = wire_queries.len();
    if n < 2 {
        return;
    }

    let mut visited = vec![false; n];
    let mut next_group_id: u32 = 1;
    let mut stack = Vec::new();
    let mut component = Vec::new();

    for start in 0..n {
        if visited[start] {
            continue;
        }
        visited[start] = true;
        stack.clear();
        component.clear();
        stack.push(start);
        while let Some(u) = stack.pop() {
            component.push(u);
            for v in 0..n {
                if !visited[v] && wire_queries_conflict(&wire_queries[u], &wire_queries[v]) {
                    visited[v] = true;
                    stack.push(v);
                }
            }
        }
        if component.len() > 1 {
            let group_id = next_group_id;
            next_group_id += 1;
            for &idx in &component {
                wire_queries[idx].param_set_group = group_id;
            }
        }
    }
}

fn build_system_registration_entry(
    ctx: &mut ModuleContext<'_>,
    fn_idx: usize,
    f: &MirFunction,
    func_id: FuncId,
    sched_info: &HashMap<String, SysSchedTopology>,
) -> Result<SystemRegistrationEntry, JitError> {
    let bare_sys_name = bare_schedule_target(&f.name);
    let name_data_id = ctx.intern_cstr(bare_sys_name)?;
    let topo = sched_info
        .get(&f.name)
        .or_else(|| sched_info.get(bare_sys_name))
        .cloned()
        .unwrap_or_else(|| {
            let default_sched = match f.kind {
                MirFnKind::SynthesizedTimerTick
                | MirFnKind::SynthesizedTimeline
                | MirFnKind::SynthesizedTask
                | MirFnKind::SynthesizedFsm
                | MirFnKind::SynthesizedSpatialCsr => ScheduleId::FIXED_UPDATE.0,
                _ => ScheduleId::UPDATE.0,
            };
            SysSchedTopology {
                schedule_id: default_sched,
                ..Default::default()
            }
        });

    // Build deduplicated ECS queries from `f.query_bindings`.
    let mut wire_queries = Vec::with_capacity(f.query_bindings.len());
    let mut query_stream_layouts: HashSet<usize> = HashSet::new();
    for qb in &f.query_bindings {
        let mut terms: Vec<WireTermSpec> = Vec::new();
        let mut term_map = Vec::with_capacity(qb.terms.len());
        let mut by_comp: HashMap<usize, usize> = HashMap::new();
        for t in &qb.terms {
            let lidx = lookup_name_in_map(&ctx.layout_map, &t.canonical_component)
                .or_else(|| lookup_name_in_map(&ctx.layout_map, &t.storage_key))
                .ok_or_else(|| {
                    JitError::Codegen(format!(
                        "unresolved component `{}` (`{}`) in system `{}`",
                        t.canonical_component, t.storage_key, f.name
                    ))
                })?;
            if matches!(
                t.mode,
                TermAccessMode::StreamRead | TermAccessMode::StreamWrite
            ) {
                query_stream_layouts.insert(lidx);
            }
            let is_changed = f.changed_terms.iter().any(|ct| {
                ct.query_idx == qb.query_idx
                    && (ct.term_idx == t.term_idx
                        || ct.canonical_component == t.canonical_component)
            });
            if let Some(&wire_idx) = by_comp.get(&lidx) {
                terms[wire_idx].mode = merge_access_mode(terms[wire_idx].mode, t.mode);
                terms[wire_idx].changed |= is_changed;
                term_map.push(wire_idx);
            } else {
                let wire_idx = terms.len();
                by_comp.insert(lidx, wire_idx);
                terms.push(WireTermSpec {
                    layout_idx: lidx,
                    mode: t.mode,
                    changed: is_changed,
                });
                term_map.push(wire_idx);
            }
        }
        let mut extra_changed_filters = Vec::new();
        for t in &terms {
            if t.changed
                && t.mode != TermAccessMode::Read
                && !extra_changed_filters.contains(&t.layout_idx)
            {
                extra_changed_filters.push(t.layout_idx);
            }
        }
        if let Some(qdesc) = f.queries.get(qb.query_idx as usize) {
            for cf in &qdesc.changed_filters {
                if let Some(lidx) = lookup_name_in_map(&ctx.layout_map, cf)
                    && !by_comp.contains_key(&lidx)
                    && !extra_changed_filters.contains(&lidx)
                {
                    extra_changed_filters.push(lidx);
                }
            }
        }
        let mut with_filters = Vec::new();
        for w in &qb.with_filters {
            if let Some(lidx) = lookup_name_in_map(&ctx.layout_map, w)
                && !by_comp.contains_key(&lidx)
                && !extra_changed_filters.contains(&lidx)
                && !with_filters.contains(&lidx)
            {
                with_filters.push(lidx);
            }
        }
        let mut without_filters = Vec::new();
        for wo in &qb.without_filters {
            if let Some(lidx) = lookup_name_in_map(&ctx.layout_map, wo)
                && !by_comp.contains_key(&lidx)
                && !with_filters.contains(&lidx)
                && !without_filters.contains(&lidx)
            {
                without_filters.push(lidx);
            }
        }
        wire_queries.push(WireQuerySpec {
            terms,
            term_map,
            with_filters,
            without_filters,
            extra_changed_filters,
            param_set_group: 0,
        });
    }
    assign_param_set_groups(&mut wire_queries);

    // Collect distinct resource borrows (`ResRead` / `ResWrite`).
    let mut res_modes: BTreeMap<usize, bool> = BTreeMap::new();
    for rb in &f.resources {
        if let Some(lidx) = lookup_name_in_map(&ctx.layout_map, &rb.canonical_name)
            .or_else(|| lookup_name_in_map(&ctx.layout_map, &rb.resource_name))
        {
            let e = res_modes.entry(lidx).or_insert(rb.mutable);
            *e |= rb.mutable;
        }
    }
    for bb in &f.blocks {
        for s in &bb.stmts {
            match &s.inst {
                Inst::ResRead { resource } => {
                    if let Some(lidx) = lookup_name_in_map(&ctx.layout_map, resource) {
                        res_modes.entry(lidx).or_insert(false);
                    }
                }
                Inst::ResWrite { resource } => {
                    if let Some(lidx) = lookup_name_in_map(&ctx.layout_map, resource) {
                        res_modes.insert(lidx, true);
                    }
                }
                _ => {}
            }
        }
    }

    let mut next_q = wire_queries.len();

    // Reserve hidden query indices right after `wire_queries` so compile-time indices are static.
    let mut extra_obj_queries = Vec::new();
    let mut seen_objs = HashSet::new();
    for bb in &f.blocks {
        for s in &bb.stmts {
            if let Inst::ResolveNamedObject { name } | Inst::BindNamedObject { name } = &s.inst
                && let Some(obj_idx) = ctx.mir.objects.iter().position(|o| &o.name == name)
                && seen_objs.insert(obj_idx)
            {
                let has_reusable = find_reusable_obj_query(ctx, f, obj_idx).is_some();
                if !has_reusable && next_q < SYSTEM_QUERY_CAP {
                    extra_obj_queries.push(ExtraObjQuery {
                        obj_idx,
                        wire_query_idx: next_q,
                    });
                    next_q += 1;
                }
            }
        }
    }

    // Reserve hidden `MESSAGE_READ` / `MESSAGE_WRITE` query indices for `f.stream_ops` & `Inst::StreamEmit`.
    let mut stream_queries: Vec<StreamQuerySlot> = Vec::new();
    let mut stream_idx_by_lidx: HashMap<usize, usize> = HashMap::new();
    for op in &f.stream_ops {
        if let Some(lidx) = lookup_name_in_map(&ctx.layout_map, &op.canonical_stream)
            .or_else(|| lookup_name_in_map(&ctx.layout_map, &op.stream))
        {
            if query_stream_layouts.contains(&lidx) {
                continue;
            }
            let is_write = matches!(
                op.kind,
                MirStreamOpKind::StreamSend | MirStreamOpKind::StreamWriteBatch
            );
            if let Some(&idx) = stream_idx_by_lidx.get(&lidx) {
                stream_queries[idx].is_write |= is_write;
            } else if next_q < SYSTEM_QUERY_CAP {
                let idx = stream_queries.len();
                stream_idx_by_lidx.insert(lidx, idx);
                stream_queries.push(StreamQuerySlot {
                    stream_layout_idx: lidx,
                    is_write,
                });
                next_q += 1;
            }
        }
    }
    for bb in &f.blocks {
        for s in &bb.stmts {
            if let Inst::StreamEmit { stream, .. } = &s.inst
                && let Some(lidx) = lookup_name_in_map(&ctx.layout_map, stream)
                && !query_stream_layouts.contains(&lidx)
            {
                if let Some(&idx) = stream_idx_by_lidx.get(&lidx) {
                    stream_queries[idx].is_write = true;
                } else if next_q < SYSTEM_QUERY_CAP {
                    let idx = stream_queries.len();
                    stream_idx_by_lidx.insert(lidx, idx);
                    stream_queries.push(StreamQuerySlot {
                        stream_layout_idx: lidx,
                        is_write: true,
                    });
                    next_q += 1;
                }
            }
        }
    }

    let run_if_guard = if let Some(ref expr) = topo.run_if_expr
        && let Some((res_name, _)) = find_res_access_in_hir(expr)
        && let Some(res_lidx) = lookup_name_in_map(&ctx.layout_map, &res_name)
    {
        res_modes.entry(res_lidx).or_insert(false);
        Some((expr.clone(), res_lidx))
    } else {
        None
    };

    let mut resource_queries = Vec::new();
    for (lidx, mutable) in res_modes {
        if next_q < SYSTEM_QUERY_CAP {
            resource_queries.push((lidx, mutable, next_q));
            next_q += 1;
        }
    }

    let mut after_names = Vec::with_capacity(topo.after.len());
    for a in &topo.after {
        after_names.push(ctx.intern_cstr(bare_schedule_target(a))?);
    }
    let mut after_weak_names = Vec::with_capacity(topo.after_weak.len());
    for a in &topo.after_weak {
        after_weak_names.push(ctx.intern_cstr(bare_schedule_target(a))?);
    }
    let mut before_names = Vec::with_capacity(topo.before.len());
    for b in &topo.before {
        before_names.push(ctx.intern_cstr(bare_schedule_target(b))?);
    }
    let mut in_set_names = Vec::with_capacity(topo.in_sets.len());
    for s in &topo.in_sets {
        in_set_names.push(ctx.intern_cstr(bare_schedule_target(s))?);
    }
    Ok(SystemRegistrationEntry {
        fn_idx,
        func_id,
        name_data_id,
        schedule_id: topo.schedule_id,
        wire_queries,
        resource_queries,
        extra_obj_queries,
        stream_queries,
        after_names,
        after_weak_names,
        before_names,
        in_set_names,
        mount_set_indices: topo.mount_set_indices,
        sched_order: topo.sched_order,
        run_if_guard,
    })
}

fn find_reusable_obj_query(
    ctx: &ModuleContext<'_>,
    f: &MirFunction,
    obj_idx: usize,
) -> Option<usize> {
    let obj = ctx.mir.objects.get(obj_idx)?;
    let mut obj_comps: HashSet<usize> = HashSet::new();
    let mut stack: Vec<usize> = Vec::new();
    for c in &obj.components {
        if let Some(lidx) = lookup_name_in_map(&ctx.layout_map, c) {
            stack.push(lidx);
        }
    }
    for ci in &obj.inits {
        if let Some(lidx) = ci
            .canonical_component
            .as_deref()
            .and_then(|c| lookup_name_in_map(&ctx.layout_map, c))
            .or_else(|| lookup_name_in_map(&ctx.layout_map, &ci.component))
        {
            stack.push(lidx);
        }
    }
    while let Some(lidx) = stack.pop() {
        if obj_comps.insert(lidx) {
            if let Some(meta) = ctx.layouts.get(lidx) {
                stack.extend_from_slice(&meta.required_indices);
            }
            if let Some(layout) = ctx.mir_layouts_sorted.get(lidx) {
                for req in &layout.required_components {
                    if let Some(req_idx) = lookup_name_in_map(&ctx.layout_map, req) {
                        stack.push(req_idx);
                    }
                }
            }
        }
    }
    if obj_comps.is_empty() {
        return None;
    }
    for (qi, qb) in f.query_bindings.iter().enumerate() {
        if !qb.terms.is_empty()
            && qb.terms.iter().all(|t| {
                lookup_name_in_map(&ctx.layout_map, &t.canonical_component)
                    .or_else(|| lookup_name_in_map(&ctx.layout_map, &t.storage_key))
                    .is_some_and(|lidx| obj_comps.contains(&lidx))
            })
            && qb.with_filters.iter().all(|w| {
                lookup_name_in_map(&ctx.layout_map, w).is_some_and(|lidx| obj_comps.contains(&lidx))
            })
            && qb.without_filters.iter().all(|wo| {
                lookup_name_in_map(&ctx.layout_map, wo)
                    .is_none_or(|lidx| !obj_comps.contains(&lidx))
            })
        {
            return Some(qi);
        }
    }
    None
}

fn find_res_access_in_hir(expr: &HirExpr) -> Option<(String, String)> {
    match expr {
        HirExpr::Field { base, field, .. } => {
            find_res_access_in_hir(base).map(|(r, _)| (r, field.clone()))
        }
        HirExpr::Call(HirCall {
            callee,
            generic_args,
            receiver,
            ..
        }) => {
            let trimmed = callee.trim();
            if matches!(trimmed, "res" | "res_mut")
                && let Some(res_name) = generic_args.first()
            {
                return Some((res_name.trim().to_owned(), String::new()));
            }
            if let Some(inner) = trimmed
                .strip_prefix("res<")
                .or_else(|| trimmed.strip_prefix("res_mut<"))
                .or_else(|| trimmed.strip_prefix("res::<"))
                .or_else(|| trimmed.strip_prefix("res_mut::<"))
                .and_then(|s| s.strip_suffix('>'))
            {
                return Some((inner.trim().to_owned(), String::new()));
            }
            receiver.as_deref().and_then(find_res_access_in_hir)
        }
        HirExpr::Path { name, .. } => name
            .trim()
            .strip_prefix("res<")
            .or_else(|| name.trim().strip_prefix("res_mut<"))
            .and_then(|s| s.strip_suffix('>'))
            .map(|inner| (inner.trim().to_owned(), String::new())),
        HirExpr::Unary { expr: inner, .. } | HirExpr::Cast { expr: inner, .. } => {
            find_res_access_in_hir(inner)
        }
        HirExpr::Binary { lhs, rhs, .. } => {
            find_res_access_in_hir(lhs).or_else(|| find_res_access_in_hir(rhs))
        }
        _ => None,
    }
}

fn eval_hir_run_if(
    res_layout: &SolvedLayout,
    consts: &HashMap<String, HirConst>,
    b: &mut FunctionBuilder<'_>,
    res_ptr: Value,
    expr: &HirExpr,
) -> Option<Value> {
    enum RunVal {
        F32(Value),
        I64(Value),
        Bool(Value),
    }

    fn eval_val(
        res_layout: &SolvedLayout,
        consts: &HashMap<String, HirConst>,
        b: &mut FunctionBuilder<'_>,
        res_ptr: Value,
        expr: &HirExpr,
    ) -> Option<RunVal> {
        match expr {
            HirExpr::BoolLit(v) => Some(RunVal::Bool(b.ins().iconst(types::I8, i64::from(*v)))),
            HirExpr::IntLit { value, .. } => Some(RunVal::I64(b.ins().iconst(types::I64, *value))),
            HirExpr::FloatLit { value, .. } => Some(RunVal::F32(b.ins().f32const(*value as f32))),
            HirExpr::Path { name, .. } => {
                let c = consts
                    .get(name)
                    .or_else(|| name.rsplit("::").next().and_then(|s| consts.get(s)))?;
                let c_expr = c.expr.as_ref()?;
                eval_val(res_layout, consts, b, res_ptr, c_expr)
            }
            HirExpr::Unary {
                op, expr: inner, ..
            } => match (op, eval_val(res_layout, consts, b, res_ptr, inner)?) {
                (HirUnOp::Neg, RunVal::F32(v)) => Some(RunVal::F32(b.ins().fneg(v))),
                (HirUnOp::Neg, RunVal::I64(v)) => Some(RunVal::I64(b.ins().ineg(v))),
                (HirUnOp::Not, RunVal::Bool(v)) => {
                    Some(RunVal::Bool(b.ins().icmp_imm_s(IntCC::Equal, v, 0)))
                }
                _ => None,
            },
            HirExpr::Field { base: _, field, ty } => {
                let f = res_layout.fields.iter().find(|f| f.name == *field)?;
                let eff_ty = if matches!(ty, Ty::Unknown) { &f.ty } else { ty };
                let mty = mir_type_from_ty(eff_ty);
                let cl_ty = scalar_cl_type(&mty, b.func.signature.call_conv);
                let val = b
                    .ins()
                    .load(cl_ty, MemFlagsData::new(), res_ptr, f.offset as i32);
                if cl_ty == types::F32 {
                    Some(RunVal::F32(val))
                } else if cl_ty == types::I8 {
                    Some(RunVal::Bool(val))
                } else if cl_ty == types::F64 {
                    Some(RunVal::F32(b.ins().fdemote(types::F32, val)))
                } else {
                    let i64v = if cl_ty == types::I64 {
                        val
                    } else {
                        b.ins().sextend(types::I64, val)
                    };
                    Some(RunVal::I64(i64v))
                }
            }
            HirExpr::Call(HirCall {
                receiver: Some(recv),
                callee,
                ..
            }) if matches!(callee.trim(), "raw" | "as_secs") => {
                eval_val(res_layout, consts, b, res_ptr, recv)
            }
            HirExpr::Cast { expr: inner, .. } => eval_val(res_layout, consts, b, res_ptr, inner),
            HirExpr::Binary { op, lhs, rhs, .. } => {
                let lv = eval_val(res_layout, consts, b, res_ptr, lhs)?;
                let rv = eval_val(res_layout, consts, b, res_ptr, rhs)?;
                match (lv, rv) {
                    (RunVal::Bool(l), RunVal::Bool(r)) => match op {
                        HirBinOp::And => Some(RunVal::Bool(b.ins().band(l, r))),
                        HirBinOp::Or => Some(RunVal::Bool(b.ins().bor(l, r))),
                        HirBinOp::Eq => Some(RunVal::Bool(b.ins().icmp(IntCC::Equal, l, r))),
                        HirBinOp::Ne => Some(RunVal::Bool(b.ins().icmp(IntCC::NotEqual, l, r))),
                        _ => None,
                    },
                    (RunVal::F32(l), RunVal::F32(r)) => match op {
                        HirBinOp::Le => {
                            Some(RunVal::Bool(b.ins().fcmp(FloatCC::LessThanOrEqual, l, r)))
                        }
                        HirBinOp::Lt => Some(RunVal::Bool(b.ins().fcmp(FloatCC::LessThan, l, r))),
                        HirBinOp::Ge => Some(RunVal::Bool(b.ins().fcmp(
                            FloatCC::GreaterThanOrEqual,
                            l,
                            r,
                        ))),
                        HirBinOp::Gt => {
                            Some(RunVal::Bool(b.ins().fcmp(FloatCC::GreaterThan, l, r)))
                        }
                        HirBinOp::Eq => Some(RunVal::Bool(b.ins().fcmp(FloatCC::Equal, l, r))),
                        HirBinOp::Ne => Some(RunVal::Bool(b.ins().fcmp(FloatCC::NotEqual, l, r))),
                        HirBinOp::Add => Some(RunVal::F32(b.ins().fadd(l, r))),
                        HirBinOp::Sub => Some(RunVal::F32(b.ins().fsub(l, r))),
                        HirBinOp::Mul => Some(RunVal::F32(b.ins().fmul(l, r))),
                        HirBinOp::Div => Some(RunVal::F32(b.ins().fdiv(l, r))),
                        _ => None,
                    },
                    (RunVal::I64(l), RunVal::I64(r)) => match op {
                        HirBinOp::Le => Some(RunVal::Bool(b.ins().icmp(
                            IntCC::SignedLessThanOrEqual,
                            l,
                            r,
                        ))),
                        HirBinOp::Lt => {
                            Some(RunVal::Bool(b.ins().icmp(IntCC::SignedLessThan, l, r)))
                        }
                        HirBinOp::Ge => Some(RunVal::Bool(b.ins().icmp(
                            IntCC::SignedGreaterThanOrEqual,
                            l,
                            r,
                        ))),
                        HirBinOp::Gt => {
                            Some(RunVal::Bool(b.ins().icmp(IntCC::SignedGreaterThan, l, r)))
                        }
                        HirBinOp::Eq => Some(RunVal::Bool(b.ins().icmp(IntCC::Equal, l, r))),
                        HirBinOp::Ne => Some(RunVal::Bool(b.ins().icmp(IntCC::NotEqual, l, r))),
                        _ => None,
                    },
                    _ => None,
                }
            }
            _ => None,
        }
    }

    match eval_val(res_layout, consts, b, res_ptr, expr)? {
        RunVal::Bool(v) => Some(v),
        RunVal::I64(v) => Some(b.ins().icmp_imm_s(IntCC::NotEqual, v, 0)),
        RunVal::F32(v) => {
            let z = b.ins().f32const(0.0);
            Some(b.ins().fcmp(FloatCC::NotEqual, v, z))
        }
    }
}

fn scalar_cl_type(mty: &MirType, _cc: cranelift_codegen::isa::CallConv) -> Type {
    match mty {
        MirType::Unit | MirType::Bool | MirType::U8 | MirType::I8 => types::I8,
        MirType::U16 | MirType::I16 => types::I16,
        MirType::U32 | MirType::I32 | MirType::Sym | MirType::Fix32 => types::I32,
        MirType::F32 => types::F32,
        MirType::F64 => types::F64,
        _ => types::I64,
    }
}

fn mir_type_from_ty(ty: &Ty) -> MirType {
    match ty {
        Ty::Unit => MirType::Unit,
        Ty::Bool => MirType::Bool,
        Ty::U8 => MirType::U8,
        Ty::U16 => MirType::U16,
        Ty::U32 | Ty::Rgba8 => MirType::U32,
        Ty::U64 => MirType::U64,
        Ty::I8 => MirType::I8,
        Ty::I16 => MirType::I16,
        Ty::I32 => MirType::I32,
        Ty::I64 => MirType::I64,
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => MirType::F32,
        Ty::F64 => MirType::F64,
        Ty::Fix32 => MirType::Fix32,
        Ty::Fix64 => MirType::Fix64,
        Ty::Sym => MirType::Sym,
        Ty::Vec2 => MirType::Vec2,
        Ty::IVec2 => MirType::IVec2,
        Ty::UVec2 => MirType::UVec2,
        Ty::Vec3 => MirType::Vec3,
        Ty::IVec3 => MirType::IVec3,
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => MirType::Vec4,
        Ty::Array { elem, len } => MirType::Array {
            elem: Box::new(mir_type_from_ty(elem)),
            len: *len,
        },
        Ty::Tuple(ts) => MirType::Tuple(ts.iter().map(mir_type_from_ty).collect()),
        Ty::Ref(_) => MirType::Entity,
        Ty::Named(n) => MirType::Named(n.clone()),
        Ty::Borrow { mutable: true, .. } => MirType::MutPtr,
        _ => MirType::Ptr,
    }
}

impl<'a> ModuleContext<'a> {
    fn intern_cstr(&mut self, text: &str) -> Result<DataId, JitError> {
        if let Some(&id) = self.cstring_cache.get(text) {
            return Ok(id);
        }
        let id = self
            .obj_mod
            .declare_anonymous_data(false, false)
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        let mut desc = DataDescription::new();
        desc.define(bytes.into_boxed_slice());
        self.obj_mod
            .define_data(id, &desc)
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        self.cstring_cache.insert(text.to_owned(), id);
        Ok(id)
    }

    fn intern_bytes(&mut self, text: &str) -> Result<(DataId, usize), JitError> {
        let len = text.len();
        if let Some(&id) = self.string_cache.get(text) {
            return Ok((id, len));
        }
        let id = self
            .obj_mod
            .declare_anonymous_data(false, false)
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        let desc_bytes = if text.is_empty() {
            vec![0u8]
        } else {
            text.as_bytes().to_vec()
        };
        let mut desc = DataDescription::new();
        desc.define(desc_bytes.into_boxed_slice());
        self.obj_mod
            .define_data(id, &desc)
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        self.string_cache.insert(text.to_owned(), id);
        Ok((id, len))
    }

    fn declare_extern_fn(
        &mut self,
        name: &str,
        params: &[Type],
        ret: Option<Type>,
    ) -> Result<FuncId, JitError> {
        if let Some(&fid) = self.extern_funcs.get(name) {
            return Ok(fid);
        }
        let mut sig = Signature::new(self.call_conv);
        for &p in params {
            sig.params.push(AbiParam::new(p));
        }
        if let Some(r) = ret {
            sig.returns.push(AbiParam::new(r));
        }
        let fid = self
            .obj_mod
            .declare_function(name, Linkage::Import, &sig)
            .map_err(|e| JitError::Codegen(format!("extern `{name}`: {e}")))?;
        self.extern_funcs.insert(name.to_owned(), fid);
        Ok(fid)
    }

    fn enum_scalar_mir_ty(&self, mty: &MirType) -> Option<MirType> {
        let MirType::Named(n) = mty else {
            return None;
        };
        let (enum_bytes, is_signed) = lookup_name_ref(&self.enums_by_name, n)
            .map(|ed| (ed.repr_bytes, ed.is_signed))
            .or_else(|| {
                lookup_name_in_map(&self.layout_map, n)
                    .map(|idx| &self.mir_layouts_sorted[idx])
                    .filter(|l| l.item_kind == SchemaItemKind::Enum)
                    .map(|l| (l.size, false))
            })?;
        Some(match (enum_bytes, is_signed) {
            (1, _) => MirType::U8,
            (2, _) => MirType::U16,
            (4, true) => MirType::I32,
            (4, false) => MirType::U32,
            _ => MirType::U64,
        })
    }

    fn is_agg_mir_ty(&self, mty: &MirType) -> bool {
        match mty {
            MirType::Named(_) => self.enum_scalar_mir_ty(mty).is_none(),
            MirType::Array { .. } | MirType::Tuple(_) => true,
            _ => false,
        }
    }

    fn layout_size_of_mir_ty(&self, mty: &MirType) -> usize {
        match mty {
            MirType::Unit | MirType::Bool | MirType::U8 | MirType::I8 => 1,
            MirType::U16 | MirType::I16 => 2,
            MirType::U32 | MirType::I32 | MirType::F32 | MirType::Sym | MirType::Fix32 => 4,
            MirType::U64
            | MirType::I64
            | MirType::F64
            | MirType::Fix64
            | MirType::Entity
            | MirType::Ptr
            | MirType::MutPtr
            | MirType::QueryIter
            | MirType::Checkpoint => self.ptr_bytes.max(8),
            MirType::Vec2 | MirType::IVec2 | MirType::UVec2 => 8,
            MirType::Vec3 | MirType::IVec3 => 12,
            MirType::Vec4 => 16,
            MirType::Array { elem, len } => self.layout_size_of_mir_ty(elem) * (*len),
            MirType::Tuple(ts) => ts
                .iter()
                .enumerate()
                .map(|(i, t)| i * 8 + self.layout_size_of_mir_ty(t))
                .max()
                .unwrap_or(0),
            MirType::Named(name) => {
                if let Some(scalar) = self.enum_scalar_mir_ty(mty) {
                    self.layout_size_of_mir_ty(&scalar)
                } else if let Some(bits) = name
                    .strip_prefix("BitSet<")
                    .and_then(|s| s.strip_suffix('>'))
                    .and_then(|s| s.parse::<usize>().ok())
                {
                    bits.div_ceil(32).max(1) * 4
                } else {
                    lookup_name_in_map(&self.layout_map, name)
                        .map(|i| self.layouts[i].size)
                        .unwrap_or(16)
                }
            }
        }
    }

    fn cl_type_for_mir_val(&self, mty: &MirType) -> Type {
        match mty {
            MirType::Ptr
            | MirType::MutPtr
            | MirType::QueryIter
            | MirType::Checkpoint
            | MirType::Array { .. }
            | MirType::Tuple(_) => self.ptr_ty,
            MirType::Named(_) => {
                if let Some(scalar) = self.enum_scalar_mir_ty(mty) {
                    scalar_cl_type(&scalar, self.call_conv)
                } else {
                    self.ptr_ty
                }
            }
            MirType::Vec2 | MirType::Vec3 | MirType::Vec4 => types::F32,
            MirType::IVec2 | MirType::IVec3 | MirType::UVec2 => types::I32,
            _ => scalar_cl_type(mty, self.call_conv),
        }
    }

    fn sema_ty_to_field_mir_ty(&self, ty: &Ty) -> Option<MirType> {
        match ty {
            Ty::Unit
            | Ty::Unknown
            | Ty::BannedWire(_)
            | Ty::Asset(_)
            | Ty::Mat3
            | Ty::Mat4
            | Ty::BitSet(_)
            | Ty::InlineStr(_)
            | Ty::InputBuffer { .. }
            | Ty::SmallVec { .. } => None,
            Ty::Named(n) if n == "GraceWindow" => Some(MirType::F32),
            Ty::Named(n) => {
                let enum_repr = lookup_name_ref(&self.enums_by_name, n)
                    .map(|ed| (ed.repr_bytes, ed.is_signed))
                    .or_else(|| {
                        lookup_name_in_map(&self.layout_map, n)
                            .map(|idx| &self.mir_layouts_sorted[idx])
                            .filter(|l| l.item_kind == SchemaItemKind::Enum)
                            .map(|l| (l.size, false))
                    });
                if let Some((sz, is_signed)) = enum_repr {
                    return Some(match (sz, is_signed) {
                        (1, _) => MirType::U8,
                        (2, _) => MirType::U16,
                        (4, true) => MirType::I32,
                        (4, false) => MirType::U32,
                        _ => MirType::U64,
                    });
                }
                Some(mir_type_from_ty(ty))
            }
            _ => Some(mir_type_from_ty(ty)),
        }
    }

    fn resolve_field_offset_and_ty(
        &self,
        layout_key: &str,
        field: &str,
    ) -> (usize, Option<MirType>) {
        let mut cur_layout = lookup_name_in_map(&self.layout_map, layout_key)
            .map(|lidx| &self.mir_layouts_sorted[lidx])
            .or_else(|| {
                self.mir
                    .relations
                    .iter()
                    .find(|r| r.canonical_name == layout_key || r.name == layout_key)
                    .and_then(|r| r.payload_layout.as_ref())
            });
        let Some(mut layout) = cur_layout.take() else {
            return (0, None);
        };
        let parts: Vec<&str> = field.split('.').collect();
        let mut offset = 0usize;
        for (i, part) in parts.iter().enumerate() {
            let Some(sf) = layout.fields.iter().find(|f| f.name == *part) else {
                return (0, None);
            };
            offset += sf.offset;
            if i + 1 < parts.len() {
                if let Ty::Named(ref inner_name) = sf.ty
                    && let Some(inner_idx) = lookup_name_in_map(&self.layout_map, inner_name)
                {
                    layout = &self.mir_layouts_sorted[inner_idx];
                    continue;
                }
                let lane = match parts[i + 1] {
                    "x" | "r" | "0" => Some(0usize),
                    "y" | "g" | "1" => Some(1),
                    "z" | "b" | "2" => Some(2),
                    "w" | "a" | "3" => Some(3),
                    _ => None,
                };
                if let Some(lane_idx) = lane {
                    offset += lane_idx * 4;
                    let lane_mty = match sf.ty {
                        Ty::IVec2 | Ty::IVec3 => MirType::I32,
                        Ty::UVec2 => MirType::U32,
                        _ => MirType::F32,
                    };
                    return (offset, Some(lane_mty));
                }
                return (0, None);
            }
            return (offset, self.sema_ty_to_field_mir_ty(&sf.ty));
        }
        (0, None)
    }
}

fn define_cstring_on(module: &mut ObjectModule, sym: &str, text: &str) -> Result<DataId, JitError> {
    let id = module
        .declare_data(sym, Linkage::Local, false, false)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    let mut desc = DataDescription::new();
    desc.define(bytes.into_boxed_slice());
    module
        .define_data(id, &desc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    Ok(id)
}

fn write_u32_le(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn write_u64_le(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn write_usize_le(buf: &mut [u8], off: usize, v: usize, ptr_bytes: usize) {
    if ptr_bytes == 4 {
        write_u32_le(buf, off, v as u32);
    } else {
        write_u64_le(buf, off, v as u64);
    }
}
