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
    BAM_COMPONENT_INVALID, BAM_EVENT_KIND_ADD, BAM_EVENT_KIND_CUSTOM, BAM_EVENT_KIND_DESPAWN,
    BAM_EVENT_KIND_INSERT, BAM_EVENT_KIND_READY, BAM_EVENT_KIND_REMOVE, BAM_SYSTEM_SET_INVALID,
    FFI_ENTITY_NULL, FFI_OK, FFI_TYPE_MISMATCH, QUERY_TERM_CAP, RELATION_FLAG_ACYCLIC,
    RELATION_FLAG_CASCADE_DESPAWN, RELATION_FLAG_CLEANUP_REMOVE, RELATION_FLAG_EXCLUSIVE,
    RELATION_FLAG_SYMMETRIC, SCHEDULE_SET_FLAG_PARALLEL, SCHEDULE_SET_FLAG_SEQUENCE,
    SCHEDULE_SET_FLAG_SEQUENCE_WEAK, SYSTEM_QUERY_CAP, TRIGGER_FLAG_PROPAGATE, WIRE_ABI_VERSION,
    api_slots, structs,
};
use crate::{JitCompileOptions, JitError, JitOptLevel};
use bamabi_sys::{
    AccessMode, BAM_REQUIRED_FLAG_CUSTOM_BYTES, BamRequiredComponent, ComponentDesc, ComponentUuid,
    ScheduleId, fnv1a_64_str,
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
use strata_mir::{
    Inst, LocalId, MirConstVal, MirFnKind, MirFunction, MirModule, MirStmt, MirType, Terminator,
};
use strata_sema::access::TermAccessMode;
use strata_sema::hir::{
    HirBinOp, HirCall, HirCompInit, HirConst, HirCurve, HirExpr, HirRelation, HirScheduleGroup,
    HirTable, HirUnOp,
};
use strata_sema::layout::{EnumDef, SchemaItemKind, SolvedField, SolvedLayout};
use strata_sema::types::Ty;
use target_lexicon::Triple;

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
/// Maximum spatial entities stored per frame ring slot in heap scratch.
const MAX_SPATIAL_ENTRIES: usize = 512;

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
}

#[derive(Clone)]
struct RelationMetaData {
    payload_size: usize,
    desc_id: DataId,
}

#[derive(Clone)]
struct SpatialIndexMeta {
    name: String,
    frames: usize,
    by_field_path: String,
    cursor_offset: usize,
    ring_offset: usize,
    entry_stride: usize,
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
        spatial_specs: &[(String, bool, usize, String, String)],
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

        cursor = align_up(cursor, 8);
        let mut spatial_metas = Vec::with_capacity(spatial_specs.len());
        // Entry layout: `[entity: u64 @ 0] [x: f32 @ 8] [y: f32 @ 12] [z: f32 @ 16] [_pad: u32 @ 20]` (24 bytes)
        let entry_stride = 24usize;
        // Per frame slot: `[count: u32 @ 0] [_pad: u32 @ 4] [entries: entry_stride * MAX_SPATIAL_ENTRIES @ 8]`
        let slot_bytes = 8 + entry_stride * MAX_SPATIAL_ENTRIES;
        for (name, _is_history, frames, _over_comp, by_field_path) in spatial_specs {
            cursor = align_up(cursor, 8);
            let cursor_offset = cursor;
            cursor += 8; // [frame_cursor: u32 @ 0, _pad: u32 @ 4]
            let ring_offset = cursor;
            let ring_frames = (*frames).max(1);
            cursor += ring_frames * slot_bytes;
            spatial_metas.push(SpatialIndexMeta {
                name: name.clone(),
                frames: ring_frames,
                by_field_path: by_field_path.clone(),
                cursor_offset,
                ring_offset,
                entry_stride,
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
}

#[derive(Clone)]
struct WireQuerySpec {
    terms: Vec<WireTermSpec>,
    /// Maps `(original_term_idx) -> wire_term_idx`.
    term_map: Vec<usize>,
    with_filters: Vec<usize>,
    without_filters: Vec<usize>,
}

#[derive(Clone)]
struct ExtraObjQuery {
    obj_idx: usize,
    wire_query_idx: usize,
}

#[derive(Clone)]
struct StreamQuerySlot {
    stream_layout_idx: usize,
    wire_query_idx: usize,
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
    name_data_id: DataId,
    event_layout_idx: Option<usize>,
    event_kind: u32,
    watched_layout_idx: Option<usize>,
    func_id: FuncId,
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
    helper_funcs: HashMap<String, (FuncId, usize)>,
    migrations_by_layout: HashMap<usize, FuncId>,
    systems: Vec<SystemRegistrationEntry>,
    observers: Vec<ObserverRegistrationEntry>,
    schedule_sets: Vec<ScheduleSetEntry>,
    init_objects_fn: Option<(FuncId, DataId, Vec<(usize, usize)>)>,
}

/// Compiles a verified `MirModule` directly from MIR CFGs into a native PIC `.o` artifact.
pub fn emit_pic_object(
    mir: &MirModule,
    opts: &JitCompileOptions,
) -> Result<PicObjectArtifact, JitError> {
    let triple = Triple::host();
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

    // 1. Emit helper functions (`mir.fns`).
    emit_all_helpers(&mut ctx)?;

    // 2. Emit migrations (`MirFnKind::Migration`).
    emit_all_migrations(&mut ctx)?;

    // 3. Emit reactive observers (`MirFnKind::Observer`).
    emit_all_observers(&mut ctx)?;

    // 4. Emit ECS systems & synthesized functions (`mir.functions`) + schedule `run_if_ctx`.
    emit_all_systems(&mut ctx)?;

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
        let uuid = ComponentUuid::from_parts(&canon, 0, 1, 0);
        let uuid_bytes = *uuid.as_bytes();
        let fp = fnv1a_64_str(&canon);
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
            ptr_bytes,
        )?;
        tables.insert(t.name.clone(), tro);
    }

    let mut curves = HashMap::new();
    for (ci, c) in mir.curves.iter().enumerate() {
        let cro = define_curve_rodata(&mut obj_mod, ci, c)?;
        curves.insert(c.name.clone(), cro);
    }

    let spatial_specs: Vec<(String, bool, usize, String, String)> = mir
        .spatial_indices
        .iter()
        .map(|s| {
            (
                s.name.clone(),
                s.is_history,
                s.frames as usize,
                s.over_component.clone(),
                s.by_field_path.clone(),
            )
        })
        .collect();

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

    let (schedule_sets, sys_sched_info) = extract_schedule_topology(&mut obj_mod, mir)?;

    let (state_layout, spatial_metas) = StateLayout::compute(
        ptr_bytes,
        &mut layouts,
        relations.len(),
        mir.objects.len(),
        sys_fn_count,
        schedule_sets.len(),
        &spatial_specs,
    );

    let mut helper_funcs = HashMap::new();
    for (hi, hfn) in mir.fns.iter().enumerate() {
        let sym = format!("strata_fn_{hi}_{}", sanitize_ident(&hfn.name));
        let sig = build_helper_signature(hfn, ptr_ty, call_conv);
        let fid = obj_mod
            .declare_function(&sym, Linkage::Local, &sig)
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        helper_funcs.insert(hfn.name.clone(), (fid, hi));
        if let Some(short) = hfn.name.rsplit("::").next() {
            helper_funcs.entry(short.to_owned()).or_insert((fid, hi));
        }
    }

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
        extern_funcs: HashMap::new(),
        helper_funcs,
        migrations_by_layout: HashMap::new(),
        systems: Vec::new(),
        observers: Vec::new(),
        schedule_sets,
        init_objects_fn: None,
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
                sig.params.push(AbiParam::new(ptr_ty)); // commands
                sig.params.push(AbiParam::new(ptr_ty)); // user_data (state_ptr)
                sig.returns.push(AbiParam::new(types::I32));
                let fid = ctx
                    .obj_mod
                    .declare_function(&sym, Linkage::Local, &sig)
                    .map_err(|e| JitError::Codegen(e.to_string()))?;
                let name_data_id = ctx.intern_cstr(bare_schedule_target(&f.name))?;
                let (event_kind, event_layout_idx) =
                    classify_observer_event(&ctx.layout_map, event);
                let watched_layout_idx = target_comp
                    .as_deref()
                    .and_then(|tc| lookup_name_in_map(&ctx.layout_map, tc));
                ctx.observers.push(ObserverRegistrationEntry {
                    name_data_id,
                    event_layout_idx,
                    event_kind,
                    watched_layout_idx,
                    func_id: fid,
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

    Ok(ctx)
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
            if let Some(&wire_idx) = by_comp.get(&lidx) {
                terms[wire_idx].mode = merge_access_mode(terms[wire_idx].mode, t.mode);
                term_map.push(wire_idx);
            } else {
                let wire_idx = terms.len();
                by_comp.insert(lidx, wire_idx);
                terms.push(WireTermSpec {
                    layout_idx: lidx,
                    mode: t.mode,
                });
                term_map.push(wire_idx);
            }
        }
        let mut with_filters = Vec::new();
        for w in &qb.with_filters {
            if let Some(lidx) = lookup_name_in_map(&ctx.layout_map, w)
                && !by_comp.contains_key(&lidx)
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
        });
    }

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

    // Reserve hidden `MESSAGE_WRITE` query indices for any `StreamEmit` targeting a host stream.
    let mut stream_queries = Vec::new();
    let mut seen_streams = HashSet::new();
    for bb in &f.blocks {
        for s in &bb.stmts {
            if let Inst::StreamEmit { stream, .. } = &s.inst
                && let Some(lidx) = lookup_name_in_map(&ctx.layout_map, stream)
                && seen_streams.insert(lidx)
                && next_q < SYSTEM_QUERY_CAP
            {
                stream_queries.push(StreamQuerySlot {
                    stream_layout_idx: lidx,
                    wire_query_idx: next_q,
                });
                next_q += 1;
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
        Ty::Vec3 | Ty::Vec3a => MirType::Vec3,
        Ty::Vec4 | Ty::Quat | Ty::Rgba => MirType::Vec4,
        Ty::Array { elem, len } => MirType::Array {
            elem: Box::new(mir_type_from_ty(elem)),
            len: *len,
        },
        Ty::Tuple(ts) => MirType::Tuple(ts.iter().map(mir_type_from_ty).collect()),
        Ty::Ref(n) if n == "Entity" => MirType::Entity,
        Ty::Named(n) | Ty::Ref(n) => MirType::Named(n.clone()),
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
            MirType::Vec2 => 8,
            MirType::Vec3 => 12,
            MirType::Vec4 => 16,
            MirType::Array { elem, len } => self.layout_size_of_mir_ty(elem) * (*len),
            MirType::Tuple(ts) => ts.iter().map(|t| self.layout_size_of_mir_ty(t)).sum(),
            MirType::Named(name) => lookup_name_in_map(&self.layout_map, name)
                .map(|i| self.layouts[i].size)
                .unwrap_or(16),
        }
    }

    fn cl_type_for_mir_val(&self, mty: &MirType) -> Type {
        match mty {
            MirType::Ptr
            | MirType::MutPtr
            | MirType::QueryIter
            | MirType::Checkpoint
            | MirType::Named(_)
            | MirType::Array { .. }
            | MirType::Tuple(_) => self.ptr_ty,
            MirType::Vec2 | MirType::Vec3 | MirType::Vec4 => types::F32,
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
            | Ty::SmallVec { .. }
            | Ty::IVec2
            | Ty::IVec3
            | Ty::UVec2 => None,
            Ty::Named(n) if n == "GraceWindow" => Some(MirType::F32),
            Ty::Named(n) => {
                let enum_bytes = lookup_name_ref(&self.enums_by_name, n)
                    .map(|ed| ed.repr_bytes)
                    .or_else(|| {
                        lookup_name_in_map(&self.layout_map, n)
                            .map(|idx| &self.mir_layouts_sorted[idx])
                            .filter(|l| l.item_kind == SchemaItemKind::Enum)
                            .map(|l| l.size)
                    });
                if let Some(sz) = enum_bytes {
                    return Some(match sz {
                        1 => MirType::U8,
                        2 => MirType::U16,
                        4 => MirType::U32,
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

fn define_manifest_data(
    module: &mut ObjectModule,
    name_id: DataId,
    ver_id: DataId,
    ptr_ty: Type,
) -> Result<DataId, JitError> {
    let id = module
        .declare_data("STRATA_JIT_MANIFEST", Linkage::Local, false, false)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let mut raw = vec![0u8; structs::MANIFEST_SIZE];
    write_u32_le(
        &mut raw,
        structs::MANIFEST_STRUCT_SIZE,
        structs::MANIFEST_SIZE as u32,
    );
    write_u32_le(&mut raw, structs::MANIFEST_ABI_VERSION, WIRE_ABI_VERSION);

    let mut desc = DataDescription::new();
    desc.define(raw.into_boxed_slice());
    desc.set_align(if ptr_ty == types::I32 { 4 } else { 8 });
    let name_gv = module.declare_data_in_data(name_id, &mut desc);
    desc.write_data_addr(structs::MANIFEST_NAME as u32, name_gv, 0);
    let ver_gv = module.declare_data_in_data(ver_id, &mut desc);
    desc.write_data_addr(structs::MANIFEST_VERSION as u32, ver_gv, 0);

    module
        .define_data(id, &desc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    Ok(id)
}

fn define_layout_rodata(
    module: &mut ObjectModule,
    idx: usize,
    layout: &SolvedLayout,
    required_indices: Vec<usize>,
    mir: &MirModule,
    ptr_bytes: usize,
) -> Result<LayoutMetaData, JitError> {
    let ident = sanitize_ident(&layout.canonical_name);
    let name_cstr_id = define_cstring_on(
        module,
        &format!("strata_cname_{idx}_{ident}"),
        &layout.canonical_name,
    )?;

    let fields_data_id = if layout.fields.is_empty() {
        None
    } else {
        let mut fnames = Vec::with_capacity(layout.fields.len());
        let mut ftags = Vec::with_capacity(layout.fields.len());
        for (fi, f) in layout.fields.iter().enumerate() {
            fnames.push(define_cstring_on(
                module,
                &format!("strata_fn_{idx}_{fi}_{ident}"),
                &f.name,
            )?);
            ftags.push(define_cstring_on(
                module,
                &format!("strata_ft_{idx}_{fi}_{ident}"),
                &f.type_tag,
            )?);
        }

        let arr_bytes = layout.fields.len() * structs::FIELD_DESC_SIZE;
        let mut arr = vec![0u8; arr_bytes];
        for (fi, f) in layout.fields.iter().enumerate() {
            let base = fi * structs::FIELD_DESC_SIZE;
            write_u32_le(
                &mut arr,
                base + structs::FIELD_STRUCT_SIZE,
                structs::FIELD_DESC_SIZE as u32,
            );
            write_u32_le(&mut arr, base + structs::FIELD_KIND, f.bam_field_kind);
            write_usize_le(
                &mut arr,
                base + structs::FIELD_NAME + structs::STRVIEW_LEN,
                f.name.len(),
                ptr_bytes,
            );
            write_usize_le(
                &mut arr,
                base + structs::FIELD_TYPE_TAG + structs::STRVIEW_LEN,
                f.type_tag.len(),
                ptr_bytes,
            );
            write_usize_le(&mut arr, base + structs::FIELD_OFFSET, f.offset, ptr_bytes);
            write_usize_le(&mut arr, base + structs::FIELD_SIZE, f.size, ptr_bytes);
            write_usize_le(&mut arr, base + structs::FIELD_ALIGN, f.align, ptr_bytes);
        }

        let f_id = module
            .declare_data(
                &format!("strata_fields_{idx}_{ident}"),
                Linkage::Local,
                false,
                false,
            )
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        let mut f_desc = DataDescription::new();
        f_desc.define(arr.into_boxed_slice());
        f_desc.set_align(8);
        for (fi, (&fn_id, &ft_id)) in fnames.iter().zip(ftags.iter()).enumerate() {
            let base = fi * structs::FIELD_DESC_SIZE;
            let fn_gv = module.declare_data_in_data(fn_id, &mut f_desc);
            f_desc.write_data_addr(
                (base + structs::FIELD_NAME + structs::STRVIEW_PTR) as u32,
                fn_gv,
                0,
            );
            let ft_gv = module.declare_data_in_data(ft_id, &mut f_desc);
            f_desc.write_data_addr(
                (base + structs::FIELD_TYPE_TAG + structs::STRVIEW_PTR) as u32,
                ft_gv,
                0,
            );
        }
        module
            .define_data(f_id, &f_desc)
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        Some(f_id)
    };

    let mut cbytes = vec![0u8; structs::COMPONENT_DESC_SIZE];
    write_u32_le(
        &mut cbytes,
        structs::COMP_STRUCT_SIZE,
        structs::COMPONENT_DESC_SIZE as u32,
    );
    write_u32_le(
        &mut cbytes,
        structs::COMP_FLAGS,
        layout.component_flags & crate::abi_offsets::COMPONENT_KNOWN_FLAGS,
    );
    cbytes[structs::COMP_UUID..structs::COMP_UUID + 16].copy_from_slice(&layout.uuid_bytes);
    write_usize_le(&mut cbytes, structs::COMP_SIZE, layout.size, ptr_bytes);
    write_usize_le(
        &mut cbytes,
        structs::COMP_ALIGN,
        layout.align.max(1),
        ptr_bytes,
    );
    write_u64_le(
        &mut cbytes,
        structs::COMP_SCHEMA_FINGERPRINT,
        layout.schema_fingerprint,
    );
    if !layout.fields.is_empty() {
        write_usize_le(
            &mut cbytes,
            structs::COMP_FIELD_COUNT,
            layout.fields.len(),
            ptr_bytes,
        );
    }

    let comp_desc_id = module
        .declare_data(
            &format!("strata_cdesc_{idx}_{ident}"),
            Linkage::Local,
            false,
            false,
        )
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut cdesc = DataDescription::new();
    cdesc.define(cbytes.into_boxed_slice());
    cdesc.set_align(8);
    let name_gv = module.declare_data_in_data(name_cstr_id, &mut cdesc);
    cdesc.write_data_addr(structs::COMP_NAME as u32, name_gv, 0);
    if let Some(f_id) = fields_data_id {
        let fields_gv = module.declare_data_in_data(f_id, &mut cdesc);
        cdesc.write_data_addr(structs::COMP_FIELDS as u32, fields_gv, 0);
    }
    module
        .define_data(comp_desc_id, &cdesc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let default_blob_id = if layout.size > 0
        && let Some(defaults) = mir.field_defaults.get(&layout.canonical_name).or_else(|| {
            layout
                .canonical_name
                .rsplit("::")
                .next()
                .and_then(|s| mir.field_defaults.get(s))
        }) {
        let mut blob = vec![0u8; layout.size];
        for (fname, cval) in defaults {
            if let Some(sf) = layout.fields.iter().find(|f| f.name == *fname) {
                write_const_val_to_buf(&mut blob, sf, cval);
            }
        }
        let bid = module
            .declare_anonymous_data(false, false)
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        let mut bd = DataDescription::new();
        bd.define(blob.into_boxed_slice());
        bd.set_align(layout.align.max(1) as u64);
        module
            .define_data(bid, &bd)
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        Some(bid)
    } else {
        None
    };

    let is_resource = matches!(
        layout.item_kind,
        SchemaItemKind::Resource | SchemaItemKind::SpatialGrid | SchemaItemKind::SpatialHistory
    );
    let is_stream = layout.item_kind == SchemaItemKind::Stream;

    Ok(LayoutMetaData {
        is_ecs_component: is_ecs_component_kind(layout.item_kind),
        is_resource,
        is_stream,
        size: layout.size,
        align: layout.align.max(1),
        required_indices,
        name_cstr_id,
        comp_desc_id,
        default_blob_id,
        mod_res_offset: 0,
    })
}

fn write_const_val_to_buf(buf: &mut [u8], field: &SolvedField, cval: &MirConstVal) {
    let off = field.offset;
    let sz = field.size;
    if off + sz > buf.len() {
        return;
    }
    match cval {
        MirConstVal::Bool(v) => {
            if sz >= 1 {
                buf[off] = u8::from(*v);
            }
        }
        MirConstVal::Int(v) => match sz {
            1 => buf[off] = *v as u8,
            2 => buf[off..off + 2].copy_from_slice(&(*v as i16).to_le_bytes()),
            4 => buf[off..off + 4].copy_from_slice(&(*v as i32).to_le_bytes()),
            8 => buf[off..off + 8].copy_from_slice(&v.to_le_bytes()),
            _ => {}
        },
        MirConstVal::Float(v) => match field.ty {
            Ty::F64 => {
                if sz >= 8 {
                    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
                }
            }
            Ty::Fix32 => {
                if sz >= 4 {
                    let q = (*v * 65536.0).round() as i32;
                    buf[off..off + 4].copy_from_slice(&q.to_le_bytes());
                }
            }
            Ty::Fix64 => {
                if sz >= 8 {
                    let q = (*v * 4_294_967_296.0).round() as i64;
                    buf[off..off + 8].copy_from_slice(&q.to_le_bytes());
                }
            }
            _ => {
                if sz >= 4 {
                    buf[off..off + 4].copy_from_slice(&(*v as f32).to_le_bytes());
                }
            }
        },
        MirConstVal::Vec2(v) => {
            if sz >= 8 {
                buf[off..off + 4].copy_from_slice(&(v[0] as f32).to_le_bytes());
                buf[off + 4..off + 8].copy_from_slice(&(v[1] as f32).to_le_bytes());
            }
        }
        MirConstVal::Vec3(v) => {
            if sz >= 12 {
                buf[off..off + 4].copy_from_slice(&(v[0] as f32).to_le_bytes());
                buf[off + 4..off + 8].copy_from_slice(&(v[1] as f32).to_le_bytes());
                buf[off + 8..off + 12].copy_from_slice(&(v[2] as f32).to_le_bytes());
            }
        }
        MirConstVal::Vec4(v) => {
            if sz >= 16 {
                for i in 0..4 {
                    buf[off + i * 4..off + (i + 1) * 4]
                        .copy_from_slice(&(v[i] as f32).to_le_bytes());
                }
            }
        }
        MirConstVal::Unit
        | MirConstVal::Struct { .. }
        | MirConstVal::String(_)
        | MirConstVal::Array(_) => {}
    }
}

fn define_relation_rodata(
    module: &mut ObjectModule,
    idx: usize,
    rel: &HirRelation,
    ptr_bytes: usize,
) -> Result<RelationMetaData, JitError> {
    let ident = sanitize_ident(&rel.canonical_name);
    let name_cstr_id = define_cstring_on(
        module,
        &format!("strata_rel_name_{idx}_{ident}"),
        &rel.canonical_name,
    )?;
    let (data_size, data_align, uuid) = if let Some(ref pl) = rel.payload_layout {
        (pl.size, pl.align.max(1), pl.uuid_bytes)
    } else {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in rel.canonical_name.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        let mut u = [0u8; 16];
        u[0..8].copy_from_slice(&h.to_le_bytes());
        u[8..16].copy_from_slice(&(!h).to_le_bytes());
        (0, 1, u)
    };

    let mut flags = 0u32;
    for f in &rel.flags {
        match f.as_str() {
            "exclusive" => flags |= RELATION_FLAG_EXCLUSIVE,
            "cascade_despawn" | "cascade_delete" => flags |= RELATION_FLAG_CASCADE_DESPAWN,
            "symmetric" => flags |= RELATION_FLAG_SYMMETRIC,
            "acyclic" => flags |= RELATION_FLAG_ACYCLIC,
            "cleanup_remove" => flags |= RELATION_FLAG_CLEANUP_REMOVE,
            _ => {}
        }
    }

    let mut bytes = vec![0u8; structs::RELATION_DESC_SIZE];
    write_u32_le(
        &mut bytes,
        structs::REL_STRUCT_SIZE,
        structs::RELATION_DESC_SIZE as u32,
    );
    write_u32_le(&mut bytes, structs::REL_FLAGS, flags);
    bytes[structs::REL_UUID..structs::REL_UUID + 16].copy_from_slice(&uuid);
    write_usize_le(&mut bytes, structs::REL_DATA_SIZE, data_size, ptr_bytes);
    write_usize_le(&mut bytes, structs::REL_DATA_ALIGN, data_align, ptr_bytes);
    write_u32_le(&mut bytes, structs::REL_MAX_DEGREE, 0);

    let desc_id = module
        .declare_data(
            &format!("strata_rel_desc_{idx}_{ident}"),
            Linkage::Local,
            false,
            false,
        )
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut rdesc = DataDescription::new();
    rdesc.define(bytes.into_boxed_slice());
    rdesc.set_align(8);
    let ngv = module.declare_data_in_data(name_cstr_id, &mut rdesc);
    rdesc.write_data_addr(structs::REL_NAME as u32, ngv, 0);
    module
        .define_data(desc_id, &rdesc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    Ok(RelationMetaData {
        payload_size: data_size,
        desc_id,
    })
}

fn eval_const_hir_expr(
    expr: &HirExpr,
    enums: &HashMap<String, EnumDef>,
    consts: &HashMap<String, HirConst>,
) -> Option<MirConstVal> {
    match expr {
        HirExpr::BoolLit(b) => Some(MirConstVal::Bool(*b)),
        HirExpr::IntLit { value, .. } => Some(MirConstVal::Int(*value)),
        HirExpr::FloatLit { value, .. } => Some(MirConstVal::Float(*value)),
        HirExpr::Path { name, .. } => {
            if let Some(c) = consts
                .get(name)
                .or_else(|| name.rsplit("::").next().and_then(|s| consts.get(s)))
                && let Some(ref c_expr) = c.expr
            {
                return eval_const_hir_expr(c_expr, enums, consts);
            }
            if let Some((enum_n, var_n)) = name.rsplit_once("::")
                && let Some(ed) = enums.get(enum_n)
                && let Some((_, d)) = ed.variants.iter().find(|(v, _)| v == var_n)
            {
                return Some(MirConstVal::Int(*d));
            }
            None
        }
        HirExpr::Unary {
            op, expr: inner, ..
        } => match (op, eval_const_hir_expr(inner, enums, consts)?) {
            (HirUnOp::Neg, MirConstVal::Int(i)) => Some(MirConstVal::Int(-i)),
            (HirUnOp::Neg, MirConstVal::Float(f)) => Some(MirConstVal::Float(-f)),
            (HirUnOp::Not, MirConstVal::Bool(b)) => Some(MirConstVal::Bool(!b)),
            _ => None,
        },
        HirExpr::Binary { op, lhs, rhs, .. } => {
            let l = eval_const_hir_expr(lhs, enums, consts)?;
            let r = eval_const_hir_expr(rhs, enums, consts)?;
            match (l, r) {
                (MirConstVal::Float(a), MirConstVal::Float(b)) => match op {
                    HirBinOp::Add => Some(MirConstVal::Float(a + b)),
                    HirBinOp::Sub => Some(MirConstVal::Float(a - b)),
                    HirBinOp::Mul => Some(MirConstVal::Float(a * b)),
                    HirBinOp::Div if b != 0.0 => Some(MirConstVal::Float(a / b)),
                    _ => None,
                },
                (MirConstVal::Int(a), MirConstVal::Int(b)) => match op {
                    HirBinOp::Add => Some(MirConstVal::Int(a + b)),
                    HirBinOp::Sub => Some(MirConstVal::Int(a - b)),
                    HirBinOp::Mul => Some(MirConstVal::Int(a * b)),
                    HirBinOp::Div if b != 0 => Some(MirConstVal::Int(a / b)),
                    _ => None,
                },
                _ => None,
            }
        }
        HirExpr::Cast {
            expr: inner,
            target_ty,
        } => {
            let v = eval_const_hir_expr(inner, enums, consts)?;
            match (v, target_ty) {
                (MirConstVal::Int(i), Ty::F32 | Ty::F64 | Ty::UnitScalar { .. }) => {
                    Some(MirConstVal::Float(i as f64))
                }
                (
                    MirConstVal::Float(f),
                    Ty::I8 | Ty::I16 | Ty::I32 | Ty::I64 | Ty::U8 | Ty::U16 | Ty::U32 | Ty::U64,
                ) => Some(MirConstVal::Int(f as i64)),
                (other, _) => Some(other),
            }
        }
        HirExpr::Call(HirCall { callee, args, .. }) => {
            let vals: Vec<f64> = args
                .iter()
                .filter_map(|a| match eval_const_hir_expr(a, enums, consts)? {
                    MirConstVal::Float(f) => Some(f),
                    MirConstVal::Int(i) => Some(i as f64),
                    _ => None,
                })
                .collect();
            match callee.rsplit("::").next().unwrap_or(callee) {
                "vec2" if vals.len() >= 2 => Some(MirConstVal::Vec2([vals[0], vals[1]])),
                "vec3" if vals.len() >= 3 => Some(MirConstVal::Vec3([vals[0], vals[1], vals[2]])),
                "vec4" if vals.len() >= 4 => {
                    Some(MirConstVal::Vec4([vals[0], vals[1], vals[2], vals[3]]))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn define_table_rodata(
    module: &mut ObjectModule,
    idx: usize,
    table: &HirTable,
    enums: &HashMap<String, EnumDef>,
    consts: &HashMap<String, HirConst>,
    ptr_bytes: usize,
) -> Result<TableRodata, JitError> {
    let mut fields = HashMap::new();
    let mut cursor = 0usize;
    let mut ordered_fields = Vec::with_capacity(table.fields.len());
    for (fname, fty) in &table.fields {
        let mty = mir_type_from_ty(fty);
        let (sz, al) = match mty {
            MirType::Bool | MirType::U8 | MirType::I8 => (1, 1),
            MirType::U16 | MirType::I16 => (2, 2),
            MirType::U32 | MirType::I32 | MirType::F32 | MirType::Sym | MirType::Fix32 => (4, 4),
            MirType::U64 | MirType::I64 | MirType::F64 | MirType::Fix64 | MirType::Entity => (8, 8),
            MirType::Vec2 => (8, 4),
            MirType::Vec3 => (12, 4),
            MirType::Vec4 => (16, 4),
            _ => (ptr_bytes.max(8), 8),
        };
        cursor = align_up(cursor, al);
        fields.insert(fname.clone(), (cursor, mty.clone()));
        ordered_fields.push((fname.clone(), cursor, sz, fty.clone()));
        cursor += sz;
    }
    let row_stride = align_up(cursor.max(8), 8);
    let enum_def = enums.get(&table.key_enum);
    let mut max_idx = table.typed_rows.len().max(table.rows.len());
    if let Some(ed) = enum_def {
        for (_, d) in &ed.variants {
            if *d >= 0 {
                max_idx = max_idx.max(*d as usize + 1);
            }
        }
    }
    let row_count = max_idx.max(1);
    let mut bytes = vec![0u8; row_count * row_stride];

    for (ri, (vname, fexprs)) in table.typed_rows.iter().enumerate() {
        let row_idx = enum_def
            .and_then(|ed| {
                ed.variants
                    .iter()
                    .find(|(v, _)| v == vname)
                    .map(|(_, d)| *d as usize)
            })
            .unwrap_or(ri);
        if row_idx >= row_count {
            continue;
        }
        let base = row_idx * row_stride;
        for (fname, fexpr) in fexprs {
            if let Some((_, off, sz, fty)) = ordered_fields.iter().find(|(n, _, _, _)| n == fname)
                && let Some(cval) = eval_const_hir_expr(fexpr, enums, consts)
            {
                let sf = SolvedField {
                    name: fname.clone(),
                    ty: fty.clone(),
                    offset: *off,
                    size: *sz,
                    align: 4,
                    is_padding: false,
                    bam_field_kind: 0,
                    type_tag: String::new(),
                };
                write_const_val_to_buf(&mut bytes[base..base + row_stride], &sf, &cval);
            }
        }
    }

    let data_id = module
        .declare_data(
            &format!("strata_tbl_{idx}_{}", sanitize_ident(&table.name)),
            Linkage::Local,
            false,
            false,
        )
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut desc = DataDescription::new();
    desc.define(bytes.into_boxed_slice());
    desc.set_align(8);
    module
        .define_data(data_id, &desc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    Ok(TableRodata {
        data_id,
        row_count,
        row_stride,
        fields,
    })
}

fn define_curve_rodata(
    module: &mut ObjectModule,
    idx: usize,
    curve: &HirCurve,
) -> Result<CurveRodata, JitError> {
    let mut pts = curve.points.clone();
    pts.sort_by(|a, b| a.0.total_cmp(&b.0));
    let mut bytes = Vec::with_capacity(pts.len().max(1) * 8);
    if pts.is_empty() {
        bytes.extend_from_slice(&0.0f32.to_le_bytes());
        bytes.extend_from_slice(&0.0f32.to_le_bytes());
    } else {
        for (x, y) in &pts {
            bytes.extend_from_slice(&(*x as f32).to_le_bytes());
            bytes.extend_from_slice(&(*y as f32).to_le_bytes());
        }
    }
    let data_id = module
        .declare_data(
            &format!("strata_crv_{idx}_{}", sanitize_ident(&curve.name)),
            Linkage::Local,
            false,
            false,
        )
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut desc = DataDescription::new();
    desc.define(bytes.into_boxed_slice());
    desc.set_align(4);
    module
        .define_data(data_id, &desc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    Ok(CurveRodata {
        data_id,
        points_len: pts.len(),
    })
}

fn build_helper_signature(hfn: &MirFunction, ptr_ty: Type, cc: CallConv) -> Signature {
    let mut sig = Signature::new(cc);
    sig.params.push(AbiParam::new(ptr_ty)); // state_ptr
    for p in &hfn.params {
        push_abi_params_for_mir_type(&mut sig.params, &p.ty, ptr_ty);
    }
    push_abi_params_for_mir_type(&mut sig.returns, &hfn.ret_ty, ptr_ty);
    sig
}

fn push_abi_params_for_mir_type(out: &mut Vec<AbiParam>, ty: &MirType, ptr_ty: Type) {
    match ty {
        MirType::Unit => {}
        MirType::Vec2 => {
            out.push(AbiParam::new(types::F32));
            out.push(AbiParam::new(types::F32));
        }
        MirType::Vec3 => {
            out.push(AbiParam::new(types::F32));
            out.push(AbiParam::new(types::F32));
            out.push(AbiParam::new(types::F32));
        }
        MirType::Vec4 => {
            for _ in 0..4 {
                out.push(AbiParam::new(types::F32));
            }
        }
        MirType::Bool | MirType::U8 | MirType::I8 => out.push(AbiParam::new(types::I8)),
        MirType::U16 | MirType::I16 => out.push(AbiParam::new(types::I16)),
        MirType::U32 | MirType::I32 | MirType::Sym | MirType::Fix32 => {
            out.push(AbiParam::new(types::I32))
        }
        MirType::U64 | MirType::I64 | MirType::Fix64 | MirType::Entity => {
            out.push(AbiParam::new(types::I64))
        }
        MirType::F32 => out.push(AbiParam::new(types::F32)),
        MirType::F64 => out.push(AbiParam::new(types::F64)),
        _ => out.push(AbiParam::new(ptr_ty)),
    }
}

fn emit_all_helpers(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    for hi in 0..ctx.mir.fns.len() {
        let hfn = &ctx.mir.fns[hi];
        let (fid, _) = ctx.helper_funcs[&hfn.name];
        emit_mir_function_body(ctx, hfn, fid, MirCallbackMode::Helper, None)?;
    }
    Ok(())
}

fn emit_all_migrations(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    let items: Vec<(usize, FuncId)> = ctx
        .mir
        .functions
        .iter()
        .enumerate()
        .filter_map(|(fi, f)| {
            if let MirFnKind::Migration { component, .. } = &f.kind {
                let lidx = lookup_name_in_map(&ctx.layout_map, component)?;
                let fid = *ctx.migrations_by_layout.get(&lidx)?;
                Some((fi, fid))
            } else {
                None
            }
        })
        .collect();
    for (fi, fid) in items {
        let f = &ctx.mir.functions[fi];
        emit_mir_function_body(ctx, f, fid, MirCallbackMode::Migration, None)?;
    }
    Ok(())
}

fn emit_all_observers(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    let mut obs_idx = 0usize;
    for fi in 0..ctx.mir.functions.len() {
        let f = &ctx.mir.functions[fi];
        if matches!(f.kind, MirFnKind::Observer { .. }) {
            let fid = ctx.observers[obs_idx].func_id;
            emit_mir_function_body(ctx, f, fid, MirCallbackMode::Observer, None)?;
            obs_idx += 1;
        }
    }
    Ok(())
}

fn emit_all_systems(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    let count = ctx.systems.len();
    for si in 0..count {
        let entry = ctx.systems[si].clone();
        let f = &ctx.mir.functions[entry.fn_idx];
        emit_mir_function_body(ctx, f, entry.func_id, MirCallbackMode::System, Some(&entry))?;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MirCallbackMode {
    System,
    Observer,
    Migration,
    Helper,
}

#[derive(Clone)]
enum LocalRep {
    Scalar(Variable),
    Vec([Variable; 4]),
    AggVar(Variable),
}

struct StrengthPlan {
    /// `(row_slot_local, base_ptr_local) -> (stride_bytes, ptr_var, is_indirect_entities)`
    reduced: HashMap<(u32, u32), (u32, Variable, bool)>,
    /// `row_slot_local -> Vec<(base_ptr_local, stride_bytes, ptr_var)>`
    by_slot: HashMap<u32, Vec<(u32, u32, Variable)>>,
    /// `base_ptr_local -> Vec<ptr_var>`
    by_base: HashMap<u32, Vec<Variable>>,
    /// Literal `0` locals and `(base_slot + 1)` increment locals detected for `row_slot`.
    zero_locals: HashSet<u32>,
    /// `step_val_local -> row_slot_local` where `step = SlotLoad(row_slot) + 1`.
    step_inc_map: HashMap<u32, u32>,
}

fn analyze_strength_reduction(
    func: &MirFunction,
    b: &mut FunctionBuilder<'_>,
    ptr_ty: Type,
) -> StrengthPlan {
    let mut zero_locals = HashSet::new();
    let mut one_locals = HashSet::new();
    let mut slot_loads: HashMap<u32, u32> = HashMap::new(); // loaded_local -> slot_local
    let mut add_one_locals: HashMap<u32, u32> = HashMap::new(); // sum_local -> loaded_local
    let mut def_block: HashMap<u32, usize> = HashMap::new();

    for (bi, bb) in func.blocks.iter().enumerate() {
        for s in &bb.stmts {
            if let Some(dst) = s.dst {
                def_block.insert(dst.0, bi);
                match &s.inst {
                    Inst::ConstInt { value: 0 } => {
                        zero_locals.insert(dst.0);
                    }
                    Inst::ConstInt { value: 1 } => {
                        one_locals.insert(dst.0);
                    }
                    Inst::SlotLoad { slot } => {
                        slot_loads.insert(dst.0, slot.0);
                    }
                    Inst::BinOp { op, lhs, rhs, .. } if op == "+" => {
                        if one_locals.contains(&rhs.0)
                            && let Some(&sl) = slot_loads.get(&lhs.0)
                        {
                            add_one_locals.insert(dst.0, sl);
                        } else if one_locals.contains(&lhs.0)
                            && let Some(&sl) = slot_loads.get(&rhs.0)
                        {
                            add_one_locals.insert(dst.0, sl);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Check which SlotAlloc locals ONLY receive `0` or `SlotLoad(slot) + 1`.
    let mut clean_slots = HashSet::new();
    let mut non_clean_slots = HashSet::new();
    for bb in &func.blocks {
        for s in &bb.stmts {
            if let Inst::SlotStore { slot, val } = &s.inst {
                let ok =
                    zero_locals.contains(&val.0) || add_one_locals.get(&val.0) == Some(&slot.0);
                if ok {
                    clean_slots.insert(slot.0);
                } else {
                    non_clean_slots.insert(slot.0);
                }
            }
        }
    }
    for bad in &non_clean_slots {
        clean_slots.remove(bad);
    }

    // Collect `IterColRead` / `IterColWrite` / `IterColWriteUntracked` / `IterEntities` base locals
    // that are computed outside the row-loop blocks (never redefined across steps without resetting slot 0).
    let mut base_kinds: HashMap<u32, bool> = HashMap::new(); // local -> is_entities_array
    for bb in &func.blocks {
        for s in &bb.stmts {
            if let Some(dst) = s.dst {
                match s.inst {
                    Inst::IterColRead { .. }
                    | Inst::IterColWrite { .. }
                    | Inst::IterColWriteUntracked { .. } => {
                        base_kinds.insert(dst.0, false);
                    }
                    Inst::IterEntities { .. } => {
                        base_kinds.insert(dst.0, true);
                    }
                    _ => {}
                }
            }
        }
    }

    let mut reduced: HashMap<(u32, u32), (u32, Variable, bool)> = HashMap::new();
    let mut by_slot: HashMap<u32, Vec<(u32, u32, Variable)>> = HashMap::new();
    let mut by_base: HashMap<u32, Vec<Variable>> = HashMap::new();

    for bb in &func.blocks {
        for s in &bb.stmts {
            match s.inst {
                Inst::RowPtr {
                    col_ptr,
                    row_idx,
                    stride_bytes,
                    is_sparse: false,
                } if stride_bytes > 0 => {
                    if let Some(&slot_id) = slot_loads.get(&row_idx.0)
                        && clean_slots.contains(&slot_id)
                        && base_kinds.get(&col_ptr.0) == Some(&false)
                    {
                        reduced.entry((slot_id, col_ptr.0)).or_insert_with(|| {
                            let var = b.declare_var(ptr_ty);
                            by_slot.entry(slot_id).or_default().push((
                                col_ptr.0,
                                stride_bytes,
                                var,
                            ));
                            by_base.entry(col_ptr.0).or_default().push(var);
                            (stride_bytes, var, false)
                        });
                    }
                }
                Inst::EntityAtRow {
                    entities_ptr,
                    row_idx,
                } => {
                    if let Some(&slot_id) = slot_loads.get(&row_idx.0)
                        && clean_slots.contains(&slot_id)
                        && base_kinds.get(&entities_ptr.0) == Some(&true)
                    {
                        reduced.entry((slot_id, entities_ptr.0)).or_insert_with(|| {
                            let var = b.declare_var(ptr_ty);
                            by_slot
                                .entry(slot_id)
                                .or_default()
                                .push((entities_ptr.0, 8, var));
                            by_base.entry(entities_ptr.0).or_default().push(var);
                            (8, var, true)
                        });
                    }
                }
                _ => {}
            }
        }
    }

    StrengthPlan {
        reduced,
        by_slot,
        by_base,
        zero_locals,
        step_inc_map: add_one_locals,
    }
}

struct ParSubCfgInfo {
    query_idx: u32,
    is_readonly: bool,
    chunk_hdr_bb: usize,
    chunk_exit_bb: usize,
    sub_blocks: Vec<usize>,
    live_in_locals: Vec<u32>,
}

fn find_par_subcfg_info(
    func: &MirFunction,
    par_stmt_bb: usize,
    query_idx: u32,
    is_readonly: bool,
    deterministic_order: bool,
) -> Option<ParSubCfgInfo> {
    if is_readonly && deterministic_order {
        return None;
    }
    let chunk_hdr_bb = match func.blocks[par_stmt_bb].terminator {
        Terminator::Goto(b) => b.0 as usize,
        _ => return None,
    };
    let (then_bb, else_bb) = match func.blocks.get(chunk_hdr_bb)?.terminator {
        Terminator::Branch {
            then_bb, else_bb, ..
        } => (then_bb.0 as usize, else_bb.0 as usize),
        _ => return None,
    };

    // Walk reachable blocks starting at `then_bb` stopping at `chunk_hdr_bb` or `else_bb`.
    let mut visited = HashSet::new();
    let mut queue = vec![then_bb];
    let mut sub_blocks = Vec::new();
    visited.insert(chunk_hdr_bb);
    while let Some(bi) = queue.pop() {
        if bi == else_bb || !visited.insert(bi) {
            continue;
        }
        sub_blocks.push(bi);
        match &func.blocks[bi].terminator {
            Terminator::Goto(dst) => queue.push(dst.0 as usize),
            Terminator::Branch {
                then_bb: a,
                else_bb: b,
                ..
            } => {
                queue.push(a.0 as usize);
                queue.push(b.0 as usize);
            }
            Terminator::Switch {
                cases, default_bb, ..
            } => {
                for (_, c) in cases {
                    queue.push(c.0 as usize);
                }
                queue.push(default_bb.0 as usize);
            }
            Terminator::Return(_) => return None,
        }
    }
    sub_blocks.insert(0, chunk_hdr_bb);
    let sub_set: HashSet<usize> = sub_blocks.iter().copied().collect();

    // Reject if sub-CFG uses commands, host EntityGet, writes outer slots, or defines values used outside.
    let mut defined_inside = HashSet::new();
    let mut allocs_inside = HashSet::new();
    for &bi in &sub_blocks {
        for s in &func.blocks[bi].stmts {
            if let Some(d) = s.dst {
                defined_inside.insert(d.0);
                if matches!(s.inst, Inst::SlotAlloc { .. }) {
                    allocs_inside.insert(d.0);
                }
            }
            match &s.inst {
                Inst::CmdSpawn { .. }
                | Inst::CmdSpawnBatch { .. }
                | Inst::SpawnBatchBegin { .. }
                | Inst::SpawnBatchPush { .. }
                | Inst::SpawnBatchCommit { .. }
                | Inst::CmdDespawn { .. }
                | Inst::CmdDespawnAll { .. }
                | Inst::CmdInsert { .. }
                | Inst::CmdRemove { .. }
                | Inst::CmdTrigger { .. }
                | Inst::StreamEmit { .. }
                | Inst::CmdCheckpoint
                | Inst::CmdRollback { .. }
                | Inst::CmdInsertRelation { .. }
                | Inst::CmdRemoveRelation { .. }
                | Inst::EntityGet { .. }
                | Inst::EntityGetMut { .. }
                | Inst::ResolveNamedObject { .. }
                | Inst::BindNamedObject { .. }
                | Inst::ReduceInit { .. }
                | Inst::ReduceAccum { .. }
                | Inst::DirtyRunInit { .. }
                | Inst::DirtyRunRecordRow { .. }
                | Inst::ParForEachChunk { .. }
                | Inst::ParForEachChunkReadonly { .. }
                | Inst::SpatialRebuildCsr { .. }
                | Inst::SpatialQueryDisc { .. }
                | Inst::SpatialQuerySegmentAt { .. } => return None,
                Inst::SlotStore { slot, .. } if !allocs_inside.contains(&slot.0) => return None,
                _ => {}
            }
        }
    }

    let mut used_inside = Vec::new();
    let mut used_seen = HashSet::new();
    for &bi in &sub_blocks {
        for s in &func.blocks[bi].stmts {
            for r in inst_read_locals(&s.inst) {
                if !defined_inside.contains(&r) && used_seen.insert(r) {
                    if matches!(
                        func.locals[r as usize].ty,
                        MirType::Named(_)
                            | MirType::Array { .. }
                            | MirType::Tuple(_)
                            | MirType::QueryIter
                    ) {
                        return None;
                    }
                    used_inside.push(r);
                }
            }
        }
        for r in term_read_locals(&func.blocks[bi].terminator) {
            if !defined_inside.contains(&r) && used_seen.insert(r) {
                used_inside.push(r);
            }
        }
    }

    // Verify nothing outside `sub_set` reads anything `defined_inside`.
    for (bi, bb) in func.blocks.iter().enumerate() {
        if sub_set.contains(&bi) {
            continue;
        }
        for s in &bb.stmts {
            for r in inst_read_locals(&s.inst) {
                if defined_inside.contains(&r) {
                    return None;
                }
            }
        }
        for r in term_read_locals(&bb.terminator) {
            if defined_inside.contains(&r) {
                return None;
            }
        }
    }

    Some(ParSubCfgInfo {
        query_idx,
        is_readonly,
        chunk_hdr_bb,
        chunk_exit_bb: else_bb,
        sub_blocks,
        live_in_locals: used_inside,
    })
}

fn inst_read_locals(inst: &Inst) -> Vec<u32> {
    let mut out = Vec::new();
    match inst {
        Inst::Copy { val }
        | Inst::SlotLoad { slot: val }
        | Inst::UnOp { val, .. }
        | Inst::Cast { val, .. }
        | Inst::VecExtract { vec: val, .. }
        | Inst::VecSwizzle { vec: val, .. }
        | Inst::FieldPtr { base_ptr: val, .. }
        | Inst::FieldLoad { base_ptr: val, .. }
        | Inst::OptionalChunkIsPresent { slice_ptr: val, .. }
        | Inst::CurveSample { x: val, .. }
        | Inst::TableLoad { key: val, .. } => out.push(val.0),
        Inst::SlotStore { slot, val } => {
            out.push(slot.0);
            out.push(val.0);
        }
        Inst::BinOp { lhs, rhs, .. }
        | Inst::VecInsert {
            vec: lhs, val: rhs, ..
        }
        | Inst::ArrayIndex {
            base: lhs,
            index: rhs,
        }
        | Inst::FieldStore {
            base_ptr: lhs,
            val: rhs,
            ..
        }
        | Inst::RowPtr {
            col_ptr: lhs,
            row_idx: rhs,
            ..
        }
        | Inst::EntityAtRow {
            entities_ptr: lhs,
            row_idx: rhs,
        }
        | Inst::GraceArm {
            ptr: lhs,
            duration_sec: rhs,
        }
        | Inst::GraceTick {
            ptr: lhs,
            dt_sec: rhs,
        }
        | Inst::InputBufTick {
            ptr: lhs,
            dt_sec: rhs,
            ..
        } => {
            out.push(lhs.0);
            out.push(rhs.0);
        }
        Inst::GraceIsActive { ptr }
        | Inst::GraceClear { ptr }
        | Inst::TimelineInWindow { ptr, .. } => {
            out.push(ptr.0);
        }
        Inst::TimelineAdvance {
            cursor_ptr, dt_sec, ..
        } => {
            out.push(cursor_ptr.0);
            out.push(dt_sec.0);
        }
        Inst::InputBufPush {
            ptr,
            action_id,
            window_sec,
            ..
        } => {
            out.push(ptr.0);
            out.push(action_id.0);
            out.push(window_sec.0);
        }
        Inst::InputBufConsume { ptr, action_id, .. }
        | Inst::InputBufPeek { ptr, action_id, .. }
        | Inst::BitSetSet {
            ptr,
            bit: action_id,
            ..
        }
        | Inst::BitSetGet {
            ptr,
            bit: action_id,
            ..
        }
        | Inst::BitSetClear {
            ptr,
            bit: action_id,
            ..
        } => {
            out.push(ptr.0);
            out.push(action_id.0);
        }
        Inst::IntrinsicMath { args, .. }
        | Inst::Call { args, .. }
        | Inst::ArrayInit { elems: args } => {
            for a in args {
                out.push(a.0);
            }
        }
        Inst::StructInit { fields, .. } => {
            for (_, v) in fields {
                out.push(v.0);
            }
        }
        Inst::SpawnBatchBegin { count, .. } => {
            out.push(count.0);
        }
        Inst::SpawnBatchPush {
            batch,
            index,
            components,
        } => {
            out.push(batch.0);
            out.push(index.0);
            for (_, v) in components {
                out.push(v.0);
            }
        }
        Inst::SpawnBatchCommit { batch } => {
            out.push(batch.0);
        }
        _ => {}
    }
    out
}

fn term_read_locals(term: &Terminator) -> Vec<u32> {
    match term {
        Terminator::Return(Some(l)) => vec![l.0],
        Terminator::Branch { cond, .. } => vec![cond.0],
        Terminator::Switch { scrutinee, .. } => vec![scrutinee.0],
        _ => Vec::new(),
    }
}

fn define_fn_checked(
    obj_mod: &mut ObjectModule,
    fid: FuncId,
    fn_ctx: &mut cranelift_codegen::Context,
    label: &str,
) -> Result<(), JitError> {
    if let Err(err) = obj_mod.define_function(fid, fn_ctx) {
        let verify_detail =
            match cranelift_codegen::verify_function(&fn_ctx.func, obj_mod.isa().flags()) {
                Ok(()) => String::new(),
                Err(errs) => format!("\nVerifier details:\n{errs}\nCLIF IR:\n{}", fn_ctx.func),
            };
        return Err(JitError::Codegen(format!("{label}: {err}{verify_detail}")));
    }
    Ok(())
}

fn collect_slot_elem_tys(mir_fn: &MirFunction) -> HashMap<u32, MirType> {
    let mut slot_elem_tys = HashMap::new();
    for bb in &mir_fn.blocks {
        for s in &bb.stmts {
            if let Some(d) = s.dst
                && let Inst::SlotAlloc { ty } = &s.inst
                && !matches!(
                    ty,
                    MirType::Named(_) | MirType::Array { .. } | MirType::Tuple(_)
                )
            {
                slot_elem_tys.insert(d.0, ty.clone());
            }
        }
    }
    slot_elem_tys
}

fn emit_mir_function_body(
    ctx: &mut ModuleContext<'_>,
    mir_fn: &MirFunction,
    fid: FuncId,
    mode: MirCallbackMode,
    sys_entry: Option<&SystemRegistrationEntry>,
) -> Result<(), JitError> {
    // Check if any `@par` sub-CFG can be outlined to `BamChunkTaskFn`.
    let slot_elem_tys = collect_slot_elem_tys(mir_fn);
    let mut par_tasks: HashMap<usize, (ParSubCfgInfo, FuncId, Vec<usize>)> = HashMap::new();
    let mut skip_blocks: HashSet<usize> = HashSet::new();
    for (bi, bb) in mir_fn.blocks.iter().enumerate() {
        for s in &bb.stmts {
            let par_spec = match s.inst {
                Inst::ParForEachChunk { query_idx, .. } => Some((query_idx, false, false)),
                Inst::ParForEachChunkReadonly {
                    query_idx,
                    deterministic_order,
                    ..
                } => Some((query_idx, true, deterministic_order)),
                _ => None,
            };
            if let Some((qi, ro, det)) = par_spec
                && mode == MirCallbackMode::System
                && let Some(info) = find_par_subcfg_info(mir_fn, bi, qi, ro, det)
            {
                let mut offsets = Vec::with_capacity(info.live_in_locals.len() + 1);
                let mut off = ctx.ptr_bytes; // offset 0 = state_ptr
                for &lid in &info.live_in_locals {
                    off = align_up(off, 8);
                    offsets.push(off);
                    let mty = slot_elem_tys
                        .get(&lid)
                        .unwrap_or(&mir_fn.locals[lid as usize].ty);
                    off += match mty {
                        MirType::Vec2 | MirType::Vec3 | MirType::Vec4 => 16,
                        _ => 8,
                    };
                }
                let task_sym = format!("strata_par_{}_b{bi}_q{qi}", sanitize_ident(&mir_fn.name));
                let mut tsig = Signature::new(ctx.call_conv);
                tsig.params.push(AbiParam::new(ctx.ptr_ty)); // sub_iter
                tsig.params.push(AbiParam::new(ctx.ptr_ty)); // par_frame user_data
                tsig.returns.push(AbiParam::new(types::I32));
                let task_fid = ctx
                    .obj_mod
                    .declare_function(&task_sym, Linkage::Local, &tsig)
                    .map_err(|e| JitError::Codegen(e.to_string()))?;
                for &sb in &info.sub_blocks {
                    skip_blocks.insert(sb);
                }
                par_tasks.insert(bi, (info, task_fid, offsets));
            }
        }
    }

    // Emit any outlined `BamChunkTaskFn` functions first!
    for (info, task_fid, offsets) in par_tasks.values() {
        emit_par_task_function(ctx, mir_fn, info, *task_fid, offsets, sys_entry)?;
    }

    let ptr_ty = ctx.ptr_ty;
    let call_conv = ctx.call_conv;
    let mut fn_ctx = ctx.obj_mod.make_context();
    fn_ctx.func.signature = match mode {
        MirCallbackMode::Helper => build_helper_signature(mir_fn, ptr_ty, call_conv),
        MirCallbackMode::Observer => {
            let mut s = Signature::new(call_conv);
            s.params.push(AbiParam::new(types::I64));
            s.params.push(AbiParam::new(ptr_ty));
            s.params.push(AbiParam::new(ptr_ty));
            s.params.push(AbiParam::new(ptr_ty));
            s.returns.push(AbiParam::new(types::I32));
            s
        }
        MirCallbackMode::Migration => {
            let mut s = Signature::new(call_conv);
            s.params.push(AbiParam::new(ptr_ty));
            s.params.push(AbiParam::new(ptr_ty));
            s.params.push(AbiParam::new(ptr_ty));
            s.returns.push(AbiParam::new(types::I32));
            s
        }
        MirCallbackMode::System => {
            let mut s = Signature::new(call_conv);
            s.params.push(AbiParam::new(ptr_ty));
            s.params.push(AbiParam::new(ptr_ty));
            s.returns.push(AbiParam::new(types::I32));
            s
        }
    };

    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut fn_ctx.func, &mut fb_ctx);
        let cl_blocks: Vec<Block> = (0..mir_fn.blocks.len()).map(|_| b.create_block()).collect();
        if cl_blocks.is_empty() {
            let entry = b.create_block();
            b.append_block_params_for_function_params(entry);
            b.switch_to_block(entry);
            b.seal_block(entry);
            let ok = b.ins().iconst(types::I32, i64::from(FFI_OK));
            b.ins().return_(&[ok]);
            b.finalize(ctx.fe_cfg);
            define_fn_checked(
                &mut ctx.obj_mod,
                fid,
                &mut fn_ctx,
                &format!("empty MIR function `{}`", mir_fn.name),
            )?;
            return Ok(());
        }

        b.append_block_params_for_function_params(cl_blocks[0]);
        b.switch_to_block(cl_blocks[0]);

        let params = b.block_params(cl_blocks[0]).to_vec();
        let (sys_ctx, state_ptr, obs_entity, obs_event_data, obs_commands, mig_src, mig_dst) =
            match mode {
                MirCallbackMode::System => (params[0], params[1], None, None, None, None, None),
                MirCallbackMode::Observer => (
                    b.ins().iconst(ptr_ty, 0),
                    params[3],
                    Some(params[0]),
                    Some(params[1]),
                    Some(params[2]),
                    None,
                    None,
                ),
                MirCallbackMode::Migration => (
                    b.ins().iconst(ptr_ty, 0),
                    params[2],
                    None,
                    None,
                    None,
                    Some(params[0]),
                    Some(params[1]),
                ),
                MirCallbackMode::Helper => (
                    b.ins().iconst(ptr_ty, 0),
                    params[0],
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
            };

        let api_ptr = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.api_off as i32,
        );
        let host_ctx = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.host_ctx_off as i32,
        );

        let sr_plan = analyze_strength_reduction(mir_fn, &mut b, ptr_ty);
        if mode == MirCallbackMode::System
            && let Some(entry) = sys_entry
            && let Some((ref guard_expr, res_lidx)) = entry.run_if_guard
        {
            let rptr =
                emit_res_ptr_lookup(ctx, &mut b, api_ptr, sys_ctx, state_ptr, res_lidx, false);
            if let Some(cond) = eval_hir_run_if(
                &ctx.mir_layouts_sorted[res_lidx],
                &ctx.consts_by_name,
                &mut b,
                rptr,
                guard_expr,
            ) {
                let run_bb = b.create_block();
                let skip_bb = b.create_block();
                b.ins().brif(cond, run_bb, &[], skip_bb, &[]);
                b.switch_to_block(skip_bb);
                b.seal_block(skip_bb);
                let ok_ret = b.ins().iconst(types::I32, i64::from(FFI_OK));
                b.ins().return_(&[ok_ret]);
                b.switch_to_block(run_bb);
                b.seal_block(run_bb);
            }
        }
        let mut lowerer = FnLowerer::new(
            ctx,
            mir_fn,
            &mut b,
            cl_blocks.clone(),
            mode,
            sys_entry,
            api_ptr,
            host_ctx,
            state_ptr,
            sys_ctx,
            obs_entity,
            obs_event_data,
            obs_commands,
            mig_src,
            mig_dst,
            sr_plan,
        );

        // Bind `HelperFn` parameters onto `MirParam.local`.
        if mode == MirCallbackMode::Helper {
            let mut p_off = 1usize;
            for p in &mir_fn.params {
                let count = match p.ty {
                    MirType::Unit => 0,
                    MirType::Vec2 => 2,
                    MirType::Vec3 => 3,
                    MirType::Vec4 => 4,
                    _ => 1,
                };
                if let Some(lid) = p.local {
                    lowerer.bind_param_val(lid, &params[p_off..p_off + count], &p.ty);
                }
                p_off += count;
            }
        }

        // Lower all reachable/participating MIR basic blocks in order.
        for (bi, bb) in mir_fn.blocks.iter().enumerate() {
            if bi != 0 {
                lowerer.b.switch_to_block(cl_blocks[bi]);
            }
            if skip_blocks.contains(&bi) {
                let zero = lowerer.b.ins().iconst(types::I32, 0);
                if matches!(
                    mode,
                    MirCallbackMode::System
                        | MirCallbackMode::Observer
                        | MirCallbackMode::Migration
                ) {
                    lowerer.b.ins().return_(&[zero]);
                } else {
                    lowerer.emit_default_helper_return();
                }
                continue;
            }

            let mut par_jumped = false;
            for s in &bb.stmts {
                if matches!(
                    s.inst,
                    Inst::ParForEachChunk { .. } | Inst::ParForEachChunkReadonly { .. }
                ) && let Some((info, task_fid, offsets)) = par_tasks.get(&bi)
                {
                    lowerer.emit_par_dispatch(info, *task_fid, offsets)?;
                    let exit_cl = cl_blocks[info.chunk_exit_bb];
                    lowerer.b.ins().jump(exit_cl, &[]);
                    par_jumped = true;
                    break;
                }
                lowerer.lower_stmt(s)?;
            }
            if !par_jumped {
                lowerer.lower_terminator(&bb.terminator);
            }
        }

        drop(lowerer);
        b.seal_all_blocks();
        b.finalize(ctx.fe_cfg);
    }

    define_fn_checked(
        &mut ctx.obj_mod,
        fid,
        &mut fn_ctx,
        &format!("MIR function `{}`", mir_fn.name),
    )
}

fn emit_par_task_function(
    ctx: &mut ModuleContext<'_>,
    mir_fn: &MirFunction,
    info: &ParSubCfgInfo,
    task_fid: FuncId,
    offsets: &[usize],
    sys_entry: Option<&SystemRegistrationEntry>,
) -> Result<(), JitError> {
    let ptr_ty = ctx.ptr_ty;
    let call_conv = ctx.call_conv;
    let mut fn_ctx = ctx.obj_mod.make_context();
    fn_ctx.func.signature.call_conv = call_conv;
    fn_ctx.func.signature.params.push(AbiParam::new(ptr_ty)); // sub_iter
    fn_ctx.func.signature.params.push(AbiParam::new(ptr_ty)); // par_frame
    fn_ctx
        .func
        .signature
        .returns
        .push(AbiParam::new(types::I32));

    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut fn_ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);

        let sub_iter = b.block_params(entry)[0];
        let par_frame = b.block_params(entry)[1];
        let state_ptr = b.ins().load(ptr_ty, MemFlagsData::trusted(), par_frame, 0);
        let api_ptr = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.api_off as i32,
        );
        let host_ctx = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.host_ctx_off as i32,
        );
        let sys_ctx = b.ins().iconst(ptr_ty, 0);

        let mut cl_blocks: Vec<Block> = (0..mir_fn.blocks.len()).map(|_| entry).collect();
        let exit_bb = b.create_block();
        for &sb in &info.sub_blocks {
            cl_blocks[sb] = b.create_block();
        }
        cl_blocks[info.chunk_exit_bb] = exit_bb;

        let sr_plan = analyze_strength_reduction(mir_fn, &mut b, ptr_ty);
        let mut lowerer = FnLowerer::new(
            ctx,
            mir_fn,
            &mut b,
            cl_blocks.clone(),
            MirCallbackMode::System,
            sys_entry,
            api_ptr,
            host_ctx,
            state_ptr,
            sys_ctx,
            None,
            None,
            None,
            None,
            None,
            sr_plan,
        );

        // Pre-populate `iter_vars[query_idx]` with `sub_iter`.
        let qi = info.query_idx as usize;
        if qi < lowerer.iter_vars.len() {
            lowerer.b.def_var(lowerer.iter_vars[qi], sub_iter);
        }

        // Load captured live-in locals from `par_frame`.
        for (&lid, &off) in info.live_in_locals.iter().zip(offsets.iter()) {
            let mty = lowerer.effective_local_mir_ty(LocalId(lid)).clone();
            lowerer.load_local_from_mem(LocalId(lid), &mty, par_frame, off as i32);
        }

        let hdr_cl = cl_blocks[info.chunk_hdr_bb];
        lowerer.b.ins().jump(hdr_cl, &[]);

        for &sb in &info.sub_blocks {
            lowerer.b.switch_to_block(cl_blocks[sb]);
            let bb = &mir_fn.blocks[sb];
            for s in &bb.stmts {
                lowerer.lower_stmt(s)?;
            }
            lowerer.lower_terminator(&bb.terminator);
        }

        lowerer.b.switch_to_block(exit_bb);
        let ok = lowerer.b.ins().iconst(types::I32, i64::from(FFI_OK));
        lowerer.b.ins().return_(&[ok]);
        drop(lowerer);
        b.seal_all_blocks();
        b.finalize(ctx.fe_cfg);
    }

    define_fn_checked(
        &mut ctx.obj_mod,
        task_fid,
        &mut fn_ctx,
        "par chunk task define failed",
    )
}

fn sema_ty_vec_dims(ty: &Ty) -> Option<u8> {
    match ty {
        Ty::Vec2 => Some(2),
        Ty::Vec3 => Some(3),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => Some(4),
        _ => None,
    }
}

fn find_layout_vec_hint(
    ctx: &ModuleContext<'_>,
    comp_name: &str,
    projected_field: Option<&str>,
) -> Option<(i32, u8)> {
    let lidx = lookup_name_in_map(&ctx.layout_map, comp_name)?;
    let layout = &ctx.mir_layouts_sorted[lidx];
    if let Some(fname) = projected_field
        && let Some(sf) = layout
            .fields
            .iter()
            .find(|f| !f.is_padding && f.name == fname)
        && let Some(dims) = sema_ty_vec_dims(&sf.ty)
    {
        return Some((sf.offset as i32, dims));
    }
    let mut found: Option<(i32, u8)> = None;
    for sf in layout.fields.iter().filter(|f| !f.is_padding) {
        if let Some(dims) = sema_ty_vec_dims(&sf.ty) {
            if found.is_some() {
                return None;
            }
            found = Some((sf.offset as i32, dims));
        }
    }
    found
}

fn compute_ptr_vec_hints(ctx: &ModuleContext<'_>, mir_fn: &MirFunction) -> HashMap<u32, (i32, u8)> {
    let mut hints: HashMap<u32, (i32, u8)> = HashMap::new();
    let mut slot_hints: HashMap<u32, (i32, u8)> = HashMap::new();
    for _pass in 0..3 {
        for bb in &mir_fn.blocks {
            for s in &bb.stmts {
                match &s.inst {
                    Inst::IterColRead {
                        query_idx,
                        term_idx,
                        storage_key,
                    }
                    | Inst::IterColWrite {
                        query_idx,
                        term_idx,
                        storage_key,
                    }
                    | Inst::IterColWriteUntracked {
                        query_idx,
                        term_idx,
                        storage_key,
                    }
                    | Inst::IterColRowsRead {
                        query_idx,
                        term_idx,
                        storage_key,
                    }
                    | Inst::IterColRowsWrite {
                        query_idx,
                        term_idx,
                        storage_key,
                    }
                    | Inst::EntityGet {
                        query_idx,
                        term_idx,
                        storage_key,
                        ..
                    }
                    | Inst::EntityGetMut {
                        query_idx,
                        term_idx,
                        storage_key,
                        ..
                    } => {
                        if let Some(d) = s.dst {
                            let proj = mir_fn
                                .query_bindings
                                .iter()
                                .find(|qb| qb.query_idx == *query_idx)
                                .and_then(|qb| qb.terms.get(*term_idx as usize))
                                .and_then(|t| t.field_name.as_deref());
                            if let Some(h) = find_layout_vec_hint(ctx, storage_key, proj) {
                                hints.insert(d.0, h);
                            }
                        }
                    }
                    Inst::ResRead { resource } | Inst::ResWrite { resource } => {
                        if let Some(d) = s.dst
                            && let Some(h) = find_layout_vec_hint(ctx, resource, None)
                        {
                            hints.insert(d.0, h);
                        }
                    }
                    Inst::RowPtr { col_ptr, .. } => {
                        if let Some(d) = s.dst
                            && let Some(&h) = hints.get(&col_ptr.0)
                        {
                            hints.insert(d.0, h);
                        }
                    }
                    Inst::FieldPtr {
                        layout_key, field, ..
                    } => {
                        if let Some(d) = s.dst
                            && let Some((_, dims)) =
                                find_layout_vec_hint(ctx, layout_key, Some(field))
                        {
                            hints.insert(d.0, (0, dims));
                        }
                    }
                    Inst::Copy { val } => {
                        if let Some(d) = s.dst
                            && let Some(&h) = hints.get(&val.0)
                        {
                            hints.insert(d.0, h);
                        }
                    }
                    Inst::SlotStore { slot, val } => {
                        if let Some(&h) = hints.get(&val.0) {
                            slot_hints.insert(slot.0, h);
                        }
                    }
                    Inst::SlotLoad { slot } => {
                        if let Some(d) = s.dst
                            && let Some(&h) = slot_hints.get(&slot.0)
                        {
                            hints.insert(d.0, h);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    hints
}

struct FnLowerer<'a, 'b, 'f> {
    ctx: &'a mut ModuleContext<'b>,
    mir_fn: &'a MirFunction,
    b: &'a mut FunctionBuilder<'f>,
    cl_blocks: Vec<Block>,
    mode: MirCallbackMode,
    sys_entry: Option<&'a SystemRegistrationEntry>,
    api_ptr: Value,
    host_ctx: Value,
    state_ptr: Value,
    sys_ctx: Value,
    obs_entity: Option<Value>,
    obs_event_data: Option<Value>,
    obs_commands: Option<Value>,
    mig_src: Option<Value>,
    mig_dst: Option<Value>,
    local_reps: Vec<LocalRep>,
    slot_elem_tys: HashMap<u32, MirType>,
    agg_slots: HashMap<u32, StackSlot>,
    dirty_targets: HashMap<(u32, u32), (u32, u32)>,
    iter_vars: Vec<Variable>,
    chunk_len_vars: Vec<Variable>,
    commands_var: Variable,
    sr_plan: StrengthPlan,
    ptr_vec_hints: HashMap<u32, (i32, u8)>,
    const_strings: HashMap<u32, (DataId, usize)>,
    batch_schemas: HashMap<u32, Vec<usize>>,
}

impl<'a, 'b, 'f> FnLowerer<'a, 'b, 'f> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        ctx: &'a mut ModuleContext<'b>,
        mir_fn: &'a MirFunction,
        b: &'a mut FunctionBuilder<'f>,
        cl_blocks: Vec<Block>,
        mode: MirCallbackMode,
        sys_entry: Option<&'a SystemRegistrationEntry>,
        api_ptr: Value,
        host_ctx: Value,
        state_ptr: Value,
        sys_ctx: Value,
        obs_entity: Option<Value>,
        obs_event_data: Option<Value>,
        obs_commands: Option<Value>,
        mig_src: Option<Value>,
        mig_dst: Option<Value>,
        sr_plan: StrengthPlan,
    ) -> Self {
        let ptr_ty = ctx.ptr_ty;
        let cc = ctx.call_conv;

        let mut dirty_targets = HashMap::new();
        for bb in &mir_fn.blocks {
            for s in &bb.stmts {
                if let Inst::IterMarkChangedRange {
                    query_idx,
                    term_idx,
                    run_start,
                    run_len,
                } = &s.inst
                {
                    dirty_targets.insert((run_start.0, run_len.0), (*query_idx, *term_idx));
                }
            }
        }

        let zero_ptr = b.ins().iconst(ptr_ty, 0);
        let zero_f32 = b.ins().f32const(0.0);
        let zero_f64 = b.ins().f64const(0.0);
        let slot_elem_tys = collect_slot_elem_tys(mir_fn);
        let mut agg_slots = HashMap::new();
        for bb in &mir_fn.blocks {
            for s in &bb.stmts {
                if let Some(d) = s.dst
                    && let Inst::SlotAlloc { ty } = &s.inst
                    && matches!(
                        ty,
                        MirType::Named(_) | MirType::Array { .. } | MirType::Tuple(_)
                    )
                {
                    let sz = ctx.layout_size_of_mir_ty(ty).max(8);
                    let slot = alloc_zero_slot(b, sz, ptr_ty);
                    agg_slots.insert(d.0, slot);
                }
            }
        }

        let mut local_reps = Vec::with_capacity(mir_fn.locals.len());

        for (li, loc) in mir_fn.locals.iter().enumerate() {
            let eff_ty = slot_elem_tys.get(&(li as u32)).unwrap_or(&loc.ty);
            match eff_ty {
                MirType::Vec2 | MirType::Vec3 | MirType::Vec4 => {
                    let vs = [
                        b.declare_var(types::F32),
                        b.declare_var(types::F32),
                        b.declare_var(types::F32),
                        b.declare_var(types::F32),
                    ];
                    for v in vs {
                        b.def_var(v, zero_f32);
                    }
                    local_reps.push(LocalRep::Vec(vs));
                }
                MirType::Named(_) | MirType::Array { .. } | MirType::Tuple(_) => {
                    let var = b.declare_var(ptr_ty);
                    b.def_var(var, zero_ptr);
                    local_reps.push(LocalRep::AggVar(var));
                }
                _ => {
                    let cl_ty = if matches!(
                        eff_ty,
                        MirType::Ptr | MirType::MutPtr | MirType::QueryIter | MirType::Checkpoint
                    ) {
                        ptr_ty
                    } else {
                        scalar_cl_type(eff_ty, cc)
                    };
                    let var = b.declare_var(cl_ty);
                    let z = if cl_ty == types::F32 {
                        zero_f32
                    } else if cl_ty == types::F64 {
                        zero_f64
                    } else {
                        b.ins().iconst(cl_ty, 0)
                    };
                    b.def_var(var, z);
                    local_reps.push(LocalRep::Scalar(var));
                }
            }
        }

        // Initialize strength-reduced pointer variables on entry so all paths dominate.
        for vars in sr_plan.by_base.values() {
            for &v in vars {
                b.def_var(v, zero_ptr);
            }
        }

        let max_q = mir_fn
            .query_bindings
            .len()
            .max(sys_entry.map_or(0, |e| {
                e.wire_queries.len()
                    + e.resource_queries.len()
                    + e.extra_obj_queries.len()
                    + e.stream_queries.len()
            }))
            .max(1);
        let mut iter_vars = Vec::with_capacity(max_q);
        let mut chunk_len_vars = Vec::with_capacity(max_q);
        let zero_i32 = b.ins().iconst(types::I32, 0);
        for _ in 0..max_q {
            let iv = b.declare_var(ptr_ty);
            b.def_var(iv, zero_ptr);
            iter_vars.push(iv);
            let cv = b.declare_var(types::I32);
            b.def_var(cv, zero_i32);
            chunk_len_vars.push(cv);
        }

        let commands_var = b.declare_var(ptr_ty);
        b.def_var(commands_var, obs_commands.unwrap_or(zero_ptr));

        let ptr_vec_hints = compute_ptr_vec_hints(ctx, mir_fn);
        Self {
            ctx,
            mir_fn,
            b,
            cl_blocks,
            mode,
            sys_entry,
            api_ptr,
            host_ctx,
            state_ptr,
            sys_ctx,
            obs_entity,
            obs_event_data,
            obs_commands,
            mig_src,
            mig_dst,
            local_reps,
            slot_elem_tys,
            agg_slots,
            dirty_targets,
            iter_vars,
            chunk_len_vars,
            commands_var,
            sr_plan,
            ptr_vec_hints,
            const_strings: HashMap::new(),
            batch_schemas: HashMap::new(),
        }
    }

    fn bind_param_val(&mut self, lid: LocalId, vals: &[Value], ty: &MirType) {
        match (&self.local_reps[lid.0 as usize], ty) {
            (LocalRep::Vec(vs), MirType::Vec2) if vals.len() >= 2 => {
                self.b.def_var(vs[0], vals[0]);
                self.b.def_var(vs[1], vals[1]);
            }
            (LocalRep::Vec(vs), MirType::Vec3) if vals.len() >= 3 => {
                self.b.def_var(vs[0], vals[0]);
                self.b.def_var(vs[1], vals[1]);
                self.b.def_var(vs[2], vals[2]);
            }
            (LocalRep::Vec(vs), MirType::Vec4) if vals.len() >= 4 => {
                for i in 0..4 {
                    self.b.def_var(vs[i], vals[i]);
                }
            }
            (LocalRep::Scalar(v) | LocalRep::AggVar(v), _) if !vals.is_empty() => {
                self.b.def_var(*v, vals[0]);
            }
            _ => {}
        }
    }

    fn use_scalar(&mut self, lid: LocalId) -> Value {
        match self.local_reps[lid.0 as usize] {
            LocalRep::Scalar(v) | LocalRep::AggVar(v) => self.b.use_var(v),
            LocalRep::Vec(vs) => self.b.use_var(vs[0]),
        }
    }

    fn effective_local_mir_ty(&self, lid: LocalId) -> &MirType {
        self.slot_elem_tys
            .get(&lid.0)
            .unwrap_or(&self.mir_fn.locals[lid.0 as usize].ty)
    }

    fn effective_vec_dims(&self, lid: LocalId) -> Option<u8> {
        vec_dims(self.effective_local_mir_ty(lid))
            .or_else(|| self.ptr_vec_hints.get(&lid.0).map(|&(_, dims)| dims))
    }

    fn use_vec(&mut self, lid: LocalId) -> [Value; 4] {
        self.use_vec_dims(lid, 4)
    }

    fn use_vec_dims(&mut self, lid: LocalId, fallback_dims: u8) -> [Value; 4] {
        match self.local_reps[lid.0 as usize] {
            LocalRep::Vec(vs) => [
                self.b.use_var(vs[0]),
                self.b.use_var(vs[1]),
                self.b.use_var(vs[2]),
                self.b.use_var(vs[3]),
            ],
            LocalRep::Scalar(v) => {
                let s = self.b.use_var(v);
                let z = self.b.ins().f32const(0.0);
                if matches!(
                    self.effective_local_mir_ty(lid),
                    MirType::Ptr | MirType::MutPtr
                ) {
                    let (off, dims) = self
                        .ptr_vec_hints
                        .get(&lid.0)
                        .copied()
                        .unwrap_or((0, fallback_dims));
                    return self.load_vec_from_ptr(s, off, dims, z);
                }
                let f = coerce_cl_val(self.b, s, types::F32, self.ctx.ptr_ty);
                [f, z, z, z]
            }
            LocalRep::AggVar(v) => {
                let ptr = self.b.use_var(v);
                let zero = self.b.ins().f32const(0.0);
                let dims = vec_dims(self.effective_local_mir_ty(lid)).unwrap_or(fallback_dims);
                self.load_vec_from_ptr(ptr, 0, dims, zero)
            }
        }
    }

    fn def_vec(&mut self, dst: LocalId, vals: [Value; 4]) {
        match self.local_reps[dst.0 as usize] {
            LocalRep::Vec(vs) => {
                for i in 0..4 {
                    self.b.def_var(vs[i], vals[i]);
                }
            }
            LocalRep::AggVar(v) => {
                let sz = self
                    .ctx
                    .layout_size_of_mir_ty(&self.mir_fn.locals[dst.0 as usize].ty)
                    .max(16);
                let slot = alloc_zero_slot(self.b, sz, self.ctx.ptr_ty);
                let p = self.b.ins().stack_addr(self.ctx.ptr_ty, slot, 0);
                for (i, &lv) in vals.iter().enumerate() {
                    if i * 4 < sz {
                        self.b
                            .ins()
                            .store(MemFlagsData::new(), lv, p, (i * 4) as i32);
                    }
                }
                self.b.def_var(v, p);
            }
            LocalRep::Scalar(v) => {
                let target_ty = self.expected_cl_ty(dst);
                let coerced = coerce_cl_val(self.b, vals[0], target_ty, self.ctx.ptr_ty);
                self.b.def_var(v, coerced);
            }
        }
    }

    fn expected_cl_ty(&self, lid: LocalId) -> Type {
        self.ctx
            .cl_type_for_mir_val(self.effective_local_mir_ty(lid))
    }

    fn def_scalar_typed(&mut self, dst: LocalId, val: Value) {
        let target_ty = self.expected_cl_ty(dst);
        let coerced = coerce_cl_val(self.b, val, target_ty, self.ctx.ptr_ty);
        match self.local_reps[dst.0 as usize] {
            LocalRep::Scalar(v) | LocalRep::AggVar(v) => self.b.def_var(v, coerced),
            LocalRep::Vec(vs) => {
                let fv = coerce_cl_val(self.b, val, types::F32, self.ctx.ptr_ty);
                for v in vs {
                    self.b.def_var(v, fv);
                }
            }
        }
        if let Some(vars) = self.sr_plan.by_base.get(&dst.0) {
            for &pv in vars {
                self.b.def_var(pv, coerced);
            }
        }
    }

    fn load_local_from_mem(&mut self, lid: LocalId, mty: &MirType, ptr: Value, offset: i32) {
        match mty {
            MirType::Vec2 | MirType::Vec3 | MirType::Vec4 => {
                let dims = vec_dims(mty).unwrap_or(2);
                let zero = self.b.ins().f32const(0.0);
                let vals = self.load_vec_from_ptr(ptr, offset, dims, zero);
                self.def_vec(lid, vals);
            }
            _ => {
                let mem_ty = self.ctx.cl_type_for_mir_val(mty);
                let val = self.b.ins().load(mem_ty, MemFlagsData::new(), ptr, offset);
                let dst_mty = self.effective_local_mir_ty(lid).clone();
                let target_ty = self.expected_cl_ty(lid);
                let coerced = cast_value(
                    self.b,
                    val,
                    mty,
                    is_signed_int_ty(mty),
                    target_ty,
                    is_signed_int_ty(&dst_mty),
                    self.ctx.ptr_ty,
                );
                self.def_scalar_typed(lid, coerced);
            }
        }
    }

    fn store_local_to_mem(&mut self, lid: LocalId, mty: &MirType, ptr: Value, offset: i32) {
        match mty {
            MirType::Vec2 | MirType::Vec3 | MirType::Vec4 => {
                let dims = vec_dims(mty).unwrap_or(2);
                let vals = self.use_vec(lid);
                for (i, &v) in vals.iter().take(dims as usize).enumerate() {
                    let fv = coerce_cl_val(self.b, v, types::F32, self.ctx.ptr_ty);
                    self.b
                        .ins()
                        .store(MemFlagsData::new(), fv, ptr, offset + (i * 4) as i32);
                }
            }
            _ => {
                let src_mty = self.effective_local_mir_ty(lid).clone();
                let val = self.use_scalar(lid);
                let target_ty = self.ctx.cl_type_for_mir_val(mty);
                let coerced = cast_value(
                    self.b,
                    val,
                    &src_mty,
                    is_signed_int_ty(&src_mty),
                    target_ty,
                    is_signed_int_ty(mty),
                    self.ctx.ptr_ty,
                );
                self.b
                    .ins()
                    .store(MemFlagsData::new(), coerced, ptr, offset);
            }
        }
    }

    fn load_vec_from_ptr(&mut self, ptr: Value, offset: i32, dims: u8, zero: Value) -> [Value; 4] {
        let mut out = [zero; 4];
        for (i, slot) in out.iter_mut().enumerate().take(usize::from(dims.min(4))) {
            *slot = self.b.ins().load(
                types::F32,
                MemFlagsData::new(),
                ptr,
                offset + (i * 4) as i32,
            );
        }
        out
    }

    fn wire_term_index(&self, query_idx: u32, term_idx: u32) -> usize {
        if let Some(entry) = self.sys_entry
            && let Some(wq) = entry.wire_queries.get(query_idx as usize)
            && let Some(&mapped) = wq.term_map.get(term_idx as usize)
        {
            return mapped;
        }
        term_idx as usize
    }

    fn ensure_query_iter(&mut self, query_idx: u32) -> Value {
        let qi = query_idx as usize;
        if qi >= self.iter_vars.len() {
            return self.b.ins().iconst(self.ctx.ptr_ty, 0);
        }
        let iv = self.iter_vars[qi];
        let cur = self.b.use_var(iv);
        let ptr_ty = self.ctx.ptr_ty;
        let need_fetch = self.b.ins().icmp_imm_s(IntCC::Equal, cur, 0);
        let ctx_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, self.sys_ctx, 0);
        let do_call = self.b.ins().band(need_fetch, ctx_ok);

        let fetch_bb = self.b.create_block();
        let cont_bb = self.b.create_block();
        self.b.ins().brif(do_call, fetch_bb, &[], cont_bb, &[]);

        self.b.switch_to_block(fetch_bb);
        self.b.seal_block(fetch_bb);
        let slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
        let out_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
        let qv = self.b.ins().iconst(ptr_ty, i64::from(query_idx));
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::SYS_QUERY,
            &[ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[self.sys_ctx, qv, out_ptr],
        );
        let fetched = self
            .b
            .ins()
            .load(ptr_ty, MemFlagsData::trusted(), out_ptr, 0);
        self.b.def_var(iv, fetched);
        self.b.ins().jump(cont_bb, &[]);

        self.b.switch_to_block(cont_bb);
        self.b.seal_block(cont_bb);
        self.b.use_var(iv)
    }

    fn ensure_commands(&mut self) -> Value {
        if let Some(c) = self.obs_commands {
            return c;
        }
        let ptr_ty = self.ctx.ptr_ty;
        let cur = self.b.use_var(self.commands_var);
        let need_fetch = self.b.ins().icmp_imm_s(IntCC::Equal, cur, 0);
        let ctx_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, self.sys_ctx, 0);
        let do_call = self.b.ins().band(need_fetch, ctx_ok);

        let fetch_bb = self.b.create_block();
        let cont_bb = self.b.create_block();
        self.b.ins().brif(do_call, fetch_bb, &[], cont_bb, &[]);

        self.b.switch_to_block(fetch_bb);
        self.b.seal_block(fetch_bb);
        let slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
        let out_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::SYS_COMMANDS,
            &[ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[self.sys_ctx, out_ptr],
        );
        let fetched = self
            .b
            .ins()
            .load(ptr_ty, MemFlagsData::trusted(), out_ptr, 0);
        self.b.def_var(self.commands_var, fetched);
        self.b.ins().jump(cont_bb, &[]);

        self.b.switch_to_block(cont_bb);
        self.b.seal_block(cont_bb);
        self.b.use_var(self.commands_var)
    }

    fn emit_par_dispatch(
        &mut self,
        info: &ParSubCfgInfo,
        task_fid: FuncId,
        offsets: &[usize],
    ) -> Result<(), JitError> {
        let ptr_ty = self.ctx.ptr_ty;
        let iter = self.ensure_query_iter(info.query_idx);
        let mut frame_bytes = self.ctx.ptr_bytes;
        for (&lid, &off) in info.live_in_locals.iter().zip(offsets.iter()) {
            let extra = match self.effective_local_mir_ty(LocalId(lid)) {
                MirType::Vec2 | MirType::Vec3 | MirType::Vec4 => 16,
                _ => 8,
            };
            frame_bytes = frame_bytes.max(off + extra);
        }
        let frame_slot = alloc_zero_slot(self.b, frame_bytes, ptr_ty);
        let frame_ptr = self.b.ins().stack_addr(ptr_ty, frame_slot, 0);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), self.state_ptr, frame_ptr, 0);
        for (&lid, &off) in info.live_in_locals.iter().zip(offsets.iter()) {
            let mty = self.effective_local_mir_ty(LocalId(lid)).clone();
            self.store_local_to_mem(LocalId(lid), &mty, frame_ptr, off as i32);
        }
        let fref = self.ctx.obj_mod.declare_func_in_func(task_fid, self.b.func);
        let fn_addr = self.b.ins().func_addr(ptr_ty, fref);
        let vtable_slot = if info.is_readonly {
            api_slots::PAR_FOR_EACH_CHUNK_READONLY
        } else {
            api_slots::PAR_FOR_EACH_CHUNK
        };
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            vtable_slot,
            &[ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[iter, fn_addr, frame_ptr],
        );
        Ok(())
    }

    fn lower_stmt(&mut self, stmt: &MirStmt) -> Result<(), JitError> {
        let dst = stmt.dst;
        let ptr_ty = self.ctx.ptr_ty;

        match &stmt.inst {
            Inst::ConstInt { value } => {
                if let Some(d) = dst {
                    let ty = self.expected_cl_ty(d);
                    let mty = &self.mir_fn.locals[d.0 as usize].ty;
                    let v = match mty {
                        MirType::Bool => self.b.ins().iconst(types::I8, i64::from(*value != 0)),
                        MirType::F32 => self.b.ins().f32const(*value as f32),
                        MirType::F64 => self.b.ins().f64const(*value as f64),
                        _ => self.b.ins().iconst(ty, *value),
                    };
                    self.def_scalar_typed(d, v);
                }
            }
            Inst::ConstFloat { value } => {
                if let Some(d) = dst {
                    match self.mir_fn.locals[d.0 as usize].ty {
                        MirType::F64 => {
                            let v = self.b.ins().f64const(*value);
                            self.def_scalar_typed(d, v);
                        }
                        MirType::Fix32 => {
                            let q = (*value * 65536.0).round() as i32;
                            let v = self.b.ins().iconst(types::I32, i64::from(q));
                            self.def_scalar_typed(d, v);
                        }
                        MirType::Fix64 => {
                            let q = (*value * 4_294_967_296.0).round() as i64;
                            let v = self.b.ins().iconst(types::I64, q);
                            self.def_scalar_typed(d, v);
                        }
                        _ => {
                            let v = self.b.ins().f32const(*value as f32);
                            self.def_scalar_typed(d, v);
                        }
                    }
                }
            }
            Inst::ConstBool { value } => {
                if let Some(d) = dst {
                    let v = self.b.ins().iconst(types::I8, i64::from(*value));
                    self.def_scalar_typed(d, v);
                }
            }
            Inst::ConstVec { dims: _, values } => {
                if let Some(d) = dst {
                    let arr = [
                        self.b.ins().f32const(values[0] as f32),
                        self.b.ins().f32const(values[1] as f32),
                        self.b.ins().f32const(values[2] as f32),
                        self.b.ins().f32const(values[3] as f32),
                    ];
                    self.def_vec(d, arr);
                }
            }
            Inst::ConstString { value } => {
                if let Some(d) = dst {
                    let cstr_id = self.ctx.intern_cstr(value)?;
                    let (raw_id, raw_len) = self.ctx.intern_bytes(value)?;
                    self.const_strings.insert(d.0, (raw_id, raw_len));
                    let gv = self.ctx.obj_mod.declare_data_in_func(cstr_id, self.b.func);
                    let addr = self.b.ins().symbol_value(ptr_ty, gv);
                    self.def_scalar_typed(d, addr);
                }
            }
            Inst::Copy { val } => {
                if let Some(d) = dst {
                    self.copy_local(*val, d);
                    if let Some(schema) = self.batch_schemas.get(&val.0).cloned() {
                        self.batch_schemas.insert(d.0, schema);
                    }
                }
            }
            Inst::SlotAlloc { .. } => {
                if let Some(d) = dst
                    && let Some(&slot) = self.agg_slots.get(&d.0)
                {
                    let p = self.b.ins().stack_addr(ptr_ty, slot, 0);
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::SlotLoad { slot } => {
                if let Some(d) = dst {
                    self.copy_local(*slot, d);
                    if let Some(schema) = self.batch_schemas.get(&slot.0).cloned() {
                        self.batch_schemas.insert(d.0, schema);
                    }
                }
            }
            Inst::SlotStore { slot, val } => {
                if self.agg_slots.contains_key(&slot.0) {
                    let dst_ptr = self.use_scalar(*slot);
                    let src_ptr = self.use_scalar(*val);
                    let sz = self
                        .ctx
                        .layout_size_of_mir_ty(&self.mir_fn.locals[val.0 as usize].ty);
                    emit_memcpy(self.b, dst_ptr, src_ptr, sz);
                } else {
                    self.copy_local(*val, *slot);
                    if let Some(schema) = self.batch_schemas.get(&val.0).cloned() {
                        self.batch_schemas.insert(slot.0, schema);
                    }
                }
                // Update any strength-reduced row pointers bound to `slot`.
                if let Some(entries) = self.sr_plan.by_slot.get(&slot.0).cloned() {
                    if self.sr_plan.zero_locals.contains(&val.0) {
                        for (base_id, _, pvar) in entries {
                            let base_val = self.use_scalar(LocalId(base_id));
                            self.b.def_var(pvar, base_val);
                        }
                    } else if self.sr_plan.step_inc_map.get(&val.0) == Some(&slot.0) {
                        for (_, stride, pvar) in entries {
                            let cur = self.b.use_var(pvar);
                            let nxt = self.b.ins().iadd_imm_s(cur, i64::from(stride));
                            self.b.def_var(pvar, nxt);
                        }
                    }
                }
            }
            Inst::BinOp {
                op,
                lhs,
                rhs,
                allow_fma,
            } => {
                if let Some(d) = dst {
                    self.lower_binop(d, op, *lhs, *rhs, *allow_fma);
                }
            }
            Inst::UnOp { op, val } => {
                if let Some(d) = dst {
                    self.lower_unop(d, op, *val);
                }
            }
            Inst::Cast { val, target_ty } => {
                if let Some(d) = dst {
                    self.lower_cast(d, *val, target_ty);
                }
            }
            Inst::VecExtract { vec, lane } => {
                if let Some(d) = dst {
                    let vs = self.use_vec(*vec);
                    let l = usize::from((*lane).min(3));
                    self.def_scalar_typed(d, vs[l]);
                }
            }
            Inst::VecInsert { vec, lane, val } => {
                if let Some(d) = dst {
                    let mut vs = self.use_vec(*vec);
                    let l = usize::from((*lane).min(3));
                    let sv = {
                        let __tmp = self.use_scalar(*val);
                        coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                    };
                    vs[l] = sv;
                    self.def_vec(d, vs);
                }
            }
            Inst::VecSwizzle { vec, lanes } => {
                if let Some(d) = dst {
                    let src = self.use_vec(*vec);
                    let z = self.b.ins().f32const(0.0);
                    if lanes.len() <= 1 {
                        let idx = usize::from(lanes.first().copied().unwrap_or(0).min(3));
                        self.def_scalar_typed(d, src[idx]);
                    } else {
                        let mut out = [z; 4];
                        for (i, &l) in lanes.iter().take(4).enumerate() {
                            out[i] = src[usize::from(l.min(3))];
                        }
                        self.def_vec(d, out);
                    }
                }
            }
            Inst::IntrinsicMath {
                name,
                args,
                deterministic,
            } => {
                if let Some(d) = dst {
                    self.lower_intrinsic_math(d, name, args, *deterministic)?;
                }
            }
            Inst::Call { callee, args } => {
                self.lower_helper_call(dst, callee, args)?;
            }
            Inst::StructInit { type_name, fields } => {
                if let Some(d) = dst {
                    self.lower_struct_init(d, type_name, fields);
                }
            }
            Inst::ArrayInit { elems } => {
                if let Some(d) = dst {
                    self.lower_array_init(d, elems);
                }
            }
            Inst::ArrayIndex { base, index } => {
                if let Some(d) = dst {
                    self.lower_array_index(d, *base, *index);
                }
            }
            Inst::FieldPtr {
                base_ptr,
                offset_bytes,
                ..
            } => {
                if let Some(d) = dst {
                    let bp = self.use_scalar(*base_ptr);
                    let zero_p = self.b.ins().iconst(ptr_ty, 0);
                    let is_null = self.b.ins().icmp_imm_s(IntCC::Equal, bp, 0);
                    let added = self.b.ins().iadd_imm_s(bp, i64::from(*offset_bytes));
                    let res = self.b.ins().select(is_null, zero_p, added);
                    self.def_scalar_typed(d, res);
                }
            }
            Inst::FieldLoad {
                base_ptr,
                offset_bytes,
                field_ty,
                ..
            } => {
                if let Some(d) = dst {
                    self.lower_field_load(d, *base_ptr, *offset_bytes, field_ty);
                }
            }
            Inst::FieldStore {
                base_ptr,
                layout_key,
                field,
                offset_bytes,
                val,
            } => {
                self.lower_field_store(*base_ptr, layout_key, field, *offset_bytes, *val);
            }
            Inst::RowPtr {
                col_ptr,
                row_idx,
                stride_bytes,
                is_sparse,
            } => {
                if let Some(d) = dst {
                    self.lower_row_ptr(d, *col_ptr, *row_idx, *stride_bytes, *is_sparse);
                }
            }
            Inst::IterNextChunk { query_idx } => {
                if let Some(d) = dst {
                    let iter = self.ensure_query_iter(*query_idx);
                    let len_slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
                    let len_slot_ptr = self.b.ins().stack_addr(ptr_ty, len_slot, 0);
                    let iter_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, iter, 0);
                    let call_bb = self.b.create_block();
                    let skip_bb = self.b.create_block();
                    let done_bb = self.b.create_block();
                    self.b.append_block_param(done_bb, types::I8);
                    self.b.ins().brif(iter_ok, call_bb, &[], skip_bb, &[]);

                    self.b.switch_to_block(call_bb);
                    self.b.seal_block(call_bb);
                    let has_ch = call_vtable(
                        &self.ctx.obj_mod,
                        self.b,
                        self.api_ptr,
                        api_slots::ITER_NEXT_CHUNK,
                        &[ptr_ty, ptr_ty],
                        Some(types::I8),
                        ptr_ty,
                        self.ctx.call_conv,
                        &[iter, len_slot_ptr],
                    );
                    let clen_raw =
                        self.b
                            .ins()
                            .load(ptr_ty, MemFlagsData::trusted(), len_slot_ptr, 0);
                    let clen_i32 = coerce_cl_val(self.b, clen_raw, types::I32, ptr_ty);
                    if (*query_idx as usize) < self.chunk_len_vars.len() {
                        self.b
                            .def_var(self.chunk_len_vars[*query_idx as usize], clen_i32);
                    }
                    self.b.ins().jump(done_bb, &[BlockArg::Value(has_ch)]);

                    self.b.switch_to_block(skip_bb);
                    self.b.seal_block(skip_bb);
                    let f_i8 = self.b.ins().iconst(types::I8, 0);
                    if (*query_idx as usize) < self.chunk_len_vars.len() {
                        let z32 = self.b.ins().iconst(types::I32, 0);
                        self.b
                            .def_var(self.chunk_len_vars[*query_idx as usize], z32);
                    }
                    self.b.ins().jump(done_bb, &[BlockArg::Value(f_i8)]);

                    self.b.switch_to_block(done_bb);
                    self.b.seal_block(done_bb);
                    let res = self.b.block_params(done_bb)[0];
                    self.def_scalar_typed(d, res);
                }
            }
            Inst::IterChunkLen { query_idx } => {
                if let Some(d) = dst {
                    let val = if (*query_idx as usize) < self.chunk_len_vars.len() {
                        self.b.use_var(self.chunk_len_vars[*query_idx as usize])
                    } else {
                        self.b.ins().iconst(types::I32, 0)
                    };
                    self.def_scalar_typed(d, val);
                }
            }
            Inst::IterEntities { query_idx } => {
                if let Some(d) = dst {
                    let iter = self.ensure_query_iter(*query_idx);
                    let p = call_vtable_guarded(
                        &self.ctx.obj_mod,
                        self.b,
                        self.api_ptr,
                        api_slots::ITER_ENTITIES,
                        &[ptr_ty],
                        ptr_ty,
                        ptr_ty,
                        self.ctx.call_conv,
                        iter,
                        &[iter],
                    );
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::EntityAtRow {
                entities_ptr,
                row_idx,
            } => {
                if let Some(d) = dst {
                    self.lower_entity_at_row(d, *entities_ptr, *row_idx);
                }
            }
            Inst::IterColRead {
                query_idx,
                term_idx,
                ..
            } => {
                if let Some(d) = dst {
                    let p =
                        self.call_iter_col(*query_idx, *term_idx, api_slots::ITER_COLUMN_READONLY);
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::IterColWrite {
                query_idx,
                term_idx,
                ..
            } => {
                if let Some(d) = dst {
                    let p =
                        self.call_iter_col(*query_idx, *term_idx, api_slots::ITER_COLUMN_MUTABLE);
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::IterColWriteUntracked {
                query_idx,
                term_idx,
                ..
            } => {
                if let Some(d) = dst {
                    let p = self.call_iter_col(
                        *query_idx,
                        *term_idx,
                        api_slots::ITER_COLUMN_MUTABLE_UNTRACKED,
                    );
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::IterColRowsRead {
                query_idx,
                term_idx,
                ..
            } => {
                if let Some(d) = dst {
                    let p = self.call_iter_col(
                        *query_idx,
                        *term_idx,
                        api_slots::ITER_COLUMN_ROWS_READONLY,
                    );
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::IterColRowsWrite {
                query_idx,
                term_idx,
                ..
            } => {
                if let Some(d) = dst {
                    let p = self.call_iter_col(
                        *query_idx,
                        *term_idx,
                        api_slots::ITER_COLUMN_ROWS_MUTABLE,
                    );
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::IterMarkChangedRange {
                query_idx,
                term_idx,
                run_start,
                run_len,
            } => {
                let rlen = self.use_scalar(*run_len);
                let rstart = self.use_scalar(*run_start);
                self.emit_flush_changed_range(*query_idx, *term_idx, rstart, rlen);
            }
            Inst::IterCount { query_idx } => {
                if let Some(d) = dst {
                    let iter = self.ensure_query_iter(*query_idx);
                    let cnt_slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
                    let cnt_ptr = self.b.ins().stack_addr(ptr_ty, cnt_slot, 0);
                    let iter_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, iter, 0);
                    let call_bb = self.b.create_block();
                    let skip_bb = self.b.create_block();
                    self.b.ins().brif(iter_ok, call_bb, &[], skip_bb, &[]);

                    self.b.switch_to_block(call_bb);
                    self.b.seal_block(call_bb);
                    let _rc = call_vtable(
                        &self.ctx.obj_mod,
                        self.b,
                        self.api_ptr,
                        api_slots::ITER_COUNT,
                        &[ptr_ty, ptr_ty],
                        Some(types::I32),
                        ptr_ty,
                        self.ctx.call_conv,
                        &[iter, cnt_ptr],
                    );
                    self.b.ins().jump(skip_bb, &[]);

                    self.b.switch_to_block(skip_bb);
                    self.b.seal_block(skip_bb);
                    let count = self
                        .b
                        .ins()
                        .load(ptr_ty, MemFlagsData::trusted(), cnt_ptr, 0);
                    self.def_scalar_typed(d, count);
                }
            }
            Inst::IterUpCascade {
                query_idx,
                relation: _,
            } => {
                if let Some(d) = dst {
                    let iter = self.ensure_query_iter(*query_idx);
                    let len_slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
                    let len_slot_ptr = self.b.ins().stack_addr(ptr_ty, len_slot, 0);
                    let has_ch = call_vtable_guarded_i8(
                        &self.ctx.obj_mod,
                        self.b,
                        self.api_ptr,
                        api_slots::ITER_NEXT_CHUNK,
                        &[ptr_ty, ptr_ty],
                        ptr_ty,
                        self.ctx.call_conv,
                        iter,
                        &[iter, len_slot_ptr],
                    );
                    let clen_raw =
                        self.b
                            .ins()
                            .load(ptr_ty, MemFlagsData::trusted(), len_slot_ptr, 0);
                    let clen_i32 = coerce_cl_val(self.b, clen_raw, types::I32, ptr_ty);
                    if (*query_idx as usize) < self.chunk_len_vars.len() {
                        self.b
                            .def_var(self.chunk_len_vars[*query_idx as usize], clen_i32);
                    }
                    self.def_scalar_typed(d, has_ch);
                }
            }
            Inst::ParForEachChunk { .. } | Inst::ParForEachChunkReadonly { .. } => {
                // Fallback path when not safely outlinable (`has_commands`, reductions, deterministic order):
                // ensure iterator is obtained and proceed into the MIR chunk loop sequentially.
                if let Inst::ParForEachChunk { query_idx, .. }
                | Inst::ParForEachChunkReadonly { query_idx, .. } = stmt.inst
                {
                    let _ = self.ensure_query_iter(query_idx);
                }
            }
            Inst::ReduceInit { identity, .. } => {
                if let Some(d) = dst {
                    self.copy_local(*identity, d);
                }
            }
            Inst::ReduceAccum { acc, op, val } => {
                let d_target = dst.unwrap_or(*acc);
                let eff_op = if op == "sum" || op == "add" || op == "+" || op == "count" {
                    "+"
                } else if op == "prod" || op == "mul" || op == "*" {
                    "*"
                } else {
                    op.as_str()
                };
                if eff_op == "min" || eff_op == "max" {
                    let a = self.use_scalar(*acc);
                    let v = self.use_scalar(*val);
                    let ty = self.expected_cl_ty(d_target);
                    let res = apply_min_max(self.b, ty, eff_op == "min", a, v);
                    self.def_scalar_typed(d_target, res);
                } else {
                    self.lower_binop(d_target, eff_op, *acc, *val, false);
                }
            }
            Inst::ResRead { resource } => {
                if let Some(d) = dst {
                    let p = self.lower_res_access(resource, false);
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::ResWrite { resource } => {
                if let Some(d) = dst {
                    let p = self.lower_res_access(resource, true);
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::EntityGet {
                query_idx,
                term_idx,
                entity,
                ..
            } => {
                if let Some(d) = dst {
                    let ent = self.use_scalar(*entity);
                    let p = self.call_entity_get(*query_idx, *term_idx, ent, false);
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::EntityGetMut {
                query_idx,
                term_idx,
                entity,
                ..
            } => {
                if let Some(d) = dst {
                    let ent = self.use_scalar(*entity);
                    let p = self.call_entity_get(*query_idx, *term_idx, ent, true);
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::ResolveNamedObject { name } => {
                if let Some(d) = dst {
                    let ent = self.lower_resolve_named_object(name)?;
                    self.def_scalar_typed(d, ent);
                }
            }
            Inst::BindNamedObject { name } => {
                let _ent = self.lower_resolve_named_object(name)?;
            }
            Inst::InternSymbol { symbol } => {
                if let Some(d) = dst {
                    let sym = self.lower_intern_symbol(symbol)?;
                    self.def_scalar_typed(d, sym);
                }
            }
            Inst::TriggerPayload { .. } => {
                if let Some(d) = dst {
                    let p = self
                        .obs_event_data
                        .unwrap_or_else(|| self.b.ins().iconst(ptr_ty, 0));
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::TriggerTarget => {
                if let Some(d) = dst {
                    let e = self
                        .obs_entity
                        .unwrap_or_else(|| self.b.ins().iconst(types::I64, FFI_ENTITY_NULL as i64));
                    self.def_scalar_typed(d, e);
                }
            }
            Inst::GraceArm { ptr, duration_sec } => {
                let p = self.use_scalar(*ptr);
                let dur = {
                    let __tmp = self.use_scalar(*duration_sec);
                    coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                };
                self.guarded_store(p, 0, dur);
            }
            Inst::GraceTick { ptr, dt_sec } => {
                let p = self.use_scalar(*ptr);
                let dt = {
                    let __tmp = self.use_scalar(*dt_sec);
                    coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                };
                self.lower_grace_tick(p, dt);
            }
            Inst::GraceIsActive { ptr } => {
                if let Some(d) = dst {
                    let p = self.use_scalar(*ptr);
                    let rem = self.guarded_load(p, 0, types::F32);
                    let zero = self.b.ins().f32const(0.0);
                    let act = self.b.ins().fcmp(FloatCC::GreaterThan, rem, zero);
                    self.def_scalar_typed(d, act);
                }
            }
            Inst::GraceClear { ptr } => {
                let p = self.use_scalar(*ptr);
                let zero = self.b.ins().f32const(0.0);
                self.guarded_store(p, 0, zero);
            }
            Inst::InputBufPush {
                ptr,
                capacity,
                action_id,
                window_sec,
            } => {
                let p = self.use_scalar(*ptr);
                let aid = {
                    let __tmp = self.use_scalar(*action_id);
                    coerce_cl_val(self.b, __tmp, types::I16, ptr_ty)
                };
                let win = {
                    let __tmp = self.use_scalar(*window_sec);
                    coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                };
                self.lower_input_buf_push(p, *capacity, aid, win);
            }
            Inst::InputBufConsume {
                ptr,
                capacity,
                action_id,
            } => {
                if let Some(d) = dst {
                    let p = self.use_scalar(*ptr);
                    let aid = {
                        let __tmp = self.use_scalar(*action_id);
                        coerce_cl_val(self.b, __tmp, types::I16, ptr_ty)
                    };
                    let hit = self.lower_input_buf_find(p, *capacity, aid, true);
                    self.def_scalar_typed(d, hit);
                }
            }
            Inst::InputBufPeek {
                ptr,
                capacity,
                action_id,
            } => {
                if let Some(d) = dst {
                    let p = self.use_scalar(*ptr);
                    let aid = {
                        let __tmp = self.use_scalar(*action_id);
                        coerce_cl_val(self.b, __tmp, types::I16, ptr_ty)
                    };
                    let hit = self.lower_input_buf_find(p, *capacity, aid, false);
                    self.def_scalar_typed(d, hit);
                }
            }
            Inst::InputBufTick {
                ptr,
                capacity,
                dt_sec,
            } => {
                let p = self.use_scalar(*ptr);
                let dt = {
                    let __tmp = self.use_scalar(*dt_sec);
                    coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                };
                self.lower_input_buf_tick(p, *capacity, dt);
            }
            Inst::BitSetSet { ptr, words, bit } => {
                let p = self.use_scalar(*ptr);
                let bit_v = {
                    let __tmp = self.use_scalar(*bit);
                    coerce_cl_val(self.b, __tmp, types::I32, ptr_ty)
                };
                self.lower_bitset_mut(p, *words, bit_v, true);
            }
            Inst::BitSetClear { ptr, words, bit } => {
                let p = self.use_scalar(*ptr);
                let bit_v = {
                    let __tmp = self.use_scalar(*bit);
                    coerce_cl_val(self.b, __tmp, types::I32, ptr_ty)
                };
                self.lower_bitset_mut(p, *words, bit_v, false);
            }
            Inst::BitSetGet { ptr, words, bit } => {
                if let Some(d) = dst {
                    let p = self.use_scalar(*ptr);
                    let bit_v = {
                        let __tmp = self.use_scalar(*bit);
                        coerce_cl_val(self.b, __tmp, types::I32, ptr_ty)
                    };
                    let res = self.lower_bitset_get(p, *words, bit_v);
                    self.def_scalar_typed(d, res);
                }
            }
            Inst::TimelineInWindow { ptr, window_bit } => {
                if let Some(d) = dst {
                    let p = self.use_scalar(*ptr);
                    let mask = self.guarded_load(p, 4, types::I32);
                    let bit = 1i64 << (*window_bit & 31);
                    let masked = self.b.ins().band_imm_u(mask, bit);
                    let active = self.b.ins().icmp_imm_s(IntCC::NotEqual, masked, 0);
                    self.def_scalar_typed(d, active);
                }
            }
            Inst::TimelineAdvance {
                cursor_ptr,
                rate_hz,
                duration_frames,
                window_masks,
                ..
            } => {
                let p = self.use_scalar(*cursor_ptr);
                self.lower_timeline_advance(p, *rate_hz, *duration_frames, window_masks);
            }
            Inst::CmdSpawn {
                persistent,
                components,
            } => {
                let out_ent = self.lower_cmd_spawn(*persistent, components)?;
                if let Some(d) = dst {
                    self.def_scalar_typed(d, out_ent);
                }
            }
            Inst::CmdSpawnBatch { count, components } => {
                self.lower_cmd_spawn_batch(*count, components)?;
            }
            Inst::SpawnBatchBegin { count, components } => {
                let (hdr_u64, schema) = self.lower_spawn_batch_begin(*count, components)?;
                if let Some(d) = dst {
                    self.def_scalar_typed(d, hdr_u64);
                    self.batch_schemas.insert(d.0, schema);
                }
            }
            Inst::SpawnBatchPush {
                batch,
                index,
                components,
            } => {
                self.lower_spawn_batch_push(*batch, *index, components);
            }
            Inst::SpawnBatchCommit { batch } => {
                self.lower_spawn_batch_commit(*batch)?;
            }
            Inst::CmdDespawn { entity } => {
                let ent = self.use_scalar(*entity);
                let cmds = self.ensure_commands();
                let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
                let do_bb = self.b.create_block();
                let done_bb = self.b.create_block();
                self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);
                self.b.switch_to_block(do_bb);
                self.b.seal_block(do_bb);
                let _rc = call_vtable(
                    &self.ctx.obj_mod,
                    self.b,
                    self.api_ptr,
                    api_slots::CMD_DESPAWN,
                    &[ptr_ty, types::I64],
                    Some(types::I32),
                    ptr_ty,
                    self.ctx.call_conv,
                    &[cmds, ent],
                );
                self.b.ins().jump(done_bb, &[]);
                self.b.switch_to_block(done_bb);
                self.b.seal_block(done_bb);
            }
            Inst::CmdDespawnAll { filter } => {
                self.lower_cmd_despawn_all(filter)?;
            }
            Inst::CmdInsert {
                entity,
                component,
                data,
                if_new,
            } => {
                let ent = self.use_scalar(*entity);
                self.lower_cmd_insert(ent, component, *data, *if_new)?;
            }
            Inst::CmdRemove { entity, component } => {
                let ent = self.use_scalar(*entity);
                self.lower_cmd_remove(ent, component);
            }
            Inst::CmdTrigger {
                event,
                target,
                payload,
                propagate,
            } => {
                self.lower_cmd_trigger(event, *target, *payload, *propagate);
            }
            Inst::StreamEmit { stream, payload } => {
                self.lower_stream_emit(stream, *payload);
            }
            Inst::CmdCheckpoint => {
                let cmds = self.ensure_commands();
                let slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
                let out_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
                let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
                let do_bb = self.b.create_block();
                let done_bb = self.b.create_block();
                self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);
                self.b.switch_to_block(do_bb);
                self.b.seal_block(do_bb);
                let _rc = call_vtable(
                    &self.ctx.obj_mod,
                    self.b,
                    self.api_ptr,
                    api_slots::CMD_CHECKPOINT,
                    &[ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    self.ctx.call_conv,
                    &[cmds, out_ptr],
                );
                self.b.ins().jump(done_bb, &[]);
                self.b.switch_to_block(done_bb);
                self.b.seal_block(done_bb);
                if let Some(d) = dst {
                    let ck = self
                        .b
                        .ins()
                        .load(ptr_ty, MemFlagsData::trusted(), out_ptr, 0);
                    self.def_scalar_typed(d, ck);
                }
            }
            Inst::CmdRollback { checkpoint } => {
                let ck = self.use_scalar(*checkpoint);
                let cmds = self.ensure_commands();
                let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
                let do_bb = self.b.create_block();
                let done_bb = self.b.create_block();
                self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);
                self.b.switch_to_block(do_bb);
                self.b.seal_block(do_bb);
                let _rc = call_vtable(
                    &self.ctx.obj_mod,
                    self.b,
                    self.api_ptr,
                    api_slots::CMD_ROLLBACK,
                    &[ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    self.ctx.call_conv,
                    &[cmds, ck],
                );
                self.b.ins().jump(done_bb, &[]);
                self.b.switch_to_block(done_bb);
                self.b.seal_block(done_bb);
            }
            Inst::CmdInsertRelation {
                relation,
                entity,
                target,
                payload,
            } => {
                self.lower_cmd_insert_relation(relation, *entity, *target, *payload);
            }
            Inst::CmdRemoveRelation {
                relation,
                entity,
                target,
            } => {
                self.lower_cmd_remove_relation(relation, *entity, *target);
            }
            Inst::TableLoad {
                table_name,
                key,
                field,
            } => {
                if let Some(d) = dst {
                    self.lower_table_load(d, table_name, *key, field);
                }
            }
            Inst::CurveSample { curve_name, x } => {
                if let Some(d) = dst {
                    self.lower_curve_sample(d, curve_name, *x);
                }
            }
            Inst::OptionalChunkIsPresent { slice_ptr, .. } => {
                if let Some(d) = dst {
                    let p = self.use_scalar(*slice_ptr);
                    let present = self.b.ins().icmp_imm_s(IntCC::NotEqual, p, 0);
                    self.def_scalar_typed(d, present);
                }
            }
            Inst::DirtyRunInit { run_start, run_len } => {
                let z32 = self.b.ins().iconst(types::I32, 0);
                self.def_scalar_typed(*run_start, z32);
                self.def_scalar_typed(*run_len, z32);
            }
            Inst::DirtyRunRecordRow {
                run_start,
                run_len,
                row_idx,
            } => {
                self.lower_dirty_run_record_row(*run_start, *run_len, *row_idx);
            }
            Inst::SpatialRebuildCsr { index_name, .. } => {
                self.lower_spatial_rebuild_csr(index_name);
            }
            Inst::SpatialQueryDisc {
                grid_name,
                center,
                radius,
            } => {
                if let Some(d) = dst {
                    self.lower_spatial_query_disc(d, grid_name, *center, *radius);
                }
            }
            Inst::SpatialQuerySegmentAt {
                history_name,
                start,
                end,
                radius,
                tick_offset,
            } => {
                if let Some(d) = dst {
                    self.lower_spatial_query_segment(
                        d,
                        history_name,
                        *start,
                        *end,
                        *radius,
                        *tick_offset,
                    );
                }
            }
            Inst::ShadowWrite {
                shadow_slot, val, ..
            } => {
                if self.agg_slots.contains_key(&shadow_slot.0) {
                    let dst_ptr = self.use_scalar(*shadow_slot);
                    let src_ptr = self.use_scalar(*val);
                    let sz = self
                        .ctx
                        .layout_size_of_mir_ty(&self.mir_fn.locals[val.0 as usize].ty);
                    emit_memcpy(self.b, dst_ptr, src_ptr, sz);
                } else {
                    self.copy_local(*val, *shadow_slot);
                }
            }
            Inst::ShadowCommit { .. }
            | Inst::RequireTrue { .. }
            | Inst::FsmDispatch { .. }
            | Inst::TaskStep { .. } => {
                // `atomic_tx` / `state_machines` passes already lowered control flow & state steps.
            }
            Inst::MigrateSrcPtr { .. } => {
                if let Some(d) = dst {
                    let p = self
                        .mig_src
                        .unwrap_or_else(|| self.b.ins().iconst(ptr_ty, 0));
                    self.def_scalar_typed(d, p);
                }
            }
            Inst::MigrateDstPtr { .. } => {
                if let Some(d) = dst {
                    let p = self
                        .mig_dst
                        .unwrap_or_else(|| self.b.ins().iconst(ptr_ty, 0));
                    self.def_scalar_typed(d, p);
                }
            }
        }
        Ok(())
    }

    fn copy_local(&mut self, src: LocalId, dst: LocalId) {
        if let Some((id, len)) = self.const_strings.get(&src.0).copied() {
            self.const_strings.insert(dst.0, (id, len));
        }
        match (
            &self.local_reps[src.0 as usize],
            &self.local_reps[dst.0 as usize],
        ) {
            (LocalRep::Vec(_), _) => {
                let vs = self.use_vec(src);
                self.def_vec(dst, vs);
            }
            (_, LocalRep::Vec(_)) => {
                if matches!(
                    self.effective_local_mir_ty(src),
                    MirType::Ptr | MirType::MutPtr
                ) {
                    let vs = self.use_vec(src);
                    self.def_vec(dst, vs);
                } else {
                    let s = self.use_scalar(src);
                    let fv = coerce_cl_val(self.b, s, types::F32, self.ctx.ptr_ty);
                    self.def_vec(dst, [fv; 4]);
                }
            }
            _ => {
                let v = self.use_scalar(src);
                self.def_scalar_typed(dst, v);
            }
        }
    }

    fn lower_binop(&mut self, dst: LocalId, op: &str, lhs: LocalId, rhs: LocalId, allow_fma: bool) {
        let lty = &self.mir_fn.locals[lhs.0 as usize].ty;
        let rty = &self.mir_fn.locals[rhs.0 as usize].ty;
        let dst_ty = &self.mir_fn.locals[dst.0 as usize].ty;
        let ptr_ty = self.ctx.ptr_ty;

        // Handle vector arithmetic (`Vec + Vec`, `Vec * s`, `s * Vec`, `Vec == Vec`).
        if let (Some(ld), Some(rd)) = (vec_dims(lty), vec_dims(rty)) {
            let lv = self.use_vec(lhs);
            let rv = self.use_vec(rhs);
            let dims = usize::from(ld.max(rd));
            if op == "==" || op == "!=" {
                let mut acc = self.b.ins().iconst(types::I8, 1);
                for i in 0..dims {
                    let eq = self.b.ins().fcmp(FloatCC::Equal, lv[i], rv[i]);
                    acc = self.b.ins().band(acc, eq);
                }
                let res = if op == "!=" {
                    self.b.ins().icmp_imm_s(IntCC::Equal, acc, 0)
                } else {
                    acc
                };
                self.def_scalar_typed(dst, res);
                return;
            }
            let z = self.b.ins().f32const(0.0);
            let mut out = [z; 4];
            for i in 0..dims {
                out[i] = float_binop(self.b, types::F32, op, lv[i], rv[i]);
            }
            self.def_vec(dst, out);
            return;
        }
        if let Some(ld) = vec_dims(lty) {
            let lv = self.use_vec(lhs);
            let s = {
                let __tmp = self.use_scalar(rhs);
                coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
            };
            let z = self.b.ins().f32const(0.0);
            let mut out = [z; 4];
            for i in 0..usize::from(ld) {
                out[i] = float_binop(self.b, types::F32, op, lv[i], s);
            }
            self.def_vec(dst, out);
            return;
        }
        if let Some(rd) = vec_dims(rty) {
            let s = {
                let __tmp = self.use_scalar(lhs);
                coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
            };
            let rv = self.use_vec(rhs);
            let z = self.b.ins().f32const(0.0);
            let mut out = [z; 4];
            for i in 0..usize::from(rd) {
                out[i] = float_binop(self.b, types::F32, op, s, rv[i]);
            }
            self.def_vec(dst, out);
            return;
        }

        // Handle Q16.16 (`Fix32`) and Q32.32 (`Fix64`) deterministic fixed-point arithmetic.
        if matches!(lty, MirType::Fix32) || matches!(rty, MirType::Fix32) {
            let l = {
                let __tmp = self.use_scalar(lhs);
                coerce_cl_val(self.b, __tmp, types::I32, ptr_ty)
            };
            let r = {
                let __tmp = self.use_scalar(rhs);
                coerce_cl_val(self.b, __tmp, types::I32, ptr_ty)
            };
            let res = match op {
                "*" => {
                    let l64 = self.b.ins().sextend(types::I64, l);
                    let r64 = self.b.ins().sextend(types::I64, r);
                    let prod = self.b.ins().imul(l64, r64);
                    let sh = self.b.ins().sshr_imm_u(prod, 16);
                    self.b.ins().ireduce(types::I32, sh)
                }
                "/" => {
                    let l64 = self.b.ins().sextend(types::I64, l);
                    let r64 = self.b.ins().sextend(types::I64, r);
                    let shifted = self.b.ins().ishl_imm_u(l64, 16);
                    let q = guarded_sdiv(self.b, types::I64, shifted, r64);
                    self.b.ins().ireduce(types::I32, q)
                }
                _ => int_binop_or_cmp(self.b, types::I32, true, op, l, r),
            };
            self.def_scalar_typed(dst, res);
            return;
        }
        if matches!(lty, MirType::Fix64) || matches!(rty, MirType::Fix64) {
            let l = {
                let __tmp = self.use_scalar(lhs);
                coerce_cl_val(self.b, __tmp, types::I64, ptr_ty)
            };
            let r = {
                let __tmp = self.use_scalar(rhs);
                coerce_cl_val(self.b, __tmp, types::I64, ptr_ty)
            };
            let res = match op {
                "*" => {
                    let lo = self.b.ins().imul(l, r);
                    let hi = self.b.ins().smulhi(l, r);
                    let lo_hi = self.b.ins().ushr_imm_u(lo, 32);
                    let hi_lo = self.b.ins().ishl_imm_u(hi, 32);
                    self.b.ins().bor(lo_hi, hi_lo)
                }
                "/" => guarded_sdiv(self.b, types::I64, l, r),
                _ => int_binop_or_cmp(self.b, types::I64, true, op, l, r),
            };
            self.def_scalar_typed(dst, res);
            return;
        }

        // Scalar float / int / bool / pointer operation.
        let is_float = matches!(lty, MirType::F32 | MirType::F64)
            || matches!(rty, MirType::F32 | MirType::F64);
        if is_float {
            let fty = if matches!(lty, MirType::F64) || matches!(rty, MirType::F64) {
                types::F64
            } else {
                types::F32
            };
            let lv = {
                let __tmp = self.use_scalar(lhs);
                coerce_cl_val(self.b, __tmp, fty, ptr_ty)
            };
            let rv = {
                let __tmp = self.use_scalar(rhs);
                coerce_cl_val(self.b, __tmp, fty, ptr_ty)
            };
            // Match C99 `-ffp-contract=off` and RustGuest/BevyNative IEEE-754 float semantics so
            // multi-target simulation digests remain bit-identical across backends; explicit `fma`
            // / `mul_add` intrinsics still emit `b.ins().fma(...)` when requested.
            let _ = allow_fma;

            let res = if is_cmp_op(op) {
                float_cmp(self.b, op, lv, rv)
            } else {
                float_binop(self.b, fty, op, lv, rv)
            };
            self.def_scalar_typed(dst, res);
            return;
        }

        let op_ty = common_int_ty(lty, rty, dst_ty, ptr_ty, self.ctx.call_conv);
        let signed = is_signed_int_ty(lty) || is_signed_int_ty(rty);
        let lv = {
            let __tmp = self.use_scalar(lhs);
            coerce_cl_val(self.b, __tmp, op_ty, ptr_ty)
        };
        let rv = {
            let __tmp = self.use_scalar(rhs);
            coerce_cl_val(self.b, __tmp, op_ty, ptr_ty)
        };
        let res = int_binop_or_cmp(self.b, op_ty, signed, op, lv, rv);
        self.def_scalar_typed(dst, res);
    }

    fn lower_unop(&mut self, dst: LocalId, op: &str, val: LocalId) {
        let vty = &self.mir_fn.locals[val.0 as usize].ty;
        if let Some(dims) = vec_dims(vty) {
            let mut vs = self.use_vec(val);
            if op == "-" {
                for v in vs.iter_mut().take(usize::from(dims)) {
                    *v = self.b.ins().fneg(*v);
                }
            }
            self.def_vec(dst, vs);
            return;
        }
        let sv = self.use_scalar(val);
        let res = match op {
            "-" => match vty {
                MirType::F32 | MirType::F64 => self.b.ins().fneg(sv),
                _ => self.b.ins().ineg(sv),
            },
            "!" => self.b.ins().icmp_imm_s(IntCC::Equal, sv, 0),
            "~" => self.b.ins().bnot(sv),
            _ => sv,
        };
        self.def_scalar_typed(dst, res);
    }

    fn lower_cast(&mut self, dst: LocalId, val: LocalId, target_ty: &MirType) {
        let src_ty = self.mir_fn.locals[val.0 as usize].ty.clone();
        if let Some(dims) = vec_dims(target_ty) {
            let mut vs = self.use_vec(val);
            for v in vs.iter_mut().skip(usize::from(dims)) {
                *v = self.b.ins().f32const(0.0);
            }
            self.def_vec(dst, vs);
            return;
        }
        let sv = self.use_scalar(val);
        let ptr_ty = self.ctx.ptr_ty;
        // Handle Fix32 / Fix64 scaling casts.
        if matches!(src_ty, MirType::Fix32) && matches!(target_ty, MirType::F32 | MirType::F64) {
            let f = self.b.ins().fcvt_from_sint(types::F64, sv);
            let scale = self.b.ins().f64const(1.0 / 65536.0);
            let scaled = self.b.ins().fmul(f, scale);
            let out = if *target_ty == MirType::F32 {
                self.b.ins().fdemote(types::F32, scaled)
            } else {
                scaled
            };
            self.def_scalar_typed(dst, out);
            return;
        }
        if matches!(src_ty, MirType::F32 | MirType::F64) && matches!(target_ty, MirType::Fix32) {
            let f64v = coerce_cl_val(self.b, sv, types::F64, ptr_ty);
            let scale = self.b.ins().f64const(65536.0);
            let scaled = self.b.ins().fmul(f64v, scale);
            let iv = self.b.ins().fcvt_to_sint_sat(types::I32, scaled);
            self.def_scalar_typed(dst, iv);
            return;
        }
        if matches!(src_ty, MirType::Fix64) && matches!(target_ty, MirType::F32 | MirType::F64) {
            let f = self.b.ins().fcvt_from_sint(types::F64, sv);
            let scale = self.b.ins().f64const(1.0 / 4_294_967_296.0);
            let scaled = self.b.ins().fmul(f, scale);
            let out = if *target_ty == MirType::F32 {
                self.b.ins().fdemote(types::F32, scaled)
            } else {
                scaled
            };
            self.def_scalar_typed(dst, out);
            return;
        }
        if matches!(src_ty, MirType::F32 | MirType::F64) && matches!(target_ty, MirType::Fix64) {
            let f64v = coerce_cl_val(self.b, sv, types::F64, ptr_ty);
            let scale = self.b.ins().f64const(4_294_967_296.0);
            let scaled = self.b.ins().fmul(f64v, scale);
            let iv = self.b.ins().fcvt_to_sint_sat(types::I64, scaled);
            self.def_scalar_typed(dst, iv);
            return;
        }

        let dst_cl = if matches!(
            target_ty,
            MirType::Ptr | MirType::MutPtr | MirType::QueryIter | MirType::Checkpoint
        ) {
            ptr_ty
        } else {
            scalar_cl_type(target_ty, self.ctx.call_conv)
        };
        let src_signed = is_signed_int_ty(&src_ty);
        let dst_signed = is_signed_int_ty(target_ty);
        let res = cast_value(self.b, sv, &src_ty, src_signed, dst_cl, dst_signed, ptr_ty);
        self.def_scalar_typed(dst, res);
    }

    fn lower_intrinsic_math(
        &mut self,
        dst: LocalId,
        name: &str,
        args: &[LocalId],
        _deterministic: bool,
    ) -> Result<(), JitError> {
        let short = name.rsplit("::").next().unwrap_or(name);
        let ptr_ty = self.ctx.ptr_ty;
        let zero_f32 = self.b.ins().f32const(0.0);

        match short {
            "vec2" | "vec3" | "vec4" => {
                let mut lanes = [zero_f32; 4];
                if args.len() == 1 && vec_dims(&self.mir_fn.locals[args[0].0 as usize].ty).is_some()
                {
                    lanes = self.use_vec(args[0]);
                } else {
                    for (i, &a) in args.iter().take(4).enumerate() {
                        lanes[i] = {
                            let __tmp = self.use_scalar(a);
                            coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                        };
                    }
                }
                self.def_vec(dst, lanes);
                return Ok(());
            }
            "dot" if args.len() >= 2 => {
                let dims = self
                    .effective_vec_dims(args[0])
                    .or_else(|| self.effective_vec_dims(args[1]))
                    .unwrap_or(3);
                let a = self.use_vec_dims(args[0], dims);
                let b = self.use_vec_dims(args[1], dims);
                let mut acc = self.b.ins().fmul(a[0], b[0]);
                for i in 1..usize::from(dims) {
                    let p = self.b.ins().fmul(a[i], b[i]);
                    acc = self.b.ins().fadd(acc, p);
                }
                self.def_scalar_typed(dst, acc);
                return Ok(());
            }
            "length" | "len" if !args.is_empty() => {
                let dims = self.effective_vec_dims(args[0]).unwrap_or(3);
                let a = self.use_vec_dims(args[0], dims);
                let mut acc = self.b.ins().fmul(a[0], a[0]);
                for &lane in a.iter().take(usize::from(dims)).skip(1) {
                    let p = self.b.ins().fmul(lane, lane);
                    acc = self.b.ins().fadd(acc, p);
                }
                let l = self.b.ins().sqrt(acc);
                self.def_scalar_typed(dst, l);
                return Ok(());
            }
            "length_sq" | "sqr" if !args.is_empty() => {
                if let Some(dims) = self.effective_vec_dims(args[0]) {
                    let a = self.use_vec_dims(args[0], dims);
                    let mut acc = self.b.ins().fmul(a[0], a[0]);
                    for &lane in a.iter().take(usize::from(dims)).skip(1) {
                        let p = self.b.ins().fmul(lane, lane);
                        acc = self.b.ins().fadd(acc, p);
                    }
                    self.def_scalar_typed(dst, acc);
                } else {
                    let s = self.use_scalar(args[0]);
                    let sq = if matches!(
                        self.mir_fn.locals[args[0].0 as usize].ty,
                        MirType::F32 | MirType::F64
                    ) {
                        self.b.ins().fmul(s, s)
                    } else {
                        self.b.ins().imul(s, s)
                    };
                    self.def_scalar_typed(dst, sq);
                }
                return Ok(());
            }
            "distance" | "distance_sq" if args.len() >= 2 => {
                let dims = self
                    .effective_vec_dims(args[0])
                    .or_else(|| self.effective_vec_dims(args[1]))
                    .unwrap_or(3);
                let a = self.use_vec_dims(args[0], dims);
                let b = self.use_vec_dims(args[1], dims);
                let d0 = self.b.ins().fsub(a[0], b[0]);
                let mut acc = self.b.ins().fmul(d0, d0);
                for i in 1..usize::from(dims) {
                    let di = self.b.ins().fsub(a[i], b[i]);
                    let sq = self.b.ins().fmul(di, di);
                    acc = self.b.ins().fadd(acc, sq);
                }
                let out = if short == "distance" {
                    self.b.ins().sqrt(acc)
                } else {
                    acc
                };
                self.def_scalar_typed(dst, out);
                return Ok(());
            }
            "normalize" | "normalize_or_zero" if !args.is_empty() => {
                let dims = self.effective_vec_dims(args[0]).unwrap_or(3);
                let a = self.use_vec_dims(args[0], dims);
                let mut acc = self.b.ins().fmul(a[0], a[0]);
                for &lane in a.iter().take(usize::from(dims)).skip(1) {
                    let p = self.b.ins().fmul(lane, lane);
                    acc = self.b.ins().fadd(acc, p);
                }
                let eps = self.b.ins().f32const(1e-12);
                let len = self.b.ins().sqrt(acc);
                let safe_ok = self.b.ins().fcmp(FloatCC::GreaterThan, len, eps);
                let one = self.b.ins().f32const(1.0);
                let inv = self.b.ins().fdiv(one, len);
                let inv_safe = self.b.ins().select(safe_ok, inv, zero_f32);
                let mut out = [zero_f32; 4];
                for i in 0..usize::from(dims) {
                    out[i] = self.b.ins().fmul(a[i], inv_safe);
                }
                self.def_vec(dst, out);
                return Ok(());
            }
            "cross" if args.len() >= 2 => {
                let a = self.use_vec_dims(args[0], 3);
                let b = self.use_vec_dims(args[1], 3);
                let p0 = self.b.ins().fmul(a[1], b[2]);
                let p1 = self.b.ins().fmul(a[2], b[1]);
                let cx = self.b.ins().fsub(p0, p1);
                let q0 = self.b.ins().fmul(a[2], b[0]);
                let q1 = self.b.ins().fmul(a[0], b[2]);
                let cy = self.b.ins().fsub(q0, q1);
                let r0 = self.b.ins().fmul(a[0], b[1]);
                let r1 = self.b.ins().fmul(a[1], b[0]);
                let cz = self.b.ins().fsub(r0, r1);
                self.def_vec(dst, [cx, cy, cz, zero_f32]);
                return Ok(());
            }
            "perp" if !args.is_empty() => {
                let a = self.use_vec(args[0]);
                let nx = self.b.ins().fneg(a[1]);
                self.def_vec(dst, [nx, a[0], zero_f32, zero_f32]);
                return Ok(());
            }
            "lerp" if args.len() >= 3 => {
                if let Some(dims) = vec_dims(&self.mir_fn.locals[dst.0 as usize].ty) {
                    let a = self.use_vec(args[0]);
                    let b = self.use_vec(args[1]);
                    let t = {
                        let __tmp = self.use_scalar(args[2]);
                        coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
                    };
                    let mut out = [zero_f32; 4];
                    for i in 0..usize::from(dims) {
                        let d = self.b.ins().fsub(b[i], a[i]);
                        let s = self.b.ins().fmul(d, t);
                        out[i] = self.b.ins().fadd(a[i], s);
                    }
                    self.def_vec(dst, out);
                    return Ok(());
                }
                let fty = if matches!(self.mir_fn.locals[dst.0 as usize].ty, MirType::F64) {
                    types::F64
                } else {
                    types::F32
                };
                let a = {
                    let __tmp = self.use_scalar(args[0]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                let b = {
                    let __tmp = self.use_scalar(args[1]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                let t = {
                    let __tmp = self.use_scalar(args[2]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                let d = self.b.ins().fsub(b, a);
                let s = self.b.ins().fmul(d, t);
                let out = self.b.ins().fadd(a, s);
                self.def_scalar_typed(dst, out);
                return Ok(());
            }
            _ => {}
        }

        // Scalar hardware or imported libm math.
        let dst_mty = self.mir_fn.locals[dst.0 as usize].ty.clone();
        let is_f64 = dst_mty == MirType::F64
            || args
                .first()
                .is_some_and(|a| self.mir_fn.locals[a.0 as usize].ty == MirType::F64);
        let is_int = !is_f64 && dst_mty != MirType::F32 && vec_dims(&dst_mty).is_none();

        if is_int && !args.is_empty() {
            let ity = self.expected_cl_ty(dst);
            let signed = is_signed_int_ty(&dst_mty);
            let a = {
                let __tmp = self.use_scalar(args[0]);
                coerce_cl_val(self.b, __tmp, ity, ptr_ty)
            };
            let out = match short {
                "abs" => {
                    if signed {
                        self.b.ins().iabs(a)
                    } else {
                        a
                    }
                }
                "min" if args.len() >= 2 => {
                    let b = {
                        let __tmp = self.use_scalar(args[1]);
                        coerce_cl_val(self.b, __tmp, ity, ptr_ty)
                    };
                    if signed {
                        self.b.ins().smin(a, b)
                    } else {
                        self.b.ins().umin(a, b)
                    }
                }
                "max" if args.len() >= 2 => {
                    let b = {
                        let __tmp = self.use_scalar(args[1]);
                        coerce_cl_val(self.b, __tmp, ity, ptr_ty)
                    };
                    if signed {
                        self.b.ins().smax(a, b)
                    } else {
                        self.b.ins().umax(a, b)
                    }
                }
                "clamp" if args.len() >= 3 => {
                    let lo = {
                        let __tmp = self.use_scalar(args[1]);
                        coerce_cl_val(self.b, __tmp, ity, ptr_ty)
                    };
                    let hi = {
                        let __tmp = self.use_scalar(args[2]);
                        coerce_cl_val(self.b, __tmp, ity, ptr_ty)
                    };
                    if signed {
                        let c1 = self.b.ins().smax(a, lo);
                        self.b.ins().smin(c1, hi)
                    } else {
                        let c1 = self.b.ins().umax(a, lo);
                        self.b.ins().umin(c1, hi)
                    }
                }
                _ => a,
            };
            self.def_scalar_typed(dst, out);
            return Ok(());
        }

        let fty = if is_f64 { types::F64 } else { types::F32 };
        let a = if let Some(&a0) = args.first() {
            {
                let __tmp = self.use_scalar(a0);
                coerce_cl_val(self.b, __tmp, fty, ptr_ty)
            }
        } else {
            zero_f32
        };

        let hardware_val = match short {
            "sqrt" => Some(self.b.ins().sqrt(a)),
            "abs" => Some(self.b.ins().fabs(a)),
            "floor" => Some(self.b.ins().floor(a)),
            "ceil" => Some(self.b.ins().ceil(a)),
            "trunc" => Some(self.b.ins().trunc(a)),
            "min" if args.len() >= 2 => {
                let b = {
                    let __tmp = self.use_scalar(args[1]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                Some(self.b.ins().fmin(a, b))
            }
            "max" if args.len() >= 2 => {
                let b = {
                    let __tmp = self.use_scalar(args[1]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                Some(self.b.ins().fmax(a, b))
            }
            "clamp" if args.len() >= 3 => {
                let lo = {
                    let __tmp = self.use_scalar(args[1]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                let hi = {
                    let __tmp = self.use_scalar(args[2]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                let c1 = self.b.ins().fmax(a, lo);
                Some(self.b.ins().fmin(c1, hi))
            }
            "saturate" => {
                let z = if is_f64 {
                    self.b.ins().f64const(0.0)
                } else {
                    zero_f32
                };
                let o = if is_f64 {
                    self.b.ins().f64const(1.0)
                } else {
                    self.b.ins().f32const(1.0)
                };
                let c1 = self.b.ins().fmax(a, z);
                Some(self.b.ins().fmin(c1, o))
            }
            "fract" => {
                let fl = self.b.ins().floor(a);
                Some(self.b.ins().fsub(a, fl))
            }
            "sign" | "signum" => {
                let z = if is_f64 {
                    self.b.ins().f64const(0.0)
                } else {
                    zero_f32
                };
                let p1 = if is_f64 {
                    self.b.ins().f64const(1.0)
                } else {
                    self.b.ins().f32const(1.0)
                };
                let m1 = if is_f64 {
                    self.b.ins().f64const(-1.0)
                } else {
                    self.b.ins().f32const(-1.0)
                };
                let gt = self.b.ins().fcmp(FloatCC::GreaterThan, a, z);
                let lt = self.b.ins().fcmp(FloatCC::LessThan, a, z);
                let s1 = self.b.ins().select(lt, m1, z);
                Some(self.b.ins().select(gt, p1, s1))
            }
            "select" if args.len() >= 3 => {
                let cond = self.use_scalar(args[0]);
                let tv = {
                    let __tmp = self.use_scalar(args[1]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                let fv = {
                    let __tmp = self.use_scalar(args[2]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                Some(self.b.ins().select(cond, tv, fv))
            }
            "mul_add" | "fma" if args.len() >= 3 => {
                let b = {
                    let __tmp = self.use_scalar(args[1]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                let c = {
                    let __tmp = self.use_scalar(args[2]);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                };
                Some(self.b.ins().fma(a, b, c))
            }
            _ => None,
        };
        if let Some(v) = hardware_val {
            self.def_scalar_typed(dst, v);
            return Ok(());
        }

        // Imported libm calls (`sinf`, `cosf`, `tanf`, `atan2f`, `powf`, `expf`, `logf`, `roundf`, ...).
        let (sym_name, arity): (&str, usize) = match (short, is_f64) {
            ("sin", false) => ("sinf", 1),
            ("sin", true) => ("sin", 1),
            ("cos", false) => ("cosf", 1),
            ("cos", true) => ("cos", 1),
            ("tan", false) => ("tanf", 1),
            ("tan", true) => ("tan", 1),
            ("asin", false) => ("asinf", 1),
            ("asin", true) => ("asin", 1),
            ("acos", false) => ("acosf", 1),
            ("acos", true) => ("acos", 1),
            ("atan", false) => ("atanf", 1),
            ("atan", true) => ("atan", 1),
            ("atan2", false) => ("atan2f", 2),
            ("atan2", true) => ("atan2", 2),
            ("pow" | "powf", false) => ("powf", 2),
            ("pow" | "powf", true) => ("pow", 2),
            ("exp", false) => ("expf", 1),
            ("exp", true) => ("exp", 1),
            ("log" | "ln", false) => ("logf", 1),
            ("log" | "ln", true) => ("log", 1),
            ("log2", false) => ("log2f", 1),
            ("log2", true) => ("log2", 1),
            ("log10", false) => ("log10f", 1),
            ("log10", true) => ("log10", 1),
            ("round", false) => ("roundf", 1),
            ("round", true) => ("round", 1),
            ("fmod", false) => ("fmodf", 2),
            ("fmod", true) => ("fmod", 2),
            ("copysign", false) => ("copysignf", 2),
            ("copysign", true) => ("copysign", 2),
            ("hypot", false) => ("hypotf", 2),
            ("hypot", true) => ("hypot", 2),
            _ => {
                self.def_scalar_typed(dst, a);
                return Ok(());
            }
        };

        let mut arg_vals = vec![a];
        if arity == 2 {
            let b_val = if let Some(&a1) = args.get(1) {
                {
                    let __tmp = self.use_scalar(a1);
                    coerce_cl_val(self.b, __tmp, fty, ptr_ty)
                }
            } else {
                a
            };
            arg_vals.push(b_val);
        }
        let param_tys = vec![fty; arity];
        let fid = self
            .ctx
            .declare_extern_fn(sym_name, &param_tys, Some(fty))?;
        let fref = self.ctx.obj_mod.declare_func_in_func(fid, self.b.func);
        let call = self.b.ins().call(fref, &arg_vals);
        let res = self.b.inst_results(call)[0];
        self.def_scalar_typed(dst, res);
        Ok(())
    }

    fn lower_helper_call(
        &mut self,
        dst: Option<LocalId>,
        callee: &str,
        args: &[LocalId],
    ) -> Result<(), JitError> {
        let short = callee.rsplit("::").next().unwrap_or(callee);
        let Some(&(fid, hidx)) = self
            .ctx
            .helper_funcs
            .get(callee)
            .or_else(|| self.ctx.helper_funcs.get(short))
        else {
            // Fallback for unqualified math intrinsics emitted as `Call`.
            if let Some(d) = dst {
                return self.lower_intrinsic_math(d, callee, args, false);
            }
            return Ok(());
        };
        let ptr_ty = self.ctx.ptr_ty;
        let hfn = self.ctx.mir.fns[hidx].clone();
        let mut call_args = vec![self.state_ptr];
        for (i, &arg) in args.iter().enumerate() {
            let expected_ty = hfn.params.get(i).map_or_else(
                || self.mir_fn.locals[arg.0 as usize].ty.clone(),
                |p| p.ty.clone(),
            );
            match expected_ty {
                MirType::Unit => {}
                MirType::Vec2 => {
                    let vs = self.use_vec(arg);
                    call_args.push(vs[0]);
                    call_args.push(vs[1]);
                }
                MirType::Vec3 => {
                    let vs = self.use_vec(arg);
                    call_args.push(vs[0]);
                    call_args.push(vs[1]);
                    call_args.push(vs[2]);
                }
                MirType::Vec4 => {
                    let vs = self.use_vec(arg);
                    call_args.extend_from_slice(&vs);
                }
                other => {
                    let cl_ty = if matches!(
                        other,
                        MirType::Ptr
                            | MirType::MutPtr
                            | MirType::Named(_)
                            | MirType::Array { .. }
                            | MirType::Tuple(_)
                    ) {
                        ptr_ty
                    } else {
                        scalar_cl_type(&other, self.ctx.call_conv)
                    };
                    let v = {
                        let __tmp = self.use_scalar(arg);
                        coerce_cl_val(self.b, __tmp, cl_ty, ptr_ty)
                    };
                    call_args.push(v);
                }
            }
        }
        let fref = self.ctx.obj_mod.declare_func_in_func(fid, self.b.func);
        let call = self.b.ins().call(fref, &call_args);
        let results = self.b.inst_results(call).to_vec();
        if let Some(d) = dst {
            let dty = self.mir_fn.locals[d.0 as usize].ty.clone();
            self.bind_param_val(d, &results, &dty);
        }
        Ok(())
    }

    fn lower_struct_init(&mut self, dst: LocalId, type_name: &str, fields: &[(String, LocalId)]) {
        let ptr_ty = self.ctx.ptr_ty;
        let lidx = lookup_name_in_map(&self.ctx.layout_map, type_name);
        let sz = lidx.map_or(16, |i| self.ctx.layouts[i].size).max(8);
        let slot = alloc_zero_slot(self.b, sz, ptr_ty);
        let base_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);

        if let Some(i) = lidx
            && let Some(blob_id) = self.ctx.layouts[i].default_blob_id
        {
            let gv = self.ctx.obj_mod.declare_data_in_func(blob_id, self.b.func);
            let def_ptr = self.b.ins().symbol_value(ptr_ty, gv);
            emit_memcpy(self.b, base_ptr, def_ptr, self.ctx.layouts[i].size);
        }

        for (fname, fval) in fields {
            let (off, resolved_ty) = self.ctx.resolve_field_offset_and_ty(type_name, fname);
            let local_ty = self.effective_local_mir_ty(*fval).clone();
            let dst_mty = resolved_ty.unwrap_or_else(|| local_ty.clone());
            self.store_typed_field_to_mem(*fval, &local_ty, &dst_mty, base_ptr, off as i32);
        }
        self.def_scalar_typed(dst, base_ptr);
    }

    fn lower_array_init(&mut self, dst: LocalId, elems: &[LocalId]) {
        let ptr_ty = self.ctx.ptr_ty;
        let elem_sz = elems.first().map_or(4, |e| {
            self.ctx
                .layout_size_of_mir_ty(&self.mir_fn.locals[e.0 as usize].ty)
        });
        let total = (elems.len().max(1) * elem_sz.max(1)).max(8);
        let slot = alloc_zero_slot(self.b, total, ptr_ty);
        let base_ptr = self.b.ins().stack_addr(ptr_ty, slot, 0);
        for (i, &el) in elems.iter().enumerate() {
            let ety = self.mir_fn.locals[el.0 as usize].ty.clone();
            self.store_local_to_mem(el, &ety, base_ptr, (i * elem_sz) as i32);
        }
        self.def_scalar_typed(dst, base_ptr);
    }

    fn lower_array_index(&mut self, dst: LocalId, base: LocalId, index: LocalId) {
        let ptr_ty = self.ctx.ptr_ty;
        let bp = self.use_scalar(base);
        let idx = {
            let __tmp = self.use_scalar(index);
            coerce_cl_val(self.b, __tmp, ptr_ty, ptr_ty)
        };
        let base_mty = &self.mir_fn.locals[base.0 as usize].ty;
        let dty = self.mir_fn.locals[dst.0 as usize].ty.clone();
        let stride = match base_mty {
            MirType::Array { elem, .. } => self.ctx.layout_size_of_mir_ty(elem),
            MirType::QueryIter => 8,
            _ => self.ctx.layout_size_of_mir_ty(&dty),
        };
        let off = self.b.ins().imul_imm_s(idx, stride as i64);
        let addr = self.b.ins().iadd(bp, off);
        if matches!(
            dty,
            MirType::Named(_) | MirType::Array { .. } | MirType::Tuple(_)
        ) {
            self.def_scalar_typed(dst, addr);
        } else {
            self.load_local_from_mem(dst, &dty, addr, 0);
        }
    }

    fn lower_field_load(
        &mut self,
        dst: LocalId,
        base_ptr: LocalId,
        offset_bytes: u32,
        field_ty: &MirType,
    ) {
        let bp = self.use_scalar(base_ptr);
        let ptr_ty = self.ctx.ptr_ty;
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, bp, 0);
        let load_bb = self.b.create_block();
        let null_bb = self.b.create_block();
        let merge_bb = self.b.create_block();
        self.b.ins().brif(ok, load_bb, &[], null_bb, &[]);

        self.b.switch_to_block(load_bb);
        self.b.seal_block(load_bb);
        if matches!(
            field_ty,
            MirType::Named(_) | MirType::Array { .. } | MirType::Tuple(_)
        ) {
            let addr = self.b.ins().iadd_imm_s(bp, i64::from(offset_bytes));
            self.def_scalar_typed(dst, addr);
        } else {
            self.load_local_from_mem(dst, field_ty, bp, offset_bytes as i32);
        }
        self.b.ins().jump(merge_bb, &[]);

        self.b.switch_to_block(null_bb);
        self.b.seal_block(null_bb);
        self.def_zero_for_local(dst);
        self.b.ins().jump(merge_bb, &[]);

        self.b.switch_to_block(merge_bb);
        self.b.seal_block(merge_bb);
        let _ = ptr_ty;
    }

    fn store_typed_field_to_mem(
        &mut self,
        val: LocalId,
        val_mty: &MirType,
        dst_mty: &MirType,
        dst_base: Value,
        offset: i32,
    ) {
        let val_is_agg_ptr = matches!(
            val_mty,
            MirType::Named(_)
                | MirType::Array { .. }
                | MirType::Tuple(_)
                | MirType::Ptr
                | MirType::MutPtr
        );
        if matches!(
            dst_mty,
            MirType::Named(_) | MirType::Array { .. } | MirType::Tuple(_)
        ) && val_is_agg_ptr
        {
            let src_ptr = self.use_scalar(val);
            let sz = self.ctx.layout_size_of_mir_ty(dst_mty);
            let dst_addr = self.b.ins().iadd_imm_s(dst_base, i64::from(offset));
            emit_memcpy(self.b, dst_addr, src_ptr, sz);
        } else {
            let store_mty = if matches!(
                dst_mty,
                MirType::Named(_) | MirType::Array { .. } | MirType::Tuple(_)
            ) {
                val_mty
            } else {
                dst_mty
            };
            self.store_local_to_mem(val, store_mty, dst_base, offset);
        }
    }

    fn lower_field_store(
        &mut self,
        base_ptr: LocalId,
        layout_key: &str,
        field: &str,
        offset_bytes: u32,
        val: LocalId,
    ) {
        let bp = self.use_scalar(base_ptr);
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, bp, 0);
        let store_bb = self.b.create_block();
        let skip_bb = self.b.create_block();
        self.b.ins().brif(ok, store_bb, &[], skip_bb, &[]);

        self.b.switch_to_block(store_bb);
        self.b.seal_block(store_bb);
        let val_mty = self.effective_local_mir_ty(val).clone();
        let (_, resolved_field_ty) = self.ctx.resolve_field_offset_and_ty(layout_key, field);
        let dst_mty = resolved_field_ty.unwrap_or_else(|| val_mty.clone());
        self.store_typed_field_to_mem(val, &val_mty, &dst_mty, bp, offset_bytes as i32);
        self.b.ins().jump(skip_bb, &[]);

        self.b.switch_to_block(skip_bb);
        self.b.seal_block(skip_bb);
    }

    fn def_zero_for_local(&mut self, lid: LocalId) {
        let zero_f32 = self.b.ins().f32const(0.0);
        match self.effective_local_mir_ty(lid) {
            MirType::Vec2 | MirType::Vec3 | MirType::Vec4 => {
                self.def_vec(lid, [zero_f32; 4]);
            }
            MirType::F32 => self.def_scalar_typed(lid, zero_f32),
            MirType::F64 => {
                let z = self.b.ins().f64const(0.0);
                self.def_scalar_typed(lid, z);
            }
            _ => {
                let ty = self.expected_cl_ty(lid);
                let z = self.b.ins().iconst(ty, 0);
                self.def_scalar_typed(lid, z);
            }
        }
    }

    fn lower_row_ptr(
        &mut self,
        dst: LocalId,
        col_ptr: LocalId,
        row_idx: LocalId,
        stride_bytes: u32,
        is_sparse: bool,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        if !is_sparse {
            // Check strength reduction plan (`iadd_imm_s` inside row loop, ZERO `imul`!).
            for ((slot_id, base_id), &(stride, ptr_var, is_ent)) in &self.sr_plan.reduced {
                let _ = slot_id;
                if !is_ent && *base_id == col_ptr.0 && stride == stride_bytes {
                    let p = self.b.use_var(ptr_var);
                    self.def_scalar_typed(dst, p);
                    return;
                }
            }
            let base = self.use_scalar(col_ptr);
            let idx = {
                let __tmp = self.use_scalar(row_idx);
                coerce_cl_val(self.b, __tmp, ptr_ty, ptr_ty)
            };
            let off = self.b.ins().imul_imm_s(idx, i64::from(stride_bytes));
            let res = self.b.ins().iadd(base, off);
            self.def_scalar_typed(dst, res);
            return;
        }

        // Batched `@sparse` indirection: `col_ptr` points to `*const *const u8` (`row_ptrs[row_idx]`).
        let base = self.use_scalar(col_ptr);
        let zero_p = self.b.ins().iconst(ptr_ty, 0);
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, base, 0);
        let ld_bb = self.b.create_block();
        let skip_bb = self.b.create_block();
        let merge_bb = self.b.create_block();
        self.b.append_block_param(merge_bb, ptr_ty);
        self.b.ins().brif(ok, ld_bb, &[], skip_bb, &[]);

        self.b.switch_to_block(ld_bb);
        self.b.seal_block(ld_bb);
        let idx = {
            let __tmp = self.use_scalar(row_idx);
            coerce_cl_val(self.b, __tmp, ptr_ty, ptr_ty)
        };
        let off = self.b.ins().imul_imm_s(idx, self.ctx.ptr_bytes as i64);
        let slot_addr = self.b.ins().iadd(base, off);
        let loaded = self
            .b
            .ins()
            .load(ptr_ty, MemFlagsData::trusted(), slot_addr, 0);
        self.b.ins().jump(merge_bb, &[BlockArg::Value(loaded)]);

        self.b.switch_to_block(skip_bb);
        self.b.seal_block(skip_bb);
        self.b.ins().jump(merge_bb, &[BlockArg::Value(zero_p)]);

        self.b.switch_to_block(merge_bb);
        self.b.seal_block(merge_bb);
        let res = self.b.block_params(merge_bb)[0];
        self.def_scalar_typed(dst, res);
    }

    fn lower_entity_at_row(&mut self, dst: LocalId, entities_ptr: LocalId, row_idx: LocalId) {
        let ptr_ty = self.ctx.ptr_ty;
        for ((_, base_id), &(_, ptr_var, is_ent)) in &self.sr_plan.reduced {
            if is_ent && *base_id == entities_ptr.0 {
                let ep = self.b.use_var(ptr_var);
                let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ep, 0);
                let ld_bb = self.b.create_block();
                let null_bb = self.b.create_block();
                let done_bb = self.b.create_block();
                self.b.append_block_param(done_bb, types::I64);
                self.b.ins().brif(ok, ld_bb, &[], null_bb, &[]);

                self.b.switch_to_block(ld_bb);
                self.b.seal_block(ld_bb);
                let ent = self
                    .b
                    .ins()
                    .load(types::I64, MemFlagsData::trusted(), ep, 0);
                self.b.ins().jump(done_bb, &[BlockArg::Value(ent)]);

                self.b.switch_to_block(null_bb);
                self.b.seal_block(null_bb);
                let z = self.b.ins().iconst(types::I64, 0);
                self.b.ins().jump(done_bb, &[BlockArg::Value(z)]);

                self.b.switch_to_block(done_bb);
                self.b.seal_block(done_bb);
                let res = self.b.block_params(done_bb)[0];
                self.def_scalar_typed(dst, res);
                return;
            }
        }

        let ep = self.use_scalar(entities_ptr);
        let idx = {
            let __tmp = self.use_scalar(row_idx);
            coerce_cl_val(self.b, __tmp, ptr_ty, ptr_ty)
        };
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ep, 0);
        let ld_bb = self.b.create_block();
        let null_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.append_block_param(done_bb, types::I64);
        self.b.ins().brif(ok, ld_bb, &[], null_bb, &[]);

        self.b.switch_to_block(ld_bb);
        self.b.seal_block(ld_bb);
        let off = self.b.ins().imul_imm_s(idx, 8);
        let addr = self.b.ins().iadd(ep, off);
        let ent = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), addr, 0);
        self.b.ins().jump(done_bb, &[BlockArg::Value(ent)]);

        self.b.switch_to_block(null_bb);
        self.b.seal_block(null_bb);
        let z = self.b.ins().iconst(types::I64, 0);
        self.b.ins().jump(done_bb, &[BlockArg::Value(z)]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        let res = self.b.block_params(done_bb)[0];
        self.def_scalar_typed(dst, res);
    }

    fn call_iter_col(&mut self, query_idx: u32, term_idx: u32, slot_offset: usize) -> Value {
        let ptr_ty = self.ctx.ptr_ty;
        let iter = self.ensure_query_iter(query_idx);
        let wire_term = self.wire_term_index(query_idx, term_idx);
        let tv = self.b.ins().iconst(ptr_ty, wire_term as i64);
        call_vtable_guarded(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            slot_offset,
            &[ptr_ty, ptr_ty],
            ptr_ty,
            ptr_ty,
            self.ctx.call_conv,
            iter,
            &[iter, tv],
        )
    }

    fn emit_flush_changed_range(
        &mut self,
        query_idx: u32,
        term_idx: u32,
        run_start: Value,
        run_len: Value,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        let iter = self.ensure_query_iter(query_idx);
        let wire_term = self.wire_term_index(query_idx, term_idx);
        let rlen_nz = self.b.ins().icmp_imm_s(IntCC::NotEqual, run_len, 0);
        let iter_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, iter, 0);
        let go = self.b.ins().band(rlen_nz, iter_ok);
        let call_bb = self.b.create_block();
        let skip_bb = self.b.create_block();
        self.b.ins().brif(go, call_bb, &[], skip_bb, &[]);

        self.b.switch_to_block(call_bb);
        self.b.seal_block(call_bb);
        let tv = self.b.ins().iconst(ptr_ty, wire_term as i64);
        let rs = coerce_cl_val(self.b, run_start, ptr_ty, ptr_ty);
        let rl = coerce_cl_val(self.b, run_len, ptr_ty, ptr_ty);
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::ITER_MARK_CHANGED_RANGE,
            &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[iter, tv, rs, rl],
        );
        self.b.ins().jump(skip_bb, &[]);

        self.b.switch_to_block(skip_bb);
        self.b.seal_block(skip_bb);
    }

    fn lower_dirty_run_record_row(
        &mut self,
        run_start: LocalId,
        run_len: LocalId,
        row_idx: LocalId,
    ) {
        let cur_start_raw = self.use_scalar(run_start);
        let cur_start = coerce_cl_val(self.b, cur_start_raw, types::I32, self.ctx.ptr_ty);
        let cur_len_raw = self.use_scalar(run_len);
        let cur_len = coerce_cl_val(self.b, cur_len_raw, types::I32, self.ctx.ptr_ty);
        let r_raw = self.use_scalar(row_idx);
        let r = coerce_cl_val(self.b, r_raw, types::I32, self.ctx.ptr_ty);

        let is_empty = self.b.ins().icmp_imm_s(IntCC::Equal, cur_len, 0);
        let expected_next = self.b.ins().iadd(cur_start, cur_len);
        let is_contig = self.b.ins().icmp(IntCC::Equal, r, expected_next);
        let is_dup = self.b.ins().icmp(IntCC::Equal, r, cur_start);

        let start_bb = self.b.create_block();
        let non_empty_bb = self.b.create_block();
        let contig_bb = self.b.create_block();
        let gap_bb = self.b.create_block();
        let done_bb = self.b.create_block();

        self.b
            .ins()
            .brif(is_empty, start_bb, &[], non_empty_bb, &[]);

        self.b.switch_to_block(start_bb);
        self.b.seal_block(start_bb);
        let one = self.b.ins().iconst(types::I32, 1);
        self.def_scalar_typed(run_start, r);
        self.def_scalar_typed(run_len, one);
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(non_empty_bb);
        self.b.seal_block(non_empty_bb);
        let keep_bb = done_bb;
        let check_contig_bb = self.b.create_block();
        self.b
            .ins()
            .brif(is_dup, keep_bb, &[], check_contig_bb, &[]);

        self.b.switch_to_block(check_contig_bb);
        self.b.seal_block(check_contig_bb);
        self.b.ins().brif(is_contig, contig_bb, &[], gap_bb, &[]);

        self.b.switch_to_block(contig_bb);
        self.b.seal_block(contig_bb);
        let inc_len = self.b.ins().iadd_imm_s(cur_len, 1);
        self.def_scalar_typed(run_len, inc_len);
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(gap_bb);
        self.b.seal_block(gap_bb);
        if let Some(&(qi, ti)) = self.dirty_targets.get(&(run_start.0, run_len.0)) {
            self.emit_flush_changed_range(qi, ti, cur_start, cur_len);
        }
        let one2 = self.b.ins().iconst(types::I32, 1);
        self.def_scalar_typed(run_start, r);
        self.def_scalar_typed(run_len, one2);
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    fn lower_res_access(&mut self, resource: &str, mutable: bool) -> Value {
        let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, resource) else {
            return self.b.ins().iconst(self.ctx.ptr_ty, 0);
        };
        emit_res_ptr_lookup(
            self.ctx,
            self.b,
            self.api_ptr,
            self.sys_ctx,
            self.state_ptr,
            lidx,
            mutable,
        )
    }

    fn call_entity_get(
        &mut self,
        query_idx: u32,
        term_idx: u32,
        entity: Value,
        mutable: bool,
    ) -> Value {
        let ptr_ty = self.ctx.ptr_ty;
        let wire_term = self.wire_term_index(query_idx, term_idx);
        let qv = self.b.ins().iconst(ptr_ty, i64::from(query_idx));
        let tv = self.b.ins().iconst(ptr_ty, wire_term as i64);
        let slot = if mutable {
            api_slots::SYS_ENTITY_GET_MUT
        } else {
            api_slots::SYS_ENTITY_GET
        };
        let ent_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, entity, 0);
        let ctx_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, self.sys_ctx, 0);
        let ok = self.b.ins().band(ent_ok, ctx_ok);
        let call_bb = self.b.create_block();
        let null_bb = self.b.create_block();
        let merge_bb = self.b.create_block();
        self.b.append_block_param(merge_bb, ptr_ty);
        self.b.ins().brif(ok, call_bb, &[], null_bb, &[]);

        self.b.switch_to_block(call_bb);
        self.b.seal_block(call_bb);
        let p = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            slot,
            &[ptr_ty, ptr_ty, types::I64, ptr_ty],
            Some(ptr_ty),
            ptr_ty,
            self.ctx.call_conv,
            &[self.sys_ctx, qv, entity, tv],
        );
        self.b.ins().jump(merge_bb, &[BlockArg::Value(p)]);

        self.b.switch_to_block(null_bb);
        self.b.seal_block(null_bb);
        let zp = self.b.ins().iconst(ptr_ty, 0);
        self.b.ins().jump(merge_bb, &[BlockArg::Value(zp)]);

        self.b.switch_to_block(merge_bb);
        self.b.seal_block(merge_bb);
        self.b.block_params(merge_bb)[0]
    }

    fn lower_resolve_named_object(&mut self, name: &str) -> Result<Value, JitError> {
        let Some(obj_idx) = self.ctx.mir.objects.iter().position(|o| o.name == name) else {
            return Ok(self.b.ins().iconst(types::I64, FFI_ENTITY_NULL as i64));
        };
        let ptr_ty = self.ctx.ptr_ty;
        let off = self.ctx.state_layout.obj_slot_offset(obj_idx) as i32;
        let cached = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), self.state_ptr, off);

        let is_zero = self.b.ins().icmp_imm_s(IntCC::Equal, cached, 0);
        let ctx_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, self.sys_ctx, 0);
        let need_lazy = self.b.ins().band(is_zero, ctx_ok);

        let lazy_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.append_block_param(done_bb, types::I64);
        self.b
            .ins()
            .brif(need_lazy, lazy_bb, &[], done_bb, &[BlockArg::Value(cached)]);

        self.b.switch_to_block(lazy_bb);
        self.b.seal_block(lazy_bb);

        let lookup_qi = self
            .sys_entry
            .and_then(|e| {
                e.extra_obj_queries
                    .iter()
                    .find(|x| x.obj_idx == obj_idx)
                    .map(|x| x.wire_query_idx)
            })
            .or_else(|| find_reusable_obj_query(self.ctx, self.mir_fn, obj_idx));

        let mut resolved = cached;
        if let Some(qi) = lookup_qi {
            let iter_slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
            let iter_ptr_out = self.b.ins().stack_addr(ptr_ty, iter_slot, 0);
            let qv = self.b.ins().iconst(ptr_ty, qi as i64);
            let rc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::SYS_QUERY,
                &[ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[self.sys_ctx, qv, iter_ptr_out],
            );
            let iter = self
                .b
                .ins()
                .load(ptr_ty, MemFlagsData::trusted(), iter_ptr_out, 0);
            let rc_ok = self.b.ins().icmp_imm_s(IntCC::Equal, rc, 0);
            let iter_nz = self.b.ins().icmp_imm_s(IntCC::NotEqual, iter, 0);
            let ok_iter = self.b.ins().band(rc_ok, iter_nz);

            let chunk_bb = self.b.create_block();
            let after_q_bb = self.b.create_block();
            self.b.append_block_param(after_q_bb, types::I64);
            self.b.ins().brif(
                ok_iter,
                chunk_bb,
                &[],
                after_q_bb,
                &[BlockArg::Value(cached)],
            );

            self.b.switch_to_block(chunk_bb);
            self.b.seal_block(chunk_bb);
            let len_slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
            let len_ptr = self.b.ins().stack_addr(ptr_ty, len_slot, 0);
            let has = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::ITER_NEXT_CHUNK,
                &[ptr_ty, ptr_ty],
                Some(types::I8),
                ptr_ty,
                self.ctx.call_conv,
                &[iter, len_ptr],
            );
            let clen = self
                .b
                .ins()
                .load(ptr_ty, MemFlagsData::trusted(), len_ptr, 0);
            let has_b = self.b.ins().icmp_imm_s(IntCC::NotEqual, has, 0);
            let len_pos = self.b.ins().icmp_imm_s(IntCC::SignedGreaterThan, clen, 0);
            let got = self.b.ins().band(has_b, len_pos);

            let take_bb = self.b.create_block();
            self.b
                .ins()
                .brif(got, take_bb, &[], after_q_bb, &[BlockArg::Value(cached)]);

            self.b.switch_to_block(take_bb);
            self.b.seal_block(take_bb);
            let ents = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::ITER_ENTITIES,
                &[ptr_ty],
                Some(ptr_ty),
                ptr_ty,
                self.ctx.call_conv,
                &[iter],
            );
            let e0 = self
                .b
                .ins()
                .load(types::I64, MemFlagsData::trusted(), ents, 0);
            self.b
                .ins()
                .store(MemFlagsData::trusted(), e0, self.state_ptr, off);

            // Reset iterator if `qi` came from one of the system's own ECS queries so normal iteration still sees chunk 0!
            let _rst = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::ITER_RESET,
                &[ptr_ty],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[iter],
            );

            // Also call `bind_named_object(host_ctx, name_strview, e0)` (`Slot 56`).
            let (str_id, str_len) = self.ctx.intern_bytes(name)?;
            let gv = self.ctx.obj_mod.declare_data_in_func(str_id, self.b.func);
            let s_ptr = self.b.ins().symbol_value(ptr_ty, gv);
            let s_len = self.b.ins().iconst(ptr_ty, str_len as i64);
            let _bind_rc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::BIND_NAMED_OBJECT,
                &[ptr_ty, ptr_ty, ptr_ty, types::I64],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[self.host_ctx, s_ptr, s_len, e0],
            );
            self.b.ins().jump(after_q_bb, &[BlockArg::Value(e0)]);

            self.b.switch_to_block(after_q_bb);
            self.b.seal_block(after_q_bb);
            resolved = self.b.block_params(after_q_bb)[0];
        }
        self.b.ins().jump(done_bb, &[BlockArg::Value(resolved)]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        Ok(self.b.block_params(done_bb)[0])
    }

    fn lower_intern_symbol(&mut self, symbol: &str) -> Result<Value, JitError> {
        let ptr_ty = self.ctx.ptr_ty;
        let (sid, slen) = self.ctx.intern_bytes(symbol)?;
        let gv = self.ctx.obj_mod.declare_data_in_func(sid, self.b.func);
        let sptr = self.b.ins().symbol_value(ptr_ty, gv);
        let len_v = self.b.ins().iconst(ptr_ty, slen as i64);
        let out_slot = alloc_zero_slot(self.b, structs::BAM_SYMBOL_SIZE, ptr_ty);
        let out_ptr = self.b.ins().stack_addr(ptr_ty, out_slot, 0);
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::INTERN_SYMBOL,
            &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[self.host_ctx, sptr, len_v, out_ptr],
        );
        Ok(self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), out_ptr, 0))
    }

    fn guarded_load(&mut self, ptr: Value, offset: i32, ty: Type) -> Value {
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let l_bb = self.b.create_block();
        let n_bb = self.b.create_block();
        let m_bb = self.b.create_block();
        self.b.append_block_param(m_bb, ty);
        self.b.ins().brif(ok, l_bb, &[], n_bb, &[]);
        self.b.switch_to_block(l_bb);
        self.b.seal_block(l_bb);
        let v = self.b.ins().load(ty, MemFlagsData::new(), ptr, offset);
        self.b.ins().jump(m_bb, &[BlockArg::Value(v)]);
        self.b.switch_to_block(n_bb);
        self.b.seal_block(n_bb);
        let z = zero_for_cl_type(self.b, ty);
        self.b.ins().jump(m_bb, &[BlockArg::Value(z)]);
        self.b.switch_to_block(m_bb);
        self.b.seal_block(m_bb);
        self.b.block_params(m_bb)[0]
    }

    fn guarded_store(&mut self, ptr: Value, offset: i32, val: Value) {
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let s_bb = self.b.create_block();
        let d_bb = self.b.create_block();
        self.b.ins().brif(ok, s_bb, &[], d_bb, &[]);
        self.b.switch_to_block(s_bb);
        self.b.seal_block(s_bb);
        self.b.ins().store(MemFlagsData::new(), val, ptr, offset);
        self.b.ins().jump(d_bb, &[]);
        self.b.switch_to_block(d_bb);
        self.b.seal_block(d_bb);
    }

    fn lower_grace_tick(&mut self, ptr: Value, dt_sec: Value) {
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);
        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let rem = self.b.ins().load(types::F32, MemFlagsData::new(), ptr, 0);
        let sub = self.b.ins().fsub(rem, dt_sec);
        let zero = self.b.ins().f32const(0.0);
        let clamped = self.b.ins().fmax(sub, zero);
        self.b.ins().store(MemFlagsData::new(), clamped, ptr, 0);
        self.b.ins().jump(done_bb, &[]);
        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    fn lower_input_buf_push(
        &mut self,
        ptr: Value,
        capacity: u32,
        action_id: Value,
        window_sec: Value,
    ) {
        let cap = capacity.max(1);
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let do_bb = self.b.create_block();
        let exit_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], exit_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);

        let idx_var = self.b.declare_var(types::I32);
        let best_idx_var = self.b.declare_var(types::I32);
        let best_rem_var = self.b.declare_var(types::F32);
        let z32 = self.b.ins().iconst(types::I32, 0);
        let huge = self.b.ins().f32const(1e30);
        self.b.def_var(idx_var, z32);
        self.b.def_var(best_idx_var, z32);
        self.b.def_var(best_rem_var, huge);

        let hdr_bb = self.b.create_block();
        let body_bb = self.b.create_block();
        let write_best_bb = self.b.create_block();
        self.b.ins().jump(hdr_bb, &[]);

        self.b.switch_to_block(hdr_bb);
        let i = self.b.use_var(idx_var);
        let in_bounds = self
            .b
            .ins()
            .icmp_imm_s(IntCC::UnsignedLessThan, i, i64::from(cap));
        self.b
            .ins()
            .brif(in_bounds, body_bb, &[], write_best_bb, &[]);

        self.b.switch_to_block(body_bb);
        self.b.seal_block(body_bb);
        let i_ptr = coerce_cl_val(self.b, i, self.ctx.ptr_ty, self.ctx.ptr_ty);
        let byte_off = self.b.ins().imul_imm_s(i_ptr, 8);
        let entry_ptr = self.b.ins().iadd(ptr, byte_off);
        let cur_aid = self
            .b
            .ins()
            .load(types::I16, MemFlagsData::new(), entry_ptr, 0);
        let cur_rem = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::new(), entry_ptr, 4);

        let same_aid = self.b.ins().icmp(IntCC::Equal, cur_aid, action_id);
        let zero_f = self.b.ins().f32const(0.0);
        let cur_active = self.b.ins().fcmp(FloatCC::GreaterThan, cur_rem, zero_f);
        let match_active = self.b.ins().band(same_aid, cur_active);

        let overwrite_here_bb = self.b.create_block();
        let check_empty_bb = self.b.create_block();
        self.b
            .ins()
            .brif(match_active, overwrite_here_bb, &[], check_empty_bb, &[]);

        self.b.switch_to_block(overwrite_here_bb);
        self.b.seal_block(overwrite_here_bb);
        let z16 = self.b.ins().iconst(types::I16, 0);
        self.b
            .ins()
            .store(MemFlagsData::new(), action_id, entry_ptr, 0);
        self.b.ins().store(MemFlagsData::new(), z16, entry_ptr, 2);
        self.b
            .ins()
            .store(MemFlagsData::new(), window_sec, entry_ptr, 4);
        self.b.ins().jump(exit_bb, &[]);

        self.b.switch_to_block(check_empty_bb);
        self.b.seal_block(check_empty_bb);
        let cur_best_rem = self.b.use_var(best_rem_var);
        let cur_best_idx = self.b.use_var(best_idx_var);
        let is_empty_sentinel = self.b.ins().icmp_imm_s(IntCC::Equal, cur_aid, -1);
        let is_expired = self.b.ins().fcmp(FloatCC::LessThanOrEqual, cur_rem, zero_f);
        let slot_free = self.b.ins().bor(is_empty_sentinel, is_expired);
        let smaller_rem = self.b.ins().fcmp(FloatCC::LessThan, cur_rem, cur_best_rem);
        let take_best = self.b.ins().bor(slot_free, smaller_rem);
        let eff_rem = self.b.ins().select(slot_free, zero_f, cur_rem);
        let next_best_rem = self.b.ins().select(take_best, eff_rem, cur_best_rem);
        let next_best_idx = self.b.ins().select(take_best, i, cur_best_idx);
        self.b.def_var(best_rem_var, next_best_rem);
        self.b.def_var(best_idx_var, next_best_idx);
        let next_i = self.b.ins().iadd_imm_s(i, 1);
        self.b.def_var(idx_var, next_i);
        self.b.ins().jump(hdr_bb, &[]);

        self.b.switch_to_block(write_best_bb);
        self.b.seal_block(write_best_bb);
        let best_idx_raw = self.b.use_var(best_idx_var);
        let bi = coerce_cl_val(self.b, best_idx_raw, self.ctx.ptr_ty, self.ctx.ptr_ty);
        let boff = self.b.ins().imul_imm_s(bi, 8);
        let bptr = self.b.ins().iadd(ptr, boff);
        let z16_2 = self.b.ins().iconst(types::I16, 0);
        self.b.ins().store(MemFlagsData::new(), action_id, bptr, 0);
        self.b.ins().store(MemFlagsData::new(), z16_2, bptr, 2);
        self.b.ins().store(MemFlagsData::new(), window_sec, bptr, 4);
        self.b.ins().jump(exit_bb, &[]);

        self.b.seal_block(hdr_bb);
        self.b.switch_to_block(exit_bb);
        self.b.seal_block(exit_bb);
    }

    fn lower_input_buf_find(
        &mut self,
        ptr: Value,
        capacity: u32,
        action_id: Value,
        consume: bool,
    ) -> Value {
        let cap = capacity.max(1);
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let do_bb = self.b.create_block();
        let fail_bb = self.b.create_block();
        let exit_bb = self.b.create_block();
        self.b.append_block_param(exit_bb, types::I8);
        self.b.ins().brif(ok, do_bb, &[], fail_bb, &[]);

        self.b.switch_to_block(fail_bb);
        self.b.seal_block(fail_bb);
        let f_i8 = self.b.ins().iconst(types::I8, 0);
        self.b.ins().jump(exit_bb, &[BlockArg::Value(f_i8)]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let idx_var = self.b.declare_var(types::I32);
        let z32 = self.b.ins().iconst(types::I32, 0);
        self.b.def_var(idx_var, z32);
        let hdr_bb = self.b.create_block();
        let body_bb = self.b.create_block();
        let miss_bb = self.b.create_block();
        self.b.ins().jump(hdr_bb, &[]);

        self.b.switch_to_block(hdr_bb);
        let i = self.b.use_var(idx_var);
        let in_b = self
            .b
            .ins()
            .icmp_imm_s(IntCC::UnsignedLessThan, i, i64::from(cap));
        self.b.ins().brif(in_b, body_bb, &[], miss_bb, &[]);

        self.b.switch_to_block(body_bb);
        self.b.seal_block(body_bb);
        let i_ptr = coerce_cl_val(self.b, i, self.ctx.ptr_ty, self.ctx.ptr_ty);
        let off = self.b.ins().imul_imm_s(i_ptr, 8);
        let eptr = self.b.ins().iadd(ptr, off);
        let cur_aid = self.b.ins().load(types::I16, MemFlagsData::new(), eptr, 0);
        let cur_rem = self.b.ins().load(types::F32, MemFlagsData::new(), eptr, 4);
        let zero_f = self.b.ins().f32const(0.0);
        let eq = self.b.ins().icmp(IntCC::Equal, cur_aid, action_id);
        let act = self.b.ins().fcmp(FloatCC::GreaterThan, cur_rem, zero_f);
        let hit = self.b.ins().band(eq, act);

        let hit_bb = self.b.create_block();
        let step_bb = self.b.create_block();
        self.b.ins().brif(hit, hit_bb, &[], step_bb, &[]);

        self.b.switch_to_block(hit_bb);
        self.b.seal_block(hit_bb);
        if consume {
            let empty_aid = self.b.ins().iconst(types::I16, 0xFFFF);
            self.b.ins().store(MemFlagsData::new(), empty_aid, eptr, 0);
            self.b.ins().store(MemFlagsData::new(), zero_f, eptr, 4);
        }
        let t_i8 = self.b.ins().iconst(types::I8, 1);
        self.b.ins().jump(exit_bb, &[BlockArg::Value(t_i8)]);

        self.b.switch_to_block(step_bb);
        self.b.seal_block(step_bb);
        let ni = self.b.ins().iadd_imm_s(i, 1);
        self.b.def_var(idx_var, ni);
        self.b.ins().jump(hdr_bb, &[]);

        self.b.switch_to_block(miss_bb);
        self.b.seal_block(miss_bb);
        let miss_i8 = self.b.ins().iconst(types::I8, 0);
        self.b.ins().jump(exit_bb, &[BlockArg::Value(miss_i8)]);

        self.b.seal_block(hdr_bb);
        self.b.switch_to_block(exit_bb);
        self.b.seal_block(exit_bb);
        self.b.block_params(exit_bb)[0]
    }

    fn lower_input_buf_tick(&mut self, ptr: Value, capacity: u32, dt_sec: Value) {
        let cap = capacity.max(1);
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let do_bb = self.b.create_block();
        let exit_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], exit_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let idx_var = self.b.declare_var(types::I32);
        let z32 = self.b.ins().iconst(types::I32, 0);
        self.b.def_var(idx_var, z32);
        let hdr_bb = self.b.create_block();
        let body_bb = self.b.create_block();
        self.b.ins().jump(hdr_bb, &[]);

        self.b.switch_to_block(hdr_bb);
        let i = self.b.use_var(idx_var);
        let in_b = self
            .b
            .ins()
            .icmp_imm_s(IntCC::UnsignedLessThan, i, i64::from(cap));
        self.b.ins().brif(in_b, body_bb, &[], exit_bb, &[]);

        self.b.switch_to_block(body_bb);
        self.b.seal_block(body_bb);
        let i_ptr = coerce_cl_val(self.b, i, self.ctx.ptr_ty, self.ctx.ptr_ty);
        let off = self.b.ins().imul_imm_s(i_ptr, 8);
        let eptr = self.b.ins().iadd(ptr, off);
        let cur_rem = self.b.ins().load(types::F32, MemFlagsData::new(), eptr, 4);
        let zero_f = self.b.ins().f32const(0.0);
        let pos = self.b.ins().fcmp(FloatCC::GreaterThan, cur_rem, zero_f);

        let dec_bb = self.b.create_block();
        let step_bb = self.b.create_block();
        self.b.ins().brif(pos, dec_bb, &[], step_bb, &[]);

        self.b.switch_to_block(dec_bb);
        self.b.seal_block(dec_bb);
        let rem_next = self.b.ins().fsub(cur_rem, dt_sec);
        let expired = self
            .b
            .ins()
            .fcmp(FloatCC::LessThanOrEqual, rem_next, zero_f);
        let clamped = self.b.ins().fmax(rem_next, zero_f);
        self.b.ins().store(MemFlagsData::new(), clamped, eptr, 4);
        let cur_aid = self.b.ins().load(types::I16, MemFlagsData::new(), eptr, 0);
        let empty_aid = self.b.ins().iconst(types::I16, 0xFFFF);
        let next_aid = self.b.ins().select(expired, empty_aid, cur_aid);
        self.b.ins().store(MemFlagsData::new(), next_aid, eptr, 0);
        self.b.ins().jump(step_bb, &[]);

        self.b.switch_to_block(step_bb);
        self.b.seal_block(step_bb);
        let ni = self.b.ins().iadd_imm_s(i, 1);
        self.b.def_var(idx_var, ni);
        self.b.ins().jump(hdr_bb, &[]);

        self.b.seal_block(hdr_bb);
        self.b.switch_to_block(exit_bb);
        self.b.seal_block(exit_bb);
    }

    fn lower_bitset_mut(&mut self, ptr: Value, words: u32, bit: Value, set_bit: bool) {
        let word_idx = self.b.ins().ushr_imm_u(bit, 5);
        let bit_idx = self.b.ins().band_imm_u(bit, 31);
        let ok_ptr = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let ok_bounds =
            self.b
                .ins()
                .icmp_imm_s(IntCC::UnsignedLessThan, word_idx, i64::from(words));
        let ok = self.b.ins().band(ok_ptr, ok_bounds);

        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let wi_ptr = coerce_cl_val(self.b, word_idx, self.ctx.ptr_ty, self.ctx.ptr_ty);
        let off = self.b.ins().imul_imm_s(wi_ptr, 4);
        let addr = self.b.ins().iadd(ptr, off);
        let cur = self.b.ins().load(types::I32, MemFlagsData::new(), addr, 0);
        let one = self.b.ins().iconst(types::I32, 1);
        let mask = self.b.ins().ishl(one, bit_idx);
        let next = if set_bit {
            self.b.ins().bor(cur, mask)
        } else {
            let inv = self.b.ins().bnot(mask);
            self.b.ins().band(cur, inv)
        };
        self.b.ins().store(MemFlagsData::new(), next, addr, 0);
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    fn lower_bitset_get(&mut self, ptr: Value, words: u32, bit: Value) -> Value {
        let word_idx = self.b.ins().ushr_imm_u(bit, 5);
        let bit_idx = self.b.ins().band_imm_u(bit, 31);
        let ok_ptr = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let ok_bounds =
            self.b
                .ins()
                .icmp_imm_s(IntCC::UnsignedLessThan, word_idx, i64::from(words));
        let ok = self.b.ins().band(ok_ptr, ok_bounds);

        let do_bb = self.b.create_block();
        let zero_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.append_block_param(done_bb, types::I8);
        self.b.ins().brif(ok, do_bb, &[], zero_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let wi_ptr = coerce_cl_val(self.b, word_idx, self.ctx.ptr_ty, self.ctx.ptr_ty);
        let off = self.b.ins().imul_imm_s(wi_ptr, 4);
        let addr = self.b.ins().iadd(ptr, off);
        let cur = self.b.ins().load(types::I32, MemFlagsData::new(), addr, 0);
        let shifted = self.b.ins().ushr(cur, bit_idx);
        let bit_val = self.b.ins().band_imm_u(shifted, 1);
        let res = self.b.ins().icmp_imm_s(IntCC::NotEqual, bit_val, 0);
        self.b.ins().jump(done_bb, &[BlockArg::Value(res)]);

        self.b.switch_to_block(zero_bb);
        self.b.seal_block(zero_bb);
        let z8 = self.b.ins().iconst(types::I8, 0);
        self.b.ins().jump(done_bb, &[BlockArg::Value(z8)]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        self.b.block_params(done_bb)[0]
    }

    fn lower_timeline_advance(
        &mut self,
        ptr: Value,
        rate_hz: u32,
        duration_frames: u32,
        window_masks: &[(String, u32, u32, u32)],
    ) {
        // Layout: cur_frame: u16 @ 0, flags: u16 @ 2, active_mask: u32 @ 4, accum_sec: f32 @ 8.
        // Note: `state_machines` pass ALREADY incremented `accum_sec` by `dt_sec` at offset 8 right
        // before emitting `TimelineAdvance`.
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ptr, 0);
        let do_bb = self.b.create_block();
        let exit_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], exit_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let frame_dt = self.b.ins().f32const(1.0 / (rate_hz.max(1) as f32));
        let cur_f16 = self.b.ins().load(types::I16, MemFlagsData::new(), ptr, 0);
        let cur_f32 = self.b.ins().uextend(types::I32, cur_f16);
        let cur_acc = self.b.ins().load(types::F32, MemFlagsData::new(), ptr, 8);

        let f_var = self.b.declare_var(types::I32);
        let acc_var = self.b.declare_var(types::F32);
        self.b.def_var(f_var, cur_f32);
        self.b.def_var(acc_var, cur_acc);

        let loop_hdr = self.b.create_block();
        let loop_body = self.b.create_block();
        let after_loop = self.b.create_block();
        self.b.ins().jump(loop_hdr, &[]);

        self.b.switch_to_block(loop_hdr);
        let fv = self.b.use_var(f_var);
        let av = self.b.use_var(acc_var);
        let can_step = self.b.ins().fcmp(FloatCC::GreaterThanOrEqual, av, frame_dt);
        let not_done =
            self.b
                .ins()
                .icmp_imm_s(IntCC::UnsignedLessThan, fv, i64::from(duration_frames));
        let cond = self.b.ins().band(can_step, not_done);
        self.b.ins().brif(cond, loop_body, &[], after_loop, &[]);

        self.b.switch_to_block(loop_body);
        self.b.seal_block(loop_body);
        let av2 = self.b.ins().fsub(av, frame_dt);
        let fv2 = self.b.ins().iadd_imm_s(fv, 1);
        self.b.def_var(acc_var, av2);
        self.b.def_var(f_var, fv2);
        self.b.ins().jump(loop_hdr, &[]);

        self.b.seal_block(loop_hdr);
        self.b.switch_to_block(after_loop);
        self.b.seal_block(after_loop);
        let final_f = self.b.use_var(f_var);
        let final_acc = self.b.use_var(acc_var);
        let final_f16 = self.b.ins().ireduce(types::I16, final_f);
        self.b.ins().store(MemFlagsData::new(), final_f16, ptr, 0);
        self.b.ins().store(MemFlagsData::new(), final_acc, ptr, 8);

        let mut mask_val = self.b.ins().iconst(types::I32, 0);
        for &(_, start_f, end_f, bit_mask) in window_masks {
            let ge = self.b.ins().icmp_imm_s(
                IntCC::UnsignedGreaterThanOrEqual,
                final_f,
                i64::from(start_f),
            );
            let lt = self
                .b
                .ins()
                .icmp_imm_s(IntCC::UnsignedLessThan, final_f, i64::from(end_f));
            let in_w = self.b.ins().band(ge, lt);
            let with_bit = self.b.ins().bor_imm_u(mask_val, i64::from(bit_mask));
            mask_val = self.b.ins().select(in_w, with_bit, mask_val);
        }
        self.b.ins().store(MemFlagsData::new(), mask_val, ptr, 4);

        let finished = self.b.ins().icmp_imm_s(
            IntCC::UnsignedGreaterThanOrEqual,
            final_f,
            i64::from(duration_frames),
        );
        let cur_flags = self.b.ins().load(types::I16, MemFlagsData::new(), ptr, 2);
        let cleared_flags = self.b.ins().band_imm_s(cur_flags, !1);
        let set_flags = self.b.ins().bor_imm_u(cur_flags, 1);
        let next_flags = self.b.ins().select(finished, cleared_flags, set_flags);
        self.b.ins().store(MemFlagsData::new(), next_flags, ptr, 2);
        self.b.ins().jump(exit_bb, &[]);

        self.b.switch_to_block(exit_bb);
        self.b.seal_block(exit_bb);
    }

    fn lower_cmd_spawn(
        &mut self,
        persistent: bool,
        components: &[(String, LocalId)],
    ) -> Result<Value, JitError> {
        let ptr_ty = self.ctx.ptr_ty;
        let count = components.len();
        let out_slot = alloc_zero_slot(self.b, structs::FFI_ENTITY_SIZE, ptr_ty);
        let out_ptr = self.b.ins().stack_addr(ptr_ty, out_slot, 0);
        if count == 0 {
            let cmds = self.ensure_commands();
            let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
            let call_bb = self.b.create_block();
            let skip_bb = self.b.create_block();
            self.b.ins().brif(ok, call_bb, &[], skip_bb, &[]);
            self.b.switch_to_block(call_bb);
            self.b.seal_block(call_bb);
            let _rc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::CMD_SPAWN_EMPTY,
                &[ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[cmds, out_ptr],
            );
            self.b.ins().jump(skip_bb, &[]);
            self.b.switch_to_block(skip_bb);
            self.b.seal_block(skip_bb);
            return Ok(self
                .b
                .ins()
                .load(types::I64, MemFlagsData::trusted(), out_ptr, 0));
        }

        let comp_slot = alloc_zero_slot(self.b, count * structs::BAM_COMPONENT_SIZE, ptr_ty);
        let comp_arr = self.b.ins().stack_addr(ptr_ty, comp_slot, 0);
        let ptrs_slot = alloc_zero_slot(self.b, count * self.ctx.ptr_bytes, ptr_ty);
        let ptrs_arr = self.b.ins().stack_addr(ptr_ty, ptrs_slot, 0);

        for (i, (cname, val_lid)) in components.iter().enumerate() {
            let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, cname) else {
                continue;
            };
            let handle = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.comp_slot_offset(lidx) as i32,
            );
            self.b.ins().store(
                MemFlagsData::trusted(),
                handle,
                comp_arr,
                (i * structs::BAM_COMPONENT_SIZE) as i32,
            );
            let data_ptr = if self.ctx.layouts[lidx].size == 0 {
                self.b.ins().iconst(ptr_ty, 0)
            } else {
                self.use_scalar(*val_lid)
            };
            self.b.ins().store(
                MemFlagsData::trusted(),
                data_ptr,
                ptrs_arr,
                (i * self.ctx.ptr_bytes) as i32,
            );
        }

        let cmds = self.ensure_commands();
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let call_bb = self.b.create_block();
        let skip_bb = self.b.create_block();
        self.b.ins().brif(ok, call_bb, &[], skip_bb, &[]);

        self.b.switch_to_block(call_bb);
        self.b.seal_block(call_bb);
        let cnt_v = self.b.ins().iconst(ptr_ty, count as i64);
        let vtable_slot = if persistent {
            api_slots::CMD_SPAWN_PERSISTENT
        } else {
            api_slots::CMD_SPAWN
        };
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            vtable_slot,
            &[ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[cmds, comp_arr, ptrs_arr, cnt_v, out_ptr],
        );
        self.b.ins().jump(skip_bb, &[]);

        self.b.switch_to_block(skip_bb);
        self.b.seal_block(skip_bb);
        Ok(self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), out_ptr, 0))
    }

    fn lower_cmd_spawn_batch(
        &mut self,
        count: LocalId,
        components: &[(String, LocalId)],
    ) -> Result<(), JitError> {
        let ptr_ty = self.ctx.ptr_ty;
        let ent_cnt = {
            let __tmp = self.use_scalar(count);
            coerce_cl_val(self.b, __tmp, ptr_ty, ptr_ty)
        };
        let cmds = self.ensure_commands();
        let cnt_pos = self
            .b
            .ins()
            .icmp_imm_s(IntCC::SignedGreaterThan, ent_cnt, 0);
        let cmds_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let go = self.b.ins().band(cnt_pos, cmds_ok);

        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(go, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);

        let n = components.len();
        let comp_slot = alloc_zero_slot(self.b, (n * structs::BAM_COMPONENT_SIZE).max(8), ptr_ty);
        let comp_arr = self.b.ins().stack_addr(ptr_ty, comp_slot, 0);
        let ptrs_slot = alloc_zero_slot(self.b, (n * self.ctx.ptr_bytes).max(8), ptr_ty);
        let ptrs_arr = self.b.ins().stack_addr(ptr_ty, ptrs_slot, 0);
        let calloc_fid = self
            .ctx
            .declare_extern_fn("calloc", &[ptr_ty, ptr_ty], Some(ptr_ty))?;
        let free_fid = self.ctx.declare_extern_fn("free", &[ptr_ty], None)?;
        let calloc_ref = self
            .ctx
            .obj_mod
            .declare_func_in_func(calloc_fid, self.b.func);
        let free_ref = self.ctx.obj_mod.declare_func_in_func(free_fid, self.b.func);

        let mut temp_bufs = Vec::new();
        for (i, (cname, val_lid)) in components.iter().enumerate() {
            let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, cname) else {
                continue;
            };
            let handle = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.comp_slot_offset(lidx) as i32,
            );
            self.b.ins().store(
                MemFlagsData::trusted(),
                handle,
                comp_arr,
                (i * structs::BAM_COMPONENT_SIZE) as i32,
            );
            let sz = self.ctx.layouts[lidx].size;
            if sz == 0 {
                let z = self.b.ins().iconst(ptr_ty, 0);
                self.b.ins().store(
                    MemFlagsData::trusted(),
                    z,
                    ptrs_arr,
                    (i * self.ctx.ptr_bytes) as i32,
                );
            } else {
                let sz_v = self.b.ins().iconst(ptr_ty, sz as i64);
                let call = self.b.ins().call(calloc_ref, &[ent_cnt, sz_v]);
                let buf = self.b.inst_results(call)[0];
                let tmpl_ptr = self.use_scalar(*val_lid);
                self.emit_replicate_template(buf, tmpl_ptr, ent_cnt, sz);
                self.b.ins().store(
                    MemFlagsData::trusted(),
                    buf,
                    ptrs_arr,
                    (i * self.ctx.ptr_bytes) as i32,
                );
                temp_bufs.push(buf);
            }
        }

        let comp_cnt_v = self.b.ins().iconst(ptr_ty, n as i64);
        let null_out = self.b.ins().iconst(ptr_ty, 0);
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::CMD_SPAWN_BATCH,
            &[ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[cmds, comp_arr, ptrs_arr, comp_cnt_v, ent_cnt, null_out],
        );

        for buf in temp_bufs {
            self.b.ins().call(free_ref, &[buf]);
        }
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        Ok(())
    }

    fn lower_spawn_batch_begin(
        &mut self,
        count: LocalId,
        components: &[String],
    ) -> Result<(Value, Vec<usize>), JitError> {
        let ptr_ty = self.ctx.ptr_ty;
        let resolved_lidxs: Vec<usize> = components
            .iter()
            .filter_map(|c| lookup_name_in_map(&self.ctx.layout_map, c))
            .collect();
        let k = resolved_lidxs.len();
        let comps_off = 32usize;
        let ptrs_off = comps_off + align_up(k * structs::BAM_COMPONENT_SIZE, 8);
        let hdr_bytes = (ptrs_off + k * self.ctx.ptr_bytes).max(32);

        let raw_cnt = self.use_scalar(count);
        let cnt_u64 = coerce_cl_val(self.b, raw_cnt, types::I64, ptr_ty);
        let cnt_ptr = coerce_cl_val(self.b, raw_cnt, ptr_ty, ptr_ty);

        let calloc_fid = self
            .ctx
            .declare_extern_fn("calloc", &[ptr_ty, ptr_ty], Some(ptr_ty))?;
        let calloc_ref = self
            .ctx
            .obj_mod
            .declare_func_in_func(calloc_fid, self.b.func);

        let one = self.b.ins().iconst(ptr_ty, 1);
        let hsz = self.b.ins().iconst(ptr_ty, hdr_bytes as i64);
        let hcall = self.b.ins().call(calloc_ref, &[one, hsz]);
        let hdr = self.b.inst_results(hcall)[0];

        let hdr_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, hdr, 0);
        let init_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(hdr_ok, init_bb, &[], done_bb, &[]);

        self.b.switch_to_block(init_bb);
        self.b.seal_block(init_bb);

        let k_u64 = self.b.ins().iconst(types::I64, k as i64);
        let comps_ptr = self.b.ins().iadd_imm_s(hdr, comps_off as i64);
        let ptrs_ptr = self.b.ins().iadd_imm_s(hdr, ptrs_off as i64);
        self.b.ins().store(MemFlagsData::trusted(), cnt_u64, hdr, 0);
        self.b.ins().store(MemFlagsData::trusted(), k_u64, hdr, 8);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), comps_ptr, hdr, 16);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), ptrs_ptr, hdr, 24);

        let cnt_pos = self.b.ins().icmp_imm_s(IntCC::NotEqual, cnt_u64, 0);
        for (i, &lidx) in resolved_lidxs.iter().enumerate() {
            let handle = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.comp_slot_offset(lidx) as i32,
            );
            self.b.ins().store(
                MemFlagsData::trusted(),
                handle,
                comps_ptr,
                (i * structs::BAM_COMPONENT_SIZE) as i32,
            );
            let sz = self.ctx.layouts[lidx].size;
            if sz > 0 {
                let alloc_bb = self.b.create_block();
                let next_c_bb = self.b.create_block();
                self.b.ins().brif(cnt_pos, alloc_bb, &[], next_c_bb, &[]);

                self.b.switch_to_block(alloc_bb);
                self.b.seal_block(alloc_bb);
                let sz_v = self.b.ins().iconst(ptr_ty, sz as i64);
                let ccall = self.b.ins().call(calloc_ref, &[cnt_ptr, sz_v]);
                let col_buf = self.b.inst_results(ccall)[0];
                self.b.ins().store(
                    MemFlagsData::trusted(),
                    col_buf,
                    ptrs_ptr,
                    (i * self.ctx.ptr_bytes) as i32,
                );
                self.b.ins().jump(next_c_bb, &[]);

                self.b.switch_to_block(next_c_bb);
                self.b.seal_block(next_c_bb);
            }
        }
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        let hdr_u64 = coerce_cl_val(self.b, hdr, types::I64, ptr_ty);
        Ok((hdr_u64, resolved_lidxs))
    }

    fn lookup_batch_col_buf_by_handle(
        &mut self,
        comps_ptr: Value,
        ptrs_ptr: Value,
        comp_cnt_ptr: Value,
        lidx: usize,
    ) -> Value {
        let ptr_ty = self.ctx.ptr_ty;
        let target_h = self.b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            self.state_ptr,
            self.ctx.state_layout.comp_slot_offset(lidx) as i32,
        );
        let k_var = self.b.declare_var(ptr_ty);
        let z_ptr = self.b.ins().iconst(ptr_ty, 0);
        self.b.def_var(k_var, z_ptr);

        let hdr_bb = self.b.create_block();
        let body_bb = self.b.create_block();
        let hit_bb = self.b.create_block();
        let step_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.append_block_param(done_bb, ptr_ty);
        self.b.ins().jump(hdr_bb, &[]);

        self.b.switch_to_block(hdr_bb);
        let k = self.b.use_var(k_var);
        let in_b = self.b.ins().icmp(IntCC::UnsignedLessThan, k, comp_cnt_ptr);
        self.b
            .ins()
            .brif(in_b, body_bb, &[], done_bb, &[BlockArg::Value(z_ptr)]);

        self.b.switch_to_block(body_bb);
        self.b.seal_block(body_bb);
        let coff = self
            .b
            .ins()
            .imul_imm_s(k, structs::BAM_COMPONENT_SIZE as i64);
        let caddr = self.b.ins().iadd(comps_ptr, coff);
        let h = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), caddr, 0);
        let eq = self.b.ins().icmp(IntCC::Equal, h, target_h);
        self.b.ins().brif(eq, hit_bb, &[], step_bb, &[]);

        self.b.switch_to_block(hit_bb);
        self.b.seal_block(hit_bb);
        let poff = self.b.ins().imul_imm_s(k, self.ctx.ptr_bytes as i64);
        let paddr = self.b.ins().iadd(ptrs_ptr, poff);
        let buf = self.b.ins().load(ptr_ty, MemFlagsData::trusted(), paddr, 0);
        self.b.ins().jump(done_bb, &[BlockArg::Value(buf)]);

        self.b.switch_to_block(step_bb);
        self.b.seal_block(step_bb);
        let nk = self.b.ins().iadd_imm_s(k, 1);
        self.b.def_var(k_var, nk);
        self.b.ins().jump(hdr_bb, &[]);

        self.b.seal_block(hdr_bb);
        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        self.b.block_params(done_bb)[0]
    }

    fn lower_spawn_batch_push(
        &mut self,
        batch: LocalId,
        index: LocalId,
        components: &[(String, LocalId)],
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        let hdr_raw = self.use_scalar(batch);
        let hdr = coerce_cl_val(self.b, hdr_raw, ptr_ty, ptr_ty);
        let idx_raw = self.use_scalar(index);
        let idx_u64 = coerce_cl_val(self.b, idx_raw, types::I64, ptr_ty);

        let hdr_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, hdr, 0);
        let chk_bb = self.b.create_block();
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(hdr_ok, chk_bb, &[], done_bb, &[]);

        self.b.switch_to_block(chk_bb);
        self.b.seal_block(chk_bb);
        let cnt_u64 = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), hdr, 0);
        let in_bounds = self.b.ins().icmp(IntCC::UnsignedLessThan, idx_u64, cnt_u64);
        self.b.ins().brif(in_bounds, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let comp_cnt = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), hdr, 8);
        let comp_cnt_ptr = coerce_cl_val(self.b, comp_cnt, ptr_ty, ptr_ty);
        let comps_ptr = self.b.ins().load(ptr_ty, MemFlagsData::trusted(), hdr, 16);
        let ptrs_ptr = self.b.ins().load(ptr_ty, MemFlagsData::trusted(), hdr, 24);
        let idx_ptr = coerce_cl_val(self.b, idx_u64, ptr_ty, ptr_ty);
        let schema = self.batch_schemas.get(&batch.0).cloned();

        for (cname, val_lid) in components {
            let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, cname) else {
                continue;
            };
            let sz = self.ctx.layouts[lidx].size;
            if sz == 0 {
                continue;
            }
            let col_buf = if let Some(k) = schema
                .as_ref()
                .and_then(|s| s.iter().position(|&x| x == lidx))
            {
                self.b.ins().load(
                    ptr_ty,
                    MemFlagsData::trusted(),
                    ptrs_ptr,
                    (k * self.ctx.ptr_bytes) as i32,
                )
            } else {
                self.lookup_batch_col_buf_by_handle(comps_ptr, ptrs_ptr, comp_cnt_ptr, lidx)
            };

            let buf_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, col_buf, 0);
            let wr_bb = self.b.create_block();
            let next_c_bb = self.b.create_block();
            self.b.ins().brif(buf_ok, wr_bb, &[], next_c_bb, &[]);

            self.b.switch_to_block(wr_bb);
            self.b.seal_block(wr_bb);
            let off = self.b.ins().imul_imm_s(idx_ptr, sz as i64);
            let dst_ptr = self.b.ins().iadd(col_buf, off);
            let mty = self.mir_fn.locals[val_lid.0 as usize].ty.clone();
            if matches!(
                mty,
                MirType::Named(_)
                    | MirType::Ptr
                    | MirType::MutPtr
                    | MirType::Array { .. }
                    | MirType::Tuple(_)
            ) {
                let src_ptr = self.use_scalar(*val_lid);
                let src_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, src_ptr, 0);
                let cp_bb = self.b.create_block();
                self.b.ins().brif(src_ok, cp_bb, &[], next_c_bb, &[]);

                self.b.switch_to_block(cp_bb);
                self.b.seal_block(cp_bb);
                emit_memcpy(self.b, dst_ptr, src_ptr, sz);
                self.b.ins().jump(next_c_bb, &[]);
            } else {
                self.store_local_to_mem(*val_lid, &mty, dst_ptr, 0);
                self.b.ins().jump(next_c_bb, &[]);
            }

            self.b.switch_to_block(next_c_bb);
            self.b.seal_block(next_c_bb);
        }
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    fn lower_spawn_batch_commit(&mut self, batch: LocalId) -> Result<(), JitError> {
        let ptr_ty = self.ctx.ptr_ty;
        let hdr_raw = self.use_scalar(batch);
        let hdr = coerce_cl_val(self.b, hdr_raw, ptr_ty, ptr_ty);
        let cmds = self.ensure_commands();

        let free_fid = self.ctx.declare_extern_fn("free", &[ptr_ty], None)?;
        let free_ref = self.ctx.obj_mod.declare_func_in_func(free_fid, self.b.func);

        let hdr_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, hdr, 0);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(hdr_ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let cnt_u64 = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), hdr, 0);
        let comp_cnt_u64 = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), hdr, 8);
        let comps_ptr = self.b.ins().load(ptr_ty, MemFlagsData::trusted(), hdr, 16);
        let ptrs_ptr = self.b.ins().load(ptr_ty, MemFlagsData::trusted(), hdr, 24);
        let cnt_ptr = coerce_cl_val(self.b, cnt_u64, ptr_ty, ptr_ty);
        let comp_cnt_ptr = coerce_cl_val(self.b, comp_cnt_u64, ptr_ty, ptr_ty);

        let cnt_pos = self.b.ins().icmp_imm_s(IntCC::NotEqual, cnt_u64, 0);
        let comp_pos = self.b.ins().icmp_imm_s(IntCC::NotEqual, comp_cnt_u64, 0);
        let cmds_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let pos_both = self.b.ins().band(cnt_pos, comp_pos);
        let can_spawn = self.b.ins().band(pos_both, cmds_ok);

        let spawn_bb = self.b.create_block();
        let free_loop_init_bb = self.b.create_block();
        self.b
            .ins()
            .brif(can_spawn, spawn_bb, &[], free_loop_init_bb, &[]);

        self.b.switch_to_block(spawn_bb);
        self.b.seal_block(spawn_bb);
        let null_out = self.b.ins().iconst(ptr_ty, 0);
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::CMD_SPAWN_BATCH,
            &[ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[cmds, comps_ptr, ptrs_ptr, comp_cnt_ptr, cnt_ptr, null_out],
        );
        self.b.ins().jump(free_loop_init_bb, &[]);

        self.b.switch_to_block(free_loop_init_bb);
        self.b.seal_block(free_loop_init_bb);
        let k_var = self.b.declare_var(ptr_ty);
        let z_ptr = self.b.ins().iconst(ptr_ty, 0);
        self.b.def_var(k_var, z_ptr);
        let free_hdr_bb = self.b.create_block();
        let free_body_bb = self.b.create_block();
        let free_col_bb = self.b.create_block();
        let free_step_bb = self.b.create_block();
        let free_self_bb = self.b.create_block();
        self.b.ins().jump(free_hdr_bb, &[]);

        self.b.switch_to_block(free_hdr_bb);
        let k = self.b.use_var(k_var);
        let more = self.b.ins().icmp(IntCC::UnsignedLessThan, k, comp_cnt_ptr);
        self.b
            .ins()
            .brif(more, free_body_bb, &[], free_self_bb, &[]);

        self.b.switch_to_block(free_body_bb);
        self.b.seal_block(free_body_bb);
        let poff = self.b.ins().imul_imm_s(k, self.ctx.ptr_bytes as i64);
        let paddr = self.b.ins().iadd(ptrs_ptr, poff);
        let col_buf = self.b.ins().load(ptr_ty, MemFlagsData::trusted(), paddr, 0);
        let col_nz = self.b.ins().icmp_imm_s(IntCC::NotEqual, col_buf, 0);
        self.b
            .ins()
            .brif(col_nz, free_col_bb, &[], free_step_bb, &[]);

        self.b.switch_to_block(free_col_bb);
        self.b.seal_block(free_col_bb);
        self.b.ins().call(free_ref, &[col_buf]);
        self.b.ins().jump(free_step_bb, &[]);

        self.b.switch_to_block(free_step_bb);
        self.b.seal_block(free_step_bb);
        let nk = self.b.ins().iadd_imm_s(k, 1);
        self.b.def_var(k_var, nk);
        self.b.ins().jump(free_hdr_bb, &[]);

        self.b.seal_block(free_hdr_bb);
        self.b.switch_to_block(free_self_bb);
        self.b.seal_block(free_self_bb);
        self.b.ins().call(free_ref, &[hdr]);
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        Ok(())
    }

    fn emit_replicate_template(
        &mut self,
        dst_buf: Value,
        tmpl_ptr: Value,
        count: Value,
        elem_sz: usize,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        let idx_v = self.b.declare_var(ptr_ty);
        let z = self.b.ins().iconst(ptr_ty, 0);
        self.b.def_var(idx_v, z);
        let hdr = self.b.create_block();
        let body = self.b.create_block();
        let exit = self.b.create_block();
        self.b.ins().jump(hdr, &[]);

        self.b.switch_to_block(hdr);
        let i = self.b.use_var(idx_v);
        let cond = self.b.ins().icmp(IntCC::UnsignedLessThan, i, count);
        self.b.ins().brif(cond, body, &[], exit, &[]);

        self.b.switch_to_block(body);
        self.b.seal_block(body);
        let off = self.b.ins().imul_imm_s(i, elem_sz as i64);
        let dst = self.b.ins().iadd(dst_buf, off);
        emit_memcpy(self.b, dst, tmpl_ptr, elem_sz);
        let ni = self.b.ins().iadd_imm_s(i, 1);
        self.b.def_var(idx_v, ni);
        self.b.ins().jump(hdr, &[]);

        self.b.seal_block(hdr);
        self.b.switch_to_block(exit);
        self.b.seal_block(exit);
    }

    fn lower_cmd_despawn_all(&mut self, filter: &str) -> Result<(), JitError> {
        let ptr_ty = self.ctx.ptr_ty;
        let mut comp_indices = Vec::new();
        for tok in filter.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let clean = tok
                .strip_prefix("With<")
                .and_then(|s| s.strip_suffix('>'))
                .unwrap_or(tok)
                .trim();
            if let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, clean) {
                comp_indices.push(lidx);
            }
        }
        if comp_indices.is_empty() {
            return Ok(());
        }
        let cmds = self.ensure_commands();
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let terms_slot =
            alloc_zero_slot(self.b, comp_indices.len() * structs::TERM_DESC_SIZE, ptr_ty);
        let terms_ptr = self.b.ins().stack_addr(ptr_ty, terms_slot, 0);
        let mode_filter = self
            .b
            .ins()
            .iconst(types::I32, i64::from(AccessMode::FILTER_ONLY.0));
        for (i, lidx) in comp_indices.iter().enumerate() {
            let base = (i * structs::TERM_DESC_SIZE) as i32;
            let comp = self.b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.comp_slot_offset(*lidx) as i32,
            );
            self.b.ins().store(
                MemFlagsData::trusted(),
                comp,
                terms_ptr,
                base + structs::TERM_COMPONENT as i32,
            );
            self.b.ins().store(
                MemFlagsData::trusted(),
                mode_filter,
                terms_ptr,
                base + structs::TERM_MODE as i32,
            );
        }
        let tc = self.b.ins().iconst(ptr_ty, comp_indices.len() as i64);
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::CMD_DESPAWN_ALL,
            &[ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[cmds, terms_ptr, tc],
        );
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        Ok(())
    }

    fn lower_cmd_insert(
        &mut self,
        entity: Value,
        component: &str,
        data: Option<LocalId>,
        if_new: bool,
    ) -> Result<(), JitError> {
        let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, component) else {
            return Ok(());
        };
        let ptr_ty = self.ctx.ptr_ty;
        let cmds = self.ensure_commands();
        let cmds_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let ent_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, entity, 0);
        let ok = self.b.ins().band(cmds_ok, ent_ok);

        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let comp = self.b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            self.state_ptr,
            self.ctx.state_layout.comp_slot_offset(lidx) as i32,
        );
        let sz = self.ctx.layouts[lidx].size;
        let dptr = if sz == 0 {
            self.b.ins().iconst(ptr_ty, 0)
        } else if let Some(dl) = data {
            let mty = &self.mir_fn.locals[dl.0 as usize].ty;
            if matches!(
                mty,
                MirType::Named(_)
                    | MirType::Ptr
                    | MirType::MutPtr
                    | MirType::Array { .. }
                    | MirType::Tuple(_)
            ) {
                self.use_scalar(dl)
            } else {
                let s = alloc_zero_slot(self.b, sz.max(8), ptr_ty);
                let sp = self.b.ins().stack_addr(ptr_ty, s, 0);
                let cloned = mty.clone();
                self.store_local_to_mem(dl, &cloned, sp, 0);
                sp
            }
        } else if let Some(blob_id) = self.ctx.layouts[lidx].default_blob_id {
            let gv = self.ctx.obj_mod.declare_data_in_func(blob_id, self.b.func);
            self.b.ins().symbol_value(ptr_ty, gv)
        } else {
            let s = alloc_zero_slot(self.b, sz.max(8), ptr_ty);
            self.b.ins().stack_addr(ptr_ty, s, 0)
        };
        let dlen = self.b.ins().iconst(ptr_ty, sz as i64);
        let vtable_slot = if if_new {
            api_slots::CMD_INSERT_IF_NEW
        } else {
            api_slots::CMD_INSERT
        };
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            vtable_slot,
            &[ptr_ty, types::I64, types::I32, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[cmds, entity, comp, dptr, dlen],
        );
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        Ok(())
    }

    fn lower_cmd_remove(&mut self, entity: Value, component: &str) {
        let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, component) else {
            return;
        };
        let ptr_ty = self.ctx.ptr_ty;
        let cmds = self.ensure_commands();
        let cmds_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let ent_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, entity, 0);
        let ok = self.b.ins().band(cmds_ok, ent_ok);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let comp = self.b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            self.state_ptr,
            self.ctx.state_layout.comp_slot_offset(lidx) as i32,
        );
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::CMD_REMOVE,
            &[ptr_ty, types::I64, types::I32],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[cmds, entity, comp],
        );
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    fn lower_cmd_trigger(
        &mut self,
        event: &str,
        target: Option<LocalId>,
        payload: Option<LocalId>,
        propagate: bool,
    ) {
        let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, event) else {
            return;
        };
        let ptr_ty = self.ctx.ptr_ty;
        let cmds = self.ensure_commands();
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let ev_comp = self.b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            self.state_ptr,
            self.ctx.state_layout.comp_slot_offset(lidx) as i32,
        );
        let tgt_ent = target
            .map(|t| self.use_scalar(t))
            .unwrap_or_else(|| self.b.ins().iconst(types::I64, FFI_ENTITY_NULL as i64));
        let sz = self.ctx.layouts[lidx].size;
        let dptr = if sz == 0 {
            self.b.ins().iconst(ptr_ty, 0)
        } else if let Some(pl) = payload {
            let mty = &self.mir_fn.locals[pl.0 as usize].ty;
            if matches!(
                mty,
                MirType::Named(_)
                    | MirType::Ptr
                    | MirType::MutPtr
                    | MirType::Array { .. }
                    | MirType::Tuple(_)
            ) {
                self.use_scalar(pl)
            } else {
                let s = alloc_zero_slot(self.b, sz.max(8), ptr_ty);
                let sp = self.b.ins().stack_addr(ptr_ty, s, 0);
                let cloned = mty.clone();
                self.store_local_to_mem(pl, &cloned, sp, 0);
                sp
            }
        } else {
            let s = alloc_zero_slot(self.b, sz.max(8), ptr_ty);
            self.b.ins().stack_addr(ptr_ty, s, 0)
        };
        let dlen = self.b.ins().iconst(ptr_ty, sz as i64);

        if propagate {
            let tslot = alloc_zero_slot(self.b, structs::TRIGGER_DESC_SIZE, ptr_ty);
            let tptr = self.b.ins().stack_addr(ptr_ty, tslot, 0);
            let tsz = self
                .b
                .ins()
                .iconst(types::I32, structs::TRIGGER_DESC_SIZE as i64);
            let tflags = self
                .b
                .ins()
                .iconst(types::I32, i64::from(TRIGGER_FLAG_PROPAGATE));
            let ekind = self
                .b
                .ins()
                .iconst(types::I32, i64::from(BAM_EVENT_KIND_CUSTOM));
            let elo = self.b.ins().ireduce(types::I32, tgt_ent);
            let shifted = self.b.ins().ushr_imm_u(tgt_ent, 32);
            let ehi = self.b.ins().ireduce(types::I32, shifted);
            let inv_rel = self
                .b
                .ins()
                .iconst(types::I32, i64::from(BAM_COMPONENT_INVALID));
            self.b
                .ins()
                .stack_store(ptr_ty, tsz, tslot, structs::TRG_STRUCT_SIZE as i32);
            self.b
                .ins()
                .stack_store(ptr_ty, tflags, tslot, structs::TRG_FLAGS as i32);
            self.b
                .ins()
                .stack_store(ptr_ty, ev_comp, tslot, structs::TRG_EVENT as i32);
            self.b
                .ins()
                .stack_store(ptr_ty, ekind, tslot, structs::TRG_EVENT_KIND as i32);
            self.b
                .ins()
                .stack_store(ptr_ty, elo, tslot, structs::TRG_ENTITY_LO as i32);
            self.b
                .ins()
                .stack_store(ptr_ty, ehi, tslot, structs::TRG_ENTITY_HI as i32);
            self.b
                .ins()
                .stack_store(ptr_ty, dptr, tslot, structs::TRG_DATA_PTR as i32);
            self.b
                .ins()
                .stack_store(ptr_ty, dlen, tslot, structs::TRG_DATA_LEN as i32);
            self.b.ins().stack_store(
                ptr_ty,
                inv_rel,
                tslot,
                structs::TRG_PROPAGATE_RELATIONSHIP as i32,
            );
            let _rc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::CMD_TRIGGER_EX,
                &[ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[cmds, tptr],
            );
        } else {
            let _rc = call_vtable(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::CMD_TRIGGER,
                &[ptr_ty, types::I32, types::I64, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                self.ctx.call_conv,
                &[cmds, ev_comp, tgt_ent, dptr, dlen],
            );
        }
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    fn lower_stream_emit(&mut self, stream: &str, payload: LocalId) {
        let Some(lidx) = lookup_name_in_map(&self.ctx.layout_map, stream) else {
            return;
        };
        let ptr_ty = self.ctx.ptr_ty;
        let sz = self.ctx.layouts[lidx].size;
        let dptr = if sz == 0 {
            self.b.ins().iconst(ptr_ty, 0)
        } else {
            let mty = &self.mir_fn.locals[payload.0 as usize].ty;
            if matches!(
                mty,
                MirType::Named(_)
                    | MirType::Ptr
                    | MirType::MutPtr
                    | MirType::Array { .. }
                    | MirType::Tuple(_)
            ) {
                self.use_scalar(payload)
            } else {
                let s = alloc_zero_slot(self.b, sz.max(8), ptr_ty);
                let sp = self.b.ins().stack_addr(ptr_ty, s, 0);
                let cloned = mty.clone();
                self.store_local_to_mem(payload, &cloned, sp, 0);
                sp
            }
        };
        let dlen = self.b.ins().iconst(ptr_ty, sz as i64);

        // If host registered `stream` as `BAM_STORAGE_FLAG_MESSAGE`, emit via `msg_send(iter, 0, ...)`.
        if let Some(sq) = self
            .sys_entry
            .and_then(|e| {
                e.stream_queries
                    .iter()
                    .find(|s| s.stream_layout_idx == lidx)
            })
            .cloned()
        {
            let flag = self.b.ins().load(
                types::I8,
                MemFlagsData::trusted(),
                self.state_ptr,
                self.ctx.state_layout.res_flag_offset(lidx) as i32,
            );
            let is_host_msg = self.b.ins().icmp_imm_s(IntCC::Equal, flag, 2);
            let msg_bb = self.b.create_block();
            let trig_bb = self.b.create_block();
            let done_bb = self.b.create_block();
            self.b.ins().brif(is_host_msg, msg_bb, &[], trig_bb, &[]);

            self.b.switch_to_block(msg_bb);
            self.b.seal_block(msg_bb);
            let iter = self.ensure_query_iter(sq.wire_query_idx as u32);
            let z_term = self.b.ins().iconst(ptr_ty, 0);
            let _rc = call_vtable_guarded(
                &self.ctx.obj_mod,
                self.b,
                self.api_ptr,
                api_slots::MSG_SEND,
                &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                types::I32,
                ptr_ty,
                self.ctx.call_conv,
                iter,
                &[iter, z_term, dptr, dlen],
            );
            self.b.ins().jump(done_bb, &[]);

            self.b.switch_to_block(trig_bb);
            self.b.seal_block(trig_bb);
            self.lower_cmd_trigger(stream, None, Some(payload), false);
            self.b.ins().jump(done_bb, &[]);

            self.b.switch_to_block(done_bb);
            self.b.seal_block(done_bb);
            return;
        }

        self.lower_cmd_trigger(stream, None, Some(payload), false);
    }

    fn lower_cmd_insert_relation(
        &mut self,
        relation: &str,
        entity: LocalId,
        target: LocalId,
        payload: Option<LocalId>,
    ) {
        let Some(&ri) = self.ctx.relation_map.get(relation).or_else(|| {
            relation
                .rsplit("::")
                .next()
                .and_then(|s| self.ctx.relation_map.get(s))
        }) else {
            return;
        };
        let ptr_ty = self.ctx.ptr_ty;
        let ent = self.use_scalar(entity);
        let tgt = self.use_scalar(target);
        let cmds = self.ensure_commands();
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let rel_comp = self.b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            self.state_ptr,
            self.ctx.state_layout.rel_slot_offset(ri) as i32,
        );
        let sz = self.ctx.relations[ri].payload_size;
        let dptr = if sz == 0 {
            self.b.ins().iconst(ptr_ty, 0)
        } else if let Some(pl) = payload {
            let mty = &self.mir_fn.locals[pl.0 as usize].ty;
            if matches!(
                mty,
                MirType::Named(_)
                    | MirType::Ptr
                    | MirType::MutPtr
                    | MirType::Array { .. }
                    | MirType::Tuple(_)
            ) {
                self.use_scalar(pl)
            } else {
                let s = alloc_zero_slot(self.b, sz.max(8), ptr_ty);
                let sp = self.b.ins().stack_addr(ptr_ty, s, 0);
                let cloned = mty.clone();
                self.store_local_to_mem(pl, &cloned, sp, 0);
                sp
            }
        } else {
            self.b.ins().iconst(ptr_ty, 0)
        };
        let dlen = self.b.ins().iconst(ptr_ty, sz as i64);
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::CMD_INSERT_RELATION,
            &[ptr_ty, types::I64, types::I32, types::I64, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[cmds, ent, rel_comp, tgt, dptr, dlen],
        );
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    fn lower_cmd_remove_relation(&mut self, relation: &str, entity: LocalId, target: LocalId) {
        let Some(&ri) = self.ctx.relation_map.get(relation).or_else(|| {
            relation
                .rsplit("::")
                .next()
                .and_then(|s| self.ctx.relation_map.get(s))
        }) else {
            return;
        };
        let ptr_ty = self.ctx.ptr_ty;
        let ent = self.use_scalar(entity);
        let tgt = self.use_scalar(target);
        let cmds = self.ensure_commands();
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, cmds, 0);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);
        let rel_comp = self.b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            self.state_ptr,
            self.ctx.state_layout.rel_slot_offset(ri) as i32,
        );
        let _rc = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::CMD_REMOVE_RELATION,
            &[ptr_ty, types::I64, types::I32, types::I64],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[cmds, ent, rel_comp, tgt],
        );
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    fn lower_table_load(&mut self, dst: LocalId, table_name: &str, key: LocalId, field: &str) {
        let Some(tbl) = self.ctx.tables.get(table_name).cloned() else {
            self.def_zero_for_local(dst);
            return;
        };
        let Some((foff, fmty)) = tbl.fields.get(field).cloned() else {
            self.def_zero_for_local(dst);
            return;
        };
        let ptr_ty = self.ctx.ptr_ty;
        let raw_k = {
            let __tmp = self.use_scalar(key);
            coerce_cl_val(self.b, __tmp, ptr_ty, ptr_ty)
        };
        let in_range =
            self.b
                .ins()
                .icmp_imm_s(IntCC::UnsignedLessThan, raw_k, tbl.row_count as i64);
        let z = self.b.ins().iconst(ptr_ty, 0);
        let safe_k = self.b.ins().select(in_range, raw_k, z);
        let gv = self
            .ctx
            .obj_mod
            .declare_data_in_func(tbl.data_id, self.b.func);
        let tbl_ptr = self.b.ins().symbol_value(ptr_ty, gv);
        let row_off = self.b.ins().imul_imm_s(safe_k, tbl.row_stride as i64);
        let row_ptr = self.b.ins().iadd(tbl_ptr, row_off);
        self.load_local_from_mem(dst, &fmty, row_ptr, foff as i32);
    }

    fn lower_curve_sample(&mut self, dst: LocalId, curve_name: &str, x: LocalId) {
        let Some(crv) = self.ctx.curves.get(curve_name).cloned() else {
            self.def_zero_for_local(dst);
            return;
        };
        let ptr_ty = self.ctx.ptr_ty;
        let xv = {
            let __tmp = self.use_scalar(x);
            coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
        };
        let gv = self
            .ctx
            .obj_mod
            .declare_data_in_func(crv.data_id, self.b.func);
        let ptr = self.b.ins().symbol_value(ptr_ty, gv);

        if crv.points_len == 0 {
            let z = self.b.ins().f32const(0.0);
            self.def_scalar_typed(dst, z);
            return;
        }
        if crv.points_len == 1 {
            let y0 = self
                .b
                .ins()
                .load(types::F32, MemFlagsData::trusted(), ptr, 4);
            self.def_scalar_typed(dst, y0);
            return;
        }

        let x0 = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), ptr, 0);
        let y0 = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), ptr, 4);
        let last_off = ((crv.points_len - 1) * 8) as i32;
        let xn = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), ptr, last_off);
        let yn = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), ptr, last_off + 4);

        let le_first = self.b.ins().fcmp(FloatCC::LessThanOrEqual, xv, x0);
        let ge_last = self.b.ins().fcmp(FloatCC::GreaterThanOrEqual, xv, xn);

        let ret_first_bb = self.b.create_block();
        let check_last_bb = self.b.create_block();
        let ret_last_bb = self.b.create_block();
        let scan_init_bb = self.b.create_block();
        let scan_hdr_bb = self.b.create_block();
        let scan_body_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.append_block_param(done_bb, types::F32);

        self.b
            .ins()
            .brif(le_first, ret_first_bb, &[], check_last_bb, &[]);

        self.b.switch_to_block(ret_first_bb);
        self.b.seal_block(ret_first_bb);
        self.b.ins().jump(done_bb, &[BlockArg::Value(y0)]);

        self.b.switch_to_block(check_last_bb);
        self.b.seal_block(check_last_bb);
        self.b
            .ins()
            .brif(ge_last, ret_last_bb, &[], scan_init_bb, &[]);

        self.b.switch_to_block(ret_last_bb);
        self.b.ins().jump(done_bb, &[BlockArg::Value(yn)]);

        self.b.switch_to_block(scan_init_bb);
        self.b.seal_block(scan_init_bb);
        let iv = self.b.declare_var(ptr_ty);
        let z = self.b.ins().iconst(ptr_ty, 0);
        self.b.def_var(iv, z);
        self.b.ins().jump(scan_hdr_bb, &[]);

        self.b.switch_to_block(scan_hdr_bb);
        let i = self.b.use_var(iv);
        let ok = self
            .b
            .ins()
            .icmp_imm_s(IntCC::UnsignedLessThan, i, (crv.points_len - 1) as i64);
        self.b.ins().brif(ok, scan_body_bb, &[], ret_last_bb, &[]);
        self.b.seal_block(ret_last_bb);

        self.b.switch_to_block(scan_body_bb);
        self.b.seal_block(scan_body_bb);
        let off = self.b.ins().imul_imm_s(i, 8);
        let seg_ptr = self.b.ins().iadd(ptr, off);
        let x1 = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), seg_ptr, 8);
        let in_seg = self.b.ins().fcmp(FloatCC::LessThanOrEqual, xv, x1);

        let interp_bb = self.b.create_block();
        let step_bb = self.b.create_block();
        self.b.ins().brif(in_seg, interp_bb, &[], step_bb, &[]);

        self.b.switch_to_block(interp_bb);
        self.b.seal_block(interp_bb);
        let xa = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), seg_ptr, 0);
        let ya = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), seg_ptr, 4);
        let yb = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), seg_ptr, 12);
        let dx = self.b.ins().fsub(x1, xa);
        let eps = self.b.ins().f32const(1e-12);
        let dx_pos = self.b.ins().fcmp(FloatCC::GreaterThan, dx, eps);
        let num = self.b.ins().fsub(xv, xa);
        let ratio = self.b.ins().fdiv(num, dx);
        let zf = self.b.ins().f32const(0.0);
        let t = self.b.ins().select(dx_pos, ratio, zf);
        let dy = self.b.ins().fsub(yb, ya);
        let delta = self.b.ins().fmul(dy, t);
        let out_y = self.b.ins().fadd(ya, delta);
        self.b.ins().jump(done_bb, &[BlockArg::Value(out_y)]);

        self.b.switch_to_block(step_bb);
        self.b.seal_block(step_bb);
        let ni = self.b.ins().iadd_imm_s(i, 1);
        self.b.def_var(iv, ni);
        self.b.ins().jump(scan_hdr_bb, &[]);

        self.b.seal_block(scan_hdr_bb);
        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
        let final_y = self.b.block_params(done_bb)[0];
        self.def_scalar_typed(dst, final_y);
    }

    fn lower_spatial_rebuild_csr(&mut self, index_name: &str) {
        let Some(meta) = self
            .ctx
            .spatial_metas
            .iter()
            .find(|m| m.name == index_name)
            .cloned()
        else {
            return;
        };
        let ptr_ty = self.ctx.ptr_ty;
        let iter = self.ensure_query_iter(0);
        let ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, iter, 0);
        let do_bb = self.b.create_block();
        let done_bb = self.b.create_block();
        self.b.ins().brif(ok, do_bb, &[], done_bb, &[]);

        self.b.switch_to_block(do_bb);
        self.b.seal_block(do_bb);

        // Reset iterator back to chunk 0 using `ITER_RESET` (`Slot 10`).
        let _rst = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::ITER_RESET,
            &[ptr_ty],
            Some(types::I32),
            ptr_ty,
            self.ctx.call_conv,
            &[iter],
        );

        let cur_slot_idx = self.b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            self.state_ptr,
            meta.cursor_offset as i32,
        );
        let next_tick = self.b.ins().iadd_imm_s(cur_slot_idx, 1);
        let frames_v = self.b.ins().iconst(types::I32, meta.frames as i64);
        let next_mod = self.b.ins().urem(next_tick, frames_v);
        self.b.ins().store(
            MemFlagsData::trusted(),
            next_mod,
            self.state_ptr,
            meta.cursor_offset as i32,
        );
        let mod_ptr = coerce_cl_val(self.b, next_mod, ptr_ty, ptr_ty);
        let slot_off = self.b.ins().imul_imm_s(mod_ptr, meta.slot_bytes as i64);
        let ring_base = self
            .b
            .ins()
            .iadd_imm_s(self.state_ptr, meta.ring_offset as i64);
        let frame_ptr = self.b.ins().iadd(ring_base, slot_off);

        let count_var = self.b.declare_var(types::I32);
        let z32 = self.b.ins().iconst(types::I32, 0);
        self.b.def_var(count_var, z32);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), z32, frame_ptr, 0);

        let (pos_comp, pos_field) = meta
            .by_field_path
            .split_once('.')
            .unwrap_or((&meta.by_field_path, "xy"));
        let (pos_off, pos_mty) = self.ctx.resolve_field_offset_and_ty(pos_comp, pos_field);
        let pos_dims = pos_mty.as_ref().and_then(vec_dims).unwrap_or(2);
        let pos_stride = lookup_name_in_map(&self.ctx.layout_map, pos_comp)
            .map_or(12, |i| self.ctx.layouts[i].size);

        let len_slot = alloc_zero_slot(self.b, self.ctx.ptr_bytes, ptr_ty);
        let len_ptr = self.b.ins().stack_addr(ptr_ty, len_slot, 0);
        let ch_hdr = self.b.create_block();
        let ch_body = self.b.create_block();
        let row_hdr = self.b.create_block();
        let row_body = self.b.create_block();
        let finish_bb = self.b.create_block();
        self.b.ins().jump(ch_hdr, &[]);

        self.b.switch_to_block(ch_hdr);
        let has = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::ITER_NEXT_CHUNK,
            &[ptr_ty, ptr_ty],
            Some(types::I8),
            ptr_ty,
            self.ctx.call_conv,
            &[iter, len_ptr],
        );
        let has_b = self.b.ins().icmp_imm_s(IntCC::NotEqual, has, 0);
        self.b.ins().brif(has_b, ch_body, &[], finish_bb, &[]);

        self.b.switch_to_block(ch_body);
        self.b.seal_block(ch_body);
        let clen_raw = self
            .b
            .ins()
            .load(ptr_ty, MemFlagsData::trusted(), len_ptr, 0);
        let clen = coerce_cl_val(self.b, clen_raw, types::I32, ptr_ty);
        let ents = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::ITER_ENTITIES,
            &[ptr_ty],
            Some(ptr_ty),
            ptr_ty,
            self.ctx.call_conv,
            &[iter],
        );
        let z_term = self.b.ins().iconst(ptr_ty, 0);
        let pos_col = call_vtable(
            &self.ctx.obj_mod,
            self.b,
            self.api_ptr,
            api_slots::ITER_COLUMN_READONLY,
            &[ptr_ty, ptr_ty],
            Some(ptr_ty),
            ptr_ty,
            self.ctx.call_conv,
            &[iter, z_term],
        );
        let r_var = self.b.declare_var(types::I32);
        self.b.def_var(r_var, z32);
        let pos_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, pos_col, 0);
        let ent_ok = self.b.ins().icmp_imm_s(IntCC::NotEqual, ents, 0);
        let cols_ok = self.b.ins().band(pos_ok, ent_ok);
        self.b.ins().brif(cols_ok, row_hdr, &[], ch_hdr, &[]);

        self.b.switch_to_block(row_hdr);
        let r = self.b.use_var(r_var);
        let cur_cnt = self.b.use_var(count_var);
        let r_ok = self.b.ins().icmp(IntCC::UnsignedLessThan, r, clen);
        let c_ok =
            self.b
                .ins()
                .icmp_imm_s(IntCC::UnsignedLessThan, cur_cnt, MAX_SPATIAL_ENTRIES as i64);
        let go_row = self.b.ins().band(r_ok, c_ok);
        self.b.ins().brif(go_row, row_body, &[], ch_hdr, &[]);

        self.b.switch_to_block(row_body);
        self.b.seal_block(row_body);
        let r_ptr = coerce_cl_val(self.b, r, ptr_ty, ptr_ty);
        let ent_off = self.b.ins().imul_imm_s(r_ptr, 8);
        let ent_addr = self.b.ins().iadd(ents, ent_off);
        let ent = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), ent_addr, 0);
        let pos_off_row = self.b.ins().imul_imm_s(r_ptr, pos_stride as i64);
        let pos_ptr = self.b.ins().iadd(pos_col, pos_off_row);
        let x = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::new(), pos_ptr, pos_off as i32);
        let y = self.b.ins().load(
            types::F32,
            MemFlagsData::new(),
            pos_ptr,
            (pos_off + 4) as i32,
        );
        let z = if pos_dims >= 3 {
            self.b.ins().load(
                types::F32,
                MemFlagsData::new(),
                pos_ptr,
                (pos_off + 8) as i32,
            )
        } else {
            self.b.ins().f32const(0.0)
        };

        let cnt_ptr = coerce_cl_val(self.b, cur_cnt, ptr_ty, ptr_ty);
        let dst_off = self.b.ins().imul_imm_s(cnt_ptr, meta.entry_stride as i64);
        let entries_base = self.b.ins().iadd_imm_s(frame_ptr, 8);
        let dst = self.b.ins().iadd(entries_base, dst_off);
        self.b.ins().store(MemFlagsData::trusted(), ent, dst, 0);
        self.b.ins().store(MemFlagsData::trusted(), x, dst, 8);
        self.b.ins().store(MemFlagsData::trusted(), y, dst, 12);
        self.b.ins().store(MemFlagsData::trusted(), z, dst, 16);

        let ncnt = self.b.ins().iadd_imm_s(cur_cnt, 1);
        self.b.def_var(count_var, ncnt);
        let nr = self.b.ins().iadd_imm_s(r, 1);
        self.b.def_var(r_var, nr);
        self.b.ins().jump(row_hdr, &[]);

        self.b.seal_block(row_hdr);
        self.b.seal_block(ch_hdr);
        self.b.switch_to_block(finish_bb);
        self.b.seal_block(finish_bb);
        let final_cnt = self.b.use_var(count_var);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), final_cnt, frame_ptr, 0);
        self.b.ins().jump(done_bb, &[]);

        self.b.switch_to_block(done_bb);
        self.b.seal_block(done_bb);
    }

    fn lower_spatial_query_disc(
        &mut self,
        dst: LocalId,
        grid_name: &str,
        center: LocalId,
        radius: LocalId,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        let out_slot = alloc_zero_slot(self.b, MAX_SPATIAL_CANDIDATES * 8, ptr_ty);
        let out_ptr = self.b.ins().stack_addr(ptr_ty, out_slot, 0);
        let Some(meta) = self
            .ctx
            .spatial_metas
            .iter()
            .find(|m| m.name == grid_name)
            .cloned()
        else {
            self.def_scalar_typed(dst, out_ptr);
            return;
        };

        let cvec = self.use_vec(center);
        let rad = {
            let __tmp = self.use_scalar(radius);
            coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
        };
        let r2 = self.b.ins().fmul(rad, rad);
        let is_3d = vec_dims(&self.mir_fn.locals[center.0 as usize].ty).unwrap_or(2) >= 3;

        let cur_slot = self.b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            self.state_ptr,
            meta.cursor_offset as i32,
        );
        let cur_ptr = coerce_cl_val(self.b, cur_slot, ptr_ty, ptr_ty);
        let slot_off = self.b.ins().imul_imm_s(cur_ptr, meta.slot_bytes as i64);
        let ring_base = self
            .b
            .ins()
            .iadd_imm_s(self.state_ptr, meta.ring_offset as i64);
        let frame_ptr = self.b.ins().iadd(ring_base, slot_off);
        let total = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), frame_ptr, 0);
        let entries_base = self.b.ins().iadd_imm_s(frame_ptr, 8);

        let i_var = self.b.declare_var(types::I32);
        let w_var = self.b.declare_var(types::I32);
        let z32 = self.b.ins().iconst(types::I32, 0);
        self.b.def_var(i_var, z32);
        self.b.def_var(w_var, z32);

        let hdr = self.b.create_block();
        let body = self.b.create_block();
        let add_bb = self.b.create_block();
        let step_bb = self.b.create_block();
        let exit = self.b.create_block();
        self.b.ins().jump(hdr, &[]);

        self.b.switch_to_block(hdr);
        let i = self.b.use_var(i_var);
        let w = self.b.use_var(w_var);
        let i_ok = self.b.ins().icmp(IntCC::UnsignedLessThan, i, total);
        let w_ok = self.b.ins().icmp_imm_s(
            IntCC::UnsignedLessThan,
            w,
            (MAX_SPATIAL_CANDIDATES - 1) as i64,
        );
        let loop_ok = self.b.ins().band(i_ok, w_ok);
        self.b.ins().brif(loop_ok, body, &[], exit, &[]);

        self.b.switch_to_block(body);
        self.b.seal_block(body);
        let ip = coerce_cl_val(self.b, i, ptr_ty, ptr_ty);
        let eoff = self.b.ins().imul_imm_s(ip, meta.entry_stride as i64);
        let eptr = self.b.ins().iadd(entries_base, eoff);
        let ex = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), eptr, 8);
        let ey = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), eptr, 12);
        let dx = self.b.ins().fsub(ex, cvec[0]);
        let dy = self.b.ins().fsub(ey, cvec[1]);
        let dx2 = self.b.ins().fmul(dx, dx);
        let dy2 = self.b.ins().fmul(dy, dy);
        let mut d2 = self.b.ins().fadd(dx2, dy2);
        if is_3d {
            let ez = self
                .b
                .ins()
                .load(types::F32, MemFlagsData::trusted(), eptr, 16);
            let dz = self.b.ins().fsub(ez, cvec[2]);
            let dz2 = self.b.ins().fmul(dz, dz);
            d2 = self.b.ins().fadd(d2, dz2);
        }
        let hit = self.b.ins().fcmp(FloatCC::LessThanOrEqual, d2, r2);
        self.b.ins().brif(hit, add_bb, &[], step_bb, &[]);

        self.b.switch_to_block(add_bb);
        self.b.seal_block(add_bb);
        let ent = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), eptr, 0);
        let wp = coerce_cl_val(self.b, w, ptr_ty, ptr_ty);
        let woff = self.b.ins().imul_imm_s(wp, 8);
        let dst_addr = self.b.ins().iadd(out_ptr, woff);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), ent, dst_addr, 0);
        let nw = self.b.ins().iadd_imm_s(w, 1);
        self.b.def_var(w_var, nw);
        self.b.ins().jump(step_bb, &[]);

        self.b.switch_to_block(step_bb);
        self.b.seal_block(step_bb);
        let ni = self.b.ins().iadd_imm_s(i, 1);
        self.b.def_var(i_var, ni);
        self.b.ins().jump(hdr, &[]);

        self.b.seal_block(hdr);
        self.b.switch_to_block(exit);
        self.b.seal_block(exit);
        self.def_scalar_typed(dst, out_ptr);
    }

    fn lower_spatial_query_segment(
        &mut self,
        dst: LocalId,
        history_name: &str,
        start: LocalId,
        end: LocalId,
        radius: LocalId,
        tick_offset: LocalId,
    ) {
        let ptr_ty = self.ctx.ptr_ty;
        let out_slot = alloc_zero_slot(self.b, MAX_SPATIAL_CANDIDATES * 8, ptr_ty);
        let out_ptr = self.b.ins().stack_addr(ptr_ty, out_slot, 0);
        let Some(meta) = self
            .ctx
            .spatial_metas
            .iter()
            .find(|m| m.name == history_name)
            .cloned()
        else {
            self.def_scalar_typed(dst, out_ptr);
            return;
        };

        let svec = self.use_vec(start);
        let evec = self.use_vec(end);
        let rad = {
            let __tmp = self.use_scalar(radius);
            coerce_cl_val(self.b, __tmp, types::F32, ptr_ty)
        };
        let r2 = self.b.ins().fmul(rad, rad);
        let toff = {
            let __tmp = self.use_scalar(tick_offset);
            coerce_cl_val(self.b, __tmp, types::I32, ptr_ty)
        };

        let cur_slot = self.b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            self.state_ptr,
            meta.cursor_offset as i32,
        );
        let frames_v = self.b.ins().iconst(types::I32, meta.frames as i64);
        let toff_mod = self.b.ins().urem(toff, frames_v);
        let added = self.b.ins().iadd(cur_slot, frames_v);
        let diff = self.b.ins().isub(added, toff_mod);
        let target_slot = self.b.ins().urem(diff, frames_v);

        let slot_ptr = coerce_cl_val(self.b, target_slot, ptr_ty, ptr_ty);
        let slot_off = self.b.ins().imul_imm_s(slot_ptr, meta.slot_bytes as i64);
        let ring_base = self
            .b
            .ins()
            .iadd_imm_s(self.state_ptr, meta.ring_offset as i64);
        let frame_ptr = self.b.ins().iadd(ring_base, slot_off);
        let total = self
            .b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), frame_ptr, 0);
        let entries_base = self.b.ins().iadd_imm_s(frame_ptr, 8);

        let abx = self.b.ins().fsub(evec[0], svec[0]);
        let aby = self.b.ins().fsub(evec[1], svec[1]);
        let abz = self.b.ins().fsub(evec[2], svec[2]);
        let abx2 = self.b.ins().fmul(abx, abx);
        let aby2 = self.b.ins().fmul(aby, aby);
        let abz2 = self.b.ins().fmul(abz, abz);
        let ab_xy2 = self.b.ins().fadd(abx2, aby2);
        let ab_len2 = self.b.ins().fadd(ab_xy2, abz2);
        let eps = self.b.ins().f32const(1e-8);
        let ab_ok = self.b.ins().fcmp(FloatCC::GreaterThan, ab_len2, eps);
        let zf = self.b.ins().f32const(0.0);
        let onef = self.b.ins().f32const(1.0);

        let i_var = self.b.declare_var(types::I32);
        let w_var = self.b.declare_var(types::I32);
        let z32 = self.b.ins().iconst(types::I32, 0);
        self.b.def_var(i_var, z32);
        self.b.def_var(w_var, z32);

        let hdr = self.b.create_block();
        let body = self.b.create_block();
        let add_bb = self.b.create_block();
        let step_bb = self.b.create_block();
        let exit = self.b.create_block();
        self.b.ins().jump(hdr, &[]);

        self.b.switch_to_block(hdr);
        let i = self.b.use_var(i_var);
        let w = self.b.use_var(w_var);
        let i_ok = self.b.ins().icmp(IntCC::UnsignedLessThan, i, total);
        let w_ok = self.b.ins().icmp_imm_s(
            IntCC::UnsignedLessThan,
            w,
            (MAX_SPATIAL_CANDIDATES - 1) as i64,
        );
        let loop_ok = self.b.ins().band(i_ok, w_ok);
        self.b.ins().brif(loop_ok, body, &[], exit, &[]);

        self.b.switch_to_block(body);
        self.b.seal_block(body);
        let ip = coerce_cl_val(self.b, i, ptr_ty, ptr_ty);
        let eoff = self.b.ins().imul_imm_s(ip, meta.entry_stride as i64);
        let eptr = self.b.ins().iadd(entries_base, eoff);
        let px = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), eptr, 8);
        let py = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), eptr, 12);
        let pz = self
            .b
            .ins()
            .load(types::F32, MemFlagsData::trusted(), eptr, 16);

        let apx = self.b.ins().fsub(px, svec[0]);
        let apy = self.b.ins().fsub(py, svec[1]);
        let apz = self.b.ins().fsub(pz, svec[2]);
        let dot_x = self.b.ins().fmul(apx, abx);
        let dot_y = self.b.ins().fmul(apy, aby);
        let dot_z = self.b.ins().fmul(apz, abz);
        let dot_xy = self.b.ins().fadd(dot_x, dot_y);
        let dot = self.b.ins().fadd(dot_xy, dot_z);
        let raw_t = self.b.ins().fdiv(dot, ab_len2);
        let t_safe = self.b.ins().select(ab_ok, raw_t, zf);
        let t_min = self.b.ins().fmax(t_safe, zf);
        let t_clamped = self.b.ins().fmin(t_min, onef);

        let sx_step = self.b.ins().fmul(abx, t_clamped);
        let sy_step = self.b.ins().fmul(aby, t_clamped);
        let sz_step = self.b.ins().fmul(abz, t_clamped);
        let cx = self.b.ins().fadd(svec[0], sx_step);
        let cy = self.b.ins().fadd(svec[1], sy_step);
        let cz = self.b.ins().fadd(svec[2], sz_step);
        let dx = self.b.ins().fsub(px, cx);
        let dy = self.b.ins().fsub(py, cy);
        let dz = self.b.ins().fsub(pz, cz);
        let dx2 = self.b.ins().fmul(dx, dx);
        let dy2 = self.b.ins().fmul(dy, dy);
        let dz2 = self.b.ins().fmul(dz, dz);
        let dxy2 = self.b.ins().fadd(dx2, dy2);
        let d2 = self.b.ins().fadd(dxy2, dz2);
        let hit = self.b.ins().fcmp(FloatCC::LessThanOrEqual, d2, r2);
        self.b.ins().brif(hit, add_bb, &[], step_bb, &[]);

        self.b.switch_to_block(add_bb);
        self.b.seal_block(add_bb);
        let ent = self
            .b
            .ins()
            .load(types::I64, MemFlagsData::trusted(), eptr, 0);
        let wp = coerce_cl_val(self.b, w, ptr_ty, ptr_ty);
        let woff = self.b.ins().imul_imm_s(wp, 8);
        let dst_addr = self.b.ins().iadd(out_ptr, woff);
        self.b
            .ins()
            .store(MemFlagsData::trusted(), ent, dst_addr, 0);
        let nw = self.b.ins().iadd_imm_s(w, 1);
        self.b.def_var(w_var, nw);
        self.b.ins().jump(step_bb, &[]);

        self.b.switch_to_block(step_bb);
        self.b.seal_block(step_bb);
        let ni = self.b.ins().iadd_imm_s(i, 1);
        self.b.def_var(i_var, ni);
        self.b.ins().jump(hdr, &[]);

        self.b.seal_block(hdr);
        self.b.switch_to_block(exit);
        self.b.seal_block(exit);
        self.def_scalar_typed(dst, out_ptr);
    }

    fn lower_terminator(&mut self, term: &Terminator) {
        match term {
            Terminator::Return(opt_val) => {
                if self.mode == MirCallbackMode::Helper {
                    self.emit_helper_return(*opt_val);
                } else {
                    let ok = self.b.ins().iconst(types::I32, i64::from(FFI_OK));
                    self.b.ins().return_(&[ok]);
                }
            }
            Terminator::Goto(dst) => {
                let target = self.cl_blocks[dst.0 as usize];
                self.b.ins().jump(target, &[]);
            }
            Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } => {
                let c = self.use_scalar(*cond);
                let tb = self.cl_blocks[then_bb.0 as usize];
                let eb = self.cl_blocks[else_bb.0 as usize];
                self.b.ins().brif(c, tb, &[], eb, &[]);
            }
            Terminator::Switch {
                scrutinee,
                cases,
                default_bb,
            } => {
                let sv = self.use_scalar(*scrutinee);
                let mut sw = Switch::new();
                for &(k, bb) in cases {
                    sw.set_entry(u128::from(k), self.cl_blocks[bb.0 as usize]);
                }
                sw.emit(self.b, sv, self.cl_blocks[default_bb.0 as usize]);
            }
        }
    }

    fn emit_helper_return(&mut self, opt_val: Option<LocalId>) {
        if self.mir_fn.ret_ty == MirType::Unit {
            self.b.ins().return_(&[]);
            return;
        }
        let Some(lid) = opt_val else {
            self.emit_default_helper_return();
            return;
        };
        match self.mir_fn.ret_ty {
            MirType::Vec2 => {
                let vs = self.use_vec(lid);
                self.b.ins().return_(&[vs[0], vs[1]]);
            }
            MirType::Vec3 => {
                let vs = self.use_vec(lid);
                self.b.ins().return_(&[vs[0], vs[1], vs[2]]);
            }
            MirType::Vec4 => {
                let vs = self.use_vec(lid);
                self.b.ins().return_(&vs);
            }
            _ => {
                let v = self.use_scalar(lid);
                let rty = self.b.func.signature.returns[0].value_type;
                let cv = coerce_cl_val(self.b, v, rty, self.ctx.ptr_ty);
                self.b.ins().return_(&[cv]);
            }
        }
    }

    fn emit_default_helper_return(&mut self) {
        let rets: Vec<Type> = self
            .b
            .func
            .signature
            .returns
            .iter()
            .map(|r| r.value_type)
            .collect();
        let vals: Vec<Value> = rets
            .into_iter()
            .map(|t| zero_for_cl_type(self.b, t))
            .collect();
        self.b.ins().return_(&vals);
    }
}

fn emit_startup_object_initializer(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    if ctx.mir.objects.is_empty() {
        return Ok(());
    }
    let sym = "strata_init_objects";
    let ptr_ty = ctx.ptr_ty;
    let call_conv = ctx.call_conv;
    let mut sig = Signature::new(call_conv);
    sig.params.push(AbiParam::new(ptr_ty)); // sys_ctx
    sig.params.push(AbiParam::new(ptr_ty)); // user_data (state_ptr)
    sig.returns.push(AbiParam::new(types::I32));
    let fid = ctx
        .obj_mod
        .declare_function(sym, Linkage::Local, &sig)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let name_id = ctx.intern_cstr(sym)?;

    // Build per-object primary-component query list and materialize any literal `HirCompInit` defaults.
    let mut obj_queries = Vec::new();
    let mut obj_blobs: Vec<(usize, Vec<(usize, Option<DataId>)>)> = Vec::new();

    for (oi, obj) in ctx.mir.objects.iter().enumerate() {
        let mut comp_blobs = Vec::new();
        for cname in &obj.components {
            if let Some(lidx) = lookup_name_in_map(&ctx.layout_map, cname) {
                let blob_id = define_object_comp_blob(
                    ctx,
                    oi,
                    lidx,
                    obj.inits.iter().find(|init| {
                        lookup_name_in_map(&ctx.layout_map, &init.component) == Some(lidx)
                    }),
                )?;
                comp_blobs.push((lidx, blob_id));
            }
        }
        if let Some(&(primary_lidx, _)) = comp_blobs.first() {
            let qi = obj_queries.len();
            obj_queries.push((oi, primary_lidx));
            obj_blobs.push((qi, comp_blobs));
        } else {
            obj_blobs.push((usize::MAX, comp_blobs));
        }
    }

    let obj_count = ctx.mir.objects.len();
    let mut obj_names = Vec::with_capacity(obj_count);
    let mut obj_persists = Vec::with_capacity(obj_count);
    for obj in &ctx.mir.objects {
        obj_names.push(ctx.intern_bytes(&obj.name)?);
        obj_persists.push(obj.is_persist);
    }

    let mut fn_ctx = ctx.obj_mod.make_context();
    fn_ctx.func.signature = sig;
    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut fn_ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);
        b.seal_block(entry);

        let sys_ctx = b.block_params(entry)[0];
        let state_ptr = b.block_params(entry)[1];
        let api_ptr = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.api_off as i32,
        );
        let host_ctx = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.host_ctx_off as i32,
        );

        let iter_slot = alloc_zero_slot(&mut b, ctx.ptr_bytes, ptr_ty);
        let iter_out = b.ins().stack_addr(ptr_ty, iter_slot, 0);
        let len_slot = alloc_zero_slot(&mut b, ctx.ptr_bytes, ptr_ty);
        let len_ptr = b.ins().stack_addr(ptr_ty, len_slot, 0);
        let cmd_slot = alloc_zero_slot(&mut b, ctx.ptr_bytes, ptr_ty);
        let cmd_out = b.ins().stack_addr(ptr_ty, cmd_slot, 0);
        let _cmd_rc = call_vtable(
            &ctx.obj_mod,
            &mut b,
            api_ptr,
            api_slots::SYS_COMMANDS,
            &[ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            call_conv,
            &[sys_ctx, cmd_out],
        );
        let cmds = b.ins().load(ptr_ty, MemFlagsData::trusted(), cmd_out, 0);

        for oi in 0..obj_count {
            let slot_off = ctx.state_layout.obj_slot_offset(oi) as i32;
            let cur = b
                .ins()
                .load(types::I64, MemFlagsData::trusted(), state_ptr, slot_off);
            let need = b.ins().icmp_imm_s(IntCC::Equal, cur, 0);
            let check_bb = b.create_block();
            let next_bb = b.create_block();
            b.ins().brif(need, check_bb, &[], next_bb, &[]);

            b.switch_to_block(check_bb);
            b.seal_block(check_bb);

            let (qi, comp_blobs) = &obj_blobs[oi];
            let spawn_bb = b.create_block();
            let bind_bb = b.create_block();
            b.append_block_param(bind_bb, types::I64);

            if *qi != usize::MAX {
                let qv = b.ins().iconst(ptr_ty, *qi as i64);
                let qrc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::SYS_QUERY,
                    &[ptr_ty, ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    call_conv,
                    &[sys_ctx, qv, iter_out],
                );
                let iter = b.ins().load(ptr_ty, MemFlagsData::trusted(), iter_out, 0);
                let rc_ok = b.ins().icmp_imm_s(IntCC::Equal, qrc, 0);
                let inz = b.ins().icmp_imm_s(IntCC::NotEqual, iter, 0);
                let ok = b.ins().band(rc_ok, inz);
                let probe_bb = b.create_block();
                b.ins().brif(ok, probe_bb, &[], spawn_bb, &[]);

                b.switch_to_block(probe_bb);
                b.seal_block(probe_bb);
                let has = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::ITER_NEXT_CHUNK,
                    &[ptr_ty, ptr_ty],
                    Some(types::I8),
                    ptr_ty,
                    call_conv,
                    &[iter, len_ptr],
                );
                let clen = b.ins().load(ptr_ty, MemFlagsData::trusted(), len_ptr, 0);
                let has_b = b.ins().icmp_imm_s(IntCC::NotEqual, has, 0);
                let len_p = b.ins().icmp_imm_s(IntCC::SignedGreaterThan, clen, 0);
                let found = b.ins().band(has_b, len_p);
                let take_bb = b.create_block();
                b.ins().brif(found, take_bb, &[], spawn_bb, &[]);

                b.switch_to_block(take_bb);
                b.seal_block(take_bb);
                let ents = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::ITER_ENTITIES,
                    &[ptr_ty],
                    Some(ptr_ty),
                    ptr_ty,
                    call_conv,
                    &[iter],
                );
                let e0 = b.ins().load(types::I64, MemFlagsData::trusted(), ents, 0);
                b.ins().jump(bind_bb, &[BlockArg::Value(e0)]);
            } else {
                b.ins().jump(spawn_bb, &[]);
            }

            b.switch_to_block(spawn_bb);
            b.seal_block(spawn_bb);
            let out_ent_slot = alloc_zero_slot(&mut b, structs::FFI_ENTITY_SIZE, ptr_ty);
            let out_ent_ptr = b.ins().stack_addr(ptr_ty, out_ent_slot, 0);
            if !comp_blobs.is_empty() {
                let comp_arr_slot = alloc_zero_slot(
                    &mut b,
                    comp_blobs.len() * structs::BAM_COMPONENT_SIZE,
                    ptr_ty,
                );
                let comp_arr = b.ins().stack_addr(ptr_ty, comp_arr_slot, 0);
                let ptr_arr_slot =
                    alloc_zero_slot(&mut b, comp_blobs.len() * ctx.ptr_bytes, ptr_ty);
                let ptr_arr = b.ins().stack_addr(ptr_ty, ptr_arr_slot, 0);
                for (ci, &(lidx, blob_opt)) in comp_blobs.iter().enumerate() {
                    let h = b.ins().load(
                        types::I32,
                        MemFlagsData::trusted(),
                        state_ptr,
                        ctx.state_layout.comp_slot_offset(lidx) as i32,
                    );
                    b.ins().store(
                        MemFlagsData::trusted(),
                        h,
                        comp_arr,
                        (ci * structs::BAM_COMPONENT_SIZE) as i32,
                    );
                    let dp = if let Some(bid) = blob_opt {
                        let gv = ctx.obj_mod.declare_data_in_func(bid, b.func);
                        b.ins().symbol_value(ptr_ty, gv)
                    } else {
                        b.ins().iconst(ptr_ty, 0)
                    };
                    b.ins().store(
                        MemFlagsData::trusted(),
                        dp,
                        ptr_arr,
                        (ci * ctx.ptr_bytes) as i32,
                    );
                }
                let cnt = b.ins().iconst(ptr_ty, comp_blobs.len() as i64);
                let sp_slot = if obj_persists[oi] {
                    api_slots::CMD_SPAWN_PERSISTENT
                } else {
                    api_slots::CMD_SPAWN
                };
                let _rc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    sp_slot,
                    &[ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    call_conv,
                    &[cmds, comp_arr, ptr_arr, cnt, out_ent_ptr],
                );
            } else {
                let _rc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::CMD_SPAWN_EMPTY,
                    &[ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    call_conv,
                    &[cmds, out_ent_ptr],
                );
            }
            let spawned = b
                .ins()
                .load(types::I64, MemFlagsData::trusted(), out_ent_ptr, 0);
            b.ins().jump(bind_bb, &[BlockArg::Value(spawned)]);

            b.switch_to_block(bind_bb);
            b.seal_block(bind_bb);
            let ent = b.block_params(bind_bb)[0];
            b.ins()
                .store(MemFlagsData::trusted(), ent, state_ptr, slot_off);
            let (nid, nlen) = obj_names[oi];
            let ngv = ctx.obj_mod.declare_data_in_func(nid, b.func);
            let nptr = b.ins().symbol_value(ptr_ty, ngv);
            let nlen_v = b.ins().iconst(ptr_ty, nlen as i64);
            let _bind_rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::BIND_NAMED_OBJECT,
                &[ptr_ty, ptr_ty, ptr_ty, types::I64],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[host_ctx, nptr, nlen_v, ent],
            );
            b.ins().jump(next_bb, &[]);

            b.switch_to_block(next_bb);
            b.seal_block(next_bb);
        }

        let ok = b.ins().iconst(types::I32, i64::from(FFI_OK));
        b.ins().return_(&[ok]);
        b.finalize(ctx.fe_cfg);
    }
    ctx.obj_mod
        .define_function(fid, &mut fn_ctx)
        .map_err(|e| JitError::Codegen(format!("strata_init_objects failed: {e}")))?;

    ctx.init_objects_fn = Some((fid, name_id, obj_queries));
    Ok(())
}

fn define_object_comp_blob(
    ctx: &mut ModuleContext<'_>,
    _obj_idx: usize,
    lidx: usize,
    init: Option<&HirCompInit>,
) -> Result<Option<DataId>, JitError> {
    let layout = &ctx.mir_layouts_sorted[lidx];
    if layout.size == 0 {
        return Ok(None);
    }
    let mut blob = vec![0u8; layout.size];
    if let Some(defaults) = ctx.mir.field_defaults.get(&layout.canonical_name) {
        for (fname, cval) in defaults {
            if let Some(sf) = layout.fields.iter().find(|f| f.name == *fname) {
                write_const_val_to_buf(&mut blob, sf, cval);
            }
        }
    }
    if let Some(ci) = init {
        for (fname, fexpr) in &ci.fields {
            if let Some(sf) = layout.fields.iter().find(|f| f.name == *fname)
                && let Some(cval) =
                    eval_const_hir_expr(fexpr, &ctx.enums_by_name, &ctx.consts_by_name)
            {
                write_const_val_to_buf(&mut blob, sf, &cval);
            }
        }
    }
    let bid = ctx
        .obj_mod
        .declare_anonymous_data(false, false)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut desc = DataDescription::new();
    desc.define(blob.into_boxed_slice());
    desc.set_align(layout.align.max(1) as u64);
    ctx.obj_mod
        .define_data(bid, &desc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    Ok(Some(bid))
}

fn emit_res_ptr_lookup(
    ctx: &ModuleContext<'_>,
    b: &mut FunctionBuilder<'_>,
    api_ptr: Value,
    sys_ctx: Value,
    state_ptr: Value,
    lidx: usize,
    mutable: bool,
) -> Value {
    let ptr_ty = ctx.ptr_ty;
    let flag = b.ins().load(
        types::I8,
        MemFlagsData::trusted(),
        state_ptr,
        ctx.state_layout.res_flag_offset(lidx) as i32,
    );
    let is_host = b.ins().icmp_imm_s(IntCC::Equal, flag, 1);
    let has_sys = b.ins().icmp_imm_s(IntCC::NotEqual, sys_ctx, 0);
    let use_host = b.ins().band(is_host, has_sys);

    let host_bb = b.create_block();
    let local_bb = b.create_block();
    let merge_bb = b.create_block();
    b.append_block_param(merge_bb, ptr_ty);
    b.ins().brif(use_host, host_bb, &[], local_bb, &[]);

    b.switch_to_block(host_bb);
    b.seal_block(host_bb);
    let comp = b.ins().load(
        types::I32,
        MemFlagsData::trusted(),
        state_ptr,
        ctx.state_layout.comp_slot_offset(lidx) as i32,
    );
    let tick_slot = alloc_zero_slot(b, 16, ptr_ty);
    let tick_ptr = b.ins().stack_addr(ptr_ty, tick_slot, 0);
    let vslot = if mutable {
        api_slots::SYS_RES_MUT_PTR
    } else {
        api_slots::SYS_RES_PTR
    };
    let hptr = call_vtable(
        &ctx.obj_mod,
        b,
        api_ptr,
        vslot,
        &[ptr_ty, types::I32, ptr_ty],
        Some(ptr_ty),
        ptr_ty,
        ctx.call_conv,
        &[sys_ctx, comp, tick_ptr],
    );
    let h_ok = b.ins().icmp_imm_s(IntCC::NotEqual, hptr, 0);
    b.ins()
        .brif(h_ok, merge_bb, &[BlockArg::Value(hptr)], local_bb, &[]);

    b.switch_to_block(local_bb);
    b.seal_block(local_bb);
    let off = ctx.layouts[lidx].mod_res_offset as i64;
    let lptr = b.ins().iadd_imm_s(state_ptr, off);
    b.ins().jump(merge_bb, &[BlockArg::Value(lptr)]);

    b.switch_to_block(merge_bb);
    b.seal_block(merge_bb);
    b.block_params(merge_bb)[0]
}

fn emit_bamabi_manifest(
    ctx: &mut ModuleContext<'_>,
    manifest_data_id: DataId,
) -> Result<(), JitError> {
    let mut sig = Signature::new(ctx.call_conv);
    sig.returns.push(AbiParam::new(ctx.ptr_ty));
    let fid = ctx
        .obj_mod
        .declare_function("bamabi_manifest", Linkage::Export, &sig)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let mut fn_ctx = ctx.obj_mod.make_context();
    fn_ctx.func.signature = sig;
    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut fn_ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.switch_to_block(entry);
        b.seal_block(entry);
        let gv = ctx.obj_mod.declare_data_in_func(manifest_data_id, b.func);
        let addr = b.ins().symbol_value(ctx.ptr_ty, gv);
        b.ins().return_(&[addr]);
        b.finalize(ctx.fe_cfg);
    }
    ctx.obj_mod
        .define_function(fid, &mut fn_ctx)
        .map_err(|e| JitError::Codegen(e.to_string()))
}

fn emit_bamabi_shutdown(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    let ptr_ty = ctx.ptr_ty;
    let free_fid = ctx.declare_extern_fn("free", &[ptr_ty], None)?;

    let mut sig = Signature::new(ctx.call_conv);
    sig.params.push(AbiParam::new(ptr_ty)); // instance
    let fid = ctx
        .obj_mod
        .declare_function("bamabi_shutdown", Linkage::Export, &sig)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let mut fn_ctx = ctx.obj_mod.make_context();
    fn_ctx.func.signature = sig;
    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut fn_ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);
        b.seal_block(entry);
        let inst = b.block_params(entry)[0];
        let nz = b.ins().icmp_imm_s(IntCC::NotEqual, inst, 0);
        let free_bb = b.create_block();
        let ret_bb = b.create_block();
        b.ins().brif(nz, free_bb, &[], ret_bb, &[]);

        b.switch_to_block(free_bb);
        b.seal_block(free_bb);
        let fref = ctx.obj_mod.declare_func_in_func(free_fid, b.func);
        b.ins().call(fref, &[inst]);
        b.ins().jump(ret_bb, &[]);

        b.switch_to_block(ret_bb);
        b.seal_block(ret_bb);
        b.ins().return_(&[]);
        b.finalize(ctx.fe_cfg);
    }
    ctx.obj_mod
        .define_function(fid, &mut fn_ctx)
        .map_err(|e| JitError::Codegen(e.to_string()))
}

fn emit_bamabi_init(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    let ptr_ty = ctx.ptr_ty;
    let ptr_bytes = ctx.ptr_bytes;
    let call_conv = ctx.call_conv;
    let calloc_fid = ctx.declare_extern_fn("calloc", &[ptr_ty, ptr_ty], Some(ptr_ty))?;

    let mut sig = Signature::new(call_conv);
    sig.params.push(AbiParam::new(ptr_ty)); // api_ptr
    sig.params.push(AbiParam::new(ptr_ty)); // load_ctx
    sig.params.push(AbiParam::new(ptr_ty)); // instance_out
    sig.returns.push(AbiParam::new(types::I32));
    let fid = ctx
        .obj_mod
        .declare_function("bamabi_init", Linkage::Export, &sig)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let mut fn_ctx = ctx.obj_mod.make_context();
    fn_ctx.func.signature = sig;
    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut fn_ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);
        b.seal_block(entry);

        let api_ptr = b.block_params(entry)[0];
        let load_ctx = b.block_params(entry)[1];
        let instance_out = b.block_params(entry)[2];

        let err_null_blk = b.create_block();
        let init_ok_blk = b.create_block();
        let err_ret_blk = b.create_block();
        b.append_block_param(err_ret_blk, types::I32);

        let api_null = b.ins().icmp_imm_s(IntCC::Equal, api_ptr, 0);
        let lctx_null = b.ins().icmp_imm_s(IntCC::Equal, load_ctx, 0);
        let any_null = b.ins().bor(api_null, lctx_null);
        b.ins().brif(any_null, err_null_blk, &[], init_ok_blk, &[]);

        b.switch_to_block(err_null_blk);
        b.seal_block(err_null_blk);
        let null_res = b
            .ins()
            .iconst(types::I32, i64::from(crate::abi_offsets::FFI_NULL_POINTER));
        b.ins().return_(&[null_res]);

        b.switch_to_block(init_ok_blk);
        b.seal_block(init_ok_blk);

        // Allocate per-world `StrataJitState` via `calloc(1, total_bytes)`.
        let cref = ctx.obj_mod.declare_func_in_func(calloc_fid, b.func);
        let one_sz = b.ins().iconst(ptr_ty, 1);
        let tot_sz = b.ins().iconst(ptr_ty, ctx.state_layout.total_bytes as i64);
        let cal = b.ins().call(cref, &[one_sz, tot_sz]);
        let state_addr = b.func.dfg.inst_results(cal)[0];
        let state_null = b.ins().icmp_imm_s(IntCC::Equal, state_addr, 0);
        let state_ok_blk = b.create_block();
        let oom_res = b.ins().iconst(
            types::I32,
            i64::from(bamabi_sys::FfiResult::INTERNAL_ERROR.0),
        );
        b.ins().brif(
            state_null,
            err_ret_blk,
            &[BlockArg::Value(oom_res)],
            state_ok_blk,
            &[],
        );

        b.switch_to_block(state_ok_blk);
        b.seal_block(state_ok_blk);
        b.ins().store(
            MemFlagsData::trusted(),
            api_ptr,
            state_addr,
            ctx.state_layout.api_off as i32,
        );

        let io_null = b.ins().icmp_imm_s(IntCC::Equal, instance_out, 0);
        let write_inst_blk = b.create_block();
        let after_inst_blk = b.create_block();
        b.ins()
            .brif(io_null, after_inst_blk, &[], write_inst_blk, &[]);
        b.switch_to_block(write_inst_blk);
        b.seal_block(write_inst_blk);
        b.ins()
            .store(MemFlagsData::trusted(), state_addr, instance_out, 0);
        b.ins().jump(after_inst_blk, &[]);
        b.switch_to_block(after_inst_blk);
        b.seal_block(after_inst_blk);

        let host_ctx = call_vtable(
            &ctx.obj_mod,
            &mut b,
            api_ptr,
            api_slots::LOAD_HOST_CTX,
            &[ptr_ty],
            Some(ptr_ty),
            ptr_ty,
            call_conv,
            &[load_ctx],
        );
        b.ins().store(
            MemFlagsData::trusted(),
            host_ctx,
            state_addr,
            ctx.state_layout.host_ctx_off as i32,
        );

        // Initialize mod-local resource defaults inside `StrataJitState`.
        for l in &ctx.layouts {
            if (l.is_resource || l.is_stream)
                && let Some(blob_id) = l.default_blob_id
                && l.size > 0
            {
                let gv = ctx.obj_mod.declare_data_in_func(blob_id, b.func);
                let src_ptr = b.ins().symbol_value(ptr_ty, gv);
                let dst_ptr = b.ins().iadd_imm_s(state_addr, l.mod_res_offset as i64);
                emit_memcpy(&mut b, dst_ptr, src_ptr, l.size);
            }
        }

        // Reusable scratch slots for registration.
        let cdesc_slot = alloc_zero_slot(&mut b, structs::COMPONENT_DESC_SIZE, ptr_ty);
        let cdesc_buf = b.ins().stack_addr(ptr_ty, cdesc_slot, 0);
        let req_cap = ctx
            .layouts
            .iter()
            .map(|l| l.required_indices.len())
            .max()
            .unwrap_or(1)
            .max(1);
        let req_slot = alloc_zero_slot(&mut b, req_cap * structs::BAM_COMPONENT_SIZE, ptr_ty);
        let req_buf = b.ins().stack_addr(ptr_ty, req_slot, 0);
        let req_init_slot = alloc_zero_slot(&mut b, req_cap * REQ_COMP_DESC_SIZE, ptr_ty);
        let req_init_buf = b.ins().stack_addr(ptr_ty, req_init_slot, 0);
        let linfo_slot = alloc_zero_slot(&mut b, structs::LAYOUT_INFO_SIZE, ptr_ty);
        let linfo_ptr = b.ins().stack_addr(ptr_ty, linfo_slot, 0);
        let linfo_sz_v = b.ins().iconst(types::I32, structs::LAYOUT_INFO_SIZE as i64);

        // Step 1: Resolve host-registered resources & streams BEFORE registering dynamic mod components,
        // checking `component_layout_info` flags (`RESOURCE` / `MESSAGE`) to distinguish cleanly.
        for (lidx, l) in ctx.layouts.iter().enumerate() {
            if !l.is_resource && !l.is_stream {
                continue;
            }
            let comp_out = b
                .ins()
                .iadd_imm_s(state_addr, ctx.state_layout.comp_slot_offset(lidx) as i64);
            let ngv = ctx.obj_mod.declare_data_in_func(l.name_cstr_id, b.func);
            let nptr = b.ins().symbol_value(ptr_ty, ngv);
            let null_uuid = b.ins().iconst(ptr_ty, 0);
            let rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::RESOLVE_COMPONENT,
                &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[host_ctx, nptr, null_uuid, comp_out],
            );
            let ok = b.ins().icmp_imm_s(IntCC::Equal, rc, 0);
            let info_bb = b.create_block();
            let reg_stream_bb = b.create_block();
            let next_l_bb = b.create_block();
            b.ins().brif(ok, info_bb, &[], reg_stream_bb, &[]);

            b.switch_to_block(info_bb);
            b.seal_block(info_bb);
            b.ins().store(
                MemFlagsData::trusted(),
                linfo_sz_v,
                linfo_ptr,
                structs::LINFO_STRUCT_SIZE as i32,
            );
            let comp_h = b
                .ins()
                .load(types::I32, MemFlagsData::trusted(), comp_out, 0);
            let irc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::COMPONENT_LAYOUT_INFO,
                &[ptr_ty, types::I32, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[host_ctx, comp_h, linfo_ptr],
            );
            let irc_ok = b.ins().icmp_imm_s(IntCC::Equal, irc, 0);
            let lflags = b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                linfo_ptr,
                structs::LINFO_FLAGS as i32,
            );
            let expected_flag = if l.is_stream {
                i64::from(STORAGE_FLAG_MESSAGE)
            } else {
                i64::from(STORAGE_FLAG_RESOURCE)
            };
            let masked = b.ins().band_imm_u(lflags, expected_flag);
            let flag_set = b.ins().icmp_imm_s(IntCC::NotEqual, masked, 0);
            let matched = b.ins().band(irc_ok, flag_set);
            let mark_bb = b.create_block();
            b.ins().brif(matched, mark_bb, &[], reg_stream_bb, &[]);

            b.switch_to_block(mark_bb);
            b.seal_block(mark_bb);
            let kind_val = b.ins().iconst(types::I8, if l.is_stream { 2 } else { 1 });
            b.ins().store(
                MemFlagsData::trusted(),
                kind_val,
                state_addr,
                ctx.state_layout.res_flag_offset(lidx) as i32,
            );
            b.ins().jump(next_l_bb, &[]);

            b.switch_to_block(reg_stream_bb);
            b.seal_block(reg_stream_bb);
            if l.is_stream {
                let cgv = ctx.obj_mod.declare_data_in_func(l.comp_desc_id, b.func);
                let ro_cd = b.ins().symbol_value(ptr_ty, cgv);
                let _s_rc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::REGISTER_COMPONENT,
                    &[ptr_ty, ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    call_conv,
                    &[load_ctx, ro_cd, comp_out],
                );
            }
            b.ins().jump(next_l_bb, &[]);

            b.switch_to_block(next_l_bb);
            b.seal_block(next_l_bb);
        }

        // Step 2: Register ECS components in topological `@require` order, supporting schema migration
        // (`TYPE_MISMATCH` -> `resolve_component(name, null)` -> `migrate_component_column` Slot 67).
        for (lidx, l) in ctx.layouts.iter().enumerate() {
            if !l.is_ecs_component || l.is_stream {
                continue;
            }
            let comp_out = b
                .ins()
                .iadd_imm_s(state_addr, ctx.state_layout.comp_slot_offset(lidx) as i64);
            let cgv = ctx.obj_mod.declare_data_in_func(l.comp_desc_id, b.func);
            let ro_cd = b.ins().symbol_value(ptr_ty, cgv);
            emit_memcpy(&mut b, cdesc_buf, ro_cd, structs::COMPONENT_DESC_SIZE);

            if !l.required_indices.is_empty() {
                zero_slot(
                    &mut b,
                    req_init_slot,
                    l.required_indices.len() * REQ_COMP_DESC_SIZE,
                    ptr_ty,
                );
                let req_init_sz_v = b.ins().iconst(types::I32, REQ_COMP_DESC_SIZE as i64);
                let custom_flag_v = b
                    .ins()
                    .iconst(types::I32, i64::from(BAM_REQUIRED_FLAG_CUSTOM_BYTES));
                for (ri, &req_lidx) in l.required_indices.iter().enumerate() {
                    let rh = b.ins().load(
                        types::I32,
                        MemFlagsData::trusted(),
                        state_addr,
                        ctx.state_layout.comp_slot_offset(req_lidx) as i32,
                    );
                    b.ins().store(
                        MemFlagsData::trusted(),
                        rh,
                        req_buf,
                        (ri * structs::BAM_COMPONENT_SIZE) as i32,
                    );
                    let entry_off = ri * REQ_COMP_DESC_SIZE;
                    b.ins().store(
                        MemFlagsData::trusted(),
                        req_init_sz_v,
                        req_init_buf,
                        (entry_off + REQ_COMP_STRUCT_SIZE_OFF) as i32,
                    );
                    b.ins().store(
                        MemFlagsData::trusted(),
                        rh,
                        req_init_buf,
                        (entry_off + REQ_COMP_COMPONENT_OFF) as i32,
                    );
                    let req_meta = &ctx.layouts[req_lidx];
                    if req_meta.size > 0
                        && ctx.mir_layouts_sorted[req_lidx].is_abi_pod
                        && let Some(def_bid) = req_meta.default_blob_id
                    {
                        let def_gv = ctx.obj_mod.declare_data_in_func(def_bid, b.func);
                        let def_ptr = b.ins().symbol_value(ptr_ty, def_gv);
                        let def_sz = b.ins().iconst(ptr_ty, req_meta.size as i64);
                        b.ins().store(
                            MemFlagsData::trusted(),
                            custom_flag_v,
                            req_init_buf,
                            (entry_off + REQ_COMP_FLAGS_OFF) as i32,
                        );
                        b.ins().store(
                            MemFlagsData::trusted(),
                            def_ptr,
                            req_init_buf,
                            (entry_off + REQ_COMP_INIT_BYTES_OFF) as i32,
                        );
                        b.ins().store(
                            MemFlagsData::trusted(),
                            def_sz,
                            req_init_buf,
                            (entry_off + REQ_COMP_INIT_SIZE_OFF) as i32,
                        );
                    }
                }
                let rcnt = b.ins().iconst(ptr_ty, l.required_indices.len() as i64);
                b.ins().store(
                    MemFlagsData::trusted(),
                    req_buf,
                    cdesc_buf,
                    structs::COMP_REQUIRED_COMPONENTS as i32,
                );
                b.ins().store(
                    MemFlagsData::trusted(),
                    rcnt,
                    cdesc_buf,
                    structs::COMP_REQUIRED_COMPONENT_COUNT as i32,
                );
                b.ins().store(
                    MemFlagsData::trusted(),
                    req_init_buf,
                    cdesc_buf,
                    COMP_REQUIRED_INIT_DESCS_OFF as i32,
                );
                b.ins().store(
                    MemFlagsData::trusted(),
                    rcnt,
                    cdesc_buf,
                    COMP_REQUIRED_INIT_DESC_COUNT_OFF as i32,
                );
            }

            let rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::REGISTER_COMPONENT,
                &[ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[load_ctx, cdesc_buf, comp_out],
            );
            let is_ok = b.ins().icmp_imm_s(IntCC::Equal, rc, 0);
            let next_comp_bb = b.create_block();
            let err_chk_bb = b.create_block();
            b.ins().brif(is_ok, next_comp_bb, &[], err_chk_bb, &[]);

            b.switch_to_block(err_chk_bb);
            b.seal_block(err_chk_bb);
            if let Some(&mig_fid) = ctx.migrations_by_layout.get(&lidx) {
                let is_mismatch =
                    b.ins()
                        .icmp_imm_s(IntCC::Equal, rc, i64::from(FFI_TYPE_MISMATCH));
                let mig_bb = b.create_block();
                b.ins().brif(
                    is_mismatch,
                    mig_bb,
                    &[],
                    err_ret_blk,
                    &[BlockArg::Value(rc)],
                );

                b.switch_to_block(mig_bb);
                b.seal_block(mig_bb);
                let ngv = ctx.obj_mod.declare_data_in_func(l.name_cstr_id, b.func);
                let nptr = b.ins().symbol_value(ptr_ty, ngv);
                let null_uuid = b.ins().iconst(ptr_ty, 0);
                let rrc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::RESOLVE_COMPONENT,
                    &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    call_conv,
                    &[host_ctx, nptr, null_uuid, comp_out],
                );
                let rrc_ok = b.ins().icmp_imm_s(IntCC::Equal, rrc, 0);
                let do_mig_bb = b.create_block();
                b.ins()
                    .brif(rrc_ok, do_mig_bb, &[], err_ret_blk, &[BlockArg::Value(rrc)]);

                b.switch_to_block(do_mig_bb);
                b.seal_block(do_mig_bb);
                let existing_comp = b
                    .ins()
                    .load(types::I32, MemFlagsData::trusted(), comp_out, 0);
                let old_fp = b.ins().iconst(types::I64, 0);
                let mig_ref = ctx.obj_mod.declare_func_in_func(mig_fid, b.func);
                let mig_fn_ptr = b.ins().func_addr(ptr_ty, mig_ref);
                let mrc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::MIGRATE_COMPONENT_COLUMN,
                    &[ptr_ty, types::I32, types::I64, ptr_ty, ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    call_conv,
                    &[
                        load_ctx,
                        existing_comp,
                        old_fp,
                        cdesc_buf,
                        mig_fn_ptr,
                        state_addr,
                    ],
                );
                let mrc_ok = b.ins().icmp_imm_s(IntCC::Equal, mrc, 0);
                b.ins().brif(
                    mrc_ok,
                    next_comp_bb,
                    &[],
                    err_ret_blk,
                    &[BlockArg::Value(mrc)],
                );
            } else {
                b.ins().jump(err_ret_blk, &[BlockArg::Value(rc)]);
            }

            b.switch_to_block(next_comp_bb);
            b.seal_block(next_comp_bb);
        }

        // Step 3: Register typed relations (`Slot 54`).
        for (ri, r) in ctx.relations.iter().enumerate() {
            let rel_out = b
                .ins()
                .iadd_imm_s(state_addr, ctx.state_layout.rel_slot_offset(ri) as i64);
            let rgv = ctx.obj_mod.declare_data_in_func(r.desc_id, b.func);
            let rdesc_ptr = b.ins().symbol_value(ptr_ty, rgv);
            let rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::REGISTER_RELATION,
                &[ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[load_ctx, rdesc_ptr, rel_out],
            );
            let is_err = b.ins().icmp_imm_s(IntCC::NotEqual, rc, 0);
            let ok_bb = b.create_block();
            b.ins()
                .brif(is_err, err_ret_blk, &[BlockArg::Value(rc)], ok_bb, &[]);
            b.switch_to_block(ok_bb);
            b.seal_block(ok_bb);
        }

        // Step 4: Register reactive observers (`Slot 36`).
        let obs_slot = alloc_zero_slot(&mut b, structs::OBSERVER_DESC_SIZE, ptr_ty);
        let obs_ptr = b.ins().stack_addr(ptr_ty, obs_slot, 0);
        let watch_slot = alloc_zero_slot(&mut b, structs::BAM_COMPONENT_SIZE, ptr_ty);
        let watch_ptr = b.ins().stack_addr(ptr_ty, watch_slot, 0);

        for obs in &ctx.observers {
            zero_slot(&mut b, obs_slot, structs::OBSERVER_DESC_SIZE, ptr_ty);
            let osz = b
                .ins()
                .iconst(types::I32, structs::OBSERVER_DESC_SIZE as i64);
            let ngv = ctx.obj_mod.declare_data_in_func(obs.name_data_id, b.func);
            let nptr = b.ins().symbol_value(ptr_ty, ngv);
            let ev_comp = if let Some(ev_lidx) = obs.event_layout_idx {
                b.ins().load(
                    types::I32,
                    MemFlagsData::trusted(),
                    state_ptr_alias(state_addr),
                    ctx.state_layout.comp_slot_offset(ev_lidx) as i32,
                )
            } else {
                b.ins().iconst(types::I32, i64::from(BAM_COMPONENT_INVALID))
            };
            let ekind = b.ins().iconst(types::I32, i64::from(obs.event_kind));
            let inv_rel = b.ins().iconst(types::I32, i64::from(BAM_COMPONENT_INVALID));
            let fref = ctx.obj_mod.declare_func_in_func(obs.func_id, b.func);
            let fn_addr = b.ins().func_addr(ptr_ty, fref);

            b.ins()
                .stack_store(ptr_ty, osz, obs_slot, structs::OBS_STRUCT_SIZE as i32);
            b.ins()
                .stack_store(ptr_ty, nptr, obs_slot, structs::OBS_NAME as i32);
            b.ins()
                .stack_store(ptr_ty, ev_comp, obs_slot, structs::OBS_EVENT as i32);
            b.ins()
                .stack_store(ptr_ty, fn_addr, obs_slot, structs::OBS_CALLBACK as i32);
            b.ins()
                .stack_store(ptr_ty, state_addr, obs_slot, structs::OBS_USER_DATA as i32);
            b.ins()
                .stack_store(ptr_ty, ekind, obs_slot, structs::OBS_EVENT_KIND as i32);
            b.ins().stack_store(
                ptr_ty,
                inv_rel,
                obs_slot,
                structs::OBS_PROPAGATE_RELATIONSHIP as i32,
            );

            if let Some(w_lidx) = obs.watched_layout_idx {
                let wh = b.ins().load(
                    types::I32,
                    MemFlagsData::trusted(),
                    state_addr,
                    ctx.state_layout.comp_slot_offset(w_lidx) as i32,
                );
                b.ins().stack_store(ptr_ty, wh, watch_slot, 0);
                let one = b.ins().iconst(ptr_ty, 1);
                b.ins().stack_store(
                    ptr_ty,
                    watch_ptr,
                    obs_slot,
                    structs::OBS_WATCHED_COMPONENTS as i32,
                );
                b.ins().stack_store(
                    ptr_ty,
                    one,
                    obs_slot,
                    structs::OBS_WATCHED_COMPONENT_COUNT as i32,
                );
            }

            let rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::REGISTER_OBSERVER,
                &[ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[load_ctx, obs_ptr],
            );
            let is_err = b.ins().icmp_imm_s(IntCC::NotEqual, rc, 0);
            let ok_bb = b.create_block();
            b.ins()
                .brif(is_err, err_ret_blk, &[BlockArg::Value(rc)], ok_bb, &[]);
            b.switch_to_block(ok_bb);
            b.seal_block(ok_bb);
        }

        // Step 5: Configure schedule sets (`Slot 61`), best-effort (ignores `INVALID_STATE` when `world_ptr` null).
        let sset_slot = alloc_zero_slot(&mut b, structs::SCHEDULE_SET_DESC_SIZE, ptr_ty);
        let sset_ptr = b.ins().stack_addr(ptr_ty, sset_slot, 0);
        let max_set_edges = ctx
            .schedule_sets
            .iter()
            .map(|s| s.before_set_indices.len().max(s.after_set_indices.len()))
            .max()
            .unwrap_or(1)
            .max(1);
        let set_edge_slot =
            alloc_zero_slot(&mut b, max_set_edges * structs::BAM_SYSTEM_SET_SIZE, ptr_ty);
        let set_edge_ptr = b.ins().stack_addr(ptr_ty, set_edge_slot, 0);

        for (set_idx, sset) in ctx.schedule_sets.iter().enumerate() {
            let out_set = b
                .ins()
                .iadd_imm_s(state_addr, ctx.state_layout.set_slot_offset(set_idx) as i64);
            let inv_set = b
                .ins()
                .iconst(types::I32, i64::from(BAM_SYSTEM_SET_INVALID));
            b.ins().store(MemFlagsData::trusted(), inv_set, out_set, 0);

            zero_slot(&mut b, sset_slot, structs::SCHEDULE_SET_DESC_SIZE, ptr_ty);
            let sz = b
                .ins()
                .iconst(types::I32, structs::SCHEDULE_SET_DESC_SIZE as i64);
            let fl = b.ins().iconst(types::I32, i64::from(sset.flags));
            let sid = b.ins().iconst(types::I32, i64::from(sset.schedule_id));
            let ngv = ctx
                .obj_mod
                .declare_data_in_func(sset.qualified_name_cstr, b.func);
            let nptr = b.ins().symbol_value(ptr_ty, ngv);
            b.ins()
                .stack_store(ptr_ty, sz, sset_slot, structs::SSET_STRUCT_SIZE as i32);
            b.ins()
                .stack_store(ptr_ty, fl, sset_slot, structs::SSET_FLAGS as i32);
            b.ins()
                .stack_store(ptr_ty, sid, sset_slot, structs::SSET_SCHEDULE as i32);
            b.ins()
                .stack_store(ptr_ty, nptr, sset_slot, structs::SSET_NAME as i32);
            if !sset.after_set_indices.is_empty() {
                let mut valid_cnt = 0usize;
                for &after_idx in &sset.after_set_indices {
                    if after_idx < set_idx {
                        let ah = b.ins().load(
                            types::I32,
                            MemFlagsData::trusted(),
                            state_addr,
                            ctx.state_layout.set_slot_offset(after_idx) as i32,
                        );
                        b.ins().store(
                            MemFlagsData::trusted(),
                            ah,
                            set_edge_ptr,
                            (valid_cnt * structs::BAM_SYSTEM_SET_SIZE) as i32,
                        );
                        valid_cnt += 1;
                    }
                }
                if valid_cnt > 0 {
                    let acnt = b.ins().iconst(ptr_ty, valid_cnt as i64);
                    b.ins().stack_store(
                        ptr_ty,
                        set_edge_ptr,
                        sset_slot,
                        structs::SSET_AFTER_SETS as i32,
                    );
                    b.ins()
                        .stack_store(ptr_ty, acnt, sset_slot, structs::SSET_AFTER_COUNT as i32);
                }
            }
            let _ = max_set_edges;

            let _rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::CONFIGURE_SCHEDULE_SET,
                &[ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[load_ctx, sset_ptr, out_set],
            );
        }

        // Step 6: Register Startup named-object initializer system (if `mir.objects` non-empty).
        let mut cur_sys_slot_idx = 0usize;
        if let Some((init_fid, init_name_id, ref obj_queries)) = ctx.init_objects_fn {
            let sys_out = b.ins().iadd_imm_s(
                state_addr,
                ctx.state_layout.sys_slot_offset(cur_sys_slot_idx) as i64,
            );
            cur_sys_slot_idx += 1;
            let qcount = obj_queries.len().min(SYSTEM_QUERY_CAP);
            let sdesc_slot = alloc_zero_slot(&mut b, structs::SYSTEM_DESC_SIZE, ptr_ty);
            let sdesc_ptr = b.ins().stack_addr(ptr_ty, sdesc_slot, 0);
            let qdescs_slot = alloc_zero_slot(
                &mut b,
                (qcount * structs::QUERY_DESC_SIZE).max(structs::QUERY_DESC_SIZE),
                ptr_ty,
            );
            let qdescs_ptr = b.ins().stack_addr(ptr_ty, qdescs_slot, 0);

            for (qi, &(_, lidx)) in obj_queries.iter().take(qcount).enumerate() {
                let term_slot = alloc_zero_slot(&mut b, structs::TERM_DESC_SIZE, ptr_ty);
                let term_ptr = b.ins().stack_addr(ptr_ty, term_slot, 0);
                let comp = b.ins().load(
                    types::I32,
                    MemFlagsData::trusted(),
                    state_addr,
                    ctx.state_layout.comp_slot_offset(lidx) as i32,
                );
                let mode = b
                    .ins()
                    .iconst(types::I32, i64::from(AccessMode::FILTER_ONLY.0));
                b.ins()
                    .stack_store(ptr_ty, comp, term_slot, structs::TERM_COMPONENT as i32);
                b.ins()
                    .stack_store(ptr_ty, mode, term_slot, structs::TERM_MODE as i32);
                let qb = (qi * structs::QUERY_DESC_SIZE) as i32;
                let qsz = b.ins().iconst(types::I32, structs::QUERY_DESC_SIZE as i64);
                let one = b.ins().iconst(ptr_ty, 1);
                b.ins().stack_store(
                    ptr_ty,
                    qsz,
                    qdescs_slot,
                    qb + structs::QUERY_STRUCT_SIZE as i32,
                );
                b.ins().stack_store(
                    ptr_ty,
                    term_ptr,
                    qdescs_slot,
                    qb + structs::QUERY_TERMS as i32,
                );
                b.ins().stack_store(
                    ptr_ty,
                    one,
                    qdescs_slot,
                    qb + structs::QUERY_TERM_COUNT as i32,
                );
            }
            let ssz = b.ins().iconst(types::I32, structs::SYSTEM_DESC_SIZE as i64);
            let ngv = ctx.obj_mod.declare_data_in_func(init_name_id, b.func);
            let nptr = b.ins().symbol_value(ptr_ty, ngv);
            let fref = ctx.obj_mod.declare_func_in_func(init_fid, b.func);
            let faddr = b.ins().func_addr(ptr_ty, fref);
            let sched_v = b.ins().iconst(types::I32, i64::from(ScheduleId::STARTUP.0));
            let qcv = b.ins().iconst(ptr_ty, qcount as i64);
            b.ins()
                .stack_store(ptr_ty, ssz, sdesc_slot, structs::SYS_STRUCT_SIZE as i32);
            b.ins()
                .stack_store(ptr_ty, nptr, sdesc_slot, structs::SYS_NAME as i32);
            b.ins()
                .stack_store(ptr_ty, qdescs_ptr, sdesc_slot, structs::SYS_QUERIES as i32);
            b.ins()
                .stack_store(ptr_ty, qcv, sdesc_slot, structs::SYS_QUERY_COUNT as i32);
            b.ins()
                .stack_store(ptr_ty, faddr, sdesc_slot, structs::SYS_CALLBACK as i32);
            b.ins().stack_store(
                ptr_ty,
                state_addr,
                sdesc_slot,
                structs::SYS_USER_DATA as i32,
            );
            b.ins()
                .stack_store(ptr_ty, sched_v, sdesc_slot, structs::SYS_SCHEDULE as i32);

            let rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::REGISTER_SYSTEM_HANDLE,
                &[ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[load_ctx, sdesc_ptr, sys_out],
            );
            let is_err = b.ins().icmp_imm_s(IntCC::NotEqual, rc, 0);
            let ok_bb = b.create_block();
            b.ins()
                .brif(is_err, err_ret_blk, &[BlockArg::Value(rc)], ok_bb, &[]);
            b.switch_to_block(ok_bb);
            b.seal_block(ok_bb);
        }

        // Step 7: Register all module ECS systems via `REGISTER_SYSTEM_HANDLE` (`Slot 60`) and mount into
        // schedule sets (`MOUNT_SYSTEM_IN_SCHEDULE`, `Slot 62`).
        let sdesc_slot = alloc_zero_slot(&mut b, structs::SYSTEM_DESC_SIZE, ptr_ty);
        let sdesc_ptr = b.ins().stack_addr(ptr_ty, sdesc_slot, 0);
        let qdescs_slot =
            alloc_zero_slot(&mut b, structs::QUERY_DESC_SIZE * SYSTEM_QUERY_CAP, ptr_ty);
        let qdescs_ptr = b.ins().stack_addr(ptr_ty, qdescs_slot, 0);

        let mut mount_ops: Vec<(usize, usize, u32, Vec<usize>)> = Vec::new();
        for sys in &ctx.systems {
            let sys_slot_idx = cur_sys_slot_idx;
            let sys_out = b.ins().iadd_imm_s(
                state_addr,
                ctx.state_layout.sys_slot_offset(sys_slot_idx) as i64,
            );
            cur_sys_slot_idx += 1;

            zero_slot(&mut b, sdesc_slot, structs::SYSTEM_DESC_SIZE, ptr_ty);
            zero_slot(
                &mut b,
                qdescs_slot,
                structs::QUERY_DESC_SIZE * SYSTEM_QUERY_CAP,
                ptr_ty,
            );

            let ssz = b.ins().iconst(types::I32, structs::SYSTEM_DESC_SIZE as i64);
            let ngv = ctx.obj_mod.declare_data_in_func(sys.name_data_id, b.func);
            let nptr = b.ins().symbol_value(ptr_ty, ngv);
            let fref = ctx.obj_mod.declare_func_in_func(sys.func_id, b.func);
            let fn_addr = b.ins().func_addr(ptr_ty, fref);
            let sched_v = b.ins().iconst(types::I32, i64::from(sys.schedule_id));

            b.ins()
                .stack_store(ptr_ty, ssz, sdesc_slot, structs::SYS_STRUCT_SIZE as i32);
            b.ins()
                .stack_store(ptr_ty, nptr, sdesc_slot, structs::SYS_NAME as i32);
            b.ins()
                .stack_store(ptr_ty, fn_addr, sdesc_slot, structs::SYS_CALLBACK as i32);
            b.ins().stack_store(
                ptr_ty,
                state_addr,
                sdesc_slot,
                structs::SYS_USER_DATA as i32,
            );
            b.ins()
                .stack_store(ptr_ty, sched_v, sdesc_slot, structs::SYS_SCHEDULE as i32);

            // Populate queries dynamically (note: `resource_queries` and `stream_queries` depend on
            // runtime `res_flags` in `StrataJitState`, so pack query slots sequentially in IR!).
            let q_idx_var = b.declare_var(ptr_ty);
            let z_ptr = b.ins().iconst(ptr_ty, 0);
            b.def_var(q_idx_var, z_ptr);

            for (qi, wq) in sys.wire_queries.iter().take(SYSTEM_QUERY_CAP).enumerate() {
                let mut term_items = Vec::new();
                for t in &wq.terms {
                    term_items.push((t.layout_idx, access_mode_u32(t.mode)));
                }
                for &wf in &wq.with_filters {
                    term_items.push((wf, AccessMode::FILTER_ONLY.0));
                }
                for &wof in &wq.without_filters {
                    term_items.push((wof, AccessMode::WITHOUT.0));
                }
                term_items.truncate(QUERY_TERM_CAP);
                if !term_items.is_empty() {
                    emit_fill_query_slot(
                        &mut b,
                        state_addr,
                        &ctx.state_layout,
                        qdescs_ptr,
                        qi,
                        &term_items,
                        ptr_ty,
                    );
                    let nxt = b.ins().iconst(ptr_ty, (qi + 1) as i64);
                    b.def_var(q_idx_var, nxt);
                }
            }

            // Append hidden lookup queries for `extra_obj_queries` (always added in static order).
            for eq in &sys.extra_obj_queries {
                if let Some(obj) = ctx.mir.objects.get(eq.obj_idx)
                    && let Some(cname) = obj.components.first().map(String::as_str).or_else(|| {
                        obj.inits.first().map(|ci| {
                            ci.canonical_component
                                .as_deref()
                                .unwrap_or(ci.component.as_str())
                        })
                    })
                    && let Some(lidx) = lookup_name_in_map(&ctx.layout_map, cname)
                {
                    let cur_q = b.use_var(q_idx_var);
                    let cap_ok =
                        b.ins()
                            .icmp_imm_s(IntCC::UnsignedLessThan, cur_q, SYSTEM_QUERY_CAP as i64);
                    let w_bb = b.create_block();
                    let n_bb = b.create_block();
                    b.ins().brif(cap_ok, w_bb, &[], n_bb, &[]);
                    b.switch_to_block(w_bb);
                    b.seal_block(w_bb);
                    emit_fill_dynamic_query_slot(
                        &mut b,
                        state_addr,
                        &ctx.state_layout,
                        qdescs_ptr,
                        cur_q,
                        lidx,
                        AccessMode::FILTER_ONLY.0,
                        ptr_ty,
                    );
                    let nxt = b.ins().iadd_imm_s(cur_q, 1);
                    b.def_var(q_idx_var, nxt);
                    b.ins().jump(n_bb, &[]);
                    b.switch_to_block(n_bb);
                    b.seal_block(n_bb);
                }
            }

            // Append runtime-verified host `MESSAGE_WRITE` terms.
            for sq in &sys.stream_queries {
                let sflag = b.ins().load(
                    types::I8,
                    MemFlagsData::trusted(),
                    state_addr,
                    ctx.state_layout.res_flag_offset(sq.stream_layout_idx) as i32,
                );
                let is_msg = b.ins().icmp_imm_s(IntCC::Equal, sflag, 2);
                let add_bb = b.create_block();
                let next_bb = b.create_block();
                b.ins().brif(is_msg, add_bb, &[], next_bb, &[]);
                b.switch_to_block(add_bb);
                b.seal_block(add_bb);
                let cur_q = b.use_var(q_idx_var);
                let cap_ok =
                    b.ins()
                        .icmp_imm_s(IntCC::UnsignedLessThan, cur_q, SYSTEM_QUERY_CAP as i64);
                let w_bb = b.create_block();
                b.ins().brif(cap_ok, w_bb, &[], next_bb, &[]);
                b.switch_to_block(w_bb);
                b.seal_block(w_bb);
                emit_fill_dynamic_query_slot(
                    &mut b,
                    state_addr,
                    &ctx.state_layout,
                    qdescs_ptr,
                    cur_q,
                    sq.stream_layout_idx,
                    AccessMode::MESSAGE_WRITE.0,
                    ptr_ty,
                );
                let nxt = b.ins().iadd_imm_s(cur_q, 1);
                b.def_var(q_idx_var, nxt);
                b.ins().jump(next_bb, &[]);
                b.switch_to_block(next_bb);
                b.seal_block(next_bb);
            }

            // Append runtime-verified host `Resource` terms at the tail (`sys_res_ptr` uses component ID).
            for &(lidx, mutable, _) in &sys.resource_queries {
                let rflag = b.ins().load(
                    types::I8,
                    MemFlagsData::trusted(),
                    state_addr,
                    ctx.state_layout.res_flag_offset(lidx) as i32,
                );
                let is_host = b.ins().icmp_imm_s(IntCC::Equal, rflag, 1);
                let add_bb = b.create_block();
                let next_bb = b.create_block();
                b.ins().brif(is_host, add_bb, &[], next_bb, &[]);

                b.switch_to_block(add_bb);
                b.seal_block(add_bb);
                let cur_q = b.use_var(q_idx_var);
                let cap_ok =
                    b.ins()
                        .icmp_imm_s(IntCC::UnsignedLessThan, cur_q, SYSTEM_QUERY_CAP as i64);
                let write_bb = b.create_block();
                b.ins().brif(cap_ok, write_bb, &[], next_bb, &[]);

                b.switch_to_block(write_bb);
                b.seal_block(write_bb);
                let mode_u = if mutable {
                    AccessMode::RESOURCE_WRITE.0
                } else {
                    AccessMode::RESOURCE_READ.0
                };
                emit_fill_dynamic_query_slot(
                    &mut b,
                    state_addr,
                    &ctx.state_layout,
                    qdescs_ptr,
                    cur_q,
                    lidx,
                    mode_u,
                    ptr_ty,
                );
                let nxt = b.ins().iadd_imm_s(cur_q, 1);
                b.def_var(q_idx_var, nxt);
                b.ins().jump(next_bb, &[]);

                b.switch_to_block(next_bb);
                b.seal_block(next_bb);
            }

            let final_qc = b.use_var(q_idx_var);
            let has_q = b.ins().icmp_imm_s(IntCC::SignedGreaterThan, final_qc, 0);
            let set_q_bb = b.create_block();
            let after_q_bb = b.create_block();
            b.ins().brif(has_q, set_q_bb, &[], after_q_bb, &[]);
            b.switch_to_block(set_q_bb);
            b.seal_block(set_q_bb);
            b.ins()
                .stack_store(ptr_ty, qdescs_ptr, sdesc_slot, structs::SYS_QUERIES as i32);
            b.ins().stack_store(
                ptr_ty,
                final_qc,
                sdesc_slot,
                structs::SYS_QUERY_COUNT as i32,
            );
            b.ins().jump(after_q_bb, &[]);
            b.switch_to_block(after_q_bb);
            b.seal_block(after_q_bb);

            // Ordering constraints (`after`, `after_weak`, `before`).
            populate_cstr_ptr_array(
                &ctx.obj_mod,
                &mut b,
                &sys.after_names,
                sdesc_slot,
                structs::SYS_AFTER,
                structs::SYS_AFTER_COUNT,
                ptr_ty,
                ptr_bytes,
            );
            populate_cstr_ptr_array(
                &ctx.obj_mod,
                &mut b,
                &sys.after_weak_names,
                sdesc_slot,
                structs::SYS_AFTER_WEAK,
                structs::SYS_AFTER_WEAK_COUNT,
                ptr_ty,
                ptr_bytes,
            );
            populate_cstr_ptr_array(
                &ctx.obj_mod,
                &mut b,
                &sys.before_names,
                sdesc_slot,
                structs::SYS_BEFORE,
                structs::SYS_BEFORE_COUNT,
                ptr_ty,
                ptr_bytes,
            );
            populate_cstr_ptr_array(
                &ctx.obj_mod,
                &mut b,
                &sys.in_set_names,
                sdesc_slot,
                structs::SYS_IN_SETS,
                structs::SYS_IN_SET_COUNT,
                ptr_ty,
                ptr_bytes,
            );

            let rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::REGISTER_SYSTEM_HANDLE,
                &[ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[load_ctx, sdesc_ptr, sys_out],
            );
            let is_err = b.ins().icmp_imm_s(IntCC::NotEqual, rc, 0);
            let reg_ok_bb = b.create_block();
            b.ins()
                .brif(is_err, err_ret_blk, &[BlockArg::Value(rc)], reg_ok_bb, &[]);

            b.switch_to_block(reg_ok_bb);
            b.seal_block(reg_ok_bb);

            if !sys.mount_set_indices.is_empty() {
                mount_ops.push((
                    sys.sched_order,
                    sys_slot_idx,
                    sys.schedule_id,
                    sys.mount_set_indices.clone(),
                ));
            }
        }

        mount_ops.sort_by_key(|&(ord, slot_idx, _, _)| (ord, slot_idx));
        for (_, sys_slot_idx, schedule_id, set_indices) in mount_ops {
            let sys_handle = b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                state_addr,
                ctx.state_layout.sys_slot_offset(sys_slot_idx) as i32,
            );
            let sched_v = b.ins().iconst(types::I32, i64::from(schedule_id));
            for set_idx in set_indices {
                let set_h = b.ins().load(
                    types::I32,
                    MemFlagsData::trusted(),
                    state_addr,
                    ctx.state_layout.set_slot_offset(set_idx) as i32,
                );
                let set_valid =
                    b.ins()
                        .icmp_imm_s(IntCC::NotEqual, set_h, i64::from(BAM_SYSTEM_SET_INVALID));
                let mount_bb = b.create_block();
                let next_m_bb = b.create_block();
                b.ins().brif(set_valid, mount_bb, &[], next_m_bb, &[]);

                b.switch_to_block(mount_bb);
                b.seal_block(mount_bb);
                let _mrc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::MOUNT_SYSTEM_IN_SCHEDULE,
                    &[ptr_ty, types::I32, types::I32, types::I32],
                    Some(types::I32),
                    ptr_ty,
                    call_conv,
                    &[load_ctx, sys_handle, sched_v, set_h],
                );
                b.ins().jump(next_m_bb, &[]);

                b.switch_to_block(next_m_bb);
                b.seal_block(next_m_bb);
            }
        }

        let ok_res = b.ins().iconst(types::I32, i64::from(FFI_OK));
        b.ins().return_(&[ok_res]);

        b.switch_to_block(err_ret_blk);
        b.seal_block(err_ret_blk);
        let err_code = b.block_params(err_ret_blk)[0];
        b.ins().return_(&[err_code]);

        b.finalize(ctx.fe_cfg);
    }

    define_fn_checked(
        &mut ctx.obj_mod,
        fid,
        &mut fn_ctx,
        "bamabi_init define failed",
    )
}

#[inline]
fn state_ptr_alias(v: Value) -> Value {
    v
}

fn emit_fill_query_slot(
    b: &mut FunctionBuilder<'_>,
    state_addr: Value,
    state_layout: &StateLayout,
    qdescs_ptr: Value,
    q_idx: usize,
    terms: &[(usize, u32)],
    ptr_ty: Type,
) {
    let terms_slot = alloc_zero_slot(b, terms.len() * structs::TERM_DESC_SIZE, ptr_ty);
    let terms_ptr = b.ins().stack_addr(ptr_ty, terms_slot, 0);
    for (ti, &(lidx, mode_u)) in terms.iter().enumerate() {
        let base = (ti * structs::TERM_DESC_SIZE) as i32;
        let comp_h = b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            state_addr,
            state_layout.comp_slot_offset(lidx) as i32,
        );
        let mv = b.ins().iconst(types::I32, i64::from(mode_u));
        b.ins().stack_store(
            ptr_ty,
            comp_h,
            terms_slot,
            base + structs::TERM_COMPONENT as i32,
        );
        b.ins()
            .stack_store(ptr_ty, mv, terms_slot, base + structs::TERM_MODE as i32);
    }
    let q_off = (q_idx * structs::QUERY_DESC_SIZE) as i32;
    let qsz = b.ins().iconst(types::I32, structs::QUERY_DESC_SIZE as i64);
    let tc = b.ins().iconst(ptr_ty, terms.len() as i64);
    b.ins().store(
        MemFlagsData::trusted(),
        qsz,
        qdescs_ptr,
        q_off + structs::QUERY_STRUCT_SIZE as i32,
    );
    b.ins().store(
        MemFlagsData::trusted(),
        terms_ptr,
        qdescs_ptr,
        q_off + structs::QUERY_TERMS as i32,
    );
    b.ins().store(
        MemFlagsData::trusted(),
        tc,
        qdescs_ptr,
        q_off + structs::QUERY_TERM_COUNT as i32,
    );
}

#[allow(clippy::too_many_arguments)]
fn emit_fill_dynamic_query_slot(
    b: &mut FunctionBuilder<'_>,
    state_addr: Value,
    state_layout: &StateLayout,
    qdescs_ptr: Value,
    q_idx_val: Value,
    lidx: usize,
    mode_u: u32,
    ptr_ty: Type,
) {
    let term_slot = alloc_zero_slot(b, structs::TERM_DESC_SIZE, ptr_ty);
    let term_ptr = b.ins().stack_addr(ptr_ty, term_slot, 0);
    let comp_h = b.ins().load(
        types::I32,
        MemFlagsData::trusted(),
        state_addr,
        state_layout.comp_slot_offset(lidx) as i32,
    );
    let mv = b.ins().iconst(types::I32, i64::from(mode_u));
    b.ins()
        .stack_store(ptr_ty, comp_h, term_slot, structs::TERM_COMPONENT as i32);
    b.ins()
        .stack_store(ptr_ty, mv, term_slot, structs::TERM_MODE as i32);

    let q_off = b
        .ins()
        .imul_imm_s(q_idx_val, structs::QUERY_DESC_SIZE as i64);
    let q_addr = b.ins().iadd(qdescs_ptr, q_off);
    let qsz = b.ins().iconst(types::I32, structs::QUERY_DESC_SIZE as i64);
    let one = b.ins().iconst(ptr_ty, 1);
    b.ins().store(
        MemFlagsData::trusted(),
        qsz,
        q_addr,
        structs::QUERY_STRUCT_SIZE as i32,
    );
    b.ins().store(
        MemFlagsData::trusted(),
        term_ptr,
        q_addr,
        structs::QUERY_TERMS as i32,
    );
    b.ins().store(
        MemFlagsData::trusted(),
        one,
        q_addr,
        structs::QUERY_TERM_COUNT as i32,
    );
}

#[allow(clippy::too_many_arguments)]
fn populate_cstr_ptr_array(
    obj_mod: &ObjectModule,
    b: &mut FunctionBuilder<'_>,
    ids: &[DataId],
    sdesc_slot: StackSlot,
    ptr_off: usize,
    cnt_off: usize,
    ptr_ty: Type,
    ptr_bytes: usize,
) {
    if ids.is_empty() {
        return;
    }
    let arr_slot = alloc_zero_slot(b, ids.len() * ptr_bytes, ptr_ty);
    let arr_ptr = b.ins().stack_addr(ptr_ty, arr_slot, 0);
    for (i, &id) in ids.iter().enumerate() {
        let gv = obj_mod.declare_data_in_func(id, b.func);
        let cstr = b.ins().symbol_value(ptr_ty, gv);
        b.ins()
            .stack_store(ptr_ty, cstr, arr_slot, (i * ptr_bytes) as i32);
    }
    let cnt_v = b.ins().iconst(ptr_ty, ids.len() as i64);
    b.ins()
        .stack_store(ptr_ty, arr_ptr, sdesc_slot, ptr_off as i32);
    b.ins()
        .stack_store(ptr_ty, cnt_v, sdesc_slot, cnt_off as i32);
}

fn vec_dims(ty: &MirType) -> Option<u8> {
    match ty {
        MirType::Vec2 => Some(2),
        MirType::Vec3 => Some(3),
        MirType::Vec4 => Some(4),
        _ => None,
    }
}

fn is_signed_int_ty(ty: &MirType) -> bool {
    matches!(
        ty,
        MirType::I8 | MirType::I16 | MirType::I32 | MirType::I64 | MirType::Fix32 | MirType::Fix64
    )
}

fn common_int_ty(a: &MirType, b: &MirType, dst: &MirType, ptr_ty: Type, cc: CallConv) -> Type {
    if matches!(
        a,
        MirType::Ptr
            | MirType::MutPtr
            | MirType::Entity
            | MirType::U64
            | MirType::I64
            | MirType::QueryIter
            | MirType::Checkpoint
    ) || matches!(
        b,
        MirType::Ptr
            | MirType::MutPtr
            | MirType::Entity
            | MirType::U64
            | MirType::I64
            | MirType::QueryIter
            | MirType::Checkpoint
    ) {
        return if ptr_ty == types::I32 {
            types::I64
        } else {
            ptr_ty
        };
    }
    if matches!(a, MirType::U32 | MirType::I32 | MirType::Sym)
        || matches!(b, MirType::U32 | MirType::I32 | MirType::Sym)
    {
        return types::I32;
    }
    if matches!(a, MirType::U16 | MirType::I16) || matches!(b, MirType::U16 | MirType::I16) {
        return types::I16;
    }
    if *dst == MirType::Bool {
        return types::I8;
    }
    scalar_cl_type(a, cc)
}

fn is_cmp_op(op: &str) -> bool {
    matches!(op, "==" | "!=" | "<" | "<=" | ">" | ">=")
}

fn float_binop(b: &mut FunctionBuilder<'_>, fty: Type, op: &str, l: Value, r: Value) -> Value {
    match op {
        "+" => b.ins().fadd(l, r),
        "-" => b.ins().fsub(l, r),
        "*" => b.ins().fmul(l, r),
        "/" => b.ins().fdiv(l, r),
        "%" => {
            let q = b.ins().fdiv(l, r);
            let tq = b.ins().trunc(q);
            let p = b.ins().fmul(tq, r);
            b.ins().fsub(l, p)
        }
        _ => {
            let _ = fty;
            l
        }
    }
}

fn float_cmp(b: &mut FunctionBuilder<'_>, op: &str, l: Value, r: Value) -> Value {
    let cc = match op {
        "!=" => FloatCC::NotEqual,
        "<" => FloatCC::LessThan,
        "<=" => FloatCC::LessThanOrEqual,
        ">" => FloatCC::GreaterThan,
        ">=" => FloatCC::GreaterThanOrEqual,
        _ => FloatCC::Equal,
    };
    b.ins().fcmp(cc, l, r)
}

fn guarded_sdiv(b: &mut FunctionBuilder<'_>, ty: Type, l: Value, r: Value) -> Value {
    let nz = b.ins().icmp_imm_s(IntCC::NotEqual, r, 0);
    let ok_bb = b.create_block();
    let zero_bb = b.create_block();
    let done_bb = b.create_block();
    b.append_block_param(done_bb, ty);
    b.ins().brif(nz, ok_bb, &[], zero_bb, &[]);

    self_block_div(b, ty, true, false, l, r, ok_bb, zero_bb, done_bb)
}

fn self_block_div(
    b: &mut FunctionBuilder<'_>,
    ty: Type,
    signed: bool,
    is_rem: bool,
    l: Value,
    r: Value,
    ok_bb: Block,
    zero_bb: Block,
    done_bb: Block,
) -> Value {
    b.switch_to_block(ok_bb);
    b.seal_block(ok_bb);
    let q = match (signed, is_rem) {
        (true, false) => b.ins().sdiv(l, r),
        (false, false) => b.ins().udiv(l, r),
        (true, true) => b.ins().srem(l, r),
        (false, true) => b.ins().urem(l, r),
    };
    b.ins().jump(done_bb, &[BlockArg::Value(q)]);

    b.switch_to_block(zero_bb);
    b.seal_block(zero_bb);
    let z = b.ins().iconst(ty, 0);
    b.ins().jump(done_bb, &[BlockArg::Value(z)]);

    b.switch_to_block(done_bb);
    b.seal_block(done_bb);
    b.block_params(done_bb)[0]
}

fn int_binop_or_cmp(
    b: &mut FunctionBuilder<'_>,
    ty: Type,
    signed: bool,
    op: &str,
    l: Value,
    r: Value,
) -> Value {
    match op {
        "+" => b.ins().iadd(l, r),
        "-" => b.ins().isub(l, r),
        "*" => b.ins().imul(l, r),
        "/" => {
            let nz = b.ins().icmp_imm_s(IntCC::NotEqual, r, 0);
            let ok_bb = b.create_block();
            let zero_bb = b.create_block();
            let done_bb = b.create_block();
            b.append_block_param(done_bb, ty);
            b.ins().brif(nz, ok_bb, &[], zero_bb, &[]);
            self_block_div(b, ty, signed, false, l, r, ok_bb, zero_bb, done_bb)
        }
        "%" => {
            let nz = b.ins().icmp_imm_s(IntCC::NotEqual, r, 0);
            let ok_bb = b.create_block();
            let zero_bb = b.create_block();
            let done_bb = b.create_block();
            b.append_block_param(done_bb, ty);
            b.ins().brif(nz, ok_bb, &[], zero_bb, &[]);
            self_block_div(b, ty, signed, true, l, r, ok_bb, zero_bb, done_bb)
        }
        "&" | "&&" => b.ins().band(l, r),
        "|" | "||" => b.ins().bor(l, r),
        "^" => b.ins().bxor(l, r),
        "<<" => b.ins().ishl(l, r),
        ">>" => {
            if signed {
                b.ins().sshr(l, r)
            } else {
                b.ins().ushr(l, r)
            }
        }
        "==" => b.ins().icmp(IntCC::Equal, l, r),
        "!=" => b.ins().icmp(IntCC::NotEqual, l, r),
        "<" => b.ins().icmp(
            if signed {
                IntCC::SignedLessThan
            } else {
                IntCC::UnsignedLessThan
            },
            l,
            r,
        ),
        "<=" => b.ins().icmp(
            if signed {
                IntCC::SignedLessThanOrEqual
            } else {
                IntCC::UnsignedLessThanOrEqual
            },
            l,
            r,
        ),
        ">" => b.ins().icmp(
            if signed {
                IntCC::SignedGreaterThan
            } else {
                IntCC::UnsignedGreaterThan
            },
            l,
            r,
        ),
        ">=" => b.ins().icmp(
            if signed {
                IntCC::SignedGreaterThanOrEqual
            } else {
                IntCC::UnsignedGreaterThanOrEqual
            },
            l,
            r,
        ),
        _ => l,
    }
}

fn apply_min_max(b: &mut FunctionBuilder<'_>, ty: Type, is_min: bool, a: Value, v: Value) -> Value {
    if ty == types::F32 || ty == types::F64 {
        if is_min {
            b.ins().fmin(a, v)
        } else {
            b.ins().fmax(a, v)
        }
    } else if is_min {
        b.ins().smin(a, v)
    } else {
        b.ins().smax(a, v)
    }
}

fn coerce_cl_val(b: &mut FunctionBuilder<'_>, val: Value, to: Type, ptr_ty: Type) -> Value {
    let from = b.func.dfg.value_type(val);
    if from == to {
        return val;
    }
    if from == types::F32 && to == types::F64 {
        return b.ins().fpromote(types::F64, val);
    }
    if from == types::F64 && to == types::F32 {
        return b.ins().fdemote(types::F32, val);
    }
    if (from == types::F32 || from == types::F64) && to.is_int() {
        return b.ins().fcvt_to_sint_sat(to, val);
    }
    if from.is_int() && (to == types::F32 || to == types::F64) {
        return b.ins().fcvt_from_sint(to, val);
    }
    if from.is_int() && to.is_int() {
        let fb = from.bits();
        let tb = to.bits();
        if tb > fb {
            return b.ins().uextend(to, val);
        }
        return b.ins().ireduce(to, val);
    }
    let _ = ptr_ty;
    val
}

fn cast_value(
    b: &mut FunctionBuilder<'_>,
    val: Value,
    src_mty: &MirType,
    src_signed: bool,
    dst_ty: Type,
    dst_signed: bool,
    ptr_ty: Type,
) -> Value {
    let from = b.func.dfg.value_type(val);
    if from == dst_ty {
        return val;
    }
    if *src_mty == MirType::Bool && (dst_ty == types::F32 || dst_ty == types::F64) {
        return b.ins().fcvt_from_uint(dst_ty, val);
    }
    if (from == types::F32 || from == types::F64) && dst_ty.is_int() {
        if dst_signed {
            return b.ins().fcvt_to_sint_sat(dst_ty, val);
        }
        return b.ins().fcvt_to_uint_sat(dst_ty, val);
    }
    if from.is_int() && (dst_ty == types::F32 || dst_ty == types::F64) {
        if src_signed {
            return b.ins().fcvt_from_sint(dst_ty, val);
        }
        return b.ins().fcvt_from_uint(dst_ty, val);
    }
    if from == types::F32 && dst_ty == types::F64 {
        return b.ins().fpromote(types::F64, val);
    }
    if from == types::F64 && dst_ty == types::F32 {
        return b.ins().fdemote(types::F32, val);
    }
    if from.is_int() && dst_ty.is_int() {
        let fb = from.bits();
        let tb = dst_ty.bits();
        if tb > fb {
            if src_signed {
                return b.ins().sextend(dst_ty, val);
            }
            return b.ins().uextend(dst_ty, val);
        }
        return b.ins().ireduce(dst_ty, val);
    }
    coerce_cl_val(b, val, dst_ty, ptr_ty)
}

fn zero_for_cl_type(b: &mut FunctionBuilder<'_>, ty: Type) -> Value {
    if ty == types::F32 {
        b.ins().f32const(0.0)
    } else if ty == types::F64 {
        b.ins().f64const(0.0)
    } else {
        b.ins().iconst(ty, 0)
    }
}

fn emit_memcpy(b: &mut FunctionBuilder<'_>, dst: Value, src: Value, size: usize) {
    let mut off = 0usize;
    while off + 8 <= size {
        let v = b
            .ins()
            .load(types::I64, MemFlagsData::new(), src, off as i32);
        b.ins().store(MemFlagsData::new(), v, dst, off as i32);
        off += 8;
    }
    while off + 4 <= size {
        let v = b
            .ins()
            .load(types::I32, MemFlagsData::new(), src, off as i32);
        b.ins().store(MemFlagsData::new(), v, dst, off as i32);
        off += 4;
    }
    while off < size {
        let v = b
            .ins()
            .load(types::I8, MemFlagsData::new(), src, off as i32);
        b.ins().store(MemFlagsData::new(), v, dst, off as i32);
        off += 1;
    }
}

#[allow(clippy::too_many_arguments)]
fn call_vtable(
    module: &ObjectModule,
    b: &mut FunctionBuilder<'_>,
    api_ptr: Value,
    slot_offset: usize,
    params: &[Type],
    ret: Option<Type>,
    ptr_ty: Type,
    call_conv: CallConv,
    args: &[Value],
) -> Value {
    let mut sig = Signature::new(call_conv);
    for &p in params {
        sig.params.push(AbiParam::new(p));
    }
    if let Some(r) = ret {
        sig.returns.push(AbiParam::new(r));
    }
    let sig_ref = b.import_signature(sig);
    let _ = module;
    let fn_ptr = b
        .ins()
        .load(ptr_ty, MemFlagsData::trusted(), api_ptr, slot_offset as i32);
    let coerced_args: Vec<Value> = args
        .iter()
        .zip(params.iter())
        .map(|(&a, &p)| coerce_cl_val(b, a, p, ptr_ty))
        .collect();
    let call = b.ins().call_indirect(sig_ref, fn_ptr, &coerced_args);
    b.inst_results(call)
        .first()
        .copied()
        .unwrap_or_else(|| b.ins().iconst(types::I32, 0))
}

#[allow(clippy::too_many_arguments)]
fn call_vtable_guarded(
    module: &ObjectModule,
    b: &mut FunctionBuilder<'_>,
    api_ptr: Value,
    slot_offset: usize,
    params: &[Type],
    ret: Type,
    ptr_ty: Type,
    call_conv: CallConv,
    guard_ptr: Value,
    args: &[Value],
) -> Value {
    let ok = b.ins().icmp_imm_s(IntCC::NotEqual, guard_ptr, 0);
    let call_bb = b.create_block();
    let skip_bb = b.create_block();
    let merge_bb = b.create_block();
    b.append_block_param(merge_bb, ret);
    b.ins().brif(ok, call_bb, &[], skip_bb, &[]);

    b.switch_to_block(call_bb);
    b.seal_block(call_bb);
    let r = call_vtable(
        module,
        b,
        api_ptr,
        slot_offset,
        params,
        Some(ret),
        ptr_ty,
        call_conv,
        args,
    );
    b.ins().jump(merge_bb, &[BlockArg::Value(r)]);

    b.switch_to_block(skip_bb);
    b.seal_block(skip_bb);
    let z = zero_for_cl_type(b, ret);
    b.ins().jump(merge_bb, &[BlockArg::Value(z)]);

    b.switch_to_block(merge_bb);
    b.seal_block(merge_bb);
    b.block_params(merge_bb)[0]
}

#[allow(clippy::too_many_arguments)]
fn call_vtable_guarded_i8(
    module: &ObjectModule,
    b: &mut FunctionBuilder<'_>,
    api_ptr: Value,
    slot_offset: usize,
    params: &[Type],
    ptr_ty: Type,
    call_conv: CallConv,
    guard_ptr: Value,
    args: &[Value],
) -> Value {
    call_vtable_guarded(
        module,
        b,
        api_ptr,
        slot_offset,
        params,
        types::I8,
        ptr_ty,
        call_conv,
        guard_ptr,
        args,
    )
}

fn alloc_zero_slot(b: &mut FunctionBuilder<'_>, size: usize, ptr_ty: Type) -> StackSlot {
    let aligned_sz = align_up(size.max(8), 8) as u32;
    let slot = b.create_sized_stack_slot(StackSlotData::new(
        StackSlotKind::ExplicitSlot,
        aligned_sz,
        3, // 8-byte alignment
    ));
    zero_slot(b, slot, aligned_sz as usize, ptr_ty);
    slot
}

fn zero_slot(b: &mut FunctionBuilder<'_>, slot: StackSlot, size: usize, ptr_ty: Type) {
    let words = size.div_ceil(8);
    let z64 = b.ins().iconst(types::I64, 0);
    for w in 0..words {
        b.ins().stack_store(ptr_ty, z64, slot, (w * 8) as i32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies wire `AccessMode` mappings match `bamabi_sys` constants.
    #[test]
    fn access_mode_wire_discriminants_match_bamabi_sys() {
        assert_eq!(access_mode_u32(TermAccessMode::Read), AccessMode::READ.0);
        assert_eq!(access_mode_u32(TermAccessMode::Write), AccessMode::WRITE.0);
        assert_eq!(
            access_mode_u32(TermAccessMode::SelectiveWrite),
            AccessMode::WRITE.0
        );
        assert_eq!(
            access_mode_u32(TermAccessMode::OptionalRead),
            AccessMode::OPTIONAL_READ.0
        );
        assert_eq!(
            access_mode_u32(TermAccessMode::OptionalWrite),
            AccessMode::OPTIONAL_WRITE.0
        );
        assert_eq!(
            access_mode_u32(TermAccessMode::With),
            AccessMode::FILTER_ONLY.0
        );
        assert_eq!(
            access_mode_u32(TermAccessMode::Without),
            AccessMode::WITHOUT.0
        );
        assert_eq!(access_mode_u32(TermAccessMode::Allow), AccessMode::ALLOW.0);
        assert_eq!(access_mode_u32(TermAccessMode::Has), AccessMode::HAS.0);
        assert_eq!(
            access_mode_u32(TermAccessMode::RemovedRead),
            AccessMode::REMOVED_READ.0
        );
        assert_eq!(
            access_mode_u32(TermAccessMode::ResRead),
            AccessMode::RESOURCE_READ.0
        );
        assert_eq!(
            access_mode_u32(TermAccessMode::ResWrite),
            AccessMode::RESOURCE_WRITE.0
        );
        assert_eq!(
            access_mode_u32(TermAccessMode::StreamRead),
            AccessMode::MESSAGE_READ.0
        );
        assert_eq!(
            access_mode_u32(TermAccessMode::StreamWrite),
            AccessMode::MESSAGE_WRITE.0
        );
        assert_eq!(
            AccessMode::FILTER_ONLY.0,
            bamabi_sys::AccessMode::FILTER_ONLY.0
        );
    }

    #[test]
    fn bare_schedule_target_strips_multi_module_prefixes_and_preserves_host() {
        assert_eq!(
            bare_schedule_target("genres::metroidvania::MetroidvaniaFrame"),
            "MetroidvaniaFrame"
        );
        assert_eq!(bare_schedule_target("foo::bar"), "bar");
        assert_eq!(bare_schedule_target("host::PreUpdate"), "host::PreUpdate");
        assert_eq!(bare_schedule_target("Movement"), "Movement");
    }

    #[test]
    fn find_res_access_in_hir_matches_generic_res_call_expression() {
        let call_expr = HirExpr::Call(HirCall {
            receiver: None,
            callee: "res".to_string(),
            generic_args: vec!["SimClock".to_string()],
            args: Vec::new(),
            arg_names: Vec::new(),
            ty: Ty::Unknown,
        });
        let field_expr = HirExpr::Field {
            base: Box::new(call_expr),
            field: "hitstop_rem".to_string(),
            ty: Ty::F32,
        };
        assert_eq!(
            find_res_access_in_hir(&field_expr),
            Some(("SimClock".to_string(), "hitstop_rem".to_string()))
        );
    }

    #[test]
    fn metroidvania_obj_query_reuse_and_jit_emit_succeed() {
        let src = include_str!("../../../fixtures/cookbooks/03_metroidvania_core.strata");
        let analyzed = strata_sema::analyze_source("03_metroidvania_core.strata", src);
        assert!(
            analyzed.ok(),
            "03_metroidvania_core diagnostics: {:?}",
            analyzed.diagnostics
        );

        let mir = strata_mir::lower_to_mir(&analyzed);
        assert!(mir.objects.iter().any(|o| o.name == "PlayerHero"));
        assert!(
            mir.functions
                .iter()
                .any(|f| f.name == "sample_platformer_inputs")
        );

        let opts = JitCompileOptions {
            out_dir: std::env::temp_dir(),
            module_stem: "test_03_mv".into(),
            opt_level: JitOptLevel::Speed,
        };
        let artifact = emit_pic_object(&mir, &opts).expect("03_metroidvania_core JIT should emit");
        assert!(!artifact.object_bytes.is_empty());
    }

    #[test]
    fn rain_swarm_indexed_spawn_batch_emits_pic_object() {
        let src = include_str!("../../../fixtures/cookbooks/01_rain_swarm.strata");
        let analyzed = strata_sema::analyze_source("01_rain_swarm.strata", src);
        assert!(
            analyzed.ok(),
            "01_rain_swarm diagnostics: {:?}",
            analyzed.diagnostics
        );
        let mir = strata_mir::lower_to_mir(&analyzed);
        let has_spawn_batch_begin = mir.functions.iter().any(|f| {
            f.blocks.iter().any(|b| {
                b.stmts
                    .iter()
                    .any(|s| matches!(s.inst, Inst::SpawnBatchBegin { .. }))
            })
        });
        assert!(has_spawn_batch_begin);
        let opts = JitCompileOptions {
            out_dir: std::env::temp_dir(),
            module_stem: "test_01_rain".into(),
            opt_level: JitOptLevel::Speed,
        };
        let artifact = emit_pic_object(&mir, &opts).expect("01_rain_swarm JIT should emit");
        assert!(!artifact.object_bytes.is_empty());
    }

    #[test]
    fn subword_field_store_narrowing_emits_cleanly() {
        assert_eq!(mir_type_from_ty(&Ty::GraceWindow), MirType::F32);
        let src = r#"
module test_subword;
component Flags { count: u8 = 0, pad_u8: u8 = 0, armed: bool = true }
sys set_count() {
    for f in query(fl: &mut Flags) {
        f.fl.count = 1;
    }
}
"#;
        let analyzed = strata_sema::analyze_source("test_subword.strata", src);
        assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
        let mir = strata_mir::lower_to_mir(&analyzed);
        let opts = JitCompileOptions {
            out_dir: std::env::temp_dir(),
            module_stem: "test_subword".into(),
            opt_level: JitOptLevel::Speed,
        };
        let artifact = emit_pic_object(&mir, &opts).expect("subword JIT should emit");
        assert!(!artifact.object_bytes.is_empty());
    }
}
