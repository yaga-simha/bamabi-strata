//! Headless `bamabi_host` Bevy `World` simulation runner, canonical archetype column SHA-256 +
//! FNV-1a hasher (`hash_world_pod_state`), and real compiled `sim_test` executor.

use crate::commands::SimTestCaseResult;
use bamabi_host::prelude::*;
use bamabi_host::{
    ExportedFieldRecord, ModBudgetTelemetry, ModRegistry, RegisteredComponent,
    apply_entity_component_fields, apply_resource_fields, export_entity_component_fields,
    export_resource_fields, read_entity_pod_bytes, write_entity_pod_bytes,
};
use bamabi_sys::{
    BAM_STORAGE_FLAG_ENTITY_EVENT, BAM_STORAGE_FLAG_EVENT, BAM_STORAGE_FLAG_MESSAGE,
    BAM_STORAGE_FLAG_RESOURCE, fnv1a_64_init, fnv1a_64_update_bytes, fnv1a_64_update_u64,
};
use bevy_app::{App, FixedUpdate, Last, PostStartup, PostUpdate, PreUpdate, Startup, Update};
use bevy_ecs::entity::Entity;
use bevy_ecs::schedule::SingleThreadedExecutor;
use bevy_ecs::world::World;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use std::alloc::System;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Mutex;
use strata_jit::{JitCompileOptions, JitOptLevel, compile_module_to_dylib};
use strata_mir::{
    BlockId, Inst, LocalId, MirFnKind, MirFunction, MirModule, MirQueryBinding,
    MirQueryTermBinding, MirResourceBinding, MirStmt, MirType, Terminator, verify_mir,
};
use strata_sema::access::{QueryAccessDesc, QueryTerm, TermAccessMode};
use strata_sema::hir::{
    HirAssignOp, HirBinOp, HirCall, HirExpr, HirForIter, HirLValue, HirPattern, HirQuery,
    HirQueryTerm, HirSchedule, HirScheduleGroup, HirSimTest, HirStmt, HirUnOp,
};
use strata_sema::layout::{EnumDef, LayoutEnv, SchemaItemKind, SolvedLayout, solve_pod_layout};
use strata_sema::types::Ty;
use tempfile::TempDir;

#[global_allocator]
static SIM_GLOBAL_ALLOC: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

pub(crate) static SIM_EXEC_MUTEX: Mutex<()> = Mutex::new(());

const SIM_CTRL_SHORT_NAME: &str = "__StrataSimCtrl";
const DISPATCH_RESOURCES_PER_SYS: usize = 8;
const DISPATCH_OBJECTS_PER_SYS: usize = 8;

/// Canonical cryptographic digest of all sorted archetype POD columns in a Bevy `World`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldPodDigest {
    /// SHA-256 digest bytes across canonically sorted archetype column bytes.
    pub sha256: [u8; 32],
    /// 64-bit FNV-1a digest over the identical canonical stream.
    pub fnv1a64: u64,
    /// Number of non-empty archetypes containing registered POD components.
    pub archetype_count: usize,
    /// Total live entities across hashed archetypes.
    pub entity_count: usize,
    /// Total raw POD column bytes hashed.
    pub pod_bytes_hashed: usize,
}

impl WorldPodDigest {
    /// Formats [`Self::sha256`] as lowercase 64-character hexadecimal.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.sha256 {
            use core::fmt::Write as _;
            let _ = write!(&mut s, "{b:02x}");
        }
        s
    }
}

struct DualHasher {
    sha: Sha256,
    fnv: u64,
}

impl DualHasher {
    fn new() -> Self {
        Self {
            sha: Sha256::new(),
            fnv: fnv1a_64_init(),
        }
    }

    fn update_bytes(&mut self, bytes: &[u8]) {
        self.sha.update(bytes);
        self.fnv = fnv1a_64_update_bytes(self.fnv, bytes);
    }

    fn update_u64(&mut self, val: u64) {
        self.sha.update(val.to_le_bytes());
        self.fnv = fnv1a_64_update_u64(self.fnv, val);
    }

    fn update_str(&mut self, s: &str) {
        self.update_u64(s.len() as u64);
        self.update_bytes(s.as_bytes());
    }

    fn finish(self) -> ([u8; 32], u64) {
        let d = self.sha.finalize();
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&d);
        (sha256, self.fnv)
    }
}

fn is_hashable_entity_pod(entry: &RegisteredComponent) -> bool {
    let non_entity_mask = BAM_STORAGE_FLAG_RESOURCE
        | BAM_STORAGE_FLAG_MESSAGE
        | BAM_STORAGE_FLAG_EVENT
        | BAM_STORAGE_FLAG_ENTITY_EVENT;
    entry.is_abi_pod
        && (entry.storage_flags & non_entity_mask) == 0
        && !entry.name.starts_with("bevy_ecs::")
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ComponentSig {
    name: String,
    uuid_bytes: [u8; 16],
    schema_fingerprint: u64,
    size: usize,
    align: usize,
}

/// Computes a deterministic SHA-256 + FNV-1a digest across ALL sorted archetype POD component
/// column bytes in `world`.
#[must_use]
pub fn hash_world_pod_state(world: &World) -> WorldPodDigest {
    let mut hasher = DualHasher::new();
    let Some(registry) = world.get_resource::<ModRegistry>() else {
        let (sha256, fnv1a64) = hasher.finish();
        return WorldPodDigest {
            sha256,
            fnv1a64,
            archetype_count: 0,
            entity_count: 0,
            pod_bytes_hashed: 0,
        };
    };
    let snap = registry.snapshot();

    let mut pod_components: Vec<&RegisteredComponent> = snap
        .entries()
        .iter()
        .filter(|e| is_hashable_entity_pod(e))
        .collect();
    pod_components.sort_by(|a, b| a.name.as_ref().cmp(b.name.as_ref()));

    struct ArchRecord<'a> {
        sig: Vec<ComponentSig>,
        components: Vec<&'a RegisteredComponent>,
        entities: Vec<Entity>,
    }

    let mut arch_records = Vec::new();
    for arch in world.archetypes().iter() {
        if arch.is_empty() {
            continue;
        }
        let mut comps = Vec::new();
        let mut sig = Vec::new();
        for &entry in &pod_components {
            if arch.contains(entry.component_id) {
                comps.push(entry);
                sig.push(ComponentSig {
                    name: entry.name.to_string(),
                    uuid_bytes: entry.uuid.bytes,
                    schema_fingerprint: entry.schema_fingerprint,
                    size: entry.size,
                    align: entry.align,
                });
            }
        }
        if comps.is_empty() {
            continue;
        }
        let mut entities: Vec<Entity> = arch.entities().iter().map(|ae| ae.id()).collect();
        entities.sort_unstable_by_key(|e| e.to_bits());
        arch_records.push(ArchRecord {
            sig,
            components: comps,
            entities,
        });
    }

    arch_records.sort_by(|a, b| {
        a.sig
            .cmp(&b.sig)
            .then_with(|| a.entities.len().cmp(&b.entities.len()))
            .then_with(|| {
                a.entities
                    .first()
                    .map(|e| e.to_bits())
                    .cmp(&b.entities.first().map(|e| e.to_bits()))
            })
    });

    hasher.update_str("ARCHETYPES");
    hasher.update_u64(arch_records.len() as u64);

    let mut total_entities = 0usize;
    let mut total_bytes = 0usize;

    for rec in &arch_records {
        total_entities += rec.entities.len();
        hasher.update_u64(rec.sig.len() as u64);
        for s in &rec.sig {
            hasher.update_str(&s.name);
            hasher.update_bytes(&s.uuid_bytes);
            hasher.update_u64(s.schema_fingerprint);
            hasher.update_u64(s.size as u64);
            hasher.update_u64(s.align as u64);
        }
        hasher.update_u64(rec.entities.len() as u64);

        for &entry in &rec.components {
            hasher.update_str(&entry.name);
            for &entity in &rec.entities {
                let bytes = read_entity_pod_bytes(world, entity, entry.handle).unwrap_or_default();
                total_bytes += bytes.len();
                hasher.update_bytes(&bytes);
            }
        }
    }

    let (sha256, fnv1a64) = hasher.finish();
    WorldPodDigest {
        sha256,
        fnv1a64,
        archetype_count: arch_records.len(),
        entity_count: total_entities,
        pod_bytes_hashed: total_bytes,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DispatchSchedule {
    PostUpdate,
    PreUpdate,
    Last,
    Update,
}

impl DispatchSchedule {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PostUpdate => "PostUpdate",
            Self::PreUpdate => "PreUpdate",
            Self::Last => "Last",
            Self::Update => "Update",
        }
    }

    pub(crate) fn init_on_app(self, app: &mut App) {
        match self {
            Self::PostUpdate => {
                app.init_schedule(PostUpdate);
            }
            Self::PreUpdate => {
                app.init_schedule(PreUpdate);
            }
            Self::Last => {
                app.init_schedule(Last);
            }
            Self::Update => {
                app.init_schedule(Update);
            }
        }
    }

    pub(crate) fn run_on_world(self, world: &mut World) {
        match self {
            Self::PostUpdate => world.run_schedule(PostUpdate),
            Self::PreUpdate => world.run_schedule(PreUpdate),
            Self::Last => world.run_schedule(Last),
            Self::Update => world.run_schedule(Update),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ResFieldDispatch {
    pub(crate) read_op: u32,
    pub(crate) write_op: u32,
    pub(crate) mir_ty: MirType,
    pub(crate) ty: Ty,
}

#[derive(Debug, Clone)]
pub(crate) struct DispatchMetadata {
    pub(crate) schedule: DispatchSchedule,
    pub(crate) ctrl_layout: Option<SolvedLayout>,
    pub(crate) res_ops: HashMap<(String, String), ResFieldDispatch>,
    pub(crate) obj_ops: HashMap<String, u32>,
}

impl DispatchMetadata {
    pub(crate) fn ctrl_offsets(&self) -> Option<(usize, usize, usize, usize)> {
        let l = self.ctrl_layout.as_ref()?;
        let op_off = l.fields.iter().find(|f| f.name == "op")?.offset;
        let i64_off = l.fields.iter().find(|f| f.name == "val_i64")?.offset;
        let f64_off = l.fields.iter().find(|f| f.name == "val_f64")?.offset;
        let vec_off = l.fields.iter().find(|f| f.name == "val_vec")?.offset;
        Some((op_off, i64_off, f64_off, vec_off))
    }

    pub(crate) fn ctrl_int_vec_offsets(&self) -> Option<(usize, usize)> {
        let l = self.ctrl_layout.as_ref()?;
        let ivec_off = l.fields.iter().find(|f| f.name == "val_ivec")?.offset;
        let uvec_off = l.fields.iter().find(|f| f.name == "val_uvec")?.offset;
        Some((ivec_off, uvec_off))
    }
}

fn mir_type_for_ty(ty: &Ty, enums: &[EnumDef], module_path: &str) -> Option<MirType> {
    match ty {
        Ty::Bool => Some(MirType::Bool),
        Ty::U8 => Some(MirType::U8),
        Ty::I8 => Some(MirType::I8),
        Ty::U16 => Some(MirType::U16),
        Ty::I16 => Some(MirType::I16),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => Some(MirType::U32),
        Ty::I32 => Some(MirType::I32),
        Ty::U64 => Some(MirType::U64),
        Ty::I64 => Some(MirType::I64),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => Some(MirType::F32),
        Ty::F64 => Some(MirType::F64),
        Ty::Fix32 => Some(MirType::Fix32),
        Ty::Fix64 => Some(MirType::Fix64),
        Ty::Vec2 => Some(MirType::Vec2),
        Ty::UVec2 => Some(MirType::UVec2),
        Ty::IVec2 => Some(MirType::IVec2),
        Ty::Vec3 => Some(MirType::Vec3),
        Ty::IVec3 => Some(MirType::IVec3),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => Some(MirType::Vec4),
        Ty::Ref(n) if n == "Entity" => Some(MirType::Entity),
        Ty::Named(name) => {
            let qualified = format!("{module_path}::{name}");
            let ed = enums
                .iter()
                .find(|e| e.canonical_name == *name || e.canonical_name == qualified)?;
            match (ed.repr_bytes, ed.is_signed) {
                (1, _) => Some(MirType::U8),
                (2, _) => Some(MirType::U16),
                (_, true) => Some(MirType::I32),
                _ => Some(MirType::U32),
            }
        }
        _ => None,
    }
}

pub(crate) fn find_layout_in_slice<'a>(
    layouts: &'a [SolvedLayout],
    module_path: &str,
    key: &str,
) -> Option<&'a SolvedLayout> {
    let qualified = format!("{module_path}::{key}");
    let normalized = if let Some((comp, strat)) = key.split_once("::") {
        if strat == "hot" {
            comp.to_owned()
        } else {
            format!("{comp}__{strat}")
        }
    } else {
        key.to_owned()
    };
    let qual_norm = format!("{module_path}::{normalized}");
    layouts
        .iter()
        .find(|l| l.canonical_name == key || l.canonical_name == qualified)
        .or_else(|| {
            layouts.iter().find(|l| {
                l.canonical_name == normalized
                    || l.canonical_name == qual_norm
                    || l.canonical_name.rsplit("::").next() == Some(key)
                    || l.canonical_name.rsplit("::").next() == Some(normalized.as_str())
            })
        })
}

fn collect_resource_leaf_fields(
    mir: &MirModule,
    layout: &SolvedLayout,
    prefix: &str,
    base_off: u32,
    out: &mut Vec<(String, u32, MirType, Ty)>,
) {
    for sf in &layout.fields {
        if sf.is_padding {
            continue;
        }
        let path = if prefix.is_empty() {
            sf.name.clone()
        } else {
            format!("{prefix}.{}", sf.name)
        };
        let off = base_off + sf.offset as u32;
        if let Some(mty) = mir_type_for_ty(&sf.ty, &mir.enums, &mir.module_path) {
            out.push((path, off, mty, sf.ty.clone()));
        } else if let Ty::Named(ref inner) = sf.ty
            && let Some(inner_layout) = find_layout_in_slice(&mir.layouts, &mir.module_path, inner)
        {
            collect_resource_leaf_fields(mir, inner_layout, &path, off, out);
        }
    }
}

fn pick_dispatch_schedule(mir: &MirModule) -> DispatchSchedule {
    let used = |label: &str| mir.schedules.iter().any(|s| s.label == label);
    if !used("PostUpdate") {
        DispatchSchedule::PostUpdate
    } else if !used("PreUpdate") {
        DispatchSchedule::PreUpdate
    } else if !used("Last") {
        DispatchSchedule::Last
    } else {
        DispatchSchedule::Update
    }
}

#[derive(Clone)]
struct ResOpPlan {
    res_canonical: String,
    res_short: String,
    field_path: String,
    byte_offset: u32,
    mir_ty: MirType,
    ty: Ty,
    read_op: u32,
    write_op: u32,
}

fn is_int_like_mir_ty(ty: &MirType) -> bool {
    matches!(
        ty,
        MirType::Bool
            | MirType::U8
            | MirType::I8
            | MirType::U16
            | MirType::I16
            | MirType::U32
            | MirType::I32
            | MirType::U64
            | MirType::I64
            | MirType::Sym
            | MirType::Entity
    )
}

fn is_float_like_mir_ty(ty: &MirType) -> bool {
    matches!(
        ty,
        MirType::F32 | MirType::F64 | MirType::Fix32 | MirType::Fix64
    )
}

fn vec_dims_for_mir_ty(ty: &MirType) -> Option<u8> {
    match ty {
        MirType::Vec2 | MirType::IVec2 | MirType::UVec2 => Some(2),
        MirType::Vec3 | MirType::IVec3 => Some(3),
        MirType::Vec4 => Some(4),
        _ => None,
    }
}

fn append_ctrl_query_binding(func: &mut MirFunction, ctrl_layout: &SolvedLayout) {
    func.queries.push(QueryAccessDesc {
        terms: vec![QueryTerm {
            storage_key: SIM_CTRL_SHORT_NAME.to_owned(),
            field_name: None,
            mode: TermAccessMode::Write,
            byte_start: 0,
            byte_end: 0,
        }],
        ..Default::default()
    });
    func.query_bindings.push(MirQueryBinding {
        query_idx: 0,
        terms: vec![MirQueryTermBinding {
            term_idx: 0,
            alias: "ctrl".to_owned(),
            storage_key: SIM_CTRL_SHORT_NAME.to_owned(),
            canonical_component: ctrl_layout.canonical_name.clone(),
            field_name: None,
            mode: TermAccessMode::Write,
            is_sparse: false,
        }],
        with_filters: Vec::new(),
        without_filters: Vec::new(),
        is_point_lookup: false,
    });
}

fn build_ctrl_loop_skeleton(
    func: &mut MirFunction,
    ctrl_layout: &SolvedLayout,
    op_off: u32,
    entry_stmts: Vec<MirStmt>,
) -> (BlockId, BlockId, LocalId, LocalId, LocalId, BlockId) {
    let entry_bb = func.alloc_block("entry", Terminator::Return(None));
    let chunk_hdr = func.alloc_block("chunk_hdr", Terminator::Return(None));
    let chunk_body = func.alloc_block("chunk_body", Terminator::Return(None));
    let row_hdr = func.alloc_block("row_hdr", Terminator::Return(None));
    let row_body = func.alloc_block("row_body", Terminator::Return(None));
    let row_next = func.alloc_block("row_next", Terminator::Return(None));
    let exit_bb = func.alloc_block("exit", Terminator::Return(None));

    func.blocks[entry_bb.0 as usize].stmts.extend(entry_stmts);
    let ridx_slot = func.alloc_local("ridx_slot", MirType::MutPtr);
    func.blocks[entry_bb.0 as usize].stmts.push(MirStmt {
        dst: Some(ridx_slot),
        inst: Inst::SlotAlloc { ty: MirType::U32 },
    });
    func.blocks[entry_bb.0 as usize].terminator = Terminator::Goto(chunk_hdr);

    // chunk_hdr
    let has_chunk = func.alloc_local("has_chunk", MirType::Bool);
    func.blocks[chunk_hdr.0 as usize].stmts.push(MirStmt {
        dst: Some(has_chunk),
        inst: Inst::IterNextChunk { query_idx: 0 },
    });
    func.blocks[chunk_hdr.0 as usize].terminator = Terminator::Branch {
        cond: has_chunk,
        then_bb: chunk_body,
        else_bb: exit_bb,
    };

    // chunk_body
    let chunk_len = func.alloc_local("chunk_len", MirType::U32);
    let col_ptr = func.alloc_local("ctrl_col", MirType::MutPtr);
    let zero = func.alloc_local("zero_idx", MirType::U32);
    func.blocks[chunk_body.0 as usize].stmts.extend([
        MirStmt {
            dst: Some(chunk_len),
            inst: Inst::IterChunkLen { query_idx: 0 },
        },
        MirStmt {
            dst: Some(col_ptr),
            inst: Inst::IterColWrite {
                query_idx: 0,
                term_idx: 0,
                storage_key: ctrl_layout.canonical_name.clone(),
            },
        },
        MirStmt {
            dst: Some(zero),
            inst: Inst::ConstInt { value: 0 },
        },
        MirStmt {
            dst: None,
            inst: Inst::SlotStore {
                slot: ridx_slot,
                val: zero,
            },
        },
    ]);
    func.blocks[chunk_body.0 as usize].terminator = Terminator::Goto(row_hdr);

    // row_hdr
    let ridx = func.alloc_local("ridx", MirType::U32);
    let cond = func.alloc_local("row_cond", MirType::Bool);
    func.blocks[row_hdr.0 as usize].stmts.extend([
        MirStmt {
            dst: Some(ridx),
            inst: Inst::SlotLoad { slot: ridx_slot },
        },
        MirStmt {
            dst: Some(cond),
            inst: Inst::BinOp {
                op: "<".to_owned(),
                lhs: ridx,
                rhs: chunk_len,
                allow_fma: false,
            },
        },
    ]);
    func.blocks[row_hdr.0 as usize].terminator = Terminator::Branch {
        cond,
        then_bb: row_body,
        else_bb: chunk_hdr,
    };

    // row_body
    let ctrl_ptr = func.alloc_local("ctrl_ptr", MirType::MutPtr);
    let op_val = func.alloc_local("op", MirType::U32);
    func.blocks[row_body.0 as usize].stmts.extend([
        MirStmt {
            dst: Some(ctrl_ptr),
            inst: Inst::RowPtr {
                col_ptr,
                row_idx: ridx,
                stride_bytes: ctrl_layout.size as u32,
                is_sparse: false,
            },
        },
        MirStmt {
            dst: Some(op_val),
            inst: Inst::FieldLoad {
                base_ptr: ctrl_ptr,
                layout_key: ctrl_layout.canonical_name.clone(),
                field: "op".to_owned(),
                offset_bytes: op_off,
                field_ty: MirType::U32,
            },
        },
    ]);

    // row_next
    let one = func.alloc_local("one", MirType::U32);
    let nxt = func.alloc_local("r_nxt", MirType::U32);
    func.blocks[row_next.0 as usize].stmts.extend([
        MirStmt {
            dst: Some(one),
            inst: Inst::ConstInt { value: 1 },
        },
        MirStmt {
            dst: Some(nxt),
            inst: Inst::BinOp {
                op: "+".to_owned(),
                lhs: ridx,
                rhs: one,
                allow_fma: false,
            },
        },
        MirStmt {
            dst: None,
            inst: Inst::SlotStore {
                slot: ridx_slot,
                val: nxt,
            },
        },
    ]);
    func.blocks[row_next.0 as usize].terminator = Terminator::Goto(row_hdr);

    (row_body, row_next, ctrl_ptr, op_val, ridx, exit_bb)
}

fn emit_clear_ctrl_op(
    func: &mut MirFunction,
    bb: BlockId,
    ctrl_ptr: LocalId,
    ctrl_canon: &str,
    op_off: u32,
) {
    let zero_op = func.alloc_local("zero_op", MirType::U32);
    func.blocks[bb.0 as usize].stmts.extend([
        MirStmt {
            dst: Some(zero_op),
            inst: Inst::ConstInt { value: 0 },
        },
        MirStmt {
            dst: None,
            inst: Inst::FieldStore {
                base_ptr: ctrl_ptr,
                layout_key: ctrl_canon.to_owned(),
                field: "op".to_owned(),
                offset_bytes: op_off,
                val: zero_op,
            },
        },
    ]);
}

fn build_res_dispatch_function(
    name: String,
    is_deterministic: bool,
    ctrl_layout: &SolvedLayout,
    offsets: (u32, u32, u32, u32, u32, u32),
    res_ops: &[ResOpPlan],
) -> MirFunction {
    let (op_off, i64_off, f64_off, vec_off, ivec_off, uvec_off) = offsets;
    let mut func = MirFunction::new(name, MirFnKind::System);
    func.is_deterministic = is_deterministic;
    append_ctrl_query_binding(&mut func, ctrl_layout);

    // Emit one `ResWrite` per distinct resource in entry block.
    let mut res_ptrs: HashMap<String, LocalId> = HashMap::new();
    let mut entry_stmts = Vec::new();
    for plan in res_ops {
        if !res_ptrs.contains_key(&plan.res_canonical) {
            let ptr_local = func.alloc_local(format!("res_{}", plan.res_short), MirType::MutPtr);
            entry_stmts.push(MirStmt {
                dst: Some(ptr_local),
                inst: Inst::ResWrite {
                    resource: plan.res_canonical.clone(),
                },
            });
            func.resources.push(MirResourceBinding {
                param_name: plan.res_short.clone(),
                resource_name: plan.res_short.clone(),
                canonical_name: plan.res_canonical.clone(),
                mutable: true,
                ptr_local,
            });
            res_ptrs.insert(plan.res_canonical.clone(), ptr_local);
        }
    }

    let (row_body, row_next, ctrl_ptr, op_val, _ridx, _exit_bb) =
        build_ctrl_loop_skeleton(&mut func, ctrl_layout, op_off, entry_stmts);

    let mut switch_cases = Vec::new();
    let ctrl_canon = &ctrl_layout.canonical_name;

    for plan in res_ops {
        let res_ptr = res_ptrs[&plan.res_canonical];

        // Read op
        let read_bb = func.alloc_block(
            format!("read_{}_{}", plan.res_short, plan.field_path),
            Terminator::Goto(row_next),
        );
        switch_cases.push((plan.read_op, read_bb));
        if is_int_like_mir_ty(&plan.mir_ty) {
            let raw = func.alloc_local("r_raw", plan.mir_ty.clone());
            let ext = func.alloc_local("r_i64", MirType::I64);
            func.blocks[read_bb.0 as usize].stmts.extend([
                MirStmt {
                    dst: Some(raw),
                    inst: Inst::FieldLoad {
                        base_ptr: res_ptr,
                        layout_key: plan.res_canonical.clone(),
                        field: plan.field_path.clone(),
                        offset_bytes: plan.byte_offset,
                        field_ty: plan.mir_ty.clone(),
                    },
                },
                MirStmt {
                    dst: Some(ext),
                    inst: Inst::Cast {
                        val: raw,
                        target_ty: MirType::I64,
                    },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::FieldStore {
                        base_ptr: ctrl_ptr,
                        layout_key: ctrl_canon.clone(),
                        field: "val_i64".to_owned(),
                        offset_bytes: i64_off,
                        val: ext,
                    },
                },
            ]);
        } else if is_float_like_mir_ty(&plan.mir_ty) {
            let raw = func.alloc_local("r_raw", plan.mir_ty.clone());
            let ext = func.alloc_local("r_f64", MirType::F64);
            func.blocks[read_bb.0 as usize].stmts.extend([
                MirStmt {
                    dst: Some(raw),
                    inst: Inst::FieldLoad {
                        base_ptr: res_ptr,
                        layout_key: plan.res_canonical.clone(),
                        field: plan.field_path.clone(),
                        offset_bytes: plan.byte_offset,
                        field_ty: plan.mir_ty.clone(),
                    },
                },
                MirStmt {
                    dst: Some(ext),
                    inst: Inst::Cast {
                        val: raw,
                        target_ty: MirType::F64,
                    },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::FieldStore {
                        base_ptr: ctrl_ptr,
                        layout_key: ctrl_canon.clone(),
                        field: "val_f64".to_owned(),
                        offset_bytes: f64_off,
                        val: ext,
                    },
                },
            ]);
        } else if let Some(dims) = vec_dims_for_mir_ty(&plan.mir_ty) {
            let (ctrl_prefix, ctrl_base_off, lane_ty) = match plan.ty {
                Ty::IVec2 | Ty::IVec3 => ("val_ivec", ivec_off, MirType::I32),
                Ty::UVec2 => ("val_uvec", uvec_off, MirType::U32),
                _ => ("val_vec", vec_off, MirType::F32),
            };
            for lane in 0..u32::from(dims) {
                let lv = func.alloc_local(format!("r_lane_{lane}"), lane_ty.clone());
                func.blocks[read_bb.0 as usize].stmts.extend([
                    MirStmt {
                        dst: Some(lv),
                        inst: Inst::FieldLoad {
                            base_ptr: res_ptr,
                            layout_key: plan.res_canonical.clone(),
                            field: format!("{}.{lane}", plan.field_path),
                            offset_bytes: plan.byte_offset + lane * 4,
                            field_ty: lane_ty.clone(),
                        },
                    },
                    MirStmt {
                        dst: None,
                        inst: Inst::FieldStore {
                            base_ptr: ctrl_ptr,
                            layout_key: ctrl_canon.clone(),
                            field: format!("{ctrl_prefix}.{lane}"),
                            offset_bytes: ctrl_base_off + lane * 4,
                            val: lv,
                        },
                    },
                ]);
            }
        }
        emit_clear_ctrl_op(&mut func, read_bb, ctrl_ptr, ctrl_canon, op_off);

        // Write op
        let write_bb = func.alloc_block(
            format!("write_{}_{}", plan.res_short, plan.field_path),
            Terminator::Goto(row_next),
        );
        switch_cases.push((plan.write_op, write_bb));
        if plan.mir_ty == MirType::Bool {
            let v64 = func.alloc_local("w_i64", MirType::I64);
            let z64 = func.alloc_local("w_z64", MirType::I64);
            let bval = func.alloc_local("w_bool", MirType::Bool);
            func.blocks[write_bb.0 as usize].stmts.extend([
                MirStmt {
                    dst: Some(v64),
                    inst: Inst::FieldLoad {
                        base_ptr: ctrl_ptr,
                        layout_key: ctrl_canon.clone(),
                        field: "val_i64".to_owned(),
                        offset_bytes: i64_off,
                        field_ty: MirType::I64,
                    },
                },
                MirStmt {
                    dst: Some(z64),
                    inst: Inst::ConstInt { value: 0 },
                },
                MirStmt {
                    dst: Some(bval),
                    inst: Inst::BinOp {
                        op: "!=".to_owned(),
                        lhs: v64,
                        rhs: z64,
                        allow_fma: false,
                    },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::FieldStore {
                        base_ptr: res_ptr,
                        layout_key: plan.res_canonical.clone(),
                        field: plan.field_path.clone(),
                        offset_bytes: plan.byte_offset,
                        val: bval,
                    },
                },
            ]);
        } else if is_int_like_mir_ty(&plan.mir_ty) {
            let v64 = func.alloc_local("w_i64", MirType::I64);
            let cast_v = func.alloc_local("w_cast", plan.mir_ty.clone());
            func.blocks[write_bb.0 as usize].stmts.extend([
                MirStmt {
                    dst: Some(v64),
                    inst: Inst::FieldLoad {
                        base_ptr: ctrl_ptr,
                        layout_key: ctrl_canon.clone(),
                        field: "val_i64".to_owned(),
                        offset_bytes: i64_off,
                        field_ty: MirType::I64,
                    },
                },
                MirStmt {
                    dst: Some(cast_v),
                    inst: Inst::Cast {
                        val: v64,
                        target_ty: plan.mir_ty.clone(),
                    },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::FieldStore {
                        base_ptr: res_ptr,
                        layout_key: plan.res_canonical.clone(),
                        field: plan.field_path.clone(),
                        offset_bytes: plan.byte_offset,
                        val: cast_v,
                    },
                },
            ]);
        } else if is_float_like_mir_ty(&plan.mir_ty) {
            let v64 = func.alloc_local("w_f64", MirType::F64);
            let cast_v = func.alloc_local("w_cast", plan.mir_ty.clone());
            func.blocks[write_bb.0 as usize].stmts.extend([
                MirStmt {
                    dst: Some(v64),
                    inst: Inst::FieldLoad {
                        base_ptr: ctrl_ptr,
                        layout_key: ctrl_canon.clone(),
                        field: "val_f64".to_owned(),
                        offset_bytes: f64_off,
                        field_ty: MirType::F64,
                    },
                },
                MirStmt {
                    dst: Some(cast_v),
                    inst: Inst::Cast {
                        val: v64,
                        target_ty: plan.mir_ty.clone(),
                    },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::FieldStore {
                        base_ptr: res_ptr,
                        layout_key: plan.res_canonical.clone(),
                        field: plan.field_path.clone(),
                        offset_bytes: plan.byte_offset,
                        val: cast_v,
                    },
                },
            ]);
        } else if let Some(dims) = vec_dims_for_mir_ty(&plan.mir_ty) {
            let (ctrl_prefix, ctrl_base_off, lane_ty) = match plan.ty {
                Ty::IVec2 | Ty::IVec3 => ("val_ivec", ivec_off, MirType::I32),
                Ty::UVec2 => ("val_uvec", uvec_off, MirType::U32),
                _ => ("val_vec", vec_off, MirType::F32),
            };
            for lane in 0..u32::from(dims) {
                let lv = func.alloc_local(format!("w_lane_{lane}"), lane_ty.clone());
                func.blocks[write_bb.0 as usize].stmts.extend([
                    MirStmt {
                        dst: Some(lv),
                        inst: Inst::FieldLoad {
                            base_ptr: ctrl_ptr,
                            layout_key: ctrl_canon.clone(),
                            field: format!("{ctrl_prefix}.{lane}"),
                            offset_bytes: ctrl_base_off + lane * 4,
                            field_ty: lane_ty.clone(),
                        },
                    },
                    MirStmt {
                        dst: None,
                        inst: Inst::FieldStore {
                            base_ptr: res_ptr,
                            layout_key: plan.res_canonical.clone(),
                            field: format!("{}.{lane}", plan.field_path),
                            offset_bytes: plan.byte_offset + lane * 4,
                            val: lv,
                        },
                    },
                ]);
            }
        }
        emit_clear_ctrl_op(&mut func, write_bb, ctrl_ptr, ctrl_canon, op_off);
    }

    func.blocks[row_body.0 as usize].terminator = Terminator::Switch {
        scrutinee: op_val,
        cases: switch_cases,
        default_bb: row_next,
    };

    func
}

fn build_obj_dispatch_function(
    name: String,
    is_deterministic: bool,
    ctrl_layout: &SolvedLayout,
    offsets: (u32, u32, u32, u32),
    obj_ops: &[(String, u32)],
) -> MirFunction {
    let (op_off, i64_off, _f64_off, _vec_off) = offsets;
    let mut func = MirFunction::new(name, MirFnKind::System);
    func.is_deterministic = is_deterministic;
    append_ctrl_query_binding(&mut func, ctrl_layout);

    let (row_body, row_next, ctrl_ptr, op_val, _ridx, _exit_bb) =
        build_ctrl_loop_skeleton(&mut func, ctrl_layout, op_off, Vec::new());

    let mut switch_cases = Vec::new();
    let ctrl_canon = &ctrl_layout.canonical_name;
    for (obj_name, op_id) in obj_ops {
        let bb = func.alloc_block(format!("resolve_{obj_name}"), Terminator::Goto(row_next));
        switch_cases.push((*op_id, bb));
        let ent = func.alloc_local("ent", MirType::Entity);
        let bits = func.alloc_local("ent_bits", MirType::I64);
        func.blocks[bb.0 as usize].stmts.extend([
            MirStmt {
                dst: Some(ent),
                inst: Inst::ResolveNamedObject {
                    name: obj_name.clone(),
                },
            },
            MirStmt {
                dst: Some(bits),
                inst: Inst::Cast {
                    val: ent,
                    target_ty: MirType::I64,
                },
            },
            MirStmt {
                dst: None,
                inst: Inst::FieldStore {
                    base_ptr: ctrl_ptr,
                    layout_key: ctrl_canon.clone(),
                    field: "val_i64".to_owned(),
                    offset_bytes: i64_off,
                    val: bits,
                },
            },
        ]);
        emit_clear_ctrl_op(&mut func, bb, ctrl_ptr, ctrl_canon, op_off);
    }

    func.blocks[row_body.0 as usize].terminator = Terminator::Switch {
        scrutinee: op_val,
        cases: switch_cases,
        default_bb: row_next,
    };

    func
}

pub(crate) fn augment_mir_for_sim_tests(
    mir: &MirModule,
) -> Result<(MirModule, DispatchMetadata), String> {
    let schedule = pick_dispatch_schedule(mir);

    let mut by_resource: BTreeMap<String, Vec<ResOpPlan>> = BTreeMap::new();
    let mut res_ops_map: HashMap<(String, String), ResFieldDispatch> = HashMap::new();
    let mut next_op = 1u32;

    for rl in &mir.layouts {
        if rl.item_kind != SchemaItemKind::Resource {
            continue;
        }
        let res_short = rl
            .canonical_name
            .rsplit("::")
            .next()
            .unwrap_or(&rl.canonical_name)
            .to_owned();
        let mut leaf_fields = Vec::new();
        collect_resource_leaf_fields(mir, rl, "", 0, &mut leaf_fields);
        for (field_path, byte_offset, mir_ty, ty) in leaf_fields {
            let read_op = next_op;
            let write_op = next_op + 1;
            next_op += 2;

            let dispatch = ResFieldDispatch {
                read_op,
                write_op,
                mir_ty: mir_ty.clone(),
                ty: ty.clone(),
            };
            res_ops_map.insert(
                (rl.canonical_name.clone(), field_path.clone()),
                dispatch.clone(),
            );
            res_ops_map.insert((res_short.clone(), field_path.clone()), dispatch);
            by_resource
                .entry(rl.canonical_name.clone())
                .or_default()
                .push(ResOpPlan {
                    res_canonical: rl.canonical_name.clone(),
                    res_short: res_short.clone(),
                    field_path,
                    byte_offset,
                    mir_ty,
                    ty,
                    read_op,
                    write_op,
                });
        }
    }

    let mut obj_ops_list: Vec<(String, u32)> = Vec::with_capacity(mir.objects.len());
    let mut obj_ops_map: HashMap<String, u32> = HashMap::new();
    for obj in &mir.objects {
        let op_id = next_op;
        next_op += 1;
        obj_ops_list.push((obj.name.clone(), op_id));
        obj_ops_map.insert(obj.name.clone(), op_id);
    }

    if by_resource.is_empty() && obj_ops_list.is_empty() {
        return Ok((
            mir.clone(),
            DispatchMetadata {
                schedule,
                ctrl_layout: None,
                res_ops: res_ops_map,
                obj_ops: obj_ops_map,
            },
        ));
    }

    let ctrl_canon = if mir.module_path.is_empty() {
        SIM_CTRL_SHORT_NAME.to_owned()
    } else {
        format!("{}::{SIM_CTRL_SHORT_NAME}", mir.module_path)
    };
    let ctrl_layout = solve_pod_layout(
        &ctrl_canon,
        SchemaItemKind::Component,
        &[
            ("op".to_owned(), Ty::U32),
            ("val_i64".to_owned(), Ty::I64),
            ("val_f64".to_owned(), Ty::F64),
            ("val_vec".to_owned(), Ty::Vec4),
            ("val_ivec".to_owned(), Ty::IVec3),
            ("val_uvec".to_owned(), Ty::UVec2),
        ],
        0,
        Vec::new(),
        &LayoutEnv::default(),
    )?;

    let op_off = ctrl_layout
        .fields
        .iter()
        .find(|f| f.name == "op")
        .map(|f| f.offset as u32)
        .unwrap_or(0);
    let i64_off = ctrl_layout
        .fields
        .iter()
        .find(|f| f.name == "val_i64")
        .map(|f| f.offset as u32)
        .unwrap_or(8);
    let f64_off = ctrl_layout
        .fields
        .iter()
        .find(|f| f.name == "val_f64")
        .map(|f| f.offset as u32)
        .unwrap_or(16);
    let vec_off = ctrl_layout
        .fields
        .iter()
        .find(|f| f.name == "val_vec")
        .map(|f| f.offset as u32)
        .unwrap_or(24);
    let ivec_off = ctrl_layout
        .fields
        .iter()
        .find(|f| f.name == "val_ivec")
        .map(|f| f.offset as u32)
        .unwrap_or(40);
    let uvec_off = ctrl_layout
        .fields
        .iter()
        .find(|f| f.name == "val_uvec")
        .map(|f| f.offset as u32)
        .unwrap_or(52);
    let offsets = (op_off, i64_off, f64_off, vec_off);
    let res_offsets = (op_off, i64_off, f64_off, vec_off, ivec_off, uvec_off);

    let mut augmented = mir.clone();
    augmented.layouts.push(ctrl_layout.clone());

    let mut dispatch_sys_names = Vec::new();
    let res_keys: Vec<String> = by_resource.keys().cloned().collect();
    for (ci, key_chunk) in res_keys.chunks(DISPATCH_RESOURCES_PER_SYS).enumerate() {
        let mut ops = Vec::new();
        for k in key_chunk {
            if let Some(list) = by_resource.get(k) {
                ops.extend(list.iter().cloned());
            }
        }
        let sys_name = format!("__strata_sim_dispatch_res_{ci}");
        let func = build_res_dispatch_function(
            sys_name.clone(),
            mir.is_deterministic,
            &ctrl_layout,
            res_offsets,
            &ops,
        );
        augmented.functions.push(func);
        dispatch_sys_names.push(sys_name);
    }

    for (ci, obj_chunk) in obj_ops_list.chunks(DISPATCH_OBJECTS_PER_SYS).enumerate() {
        let sys_name = format!("__strata_sim_dispatch_obj_{ci}");
        let func = build_obj_dispatch_function(
            sys_name.clone(),
            mir.is_deterministic,
            &ctrl_layout,
            offsets,
            obj_chunk,
        );
        augmented.functions.push(func);
        dispatch_sys_names.push(sys_name);
    }

    let nodes: Vec<HirScheduleGroup> = dispatch_sys_names
        .into_iter()
        .map(|name| HirScheduleGroup {
            kind: "leaf".to_owned(),
            name,
            children: Vec::new(),
        })
        .collect();
    if let Some(existing) = augmented
        .schedules
        .iter_mut()
        .find(|s| s.label == schedule.as_str())
    {
        existing.nodes.extend(nodes);
    } else {
        augmented.schedules.push(HirSchedule {
            label: schedule.as_str().to_owned(),
            run_if: None,
            run_if_expr: None,
            nodes,
        });
    }

    if let Err(errs) = verify_mir(&augmented) {
        let msg = errs
            .into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("sim_test MIR verification failed: {msg}"));
    }

    Ok((
        augmented,
        DispatchMetadata {
            schedule,
            ctrl_layout: Some(ctrl_layout),
            res_ops: res_ops_map,
            obj_ops: obj_ops_map,
        },
    ))
}

/// Runs all embedded `sim_test` blocks inside a real headless `bamabi_host` Bevy `World`.
pub fn run_headless_sim_tests(mir: &MirModule, source_stem: &str) -> Vec<SimTestCaseResult> {
    if mir.sim_tests.is_empty() {
        return Vec::new();
    }
    let _guard = SIM_EXEC_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let make_err = |msg: String| -> Vec<SimTestCaseResult> {
        mir.sim_tests
            .iter()
            .map(|t| SimTestCaseResult {
                name: t.name.clone(),
                passed: false,
                frames_simulated: 0,
                peak_cmd_bytes: 0,
                steady_state_allocs: 0,
                detail: msg.clone(),
            })
            .collect()
    };

    let (compiled_mir, dispatch_meta) = match augment_mir_for_sim_tests(mir) {
        Ok(pair) => pair,
        Err(e) => return make_err(e),
    };

    let tmp = match TempDir::new() {
        Ok(d) => d,
        Err(e) => return make_err(format!("failed creating tempdir: {e}")),
    };

    let dylib_path = match compile_module_to_dylib(
        &compiled_mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: format!("sim_{source_stem}"),
            opt_level: JitOptLevel::Speed,
        },
    ) {
        Ok(art) => art.dylib_path,
        Err(e) => return make_err(format!("JIT compile failed: {e}")),
    };

    let mut results = Vec::with_capacity(mir.sim_tests.len());
    for st in &mir.sim_tests {
        results.push(run_single_sim_test(
            &compiled_mir,
            &dispatch_meta,
            &dylib_path,
            st,
        ));
    }
    results
}

pub(crate) fn find_registry_component(
    world: &World,
    module_path: &str,
    key: &str,
) -> Option<RegisteredComponent> {
    let reg = world.get_resource::<ModRegistry>()?;
    let snap = reg.snapshot();
    let qualified = format!("{module_path}::{key}");
    let normalized = if let Some((comp, strat)) = key.split_once("::") {
        if strat == "hot" {
            comp.to_owned()
        } else {
            format!("{comp}__{strat}")
        }
    } else {
        key.to_owned()
    };
    let qual_norm = format!("{module_path}::{normalized}");

    snap.entries()
        .iter()
        .find(|e| e.name.as_ref() == key || e.name.as_ref() == qualified)
        .or_else(|| {
            snap.entries().iter().find(|e| {
                e.name.as_ref() == normalized
                    || e.name.as_ref() == qual_norm
                    || e.name.rsplit("::").next() == Some(key)
                    || e.name.rsplit("::").next() == Some(normalized.as_str())
            })
        })
        .cloned()
}

fn run_single_sim_test(
    mir: &MirModule,
    dispatch: &DispatchMetadata,
    dylib_path: &Path,
    st: &HirSimTest,
) -> SimTestCaseResult {
    let mut app = App::new();
    app.init_schedule(Startup);
    app.init_schedule(PostStartup);
    app.init_schedule(FixedUpdate);
    app.edit_schedule(FixedUpdate, |s| {
        s.set_executor(SingleThreadedExecutor::new());
    });
    dispatch.schedule.init_on_app(&mut app);
    app.add_plugins(AbiModPlugin::with_error_policy(ModErrorPolicy::Quarantine));

    let mod_id = match app.load_mod_with(dylib_path, LoadOptions::default()) {
        Ok(id) => id,
        Err(err) => {
            return SimTestCaseResult {
                name: st.name.clone(),
                passed: false,
                frames_simulated: 0,
                peak_cmd_bytes: 0,
                steady_state_allocs: 0,
                detail: format!("bamabi_host failed loading compiled mod: {err}"),
            };
        }
    };

    // Execute Bevy Startup once so `strata_init_objects` spawns `object` entities & binds them.
    app.world_mut().run_schedule(Startup);
    app.world_mut().run_schedule(PostStartup);

    // Attach synthetic `__StrataSimCtrl` control component for in-mod resource/object dispatch.
    let (ctrl_entity, ctrl_handle) = if let Some(ref ctrl_layout) = dispatch.ctrl_layout {
        let Some(entry) =
            find_registry_component(app.world(), &mir.module_path, &ctrl_layout.canonical_name)
        else {
            return SimTestCaseResult {
                name: st.name.clone(),
                passed: false,
                frames_simulated: 0,
                peak_cmd_bytes: 0,
                steady_state_allocs: 0,
                detail: "internal error: __StrataSimCtrl not registered in ModRegistry".to_owned(),
            };
        };
        let ent = app.world_mut().spawn_empty().id();
        let zero_bytes = vec![0u8; ctrl_layout.size];
        if let Err(err) = write_entity_pod_bytes(app.world_mut(), ent, entry.handle, &zero_bytes) {
            return SimTestCaseResult {
                name: st.name.clone(),
                passed: false,
                frames_simulated: 0,
                peak_cmd_bytes: 0,
                steady_state_allocs: 0,
                detail: format!("failed initializing __StrataSimCtrl entity: {err:?}"),
            };
        }
        (Some(ent), Some(entry.handle))
    } else {
        (None, None)
    };

    // Initialize FixedUpdate schedule graph before steady-state stepping so Bevy graph setup does
    // not execute systems early.
    app.world_mut().schedule_scope(FixedUpdate, |w, sched| {
        let _ = sched.initialize(w);
    });

    let mut runner = SimRunner {
        app: &mut app,
        mir,
        dispatch,
        mod_id,
        ctrl_entity,
        ctrl_handle,
        named_entities: HashMap::new(),
        frames_simulated: 0,
        steady_state_allocs: 0,
        scopes: vec![HashMap::new()],
    };

    if let Err(msg) = runner.preresolve_objects() {
        return SimTestCaseResult {
            name: st.name.clone(),
            passed: false,
            frames_simulated: runner.frames_simulated,
            peak_cmd_bytes: runner.peak_cmd_bytes(),
            steady_state_allocs: runner.steady_state_allocs,
            detail: msg,
        };
    }

    match runner.exec_stmts(&st.body) {
        Ok(Flow::Normal | Flow::Return(_)) => SimTestCaseResult {
            name: st.name.clone(),
            passed: true,
            frames_simulated: runner.frames_simulated,
            peak_cmd_bytes: runner.peak_cmd_bytes(),
            steady_state_allocs: runner.steady_state_allocs,
            detail: "ok".to_owned(),
        },
        Ok(Flow::Break | Flow::Continue) => SimTestCaseResult {
            name: st.name.clone(),
            passed: false,
            frames_simulated: runner.frames_simulated,
            peak_cmd_bytes: runner.peak_cmd_bytes(),
            steady_state_allocs: runner.steady_state_allocs,
            detail: "break/continue outside loop in sim_test".to_owned(),
        },
        Err(detail) => SimTestCaseResult {
            name: st.name.clone(),
            passed: false,
            frames_simulated: runner.frames_simulated,
            peak_cmd_bytes: runner.peak_cmd_bytes(),
            steady_state_allocs: runner.steady_state_allocs,
            detail,
        },
    }
}

#[derive(Debug, Clone)]
pub(crate) enum SimVal {
    Unit,
    Bool(bool),
    Int(i64),
    Float(f64),
    Vec([f32; 4], u8),
    IVec([i32; 4], u8),
    UVec([u32; 4], u8),
    String(String),
    Entity(Option<Entity>),
    QueryHit {
        entity: Entity,
        terms: Vec<HirQueryTerm>,
    },
    OptionHit(Option<Box<SimVal>>),
    ComponentRef {
        entity: Entity,
        layout_key: String,
        sub_path: Vec<String>,
    },
    ResourceRef {
        resource: String,
        sub_path: Vec<String>,
    },
    Tuple(Vec<SimVal>),
    Array(Vec<SimVal>),
    Struct {
        _name: String,
        fields: Vec<(String, SimVal)>,
    },
}

pub(crate) enum Flow {
    Normal,
    Return(SimVal),
    Break,
    Continue,
}

pub(crate) struct SimRunner<'a> {
    pub(crate) app: &'a mut App,
    pub(crate) mir: &'a MirModule,
    pub(crate) dispatch: &'a DispatchMetadata,
    pub(crate) mod_id: ModId,
    pub(crate) ctrl_entity: Option<Entity>,
    pub(crate) ctrl_handle: Option<bamabi_sys::BamComponent>,
    pub(crate) named_entities: HashMap<String, Entity>,
    pub(crate) frames_simulated: u64,
    pub(crate) steady_state_allocs: usize,
    pub(crate) scopes: Vec<HashMap<String, SimVal>>,
}

impl<'a> SimRunner<'a> {
    pub(crate) fn peak_cmd_bytes(&self) -> usize {
        self.app
            .world()
            .get_resource::<ModBudgetTelemetry>()
            .map(|t| {
                t.mod_snapshots(self.mod_id)
                    .iter()
                    .map(|s| s.arena_bytes_peak)
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0)
    }

    pub(crate) fn check_mod_faults(&self) -> Result<(), String> {
        if let Some(telemetry) = self.app.world().get_resource::<ModBudgetTelemetry>() {
            for snap in telemetry.mod_snapshots(self.mod_id) {
                if snap.quarantined {
                    return Err(format!(
                        "guest system `{}` was quarantined during simulation",
                        snap.system_name
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    pub(crate) fn pop_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    pub(crate) fn bind_var(&mut self, name: &str, val: SimVal) {
        if let Some(top) = self.scopes.last_mut() {
            top.insert(name.to_owned(), val);
        }
    }

    pub(crate) fn update_var(&mut self, name: &str, val: SimVal) -> bool {
        for frame in self.scopes.iter_mut().rev() {
            if frame.contains_key(name) {
                frame.insert(name.to_owned(), val);
                return true;
            }
        }
        false
    }

    pub(crate) fn get_var(&self, name: &str) -> Option<&SimVal> {
        for frame in self.scopes.iter().rev() {
            if let Some(v) = frame.get(name) {
                return Some(v);
            }
        }
        None
    }

    pub(crate) fn preresolve_objects(&mut self) -> Result<(), String> {
        let names: Vec<String> = self.mir.objects.iter().map(|o| o.name.clone()).collect();
        for name in names {
            if let Some(ent) = self.resolve_named_object_via_dispatch(&name)? {
                self.named_entities.insert(name, ent);
            }
        }
        Ok(())
    }

    pub(crate) fn resolve_named_object_via_dispatch(
        &mut self,
        name: &str,
    ) -> Result<Option<Entity>, String> {
        if let Some(&ent) = self.named_entities.get(name)
            && self.app.world().entities().contains(ent)
        {
            return Ok(Some(ent));
        }
        let Some(&op_id) = self.dispatch.obj_ops.get(name) else {
            return Ok(None);
        };
        let Some(ctrl_ent) = self.ctrl_entity else {
            return Ok(None);
        };
        let Some(ctrl_h) = self.ctrl_handle else {
            return Ok(None);
        };
        let Some(ref ctrl_layout) = self.dispatch.ctrl_layout else {
            return Ok(None);
        };
        let Some((op_off, i64_off, _, _)) = self.dispatch.ctrl_offsets() else {
            return Ok(None);
        };

        let mut bytes = vec![0u8; ctrl_layout.size];
        bytes[op_off..op_off + 4].copy_from_slice(&op_id.to_le_bytes());
        write_entity_pod_bytes(self.app.world_mut(), ctrl_ent, ctrl_h, &bytes)
            .map_err(|e| format!("failed writing object-resolve ctrl op: {e:?}"))?;

        self.dispatch.schedule.run_on_world(self.app.world_mut());
        self.check_mod_faults()?;

        let out = read_entity_pod_bytes(self.app.world(), ctrl_ent, ctrl_h)
            .map_err(|e| format!("failed reading object-resolve ctrl op: {e:?}"))?;
        let out_op = u32::from_le_bytes(out[op_off..op_off + 4].try_into().unwrap_or([0; 4]));
        if out_op != 0 {
            return Err(format!(
                "object-resolve dispatch did not execute for `{name}` (op={out_op})"
            ));
        }
        let bits = u64::from_le_bytes(out[i64_off..i64_off + 8].try_into().unwrap_or([0; 8]));
        if bits == 0 || bits == bamabi_sys::FfiEntity::NULL.to_bits() {
            Ok(None)
        } else {
            let ent = Entity::from_bits(bits);
            if self.app.world().entities().contains(ent) {
                self.named_entities.insert(name.to_owned(), ent);
                Ok(Some(ent))
            } else {
                Ok(None)
            }
        }
    }

    fn step_fixed(&mut self, count: u64) -> Result<(), String> {
        for _ in 0..count {
            let is_steady = self.frames_simulated > 0;
            let region = Region::new(&INSTRUMENTED_SYSTEM);
            self.app.world_mut().run_schedule(FixedUpdate);
            let frame_allocs = region.change().allocations;
            if is_steady {
                self.steady_state_allocs += frame_allocs;
            }
            self.frames_simulated += 1;
            self.check_mod_faults()?;
        }
        Ok(())
    }

    fn exec_stmts(&mut self, stmts: &[HirStmt]) -> Result<Flow, String> {
        for stmt in stmts {
            match self.exec_stmt(stmt)? {
                Flow::Normal => {}
                other => return Ok(other),
            }
        }
        Ok(Flow::Normal)
    }

    fn exec_stmt(&mut self, stmt: &HirStmt) -> Result<Flow, String> {
        match stmt {
            HirStmt::Let {
                pattern,
                value,
                else_block,
                ..
            } => {
                let v = self.eval_expr(value)?;
                if !self.try_bind_pattern(pattern, &v) {
                    if !else_block.is_empty() {
                        self.push_scope();
                        let flow = self.exec_stmts(else_block)?;
                        self.pop_scope();
                        return Ok(flow);
                    }
                    return Err(format!(
                        "let pattern `{pattern:?}` did not match value `{v:?}`"
                    ));
                }
                Ok(Flow::Normal)
            }
            HirStmt::Assign { target, op, value } => {
                let rhs = self.eval_expr(value)?;
                self.assign_lvalue(target, *op, rhs)?;
                Ok(Flow::Normal)
            }
            HirStmt::Expr(expr) => {
                let _ = self.eval_expr(expr)?;
                Ok(Flow::Normal)
            }
            HirStmt::Return(opt) => {
                let v = match opt {
                    Some(e) => self.eval_expr(e)?,
                    None => SimVal::Unit,
                };
                Ok(Flow::Return(v))
            }
            HirStmt::Break(opt) => {
                if let Some(e) = opt {
                    let _ = self.eval_expr(e)?;
                }
                Ok(Flow::Break)
            }
            HirStmt::Continue => Ok(Flow::Continue),
            HirStmt::While { cond, body } => {
                loop {
                    let c = self.eval_expr(cond)?;
                    if !as_bool(&c)? {
                        break;
                    }
                    self.push_scope();
                    let flow = self.exec_stmts(body)?;
                    self.pop_scope();
                    match flow {
                        Flow::Normal | Flow::Continue => {}
                        Flow::Break => break,
                        Flow::Return(v) => return Ok(Flow::Return(v)),
                    }
                }
                Ok(Flow::Normal)
            }
            HirStmt::Loop { body } => {
                loop {
                    self.push_scope();
                    let flow = self.exec_stmts(body)?;
                    self.pop_scope();
                    match flow {
                        Flow::Normal | Flow::Continue => {}
                        Flow::Break => break,
                        Flow::Return(v) => return Ok(Flow::Return(v)),
                    }
                }
                Ok(Flow::Normal)
            }
            other => Err(format!(
                "unsupported statement in sim_test body: `{other:?}`"
            )),
        }
    }

    fn try_bind_pattern(&mut self, pat: &HirPattern, val: &SimVal) -> bool {
        match pat {
            HirPattern::Wildcard => true,
            HirPattern::Binding { name, .. } => {
                self.bind_var(name, val.clone());
                true
            }
            HirPattern::Tuple(pats) => {
                let SimVal::Tuple(items) = val else {
                    return false;
                };
                if pats.len() != items.len() {
                    return false;
                }
                for (p, item) in pats.iter().zip(items.iter()) {
                    if !self.try_bind_pattern(p, item) {
                        return false;
                    }
                }
                true
            }
            HirPattern::TupleStruct { path, fields } => {
                let short = path.rsplit("::").next().unwrap_or(path);
                if short == "Some" {
                    if let SimVal::OptionHit(Some(inner)) = val {
                        if let Some(f0) = fields.first() {
                            return self.try_bind_pattern(f0, inner);
                        }
                        return true;
                    }
                    return false;
                }
                false
            }
            HirPattern::Path(p) => {
                let short = p.rsplit("::").next().unwrap_or(p);
                if short == "None" {
                    return matches!(val, SimVal::OptionHit(None));
                }
                if let Ok(cval) = self.eval_path(p) {
                    return sim_val_eq(val, &cval);
                }
                false
            }
            HirPattern::Literal(expr) => {
                if let Ok(lit) = self.eval_expr(expr) {
                    sim_val_eq(val, &lit)
                } else {
                    false
                }
            }
        }
    }

    fn eval_expr(&mut self, expr: &HirExpr) -> Result<SimVal, String> {
        match expr {
            HirExpr::IntLit { value, .. } => Ok(SimVal::Int(*value)),
            HirExpr::FloatLit { value, .. } => Ok(SimVal::Float(*value)),
            HirExpr::BoolLit(b) => Ok(SimVal::Bool(*b)),
            HirExpr::StringLit(s) => Ok(SimVal::String(s.clone())),
            HirExpr::CharLit(c) => Ok(SimVal::Int(i64::from(*c as u32))),
            HirExpr::Path { name, .. } => self.eval_path(name),
            HirExpr::Unary { op, expr, .. } => {
                let v = self.eval_expr(expr)?;
                eval_unary(*op, v)
            }
            HirExpr::Binary { op, lhs, rhs, .. } => self.eval_binary(*op, lhs, rhs),
            HirExpr::Cast { expr, target_ty } => {
                let v = self.eval_expr(expr)?;
                eval_cast(v, target_ty)
            }
            HirExpr::Field { base, field, .. } => {
                let b = self.eval_expr(base)?;
                self.read_field_on_val(b, field)
            }
            HirExpr::Index { base, index, .. } => {
                let b = self.eval_expr(base)?;
                let idx = as_int(&self.eval_expr(index)?)?;
                match b {
                    SimVal::Array(elems) => {
                        let ui = usize::try_from(idx)
                            .map_err(|_| format!("negative array index `{idx}`"))?;
                        elems
                            .get(ui)
                            .cloned()
                            .ok_or_else(|| format!("array index `{ui}` out of bounds"))
                    }
                    other => Err(format!("cannot index value `{other:?}`")),
                }
            }
            HirExpr::Call(call) => self.eval_call(call),
            HirExpr::Query(q) => self.eval_query(q),
            HirExpr::Tuple { elems, .. } => {
                if elems.is_empty() {
                    return Ok(SimVal::Unit);
                }
                let mut out = Vec::with_capacity(elems.len());
                for e in elems {
                    out.push(self.eval_expr(e)?);
                }
                Ok(SimVal::Tuple(out))
            }
            HirExpr::ArrayLit { elems, .. } => {
                let mut out = Vec::with_capacity(elems.len());
                for e in elems {
                    out.push(self.eval_expr(e)?);
                }
                Ok(SimVal::Array(out))
            }
            HirExpr::StructLit { name, fields, .. } => {
                let mut out = Vec::with_capacity(fields.len());
                for (fname, fexpr) in fields {
                    out.push((fname.clone(), self.eval_expr(fexpr)?));
                }
                Ok(SimVal::Struct {
                    _name: name.clone(),
                    fields: out,
                })
            }
            HirExpr::Block { stmts, tail, .. } => {
                self.push_scope();
                let flow = self.exec_stmts(stmts)?;
                let res = match flow {
                    Flow::Normal => match tail {
                        Some(t) => self.eval_expr(t),
                        None => Ok(SimVal::Unit),
                    },
                    Flow::Return(v) => Ok(v),
                    Flow::Break | Flow::Continue => Err("unexpected break/continue".to_owned()),
                };
                self.pop_scope();
                res
            }
            HirExpr::If {
                let_pat,
                cond,
                then_stmts,
                then_tail,
                else_stmts,
                else_tail,
                ..
            } => {
                if let Some(pat) = let_pat {
                    let scrut = self.eval_expr(cond)?;
                    self.push_scope();
                    let matched = self.try_bind_pattern(pat, &scrut);
                    let res = if matched {
                        self.exec_block_parts(then_stmts, then_tail.as_deref())
                    } else {
                        self.pop_scope();
                        self.push_scope();
                        self.exec_block_parts(else_stmts, else_tail.as_deref())
                    };
                    self.pop_scope();
                    res
                } else {
                    let c = as_bool(&self.eval_expr(cond)?)?;
                    self.push_scope();
                    let res = if c {
                        self.exec_block_parts(then_stmts, then_tail.as_deref())
                    } else {
                        self.exec_block_parts(else_stmts, else_tail.as_deref())
                    };
                    self.pop_scope();
                    res
                }
            }
            HirExpr::For(hf) => self.eval_for(hf),
            HirExpr::Match(m) => {
                let scrut = self.eval_expr(&m.scrutinee)?;
                for arm in &m.arms {
                    self.push_scope();
                    let matched = self.try_bind_pattern(&arm.pattern, &scrut);
                    let guard_ok = if matched {
                        if let Some(ref g) = arm.guard {
                            as_bool(&self.eval_expr(g)?)?
                        } else {
                            true
                        }
                    } else {
                        false
                    };
                    if matched && guard_ok {
                        let res = self.eval_expr(&arm.body);
                        self.pop_scope();
                        return res;
                    }
                    self.pop_scope();
                }
                Err("non-exhaustive match in sim_test".to_owned())
            }
            other => Err(format!(
                "unsupported expression in sim_test body: `{other:?}`"
            )),
        }
    }

    fn exec_block_parts(
        &mut self,
        stmts: &[HirStmt],
        tail: Option<&HirExpr>,
    ) -> Result<SimVal, String> {
        match self.exec_stmts(stmts)? {
            Flow::Normal => match tail {
                Some(t) => self.eval_expr(t),
                None => Ok(SimVal::Unit),
            },
            Flow::Return(v) => Ok(v),
            Flow::Break | Flow::Continue => Err("unexpected break/continue in block".to_owned()),
        }
    }

    fn eval_for(&mut self, hf: &strata_sema::hir::HirFor) -> Result<SimVal, String> {
        match &hf.iter {
            HirForIter::Range {
                start,
                end,
                inclusive,
            } => {
                let s = as_int(&self.eval_expr(start)?)?;
                let e = as_int(&self.eval_expr(end)?)?;
                let end_val = if *inclusive { e + 1 } else { e };
                for i in s..end_val {
                    self.push_scope();
                    self.try_bind_pattern(&hf.binding, &SimVal::Int(i));
                    let flow = self.exec_stmts(&hf.body)?;
                    self.pop_scope();
                    match flow {
                        Flow::Normal | Flow::Continue => {}
                        Flow::Break => break,
                        Flow::Return(v) => return Ok(v),
                    }
                }
                Ok(SimVal::Unit)
            }
            HirForIter::Query(q) => {
                let entities = self.collect_matching_entities(q)?;
                let single_proj = if q.terms.len() == 1
                    && let Some(ref proj) = q.terms[0].field_name
                    && !matches!(
                        q.terms[0].mode,
                        TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                    )
                    && matches!(
                        &hf.binding,
                        HirPattern::Binding { name, .. } if name == &q.terms[0].alias
                    ) {
                    Some((&q.terms[0], proj.clone()))
                } else {
                    None
                };
                for ent in entities {
                    let bound = if let Some((term, proj)) = &single_proj {
                        if matches!(
                            term.mode,
                            TermAccessMode::Write | TermAccessMode::SelectiveWrite
                        ) {
                            SimVal::ComponentRef {
                                entity: ent,
                                layout_key: term.canonical_component.clone(),
                                sub_path: vec![proj.clone()],
                            }
                        } else {
                            self.read_component_field(
                                ent,
                                &term.canonical_component,
                                std::slice::from_ref(proj),
                            )?
                        }
                    } else {
                        SimVal::QueryHit {
                            entity: ent,
                            terms: q.terms.clone(),
                        }
                    };
                    self.push_scope();
                    self.try_bind_pattern(&hf.binding, &bound);
                    let flow = self.exec_stmts(&hf.body)?;
                    self.pop_scope();
                    match flow {
                        Flow::Normal | Flow::Continue => {}
                        Flow::Break => break,
                        Flow::Return(v) => return Ok(v),
                    }
                }
                Ok(SimVal::Unit)
            }
            other => Err(format!(
                "unsupported `for` iterator in sim_test: `{other:?}`"
            )),
        }
    }

    fn eval_path(&mut self, name: &str) -> Result<SimVal, String> {
        if let Some(v) = self.get_var(name).cloned() {
            if let SimVal::ComponentRef {
                entity,
                layout_key,
                sub_path,
            } = v
            {
                if sub_path.is_empty() {
                    return Ok(SimVal::ComponentRef {
                        entity,
                        layout_key,
                        sub_path,
                    });
                }
                return self.read_component_or_subref(entity, &layout_key, sub_path);
            }
            return Ok(v);
        }
        match name {
            "vec2::ZERO" => return Ok(SimVal::Vec([0.0, 0.0, 0.0, 0.0], 2)),
            "vec2::ONE" => return Ok(SimVal::Vec([1.0, 1.0, 0.0, 0.0], 2)),
            "vec2::X" => return Ok(SimVal::Vec([1.0, 0.0, 0.0, 0.0], 2)),
            "vec2::Y" => return Ok(SimVal::Vec([0.0, 1.0, 0.0, 0.0], 2)),
            "vec3::ZERO" => return Ok(SimVal::Vec([0.0, 0.0, 0.0, 0.0], 3)),
            "vec3::ONE" => return Ok(SimVal::Vec([1.0, 1.0, 1.0, 0.0], 3)),
            "vec3::X" => return Ok(SimVal::Vec([1.0, 0.0, 0.0, 0.0], 3)),
            "vec3::Y" | "vec3::UP" => return Ok(SimVal::Vec([0.0, 1.0, 0.0, 0.0], 3)),
            "vec3::Z" => return Ok(SimVal::Vec([0.0, 0.0, 1.0, 0.0], 3)),
            "vec4::ZERO" => return Ok(SimVal::Vec([0.0, 0.0, 0.0, 0.0], 4)),
            "vec4::ONE" => return Ok(SimVal::Vec([1.0, 1.0, 1.0, 1.0], 4)),
            "vec4::X" => return Ok(SimVal::Vec([1.0, 0.0, 0.0, 0.0], 4)),
            "vec4::Y" => return Ok(SimVal::Vec([0.0, 1.0, 0.0, 0.0], 4)),
            "vec4::Z" => return Ok(SimVal::Vec([0.0, 0.0, 1.0, 0.0], 4)),
            "vec4::W" => return Ok(SimVal::Vec([0.0, 0.0, 0.0, 1.0], 4)),
            "ivec2::ZERO" => return Ok(SimVal::IVec([0, 0, 0, 0], 2)),
            "ivec2::ONE" => return Ok(SimVal::IVec([1, 1, 0, 0], 2)),
            "ivec2::X" => return Ok(SimVal::IVec([1, 0, 0, 0], 2)),
            "ivec2::Y" => return Ok(SimVal::IVec([0, 1, 0, 0], 2)),
            "ivec3::ZERO" => return Ok(SimVal::IVec([0, 0, 0, 0], 3)),
            "ivec3::ONE" => return Ok(SimVal::IVec([1, 1, 1, 0], 3)),
            "ivec3::X" => return Ok(SimVal::IVec([1, 0, 0, 0], 3)),
            "ivec3::Y" => return Ok(SimVal::IVec([0, 1, 0, 0], 3)),
            "ivec3::Z" => return Ok(SimVal::IVec([0, 0, 1, 0], 3)),
            "uvec2::ZERO" => return Ok(SimVal::UVec([0, 0, 0, 0], 2)),
            "uvec2::ONE" => return Ok(SimVal::UVec([1, 1, 0, 0], 2)),
            "uvec2::X" => return Ok(SimVal::UVec([1, 0, 0, 0], 2)),
            "uvec2::Y" => return Ok(SimVal::UVec([0, 1, 0, 0], 2)),
            "None" | "Option::None" => return Ok(SimVal::OptionHit(None)),
            _ => {}
        }
        if let Some((ename, vname)) = name.rsplit_once("::") {
            let qual_enum = format!("{}::{ename}", self.mir.module_path);
            if let Some(ed) = self
                .mir
                .enums
                .iter()
                .find(|e| e.canonical_name == ename || e.canonical_name == qual_enum)
                && let Some(&(_, disc)) = ed.variants.iter().find(|(v, _)| v == vname)
            {
                return Ok(SimVal::Int(disc));
            }
        }
        if let Some(c) = self.mir.consts.iter().find(|c| c.name == name).cloned()
            && let Some(ref c_expr) = c.expr
        {
            return self.eval_expr(c_expr);
        }
        if let Some(ent) = self.resolve_named_object_via_dispatch(name)? {
            return Ok(SimVal::Entity(Some(ent)));
        }
        Err(format!("unresolved path `{name}` in sim_test"))
    }

    fn eval_binary(
        &mut self,
        op: HirBinOp,
        lhs: &HirExpr,
        rhs: &HirExpr,
    ) -> Result<SimVal, String> {
        if op == HirBinOp::And {
            let l = as_bool(&self.eval_expr(lhs)?)?;
            if !l {
                return Ok(SimVal::Bool(false));
            }
            return Ok(SimVal::Bool(as_bool(&self.eval_expr(rhs)?)?));
        }
        if op == HirBinOp::Or {
            let l = as_bool(&self.eval_expr(lhs)?)?;
            if l {
                return Ok(SimVal::Bool(true));
            }
            return Ok(SimVal::Bool(as_bool(&self.eval_expr(rhs)?)?));
        }
        let lv = self.eval_expr(lhs)?;
        let rv = self.eval_expr(rhs)?;
        eval_binop_vals(op, lv, rv)
    }

    fn eval_call(&mut self, call: &HirCall) -> Result<SimVal, String> {
        if let Some(ref recv_expr) = call.receiver {
            let recv = self.eval_expr(recv_expr)?;
            match call.callee.as_str() {
                "unwrap" | "expect" => {
                    return match recv {
                        SimVal::OptionHit(Some(inner)) => Ok(*inner),
                        SimVal::OptionHit(None) => Err(format!(
                            "called `{}()` on empty `query_one` result",
                            call.callee
                        )),
                        SimVal::QueryHit { .. } => Ok(recv),
                        other => Err(format!("cannot call `.{}()` on `{other:?}`", call.callee)),
                    };
                }
                "is_some" => {
                    return match recv {
                        SimVal::OptionHit(opt) => Ok(SimVal::Bool(opt.is_some())),
                        other => Err(format!("cannot call `.is_some()` on `{other:?}`")),
                    };
                }
                "is_none" => {
                    return match recv {
                        SimVal::OptionHit(opt) => Ok(SimVal::Bool(opt.is_none())),
                        other => Err(format!("cannot call `.is_none()` on `{other:?}`")),
                    };
                }
                "raw" => return Ok(recv),
                "is_active" => {
                    let rem = as_float(&recv)?;
                    return Ok(SimVal::Bool(rem > 0.0));
                }
                "abs" | "floor" | "ceil" | "round" | "sqrt" | "sin" | "cos" => {
                    return eval_math_fn(&call.callee, &[recv]);
                }
                "min" | "max" | "powf" | "dot" | "clamp" | "lerp" => {
                    let mut args = vec![recv];
                    for a in &call.args {
                        args.push(self.eval_expr(a)?);
                    }
                    return eval_math_fn(&call.callee, &args);
                }
                "len" | "length" => {
                    return match recv {
                        SimVal::Vec(v, dims) => {
                            let mut sum = 0.0f64;
                            for lane in v.iter().take(usize::from(dims)) {
                                sum += f64::from(*lane) * f64::from(*lane);
                            }
                            Ok(SimVal::Float(sum.sqrt()))
                        }
                        SimVal::IVec(v, dims) => {
                            let mut sum = 0.0f64;
                            for lane in v.iter().take(usize::from(dims)) {
                                let f = f64::from(*lane);
                                sum += f * f;
                            }
                            Ok(SimVal::Float(sum.sqrt()))
                        }
                        SimVal::UVec(v, dims) => {
                            let mut sum = 0.0f64;
                            for lane in v.iter().take(usize::from(dims)) {
                                let f = f64::from(*lane);
                                sum += f * f;
                            }
                            Ok(SimVal::Float(sum.sqrt()))
                        }
                        SimVal::Array(a) => Ok(SimVal::Int(a.len() as i64)),
                        other => Err(format!("cannot call `.len()` on `{other:?}`")),
                    };
                }
                other => {
                    return Err(format!(
                        "unsupported method call `.{other}(...)` in sim_test"
                    ));
                }
            }
        }

        match call.callee.as_str() {
            "step_fixed" => {
                let count_val = call
                    .args
                    .first()
                    .ok_or_else(|| "step_fixed requires an argument".to_owned())?;
                let n = as_int(&self.eval_expr(count_val)?)?;
                if n < 0 {
                    return Err(format!("step_fixed count cannot be negative: {n}"));
                }
                self.step_fixed(n as u64)?;
                Ok(SimVal::Unit)
            }
            "assert" => {
                let cond_expr = call
                    .args
                    .first()
                    .ok_or_else(|| "assert requires a condition argument".to_owned())?;
                let cond_val = self.eval_expr(cond_expr)?;
                let ok = as_bool(&cond_val)?;
                if !ok {
                    let msg = if let Some(msg_expr) = call.args.get(1) {
                        format!("{:?}", self.eval_expr(msg_expr)?)
                    } else {
                        format!("{cond_expr:?}")
                    };
                    return Err(format!(
                        "assertion failed at frame {}: {msg}",
                        self.frames_simulated
                    ));
                }
                Ok(SimVal::Unit)
            }
            "assert_eq" => {
                if call.args.len() < 2 {
                    return Err("assert_eq requires 2 arguments".to_owned());
                }
                let a = self.eval_expr(&call.args[0])?;
                let b = self.eval_expr(&call.args[1])?;
                if !sim_val_eq(&a, &b) {
                    return Err(format!(
                        "assert_eq failed at frame {}: {a:?} != {b:?}",
                        self.frames_simulated
                    ));
                }
                Ok(SimVal::Unit)
            }
            "assert_ne" => {
                if call.args.len() < 2 {
                    return Err("assert_ne requires 2 arguments".to_owned());
                }
                let a = self.eval_expr(&call.args[0])?;
                let b = self.eval_expr(&call.args[1])?;
                if sim_val_eq(&a, &b) {
                    return Err(format!(
                        "assert_ne failed at frame {}: {a:?} == {b:?}",
                        self.frames_simulated
                    ));
                }
                Ok(SimVal::Unit)
            }
            "res" | "res_mut" => {
                let rname = call
                    .generic_args
                    .first()
                    .cloned()
                    .ok_or_else(|| "res<T>() requires resource type argument".to_owned())?;
                Ok(SimVal::ResourceRef {
                    resource: rname,
                    sub_path: Vec::new(),
                })
            }
            "vec2" => {
                let x = as_float(&self.eval_expr(call.args.first().ok_or("vec2 needs x")?)?)?;
                let y = as_float(&self.eval_expr(call.args.get(1).ok_or("vec2 needs y")?)?)?;
                Ok(SimVal::Vec([x as f32, y as f32, 0.0, 0.0], 2))
            }
            "vec3" => {
                let x = as_float(&self.eval_expr(call.args.first().ok_or("vec3 needs x")?)?)?;
                let y = as_float(&self.eval_expr(call.args.get(1).ok_or("vec3 needs y")?)?)?;
                let z = as_float(&self.eval_expr(call.args.get(2).ok_or("vec3 needs z")?)?)?;
                Ok(SimVal::Vec([x as f32, y as f32, z as f32, 0.0], 3))
            }
            "vec4" => {
                let x = as_float(&self.eval_expr(call.args.first().ok_or("vec4 needs x")?)?)?;
                let y = as_float(&self.eval_expr(call.args.get(1).ok_or("vec4 needs y")?)?)?;
                let z = as_float(&self.eval_expr(call.args.get(2).ok_or("vec4 needs z")?)?)?;
                let w = as_float(&self.eval_expr(call.args.get(3).ok_or("vec4 needs w")?)?)?;
                Ok(SimVal::Vec([x as f32, y as f32, z as f32, w as f32], 4))
            }
            "vec3a" | "Vec3a" => {
                let x = as_float(&self.eval_expr(call.args.first().ok_or("vec3a needs x")?)?)?;
                let y = as_float(&self.eval_expr(call.args.get(1).ok_or("vec3a needs y")?)?)?;
                let z = as_float(&self.eval_expr(call.args.get(2).ok_or("vec3a needs z")?)?)?;
                Ok(SimVal::Vec([x as f32, y as f32, z as f32, 0.0], 4))
            }
            "Some" | "Option::Some" => {
                let v =
                    self.eval_expr(call.args.first().ok_or("Some(...) requires 1 argument")?)?;
                Ok(SimVal::OptionHit(Some(Box::new(v))))
            }
            "ivec2" => {
                let x = as_int(&self.eval_expr(call.args.first().ok_or("ivec2 needs x")?)?)?;
                let y = as_int(&self.eval_expr(call.args.get(1).ok_or("ivec2 needs y")?)?)?;
                Ok(SimVal::IVec([x as i32, y as i32, 0, 0], 2))
            }
            "ivec3" => {
                let x = as_int(&self.eval_expr(call.args.first().ok_or("ivec3 needs x")?)?)?;
                let y = as_int(&self.eval_expr(call.args.get(1).ok_or("ivec3 needs y")?)?)?;
                let z = as_int(&self.eval_expr(call.args.get(2).ok_or("ivec3 needs z")?)?)?;
                Ok(SimVal::IVec([x as i32, y as i32, z as i32, 0], 3))
            }
            "uvec2" => {
                let x = as_int(&self.eval_expr(call.args.first().ok_or("uvec2 needs x")?)?)?;
                let y = as_int(&self.eval_expr(call.args.get(1).ok_or("uvec2 needs y")?)?)?;
                Ok(SimVal::UVec([x as u32, y as u32, 0, 0], 2))
            }
            "abs" | "floor" | "ceil" | "round" | "sqrt" | "sin" | "cos" | "min" | "max"
            | "clamp" | "lerp" | "powf" | "dot" => {
                let mut vals = Vec::with_capacity(call.args.len());
                for a in &call.args {
                    vals.push(self.eval_expr(a)?);
                }
                eval_math_fn(&call.callee, &vals)
            }
            other => Err(format!("unsupported call `{other}(...)` in sim_test")),
        }
    }

    pub(crate) fn entity_matches_query(&self, ent: Entity, q: &HirQuery) -> Result<bool, String> {
        let Ok(ent_ref) = self.app.world().get_entity(ent) else {
            return Ok(false);
        };
        for term in &q.terms {
            if matches!(
                term.mode,
                TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
            ) {
                continue;
            }
            let Some(reg) = find_registry_component(
                self.app.world(),
                &self.mir.module_path,
                &term.canonical_component,
            )
            .or_else(|| {
                find_registry_component(self.app.world(), &self.mir.module_path, &term.storage_key)
            }) else {
                return Ok(false);
            };
            if !ent_ref.contains_id(reg.component_id) {
                return Ok(false);
            }
        }
        for w in &q.with_filters {
            let Some(reg) = find_registry_component(self.app.world(), &self.mir.module_path, w)
            else {
                return Ok(false);
            };
            if !ent_ref.contains_id(reg.component_id) {
                return Ok(false);
            }
        }
        for wo in &q.without_filters {
            if let Some(reg) = find_registry_component(self.app.world(), &self.mir.module_path, wo)
                && ent_ref.contains_id(reg.component_id)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn collect_matching_entities(&self, q: &HirQuery) -> Result<Vec<Entity>, String> {
        let mut required_ids = Vec::new();
        for term in &q.terms {
            if matches!(
                term.mode,
                TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
            ) {
                continue;
            }
            let Some(reg) = find_registry_component(
                self.app.world(),
                &self.mir.module_path,
                &term.canonical_component,
            )
            .or_else(|| {
                find_registry_component(self.app.world(), &self.mir.module_path, &term.storage_key)
            }) else {
                return Ok(Vec::new());
            };
            required_ids.push(reg.component_id);
        }
        for w in &q.with_filters {
            let Some(reg) = find_registry_component(self.app.world(), &self.mir.module_path, w)
            else {
                return Ok(Vec::new());
            };
            required_ids.push(reg.component_id);
        }
        let mut excluded_ids = Vec::new();
        for wo in &q.without_filters {
            if let Some(reg) = find_registry_component(self.app.world(), &self.mir.module_path, wo)
            {
                excluded_ids.push(reg.component_id);
            }
        }

        let mut entities = Vec::new();
        for arch in self.app.world().archetypes().iter() {
            if arch.is_empty() {
                continue;
            }
            if required_ids.iter().all(|id| arch.contains(*id))
                && excluded_ids.iter().all(|id| !arch.contains(*id))
            {
                entities.extend(arch.entities().iter().map(|ae| ae.id()));
            }
        }
        Ok(entities)
    }

    fn eval_query(&mut self, q: &HirQuery) -> Result<SimVal, String> {
        if q.is_count {
            let ents = self.collect_matching_entities(q)?;
            return Ok(SimVal::Int(ents.len() as i64));
        }

        if q.is_point_lookup {
            let target_ent = if let Some(ref on_expr) = q.on_target {
                match self.eval_expr(on_expr)? {
                    SimVal::Entity(opt) => opt,
                    SimVal::QueryHit { entity, .. } => Some(entity),
                    other => {
                        return Err(format!(
                            "query_one(...).on(target) expects Entity/object, got `{other:?}`"
                        ));
                    }
                }
            } else {
                return Err("query_one(...) in sim_test requires `.on(target)`".to_owned());
            };

            let matched = match target_ent {
                Some(ent) if self.entity_matches_query(ent, q)? => Some(SimVal::QueryHit {
                    entity: ent,
                    terms: q.terms.clone(),
                }),
                _ => None,
            };

            if q.is_unwrap {
                return matched.ok_or_else(|| {
                    "query_one(...).unwrap() did not match target entity".to_owned()
                });
            }
            return Ok(SimVal::OptionHit(matched.map(Box::new)));
        }

        Err("standalone `query(...)` outside `for` or `.count()` in sim_test".to_owned())
    }

    pub(crate) fn read_field_on_val(
        &mut self,
        base: SimVal,
        field: &str,
    ) -> Result<SimVal, String> {
        match base {
            SimVal::QueryHit { entity, terms } => {
                if field == "id" {
                    return Ok(SimVal::Entity(Some(entity)));
                }
                let term = terms
                    .iter()
                    .find(|t| t.alias == field || t.storage_key == field)
                    .ok_or_else(|| format!("query row has no term `{field}`"))?;
                let comp_key = term.canonical_component.clone();
                if matches!(
                    term.mode,
                    TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                ) {
                    let has_comp =
                        find_registry_component(self.app.world(), &self.mir.module_path, &comp_key)
                            .or_else(|| {
                                find_registry_component(
                                    self.app.world(),
                                    &self.mir.module_path,
                                    &term.storage_key,
                                )
                            })
                            .is_some_and(|reg| {
                                self.app
                                    .world()
                                    .get_entity(entity)
                                    .is_ok_and(|er| er.contains_id(reg.component_id))
                            });
                    if !has_comp {
                        return Ok(SimVal::OptionHit(None));
                    }
                    let inner = if let Some(ref proj) = term.field_name {
                        self.read_component_field(entity, &comp_key, std::slice::from_ref(proj))?
                    } else {
                        SimVal::ComponentRef {
                            entity,
                            layout_key: comp_key,
                            sub_path: Vec::new(),
                        }
                    };
                    return Ok(SimVal::OptionHit(Some(Box::new(inner))));
                }
                if let Some(ref proj) = term.field_name {
                    self.read_component_field(entity, &comp_key, std::slice::from_ref(proj))
                } else {
                    Ok(SimVal::ComponentRef {
                        entity,
                        layout_key: comp_key,
                        sub_path: Vec::new(),
                    })
                }
            }
            SimVal::ComponentRef {
                entity,
                layout_key,
                mut sub_path,
            } => {
                sub_path.push(field.to_owned());
                self.read_component_or_subref(entity, &layout_key, sub_path)
            }
            SimVal::ResourceRef {
                resource,
                mut sub_path,
            } => {
                sub_path.push(field.to_owned());
                self.read_resource_field(&resource, &sub_path)
            }
            SimVal::Vec(v, dims) => eval_vec_field(v, dims, field),
            SimVal::IVec(v, dims) => eval_ivec_field(v, dims, field),
            SimVal::UVec(v, dims) => eval_uvec_field(v, dims, field),
            SimVal::Struct { fields, .. } => fields
                .into_iter()
                .find(|(n, _)| n == field)
                .map(|(_, v)| v)
                .ok_or_else(|| format!("struct has no field `{field}`")),
            other => Err(format!("cannot access field `.{field}` on `{other:?}`")),
        }
    }

    pub(crate) fn resolve_field_chain(
        &self,
        layout_key: &str,
        segments: &[String],
    ) -> Result<(SolvedLayout, usize, Ty, Option<u8>), String> {
        let base_layout =
            find_layout_in_slice(&self.mir.layouts, &self.mir.module_path, layout_key)
                .ok_or_else(|| format!("unknown component/resource layout `{layout_key}`"))?
                .clone();

        let mut cur_layout = base_layout.clone();
        let mut offset = 0usize;
        let mut cur_ty = Ty::Unknown;

        for (i, seg) in segments.iter().enumerate() {
            if let Some(sf) = cur_layout.fields.iter().find(|f| f.name == *seg) {
                offset += sf.offset;
                cur_ty = sf.ty.clone();
                if i + 1 < segments.len() {
                    if let Ty::Named(ref inner) = sf.ty
                        && let Some(inner_layout) =
                            find_layout_in_slice(&self.mir.layouts, &self.mir.module_path, inner)
                    {
                        cur_layout = inner_layout.clone();
                        continue;
                    }
                    if is_vec_ty(&sf.ty) && i + 2 == segments.len() {
                        let lane = vec_lane_index(&segments[i + 1]).ok_or_else(|| {
                            format!("invalid vector lane `{}` on `{seg}`", segments[i + 1])
                        })?;
                        return Ok((base_layout, offset, cur_ty, Some(lane)));
                    }
                    return Err(format!(
                        "cannot traverse sub-field `{}` inside `{seg}`",
                        segments[i + 1]
                    ));
                }
            } else {
                return Err(format!(
                    "layout `{}` has no field `{seg}`",
                    cur_layout.canonical_name
                ));
            }
        }

        Ok((base_layout, offset, cur_ty, None))
    }

    pub(crate) fn read_component_or_subref(
        &self,
        entity: Entity,
        layout_key: &str,
        segments: Vec<String>,
    ) -> Result<SimVal, String> {
        let (base_layout, offset, cur_ty, lane_opt) =
            self.resolve_field_chain(layout_key, &segments)?;
        if let Ty::Named(ref inner) = cur_ty
            && find_layout_in_slice(&self.mir.layouts, &self.mir.module_path, inner).is_some()
        {
            return Ok(SimVal::ComponentRef {
                entity,
                layout_key: layout_key.to_owned(),
                sub_path: segments,
            });
        }
        self.read_component_at_offset(entity, &base_layout, &segments, offset, &cur_ty, lane_opt)
    }

    pub(crate) fn read_component_field(
        &self,
        entity: Entity,
        layout_key: &str,
        segments: &[String],
    ) -> Result<SimVal, String> {
        let (base_layout, offset, cur_ty, lane_opt) =
            self.resolve_field_chain(layout_key, segments)?;
        self.read_component_at_offset(entity, &base_layout, segments, offset, &cur_ty, lane_opt)
    }

    pub(crate) fn read_component_at_offset(
        &self,
        entity: Entity,
        base_layout: &SolvedLayout,
        segments: &[String],
        offset: usize,
        cur_ty: &Ty,
        lane_opt: Option<u8>,
    ) -> Result<SimVal, String> {
        let reg = find_registry_component(
            self.app.world(),
            &self.mir.module_path,
            &base_layout.canonical_name,
        )
        .ok_or_else(|| {
            format!(
                "component `{}` not registered in ModRegistry",
                base_layout.canonical_name
            )
        })?;

        if reg.is_abi_pod {
            let bytes =
                read_entity_pod_bytes(self.app.world(), entity, reg.handle).map_err(|e| {
                    format!(
                        "read_entity_pod_bytes failed on `{}`: {e:?}",
                        base_layout.canonical_name
                    )
                })?;
            let val = decode_ty_from_bytes(
                &bytes,
                offset,
                cur_ty,
                &self.mir.enums,
                &self.mir.module_path,
            )?;
            if let Some(lane) = lane_opt {
                return extract_vec_lane_val(val, lane);
            }
            return Ok(val);
        }

        // Host non-POD fallback via witness `export_entity_component_fields`.
        let exported = export_entity_component_fields(self.app.world(), entity, reg.handle)
            .map_err(|e| format!("export_entity_component_fields failed: {e:?}"))?;
        let fname = segments.first().map(String::as_str).unwrap_or("");
        let rec = exported
            .iter()
            .find(|r| r.field_name == fname)
            .ok_or_else(|| format!("exported field `{fname}` missing"))?;
        let val = decode_ty_from_bytes(
            &rec.bytes,
            0,
            cur_ty,
            &self.mir.enums,
            &self.mir.module_path,
        )?;
        if let Some(lane) = lane_opt {
            extract_vec_lane_val(val, lane)
        } else {
            Ok(val)
        }
    }

    pub(crate) fn write_component_field(
        &mut self,
        entity: Entity,
        layout_key: &str,
        segments: &[String],
        op: HirAssignOp,
        rhs: SimVal,
    ) -> Result<(), String> {
        let (base_layout, offset, cur_ty, lane_opt) =
            self.resolve_field_chain(layout_key, segments)?;
        let reg = find_registry_component(
            self.app.world(),
            &self.mir.module_path,
            &base_layout.canonical_name,
        )
        .ok_or_else(|| {
            format!(
                "component `{}` not registered in ModRegistry",
                base_layout.canonical_name
            )
        })?;

        let effective_ty = if lane_opt.is_some() {
            vec_lane_scalar_ty(&cur_ty)
        } else {
            cur_ty
        };
        let effective_off = offset + lane_opt.map_or(0, |l| usize::from(l) * 4);

        if reg.is_abi_pod {
            let mut bytes = read_entity_pod_bytes(self.app.world(), entity, reg.handle)
                .map_err(|e| format!("read_entity_pod_bytes failed: {e:?}"))?;
            let new_val = if op == HirAssignOp::Set {
                rhs
            } else {
                let old_val = decode_ty_from_bytes(
                    &bytes,
                    effective_off,
                    &effective_ty,
                    &self.mir.enums,
                    &self.mir.module_path,
                )?;
                apply_assign_op(op, old_val, rhs)?
            };
            encode_ty_to_bytes(
                &mut bytes,
                effective_off,
                &effective_ty,
                &new_val,
                &self.mir.enums,
                &self.mir.module_path,
            )?;
            if write_entity_pod_bytes(self.app.world_mut(), entity, reg.handle, &bytes).is_ok() {
                return Ok(());
            }
            // Host non-raw-insertable POD fallback via `apply_entity_component_fields`.
            let fsize = field_byte_size(&effective_ty, &self.mir.enums, &self.mir.module_path);
            let rec = ExportedFieldRecord {
                field_name: segments.join("."),
                type_tag: effective_ty.canonical_tag(),
                bytes: bytes[effective_off..effective_off + fsize].to_vec(),
            };
            return apply_entity_component_fields(self.app.world_mut(), entity, reg.handle, &[rec])
                .map_err(|e| format!("apply_entity_component_fields failed: {e:?}"));
        }

        // Non-POD host component path via `export_entity_component_fields` / `apply_entity_component_fields`.
        let exported = export_entity_component_fields(self.app.world(), entity, reg.handle)
            .map_err(|e| format!("export_entity_component_fields failed: {e:?}"))?;
        let fname = segments.first().map(String::as_str).unwrap_or("");
        let existing = exported
            .iter()
            .find(|r| r.field_name == fname)
            .ok_or_else(|| format!("exported field `{fname}` missing"))?;
        let mut fbytes = existing.bytes.clone();
        let rel_off = lane_opt.map_or(0, |l| usize::from(l) * 4);
        let new_val = if op == HirAssignOp::Set {
            rhs
        } else {
            let old_val = decode_ty_from_bytes(
                &fbytes,
                rel_off,
                &effective_ty,
                &self.mir.enums,
                &self.mir.module_path,
            )?;
            apply_assign_op(op, old_val, rhs)?
        };
        encode_ty_to_bytes(
            &mut fbytes,
            rel_off,
            &effective_ty,
            &new_val,
            &self.mir.enums,
            &self.mir.module_path,
        )?;
        let rec = ExportedFieldRecord {
            field_name: fname.to_owned(),
            type_tag: existing.type_tag.clone(),
            bytes: fbytes,
        };
        apply_entity_component_fields(self.app.world_mut(), entity, reg.handle, &[rec])
            .map_err(|e| format!("apply_entity_component_fields failed: {e:?}"))
    }

    fn split_resource_field_and_lane(
        &self,
        resource: &str,
        segments: &[String],
    ) -> Result<(String, Option<u8>, ResFieldDispatch), String> {
        let full_path = segments.join(".");
        if let Some(disp) = self
            .dispatch
            .res_ops
            .get(&(resource.to_owned(), full_path.clone()))
        {
            return Ok((full_path, None, disp.clone()));
        }
        if segments.len() >= 2
            && let Some(lane) = vec_lane_index(segments.last().map(String::as_str).unwrap_or(""))
        {
            let parent = segments[..segments.len() - 1].join(".");
            if let Some(disp) = self
                .dispatch
                .res_ops
                .get(&(resource.to_owned(), parent.clone()))
                && is_vec_ty(&disp.ty)
            {
                return Ok((parent, Some(lane), disp.clone()));
            }
        }
        Err(format!(
            "resource `{resource}` has no accessible field `{full_path}`"
        ))
    }

    pub(crate) fn read_resource_field(
        &mut self,
        resource: &str,
        segments: &[String],
    ) -> Result<SimVal, String> {
        if segments.is_empty() {
            return Ok(SimVal::ResourceRef {
                resource: resource.to_owned(),
                sub_path: Vec::new(),
            });
        }

        // Check if this resource is a Rust host-registered `ModComponent + Resource` first.
        if let Some(reg) =
            find_registry_component(self.app.world(), &self.mir.module_path, resource)
            && reg.is_resource()
        {
            let res_layout =
                find_layout_in_slice(&self.mir.layouts, &self.mir.module_path, resource);
            let (_, _, cur_ty, lane_opt) = if let Some(rl) = res_layout {
                self.resolve_field_chain(&rl.canonical_name, segments)?
            } else {
                return Err(format!("missing layout for host resource `{resource}`"));
            };
            let exported = export_resource_fields(self.app.world(), reg.handle)
                .map_err(|e| format!("export_resource_fields failed for `{resource}`: {e:?}"))?;
            let fname = segments[0].as_str();
            let rec = exported
                .iter()
                .find(|r| r.field_name == fname)
                .ok_or_else(|| format!("host resource `{resource}` has no field `{fname}`"))?;
            let val = decode_ty_from_bytes(
                &rec.bytes,
                0,
                &cur_ty,
                &self.mir.enums,
                &self.mir.module_path,
            )?;
            return match lane_opt {
                Some(lane) => extract_vec_lane_val(val, lane),
                None => Ok(val),
            };
        }

        // Mod-local `.strata` resource stored in `StrataModState`: dispatch inside compiled module!
        let (field_path, lane_opt, disp) =
            self.split_resource_field_and_lane(resource, segments)?;
        let val = self.dispatch_read_mod_resource(&field_path, &disp)?;
        if let Some(lane) = lane_opt {
            extract_vec_lane_val(val, lane)
        } else {
            Ok(val)
        }
    }

    pub(crate) fn write_resource_field(
        &mut self,
        resource: &str,
        segments: &[String],
        op: HirAssignOp,
        rhs: SimVal,
    ) -> Result<(), String> {
        if segments.is_empty() {
            return Err(format!(
                "cannot overwrite whole resource `{resource}` directly"
            ));
        }

        // Host-registered `ModComponent + Resource` path via `apply_resource_fields`.
        if let Some(reg) =
            find_registry_component(self.app.world(), &self.mir.module_path, resource)
            && reg.is_resource()
        {
            let res_layout =
                find_layout_in_slice(&self.mir.layouts, &self.mir.module_path, resource)
                    .ok_or_else(|| format!("missing layout for host resource `{resource}`"))?
                    .clone();
            let (_, _, cur_ty, lane_opt) =
                self.resolve_field_chain(&res_layout.canonical_name, segments)?;
            let exported = export_resource_fields(self.app.world(), reg.handle)
                .map_err(|e| format!("export_resource_fields failed for `{resource}`: {e:?}"))?;
            let fname = segments[0].as_str();
            let rec = exported
                .iter()
                .find(|r| r.field_name == fname)
                .ok_or_else(|| format!("host resource `{resource}` has no field `{fname}`"))?;
            let mut fbytes = rec.bytes.clone();
            let rel_off = lane_opt.map_or(0, |l| usize::from(l) * 4);
            let eff_ty = if lane_opt.is_some() {
                vec_lane_scalar_ty(&cur_ty)
            } else {
                cur_ty
            };
            let new_val = if op == HirAssignOp::Set {
                rhs
            } else {
                let old_val = decode_ty_from_bytes(
                    &fbytes,
                    rel_off,
                    &eff_ty,
                    &self.mir.enums,
                    &self.mir.module_path,
                )?;
                apply_assign_op(op, old_val, rhs)?
            };
            encode_ty_to_bytes(
                &mut fbytes,
                rel_off,
                &eff_ty,
                &new_val,
                &self.mir.enums,
                &self.mir.module_path,
            )?;
            let patch = ExportedFieldRecord {
                field_name: fname.to_owned(),
                type_tag: rec.type_tag.clone(),
                bytes: fbytes,
            };
            return apply_resource_fields(self.app.world_mut(), reg.handle, &[patch])
                .map_err(|e| format!("apply_resource_fields failed for `{resource}`: {e:?}"));
        }

        // Mod-local `.strata` resource stored in `StrataModState`: dispatch inside compiled module!
        let (field_path, lane_opt, disp) =
            self.split_resource_field_and_lane(resource, segments)?;
        let final_val = match (lane_opt, op) {
            (Some(lane), _) => {
                let cur = self.dispatch_read_mod_resource(&field_path, &disp)?;
                let idx = usize::from(lane);
                match cur {
                    SimVal::Vec(mut v, dims) => {
                        let updated_lane = if op == HirAssignOp::Set {
                            as_float(&rhs)?
                        } else {
                            let old_lane = SimVal::Float(f64::from(v[idx]));
                            as_float(&apply_assign_op(op, old_lane, rhs)?)?
                        };
                        v[idx] = updated_lane as f32;
                        SimVal::Vec(v, dims)
                    }
                    SimVal::IVec(mut v, dims) => {
                        let updated_lane = if op == HirAssignOp::Set {
                            as_int(&rhs)?
                        } else {
                            let old_lane = SimVal::Int(i64::from(v[idx]));
                            as_int(&apply_assign_op(op, old_lane, rhs)?)?
                        };
                        v[idx] = updated_lane as i32;
                        SimVal::IVec(v, dims)
                    }
                    SimVal::UVec(mut v, dims) => {
                        let updated_lane = if op == HirAssignOp::Set {
                            as_int(&rhs)?
                        } else {
                            let old_lane = SimVal::Int(i64::from(v[idx]));
                            as_int(&apply_assign_op(op, old_lane, rhs)?)?
                        };
                        v[idx] = updated_lane as u32;
                        SimVal::UVec(v, dims)
                    }
                    _ => return Err(format!("expected vector field for `{field_path}`")),
                }
            }
            (None, HirAssignOp::Set) => rhs,
            (None, _) => {
                let old_val = self.dispatch_read_mod_resource(&field_path, &disp)?;
                apply_assign_op(op, old_val, rhs)?
            }
        };
        self.dispatch_write_mod_resource(&field_path, &disp, final_val)
    }

    fn dispatch_read_mod_resource(
        &mut self,
        field_path: &str,
        disp: &ResFieldDispatch,
    ) -> Result<SimVal, String> {
        let ctrl_ent = self
            .ctrl_entity
            .ok_or_else(|| "missing __StrataSimCtrl entity".to_owned())?;
        let ctrl_h = self
            .ctrl_handle
            .ok_or_else(|| "missing __StrataSimCtrl handle".to_owned())?;
        let ctrl_size = self
            .dispatch
            .ctrl_layout
            .as_ref()
            .map(|l| l.size)
            .ok_or_else(|| "missing __StrataSimCtrl layout".to_owned())?;
        let (op_off, i64_off, f64_off, vec_off) = self
            .dispatch
            .ctrl_offsets()
            .ok_or_else(|| "missing __StrataSimCtrl offsets".to_owned())?;

        let mut bytes = vec![0u8; ctrl_size];
        bytes[op_off..op_off + 4].copy_from_slice(&disp.read_op.to_le_bytes());
        write_entity_pod_bytes(self.app.world_mut(), ctrl_ent, ctrl_h, &bytes)
            .map_err(|e| format!("ctrl write failed for `{field_path}`: {e:?}"))?;

        self.dispatch.schedule.run_on_world(self.app.world_mut());
        self.check_mod_faults()?;

        let out = read_entity_pod_bytes(self.app.world(), ctrl_ent, ctrl_h)
            .map_err(|e| format!("ctrl read failed for `{field_path}`: {e:?}"))?;
        let out_op = u32::from_le_bytes(out[op_off..op_off + 4].try_into().unwrap_or([0; 4]));
        if out_op != 0 {
            return Err(format!(
                "resource read dispatch did not execute for `{field_path}` (op={out_op})"
            ));
        }

        if disp.mir_ty == MirType::Bool {
            let v = i64::from_le_bytes(out[i64_off..i64_off + 8].try_into().unwrap_or([0; 8]));
            Ok(SimVal::Bool(v != 0))
        } else if is_int_like_mir_ty(&disp.mir_ty) {
            let v = i64::from_le_bytes(out[i64_off..i64_off + 8].try_into().unwrap_or([0; 8]));
            Ok(SimVal::Int(v))
        } else if is_float_like_mir_ty(&disp.mir_ty) {
            let v = f64::from_le_bytes(out[f64_off..f64_off + 8].try_into().unwrap_or([0; 8]));
            Ok(SimVal::Float(v))
        } else if let Some(dims) = vec_dims_for_mir_ty(&disp.mir_ty) {
            let (ivec_off, uvec_off) = self
                .dispatch
                .ctrl_int_vec_offsets()
                .ok_or_else(|| "missing __StrataSimCtrl int vec offsets".to_owned())?;
            match disp.ty {
                Ty::IVec2 | Ty::IVec3 => {
                    let mut vec = [0i32; 4];
                    for (i, slot) in vec.iter_mut().enumerate().take(usize::from(dims)) {
                        let s = ivec_off + i * 4;
                        *slot = i32::from_le_bytes(out[s..s + 4].try_into().unwrap_or([0; 4]));
                    }
                    Ok(SimVal::IVec(vec, dims))
                }
                Ty::UVec2 => {
                    let mut vec = [0u32; 4];
                    for (i, slot) in vec.iter_mut().enumerate().take(usize::from(dims)) {
                        let s = uvec_off + i * 4;
                        *slot = u32::from_le_bytes(out[s..s + 4].try_into().unwrap_or([0; 4]));
                    }
                    Ok(SimVal::UVec(vec, dims))
                }
                _ => {
                    let mut vec = [0.0f32; 4];
                    for (i, slot) in vec.iter_mut().enumerate().take(usize::from(dims)) {
                        let s = vec_off + i * 4;
                        *slot = f32::from_le_bytes(out[s..s + 4].try_into().unwrap_or([0; 4]));
                    }
                    Ok(SimVal::Vec(vec, dims))
                }
            }
        } else {
            Err(format!(
                "unsupported MIR resource field type `{:?}`",
                disp.mir_ty
            ))
        }
    }

    fn dispatch_write_mod_resource(
        &mut self,
        field_path: &str,
        disp: &ResFieldDispatch,
        val: SimVal,
    ) -> Result<(), String> {
        let ctrl_ent = self
            .ctrl_entity
            .ok_or_else(|| "missing __StrataSimCtrl entity".to_owned())?;
        let ctrl_h = self
            .ctrl_handle
            .ok_or_else(|| "missing __StrataSimCtrl handle".to_owned())?;
        let ctrl_size = self
            .dispatch
            .ctrl_layout
            .as_ref()
            .map(|l| l.size)
            .ok_or_else(|| "missing __StrataSimCtrl layout".to_owned())?;
        let (op_off, i64_off, f64_off, vec_off) = self
            .dispatch
            .ctrl_offsets()
            .ok_or_else(|| "missing __StrataSimCtrl offsets".to_owned())?;

        let mut bytes = vec![0u8; ctrl_size];
        bytes[op_off..op_off + 4].copy_from_slice(&disp.write_op.to_le_bytes());

        if disp.mir_ty == MirType::Bool {
            let b = i64::from(as_bool(&val)?);
            bytes[i64_off..i64_off + 8].copy_from_slice(&b.to_le_bytes());
        } else if is_int_like_mir_ty(&disp.mir_ty) {
            let i = as_int(&val)?;
            bytes[i64_off..i64_off + 8].copy_from_slice(&i.to_le_bytes());
        } else if is_float_like_mir_ty(&disp.mir_ty) {
            let f = as_float(&val)?;
            bytes[f64_off..f64_off + 8].copy_from_slice(&f.to_le_bytes());
        } else if let Some(dims) = vec_dims_for_mir_ty(&disp.mir_ty) {
            let (ivec_off, uvec_off) = self
                .dispatch
                .ctrl_int_vec_offsets()
                .ok_or_else(|| "missing __StrataSimCtrl int vec offsets".to_owned())?;
            match (&disp.ty, val) {
                (Ty::IVec2 | Ty::IVec3, SimVal::IVec(v, _)) => {
                    for (i, &lane) in v.iter().take(usize::from(dims)).enumerate() {
                        let s = ivec_off + i * 4;
                        bytes[s..s + 4].copy_from_slice(&lane.to_le_bytes());
                    }
                }
                (Ty::IVec2 | Ty::IVec3, SimVal::Vec(v, _)) => {
                    for (i, &lane) in v.iter().take(usize::from(dims)).enumerate() {
                        let s = ivec_off + i * 4;
                        bytes[s..s + 4].copy_from_slice(&(lane as i32).to_le_bytes());
                    }
                }
                (Ty::UVec2, SimVal::UVec(v, _)) => {
                    for (i, &lane) in v.iter().take(usize::from(dims)).enumerate() {
                        let s = uvec_off + i * 4;
                        bytes[s..s + 4].copy_from_slice(&lane.to_le_bytes());
                    }
                }
                (Ty::UVec2, SimVal::Vec(v, _)) => {
                    for (i, &lane) in v.iter().take(usize::from(dims)).enumerate() {
                        let s = uvec_off + i * 4;
                        bytes[s..s + 4].copy_from_slice(&(lane as u32).to_le_bytes());
                    }
                }
                (_, SimVal::Vec(v, _)) => {
                    for (i, &lane) in v.iter().take(usize::from(dims)).enumerate() {
                        let s = vec_off + i * 4;
                        bytes[s..s + 4].copy_from_slice(&lane.to_le_bytes());
                    }
                }
                (_, other) => {
                    return Err(format!(
                        "expected vector value for resource field `{field_path}`, got `{other:?}`"
                    ));
                }
            }
        } else {
            return Err(format!(
                "unsupported MIR resource field type `{:?}`",
                disp.mir_ty
            ));
        }

        write_entity_pod_bytes(self.app.world_mut(), ctrl_ent, ctrl_h, &bytes)
            .map_err(|e| format!("ctrl write failed for `{field_path}`: {e:?}"))?;

        self.dispatch.schedule.run_on_world(self.app.world_mut());
        self.check_mod_faults()?;

        let out = read_entity_pod_bytes(self.app.world(), ctrl_ent, ctrl_h)
            .map_err(|e| format!("ctrl verify read failed for `{field_path}`: {e:?}"))?;
        let out_op = u32::from_le_bytes(out[op_off..op_off + 4].try_into().unwrap_or([0; 4]));
        if out_op != 0 {
            return Err(format!(
                "resource write dispatch did not execute for `{field_path}` (op={out_op})"
            ));
        }
        Ok(())
    }

    fn assign_lvalue(
        &mut self,
        target: &HirLValue,
        op: HirAssignOp,
        rhs: SimVal,
    ) -> Result<(), String> {
        let mut fields = Vec::new();
        let mut cur = target;
        while let HirLValue::Field { base, field, .. } = cur {
            fields.push(field.clone());
            cur = base;
        }
        fields.reverse();

        match cur {
            HirLValue::ResourceAccess {
                resource, is_mut, ..
            } => {
                if !is_mut {
                    return Err(format!("cannot mutate immutable `res<{resource}>()`"));
                }
                self.write_resource_field(resource, &fields, op, rhs)
            }
            HirLValue::Local { name, .. } => {
                let base_val = self
                    .get_var(name)
                    .cloned()
                    .ok_or_else(|| format!("unknown variable `{name}` in assignment"))?;
                if fields.is_empty() {
                    if let SimVal::ComponentRef {
                        entity,
                        ref layout_key,
                        ref sub_path,
                    } = base_val
                        && !sub_path.is_empty()
                    {
                        return self.write_component_field(entity, layout_key, sub_path, op, rhs);
                    }
                    let final_val = if op == HirAssignOp::Set {
                        rhs
                    } else {
                        apply_assign_op(op, base_val, rhs)?
                    };
                    self.update_var(name, final_val);
                    return Ok(());
                }

                match base_val {
                    SimVal::ResourceRef {
                        resource,
                        mut sub_path,
                    } => {
                        sub_path.extend(fields);
                        self.write_resource_field(&resource, &sub_path, op, rhs)
                    }
                    SimVal::ComponentRef {
                        entity,
                        layout_key,
                        mut sub_path,
                    } => {
                        sub_path.extend(fields);
                        self.write_component_field(entity, &layout_key, &sub_path, op, rhs)
                    }
                    SimVal::QueryHit { entity, terms } => {
                        let term_name = &fields[0];
                        let term = terms
                            .iter()
                            .find(|t| t.alias == *term_name || t.storage_key == *term_name)
                            .ok_or_else(|| format!("query row has no term `{term_name}`"))?;
                        if !matches!(
                            term.mode,
                            TermAccessMode::Write
                                | TermAccessMode::SelectiveWrite
                                | TermAccessMode::OptionalWrite
                        ) {
                            return Err(format!(
                                "cannot mutate read-only query term `{term_name}`"
                            ));
                        }
                        let mut segs = Vec::new();
                        if let Some(ref proj) = term.field_name {
                            segs.push(proj.clone());
                        }
                        segs.extend_from_slice(&fields[1..]);
                        self.write_component_field(
                            entity,
                            &term.canonical_component,
                            &segs,
                            op,
                            rhs,
                        )
                    }
                    SimVal::Vec(mut v, dims) if fields.len() == 1 => {
                        let lane = vec_lane_index(&fields[0])
                            .ok_or_else(|| format!("invalid vector lane `{}`", fields[0]))?;
                        let idx = usize::from(lane);
                        let updated = if op == HirAssignOp::Set {
                            as_float(&rhs)?
                        } else {
                            let old = SimVal::Float(f64::from(v[idx]));
                            as_float(&apply_assign_op(op, old, rhs)?)?
                        };
                        v[idx] = updated as f32;
                        self.update_var(name, SimVal::Vec(v, dims));
                        Ok(())
                    }
                    SimVal::IVec(mut v, dims) if fields.len() == 1 => {
                        let lane = vec_lane_index(&fields[0])
                            .ok_or_else(|| format!("invalid vector lane `{}`", fields[0]))?;
                        let idx = usize::from(lane);
                        let updated = if op == HirAssignOp::Set {
                            as_int(&rhs)?
                        } else {
                            let old = SimVal::Int(i64::from(v[idx]));
                            as_int(&apply_assign_op(op, old, rhs)?)?
                        };
                        v[idx] = updated as i32;
                        self.update_var(name, SimVal::IVec(v, dims));
                        Ok(())
                    }
                    SimVal::UVec(mut v, dims) if fields.len() == 1 => {
                        let lane = vec_lane_index(&fields[0])
                            .ok_or_else(|| format!("invalid vector lane `{}`", fields[0]))?;
                        let idx = usize::from(lane);
                        let updated = if op == HirAssignOp::Set {
                            as_int(&rhs)?
                        } else {
                            let old = SimVal::Int(i64::from(v[idx]));
                            as_int(&apply_assign_op(op, old, rhs)?)?
                        };
                        v[idx] = updated as u32;
                        self.update_var(name, SimVal::UVec(v, dims));
                        Ok(())
                    }
                    other => Err(format!(
                        "cannot assign to field path `{}` on `{other:?}`",
                        fields.join(".")
                    )),
                }
            }
            HirLValue::Expr(_) => Err(format!("unsupported assignment target `{cur:?}`")),
            other => Err(format!("unsupported assignment target `{other:?}`")),
        }
    }
    pub(crate) fn spawn_entity_with_components(
        &mut self,
        comps: &[(String, Vec<(String, SimVal)>)],
    ) -> Result<Entity, String> {
        let ent = self.app.world_mut().spawn_empty().id();
        for (comp_name, explicit_fields) in comps {
            let layout = find_layout_in_slice(&self.mir.layouts, &self.mir.module_path, comp_name)
                .ok_or_else(|| format!("unknown component layout `{comp_name}` in spawn"))?
                .clone();
            let reg = find_registry_component(
                self.app.world(),
                &self.mir.module_path,
                &layout.canonical_name,
            )
            .ok_or_else(|| {
                format!(
                    "component `{}` not registered in ModRegistry",
                    layout.canonical_name
                )
            })?;

            let mut bytes = vec![0u8; layout.size];
            // Populate defaults from `mir.field_defaults` first.
            if let Some(defs) = self.mir.field_defaults.get(&layout.canonical_name) {
                for (fname, dval) in defs {
                    if let Some(sf) = layout.fields.iter().find(|f| f.name == *fname)
                        && let Some(sv) = mir_const_to_sim_val(dval)
                    {
                        let _ = encode_ty_to_bytes(
                            &mut bytes,
                            sf.offset,
                            &sf.ty,
                            &sv,
                            &self.mir.enums,
                            &self.mir.module_path,
                        );
                    }
                }
            }
            // Apply explicit overrides from struct/component literal.
            for (fname, fval) in explicit_fields {
                let sf = layout
                    .fields
                    .iter()
                    .find(|f| f.name == *fname)
                    .ok_or_else(|| {
                        format!(
                            "component `{}` has no field `{fname}`",
                            layout.canonical_name
                        )
                    })?;
                encode_ty_to_bytes(
                    &mut bytes,
                    sf.offset,
                    &sf.ty,
                    fval,
                    &self.mir.enums,
                    &self.mir.module_path,
                )?;
            }
            write_entity_pod_bytes(self.app.world_mut(), ent, reg.handle, &bytes).map_err(|e| {
                format!(
                    "failed inserting component `{}` on spawned entity: {e:?}",
                    layout.canonical_name
                )
            })?;
        }
        Ok(ent)
    }
}

pub(crate) fn mir_const_to_sim_val(val: &strata_mir::MirConstVal) -> Option<SimVal> {
    match val {
        strata_mir::MirConstVal::Unit => Some(SimVal::Unit),
        strata_mir::MirConstVal::Bool(b) => Some(SimVal::Bool(*b)),
        strata_mir::MirConstVal::Int(i) => Some(SimVal::Int(*i)),
        strata_mir::MirConstVal::Float(f) => Some(SimVal::Float(*f)),
        strata_mir::MirConstVal::Vec2(v) => {
            Some(SimVal::Vec([v[0] as f32, v[1] as f32, 0.0, 0.0], 2))
        }
        strata_mir::MirConstVal::Vec3(v) => {
            Some(SimVal::Vec([v[0] as f32, v[1] as f32, v[2] as f32, 0.0], 3))
        }
        strata_mir::MirConstVal::Vec4(v) => Some(SimVal::Vec(
            [v[0] as f32, v[1] as f32, v[2] as f32, v[3] as f32],
            4,
        )),
        strata_mir::MirConstVal::String(s) => Some(SimVal::String(s.clone())),
        _ => None,
    }
}

pub(crate) fn is_vec_ty(ty: &Ty) -> bool {
    matches!(
        ty,
        Ty::Vec2
            | Ty::UVec2
            | Ty::IVec2
            | Ty::Vec3
            | Ty::IVec3
            | Ty::Vec3a
            | Ty::Vec4
            | Ty::Quat
            | Ty::Rgba
    )
}

pub(crate) fn vec_lane_index(field: &str) -> Option<u8> {
    match field {
        "x" | "r" => Some(0),
        "y" | "g" => Some(1),
        "z" | "b" => Some(2),
        "w" | "a" => Some(3),
        _ => None,
    }
}

pub(crate) fn vec_lane_scalar_ty(ty: &Ty) -> Ty {
    match ty {
        Ty::IVec2 | Ty::IVec3 => Ty::I32,
        Ty::UVec2 => Ty::U32,
        _ => Ty::F32,
    }
}

pub(crate) fn eval_vec_field(v: [f32; 4], dims: u8, field: &str) -> Result<SimVal, String> {
    if let Some(lane) = vec_lane_index(field) {
        if lane >= dims {
            return Err(format!("lane `{field}` out of range for vec{dims}"));
        }
        return Ok(SimVal::Float(f64::from(v[usize::from(lane)])));
    }
    let lanes: Vec<u8> = field
        .chars()
        .filter_map(|c| {
            let mut buf = [0u8; 4];
            vec_lane_index(c.encode_utf8(&mut buf))
        })
        .collect();
    if lanes.len() == field.len() && (2..=4).contains(&lanes.len()) {
        let mut out = [0.0f32; 4];
        for (i, &l) in lanes.iter().enumerate() {
            if l >= dims {
                return Err(format!("swizzle `{field}` out of range for vec{dims}"));
            }
            out[i] = v[usize::from(l)];
        }
        return Ok(SimVal::Vec(out, lanes.len() as u8));
    }
    Err(format!("unknown field `{field}` on vec{dims}"))
}

pub(crate) fn eval_ivec_field(v: [i32; 4], dims: u8, field: &str) -> Result<SimVal, String> {
    if let Some(lane) = vec_lane_index(field) {
        if lane >= dims {
            return Err(format!("lane `{field}` out of range for ivec{dims}"));
        }
        return Ok(SimVal::Int(i64::from(v[usize::from(lane)])));
    }
    let lanes: Vec<u8> = field
        .chars()
        .filter_map(|c| {
            let mut buf = [0u8; 4];
            vec_lane_index(c.encode_utf8(&mut buf))
        })
        .collect();
    if lanes.len() == field.len() && (2..=4).contains(&lanes.len()) {
        let mut out = [0i32; 4];
        for (i, &l) in lanes.iter().enumerate() {
            if l >= dims {
                return Err(format!("swizzle `{field}` out of range for ivec{dims}"));
            }
            out[i] = v[usize::from(l)];
        }
        return Ok(SimVal::IVec(out, lanes.len() as u8));
    }
    Err(format!("unknown field `{field}` on ivec{dims}"))
}

pub(crate) fn eval_uvec_field(v: [u32; 4], dims: u8, field: &str) -> Result<SimVal, String> {
    if let Some(lane) = vec_lane_index(field) {
        if lane >= dims {
            return Err(format!("lane `{field}` out of range for uvec{dims}"));
        }
        return Ok(SimVal::Int(i64::from(v[usize::from(lane)])));
    }
    let lanes: Vec<u8> = field
        .chars()
        .filter_map(|c| {
            let mut buf = [0u8; 4];
            vec_lane_index(c.encode_utf8(&mut buf))
        })
        .collect();
    if lanes.len() == field.len() && (2..=4).contains(&lanes.len()) {
        let mut out = [0u32; 4];
        for (i, &l) in lanes.iter().enumerate() {
            if l >= dims {
                return Err(format!("swizzle `{field}` out of range for uvec{dims}"));
            }
            out[i] = v[usize::from(l)];
        }
        return Ok(SimVal::UVec(out, lanes.len() as u8));
    }
    Err(format!("unknown field `{field}` on uvec{dims}"))
}

pub(crate) fn extract_vec_lane_val(val: SimVal, lane: u8) -> Result<SimVal, String> {
    match val {
        SimVal::Vec(v, dims) => {
            if lane >= dims {
                return Err(format!("lane {lane} out of range for vec{dims}"));
            }
            Ok(SimVal::Float(f64::from(v[usize::from(lane)])))
        }
        SimVal::IVec(v, dims) => {
            if lane >= dims {
                return Err(format!("lane {lane} out of range for ivec{dims}"));
            }
            Ok(SimVal::Int(i64::from(v[usize::from(lane)])))
        }
        SimVal::UVec(v, dims) => {
            if lane >= dims {
                return Err(format!("lane {lane} out of range for uvec{dims}"));
            }
            Ok(SimVal::Int(i64::from(v[usize::from(lane)])))
        }
        other => Err(format!("cannot extract vector lane from `{other:?}`")),
    }
}

pub(crate) fn field_byte_size(ty: &Ty, enums: &[EnumDef], module_path: &str) -> usize {
    match ty {
        Ty::Bool | Ty::U8 | Ty::I8 => 1,
        Ty::U16 | Ty::I16 => 2,
        Ty::U64 | Ty::I64 | Ty::F64 | Ty::Fix64 | Ty::Vec2 | Ty::UVec2 | Ty::IVec2 => 8,
        Ty::Vec3 | Ty::IVec3 => 12,
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => 16,
        Ty::Ref(n) if n == "Entity" => 8,
        Ty::Named(n) => {
            let q = format!("{module_path}::{n}");
            enums
                .iter()
                .find(|e| e.canonical_name == *n || e.canonical_name == q)
                .map(|e| e.repr_bytes)
                .unwrap_or(4)
        }
        _ => 4,
    }
}

pub(crate) fn decode_ty_from_bytes(
    bytes: &[u8],
    offset: usize,
    ty: &Ty,
    enums: &[EnumDef],
    module_path: &str,
) -> Result<SimVal, String> {
    let need = field_byte_size(ty, enums, module_path);
    if offset + need > bytes.len() {
        return Err(format!(
            "POD field read out of bounds: offset={offset}, need={need}, len={}",
            bytes.len()
        ));
    }
    let slice = &bytes[offset..offset + need];
    match ty {
        Ty::Bool => Ok(SimVal::Bool(slice[0] != 0)),
        Ty::U8 => Ok(SimVal::Int(i64::from(slice[0]))),
        Ty::I8 => Ok(SimVal::Int(i64::from(slice[0] as i8))),
        Ty::U16 => Ok(SimVal::Int(i64::from(u16::from_le_bytes(
            slice.try_into().unwrap(),
        )))),
        Ty::I16 => Ok(SimVal::Int(i64::from(i16::from_le_bytes(
            slice.try_into().unwrap(),
        )))),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => Ok(SimVal::Int(i64::from(u32::from_le_bytes(
            slice.try_into().unwrap(),
        )))),
        Ty::I32 => Ok(SimVal::Int(i64::from(i32::from_le_bytes(
            slice.try_into().unwrap(),
        )))),
        Ty::U64 => Ok(SimVal::Int(
            u64::from_le_bytes(slice.try_into().unwrap()) as i64
        )),
        Ty::I64 => Ok(SimVal::Int(i64::from_le_bytes(slice.try_into().unwrap()))),
        Ty::Fix32 => {
            let raw = i32::from_le_bytes(slice.try_into().unwrap());
            Ok(SimVal::Float(f64::from(raw) / 65536.0))
        }
        Ty::Fix64 => {
            let raw = i64::from_le_bytes(slice.try_into().unwrap());
            Ok(SimVal::Float((raw as f64) / 4_294_967_296.0))
        }
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => Ok(SimVal::Float(f64::from(
            f32::from_le_bytes(slice.try_into().unwrap()),
        ))),
        Ty::F64 => Ok(SimVal::Float(f64::from_le_bytes(slice.try_into().unwrap()))),
        Ty::Vec2 => {
            let x = f32::from_le_bytes(slice[0..4].try_into().unwrap());
            let y = f32::from_le_bytes(slice[4..8].try_into().unwrap());
            Ok(SimVal::Vec([x, y, 0.0, 0.0], 2))
        }
        Ty::IVec2 => {
            let x = i32::from_le_bytes(slice[0..4].try_into().unwrap());
            let y = i32::from_le_bytes(slice[4..8].try_into().unwrap());
            Ok(SimVal::IVec([x, y, 0, 0], 2))
        }
        Ty::UVec2 => {
            let x = u32::from_le_bytes(slice[0..4].try_into().unwrap());
            let y = u32::from_le_bytes(slice[4..8].try_into().unwrap());
            Ok(SimVal::UVec([x, y, 0, 0], 2))
        }
        Ty::Vec3 => {
            let x = f32::from_le_bytes(slice[0..4].try_into().unwrap());
            let y = f32::from_le_bytes(slice[4..8].try_into().unwrap());
            let z = f32::from_le_bytes(slice[8..12].try_into().unwrap());
            Ok(SimVal::Vec([x, y, z, 0.0], 3))
        }
        Ty::IVec3 => {
            let x = i32::from_le_bytes(slice[0..4].try_into().unwrap());
            let y = i32::from_le_bytes(slice[4..8].try_into().unwrap());
            let z = i32::from_le_bytes(slice[8..12].try_into().unwrap());
            Ok(SimVal::IVec([x, y, z, 0], 3))
        }
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => {
            let x = f32::from_le_bytes(slice[0..4].try_into().unwrap());
            let y = f32::from_le_bytes(slice[4..8].try_into().unwrap());
            let z = f32::from_le_bytes(slice[8..12].try_into().unwrap());
            let w = f32::from_le_bytes(slice[12..16].try_into().unwrap());
            Ok(SimVal::Vec([x, y, z, w], 4))
        }
        Ty::Ref(n) if n == "Entity" => {
            let bits = u64::from_le_bytes(slice.try_into().unwrap());
            if bits == 0 || bits == bamabi_sys::FfiEntity::NULL.to_bits() {
                Ok(SimVal::Entity(None))
            } else {
                Ok(SimVal::Entity(Some(Entity::from_bits(bits))))
            }
        }
        Ty::Named(n) => {
            let q = format!("{module_path}::{n}");
            if let Some(ed) = enums
                .iter()
                .find(|e| e.canonical_name == *n || e.canonical_name == q)
            {
                let v = match (ed.repr_bytes, ed.is_signed) {
                    (1, _) => i64::from(slice[0]),
                    (2, _) => i64::from(u16::from_le_bytes(slice.try_into().unwrap())),
                    (_, true) => i64::from(i32::from_le_bytes(slice.try_into().unwrap())),
                    _ => i64::from(u32::from_le_bytes(slice.try_into().unwrap())),
                };
                return Ok(SimVal::Int(v));
            }
            Err(format!("unsupported POD field type `{ty:?}`"))
        }
        _ => Err(format!("unsupported POD field type `{ty:?}`")),
    }
}

pub(crate) fn encode_ty_to_bytes(
    bytes: &mut [u8],
    offset: usize,
    ty: &Ty,
    val: &SimVal,
    enums: &[EnumDef],
    module_path: &str,
) -> Result<(), String> {
    let need = field_byte_size(ty, enums, module_path);
    if offset + need > bytes.len() {
        return Err(format!(
            "POD field write out of bounds: offset={offset}, need={need}, len={}",
            bytes.len()
        ));
    }
    let slice = &mut bytes[offset..offset + need];
    match ty {
        Ty::Bool => slice[0] = u8::from(as_bool(val)?),
        Ty::U8 => slice[0] = as_int(val)? as u8,
        Ty::I8 => slice[0] = (as_int(val)? as i8) as u8,
        Ty::U16 => slice.copy_from_slice(&(as_int(val)? as u16).to_le_bytes()),
        Ty::I16 => slice.copy_from_slice(&(as_int(val)? as i16).to_le_bytes()),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => {
            slice.copy_from_slice(&(as_int(val)? as u32).to_le_bytes());
        }
        Ty::I32 => slice.copy_from_slice(&(as_int(val)? as i32).to_le_bytes()),
        Ty::U64 => slice.copy_from_slice(&(as_int(val)? as u64).to_le_bytes()),
        Ty::I64 => slice.copy_from_slice(&as_int(val)?.to_le_bytes()),
        Ty::Fix32 => {
            let q = (as_float(val)? * 65536.0).round() as i32;
            slice.copy_from_slice(&q.to_le_bytes());
        }
        Ty::Fix64 => {
            let q = (as_float(val)? * 4_294_967_296.0).round() as i64;
            slice.copy_from_slice(&q.to_le_bytes());
        }
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => {
            slice.copy_from_slice(&(as_float(val)? as f32).to_le_bytes());
        }
        Ty::F64 => slice.copy_from_slice(&as_float(val)?.to_le_bytes()),
        Ty::Vec2 => {
            let SimVal::Vec(v, _) = val else {
                return Err(format!("expected vec2, got `{val:?}`"));
            };
            slice[0..4].copy_from_slice(&v[0].to_le_bytes());
            slice[4..8].copy_from_slice(&v[1].to_le_bytes());
        }
        Ty::IVec2 => match val {
            SimVal::IVec(v, _) => {
                slice[0..4].copy_from_slice(&v[0].to_le_bytes());
                slice[4..8].copy_from_slice(&v[1].to_le_bytes());
            }
            SimVal::Vec(v, _) => {
                slice[0..4].copy_from_slice(&(v[0] as i32).to_le_bytes());
                slice[4..8].copy_from_slice(&(v[1] as i32).to_le_bytes());
            }
            other => return Err(format!("expected ivec2, got `{other:?}`")),
        },
        Ty::UVec2 => match val {
            SimVal::UVec(v, _) => {
                slice[0..4].copy_from_slice(&v[0].to_le_bytes());
                slice[4..8].copy_from_slice(&v[1].to_le_bytes());
            }
            SimVal::Vec(v, _) => {
                slice[0..4].copy_from_slice(&(v[0] as u32).to_le_bytes());
                slice[4..8].copy_from_slice(&(v[1] as u32).to_le_bytes());
            }
            other => return Err(format!("expected uvec2, got `{other:?}`")),
        },
        Ty::Vec3 => {
            let SimVal::Vec(v, _) = val else {
                return Err(format!("expected vec3, got `{val:?}`"));
            };
            slice[0..4].copy_from_slice(&v[0].to_le_bytes());
            slice[4..8].copy_from_slice(&v[1].to_le_bytes());
            slice[8..12].copy_from_slice(&v[2].to_le_bytes());
        }
        Ty::IVec3 => match val {
            SimVal::IVec(v, _) => {
                slice[0..4].copy_from_slice(&v[0].to_le_bytes());
                slice[4..8].copy_from_slice(&v[1].to_le_bytes());
                slice[8..12].copy_from_slice(&v[2].to_le_bytes());
            }
            SimVal::Vec(v, _) => {
                slice[0..4].copy_from_slice(&(v[0] as i32).to_le_bytes());
                slice[4..8].copy_from_slice(&(v[1] as i32).to_le_bytes());
                slice[8..12].copy_from_slice(&(v[2] as i32).to_le_bytes());
            }
            other => return Err(format!("expected ivec3, got `{other:?}`")),
        },
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => {
            let SimVal::Vec(v, _) = val else {
                return Err(format!("expected vec4, got `{val:?}`"));
            };
            for i in 0..4 {
                slice[i * 4..(i + 1) * 4].copy_from_slice(&v[i].to_le_bytes());
            }
        }
        Ty::Ref(n) if n == "Entity" => {
            let bits = match val {
                SimVal::Entity(Some(e)) => e.to_bits(),
                SimVal::Entity(None) => 0,
                other => return Err(format!("expected Entity, got `{other:?}`")),
            };
            slice.copy_from_slice(&bits.to_le_bytes());
        }
        Ty::Named(n) => {
            let q = format!("{module_path}::{n}");
            if let Some(ed) = enums
                .iter()
                .find(|e| e.canonical_name == *n || e.canonical_name == q)
            {
                let iv = as_int(val)?;
                match ed.repr_bytes {
                    1 => slice[0] = iv as u8,
                    2 => slice.copy_from_slice(&(iv as u16).to_le_bytes()),
                    _ => slice.copy_from_slice(&(iv as u32).to_le_bytes()),
                }
                return Ok(());
            }
            return Err(format!("unsupported POD write type `{ty:?}`"));
        }
        _ => return Err(format!("unsupported POD write type `{ty:?}`")),
    }
    Ok(())
}

pub(crate) fn as_bool(v: &SimVal) -> Result<bool, String> {
    match v {
        SimVal::Bool(b) => Ok(*b),
        other => Err(format!("expected bool, got `{other:?}`")),
    }
}

pub(crate) fn as_int(v: &SimVal) -> Result<i64, String> {
    match v {
        SimVal::Int(i) => Ok(*i),
        SimVal::Bool(b) => Ok(i64::from(*b)),
        other => Err(format!("expected integer, got `{other:?}`")),
    }
}

pub(crate) fn as_float(v: &SimVal) -> Result<f64, String> {
    match v {
        SimVal::Float(f) => Ok(*f),
        SimVal::Int(i) => Ok(*i as f64),
        other => Err(format!("expected float, got `{other:?}`")),
    }
}

pub(crate) fn sim_val_eq(a: &SimVal, b: &SimVal) -> bool {
    match (a, b) {
        (SimVal::Unit, SimVal::Unit) | (SimVal::OptionHit(None), SimVal::OptionHit(None)) => true,
        (SimVal::Bool(x), SimVal::Bool(y)) => x == y,
        (SimVal::Int(x), SimVal::Int(y)) => x == y,
        (SimVal::Float(x), SimVal::Float(y)) => (x - y).abs() < 1e-6,
        (SimVal::Int(x), SimVal::Float(y)) => ((*x as f64) - y).abs() < 1e-6,
        (SimVal::Float(x), SimVal::Int(y)) => (x - (*y as f64)).abs() < 1e-6,
        (SimVal::String(x), SimVal::String(y)) => x == y,
        (SimVal::Entity(x), SimVal::Entity(y)) => x == y,
        (SimVal::Vec(x, dx), SimVal::Vec(y, dy)) if dx == dy => {
            (0..usize::from(*dx)).all(|i| (x[i] - y[i]).abs() < 1e-5)
        }
        (SimVal::IVec(x, dx), SimVal::IVec(y, dy)) if dx == dy => {
            (0..usize::from(*dx)).all(|i| x[i] == y[i])
        }
        (SimVal::UVec(x, dx), SimVal::UVec(y, dy)) if dx == dy => {
            (0..usize::from(*dx)).all(|i| x[i] == y[i])
        }
        (SimVal::QueryHit { entity: a, .. }, SimVal::QueryHit { entity: b, .. }) => a == b,
        (SimVal::OptionHit(Some(x)), SimVal::OptionHit(Some(y))) => sim_val_eq(x, y),
        _ => false,
    }
}

pub(crate) fn eval_unary(op: HirUnOp, v: SimVal) -> Result<SimVal, String> {
    match (op, v) {
        (HirUnOp::Neg, SimVal::Int(i)) => Ok(SimVal::Int(-i)),
        (HirUnOp::Neg, SimVal::Float(f)) => Ok(SimVal::Float(-f)),
        (HirUnOp::Neg, SimVal::Vec(mut vec, dims)) => {
            for lane in vec.iter_mut().take(usize::from(dims)) {
                *lane = -*lane;
            }
            Ok(SimVal::Vec(vec, dims))
        }
        (HirUnOp::Neg, SimVal::IVec(mut vec, dims)) => {
            for lane in vec.iter_mut().take(usize::from(dims)) {
                *lane = lane.wrapping_neg();
            }
            Ok(SimVal::IVec(vec, dims))
        }
        (HirUnOp::Not, SimVal::Bool(b)) => Ok(SimVal::Bool(!b)),
        (HirUnOp::BitNot, SimVal::Int(i)) => Ok(SimVal::Int(!i)),
        (HirUnOp::Ref | HirUnOp::RefMut, inner) => Ok(inner),
        (op, other) => Err(format!("unsupported unary `{op:?}` on `{other:?}`")),
    }
}

pub(crate) fn eval_cast(v: SimVal, target: &Ty) -> Result<SimVal, String> {
    match target {
        Ty::Bool => Ok(SimVal::Bool(match v {
            SimVal::Bool(b) => b,
            SimVal::Int(i) => i != 0,
            SimVal::Float(f) => f != 0.0,
            other => return Err(format!("cannot cast `{other:?}` to bool")),
        })),
        Ty::I8 => {
            let iv = match v {
                SimVal::Int(i) => i64::from(i as i8),
                SimVal::Float(f) => i64::from(f as i8),
                SimVal::Bool(b) => i64::from(b),
                other => return Err(format!("cannot cast `{other:?}` to i8")),
            };
            Ok(SimVal::Int(iv))
        }
        Ty::I16 => {
            let iv = match v {
                SimVal::Int(i) => i64::from(i as i16),
                SimVal::Float(f) => i64::from(f as i16),
                SimVal::Bool(b) => i64::from(b),
                other => return Err(format!("cannot cast `{other:?}` to i16")),
            };
            Ok(SimVal::Int(iv))
        }
        Ty::I32 => {
            let iv = match v {
                SimVal::Int(i) => i64::from(i as i32),
                SimVal::Float(f) => i64::from(f as i32),
                SimVal::Bool(b) => i64::from(b),
                other => return Err(format!("cannot cast `{other:?}` to i32")),
            };
            Ok(SimVal::Int(iv))
        }
        Ty::I64 => {
            let iv = match v {
                SimVal::Int(i) => i,
                SimVal::Float(f) => f as i64,
                SimVal::Bool(b) => i64::from(b),
                other => return Err(format!("cannot cast `{other:?}` to i64")),
            };
            Ok(SimVal::Int(iv))
        }
        Ty::U8 => {
            let iv = match v {
                SimVal::Int(i) => i64::from(i as u8),
                SimVal::Float(f) => i64::from(f as u8),
                SimVal::Bool(b) => i64::from(b),
                other => return Err(format!("cannot cast `{other:?}` to u8")),
            };
            Ok(SimVal::Int(iv))
        }
        Ty::U16 => {
            let iv = match v {
                SimVal::Int(i) => i64::from(i as u16),
                SimVal::Float(f) => i64::from(f as u16),
                SimVal::Bool(b) => i64::from(b),
                other => return Err(format!("cannot cast `{other:?}` to u16")),
            };
            Ok(SimVal::Int(iv))
        }
        Ty::U32 | Ty::Sym | Ty::Rgba8 => {
            let iv = match v {
                SimVal::Int(i) => i64::from(i as u32),
                SimVal::Float(f) => i64::from(f as u32),
                SimVal::Bool(b) => i64::from(b),
                other => return Err(format!("cannot cast `{other:?}` to u32")),
            };
            Ok(SimVal::Int(iv))
        }
        Ty::U64 => {
            let iv = match v {
                SimVal::Int(i) => i,
                SimVal::Float(f) => (f as u64) as i64,
                SimVal::Bool(b) => i64::from(b),
                other => return Err(format!("cannot cast `{other:?}` to u64")),
            };
            Ok(SimVal::Int(iv))
        }
        Ty::F32 | Ty::F64 | Ty::UnitScalar { .. } => Ok(SimVal::Float(as_float(&v)?)),
        _ => Ok(v),
    }
}

pub(crate) fn eval_binop_vals(op: HirBinOp, lv: SimVal, rv: SimVal) -> Result<SimVal, String> {
    match (lv, rv) {
        (SimVal::Vec(mut a, da), SimVal::Vec(b, db)) if da == db => {
            if op == HirBinOp::Eq {
                return Ok(SimVal::Bool(
                    (0..usize::from(da)).all(|i| (a[i] - b[i]).abs() < 1e-5),
                ));
            }
            if op == HirBinOp::Ne {
                return Ok(SimVal::Bool(
                    (0..usize::from(da)).any(|i| (a[i] - b[i]).abs() >= 1e-5),
                ));
            }
            for i in 0..usize::from(da) {
                a[i] = match op {
                    HirBinOp::Add => a[i] + b[i],
                    HirBinOp::Sub => a[i] - b[i],
                    HirBinOp::Mul => a[i] * b[i],
                    HirBinOp::Div => a[i] / b[i],
                    _ => return Err(format!("unsupported vector binop `{op:?}`")),
                };
            }
            Ok(SimVal::Vec(a, da))
        }
        (SimVal::IVec(mut a, da), SimVal::IVec(b, db)) if da == db => {
            if op == HirBinOp::Eq {
                return Ok(SimVal::Bool((0..usize::from(da)).all(|i| a[i] == b[i])));
            }
            if op == HirBinOp::Ne {
                return Ok(SimVal::Bool((0..usize::from(da)).any(|i| a[i] != b[i])));
            }
            for i in 0..usize::from(da) {
                a[i] = match op {
                    HirBinOp::Add => a[i].wrapping_add(b[i]),
                    HirBinOp::Sub => a[i].wrapping_sub(b[i]),
                    HirBinOp::Mul => a[i].wrapping_mul(b[i]),
                    HirBinOp::Div if b[i] != 0 => a[i].wrapping_div(b[i]),
                    HirBinOp::Div => return Err("ivec division by zero in sim_test".to_owned()),
                    _ => return Err(format!("unsupported ivec binop `{op:?}`")),
                };
            }
            Ok(SimVal::IVec(a, da))
        }
        (SimVal::UVec(mut a, da), SimVal::UVec(b, db)) if da == db => {
            if op == HirBinOp::Eq {
                return Ok(SimVal::Bool((0..usize::from(da)).all(|i| a[i] == b[i])));
            }
            if op == HirBinOp::Ne {
                return Ok(SimVal::Bool((0..usize::from(da)).any(|i| a[i] != b[i])));
            }
            for i in 0..usize::from(da) {
                a[i] = match op {
                    HirBinOp::Add => a[i].wrapping_add(b[i]),
                    HirBinOp::Sub => a[i].wrapping_sub(b[i]),
                    HirBinOp::Mul => a[i].wrapping_mul(b[i]),
                    HirBinOp::Div if b[i] != 0 => a[i] / b[i],
                    HirBinOp::Div => return Err("uvec division by zero in sim_test".to_owned()),
                    _ => return Err(format!("unsupported uvec binop `{op:?}`")),
                };
            }
            Ok(SimVal::UVec(a, da))
        }
        (SimVal::Vec(mut a, da), s @ (SimVal::Float(_) | SimVal::Int(_))) => {
            let sv = as_float(&s)? as f32;
            for lane in a.iter_mut().take(usize::from(da)) {
                *lane = match op {
                    HirBinOp::Mul => *lane * sv,
                    HirBinOp::Div => *lane / sv,
                    _ => return Err(format!("unsupported vec-scalar binop `{op:?}`")),
                };
            }
            Ok(SimVal::Vec(a, da))
        }
        (s @ (SimVal::Float(_) | SimVal::Int(_)), SimVal::Vec(mut b, db)) => {
            let sv = as_float(&s)? as f32;
            if op != HirBinOp::Mul {
                return Err(format!("unsupported scalar-vec binop `{op:?}`"));
            }
            for lane in b.iter_mut().take(usize::from(db)) {
                *lane *= sv;
            }
            Ok(SimVal::Vec(b, db))
        }
        (SimVal::Bool(a), SimVal::Bool(b)) => match op {
            HirBinOp::Eq => Ok(SimVal::Bool(a == b)),
            HirBinOp::Ne => Ok(SimVal::Bool(a != b)),
            _ => Err(format!("unsupported bool binop `{op:?}`")),
        },
        (SimVal::Int(a), SimVal::Int(b)) => match op {
            HirBinOp::Add => Ok(SimVal::Int(a.wrapping_add(b))),
            HirBinOp::Sub => Ok(SimVal::Int(a.wrapping_sub(b))),
            HirBinOp::Mul => Ok(SimVal::Int(a.wrapping_mul(b))),
            HirBinOp::Div => {
                if b == 0 {
                    Err("integer division by zero in sim_test".to_owned())
                } else {
                    Ok(SimVal::Int(a / b))
                }
            }
            HirBinOp::Rem => {
                if b == 0 {
                    Err("integer remainder by zero in sim_test".to_owned())
                } else {
                    Ok(SimVal::Int(a % b))
                }
            }
            HirBinOp::BitAnd => Ok(SimVal::Int(a & b)),
            HirBinOp::BitOr => Ok(SimVal::Int(a | b)),
            HirBinOp::BitXor => Ok(SimVal::Int(a ^ b)),
            HirBinOp::Shl => Ok(SimVal::Int(a.wrapping_shl(b as u32))),
            HirBinOp::Shr => Ok(SimVal::Int(a.wrapping_shr(b as u32))),
            HirBinOp::Eq => Ok(SimVal::Bool(a == b)),
            HirBinOp::Ne => Ok(SimVal::Bool(a != b)),
            HirBinOp::Lt => Ok(SimVal::Bool(a < b)),
            HirBinOp::Le => Ok(SimVal::Bool(a <= b)),
            HirBinOp::Gt => Ok(SimVal::Bool(a > b)),
            HirBinOp::Ge => Ok(SimVal::Bool(a >= b)),
            _ => Err(format!("unsupported int binop `{op:?}`")),
        },
        (l @ (SimVal::Float(_) | SimVal::Int(_)), r @ (SimVal::Float(_) | SimVal::Int(_))) => {
            let a = as_float(&l)?;
            let b = as_float(&r)?;
            match op {
                HirBinOp::Add => Ok(SimVal::Float(a + b)),
                HirBinOp::Sub => Ok(SimVal::Float(a - b)),
                HirBinOp::Mul => Ok(SimVal::Float(a * b)),
                HirBinOp::Div => Ok(SimVal::Float(a / b)),
                HirBinOp::Rem => Ok(SimVal::Float(a % b)),
                HirBinOp::Eq => Ok(SimVal::Bool((a - b).abs() < 1e-6)),
                HirBinOp::Ne => Ok(SimVal::Bool((a - b).abs() >= 1e-6)),
                HirBinOp::Lt => Ok(SimVal::Bool(a < b)),
                HirBinOp::Le => Ok(SimVal::Bool(a <= b)),
                HirBinOp::Gt => Ok(SimVal::Bool(a > b)),
                HirBinOp::Ge => Ok(SimVal::Bool(a >= b)),
                _ => Err(format!("unsupported float binop `{op:?}`")),
            }
        }
        (SimVal::Entity(a), SimVal::Entity(b)) => match op {
            HirBinOp::Eq => Ok(SimVal::Bool(a == b)),
            HirBinOp::Ne => Ok(SimVal::Bool(a != b)),
            _ => Err(format!("unsupported entity binop `{op:?}`")),
        },
        (SimVal::String(a), SimVal::String(b)) => match op {
            HirBinOp::Eq => Ok(SimVal::Bool(a == b)),
            HirBinOp::Ne => Ok(SimVal::Bool(a != b)),
            _ => Err(format!("unsupported string binop `{op:?}`")),
        },
        (l, r) => Err(format!(
            "incompatible operands for `{op:?}`: `{l:?}` and `{r:?}`"
        )),
    }
}

pub(crate) fn apply_assign_op(op: HirAssignOp, old: SimVal, rhs: SimVal) -> Result<SimVal, String> {
    let bin = match op {
        HirAssignOp::Set => return Ok(rhs),
        HirAssignOp::AddAssign => HirBinOp::Add,
        HirAssignOp::SubAssign => HirBinOp::Sub,
        HirAssignOp::MulAssign => HirBinOp::Mul,
        HirAssignOp::DivAssign => HirBinOp::Div,
        HirAssignOp::RemAssign => HirBinOp::Rem,
        HirAssignOp::BitAndAssign => HirBinOp::BitAnd,
        HirAssignOp::BitOrAssign => HirBinOp::BitOr,
        HirAssignOp::BitXorAssign => HirBinOp::BitXor,
        HirAssignOp::ShlAssign => HirBinOp::Shl,
        HirAssignOp::ShrAssign => HirBinOp::Shr,
    };
    eval_binop_vals(bin, old, rhs)
}

pub(crate) fn eval_math_fn(name: &str, args: &[SimVal]) -> Result<SimVal, String> {
    match name {
        "abs" => {
            let v = args.first().ok_or("abs requires 1 arg")?;
            match v {
                SimVal::Int(i) => Ok(SimVal::Int(i.abs())),
                _ => Ok(SimVal::Float(as_float(v)?.abs())),
            }
        }
        "floor" => Ok(SimVal::Float(
            as_float(args.first().ok_or("floor requires 1 arg")?)?.floor(),
        )),
        "ceil" => Ok(SimVal::Float(
            as_float(args.first().ok_or("ceil requires 1 arg")?)?.ceil(),
        )),
        "round" => Ok(SimVal::Float(
            as_float(args.first().ok_or("round requires 1 arg")?)?.round(),
        )),
        "sqrt" => Ok(SimVal::Float(
            as_float(args.first().ok_or("sqrt requires 1 arg")?)?.sqrt(),
        )),
        "sin" => Ok(SimVal::Float(
            as_float(args.first().ok_or("sin requires 1 arg")?)?.sin(),
        )),
        "cos" => Ok(SimVal::Float(
            as_float(args.first().ok_or("cos requires 1 arg")?)?.cos(),
        )),
        "powf" => {
            let a = as_float(args.first().ok_or("powf requires 2 args")?)?;
            let b = as_float(args.get(1).ok_or("powf requires 2 args")?)?;
            Ok(SimVal::Float(a.powf(b)))
        }
        "min" => {
            let a = as_float(args.first().ok_or("min requires 2 args")?)?;
            let b = as_float(args.get(1).ok_or("min requires 2 args")?)?;
            Ok(SimVal::Float(a.min(b)))
        }
        "max" => {
            let a = as_float(args.first().ok_or("max requires 2 args")?)?;
            let b = as_float(args.get(1).ok_or("max requires 2 args")?)?;
            Ok(SimVal::Float(a.max(b)))
        }
        "clamp" => {
            let x = as_float(args.first().ok_or("clamp requires 3 args")?)?;
            let lo = as_float(args.get(1).ok_or("clamp requires 3 args")?)?;
            let hi = as_float(args.get(2).ok_or("clamp requires 3 args")?)?;
            Ok(SimVal::Float(x.clamp(lo, hi)))
        }
        "lerp" => {
            let a = as_float(args.first().ok_or("lerp requires 3 args")?)?;
            let b = as_float(args.get(1).ok_or("lerp requires 3 args")?)?;
            let t = as_float(args.get(2).ok_or("lerp requires 3 args")?)?;
            Ok(SimVal::Float(a + (b - a) * t))
        }
        "dot" => match (args.first(), args.get(1)) {
            (Some(SimVal::Vec(a, da)), Some(SimVal::Vec(b, db))) if da == db => {
                let mut sum = 0.0f64;
                for i in 0..usize::from(*da) {
                    sum += f64::from(a[i]) * f64::from(b[i]);
                }
                Ok(SimVal::Float(sum))
            }
            (Some(SimVal::IVec(a, da)), Some(SimVal::IVec(b, db))) if da == db => {
                let mut sum = 0i64;
                for i in 0..usize::from(*da) {
                    sum += i64::from(a[i]) * i64::from(b[i]);
                }
                Ok(SimVal::Int(sum))
            }
            (Some(SimVal::UVec(a, da)), Some(SimVal::UVec(b, db))) if da == db => {
                let mut sum = 0i64;
                for i in 0..usize::from(*da) {
                    sum += i64::from(a[i]) * i64::from(b[i]);
                }
                Ok(SimVal::Int(sum))
            }
            _ => Err("dot requires two matching vectors".to_owned()),
        },
        _ => Err(format!("unknown math function `{name}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bevy_ecs::prelude::Resource;
    use std::path::PathBuf;
    use strata_mir::lower_to_mir;
    use strata_sema::analyze_source;

    /// Verifies `fixtures/cookbooks/03_metroidvania_core.strata` `sim_test` passes by genuinely
    /// executing the compiled module (`sample_platformer_inputs`, `strata_timer_tick`,
    /// `GraceWindow`, `InputBuffer`, and `PadInput`) inside a headless `bamabi_host` Bevy `World`.
    #[test]
    fn metroidvania_coyote_within_95ms_passes_real_execution() {
        let _alloc_guard = crate::test_alloc_read_guard();
        let cookbook = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("cookbooks")
            .join("03_metroidvania_core.strata");
        let src = std::fs::read_to_string(&cookbook).expect("read metroidvania cookbook");
        let analyzed = analyze_source("03_metroidvania_core.strata", &src);
        assert!(analyzed.ok(), "sema errors: {:?}", analyzed.diagnostics);
        let mir = lower_to_mir(&analyzed);

        let results = run_headless_sim_tests(&mir, "metroidvania_pos");
        assert_eq!(results.len(), 1);
        let res = &results[0];
        assert_eq!(res.name, "coyote_time_allows_late_jump_within_95ms");
        assert!(res.passed, "expected pass, got detail: {}", res.detail);
        assert_eq!(res.frames_simulated, 8);
    }

    /// Negative coyote-time test: waiting 13 FixedUpdate frames (~108.3ms > 95ms) after leaving
    /// ground expires the `GraceWindow` via `strata_timer_tick`, so pressing jump leaves `vel.y`
    /// near `0.0` and `assert(vy > 14.0)` fails!
    #[test]
    fn metroidvania_expired_coyote_after_95ms_fails_real_execution() {
        let _alloc_guard = crate::test_alloc_read_guard();
        let cookbook = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("cookbooks")
            .join("03_metroidvania_core.strata");
        let base_src = std::fs::read_to_string(&cookbook).expect("read metroidvania cookbook");
        let expired_src = format!(
            "{base_src}\n\
            sim_test \"expired_coyote_rejects_late_jump\" {{\n\
                if let Some(p) = query_one(body: &mut KinematicBody).on(PlayerHero) {{\n\
                    p.body.grounded = true;\n\
                }}\n\
                step_fixed(1);\n\
                if let Some(p) = query_one(body: &mut KinematicBody).on(PlayerHero) {{\n\
                    p.body.grounded = false;\n\
                }}\n\
                step_fixed(13);\n\
                res_mut<PadInput>().jump_pressed = true;\n\
                step_fixed(1);\n\
                let vy = query_one(vel: &Vel2D.dxy).on(PlayerHero).unwrap().vel.y;\n\
                assert(vy < 0.01 && vy > -0.01);\n\
                assert(vy > 14.0);\n\
            }}\n"
        );
        let analyzed = analyze_source("metroidvania_expired.strata", &expired_src);
        assert!(analyzed.ok(), "sema errors: {:?}", analyzed.diagnostics);
        let mir = lower_to_mir(&analyzed);

        let results = run_headless_sim_tests(&mir, "metroidvania_neg");
        assert_eq!(results.len(), 2);
        assert!(
            results[0].passed,
            "original test should pass: {}",
            results[0].detail
        );
        let neg = &results[1];
        assert_eq!(neg.name, "expired_coyote_rejects_late_jump");
        assert!(
            !neg.passed,
            "expired coyote >95ms must fail assert(vy > 14.0)"
        );
        assert_eq!(neg.frames_simulated, 15);
        assert!(
            neg.detail.contains("assertion failed"),
            "expected assertion failure detail, got `{}`",
            neg.detail
        );
    }

    /// Verifies mod-local resource reads/writes (`res_mut<SimConfig>()`, `res<SimConfig>()`) and
    /// allocation counting work end-to-end without any gameplay mocks.
    #[test]
    fn mod_local_resource_roundtrip_and_alloc_region_work() {
        let _alloc_guard = crate::test_alloc_write_guard();
        let src = r#"
module test::res_roundtrip @version(1.0.0);

resource SimConfig { scale: f32 = 2.0, enabled: bool = false }
component Counter { val: f32 = 1.0 }
object MainCounter { Counter {} }

sys step_counter(cfg: &res SimConfig) {
    if cfg.enabled {
        if let Some(c) = query_one(cnt: &mut Counter).on(MainCounter) {
            c.cnt.val += cfg.scale;
        }
    }
}

schedule FixedUpdate { step_counter }

sim_test "resource_mutation_drives_system" {
    step_fixed(2);
    let v0 = query_one(cnt: &Counter).on(MainCounter).unwrap().cnt.val;
    assert(v0 == 1.0);
    res_mut<SimConfig>().enabled = true;
    res_mut<SimConfig>().scale = 3.5;
    assert(res<SimConfig>().enabled);
    assert(res<SimConfig>().scale == 3.5);
    step_fixed(2);
    let v1 = query_one(cnt: &Counter).on(MainCounter).unwrap().cnt.val;
    assert(v1 == 8.0);
}
"#;
        let analyzed = analyze_source("res_roundtrip.strata", src);
        assert!(analyzed.ok(), "sema errors: {:?}", analyzed.diagnostics);
        let mir = lower_to_mir(&analyzed);
        let results = run_headless_sim_tests(&mir, "res_roundtrip");
        assert_eq!(results.len(), 1);
        assert!(
            results[0].passed,
            "resource roundtrip failed: {}",
            results[0].detail
        );
        assert_eq!(results[0].frames_simulated, 4);
        assert_eq!(results[0].steady_state_allocs, 0);

        let _guard = SIM_EXEC_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let region = Region::new(&INSTRUMENTED_SYSTEM);
        let heap_probe = Box::new(42_u64);
        std::hint::black_box(&heap_probe);
        let observed = region.change().allocations;
        drop(heap_probe);
        assert!(
            observed >= 1,
            "StatsAlloc Region must observe real heap allocations, got {observed}"
        );
    }

    #[repr(C)]
    #[derive(Resource, Clone, Copy, Default, ModComponent)]
    #[mod_component(name = "test::host_res::HostClock")]
    struct HostClock {
        dt: f32,
        paused: bool,
        _pad: [u8; 3],
    }

    /// Verifies `apply_resource_fields` / `export_resource_fields` path when a resource IS
    /// host-registered via `ModAppExt::register_mod_resource`.
    #[test]
    fn host_registered_resource_apply_and_export_work() {
        let _alloc_guard = crate::test_alloc_read_guard();
        let mut app = App::new();
        app.add_plugins(AbiModPlugin::with_error_policy(ModErrorPolicy::Quarantine));
        app.world_mut().insert_resource(HostClock {
            dt: 0.016,
            paused: false,
            _pad: [0; 3],
        });
        let _ = app.register_mod_resource::<HostClock>().unwrap();

        let src = r#"
module test::host_res @version(1.0.0);
resource HostClock { dt: f32 = 0.016, paused: bool = false }
"#;
        let analyzed = analyze_source("host_res.strata", src);
        assert!(analyzed.ok());
        let mir = lower_to_mir(&analyzed);
        let dispatch = DispatchMetadata {
            schedule: DispatchSchedule::PostUpdate,
            ctrl_layout: None,
            res_ops: HashMap::new(),
            obj_ops: HashMap::new(),
        };
        let mut runner = SimRunner {
            app: &mut app,
            mir: &mir,
            dispatch: &dispatch,
            mod_id: ModId(0),
            ctrl_entity: None,
            ctrl_handle: None,
            named_entities: HashMap::new(),
            frames_simulated: 0,
            steady_state_allocs: 0,
            scopes: vec![HashMap::new()],
        };

        let dt0 = runner
            .read_resource_field("HostClock", &["dt".to_owned()])
            .unwrap();
        assert!(sim_val_eq(&dt0, &SimVal::Float(0.016)));

        runner
            .write_resource_field(
                "HostClock",
                &["paused".to_owned()],
                HirAssignOp::Set,
                SimVal::Bool(true),
            )
            .unwrap();
        let paused = runner
            .read_resource_field("HostClock", &["paused".to_owned()])
            .unwrap();
        assert!(as_bool(&paused).unwrap());
        assert!(app.world().resource::<HostClock>().paused);
    }
}
