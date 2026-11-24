//! Headless virtual network simulation runner (`net_sim_test`) executing `ServerWorld` +
//! `ClientWorld[]` over `bamabi_host` with deterministic `latency`, `jitter`, `loss`, reliable
//! ARQ retransmission, and quantization-aware convergence checks.

use crate::commands::SimTestCaseResult;
use crate::sim_runner::{
    DispatchMetadata, SIM_EXEC_MUTEX, SimRunner, SimVal, apply_assign_op, as_bool, as_float,
    as_int, augment_mir_for_sim_tests, configure_dedicated_dispatch,
    encode_ty_to_bytes_with_layouts, ensure_child_of_registered, eval_binop_vals, eval_cast,
    eval_math_fn, eval_unary, find_layout_in_slice, find_registry_component, sim_val_eq,
};
use bamabi_host::prelude::*;
use bamabi_host::{ModBudgetTelemetry, write_entity_pod_bytes};
use bamabi_native_rt::{
    FLAG_IS_PREDICTED, FLAG_IS_RELIABLE, FLAG_IS_RESOURCE, FLAG_IS_RPC,
    PACKET_KIND_COMPONENT_DELTA, PACKET_KIND_RESOURCE_DELTA, PACKET_KIND_RPC,
    STRATA_NET_MAX_PAYLOAD_BYTES, STRATA_NET_PACKET_MAGIC, STRATA_NET_WIRE_VERSION,
    SharedBridgeAppExt, StrataNetPacket, dequantize_scalar_f64, pack_bits_le, quantize_scalar_f64,
    unpack_bits_le, verify_handshake_fingerprint,
};
use bamabi_sys::fnv1a_64_str;
use bevy_app::{App, FixedUpdate, PostStartup, Startup};
use bevy_ecs::entity::Entity;
use bevy_ecs::message::{MessageCursor, Messages};
use bevy_ecs::schedule::SingleThreadedExecutor;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use strata_jit::{JitCompileOptions, JitOptLevel, compile_module_to_dylib};
use strata_mir::{
    BasicBlock, BlockId, Inst, LocalId, MirFnKind, MirFunction, MirModule, MirNetComponent,
    MirQueryBinding, MirQueryTermBinding, MirRpc, MirStmt, MirStreamOp, MirStreamOpKind, MirType,
    Terminator, verify_mir,
};
use strata_sema::access::{QueryAccessDesc, QueryTerm, TermAccessMode};
use strata_sema::hir::{
    AuthorityKind, HirAssignOp, HirBinOp, HirCall, HirExpr, HirFor, HirForIter, HirLValue,
    HirPattern, HirQuery, HirQueryTerm, HirSchedule, HirScheduleGroup, HirStmt, HirUnOp,
    NetDirection, NetReliability,
};
use strata_sema::layout::{LayoutEnv, SchemaItemKind, solve_pod_layout};
use strata_sema::types::Ty;
use tempfile::TempDir;

const SIM_TICK_MS: f64 = 1000.0 / 60.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum NetWorldTarget {
    Server,
    Client(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetWorldRole {
    Server,
    Client,
}

/// Executes all embedded `net_sim_test` blocks inside isolated headless `ServerWorld` and
/// `ClientWorld[]` instances over `bamabi_host`.
pub fn run_headless_net_sim_tests(mir: &MirModule, source_stem: &str) -> Vec<SimTestCaseResult> {
    if mir.net_sim_tests.is_empty() {
        return Vec::new();
    }
    let _guard = SIM_EXEC_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

    let make_err = |msg: String| -> Vec<SimTestCaseResult> {
        mir.net_sim_tests
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

    let tmp = match TempDir::new() {
        Ok(d) => d,
        Err(e) => return make_err(format!("failed creating tempdir: {e}")),
    };

    let compiled = match compile_role_artifacts(mir, source_stem, tmp.path()) {
        Ok(c) => c,
        Err(e) => return make_err(e),
    };

    let mut results = Vec::with_capacity(mir.net_sim_tests.len());
    for nst in &mir.net_sim_tests {
        results.push(run_single_net_sim_test(mir, &compiled, nst));
    }
    results
}

struct CompiledNetArtifacts {
    server_mir: MirModule,
    server_dispatch: DispatchMetadata,
    server_dylib: PathBuf,
    client_mir: MirModule,
    client_dispatch: DispatchMetadata,
    client_dylib: PathBuf,
}

fn is_server_auth_key(mir: &MirModule, key: &str) -> bool {
    let bare = bare_name(key);
    mir.net_components.iter().any(|nc| {
        nc.authority == AuthorityKind::Server
            && (nc.canonical_name == key
                || nc.name == bare
                || nc.canonical_name.rsplit("::").next() == Some(bare))
    })
}

fn fn_mutates_server_state(
    mir: &MirModule,
    func: &MirFunction,
    visited: &mut HashSet<String>,
) -> bool {
    if !visited.insert(func.name.clone()) {
        return false;
    }
    if func.resources.iter().any(|r| {
        r.mutable
            && (is_server_auth_key(mir, &r.canonical_name)
                || is_server_auth_key(mir, &r.resource_name))
    }) {
        return true;
    }
    if func.queries.iter().any(|q| {
        q.terms
            .iter()
            .any(|t| t.mode.is_mutable() && is_server_auth_key(mir, &t.storage_key))
    }) {
        return true;
    }
    if func.query_bindings.iter().any(|qb| {
        qb.terms.iter().any(|t| {
            t.mode.is_mutable()
                && (is_server_auth_key(mir, &t.canonical_component)
                    || is_server_auth_key(mir, &t.storage_key))
        })
    }) {
        return true;
    }
    for bb in &func.blocks {
        for stmt in &bb.stmts {
            match &stmt.inst {
                Inst::ResWrite { resource } if is_server_auth_key(mir, resource) => return true,
                Inst::FieldStore { layout_key, .. } if is_server_auth_key(mir, layout_key) => {
                    return true;
                }
                Inst::CmdInsert { component, .. } | Inst::CmdRemove { component, .. }
                    if is_server_auth_key(mir, component) =>
                {
                    return true;
                }
                Inst::CmdDespawn { .. }
                    if func.queries.iter().any(|q| {
                        q.terms
                            .iter()
                            .any(|t| is_server_auth_key(mir, &t.storage_key))
                    }) =>
                {
                    return true;
                }
                Inst::Call { callee, .. } => {
                    let cbare = bare_name(callee);
                    if let Some(helper) = mir
                        .fns
                        .iter()
                        .find(|h| h.name == *callee || bare_name(&h.name) == cbare)
                        && fn_mutates_server_state(mir, helper, visited)
                    {
                        return true;
                    }
                }
                _ => {}
            }
        }
    }
    false
}

fn is_role_filtered_fn_kind(kind: &MirFnKind) -> bool {
    matches!(
        kind,
        MirFnKind::System
            | MirFnKind::Observer { .. }
            | MirFnKind::SynthesizedTask
            | MirFnKind::SynthesizedFsm
            | MirFnKind::SynthesizedTimeline
    )
}

fn effective_fn_authority(mir: &MirModule, f: &MirFunction) -> AuthorityKind {
    if f.is_predicted {
        return AuthorityKind::Predicted;
    }
    if f.authority != AuthorityKind::Unspecified {
        return f.authority;
    }
    if matches!(
        f.kind,
        MirFnKind::Observer { .. }
            | MirFnKind::SynthesizedTask
            | MirFnKind::SynthesizedFsm
            | MirFnKind::SynthesizedTimeline
    ) && fn_mutates_server_state(mir, f, &mut HashSet::new())
    {
        return AuthorityKind::Server;
    }
    AuthorityKind::Unspecified
}

fn has_role_restricted_systems(mir: &MirModule) -> bool {
    mir.functions.iter().any(|f| {
        is_role_filtered_fn_kind(&f.kind)
            && (f.is_predicted
                || matches!(
                    effective_fn_authority(mir, f),
                    AuthorityKind::Server | AuthorityKind::Client | AuthorityKind::Predicted
                ))
    })
}

fn bare_name(s: &str) -> &str {
    s.rsplit("::").next().unwrap_or(s)
}

fn prune_schedule_group(
    group: &HirScheduleGroup,
    kept_names: &HashSet<String>,
) -> Option<HirScheduleGroup> {
    if group.kind == "leaf" {
        if group.name.is_empty() || kept_names.contains(bare_name(&group.name)) {
            return Some(group.clone());
        }
        return None;
    }
    let mut children = Vec::new();
    for ch in &group.children {
        if let Some(pruned) = prune_schedule_group(ch, kept_names) {
            children.push(pruned);
        }
    }
    if children.is_empty() {
        None
    } else {
        Some(HirScheduleGroup {
            kind: group.kind.clone(),
            name: group.name.clone(),
            before: group.before.clone(),
            after: group.after.clone(),
            children,
        })
    }
}

fn filter_mir_for_role(mir: &MirModule, role: NetWorldRole) -> MirModule {
    let mut filtered = mir.clone();
    filtered.functions.retain(|f| {
        if !is_role_filtered_fn_kind(&f.kind) {
            return true;
        }
        let auth = effective_fn_authority(mir, f);
        match role {
            NetWorldRole::Server => {
                matches!(
                    auth,
                    AuthorityKind::Server | AuthorityKind::Shared | AuthorityKind::Unspecified
                ) && !f.is_predicted
            }
            NetWorldRole::Client => matches!(
                auth,
                AuthorityKind::Client
                    | AuthorityKind::Predicted
                    | AuthorityKind::Shared
                    | AuthorityKind::Unspecified
            ),
        }
    });

    let mut kept_names: HashSet<String> = HashSet::new();
    for f in &filtered.functions {
        kept_names.insert(f.name.clone());
        kept_names.insert(bare_name(&f.name).to_owned());
    }
    filtered
        .timelines
        .retain(|tl| kept_names.contains(&tl.name) || kept_names.contains(&tl.canonical_name));
    filtered
        .tasks
        .retain(|task| kept_names.contains(&task.name));
    filtered.fsms.retain(|fsm| kept_names.contains(&fsm.name));

    let mut new_schedules = Vec::with_capacity(filtered.schedules.len());
    for s in &filtered.schedules {
        let mut nodes = Vec::new();
        for n in &s.nodes {
            if let Some(pruned) = prune_schedule_group(n, &kept_names) {
                nodes.push(pruned);
            }
        }
        new_schedules.push(HirSchedule {
            label: s.label.clone(),
            run_if: s.run_if.clone(),
            run_if_expr: s.run_if_expr.clone(),
            nodes,
        });
    }
    filtered.schedules = new_schedules;
    filtered
}

fn rpc_slot_name(idx: usize) -> String {
    format!("__StrataSimRpcSlot_{idx}")
}

fn augment_mir_for_rpc_dispatch(mir: &mut MirModule) -> Result<(), String> {
    if mir.rpcs.is_empty() {
        return Ok(());
    }
    let mut env = LayoutEnv::default();
    for e in &mir.enums {
        let size = e.repr_bytes.max(1);
        let kind = match size {
            1 => bamabi_sys::BamFieldKind::U8.0,
            2 => bamabi_sys::BamFieldKind::U16.0,
            _ => bamabi_sys::BamFieldKind::U32.0,
        };
        let entry = (size, size, true, kind, e.canonical_name.clone());
        env.resolved.insert(e.canonical_name.clone(), entry.clone());
        env.resolved
            .entry(bare_name(&e.canonical_name).to_owned())
            .or_insert(entry);
    }
    for l in &mir.layouts {
        let short = bare_name(&l.canonical_name);
        let entry = (
            l.size,
            l.align.max(1),
            l.is_abi_pod,
            bamabi_sys::BamFieldKind::NESTED.0,
            l.canonical_name.clone(),
        );
        env.resolved.insert(l.canonical_name.clone(), entry.clone());
        env.resolved.entry(short.to_owned()).or_insert(entry);
    }

    let rpcs = mir.rpcs.clone();
    let mut dispatch_leaves = Vec::new();
    for (ri, rpc) in rpcs.iter().enumerate() {
        let has_observer = mir.functions.iter().any(|f| {
            matches!(&f.kind, MirFnKind::Observer { event, .. }
                if bare_name(event) == rpc.name || event == &rpc.canonical_name)
        });
        let has_stream_reader = mir.functions.iter().any(|f| {
            f.stream_ops.iter().any(|op| {
                op.kind == MirStreamOpKind::StreamRead
                    && (op.stream == rpc.name
                        || op.canonical_stream == rpc.canonical_name
                        || bare_name(&op.canonical_stream) == rpc.name)
            })
        });
        if !has_observer && !has_stream_reader {
            continue;
        }

        if !mir
            .layouts
            .iter()
            .any(|l| l.canonical_name == rpc.canonical_name)
        {
            let rpc_fields_ty: Vec<(String, Ty)> = rpc
                .fields
                .iter()
                .map(|(fname, mty, _, _)| (fname.clone(), mir_type_to_ty(mty)))
                .collect();
            let rpc_layout = solve_pod_layout(
                &rpc.canonical_name,
                SchemaItemKind::Event,
                &rpc_fields_ty,
                0,
                Vec::new(),
                &env,
            )
            .map_err(|e| format!("failed solving RPC layout `{}`: {e:?}", rpc.canonical_name))?;
            let rpc_entry = (
                rpc_layout.size,
                rpc_layout.align.max(1),
                rpc_layout.is_abi_pod,
                bamabi_sys::BamFieldKind::NESTED.0,
                rpc_layout.canonical_name.clone(),
            );
            env.resolved
                .insert(rpc_layout.canonical_name.clone(), rpc_entry.clone());
            env.resolved.entry(rpc.name.clone()).or_insert(rpc_entry);
            mir.layouts.push(rpc_layout);
        }

        let slot_short = rpc_slot_name(ri);
        let slot_canon = if mir.module_path.is_empty() {
            slot_short.clone()
        } else {
            format!("{}::{slot_short}", mir.module_path)
        };
        let slot_fields = if rpc.payload_bytes > 0 {
            vec![
                ("seq".to_owned(), Ty::U32),
                ("payload".to_owned(), Ty::Named(rpc.canonical_name.clone())),
            ]
        } else {
            vec![("seq".to_owned(), Ty::U32)]
        };
        let slot_layout = solve_pod_layout(
            &slot_canon,
            SchemaItemKind::Component,
            &slot_fields,
            0,
            Vec::new(),
            &env,
        )
        .map_err(|e| format!("failed solving RPC slot layout `{slot_canon}`: {e:?}"))?;
        let payload_off = slot_layout
            .fields
            .iter()
            .find(|f| f.name == "payload")
            .map_or(0u32, |f| f.offset as u32);
        let slot_size = slot_layout.size as u32;
        mir.layouts.push(slot_layout);

        let sys_name = format!("__strata_sim_rpc_dispatch_{ri}");
        let mut func = MirFunction::new(sys_name.clone(), MirFnKind::System);
        func.is_deterministic = mir.is_deterministic;
        func.queries.push(QueryAccessDesc {
            terms: vec![QueryTerm {
                storage_key: slot_short.clone(),
                field_name: None,
                mode: TermAccessMode::Read,
                byte_start: 0,
                byte_end: 0,
            }],
            ..Default::default()
        });
        func.query_bindings.push(MirQueryBinding {
            query_idx: 0,
            terms: vec![MirQueryTermBinding {
                term_idx: 0,
                alias: "slot".to_owned(),
                storage_key: slot_short.clone(),
                canonical_component: slot_canon.clone(),
                field_name: None,
                mode: TermAccessMode::Read,
                is_sparse: false,
            }],
            with_filters: Vec::new(),
            without_filters: Vec::new(),
            is_point_lookup: false,
        });
        if has_stream_reader {
            func.stream_ops.push(MirStreamOp {
                kind: MirStreamOpKind::StreamSend,
                stream: rpc.name.clone(),
                canonical_stream: rpc.canonical_name.clone(),
                requires_outside_par: false,
                channel: None,
            });
        }

        let mut next_loc = 0u32;
        let mut alloc = |name: &str, ty: MirType| -> LocalId {
            let id = LocalId(next_loc);
            next_loc += 1;
            func.locals.push(strata_mir::MirLocal {
                id,
                name: name.to_owned(),
                ty,
            });
            id
        };

        let entry_bb = BlockId(0);
        let chunk_hdr = BlockId(1);
        let chunk_body = BlockId(2);
        let row_hdr = BlockId(3);
        let row_body = BlockId(4);
        let exit_bb = BlockId(5);

        let has_chunk = alloc("has_chunk", MirType::Bool);
        let chunk_len = alloc("chunk_len", MirType::U32);
        let ents_ptr = alloc("ents", MirType::Ptr);
        let col_ptr = alloc("col", MirType::Ptr);
        let rslot = alloc("ridx_slot", MirType::MutPtr);
        let zero = alloc("z", MirType::U32);
        let ridx = alloc("ridx", MirType::U32);
        let rcond = alloc("rcond", MirType::Bool);
        let ent = alloc("ent", MirType::Entity);
        let rptr = alloc("rptr", MirType::Ptr);
        let payload_local = if rpc.payload_bytes > 0 {
            Some(alloc("payload_ptr", MirType::Ptr))
        } else {
            None
        };
        let dummy_payload = if rpc.payload_bytes == 0 && has_stream_reader {
            Some(alloc("dummy_pl", MirType::U32))
        } else {
            None
        };
        let one = alloc("one", MirType::U32);
        let nxt = alloc("r_nxt", MirType::U32);

        func.blocks.push(BasicBlock {
            id: entry_bb,
            label: "entry".to_owned(),
            stmts: Vec::new(),
            terminator: Terminator::Goto(chunk_hdr),
        });
        func.blocks.push(BasicBlock {
            id: chunk_hdr,
            label: "chunk_hdr".to_owned(),
            stmts: vec![MirStmt {
                dst: Some(has_chunk),
                inst: Inst::IterNextChunk { query_idx: 0 },
            }],
            terminator: Terminator::Branch {
                cond: has_chunk,
                then_bb: chunk_body,
                else_bb: exit_bb,
            },
        });
        func.blocks.push(BasicBlock {
            id: chunk_body,
            label: "chunk_body".to_owned(),
            stmts: vec![
                MirStmt {
                    dst: Some(chunk_len),
                    inst: Inst::IterChunkLen { query_idx: 0 },
                },
                MirStmt {
                    dst: Some(ents_ptr),
                    inst: Inst::IterEntities { query_idx: 0 },
                },
                MirStmt {
                    dst: Some(col_ptr),
                    inst: Inst::IterColRead {
                        query_idx: 0,
                        term_idx: 0,
                        storage_key: slot_short,
                    },
                },
                MirStmt {
                    dst: Some(rslot),
                    inst: Inst::SlotAlloc { ty: MirType::U32 },
                },
                MirStmt {
                    dst: Some(zero),
                    inst: Inst::ConstInt { value: 0 },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::SlotStore {
                        slot: rslot,
                        val: zero,
                    },
                },
            ],
            terminator: Terminator::Goto(row_hdr),
        });
        func.blocks.push(BasicBlock {
            id: row_hdr,
            label: "row_hdr".to_owned(),
            stmts: vec![
                MirStmt {
                    dst: Some(ridx),
                    inst: Inst::SlotLoad { slot: rslot },
                },
                MirStmt {
                    dst: Some(rcond),
                    inst: Inst::BinOp {
                        op: "<".to_owned(),
                        lhs: ridx,
                        rhs: chunk_len,
                        allow_fma: false,
                    },
                },
            ],
            terminator: Terminator::Branch {
                cond: rcond,
                then_bb: row_body,
                else_bb: chunk_hdr,
            },
        });

        let mut row_stmts = vec![
            MirStmt {
                dst: Some(ent),
                inst: Inst::EntityAtRow {
                    entities_ptr: ents_ptr,
                    row_idx: ridx,
                },
            },
            MirStmt {
                dst: Some(rptr),
                inst: Inst::RowPtr {
                    col_ptr,
                    row_idx: ridx,
                    stride_bytes: slot_size,
                    is_sparse: false,
                },
            },
        ];
        if let Some(pl) = payload_local {
            row_stmts.push(MirStmt {
                dst: Some(pl),
                inst: Inst::FieldPtr {
                    base_ptr: rptr,
                    layout_key: slot_canon,
                    field: "payload".to_owned(),
                    offset_bytes: payload_off,
                },
            });
        }
        if let Some(dpl) = dummy_payload {
            row_stmts.push(MirStmt {
                dst: Some(dpl),
                inst: Inst::ConstInt { value: 0 },
            });
        }
        if has_observer {
            row_stmts.push(MirStmt {
                dst: None,
                inst: Inst::CmdTrigger {
                    event: rpc.canonical_name.clone(),
                    target: None,
                    payload: payload_local,
                    propagate: false,
                },
            });
        }
        if has_stream_reader {
            let emit_pl = payload_local.or(dummy_payload).unwrap();
            row_stmts.push(MirStmt {
                dst: None,
                inst: Inst::StreamEmit {
                    stream: rpc.canonical_name.clone(),
                    payload: emit_pl,
                },
            });
        }
        row_stmts.push(MirStmt {
            dst: None,
            inst: Inst::CmdDespawn { entity: ent },
        });
        row_stmts.push(MirStmt {
            dst: Some(one),
            inst: Inst::ConstInt { value: 1 },
        });
        row_stmts.push(MirStmt {
            dst: Some(nxt),
            inst: Inst::BinOp {
                op: "+".to_owned(),
                lhs: ridx,
                rhs: one,
                allow_fma: false,
            },
        });
        row_stmts.push(MirStmt {
            dst: None,
            inst: Inst::SlotStore {
                slot: rslot,
                val: nxt,
            },
        });

        func.blocks.push(BasicBlock {
            id: row_body,
            label: "row_body".to_owned(),
            stmts: row_stmts,
            terminator: Terminator::Goto(row_hdr),
        });
        func.blocks.push(BasicBlock {
            id: exit_bb,
            label: "exit".to_owned(),
            stmts: Vec::new(),
            terminator: Terminator::Return(None),
        });

        mir.functions.push(func);
        dispatch_leaves.push(HirScheduleGroup {
            kind: "leaf".to_owned(),
            name: sys_name,
            before: Vec::new(),
            after: Vec::new(),
            children: Vec::new(),
        });
    }

    if !dispatch_leaves.is_empty() {
        if let Some(fixed) = mir.schedules.iter_mut().find(|s| s.label == "FixedUpdate") {
            let mut merged = dispatch_leaves;
            merged.extend(std::mem::take(&mut fixed.nodes));
            fixed.nodes = merged;
        } else {
            mir.schedules.push(HirSchedule {
                label: "FixedUpdate".to_owned(),
                run_if: None,
                run_if_expr: None,
                nodes: dispatch_leaves,
            });
        }
    }
    Ok(())
}

fn compile_role_artifacts(
    mir: &MirModule,
    source_stem: &str,
    out_dir: &Path,
) -> Result<CompiledNetArtifacts, String> {
    if !has_role_restricted_systems(mir) {
        let mut role_mir = mir.clone();
        augment_mir_for_rpc_dispatch(&mut role_mir)?;
        let (aug_mir, dispatch) = augment_mir_for_sim_tests(&role_mir)?;
        let art = compile_module_to_dylib(
            &aug_mir,
            &JitCompileOptions {
                out_dir: out_dir.to_path_buf(),
                module_stem: format!("netsim_shared_{source_stem}"),
                opt_level: JitOptLevel::Speed,
            },
        )
        .map_err(|e| format!("JIT compile failed: {e}"))?;
        return Ok(CompiledNetArtifacts {
            server_mir: aug_mir.clone(),
            server_dispatch: dispatch.clone(),
            server_dylib: art.dylib_path.clone(),
            client_mir: aug_mir,
            client_dispatch: dispatch,
            client_dylib: art.dylib_path,
        });
    }

    let mut srv_raw = filter_mir_for_role(mir, NetWorldRole::Server);
    augment_mir_for_rpc_dispatch(&mut srv_raw)?;
    if let Err(errs) = verify_mir(&srv_raw) {
        let msg = errs
            .into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("server role MIR verification failed: {msg}"));
    }
    let (server_mir, server_dispatch) = augment_mir_for_sim_tests(&srv_raw)?;
    let srv_art = compile_module_to_dylib(
        &server_mir,
        &JitCompileOptions {
            out_dir: out_dir.to_path_buf(),
            module_stem: format!("netsim_srv_{source_stem}"),
            opt_level: JitOptLevel::Speed,
        },
    )
    .map_err(|e| format!("server JIT compile failed: {e}"))?;

    let mut cli_raw = filter_mir_for_role(mir, NetWorldRole::Client);
    augment_mir_for_rpc_dispatch(&mut cli_raw)?;
    if let Err(errs) = verify_mir(&cli_raw) {
        let msg = errs
            .into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(format!("client role MIR verification failed: {msg}"));
    }
    let (client_mir, client_dispatch) = augment_mir_for_sim_tests(&cli_raw)?;
    let cli_art = compile_module_to_dylib(
        &client_mir,
        &JitCompileOptions {
            out_dir: out_dir.to_path_buf(),
            module_stem: format!("netsim_cli_{source_stem}"),
            opt_level: JitOptLevel::Speed,
        },
    )
    .map_err(|e| format!("client JIT compile failed: {e}"))?;

    Ok(CompiledNetArtifacts {
        server_mir,
        server_dispatch,
        server_dylib: srv_art.dylib_path,
        client_mir,
        client_dispatch,
        client_dylib: cli_art.dylib_path,
    })
}

struct NetWorld {
    app: App,
    mod_id: ModId,
    ctrl_entity: Option<Entity>,
    ctrl_handle: Option<bamabi_sys::BamComponent>,
    named_entities: HashMap<String, Entity>,
    host_tx_cursor: MessageCursor<StrataNetPacket>,
    frames_simulated: u64,
    steady_state_allocs: usize,
}

impl NetWorld {
    fn spawn(
        mir: &MirModule,
        dispatch: &DispatchMetadata,
        dylib_path: &Path,
    ) -> Result<Self, String> {
        let mut app = App::new();
        app.init_schedule(Startup);
        app.init_schedule(PostStartup);
        app.init_schedule(FixedUpdate);
        app.edit_schedule(FixedUpdate, |s| {
            s.set_executor(SingleThreadedExecutor::new());
        });
        dispatch.schedule.init_on_app(&mut app);
        app.add_plugins(AbiModPlugin::with_error_policy(ModErrorPolicy::Quarantine));
        ensure_child_of_registered(app.world_mut());
        app.register_strata_net_transport()
            .map_err(|err| format!("failed registering strata net transport: {err:?}"))?;

        let mod_id = app
            .load_mod_with(dylib_path, LoadOptions::default())
            .map_err(|err| format!("bamabi_host failed loading compiled mod: {err}"))?;
        configure_dedicated_dispatch(&mut app, mir, mod_id, dispatch);

        app.world_mut().run_schedule(Startup);
        app.world_mut().run_schedule(PostStartup);
        if let Some(mut msgs) = app
            .world_mut()
            .get_resource_mut::<Messages<StrataNetPacket>>()
        {
            msgs.clear();
        }

        let (ctrl_entity, ctrl_handle) = if let Some(ref ctrl_layout) = dispatch.ctrl_layout {
            let entry =
                find_registry_component(app.world(), &mir.module_path, &ctrl_layout.canonical_name)
                    .ok_or_else(|| {
                        "internal error: __StrataSimCtrl not registered in ModRegistry".to_owned()
                    })?;
            let ent = app.world_mut().spawn_empty().id();
            let zero_bytes = vec![0u8; ctrl_layout.size];
            write_entity_pod_bytes(app.world_mut(), ent, entry.handle, &zero_bytes)
                .map_err(|err| format!("failed initializing __StrataSimCtrl entity: {err:?}"))?;
            (Some(ent), Some(entry.handle))
        } else {
            (None, None)
        };

        app.world_mut().schedule_scope(FixedUpdate, |w, sched| {
            let _ = sched.initialize(w);
        });

        let mut world = Self {
            app,
            mod_id,
            ctrl_entity,
            ctrl_handle,
            named_entities: HashMap::new(),
            host_tx_cursor: MessageCursor::default(),
            frames_simulated: 0,
            steady_state_allocs: 0,
        };

        world.with_runner(mir, dispatch, |r| r.preresolve_objects())?;
        Ok(world)
    }

    fn with_runner<T>(
        &mut self,
        mir: &MirModule,
        dispatch: &DispatchMetadata,
        f: impl FnOnce(&mut SimRunner<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        let named = std::mem::take(&mut self.named_entities);
        let mut runner = SimRunner {
            app: &mut self.app,
            mir,
            dispatch,
            mod_id: self.mod_id,
            ctrl_entity: self.ctrl_entity,
            ctrl_handle: self.ctrl_handle,
            named_entities: named,
            frames_simulated: self.frames_simulated,
            steady_state_allocs: self.steady_state_allocs,
            scopes: vec![HashMap::new()],
        };
        let res = f(&mut runner);
        self.named_entities = runner.named_entities;
        res
    }

    fn peak_cmd_bytes(&self) -> usize {
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

    fn check_mod_faults(&self) -> Result<(), String> {
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

    fn inject_inbound_packets(&mut self, packets: &[StrataNetPacket]) {
        if packets.is_empty() {
            return;
        }
        let mut msgs = self
            .app
            .world_mut()
            .resource_mut::<Messages<StrataNetPacket>>();
        for pkt in packets {
            msgs.write(*pkt);
        }
        // Advance host_tx_cursor past inbound RX packets so TX draining ignores them.
        for _ in self.host_tx_cursor.read(&msgs) {}
    }

    fn step_tick(&mut self) -> Result<Vec<StrataNetPacket>, String> {
        let is_steady = self.frames_simulated > 0;
        let region = Region::new(&INSTRUMENTED_SYSTEM);
        self.app.world_mut().run_schedule(FixedUpdate);
        let frame_allocs = region.change().allocations;
        if is_steady {
            self.steady_state_allocs += frame_allocs;
        }
        self.frames_simulated += 1;
        self.check_mod_faults()?;

        let mut msgs = self
            .app
            .world_mut()
            .resource_mut::<Messages<StrataNetPacket>>();
        let outbound: Vec<StrataNetPacket> = self.host_tx_cursor.read(&msgs).copied().collect();
        msgs.clear();
        Ok(outbound)
    }
}

struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_f64(&mut self) -> f64 {
        ((self.next_u64() >> 11) as f64) / ((1u64 << 53) as f64)
    }
}

#[derive(Clone)]
struct InFlightPacket {
    seq: u64,
    deliver_tick: u64,
    src: NetWorldTarget,
    dst: NetWorldTarget,
    packet: StrataNetPacket,
}

#[derive(Clone)]
struct RetryPacket {
    seq: u64,
    retry_tick: u64,
    src: NetWorldTarget,
    dst: NetWorldTarget,
    packet: StrataNetPacket,
}

#[derive(Clone)]
struct InFlightRemoval {
    seq: u64,
    deliver_tick: u64,
    dst: NetWorldTarget,
    s_ent_bits: u64,
    comp_canonical: String,
}

#[derive(Clone)]
struct RetryRemoval {
    seq: u64,
    retry_tick: u64,
    dst: NetWorldTarget,
    s_ent_bits: u64,
    comp_canonical: String,
}

struct SimulatedChannel {
    rng: SplitMix64,
    latency_ms: f64,
    jitter_ms: f64,
    loss: f64,
    current_tick: u64,
    next_seq: u64,
    next_rpc_seq: u32,
    in_flight: Vec<InFlightPacket>,
    retry_queue: Vec<RetryPacket>,
    in_flight_removals: Vec<InFlightRemoval>,
    retry_removals: Vec<RetryRemoval>,
    highest_state_seq: HashMap<(NetWorldTarget, NetWorldTarget, u8, u64, u64), u64>,
}

impl SimulatedChannel {
    fn new(latency_ms: f64, jitter_ms: f64, loss: f64, seed: u64) -> Self {
        Self {
            rng: SplitMix64(seed),
            latency_ms,
            jitter_ms,
            loss,
            current_tick: 0,
            next_seq: 1,
            next_rpc_seq: 1,
            in_flight: Vec::new(),
            retry_queue: Vec::new(),
            in_flight_removals: Vec::new(),
            retry_removals: Vec::new(),
            highest_state_seq: HashMap::new(),
        }
    }

    fn sample_delay_ticks(&mut self) -> u64 {
        if self.latency_ms <= 0.0 && self.jitter_ms <= 0.0 {
            return 0;
        }
        let jitter_offset = if self.jitter_ms > 0.0 {
            (self.rng.next_f64() * 2.0 - 1.0) * self.jitter_ms
        } else {
            0.0
        };
        let total_ms = (self.latency_ms + jitter_offset).max(0.0);
        (total_ms / SIM_TICK_MS).floor() as u64
    }

    fn should_deliver(&mut self) -> bool {
        if self.loss >= 1.0 {
            false
        } else if self.loss <= 0.0 {
            true
        } else {
            self.rng.next_f64() >= self.loss
        }
    }

    fn retransmit_delay_ticks(&self) -> u64 {
        ((self.latency_ms + self.jitter_ms) / SIM_TICK_MS)
            .ceil()
            .clamp(1.0, 3.0) as u64
    }

    fn enqueue(&mut self, src: NetWorldTarget, dst: NetWorldTarget, packet: StrataNetPacket) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.enqueue_attempt(seq, src, dst, packet);
    }

    fn enqueue_removal(&mut self, dst: NetWorldTarget, s_ent_bits: u64, comp_canonical: String) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.enqueue_removal_attempt(seq, dst, s_ent_bits, comp_canonical);
    }

    fn enqueue_removal_attempt(
        &mut self,
        seq: u64,
        dst: NetWorldTarget,
        s_ent_bits: u64,
        comp_canonical: String,
    ) {
        if self.should_deliver() {
            let delay = self.sample_delay_ticks();
            self.in_flight_removals.push(InFlightRemoval {
                seq,
                deliver_tick: self.current_tick + delay,
                dst,
                s_ent_bits,
                comp_canonical,
            });
        } else if self.loss < 1.0 {
            let retry_delay = self.retransmit_delay_ticks();
            self.retry_removals.push(RetryRemoval {
                seq,
                retry_tick: self.current_tick + retry_delay,
                dst,
                s_ent_bits,
                comp_canonical,
            });
        }
    }

    fn enqueue_attempt(
        &mut self,
        seq: u64,
        src: NetWorldTarget,
        dst: NetWorldTarget,
        packet: StrataNetPacket,
    ) {
        let reliable = (packet.flags & FLAG_IS_RELIABLE) != 0;
        if self.should_deliver() {
            let delay = self.sample_delay_ticks();
            self.in_flight.push(InFlightPacket {
                seq,
                deliver_tick: self.current_tick + delay,
                src,
                dst,
                packet,
            });
        } else if reliable && self.loss < 1.0 {
            let retry_delay = self.retransmit_delay_ticks();
            self.retry_queue.push(RetryPacket {
                seq,
                retry_tick: self.current_tick + retry_delay,
                src,
                dst,
                packet,
            });
        }
    }

    fn process_due_retries(&mut self) {
        let cur = self.current_tick;
        let mut remaining = Vec::with_capacity(self.retry_queue.len());
        let mut due = Vec::new();
        for item in self.retry_queue.drain(..) {
            if item.retry_tick <= cur {
                due.push(item);
            } else {
                remaining.push(item);
            }
        }
        self.retry_queue = remaining;
        for item in due {
            self.enqueue_attempt(item.seq, item.src, item.dst, item.packet);
        }

        let mut rem_removals = Vec::with_capacity(self.retry_removals.len());
        let mut due_removals = Vec::new();
        for item in self.retry_removals.drain(..) {
            if item.retry_tick <= cur {
                due_removals.push(item);
            } else {
                rem_removals.push(item);
            }
        }
        self.retry_removals = rem_removals;
        for item in due_removals {
            self.enqueue_removal_attempt(item.seq, item.dst, item.s_ent_bits, item.comp_canonical);
        }
    }

    fn take_due_packets(&mut self, dst: NetWorldTarget) -> Vec<(NetWorldTarget, StrataNetPacket)> {
        let cur = self.current_tick;
        let mut remaining = Vec::with_capacity(self.in_flight.len());
        let mut due = Vec::new();
        for item in self.in_flight.drain(..) {
            if item.dst == dst && item.deliver_tick <= cur {
                due.push(item);
            } else {
                remaining.push(item);
            }
        }
        self.in_flight = remaining;

        due.sort_by_key(|p| p.seq);

        let mut out = Vec::with_capacity(due.len());
        for item in due {
            let is_state_snapshot = matches!(
                item.packet.kind,
                PACKET_KIND_COMPONENT_DELTA | PACKET_KIND_RESOURCE_DELTA
            );
            if is_state_snapshot {
                let key = (
                    item.src,
                    dst,
                    item.packet.kind,
                    item.packet.target_id,
                    item.packet.entity_bits,
                );
                let prev = self.highest_state_seq.get(&key).copied().unwrap_or(0);
                if item.seq < prev {
                    continue;
                }
                self.highest_state_seq.insert(key, item.seq);
            }
            out.push((item.src, item.packet));
        }
        out
    }

    fn take_due_removals(&mut self, dst: NetWorldTarget) -> Vec<InFlightRemoval> {
        let cur = self.current_tick;
        let mut remaining = Vec::with_capacity(self.in_flight_removals.len());
        let mut due = Vec::new();
        for item in self.in_flight_removals.drain(..) {
            if item.dst == dst && item.deliver_tick <= cur {
                due.push(item);
            } else {
                remaining.push(item);
            }
        }
        self.in_flight_removals = remaining;
        due.sort_by_key(|r| r.seq);
        due
    }
}

#[derive(Debug, Clone)]
enum NetSimVal {
    Plain(SimVal),
    NamedObject(String),
    Entity {
        world: NetWorldTarget,
        entity: Option<Entity>,
    },
    QueryHit {
        world: NetWorldTarget,
        entity: Entity,
        terms: Vec<HirQueryTerm>,
    },
    OptionHit(Option<Box<NetSimVal>>),
    ComponentRef {
        world: NetWorldTarget,
        entity: Entity,
        layout_key: String,
        sub_path: Vec<String>,
    },
    ResourceRef {
        world: NetWorldTarget,
        resource: String,
        sub_path: Vec<String>,
    },
}

enum NetFlow {
    Normal,
    Return(NetSimVal),
    Break,
    Continue,
}

fn net_val_to_sim_val(val: &NetSimVal) -> Result<SimVal, String> {
    match val {
        NetSimVal::Plain(s) => Ok(s.clone()),
        NetSimVal::Entity { entity, .. } => Ok(SimVal::Entity(*entity)),
        NetSimVal::ComponentRef {
            entity,
            layout_key,
            sub_path,
            ..
        } => Ok(SimVal::ComponentRef {
            entity: *entity,
            layout_key: layout_key.clone(),
            sub_path: sub_path.clone(),
        }),
        NetSimVal::ResourceRef {
            resource, sub_path, ..
        } => Ok(SimVal::ResourceRef {
            resource: resource.clone(),
            sub_path: sub_path.clone(),
        }),
        NetSimVal::QueryHit { entity, terms, .. } => Ok(SimVal::QueryHit {
            entity: *entity,
            terms: terms.clone(),
        }),
        NetSimVal::OptionHit(opt) => match opt {
            Some(inner) => Ok(SimVal::OptionHit(Some(Box::new(net_val_to_sim_val(
                inner,
            )?)))),
            None => Ok(SimVal::OptionHit(None)),
        },
        NetSimVal::NamedObject(name) => Err(format!(
            "named object `{name}` cannot be converted to plain SimVal without world target"
        )),
    }
}

fn sim_val_to_net_val(val: SimVal, world: NetWorldTarget) -> NetSimVal {
    match val {
        SimVal::Entity(entity) => NetSimVal::Entity { world, entity },
        SimVal::ComponentRef {
            entity,
            layout_key,
            sub_path,
        } => NetSimVal::ComponentRef {
            world,
            entity,
            layout_key,
            sub_path,
        },
        SimVal::ResourceRef { resource, sub_path } => NetSimVal::ResourceRef {
            world,
            resource,
            sub_path,
        },
        SimVal::QueryHit { entity, terms } => NetSimVal::QueryHit {
            world,
            entity,
            terms,
        },
        SimVal::OptionHit(opt) => {
            NetSimVal::OptionHit(opt.map(|inner| Box::new(sim_val_to_net_val(*inner, world))))
        }
        other => NetSimVal::Plain(other),
    }
}

struct NetSimRunner<'a> {
    base_mir: &'a MirModule,
    artifacts: &'a CompiledNetArtifacts,
    server: NetWorld,
    clients: Vec<NetWorld>,
    s_to_c: Vec<HashMap<u64, u64>>,
    c_to_s: Vec<HashMap<u64, u64>>,
    net_comps_by_id: HashMap<u64, &'a MirNetComponent>,
    rpcs_by_id: HashMap<u64, &'a MirRpc>,
    rpc_slot_indices: HashMap<u64, usize>,
    known_server_replicated: HashSet<(u64, String)>,
    clients_initialized: bool,
    channel: SimulatedChannel,
    scopes: Vec<HashMap<String, NetSimVal>>,
}

impl<'a> NetSimRunner<'a> {
    fn new(
        base_mir: &'a MirModule,
        artifacts: &'a CompiledNetArtifacts,
        latency_ms: f64,
        jitter_ms: f64,
        loss: f64,
        seed: u64,
        initial_clients: u32,
    ) -> Result<Self, String> {
        let server = NetWorld::spawn(
            &artifacts.server_mir,
            &artifacts.server_dispatch,
            &artifacts.server_dylib,
        )?;

        let mut net_comps_by_id = HashMap::new();
        for nc in &base_mir.net_components {
            net_comps_by_id.insert(fnv1a_64_str(&nc.canonical_name), nc);
        }
        let mut rpcs_by_id = HashMap::new();
        let mut rpc_slot_indices = HashMap::new();
        for (ri, rpc) in base_mir.rpcs.iter().enumerate() {
            rpcs_by_id.insert(rpc.rpc_id, rpc);
            rpc_slot_indices.insert(rpc.rpc_id, ri);
        }

        let mut runner = Self {
            base_mir,
            artifacts,
            server,
            clients: Vec::new(),
            s_to_c: Vec::new(),
            c_to_s: Vec::new(),
            net_comps_by_id,
            rpcs_by_id,
            rpc_slot_indices,
            known_server_replicated: HashSet::new(),
            clients_initialized: false,
            channel: SimulatedChannel::new(latency_ms, jitter_ms, loss, seed),
            scopes: vec![HashMap::new()],
        };
        runner.ensure_clients(initial_clients as usize)?;
        runner.clients_initialized = true;
        runner.known_server_replicated = runner.collect_server_replicated_pairs();
        Ok(runner)
    }

    fn is_server_replicated_nc(nc: &MirNetComponent) -> bool {
        nc.is_replicated
            && !nc.is_predicted
            && matches!(
                nc.authority,
                AuthorityKind::Server | AuthorityKind::Shared | AuthorityKind::Unspecified
            )
    }

    fn is_client_replicated_nc(nc: &MirNetComponent) -> bool {
        nc.is_replicated
            && (nc.is_predicted
                || matches!(
                    nc.authority,
                    AuthorityKind::Client | AuthorityKind::Predicted | AuthorityKind::Shared
                ))
    }

    fn collect_server_replicated_pairs(&mut self) -> HashSet<(u64, String)> {
        let mut pairs = HashSet::new();
        let mut comps = Vec::new();
        for nc in &self.base_mir.net_components {
            if !nc.is_resource
                && Self::is_server_replicated_nc(nc)
                && let Some(reg) = find_registry_component(
                    self.server.app.world(),
                    &self.base_mir.module_path,
                    &nc.canonical_name,
                )
            {
                comps.push((nc.canonical_name.clone(), reg.component_id));
            }
        }
        if comps.is_empty() {
            return pairs;
        }
        let world = self.server.app.world_mut();
        let entities: Vec<Entity> = {
            let mut q = world.query::<Entity>();
            q.iter(world).collect()
        };
        for ent in entities {
            if let Ok(er) = world.get_entity(ent) {
                for (cname, cid) in &comps {
                    if er.contains_id(*cid) {
                        pairs.insert((ent.to_bits(), cname.clone()));
                    }
                }
            }
        }
        pairs
    }

    fn reconcile_server_removals(&mut self) {
        let current = self.collect_server_replicated_pairs();
        let mut removed: Vec<(u64, String)> = self
            .known_server_replicated
            .difference(&current)
            .cloned()
            .collect();
        removed.sort();
        for (s_ent_bits, comp_canonical) in removed {
            for cid in 0..self.clients.len() {
                self.channel.enqueue_removal(
                    NetWorldTarget::Client(cid),
                    s_ent_bits,
                    comp_canonical.clone(),
                );
            }
        }
        self.known_server_replicated = current;
    }

    fn encode_net_component_packet(
        &mut self,
        nc: &MirNetComponent,
        s_ent: Option<Entity>,
        cid: usize,
    ) -> Result<StrataNetPacket, String> {
        if nc.packed_bytes as usize > STRATA_NET_MAX_PAYLOAD_BYTES {
            return Err(format!(
                "component `{}` payload ({} bytes) exceeds max packet size ({} bytes)",
                nc.name, nc.packed_bytes, STRATA_NET_MAX_PAYLOAD_BYTES
            ));
        }
        let layout = find_layout_in_slice(
            &self.base_mir.layouts,
            &self.base_mir.module_path,
            &nc.canonical_name,
        )
        .cloned();
        let mut payload = [0u8; STRATA_NET_MAX_PAYLOAD_BYTES];
        for wf in &nc.wire_fields {
            let target_comp = wf.stratum_layout.as_deref().unwrap_or(&nc.canonical_name);
            let seg: Vec<String> = wf.field_name.split('.').map(str::to_owned).collect();
            let sv = self.with_target_runner(NetWorldTarget::Server, |r| {
                if nc.is_resource {
                    r.read_resource_field(target_comp, &seg)
                } else {
                    let ent = s_ent.ok_or_else(|| {
                        format!(
                            "missing server entity for component `{}`",
                            nc.canonical_name
                        )
                    })?;
                    r.read_component_field(ent, target_comp, &seg)
                }
            })?;
            let field_ty = layout
                .as_ref()
                .and_then(|l| resolve_layout_field_ty(self.base_mir, l, &seg))
                .unwrap_or_else(|| mir_type_to_ty(&wf.ty));
            pack_wire_field_value(wf, Some(&sv), &field_ty, self.base_mir, &mut payload)?;
        }
        let mut flags = FLAG_IS_RELIABLE;
        if nc.is_resource {
            flags |= FLAG_IS_RESOURCE;
        }
        if nc.is_predicted || nc.authority == AuthorityKind::Predicted {
            flags |= FLAG_IS_PREDICTED;
        }
        Ok(StrataNetPacket {
            module_net_fingerprint: self.base_mir.net_handshake.module_net_fingerprint,
            item_schema_fingerprint: nc.schema_fingerprint,
            target_id: fnv1a_64_str(&nc.canonical_name),
            entity_bits: s_ent.map_or(0, |e| e.to_bits()),
            magic: STRATA_NET_PACKET_MAGIC,
            tick_or_seq: self.server.frames_simulated as u32,
            version: STRATA_NET_WIRE_VERSION,
            payload_bits: nc.packed_bits as u16,
            flags,
            kind: if nc.is_resource {
                PACKET_KIND_RESOURCE_DELTA
            } else {
                PACKET_KIND_COMPONENT_DELTA
            },
            channel: nc.channel,
            payload_bytes: nc.packed_bytes as u8,
            client_id: cid as u8,
            _pad: [0; 6],
            payload,
        })
    }

    fn send_baseline_state_to_client(&mut self, cid: usize) -> Result<(), String> {
        let server_ncs: Vec<MirNetComponent> = self
            .base_mir
            .net_components
            .iter()
            .filter(|nc| Self::is_server_replicated_nc(nc))
            .cloned()
            .collect();
        for nc in &server_ncs {
            if nc.is_resource {
                let pkt = self.encode_net_component_packet(nc, None, cid)?;
                self.channel
                    .enqueue(NetWorldTarget::Server, NetWorldTarget::Client(cid), pkt);
                continue;
            }
            let Some(reg) = find_registry_component(
                self.server.app.world(),
                &self.base_mir.module_path,
                &nc.canonical_name,
            ) else {
                continue;
            };
            let world = self.server.app.world_mut();
            let matching_entities: Vec<Entity> = {
                let mut q = world.query::<Entity>();
                q.iter(world)
                    .filter(|&ent| {
                        world
                            .get_entity(ent)
                            .is_ok_and(|er| er.contains_id(reg.component_id))
                    })
                    .collect()
            };
            for ent in matching_entities {
                let pkt = self.encode_net_component_packet(nc, Some(ent), cid)?;
                self.channel
                    .enqueue(NetWorldTarget::Server, NetWorldTarget::Client(cid), pkt);
            }
        }
        Ok(())
    }

    fn ensure_clients(&mut self, count: usize) -> Result<(), String> {
        while self.clients.len() < count {
            let cid = self.clients.len();
            let client = NetWorld::spawn(
                &self.artifacts.client_mir,
                &self.artifacts.client_dispatch,
                &self.artifacts.client_dylib,
            )?;
            let mut s2c = HashMap::new();
            let mut c2s = HashMap::new();
            for obj in &self.base_mir.objects {
                if let (Some(&s_ent), Some(&c_ent)) = (
                    self.server.named_entities.get(&obj.name),
                    client.named_entities.get(&obj.name),
                ) {
                    s2c.insert(s_ent.to_bits(), c_ent.to_bits());
                    c2s.insert(c_ent.to_bits(), s_ent.to_bits());
                }
            }
            self.clients.push(client);
            self.s_to_c.push(s2c);
            self.c_to_s.push(c2s);
            if self.clients_initialized {
                self.send_baseline_state_to_client(cid)?;
            }
        }
        Ok(())
    }

    fn total_frames(&self) -> u64 {
        self.server.frames_simulated
    }

    fn peak_cmd_bytes(&self) -> usize {
        let mut peak = self.server.peak_cmd_bytes();
        for c in &self.clients {
            peak = peak.max(c.peak_cmd_bytes());
        }
        peak
    }

    fn steady_state_allocs(&self) -> usize {
        let mut total = self.server.steady_state_allocs;
        for c in &self.clients {
            total += c.steady_state_allocs;
        }
        total
    }

    fn world_mir_dispatch(&self, target: NetWorldTarget) -> (&MirModule, &DispatchMetadata) {
        match target {
            NetWorldTarget::Server => (&self.artifacts.server_mir, &self.artifacts.server_dispatch),
            NetWorldTarget::Client(_) => {
                (&self.artifacts.client_mir, &self.artifacts.client_dispatch)
            }
        }
    }

    fn with_target_runner<T>(
        &mut self,
        target: NetWorldTarget,
        f: impl FnOnce(&mut SimRunner<'_>) -> Result<T, String>,
    ) -> Result<T, String> {
        match target {
            NetWorldTarget::Server => self.server.with_runner(
                &self.artifacts.server_mir,
                &self.artifacts.server_dispatch,
                f,
            ),
            NetWorldTarget::Client(cid) => {
                let count = self.clients.len();
                let c = self
                    .clients
                    .get_mut(cid)
                    .ok_or_else(|| format!("client id `{cid}` out of range (count={count})"))?;
                c.with_runner(
                    &self.artifacts.client_mir,
                    &self.artifacts.client_dispatch,
                    f,
                )
            }
        }
    }

    fn resolve_entity_in_world(
        &mut self,
        target: NetWorldTarget,
        val: &NetSimVal,
    ) -> Result<Option<Entity>, String> {
        match val {
            NetSimVal::NamedObject(name) => {
                self.with_target_runner(target, |r| r.resolve_named_object_via_dispatch(name))
            }
            NetSimVal::Entity { world, entity } => {
                if *world == target {
                    Ok(*entity)
                } else if let (NetWorldTarget::Server, NetWorldTarget::Client(cid), Some(e)) =
                    (*world, target, *entity)
                {
                    Ok(self
                        .s_to_c
                        .get(cid)
                        .and_then(|m| m.get(&e.to_bits()))
                        .map(|&b| Entity::from_bits(b)))
                } else if let (NetWorldTarget::Client(cid), NetWorldTarget::Server, Some(e)) =
                    (*world, target, *entity)
                {
                    Ok(self
                        .c_to_s
                        .get(cid)
                        .and_then(|m| m.get(&e.to_bits()))
                        .map(|&b| Entity::from_bits(b)))
                } else {
                    Ok(None)
                }
            }
            NetSimVal::QueryHit { entity, .. } => Ok(Some(*entity)),
            other => Err(format!(
                "expected Entity or named object for `.on(target)`, got `{other:?}`"
            )),
        }
    }

    fn verify_and_translate_packet(
        &mut self,
        src: NetWorldTarget,
        dst: NetWorldTarget,
        mut pkt: StrataNetPacket,
    ) -> Option<StrataNetPacket> {
        if pkt.magic != STRATA_NET_PACKET_MAGIC || pkt.version != STRATA_NET_WIRE_VERSION {
            return None;
        }
        let expected_mod_fp = self.base_mir.net_handshake.module_net_fingerprint;
        if expected_mod_fp != 0
            && !verify_handshake_fingerprint(expected_mod_fp, pkt.module_net_fingerprint)
        {
            return None;
        }
        if pkt.kind == PACKET_KIND_COMPONENT_DELTA {
            let nc = *self.net_comps_by_id.get(&pkt.target_id)?;
            let nc_canon = nc.canonical_name.clone();
            let layout_size = find_layout_in_slice(
                &self.base_mir.layouts,
                &self.base_mir.module_path,
                &nc_canon,
            )
            .map_or(0, |l| l.size);
            match (src, dst) {
                (NetWorldTarget::Server, NetWorldTarget::Client(cid)) => {
                    if !Self::is_server_replicated_nc(nc) || cid >= self.clients.len() {
                        return None;
                    }
                    let c_ent = if let Some(&c_bits) =
                        self.s_to_c.get(cid).and_then(|m| m.get(&pkt.entity_bits))
                    {
                        let ent = Entity::from_bits(c_bits);
                        if self.clients[cid].app.world().get_entity(ent).is_ok() {
                            ent
                        } else {
                            let spawned = self.clients[cid].app.world_mut().spawn_empty().id();
                            self.s_to_c[cid].insert(pkt.entity_bits, spawned.to_bits());
                            self.c_to_s[cid].insert(spawned.to_bits(), pkt.entity_bits);
                            spawned
                        }
                    } else {
                        let spawned = self.clients[cid].app.world_mut().spawn_empty().id();
                        self.s_to_c[cid].insert(pkt.entity_bits, spawned.to_bits());
                        self.c_to_s[cid].insert(spawned.to_bits(), pkt.entity_bits);
                        spawned
                    };
                    if let Some(reg) = find_registry_component(
                        self.clients[cid].app.world(),
                        &self.base_mir.module_path,
                        &nc_canon,
                    ) {
                        let has_comp = self.clients[cid]
                            .app
                            .world()
                            .get_entity(c_ent)
                            .is_ok_and(|er| er.contains_id(reg.component_id));
                        if !has_comp && reg.is_abi_pod {
                            let _ = write_entity_pod_bytes(
                                self.clients[cid].app.world_mut(),
                                c_ent,
                                reg.handle,
                                &vec![0u8; layout_size],
                            );
                        }
                    }
                    pkt.entity_bits = c_ent.to_bits();
                }
                (NetWorldTarget::Client(cid), NetWorldTarget::Server) => {
                    if !Self::is_client_replicated_nc(nc) || cid >= self.clients.len() {
                        return None;
                    }
                    let s_ent = if let Some(&s_bits) =
                        self.c_to_s.get(cid).and_then(|m| m.get(&pkt.entity_bits))
                    {
                        let ent = Entity::from_bits(s_bits);
                        if self.server.app.world().get_entity(ent).is_ok() {
                            ent
                        } else {
                            let spawned = self.server.app.world_mut().spawn_empty().id();
                            self.c_to_s[cid].insert(pkt.entity_bits, spawned.to_bits());
                            self.s_to_c[cid].insert(spawned.to_bits(), pkt.entity_bits);
                            spawned
                        }
                    } else {
                        let spawned = self.server.app.world_mut().spawn_empty().id();
                        self.c_to_s[cid].insert(pkt.entity_bits, spawned.to_bits());
                        self.s_to_c[cid].insert(spawned.to_bits(), pkt.entity_bits);
                        spawned
                    };
                    if let Some(reg) = find_registry_component(
                        self.server.app.world(),
                        &self.base_mir.module_path,
                        &nc_canon,
                    ) {
                        let has_comp = self
                            .server
                            .app
                            .world()
                            .get_entity(s_ent)
                            .is_ok_and(|er| er.contains_id(reg.component_id));
                        if !has_comp && reg.is_abi_pod {
                            let _ = write_entity_pod_bytes(
                                self.server.app.world_mut(),
                                s_ent,
                                reg.handle,
                                &vec![0u8; layout_size],
                            );
                        }
                    }
                    pkt.entity_bits = s_ent.to_bits();
                }
                _ => return None,
            }
        } else if pkt.kind == PACKET_KIND_RPC {
            let rpc = *self.rpcs_by_id.get(&pkt.target_id)?;
            if !verify_handshake_fingerprint(rpc.schema_fingerprint, pkt.item_schema_fingerprint) {
                return None;
            }
            let dir_ok = matches!(
                (src, dst, rpc.direction),
                (
                    NetWorldTarget::Client(_),
                    NetWorldTarget::Server,
                    NetDirection::ClientToServer | NetDirection::Bidirectional,
                ) | (
                    NetWorldTarget::Server,
                    NetWorldTarget::Client(_),
                    NetDirection::ServerToClient | NetDirection::Bidirectional,
                )
            );
            if !dir_ok {
                return None;
            }
        }
        Some(pkt)
    }

    fn apply_due_removal(&mut self, cid: usize, s_ent_bits: u64, comp_canonical: &str) {
        if cid >= self.clients.len() {
            return;
        }
        let Some(&c_bits) = self.s_to_c.get(cid).and_then(|m| m.get(&s_ent_bits)) else {
            return;
        };
        let c_ent = Entity::from_bits(c_bits);
        if let Some(reg) = find_registry_component(
            self.clients[cid].app.world(),
            &self.base_mir.module_path,
            comp_canonical,
        ) && let Ok(mut em) = self.clients[cid].app.world_mut().get_entity_mut(c_ent)
        {
            em.remove_by_id(reg.component_id);
        }

        let s_alive = self
            .server
            .app
            .world()
            .get_entity(Entity::from_bits(s_ent_bits))
            .is_ok();
        let is_static_object = self.base_mir.objects.iter().any(|o| {
            self.server
                .named_entities
                .get(&o.name)
                .is_some_and(|e| e.to_bits() == s_ent_bits)
        });
        if !s_alive && !is_static_object {
            let mut has_remaining_replicated = false;
            for nc in &self.base_mir.net_components {
                if !nc.is_resource
                    && Self::is_server_replicated_nc(nc)
                    && let Some(reg) = find_registry_component(
                        self.clients[cid].app.world(),
                        &self.base_mir.module_path,
                        &nc.canonical_name,
                    )
                    && self.clients[cid]
                        .app
                        .world()
                        .get_entity(c_ent)
                        .is_ok_and(|er| er.contains_id(reg.component_id))
                {
                    has_remaining_replicated = true;
                    break;
                }
            }
            if !has_remaining_replicated {
                let _ = self.clients[cid].app.world_mut().despawn(c_ent);
                self.s_to_c[cid].remove(&s_ent_bits);
                self.c_to_s[cid].remove(&c_bits);
            }
        }
    }

    fn inject_rpc_dispatch_slot(&mut self, dst: NetWorldTarget, pkt: &StrataNetPacket) {
        let Some(&rpc) = self.rpcs_by_id.get(&pkt.target_id) else {
            return;
        };
        let Some(&slot_idx) = self.rpc_slot_indices.get(&pkt.target_id) else {
            return;
        };
        let slot_short = rpc_slot_name(slot_idx);
        let slot_canon = if self.base_mir.module_path.is_empty() {
            slot_short
        } else {
            format!("{}::{slot_short}", self.base_mir.module_path)
        };
        let rpc_mir = match dst {
            NetWorldTarget::Server => &self.artifacts.server_mir,
            NetWorldTarget::Client(_) => &self.artifacts.client_mir,
        };
        let Some(slot_layout) =
            find_layout_in_slice(&rpc_mir.layouts, &rpc_mir.module_path, &slot_canon).cloned()
        else {
            return;
        };
        let mut slot_bytes = vec![0u8; slot_layout.size];
        let payload_off = slot_layout
            .fields
            .iter()
            .find(|f| f.name == "payload")
            .map_or(0, |f| f.offset);
        if slot_bytes.len() >= 4 {
            slot_bytes[0..4].copy_from_slice(&pkt.tick_or_seq.to_le_bytes());
        }
        let rpc_layout = find_layout_in_slice(
            &self.world_mir_dispatch(dst).0.layouts,
            &self.base_mir.module_path,
            &rpc.canonical_name,
        )
        .or_else(|| {
            find_layout_in_slice(
                &self.base_mir.layouts,
                &self.base_mir.module_path,
                &rpc.canonical_name,
            )
        });
        for wf in &rpc.wire_fields {
            if let Some(ref q) = wf.quantize {
                let seg: Vec<String> = wf.field_name.split('.').map(str::to_owned).collect();
                let mut f_off = wf.byte_offset as usize;
                let mut f_ty = mir_type_to_ty(&wf.ty);
                if let Some(rl) = rpc_layout
                    && let Some((resolved_off, resolved_ty)) =
                        resolve_layout_field_offset_ty(self.base_mir, rl, &seg)
                {
                    f_off = resolved_off;
                    f_ty = resolved_ty;
                }
                let val = if q.lane_count == 1 {
                    let raw = unpack_bits_le(&pkt.payload, wf.bit_offset, q.bits);
                    let f = dequantize_scalar_f64(raw, q.min, q.max, q.bits, q.step);
                    match &f_ty {
                        Ty::Bool => SimVal::Bool(f >= 0.5),
                        Ty::U8
                        | Ty::I8
                        | Ty::U16
                        | Ty::I16
                        | Ty::U32
                        | Ty::I32
                        | Ty::U64
                        | Ty::I64
                        | Ty::Sym
                        | Ty::Rgba8 => SimVal::Int(f.round() as i64),
                        _ => SimVal::Float(f),
                    }
                } else {
                    let mut vals = [0.0f64; 4];
                    for (li, slot) in vals
                        .iter_mut()
                        .enumerate()
                        .take(usize::from(q.lane_count).min(4))
                    {
                        let boff = wf.bit_offset + (li as u32) * u32::from(q.bits);
                        let raw = unpack_bits_le(&pkt.payload, boff, q.bits);
                        *slot = dequantize_scalar_f64(raw, q.min, q.max, q.bits, q.step);
                    }
                    match &f_ty {
                        Ty::IVec2 | Ty::IVec3 => SimVal::IVec(
                            [
                                vals[0].round() as i32,
                                vals[1].round() as i32,
                                vals[2].round() as i32,
                                vals[3].round() as i32,
                            ],
                            q.lane_count,
                        ),
                        Ty::UVec2 => SimVal::UVec(
                            [
                                vals[0].round().max(0.0) as u32,
                                vals[1].round().max(0.0) as u32,
                                vals[2].round().max(0.0) as u32,
                                vals[3].round().max(0.0) as u32,
                            ],
                            q.lane_count,
                        ),
                        _ => SimVal::Vec(
                            [
                                vals[0] as f32,
                                vals[1] as f32,
                                vals[2] as f32,
                                vals[3] as f32,
                            ],
                            q.lane_count,
                        ),
                    }
                };
                let _ = encode_ty_to_bytes_with_layouts(
                    &mut slot_bytes,
                    payload_off + f_off,
                    &f_ty,
                    &val,
                    &self.base_mir.enums,
                    &self.base_mir.layouts,
                    &self.base_mir.module_path,
                );
            } else if wf.byte_size > 0 {
                let dst_start = payload_off + wf.byte_offset as usize;
                let dst_end = dst_start + wf.byte_size as usize;
                if dst_end <= slot_bytes.len() {
                    for (bi, byte) in slot_bytes[dst_start..dst_end].iter_mut().enumerate() {
                        *byte =
                            unpack_bits_le(&pkt.payload, wf.bit_offset + (bi as u32) * 8, 8) as u8;
                    }
                }
            }
        }

        let target_world = match dst {
            NetWorldTarget::Server => &mut self.server,
            NetWorldTarget::Client(cid) => {
                let Some(c) = self.clients.get_mut(cid) else {
                    return;
                };
                c
            }
        };
        let Some(reg) = find_registry_component(
            target_world.app.world(),
            &self.base_mir.module_path,
            &slot_canon,
        ) else {
            return;
        };
        let ent = target_world.app.world_mut().spawn_empty().id();
        let _ = write_entity_pod_bytes(target_world.app.world_mut(), ent, reg.handle, &slot_bytes);
    }

    fn deliver_due_to(&mut self, dst: NetWorldTarget) {
        let due_removals = self.channel.take_due_removals(dst);
        if let NetWorldTarget::Client(cid) = dst {
            for rem in due_removals {
                self.apply_due_removal(cid, rem.s_ent_bits, &rem.comp_canonical);
            }
        }

        let due = self.channel.take_due_packets(dst);
        if due.is_empty() {
            return;
        }
        let mut translated = Vec::with_capacity(due.len());
        for (src, pkt) in due {
            if let Some(t) = self.verify_and_translate_packet(src, dst, pkt) {
                if t.kind == PACKET_KIND_RPC {
                    self.inject_rpc_dispatch_slot(dst, &t);
                }
                translated.push(t);
            }
        }
        if translated.is_empty() {
            return;
        }
        match dst {
            NetWorldTarget::Server => self.server.inject_inbound_packets(&translated),
            NetWorldTarget::Client(cid) => {
                if let Some(c) = self.clients.get_mut(cid) {
                    c.inject_inbound_packets(&translated);
                }
            }
        }
    }

    fn route_server_outbound(&mut self, packets: Vec<StrataNetPacket>) {
        for pkt in packets {
            match pkt.kind {
                PACKET_KIND_COMPONENT_DELTA | PACKET_KIND_RESOURCE_DELTA => {
                    let Some(nc) = self.net_comps_by_id.get(&pkt.target_id) else {
                        continue;
                    };
                    if !nc.is_replicated
                        || nc.is_predicted
                        || !matches!(
                            nc.authority,
                            AuthorityKind::Server
                                | AuthorityKind::Shared
                                | AuthorityKind::Unspecified
                        )
                    {
                        continue;
                    }
                    for cid in 0..self.clients.len() {
                        let mut p = pkt;
                        p.client_id = cid as u8;
                        self.channel.enqueue(
                            NetWorldTarget::Server,
                            NetWorldTarget::Client(cid),
                            p,
                        );
                    }
                }
                PACKET_KIND_RPC => {
                    let Some(rpc) = self.rpcs_by_id.get(&pkt.target_id) else {
                        continue;
                    };
                    if matches!(
                        rpc.direction,
                        NetDirection::ServerToClient | NetDirection::Bidirectional
                    ) {
                        let cid = usize::from(pkt.client_id);
                        if cid < self.clients.len() {
                            self.channel.enqueue(
                                NetWorldTarget::Server,
                                NetWorldTarget::Client(cid),
                                pkt,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn route_client_outbound(&mut self, cid: usize, packets: Vec<StrataNetPacket>) {
        for mut pkt in packets {
            pkt.client_id = cid as u8;
            match pkt.kind {
                PACKET_KIND_COMPONENT_DELTA | PACKET_KIND_RESOURCE_DELTA => {
                    let Some(nc) = self.net_comps_by_id.get(&pkt.target_id) else {
                        continue;
                    };
                    if !nc.is_replicated
                        || !(nc.is_predicted
                            || matches!(
                                nc.authority,
                                AuthorityKind::Client
                                    | AuthorityKind::Predicted
                                    | AuthorityKind::Shared
                            ))
                    {
                        continue;
                    }
                    self.channel
                        .enqueue(NetWorldTarget::Client(cid), NetWorldTarget::Server, pkt);
                }
                PACKET_KIND_RPC => {
                    let Some(rpc) = self.rpcs_by_id.get(&pkt.target_id) else {
                        continue;
                    };
                    if matches!(
                        rpc.direction,
                        NetDirection::ClientToServer | NetDirection::Bidirectional
                    ) {
                        self.channel.enqueue(
                            NetWorldTarget::Client(cid),
                            NetWorldTarget::Server,
                            pkt,
                        );
                    }
                }
                _ => {}
            }
        }
    }

    fn step_net(&mut self, count: u64) -> Result<(), String> {
        for _ in 0..count {
            self.channel.current_tick += 1;
            self.channel.process_due_retries();

            self.deliver_due_to(NetWorldTarget::Server);
            let srv_out = self.server.step_tick()?;
            self.reconcile_server_removals();
            self.route_server_outbound(srv_out);

            for cid in 0..self.clients.len() {
                self.deliver_due_to(NetWorldTarget::Client(cid));
                let cli_out = self.clients[cid].step_tick()?;
                self.route_client_outbound(cid, cli_out);
            }
        }
        Ok(())
    }

    fn step_server_only(&mut self, count: u64) -> Result<(), String> {
        for _ in 0..count {
            self.channel.current_tick += 1;
            self.channel.process_due_retries();
            self.deliver_due_to(NetWorldTarget::Server);
            let srv_out = self.server.step_tick()?;
            self.reconcile_server_removals();
            self.route_server_outbound(srv_out);
        }
        Ok(())
    }

    fn step_client_only(&mut self, cid: usize, count: u64) -> Result<(), String> {
        if cid >= self.clients.len() {
            return Err(format!(
                "client id `{cid}` out of range (count={})",
                self.clients.len()
            ));
        }
        for _ in 0..count {
            self.channel.current_tick += 1;
            self.channel.process_due_retries();
            self.deliver_due_to(NetWorldTarget::Client(cid));
            let cli_out = self.clients[cid].step_tick()?;
            self.route_client_outbound(cid, cli_out);
        }
        Ok(())
    }

    fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    fn pop_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    fn bind_var(&mut self, name: &str, val: NetSimVal) {
        if let Some(top) = self.scopes.last_mut() {
            top.insert(name.to_owned(), val);
        }
    }

    fn update_var(&mut self, name: &str, val: NetSimVal) -> bool {
        for frame in self.scopes.iter_mut().rev() {
            if frame.contains_key(name) {
                frame.insert(name.to_owned(), val);
                return true;
            }
        }
        false
    }

    fn get_var(&self, name: &str) -> Option<&NetSimVal> {
        for frame in self.scopes.iter().rev() {
            if let Some(v) = frame.get(name) {
                return Some(v);
            }
        }
        None
    }

    fn exec_stmts(&mut self, stmts: &[HirStmt]) -> Result<NetFlow, String> {
        for stmt in stmts {
            match self.exec_stmt(stmt)? {
                NetFlow::Normal => {}
                other => return Ok(other),
            }
        }
        Ok(NetFlow::Normal)
    }

    fn exec_stmt(&mut self, stmt: &HirStmt) -> Result<NetFlow, String> {
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
                Ok(NetFlow::Normal)
            }
            HirStmt::Assign { target, op, value } => {
                let rhs = self.eval_expr(value)?;
                self.assign_lvalue(target, *op, rhs)?;
                Ok(NetFlow::Normal)
            }
            HirStmt::Expr(expr) => {
                let _ = self.eval_expr(expr)?;
                Ok(NetFlow::Normal)
            }
            HirStmt::Return(opt) => {
                let v = match opt {
                    Some(e) => self.eval_expr(e)?,
                    None => NetSimVal::Plain(SimVal::Unit),
                };
                Ok(NetFlow::Return(v))
            }
            HirStmt::Break(opt) => {
                if let Some(e) = opt {
                    let _ = self.eval_expr(e)?;
                }
                Ok(NetFlow::Break)
            }
            HirStmt::Continue => Ok(NetFlow::Continue),
            HirStmt::While { cond, body } => {
                loop {
                    let c = net_val_to_sim_val(&self.eval_expr(cond)?)?;
                    if !as_bool(&c)? {
                        break;
                    }
                    self.push_scope();
                    let flow = self.exec_stmts(body)?;
                    self.pop_scope();
                    match flow {
                        NetFlow::Normal | NetFlow::Continue => {}
                        NetFlow::Break => break,
                        NetFlow::Return(v) => return Ok(NetFlow::Return(v)),
                    }
                }
                Ok(NetFlow::Normal)
            }
            HirStmt::Loop { body } => {
                loop {
                    self.push_scope();
                    let flow = self.exec_stmts(body)?;
                    self.pop_scope();
                    match flow {
                        NetFlow::Normal | NetFlow::Continue => {}
                        NetFlow::Break => break,
                        NetFlow::Return(v) => return Ok(NetFlow::Return(v)),
                    }
                }
                Ok(NetFlow::Normal)
            }
            other => Err(format!(
                "unsupported statement in net_sim_test body: `{other:?}`"
            )),
        }
    }

    fn try_bind_pattern(&mut self, pat: &HirPattern, val: &NetSimVal) -> bool {
        match pat {
            HirPattern::Wildcard => true,
            HirPattern::Binding { name, .. } => {
                self.bind_var(name, val.clone());
                true
            }
            HirPattern::Tuple(pats) => {
                let NetSimVal::Plain(SimVal::Tuple(items)) = val else {
                    return false;
                };
                if pats.len() != items.len() {
                    return false;
                }
                for (p, item) in pats.iter().zip(items.iter()) {
                    if !self.try_bind_pattern(p, &NetSimVal::Plain(item.clone())) {
                        return false;
                    }
                }
                true
            }
            HirPattern::TupleStruct { path, fields } => {
                let short = bare_name(path);
                if short == "Some" {
                    if let NetSimVal::OptionHit(Some(inner)) = val {
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
                let short = bare_name(p);
                if short == "None" {
                    return matches!(val, NetSimVal::OptionHit(None));
                }
                if let (Ok(cval), Ok(sval)) = (
                    self.eval_path(p).and_then(|v| net_val_to_sim_val(&v)),
                    net_val_to_sim_val(val),
                ) {
                    return sim_val_eq(&sval, &cval);
                }
                false
            }
            HirPattern::Literal(expr) => {
                if let (Ok(lit), Ok(sval)) = (
                    self.eval_expr(expr).and_then(|v| net_val_to_sim_val(&v)),
                    net_val_to_sim_val(val),
                ) {
                    sim_val_eq(&sval, &lit)
                } else {
                    false
                }
            }
        }
    }

    fn eval_expr(&mut self, expr: &HirExpr) -> Result<NetSimVal, String> {
        match expr {
            HirExpr::IntLit { value, .. } => Ok(NetSimVal::Plain(SimVal::Int(*value))),
            HirExpr::FloatLit { value, .. } => Ok(NetSimVal::Plain(SimVal::Float(*value))),
            HirExpr::BoolLit(b) => Ok(NetSimVal::Plain(SimVal::Bool(*b))),
            HirExpr::StringLit(s) => Ok(NetSimVal::Plain(SimVal::String(s.clone()))),
            HirExpr::CharLit(c) => Ok(NetSimVal::Plain(SimVal::Int(i64::from(*c as u32)))),
            HirExpr::Path { name, .. } => self.eval_path(name),
            HirExpr::Unary { op, expr, .. } => {
                let v = self.eval_expr(expr)?;
                if matches!(op, HirUnOp::Ref | HirUnOp::RefMut) {
                    return Ok(v);
                }
                Ok(NetSimVal::Plain(eval_unary(*op, net_val_to_sim_val(&v)?)?))
            }
            HirExpr::Binary { op, lhs, rhs, .. } => self.eval_binary(*op, lhs, rhs),
            HirExpr::Cast { expr, target_ty } => {
                let v = net_val_to_sim_val(&self.eval_expr(expr)?)?;
                Ok(NetSimVal::Plain(eval_cast(v, target_ty)?))
            }
            HirExpr::Field { base, field, .. } => {
                let b = self.eval_expr(base)?;
                self.read_field_on_val(b, field)
            }
            HirExpr::Index { base, index, .. } => {
                let b = net_val_to_sim_val(&self.eval_expr(base)?)?;
                let idx = as_int(&net_val_to_sim_val(&self.eval_expr(index)?)?)?;
                match b {
                    SimVal::Array(elems) => {
                        let ui = usize::try_from(idx)
                            .map_err(|_| format!("negative array index `{idx}`"))?;
                        elems
                            .get(ui)
                            .cloned()
                            .map(NetSimVal::Plain)
                            .ok_or_else(|| format!("array index `{ui}` out of bounds"))
                    }
                    other => Err(format!("cannot index value `{other:?}`")),
                }
            }
            HirExpr::Call(call) => self.eval_call(call),
            HirExpr::Tuple { elems, .. } => {
                if elems.is_empty() {
                    return Ok(NetSimVal::Plain(SimVal::Unit));
                }
                let mut out = Vec::with_capacity(elems.len());
                for e in elems {
                    out.push(net_val_to_sim_val(&self.eval_expr(e)?)?);
                }
                Ok(NetSimVal::Plain(SimVal::Tuple(out)))
            }
            HirExpr::ArrayLit { elems, .. } => {
                let mut out = Vec::with_capacity(elems.len());
                for e in elems {
                    out.push(net_val_to_sim_val(&self.eval_expr(e)?)?);
                }
                Ok(NetSimVal::Plain(SimVal::Array(out)))
            }
            HirExpr::StructLit { name, fields, .. } => {
                let mut out = Vec::with_capacity(fields.len());
                for (fname, fexpr) in fields {
                    out.push((fname.clone(), net_val_to_sim_val(&self.eval_expr(fexpr)?)?));
                }
                Ok(NetSimVal::Plain(SimVal::Struct {
                    _name: name.clone(),
                    fields: out,
                }))
            }
            HirExpr::Block { stmts, tail, .. } => {
                self.push_scope();
                let flow = self.exec_stmts(stmts)?;
                let res = match flow {
                    NetFlow::Normal => match tail {
                        Some(t) => self.eval_expr(t),
                        None => Ok(NetSimVal::Plain(SimVal::Unit)),
                    },
                    NetFlow::Return(v) => Ok(v),
                    NetFlow::Break | NetFlow::Continue => {
                        Err("unexpected break/continue".to_owned())
                    }
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
                    let c = as_bool(&net_val_to_sim_val(&self.eval_expr(cond)?)?)?;
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
                            as_bool(&net_val_to_sim_val(&self.eval_expr(g)?)?)?
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
                Err("non-exhaustive match in net_sim_test".to_owned())
            }
            other => Err(format!(
                "unsupported expression in net_sim_test body: `{other:?}`"
            )),
        }
    }

    fn exec_block_parts(
        &mut self,
        stmts: &[HirStmt],
        tail: Option<&HirExpr>,
    ) -> Result<NetSimVal, String> {
        match self.exec_stmts(stmts)? {
            NetFlow::Normal => match tail {
                Some(t) => self.eval_expr(t),
                None => Ok(NetSimVal::Plain(SimVal::Unit)),
            },
            NetFlow::Return(v) => Ok(v),
            NetFlow::Break | NetFlow::Continue => {
                Err("unexpected break/continue in block".to_owned())
            }
        }
    }

    fn eval_for(&mut self, hf: &HirFor) -> Result<NetSimVal, String> {
        match &hf.iter {
            HirForIter::Range {
                start,
                end,
                inclusive,
            } => {
                let s = as_int(&net_val_to_sim_val(&self.eval_expr(start)?)?)?;
                let e = as_int(&net_val_to_sim_val(&self.eval_expr(end)?)?)?;
                let end_val = if *inclusive { e + 1 } else { e };
                for i in s..end_val {
                    self.push_scope();
                    self.try_bind_pattern(&hf.binding, &NetSimVal::Plain(SimVal::Int(i)));
                    let flow = self.exec_stmts(&hf.body)?;
                    self.pop_scope();
                    match flow {
                        NetFlow::Normal | NetFlow::Continue => {}
                        NetFlow::Break => break,
                        NetFlow::Return(v) => return Ok(v),
                    }
                }
                Ok(NetSimVal::Plain(SimVal::Unit))
            }
            HirForIter::Expr(iter_expr) => {
                if let Some((target, q, _)) = self.try_parse_net_query_chain(iter_expr)? {
                    let entities =
                        self.with_target_runner(target, |r| r.collect_matching_entities(&q))?;
                    for ent in entities {
                        let hit = NetSimVal::QueryHit {
                            world: target,
                            entity: ent,
                            terms: q.terms.clone(),
                        };
                        self.push_scope();
                        self.try_bind_pattern(&hf.binding, &hit);
                        let flow = self.exec_stmts(&hf.body)?;
                        self.pop_scope();
                        match flow {
                            NetFlow::Normal | NetFlow::Continue => {}
                            NetFlow::Break => break,
                            NetFlow::Return(v) => return Ok(v),
                        }
                    }
                    return Ok(NetSimVal::Plain(SimVal::Unit));
                }
                Err(format!(
                    "unsupported `for` iterator expression in net_sim_test: `{iter_expr:?}`"
                ))
            }
            other => Err(format!(
                "unsupported `for` iterator in net_sim_test: `{other:?}`"
            )),
        }
    }

    fn eval_path(&mut self, name: &str) -> Result<NetSimVal, String> {
        if let Some(v) = self.get_var(name) {
            return Ok(v.clone());
        }
        match name {
            "vec2::ZERO" => return Ok(NetSimVal::Plain(SimVal::Vec([0.0, 0.0, 0.0, 0.0], 2))),
            "vec2::ONE" => return Ok(NetSimVal::Plain(SimVal::Vec([1.0, 1.0, 0.0, 0.0], 2))),
            "vec2::X" => return Ok(NetSimVal::Plain(SimVal::Vec([1.0, 0.0, 0.0, 0.0], 2))),
            "vec2::Y" => return Ok(NetSimVal::Plain(SimVal::Vec([0.0, 1.0, 0.0, 0.0], 2))),
            "vec3::ZERO" => return Ok(NetSimVal::Plain(SimVal::Vec([0.0, 0.0, 0.0, 0.0], 3))),
            "vec3::ONE" => return Ok(NetSimVal::Plain(SimVal::Vec([1.0, 1.0, 1.0, 0.0], 3))),
            "vec3::X" => return Ok(NetSimVal::Plain(SimVal::Vec([1.0, 0.0, 0.0, 0.0], 3))),
            "vec3::Y" | "vec3::UP" => {
                return Ok(NetSimVal::Plain(SimVal::Vec([0.0, 1.0, 0.0, 0.0], 3)));
            }
            "vec3::Z" => return Ok(NetSimVal::Plain(SimVal::Vec([0.0, 0.0, 1.0, 0.0], 3))),
            "vec4::ZERO" => return Ok(NetSimVal::Plain(SimVal::Vec([0.0, 0.0, 0.0, 0.0], 4))),
            "vec4::ONE" => return Ok(NetSimVal::Plain(SimVal::Vec([1.0, 1.0, 1.0, 1.0], 4))),
            "vec4::X" => return Ok(NetSimVal::Plain(SimVal::Vec([1.0, 0.0, 0.0, 0.0], 4))),
            "vec4::Y" => return Ok(NetSimVal::Plain(SimVal::Vec([0.0, 1.0, 0.0, 0.0], 4))),
            "vec4::Z" => return Ok(NetSimVal::Plain(SimVal::Vec([0.0, 0.0, 1.0, 0.0], 4))),
            "vec4::W" => return Ok(NetSimVal::Plain(SimVal::Vec([0.0, 0.0, 0.0, 1.0], 4))),
            "ivec2::ZERO" => return Ok(NetSimVal::Plain(SimVal::IVec([0, 0, 0, 0], 2))),
            "ivec2::ONE" => return Ok(NetSimVal::Plain(SimVal::IVec([1, 1, 0, 0], 2))),
            "ivec2::X" => return Ok(NetSimVal::Plain(SimVal::IVec([1, 0, 0, 0], 2))),
            "ivec2::Y" => return Ok(NetSimVal::Plain(SimVal::IVec([0, 1, 0, 0], 2))),
            "ivec3::ZERO" => return Ok(NetSimVal::Plain(SimVal::IVec([0, 0, 0, 0], 3))),
            "ivec3::ONE" => return Ok(NetSimVal::Plain(SimVal::IVec([1, 1, 1, 0], 3))),
            "ivec3::X" => return Ok(NetSimVal::Plain(SimVal::IVec([1, 0, 0, 0], 3))),
            "ivec3::Y" => return Ok(NetSimVal::Plain(SimVal::IVec([0, 1, 0, 0], 3))),
            "ivec3::Z" => return Ok(NetSimVal::Plain(SimVal::IVec([0, 0, 1, 0], 3))),
            "uvec2::ZERO" => return Ok(NetSimVal::Plain(SimVal::UVec([0, 0, 0, 0], 2))),
            "uvec2::ONE" => return Ok(NetSimVal::Plain(SimVal::UVec([1, 1, 0, 0], 2))),
            "uvec2::X" => return Ok(NetSimVal::Plain(SimVal::UVec([1, 0, 0, 0], 2))),
            "uvec2::Y" => return Ok(NetSimVal::Plain(SimVal::UVec([0, 1, 0, 0], 2))),
            "None" | "Option::None" => return Ok(NetSimVal::OptionHit(None)),
            _ => {}
        }
        if let Some((ename, vname)) = name.rsplit_once("::") {
            let qual_enum = format!("{}::{ename}", self.base_mir.module_path);
            if let Some(ed) = self
                .base_mir
                .enums
                .iter()
                .find(|e| e.canonical_name == ename || e.canonical_name == qual_enum)
                && let Some(&(_, disc)) = ed.variants.iter().find(|(v, _)| v == vname)
            {
                return Ok(NetSimVal::Plain(SimVal::Int(disc)));
            }
        }
        if let Some(c) = self
            .base_mir
            .consts
            .iter()
            .find(|c| c.name == name)
            .cloned()
            && let Some(ref c_expr) = c.expr
        {
            return self.eval_expr(c_expr);
        }
        if self.base_mir.objects.iter().any(|o| o.name == name) {
            return Ok(NetSimVal::NamedObject(name.to_owned()));
        }
        Err(format!("unresolved path `{name}` in net_sim_test"))
    }

    fn eval_binary(
        &mut self,
        op: HirBinOp,
        lhs: &HirExpr,
        rhs: &HirExpr,
    ) -> Result<NetSimVal, String> {
        if op == HirBinOp::And {
            let l = as_bool(&net_val_to_sim_val(&self.eval_expr(lhs)?)?)?;
            if !l {
                return Ok(NetSimVal::Plain(SimVal::Bool(false)));
            }
            let r = as_bool(&net_val_to_sim_val(&self.eval_expr(rhs)?)?)?;
            return Ok(NetSimVal::Plain(SimVal::Bool(r)));
        }
        if op == HirBinOp::Or {
            let l = as_bool(&net_val_to_sim_val(&self.eval_expr(lhs)?)?)?;
            if l {
                return Ok(NetSimVal::Plain(SimVal::Bool(true)));
            }
            let r = as_bool(&net_val_to_sim_val(&self.eval_expr(rhs)?)?)?;
            return Ok(NetSimVal::Plain(SimVal::Bool(r)));
        }
        let lv = self.eval_expr(lhs)?;
        let rv = self.eval_expr(rhs)?;
        if matches!(op, HirBinOp::Eq | HirBinOp::Ne) {
            let eq = match (&lv, &rv) {
                (NetSimVal::NamedObject(n1), NetSimVal::NamedObject(n2)) => Some(n1 == n2),
                (NetSimVal::NamedObject(n), NetSimVal::Entity { world, entity })
                | (NetSimVal::Entity { world, entity }, NetSimVal::NamedObject(n)) => {
                    let resolved =
                        self.resolve_entity_in_world(*world, &NetSimVal::NamedObject(n.clone()))?;
                    Some(resolved == *entity)
                }
                _ => None,
            };
            if let Some(is_eq) = eq {
                return Ok(NetSimVal::Plain(SimVal::Bool(if op == HirBinOp::Eq {
                    is_eq
                } else {
                    !is_eq
                })));
            }
        }
        let ls = net_val_to_sim_val(&lv)?;
        let rs = net_val_to_sim_val(&rv)?;
        Ok(NetSimVal::Plain(eval_binop_vals(op, ls, rs)?))
    }

    fn try_parse_net_query_chain<'b>(
        &mut self,
        expr: &'b HirExpr,
    ) -> Result<Option<(NetWorldTarget, HirQuery, Option<&'b HirExpr>)>, String> {
        let mut chain: Vec<&HirCall> = Vec::new();
        let mut cur = expr;
        loop {
            let HirExpr::Call(c) = cur else {
                return Ok(None);
            };
            chain.push(c);
            if c.receiver.is_none() && matches!(c.callee.as_str(), "server_query" | "client_query")
            {
                break;
            }
            if matches!(
                c.callee.as_str(),
                "on" | "unwrap" | "with" | "without" | "changed" | "allow" | "has"
            ) && let Some(ref recv) = c.receiver
            {
                cur = recv.as_ref();
            } else {
                return Ok(None);
            }
        }

        let base = *chain.last().expect("non-empty chain");
        let (target, term_start_idx) = if base.callee == "server_query" {
            (NetWorldTarget::Server, 0usize)
        } else {
            let cid_expr = base
                .args
                .first()
                .ok_or_else(|| "client_query requires client_id as first argument".to_owned())?;
            let cid = as_int(&net_val_to_sim_val(&self.eval_expr(cid_expr)?)?)?;
            if cid < 0 || (cid as usize) >= self.clients.len() {
                return Err(format!(
                    "client_query client_id `{cid}` out of range (count={})",
                    self.clients.len()
                ));
            }
            (NetWorldTarget::Client(cid as usize), 1usize)
        };

        let mut terms = Vec::new();
        for (arg_name, arg) in base
            .arg_names
            .iter()
            .zip(base.args.iter())
            .skip(term_start_idx)
        {
            let Some(alias) = arg_name else { continue };
            let (mode, inner) = match arg {
                HirExpr::Unary {
                    op: HirUnOp::RefMut,
                    expr,
                    ..
                } => (TermAccessMode::Write, expr.as_ref()),
                HirExpr::Unary { expr, .. } => (TermAccessMode::Read, expr.as_ref()),
                other => (TermAccessMode::Read, other),
            };
            let (comp_name, field_name) = match inner {
                HirExpr::Path { name, .. } => (name.clone(), None),
                HirExpr::Field { base, field, .. } => {
                    let comp = match base.as_ref() {
                        HirExpr::Path { name, .. } => name.clone(),
                        _ => continue,
                    };
                    (comp, Some(field.clone()))
                }
                _ => continue,
            };
            let canonical_component = find_layout_in_slice(
                &self.base_mir.layouts,
                &self.base_mir.module_path,
                &comp_name,
            )
            .map_or_else(|| comp_name.clone(), |l| l.canonical_name.clone());
            terms.push(HirQueryTerm {
                alias: alias.clone(),
                storage_key: comp_name,
                canonical_component,
                field_name,
                mode,
                is_sparse: false,
            });
        }

        let mut with_filters = Vec::new();
        let mut without_filters = Vec::new();
        let mut allow_filters = Vec::new();
        let mut has_filters = Vec::new();
        let mut changed_filters = Vec::new();
        let mut on_target_expr: Option<&'b HirExpr> = None;
        let mut is_count = false;
        let mut is_unwrap = false;

        for c in chain.iter().rev().skip(1) {
            match c.callee.as_str() {
                "with" => with_filters.extend(c.generic_args.iter().cloned()),
                "without" => without_filters.extend(c.generic_args.iter().cloned()),
                "allow" => allow_filters.extend(c.generic_args.iter().cloned()),
                "has" => has_filters.extend(c.generic_args.iter().cloned()),
                "changed" => {
                    if c.generic_args.is_empty() {
                        for t in &terms {
                            if !changed_filters.contains(&t.storage_key) {
                                changed_filters.push(t.storage_key.clone());
                            }
                        }
                    } else {
                        changed_filters.extend(c.generic_args.iter().cloned());
                    }
                }
                "on" => {
                    on_target_expr = c.args.first();
                }
                "count" => is_count = true,
                "unwrap" => is_unwrap = true,
                _ => {}
            }
        }

        let q = HirQuery {
            is_point_lookup: on_target_expr.is_some() || is_unwrap,
            terms,
            with_filters,
            without_filters,
            allow_filters,
            has_filters,
            changed_filters,
            added_filters: Vec::new(),
            where_pred: None,
            on_target: None,
            up_relation: None,
            is_count,
            is_unwrap,
            query_idx: None,
        };
        Ok(Some((target, q, on_target_expr)))
    }

    fn eval_net_query_chain(
        &mut self,
        target: NetWorldTarget,
        q: &HirQuery,
        on_target_expr: Option<&HirExpr>,
    ) -> Result<NetSimVal, String> {
        if q.is_count {
            let ents = self.with_target_runner(target, |r| r.collect_matching_entities(q))?;
            return Ok(NetSimVal::Plain(SimVal::Int(ents.len() as i64)));
        }
        if q.is_point_lookup {
            let on_expr = on_target_expr.ok_or_else(|| {
                "server_query/client_query point lookup in net_sim_test requires `.on(target)`"
                    .to_owned()
            })?;
            let on_val = self.eval_expr(on_expr)?;
            let target_ent = self.resolve_entity_in_world(target, &on_val)?;
            let matched = match target_ent {
                Some(ent)
                    if self.with_target_runner(target, |r| r.entity_matches_query(ent, q))? =>
                {
                    Some(NetSimVal::QueryHit {
                        world: target,
                        entity: ent,
                        terms: q.terms.clone(),
                    })
                }
                _ => None,
            };
            if q.is_unwrap {
                return matched.ok_or_else(|| {
                    "server_query/client_query(...).unwrap() did not match target entity".to_owned()
                });
            }
            return Ok(NetSimVal::OptionHit(matched.map(Box::new)));
        }
        Err("standalone `server_query`/`client_query` outside `for` or `.count()`".to_owned())
    }

    fn eval_call(&mut self, call: &HirCall) -> Result<NetSimVal, String> {
        if call.receiver.is_some() {
            let probe = HirExpr::Call(call.clone());
            if let Some((target, q, on_expr)) = self.try_parse_net_query_chain(&probe)? {
                return self.eval_net_query_chain(target, &q, on_expr);
            }
        }

        if let Some(ref recv_expr) = call.receiver {
            let recv = self.eval_expr(recv_expr)?;
            match call.callee.as_str() {
                "unwrap" | "expect" => {
                    return match recv {
                        NetSimVal::OptionHit(Some(inner)) => Ok(*inner),
                        NetSimVal::OptionHit(None) => {
                            Err(format!("called `{}()` on empty query result", call.callee))
                        }
                        NetSimVal::QueryHit { .. } => Ok(recv),
                        other => Err(format!("cannot call `.{}()` on `{other:?}`", call.callee)),
                    };
                }
                "is_some" => {
                    return match recv {
                        NetSimVal::OptionHit(opt) => {
                            Ok(NetSimVal::Plain(SimVal::Bool(opt.is_some())))
                        }
                        other => Err(format!("cannot call `.is_some()` on `{other:?}`")),
                    };
                }
                "is_none" => {
                    return match recv {
                        NetSimVal::OptionHit(opt) => {
                            Ok(NetSimVal::Plain(SimVal::Bool(opt.is_none())))
                        }
                        other => Err(format!("cannot call `.is_none()` on `{other:?}`")),
                    };
                }
                "raw" => return Ok(recv),
                "is_active" => {
                    let rem = as_float(&net_val_to_sim_val(&recv)?)?;
                    return Ok(NetSimVal::Plain(SimVal::Bool(rem > 0.0)));
                }
                "abs" | "floor" | "ceil" | "round" | "sqrt" | "sin" | "cos" => {
                    let sv = net_val_to_sim_val(&recv)?;
                    return Ok(NetSimVal::Plain(eval_math_fn(&call.callee, &[sv])?));
                }
                "min" | "max" | "powf" | "dot" | "clamp" | "lerp" => {
                    let mut args = vec![net_val_to_sim_val(&recv)?];
                    for a in &call.args {
                        args.push(net_val_to_sim_val(&self.eval_expr(a)?)?);
                    }
                    return Ok(NetSimVal::Plain(eval_math_fn(&call.callee, &args)?));
                }
                "len" | "length" => {
                    let sv = net_val_to_sim_val(&recv)?;
                    return match sv {
                        SimVal::Vec(v, dims) => {
                            let mut sum = 0.0f64;
                            for lane in v.iter().take(usize::from(dims)) {
                                sum += f64::from(*lane) * f64::from(*lane);
                            }
                            Ok(NetSimVal::Plain(SimVal::Float(sum.sqrt())))
                        }
                        SimVal::IVec(v, dims) => {
                            let mut sum = 0.0f64;
                            for lane in v.iter().take(usize::from(dims)) {
                                let f = f64::from(*lane);
                                sum += f * f;
                            }
                            Ok(NetSimVal::Plain(SimVal::Float(sum.sqrt())))
                        }
                        SimVal::UVec(v, dims) => {
                            let mut sum = 0.0f64;
                            for lane in v.iter().take(usize::from(dims)) {
                                let f = f64::from(*lane);
                                sum += f * f;
                            }
                            Ok(NetSimVal::Plain(SimVal::Float(sum.sqrt())))
                        }
                        SimVal::Array(a) => Ok(NetSimVal::Plain(SimVal::Int(a.len() as i64))),
                        other => Err(format!("cannot call `.len()` on `{other:?}`")),
                    };
                }
                other => {
                    return Err(format!(
                        "unsupported method call `.{other}(...)` in net_sim_test"
                    ));
                }
            }
        }

        match call.callee.as_str() {
            "clients" => {
                let arg = call
                    .args
                    .first()
                    .ok_or_else(|| "clients requires an integer count".to_owned())?;
                let n = as_int(&net_val_to_sim_val(&self.eval_expr(arg)?)?)?;
                if n < 1 {
                    return Err(format!("clients count must be >= 1, got {n}"));
                }
                self.ensure_clients(n as usize)?;
                Ok(NetSimVal::Plain(SimVal::Unit))
            }
            "spawn_client" => {
                let arg = call
                    .args
                    .first()
                    .ok_or_else(|| "spawn_client requires client id".to_owned())?;
                let cid = as_int(&net_val_to_sim_val(&self.eval_expr(arg)?)?)?;
                if cid < 0 {
                    return Err(format!("spawn_client id cannot be negative: {cid}"));
                }
                self.ensure_clients(cid as usize + 1)?;
                Ok(NetSimVal::Plain(SimVal::Unit))
            }
            "step_net" => {
                let arg = call
                    .args
                    .first()
                    .ok_or_else(|| "step_net requires tick count".to_owned())?;
                let n = as_int(&net_val_to_sim_val(&self.eval_expr(arg)?)?)?;
                if n < 0 {
                    return Err(format!("step_net count cannot be negative: {n}"));
                }
                self.step_net(n as u64)?;
                Ok(NetSimVal::Plain(SimVal::Unit))
            }
            "server_step" => {
                let arg = call
                    .args
                    .first()
                    .ok_or_else(|| "server_step requires tick count".to_owned())?;
                let n = as_int(&net_val_to_sim_val(&self.eval_expr(arg)?)?)?;
                if n < 0 {
                    return Err(format!("server_step count cannot be negative: {n}"));
                }
                self.step_server_only(n as u64)?;
                Ok(NetSimVal::Plain(SimVal::Unit))
            }
            "client_step" => {
                if call.args.len() < 2 {
                    return Err("client_step requires (client_id, count)".to_owned());
                }
                let cid = as_int(&net_val_to_sim_val(&self.eval_expr(&call.args[0])?)?)?;
                let n = as_int(&net_val_to_sim_val(&self.eval_expr(&call.args[1])?)?)?;
                if cid < 0 || n < 0 {
                    return Err(format!(
                        "client_step arguments must be non-negative: ({cid}, {n})"
                    ));
                }
                self.step_client_only(cid as usize, n as u64)?;
                Ok(NetSimVal::Plain(SimVal::Unit))
            }
            "send_rpc" => {
                if call.args.len() < 2 {
                    return Err("send_rpc requires (client_id, RpcStructLit)".to_owned());
                }
                let cid = as_int(&net_val_to_sim_val(&self.eval_expr(&call.args[0])?)?)?;
                if cid < 0 || (cid as usize) >= self.clients.len() {
                    return Err(format!(
                        "send_rpc client_id `{cid}` out of range (count={})",
                        self.clients.len()
                    ));
                }
                self.exec_send_rpc(cid as usize, &call.args[1])?;
                Ok(NetSimVal::Plain(SimVal::Unit))
            }
            "server_spawn" => {
                let arg = call
                    .args
                    .first()
                    .ok_or_else(|| "server_spawn requires component/bundle literal".to_owned())?;
                let comps = self.eval_spawn_arg(arg)?;
                let ent = self.with_target_runner(NetWorldTarget::Server, |r| {
                    r.spawn_entity_with_components(&comps)
                })?;
                self.known_server_replicated = self.collect_server_replicated_pairs();
                Ok(NetSimVal::Entity {
                    world: NetWorldTarget::Server,
                    entity: Some(ent),
                })
            }
            "client_spawn" => {
                if call.args.len() < 2 {
                    return Err(
                        "client_spawn requires (client_id, component/bundle literal)".to_owned(),
                    );
                }
                let cid = as_int(&net_val_to_sim_val(&self.eval_expr(&call.args[0])?)?)?;
                if cid < 0 || (cid as usize) >= self.clients.len() {
                    return Err(format!(
                        "client_spawn client_id `{cid}` out of range (count={})",
                        self.clients.len()
                    ));
                }
                let comps = self.eval_spawn_arg(&call.args[1])?;
                let target = NetWorldTarget::Client(cid as usize);
                let ent =
                    self.with_target_runner(target, |r| r.spawn_entity_with_components(&comps))?;
                Ok(NetSimVal::Entity {
                    world: target,
                    entity: Some(ent),
                })
            }
            "server_res" => {
                let rname =
                    call.generic_args.first().cloned().ok_or_else(|| {
                        "server_res<T>() requires resource type argument".to_owned()
                    })?;
                Ok(NetSimVal::ResourceRef {
                    world: NetWorldTarget::Server,
                    resource: rname,
                    sub_path: Vec::new(),
                })
            }
            "client_res" => {
                let rname = call.generic_args.first().cloned().ok_or_else(|| {
                    "client_res<T>(id) requires resource type argument".to_owned()
                })?;
                let cid_expr = call
                    .args
                    .first()
                    .ok_or_else(|| "client_res<T>(id) requires client_id argument".to_owned())?;
                let cid = as_int(&net_val_to_sim_val(&self.eval_expr(cid_expr)?)?)?;
                if cid < 0 || (cid as usize) >= self.clients.len() {
                    return Err(format!(
                        "client_res client_id `{cid}` out of range (count={})",
                        self.clients.len()
                    ));
                }
                Ok(NetSimVal::ResourceRef {
                    world: NetWorldTarget::Client(cid as usize),
                    resource: rname,
                    sub_path: Vec::new(),
                })
            }
            "server_query" | "client_query" => {
                let probe = HirExpr::Call(call.clone());
                if let Some((target, q, on_expr)) = self.try_parse_net_query_chain(&probe)? {
                    self.eval_net_query_chain(target, &q, on_expr)
                } else {
                    Err(format!("invalid `{}` call in net_sim_test", call.callee))
                }
            }
            "assert_converged" => {
                self.exec_assert_converged(&call.args)?;
                Ok(NetSimVal::Plain(SimVal::Unit))
            }
            "assert" => {
                let cond_expr = call
                    .args
                    .first()
                    .ok_or_else(|| "assert requires a condition argument".to_owned())?;
                let cond_val = net_val_to_sim_val(&self.eval_expr(cond_expr)?)?;
                if !as_bool(&cond_val)? {
                    let msg = if let Some(msg_expr) = call.args.get(1) {
                        format!("{:?}", self.eval_expr(msg_expr)?)
                    } else {
                        format!("{cond_expr:?}")
                    };
                    return Err(format!(
                        "assertion failed at tick {}: {msg}",
                        self.channel.current_tick
                    ));
                }
                Ok(NetSimVal::Plain(SimVal::Unit))
            }
            "assert_eq" => {
                if call.args.len() < 2 {
                    return Err("assert_eq requires 2 arguments".to_owned());
                }
                let a = net_val_to_sim_val(&self.eval_expr(&call.args[0])?)?;
                let b = net_val_to_sim_val(&self.eval_expr(&call.args[1])?)?;
                if !sim_val_eq(&a, &b) {
                    return Err(format!(
                        "assert_eq failed at tick {}: {a:?} != {b:?}",
                        self.channel.current_tick
                    ));
                }
                Ok(NetSimVal::Plain(SimVal::Unit))
            }
            "assert_ne" => {
                if call.args.len() < 2 {
                    return Err("assert_ne requires 2 arguments".to_owned());
                }
                let a = net_val_to_sim_val(&self.eval_expr(&call.args[0])?)?;
                let b = net_val_to_sim_val(&self.eval_expr(&call.args[1])?)?;
                if sim_val_eq(&a, &b) {
                    return Err(format!(
                        "assert_ne failed at tick {}: {a:?} == {b:?}",
                        self.channel.current_tick
                    ));
                }
                Ok(NetSimVal::Plain(SimVal::Unit))
            }
            "vec2" => {
                let x = as_float(&net_val_to_sim_val(
                    &self.eval_expr(call.args.first().ok_or("vec2 needs x")?)?,
                )?)?;
                let y = as_float(&net_val_to_sim_val(
                    &self.eval_expr(call.args.get(1).ok_or("vec2 needs y")?)?,
                )?)?;
                Ok(NetSimVal::Plain(SimVal::Vec(
                    [x as f32, y as f32, 0.0, 0.0],
                    2,
                )))
            }
            "vec3" => {
                let x = as_float(&net_val_to_sim_val(
                    &self.eval_expr(call.args.first().ok_or("vec3 needs x")?)?,
                )?)?;
                let y = as_float(&net_val_to_sim_val(
                    &self.eval_expr(call.args.get(1).ok_or("vec3 needs y")?)?,
                )?)?;
                let z = as_float(&net_val_to_sim_val(
                    &self.eval_expr(call.args.get(2).ok_or("vec3 needs z")?)?,
                )?)?;
                Ok(NetSimVal::Plain(SimVal::Vec(
                    [x as f32, y as f32, z as f32, 0.0],
                    3,
                )))
            }
            "vec4" => {
                let x = as_float(&net_val_to_sim_val(
                    &self.eval_expr(call.args.first().ok_or("vec4 needs x")?)?,
                )?)?;
                let y = as_float(&net_val_to_sim_val(
                    &self.eval_expr(call.args.get(1).ok_or("vec4 needs y")?)?,
                )?)?;
                let z = as_float(&net_val_to_sim_val(
                    &self.eval_expr(call.args.get(2).ok_or("vec4 needs z")?)?,
                )?)?;
                let w = as_float(&net_val_to_sim_val(
                    &self.eval_expr(call.args.get(3).ok_or("vec4 needs w")?)?,
                )?)?;
                Ok(NetSimVal::Plain(SimVal::Vec(
                    [x as f32, y as f32, z as f32, w as f32],
                    4,
                )))
            }
            "vec3a" | "Vec3a" => {
                let x = as_float(&net_val_to_sim_val(
                    &self.eval_expr(call.args.first().ok_or("vec3a needs x")?)?,
                )?)?;
                let y = as_float(&net_val_to_sim_val(
                    &self.eval_expr(call.args.get(1).ok_or("vec3a needs y")?)?,
                )?)?;
                let z = as_float(&net_val_to_sim_val(
                    &self.eval_expr(call.args.get(2).ok_or("vec3a needs z")?)?,
                )?)?;
                Ok(NetSimVal::Plain(SimVal::Vec(
                    [x as f32, y as f32, z as f32, 0.0],
                    4,
                )))
            }
            "Some" | "Option::Some" => {
                let v =
                    self.eval_expr(call.args.first().ok_or("Some(...) requires 1 argument")?)?;
                Ok(NetSimVal::OptionHit(Some(Box::new(v))))
            }
            "ivec2" => {
                let x = as_int(&net_val_to_sim_val(
                    &self.eval_expr(call.args.first().ok_or("ivec2 needs x")?)?,
                )?)?;
                let y = as_int(&net_val_to_sim_val(
                    &self.eval_expr(call.args.get(1).ok_or("ivec2 needs y")?)?,
                )?)?;
                Ok(NetSimVal::Plain(SimVal::IVec(
                    [x as i32, y as i32, 0, 0],
                    2,
                )))
            }
            "ivec3" => {
                let x = as_int(&net_val_to_sim_val(
                    &self.eval_expr(call.args.first().ok_or("ivec3 needs x")?)?,
                )?)?;
                let y = as_int(&net_val_to_sim_val(
                    &self.eval_expr(call.args.get(1).ok_or("ivec3 needs y")?)?,
                )?)?;
                let z = as_int(&net_val_to_sim_val(
                    &self.eval_expr(call.args.get(2).ok_or("ivec3 needs z")?)?,
                )?)?;
                Ok(NetSimVal::Plain(SimVal::IVec(
                    [x as i32, y as i32, z as i32, 0],
                    3,
                )))
            }
            "uvec2" => {
                let x = as_int(&net_val_to_sim_val(
                    &self.eval_expr(call.args.first().ok_or("uvec2 needs x")?)?,
                )?)?;
                let y = as_int(&net_val_to_sim_val(
                    &self.eval_expr(call.args.get(1).ok_or("uvec2 needs y")?)?,
                )?)?;
                Ok(NetSimVal::Plain(SimVal::UVec(
                    [x as u32, y as u32, 0, 0],
                    2,
                )))
            }
            "abs" | "floor" | "ceil" | "round" | "sqrt" | "sin" | "cos" | "min" | "max"
            | "clamp" | "lerp" | "powf" | "dot" => {
                let mut vals = Vec::with_capacity(call.args.len());
                for a in &call.args {
                    vals.push(net_val_to_sim_val(&self.eval_expr(a)?)?);
                }
                Ok(NetSimVal::Plain(eval_math_fn(&call.callee, &vals)?))
            }
            other => Err(format!("unsupported call `{other}(...)` in net_sim_test")),
        }
    }

    fn eval_spawn_arg(
        &mut self,
        expr: &HirExpr,
    ) -> Result<Vec<(String, Vec<(String, SimVal)>)>, String> {
        match expr {
            HirExpr::StructLit { name, fields, .. } => {
                let mut fvals = Vec::with_capacity(fields.len());
                for (fname, fexpr) in fields {
                    fvals.push((fname.clone(), net_val_to_sim_val(&self.eval_expr(fexpr)?)?));
                }
                Ok(vec![(name.clone(), fvals)])
            }
            HirExpr::BundleLit { components } => {
                let mut out = Vec::with_capacity(components.len());
                for ci in components {
                    let cname = ci
                        .canonical_component
                        .as_deref()
                        .unwrap_or(&ci.component)
                        .to_owned();
                    let mut fvals = Vec::with_capacity(ci.fields.len());
                    for (fname, fexpr) in &ci.fields {
                        fvals.push((fname.clone(), net_val_to_sim_val(&self.eval_expr(fexpr)?)?));
                    }
                    out.push((cname, fvals));
                }
                Ok(out)
            }
            HirExpr::Path { name, .. } => Ok(vec![(name.clone(), Vec::new())]),
            other => Err(format!(
                "server_spawn/client_spawn expects component or bundle literal, got `{other:?}`"
            )),
        }
    }

    fn exec_send_rpc(&mut self, cid: usize, rpc_expr: &HirExpr) -> Result<(), String> {
        let (rpc_name, field_exprs): (&str, &[(String, HirExpr)]) = match rpc_expr {
            HirExpr::StructLit { name, fields, .. } => (name.as_str(), fields.as_slice()),
            HirExpr::Path { name, .. } => (name.as_str(), &[]),
            other => {
                return Err(format!(
                    "send_rpc expects RPC struct literal as second argument, got `{other:?}`"
                ));
            }
        };

        let rpc = self
            .base_mir
            .rpcs
            .iter()
            .find(|r| r.name == rpc_name || r.canonical_name == rpc_name)
            .ok_or_else(|| format!("unknown RPC `{rpc_name}` in send_rpc"))?
            .clone();

        if rpc.packed_bytes as usize > STRATA_NET_MAX_PAYLOAD_BYTES {
            return Err(format!(
                "RPC `{}` payload ({} bytes) exceeds max packet size ({} bytes)",
                rpc.name, rpc.packed_bytes, STRATA_NET_MAX_PAYLOAD_BYTES
            ));
        }

        let mut evaluated_fields: HashMap<String, SimVal> = HashMap::new();
        for (fname, fexpr) in field_exprs {
            evaluated_fields.insert(fname.clone(), net_val_to_sim_val(&self.eval_expr(fexpr)?)?);
        }

        let rpc_layout = find_layout_in_slice(
            &self.base_mir.layouts,
            &self.base_mir.module_path,
            &rpc.canonical_name,
        )
        .or_else(|| {
            find_layout_in_slice(
                &self.artifacts.server_mir.layouts,
                &self.base_mir.module_path,
                &rpc.canonical_name,
            )
        })
        .or_else(|| {
            find_layout_in_slice(
                &self.artifacts.client_mir.layouts,
                &self.base_mir.module_path,
                &rpc.canonical_name,
            )
        })
        .cloned();
        let mut payload = [0u8; STRATA_NET_MAX_PAYLOAD_BYTES];
        for wf in &rpc.wire_fields {
            let val = lookup_sim_val_path(&evaluated_fields, &wf.field_name);
            let seg: Vec<String> = wf.field_name.split('.').map(str::to_owned).collect();
            let field_ty = rpc_layout
                .as_ref()
                .and_then(|l| resolve_layout_field_ty(self.base_mir, l, &seg))
                .unwrap_or_else(|| mir_type_to_ty(&wf.ty));
            pack_wire_field_value(wf, val, &field_ty, self.base_mir, &mut payload)?;
        }

        let seq = self.channel.next_rpc_seq;
        self.channel.next_rpc_seq = self.channel.next_rpc_seq.wrapping_add(1);
        let mut flags = FLAG_IS_RPC;
        if rpc.reliability == NetReliability::Reliable {
            flags |= FLAG_IS_RELIABLE;
        }
        let pkt = StrataNetPacket {
            module_net_fingerprint: self.base_mir.net_handshake.module_net_fingerprint,
            item_schema_fingerprint: rpc.schema_fingerprint,
            target_id: rpc.rpc_id,
            entity_bits: 0,
            magic: STRATA_NET_PACKET_MAGIC,
            tick_or_seq: seq,
            version: STRATA_NET_WIRE_VERSION,
            payload_bits: rpc.packed_bits as u16,
            flags,
            kind: PACKET_KIND_RPC,
            channel: rpc.channel,
            payload_bytes: rpc.packed_bytes as u8,
            client_id: cid as u8,
            _pad: [0; 6],
            payload,
        };

        let (src, dst) = match rpc.direction {
            NetDirection::ServerToClient => (NetWorldTarget::Server, NetWorldTarget::Client(cid)),
            NetDirection::ClientToServer | NetDirection::Bidirectional => {
                (NetWorldTarget::Client(cid), NetWorldTarget::Server)
            }
        };
        self.channel.enqueue(src, dst, pkt);
        Ok(())
    }

    fn assert_entity_component_fields_converged(
        &mut self,
        cid: usize,
        nc: &MirNetComponent,
        s_ent: Entity,
        c_ent: Entity,
        entity_label: &str,
        explicit_tol: Option<f64>,
    ) -> Result<(), String> {
        for wf in &nc.wire_fields {
            let seg: Vec<String> = wf.field_name.split('.').map(str::to_owned).collect();
            let s_val = self.with_target_runner(NetWorldTarget::Server, |r| {
                r.read_component_field(s_ent, &nc.canonical_name, &seg)
            })?;
            let c_val = self.with_target_runner(NetWorldTarget::Client(cid), |r| {
                r.read_component_field(c_ent, &nc.canonical_name, &seg)
            })?;
            if !net_field_converged(&s_val, &c_val, wf, explicit_tol) {
                return Err(format!(
                    "assert_converged failed at tick {}: client {cid} {entity_label} component `{}`.`{}` mismatch (server={s_val:?}, client={c_val:?})",
                    self.channel.current_tick, nc.name, wf.field_name
                ));
            }
        }
        Ok(())
    }

    fn exec_assert_converged(&mut self, args: &[HirExpr]) -> Result<(), String> {
        let (target_clients, explicit_tol): (Vec<usize>, Option<f64>) = match args.len() {
            0 => ((0..self.clients.len()).collect(), None),
            1 => {
                let cid = as_int(&net_val_to_sim_val(&self.eval_expr(&args[0])?)?)?;
                if cid < 0 || (cid as usize) >= self.clients.len() {
                    return Err(format!(
                        "assert_converged client_id `{cid}` out of range (count={})",
                        self.clients.len()
                    ));
                }
                (vec![cid as usize], None)
            }
            _ => {
                let cid = as_int(&net_val_to_sim_val(&self.eval_expr(&args[0])?)?)?;
                if cid < 0 || (cid as usize) >= self.clients.len() {
                    return Err(format!(
                        "assert_converged client_id `{cid}` out of range (count={})",
                        self.clients.len()
                    ));
                }
                let tol = as_float(&net_val_to_sim_val(&self.eval_expr(&args[1])?)?)?;
                if !tol.is_finite() || tol < 0.0 {
                    return Err(format!(
                        "assert_converged tolerance must be finite and non-negative, got `{tol}`"
                    ));
                }
                (vec![cid as usize], Some(tol))
            }
        };

        let replicated: Vec<MirNetComponent> = self
            .base_mir
            .net_components
            .iter()
            .filter(|nc| nc.is_replicated)
            .cloned()
            .collect();

        let object_names: Vec<String> = self
            .base_mir
            .objects
            .iter()
            .map(|o| o.name.clone())
            .collect();

        for cid in target_clients {
            for nc in &replicated {
                // Non-server-authored components are only replicated from a single client when
                // explicitly marked `@authority(client)` / `@predicted`; multi-client worlds only
                // expect server/shared replicated state to converge across all clients.
                if self.clients.len() > 1
                    && (nc.is_predicted
                        || matches!(
                            nc.authority,
                            AuthorityKind::Client | AuthorityKind::Predicted
                        ))
                {
                    continue;
                }

                if nc.is_resource {
                    let host_res = find_registry_component(
                        self.server.app.world(),
                        &self.base_mir.module_path,
                        &nc.canonical_name,
                    )
                    .is_some_and(|r| r.is_resource());
                    for wf in &nc.wire_fields {
                        let use_direct = host_res
                            || self
                                .artifacts
                                .server_dispatch
                                .res_ops
                                .contains_key(&(nc.canonical_name.clone(), wf.field_name.clone()));
                        let mut checks: Vec<(Vec<String>, Option<strata_mir::MirQuantizeSpec>)> =
                            Vec::new();
                        if !use_direct
                            && let MirType::Named(ref inner) = wf.ty
                            && let Some(inner_layout) = find_layout_in_slice(
                                &self.base_mir.layouts,
                                &self.base_mir.module_path,
                                inner,
                            )
                            && inner_layout.item_kind != strata_sema::layout::SchemaItemKind::Enum
                        {
                            collect_net_field_leaf_paths(
                                self.base_mir,
                                inner_layout,
                                vec![wf.field_name.clone()],
                                &mut checks,
                            );
                        } else {
                            checks.push((vec![wf.field_name.clone()], wf.quantize.clone()));
                        }

                        for (seg, q_override) in checks {
                            let mut check_wf = wf.clone();
                            if q_override.is_none() && seg.len() > 1 {
                                check_wf.quantize = None;
                            }
                            let s_val = self.with_target_runner(NetWorldTarget::Server, |r| {
                                r.read_resource_field(&nc.canonical_name, &seg)
                            })?;
                            let c_val = self
                                .with_target_runner(NetWorldTarget::Client(cid), |r| {
                                    r.read_resource_field(&nc.canonical_name, &seg)
                                })?;
                            if !net_field_converged(&s_val, &c_val, &check_wf, explicit_tol) {
                                return Err(format!(
                                    "assert_converged failed at tick {}: client {cid} resource `{}`.`{}` mismatch (server={s_val:?}, client={c_val:?})",
                                    self.channel.current_tick,
                                    nc.name,
                                    seg.join(".")
                                ));
                            }
                        }
                    }
                    continue;
                }

                let s_reg = find_registry_component(
                    self.server.app.world(),
                    &self.base_mir.module_path,
                    &nc.canonical_name,
                );
                let c_reg = find_registry_component(
                    self.clients[cid].app.world(),
                    &self.base_mir.module_path,
                    &nc.canonical_name,
                );
                let mut checked_s_bits: HashSet<u64> = HashSet::new();
                let mut checked_c_bits: HashSet<u64> = HashSet::new();

                for obj_name in &object_names {
                    let s_ent_opt = self.server.named_entities.get(obj_name).copied();
                    let c_ent_opt = self.clients[cid].named_entities.get(obj_name).copied();
                    let (Some(s_ent), Some(c_ent)) = (s_ent_opt, c_ent_opt) else {
                        continue;
                    };
                    let s_has = s_reg.as_ref().is_some_and(|reg| {
                        self.server
                            .app
                            .world()
                            .get_entity(s_ent)
                            .is_ok_and(|er| er.contains_id(reg.component_id))
                    });
                    let c_has = c_reg.as_ref().is_some_and(|reg| {
                        self.clients[cid]
                            .app
                            .world()
                            .get_entity(c_ent)
                            .is_ok_and(|er| er.contains_id(reg.component_id))
                    });
                    checked_s_bits.insert(s_ent.to_bits());
                    checked_c_bits.insert(c_ent.to_bits());
                    if !s_has && !c_has {
                        continue;
                    }
                    if s_has != c_has {
                        return Err(format!(
                            "assert_converged failed at tick {}: client {cid} object `{obj_name}` component `{}` presence mismatch (server={s_has}, client={c_has})",
                            self.channel.current_tick, nc.name
                        ));
                    }

                    self.assert_entity_component_fields_converged(
                        cid,
                        nc,
                        s_ent,
                        c_ent,
                        &format!("object `{obj_name}`"),
                        explicit_tol,
                    )?;
                }

                // Also verify all dynamically spawned/attached/removed entities holding `nc`.
                let s_live: Vec<Entity> = if let Some(ref reg) = s_reg {
                    let world = self.server.app.world_mut();
                    let entities: Vec<Entity> = {
                        let mut q = world.query::<Entity>();
                        q.iter(world).collect()
                    };
                    entities
                        .into_iter()
                        .filter(|&ent| {
                            world
                                .get_entity(ent)
                                .is_ok_and(|er| er.contains_id(reg.component_id))
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                let c_live: Vec<Entity> = if let Some(ref reg) = c_reg {
                    let world = self.clients[cid].app.world_mut();
                    let entities: Vec<Entity> = {
                        let mut q = world.query::<Entity>();
                        q.iter(world).collect()
                    };
                    entities
                        .into_iter()
                        .filter(|&ent| {
                            world
                                .get_entity(ent)
                                .is_ok_and(|er| er.contains_id(reg.component_id))
                        })
                        .collect()
                } else {
                    Vec::new()
                };
                let c_live_bits: HashSet<u64> = c_live.iter().map(|e| e.to_bits()).collect();

                for s_ent in s_live {
                    let s_bits = s_ent.to_bits();
                    if checked_s_bits.contains(&s_bits) {
                        continue;
                    }
                    let Some(&c_bits) = self.s_to_c.get(cid).and_then(|m| m.get(&s_bits)) else {
                        return Err(format!(
                            "assert_converged failed at tick {}: client {cid} missing replicated entity for server entity {s_ent:?} component `{}`",
                            self.channel.current_tick, nc.name
                        ));
                    };
                    if !c_live_bits.contains(&c_bits) {
                        return Err(format!(
                            "assert_converged failed at tick {}: client {cid} missing replicated component `{}` on proxy entity (server={s_ent:?})",
                            self.channel.current_tick, nc.name
                        ));
                    }
                    let c_ent = Entity::from_bits(c_bits);
                    checked_s_bits.insert(s_bits);
                    checked_c_bits.insert(c_bits);
                    self.assert_entity_component_fields_converged(
                        cid,
                        nc,
                        s_ent,
                        c_ent,
                        &format!("entity {s_ent:?}"),
                        explicit_tol,
                    )?;
                }

                for c_ent in c_live {
                    let c_bits = c_ent.to_bits();
                    if checked_c_bits.contains(&c_bits) {
                        continue;
                    }
                    return Err(format!(
                        "assert_converged failed at tick {}: client {cid} still holds unreplicated/stale component `{}` on entity {c_ent:?}",
                        self.channel.current_tick, nc.name
                    ));
                }
            }
        }

        Ok(())
    }

    fn read_field_on_val(&mut self, base: NetSimVal, field: &str) -> Result<NetSimVal, String> {
        match base {
            NetSimVal::QueryHit {
                world,
                entity,
                terms,
            } => {
                let sv = SimVal::QueryHit { entity, terms };
                let out = self.with_target_runner(world, |r| r.read_field_on_val(sv, field))?;
                Ok(sim_val_to_net_val(out, world))
            }
            NetSimVal::ComponentRef {
                world,
                entity,
                layout_key,
                sub_path,
            } => {
                let sv = SimVal::ComponentRef {
                    entity,
                    layout_key,
                    sub_path,
                };
                let out = self.with_target_runner(world, |r| r.read_field_on_val(sv, field))?;
                Ok(sim_val_to_net_val(out, world))
            }
            NetSimVal::ResourceRef {
                world,
                resource,
                sub_path,
            } => {
                let sv = SimVal::ResourceRef { resource, sub_path };
                let out = self.with_target_runner(world, |r| r.read_field_on_val(sv, field))?;
                Ok(sim_val_to_net_val(out, world))
            }
            NetSimVal::Plain(sv) => {
                let (mir, dispatch) = self.world_mir_dispatch(NetWorldTarget::Server);
                let _ = (mir, dispatch);
                let out = self.with_target_runner(NetWorldTarget::Server, |r| {
                    r.read_field_on_val(sv, field)
                })?;
                Ok(NetSimVal::Plain(out))
            }
            other => Err(format!("cannot access field `.{field}` on `{other:?}`")),
        }
    }

    fn assign_lvalue(
        &mut self,
        target: &HirLValue,
        op: HirAssignOp,
        rhs: NetSimVal,
    ) -> Result<(), String> {
        let mut fields = Vec::new();
        let mut cur = target;
        while let HirLValue::Field { base, field, .. } = cur {
            fields.push(field.clone());
            cur = base;
        }
        fields.reverse();

        let rhs_sim = net_val_to_sim_val(&rhs)?;

        match cur {
            HirLValue::ResourceAccess {
                resource,
                is_mut,
                client_id,
                ..
            } => {
                if !is_mut {
                    return Err(format!("cannot mutate immutable `res<{resource}>()`"));
                }
                let target = if let Some(cid_expr) = client_id {
                    let cid = as_int(&net_val_to_sim_val(&self.eval_expr(cid_expr)?)?)?;
                    if cid < 0 || (cid as usize) >= self.clients.len() {
                        return Err(format!(
                            "client_res client_id `{cid}` out of range (count={})",
                            self.clients.len()
                        ));
                    }
                    NetWorldTarget::Client(cid as usize)
                } else {
                    NetWorldTarget::Server
                };
                self.with_target_runner(target, |r| {
                    r.write_resource_field(resource, &fields, op, rhs_sim)
                })
            }
            HirLValue::Local { name, .. } => {
                let base_val = self
                    .get_var(name)
                    .cloned()
                    .ok_or_else(|| format!("unknown variable `{name}` in assignment"))?;
                if fields.is_empty() {
                    let final_val = if op == HirAssignOp::Set {
                        rhs
                    } else {
                        let old = net_val_to_sim_val(&base_val)?;
                        NetSimVal::Plain(apply_assign_op(op, old, rhs_sim)?)
                    };
                    self.update_var(name, final_val);
                    return Ok(());
                }

                match base_val {
                    NetSimVal::ResourceRef {
                        world,
                        resource,
                        mut sub_path,
                    } => {
                        sub_path.extend(fields);
                        self.with_target_runner(world, |r| {
                            r.write_resource_field(&resource, &sub_path, op, rhs_sim)
                        })
                    }
                    NetSimVal::ComponentRef {
                        world,
                        entity,
                        layout_key,
                        mut sub_path,
                    } => {
                        sub_path.extend(fields);
                        self.with_target_runner(world, |r| {
                            r.write_component_field(entity, &layout_key, &sub_path, op, rhs_sim)
                        })
                    }
                    NetSimVal::QueryHit {
                        world,
                        entity,
                        terms,
                    } => {
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
                        self.with_target_runner(world, |r| {
                            r.write_component_field(
                                entity,
                                &term.canonical_component,
                                &segs,
                                op,
                                rhs_sim,
                            )
                        })
                    }
                    NetSimVal::Plain(SimVal::Vec(mut v, dims)) if fields.len() == 1 => {
                        let lane = crate::sim_runner::vec_lane_index(&fields[0])
                            .ok_or_else(|| format!("invalid vector lane `{}`", fields[0]))?;
                        let idx = usize::from(lane);
                        let updated = if op == HirAssignOp::Set {
                            as_float(&rhs_sim)?
                        } else {
                            let old = SimVal::Float(f64::from(v[idx]));
                            as_float(&apply_assign_op(op, old, rhs_sim)?)?
                        };
                        v[idx] = updated as f32;
                        self.update_var(name, NetSimVal::Plain(SimVal::Vec(v, dims)));
                        Ok(())
                    }
                    NetSimVal::Plain(SimVal::IVec(mut v, dims)) if fields.len() == 1 => {
                        let lane = crate::sim_runner::vec_lane_index(&fields[0])
                            .ok_or_else(|| format!("invalid vector lane `{}`", fields[0]))?;
                        let idx = usize::from(lane);
                        let updated = if op == HirAssignOp::Set {
                            as_int(&rhs_sim)?
                        } else {
                            let old = SimVal::Int(i64::from(v[idx]));
                            as_int(&apply_assign_op(op, old, rhs_sim)?)?
                        };
                        v[idx] = updated as i32;
                        self.update_var(name, NetSimVal::Plain(SimVal::IVec(v, dims)));
                        Ok(())
                    }
                    NetSimVal::Plain(SimVal::UVec(mut v, dims)) if fields.len() == 1 => {
                        let lane = crate::sim_runner::vec_lane_index(&fields[0])
                            .ok_or_else(|| format!("invalid vector lane `{}`", fields[0]))?;
                        let idx = usize::from(lane);
                        let updated = if op == HirAssignOp::Set {
                            as_int(&rhs_sim)?
                        } else {
                            let old = SimVal::Int(i64::from(v[idx]));
                            as_int(&apply_assign_op(op, old, rhs_sim)?)?
                        };
                        v[idx] = updated as u32;
                        self.update_var(name, NetSimVal::Plain(SimVal::UVec(v, dims)));
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
}

fn lookup_sim_val_path<'v>(fields: &'v HashMap<String, SimVal>, path: &str) -> Option<&'v SimVal> {
    if let Some(direct) = fields.get(path) {
        return Some(direct);
    }
    let mut segs = path.split('.');
    let first = segs.next()?;
    let mut cur = fields.get(first)?;
    for seg in segs {
        match cur {
            SimVal::Struct { fields: inner, .. } => {
                cur = inner.iter().find(|(name, _)| name == seg).map(|(_, v)| v)?;
            }
            _ => return None,
        }
    }
    Some(cur)
}

fn resolve_layout_field_offset_ty(
    base_mir: &MirModule,
    base_layout: &strata_sema::layout::SolvedLayout,
    segments: &[String],
) -> Option<(usize, Ty)> {
    let mut cur_layout = base_layout;
    let mut offset = 0usize;
    let mut cur_ty = Ty::Unknown;
    for (i, seg) in segments.iter().enumerate() {
        let sf = cur_layout
            .fields
            .iter()
            .find(|f| !f.is_padding && f.name == *seg)?;
        offset += sf.offset;
        cur_ty = sf.ty.clone();
        if i + 1 < segments.len() {
            let Ty::Named(ref inner) = sf.ty else {
                return None;
            };
            cur_layout = find_layout_in_slice(&base_mir.layouts, &base_mir.module_path, inner)?;
        }
    }
    Some((offset, cur_ty))
}

fn resolve_layout_field_ty(
    base_mir: &MirModule,
    base_layout: &strata_sema::layout::SolvedLayout,
    segments: &[String],
) -> Option<Ty> {
    resolve_layout_field_offset_ty(base_mir, base_layout, segments).map(|(_, ty)| ty)
}

fn pack_wire_field_value(
    wf: &strata_mir::MirNetFieldSpec,
    val: Option<&SimVal>,
    field_ty: &Ty,
    base_mir: &MirModule,
    payload: &mut [u8; STRATA_NET_MAX_PAYLOAD_BYTES],
) -> Result<(), String> {
    if let Some(ref q) = wf.quantize {
        let pack_lanes =
            |payload: &mut [u8; STRATA_NET_MAX_PAYLOAD_BYTES], lanes: &[f64; 4], count: usize| {
                for li in 0..q.lane_count {
                    let idx = usize::from(li);
                    let fval = if idx < count { lanes[idx] } else { 0.0 };
                    let qval = quantize_scalar_f64(fval, q.min, q.max, q.bits, q.step);
                    let boff = wf.bit_offset + u32::from(li) * u32::from(q.bits);
                    pack_bits_le(payload, boff, q.bits, qval);
                }
            };
        match val {
            Some(SimVal::Vec(v, dims)) => {
                let n = usize::from((*dims).min(4));
                let mut lanes = [0.0f64; 4];
                for i in 0..n {
                    lanes[i] = f64::from(v[i]);
                }
                pack_lanes(payload, &lanes, n);
            }
            Some(SimVal::IVec(v, dims)) => {
                let n = usize::from((*dims).min(4));
                let mut lanes = [0.0f64; 4];
                for i in 0..n {
                    lanes[i] = f64::from(v[i]);
                }
                pack_lanes(payload, &lanes, n);
            }
            Some(SimVal::UVec(v, dims)) => {
                let n = usize::from((*dims).min(4));
                let mut lanes = [0.0f64; 4];
                for i in 0..n {
                    lanes[i] = f64::from(v[i]);
                }
                pack_lanes(payload, &lanes, n);
            }
            Some(sv) => {
                let fval = as_float(sv)?;
                let qval = quantize_scalar_f64(fval, q.min, q.max, q.bits, q.step);
                pack_bits_le(payload, wf.bit_offset, q.bits, qval);
            }
            None => pack_lanes(payload, &[0.0; 4], 0),
        }
    } else if wf.byte_size > 0 {
        let mut raw = vec![0u8; wf.byte_size as usize];
        if let Some(sv) = val {
            encode_ty_to_bytes_with_layouts(
                &mut raw,
                0,
                field_ty,
                sv,
                &base_mir.enums,
                &base_mir.layouts,
                &base_mir.module_path,
            )?;
        }
        for (bi, &b) in raw.iter().enumerate() {
            pack_bits_le(payload, wf.bit_offset + (bi as u32) * 8, 8, u64::from(b));
        }
    }
    Ok(())
}

fn collect_net_field_leaf_paths(
    base_mir: &MirModule,
    layout: &strata_sema::layout::SolvedLayout,
    prefix: Vec<String>,
    out: &mut Vec<(Vec<String>, Option<strata_mir::MirQuantizeSpec>)>,
) {
    for sf in &layout.fields {
        if sf.is_padding {
            continue;
        }
        let mut next = prefix.clone();
        next.push(sf.name.clone());
        if let Ty::Named(ref inner) = sf.ty
            && let Some(inner_layout) =
                find_layout_in_slice(&base_mir.layouts, &base_mir.module_path, inner)
            && inner_layout.item_kind != strata_sema::layout::SchemaItemKind::Enum
        {
            collect_net_field_leaf_paths(base_mir, inner_layout, next, out);
        } else {
            out.push((next, None));
        }
    }
}

fn float_within_tol(a: f64, b: f64, tol: f64) -> bool {
    if !a.is_finite() || !b.is_finite() || !tol.is_finite() || tol < 0.0 {
        return false;
    }
    let diff = a - b;
    if diff.is_finite() {
        diff.abs() <= tol
    } else {
        ((a * 0.5) - (b * 0.5)).abs() <= (tol * 0.5)
    }
}

fn sim_vals_converged(
    s_val: &SimVal,
    c_val: &SimVal,
    tol: f64,
    int_tol: f64,
    has_quantize: bool,
) -> bool {
    if !tol.is_finite() || tol < 0.0 || !int_tol.is_finite() || int_tol < 0.0 {
        return false;
    }
    match (s_val, c_val) {
        (SimVal::Float(a), SimVal::Float(b)) => float_within_tol(*a, *b, tol),
        (SimVal::Vec(a, da), SimVal::Vec(b, db)) if da == db => {
            (0..usize::from(*da)).all(|i| float_within_tol(f64::from(a[i]), f64::from(b[i]), tol))
        }
        (SimVal::IVec(a, da), SimVal::IVec(b, db)) if da == db => (0..usize::from(*da)).all(|i| {
            if has_quantize {
                ((i64::from(a[i]) - i64::from(b[i])).abs() as f64) <= int_tol
            } else {
                a[i] == b[i]
            }
        }),
        (SimVal::UVec(a, da), SimVal::UVec(b, db)) if da == db => (0..usize::from(*da)).all(|i| {
            if has_quantize {
                ((i64::from(a[i]) - i64::from(b[i])).abs() as f64) <= int_tol
            } else {
                a[i] == b[i]
            }
        }),
        (SimVal::Int(a), SimVal::Int(b)) => {
            if has_quantize {
                ((*a as f64) - (*b as f64)).abs() <= int_tol
            } else {
                a == b
            }
        }
        (SimVal::Bool(a), SimVal::Bool(b)) => a == b,
        (SimVal::Int(a), SimVal::Float(b)) => float_within_tol(*a as f64, *b, tol),
        (SimVal::Float(a), SimVal::Int(b)) => float_within_tol(*a, *b as f64, tol),
        (SimVal::Array(a), SimVal::Array(b)) | (SimVal::Tuple(a), SimVal::Tuple(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|(x, y)| sim_vals_converged(x, y, tol, int_tol, has_quantize))
        }
        (SimVal::Struct { fields: fa, .. }, SimVal::Struct { fields: fb, .. }) => {
            fa.len() == fb.len()
                && fa.iter().all(|(name, va)| {
                    fb.iter().find(|(nb, _)| nb == name).is_some_and(|(_, vb)| {
                        sim_vals_converged(va, vb, tol, int_tol, has_quantize)
                    })
                })
        }
        _ => sim_val_eq(s_val, c_val),
    }
}

fn net_field_converged(
    s_val: &SimVal,
    c_val: &SimVal,
    wf: &strata_mir::MirNetFieldSpec,
    explicit_tol: Option<f64>,
) -> bool {
    let tol = match &wf.quantize {
        Some(q) => {
            let q_step = q.effective_step();
            let q_tol = if q_step.is_finite() {
                let scaled = q_step * 1.01;
                if scaled.is_finite() {
                    let with_eps = scaled + 1e-4;
                    if with_eps.is_finite() {
                        with_eps
                    } else {
                        scaled
                    }
                } else {
                    q_step
                }
            } else {
                return explicit_tol.is_some_and(|t| t.is_finite() && t >= 0.0)
                    && sim_vals_converged(
                        s_val,
                        c_val,
                        explicit_tol.unwrap(),
                        explicit_tol.unwrap(),
                        true,
                    );
            };
            explicit_tol.unwrap_or(q_tol)
        }
        None => explicit_tol.unwrap_or(1e-4),
    };
    if !tol.is_finite() || tol < 0.0 {
        return false;
    }
    let int_tol = explicit_tol.unwrap_or_else(|| tol.max(1.0));
    sim_vals_converged(s_val, c_val, tol, int_tol, wf.quantize.is_some())
}

fn mir_type_to_ty(mty: &MirType) -> Ty {
    match mty {
        MirType::Unit => Ty::Unit,
        MirType::Bool => Ty::Bool,
        MirType::U8 => Ty::U8,
        MirType::I8 => Ty::I8,
        MirType::U16 => Ty::U16,
        MirType::I16 => Ty::I16,
        MirType::I32 => Ty::I32,
        MirType::U64 => Ty::U64,
        MirType::I64 => Ty::I64,
        MirType::F32 => Ty::F32,
        MirType::F64 => Ty::F64,
        MirType::Fix32 => Ty::Fix32,
        MirType::Fix64 => Ty::Fix64,
        MirType::Sym => Ty::Sym,
        MirType::Vec2 => Ty::Vec2,
        MirType::Vec3 => Ty::Vec3,
        MirType::Vec4 => Ty::Vec4,
        MirType::IVec2 => Ty::IVec2,
        MirType::IVec3 => Ty::IVec3,
        MirType::UVec2 => Ty::UVec2,
        MirType::Entity => Ty::Ref("Entity".to_owned()),
        MirType::Array { elem, len } => Ty::Array {
            elem: Box::new(mir_type_to_ty(elem)),
            len: *len,
        },
        MirType::Tuple(elems) => Ty::Tuple(elems.iter().map(mir_type_to_ty).collect()),
        MirType::Named(n) if n == "IVec2" => Ty::IVec2,
        MirType::Named(n) if n == "IVec3" => Ty::IVec3,
        MirType::Named(n) if n == "UVec2" => Ty::UVec2,
        MirType::Named(n) if n == "Vec3a" => Ty::Vec3a,
        MirType::Named(n) if n == "Rgba8" => Ty::Rgba8,
        MirType::Named(n) => {
            if let Some(cap) = n
                .strip_prefix("InlineStr<")
                .and_then(|rest| rest.strip_suffix('>'))
                .and_then(|digits| digits.parse::<usize>().ok())
            {
                Ty::InlineStr(cap)
            } else {
                Ty::Named(n.clone())
            }
        }
        _ => Ty::U32,
    }
}

fn run_single_net_sim_test(
    base_mir: &MirModule,
    artifacts: &CompiledNetArtifacts,
    nst: &strata_mir::MirNetSimTest,
) -> SimTestCaseResult {
    let mut runner = match NetSimRunner::new(
        base_mir,
        artifacts,
        nst.latency_ms,
        nst.jitter_ms,
        nst.loss,
        nst.seed,
        nst.clients,
    ) {
        Ok(r) => r,
        Err(detail) => {
            return SimTestCaseResult {
                name: nst.name.clone(),
                passed: false,
                frames_simulated: 0,
                peak_cmd_bytes: 0,
                steady_state_allocs: 0,
                detail,
            };
        }
    };

    match runner.exec_stmts(&nst.body) {
        Ok(NetFlow::Normal | NetFlow::Return(_)) => SimTestCaseResult {
            name: nst.name.clone(),
            passed: true,
            frames_simulated: runner.total_frames(),
            peak_cmd_bytes: runner.peak_cmd_bytes(),
            steady_state_allocs: runner.steady_state_allocs(),
            detail: "ok".to_owned(),
        },
        Ok(NetFlow::Break | NetFlow::Continue) => SimTestCaseResult {
            name: nst.name.clone(),
            passed: false,
            frames_simulated: runner.total_frames(),
            peak_cmd_bytes: runner.peak_cmd_bytes(),
            steady_state_allocs: runner.steady_state_allocs(),
            detail: "break/continue outside loop in net_sim_test".to_owned(),
        },
        Err(detail) => SimTestCaseResult {
            name: nst.name.clone(),
            passed: false,
            frames_simulated: runner.total_frames(),
            peak_cmd_bytes: runner.peak_cmd_bytes(),
            steady_state_allocs: runner.steady_state_allocs(),
            detail,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim_runner::decode_ty_from_bytes_with_layouts;
    use strata_mir::lower_to_mir;
    use strata_sema::analyze_source;
    use strata_sema::layout::SolvedLayout;

    #[test]
    fn rpc_wire_roundtrip_wide_quantize_and_composite_struct_array_inline_str() {
        let _guard = SIM_EXEC_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        let src = r#"
module test::rpc_wire_ut @version(1.0.0);

struct PayloadMeta {
    tier: u32 = 0,
    label: InlineStr<16> = "init",
}

@authority(server)
resource Audit {
    calls: u32 = 0,
}

@net_rpc(direction = client_to_server, reliability = reliable, channel = 0)
rpc WideRpc {
    @quantize(min = -1.0e308, max = 1.0e308, bits = 16)
    val: f64,
}

@net_rpc(direction = client_to_server, reliability = reliable, channel = 0)
rpc ComplexCmd {
    meta: PayloadMeta,
    codes: [u32; 3],
}

obs on_wide(trg: &Trigger<WideRpc>, a: &mut res Audit) {
    a.calls += 1_u32;
}

obs on_complex(trg: &Trigger<ComplexCmd>, a: &mut res Audit) {
    a.calls += 1_u32;
}

net_sim_test "ut_wire"(latency: 16ms, jitter: 0ms, loss: 0.0, seed: 1, clients: 1) {
    send_rpc(0, WideRpc { val: 1.0e307_f64 });
    send_rpc(0, ComplexCmd {
        meta: PayloadMeta { tier: 7_u32, label: "alpha" },
        codes: [10_u32, 20_u32, 30_u32],
    });
}
"#;
        let analyzed = analyze_source("rpc_wire_ut.strata", src);
        assert!(analyzed.ok(), "diagnostics: {:?}", analyzed.diagnostics);
        let mir = lower_to_mir(&analyzed);
        let tmp = TempDir::new().expect("tempdir");
        let artifacts =
            compile_role_artifacts(&mir, "rpc_wire_ut", tmp.path()).expect("compile artifacts");
        let mut runner = NetSimRunner::new(&mir, &artifacts, 16.0, 0.0, 0.0, 1, 1).expect("new");
        let body = mir.net_sim_tests[0].body.clone();
        runner.exec_stmts(&body).expect("exec send_rpc calls");
        // Advance channel to tick 1 so packets queued with 16ms latency become due,
        // deliver directly into server's RPC dispatch slots, and inspect raw slot bytes
        // before `server.step_tick()` consumes and despawns the transient slot entities.
        runner.channel.current_tick = 1;
        runner.deliver_due_to(NetWorldTarget::Server);

        let mut inspect_slot = |slot_idx: usize, rpc_name: &str| -> (Vec<u8>, SolvedLayout) {
            let slot_canon = format!("test::rpc_wire_ut::{}", rpc_slot_name(slot_idx));
            let reg =
                find_registry_component(runner.server.app.world(), &mir.module_path, &slot_canon)
                    .expect("slot component registered");
            let world = runner.server.app.world_mut();
            let entities: Vec<Entity> = {
                let mut q = world.query::<Entity>();
                q.iter(world).collect()
            };
            let ent = entities
                .into_iter()
                .find(|&e| {
                    world
                        .get_entity(e)
                        .is_ok_and(|er| er.contains_id(reg.component_id))
                })
                .unwrap_or_else(|| panic!("missing injected slot entity for {rpc_name}"));
            let bytes = bamabi_host::read_entity_pod_bytes(world, ent, reg.handle)
                .expect("read slot bytes");
            let rpc_layout = find_layout_in_slice(
                &artifacts.server_mir.layouts,
                &mir.module_path,
                &format!("test::rpc_wire_ut::{rpc_name}"),
            )
            .expect("rpc layout")
            .clone();
            let slot_layout =
                find_layout_in_slice(&artifacts.server_mir.layouts, &mir.module_path, &slot_canon)
                    .expect("slot layout")
                    .clone();
            let payload_off = slot_layout
                .fields
                .iter()
                .find(|f| f.name == "payload")
                .map_or(0, |f| f.offset);
            (bytes[payload_off..].to_vec(), rpc_layout)
        };

        let (wide_bytes, wide_layout) = inspect_slot(0, "WideRpc");
        let wide_val_f = wide_layout.fields.iter().find(|f| f.name == "val").unwrap();
        let wide_sv = decode_ty_from_bytes_with_layouts(
            &wide_bytes,
            wide_val_f.offset,
            &wide_val_f.ty,
            &mir.enums,
            &artifacts.server_mir.layouts,
            &mir.module_path,
        )
        .expect("decode wide f64");
        let SimVal::Float(got_wide) = wide_sv else {
            panic!("expected Float, got {wide_sv:?}");
        };
        assert!(
            got_wide.is_finite() && got_wide > 5.0e306 && got_wide < 2.0e307,
            "got={got_wide}"
        );

        let (cplx_bytes, cplx_layout) = inspect_slot(1, "ComplexCmd");
        let meta_f = cplx_layout
            .fields
            .iter()
            .find(|f| f.name == "meta")
            .unwrap();
        let meta_sv = decode_ty_from_bytes_with_layouts(
            &cplx_bytes,
            meta_f.offset,
            &meta_f.ty,
            &mir.enums,
            &artifacts.server_mir.layouts,
            &mir.module_path,
        )
        .expect("decode PayloadMeta");
        assert!(
            matches!(
                &meta_sv,
                SimVal::Struct { fields, .. }
                    if fields.iter().any(|(k, v)| k == "tier" && sim_val_eq(v, &SimVal::Int(7)))
                        && fields.iter().any(|(k, v)| k == "label" && sim_val_eq(v, &SimVal::String("alpha".to_owned())))
            ),
            "unexpected decoded meta: {meta_sv:?}"
        );
        let codes_f = cplx_layout
            .fields
            .iter()
            .find(|f| f.name == "codes")
            .unwrap();
        let codes_sv = decode_ty_from_bytes_with_layouts(
            &cplx_bytes,
            codes_f.offset,
            &codes_f.ty,
            &mir.enums,
            &artifacts.server_mir.layouts,
            &mir.module_path,
        )
        .expect("decode codes array");
        assert!(
            sim_val_eq(
                &codes_sv,
                &SimVal::Array(vec![SimVal::Int(10), SimVal::Int(20), SimVal::Int(30)])
            ),
            "unexpected decoded codes: {codes_sv:?}"
        );
    }
}
