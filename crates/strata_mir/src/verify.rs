//! Structural SSA, CFG, zero-padding ABI, `@sparse`/`&mut?`, and `@deterministic` MIR verifier.

use crate::ir::{
    Inst, LocalId, MirFunction, MirModule, MirQuantizeSpec, MirStreamOpKind, MirType, Terminator,
};
use std::collections::{HashMap, HashSet};
use strata_sema::hir::AuthorityKind;
use thiserror::Error;

/// Structural invariant violation discovered in lowered `StrataMir`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MirVerifyError {
    /// Function has no entry block.
    #[error("MIR function `{function}` has no entry basic block")]
    MissingEntryBlock {
        /// Function name.
        function: String,
    },
    /// Terminator jumps to a non-existent `BlockId`.
    #[error("MIR function `{function}` block {block} branches to out-of-bounds BlockId({target})")]
    InvalidBlockTarget {
        /// Function name.
        function: String,
        /// Source block index.
        block: u32,
        /// Invalid target block index.
        target: u32,
    },
    /// Instruction or terminator references an out-of-bounds `LocalId`.
    #[error("MIR function `{function}` block {block} references undefined LocalId({local})")]
    InvalidLocalRef {
        /// Function name.
        function: String,
        /// Block index.
        block: u32,
        /// Invalid local index.
        local: u32,
    },
    /// Layout contains implicit padding (`size != sum(fields.size)`).
    #[error(
        "layout `{canonical_name}` violates zero implicit padding: size={size}, sum={field_sum}"
    )]
    ImplicitPadding {
        /// Component canonical name.
        canonical_name: String,
        /// Total struct size.
        size: usize,
        /// Sum of field sizes.
        field_sum: usize,
    },
    /// `@deterministic` function retained unconstrained FMA or non-deterministic transcendental.
    #[error("MIR function `{function}` violates @deterministic invariant: {detail}")]
    NonDeterministicOp {
        /// Function name.
        function: String,
        /// Specific violation.
        detail: String,
    },
    /// Query or transaction invariant violation in lowered CFG.
    #[error("MIR function `{function}` violates CFG/ABI invariant: {detail}")]
    InvalidCfgInvariant {
        /// Function name.
        function: String,
        /// Violation detail.
        detail: String,
    },
    /// Networking, quantization, RPC, handshake, or `net_sim_test` invariant violation.
    #[error("MIR network/quantization invariant violation in `{subject}`: {detail}")]
    InvalidNetworkInvariant {
        /// Component, RPC, test, or module subject name.
        subject: String,
        /// Violation detail.
        detail: String,
    },
}

/// Verifies CFG well-formedness, SSA local validity, zero-padding ABI layout invariants, sparse /
/// selective access modes, and `@deterministic` rules across an entire [`MirModule`].
pub fn verify_mir(module: &MirModule) -> Result<(), Vec<MirVerifyError>> {
    let mut errors = Vec::new();

    for layout in &module.layouts {
        let field_sum: usize = layout.fields.iter().map(|f| f.size).sum();
        if field_sum != layout.size {
            errors.push(MirVerifyError::ImplicitPadding {
                canonical_name: layout.canonical_name.clone(),
                size: layout.size,
                field_sum,
            });
        }
    }

    for func in module.functions.iter().chain(module.fns.iter()) {
        verify_function(func, module.is_deterministic, &mut errors);
    }

    verify_network_ir(module, &mut errors);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn is_quantizable_mir_ty(ty: &MirType) -> bool {
    match ty {
        MirType::U8
        | MirType::U16
        | MirType::U32
        | MirType::U64
        | MirType::I8
        | MirType::I16
        | MirType::I32
        | MirType::I64
        | MirType::F32
        | MirType::F64
        | MirType::Fix32
        | MirType::Fix64
        | MirType::Vec2
        | MirType::Vec3
        | MirType::Vec4
        | MirType::IVec2
        | MirType::IVec3
        | MirType::UVec2 => true,
        MirType::Named(n) => matches!(n.as_str(), "IVec2" | "IVec3" | "UVec2" | "Vec3a"),
        _ => false,
    }
}

fn verify_quantize_spec(subject: &str, spec: &MirQuantizeSpec, errors: &mut Vec<MirVerifyError>) {
    if !(1..=32).contains(&spec.bits) {
        errors.push(MirVerifyError::InvalidNetworkInvariant {
            subject: subject.to_owned(),
            detail: format!(
                "quantize field `{}` bits={} must be in 1..=32",
                spec.field_name, spec.bits
            ),
        });
    }
    if !(1..=4).contains(&spec.lane_count) {
        errors.push(MirVerifyError::InvalidNetworkInvariant {
            subject: subject.to_owned(),
            detail: format!(
                "quantize field `{}` lane_count={} must be in 1..=4",
                spec.field_name, spec.lane_count
            ),
        });
    }
    if !spec.min.is_finite() || !spec.max.is_finite() || spec.min >= spec.max {
        errors.push(MirVerifyError::InvalidNetworkInvariant {
            subject: subject.to_owned(),
            detail: format!(
                "quantize field `{}` requires finite min < max (got min={}, max={})",
                spec.field_name, spec.min, spec.max
            ),
        });
    }
    if let Some(step) = spec.step
        && (!step.is_finite() || step <= 0.0)
    {
        errors.push(MirVerifyError::InvalidNetworkInvariant {
            subject: subject.to_owned(),
            detail: format!(
                "quantize field `{}` step={} must be finite and > 0.0",
                spec.field_name, step
            ),
        });
    }
    let expected_total = u32::from(spec.bits) * u32::from(spec.lane_count);
    if spec.total_bits != expected_total {
        errors.push(MirVerifyError::InvalidNetworkInvariant {
            subject: subject.to_owned(),
            detail: format!(
                "quantize field `{}` total_bits={} != bits({}) * lane_count({})",
                spec.field_name, spec.total_bits, spec.bits, spec.lane_count
            ),
        });
    }
    if !is_quantizable_mir_ty(&spec.field_ty) {
        errors.push(MirVerifyError::InvalidNetworkInvariant {
            subject: subject.to_owned(),
            detail: format!(
                "quantize field `{}` has non-numeric/non-vector MirType::{:?}",
                spec.field_name, spec.field_ty
            ),
        });
    }
}

fn verify_bit_intervals(
    subject: &str,
    mut intervals: Vec<(u32, u32, &str)>,
    packed_bits: u32,
    errors: &mut Vec<MirVerifyError>,
) {
    intervals.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut prev_end = 0u32;
    let mut prev_name = "";
    for (start, end, name) in intervals {
        if end < start || end > packed_bits {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: subject.to_owned(),
                detail: format!(
                    "bit interval [{start}, {end}) for field `{name}` exceeds packed_bits={packed_bits}"
                ),
            });
        }
        if start < prev_end {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: subject.to_owned(),
                detail: format!(
                    "overlapping bit-packed field `{name}` starting at bit {start} overlaps `{prev_name}` ending at bit {prev_end}"
                ),
            });
        }
        prev_end = prev_end.max(end);
        prev_name = name;
    }
}

fn verify_network_ir(module: &MirModule, errors: &mut Vec<MirVerifyError>) {
    let mut seen_net_components = HashSet::new();
    for nc in &module.net_components {
        if nc.name.is_empty() || nc.canonical_name.is_empty() {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: nc.canonical_name.clone(),
                detail: "MirNetComponent name and canonical_name must be non-empty".to_owned(),
            });
        }
        if !seen_net_components.insert(nc.canonical_name.clone()) {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: nc.canonical_name.clone(),
                detail: format!(
                    "duplicate MirNetComponent canonical_name `{}`",
                    nc.canonical_name
                ),
            });
        }
        if nc.schema_fingerprint == 0 {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: nc.canonical_name.clone(),
                detail: "MirNetComponent schema_fingerprint must be non-zero".to_owned(),
            });
        }
        if nc.authority == AuthorityKind::Server && nc.is_predicted {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: nc.canonical_name.clone(),
                detail:
                    "MirNetComponent cannot combine AuthorityKind::Server with is_predicted=true"
                        .to_owned(),
            });
        }
        if let Some(rate) = nc.rate_hz
            && (!rate.is_finite() || rate <= 0.0)
        {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: nc.canonical_name.clone(),
                detail: format!("MirNetComponent rate_hz ({rate}) must be finite and > 0"),
            });
        }
        if let Some(iv) = nc.interval_ticks
            && iv == 0
        {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: nc.canonical_name.clone(),
                detail: "MirNetComponent interval_ticks must be > 0".to_owned(),
            });
        }
        if nc.packed_bytes != nc.packed_bits.div_ceil(8) {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: nc.canonical_name.clone(),
                detail: format!(
                    "packed_bytes ({}) != packed_bits ({}).div_ceil(8)",
                    nc.packed_bytes, nc.packed_bits
                ),
            });
        }
        for spec in &nc.quantize_specs {
            verify_quantize_spec(&nc.canonical_name, spec, errors);
        }
        for wf in &nc.wire_fields {
            if let Some(ref spec) = wf.quantize {
                verify_quantize_spec(&nc.canonical_name, spec, errors);
                if spec.bit_offset != wf.bit_offset || spec.total_bits != wf.total_bits {
                    errors.push(MirVerifyError::InvalidNetworkInvariant {
                        subject: nc.canonical_name.clone(),
                        detail: format!(
                            "wire_field `{}` quantize bit range [{}..+{}) mismatches wire_field [{}..+{})",
                            wf.field_name,
                            spec.bit_offset,
                            spec.total_bits,
                            wf.bit_offset,
                            wf.total_bits
                        ),
                    });
                }
            }
        }
        let mut wf_intervals = Vec::with_capacity(nc.wire_fields.len());
        for wf in &nc.wire_fields {
            match wf.bit_offset.checked_add(wf.total_bits) {
                Some(end) => wf_intervals.push((wf.bit_offset, end, wf.field_name.as_str())),
                None => errors.push(MirVerifyError::InvalidNetworkInvariant {
                    subject: nc.canonical_name.clone(),
                    detail: format!(
                        "wire_field `{}` bit interval ({} + {}) overflows u32",
                        wf.field_name, wf.bit_offset, wf.total_bits
                    ),
                }),
            }
        }
        verify_bit_intervals(&nc.canonical_name, wf_intervals, nc.packed_bits, errors);

        let mut q_intervals = Vec::with_capacity(nc.quantize_specs.len());
        for q in &nc.quantize_specs {
            match q.bit_offset.checked_add(q.total_bits) {
                Some(end) => q_intervals.push((q.bit_offset, end, q.field_name.as_str())),
                None => errors.push(MirVerifyError::InvalidNetworkInvariant {
                    subject: nc.canonical_name.clone(),
                    detail: format!(
                        "quantize_specs `{}` bit interval ({} + {}) overflows u32",
                        q.field_name, q.bit_offset, q.total_bits
                    ),
                }),
            }
        }
        verify_bit_intervals(&nc.canonical_name, q_intervals, nc.packed_bits, errors);
    }

    let mut seen_rpc_names = HashSet::new();
    let mut seen_rpc_ids = HashSet::new();
    for rpc in &module.rpcs {
        if rpc.name.is_empty() || rpc.canonical_name.is_empty() {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: rpc.canonical_name.clone(),
                detail: "MirRpc name and canonical_name must be non-empty".to_owned(),
            });
        }
        if !seen_rpc_names.insert(rpc.canonical_name.clone()) {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: rpc.canonical_name.clone(),
                detail: format!("duplicate MirRpc canonical_name `{}`", rpc.canonical_name),
            });
        }
        if !seen_rpc_ids.insert(rpc.rpc_id) {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: rpc.canonical_name.clone(),
                detail: format!("duplicate MirRpc rpc_id {:#x}", rpc.rpc_id),
            });
        }
        if rpc.schema_fingerprint == 0 {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: rpc.canonical_name.clone(),
                detail: "MirRpc schema_fingerprint must be non-zero".to_owned(),
            });
        }
        if rpc.packed_bytes != rpc.packed_bits.div_ceil(8) {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: rpc.canonical_name.clone(),
                detail: format!(
                    "MirRpc packed_bytes ({}) != packed_bits ({}).div_ceil(8)",
                    rpc.packed_bytes, rpc.packed_bits
                ),
            });
        }
        for spec in &rpc.quantize_specs {
            verify_quantize_spec(&rpc.canonical_name, spec, errors);
        }
        for wf in &rpc.wire_fields {
            if let Some(ref spec) = wf.quantize {
                verify_quantize_spec(&rpc.canonical_name, spec, errors);
                if spec.bit_offset != wf.bit_offset || spec.total_bits != wf.total_bits {
                    errors.push(MirVerifyError::InvalidNetworkInvariant {
                        subject: rpc.canonical_name.clone(),
                        detail: format!(
                            "wire_field `{}` quantize bit range [{}..+{}) mismatches wire_field [{}..+{})",
                            wf.field_name,
                            spec.bit_offset,
                            spec.total_bits,
                            wf.bit_offset,
                            wf.total_bits
                        ),
                    });
                }
            }
        }
        let mut wf_intervals = Vec::with_capacity(rpc.wire_fields.len());
        for wf in &rpc.wire_fields {
            match wf.bit_offset.checked_add(wf.total_bits) {
                Some(end) => wf_intervals.push((wf.bit_offset, end, wf.field_name.as_str())),
                None => errors.push(MirVerifyError::InvalidNetworkInvariant {
                    subject: rpc.canonical_name.clone(),
                    detail: format!(
                        "wire_field `{}` bit interval ({} + {}) overflows u32",
                        wf.field_name, wf.bit_offset, wf.total_bits
                    ),
                }),
            }
        }
        verify_bit_intervals(&rpc.canonical_name, wf_intervals, rpc.packed_bits, errors);

        let mut q_intervals = Vec::with_capacity(rpc.quantize_specs.len());
        for q in &rpc.quantize_specs {
            match q.bit_offset.checked_add(q.total_bits) {
                Some(end) => q_intervals.push((q.bit_offset, end, q.field_name.as_str())),
                None => errors.push(MirVerifyError::InvalidNetworkInvariant {
                    subject: rpc.canonical_name.clone(),
                    detail: format!(
                        "quantize_specs `{}` bit interval ({} + {}) overflows u32",
                        q.field_name, q.bit_offset, q.total_bits
                    ),
                }),
            }
        }
        verify_bit_intervals(&rpc.canonical_name, q_intervals, rpc.packed_bits, errors);
    }

    for op in &module.net_stream_ops {
        if matches!(
            op.kind,
            MirStreamOpKind::StreamRead | MirStreamOpKind::StreamWriteBatch
        ) && !op.requires_outside_par
        {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: op.canonical_stream.clone(),
                detail: format!(
                    "net_stream_ops {:?} on `{}` (Slots 30/32) must have requires_outside_par=true",
                    op.kind, op.stream
                ),
            });
        }
    }

    for nst in &module.net_sim_tests {
        if !nst.loss.is_finite() || !(0.0..=1.0).contains(&nst.loss) {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: nst.name.clone(),
                detail: format!("MirNetSimTest loss ({}) must be in 0.0..=1.0", nst.loss),
            });
        }
        if !nst.latency_ms.is_finite() || nst.latency_ms < 0.0 {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: nst.name.clone(),
                detail: format!(
                    "MirNetSimTest latency_ms ({}) must be finite and >= 0.0",
                    nst.latency_ms
                ),
            });
        }
        if !nst.jitter_ms.is_finite() || nst.jitter_ms < 0.0 {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: nst.name.clone(),
                detail: format!(
                    "MirNetSimTest jitter_ms ({}) must be finite and >= 0.0",
                    nst.jitter_ms
                ),
            });
        }
        if nst.clients == 0 {
            errors.push(MirVerifyError::InvalidNetworkInvariant {
                subject: nst.name.clone(),
                detail: "MirNetSimTest clients must be >= 1".to_owned(),
            });
        }
    }

    let comp_fp_map: HashMap<&str, u64> = module
        .net_handshake
        .component_fingerprints
        .iter()
        .map(|(k, v)| (k.as_str(), *v))
        .collect();
    for nc in &module.net_components {
        match comp_fp_map.get(nc.canonical_name.as_str()) {
            Some(&fp) if fp == nc.schema_fingerprint => {}
            Some(&fp) => {
                errors.push(MirVerifyError::InvalidNetworkInvariant {
                    subject: nc.canonical_name.clone(),
                    detail: format!(
                        "MirNetHandshake component fingerprint mismatch: expected {:#x}, got {:#x}",
                        nc.schema_fingerprint, fp
                    ),
                });
            }
            None => {
                errors.push(MirVerifyError::InvalidNetworkInvariant {
                    subject: nc.canonical_name.clone(),
                    detail: "MirNetComponent missing from MirNetHandshake::component_fingerprints"
                        .to_owned(),
                });
            }
        }
    }

    let rpc_fp_map: HashMap<&str, u64> = module
        .net_handshake
        .rpc_fingerprints
        .iter()
        .map(|(k, v)| (k.as_str(), *v))
        .collect();
    for rpc in &module.rpcs {
        match rpc_fp_map.get(rpc.canonical_name.as_str()) {
            Some(&fp) if fp == rpc.schema_fingerprint => {}
            Some(&fp) => {
                errors.push(MirVerifyError::InvalidNetworkInvariant {
                    subject: rpc.canonical_name.clone(),
                    detail: format!(
                        "MirNetHandshake rpc fingerprint mismatch: expected {:#x}, got {:#x}",
                        rpc.schema_fingerprint, fp
                    ),
                });
            }
            None => {
                errors.push(MirVerifyError::InvalidNetworkInvariant {
                    subject: rpc.canonical_name.clone(),
                    detail: "MirRpc missing from MirNetHandshake::rpc_fingerprints".to_owned(),
                });
            }
        }
    }

    if (!module.net_components.is_empty() || !module.rpcs.is_empty())
        && module.net_handshake.module_net_fingerprint == 0
    {
        errors.push(MirVerifyError::InvalidNetworkInvariant {
            subject: module.module_path.clone(),
            detail: "MirNetHandshake module_net_fingerprint must be non-zero when net_components or rpcs exist".to_owned(),
        });
    }
}

fn verify_function(func: &MirFunction, mod_det: bool, errors: &mut Vec<MirVerifyError>) {
    if func.blocks.is_empty() {
        errors.push(MirVerifyError::MissingEntryBlock {
            function: func.name.clone(),
        });
        return;
    }

    let num_blocks = func.blocks.len() as u32;
    let num_locals = func.locals.len() as u32;
    let enforce_det = mod_det || func.is_deterministic;

    for (idx, loc) in func.locals.iter().enumerate() {
        if loc.id.0 != idx as u32 {
            errors.push(MirVerifyError::InvalidCfgInvariant {
                function: func.name.clone(),
                detail: format!("non-dense LocalId({}): expected {}", loc.id.0, idx),
            });
        }
    }

    let check_local = |local: LocalId, blk: u32, errs: &mut Vec<MirVerifyError>| {
        if local.0 >= num_locals {
            errs.push(MirVerifyError::InvalidLocalRef {
                function: func.name.clone(),
                block: blk,
                local: local.0,
            });
        }
    };

    for param in &func.params {
        if let Some(l) = param.local {
            check_local(l, 0, errors);
        }
    }
    for res in &func.resources {
        check_local(res.ptr_local, 0, errors);
    }

    let check_block = |target: u32, src: u32, errs: &mut Vec<MirVerifyError>| {
        if target >= num_blocks {
            errs.push(MirVerifyError::InvalidBlockTarget {
                function: func.name.clone(),
                block: src,
                target,
            });
        }
    };

    for (bb_idx, bb) in func.blocks.iter().enumerate() {
        let blk = bb_idx as u32;
        if bb.id.0 != blk {
            errors.push(MirVerifyError::InvalidCfgInvariant {
                function: func.name.clone(),
                detail: format!("non-dense BlockId({}): expected {}", bb.id.0, blk),
            });
        }

        for stmt in &bb.stmts {
            if let Some(dst) = stmt.dst {
                check_local(dst, blk, errors);
            }
            for used in inst_locals(&stmt.inst) {
                check_local(used, blk, errors);
            }

            let check_local_ty =
                |local: LocalId, expected: MirType, desc: &str, errs: &mut Vec<MirVerifyError>| {
                    if let Some(loc) = func.locals.get(local.0 as usize)
                        && loc.ty != expected
                    {
                        errs.push(MirVerifyError::InvalidCfgInvariant {
                            function: func.name.clone(),
                            detail: format!(
                                "{desc} LocalId({}) must have MirType::{expected:?}",
                                local.0
                            ),
                        });
                    }
                };

            match &stmt.inst {
                Inst::CmdRollback { checkpoint } => {
                    check_local_ty(
                        *checkpoint,
                        MirType::Checkpoint,
                        "CmdRollback checkpoint",
                        errors,
                    );
                }
                Inst::SpawnBatchBegin { count, .. } => {
                    if let Some(d) = stmt.dst {
                        check_local_ty(d, MirType::U64, "SpawnBatchBegin dst", errors);
                    } else {
                        errors.push(MirVerifyError::InvalidCfgInvariant {
                            function: func.name.clone(),
                            detail:
                                "SpawnBatchBegin requires a destination LocalId of MirType::U64"
                                    .to_owned(),
                        });
                    }
                    check_local_ty(*count, MirType::U32, "SpawnBatchBegin count", errors);
                }
                Inst::SpawnBatchPush { batch, index, .. } => {
                    check_local_ty(*batch, MirType::U64, "SpawnBatchPush batch", errors);
                    check_local_ty(*index, MirType::U32, "SpawnBatchPush index", errors);
                }
                Inst::SpawnBatchCommit { batch } => {
                    check_local_ty(*batch, MirType::U64, "SpawnBatchCommit batch", errors);
                }
                _ => {}
            }

            if enforce_det {
                match &stmt.inst {
                    Inst::BinOp {
                        allow_fma: true, ..
                    } => {
                        errors.push(MirVerifyError::NonDeterministicOp {
                            function: func.name.clone(),
                            detail: "hardware FMA contraction must be disabled".to_owned(),
                        });
                    }
                    Inst::IntrinsicMath {
                        name,
                        deterministic: false,
                        ..
                    } => {
                        errors.push(MirVerifyError::NonDeterministicOp {
                            function: func.name.clone(),
                            detail: format!("intrinsic `{name}` must use deterministic libm"),
                        });
                    }
                    Inst::ParForEachChunkReadonly {
                        deterministic_order: false,
                        ..
                    } => {
                        errors.push(MirVerifyError::NonDeterministicOp {
                            function: func.name.clone(),
                            detail: "ParForEachChunkReadonly requires deterministic_order = true"
                                .to_owned(),
                        });
                    }
                    _ => {}
                }
            }
        }

        match &bb.terminator {
            Terminator::Return(opt_l) => {
                if let Some(l) = opt_l {
                    check_local(*l, blk, errors);
                }
            }
            Terminator::Goto(dst) => check_block(dst.0, blk, errors),
            Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } => {
                check_local(*cond, blk, errors);
                check_block(then_bb.0, blk, errors);
                check_block(else_bb.0, blk, errors);
            }
            Terminator::Switch {
                scrutinee,
                cases,
                default_bb,
            } => {
                check_local(*scrutinee, blk, errors);
                for (_, dst) in cases {
                    check_block(dst.0, blk, errors);
                }
                check_block(default_bb.0, blk, errors);
            }
        }
    }

    // Verify `@sparse` terms use `IterColRows*` and dense terms use `IterCol*`
    for qb in &func.query_bindings {
        if qb.is_point_lookup {
            continue;
        }
        for term in &qb.terms {
            if term.is_sparse {
                let used_dense = func.blocks.iter().any(|bb| {
                    bb.stmts.iter().any(|s| match &s.inst {
                        Inst::IterColRead {
                            query_idx,
                            term_idx,
                            ..
                        }
                        | Inst::IterColWrite {
                            query_idx,
                            term_idx,
                            ..
                        }
                        | Inst::IterColWriteUntracked {
                            query_idx,
                            term_idx,
                            ..
                        } => *query_idx == qb.query_idx && *term_idx == term.term_idx,
                        _ => false,
                    })
                });
                if used_dense {
                    errors.push(MirVerifyError::InvalidCfgInvariant {
                        function: func.name.clone(),
                        detail: format!(
                            "@sparse query {} term {} (`{}`) used dense IterCol* instead of IterColRows*",
                            qb.query_idx, term.term_idx, term.storage_key
                        ),
                    });
                }
            } else {
                let used_sparse = func.blocks.iter().any(|bb| {
                    bb.stmts.iter().any(|s| match &s.inst {
                        Inst::IterColRowsRead {
                            query_idx,
                            term_idx,
                            ..
                        }
                        | Inst::IterColRowsWrite {
                            query_idx,
                            term_idx,
                            ..
                        } => *query_idx == qb.query_idx && *term_idx == term.term_idx,
                        _ => false,
                    })
                });
                if used_sparse {
                    errors.push(MirVerifyError::InvalidCfgInvariant {
                        function: func.name.clone(),
                        detail: format!(
                            "dense query {} term {} (`{}`) used sparse IterColRows* instead of IterCol*",
                            qb.query_idx, term.term_idx, term.storage_key
                        ),
                    });
                }
            }
        }
    }

    for ct in &func.changed_terms {
        let q_idx = ct.query_idx as usize;
        let t_idx = ct.term_idx as usize;
        let valid_q = q_idx < func.queries.len() && q_idx < func.query_bindings.len();
        let valid_t = valid_q && t_idx < func.query_bindings[q_idx].terms.len();
        if !valid_t {
            errors.push(MirVerifyError::InvalidCfgInvariant {
                function: func.name.clone(),
                detail: format!(
                    "MirChangedTerm ({}, {}) out of bounds for query_bindings",
                    ct.query_idx, ct.term_idx
                ),
            });
        }
    }

    for op in &func.stream_ops {
        if matches!(
            op.kind,
            MirStreamOpKind::StreamRead | MirStreamOpKind::StreamWriteBatch
        ) {
            if !op.requires_outside_par {
                errors.push(MirVerifyError::InvalidCfgInvariant {
                    function: func.name.clone(),
                    detail: format!(
                        "{:?} on `{}` (Slots 30/32) must have requires_outside_par=true",
                        op.kind, op.stream
                    ),
                });
            }
            if func.par_chunk.is_some() {
                errors.push(MirVerifyError::InvalidCfgInvariant {
                    function: func.name.clone(),
                    detail: format!(
                        "@par chunk function cannot execute {:?} on `{}` (Slots 30/32 must run outside @par)",
                        op.kind, op.stream
                    ),
                });
            }
        }
    }

    verify_atomic_tx_no_row_ptr_loops(func, errors);
}

fn verify_atomic_tx_no_row_ptr_loops(func: &MirFunction, errors: &mut Vec<MirVerifyError>) {
    use crate::ir::BlockId;
    use std::collections::VecDeque;

    let ckpt_blocks: Vec<BlockId> = func
        .blocks
        .iter()
        .filter(|bb| {
            bb.stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::CmdCheckpoint))
        })
        .map(|bb| bb.id)
        .collect();
    if ckpt_blocks.is_empty() {
        return;
    }

    // Trace locals derived from `Inst::RowPtr` (direct or via `FieldPtr` / `Copy`).
    let mut row_derived: HashSet<LocalId> = HashSet::new();
    let mut changed = true;
    while changed {
        changed = false;
        for bb in &func.blocks {
            for s in &bb.stmts {
                let Some(dst) = s.dst else { continue };
                let is_row = match &s.inst {
                    Inst::RowPtr { .. } => true,
                    Inst::FieldPtr { base_ptr, .. } => row_derived.contains(base_ptr),
                    Inst::Copy { val } => row_derived.contains(val),
                    _ => false,
                };
                if is_row && row_derived.insert(dst) {
                    changed = true;
                }
            }
        }
    }
    if row_derived.is_empty() {
        return;
    }

    let term_succs = |t: &Terminator| -> Vec<BlockId> {
        match t {
            Terminator::Return(_) => Vec::new(),
            Terminator::Goto(b) => vec![*b],
            Terminator::Branch {
                then_bb, else_bb, ..
            } => vec![*then_bb, *else_bb],
            Terminator::Switch {
                cases, default_bb, ..
            } => {
                let mut v: Vec<BlockId> = cases.iter().map(|(_, b)| *b).collect();
                v.push(*default_bb);
                v
            }
        }
    };

    for ckpt_bb in ckpt_blocks {
        // Find matching `atomic_merge` reachable from `ckpt_bb`
        let mut merge_bb = None;
        let mut vis = HashSet::new();
        let mut q = VecDeque::new();
        vis.insert(ckpt_bb);
        q.push_back(ckpt_bb);
        while let Some(b) = q.pop_front() {
            if let Some(bb) = func.blocks.get(b.0 as usize) {
                if bb.label == "atomic_merge" && b != ckpt_bb {
                    merge_bb = Some(b);
                    break;
                }
                for s in term_succs(&bb.terminator) {
                    if vis.insert(s) {
                        q.push_back(s);
                    }
                }
            }
        }
        let Some(merge_bb) = merge_bb else {
            continue;
        };

        // Collect non-rollback `tx_blocks` starting from successors of `ckpt_bb`
        let mut tx_set = HashSet::new();
        let mut tx_q = VecDeque::new();
        if let Some(cbb) = func.blocks.get(ckpt_bb.0 as usize) {
            for s in term_succs(&cbb.terminator) {
                if s != merge_bb
                    && func
                        .blocks
                        .get(s.0 as usize)
                        .is_some_and(|b| b.label != "atomic_rollback")
                    && tx_set.insert(s)
                {
                    tx_q.push_back(s);
                }
            }
        }
        while let Some(b) = tx_q.pop_front() {
            if let Some(bb) = func.blocks.get(b.0 as usize) {
                for s in term_succs(&bb.terminator) {
                    if s != merge_bb
                        && func
                            .blocks
                            .get(s.0 as usize)
                            .is_some_and(|blk| blk.label != "atomic_rollback")
                        && tx_set.insert(s)
                    {
                        tx_q.push_back(s);
                    }
                }
            }
        }

        // Any block `b` in `tx_set` that can reach itself within `tx_set` is inside a tx loop.
        for &b in &tx_set {
            let Some(bb) = func.blocks.get(b.0 as usize) else {
                continue;
            };
            let has_row_store = bb.stmts.iter().any(|s| match &s.inst {
                Inst::FieldStore { base_ptr, .. } | Inst::ArrayStore { base_ptr, .. } => {
                    row_derived.contains(base_ptr)
                }
                _ => false,
            });
            if !has_row_store {
                continue;
            }
            let mut seen = HashSet::new();
            let mut lq = VecDeque::new();
            for s in term_succs(&bb.terminator) {
                if tx_set.contains(&s) && seen.insert(s) {
                    lq.push_back(s);
                }
            }
            let mut in_cycle = false;
            while let Some(cur) = lq.pop_front() {
                if cur == b {
                    in_cycle = true;
                    break;
                }
                if let Some(cbb) = func.blocks.get(cur.0 as usize) {
                    for s in term_succs(&cbb.terminator) {
                        if tx_set.contains(&s) && seen.insert(s) {
                            lq.push_back(s);
                        }
                    }
                }
            }
            if in_cycle {
                errors.push(MirVerifyError::InvalidCfgInvariant {
                    function: func.name.clone(),
                    detail: format!(
                        "multi-entity RowPtr mutation loop inside `atomic` block `{}` is not supported by single-slot pre-image undo log",
                        bb.label
                    ),
                });
            }
        }
    }
}

fn inst_locals(inst: &Inst) -> Vec<LocalId> {
    match inst {
        Inst::ConstInt { .. }
        | Inst::ConstFloat { .. }
        | Inst::ConstBool { .. }
        | Inst::ConstVec { .. }
        | Inst::ConstString { .. }
        | Inst::SlotAlloc { .. }
        | Inst::IterNextChunk { .. }
        | Inst::IterChunkLen { .. }
        | Inst::IterEntities { .. }
        | Inst::IterColRead { .. }
        | Inst::IterColWrite { .. }
        | Inst::IterColWriteUntracked { .. }
        | Inst::IterColRowsRead { .. }
        | Inst::IterColRowsWrite { .. }
        | Inst::IterCount { .. }
        | Inst::IterReset { .. }
        | Inst::SpatialCsrBegin { .. }
        | Inst::SpatialCsrPrefixSum { .. }
        | Inst::ParForEachChunk { .. }
        | Inst::ParForEachChunkReadonly { .. }
        | Inst::ResRead { .. }
        | Inst::ResWrite { .. }
        | Inst::BindNamedObject { .. }
        | Inst::ResolveNamedObject { .. }
        | Inst::InternSymbol { .. }
        | Inst::TriggerPayload { .. }
        | Inst::TriggerTarget
        | Inst::CmdDespawnAll { .. }
        | Inst::CmdCheckpoint
        | Inst::SpatialRebuildCsr { .. }
        | Inst::FsmDispatch { .. }
        | Inst::MigrateSrcPtr { .. }
        | Inst::MigrateDstPtr { .. } => Vec::new(),

        Inst::Copy { val }
        | Inst::SlotLoad { slot: val }
        | Inst::UnOp { val, .. }
        | Inst::Cast { val, .. }
        | Inst::VecExtract { vec: val, .. }
        | Inst::VecSwizzle { vec: val, .. }
        | Inst::FieldPtr { base_ptr: val, .. }
        | Inst::FieldLoad { base_ptr: val, .. }
        | Inst::EntityGet { entity: val, .. }
        | Inst::EntityGetMut { entity: val, .. }
        | Inst::IterUpCascade { entity: val, .. }
        | Inst::SpatialCsrCount { pos: val, .. }
        | Inst::GraceIsActive { ptr: val }
        | Inst::GraceClear { ptr: val }
        | Inst::TimelineInWindow { ptr: val, .. }
        | Inst::SpawnBatchBegin { count: val, .. }
        | Inst::SpawnBatchCommit { batch: val }
        | Inst::CmdDespawn { entity: val }
        | Inst::CmdRemove { entity: val, .. }
        | Inst::StreamEmit { payload: val, .. }
        | Inst::CmdRollback { checkpoint: val }
        | Inst::CurveSample { x: val, .. }
        | Inst::TableLoad { key: val, .. }
        | Inst::OptionalChunkIsPresent { slice_ptr: val, .. }
        | Inst::ShadowCommit {
            shadow_slot: val, ..
        }
        | Inst::RequireTrue { cond: val }
        | Inst::ReduceInit { identity: val, .. } => vec![*val],

        Inst::SlotStore { slot, val }
        | Inst::VecInsert { vec: slot, val, .. }
        | Inst::FieldStore {
            base_ptr: slot,
            val,
            ..
        }
        | Inst::RowPtr {
            col_ptr: slot,
            row_idx: val,
            ..
        }
        | Inst::SpatialCsrScatter {
            entity: slot,
            pos: val,
            ..
        }
        | Inst::EntityAtRow {
            entities_ptr: slot,
            row_idx: val,
        }
        | Inst::IterMarkChangedRange {
            run_start: slot,
            run_len: val,
            ..
        }
        | Inst::ArrayIndex {
            base: slot,
            index: val,
        }
        | Inst::GraceArm {
            ptr: slot,
            duration_sec: val,
        }
        | Inst::GraceTick {
            ptr: slot,
            dt_sec: val,
        }
        | Inst::InputBufConsume {
            ptr: slot,
            action_id: val,
            ..
        }
        | Inst::InputBufPeek {
            ptr: slot,
            action_id: val,
            ..
        }
        | Inst::InputBufTick {
            ptr: slot,
            dt_sec: val,
            ..
        }
        | Inst::BitSetSet {
            ptr: slot,
            bit: val,
            ..
        }
        | Inst::BitSetGet {
            ptr: slot,
            bit: val,
            ..
        }
        | Inst::BitSetClear {
            ptr: slot,
            bit: val,
            ..
        }
        | Inst::DirtyRunInit {
            run_start: slot,
            run_len: val,
        }
        | Inst::ShadowWrite {
            shadow_slot: slot,
            val,
            ..
        }
        | Inst::TimelineAdvance {
            cursor_ptr: slot,
            dt_sec: val,
            ..
        }
        | Inst::TaskStep {
            pc_local: slot,
            timer_local: val,
            ..
        }
        | Inst::CmdRemoveRelation {
            entity: slot,
            target: val,
            ..
        }
        | Inst::BinOp {
            lhs: slot,
            rhs: val,
            ..
        } => vec![*slot, *val],

        Inst::ReduceAccum { acc, val, .. } => vec![*acc, *val],

        Inst::DirtyRunRecordRow {
            run_start,
            run_len,
            row_idx,
        }
        | Inst::ArrayStore {
            base_ptr: run_start,
            index: run_len,
            val: row_idx,
            ..
        } => vec![*run_start, *run_len, *row_idx],

        Inst::InputBufPush {
            ptr,
            action_id,
            window_sec,
            ..
        } => vec![*ptr, *action_id, *window_sec],

        Inst::SpatialQueryDisc { center, radius, .. } => vec![*center, *radius],

        Inst::SpatialQuerySegmentAt {
            start,
            end,
            radius,
            tick_offset,
            ..
        } => vec![*start, *end, *radius, *tick_offset],

        Inst::IntrinsicMath { args, .. }
        | Inst::Call { args, .. }
        | Inst::ArrayInit { elems: args } => args.clone(),

        Inst::StructInit { fields, .. } => fields.iter().map(|(_, l)| *l).collect(),

        Inst::CmdSpawn { components, .. } => components.iter().map(|(_, l)| *l).collect(),

        Inst::CmdSpawnBatch { count, components } => {
            let mut out = vec![*count];
            out.extend(components.iter().map(|(_, l)| *l));
            out
        }

        Inst::SpawnBatchPush {
            batch,
            index,
            components,
        } => {
            let mut out = vec![*batch, *index];
            out.extend(components.iter().map(|(_, l)| *l));
            out
        }

        Inst::CmdInsert { entity, data, .. } => {
            let mut out = vec![*entity];
            if let Some(d) = data {
                out.push(*d);
            }
            out
        }

        Inst::CmdTrigger {
            target, payload, ..
        } => {
            let mut out = Vec::new();
            if let Some(t) = target {
                out.push(*t);
            }
            if let Some(p) = payload {
                out.push(*p);
            }
            out
        }

        Inst::CmdInsertRelation {
            entity,
            target,
            payload,
            ..
        } => {
            let mut out = vec![*entity, *target];
            if let Some(p) = payload {
                out.push(*p);
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        BasicBlock, BlockId, Inst, LocalId, MirFnKind, MirFunction, MirModule, MirStmt, MirType,
    };
    use indexmap::IndexMap;

    fn base_module(func: MirFunction) -> MirModule {
        MirModule {
            module_path: "test::mod".to_owned(),
            is_deterministic: false,
            layouts: Vec::new(),
            enums: Vec::new(),
            consts: Vec::new(),
            tables: Vec::new(),
            curves: Vec::new(),
            relations: Vec::new(),
            spatial_indices: Vec::new(),
            timelines: Vec::new(),
            tasks: Vec::new(),
            fsms: Vec::new(),
            objects: Vec::new(),
            migrations: Vec::new(),
            fns: Vec::new(),
            functions: vec![func],
            schedules: Vec::new(),
            sim_tests: Vec::new(),
            field_defaults: IndexMap::new(),
            rpcs: Vec::new(),
            net_components: Vec::new(),
            net_sim_tests: Vec::new(),
            net_handshake: crate::ir::MirNetHandshake::default(),
            net_stream_ops: Vec::new(),
        }
    }

    /// Verifies CFG verifier rejects dangling branch target blocks and undefined SSA locals.
    #[test]
    fn verify_rejects_invalid_block_target_and_undefined_local() {
        let mut f_bad_target = MirFunction::new("bad_jump", MirFnKind::System);
        f_bad_target.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts: Vec::new(),
            terminator: Terminator::Goto(BlockId(99)),
        });
        let m_bad_target = base_module(f_bad_target);
        let errs = verify_mir(&m_bad_target).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, MirVerifyError::InvalidBlockTarget { target: 99, .. }))
        );

        let mut f_bad_local = MirFunction::new("bad_local", MirFnKind::System);
        f_bad_local.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts: vec![MirStmt {
                dst: None,
                inst: Inst::RequireTrue { cond: LocalId(7) },
            }],
            terminator: Terminator::Return(None),
        });
        let m_bad_local = base_module(f_bad_local);
        let errs_local = verify_mir(&m_bad_local).unwrap_err();
        assert!(
            errs_local
                .iter()
                .any(|e| matches!(e, MirVerifyError::InvalidLocalRef { local: 7, .. }))
        );
    }

    /// Verifies `@deterministic` validator flags any function still permitting FMA after lowering.
    #[test]
    fn verify_rejects_fma_when_deterministic() {
        let mut func = MirFunction::new("det", MirFnKind::System);
        func.is_deterministic = true;
        let a = func.alloc_local("a", MirType::F32);
        let b = func.alloc_local("b", MirType::F32);
        let out = func.alloc_local("out", MirType::F32);
        func.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts: vec![MirStmt {
                dst: Some(out),
                inst: Inst::BinOp {
                    op: "*".to_owned(),
                    lhs: a,
                    rhs: b,
                    allow_fma: true,
                },
            }],
            terminator: Terminator::Return(None),
        });
        let errs = verify_mir(&base_module(func)).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| matches!(e, MirVerifyError::NonDeterministicOp { .. }))
        );
    }

    /// Verifies `SpawnBatch*` instructions require `MirType::U64` handle and `MirType::U32` counts/indices.
    #[test]
    fn verify_rejects_mismatched_spawn_batch_types() {
        let mut func = MirFunction::new("bad_batch", MirFnKind::System);
        let cnt_bad = func.alloc_local("cnt", MirType::I32);
        let batch_bad = func.alloc_local("batch", MirType::U32);
        let idx_bad = func.alloc_local("idx", MirType::I32);
        func.blocks.push(BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts: vec![
                MirStmt {
                    dst: Some(batch_bad),
                    inst: Inst::SpawnBatchBegin {
                        count: cnt_bad,
                        components: vec!["Pos".to_owned()],
                    },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::SpawnBatchPush {
                        batch: batch_bad,
                        index: idx_bad,
                        components: Vec::new(),
                    },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::SpawnBatchCommit { batch: batch_bad },
                },
            ],
            terminator: Terminator::Return(None),
        });
        let errs = verify_mir(&base_module(func)).unwrap_err();
        assert!(errs.iter().any(|e| {
            matches!(e, MirVerifyError::InvalidCfgInvariant { detail, .. } if detail.contains("SpawnBatchBegin dst"))
        }));
        assert!(errs.iter().any(|e| {
            matches!(e, MirVerifyError::InvalidCfgInvariant { detail, .. } if detail.contains("SpawnBatchBegin count"))
        }));
        assert!(errs.iter().any(|e| {
            matches!(e, MirVerifyError::InvalidCfgInvariant { detail, .. } if detail.contains("SpawnBatchPush batch"))
        }));
        assert!(errs.iter().any(|e| {
            matches!(e, MirVerifyError::InvalidCfgInvariant { detail, .. } if detail.contains("SpawnBatchPush index"))
        }));
        assert!(errs.iter().any(|e| {
            matches!(e, MirVerifyError::InvalidCfgInvariant { detail, .. } if detail.contains("SpawnBatchCommit batch"))
        }));
    }
}
