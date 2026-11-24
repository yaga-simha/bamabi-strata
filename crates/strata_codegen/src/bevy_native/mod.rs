//! Tier 3 static Bevy `0.20` `Plugin` (`--target bevy-native`) code generator targeting
//! `bamabi_native_rt` (`#![forbid(unsafe_code)]`, supporting both `shared-bridge` and
//! `dlopen`-free `static-console` profiles).

use crate::net::{
    STRATA_NET_PACKET_SCHEMA_FINGERPRINT, has_net_protocol, validate_net_packet_capacity,
};
use crate::rust_guest::{
    aligned_blob_type, emit_read_field_from_bytes, emit_rust_wire_field_decode,
    emit_rust_wire_field_encode, emit_write_field_to_bytes, format_fix32_i32_lit,
    format_fix64_i64_lit, rust_abi_type_for_field, rust_abi_type_for_mir_ty,
    rust_default_expr_for_field, sanitize_rust_ident, scale_float_fix32, scale_float_fix64,
    scale_int_fix32, scale_int_fix64,
};
use crate::{
    BevyNativeOptions, CodegenError, GeneratedArtifact, GeneratedFile, TargetKind,
    is_ecs_component_kind, module_stem, sanitize_ident,
};
use bamabi_sys::fnv1a_64_str;
use core::fmt::Write as _;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use strata_mir::{
    BlockId, Inst, LocalId, MirConstVal, MirFnKind, MirFunction, MirModule, MirNetComponent,
    MirRpc, MirStmt, MirStreamOpKind, MirType, Terminator,
};
use strata_sema::access::TermAccessMode;
use strata_sema::hir::{HirBinOp, HirExpr, HirParamKind, HirScheduleGroup, HirUnOp};
use strata_sema::layout::{EnumDef, SchemaItemKind, SolvedField, SolvedLayout};
use strata_sema::types::Ty;

mod analysis;
mod fn_emit;
mod items;
mod places_ops;
#[cfg(test)]
mod tests;

use analysis::*;
use fn_emit::*;
use items::*;
use places_ops::*;

/// Emits a complete Tier 3 static `#![forbid(unsafe_code)]` Bevy `Plugin` crate (`Cargo.toml`, `src/lib.rs`).
pub fn emit(mir: &MirModule, opts: &BevyNativeOptions) -> Result<GeneratedArtifact, CodegenError> {
    if has_net_protocol(mir) {
        validate_net_packet_capacity(mir)?;
    }
    let stem = module_stem(&mir.module_path);
    let crate_name = if opts.crate_name.is_empty() {
        format!("strata_native_{stem}")
    } else {
        opts.crate_name.clone()
    };

    let rt_dep = match &opts.native_rt_path {
        Some(path) => {
            format!("bamabi_native_rt = {{ path = \"{path}\", default-features = false }}")
        }
        None => "bamabi_native_rt = { version = \"0.3.0\", default-features = false }".to_owned(),
    };
    let default_feat = if opts.static_console {
        "static-console"
    } else {
        "shared-bridge"
    };

    let cargo_toml = format!(
        "[package]\n\
         name = \"{crate_name}\"\n\
         version = \"0.3.0\"\n\
         edition = \"2024\"\n\n\
         [features]\n\
         default = [\"{default_feat}\"]\n\
         shared-bridge = [\"bamabi_native_rt/shared-bridge\"]\n\
         static-console = [\"bamabi_native_rt/static-console\"]\n\n\
         [dependencies]\n\
         {rt_dep}\n\
         bamabi_sys = {{ version = \"0.3.0\", git = \"https://github.com/yaga-simha/bamabi-wire.git\", branch = \"main\" }}\n\
         bevy_app = {{ version = \"0.20.1\", default-features = false, features = [\"std\"] }}\n\
         bevy_ecs = {{ version = \"0.20.1\", default-features = false, features = [\"std\", \"async_executor\"] }}\n"
    );

    let ctx = NativeCtx::new(mir);
    let mut lib = String::with_capacity(16384);
    emit_preamble(&mut lib, mir);
    emit_runtime_helpers(&mut lib);
    emit_enums_and_consts(&mut lib, &ctx);
    emit_native_layouts(&mut lib, &ctx);
    emit_synthesized_tags(&mut lib, &ctx);
    emit_spatial_and_relation_resources(&mut lib, &ctx);
    emit_tables_and_curves(&mut lib, &ctx);
    if has_net_protocol(mir) {
        emit_net_protocol_and_codecs(&mut lib, &ctx)?;
    }
    emit_helper_functions(&mut lib, &ctx)?;
    emit_native_functions(&mut lib, &ctx)?;
    if has_net_protocol(mir) {
        emit_net_synthesized_systems(&mut lib, &ctx);
    }
    emit_named_object_initializer(&mut lib, &ctx);
    emit_native_plugin(&mut lib, &ctx);

    Ok(GeneratedArtifact {
        target: TargetKind::BevyNative,
        module_name: mir.module_path.clone(),
        files: vec![
            GeneratedFile {
                path: "Cargo.toml".to_owned(),
                content: cargo_toml,
            },
            GeneratedFile {
                path: "src/lib.rs".to_owned(),
                content: lib,
            },
        ],
    })
}
