//! Tier 3 static Bevy `0.20` `Plugin` (`--target bevy-native`) code generator targeting
//! `bamabi_native_rt` (`#![forbid(unsafe_code)]`, supporting both `shared-bridge` and
//! `dlopen`-free `static-console` profiles).

use crate::expr::{
    AssignOp, BoundTerm, FieldRef, KernelExpr, KernelStmt, SystemPlan, extract_system_plan,
};
use crate::rust_guest::{
    format_rust_expr, rust_abi_type_for_field, rust_default_expr_for_field, sanitize_rust_ident,
};
use crate::{
    BevyNativeOptions, CodegenError, GeneratedArtifact, GeneratedFile, TargetKind,
    is_ecs_component_kind, module_stem, sanitize_ident, system_schedule_label,
};
use core::fmt::Write as _;
use strata_mir::MirModule;
use strata_sema::access::TermAccessMode;
use strata_sema::layout::{SchemaItemKind, SolvedLayout};

/// Emits a complete Tier 3 static `#![forbid(unsafe_code)]` Bevy `Plugin` crate (`Cargo.toml`, `src/lib.rs`).
pub fn emit(mir: &MirModule, opts: &BevyNativeOptions) -> Result<GeneratedArtifact, CodegenError> {
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

    let mut lib = String::with_capacity(8192);
    writeln!(lib, "#![forbid(unsafe_code)]").ok();
    writeln!(
        lib,
        "#![allow(unused_imports, dead_code, unused_variables, unused_mut)]"
    )
    .ok();
    writeln!(
        lib,
        "//! Auto-generated Tier 3 Static Native Bevy `Plugin` (`#![forbid(unsafe_code)]`)."
    )
    .ok();
    writeln!(lib).ok();
    writeln!(lib, "use bamabi_native_rt::{{").ok();
    writeln!(
        lib,
        "    ChunkSliceQueryExt, SelectiveMutSlice, SharedBridgeAppExt, StrataComponentOptions,"
    )
    .ok();
    writeln!(lib, "}};").ok();
    writeln!(
        lib,
        "use bamabi_sys::{{\n\
         \x20   BamFieldDesc, BamFieldKind, ComponentUuid, FfiAssetHandle, FfiBool, FfiEntity,\n\
         \x20   ModComponent, StrView, SymbolEntry, VTableHeader,\n\
         }};"
    )
    .ok();
    writeln!(
        lib,
        "use bevy_app::{{App, FixedUpdate, Last, Plugin, PostUpdate, PreUpdate, Startup, Update}};"
    )
    .ok();
    writeln!(lib, "use bevy_ecs::prelude::*;").ok();
    writeln!(lib, "use core::ffi::CStr;\n").ok();

    emit_native_layouts(&mut lib, mir);
    emit_native_systems(&mut lib, mir);
    emit_native_plugin(&mut lib, mir);

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

fn emit_native_layouts(out: &mut String, mir: &MirModule) {
    for (idx, layout) in mir.layouts.iter().enumerate() {
        let ident = sanitize_ident(&layout.canonical_name);
        let struct_name = format!("Strata{ident}_{idx}");
        let is_zst = layout.size == 0 || layout.fields.is_empty();
        let is_comp = is_ecs_component_kind(layout.item_kind);
        let is_res = layout.item_kind == SchemaItemKind::Resource;

        writeln!(out, "#[repr(C)]").ok();
        let mut derives = vec!["Clone", "Copy", "Debug", "PartialEq"];
        if is_comp {
            derives.push("Component");
        } else if is_res {
            derives.push("Resource");
        }
        writeln!(out, "#[derive({})]", derives.join(", ")).ok();
        if is_comp && (layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SUMMARY_TICK) != 0 {
            writeln!(out, "#[component(summary_tick)]").ok();
        }
        if is_zst {
            writeln!(out, "pub struct {struct_name};").ok();
            writeln!(out, "impl Default for {struct_name} {{").ok();
            writeln!(out, "    fn default() -> Self {{ Self }}").ok();
            writeln!(out, "}}").ok();
        } else {
            writeln!(out, "pub struct {struct_name} {{").ok();
            for field in &layout.fields {
                let fname = sanitize_rust_ident(&field.name);
                let rty = rust_abi_type_for_field(field, mir);
                writeln!(out, "    pub {fname}: {rty},").ok();
            }
            writeln!(out, "}}").ok();
            writeln!(out, "impl Default for {struct_name} {{").ok();
            writeln!(out, "    fn default() -> Self {{").ok();
            writeln!(out, "        Self {{").ok();
            for field in &layout.fields {
                let fname = sanitize_rust_ident(&field.name);
                let def = rust_default_expr_for_field(field, mir);
                writeln!(out, "            {fname}: {def},").ok();
            }
            writeln!(out, "        }}").ok();
            writeln!(out, "    }}").ok();
            writeln!(out, "}}").ok();
        }

        // VTable + manual zero-unsafe `impl ModComponent` matching solved UUID & fingerprint bit-for-bit.
        writeln!(out, "#[repr(C)]").ok();
        writeln!(out, "#[derive(Clone, Copy)]").ok();
        writeln!(out, "pub struct {struct_name}VTable {{").ok();
        writeln!(out, "    header: VTableHeader,").ok();
        writeln!(out, "}}").ok();

        writeln!(out, "static {struct_name}_FIELDS: &[BamFieldDesc] = &[").ok();
        for field in &layout.fields {
            let kind = match field.bam_field_kind {
                1 => "BamFieldKind::BOOL",
                2 => "BamFieldKind::U8",
                3 => "BamFieldKind::I8",
                4 => "BamFieldKind::U16",
                5 => "BamFieldKind::I16",
                6 => "BamFieldKind::U32",
                7 => "BamFieldKind::I32",
                8 => "BamFieldKind::U64",
                9 => "BamFieldKind::I64",
                10 => "BamFieldKind::F32",
                11 => "BamFieldKind::F64",
                12 => "BamFieldKind::USIZE",
                13 => "BamFieldKind::ISIZE",
                17 => "BamFieldKind::NESTED",
                _ => "BamFieldKind::UNKNOWN",
            };
            writeln!(
                out,
                "    BamFieldDesc::new({kind}, StrView::from_str(\"{name}\"), StrView::from_str(\"{tag}\"), {off}, {sz}, {al}),",
                name = field.name,
                tag = field.type_tag,
                off = field.offset,
                sz = field.size,
                al = field.align
            )
            .ok();
        }
        writeln!(out, "];").ok();

        let uuid_parts: Vec<String> = layout
            .uuid_bytes
            .iter()
            .map(|b| format!("0x{b:02X}"))
            .collect();
        let uuid_lit = format!("[{}]", uuid_parts.join(", "));
        writeln!(
            out,
            "static {struct_name}_VTABLE: {struct_name}VTable = {struct_name}VTable {{\n\
             \x20   header: VTableHeader::new::<{struct_name}VTable, {struct_name}>(ComponentUuid::from_bytes({uuid_lit})),\n\
             }};\n\
             static {struct_name}_SYMS: &[SymbolEntry] = &[];"
        )
        .ok();

        writeln!(
            out,
            "impl ModComponent for {struct_name} {{\n\
             \x20   const CANONICAL_NAME: &'static str = \"{cname}\";\n\
             \x20   const COMPONENT_CSTR: &'static CStr = c\"{cname}\";\n\
             \x20   const UUID: ComponentUuid = ComponentUuid::from_bytes({uuid_lit});\n\
             \x20   const IS_ABI_POD: bool = {is_pod};\n\
             \x20   const IS_RAW_INSERTABLE: bool = true;\n\
             \x20   const COMPONENT_FLAGS: u32 = 0x{flags:08X};\n\
             \x20   const SCHEMA_FINGERPRINT: u64 = 0x{fp:016X};\n\
             \x20   const BAM_FIELDS: &'static [BamFieldDesc] = {struct_name}_FIELDS;\n\
             \x20   type VTable = {struct_name}VTable;\n\
             \x20   fn vtable() -> &'static Self::VTable {{ &{struct_name}_VTABLE }}\n\
             \x20   fn symbols() -> &'static [SymbolEntry] {{ {struct_name}_SYMS }}\n\
             }}\n\
             const _: () = {{\n\
             \x20   assert!(core::mem::size_of::<{struct_name}>() == {sz});\n\
             \x20   assert!(core::mem::align_of::<{struct_name}>() == {al});\n\
             }};\n",
            cname = layout.canonical_name,
            is_pod = layout.is_abi_pod,
            flags = layout.component_flags,
            fp = layout.schema_fingerprint,
            sz = layout.size,
            al = layout.align
        )
        .ok();
    }
}

fn find_native_struct(mir: &MirModule, key: &str) -> Option<(usize, String, SolvedLayout)> {
    let short = key.split('.').next().unwrap_or(key);
    for (idx, l) in mir.layouts.iter().enumerate() {
        if l.canonical_name == short
            || l.canonical_name.rsplit("::").next() == Some(short)
            || sanitize_ident(&l.canonical_name) == sanitize_ident(short)
        {
            let ident = sanitize_ident(&l.canonical_name);
            return Some((idx, format!("Strata{ident}_{idx}"), l.clone()));
        }
    }
    None
}

fn emit_native_systems(out: &mut String, mir: &MirModule) {
    for func in &mir.functions {
        if func.is_observer {
            continue;
        }
        let fn_ident = sanitize_ident(&func.name);
        let plan = extract_system_plan(func, mir);

        if plan.row_stmts.is_empty() || plan.query0_terms.is_empty() {
            writeln!(out, "fn strata_sys_{fn_ident}() {{}}\n").ok();
            continue;
        }

        // Build Bevy system parameters: resources + contiguous slice query (data terms + With/Without filter tuple).
        let mut params = Vec::new();
        for (ri, res) in plan.resources.iter().enumerate() {
            if let Some((_, sname, _)) = find_native_struct(mir, &res.canonical_name) {
                if res.mutable {
                    params.push(format!("mut res_val_{ri}: ResMut<{sname}>"));
                } else {
                    params.push(format!("res_val_{ri}: Res<{sname}>"));
                }
            }
        }

        let mut data_terms: Vec<&BoundTerm> = Vec::new();
        let mut filter_terms = Vec::new();
        for term in &plan.query0_terms {
            let Some((_, sname, _)) = find_native_struct(mir, &term.component_canonical) else {
                continue;
            };
            match term.mode {
                TermAccessMode::Read
                | TermAccessMode::OptionalRead
                | TermAccessMode::Write
                | TermAccessMode::OptionalWrite
                | TermAccessMode::SelectiveWrite => {
                    data_terms.push(term);
                }
                TermAccessMode::With => {
                    filter_terms.push(format!("With<{sname}>"));
                }
                TermAccessMode::Without => {
                    filter_terms.push(format!("Without<{sname}>"));
                }
                _ => {}
            }
        }

        if data_terms.is_empty() {
            writeln!(out, "fn strata_sys_{fn_ident}() {{}}\n").ok();
            continue;
        }

        let data_tuple_parts: Vec<String> = data_terms
            .iter()
            .map(|t| {
                let (_, sname, _) =
                    find_native_struct(mir, &t.component_canonical).expect("checked above");
                if t.mode.is_mutable() {
                    format!("&'static mut {sname}")
                } else {
                    format!("&'static {sname}")
                }
            })
            .collect();
        let data_ty = format!("({})", data_tuple_parts.join(", "));
        let filter_ty = if filter_terms.is_empty() {
            "()".to_owned()
        } else {
            format!("({})", filter_terms.join(", "))
        };
        let has_any_mut = data_terms.iter().any(|t| t.mode.is_mutable());
        if has_any_mut {
            params.push(format!("mut query: Query<{data_ty}, {filter_ty}>"));
        } else {
            params.push(format!("query: Query<{data_ty}, {filter_ty}>"));
        }

        writeln!(out, "fn strata_sys_{fn_ident}({}) {{", params.join(", ")).ok();
        for stmt in &plan.uniforms {
            emit_native_stmt(out, stmt, mir, &plan, "    ", false);
        }

        let iter_call = if has_any_mut {
            "strata_contiguous_iter_mut()"
        } else {
            "strata_contiguous_iter()"
        };
        writeln!(out, "    if let Ok(mut chunks) = query.{iter_call} {{").ok();
        writeln!(out, "        while let Some(chunk) = chunks.next() {{").ok();
        let pat_names: Vec<String> = data_terms
            .iter()
            .map(|t| {
                if t.mode == TermAccessMode::SelectiveWrite {
                    format!("mut sel_{}", t.term_idx)
                } else if t.mode.is_mutable() {
                    format!("mut raw_{}", t.term_idx)
                } else {
                    format!("col_{}", t.term_idx)
                }
            })
            .collect();
        writeln!(out, "            let ({}) = chunk;", pat_names.join(", ")).ok();
        for t in &data_terms {
            if t.mode == TermAccessMode::SelectiveWrite {
                writeln!(
                    out,
                    "            let mut sel_wrap_{ti} = SelectiveMutSlice::from_contiguous_mut(sel_{ti});\n\
                     \x20           let mut row_indices_dirty_{ti}: Option<(u32, u32)> = None;",
                    ti = t.term_idx
                )
                .ok();
            } else if t.mode.is_mutable() {
                writeln!(
                    out,
                    "            let col_{ti} = &mut *raw_{ti};",
                    ti = t.term_idx
                )
                .ok();
            }
        }
        let first_ti = data_terms[0].term_idx;
        let chunk_len_expr = if data_terms[0].mode == TermAccessMode::SelectiveWrite {
            format!("sel_wrap_{first_ti}.len()")
        } else {
            format!("col_{first_ti}.len()")
        };
        writeln!(out, "            let chunk_len = {chunk_len_expr};").ok();
        writeln!(out, "            for row in 0..chunk_len {{").ok();
        if plan.has_selective_writes {
            writeln!(out, "                let mut row_dirty = false;").ok();
        }
        for stmt in &plan.row_stmts {
            emit_native_stmt(
                out,
                stmt,
                mir,
                &plan,
                "                ",
                plan.has_selective_writes,
            );
        }
        if plan.has_selective_writes {
            writeln!(out, "                if row_dirty {{").ok();
            for t in data_terms
                .iter()
                .filter(|t| t.mode == TermAccessMode::SelectiveWrite)
            {
                writeln!(
                    out,
                    "                    sel_wrap_{ti}.mark_dirty_row(row);",
                    ti = t.term_idx
                )
                .ok();
            }
            writeln!(out, "                }}").ok();
        }
        writeln!(out, "            }}").ok();
        for t in data_terms
            .iter()
            .filter(|t| t.mode == TermAccessMode::SelectiveWrite)
        {
            writeln!(
                out,
                "            sel_wrap_{ti}.flush_dirty_runs();\n\
                 \x20           let _ = row_indices_dirty_{ti};",
                ti = t.term_idx
            )
            .ok();
        }
        writeln!(out, "        }}").ok();
        writeln!(out, "    }}").ok();
        writeln!(out, "}}\n").ok();
    }
}

fn emit_native_stmt(
    out: &mut String,
    stmt: &KernelStmt,
    mir: &MirModule,
    plan: &SystemPlan,
    indent: &str,
    track_dirty: bool,
) {
    match stmt {
        KernelStmt::Let { name, expr, kind } => {
            let rty = match kind {
                crate::expr::ScalarKind::F32 => "f32",
                crate::expr::ScalarKind::F64 => "f64",
                crate::expr::ScalarKind::I32 => "i32",
                crate::expr::ScalarKind::U32 => "u32",
                crate::expr::ScalarKind::I64 => "i64",
                crate::expr::ScalarKind::U64 => "u64",
                crate::expr::ScalarKind::Bool => "bool",
            };
            let lname = sanitize_rust_ident(name);
            let rhs = format_native_expr(expr, mir, plan);
            writeln!(out, "{indent}let loc_{lname}: {rty} = ({rhs}) as {rty};").ok();
        }
        KernelStmt::Assign { target, op, value } => {
            let rhs = format_native_expr(value, mir, plan);
            let (lhs, needs_bool_wrap) = format_native_lvalue(target, mir, plan);
            let op_s = match op {
                AssignOp::Set => "=",
                AssignOp::AddAssign => "+=",
                AssignOp::SubAssign => "-=",
                AssignOp::MulAssign => "*=",
                AssignOp::DivAssign => "/=",
            };
            if needs_bool_wrap {
                writeln!(out, "{indent}{lhs} {op_s} FfiBool::from_bool({rhs});").ok();
            } else {
                writeln!(out, "{indent}{lhs} {op_s} {rhs};").ok();
            }
            if track_dirty
                && matches!(
                    target,
                    FieldRef::ColumnField {
                        is_selective: true,
                        ..
                    }
                )
            {
                writeln!(out, "{indent}row_dirty = true;").ok();
            }
        }
        KernelStmt::If {
            cond,
            then_stmts,
            else_stmts,
        } => {
            let c = format_native_expr(cond, mir, plan);
            writeln!(out, "{indent}if {c} {{").ok();
            for s in then_stmts {
                emit_native_stmt(out, s, mir, plan, &format!("{indent}    "), track_dirty);
            }
            if else_stmts.is_empty() {
                writeln!(out, "{indent}}}").ok();
            } else {
                writeln!(out, "{indent}}} else {{").ok();
                for s in else_stmts {
                    emit_native_stmt(out, s, mir, plan, &format!("{indent}    "), track_dirty);
                }
                writeln!(out, "{indent}}}").ok();
            }
        }
    }
}

fn format_native_lvalue(fref: &FieldRef, _mir: &MirModule, plan: &SystemPlan) -> (String, bool) {
    match fref {
        FieldRef::Local(n) => (format!("loc_{}", sanitize_rust_ident(n)), false),
        FieldRef::ResourceField {
            resource_canonical,
            field_name,
            kind,
            ..
        } => {
            let ri = plan
                .resources
                .iter()
                .position(|r| r.canonical_name == *resource_canonical)
                .unwrap_or(0);
            let fname = sanitize_rust_ident(field_name);
            (
                format!("res_val_{ri}.{fname}"),
                *kind == crate::expr::ScalarKind::Bool,
            )
        }
        FieldRef::ColumnField {
            term_idx,
            field_name,
            vec_lane,
            kind,
            is_selective,
            ..
        } => {
            let fname = sanitize_rust_ident(field_name);
            let slice_expr = if *is_selective {
                format!("sel_wrap_{term_idx}.as_mut_untracked()[row]")
            } else {
                format!("col_{term_idx}[row]")
            };
            let acc = if let Some(lane) = vec_lane {
                format!("{slice_expr}.{fname}[{lane}]")
            } else {
                format!("{slice_expr}.{fname}")
            };
            (acc, *kind == crate::expr::ScalarKind::Bool)
        }
    }
}

fn format_native_expr(expr: &KernelExpr, mir: &MirModule, plan: &SystemPlan) -> String {
    match expr {
        KernelExpr::Load(FieldRef::ColumnField {
            term_idx,
            field_name,
            vec_lane,
            kind,
            is_selective: true,
            ..
        }) => {
            let fname = sanitize_rust_ident(field_name);
            let base = format!("sel_wrap_{term_idx}.as_slice()[row]");
            if let Some(lane) = vec_lane {
                format!("{base}.{fname}[{lane}]")
            } else if *kind == crate::expr::ScalarKind::Bool {
                format!("{base}.{fname}.as_bool()")
            } else {
                format!("{base}.{fname}")
            }
        }
        KernelExpr::Neg(inner) => format!("(-({}))", format_native_expr(inner, mir, plan)),
        KernelExpr::Not(inner) => format!("(!({}))", format_native_expr(inner, mir, plan)),
        KernelExpr::Binary { op, lhs, rhs } => {
            let sym = match op {
                crate::expr::BinOpKind::Add => "+",
                crate::expr::BinOpKind::Sub => "-",
                crate::expr::BinOpKind::Mul => "*",
                crate::expr::BinOpKind::Div => "/",
                crate::expr::BinOpKind::Rem => "%",
                crate::expr::BinOpKind::Lt => "<",
                crate::expr::BinOpKind::Le => "<=",
                crate::expr::BinOpKind::Gt => ">",
                crate::expr::BinOpKind::Ge => ">=",
                crate::expr::BinOpKind::Eq => "==",
                crate::expr::BinOpKind::Ne => "!=",
                crate::expr::BinOpKind::And => "&&",
                crate::expr::BinOpKind::Or => "||",
            };
            format!(
                "(({}) {sym} ({}))",
                format_native_expr(lhs, mir, plan),
                format_native_expr(rhs, mir, plan)
            )
        }
        other => format_rust_expr(other, mir, plan),
    }
}

fn emit_native_plugin(out: &mut String, mir: &MirModule) {
    writeln!(
        out,
        "/// Tier 3 static Bevy `Plugin` generated by Strata v2.0."
    )
    .ok();
    writeln!(out, "pub struct StrataNativePlugin;\n").ok();
    writeln!(out, "impl Plugin for StrataNativePlugin {{").ok();
    writeln!(out, "    fn build(&self, app: &mut App) {{").ok();
    for (idx, layout) in mir.layouts.iter().enumerate() {
        let ident = sanitize_ident(&layout.canonical_name);
        let struct_name = format!("Strata{ident}_{idx}");
        if is_ecs_component_kind(layout.item_kind) {
            let mut opts = "StrataComponentOptions::new()".to_owned();
            if (layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET) != 0 {
                opts.push_str(".sparse_set()");
            }
            if (layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SUMMARY_TICK) != 0 {
                opts.push_str(".summary_tick()");
            }
            writeln!(
                out,
                "        app.register_strata_component::<{struct_name}>({opts}).expect(\"valid component registration\");"
            )
            .ok();
        } else if layout.item_kind == SchemaItemKind::Resource {
            writeln!(
                out,
                "        app.init_resource::<{struct_name}>();\n\
                 \x20       app.register_strata_resource::<{struct_name}>().expect(\"valid resource registration\");"
            )
            .ok();
        }
    }

    for func in &mir.functions {
        if func.is_observer {
            continue;
        }
        let fn_ident = sanitize_ident(&func.name);
        let sched = match system_schedule_label(mir, &func.name) {
            "Startup" => "Startup",
            "PreUpdate" => "PreUpdate",
            "PostUpdate" => "PostUpdate",
            "Last" => "Last",
            "Update" => "Update",
            _ => "FixedUpdate",
        };
        writeln!(
            out,
            "        app.add_systems({sched}, strata_sys_{fn_ident});"
        )
        .ok();
    }

    writeln!(out, "    }}").ok();
    writeln!(out, "}}").ok();
}

#[cfg(test)]
mod tests {
    use super::emit;
    use crate::{BevyNativeOptions, TargetKind};
    use strata_mir::lower_to_mir;
    use strata_sema::analyze_source;

    /// Verifies Tier 3 `--target bevy-native` emits `#![forbid(unsafe_code)]` and respects
    /// `static_console` default feature toggles.
    #[test]
    fn bevy_native_respects_static_console_feature_flag() {
        let src = "module bn::t @version(1.0.0);\ncomponent Pos { x: f32 = 0.0 }\nsys s() { for e in query(p: &mut Pos) { e.p.x += 1.0; } }\n";
        let sema = analyze_source("bn.strata", src);
        let mir = lower_to_mir(&sema);
        let art = emit(
            &mir,
            &BevyNativeOptions {
                crate_name: "native_console".to_owned(),
                native_rt_path: None,
                static_console: true,
            },
        )
        .expect("emit bevy native");
        assert_eq!(art.target, TargetKind::BevyNative);
        assert!(
            art.files[0]
                .content
                .contains("default = [\"static-console\"]")
        );
        assert!(art.files[1].content.contains("#![forbid(unsafe_code)]"));
    }
}
