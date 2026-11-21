//! Safe Rust Guest (`.cdylib`, `#![forbid(unsafe_code)]`, ZERO `bevy*` deps) code generator
//! targeting `bamabi_guest`.

use crate::expr::{
    AssignOp, BinOpKind, BoundTerm, FieldRef, KernelExpr, KernelStmt, ScalarKind, SystemPlan,
    extract_system_plan,
};
use crate::{
    CodegenError, GeneratedArtifact, GeneratedFile, RustGuestOptions, TargetKind,
    is_ecs_component_kind, module_stem, sanitize_ident, system_schedule_label,
};
use core::fmt::Write as _;
use strata_mir::{MirFunction, MirModule};
use strata_sema::access::TermAccessMode;
use strata_sema::layout::{SchemaItemKind, SolvedField, SolvedLayout};
use strata_sema::types::Ty;

/// Emits a complete `#![forbid(unsafe_code)]` Rust Guest `.cdylib` crate (`Cargo.toml`, `src/lib.rs`).
pub fn emit(mir: &MirModule, opts: &RustGuestOptions) -> Result<GeneratedArtifact, CodegenError> {
    let stem = module_stem(&mir.module_path);
    let crate_name = if opts.crate_name.is_empty() {
        format!("strata_guest_{stem}")
    } else {
        opts.crate_name.clone()
    };

    let cargo_toml = format!(
        "[package]\n\
         name = \"{crate_name}\"\n\
         version = \"0.3.0\"\n\
         edition = \"2024\"\n\n\
         [lib]\n\
         crate-type = [\"cdylib\"]\n\n\
         [dependencies]\n\
         bamabi_guest = {{ version = \"0.3.0\", git = \"https://github.com/yaga-simha/bamabi-wire.git\", rev = \"7a32b7bd329167c8dda82259659b3da54a5ab748\", features = [\"derive\"] }}\n\
         bamabi_sys = {{ version = \"0.3.0\", git = \"https://github.com/yaga-simha/bamabi-wire.git\", rev = \"7a32b7bd329167c8dda82259659b3da54a5ab748\" }}\n"
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
        "//! Auto-generated Safe Rust Guest mod (`#![forbid(unsafe_code)]`, zero `bevy*` deps)."
    )
    .ok();
    writeln!(lib).ok();
    writeln!(lib, "use bamabi_guest::prelude::*;").ok();
    writeln!(
        lib,
        "use bamabi_sys::{{BamFieldDesc, BamFieldKind, ComponentUuid, ModComponent, StrView, SymbolEntry, VTableHeader}};"
    )
    .ok();
    writeln!(lib, "use core::ffi::CStr;\n").ok();

    emit_layouts(&mut lib, mir);
    emit_plugin_and_systems(&mut lib, mir, &stem);

    Ok(GeneratedArtifact {
        target: TargetKind::RustGuest,
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

fn emit_layouts(out: &mut String, mir: &MirModule) {
    for (idx, layout) in mir.layouts.iter().enumerate() {
        let ident = sanitize_ident(&layout.canonical_name);
        let struct_name = format!("Strata{ident}_{idx}");
        let is_zst = layout.size == 0 || layout.fields.is_empty();

        writeln!(out, "#[repr(C)]").ok();
        if is_zst {
            writeln!(
                out,
                "#[derive(Clone, Copy, Default, Debug, PartialEq, AbiPod)]"
            )
            .ok();
            writeln!(out, "pub struct {struct_name};").ok();
        } else {
            writeln!(out, "#[derive(Clone, Copy, Debug, PartialEq, AbiPod)]").ok();
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

        writeln!(out, "#[repr(C)]").ok();
        writeln!(out, "#[derive(Clone, Copy)]").ok();
        writeln!(out, "pub struct {struct_name}VTable {{").ok();
        writeln!(out, "    header: VTableHeader,").ok();
        writeln!(out, "}}").ok();

        writeln!(out, "static {struct_name}_FIELDS: &[BamFieldDesc] = &[").ok();
        for field in &layout.fields {
            let kind = rust_field_kind(field.bam_field_kind);
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

        let uuid_lit = format_u8_array_16(&layout.uuid_bytes);
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
             }}",
            cname = layout.canonical_name,
            is_pod = layout.is_abi_pod,
            flags = layout.component_flags,
            fp = layout.schema_fingerprint,
        )
        .ok();

        writeln!(
            out,
            "impl GuestComponent for {struct_name} {{\n\
             \x20   const NAME: &'static CStr = <Self as ModComponent>::COMPONENT_CSTR;\n\
             \x20   const UUID: ComponentUuid = <Self as ModComponent>::UUID;\n\
             }}"
        )
        .ok();

        writeln!(
            out,
            "const _: () = {{\n\
             \x20   assert!(core::mem::size_of::<{struct_name}>() == {sz});\n\
             \x20   assert!(core::mem::align_of::<{struct_name}>() == {al});\n\
             }};\n",
            sz = layout.size,
            al = layout.align
        )
        .ok();
    }
}

pub(crate) fn rust_abi_type_for_field(field: &SolvedField, mir: &MirModule) -> String {
    if field.is_padding {
        return format!("[u8; {}]", field.size.max(1));
    }
    rust_abi_type_for_ty(&field.ty, field.size, mir)
}

pub(crate) fn rust_abi_type_for_ty(ty: &Ty, byte_size: usize, mir: &MirModule) -> String {
    match ty {
        Ty::U8 => "u8".to_owned(),
        Ty::I8 => "i8".to_owned(),
        Ty::Bool => "FfiBool".to_owned(),
        Ty::U16 => "u16".to_owned(),
        Ty::I16 => "i16".to_owned(),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => "u32".to_owned(),
        Ty::I32 | Ty::Fix32 => "i32".to_owned(),
        Ty::U64 => "u64".to_owned(),
        Ty::I64 | Ty::Fix64 => "i64".to_owned(),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => "f32".to_owned(),
        Ty::F64 => "f64".to_owned(),
        Ty::Vec2 => "[f32; 2]".to_owned(),
        Ty::Vec3 => "[f32; 3]".to_owned(),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => "[f32; 4]".to_owned(),
        Ty::IVec2 => "[i32; 2]".to_owned(),
        Ty::IVec3 => "[i32; 3]".to_owned(),
        Ty::UVec2 => "[u32; 2]".to_owned(),
        Ty::Mat3 => "[f32; 9]".to_owned(),
        Ty::Mat4 => "[f32; 16]".to_owned(),
        Ty::Ref(_) => "FfiEntity".to_owned(),
        Ty::Asset(_) => "FfiAssetHandle".to_owned(),
        Ty::Array { elem, len } => {
            let elem_ty = rust_abi_type_for_ty(elem, byte_size / (*len).max(1), mir);
            format!("[{elem_ty}; {len}]")
        }
        Ty::BitSet(bits) => format!("[u32; {}]", (*bits).div_ceil(32).max(1)),
        Ty::Named(n) => {
            if let Some(en) = mir.layouts.iter().find(|l| {
                l.canonical_name == *n || l.canonical_name.rsplit("::").next() == Some(n.as_str())
            }) && en.item_kind == SchemaItemKind::Enum
            {
                return match en.size {
                    1 => "u8".to_owned(),
                    2 => "u16".to_owned(),
                    _ => "u32".to_owned(),
                };
            }
            if byte_size >= 4 && byte_size.is_multiple_of(4) {
                format!("[u32; {}]", byte_size / 4)
            } else {
                format!("[u8; {}]", byte_size.max(1))
            }
        }
        _ => {
            if byte_size >= 4 && byte_size.is_multiple_of(4) {
                format!("[u32; {}]", byte_size / 4)
            } else {
                format!("[u8; {}]", byte_size.max(1))
            }
        }
    }
}

pub(crate) fn rust_default_expr_for_field(field: &SolvedField, mir: &MirModule) -> String {
    if field.is_padding {
        return format!("[0u8; {}]", field.size.max(1));
    }
    rust_default_expr_for_ty(&field.ty, field.size, mir)
}

fn rust_default_expr_for_ty(ty: &Ty, byte_size: usize, mir: &MirModule) -> String {
    match ty {
        Ty::U8 => "0u8".to_owned(),
        Ty::I8 => "0i8".to_owned(),
        Ty::Bool => "FfiBool::FALSE".to_owned(),
        Ty::U16 => "0u16".to_owned(),
        Ty::I16 => "0i16".to_owned(),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => "0u32".to_owned(),
        Ty::I32 | Ty::Fix32 => "0i32".to_owned(),
        Ty::U64 => "0u64".to_owned(),
        Ty::I64 | Ty::Fix64 => "0i64".to_owned(),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => "0.0f32".to_owned(),
        Ty::F64 => "0.0f64".to_owned(),
        Ty::Vec2 => "[0.0f32; 2]".to_owned(),
        Ty::Vec3 => "[0.0f32; 3]".to_owned(),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => "[0.0f32; 4]".to_owned(),
        Ty::IVec2 => "[0i32; 2]".to_owned(),
        Ty::IVec3 => "[0i32; 3]".to_owned(),
        Ty::UVec2 => "[0u32; 2]".to_owned(),
        Ty::Mat3 => "[0.0f32; 9]".to_owned(),
        Ty::Mat4 => "[0.0f32; 16]".to_owned(),
        Ty::Ref(_) => "FfiEntity::NULL".to_owned(),
        Ty::Asset(_) => "FfiAssetHandle::NONE".to_owned(),
        Ty::Array { elem, len } => {
            let inner = rust_default_expr_for_ty(elem, byte_size / (*len).max(1), mir);
            format!("[{inner}; {len}]")
        }
        Ty::BitSet(bits) => format!("[0u32; {}]", (*bits).div_ceil(32).max(1)),
        Ty::Named(n) => {
            if let Some(en) = mir.layouts.iter().find(|l| {
                l.canonical_name == *n || l.canonical_name.rsplit("::").next() == Some(n.as_str())
            }) && en.item_kind == SchemaItemKind::Enum
            {
                return match en.size {
                    1 => "0u8".to_owned(),
                    2 => "0u16".to_owned(),
                    _ => "0u32".to_owned(),
                };
            }
            if byte_size >= 4 && byte_size.is_multiple_of(4) {
                format!("[0u32; {}]", byte_size / 4)
            } else {
                format!("[0u8; {}]", byte_size.max(1))
            }
        }
        _ => {
            if byte_size >= 4 && byte_size.is_multiple_of(4) {
                format!("[0u32; {}]", byte_size / 4)
            } else {
                format!("[0u8; {}]", byte_size.max(1))
            }
        }
    }
}

fn rust_field_kind(kind: u32) -> &'static str {
    match kind {
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
    }
}

pub(crate) fn sanitize_rust_ident(raw: &str) -> String {
    let base = sanitize_ident(raw);
    match base.as_str() {
        "type" | "match" | "loop" | "in" | "ref" | "mut" | "fn" | "let" | "if" | "else" | "for"
        | "while" | "self" | "Self" | "mod" | "pub" | "struct" | "enum" => {
            format!("r#{base}")
        }
        _ => base,
    }
}

fn format_u8_array_16(bytes: &[u8; 16]) -> String {
    let parts: Vec<String> = bytes.iter().map(|b| format!("0x{b:02X}")).collect();
    format!("[{}]", parts.join(", "))
}

fn layout_struct_name(mir: &MirModule, key: &str) -> Option<(usize, String, SolvedLayout)> {
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

fn emit_plugin_and_systems(out: &mut String, mir: &MirModule, stem: &str) {
    writeln!(out, "#[derive(Default)]").ok();
    writeln!(out, "pub struct StrataGuestMod;\n").ok();
    writeln!(out, "impl GuestPlugin for StrataGuestMod {{").ok();
    writeln!(out, "    const NAME: &'static CStr = c\"{stem}\";").ok();
    writeln!(out, "    const VERSION: &'static CStr = c\"0.3.0\";\n").ok();
    writeln!(
        out,
        "    fn build(&mut self, app: &mut GuestApp<'_>) -> FfiResult {{"
    )
    .ok();

    for (idx, layout) in mir.layouts.iter().enumerate() {
        let ident = sanitize_ident(&layout.canonical_name);
        let struct_name = format!("Strata{ident}_{idx}");
        if is_ecs_component_kind(layout.item_kind) {
            writeln!(
                out,
                "        if let Err(e) = app.register_dynamic_component::<{struct_name}>() {{\n\
                 \x20           return e;\n\
                 \x20       }}"
            )
            .ok();
        } else if layout.item_kind == SchemaItemKind::Resource {
            writeln!(
                out,
                "        match app.resolve_component::<{struct_name}>() {{\n\
                 \x20           Ok(_) => {{}},\n\
                 \x20           Err(FfiResult::NOT_FOUND) => {{\n\
                 \x20               if let Err(e) = app.register_dynamic_component::<{struct_name}>() {{\n\
                 \x20                   return e;\n\
                 \x20               }}\n\
                 \x20           }}\n\
                 \x20           Err(e) => return e,\n\
                 \x20       }}"
            )
            .ok();
        }
    }

    for func in &mir.functions {
        if func.is_observer {
            continue;
        }
        emit_rust_guest_system(out, mir, func);
    }

    writeln!(out, "        FfiResult::OK").ok();
    writeln!(out, "    }}").ok();
    writeln!(out, "}}\n").ok();
    writeln!(out, "export_mod!(plugin: StrataGuestMod);").ok();
}

fn emit_rust_guest_system(out: &mut String, mir: &MirModule, func: &MirFunction) {
    let plan = extract_system_plan(func, mir);
    let sched = match system_schedule_label(mir, &func.name) {
        "Startup" => "ScheduleId::STARTUP",
        "PreUpdate" => "ScheduleId::PRE_UPDATE",
        "PostUpdate" => "ScheduleId::POST_UPDATE",
        "Last" => "ScheduleId::LAST",
        "Update" => "ScheduleId::UPDATE",
        _ => "ScheduleId::FIXED_UPDATE",
    };

    writeln!(out, "        let _sys_res = app.system(c\"{}\")", func.name).ok();
    writeln!(out, "            .schedule({sched})").ok();

    if plan.row_stmts.is_empty() || plan.query0_terms.is_empty() {
        writeln!(out, "            .build(|_ctx| {{}});").ok();
        writeln!(out, "        if !_sys_res.is_ok() {{ return _sys_res; }}").ok();
        return;
    }

    for res in &plan.resources {
        let Some((_, sname, _)) = layout_struct_name(mir, &res.canonical_name) else {
            continue;
        };
        if res.mutable {
            writeln!(out, "            .resource_write::<{sname}>()").ok();
        } else {
            writeln!(out, "            .resource_read::<{sname}>()").ok();
        }
    }

    // Build typed query tuple so multiple read+write columns borrow simultaneously under `#![forbid(unsafe_code)]`.
    let resolved_terms: Vec<(&BoundTerm, String)> = plan
        .query0_terms
        .iter()
        .filter_map(|t| {
            layout_struct_name(mir, &t.component_canonical).map(|(_, sname, _)| (t, sname))
        })
        .collect();

    if resolved_terms.is_empty() {
        writeln!(out, "            .build(|_ctx| {{}});").ok();
        writeln!(out, "        if !_sys_res.is_ok() {{ return _sys_res; }}").ok();
        return;
    }

    let term_types: Vec<String> = resolved_terms
        .iter()
        .map(|(t, sname)| match t.mode {
            TermAccessMode::OptionalRead => format!("Option<&'static {sname}>"),
            TermAccessMode::Write | TermAccessMode::SelectiveWrite => {
                format!("&'static mut {sname}")
            }
            TermAccessMode::OptionalWrite => format!("Option<&'static mut {sname}>"),
            TermAccessMode::With => format!("With<{sname}>"),
            TermAccessMode::Without => format!("Without<{sname}>"),
            TermAccessMode::Allow => format!("Allow<{sname}>"),
            TermAccessMode::Has => format!("Has<{sname}>"),
            _ => format!("&'static {sname}"),
        })
        .collect();

    let query_tuple_ty = if term_types.len() == 1 {
        term_types[0].clone()
    } else {
        format!("({})", term_types.join(", "))
    };

    writeln!(out, "            .query_typed::<{query_tuple_ty}>()").ok();
    writeln!(out, "            .build(|mut ctx| {{").ok();

    for (ri, res) in plan.resources.iter().enumerate() {
        let Some((_, sname, _)) = layout_struct_name(mir, &res.canonical_name) else {
            continue;
        };
        if res.mutable {
            writeln!(
                out,
                "                let mut res_val_{ri}: {sname} = match ctx.component_resource_mut::<{sname}>({ri}) {{ Some(r) => *r, None => return }};"
            )
            .ok();
        } else {
            writeln!(
                out,
                "                let res_val_{ri}: {sname} = match ctx.component_resource::<{sname}>({ri}) {{ Some(r) => *r, None => return }};"
            )
            .ok();
        }
    }

    for stmt in &plan.uniforms {
        emit_rust_stmt(out, stmt, mir, &plan, "                ");
    }

    let pat_names: Vec<String> = resolved_terms
        .iter()
        .map(|(t, _)| {
            if t.mode.is_mutable() {
                format!("mut col_{}", t.term_idx)
            } else {
                format!("col_{}", t.term_idx)
            }
        })
        .collect();
    let pat = if pat_names.len() == 1 {
        pat_names[0].clone()
    } else {
        format!("({})", pat_names.join(", "))
    };
    let len_term = resolved_terms[0].0.term_idx;

    writeln!(
        out,
        "                let mut qiter = ctx.single_query::<{query_tuple_ty}>();\n\
         \x20               while let Some({pat}) = qiter.next_chunk() {{\n\
         \x20                   let chunk_len = col_{len_term}.len();\n\
         \x20                   for row in 0..chunk_len {{"
    )
    .ok();

    for stmt in &plan.row_stmts {
        emit_rust_stmt(out, stmt, mir, &plan, "                        ");
    }

    writeln!(out, "                    }}\n                }}").ok();

    for (ri, res) in plan.resources.iter().enumerate() {
        if !res.mutable {
            continue;
        }
        let Some((_, sname, _)) = layout_struct_name(mir, &res.canonical_name) else {
            continue;
        };
        writeln!(
            out,
            "                if let Some(rm) = ctx.component_resource_mut::<{sname}>({ri}) {{\n\
             \x20                   *rm = res_val_{ri};\n\
             \x20               }}"
        )
        .ok();
    }

    writeln!(out, "            }});").ok();
    writeln!(out, "        if !_sys_res.is_ok() {{ return _sys_res; }}").ok();
}

fn rust_scalar_ty(kind: ScalarKind) -> &'static str {
    match kind {
        ScalarKind::F32 => "f32",
        ScalarKind::F64 => "f64",
        ScalarKind::I32 => "i32",
        ScalarKind::U32 => "u32",
        ScalarKind::I64 => "i64",
        ScalarKind::U64 => "u64",
        ScalarKind::Bool => "bool",
    }
}

fn emit_rust_stmt(
    out: &mut String,
    stmt: &KernelStmt,
    mir: &MirModule,
    plan: &SystemPlan,
    indent: &str,
) {
    match stmt {
        KernelStmt::Let { name, expr, kind } => {
            let rty = rust_scalar_ty(*kind);
            let lname = sanitize_rust_ident(name);
            let rhs = format_rust_expr(expr, mir, plan);
            writeln!(out, "{indent}let loc_{lname}: {rty} = ({rhs}) as {rty};").ok();
        }
        KernelStmt::Assign { target, op, value } => {
            let rhs = format_rust_expr(value, mir, plan);
            let (lhs, needs_bool_wrap) = format_rust_lvalue(target, mir, plan);
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
        }
        KernelStmt::If {
            cond,
            then_stmts,
            else_stmts,
        } => {
            let c = format_rust_expr(cond, mir, plan);
            writeln!(out, "{indent}if {c} {{").ok();
            for s in then_stmts {
                emit_rust_stmt(out, s, mir, plan, &format!("{indent}    "));
            }
            if else_stmts.is_empty() {
                writeln!(out, "{indent}}}").ok();
            } else {
                writeln!(out, "{indent}}} else {{").ok();
                for s in else_stmts {
                    emit_rust_stmt(out, s, mir, plan, &format!("{indent}    "));
                }
                writeln!(out, "{indent}}}").ok();
            }
        }
    }
}

pub(crate) fn format_rust_lvalue(
    fref: &FieldRef,
    _mir: &MirModule,
    plan: &SystemPlan,
) -> (String, bool) {
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
            (format!("res_val_{ri}.{fname}"), *kind == ScalarKind::Bool)
        }
        FieldRef::ColumnField {
            term_idx,
            field_name,
            vec_lane,
            kind,
            ..
        } => {
            let fname = sanitize_rust_ident(field_name);
            let acc = if let Some(lane) = vec_lane {
                format!("col_{term_idx}[row].{fname}[{lane}]")
            } else {
                format!("col_{term_idx}[row].{fname}")
            };
            (acc, *kind == ScalarKind::Bool)
        }
    }
}

pub(crate) fn format_rust_expr(expr: &KernelExpr, _mir: &MirModule, plan: &SystemPlan) -> String {
    match expr {
        KernelExpr::FloatLit(v) => format!("{v:?}f32"),
        KernelExpr::IntLit(v) => format!("{v}i32"),
        KernelExpr::BoolLit(b) => b.to_string(),
        KernelExpr::Load(fref) => match fref {
            FieldRef::Local(n) => format!("loc_{}", sanitize_rust_ident(n)),
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
                if *kind == ScalarKind::Bool {
                    format!("res_val_{ri}.{fname}.as_bool()")
                } else {
                    format!("res_val_{ri}.{fname}")
                }
            }
            FieldRef::ColumnField {
                term_idx,
                field_name,
                vec_lane,
                kind,
                ..
            } => {
                let fname = sanitize_rust_ident(field_name);
                if let Some(lane) = vec_lane {
                    format!("col_{term_idx}[row].{fname}[{lane}]")
                } else if *kind == ScalarKind::Bool {
                    format!("col_{term_idx}[row].{fname}.as_bool()")
                } else {
                    format!("col_{term_idx}[row].{fname}")
                }
            }
        },
        KernelExpr::Neg(inner) => format!("(-({}))", format_rust_expr(inner, _mir, plan)),
        KernelExpr::Not(inner) => format!("(!({}))", format_rust_expr(inner, _mir, plan)),
        KernelExpr::Binary { op, lhs, rhs } => {
            let sym = match op {
                BinOpKind::Add => "+",
                BinOpKind::Sub => "-",
                BinOpKind::Mul => "*",
                BinOpKind::Div => "/",
                BinOpKind::Rem => "%",
                BinOpKind::Lt => "<",
                BinOpKind::Le => "<=",
                BinOpKind::Gt => ">",
                BinOpKind::Ge => ">=",
                BinOpKind::Eq => "==",
                BinOpKind::Ne => "!=",
                BinOpKind::And => "&&",
                BinOpKind::Or => "||",
            };
            format!(
                "(({}) {sym} ({}))",
                format_rust_expr(lhs, _mir, plan),
                format_rust_expr(rhs, _mir, plan)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::emit;
    use crate::{RustGuestOptions, TargetKind};
    use strata_mir::lower_to_mir;
    use strata_sema::analyze_source;

    /// Verifies generated Rust guest `.cdylib` enforces `#![forbid(unsafe_code)]`, avoids `bevy*`,
    /// and binds resources + typed queries cleanly.
    #[test]
    fn rust_guest_emits_zero_unsafe_typed_query_and_resource_bind() {
        let src = r#"
module rg::t @version(1.0.0);
resource Param { dt: f32 = 0.016 }
component Pos { x: f32 = 0.0 }
sys step(p: &res Param) {
    uniform let dt = p.dt;
    for e in query(pos: &mut Pos) { e.pos.x += dt; }
}
"#;
        let sema = analyze_source("rg.strata", src);
        let mir = lower_to_mir(&sema);
        let art = emit(
            &mir,
            &RustGuestOptions {
                crate_name: "guest_test".to_owned(),
            },
        )
        .expect("emit rust guest");
        assert_eq!(art.target, TargetKind::RustGuest);
        assert!(art.files[0].content.contains("rev = \"7a32b7bd"));
        let lib_rs = &art.files[1].content;
        assert!(lib_rs.contains("#![forbid(unsafe_code)]"));
        assert!(!lib_rs.contains("bevy_"));
        assert!(lib_rs.contains(".resource_read::<"));
        assert!(lib_rs.contains(".query_typed::<"));
    }
}
