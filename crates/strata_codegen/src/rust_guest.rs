//! Safe Rust Guest (`.cdylib`, `#![forbid(unsafe_code)]`, ZERO `bevy*` deps) code generator
//! targeting `bamabi_guest` (`ABI 0.3.0`).

use crate::{
    CodegenError, GeneratedArtifact, GeneratedFile, RustGuestOptions, TargetKind,
    is_ecs_component_kind, module_stem, sanitize_ident, system_schedule_label,
};
use core::fmt::Write as _;
use std::collections::{BTreeSet, HashMap, HashSet};
use strata_mir::{
    BasicBlock, BlockId, Inst, MirConstVal, MirFnKind, MirFunction, MirModule, MirQueryBinding,
    MirType, Terminator,
};
use strata_sema::access::TermAccessMode;
use strata_sema::hir::{HirExpr, HirScheduleGroup};
use strata_sema::layout::{SchemaItemKind, SolvedField, SolvedLayout, compute_wire_identity};
use strata_sema::types::Ty;

/// Emits a complete `#![forbid(unsafe_code)]` Rust Guest `.cdylib` crate (`Cargo.toml`, `src/lib.rs`)
/// directly from [`MirModule`] without intermediate `expr.rs` plan extraction.
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
         crate-type = [\"cdylib\", \"rlib\"]\n\n\
         [dependencies]\n\
         bamabi_guest = {{ version = \"0.3.0\", git = \"https://github.com/yaga-simha/bamabi-wire.git\", branch = \"main\", features = [\"derive\"] }}\n\
         bamabi_sys = {{ version = \"0.3.0\", git = \"https://github.com/yaga-simha/bamabi-wire.git\", branch = \"main\" }}\n"
    );

    let catalog = GuestCatalog::build(mir, &stem);
    let mut lib = String::with_capacity(32768);
    emit_crate_header(&mut lib);
    emit_enums_and_consts(&mut lib, mir, &catalog);
    emit_tables_and_curves(&mut lib, mir, &catalog);
    emit_layouts_and_tags(&mut lib, mir, &catalog);
    emit_runtime_core(&mut lib, mir, &catalog);
    emit_helper_functions(&mut lib, mir, &catalog);
    emit_system_functions(&mut lib, mir, &catalog);
    emit_plugin_and_registration(&mut lib, mir, &catalog, &stem);

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

/// Maps a [`SolvedField`] to its exact `#![forbid(unsafe_code)]` Rust ABI field type.
pub(crate) fn rust_abi_type_for_field(field: &SolvedField, mir: &MirModule) -> String {
    if field.is_padding {
        return format!("[u8; {}]", field.size.max(1));
    }
    if matches!(
        field.ty,
        Ty::Named(_) | Ty::Tuple(_) | Ty::SmallVec { .. } | Ty::InputBuffer { .. } | Ty::Unknown
    ) && !matches_enum_ty(&field.ty, mir)
    {
        return aligned_blob_type(field.size, field.align);
    }
    rust_abi_type_for_ty(&field.ty, field.size, mir)
}

/// Maps a Strata semantic [`Ty`] to its Rust ABI POD type string.
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
            if let Some(en) = find_enum_layout_or_def(n, mir) {
                return match en {
                    1 => "u8".to_owned(),
                    2 => "u16".to_owned(),
                    _ => "u32".to_owned(),
                };
            }
            if let Some(l) = mir.layouts.iter().find(|l| {
                l.canonical_name == *n
                    || l.canonical_name.rsplit("::").next() == Some(n.as_str())
                    || sanitize_ident(&l.canonical_name) == sanitize_ident(n)
            }) {
                return aligned_blob_type(byte_size, l.align);
            }
            aligned_blob_type(byte_size, 4)
        }
        _ => aligned_blob_type(byte_size, 4),
    }
}

/// Computes the zero/canonical Rust default expression for a [`SolvedField`].
pub(crate) fn rust_default_expr_for_field(field: &SolvedField, mir: &MirModule) -> String {
    if field.is_padding {
        return format!("[0u8; {}]", field.size.max(1));
    }
    if matches!(
        field.ty,
        Ty::Named(_) | Ty::Tuple(_) | Ty::SmallVec { .. } | Ty::InputBuffer { .. } | Ty::Unknown
    ) && !matches_enum_ty(&field.ty, mir)
    {
        return aligned_blob_default(field.size, field.align);
    }
    rust_default_expr_for_ty(&field.ty, field.size, mir)
}

/// Sanitizes an arbitrary Strata identifier into a valid Rust identifier (handling keywords).
pub(crate) fn sanitize_rust_ident(raw: &str) -> String {
    let base = sanitize_ident(raw);
    match base.as_str() {
        "self" | "Self" | "super" | "crate" => format!("{base}_"),
        "type" | "match" | "loop" | "in" | "ref" | "mut" | "fn" | "let" | "if" | "else" | "for"
        | "while" | "mod" | "pub" | "struct" | "enum" | "as" | "break" | "const" | "continue"
        | "extern" | "false" | "impl" | "move" | "return" | "static" | "trait" | "true"
        | "unsafe" | "use" | "where" | "async" | "await" | "dyn" | "try" | "gen" => {
            format!("r#{base}")
        }
        _ => base,
    }
}

fn aligned_blob_type(byte_size: usize, align: usize) -> String {
    if byte_size == 0 {
        return "()".to_owned();
    }
    if align >= 8 && byte_size >= 8 && byte_size.is_multiple_of(8) {
        format!("[u64; {}]", byte_size / 8)
    } else if align >= 4 && byte_size >= 4 && byte_size.is_multiple_of(4) {
        format!("[u32; {}]", byte_size / 4)
    } else if align >= 2 && byte_size >= 2 && byte_size.is_multiple_of(2) {
        format!("[u16; {}]", byte_size / 2)
    } else {
        format!("[u8; {byte_size}]")
    }
}

fn aligned_blob_default(byte_size: usize, align: usize) -> String {
    if byte_size == 0 {
        return "()".to_owned();
    }
    if align >= 8 && byte_size >= 8 && byte_size.is_multiple_of(8) {
        format!("[0u64; {}]", byte_size / 8)
    } else if align >= 4 && byte_size >= 4 && byte_size.is_multiple_of(4) {
        format!("[0u32; {}]", byte_size / 4)
    } else if align >= 2 && byte_size >= 2 && byte_size.is_multiple_of(2) {
        format!("[0u16; {}]", byte_size / 2)
    } else {
        format!("[0u8; {byte_size}]")
    }
}

fn matches_enum_ty(ty: &Ty, mir: &MirModule) -> bool {
    if let Ty::Named(n) = ty {
        find_enum_layout_or_def(n, mir).is_some()
    } else {
        false
    }
}

fn find_enum_layout_or_def(name: &str, mir: &MirModule) -> Option<usize> {
    let short = name.rsplit("::").next().unwrap_or(name);
    if let Some(en) = mir.layouts.iter().find(|l| {
        l.item_kind == SchemaItemKind::Enum
            && (l.canonical_name == name
                || l.canonical_name.rsplit("::").next() == Some(short)
                || sanitize_ident(&l.canonical_name) == sanitize_ident(name))
    }) {
        return Some(en.size);
    }
    mir.enums
        .iter()
        .find(|e| {
            e.canonical_name == name
                || e.canonical_name.rsplit("::").next() == Some(short)
                || sanitize_ident(&e.canonical_name) == sanitize_ident(name)
        })
        .map(|e| e.repr_bytes)
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
            if let Some(sz) = find_enum_layout_or_def(n, mir) {
                return match sz {
                    1 => "0u8".to_owned(),
                    2 => "0u16".to_owned(),
                    _ => "0u32".to_owned(),
                };
            }
            if let Some(l) = mir.layouts.iter().find(|l| {
                l.canonical_name == *n || l.canonical_name.rsplit("::").next() == Some(n.as_str())
            }) {
                return aligned_blob_default(byte_size, l.align);
            }
            aligned_blob_default(byte_size, 4)
        }
        _ => aligned_blob_default(byte_size, 4),
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

// ============================================================================
// Catalog & Deduplicated Physical Query Resolution
// ============================================================================

#[derive(Clone)]
struct ComponentEntry {
    id: usize,
    struct_name: String,
    handle_field: String,
    variant_name: String,
    canonical_name: String,
    short_name: String,
    layout: SolvedLayout,
    register_dynamic: bool,
}

#[derive(Clone)]
struct RelationEntry {
    handle_field: String,
    canonical_name: String,
    flags: Vec<String>,
    uuid_bytes: [u8; 16],
    payload_comp_id: Option<usize>,
}

#[derive(Clone)]
struct TableEntry {
    name: String,
    struct_name: String,
    variant_name: String,
    lookup_fn: String,
    fields: Vec<(String, Ty)>,
}

struct GuestCatalog {
    components: Vec<ComponentEntry>,
    topo_order: Vec<usize>,
    relations: Vec<RelationEntry>,
    tables: Vec<TableEntry>,
}

impl GuestCatalog {
    fn build(mir: &MirModule, stem: &str) -> Self {
        let mut components = Vec::new();
        for (idx, layout) in mir.layouts.iter().enumerate() {
            let ident = sanitize_ident(&layout.canonical_name);
            let struct_name = format!("Strata{ident}_{idx}");
            let handle_field = format!("comp_{idx}_{ident}");
            let variant_name = format!("L{idx}_{ident}");
            let short_name = layout
                .canonical_name
                .rsplit("::")
                .next()
                .unwrap_or(&layout.canonical_name)
                .to_owned();
            let register_dynamic = is_ecs_component_kind(layout.item_kind)
                || matches!(
                    layout.item_kind,
                    SchemaItemKind::Resource
                        | SchemaItemKind::Event
                        | SchemaItemKind::Stream
                        | SchemaItemKind::SpatialGrid
                        | SchemaItemKind::SpatialHistory
                );
            components.push(ComponentEntry {
                id: idx,
                struct_name,
                handle_field,
                variant_name,
                canonical_name: layout.canonical_name.clone(),
                short_name,
                layout: layout.clone(),
                register_dynamic,
            });
        }

        // Collect all external/tag component names referenced across MIR not already in mir.layouts.
        let mut extra_tags: BTreeSet<String> = BTreeSet::new();
        let mut maybe_add_tag = |name: &str| {
            let trimmed = name.trim();
            if trimmed.is_empty()
                || trimmed == "Entity"
                || trimmed == "entity"
                || trimmed == "()"
                || trimmed.starts_with('[')
            {
                return;
            }
            if find_comp_idx(&components, trimmed).is_none()
                && !mir.tables.iter().any(|t| t.name == trimmed)
                && !mir.enums.iter().any(|e| {
                    e.canonical_name == trimmed
                        || e.canonical_name.rsplit("::").next() == Some(trimmed)
                })
            {
                extra_tags.insert(trimmed.to_owned());
            }
        };

        for func in mir.functions.iter().chain(mir.fns.iter()) {
            if let MirFnKind::Observer {
                event, target_comp, ..
            } = &func.kind
            {
                maybe_add_tag(event);
                if let Some(tc) = target_comp {
                    maybe_add_tag(tc);
                }
            }
            for r in &func.resources {
                maybe_add_tag(&r.canonical_name);
            }
            for qb in &func.query_bindings {
                for t in &qb.terms {
                    maybe_add_tag(&t.canonical_component);
                }
                for f in &qb.with_filters {
                    maybe_add_tag(f);
                }
                for f in &qb.without_filters {
                    maybe_add_tag(f);
                }
            }
            for bb in &func.blocks {
                for st in &bb.stmts {
                    match &st.inst {
                        Inst::CmdSpawn { components: cs, .. }
                        | Inst::CmdSpawnBatch { components: cs, .. } => {
                            for (c, _) in cs {
                                maybe_add_tag(c);
                            }
                        }
                        Inst::CmdDespawnAll { filter } => {
                            for (_, cname) in parse_despawn_filter_terms(filter) {
                                maybe_add_tag(cname);
                            }
                        }
                        Inst::CmdInsert { component, .. } | Inst::CmdRemove { component, .. } => {
                            maybe_add_tag(component);
                        }
                        Inst::CmdTrigger { event, .. }
                        | Inst::TriggerPayload { event }
                        | Inst::StreamEmit { stream: event, .. } => maybe_add_tag(event),
                        Inst::SpatialRebuildCsr { over_component, .. } => {
                            maybe_add_tag(over_component);
                        }
                        _ => {}
                    }
                }
            }
        }
        for obj in &mir.objects {
            for c in &obj.components {
                maybe_add_tag(c);
            }
            for init in &obj.inits {
                let cname = init
                    .canonical_component
                    .as_deref()
                    .unwrap_or(&init.component);
                maybe_add_tag(cname);
            }
        }
        for rel in &mir.relations {
            if let Some(ref pl) = rel.payload_layout {
                maybe_add_tag(&pl.canonical_name);
            }
        }

        // Deduplicate tags by sanitized short/canonical identity (prefer qualified canonical name).
        let mut seen_tag_shorts: HashMap<String, String> = HashMap::new();
        for raw in extra_tags {
            let short = raw.rsplit("::").next().unwrap_or(&raw).to_owned();
            let entry = seen_tag_shorts.entry(short).or_insert_with(|| raw.clone());
            if raw.contains("::") && !entry.contains("::") {
                *entry = raw;
            }
        }
        let _ = stem;
        for (_short, canon_or_short) in seen_tag_shorts {
            if find_comp_idx(&components, &canon_or_short).is_some() {
                continue;
            }
            let id = components.len();
            // Check relation payload layout if matching
            let layout = if let Some(pl) = mir.relations.iter().find_map(|r| {
                r.payload_layout.as_ref().filter(|l| {
                    l.canonical_name == canon_or_short
                        || l.canonical_name.rsplit("::").next() == Some(canon_or_short.as_str())
                })
            }) {
                pl.clone()
            } else {
                let (uuid, fp) = compute_wire_identity(&canon_or_short, 0, 1, 0, true, &[]);
                SolvedLayout {
                    canonical_name: canon_or_short.clone(),
                    item_kind: SchemaItemKind::Component,
                    fields: Vec::new(),
                    size: 0,
                    align: 1,
                    is_abi_pod: true,
                    component_flags: 0,
                    uuid_bytes: *uuid.as_bytes(),
                    uuid_hex: format!("{uuid:?}"),
                    schema_fingerprint: fp,
                    required_components: Vec::new(),
                    explicit_pad_bytes: 0,
                }
            };
            let ident = sanitize_ident(&layout.canonical_name);
            let short_name = layout
                .canonical_name
                .rsplit("::")
                .next()
                .unwrap_or(&layout.canonical_name)
                .to_owned();
            components.push(ComponentEntry {
                id,
                struct_name: format!("StrataTag_{ident}_{id}"),
                handle_field: format!("comp_{id}_{ident}"),
                variant_name: format!("L{id}_{ident}"),
                canonical_name: layout.canonical_name.clone(),
                short_name,
                layout,
                register_dynamic: true,
            });
        }

        // Topological sort by `required_components` so dependencies register before dependents.
        let mut topo_order = Vec::with_capacity(components.len());
        let mut visited = vec![0u8; components.len()];
        fn visit(
            id: usize,
            components: &[ComponentEntry],
            visited: &mut [u8],
            out: &mut Vec<usize>,
        ) {
            if visited[id] != 0 {
                return;
            }
            visited[id] = 1;
            for req in &components[id].layout.required_components {
                if let Some(dep_id) = find_comp_idx(components, req) {
                    visit(dep_id, components, visited, out);
                }
            }
            visited[id] = 2;
            out.push(id);
        }
        for i in 0..components.len() {
            visit(i, &components, &mut visited, &mut topo_order);
        }

        let mut relations = Vec::with_capacity(mir.relations.len());
        for (idx, rel) in mir.relations.iter().enumerate() {
            let ident = sanitize_ident(&rel.canonical_name);
            let (sz, al) = rel
                .payload_layout
                .as_ref()
                .map_or((0usize, 1usize), |l| (l.size, l.align.max(1)));
            let payload_comp_id = rel
                .payload_layout
                .as_ref()
                .and_then(|l| find_comp_idx(&components, &l.canonical_name));
            let schema_hash = rel
                .payload_layout
                .as_ref()
                .map_or(0, |l| l.schema_fingerprint);
            let uuid =
                bamabi_sys::ComponentUuid::from_parts(&rel.canonical_name, sz, al, schema_hash);
            relations.push(RelationEntry {
                handle_field: format!("rel_{idx}_{ident}"),
                canonical_name: rel.canonical_name.clone(),
                flags: rel.flags.clone(),
                uuid_bytes: *uuid.as_bytes(),
                payload_comp_id,
            });
        }

        let mut tables = Vec::with_capacity(mir.tables.len());
        for (idx, t) in mir.tables.iter().enumerate() {
            let ident = sanitize_ident(&t.name);
            tables.push(TableEntry {
                name: t.name.clone(),
                struct_name: format!("StrataTableRow_{ident}_{idx}"),
                variant_name: format!("T{idx}_{ident}"),
                lookup_fn: format!("strata_table_lookup_{ident}_{idx}"),
                fields: t.fields.clone(),
            });
        }

        Self {
            components,
            topo_order,
            relations,
            tables,
        }
    }

    fn resolve_comp(&self, key: &str) -> Option<&ComponentEntry> {
        find_comp_idx(&self.components, key).map(|id| &self.components[id])
    }

    fn resolve_rel(&self, key: &str) -> Option<&RelationEntry> {
        let short = key.rsplit("::").next().unwrap_or(key);
        self.relations.iter().find(|r| {
            r.canonical_name == key
                || r.canonical_name.rsplit("::").next() == Some(short)
                || sanitize_ident(&r.canonical_name) == sanitize_ident(key)
        })
    }

    fn resolve_table(&self, key: &str) -> Option<&TableEntry> {
        let short = key.rsplit("::").next().unwrap_or(key);
        self.tables.iter().find(|t| {
            t.name == key || t.name == short || sanitize_ident(&t.name) == sanitize_ident(key)
        })
    }
}

fn parse_despawn_filter_terms(filter: &str) -> Vec<(bool, &str)> {
    let mut out = Vec::new();
    for raw in filter.split(',') {
        let t = raw.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(inner) = t
            .strip_prefix("With<")
            .or_else(|| t.strip_prefix("with<"))
            .and_then(|s| s.strip_suffix('>'))
        {
            out.push((false, inner.trim()));
        } else if let Some(inner) = t
            .strip_prefix("Without<")
            .or_else(|| t.strip_prefix("without<"))
            .and_then(|s| s.strip_suffix('>'))
        {
            out.push((true, inner.trim()));
        } else {
            out.push((false, t));
        }
    }
    out
}

fn find_comp_idx(components: &[ComponentEntry], key: &str) -> Option<usize> {
    let base = key.trim();
    if base.is_empty() {
        return None;
    }
    // Try full name first (preserving `PlayerBody::hot` / `CombatantBody::caps`)
    if let Some(pos) = components.iter().position(|c| c.canonical_name == base) {
        return Some(pos);
    }
    let prefix = base.split('.').next().unwrap_or(base);
    if let Some(pos) = components.iter().position(|c| c.canonical_name == prefix) {
        return Some(pos);
    }
    let short = prefix.rsplit("::").next().unwrap_or(prefix);
    if let Some(pos) = components.iter().position(|c| {
        c.short_name == short
            || c.canonical_name.ends_with(&format!("::{prefix}"))
            || sanitize_ident(&c.canonical_name) == sanitize_ident(prefix)
    }) {
        return Some(pos);
    }
    components.iter().position(|c| {
        c.canonical_name
            .rsplit("::")
            .next()
            .is_some_and(|s| s == short)
            || sanitize_ident(&c.short_name) == sanitize_ident(short)
    })
}

/// Physical query representation deduplicating terms that project different fields of the same
/// component (e.g. `hp: &mut? DroneHull.hp, heat: &mut? DroneHull.heat` -> 1 `DroneHull` column).
#[derive(Clone)]
struct PhysicalQueryTerm {
    comp_id: usize,
    mode: TermAccessMode,
    is_sparse: bool,
    changed_filter: bool,
    added_filter: bool,
}

#[derive(Clone)]
struct PhysicalQuery {
    terms: Vec<PhysicalQueryTerm>,
    with_filters: Vec<usize>,
    without_filters: Vec<usize>,
    /// Maps MIR `term_idx` -> `phys_col`
    term_to_phys: HashMap<u32, usize>,
}

fn build_physical_queries(func: &MirFunction, cat: &GuestCatalog) -> Vec<PhysicalQuery> {
    func.query_bindings
        .iter()
        .map(|qb| build_one_physical_query(qb, cat))
        .collect()
}

fn build_one_physical_query(qb: &MirQueryBinding, cat: &GuestCatalog) -> PhysicalQuery {
    let mut terms: Vec<PhysicalQueryTerm> = Vec::new();
    let mut with_filters: Vec<usize> = Vec::new();
    let mut without_filters: Vec<usize> = Vec::new();
    let mut comp_to_phys: HashMap<usize, usize> = HashMap::new();
    let mut term_to_phys: HashMap<u32, usize> = HashMap::new();

    for t in &qb.terms {
        let Some(comp) = cat.resolve_comp(&t.canonical_component) else {
            continue;
        };
        if t.mode == TermAccessMode::With {
            if !comp_to_phys.contains_key(&comp.id) && !with_filters.contains(&comp.id) {
                with_filters.push(comp.id);
            }
            continue;
        }
        if t.mode == TermAccessMode::Without {
            if !comp_to_phys.contains_key(&comp.id) && !without_filters.contains(&comp.id) {
                without_filters.push(comp.id);
            }
            continue;
        }
        if let Some(&existing_phys) = comp_to_phys.get(&comp.id) {
            let pt = &mut terms[existing_phys];
            pt.mode = merge_access_mode(pt.mode, t.mode);
            pt.is_sparse |= t.is_sparse;
            term_to_phys.insert(t.term_idx, existing_phys);
        } else {
            let phys_col = terms.len();
            comp_to_phys.insert(comp.id, phys_col);
            term_to_phys.insert(t.term_idx, phys_col);
            terms.push(PhysicalQueryTerm {
                comp_id: comp.id,
                mode: t.mode,
                is_sparse: t.is_sparse
                    || (comp.layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET)
                        != 0,
                changed_filter: false,
                added_filter: false,
            });
        }
    }

    for f in &qb.with_filters {
        if let Some(c) = cat.resolve_comp(f)
            && !comp_to_phys.contains_key(&c.id)
            && !with_filters.contains(&c.id)
        {
            with_filters.push(c.id);
        }
    }
    for f in &qb.without_filters {
        if let Some(c) = cat.resolve_comp(f)
            && !comp_to_phys.contains_key(&c.id)
            && !without_filters.contains(&c.id)
        {
            without_filters.push(c.id);
        }
    }

    // Remove redundant `With` if already present as data term
    with_filters.retain(|id| !comp_to_phys.contains_key(id));

    PhysicalQuery {
        terms,
        with_filters,
        without_filters,
        term_to_phys,
    }
}

fn merge_access_mode(a: TermAccessMode, b: TermAccessMode) -> TermAccessMode {
    use TermAccessMode as M;
    match (a, b) {
        (M::Write, _) | (_, M::Write) => M::Write,
        (M::SelectiveWrite, _) | (_, M::SelectiveWrite) => M::SelectiveWrite,
        (M::OptionalWrite, _) | (_, M::OptionalWrite) => M::OptionalWrite,
        (M::Read, _) | (_, M::Read) => M::Read,
        (M::OptionalRead, _) | (_, M::OptionalRead) => M::OptionalRead,
        (M::Has, _) | (_, M::Has) => M::Has,
        _ => a,
    }
}

fn queries_have_conflict(queries: &[PhysicalQuery]) -> bool {
    for i in 0..queries.len() {
        for j in (i + 1)..queries.len() {
            let qi = &queries[i];
            let qj = &queries[j];
            for ti in &qi.terms {
                for tj in &qj.terms {
                    if ti.comp_id == tj.comp_id && (ti.mode.is_mutable() || tj.mode.is_mutable()) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// ============================================================================
// Header, Enums, Constants, Tables, Curves, Layouts
// ============================================================================

fn emit_crate_header(out: &mut String) {
    writeln!(out, "#![forbid(unsafe_code)]").ok();
    writeln!(
        out,
        "#![allow(unused_imports, dead_code, unused_variables, unused_mut, unused_parens, non_camel_case_types, non_snake_case, non_upper_case_globals, clippy::all)]"
    )
    .ok();
    writeln!(
        out,
        "//! Auto-generated Safe Rust Guest mod (`#![forbid(unsafe_code)]`, zero `bevy*` deps)."
    )
    .ok();
    writeln!(out).ok();
    writeln!(out, "use bamabi_guest::SymbolEntry;").ok();
    writeln!(out, "use bamabi_guest::commands::SpawnBatchColumn;").ok();
    writeln!(out, "use bamabi_guest::prelude::*;").ok();
    writeln!(out, "use bamabi_guest::raw::BamTermDesc;").ok();
    writeln!(out, "use core::ffi::CStr;").ok();
    writeln!(out, "use std::collections::HashMap;").ok();
    writeln!(out, "use std::sync::{{Arc, Mutex}};").ok();
    writeln!(out).ok();
}

fn emit_enums_and_consts(out: &mut String, mir: &MirModule, cat: &GuestCatalog) {
    for (idx, en) in mir.enums.iter().enumerate() {
        let ident = sanitize_ident(&en.canonical_name);
        writeln!(out, "pub mod enum_{ident}_{idx} {{").ok();
        for (vname, disc) in &en.variants {
            let vident = sanitize_rust_ident(vname);
            writeln!(out, "    pub const {vident}: i64 = {disc};").ok();
        }
        writeln!(out, "}}").ok();
    }
    for c in &mir.consts {
        if let Some(ref expr) = c.expr {
            let val_s = format_hir_expr_rust(expr, &c.ty, mir, cat);
            let rty = const_rust_ty(&c.ty, mir);
            let cname = sanitize_ident(&c.name).to_ascii_uppercase();
            writeln!(out, "pub const STRATA_CONST_{cname}: {rty} = {val_s};").ok();
        }
    }
    if !mir.enums.is_empty() || !mir.consts.is_empty() {
        writeln!(out).ok();
    }
}

fn const_rust_ty(ty: &Ty, mir: &MirModule) -> String {
    match ty {
        Ty::Bool => "bool".to_owned(),
        Ty::U8 => "u8".to_owned(),
        Ty::I8 => "i8".to_owned(),
        Ty::U16 => "u16".to_owned(),
        Ty::I16 => "i16".to_owned(),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => "u32".to_owned(),
        Ty::I32 | Ty::Fix32 => "i32".to_owned(),
        Ty::U64 => "u64".to_owned(),
        Ty::I64 | Ty::Fix64 => "i64".to_owned(),
        Ty::F32 | Ty::UnitScalar { .. } => "f32".to_owned(),
        Ty::F64 => "f64".to_owned(),
        Ty::Vec2 => "[f32; 2]".to_owned(),
        Ty::Vec3 => "[f32; 3]".to_owned(),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => "[f32; 4]".to_owned(),
        _ => rust_abi_type_for_ty(ty, 4, mir),
    }
}

fn emit_tables_and_curves(out: &mut String, mir: &MirModule, cat: &GuestCatalog) {
    for (idx, t) in mir.tables.iter().enumerate() {
        let te = &cat.tables[idx];
        writeln!(out, "#[derive(Clone, Debug, Default)]").ok();
        writeln!(out, "pub struct {} {{", te.struct_name).ok();
        for (fname, fty) in &t.fields {
            let rname = sanitize_rust_ident(fname);
            let rty = table_field_rust_ty(fty, mir);
            writeln!(out, "    pub {rname}: {rty},").ok();
        }
        writeln!(out, "}}").ok();

        let row_count = t.typed_rows.len();
        let ident_upper = sanitize_ident(&t.name).to_ascii_uppercase();
        writeln!(
            out,
            "static STRATA_TABLE_{ident_upper}_{idx}: [{sname}; {row_count}] = [",
            sname = te.struct_name
        )
        .ok();
        for (vname, fields) in &t.typed_rows {
            writeln!(out, "    {} {{", te.struct_name).ok();
            for (fname, fty) in &t.fields {
                let rname = sanitize_rust_ident(fname);
                let val_s = if let Some((_, fexpr)) = fields.iter().find(|(n, _)| n == fname) {
                    format_hir_expr_rust(fexpr, fty, mir, cat)
                } else {
                    table_field_default(fty, mir)
                };
                writeln!(out, "        {rname}: {val_s},").ok();
            }
            writeln!(out, "    }}, // {vname}").ok();
        }
        writeln!(out, "];").ok();

        writeln!(
            out,
            "fn {}(key: i64) -> {} {{",
            te.lookup_fn, te.struct_name
        )
        .ok();
        writeln!(out, "    match key {{").ok();
        for (row_idx, (vname, _)) in t.typed_rows.iter().enumerate() {
            let disc = lookup_enum_variant_disc(&t.key_enum, vname, mir).unwrap_or(row_idx as i64);
            writeln!(
                out,
                "        {disc} => STRATA_TABLE_{ident_upper}_{idx}[{row_idx}].clone(),"
            )
            .ok();
        }
        writeln!(out, "        _ => {}::default(),", te.struct_name).ok();
        writeln!(out, "    }}").ok();
        writeln!(out, "}}\n").ok();
    }

    for (idx, c) in mir.curves.iter().enumerate() {
        let ident = sanitize_ident(&c.name);
        let npts = c.points.len();
        writeln!(
            out,
            "static STRATA_CURVE_{ident}_{idx}: [(f64, f64); {npts}] = ["
        )
        .ok();
        for (x, y) in &c.points {
            writeln!(out, "    ({}, {}),", fmt_f64(*x), fmt_f64(*y)).ok();
        }
        writeln!(out, "];").ok();
        writeln!(
            out,
            "fn strata_curve_sample_{ident}(x: f64) -> f64 {{\n\
             \x20   strata_sample_curve_slice(&STRATA_CURVE_{ident}_{idx}, x)\n\
             }}\n"
        )
        .ok();
    }
}

fn table_field_rust_ty(ty: &Ty, mir: &MirModule) -> String {
    match ty {
        Ty::Bool => "bool".to_owned(),
        Ty::BitSet(bits) => format!("[u32; {}]", (*bits).div_ceil(32).max(1)),
        Ty::InlineStr(_) => "&'static str".to_owned(),
        _ => const_rust_ty(ty, mir),
    }
}

fn table_field_default(ty: &Ty, mir: &MirModule) -> String {
    match ty {
        Ty::Bool => "false".to_owned(),
        Ty::BitSet(bits) => format!("[0u32; {}]", (*bits).div_ceil(32).max(1)),
        Ty::InlineStr(_) => "\"\"".to_owned(),
        _ => rust_default_expr_for_ty(ty, 4, mir),
    }
}

fn emit_layouts_and_tags(out: &mut String, mir: &MirModule, cat: &GuestCatalog) {
    for c in &cat.components {
        let layout = &c.layout;
        let struct_name = &c.struct_name;
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
                let def = field_default_expr_honoring_mir(layout, field, mir, cat);
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
            let esc_name = escape_rust_str(&field.name);
            let esc_tag = escape_rust_str(&field.type_tag);
            writeln!(
                out,
                "    BamFieldDesc::new({kind}, StrView::from_str(\"{esc_name}\"), StrView::from_str(\"{esc_tag}\"), {off}, {sz}, {al}),",
                off = field.offset,
                sz = field.size,
                al = field.align
            )
            .ok();
        }
        writeln!(out, "];").ok();

        let req_uuids: Vec<String> = layout
            .required_components
            .iter()
            .filter_map(|req| cat.resolve_comp(req))
            .map(|rc| {
                format!(
                    "BamRequiredComponent::by_uuid(<{} as ModComponent>::UUID)",
                    rc.struct_name
                )
            })
            .collect();
        if req_uuids.is_empty() {
            writeln!(
                out,
                "static {struct_name}_REQS: &[BamRequiredComponent] = &[];"
            )
            .ok();
        } else {
            writeln!(
                out,
                "static {struct_name}_REQS: &[BamRequiredComponent] = &[{}];",
                req_uuids.join(", ")
            )
            .ok();
        }

        let uuid_lit = format_u8_array_16(&layout.uuid_bytes);
        writeln!(
            out,
            "static {struct_name}_VTABLE: {struct_name}VTable = {struct_name}VTable {{\n\
             \x20   header: VTableHeader::new::<{struct_name}VTable, {struct_name}>(ComponentUuid::from_bytes({uuid_lit})),\n\
             }};\n\
             static {struct_name}_SYMS: &[SymbolEntry] = &[];"
        )
        .ok();

        let esc_canon = escape_rust_str(&layout.canonical_name);
        writeln!(
            out,
            "impl ModComponent for {struct_name} {{\n\
             \x20   const CANONICAL_NAME: &'static str = \"{esc_canon}\";\n\
             \x20   const COMPONENT_CSTR: &'static CStr = c\"{esc_canon}\";\n\
             \x20   const UUID: ComponentUuid = ComponentUuid::from_bytes({uuid_lit});\n\
             \x20   const IS_ABI_POD: bool = {is_pod};\n\
             \x20   const IS_RAW_INSERTABLE: bool = true;\n\
             \x20   const COMPONENT_FLAGS: u32 = 0x{flags:08X};\n\
             \x20   const SCHEMA_FINGERPRINT: u64 = 0x{fp:016X};\n\
             \x20   const BAM_FIELDS: &'static [BamFieldDesc] = {struct_name}_FIELDS;\n\
             \x20   const REQUIRED_COMPONENTS: &'static [BamRequiredComponent] = {struct_name}_REQS;\n\
             \x20   type VTable = {struct_name}VTable;\n\
             \x20   fn vtable() -> &'static Self::VTable {{ &{struct_name}_VTABLE }}\n\
             \x20   fn symbols() -> &'static [SymbolEntry] {{ {struct_name}_SYMS }}\n\
             }}",
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
            al = layout.align.max(1)
        )
        .ok();
    }
}

fn field_default_expr_honoring_mir(
    layout: &SolvedLayout,
    field: &SolvedField,
    mir: &MirModule,
    cat: &GuestCatalog,
) -> String {
    if field.is_padding {
        return format!("[0u8; {}]", field.size.max(1));
    }
    let lookup_short = layout
        .canonical_name
        .rsplit("::")
        .next()
        .unwrap_or(&layout.canonical_name);
    let const_val = mir
        .field_defaults
        .get(&layout.canonical_name)
        .and_then(|m| m.get(&field.name))
        .or_else(|| {
            mir.field_defaults
                .iter()
                .find(|(k, _)| {
                    *k == &layout.canonical_name || k.rsplit("::").next() == Some(lookup_short)
                })
                .and_then(|(_, m)| m.get(&field.name))
        });

    if let Some(cv) = const_val {
        return format_mir_const_for_field(cv, &field.ty, field.size, field.align, mir, cat);
    }

    // If nested struct type matches a layout in `mir.layouts` that has defaults, pack its LE bytes!
    if let Ty::Named(ref n) = field.ty
        && find_enum_layout_or_def(n, mir).is_none()
        && let Some(nested) = cat.resolve_comp(n)
        && nested.layout.size == field.size
        && !nested.layout.fields.is_empty()
    {
        return pack_nested_default_expr(nested, field.size, field.align);
    }

    rust_default_expr_for_field(field, mir)
}

fn pack_nested_default_expr(comp: &ComponentEntry, size: usize, align: usize) -> String {
    let sname = &comp.struct_name;
    let blob_ty = aligned_blob_type(size, align);
    format!(
        "{{ let _v = {sname}::default(); _v.strata_to_blob_{sz}_{al}() }}",
        sz = size,
        al = align.max(1)
    )
    .replace(
        &format!("strata_to_blob_{size}_{}", align.max(1)),
        if blob_ty.starts_with("[u64;") {
            "strata_to_u64_words"
        } else if blob_ty.starts_with("[u32;") {
            "strata_to_u32_words"
        } else if blob_ty.starts_with("[u16;") {
            "strata_to_u16_words"
        } else {
            "strata_to_u8_bytes"
        },
    )
}

fn format_mir_const_for_field(
    cv: &MirConstVal,
    ty: &Ty,
    byte_size: usize,
    align: usize,
    mir: &MirModule,
    cat: &GuestCatalog,
) -> String {
    match (cv, ty) {
        (MirConstVal::Bool(b), Ty::Bool) => {
            if *b {
                "FfiBool::TRUE".to_owned()
            } else {
                "FfiBool::FALSE".to_owned()
            }
        }
        (MirConstVal::Int(v), Ty::U8) => format!("{v}i64 as u8"),
        (MirConstVal::Int(v), Ty::I8) => format!("{v}i64 as i8"),
        (MirConstVal::Int(v), Ty::U16) => format!("{v}i64 as u16"),
        (MirConstVal::Int(v), Ty::I16) => format!("{v}i64 as i16"),
        (MirConstVal::Int(v), Ty::U32 | Ty::Sym | Ty::Rgba8) => format!("{v}i64 as u32"),
        (MirConstVal::Int(v), Ty::I32) => format!("{v}i64 as i32"),
        (MirConstVal::Int(v), Ty::Fix32) => format!("(({v}i64).saturating_mul(65536)) as i32"),
        (MirConstVal::Int(v), Ty::U64) => format!("{v}i64 as u64"),
        (MirConstVal::Int(v), Ty::I64) => format!("{v}i64"),
        (MirConstVal::Int(v), Ty::Fix64) => format!("{v}i64 << 32"),
        (MirConstVal::Int(v), Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow) => {
            format!("{}f32", *v as f32)
        }
        (MirConstVal::Int(v), Ty::F64) => format!("{}f64", *v as f64),
        (MirConstVal::Float(v), Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow) => {
            fmt_f32(*v as f32)
        }
        (MirConstVal::Float(v), Ty::F64) => fmt_f64(*v),
        (MirConstVal::Float(v), Ty::Fix32) => {
            format!("{}i32", (*v * 65536.0).round() as i32)
        }
        (MirConstVal::Float(v), Ty::Fix64) => {
            format!("{}i64", (*v * 4294967296.0).round() as i64)
        }
        (MirConstVal::Int(v), Ty::Bool) => {
            if *v != 0 {
                "FfiBool::TRUE".to_owned()
            } else {
                "FfiBool::FALSE".to_owned()
            }
        }
        (MirConstVal::Vec2(v), Ty::Vec2) => {
            format!("[{}, {}]", fmt_f32(v[0] as f32), fmt_f32(v[1] as f32))
        }
        (MirConstVal::Vec3(v), Ty::Vec3) => format!(
            "[{}, {}, {}]",
            fmt_f32(v[0] as f32),
            fmt_f32(v[1] as f32),
            fmt_f32(v[2] as f32)
        ),
        (MirConstVal::Vec4(v), Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba) => format!(
            "[{}, {}, {}, {}]",
            fmt_f32(v[0] as f32),
            fmt_f32(v[1] as f32),
            fmt_f32(v[2] as f32),
            fmt_f32(v[3] as f32)
        ),
        (MirConstVal::Vec2(v), Ty::IVec2) => format!("[{}i32, {}i32]", v[0] as i32, v[1] as i32),
        (MirConstVal::Vec3(v), Ty::IVec3) => format!(
            "[{}i32, {}i32, {}i32]",
            v[0] as i32, v[1] as i32, v[2] as i32
        ),
        (MirConstVal::Vec2(v), Ty::UVec2) => format!("[{}u32, {}u32]", v[0] as u32, v[1] as u32),
        (MirConstVal::Int(v), Ty::Named(n)) => {
            if let Some(sz) = find_enum_layout_or_def(n, mir) {
                match sz {
                    1 => format!("{v}i64 as u8"),
                    2 => format!("{v}i64 as u16"),
                    _ => format!("{v}i64 as u32"),
                }
            } else {
                rust_default_expr_for_ty(ty, byte_size, mir)
            }
        }
        (MirConstVal::Array(items), Ty::BitSet(bits)) => {
            let words = (*bits).div_ceil(32).max(1);
            let mut mask_words = vec![0u32; words];
            for item in items {
                if let MirConstVal::Int(bit) = item
                    && *bit >= 0
                {
                    let b = *bit as usize;
                    if b / 32 < words {
                        mask_words[b / 32] |= 1u32 << (b % 32);
                    }
                }
            }
            let parts: Vec<String> = mask_words.iter().map(|w| format!("{w}u32")).collect();
            format!("[{}]", parts.join(", "))
        }
        (MirConstVal::Array(items), Ty::Array { elem, len }) => {
            let elem_sz = byte_size / (*len).max(1);
            let mut rendered: Vec<String> = items
                .iter()
                .take(*len)
                .map(|it| format_mir_const_for_field(it, elem, elem_sz, align, mir, cat))
                .collect();
            while rendered.len() < *len {
                rendered.push(rust_default_expr_for_ty(elem, elem_sz, mir));
            }
            format!("[{}]", rendered.join(", "))
        }
        (MirConstVal::Struct { name, fields }, Ty::Named(tn)) => {
            if let Some(nested) = cat.resolve_comp(name).or_else(|| cat.resolve_comp(tn))
                && nested.layout.size == byte_size
                && !nested.layout.fields.is_empty()
            {
                let mut f_inits = Vec::new();
                for (fname, val) in fields {
                    if let Some(sf) = nested.layout.fields.iter().find(|f| f.name == *fname) {
                        let rname = sanitize_rust_ident(fname);
                        let val_s =
                            format_mir_const_for_field(val, &sf.ty, sf.size, sf.align, mir, cat);
                        f_inits.push(format!("{rname}: {val_s}"));
                    }
                }
                let sname = &nested.struct_name;
                let blob_ty = aligned_blob_type(byte_size, align);
                let conv = if blob_ty.starts_with("[u64;") {
                    "strata_to_u64_words"
                } else if blob_ty.starts_with("[u32;") {
                    "strata_to_u32_words"
                } else if blob_ty.starts_with("[u16;") {
                    "strata_to_u16_words"
                } else {
                    "strata_to_u8_bytes"
                };
                return format!(
                    "{{ let _v = {sname} {{ {}, ..{sname}::default() }}; _v.{conv}() }}",
                    f_inits.join(", ")
                );
            }
            rust_default_expr_for_ty(ty, byte_size, mir)
        }
        _ => rust_default_expr_for_ty(ty, byte_size, mir),
    }
}

// ============================================================================
// Unified Safe Runtime Support (`StrataVal`, `StrataObj`, `StrataPtr`, Spatial, WorldState)
// ============================================================================

fn emit_runtime_core(out: &mut String, mir: &MirModule, cat: &GuestCatalog) {
    // 1. Per-component & relation BamComponent handle table + shared World state
    writeln!(out, "#[derive(Clone, Copy, Debug)]").ok();
    writeln!(out, "struct StrataHandles {{").ok();
    for c in &cat.components {
        writeln!(out, "    {}: BamComponent,", c.handle_field).ok();
    }
    for r in &cat.relations {
        writeln!(out, "    {}: BamComponent,", r.handle_field).ok();
    }
    writeln!(out, "}}").ok();

    writeln!(out, "impl Default for StrataHandles {{").ok();
    writeln!(out, "    fn default() -> Self {{").ok();
    writeln!(out, "        Self {{").ok();
    for c in &cat.components {
        writeln!(
            out,
            "            {}: BamComponent::INVALID,",
            c.handle_field
        )
        .ok();
    }
    for r in &cat.relations {
        writeln!(
            out,
            "            {}: BamComponent::INVALID,",
            r.handle_field
        )
        .ok();
    }
    writeln!(out, "        }}").ok();
    writeln!(out, "    }}").ok();
    writeln!(out, "}}\n").ok();

    writeln!(
        out,
        "#[derive(Clone, Debug, Default)]\n\
         struct StrataSpatialGridState {{\n\
         \x20   is_history: bool,\n\
         \x20   frames_cap: usize,\n\
         \x20   history: Vec<Vec<(FfiEntity, [f32; 4])>>,\n\
         }}\n\
         \n\
         #[derive(Debug, Default)]\n\
         struct StrataWorldState {{\n\
         \x20   named_objects: HashMap<String, FfiEntity>,\n\
         \x20   spatial: HashMap<String, StrataSpatialGridState>,\n\
         }}\n"
    )
    .ok();

    // 2. Unified value & aggregate enum (`StrataObj`) covering every layout + table
    writeln!(out, "#[derive(Clone, Debug)]").ok();
    writeln!(out, "enum StrataObj {{").ok();
    writeln!(out, "    Empty,").ok();
    for c in &cat.components {
        writeln!(out, "    {}({}),", c.variant_name, c.struct_name).ok();
    }
    for t in &cat.tables {
        writeln!(out, "    {}({}),", t.variant_name, t.struct_name).ok();
    }
    writeln!(out, "}}\n").ok();

    writeln!(out, "impl Default for StrataObj {{").ok();
    writeln!(out, "    fn default() -> Self {{ Self::Empty }}").ok();
    writeln!(out, "}}\n").ok();

    // Byte serialization helpers on each layout struct (pure safe Rust `.to_le_bytes()`)
    for c in &cat.components {
        emit_struct_byte_and_field_impls(out, mir, cat, c);
    }
    for t in &cat.tables {
        emit_table_field_impls(out, mir, t);
    }

    // `StrataObj` dispatchers
    writeln!(out, "impl StrataObj {{").ok();
    writeln!(
        out,
        "    fn default_for_name(name: &str) -> Self {{\n\
         \x20       match strata_short_key(name) {{"
    )
    .ok();
    for c in &cat.components {
        let esc_c = escape_rust_str(&c.canonical_name);
        let esc_s = escape_rust_str(&c.short_name);
        if esc_c == esc_s {
            writeln!(
                out,
                "            \"{esc_c}\" => Self::{}({}::default()),",
                c.variant_name, c.struct_name
            )
            .ok();
        } else {
            writeln!(
                out,
                "            \"{esc_c}\" | \"{esc_s}\" => Self::{}({}::default()),",
                c.variant_name, c.struct_name
            )
            .ok();
        }
    }
    for t in &cat.tables {
        let esc_t = escape_rust_str(&t.name);
        writeln!(
            out,
            "            \"{esc_t}\" => Self::{}({}::default()),",
            t.variant_name, t.struct_name
        )
        .ok();
    }
    writeln!(out, "            _ => Self::Empty,\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn get_field(&self, off: u32, field: &str) -> StrataVal {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        writeln!(
            out,
            "            Self::{}(v) => v.strata_get(off, field),",
            c.variant_name
        )
        .ok();
    }
    for t in &cat.tables {
        writeln!(
            out,
            "            Self::{}(v) => v.strata_get(off, field),",
            t.variant_name
        )
        .ok();
    }
    writeln!(
        out,
        "            Self::Empty => StrataVal::Unit,\n        }}\n    }}"
    )
    .ok();

    writeln!(
        out,
        "    fn set_field(&mut self, off: u32, field: &str, val: StrataVal) {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        writeln!(
            out,
            "            Self::{}(v) => v.strata_set(off, field, val),",
            c.variant_name
        )
        .ok();
    }
    for t in &cat.tables {
        writeln!(
            out,
            "            Self::{}(v) => v.strata_set(off, field, val),",
            t.variant_name
        )
        .ok();
    }
    writeln!(out, "            Self::Empty => {{}}\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn read_le_bytes(&self) -> Vec<u8> {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        writeln!(
            out,
            "            Self::{}(v) => v.strata_to_u8_bytes().to_vec(),",
            c.variant_name
        )
        .ok();
    }
    writeln!(out, "            _ => Vec::new(),\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn write_le_bytes(&mut self, bytes: &[u8]) {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        writeln!(
            out,
            "            Self::{}(v) => v.strata_from_u8_bytes(bytes),",
            c.variant_name
        )
        .ok();
    }
    writeln!(out, "            _ => {{}}\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn spawn_entry<'a>(&'a self, handles: &StrataHandles) -> Option<SpawnEntry<'a>> {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        if c.layout.size == 0 || c.layout.fields.is_empty() {
            writeln!(
                out,
                "            Self::{}(_) => Some(SpawnEntry::marker(handles.{})),",
                c.variant_name, c.handle_field
            )
            .ok();
        } else {
            writeln!(
                out,
                "            Self::{}(v) => Some(SpawnEntry::new(handles.{}, v)),",
                c.variant_name, c.handle_field
            )
            .ok();
        }
    }
    writeln!(out, "            _ => None,\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn cmd_insert(&self, cmds: &mut GuestCommands<'_>, handles: &StrataHandles, entity: FfiEntity, if_new: bool) {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        writeln!(
            out,
            "            Self::{}(v) => {{ if if_new {{ let _ = cmds.insert_if_new(entity, handles.{}, v); }} else {{ let _ = cmds.insert(entity, handles.{}, v); }} }},",
            c.variant_name, c.handle_field, c.handle_field
        )
        .ok();
    }
    writeln!(out, "            _ => {{}}\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn cmd_trigger(&self, cmds: &mut GuestCommands<'_>, handles: &StrataHandles, target: Option<FfiEntity>, propagate: bool) {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        if c.register_dynamic {
            writeln!(
                out,
                "            Self::{}(v) => {{\n\
                 \x20               if propagate {{\n\
                 \x20                   let _ = cmds.trigger_propagated_handle(handles.{hf}, target.unwrap_or(FfiEntity::NULL), v, BamComponent::INVALID);\n\
                 \x20               }} else if let Some(t) = target {{\n\
                 \x20                   let _ = cmds.trigger_entity(t, v);\n\
                 \x20               }} else {{\n\
                 \x20                   let _ = cmds.trigger(v);\n\
                 \x20               }}\n\
                 \x20           }},",
                c.variant_name,
                hf = c.handle_field
            )
            .ok();
        }
    }
    writeln!(out, "            _ => {{}}\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn cmd_insert_rel(&self, cmds: &mut GuestCommands<'_>, rel_handle: BamComponent, entity: FfiEntity, target: FfiEntity) {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        writeln!(
            out,
            "            Self::{}(v) => {{ let _ = cmds.insert_relation_with_payload(entity, rel_handle, target, v); }},",
            c.variant_name
        )
        .ok();
    }
    writeln!(out, "            _ => {{}}\n        }}\n    }}").ok();

    writeln!(
        out,
        "    fn send_msg(&self, ctx: &mut SystemContext<'_>, decl_idx: usize) {{\n\
         \x20       match self {{"
    )
    .ok();
    for c in &cat.components {
        if c.register_dynamic {
            writeln!(
                out,
                "            Self::{}(v) => {{ let _ = ctx.send_message::<{}>(decl_idx, v); }},",
                c.variant_name, c.struct_name
            )
            .ok();
        }
    }
    writeln!(out, "            _ => {{}}\n        }}\n    }}").ok();
    writeln!(out, "}}\n").ok();

    // 3. `StrataVal`, `StrataPtr`, `HostBridge`, and pure safe primitive helpers
    out.push_str(STRATA_RUNTIME_PRELUDE);
}

fn emit_struct_byte_and_field_impls(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    c: &ComponentEntry,
) {
    let sname = &c.struct_name;
    let sz = c.layout.size;
    let is_zst = sz == 0 || c.layout.fields.is_empty();

    writeln!(out, "impl {sname} {{").ok();
    if is_zst {
        writeln!(out, "    fn strata_to_u8_bytes(&self) -> [u8; 0] {{ [] }}").ok();
        writeln!(
            out,
            "    fn strata_from_u8_bytes(&mut self, _b: &[u8]) {{}}"
        )
        .ok();
        writeln!(
            out,
            "    fn strata_get(&self, _off: u32, _field: &str) -> StrataVal {{ StrataVal::Unit }}"
        )
        .ok();
        writeln!(
            out,
            "    fn strata_set(&mut self, _off: u32, _field: &str, _val: StrataVal) {{}}"
        )
        .ok();
    } else {
        writeln!(out, "    fn strata_to_u8_bytes(&self) -> [u8; {sz}] {{").ok();
        writeln!(out, "        let mut out = [0u8; {sz}];").ok();
        for f in &c.layout.fields {
            let fname = sanitize_rust_ident(&f.name);
            let off = f.offset;
            let fsz = f.size;
            let rty = rust_abi_type_for_field(f, mir);
            emit_write_field_to_bytes(out, &format!("self.{fname}"), &rty, off, fsz);
        }
        writeln!(out, "        out").ok();
        writeln!(out, "    }}").ok();

        writeln!(out, "    fn strata_from_u8_bytes(&mut self, b: &[u8]) {{").ok();
        writeln!(out, "        if b.len() < {sz} {{ return; }}").ok();
        for f in &c.layout.fields {
            if f.is_padding {
                continue;
            }
            let fname = sanitize_rust_ident(&f.name);
            let off = f.offset;
            let fsz = f.size;
            let rty = rust_abi_type_for_field(f, mir);
            emit_read_field_from_bytes(out, &format!("self.{fname}"), &rty, off, fsz);
        }
        writeln!(out, "    }}").ok();

        for (w, ty, elem_sz, conv) in [
            ("u64_words", "u64", 8usize, "u64::from_le_bytes"),
            ("u32_words", "u32", 4usize, "u32::from_le_bytes"),
            ("u16_words", "u16", 2usize, "u16::from_le_bytes"),
        ] {
            if sz >= elem_sz && sz.is_multiple_of(elem_sz) {
                let n = sz / elem_sz;
                writeln!(out, "    fn strata_to_{w}(&self) -> [{ty}; {n}] {{").ok();
                writeln!(out, "        let bytes = self.strata_to_u8_bytes();").ok();
                writeln!(out, "        let mut out = [0{ty}; {n}];").ok();
                writeln!(
                    out,
                    "        for (i, slot) in out.iter_mut().enumerate() {{\n\
                     \x20           let s = i * {elem_sz};\n\
                     \x20           *slot = {conv}(bytes[s..s + {elem_sz}].try_into().unwrap_or([0u8; {elem_sz}]));\n\
                     \x20       }}"
                )
                .ok();
                writeln!(out, "        out").ok();
                writeln!(out, "    }}").ok();
            }
        }

        writeln!(
            out,
            "    fn strata_get(&self, off: u32, field: &str) -> StrataVal {{"
        )
        .ok();
        writeln!(
            out,
            "        if field.is_empty() && off == 0 {{\n\
             \x20           return StrataVal::Obj(StrataObj::{}(*self));\n\
             \x20       }}",
            c.variant_name
        )
        .ok();
        // Dispatch by leaf offset OR field name (including nested fields via byte slice)
        let mut first = true;
        for f in &c.layout.fields {
            if f.is_padding {
                continue;
            }
            let fname_esc = escape_rust_str(&f.name);
            let rname = sanitize_rust_ident(&f.name);
            let kw = if first { "if" } else { "else if" };
            first = false;
            writeln!(
                out,
                "        {kw} field == \"{fname_esc}\" || (field.is_empty() && off as usize == {off}) {{\n\
                 \x20           return {};\n\
                 \x20       }}",
                emit_field_val_to_strata_val(&format!("self.{rname}"), &f.ty, f.size, mir, cat),
                off = f.offset
            )
            .ok();
        }
        writeln!(
            out,
            "        let bytes = self.strata_to_u8_bytes();\n\
             \x20       strata_decode_sub_field(&bytes, off as usize, field)"
        )
        .ok();
        writeln!(out, "    }}").ok();

        writeln!(
            out,
            "    fn strata_set(&mut self, off: u32, field: &str, val: StrataVal) {{"
        )
        .ok();
        writeln!(
            out,
            "        if field.is_empty() && off == 0 {{\n\
             \x20           if let StrataVal::Obj(StrataObj::{}(v)) = val {{ *self = v; return; }}\n\
             \x20       }}",
            c.variant_name
        )
        .ok();
        let mut first = true;
        for f in &c.layout.fields {
            if f.is_padding {
                continue;
            }
            let fname_esc = escape_rust_str(&f.name);
            let rname = sanitize_rust_ident(&f.name);
            let kw = if first { "if" } else { "else if" };
            first = false;
            let assign_stmt =
                emit_strata_val_assign_to_field(&format!("self.{rname}"), &f.ty, f.size, mir);
            writeln!(
                out,
                "        {kw} field == \"{fname_esc}\" || (field.is_empty() && off as usize == {off}) {{\n\
                 \x20           {assign_stmt}\n\
                 \x20           return;\n\
                 \x20       }}",
                off = f.offset
            )
            .ok();
        }
        writeln!(
            out,
            "        let mut bytes = self.strata_to_u8_bytes();\n\
             \x20       strata_encode_sub_field(&mut bytes, off as usize, &val);\n\
             \x20       self.strata_from_u8_bytes(&bytes);"
        )
        .ok();
        writeln!(out, "    }}").ok();
    }
    writeln!(out, "}}\n").ok();
}

fn emit_table_field_impls(out: &mut String, mir: &MirModule, te: &TableEntry) {
    let sname = &te.struct_name;
    writeln!(out, "impl {sname} {{").ok();
    writeln!(
        out,
        "    fn strata_get(&self, _off: u32, field: &str) -> StrataVal {{"
    )
    .ok();
    writeln!(out, "        match field {{").ok();
    writeln!(
        out,
        "            \"\" => StrataVal::Obj(StrataObj::{}(self.clone())),",
        te.variant_name
    )
    .ok();
    for (fname, fty) in &te.fields {
        let esc = escape_rust_str(fname);
        let rname = sanitize_rust_ident(fname);
        let conv = match fty {
            Ty::Bool => format!("StrataVal::Bool(self.{rname})"),
            Ty::U8 | Ty::U16 | Ty::U32 | Ty::Sym | Ty::Rgba8 => {
                format!("StrataVal::U32(self.{rname} as u32)")
            }
            Ty::I8 | Ty::I16 | Ty::I32 | Ty::Fix32 => {
                format!("StrataVal::I32(self.{rname} as i32)")
            }
            Ty::U64 => format!("StrataVal::U64(self.{rname})"),
            Ty::I64 | Ty::Fix64 => format!("StrataVal::I64(self.{rname})"),
            Ty::F32 | Ty::UnitScalar { .. } => format!("StrataVal::F32(self.{rname})"),
            Ty::F64 => format!("StrataVal::F64(self.{rname})"),
            Ty::Vec2 => format!("StrataVal::Vec2(self.{rname})"),
            Ty::Vec3 => format!("StrataVal::Vec3(self.{rname})"),
            Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => format!("StrataVal::Vec4(self.{rname})"),
            Ty::BitSet(_) => format!("StrataVal::Words(self.{rname}.to_vec())"),
            Ty::InlineStr(_) => format!("StrataVal::Str(self.{rname}.to_owned())"),
            Ty::Named(n) if find_enum_layout_or_def(n, mir).is_some() => {
                format!("StrataVal::U32(self.{rname} as u32)")
            }
            _ => "StrataVal::Unit".to_owned(),
        };
        writeln!(out, "            \"{esc}\" => {conv},").ok();
    }
    writeln!(out, "            _ => StrataVal::Unit,\n        }}\n    }}").ok();
    writeln!(
        out,
        "    fn strata_set(&mut self, _off: u32, _field: &str, _val: StrataVal) {{}}"
    )
    .ok();
    writeln!(out, "}}\n").ok();
}

fn emit_write_field_to_bytes(out: &mut String, expr: &str, rty: &str, off: usize, size: usize) {
    match rty {
        "u8" => writeln!(out, "        out[{off}] = {expr};").ok(),
        "i8" => writeln!(out, "        out[{off}] = {expr} as u8;").ok(),
        "FfiBool" => writeln!(out, "        out[{off}] = {expr}.0;").ok(),
        "u16" | "i16" | "u32" | "i32" | "u64" | "i64" | "f32" | "f64" => {
            writeln!(
                out,
                "        out[{off}..{end}].copy_from_slice(&{expr}.to_le_bytes());",
                end = off + size
            )
            .ok()
        }
        "FfiEntity" => {
            writeln!(
                out,
                "        out[{off}..{end}].copy_from_slice(&{expr}.to_bits().to_le_bytes());",
                end = off + 8
            )
            .ok()
        }
        "FfiAssetHandle" => {
            writeln!(
                out,
                "        out[{off}] = {expr}.kind;\n\
                 \x20       out[{o1}..{o4}].copy_from_slice(&{expr}.reserved0);\n\
                 \x20       out[{o4}..{o8}].copy_from_slice(&{expr}.asset_type.to_raw().to_le_bytes());\n\
                 \x20       out[{o8}..{o12}].copy_from_slice(&{expr}.index.to_le_bytes());\n\
                 \x20       out[{o12}..{o16}].copy_from_slice(&{expr}.generation.to_le_bytes());\n\
                 \x20       out[{o16}..{o32}].copy_from_slice({expr}.uuid.as_bytes());",
                o1 = off + 1,
                o4 = off + 4,
                o8 = off + 8,
                o12 = off + 12,
                o16 = off + 16,
                o32 = off + 32
            )
            .ok()
        }
        _ if rty.starts_with('[') => {
            // Parse outer `[elem; len]`
            if let Some((elem, len)) = parse_rust_array_type(rty) {
                let elem_sz = size.checked_div(len).unwrap_or(0);
                writeln!(
                    out,
                    "        for (_ai, _ael) in {expr}.iter().enumerate() {{\n\
                     \x20           let _ao = {off} + _ai * {elem_sz};"
                )
                .ok();
                match elem {
                    "u8" => writeln!(out, "            out[_ao] = *_ael;").ok(),
                    "i8" => writeln!(out, "            out[_ao] = *_ael as u8;").ok(),
                    "FfiBool" => writeln!(out, "            out[_ao] = _ael.0;").ok(),
                    "u16" | "i16" | "u32" | "i32" | "u64" | "i64" | "f32" | "f64" => {
                        writeln!(
                            out,
                            "            out[_ao.._ao + {elem_sz}].copy_from_slice(&_ael.to_le_bytes());"
                        )
                        .ok()
                    }
                    "FfiEntity" => writeln!(
                        out,
                        "            out[_ao.._ao + 8].copy_from_slice(&_ael.to_bits().to_le_bytes());"
                    )
                    .ok(),
                    _ => writeln!(out, "            let _ = (_ao, _ael);").ok(),
                };
                writeln!(out, "        }}").ok()
            } else {
                None
            }
        }
        _ => None,
    };
}

fn emit_read_field_from_bytes(out: &mut String, expr: &str, rty: &str, off: usize, size: usize) {
    match rty {
        "u8" => writeln!(out, "        {expr} = b[{off}];").ok(),
        "i8" => writeln!(out, "        {expr} = b[{off}] as i8;").ok(),
        "FfiBool" => writeln!(out, "        {expr} = FfiBool(b[{off}]);").ok(),
        "u16" | "i16" | "u32" | "i32" | "u64" | "i64" | "f32" | "f64" => {
            writeln!(
                out,
                "        {expr} = {rty}::from_le_bytes(b[{off}..{end}].try_into().unwrap_or([0u8; {size}]));",
                end = off + size
            )
            .ok()
        }
        "FfiEntity" => {
            writeln!(
                out,
                "        {expr} = FfiEntity::from_bits(u64::from_le_bytes(b[{off}..{end}].try_into().unwrap_or([0u8; 8])));",
                end = off + 8
            )
            .ok()
        }
        "FfiAssetHandle" => {
            writeln!(
                out,
                "        {expr}.kind = b[{off}];\n\
                 \x20       {expr}.reserved0 = [b[{o1}], b[{o2}], b[{o3}]];\n\
                 \x20       {expr}.asset_type = BamComponent::from_raw(u32::from_le_bytes(b[{o4}..{o8}].try_into().unwrap_or([0u8; 4])));\n\
                 \x20       {expr}.index = u32::from_le_bytes(b[{o8}..{o12}].try_into().unwrap_or([0u8; 4]));\n\
                 \x20       {expr}.generation = u32::from_le_bytes(b[{o12}..{o16}].try_into().unwrap_or([0u8; 4]));\n\
                 \x20       {expr}.uuid = ComponentUuid::from_bytes(b[{o16}..{o32}].try_into().unwrap_or([0u8; 16]));",
                o1 = off + 1,
                o2 = off + 2,
                o3 = off + 3,
                o4 = off + 4,
                o8 = off + 8,
                o12 = off + 12,
                o16 = off + 16,
                o32 = off + 32
            )
            .ok()
        }
        _ if rty.starts_with('[') => {
            if let Some((elem, len)) = parse_rust_array_type(rty) {
                let elem_sz = size.checked_div(len).unwrap_or(0);
                writeln!(
                    out,
                    "        for (_ai, _ael) in {expr}.iter_mut().enumerate() {{\n\
                     \x20           let _ao = {off} + _ai * {elem_sz};"
                )
                .ok();
                match elem {
                    "u8" => writeln!(out, "            *_ael = b[_ao];").ok(),
                    "i8" => writeln!(out, "            *_ael = b[_ao] as i8;").ok(),
                    "FfiBool" => writeln!(out, "            *_ael = FfiBool(b[_ao]);").ok(),
                    "u16" | "i16" | "u32" | "i32" | "u64" | "i64" | "f32" | "f64" => {
                        writeln!(
                            out,
                            "            *_ael = {elem}::from_le_bytes(b[_ao.._ao + {elem_sz}].try_into().unwrap_or([0u8; {elem_sz}]));"
                        )
                        .ok()
                    }
                    "FfiEntity" => writeln!(
                        out,
                        "            *_ael = FfiEntity::from_bits(u64::from_le_bytes(b[_ao.._ao + 8].try_into().unwrap_or([0u8; 8])));"
                    )
                    .ok(),
                    _ => writeln!(out, "            let _ = (_ao, _ael);").ok(),
                };
                writeln!(out, "        }}").ok()
            } else {
                None
            }
        }
        _ => None,
    };
}

fn parse_rust_array_type(rty: &str) -> Option<(&str, usize)> {
    let inner = rty.strip_prefix('[')?.strip_suffix(']')?;
    let (elem, len_str) = inner.rsplit_once(';')?;
    let len = len_str.trim().parse::<usize>().ok()?;
    Some((elem.trim(), len))
}

fn emit_field_val_to_strata_val(
    expr: &str,
    ty: &Ty,
    byte_size: usize,
    mir: &MirModule,
    cat: &GuestCatalog,
) -> String {
    match ty {
        Ty::Bool => format!("StrataVal::Bool({expr}.get())"),
        Ty::U8 | Ty::U16 | Ty::U32 | Ty::Sym | Ty::Rgba8 => {
            format!("StrataVal::U32({expr} as u32)")
        }
        Ty::I8 | Ty::I16 | Ty::I32 | Ty::Fix32 => format!("StrataVal::I32({expr} as i32)"),
        Ty::U64 => format!("StrataVal::U64({expr})"),
        Ty::I64 | Ty::Fix64 => format!("StrataVal::I64({expr})"),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => format!("StrataVal::F32({expr})"),
        Ty::F64 => format!("StrataVal::F64({expr})"),
        Ty::Vec2 => format!("StrataVal::Vec2({expr})"),
        Ty::Vec3 => format!("StrataVal::Vec3({expr})"),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => format!("StrataVal::Vec4({expr})"),
        Ty::IVec2 => format!("StrataVal::IVec2({expr})"),
        Ty::IVec3 => format!("StrataVal::IVec3({expr})"),
        Ty::UVec2 => format!("StrataVal::UVec2({expr})"),
        Ty::Ref(_) => format!("StrataVal::Entity({expr})"),
        Ty::Asset(_) => format!("StrataVal::Asset({expr})"),
        Ty::BitSet(_) => format!("StrataVal::Words({expr}.to_vec())"),
        Ty::Array { elem, .. } => {
            let inner = emit_field_val_to_strata_val("(*_x)", elem, 4, mir, cat);
            format!("StrataVal::Arr({expr}.iter().map(|_x| {inner}).collect())")
        }
        Ty::Named(n) => {
            if find_enum_layout_or_def(n, mir).is_some() {
                format!("StrataVal::U32({expr} as u32)")
            } else if let Some(nested) = cat.resolve_comp(n)
                && nested.layout.size == byte_size
            {
                let vname = &nested.variant_name;
                let sname = &nested.struct_name;
                format!(
                    "{{ let _tmp = {expr}; let mut _raw = Vec::with_capacity({byte_size}); for _w in &_tmp {{ strata_push_le_into(&mut _raw, *_w); }} let mut _dst = {sname}::default(); _dst.strata_from_u8_bytes(&_raw); StrataVal::Obj(StrataObj::{vname}(_dst)) }}"
                )
            } else {
                format!("StrataVal::Words({expr}.iter().map(|_w| *_w as u32).collect())")
            }
        }
        _ => "StrataVal::Unit".to_owned(),
    }
}

fn emit_strata_val_assign_to_field(
    expr: &str,
    ty: &Ty,
    byte_size: usize,
    mir: &MirModule,
) -> String {
    match ty {
        Ty::Bool => format!("{expr} = FfiBool::from_bool(val.as_bool());"),
        Ty::U8 => format!("{expr} = val.as_u32() as u8;"),
        Ty::I8 => format!("{expr} = val.as_i32() as i8;"),
        Ty::U16 => format!("{expr} = val.as_u32() as u16;"),
        Ty::I16 => format!("{expr} = val.as_i32() as i16;"),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => format!("{expr} = val.as_u32();"),
        Ty::I32 | Ty::Fix32 => format!("{expr} = val.as_i32();"),
        Ty::U64 => format!("{expr} = val.as_u64();"),
        Ty::I64 | Ty::Fix64 => format!("{expr} = val.as_i64();"),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => format!("{expr} = val.as_f32();"),
        Ty::F64 => format!("{expr} = val.as_f64();"),
        Ty::Vec2 => format!("{expr} = val.as_vec2();"),
        Ty::Vec3 => format!("{expr} = val.as_vec3();"),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => format!("{expr} = val.as_vec4();"),
        Ty::IVec2 => format!("{expr} = val.as_ivec2();"),
        Ty::IVec3 => format!("{expr} = val.as_ivec3();"),
        Ty::UVec2 => format!("{expr} = val.as_uvec2();"),
        Ty::Ref(_) => format!("{expr} = val.as_entity();"),
        Ty::Asset(_) => format!("if let StrataVal::Asset(a) = val {{ {expr} = a; }}"),
        Ty::BitSet(_) => format!(
            "if let StrataVal::Words(w) = val {{ for (dst, src) in {expr}.iter_mut().zip(w.into_iter()) {{ *dst = src; }} }}"
        ),
        Ty::Named(n) => {
            if let Some(sz) = find_enum_layout_or_def(n, mir) {
                match sz {
                    1 => format!("{expr} = val.as_u32() as u8;"),
                    2 => format!("{expr} = val.as_u32() as u16;"),
                    _ => format!("{expr} = val.as_u32();"),
                }
            } else {
                format!(
                    "if let StrataVal::Obj(ref o) = val {{ let _b = o.read_le_bytes(); let mut _idx = 0usize; for _slot in {expr}.iter_mut() {{ let _step = core::mem::size_of_val(_slot); if _idx + _step <= _b.len() {{ strata_copy_le_slice(_slot, &_b[_idx.._idx + _step]); _idx += _step; }} }} }} else {{ let _ = {byte_size}; }}"
                )
            }
        }
        _ => String::new(),
    }
}

const STRATA_RUNTIME_PRELUDE: &str = r#"
#[derive(Clone, Copy, Debug)]
enum StrataPtr {
    Null,
    Slot { sid: usize, off: u32 },
    Res { decl_idx: usize, comp_id: usize, off: u32, is_mut: bool },
    ChunkCol { qi: usize, phys_col: usize, comp_id: usize, is_mut: bool, is_untracked: bool, is_sparse: bool },
    ChunkRow { qi: usize, phys_col: usize, comp_id: usize, row: usize, off: u32, is_mut: bool, is_untracked: bool, is_sparse: bool },
    ChunkEntities { qi: usize },
    SpatialHits { idx: usize },
    EntityPoint { qi: usize, phys_col: usize, comp_id: usize, entity: FfiEntity, off: u32, is_mut: bool },
    EventPayload { off: u32 },
    MigrateSrc { off: u32 },
    MigrateDst { off: u32 },
}

impl StrataPtr {
    fn with_added_offset(self, add_off: u32) -> Self {
        match self {
            Self::Slot { sid, off } => Self::Slot { sid, off: off.saturating_add(add_off) },
            Self::Res { decl_idx, comp_id, off, is_mut } => Self::Res { decl_idx, comp_id, off: off.saturating_add(add_off), is_mut },
            Self::ChunkRow { qi, phys_col, comp_id, row, off, is_mut, is_untracked, is_sparse } => {
                Self::ChunkRow { qi, phys_col, comp_id, row, off: off.saturating_add(add_off), is_mut, is_untracked, is_sparse }
            }
            Self::EntityPoint { qi, phys_col, comp_id, entity, off, is_mut } => {
                Self::EntityPoint { qi, phys_col, comp_id, entity, off: off.saturating_add(add_off), is_mut }
            }
            Self::EventPayload { off } => Self::EventPayload { off: off.saturating_add(add_off) },
            Self::MigrateSrc { off } => Self::MigrateSrc { off: off.saturating_add(add_off) },
            Self::MigrateDst { off } => Self::MigrateDst { off: off.saturating_add(add_off) },
            other => other,
        }
    }

    fn set_exact_offset(self, exact_off: u32) -> Self {
        match self {
            Self::Slot { sid, .. } => Self::Slot { sid, off: exact_off },
            Self::Res { decl_idx, comp_id, is_mut, .. } => Self::Res { decl_idx, comp_id, off: exact_off, is_mut },
            Self::ChunkRow { qi, phys_col, comp_id, row, is_mut, is_untracked, is_sparse, .. } => {
                Self::ChunkRow { qi, phys_col, comp_id, row, off: exact_off, is_mut, is_untracked, is_sparse }
            }
            Self::EntityPoint { qi, phys_col, comp_id, entity, is_mut, .. } => {
                Self::EntityPoint { qi, phys_col, comp_id, entity, off: exact_off, is_mut }
            }
            Self::EventPayload { .. } => Self::EventPayload { off: exact_off },
            Self::MigrateSrc { .. } => Self::MigrateSrc { off: exact_off },
            Self::MigrateDst { .. } => Self::MigrateDst { off: exact_off },
            other => other,
        }
    }
}

#[derive(Clone, Debug)]
enum StrataVal {
    Unit,
    Bool(bool),
    I32(i32),
    U32(u32),
    I64(i64),
    U64(u64),
    F32(f32),
    F64(f64),
    Vec2([f32; 2]),
    Vec3([f32; 3]),
    Vec4([f32; 4]),
    IVec2([i32; 2]),
    IVec3([i32; 3]),
    UVec2([u32; 2]),
    Entity(FfiEntity),
    Asset(FfiAssetHandle),
    Str(String),
    Checkpoint(usize),
    Ptr(StrataPtr),
    Arr(Vec<StrataVal>),
    Words(Vec<u32>),
    Obj(StrataObj),
}

impl Default for StrataVal {
    fn default() -> Self {
        Self::Unit
    }
}

impl StrataVal {
    fn as_bool(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::I32(v) => *v != 0,
            Self::U32(v) => *v != 0,
            Self::I64(v) => *v != 0,
            Self::U64(v) => *v != 0,
            Self::F32(v) => *v != 0.0,
            Self::F64(v) => *v != 0.0,
            Self::Entity(e) => !e.is_null(),
            _ => false,
        }
    }

    fn as_i32(&self) -> i32 {
        match self {
            Self::Bool(b) => i32::from(*b),
            Self::I32(v) => *v,
            Self::U32(v) => *v as i32,
            Self::I64(v) => *v as i32,
            Self::U64(v) => *v as i32,
            Self::F32(v) => *v as i32,
            Self::F64(v) => *v as i32,
            _ => 0,
        }
    }

    fn as_u32(&self) -> u32 {
        match self {
            Self::Bool(b) => u32::from(*b),
            Self::I32(v) => *v as u32,
            Self::U32(v) => *v,
            Self::I64(v) => *v as u32,
            Self::U64(v) => *v as u32,
            Self::F32(v) => *v as u32,
            Self::F64(v) => *v as u32,
            Self::Entity(e) => e.to_bits() as u32,
            _ => 0,
        }
    }

    fn as_i64(&self) -> i64 {
        match self {
            Self::Bool(b) => i64::from(*b),
            Self::I32(v) => i64::from(*v),
            Self::U32(v) => i64::from(*v),
            Self::I64(v) => *v,
            Self::U64(v) => *v as i64,
            Self::F32(v) => *v as i64,
            Self::F64(v) => *v as i64,
            Self::Entity(e) => e.to_bits() as i64,
            _ => 0,
        }
    }

    fn as_u64(&self) -> u64 {
        match self {
            Self::Bool(b) => u64::from(*b),
            Self::I32(v) => *v as u64,
            Self::U32(v) => u64::from(*v),
            Self::I64(v) => *v as u64,
            Self::U64(v) => *v,
            Self::F32(v) => *v as u64,
            Self::F64(v) => *v as u64,
            Self::Entity(e) => e.to_bits(),
            _ => 0,
        }
    }

    fn as_f32(&self) -> f32 {
        match self {
            Self::Bool(b) => if *b { 1.0 } else { 0.0 },
            Self::I32(v) => *v as f32,
            Self::U32(v) => *v as f32,
            Self::I64(v) => *v as f32,
            Self::U64(v) => *v as f32,
            Self::F32(v) => *v,
            Self::F64(v) => *v as f32,
            _ => 0.0,
        }
    }

    fn as_f64(&self) -> f64 {
        match self {
            Self::Bool(b) => if *b { 1.0 } else { 0.0 },
            Self::I32(v) => f64::from(*v),
            Self::U32(v) => f64::from(*v),
            Self::I64(v) => *v as f64,
            Self::U64(v) => *v as f64,
            Self::F32(v) => f64::from(*v),
            Self::F64(v) => *v,
            _ => 0.0,
        }
    }

    fn as_vec2(&self) -> [f32; 2] {
        match self {
            Self::Vec2(v) => *v,
            Self::Vec3(v) => [v[0], v[1]],
            Self::Vec4(v) => [v[0], v[1]],
            Self::F32(s) => [*s, *s],
            Self::F64(s) => [*s as f32, *s as f32],
            _ => [0.0, 0.0],
        }
    }

    fn as_vec3(&self) -> [f32; 3] {
        match self {
            Self::Vec3(v) => *v,
            Self::Vec4(v) => [v[0], v[1], v[2]],
            Self::Vec2(v) => [v[0], v[1], 0.0],
            Self::F32(s) => [*s, *s, *s],
            _ => [0.0, 0.0, 0.0],
        }
    }

    fn as_vec4(&self) -> [f32; 4] {
        match self {
            Self::Vec4(v) => *v,
            Self::Vec3(v) => [v[0], v[1], v[2], 0.0],
            Self::Vec2(v) => [v[0], v[1], 0.0, 0.0],
            Self::F32(s) => [*s, *s, *s, *s],
            _ => [0.0, 0.0, 0.0, 0.0],
        }
    }

    fn as_ivec2(&self) -> [i32; 2] {
        match self {
            Self::IVec2(v) => *v,
            Self::Vec2(v) => [v[0] as i32, v[1] as i32],
            _ => [0, 0],
        }
    }

    fn as_ivec3(&self) -> [i32; 3] {
        match self {
            Self::IVec3(v) => *v,
            Self::Vec3(v) => [v[0] as i32, v[1] as i32, v[2] as i32],
            _ => [0, 0, 0],
        }
    }

    fn as_uvec2(&self) -> [u32; 2] {
        match self {
            Self::UVec2(v) => *v,
            Self::Vec2(v) => [v[0] as u32, v[1] as u32],
            _ => [0, 0],
        }
    }

    fn as_entity(&self) -> FfiEntity {
        match self {
            Self::Entity(e) => *e,
            Self::U64(u) => FfiEntity::from_bits(*u),
            Self::I64(i) => FfiEntity::from_bits(*i as u64),
            _ => FfiEntity::NULL,
        }
    }

    fn as_ptr(&self) -> StrataPtr {
        match self {
            Self::Ptr(p) => *p,
            _ => StrataPtr::Null,
        }
    }

    fn as_str(&self) -> String {
        match self {
            Self::Str(s) => s.clone(),
            _ => String::new(),
        }
    }

    fn as_checkpoint(&self) -> usize {
        match self {
            Self::Checkpoint(c) => *c,
            Self::U64(v) => *v as usize,
            Self::U32(v) => *v as usize,
            _ => 0,
        }
    }
}

trait StrataLePack {
    fn strata_pack(&self, out: &mut Vec<u8>);
    fn strata_unpack(&mut self, bytes: &[u8]);
}

impl StrataLePack for u64 {
    fn strata_pack(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.to_le_bytes()); }
    fn strata_unpack(&mut self, bytes: &[u8]) { *self = u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0u8; 8])); }
}
impl StrataLePack for u32 {
    fn strata_pack(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.to_le_bytes()); }
    fn strata_unpack(&mut self, bytes: &[u8]) { *self = u32::from_le_bytes(bytes[..4].try_into().unwrap_or([0u8; 4])); }
}
impl StrataLePack for u16 {
    fn strata_pack(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.to_le_bytes()); }
    fn strata_unpack(&mut self, bytes: &[u8]) { *self = u16::from_le_bytes(bytes[..2].try_into().unwrap_or([0u8; 2])); }
}
impl StrataLePack for u8 {
    fn strata_pack(&self, out: &mut Vec<u8>) { out.push(*self); }
    fn strata_unpack(&mut self, bytes: &[u8]) { *self = bytes[0]; }
}

fn strata_push_le_into<T: StrataLePack>(out: &mut Vec<u8>, v: T) {
    v.strata_pack(out);
}

fn strata_copy_le_slice<T: StrataLePack>(dst: &mut T, bytes: &[u8]) {
    dst.strata_unpack(bytes);
}

fn strata_short_key(name: &str) -> &str {
    name.trim()
}

fn strata_decode_sub_field(bytes: &[u8], off: usize, field: &str) -> StrataVal {
    let rem = bytes.get(off..).unwrap_or(&[]);
    if rem.len() >= 4 {
        let w0 = u32::from_le_bytes(rem[0..4].try_into().unwrap_or([0u8; 4]));
        if field.contains("is_") || field.contains("has_") || field.contains("active") || field.contains("flag") {
            return StrataVal::Bool(rem[0] != 0);
        }
        if rem.len() >= 8 && (field == "xy" || field == "vel" || field == "pos") {
            let f0 = f32::from_bits(w0);
            let f1 = f32::from_le_bytes(rem[4..8].try_into().unwrap_or([0u8; 4]));
            return StrataVal::Vec2([f0, f1]);
        }
        return StrataVal::F32(f32::from_bits(w0));
    } else if !rem.is_empty() {
        return StrataVal::U32(u32::from(rem[0]));
    }
    StrataVal::Unit
}

fn strata_encode_sub_field(bytes: &mut [u8], off: usize, val: &StrataVal) {
    let Some(dst) = bytes.get_mut(off..) else { return; };
    match val {
        StrataVal::Bool(b) => { if !dst.is_empty() { dst[0] = u8::from(*b); } }
        StrataVal::I32(v) => { if dst.len() >= 4 { dst[..4].copy_from_slice(&v.to_le_bytes()); } }
        StrataVal::U32(v) => { if dst.len() >= 4 { dst[..4].copy_from_slice(&v.to_le_bytes()); } }
        StrataVal::I64(v) => { if dst.len() >= 8 { dst[..8].copy_from_slice(&v.to_le_bytes()); } }
        StrataVal::U64(v) => { if dst.len() >= 8 { dst[..8].copy_from_slice(&v.to_le_bytes()); } }
        StrataVal::F32(v) => { if dst.len() >= 4 { dst[..4].copy_from_slice(&v.to_le_bytes()); } }
        StrataVal::F64(v) => { if dst.len() >= 8 { dst[..8].copy_from_slice(&v.to_le_bytes()); } }
        StrataVal::Vec2(v) => {
            if dst.len() >= 8 {
                dst[0..4].copy_from_slice(&v[0].to_le_bytes());
                dst[4..8].copy_from_slice(&v[1].to_le_bytes());
            }
        }
        StrataVal::Vec3(v) => {
            if dst.len() >= 12 {
                dst[0..4].copy_from_slice(&v[0].to_le_bytes());
                dst[4..8].copy_from_slice(&v[1].to_le_bytes());
                dst[8..12].copy_from_slice(&v[2].to_le_bytes());
            }
        }
        StrataVal::Vec4(v) => {
            if dst.len() >= 16 {
                dst[0..4].copy_from_slice(&v[0].to_le_bytes());
                dst[4..8].copy_from_slice(&v[1].to_le_bytes());
                dst[8..12].copy_from_slice(&v[2].to_le_bytes());
                dst[12..16].copy_from_slice(&v[3].to_le_bytes());
            }
        }
        StrataVal::Entity(e) => {
            if dst.len() >= 8 { dst[..8].copy_from_slice(&e.to_bits().to_le_bytes()); }
        }
        StrataVal::Words(w) => {
            for (i, word) in w.iter().enumerate() {
                if i * 4 + 4 <= dst.len() {
                    dst[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
                }
            }
        }
        _ => {}
    }
}

fn strata_bytes_read_f32(b: &[u8], off: usize) -> f32 {
    if off + 4 <= b.len() {
        f32::from_le_bytes(b[off..off + 4].try_into().unwrap_or([0u8; 4]))
    } else {
        0.0
    }
}

fn strata_bytes_write_f32(b: &mut [u8], off: usize, v: f32) {
    if off + 4 <= b.len() {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
}

fn strata_bytes_read_u16(b: &[u8], off: usize) -> u16 {
    if off + 2 <= b.len() {
        u16::from_le_bytes(b[off..off + 2].try_into().unwrap_or([0u8; 2]))
    } else {
        0
    }
}

fn strata_bytes_write_u16(b: &mut [u8], off: usize, v: u16) {
    if off + 2 <= b.len() {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
}

fn strata_bytes_read_u32(b: &[u8], off: usize) -> u32 {
    if off + 4 <= b.len() {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap_or([0u8; 4]))
    } else {
        0
    }
}

fn strata_bytes_write_u32(b: &mut [u8], off: usize, v: u32) {
    if off + 4 <= b.len() {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
}

fn strata_grace_arm_bytes(b: &mut [u8], off: usize, dur: f32) {
    let cur = strata_bytes_read_f32(b, off);
    strata_bytes_write_f32(b, off, if dur > cur { dur } else { cur });
}

fn strata_grace_tick_bytes(b: &mut [u8], off: usize, dt: f32) {
    let cur = strata_bytes_read_f32(b, off);
    let nxt = (cur - dt).max(0.0);
    strata_bytes_write_f32(b, off, nxt);
}

fn strata_grace_active_bytes(b: &[u8], off: usize) -> bool {
    strata_bytes_read_f32(b, off) > 0.0
}

fn strata_grace_clear_bytes(b: &mut [u8], off: usize) {
    strata_bytes_write_f32(b, off, 0.0);
}

fn strata_input_buf_push_bytes(b: &mut [u8], off: usize, cap: u32, action: u16, win_sec: f32) {
    if win_sec <= 0.0 || cap == 0 {
        return;
    }
    let n = cap as usize;
    let mut empty_slot: Option<usize> = None;
    let mut min_slot = 0usize;
    let mut min_rem = f32::MAX;
    for i in 0..n {
        let s = off + i * 8;
        if s + 8 > b.len() {
            break;
        }
        let aid = strata_bytes_read_u16(b, s);
        let rem = strata_bytes_read_f32(b, s + 4);
        if aid == action && rem > 0.0 {
            strata_bytes_write_f32(b, s + 4, win_sec.max(rem));
            return;
        }
        if (aid == u16::MAX || rem <= 0.0) && empty_slot.is_none() {
            empty_slot = Some(i);
        } else if rem < min_rem {
            min_rem = rem;
            min_slot = i;
        }
    }
    let target = empty_slot.unwrap_or(min_slot);
    let s = off + target * 8;
    if s + 8 <= b.len() {
        strata_bytes_write_u16(b, s, action);
        strata_bytes_write_u16(b, s + 2, 0);
        strata_bytes_write_f32(b, s + 4, win_sec);
    }
}

fn strata_input_buf_consume_bytes(b: &mut [u8], off: usize, cap: u32, action: u16) -> bool {
    for i in 0..(cap as usize) {
        let s = off + i * 8;
        if s + 8 > b.len() {
            break;
        }
        let aid = strata_bytes_read_u16(b, s);
        let rem = strata_bytes_read_f32(b, s + 4);
        if aid == action && rem > 0.0 {
            strata_bytes_write_u16(b, s, u16::MAX);
            strata_bytes_write_f32(b, s + 4, 0.0);
            return true;
        }
    }
    false
}

fn strata_input_buf_peek_bytes(b: &[u8], off: usize, cap: u32, action: u16) -> bool {
    for i in 0..(cap as usize) {
        let s = off + i * 8;
        if s + 8 > b.len() {
            break;
        }
        let aid = strata_bytes_read_u16(b, s);
        let rem = strata_bytes_read_f32(b, s + 4);
        if aid == action && rem > 0.0 {
            return true;
        }
    }
    false
}

fn strata_input_buf_tick_bytes(b: &mut [u8], off: usize, cap: u32, dt: f32) {
    for i in 0..(cap as usize) {
        let s = off + i * 8;
        if s + 8 > b.len() {
            break;
        }
        let aid = strata_bytes_read_u16(b, s);
        if aid != u16::MAX {
            let rem = (strata_bytes_read_f32(b, s + 4) - dt).max(0.0);
            strata_bytes_write_f32(b, s + 4, rem);
            if rem <= 0.0 {
                strata_bytes_write_u16(b, s, u16::MAX);
            }
        }
    }
}

fn strata_bitset_set_bytes(b: &mut [u8], off: usize, words: u32, bit: u32) {
    let w = (bit / 32) as usize;
    if w < words as usize {
        let s = off + w * 4;
        let cur = strata_bytes_read_u32(b, s);
        strata_bytes_write_u32(b, s, cur | (1u32 << (bit % 32)));
    }
}

fn strata_bitset_get_bytes(b: &[u8], off: usize, words: u32, bit: u32) -> bool {
    let w = (bit / 32) as usize;
    if w < words as usize {
        let s = off + w * 4;
        (strata_bytes_read_u32(b, s) & (1u32 << (bit % 32))) != 0
    } else {
        false
    }
}

fn strata_bitset_clear_bytes(b: &mut [u8], off: usize, words: u32, bit: u32) {
    let w = (bit / 32) as usize;
    if w < words as usize {
        let s = off + w * 4;
        let cur = strata_bytes_read_u32(b, s);
        strata_bytes_write_u32(b, s, cur & !(1u32 << (bit % 32)));
    }
}

fn strata_timeline_advance_bytes(
    b: &mut [u8],
    off: usize,
    dt_sec: f32,
    rate_hz: u32,
    duration_frames: u32,
    windows: &[(u32, u32, u32)],
) -> u32 {
    if off + 12 > b.len() {
        return 0;
    }
    let mut cur_frame = u32::from(strata_bytes_read_u16(b, off));
    let flags = strata_bytes_read_u16(b, off + 2);
    let mut accum = strata_bytes_read_f32(b, off + 8);
    let hz = rate_hz.max(1) as f32;
    let step = 1.0f32 / hz;
    accum += dt_sec.max(0.0);
    while accum >= step {
        accum -= step;
        if duration_frames > 0 && cur_frame + 1 < duration_frames {
            cur_frame += 1;
        } else if (flags & 1) != 0 && duration_frames > 0 {
            cur_frame = 0;
        }
    }
    let mut mask = 0u32;
    for &(start, end, bit) in windows {
        if cur_frame >= start && cur_frame <= end && bit < 32 {
            mask |= 1u32 << bit;
        }
    }
    strata_bytes_write_u16(b, off, cur_frame as u16);
    strata_bytes_write_u32(b, off + 4, mask);
    strata_bytes_write_f32(b, off + 8, accum);
    mask
}

fn strata_timeline_in_window_bytes(b: &[u8], off: usize, window_bit: u32) -> bool {
    if off + 8 > b.len() || window_bit >= 32 {
        return false;
    }
    (strata_bytes_read_u32(b, off + 4) & (1u32 << window_bit)) != 0
}

fn strata_sample_curve_slice(pts: &[(f64, f64)], x: f64) -> f64 {
    if pts.is_empty() {
        return 0.0;
    }
    if x <= pts[0].0 {
        return pts[0].1;
    }
    let last = pts.len() - 1;
    if x >= pts[last].0 {
        return pts[last].1;
    }
    for w in pts.windows(2) {
        let (x0, y0) = w[0];
        let (x1, y1) = w[1];
        if x <= x1 {
            let span = x1 - x0;
            if span.abs() <= f64::EPSILON {
                return y1;
            }
            let t = (x - x0) / span;
            return y0 + (y1 - y0) * t;
        }
    }
    pts[last].1
}

fn strata_binop(op: &str, lhs: &StrataVal, rhs: &StrataVal, allow_fma: bool) -> StrataVal {
    let _ = allow_fma;
    // Vector binary ops
    match (lhs, rhs) {
        (StrataVal::Vec2(a), StrataVal::Vec2(b)) => {
            return match op {
                "+" => StrataVal::Vec2([a[0] + b[0], a[1] + b[1]]),
                "-" => StrataVal::Vec2([a[0] - b[0], a[1] - b[1]]),
                "*" => StrataVal::Vec2([a[0] * b[0], a[1] * b[1]]),
                "/" => StrataVal::Vec2([a[0] / b[0], a[1] / b[1]]),
                "==" => StrataVal::Bool(a[0] == b[0] && a[1] == b[1]),
                "!=" => StrataVal::Bool(a[0] != b[0] || a[1] != b[1]),
                _ => StrataVal::Vec2(*a),
            };
        }
        (StrataVal::Vec2(a), StrataVal::F32(s)) => {
            return match op {
                "*" => StrataVal::Vec2([a[0] * *s, a[1] * *s]),
                "/" => StrataVal::Vec2([a[0] / *s, a[1] / *s]),
                "+" => StrataVal::Vec2([a[0] + *s, a[1] + *s]),
                "-" => StrataVal::Vec2([a[0] - *s, a[1] - *s]),
                _ => StrataVal::Vec2(*a),
            };
        }
        (StrataVal::F32(s), StrataVal::Vec2(b)) => {
            return match op {
                "*" => StrataVal::Vec2([*s * b[0], *s * b[1]]),
                "+" => StrataVal::Vec2([*s + b[0], *s + b[1]]),
                _ => StrataVal::Vec2(*b),
            };
        }
        (StrataVal::Vec3(a), StrataVal::Vec3(b)) => {
            return match op {
                "+" => StrataVal::Vec3([a[0] + b[0], a[1] + b[1], a[2] + b[2]]),
                "-" => StrataVal::Vec3([a[0] - b[0], a[1] - b[1], a[2] - b[2]]),
                "*" => StrataVal::Vec3([a[0] * b[0], a[1] * b[1], a[2] * b[2]]),
                "/" => StrataVal::Vec3([a[0] / b[0], a[1] / b[1], a[2] / b[2]]),
                "==" => StrataVal::Bool(a == b),
                "!=" => StrataVal::Bool(a != b),
                _ => StrataVal::Vec3(*a),
            };
        }
        (StrataVal::Vec3(a), StrataVal::F32(s)) => {
            return match op {
                "*" => StrataVal::Vec3([a[0] * *s, a[1] * *s, a[2] * *s]),
                "/" => StrataVal::Vec3([a[0] / *s, a[1] / *s, a[2] / *s]),
                "+" => StrataVal::Vec3([a[0] + *s, a[1] + *s, a[2] + *s]),
                "-" => StrataVal::Vec3([a[0] - *s, a[1] - *s, a[2] - *s]),
                _ => StrataVal::Vec3(*a),
            };
        }
        (StrataVal::Vec4(a), StrataVal::Vec4(b)) => {
            return match op {
                "+" => StrataVal::Vec4([a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3]]),
                "-" => StrataVal::Vec4([a[0] - b[0], a[1] - b[1], a[2] - b[2], a[3] - b[3]]),
                "*" => StrataVal::Vec4([a[0] * b[0], a[1] * b[1], a[2] * b[2], a[3] * b[3]]),
                "/" => StrataVal::Vec4([a[0] / b[0], a[1] / b[1], a[2] / b[2], a[3] / b[3]]),
                _ => StrataVal::Vec4(*a),
            };
        }
        (StrataVal::Vec4(a), StrataVal::F32(s)) => {
            return match op {
                "*" => StrataVal::Vec4([a[0] * *s, a[1] * *s, a[2] * *s, a[3] * *s]),
                "/" => StrataVal::Vec4([a[0] / *s, a[1] / *s, a[2] / *s, a[3] / *s]),
                _ => StrataVal::Vec4(*a),
            };
        }
        (StrataVal::Entity(a), StrataVal::Entity(b)) => {
            return match op {
                "==" => StrataVal::Bool(a == b),
                "!=" => StrataVal::Bool(a != b),
                _ => StrataVal::Bool(false),
            };
        }
        (StrataVal::Bool(a), StrataVal::Bool(b)) => {
            return match op {
                "&&" | "&" => StrataVal::Bool(*a && *b),
                "||" | "|" => StrataVal::Bool(*a || *b),
                "==" => StrataVal::Bool(*a == *b),
                "!=" => StrataVal::Bool(*a != *b),
                _ => StrataVal::Bool(*a),
            };
        }
        _ => {}
    }

    if matches!(lhs, StrataVal::F64(_)) || matches!(rhs, StrataVal::F64(_)) {
        let a = lhs.as_f64();
        let b = rhs.as_f64();
        return match op {
            "+" => StrataVal::F64(a + b),
            "-" => StrataVal::F64(a - b),
            "*" => StrataVal::F64(a * b),
            "/" => StrataVal::F64(a / b),
            "%" => StrataVal::F64(a % b),
            "<" => StrataVal::Bool(a < b),
            "<=" => StrataVal::Bool(a <= b),
            ">" => StrataVal::Bool(a > b),
            ">=" => StrataVal::Bool(a >= b),
            "==" => StrataVal::Bool(a == b),
            "!=" => StrataVal::Bool(a != b),
            _ => StrataVal::F64(a),
        };
    }
    if matches!(lhs, StrataVal::F32(_)) || matches!(rhs, StrataVal::F32(_)) {
        let a = lhs.as_f32();
        let b = rhs.as_f32();
        return match op {
            "+" => StrataVal::F32(a + b),
            "-" => StrataVal::F32(a - b),
            "*" => StrataVal::F32(a * b),
            "/" => StrataVal::F32(a / b),
            "%" => StrataVal::F32(a % b),
            "<" => StrataVal::Bool(a < b),
            "<=" => StrataVal::Bool(a <= b),
            ">" => StrataVal::Bool(a > b),
            ">=" => StrataVal::Bool(a >= b),
            "==" => StrataVal::Bool(a == b),
            "!=" => StrataVal::Bool(a != b),
            _ => StrataVal::F32(a),
        };
    }
    if matches!(lhs, StrataVal::U64(_)) || matches!(rhs, StrataVal::U64(_)) {
        let a = lhs.as_u64();
        let b = rhs.as_u64();
        return match op {
            "+" => StrataVal::U64(a.wrapping_add(b)),
            "-" => StrataVal::U64(a.wrapping_sub(b)),
            "*" => StrataVal::U64(a.wrapping_mul(b)),
            "/" => StrataVal::U64(if b != 0 { a / b } else { 0 }),
            "%" => StrataVal::U64(if b != 0 { a % b } else { 0 }),
            "&" => StrataVal::U64(a & b),
            "|" => StrataVal::U64(a | b),
            "^" => StrataVal::U64(a ^ b),
            "<<" => StrataVal::U64(a.wrapping_shl(b as u32)),
            ">>" => StrataVal::U64(a.wrapping_shr(b as u32)),
            "<" => StrataVal::Bool(a < b),
            "<=" => StrataVal::Bool(a <= b),
            ">" => StrataVal::Bool(a > b),
            ">=" => StrataVal::Bool(a >= b),
            "==" => StrataVal::Bool(a == b),
            "!=" => StrataVal::Bool(a != b),
            _ => StrataVal::U64(a),
        };
    }
    if matches!(lhs, StrataVal::I64(_)) || matches!(rhs, StrataVal::I64(_)) {
        let a = lhs.as_i64();
        let b = rhs.as_i64();
        return match op {
            "+" => StrataVal::I64(a.wrapping_add(b)),
            "-" => StrataVal::I64(a.wrapping_sub(b)),
            "*" => StrataVal::I64(a.wrapping_mul(b)),
            "/" => StrataVal::I64(if b != 0 { a / b } else { 0 }),
            "%" => StrataVal::I64(if b != 0 { a % b } else { 0 }),
            "&" => StrataVal::I64(a & b),
            "|" => StrataVal::I64(a | b),
            "^" => StrataVal::I64(a ^ b),
            "<<" => StrataVal::I64(a.wrapping_shl(b as u32)),
            ">>" => StrataVal::I64(a.wrapping_shr(b as u32)),
            "<" => StrataVal::Bool(a < b),
            "<=" => StrataVal::Bool(a <= b),
            ">" => StrataVal::Bool(a > b),
            ">=" => StrataVal::Bool(a >= b),
            "==" => StrataVal::Bool(a == b),
            "!=" => StrataVal::Bool(a != b),
            _ => StrataVal::I64(a),
        };
    }
    if matches!(lhs, StrataVal::U32(_)) && !matches!(rhs, StrataVal::I32(_)) {
        let a = lhs.as_u32();
        let b = rhs.as_u32();
        return match op {
            "+" => StrataVal::U32(a.wrapping_add(b)),
            "-" => StrataVal::U32(a.wrapping_sub(b)),
            "*" => StrataVal::U32(a.wrapping_mul(b)),
            "/" => StrataVal::U32(if b != 0 { a / b } else { 0 }),
            "%" => StrataVal::U32(if b != 0 { a % b } else { 0 }),
            "&" => StrataVal::U32(a & b),
            "|" => StrataVal::U32(a | b),
            "^" => StrataVal::U32(a ^ b),
            "<<" => StrataVal::U32(a.wrapping_shl(b)),
            ">>" => StrataVal::U32(a.wrapping_shr(b)),
            "<" => StrataVal::Bool(a < b),
            "<=" => StrataVal::Bool(a <= b),
            ">" => StrataVal::Bool(a > b),
            ">=" => StrataVal::Bool(a >= b),
            "==" => StrataVal::Bool(a == b),
            "!=" => StrataVal::Bool(a != b),
            _ => StrataVal::U32(a),
        };
    }
    let a = lhs.as_i32();
    let b = rhs.as_i32();
    match op {
        "+" => StrataVal::I32(a.wrapping_add(b)),
        "-" => StrataVal::I32(a.wrapping_sub(b)),
        "*" => StrataVal::I32(a.wrapping_mul(b)),
        "/" => StrataVal::I32(if b != 0 { a / b } else { 0 }),
        "%" => StrataVal::I32(if b != 0 { a % b } else { 0 }),
        "&" => StrataVal::I32(a & b),
        "|" => StrataVal::I32(a | b),
        "^" => StrataVal::I32(a ^ b),
        "<<" => StrataVal::I32(a.wrapping_shl(b as u32)),
        ">>" => StrataVal::I32(a.wrapping_shr(b as u32)),
        "<" => StrataVal::Bool(a < b),
        "<=" => StrataVal::Bool(a <= b),
        ">" => StrataVal::Bool(a > b),
        ">=" => StrataVal::Bool(a >= b),
        "==" => StrataVal::Bool(a == b),
        "!=" => StrataVal::Bool(a != b),
        "&&" => StrataVal::Bool(lhs.as_bool() && rhs.as_bool()),
        "||" => StrataVal::Bool(lhs.as_bool() || rhs.as_bool()),
        _ => StrataVal::I32(a),
    }
}

fn strata_unop(op: &str, v: &StrataVal) -> StrataVal {
    match op {
        "!" => StrataVal::Bool(!v.as_bool()),
        "~" => StrataVal::I32(!v.as_i32()),
        "-" => match v {
            StrataVal::F32(x) => StrataVal::F32(-*x),
            StrataVal::F64(x) => StrataVal::F64(-*x),
            StrataVal::I32(x) => StrataVal::I32(-*x),
            StrataVal::I64(x) => StrataVal::I64(-*x),
            StrataVal::Vec2(a) => StrataVal::Vec2([-a[0], -a[1]]),
            StrataVal::Vec3(a) => StrataVal::Vec3([-a[0], -a[1], -a[2]]),
            StrataVal::Vec4(a) => StrataVal::Vec4([-a[0], -a[1], -a[2], -a[3]]),
            _ => StrataVal::I32(-v.as_i32()),
        },
        _ => v.clone(),
    }
}

fn strata_intrinsic(name: &str, args: &[StrataVal]) -> StrataVal {
    let a0 = args.first().cloned().unwrap_or_default();
    let a1 = args.get(1).cloned().unwrap_or_default();
    let a2 = args.get(2).cloned().unwrap_or_default();
    match name {
        "sqrt" => StrataVal::F32(a0.as_f32().sqrt()),
        "abs" => match &a0 {
            StrataVal::I32(x) => StrataVal::I32(x.abs()),
            StrataVal::I64(x) => StrataVal::I64(x.abs()),
            StrataVal::F64(x) => StrataVal::F64(x.abs()),
            _ => StrataVal::F32(a0.as_f32().abs()),
        },
        "floor" => StrataVal::F32(a0.as_f32().floor()),
        "ceil" => StrataVal::F32(a0.as_f32().ceil()),
        "round" => StrataVal::F32(a0.as_f32().round()),
        "trunc" => StrataVal::F32(a0.as_f32().trunc()),
        "fract" => StrataVal::F32(a0.as_f32().fract()),
        "signum" | "sign" => StrataVal::F32(a0.as_f32().signum()),
        "sin" => StrataVal::F32(a0.as_f32().sin()),
        "cos" => StrataVal::F32(a0.as_f32().cos()),
        "tan" => StrataVal::F32(a0.as_f32().tan()),
        "asin" => StrataVal::F32(a0.as_f32().asin()),
        "acos" => StrataVal::F32(a0.as_f32().acos()),
        "atan" => StrataVal::F32(a0.as_f32().atan()),
        "atan2" => StrataVal::F32(a0.as_f32().atan2(a1.as_f32())),
        "exp" => StrataVal::F32(a0.as_f32().exp()),
        "ln" | "log" => StrataVal::F32(a0.as_f32().ln()),
        "log2" => StrataVal::F32(a0.as_f32().log2()),
        "log10" => StrataVal::F32(a0.as_f32().log10()),
        "pow" | "powf" => StrataVal::F32(a0.as_f32().powf(a1.as_f32())),
        "min" => match (&a0, &a1) {
            (StrataVal::I32(x), StrataVal::I32(y)) => StrataVal::I32((*x).min(*y)),
            (StrataVal::U32(x), StrataVal::U32(y)) => StrataVal::U32((*x).min(*y)),
            (StrataVal::Vec2(x), StrataVal::Vec2(y)) => StrataVal::Vec2([x[0].min(y[0]), x[1].min(y[1])]),
            _ => StrataVal::F32(a0.as_f32().min(a1.as_f32())),
        },
        "max" => match (&a0, &a1) {
            (StrataVal::I32(x), StrataVal::I32(y)) => StrataVal::I32((*x).max(*y)),
            (StrataVal::U32(x), StrataVal::U32(y)) => StrataVal::U32((*x).max(*y)),
            (StrataVal::Vec2(x), StrataVal::Vec2(y)) => StrataVal::Vec2([x[0].max(y[0]), x[1].max(y[1])]),
            _ => StrataVal::F32(a0.as_f32().max(a1.as_f32())),
        },
        "clamp" => match (&a0, &a1, &a2) {
            (StrataVal::I32(x), StrataVal::I32(lo), StrataVal::I32(hi)) => StrataVal::I32((*x).clamp(*lo, *hi)),
            (StrataVal::U32(x), StrataVal::U32(lo), StrataVal::U32(hi)) => StrataVal::U32((*x).clamp(*lo, *hi)),
            _ => {
                let lo = a1.as_f32();
                let hi = a2.as_f32();
                StrataVal::F32(a0.as_f32().clamp(lo, hi.max(lo)))
            }
        },
        "saturate" => StrataVal::F32(a0.as_f32().clamp(0.0, 1.0)),
        "lerp" | "mix" => {
            let t = a2.as_f32();
            match &a0 {
                StrataVal::Vec2(x) => {
                    let y = a1.as_vec2();
                    StrataVal::Vec2([x[0] + (y[0] - x[0]) * t, x[1] + (y[1] - x[1]) * t])
                }
                StrataVal::Vec3(x) => {
                    let y = a1.as_vec3();
                    StrataVal::Vec3([x[0] + (y[0] - x[0]) * t, x[1] + (y[1] - x[1]) * t, x[2] + (y[2] - x[2]) * t])
                }
                _ => {
                    let x = a0.as_f32();
                    let y = a1.as_f32();
                    StrataVal::F32(x + (y - x) * t)
                }
            }
        }
        "mul_add" | "fma" => StrataVal::F32(a0.as_f32().mul_add(a1.as_f32(), a2.as_f32())),
        "vec2" => StrataVal::Vec2([a0.as_f32(), args.get(1).map_or(a0.as_f32(), |v| v.as_f32())]),
        "vec3" => StrataVal::Vec3([a0.as_f32(), a1.as_f32(), a2.as_f32()]),
        "vec4" => StrataVal::Vec4([a0.as_f32(), a1.as_f32(), a2.as_f32(), args.get(3).map_or(0.0, |v| v.as_f32())]),
        "ivec2" => StrataVal::IVec2([a0.as_i32(), a1.as_i32()]),
        "ivec3" => StrataVal::IVec3([a0.as_i32(), a1.as_i32(), a2.as_i32()]),
        "uvec2" => StrataVal::UVec2([a0.as_u32(), a1.as_u32()]),
        "dot" => match &a0 {
            StrataVal::Vec3(x) => {
                let y = a1.as_vec3();
                StrataVal::F32(x[0] * y[0] + x[1] * y[1] + x[2] * y[2])
            }
            StrataVal::Vec4(x) => {
                let y = a1.as_vec4();
                StrataVal::F32(x[0] * y[0] + x[1] * y[1] + x[2] * y[2] + x[3] * y[3])
            }
            _ => {
                let x = a0.as_vec2();
                let y = a1.as_vec2();
                StrataVal::F32(x[0] * y[0] + x[1] * y[1])
            }
        },
        "cross" => {
            let a = a0.as_vec3();
            let b = a1.as_vec3();
            StrataVal::Vec3([
                a[1] * b[2] - a[2] * b[1],
                a[2] * b[0] - a[0] * b[2],
                a[0] * b[1] - a[1] * b[0],
            ])
        }
        "length" | "len" => match &a0 {
            StrataVal::Vec3(x) => StrataVal::F32((x[0] * x[0] + x[1] * x[1] + x[2] * x[2]).sqrt()),
            StrataVal::Vec4(x) => StrataVal::F32((x[0] * x[0] + x[1] * x[1] + x[2] * x[2] + x[3] * x[3]).sqrt()),
            _ => {
                let x = a0.as_vec2();
                StrataVal::F32((x[0] * x[0] + x[1] * x[1]).sqrt())
            }
        },
        "length_sq" | "len_sq" => match &a0 {
            StrataVal::Vec3(x) => StrataVal::F32(x[0] * x[0] + x[1] * x[1] + x[2] * x[2]),
            _ => {
                let x = a0.as_vec2();
                StrataVal::F32(x[0] * x[0] + x[1] * x[1])
            }
        },
        "distance" | "dist" => match &a0 {
            StrataVal::Vec3(x) => {
                let y = a1.as_vec3();
                let dx = x[0] - y[0];
                let dy = x[1] - y[1];
                let dz = x[2] - y[2];
                StrataVal::F32((dx * dx + dy * dy + dz * dz).sqrt())
            }
            _ => {
                let x = a0.as_vec2();
                let y = a1.as_vec2();
                let dx = x[0] - y[0];
                let dy = x[1] - y[1];
                StrataVal::F32((dx * dx + dy * dy).sqrt())
            }
        },
        "normalize" | "norm" => match &a0 {
            StrataVal::Vec3(x) => {
                let l = (x[0] * x[0] + x[1] * x[1] + x[2] * x[2]).sqrt();
                if l > 1e-6 { StrataVal::Vec3([x[0] / l, x[1] / l, x[2] / l]) } else { StrataVal::Vec3([0.0; 3]) }
            }
            _ => {
                let x = a0.as_vec2();
                let l = (x[0] * x[0] + x[1] * x[1]).sqrt();
                if l > 1e-6 { StrataVal::Vec2([x[0] / l, x[1] / l]) } else { StrataVal::Vec2([0.0; 2]) }
            }
        },
        "step" => {
            let edge = a0.as_f32();
            let x = a1.as_f32();
            StrataVal::F32(if x < edge { 0.0 } else { 1.0 })
        }
        "smoothstep" => {
            let e0 = a0.as_f32();
            let e1 = a1.as_f32();
            let x = a2.as_f32();
            let d = (e1 - e0).max(1e-6);
            let t = ((x - e0) / d).clamp(0.0, 1.0);
            StrataVal::F32(t * t * (3.0 - 2.0 * t))
        }
        "raw" | "to_bits" => match &a0 {
            StrataVal::Entity(e) => StrataVal::U64(e.to_bits()),
            StrataVal::Bool(b) => StrataVal::U32(u32::from(*b)),
            other => other.clone(),
        },
        "is_null" => StrataVal::Bool(a0.as_entity().is_null()),
        "is_valid" => StrataVal::Bool(!a0.as_entity().is_null()),
        _ => StrataVal::F32(a0.as_f32()),
    }
}

fn strata_reduce_accum(acc: &StrataVal, op: &str, val: &StrataVal) -> StrataVal {
    match op {
        "min" | "Min" => strata_intrinsic("min", &[acc.clone(), val.clone()]),
        "max" | "Max" => strata_intrinsic("max", &[acc.clone(), val.clone()]),
        "sum" | "Sum" | "+" | "+=" => strata_binop("+", acc, val, false),
        "prod" | "Prod" | "*" | "*=" => strata_binop("*", acc, val, false),
        "any" | "Any" | "||" => StrataVal::Bool(acc.as_bool() || val.as_bool()),
        "all" | "All" | "&&" => StrataVal::Bool(acc.as_bool() && val.as_bool()),
        "count" | "Count" => {
            let add = if val.as_bool() { 1 } else { 0 };
            strata_binop("+", acc, &StrataVal::U32(add), false)
        }
        _ => strata_binop("+", acc, val, false),
    }
}

fn strata_point_seg_dist_sq(p: [f32; 4], a: [f32; 4], b: [f32; 4]) -> f32 {
    let ab = [b[0] - a[0], b[1] - a[1], b[2] - a[2]];
    let ap = [p[0] - a[0], p[1] - a[1], p[2] - a[2]];
    let len_sq = ab[0] * ab[0] + ab[1] * ab[1] + ab[2] * ab[2];
    let t = if len_sq > 1e-8 {
        ((ap[0] * ab[0] + ap[1] * ab[1] + ap[2] * ab[2]) / len_sq).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let dx = a[0] + ab[0] * t - p[0];
    let dy = a[1] + ab[1] * t - p[1];
    let dz = a[2] + ab[2] * t - p[2];
    dx * dx + dy * dy + dz * dz
}

fn strata_query_disc_hits(
    world: &Arc<Mutex<StrataWorldState>>,
    grid_name: &str,
    center: [f32; 4],
    radius: f32,
) -> Vec<(FfiEntity, [f32; 4])> {
    let r2 = radius * radius;
    let Ok(w) = world.lock() else { return Vec::new(); };
    let Some(g) = w.spatial.get(grid_name) else { return Vec::new(); };
    let Some(frame) = g.history.first() else { return Vec::new(); };
    frame
        .iter()
        .copied()
        .filter(|(_, p)| {
            let dx = p[0] - center[0];
            let dy = p[1] - center[1];
            let dz = p[2] - center[2];
            dx * dx + dy * dy + dz * dz <= r2
        })
        .collect()
}

fn strata_query_segment_hits(
    world: &Arc<Mutex<StrataWorldState>>,
    hist_name: &str,
    start: [f32; 4],
    end: [f32; 4],
    radius: f32,
    tick_offset: u32,
) -> Vec<(FfiEntity, [f32; 4])> {
    let r2 = radius * radius;
    let Ok(w) = world.lock() else { return Vec::new(); };
    let Some(g) = w.spatial.get(hist_name) else { return Vec::new(); };
    if g.history.is_empty() {
        return Vec::new();
    }
    let idx = (tick_offset as usize).min(g.history.len() - 1);
    g.history[idx]
        .iter()
        .copied()
        .filter(|(_, p)| strata_point_seg_dist_sq(*p, start, end) <= r2)
        .collect()
}

enum HostBridge<'r, 'c, 'i> {
    System(&'r mut SystemContext<'i>),
    ParChunkReadonly(&'r Chunk<'c, 'i>),
    ParChunkMut(&'r mut Chunk<'c, 'i>),
    Commands(&'r mut GuestCommands<'i>),
    Pure,
}
"#;

// ============================================================================
// Helper Functions (`mir.fns`) & System/Observer/Migration Execution (`mir.functions`)
// ============================================================================

fn emit_helper_functions(out: &mut String, mir: &MirModule, cat: &GuestCatalog) {
    emit_bridge_ptr_helpers(out, cat);
    for (idx, func) in mir.fns.iter().enumerate() {
        let fname = format!("strata_helper_{}_{idx}", sanitize_ident(&func.name));
        let phys_queries = build_physical_queries(func, cat);
        writeln!(
            out,
            "fn {fname}(\n\
             \x20   bridge: &mut HostBridge<'_, '_, '_>,\n\
             \x20   world: &Arc<Mutex<StrataWorldState>>,\n\
             \x20   handles: &StrataHandles,\n\
             \x20   args: &[StrataVal],\n\
             ) -> StrataVal {{"
        )
        .ok();
        writeln!(
            out,
            "    let migrate_src = StrataObj::Empty;\n\
             \x20   let mut migrate_dst = StrataObj::Empty;\n\
             \x20   let trg_payload = StrataObj::Empty;"
        )
        .ok();
        emit_cfg_body(
            out,
            mir,
            cat,
            func,
            &phys_queries,
            &HashMap::new(),
            &HashMap::new(),
            None,
            None,
        );
        writeln!(out, "}}\n").ok();
    }
}

fn emit_system_functions(out: &mut String, mir: &MirModule, cat: &GuestCatalog) {
    for (idx, func) in mir.functions.iter().enumerate() {
        let fname = format!("strata_sys_fn_{idx}_{}", sanitize_ident(&func.name));
        let phys_queries = build_physical_queries(func, cat);
        let stream_decls = collect_func_stream_decls(func);
        let named_fallback_queries = collect_named_fallback_queries(mir, func, &phys_queries, cat);

        if let MirFnKind::Migration { .. } = &func.kind {
            writeln!(
                out,
                "fn {fname}(\n\
                 \x20   world: &Arc<Mutex<StrataWorldState>>,\n\
                 \x20   handles: &StrataHandles,\n\
                 \x20   migrate_src: StrataObj,\n\
                 \x20   mut migrate_dst: StrataObj,\n\
                 ) -> StrataObj {{"
            )
            .ok();
            writeln!(
                out,
                "    let mut pure_bridge = HostBridge::Pure;\n\
                 \x20   let bridge = &mut pure_bridge;\n\
                 \x20   let trg_payload = StrataObj::Empty;\n\
                 \x20   let args: [StrataVal; 0] = [];"
            )
            .ok();
            emit_cfg_body(
                out,
                mir,
                cat,
                func,
                &phys_queries,
                &stream_decls,
                &named_fallback_queries,
                Some(("migrate_src", "migrate_dst")),
                None,
            );
            writeln!(out, "}}\n").ok();
            continue;
        }

        if let MirFnKind::Observer { .. } = &func.kind {
            writeln!(
                out,
                "fn {fname}(\n\
                 \x20   cmds: &mut GuestCommands<'_>,\n\
                 \x20   world: &Arc<Mutex<StrataWorldState>>,\n\
                 \x20   handles: &StrataHandles,\n\
                 \x20   trg_entity: FfiEntity,\n\
                 \x20   trg_payload: StrataObj,\n\
                 ) {{"
            )
            .ok();
            writeln!(
                out,
                "    let mut cmd_bridge = HostBridge::Commands(cmds);\n\
                 \x20   let bridge = &mut cmd_bridge;\n\
                 \x20   let migrate_src = StrataObj::Empty;\n\
                 \x20   let mut migrate_dst = StrataObj::Empty;\n\
                 \x20   let args: [StrataVal; 0] = [];"
            )
            .ok();
            emit_cfg_body(
                out,
                mir,
                cat,
                func,
                &phys_queries,
                &stream_decls,
                &named_fallback_queries,
                None,
                Some(("trg_entity", "trg_payload")),
            );
            writeln!(out, "}}\n").ok();
            continue;
        }

        // Standard / Synthesized ECS System
        writeln!(
            out,
            "fn {fname}(\n\
             \x20   ctx: &mut SystemContext<'_>,\n\
             \x20   world: &Arc<Mutex<StrataWorldState>>,\n\
             \x20   handles: &StrataHandles,\n\
             ) -> FfiResult {{"
        )
        .ok();
        writeln!(
            out,
            "    let mut sys_bridge = HostBridge::System(ctx);\n\
             \x20   let bridge = &mut sys_bridge;\n\
             \x20   let migrate_src = StrataObj::Empty;\n\
             \x20   let mut migrate_dst = StrataObj::Empty;\n\
             \x20   let trg_payload = StrataObj::Empty;\n\
             \x20   let args: [StrataVal; 0] = [];"
        )
        .ok();
        emit_cfg_body(
            out,
            mir,
            cat,
            func,
            &phys_queries,
            &stream_decls,
            &named_fallback_queries,
            None,
            None,
        );
        writeln!(out, "}}\n").ok();
    }
}

fn collect_func_stream_decls(func: &MirFunction) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    let mut next_idx = func.resources.len();
    for bb in &func.blocks {
        for st in &bb.stmts {
            if let Inst::StreamEmit { stream, .. } = &st.inst
                && !map.contains_key(stream)
            {
                map.insert(stream.clone(), next_idx);
                next_idx += 1;
            }
        }
    }
    map
}

fn collect_named_fallback_queries(
    mir: &MirModule,
    func: &MirFunction,
    phys_queries: &[PhysicalQuery],
    cat: &GuestCatalog,
) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    let mut next_qi = phys_queries.len();
    for bb in &func.blocks {
        for st in &bb.stmts {
            if let Inst::ResolveNamedObject { name } = &st.inst
                && !map.contains_key(name)
                && next_qi < bamabi_sys::MAX_QUERIES_PER_SYSTEM
                && let Some(obj) = mir.objects.iter().find(|o| o.name == *name)
            {
                let has_comp = obj
                    .components
                    .iter()
                    .find_map(|c| cat.resolve_comp(c))
                    .or_else(|| {
                        obj.inits.iter().find_map(|ci| {
                            let cname = ci.canonical_component.as_deref().unwrap_or(&ci.component);
                            cat.resolve_comp(cname)
                        })
                    })
                    .is_some();
                if has_comp {
                    map.insert(name.clone(), next_qi);
                    next_qi += 1;
                }
            }
        }
    }
    map
}

#[allow(clippy::too_many_arguments)]
fn emit_cfg_body(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    func: &MirFunction,
    phys_queries: &[PhysicalQuery],
    stream_decls: &HashMap<String, usize>,
    named_fallback_queries: &HashMap<String, usize>,
    migrate_vars: Option<(&str, &str)>,
    observer_vars: Option<(&str, &str)>,
) {
    let local_count = func.locals.len().max(1);
    writeln!(
        out,
        "    let mut locals: Vec<StrataVal> = vec![StrataVal::Unit; {local_count}];"
    )
    .ok();
    for (p_idx, p) in func.params.iter().enumerate() {
        if let Some(lid) = p.local {
            writeln!(
                out,
                "    if let Some(_arg) = args.get({p_idx}) {{ locals[{li}] = _arg.clone(); }}",
                li = lid.0
            )
            .ok();
        }
    }
    writeln!(
        out,
        "    let mut slots: Vec<StrataVal> = vec![StrataVal::Unit; {local_count}];\n\
         \x20   let mut spatial_hits: Vec<Vec<(FfiEntity, [f32; 4])>> = Vec::new();\n\
         \x20   let mut par_consumed: Vec<bool> = vec![false; {nq}];\n\
         \x20   let mut iter_started_once: Vec<bool> = vec![false; {nq}];\n\
         \x20   let mut dirty_runs: HashMap<usize, (u32, u32)> = HashMap::new();",
        nq = phys_queries.len().max(1)
    )
    .ok();

    if func.blocks.is_empty() {
        emit_default_fn_return(out, func, migrate_vars);
        return;
    }

    // Emit local helper methods for field read/write on Ptr inside this function's stack/bridge!
    writeln!(out, "    let mut __bb: u32 = 0;").ok();
    writeln!(out, "    loop {{").ok();
    writeln!(out, "        match __bb {{").ok();
    for (bi, bb) in func.blocks.iter().enumerate() {
        writeln!(out, "            {bi} => {{").ok();
        // Inside `SynthesizedSpatialCsr`, reset Pass 2 query iterator cleanly at prefix-sum block!
        if func.kind == MirFnKind::SynthesizedSpatialCsr && bb.label == "csr_prefix_sum" {
            writeln!(
                out,
                "                if let HostBridge::System(sys_ctx) = bridge {{\n\
                 \x20                   if let Some(it) = sys_ctx.query_mut(0) {{ let _ = it.reset(); }}\n\
                 \x20               }}"
            )
            .ok();
        }
        for stmt in &bb.stmts {
            emit_inst(
                out,
                mir,
                cat,
                func,
                phys_queries,
                stream_decls,
                named_fallback_queries,
                migrate_vars,
                observer_vars,
                stmt,
                bb,
            );
        }
        emit_terminator(out, func, &bb.terminator, migrate_vars);
        writeln!(out, "            }}").ok();
    }
    writeln!(out, "            _ => break,").ok();
    writeln!(out, "        }}").ok();
    writeln!(out, "    }}").ok();
    emit_default_fn_return(out, func, migrate_vars);
}

fn emit_default_fn_return(
    out: &mut String,
    func: &MirFunction,
    migrate_vars: Option<(&str, &str)>,
) {
    if migrate_vars.is_some() {
        writeln!(out, "    migrate_dst").ok();
    } else {
        match func.kind {
            MirFnKind::HelperFn => writeln!(out, "    StrataVal::Unit").ok(),
            MirFnKind::Observer { .. } => writeln!(out).ok(),
            _ => writeln!(out, "    FfiResult::OK").ok(),
        };
    }
}

fn emit_terminator(
    out: &mut String,
    func: &MirFunction,
    term: &Terminator,
    migrate_vars: Option<(&str, &str)>,
) {
    match term {
        Terminator::Return(opt) => {
            if migrate_vars.is_some() {
                writeln!(out, "                return migrate_dst;").ok();
            } else {
                match func.kind {
                    MirFnKind::HelperFn => {
                        if let Some(lid) = opt {
                            writeln!(out, "                return locals[{}].clone();", lid.0).ok();
                        } else {
                            writeln!(out, "                return StrataVal::Unit;").ok();
                        }
                    }
                    MirFnKind::Observer { .. } => {
                        writeln!(out, "                return;").ok();
                    }
                    _ => {
                        writeln!(out, "                return FfiResult::OK;").ok();
                    }
                }
            }
        }
        Terminator::Goto(BlockId(dst)) => {
            writeln!(out, "                __bb = {dst};").ok();
        }
        Terminator::Branch {
            cond,
            then_bb,
            else_bb,
        } => {
            writeln!(
                out,
                "                __bb = if locals[{}].as_bool() {{ {} }} else {{ {} }};",
                cond.0, then_bb.0, else_bb.0
            )
            .ok();
        }
        Terminator::Switch {
            scrutinee,
            cases,
            default_bb,
        } => {
            writeln!(
                out,
                "                __bb = match locals[{}].as_u32() {{",
                scrutinee.0
            )
            .ok();
            for (val, BlockId(dst)) in cases {
                writeln!(out, "                    {val} => {dst},").ok();
            }
            writeln!(out, "                    _ => {},", default_bb.0).ok();
            writeln!(out, "                }};").ok();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_inst(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    func: &MirFunction,
    phys_queries: &[PhysicalQuery],
    stream_decls: &HashMap<String, usize>,
    named_fallback_queries: &HashMap<String, usize>,
    _migrate_vars: Option<(&str, &str)>,
    observer_vars: Option<(&str, &str)>,
    stmt: &strata_mir::MirStmt,
    cur_bb: &BasicBlock,
) {
    let assign_dst = |out: &mut String, expr: &str| {
        if let Some(dst) = stmt.dst {
            writeln!(out, "                locals[{}] = {expr};", dst.0).ok();
        } else {
            writeln!(out, "                let _ = {expr};").ok();
        }
    };

    let dst_ty = stmt
        .dst
        .and_then(|d| func.locals.get(d.0 as usize))
        .map_or(MirType::Unit, |l| l.ty.clone());

    match &stmt.inst {
        Inst::ConstInt { value } => {
            let expr = match dst_ty {
                MirType::U8 | MirType::U16 | MirType::U32 | MirType::Sym => {
                    format!("StrataVal::U32(({value}i64) as u32)")
                }
                MirType::U64 => format!("StrataVal::U64(({value}i64) as u64)"),
                MirType::I64 | MirType::Fix64 => format!("StrataVal::I64({value}i64)"),
                MirType::F32 => format!("StrataVal::F32({}f32)", *value as f32),
                MirType::F64 => format!("StrataVal::F64({}f64)", *value as f64),
                MirType::Bool => format!("StrataVal::Bool({})", *value != 0),
                MirType::Entity => {
                    format!("StrataVal::Entity(FfiEntity::from_bits(({value}i64) as u64))")
                }
                MirType::Unit => "StrataVal::Unit".to_owned(),
                _ => format!("StrataVal::I32(({value}i64) as i32)"),
            };
            assign_dst(out, &expr);
        }
        Inst::ConstFloat { value } => {
            let expr = match dst_ty {
                MirType::F64 => format!("StrataVal::F64({})", fmt_f64(*value)),
                MirType::Fix32 => {
                    format!("StrataVal::I32({}i32)", (*value * 65536.0).round() as i32)
                }
                MirType::Fix64 => {
                    format!(
                        "StrataVal::I64({}i64)",
                        (*value * 4294967296.0).round() as i64
                    )
                }
                _ => format!("StrataVal::F32({})", fmt_f32(*value as f32)),
            };
            assign_dst(out, &expr);
        }
        Inst::ConstBool { value } => {
            if dst_ty == MirType::Unit {
                assign_dst(out, "StrataVal::Unit");
            } else {
                assign_dst(out, &format!("StrataVal::Bool({value})"));
            }
        }
        Inst::ConstVec { dims, values } => {
            let expr = match dims {
                2 => format!(
                    "StrataVal::Vec2([{}, {}])",
                    fmt_f32(values[0] as f32),
                    fmt_f32(values[1] as f32)
                ),
                3 => format!(
                    "StrataVal::Vec3([{}, {}, {}])",
                    fmt_f32(values[0] as f32),
                    fmt_f32(values[1] as f32),
                    fmt_f32(values[2] as f32)
                ),
                _ => format!(
                    "StrataVal::Vec4([{}, {}, {}, {}])",
                    fmt_f32(values[0] as f32),
                    fmt_f32(values[1] as f32),
                    fmt_f32(values[2] as f32),
                    fmt_f32(values[3] as f32)
                ),
            };
            assign_dst(out, &expr);
        }
        Inst::ConstString { value } => {
            let esc = escape_rust_str(value);
            assign_dst(out, &format!("StrataVal::Str(\"{esc}\".to_owned())"));
        }
        Inst::Copy { val } => {
            assign_dst(out, &format!("locals[{}].clone()", val.0));
        }
        Inst::SlotAlloc { ty } => {
            if let Some(dst) = stmt.dst {
                let def = default_strata_val_for_mir_ty(ty);
                writeln!(
                    out,
                    "                slots[{d}] = {def};\n\
                     \x20               locals[{d}] = StrataVal::Ptr(StrataPtr::Slot {{ sid: {d}, off: 0 }});",
                    d = dst.0
                )
                .ok();
            }
        }
        Inst::SlotLoad { slot } => {
            assign_dst(
                out,
                &format!(
                    "match locals[{s}].as_ptr() {{ StrataPtr::Slot {{ sid, .. }} => slots[sid].clone(), _ => locals[{s}].clone() }}",
                    s = slot.0
                ),
            );
        }
        Inst::SlotStore { slot, val } => {
            writeln!(
                out,
                "                if let StrataPtr::Slot {{ sid, .. }} = locals[{s}].as_ptr() {{ slots[sid] = locals[{v}].clone(); }}",
                s = slot.0,
                v = val.0
            )
            .ok();
        }
        Inst::BinOp {
            op,
            lhs,
            rhs,
            allow_fma,
        } => {
            let esc = escape_rust_str(op);
            assign_dst(
                out,
                &format!(
                    "strata_binop(\"{esc}\", &locals[{}], &locals[{}], {allow_fma})",
                    lhs.0, rhs.0
                ),
            );
        }
        Inst::UnOp { op, val } => {
            let esc = escape_rust_str(op);
            assign_dst(out, &format!("strata_unop(\"{esc}\", &locals[{}])", val.0));
        }
        Inst::Cast { val, target_ty } => {
            let expr = match target_ty {
                MirType::Bool => format!("StrataVal::Bool(locals[{}].as_bool())", val.0),
                MirType::I8 | MirType::I16 | MirType::I32 | MirType::Fix32 => {
                    format!("StrataVal::I32(locals[{}].as_i32())", val.0)
                }
                MirType::U8 | MirType::U16 | MirType::U32 | MirType::Sym => {
                    format!("StrataVal::U32(locals[{}].as_u32())", val.0)
                }
                MirType::I64 | MirType::Fix64 => {
                    format!("StrataVal::I64(locals[{}].as_i64())", val.0)
                }
                MirType::U64 => format!("StrataVal::U64(locals[{}].as_u64())", val.0),
                MirType::F32 => format!("StrataVal::F32(locals[{}].as_f32())", val.0),
                MirType::F64 => format!("StrataVal::F64(locals[{}].as_f64())", val.0),
                MirType::Entity => format!("StrataVal::Entity(locals[{}].as_entity())", val.0),
                _ => format!("locals[{}].clone()", val.0),
            };
            assign_dst(out, &expr);
        }
        Inst::VecExtract { vec, lane } => {
            let l = *lane as usize;
            assign_dst(
                out,
                &format!(
                    "match &locals[{}] {{ StrataVal::Vec2(v) => StrataVal::F32(*v.get({l}).unwrap_or(&0.0)), StrataVal::Vec3(v) => StrataVal::F32(*v.get({l}).unwrap_or(&0.0)), StrataVal::Vec4(v) => StrataVal::F32(*v.get({l}).unwrap_or(&0.0)), StrataVal::IVec2(v) => StrataVal::I32(*v.get({l}).unwrap_or(&0)), StrataVal::IVec3(v) => StrataVal::I32(*v.get({l}).unwrap_or(&0)), StrataVal::UVec2(v) => StrataVal::U32(*v.get({l}).unwrap_or(&0)), _ => StrataVal::F32(0.0) }}",
                    vec.0
                ),
            );
        }
        Inst::VecInsert { vec, lane, val } => {
            let l = *lane as usize;
            assign_dst(
                out,
                &format!(
                    "match locals[{}].clone() {{ StrataVal::Vec2(mut v) => {{ if {l} < 2 {{ v[{l}] = locals[{}].as_f32(); }} StrataVal::Vec2(v) }} StrataVal::Vec3(mut v) => {{ if {l} < 3 {{ v[{l}] = locals[{}].as_f32(); }} StrataVal::Vec3(v) }} StrataVal::Vec4(mut v) => {{ if {l} < 4 {{ v[{l}] = locals[{}].as_f32(); }} StrataVal::Vec4(v) }} other => other }}",
                    vec.0, val.0, val.0, val.0
                ),
            );
        }
        Inst::VecSwizzle { vec, lanes } => {
            let expr = match lanes.len() {
                1 => format!(
                    "StrataVal::F32(locals[{}].as_vec4().get({}).copied().unwrap_or(0.0))",
                    vec.0, lanes[0]
                ),
                2 => format!(
                    "{{ let _a = locals[{}].as_vec4(); StrataVal::Vec2([_a.get({}).copied().unwrap_or(0.0), _a.get({}).copied().unwrap_or(0.0)]) }}",
                    vec.0, lanes[0], lanes[1]
                ),
                3 => format!(
                    "{{ let _a = locals[{}].as_vec4(); StrataVal::Vec3([_a.get({}).copied().unwrap_or(0.0), _a.get({}).copied().unwrap_or(0.0), _a.get({}).copied().unwrap_or(0.0)]) }}",
                    vec.0, lanes[0], lanes[1], lanes[2]
                ),
                _ => format!(
                    "{{ let _a = locals[{}].as_vec4(); StrataVal::Vec4([_a.get({}).copied().unwrap_or(0.0), _a.get({}).copied().unwrap_or(0.0), _a.get({}).copied().unwrap_or(0.0), _a.get({}).copied().unwrap_or(0.0)]) }}",
                    vec.0,
                    lanes.first().copied().unwrap_or(0),
                    lanes.get(1).copied().unwrap_or(0),
                    lanes.get(2).copied().unwrap_or(0),
                    lanes.get(3).copied().unwrap_or(0)
                ),
            };
            assign_dst(out, &expr);
        }
        Inst::IntrinsicMath { name, args, .. } => {
            let short = name.rsplit("::").next().unwrap_or(name);
            let esc = escape_rust_str(short);
            let arg_list: Vec<String> = args
                .iter()
                .map(|a| format!("locals[{}].clone()", a.0))
                .collect();
            assign_dst(
                out,
                &format!("strata_intrinsic(\"{esc}\", &[{}])", arg_list.join(", ")),
            );
        }
        Inst::Call { callee, args } => {
            let arg_list: Vec<String> = args
                .iter()
                .map(|a| format!("locals[{}].clone()", a.0))
                .collect();
            let short = callee.rsplit("::").next().unwrap_or(callee);
            if let Some((h_idx, hf)) = mir
                .fns
                .iter()
                .enumerate()
                .find(|(_, f)| f.name == *callee || f.name == short)
            {
                let hname = format!("strata_helper_{}_{h_idx}", sanitize_ident(&hf.name));
                assign_dst(
                    out,
                    &format!(
                        "{hname}(bridge, world, handles, &[{}])",
                        arg_list.join(", ")
                    ),
                );
            } else {
                let esc = escape_rust_str(short);
                assign_dst(
                    out,
                    &format!("strata_intrinsic(\"{esc}\", &[{}])", arg_list.join(", ")),
                );
            }
        }
        Inst::StructInit { type_name, fields } => {
            let esc_ty = escape_rust_str(type_name);
            writeln!(
                out,
                "                let mut _obj = StrataObj::default_for_name(\"{esc_ty}\");"
            )
            .ok();
            for (fname, vid) in fields {
                let esc_f = escape_rust_str(fname);
                writeln!(
                    out,
                    "                _obj.set_field(0, \"{esc_f}\", locals[{}].clone());",
                    vid.0
                )
                .ok();
            }
            assign_dst(out, "StrataVal::Obj(_obj)");
        }
        Inst::ArrayInit { elems } => {
            let parts: Vec<String> = elems
                .iter()
                .map(|e| format!("locals[{}].clone()", e.0))
                .collect();
            assign_dst(out, &format!("StrataVal::Arr(vec![{}])", parts.join(", ")));
        }
        Inst::ArrayIndex { base, index } => {
            assign_dst(
                out,
                &format!(
                    "{{ let _idx = locals[{}].as_u32() as usize; match &locals[{}] {{ StrataVal::Arr(a) => a.get(_idx).cloned().unwrap_or_default(), StrataVal::Words(w) => StrataVal::U32(*w.get(_idx).unwrap_or(&0)), StrataVal::Vec2(v) => StrataVal::F32(*v.get(_idx).unwrap_or(&0.0)), StrataVal::Vec3(v) => StrataVal::F32(*v.get(_idx).unwrap_or(&0.0)), StrataVal::Vec4(v) => StrataVal::F32(*v.get(_idx).unwrap_or(&0.0)), _ => StrataVal::Unit }} }}",
                    index.0, base.0
                ),
            );
        }
        Inst::FieldPtr {
            base_ptr,
            offset_bytes,
            ..
        } => {
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(locals[{}].as_ptr().set_exact_offset({offset_bytes}))",
                    base_ptr.0
                ),
            );
        }
        Inst::RowPtr {
            col_ptr,
            row_idx,
            is_sparse,
            ..
        } => {
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(match locals[{}].as_ptr() {{ StrataPtr::ChunkCol {{ qi, phys_col, comp_id, is_mut, is_untracked, is_sparse: cs }} => StrataPtr::ChunkRow {{ qi, phys_col, comp_id, row: locals[{}].as_u32() as usize, off: 0, is_mut, is_untracked, is_sparse: cs || {is_sparse} }}, other => other }})",
                    col_ptr.0, row_idx.0
                ),
            );
        }
        Inst::FieldLoad {
            base_ptr,
            field,
            offset_bytes,
            ..
        } => {
            let esc_f = escape_rust_str(field);
            assign_dst(
                out,
                &format!(
                    "strata_val_or_ptr_read(bridge, &locals[{}], {offset_bytes}, \"{esc_f}\", &slots, &migrate_src, &migrate_dst, &trg_payload)",
                    base_ptr.0
                ),
            );
        }
        Inst::FieldStore {
            base_ptr,
            field,
            offset_bytes,
            val,
            ..
        } => {
            let esc_f = escape_rust_str(field);
            writeln!(
                out,
                "                strata_ptr_write(bridge, locals[{}].as_ptr(), {offset_bytes}, \"{esc_f}\", locals[{}].clone(), &mut slots, &mut migrate_dst);",
                base_ptr.0, val.0
            )
            .ok();
        }
        Inst::ParForEachChunk { query_idx, .. } => {
            emit_par_chunks_dispatch(
                out,
                mir,
                cat,
                func,
                phys_queries,
                stream_decls,
                named_fallback_queries,
                cur_bb,
                *query_idx as usize,
                false,
            );
        }
        Inst::ParForEachChunkReadonly { query_idx, .. } => {
            emit_par_chunks_dispatch(
                out,
                mir,
                cat,
                func,
                phys_queries,
                stream_decls,
                named_fallback_queries,
                cur_bb,
                *query_idx as usize,
                true,
            );
        }
        Inst::ReduceInit { op, identity } => {
            let _ = op;
            assign_dst(out, &format!("locals[{}].clone()", identity.0));
        }
        Inst::ReduceAccum { acc, op, val } => {
            let esc = escape_rust_str(op);
            assign_dst(
                out,
                &format!(
                    "strata_reduce_accum(&locals[{}], \"{esc}\", &locals[{}])",
                    acc.0, val.0
                ),
            );
        }
        Inst::IterNextChunk { query_idx } => {
            let qi = *query_idx as usize;
            assign_dst(
                out,
                &format!(
                    "match bridge {{\n\
                     \x20   HostBridge::System(sys_ctx) => {{\n\
                     \x20       if par_consumed[{qi}] {{ StrataVal::U32(0) }}\n\
                     \x20       else if let Some(it) = sys_ctx.query_mut({qi}) {{\n\
                     \x20           StrataVal::U32(it.next_chunk().unwrap_or(0) as u32)\n\
                     \x20       }} else {{ StrataVal::U32(0) }}\n\
                     \x20   }}\n\
                     \x20   HostBridge::ParChunkReadonly(ch) => {{\n\
                     \x20       if !iter_started_once[{qi}] {{ iter_started_once[{qi}] = true; StrataVal::U32(ch.entities().len() as u32) }} else {{ StrataVal::U32(0) }}\n\
                     \x20   }}\n\
                     \x20   HostBridge::ParChunkMut(ch) => {{\n\
                     \x20       if !iter_started_once[{qi}] {{ iter_started_once[{qi}] = true; StrataVal::U32(ch.entities().len() as u32) }} else {{ StrataVal::U32(0) }}\n\
                     \x20   }}\n\
                     \x20   _ => StrataVal::U32(0),\n\
                     }}"
                ),
            );
        }
        Inst::IterChunkLen { query_idx } => {
            let qi = *query_idx as usize;
            assign_dst(
                out,
                &format!(
                    "match bridge {{\n\
                     \x20   HostBridge::System(sys_ctx) => StrataVal::U32(sys_ctx.query_mut({qi}).map_or(0, |it| it.current_len() as u32)),\n\
                     \x20   HostBridge::ParChunkReadonly(ch) => StrataVal::U32(ch.entities().len() as u32),\n\
                     \x20   HostBridge::ParChunkMut(ch) => StrataVal::U32(ch.entities().len() as u32),\n\
                     \x20   _ => StrataVal::U32(0),\n\
                     }}"
                ),
            );
        }
        Inst::IterEntities { query_idx } => {
            let qi = *query_idx as usize;
            assign_dst(
                out,
                &format!("StrataVal::Ptr(StrataPtr::ChunkEntities {{ qi: {qi} }})"),
            );
        }
        Inst::EntityAtRow {
            entities_ptr,
            row_idx,
        } => {
            assign_dst(
                out,
                &format!(
                    "{{ let _row = locals[{}].as_u32() as usize; match locals[{}].as_ptr() {{\n\
                     \x20   StrataPtr::ChunkEntities {{ qi }} => match bridge {{\n\
                     \x20       HostBridge::System(sys_ctx) => StrataVal::Entity(sys_ctx.query_mut(qi).and_then(|it| it.entities().get(_row).copied()).unwrap_or(FfiEntity::NULL)),\n\
                     \x20       HostBridge::ParChunkReadonly(ch) => StrataVal::Entity(ch.entities().get(_row).copied().unwrap_or(FfiEntity::NULL)),\n\
                     \x20       HostBridge::ParChunkMut(ch) => StrataVal::Entity(ch.entities().get(_row).copied().unwrap_or(FfiEntity::NULL)),\n\
                     \x20       _ => StrataVal::Entity(FfiEntity::NULL),\n\
                     \x20   }},\n\
                     \x20   StrataPtr::SpatialHits {{ idx }} => StrataVal::Entity(spatial_hits.get(idx).and_then(|h| h.get(_row)).map_or(FfiEntity::NULL, |e| e.0)),\n\
                     \x20   _ => StrataVal::Entity(FfiEntity::NULL),\n\
                     }} }}",
                    row_idx.0, entities_ptr.0
                ),
            );
        }
        Inst::IterColRead {
            query_idx,
            term_idx,
            storage_key,
        }
        | Inst::IterColRowsRead {
            query_idx,
            term_idx,
            storage_key,
        } => {
            let qi = *query_idx as usize;
            let pq = phys_queries.get(qi);
            let phys_col = pq
                .and_then(|q| q.term_to_phys.get(term_idx).copied())
                .unwrap_or(*term_idx as usize);
            let comp_id = pq
                .and_then(|q| q.terms.get(phys_col))
                .map(|t| t.comp_id)
                .or_else(|| cat.resolve_comp(storage_key).map(|c| c.id))
                .unwrap_or(0);
            let is_sparse = matches!(stmt.inst, Inst::IterColRowsRead { .. })
                || pq
                    .and_then(|q| q.terms.get(phys_col))
                    .is_some_and(|t| t.is_sparse);
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(StrataPtr::ChunkCol {{ qi: {qi}, phys_col: {phys_col}, comp_id: {comp_id}, is_mut: false, is_untracked: false, is_sparse: {is_sparse} }})"
                ),
            );
        }
        Inst::IterColWrite {
            query_idx,
            term_idx,
            storage_key,
        } => {
            let qi = *query_idx as usize;
            let pq = phys_queries.get(qi);
            let phys_col = pq
                .and_then(|q| q.term_to_phys.get(term_idx).copied())
                .unwrap_or(*term_idx as usize);
            let comp_id = pq
                .and_then(|q| q.terms.get(phys_col))
                .map(|t| t.comp_id)
                .or_else(|| cat.resolve_comp(storage_key).map(|c| c.id))
                .unwrap_or(0);
            let is_sparse = pq
                .and_then(|q| q.terms.get(phys_col))
                .is_some_and(|t| t.is_sparse);
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(StrataPtr::ChunkCol {{ qi: {qi}, phys_col: {phys_col}, comp_id: {comp_id}, is_mut: true, is_untracked: false, is_sparse: {is_sparse} }})"
                ),
            );
        }
        Inst::IterColWriteUntracked {
            query_idx,
            term_idx,
            storage_key,
        } => {
            let qi = *query_idx as usize;
            let pq = phys_queries.get(qi);
            let phys_col = pq
                .and_then(|q| q.term_to_phys.get(term_idx).copied())
                .unwrap_or(*term_idx as usize);
            let comp_id = pq
                .and_then(|q| q.terms.get(phys_col))
                .map(|t| t.comp_id)
                .or_else(|| cat.resolve_comp(storage_key).map(|c| c.id))
                .unwrap_or(0);
            let is_sparse = pq
                .and_then(|q| q.terms.get(phys_col))
                .is_some_and(|t| t.is_sparse);
            // Borrow untracked mutable slice once up front to validate column mode cleanly.
            if !is_sparse && let Some(comp) = cat.components.get(comp_id) {
                let sname = &comp.struct_name;
                writeln!(
                    out,
                    "                match bridge {{\n\
                     \x20                   HostBridge::System(sys_ctx) => {{ if let Some(it) = sys_ctx.query_mut({qi}) {{ let _ = it.mutable_slice_untracked({phys_col}).as_component_slice_mut::<{sname}>(); }} }}\n\
                     \x20                   HostBridge::ParChunkMut(ch) => {{ let _ = ch.component_mut_untracked::<{sname}>({phys_col}); }}\n\
                     \x20                   _ => {{}}\n\
                     \x20               }}"
                )
                .ok();
            }
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(StrataPtr::ChunkCol {{ qi: {qi}, phys_col: {phys_col}, comp_id: {comp_id}, is_mut: true, is_untracked: true, is_sparse: {is_sparse} }})"
                ),
            );
        }
        Inst::IterColRowsWrite {
            query_idx,
            term_idx,
            storage_key,
        } => {
            let qi = *query_idx as usize;
            let pq = phys_queries.get(qi);
            let phys_col = pq
                .and_then(|q| q.term_to_phys.get(term_idx).copied())
                .unwrap_or(*term_idx as usize);
            let comp_id = pq
                .and_then(|q| q.terms.get(phys_col))
                .map(|t| t.comp_id)
                .or_else(|| cat.resolve_comp(storage_key).map(|c| c.id))
                .unwrap_or(0);
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(StrataPtr::ChunkCol {{ qi: {qi}, phys_col: {phys_col}, comp_id: {comp_id}, is_mut: true, is_untracked: false, is_sparse: true }})"
                ),
            );
        }
        Inst::IterMarkChangedRange {
            query_idx,
            term_idx,
            run_start,
            run_len,
        } => {
            let qi = *query_idx as usize;
            let pq = phys_queries.get(qi);
            let phys_col = pq
                .and_then(|q| q.term_to_phys.get(term_idx).copied())
                .unwrap_or(*term_idx as usize);
            writeln!(
                out,
                "                {{\n\
                 \x20                   let _rs = locals[{}].as_u32() as usize;\n\
                 \x20                   let _rl = locals[{}].as_u32() as usize;\n\
                 \x20                   if _rl > 0 {{\n\
                 \x20                       match bridge {{\n\
                 \x20                           HostBridge::System(sys_ctx) => {{ if let Some(it) = sys_ctx.query_mut({qi}) {{ let _ = it.mark_changed_range({phys_col}, _rs, _rl); }} }}\n\
                 \x20                           HostBridge::ParChunkMut(ch) => {{ let _ = ch.mark_changed_range({phys_col}, _rs, _rl); }}\n\
                 \x20                           _ => {{}}\n\
                 \x20                       }}\n\
                 \x20                   }}\n\
                 \x20               }}",
                run_start.0, run_len.0
            )
            .ok();
        }
        Inst::DirtyRunInit { run_start, run_len } => {
            writeln!(
                out,
                "                if let StrataPtr::Slot {{ sid, .. }} = locals[{}].as_ptr() {{ slots[sid] = StrataVal::U32(0); }}\n\
                 \x20               if let StrataPtr::Slot {{ sid, .. }} = locals[{}].as_ptr() {{ slots[sid] = StrataVal::U32(0); }}\n\
                 \x20               dirty_runs.insert({}, (0, 0));",
                run_start.0, run_len.0, run_start.0
            )
            .ok();
        }
        Inst::DirtyRunRecordRow {
            run_start,
            run_len,
            row_idx,
        } => {
            writeln!(
                out,
                "                {{\n\
                 \x20                   let _row = locals[{}].as_u32();\n\
                 \x20                   let _cur_s = match locals[{}].as_ptr() {{ StrataPtr::Slot {{ sid, .. }} => slots[sid].as_u32(), _ => 0 }};\n\
                 \x20                   let _cur_l = match locals[{}].as_ptr() {{ StrataPtr::Slot {{ sid, .. }} => slots[sid].as_u32(), _ => 0 }};\n\
                 \x20                   let (_ns, _nl) = if _cur_l == 0 {{\n\
                 \x20                       (_row, 1)\n\
                 \x20                   }} else if _row == _cur_s + _cur_l {{\n\
                 \x20                       (_cur_s, _cur_l + 1)\n\
                 \x20                   }} else {{\n\
                 \x20                       (_cur_s, (_row + 1).saturating_sub(_cur_s).max(_cur_l))\n\
                 \x20                   }};\n\
                 \x20                   if let StrataPtr::Slot {{ sid, .. }} = locals[{}].as_ptr() {{ slots[sid] = StrataVal::U32(_ns); }}\n\
                 \x20                   if let StrataPtr::Slot {{ sid, .. }} = locals[{}].as_ptr() {{ slots[sid] = StrataVal::U32(_nl); }}\n\
                 \x20               }}",
                row_idx.0, run_start.0, run_len.0, run_start.0, run_len.0
            )
            .ok();
        }
        Inst::OptionalChunkIsPresent { slice_ptr, .. } => {
            assign_dst(
                out,
                &format!(
                    "StrataVal::Bool(strata_opt_present(bridge, locals[{}].as_ptr()))",
                    slice_ptr.0
                ),
            );
        }
        Inst::IterCount { query_idx } => {
            let qi = *query_idx as usize;
            assign_dst(
                out,
                &format!(
                    "match bridge {{ HostBridge::System(sys_ctx) => StrataVal::U32(sys_ctx.query_mut({qi}).and_then(|it| it.count().ok()).unwrap_or(0) as u32), _ => StrataVal::U32(0) }}"
                ),
            );
        }
        Inst::IterUpCascade {
            query_idx,
            relation,
        } => {
            let qi = *query_idx as usize;
            let rel_expr = if let Some(rel) = cat.resolve_rel(relation) {
                format!("handles.{}", rel.handle_field)
            } else {
                "BamComponent::INVALID".to_owned()
            };
            let first_comp = phys_queries
                .get(qi)
                .and_then(|q| q.terms.first())
                .and_then(|t| cat.components.get(t.comp_id));
            if let Some(comp) = first_comp {
                let sname = &comp.struct_name;
                let vname = &comp.variant_name;
                assign_dst(
                    out,
                    &format!(
                        "match bridge {{ HostBridge::System(sys_ctx) => {{ let _rel = {rel_expr}; let _e = FfiEntity::NULL; if let Some(it) = sys_ctx.query_mut({qi}) {{ if let Ok(Some((_anc, _val))) = it.up_cascade::<{sname}>(_rel, _e, 0) {{ StrataVal::Obj(StrataObj::{vname}(*_val)) }} else {{ StrataVal::Unit }} }} else {{ StrataVal::Unit }} }}, _ => StrataVal::Unit }}"
                    ),
                );
            } else {
                assign_dst(out, "StrataVal::Unit");
            }
        }
        Inst::ResRead { resource } | Inst::ResWrite { resource } => {
            let is_mut = matches!(stmt.inst, Inst::ResWrite { .. });
            let decl_idx = func
                .resources
                .iter()
                .position(|r| r.resource_name == *resource || r.canonical_name == *resource)
                .unwrap_or(0);
            let comp_id = func
                .resources
                .get(decl_idx)
                .and_then(|r| {
                    cat.resolve_comp(&r.canonical_name)
                        .or_else(|| cat.resolve_comp(&r.resource_name))
                })
                .or_else(|| cat.resolve_comp(resource))
                .map_or(0, |c| c.id);
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(StrataPtr::Res {{ decl_idx: {decl_idx}, comp_id: {comp_id}, off: 0, is_mut: {is_mut} }})"
                ),
            );
        }
        Inst::EntityGet {
            query_idx,
            term_idx,
            entity,
            storage_key,
        }
        | Inst::EntityGetMut {
            query_idx,
            term_idx,
            entity,
            storage_key,
        } => {
            let is_mut = matches!(stmt.inst, Inst::EntityGetMut { .. });
            let qi = *query_idx as usize;
            let pq = phys_queries.get(qi);
            let phys_col = pq
                .and_then(|q| q.term_to_phys.get(term_idx).copied())
                .unwrap_or(*term_idx as usize);
            let comp_id = pq
                .and_then(|q| q.terms.get(phys_col))
                .map(|t| t.comp_id)
                .or_else(|| cat.resolve_comp(storage_key).map(|c| c.id))
                .unwrap_or(0);
            assign_dst(
                out,
                &format!(
                    "StrataVal::Ptr(StrataPtr::EntityPoint {{ qi: {qi}, phys_col: {phys_col}, comp_id: {comp_id}, entity: locals[{}].as_entity(), off: 0, is_mut: {is_mut} }})",
                    entity.0
                ),
            );
        }
        Inst::BindNamedObject { name } => {
            let esc = escape_rust_str(name);
            writeln!(
                out,
                "                if let Ok(_w) = world.lock() {{\n\
                 \x20                   if let Some(&_ent) = _w.named_objects.get(\"{esc}\") {{\n\
                 \x20                       if let HostBridge::System(sys_ctx) = bridge {{ let _ = sys_ctx.bind_named_object(\"{esc}\", _ent); }}\n\
                 \x20                   }}\n\
                 \x20               }}"
            )
            .ok();
            assign_dst(out, "StrataVal::Unit");
        }
        Inst::ResolveNamedObject { name } => {
            let esc = escape_rust_str(name);
            let fb_block = if let Some(&fb_qi) = named_fallback_queries.get(name) {
                format!(
                    "if _resolved.is_null() {{\n\
                     \x20   if let HostBridge::System(sys_ctx) = bridge {{\n\
                     \x20       if let Some(it) = sys_ctx.query_mut({fb_qi}) {{\n\
                     \x20           if let Some(_len) = it.next_chunk() {{\n\
                     \x20               if _len > 0 {{\n\
                     \x20                   let _cand = it.entities()[0];\n\
                     \x20                   if !_cand.is_null() {{\n\
                     \x20                       _resolved = _cand;\n\
                     \x20                       if let Ok(mut _w) = world.lock() {{ _w.named_objects.insert(\"{esc}\".to_owned(), _cand); }}\n\
                     \x20                   }}\n\
                     \x20               }}\n\
                     \x20           }}\n\
                     \x20           let _ = it.reset();\n\
                     \x20       }}\n\
                     \x20       if !_resolved.is_null() {{\n\
                     \x20           let _ = sys_ctx.bind_named_object(\"{esc}\", _resolved);\n\
                     \x20       }}\n\
                     \x20   }}\n\
                     }}"
                )
            } else {
                String::new()
            };
            assign_dst(
                out,
                &format!(
                    "{{\n\
                     \x20   let mut _resolved = world.lock().ok().and_then(|_w| _w.named_objects.get(\"{esc}\").copied()).unwrap_or(FfiEntity::NULL);\n\
                     \x20   {fb_block}\n\
                     \x20   StrataVal::Entity(_resolved)\n\
                     }}"
                ),
            );
        }
        Inst::InternSymbol { symbol } => {
            let esc = escape_rust_str(symbol);
            assign_dst(
                out,
                &format!(
                    "match bridge {{\n\
                     \x20   HostBridge::System(sys_ctx) => StrataVal::U32(sys_ctx.intern_symbol(\"{esc}\").map_or(0, |s| s.to_raw())),\n\
                     \x20   _ => StrataVal::U32(0),\n\
                     }}"
                ),
            );
        }
        Inst::TriggerPayload { .. } => {
            assign_dst(out, "StrataVal::Ptr(StrataPtr::EventPayload { off: 0 })");
        }
        Inst::TriggerTarget => {
            if let Some((trg_ent_var, _)) = observer_vars {
                assign_dst(out, &format!("StrataVal::Entity({trg_ent_var})"));
            } else {
                assign_dst(out, "StrataVal::Entity(FfiEntity::NULL)");
            }
        }
        Inst::GraceArm { ptr, duration_sec } => {
            writeln!(
                out,
                "                {{ let _dur = locals[{}].as_f32(); strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, |_b, _off| strata_grace_arm_bytes(_b, _off, _dur)); }}",
                duration_sec.0, ptr.0
            )
            .ok();
        }
        Inst::GraceTick { ptr, dt_sec } => {
            writeln!(
                out,
                "                {{ let _dt = locals[{}].as_f32(); strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, |_b, _off| strata_grace_tick_bytes(_b, _off, _dt)); }}",
                dt_sec.0, ptr.0
            )
            .ok();
        }
        Inst::GraceIsActive { ptr } => {
            assign_dst(
                out,
                &format!(
                    "{{ let mut _res_b = false; strata_ptr_bytes_read(bridge, &locals[{}], &slots, &migrate_src, &migrate_dst, &trg_payload, |_b, _off| {{ _res_b = strata_grace_active_bytes(_b, _off); }}); StrataVal::Bool(_res_b) }}",
                    ptr.0
                ),
            );
        }
        Inst::GraceClear { ptr } => {
            writeln!(
                out,
                "                strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, |_b, _off| strata_grace_clear_bytes(_b, _off));",
                ptr.0
            )
            .ok();
        }
        Inst::InputBufPush {
            ptr,
            capacity,
            action_id,
            window_sec,
        } => {
            writeln!(
                out,
                "                {{ let _aid = locals[{}].as_u32() as u16; let _win = locals[{}].as_f32(); strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, |_b, _off| strata_input_buf_push_bytes(_b, _off, {capacity}, _aid, _win)); }}",
                action_id.0, window_sec.0, ptr.0
            )
            .ok();
        }
        Inst::InputBufConsume {
            ptr,
            capacity,
            action_id,
        } => {
            assign_dst(
                out,
                &format!(
                    "{{ let _aid = locals[{}].as_u32() as u16; let mut _res_b = false; strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, |_b, _off| {{ _res_b = strata_input_buf_consume_bytes(_b, _off, {capacity}, _aid); }}); StrataVal::Bool(_res_b) }}",
                    action_id.0, ptr.0
                ),
            );
        }
        Inst::InputBufPeek {
            ptr,
            capacity,
            action_id,
        } => {
            assign_dst(
                out,
                &format!(
                    "{{ let _aid = locals[{}].as_u32() as u16; let mut _res_b = false; strata_ptr_bytes_read(bridge, &locals[{}], &slots, &migrate_src, &migrate_dst, &trg_payload, |_b, _off| {{ _res_b = strata_input_buf_peek_bytes(_b, _off, {capacity}, _aid); }}); StrataVal::Bool(_res_b) }}",
                    action_id.0, ptr.0
                ),
            );
        }
        Inst::InputBufTick {
            ptr,
            capacity,
            dt_sec,
        } => {
            writeln!(
                out,
                "                {{ let _dt = locals[{}].as_f32(); strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, |_b, _off| strata_input_buf_tick_bytes(_b, _off, {capacity}, _dt)); }}",
                dt_sec.0, ptr.0
            )
            .ok();
        }
        Inst::BitSetSet { ptr, words, bit } => {
            writeln!(
                out,
                "                {{ let _bit = locals[{}].as_u32(); strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, |_b, _off| strata_bitset_set_bytes(_b, _off, {words}, _bit)); }}",
                bit.0, ptr.0
            )
            .ok();
        }
        Inst::BitSetGet { ptr, words, bit } => {
            assign_dst(
                out,
                &format!(
                    "{{ let _bidx = locals[{}].as_u32(); if let StrataVal::Words(ref _ws) = locals[{}] {{ StrataVal::Bool(_ws.get((_bidx / 32) as usize).is_some_and(|w| (*w & (1u32 << (_bidx % 32))) != 0)) }} else {{ let mut _res_b = false; strata_ptr_bytes_read(bridge, &locals[{}], &slots, &migrate_src, &migrate_dst, &trg_payload, |_b, _off| {{ _res_b = strata_bitset_get_bytes(_b, _off, {words}, _bidx); }}); StrataVal::Bool(_res_b) }} }}",
                    bit.0, ptr.0, ptr.0
                ),
            );
        }
        Inst::BitSetClear { ptr, words, bit } => {
            writeln!(
                out,
                "                {{ let _bit = locals[{}].as_u32(); strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, |_b, _off| strata_bitset_clear_bytes(_b, _off, {words}, _bit)); }}",
                bit.0, ptr.0
            )
            .ok();
        }
        Inst::TimelineAdvance {
            cursor_ptr,
            dt_sec,
            rate_hz,
            duration_frames,
            window_masks,
            ..
        } => {
            let win_lit: Vec<String> = window_masks
                .iter()
                .map(|(_, s, e, bit)| format!("({s}u32, {e}u32, {bit}u32)"))
                .collect();
            assign_dst(
                out,
                &format!(
                    "{{ let _dt = locals[{}].as_f32(); let mut _mask = 0u32; strata_ptr_bytes_mut(bridge, locals[{}].as_ptr(), &mut slots, &mut migrate_dst, |_b, _off| {{ _mask = strata_timeline_advance_bytes(_b, _off, _dt, {rate_hz}, {duration_frames}, &[{}]); }}); StrataVal::U32(_mask) }}",
                    dt_sec.0,
                    cursor_ptr.0,
                    win_lit.join(", ")
                ),
            );
        }
        Inst::TimelineInWindow { ptr, window_bit } => {
            assign_dst(
                out,
                &format!(
                    "{{ let mut _res_b = false; strata_ptr_bytes_read(bridge, &locals[{}], &slots, &migrate_src, &migrate_dst, &trg_payload, |_b, _off| {{ _res_b = strata_timeline_in_window_bytes(_b, _off, {window_bit}); }}); StrataVal::Bool(_res_b) }}",
                    ptr.0
                ),
            );
        }
        Inst::CmdSpawn {
            persistent,
            components,
        } => {
            writeln!(out, "                {{").ok();
            let parts: Vec<String> = components
                .iter()
                .map(|(cname, lid)| {
                    if let Some(comp) = cat.resolve_comp(cname)
                        && (comp.layout.size == 0 || comp.layout.fields.is_empty())
                    {
                        format!("Some(SpawnEntry::marker(handles.{}))", comp.handle_field)
                    } else {
                        format!(
                            "match &locals[{}] {{ StrataVal::Obj(o) => o.spawn_entry(handles), _ => None }}",
                            lid.0
                        )
                    }
                })
                .collect();
            writeln!(
                out,
                "                    let mut _entries: Vec<SpawnEntry<'_>> = Vec::new();\n\
                 \x20                   for _me in [{list}] {{ if let Some(_e) = _me {{ _entries.push(_e); }} }}\n\
                 \x20                   let _spawned = match bridge {{\n\
                 \x20                       HostBridge::System(sys_ctx) => {{ let cmds = sys_ctx.commands(); if {persistent} {{ cmds.spawn_persistent(&_entries) }} else {{ cmds.spawn(&_entries) }} }},\n\
                 \x20                       HostBridge::Commands(cmds) => {{ if {persistent} {{ cmds.spawn_persistent(&_entries) }} else {{ cmds.spawn(&_entries) }} }},\n\
                 \x20                       _ => Err(FfiResult::UNSUPPORTED),\n\
                 \x20                   }}.unwrap_or(FfiEntity::NULL);",
                list = parts.join(", ")
            )
            .ok();
            if let Some(dst) = stmt.dst {
                writeln!(
                    out,
                    "                    locals[{}] = StrataVal::Entity(_spawned);",
                    dst.0
                )
                .ok();
            }
            writeln!(out, "                }}").ok();
        }
        Inst::CmdSpawnBatch { count, components } => {
            writeln!(out, "                {{").ok();
            writeln!(
                out,
                "                    let _cnt = locals[{}].as_u32() as usize;",
                count.0
            )
            .ok();
            for (ci, (cname, lid)) in components.iter().enumerate() {
                if let Some(comp) = cat.resolve_comp(cname)
                    && comp.layout.size > 0
                    && !comp.layout.fields.is_empty()
                {
                    let sname = &comp.struct_name;
                    let vname = &comp.variant_name;
                    writeln!(
                        out,
                        "                    let _col_vec_{ci}: Vec<{sname}> = if let StrataVal::Obj(StrataObj::{vname}(_v)) = &locals[{}] {{ vec![*_v; _cnt] }} else {{ vec![{sname}::default(); _cnt] }};",
                        lid.0
                    )
                    .ok();
                }
            }
            writeln!(
                out,
                "                    let mut _cols: Vec<SpawnBatchColumn<'_>> = Vec::new();"
            )
            .ok();
            for (ci, (cname, _)) in components.iter().enumerate() {
                if let Some(comp) = cat.resolve_comp(cname) {
                    if comp.layout.size == 0 || comp.layout.fields.is_empty() {
                        writeln!(
                            out,
                            "                    _cols.push(SpawnBatchColumn::marker(handles.{}, _cnt));",
                            comp.handle_field
                        )
                        .ok();
                    } else {
                        writeln!(
                            out,
                            "                    _cols.push(SpawnBatchColumn::new(handles.{}, &_col_vec_{ci}));",
                            comp.handle_field
                        )
                        .ok();
                    }
                }
            }
            writeln!(
                out,
                "                    match bridge {{\n\
                 \x20                       HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().spawn_batch(&_cols, _cnt); }}\n\
                 \x20                       HostBridge::Commands(cmds) => {{ let _ = cmds.spawn_batch(&_cols, _cnt); }}\n\
                 \x20                       _ => {{}}\n\
                 \x20                   }}"
            )
            .ok();
            writeln!(out, "                }}").ok();
        }
        Inst::CmdDespawn { entity } => {
            writeln!(
                out,
                "                {{\n\
                 \x20                   let _e = locals[{}].as_entity();\n\
                 \x20                   if !_e.is_null() {{\n\
                 \x20                       match bridge {{\n\
                 \x20                           HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().despawn(_e); }}\n\
                 \x20                           HostBridge::Commands(cmds) => {{ let _ = cmds.despawn(_e); }}\n\
                 \x20                           _ => {{}}\n\
                 \x20                       }}\n\
                 \x20                   }}\n\
                 \x20               }}",
                entity.0
            )
            .ok();
        }
        Inst::CmdDespawnAll { filter } => {
            let term_exprs: Vec<String> = parse_despawn_filter_terms(filter)
                .into_iter()
                .filter_map(|(is_without, cname)| {
                    cat.resolve_comp(cname).map(|comp| {
                        let mode = if is_without {
                            "AccessMode::WITHOUT"
                        } else {
                            "AccessMode::FILTER_ONLY"
                        };
                        format!("BamTermDesc::new(handles.{}, {mode})", comp.handle_field)
                    })
                })
                .collect();
            if !term_exprs.is_empty() {
                writeln!(
                    out,
                    "                {{\n\
                     \x20                   let _terms = [{list}];\n\
                     \x20                   match bridge {{\n\
                     \x20                       HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().despawn_all(&_terms); }}\n\
                     \x20                       HostBridge::Commands(cmds) => {{ let _ = cmds.despawn_all(&_terms); }}\n\
                     \x20                       _ => {{}}\n\
                     \x20                   }}\n\
                     \x20               }}",
                    list = term_exprs.join(", ")
                )
                .ok();
            }
        }
        Inst::CmdInsert {
            entity,
            component,
            data,
            if_new,
        } => {
            let e_idx = entity.0;
            if let Some(lid) = data {
                writeln!(
                    out,
                    "                if let StrataVal::Obj(ref _o) = locals[{}] {{\n\
                     \x20                   let _e = locals[{e_idx}].as_entity();\n\
                     \x20                   match bridge {{\n\
                     \x20                       HostBridge::System(sys_ctx) => _o.cmd_insert(sys_ctx.commands(), handles, _e, {if_new}),\n\
                     \x20                       HostBridge::Commands(cmds) => _o.cmd_insert(cmds, handles, _e, {if_new}),\n\
                     \x20                       _ => {{}}\n\
                     \x20                   }}\n\
                     \x20               }}",
                    lid.0
                )
                .ok();
            } else if let Some(comp) = cat.resolve_comp(component) {
                let sname = &comp.struct_name;
                let hf = &comp.handle_field;
                writeln!(
                    out,
                    "                {{\n\
                     \x20                   let _e = locals[{e_idx}].as_entity();\n\
                     \x20                   let _def = {sname}::default();\n\
                     \x20                   match bridge {{\n\
                     \x20                       HostBridge::System(sys_ctx) => {{ let cmds = sys_ctx.commands(); if {if_new} {{ let _ = cmds.insert_if_new(_e, handles.{hf}, &_def); }} else {{ let _ = cmds.insert(_e, handles.{hf}, &_def); }} }}\n\
                     \x20                       HostBridge::Commands(cmds) => {{ if {if_new} {{ let _ = cmds.insert_if_new(_e, handles.{hf}, &_def); }} else {{ let _ = cmds.insert(_e, handles.{hf}, &_def); }} }}\n\
                     \x20                       _ => {{}}\n\
                     \x20                   }}\n\
                     \x20               }}"
                )
                .ok();
            }
        }
        Inst::CmdRemove { entity, component } => {
            if let Some(comp) = cat.resolve_comp(component) {
                writeln!(
                    out,
                    "                {{\n\
                     \x20                   let _e = locals[{}].as_entity();\n\
                     \x20                   match bridge {{\n\
                     \x20                       HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().remove(_e, handles.{}); }}\n\
                     \x20                       HostBridge::Commands(cmds) => {{ let _ = cmds.remove(_e, handles.{}); }}\n\
                     \x20                       _ => {{}}\n\
                     \x20                   }}\n\
                     \x20               }}",
                    entity.0, comp.handle_field, comp.handle_field
                )
                .ok();
            }
        }
        Inst::CmdTrigger {
            event,
            target,
            payload,
            propagate,
        } => {
            let tgt_expr = match target {
                Some(t) => format!("Some(locals[{}].as_entity())", t.0),
                None => "None".to_owned(),
            };
            if let Some(p) = payload {
                writeln!(
                    out,
                    "                if let StrataVal::Obj(ref _o) = locals[{}] {{\n\
                     \x20                   match bridge {{\n\
                     \x20                       HostBridge::System(sys_ctx) => _o.cmd_trigger(sys_ctx.commands(), handles, {tgt_expr}, {propagate}),\n\
                     \x20                       HostBridge::Commands(cmds) => _o.cmd_trigger(cmds, handles, {tgt_expr}, {propagate}),\n\
                     \x20                       _ => {{}}\n\
                     \x20                   }}\n\
                     \x20               }}",
                    p.0
                )
                .ok();
            } else if let Some(comp) = cat.resolve_comp(event) {
                let sname = &comp.struct_name;
                let vname = &comp.variant_name;
                writeln!(
                    out,
                    "                {{\n\
                     \x20                   let _o = StrataObj::{vname}({sname}::default());\n\
                     \x20                   match bridge {{\n\
                     \x20                       HostBridge::System(sys_ctx) => _o.cmd_trigger(sys_ctx.commands(), handles, {tgt_expr}, {propagate}),\n\
                     \x20                       HostBridge::Commands(cmds) => _o.cmd_trigger(cmds, handles, {tgt_expr}, {propagate}),\n\
                     \x20                       _ => {{}}\n\
                     \x20                   }}\n\
                     \x20               }}"
                )
                .ok();
            }
        }
        Inst::StreamEmit { stream, payload } => {
            let decl_idx = stream_decls.get(stream).copied().unwrap_or(0);
            writeln!(
                out,
                "                if let StrataVal::Obj(ref _o) = locals[{}] {{\n\
                 \x20                   if let HostBridge::System(sys_ctx) = bridge {{ _o.send_msg(sys_ctx, {decl_idx}); }}\n\
                 \x20               }}",
                payload.0
            )
            .ok();
        }
        Inst::CmdCheckpoint => {
            assign_dst(
                out,
                "match bridge {\n\
                 \x20   HostBridge::System(sys_ctx) => StrataVal::Checkpoint(sys_ctx.commands().checkpoint().unwrap_or(0)),\n\
                 \x20   HostBridge::Commands(cmds) => StrataVal::Checkpoint(cmds.checkpoint().unwrap_or(0)),\n\
                 \x20   _ => StrataVal::Checkpoint(0),\n\
                 }",
            );
        }
        Inst::CmdRollback { checkpoint } => {
            writeln!(
                out,
                "                {{\n\
                 \x20                   let _ckpt = locals[{}].as_checkpoint();\n\
                 \x20                   match bridge {{\n\
                 \x20                       HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().rollback(_ckpt); }}\n\
                 \x20                       HostBridge::Commands(cmds) => {{ let _ = cmds.rollback(_ckpt); }}\n\
                 \x20                       _ => {{}}\n\
                 \x20                   }}\n\
                 \x20               }}",
                checkpoint.0
            )
            .ok();
        }
        Inst::CmdInsertRelation {
            relation,
            entity,
            target,
            payload,
        } => {
            if let Some(rel) = cat.resolve_rel(relation) {
                let rh = &rel.handle_field;
                if let Some(pl) = payload {
                    writeln!(
                        out,
                        "                if let StrataVal::Obj(ref _o) = locals[{}] {{\n\
                         \x20                   let _e = locals[{}].as_entity();\n\
                         \x20                   let _t = locals[{}].as_entity();\n\
                         \x20                   match bridge {{\n\
                         \x20                       HostBridge::System(sys_ctx) => _o.cmd_insert_rel(sys_ctx.commands(), handles.{rh}, _e, _t),\n\
                         \x20                       HostBridge::Commands(cmds) => _o.cmd_insert_rel(cmds, handles.{rh}, _e, _t),\n\
                         \x20                       _ => {{}}\n\
                         \x20                   }}\n\
                         \x20               }}",
                        pl.0, entity.0, target.0
                    )
                    .ok();
                } else {
                    writeln!(
                        out,
                        "                {{\n\
                         \x20                   let _e = locals[{}].as_entity();\n\
                         \x20                   let _t = locals[{}].as_entity();\n\
                         \x20                   match bridge {{\n\
                         \x20                       HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().insert_relation(_e, handles.{rh}, _t); }}\n\
                         \x20                       HostBridge::Commands(cmds) => {{ let _ = cmds.insert_relation(_e, handles.{rh}, _t); }}\n\
                         \x20                       _ => {{}}\n\
                         \x20                   }}\n\
                         \x20               }}",
                        entity.0, target.0
                    )
                    .ok();
                }
            }
        }
        Inst::CmdRemoveRelation {
            relation,
            entity,
            target,
        } => {
            if let Some(rel) = cat.resolve_rel(relation) {
                writeln!(
                    out,
                    "                {{\n\
                     \x20                   let _e = locals[{}].as_entity();\n\
                     \x20                   let _t = locals[{}].as_entity();\n\
                     \x20                   match bridge {{\n\
                     \x20                       HostBridge::System(sys_ctx) => {{ let _ = sys_ctx.commands().remove_relation(_e, handles.{}, _t); }}\n\
                     \x20                       HostBridge::Commands(cmds) => {{ let _ = cmds.remove_relation(_e, handles.{}, _t); }}\n\
                     \x20                       _ => {{}}\n\
                     \x20                   }}\n\
                     \x20               }}",
                    entity.0, target.0, rel.handle_field, rel.handle_field
                )
                .ok();
            }
        }
        Inst::SpatialRebuildCsr {
            index_name,
            is_history,
            frames,
            by_field_path,
            ..
        } => {
            let esc_idx = escape_rust_str(index_name);
            let pos_field = by_field_path.split('.').nth(1).unwrap_or("xy");
            let esc_pf = escape_rust_str(pos_field);
            let pos_comp_id = phys_queries
                .first()
                .and_then(|q| q.terms.first())
                .map(|t| t.comp_id);
            let is_sparse = phys_queries
                .first()
                .and_then(|q| q.terms.first())
                .is_some_and(|t| t.is_sparse);
            let max_frames = (*frames).max(1) as usize;
            writeln!(out, "                {{").ok();
            writeln!(
                out,
                "                    let mut _pts: Vec<(FfiEntity, [f32; 4])> = Vec::new();"
            )
            .ok();
            if let Some(cid) = pos_comp_id
                && let Some(comp) = cat.components.get(cid)
            {
                let sname = &comp.struct_name;
                writeln!(
                    out,
                    "                    if let HostBridge::System(sys_ctx) = bridge {{\n\
                     \x20                       if let Some(it) = sys_ctx.query_mut(0) {{\n\
                     \x20                           let _ = it.reset();\n\
                     \x20                           while let Some(_len) = it.next_chunk() {{"
                )
                .ok();
                if is_sparse {
                    writeln!(
                        out,
                        "                                let _ents: Vec<FfiEntity> = it.entities().to_vec();\n\
                         \x20                               if let Some(rows) = it.component_rows::<{sname}>(0) {{\n\
                         \x20                                   for (ri, ent) in _ents.iter().copied().enumerate() {{\n\
                         \x20                                       if let Some(pv) = rows.get(ri) {{\n\
                         \x20                                           let _p = pv.strata_get(0, \"{esc_pf}\").as_vec4();\n\
                         \x20                                           _pts.push((ent, _p));\n\
                         \x20                                       }}\n\
                         \x20                                   }}\n\
                         \x20                               }}"
                    )
                    .ok();
                } else {
                    writeln!(
                        out,
                        "                                let _ents: Vec<FfiEntity> = it.entities().to_vec();\n\
                         \x20                               if let Some(slice) = it.readonly_slice(0).as_component_slice::<{sname}>() {{\n\
                         \x20                                   for (ri, ent) in _ents.iter().copied().enumerate() {{\n\
                         \x20                                       if let Some(pv) = slice.get(ri) {{\n\
                         \x20                                           let _p = pv.strata_get(0, \"{esc_pf}\").as_vec4();\n\
                         \x20                                           _pts.push((ent, _p));\n\
                         \x20                                       }}\n\
                         \x20                                   }}\n\
                         \x20                               }}"
                    )
                    .ok();
                }
                writeln!(
                    out,
                    "                           }}\n\
                     \x20                       }}\n\
                     \x20                   }}"
                )
                .ok();
            }
            writeln!(
                out,
                "                    if let Ok(mut _w) = world.lock() {{\n\
                 \x20                       let _entry = _w.spatial.entry(\"{esc_idx}\".to_owned()).or_insert_with(|| StrataSpatialGridState {{\n\
                 \x20                           is_history: {is_history},\n\
                 \x20                           frames_cap: {max_frames},\n\
                 \x20                           history: Vec::new(),\n\
                 \x20                       }});\n\
                 \x20                       if {is_history} {{\n\
                 \x20                           _entry.history.insert(0, _pts);\n\
                 \x20                           _entry.history.truncate({max_frames});\n\
                 \x20                       }} else {{\n\
                 \x20                           _entry.history.clear();\n\
                 \x20                           _entry.history.push(_pts);\n\
                 \x20                       }}\n\
                 \x20                   }}\n\
                 \x20               }}"
            )
            .ok();
        }
        Inst::SpatialQueryDisc {
            grid_name,
            center,
            radius,
        } => {
            let esc = escape_rust_str(grid_name);
            writeln!(
                out,
                "                let _sh_idx = spatial_hits.len();\n\
                 \x20               spatial_hits.push(strata_query_disc_hits(world, \"{esc}\", locals[{}].as_vec4(), locals[{}].as_f32()));",
                center.0, radius.0
            )
            .ok();
            assign_dst(
                out,
                "StrataVal::Ptr(StrataPtr::SpatialHits { idx: _sh_idx })",
            );
        }
        Inst::SpatialQuerySegmentAt {
            history_name,
            start,
            end,
            radius,
            tick_offset,
        } => {
            let esc = escape_rust_str(history_name);
            writeln!(
                out,
                "                let _sh_idx = spatial_hits.len();\n\
                 \x20               spatial_hits.push(strata_query_segment_hits(world, \"{esc}\", locals[{}].as_vec4(), locals[{}].as_vec4(), locals[{}].as_f32(), locals[{}].as_u32()));",
                start.0, end.0, radius.0, tick_offset.0
            )
            .ok();
            assign_dst(
                out,
                "StrataVal::Ptr(StrataPtr::SpatialHits { idx: _sh_idx })",
            );
        }
        Inst::TableLoad {
            table_name,
            key,
            field,
        } => {
            if let Some(te) = cat.resolve_table(table_name) {
                let lfn = &te.lookup_fn;
                let esc_f = escape_rust_str(field);
                if field.is_empty() {
                    assign_dst(
                        out,
                        &format!(
                            "StrataVal::Obj(StrataObj::{}({lfn}(locals[{}].as_i64())))",
                            te.variant_name, key.0
                        ),
                    );
                } else {
                    assign_dst(
                        out,
                        &format!(
                            "{lfn}(locals[{}].as_i64()).strata_get(0, \"{esc_f}\")",
                            key.0
                        ),
                    );
                }
            } else {
                assign_dst(out, "StrataVal::Unit");
            }
        }
        Inst::CurveSample { curve_name, x } => {
            let ident = sanitize_ident(curve_name);
            if mir
                .curves
                .iter()
                .any(|c| c.name == *curve_name || sanitize_ident(&c.name) == ident)
            {
                assign_dst(
                    out,
                    &format!(
                        "StrataVal::F32(strata_curve_sample_{ident}(locals[{}].as_f64()) as f32)",
                        x.0
                    ),
                );
            } else {
                assign_dst(out, "StrataVal::F32(0.0)");
            }
        }
        Inst::ShadowWrite {
            shadow_slot, val, ..
        } => {
            writeln!(
                out,
                "                if let StrataPtr::Slot {{ sid, .. }} = locals[{}].as_ptr() {{ slots[sid] = locals[{}].clone(); }}",
                shadow_slot.0, val.0
            )
            .ok();
        }
        Inst::ShadowCommit { .. } => {}
        Inst::RequireTrue { cond } => {
            writeln!(out, "                let _ = locals[{}].as_bool();", cond.0).ok();
        }
        Inst::FsmDispatch { transitions, .. } => {
            // Evaluate state discriminant if needed; explicit CFG branches drive state hooks
            let _ = transitions;
            assign_dst(out, "StrataVal::U32(0)");
        }
        Inst::TaskStep { pc_local, .. } => {
            assign_dst(
                out,
                &format!("StrataVal::U32(locals[{}].as_u32())", pc_local.0),
            );
        }
        Inst::MigrateSrcPtr { .. } => {
            assign_dst(out, "StrataVal::Ptr(StrataPtr::MigrateSrc { off: 0 })");
        }
        Inst::MigrateDstPtr { .. } => {
            assign_dst(out, "StrataVal::Ptr(StrataPtr::MigrateDst { off: 0 })");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_par_chunks_dispatch(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    func: &MirFunction,
    phys_queries: &[PhysicalQuery],
    stream_decls: &HashMap<String, usize>,
    named_fallback_queries: &HashMap<String, usize>,
    cur_bb: &BasicBlock,
    qi: usize,
    read_only: bool,
) {
    // Only dispatch primary query 0 chunk loop when `par_chunks`/`par_chunks_readonly` executes
    let Some(hdr_bb_id) = (match cur_bb.terminator {
        Terminator::Goto(b) => Some(b.0 as usize),
        _ => None,
    }) else {
        return;
    };
    let Some(hdr_bb) = func.blocks.get(hdr_bb_id) else {
        return;
    };
    let (body_bb_id, _exit_bb_id) = match hdr_bb.terminator {
        Terminator::Branch {
            then_bb, else_bb, ..
        } => (then_bb.0, else_bb.0),
        _ => return,
    };

    // Identify reduction accumulator slots (`ReduceInit` -> `SlotStore`)
    let mut reduce_slots: Vec<(usize, String)> = Vec::new();
    let mut red_init_locals: HashMap<u32, String> = HashMap::new();
    for bb in &func.blocks {
        for s in &bb.stmts {
            if let Inst::ReduceInit { op, .. } = &s.inst
                && let Some(d) = s.dst
            {
                red_init_locals.insert(d.0, op.clone());
            }
            if let Inst::SlotStore { slot, val } = &s.inst
                && let Some(op) = red_init_locals.get(&val.0)
            {
                reduce_slots.push((slot.0 as usize, op.clone()));
            }
        }
    }

    // Notice `Chunk` does NOT allow `component_rows` on `&Chunk` (requires `&mut Chunk`),
    // so if `read_only` has any `@sparse` query term, fall back to sequential `chunk_hdr` cleanly.
    let has_sparse_read = phys_queries
        .get(qi)
        .is_some_and(|q| q.terms.iter().any(|t| t.is_sparse));
    if read_only && has_sparse_read {
        return;
    }

    // Check if the body uses `SystemContext` features unavailable in `Chunk` (commands, streams, res, entity_get, queries > 0)
    let uses_sys_only = func.blocks.iter().any(|bb| {
        bb.stmts.iter().any(|s| {
            matches!(
                s.inst,
                Inst::CmdSpawn { .. }
                    | Inst::CmdSpawnBatch { .. }
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
                    | Inst::ResRead { .. }
                    | Inst::ResWrite { .. }
                    | Inst::EntityGet { .. }
                    | Inst::EntityGetMut { .. }
                    | Inst::ResolveNamedObject { .. }
                    | Inst::BindNamedObject { .. }
                    | Inst::IterUpCascade { .. }
                    | Inst::IterCount { .. }
            ) || matches!(s.inst, Inst::IterNextChunk { query_idx } if query_idx as usize != qi)
        })
    });
    if uses_sys_only {
        return;
    }

    // Collect loop-internal basic blocks (all blocks reachable from body_bb stopping at hdr_bb)
    let loop_blocks = collect_loop_subgraph(func, BlockId(body_bb_id), BlockId(hdr_bb_id as u32));
    let _ = (stream_decls, named_fallback_queries);

    writeln!(
        out,
        "                if let HostBridge::System(sys_ctx) = bridge {{\n\
         \x20                   let _par_locals_init = locals.clone();\n\
         \x20                   let _par_slots_init = slots.clone();\n\
         \x20                   let _par_reds = Arc::new(Mutex::new(Vec::<(usize, StrataVal)>::new()));\n\
         \x20                   let _par_reds_c = Arc::clone(&_par_reds);"
    )
    .ok();

    let par_call = if read_only {
        "sys_ctx.par_chunks_readonly(move |chunk: &Chunk<'_, '_>| {"
    } else {
        "sys_ctx.par_chunks(move |mut chunk: Chunk<'_, '_>| {"
    };
    let bridge_ctor = if read_only {
        "HostBridge::ParChunkReadonly(chunk)"
    } else {
        "HostBridge::ParChunkMut(&mut chunk)"
    };
    writeln!(out, "                    let _par_status = {par_call}").ok();
    writeln!(
        out,
        "                        let mut _p_bridge = {bridge_ctor};\n\
         \x20                       let bridge = &mut _p_bridge;\n\
         \x20                       let migrate_src = StrataObj::Empty;\n\
         \x20                       let mut migrate_dst = StrataObj::Empty;\n\
         \x20                       let trg_payload = StrataObj::Empty;\n\
         \x20                       let mut locals = _par_locals_init.clone();\n\
         \x20                       let mut slots = _par_slots_init.clone();\n\
         \x20                       let mut spatial_hits: Vec<Vec<(FfiEntity, [f32; 4])>> = Vec::new();\n\
         \x20                       let mut par_consumed: Vec<bool> = vec![false; {nq}];\n\
         \x20                       let mut iter_started_once: Vec<bool> = vec![false; {nq}];\n\
         \x20                       let mut dirty_runs: HashMap<usize, (u32, u32)> = HashMap::new();\n\
         \x20                       let args: [StrataVal; 0] = [];\n\
         \x20                       let mut _pbb: u32 = {body_bb_id};\n\
         \x20                       loop {{\n\
         \x20                           match _pbb {{", nq = phys_queries.len().max(1)
    )
    .ok();

    for &bid in &loop_blocks {
        let bb = &func.blocks[bid as usize];
        writeln!(out, "                                {bid} => {{").ok();
        let mut inner = String::new();
        for st in &bb.stmts {
            emit_inst(
                &mut inner,
                mir,
                cat,
                func,
                phys_queries,
                stream_decls,
                named_fallback_queries,
                None,
                None,
                st,
                bb,
            );
        }
        for line in inner.lines() {
            writeln!(out, "                {line}").ok();
        }
        match bb.terminator {
            Terminator::Goto(BlockId(dst)) => {
                if dst as usize == hdr_bb_id || !loop_blocks.contains(&dst) {
                    writeln!(out, "                                    break;").ok();
                } else {
                    writeln!(out, "                                    _pbb = {dst};").ok();
                }
            }
            Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } => {
                let t_step = if then_bb.0 as usize == hdr_bb_id || !loop_blocks.contains(&then_bb.0)
                {
                    "break;".to_owned()
                } else {
                    format!("_pbb = {};", then_bb.0)
                };
                let e_step = if else_bb.0 as usize == hdr_bb_id || !loop_blocks.contains(&else_bb.0)
                {
                    "break;".to_owned()
                } else {
                    format!("_pbb = {};", else_bb.0)
                };
                writeln!(
                    out,
                    "                                    if locals[{}].as_bool() {{ {t_step} }} else {{ {e_step} }}",
                    cond.0
                )
                .ok();
            }
            Terminator::Switch {
                scrutinee,
                ref cases,
                default_bb,
            } => {
                writeln!(
                    out,
                    "                                    match locals[{}].as_u32() {{",
                    scrutinee.0
                )
                .ok();
                for (cv, BlockId(dst)) in cases {
                    if *dst as usize == hdr_bb_id || !loop_blocks.contains(dst) {
                        writeln!(
                            out,
                            "                                        {cv} => break,"
                        )
                        .ok();
                    } else {
                        writeln!(
                            out,
                            "                                        {cv} => _pbb = {dst},"
                        )
                        .ok();
                    }
                }
                if default_bb.0 as usize == hdr_bb_id || !loop_blocks.contains(&default_bb.0) {
                    writeln!(out, "                                        _ => break,").ok();
                } else {
                    writeln!(
                        out,
                        "                                        _ => _pbb = {},",
                        default_bb.0
                    )
                    .ok();
                }
                writeln!(out, "                                    }}").ok();
            }
            Terminator::Return(_) => {
                writeln!(out, "                                    break;").ok();
            }
        }
        writeln!(out, "                                }}").ok();
    }

    writeln!(
        out,
        "                                _ => break,\n\
         \x20                           }}\n\
         \x20                       }}"
    )
    .ok();
    if !reduce_slots.is_empty() {
        writeln!(
            out,
            "                        if let Ok(mut _g) = _par_reds_c.lock() {{"
        )
        .ok();
        for (sid, _) in &reduce_slots {
            writeln!(
                out,
                "                            _g.push(({sid}, slots[{sid}].clone()));"
            )
            .ok();
        }
        writeln!(out, "                        }}").ok();
    }
    writeln!(
        out,
        "                    }});\n\
         \x20                   if _par_status.is_ok() {{\n\
         \x20                       par_consumed[{qi}] = true;"
    )
    .ok();
    if !reduce_slots.is_empty() {
        writeln!(
            out,
            "                        if let Ok(_g) = _par_reds.lock() {{"
        )
        .ok();
        for (sid, op) in &reduce_slots {
            let esc_op = escape_rust_str(op);
            writeln!(
                out,
                "                            for (rsid, rval) in _g.iter() {{ if *rsid == {sid} {{ slots[{sid}] = strata_reduce_accum(&slots[{sid}], \"{esc_op}\", rval); }} }}"
            )
            .ok();
        }
        writeln!(out, "                        }}").ok();
    }
    writeln!(
        out,
        "                    }}\n\
         \x20               }}"
    )
    .ok();
}

fn collect_loop_subgraph(func: &MirFunction, body_start: BlockId, hdr: BlockId) -> Vec<u32> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![body_start.0];
    while let Some(bi) = stack.pop() {
        if bi == hdr.0 || bi as usize >= func.blocks.len() || !seen.insert(bi) {
            continue;
        }
        match &func.blocks[bi as usize].terminator {
            Terminator::Goto(b) => stack.push(b.0),
            Terminator::Branch {
                then_bb, else_bb, ..
            } => {
                stack.push(then_bb.0);
                stack.push(else_bb.0);
            }
            Terminator::Switch {
                cases, default_bb, ..
            } => {
                for (_, b) in cases {
                    stack.push(b.0);
                }
                stack.push(default_bb.0);
            }
            Terminator::Return(_) => {}
        }
    }
    seen.into_iter().collect()
}

fn emit_bridge_ptr_helpers(out: &mut String, cat: &GuestCatalog) {
    // 1. `strata_val_or_ptr_read` & `strata_ptr_read`
    writeln!(
        out,
        "fn strata_val_or_ptr_read(\n\
         \x20   bridge: &mut HostBridge<'_, '_, '_>,\n\
         \x20   base: &StrataVal,\n\
         \x20   extra_off: u32,\n\
         \x20   field: &str,\n\
         \x20   slots: &[StrataVal],\n\
         \x20   migrate_src: &StrataObj,\n\
         \x20   migrate_dst: &StrataObj,\n\
         \x20   trg_payload: &StrataObj,\n\
         ) -> StrataVal {{\n\
         \x20   match base {{\n\
         \x20       StrataVal::Obj(_o) => _o.get_field(extra_off, field),\n\
         \x20       StrataVal::Vec2(v) => match field {{ \"x\" => StrataVal::F32(v[0]), \"y\" => StrataVal::F32(v[1]), _ => StrataVal::F32(0.0) }},\n\
         \x20       StrataVal::Vec3(v) => match field {{ \"x\" => StrataVal::F32(v[0]), \"y\" => StrataVal::F32(v[1]), \"z\" => StrataVal::F32(v[2]), _ => StrataVal::F32(0.0) }},\n\
         \x20       StrataVal::Vec4(v) => match field {{ \"x\" => StrataVal::F32(v[0]), \"y\" => StrataVal::F32(v[1]), \"z\" => StrataVal::F32(v[2]), \"w\" => StrataVal::F32(v[3]), _ => StrataVal::F32(0.0) }},\n\
         \x20       StrataVal::Ptr(p) => strata_ptr_read(bridge, *p, extra_off, field, slots, migrate_src, migrate_dst, trg_payload),\n\
         \x20       _ => StrataVal::Unit,\n\
         \x20   }}\n\
         }}\n"
    )
    .ok();

    writeln!(
        out,
        "fn strata_ptr_read(\n\
         \x20   bridge: &mut HostBridge<'_, '_, '_>,\n\
         \x20   ptr: StrataPtr,\n\
         \x20   extra_off: u32,\n\
         \x20   field: &str,\n\
         \x20   slots: &[StrataVal],\n\
         \x20   migrate_src: &StrataObj,\n\
         \x20   migrate_dst: &StrataObj,\n\
         \x20   trg_payload: &StrataObj,\n\
         ) -> StrataVal {{\n\
         \x20   match ptr {{\n\
         \x20       StrataPtr::Slot {{ sid, off }} => match slots.get(sid) {{\n\
         \x20           Some(StrataVal::Obj(_o)) => _o.get_field(off.saturating_add(extra_off), field),\n\
         \x20           Some(v) => v.clone(),\n\
         \x20           None => StrataVal::Unit,\n\
         \x20       }},\n\
         \x20       StrataPtr::EventPayload {{ off }} => trg_payload.get_field(off.saturating_add(extra_off), field),\n\
         \x20       StrataPtr::MigrateSrc {{ off }} => migrate_src.get_field(off.saturating_add(extra_off), field),\n\
         \x20       StrataPtr::MigrateDst {{ off }} => migrate_dst.get_field(off.saturating_add(extra_off), field),\n\
         \x20       StrataPtr::Res {{ decl_idx, comp_id, off, is_mut }} => {{\n\
         \x20           let eff_off = off.saturating_add(extra_off);\n\
         \x20           let HostBridge::System(sys_ctx) = bridge else {{ return StrataVal::Unit; }};\n\
         \x20           match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if c.register_dynamic || c.layout.item_kind == SchemaItemKind::Resource {
            writeln!(
                out,
                "                {} => if is_mut {{ sys_ctx.component_resource_mut::<{}>(decl_idx).map_or(StrataVal::Unit, |r| r.strata_get(eff_off, field)) }} else {{ sys_ctx.component_resource::<{}>(decl_idx).map_or(StrataVal::Unit, |r| r.strata_get(eff_off, field)) }},",
                c.id, c.struct_name, c.struct_name
            )
            .ok();
        }
    }
    writeln!(
        out,
        "                _ => StrataVal::Unit,\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       StrataPtr::ChunkRow {{ qi, phys_col, comp_id, row, off, is_mut, is_untracked, is_sparse }} => {{\n\
         \x20           let eff_off = off.saturating_add(extra_off);\n\
         \x20           match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if !c.register_dynamic && c.layout.fields.is_empty() {
            continue;
        }
        let sname = &c.struct_name;
        writeln!(
            out,
            "                {} => match bridge {{\n\
             \x20                   HostBridge::System(sys_ctx) => sys_ctx.query_mut(qi).and_then(|it| {{\n\
             \x20                       if is_sparse {{\n\
             \x20                           it.component_rows::<{sname}>(phys_col).and_then(|rs| rs.get(row).map(|r| r.strata_get(eff_off, field)))\n\
             \x20                       }} else if is_mut && is_untracked {{\n\
             \x20                           it.mutable_slice_untracked(phys_col).as_component_slice_mut::<{sname}>().and_then(|s| s.get(row).map(|r| r.strata_get(eff_off, field)))\n\
             \x20                       }} else {{\n\
             \x20                           it.readonly_slice(phys_col).as_component_slice::<{sname}>().and_then(|s| s.get(row).map(|r| r.strata_get(eff_off, field)))\n\
             \x20                       }}\n\
             \x20                   }}).unwrap_or(StrataVal::Unit),\n\
             \x20                   HostBridge::ParChunkReadonly(ch) => ch.component::<{sname}>(phys_col).and_then(|s| s.get(row).map(|r| r.strata_get(eff_off, field))).unwrap_or(StrataVal::Unit),\n\
             \x20                   HostBridge::ParChunkMut(ch) => {{\n\
             \x20                       if is_sparse {{\n\
             \x20                           ch.component_rows::<{sname}>(phys_col).and_then(|rs| rs.get(row).map(|r| r.strata_get(eff_off, field))).unwrap_or(StrataVal::Unit)\n\
             \x20                       }} else if is_mut {{\n\
             \x20                           ch.component_mut_untracked::<{sname}>(phys_col).and_then(|s| s.get(row).map(|r| r.strata_get(eff_off, field))).unwrap_or(StrataVal::Unit)\n\
             \x20                       }} else {{\n\
             \x20                           ch.component::<{sname}>(phys_col).and_then(|s| s.get(row).map(|r| r.strata_get(eff_off, field))).unwrap_or(StrataVal::Unit)\n\
             \x20                       }}\n\
             \x20                   }}\n\
             \x20                   _ => StrataVal::Unit,\n\
             \x20               }},",
            c.id
        )
        .ok();
    }
    writeln!(
        out,
        "                _ => StrataVal::Unit,\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       StrataPtr::EntityPoint {{ qi, phys_col, comp_id, entity, off, is_mut }} => {{\n\
         \x20           if entity.is_null() {{ return StrataVal::Unit; }}\n\
         \x20           let eff_off = off.saturating_add(extra_off);\n\
         \x20           let HostBridge::System(sys_ctx) = bridge else {{ return StrataVal::Unit; }};\n\
         \x20           match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if c.register_dynamic {
            let sname = &c.struct_name;
            writeln!(
                out,
                "                {} => if is_mut {{ sys_ctx.get_mut::<{sname}>(qi, phys_col, entity).map_or(StrataVal::Unit, |v| v.strata_get(eff_off, field)) }} else {{ sys_ctx.get::<{sname}>(qi, phys_col, entity).map_or(StrataVal::Unit, |v| v.strata_get(eff_off, field)) }},",
                c.id
            )
            .ok();
        }
    }
    writeln!(
        out,
        "                _ => StrataVal::Unit,\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       _ => StrataVal::Unit,\n\
         \x20   }}\n\
         }}\n"
    )
    .ok();

    // 2. `strata_ptr_write`
    writeln!(
        out,
        "fn strata_ptr_write(\n\
         \x20   bridge: &mut HostBridge<'_, '_, '_>,\n\
         \x20   ptr: StrataPtr,\n\
         \x20   extra_off: u32,\n\
         \x20   field: &str,\n\
         \x20   val: StrataVal,\n\
         \x20   slots: &mut [StrataVal],\n\
         \x20   migrate_dst: &mut StrataObj,\n\
         ) {{\n\
         \x20   match ptr {{\n\
         \x20       StrataPtr::Slot {{ sid, off }} => {{\n\
         \x20           if let Some(slot) = slots.get_mut(sid) {{\n\
         \x20               if let StrataVal::Obj(_o) = slot {{\n\
         \x20                   _o.set_field(off.saturating_add(extra_off), field, val);\n\
         \x20               }} else if off == 0 && extra_off == 0 && field.is_empty() {{\n\
         \x20                   *slot = val;\n\
         \x20               }}\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       StrataPtr::MigrateDst {{ off }} => migrate_dst.set_field(off.saturating_add(extra_off), field, val),\n\
         \x20       StrataPtr::Res {{ decl_idx, comp_id, off, .. }} => {{\n\
         \x20           let eff_off = off.saturating_add(extra_off);\n\
         \x20           let HostBridge::System(sys_ctx) = bridge else {{ return; }};\n\
         \x20           match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if c.register_dynamic || c.layout.item_kind == SchemaItemKind::Resource {
            writeln!(
                out,
                "                {} => if let Some(r) = sys_ctx.component_resource_mut::<{}>(decl_idx) {{ r.strata_set(eff_off, field, val); }},",
                c.id, c.struct_name
            )
            .ok();
        }
    }
    writeln!(
        out,
        "                _ => {{}}\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       StrataPtr::ChunkRow {{ qi, phys_col, comp_id, row, off, is_untracked, is_sparse, .. }} => {{\n\
         \x20           let eff_off = off.saturating_add(extra_off);\n\
         \x20           match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if !c.register_dynamic && c.layout.fields.is_empty() {
            continue;
        }
        let sname = &c.struct_name;
        writeln!(
            out,
            "                {} => match bridge {{\n\
             \x20                   HostBridge::System(sys_ctx) => if let Some(it) = sys_ctx.query_mut(qi) {{\n\
             \x20                       if is_sparse {{\n\
             \x20                           if let Some(mut rs) = it.component_rows_mut::<{sname}>(phys_col) {{ if let Some(r) = rs.get_mut(row) {{ r.strata_set(eff_off, field, val); }} }}\n\
             \x20                       }} else if is_untracked {{\n\
             \x20                           if let Some(s) = it.mutable_slice_untracked(phys_col).as_component_slice_mut::<{sname}>() {{ if let Some(r) = s.get_mut(row) {{ r.strata_set(eff_off, field, val); }} }}\n\
             \x20                       }} else {{\n\
             \x20                           if let Some(s) = it.mutable_slice(phys_col).as_component_slice_mut::<{sname}>() {{ if let Some(r) = s.get_mut(row) {{ r.strata_set(eff_off, field, val); }} }}\n\
             \x20                       }}\n\
             \x20                   }},\n\
             \x20                   HostBridge::ParChunkMut(ch) => {{\n\
             \x20                       if is_sparse {{\n\
             \x20                           if let Some(mut rs) = ch.component_rows_mut::<{sname}>(phys_col) {{ if let Some(r) = rs.get_mut(row) {{ r.strata_set(eff_off, field, val); }} }}\n\
             \x20                       }} else if is_untracked {{\n\
             \x20                           if let Some(s) = ch.component_mut_untracked::<{sname}>(phys_col) {{ if let Some(r) = s.get_mut(row) {{ r.strata_set(eff_off, field, val); }} }}\n\
             \x20                       }} else {{\n\
             \x20                           if let Some(s) = ch.component_mut::<{sname}>(phys_col) {{ if let Some(r) = s.get_mut(row) {{ r.strata_set(eff_off, field, val); }} }}\n\
             \x20                       }}\n\
             \x20                   }}\n\
             \x20                   _ => {{}}\n\
             \x20               }},",
            c.id
        )
        .ok();
    }
    writeln!(
        out,
        "                _ => {{}}\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       StrataPtr::EntityPoint {{ qi, phys_col, comp_id, entity, off, .. }} => {{\n\
         \x20           if entity.is_null() {{ return; }}\n\
         \x20           let eff_off = off.saturating_add(extra_off);\n\
         \x20           let HostBridge::System(sys_ctx) = bridge else {{ return; }};\n\
         \x20           match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if c.register_dynamic {
            writeln!(
                out,
                "                {} => if let Some(v) = sys_ctx.get_mut::<{}>(qi, phys_col, entity) {{ v.strata_set(eff_off, field, val); }},",
                c.id, c.struct_name
            )
            .ok();
        }
    }
    writeln!(
        out,
        "                _ => {{}}\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       _ => {{}}\n\
         \x20   }}\n\
         }}\n"
    )
    .ok();

    // 3. `strata_ptr_bytes_read` & `strata_ptr_bytes_mut`
    writeln!(
        out,
        "fn strata_ptr_bytes_read(\n\
         \x20   bridge: &mut HostBridge<'_, '_, '_>,\n\
         \x20   val: &StrataVal,\n\
         \x20   slots: &[StrataVal],\n\
         \x20   migrate_src: &StrataObj,\n\
         \x20   migrate_dst: &StrataObj,\n\
         \x20   trg_payload: &StrataObj,\n\
         \x20   f: impl FnOnce(&[u8], usize),\n\
         ) {{\n\
         \x20   match val {{\n\
         \x20       StrataVal::Obj(o) => {{ let _b = o.read_le_bytes(); f(&_b, 0); }}\n\
         \x20       StrataVal::Ptr(ptr) => {{\n\
         \x20           let obj = match *ptr {{\n\
         \x20               StrataPtr::Slot {{ sid, .. }} => slots.get(sid).and_then(|s| if let StrataVal::Obj(o) = s {{ Some(o.clone()) }} else {{ None }}),\n\
         \x20               StrataPtr::EventPayload {{ .. }} => Some(trg_payload.clone()),\n\
         \x20               StrataPtr::MigrateSrc {{ .. }} => Some(migrate_src.clone()),\n\
         \x20               StrataPtr::MigrateDst {{ .. }} => Some(migrate_dst.clone()),\n\
         \x20               StrataPtr::Res {{ decl_idx, comp_id, is_mut, .. }} => {{\n\
         \x20                   if let HostBridge::System(sys_ctx) = bridge {{\n\
         \x20                       match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if c.register_dynamic || c.layout.item_kind == SchemaItemKind::Resource {
            writeln!(
                out,
                "                            {} => if is_mut {{ sys_ctx.component_resource_mut::<{}>(decl_idx).map(|r| StrataObj::{}(*r)) }} else {{ sys_ctx.component_resource::<{}>(decl_idx).map(|r| StrataObj::{}(*r)) }},",
                c.id, c.struct_name, c.variant_name, c.struct_name, c.variant_name
            )
            .ok();
        }
    }
    writeln!(
        out,
        "                            _ => None,\n\
         \x20                       }}\n\
         \x20                   }} else {{ None }}\n\
         \x20               }}\n\
         \x20               _ => None,\n\
         \x20           }};\n\
         \x20           let (resolved_obj, base_off) = match *ptr {{\n\
         \x20               StrataPtr::Slot {{ off, .. }} | StrataPtr::EventPayload {{ off }} | StrataPtr::MigrateSrc {{ off }} | StrataPtr::MigrateDst {{ off }} | StrataPtr::Res {{ off, .. }} => (obj, off as usize),\n\
         \x20               StrataPtr::ChunkRow {{ qi, phys_col, comp_id, row, off, is_mut, is_untracked, is_sparse }} => {{\n\
         \x20                   let o = match strata_ptr_read(bridge, StrataPtr::ChunkRow {{ qi, phys_col, comp_id, row, off: 0, is_mut, is_untracked, is_sparse }}, 0, \"\", slots, migrate_src, migrate_dst, trg_payload) {{ StrataVal::Obj(o) => Some(o), _ => None }};\n\
         \x20                   (o, off as usize)\n\
         \x20               }}\n\
         \x20               StrataPtr::EntityPoint {{ qi, phys_col, comp_id, entity, off, is_mut }} => {{\n\
         \x20                   let o = match strata_ptr_read(bridge, StrataPtr::EntityPoint {{ qi, phys_col, comp_id, entity, off: 0, is_mut }}, 0, \"\", slots, migrate_src, migrate_dst, trg_payload) {{ StrataVal::Obj(o) => Some(o), _ => None }};\n\
         \x20                   (o, off as usize)\n\
         \x20               }}\n\
         \x20               _ => (None, 0),\n\
         \x20           }};\n\
         \x20           if let Some(o) = resolved_obj {{\n\
         \x20               let _b = o.read_le_bytes();\n\
         \x20               f(&_b, base_off);\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20       _ => {{}}\n\
         \x20   }}\n\
         }}\n"
    )
    .ok();

    writeln!(
        out,
        "fn strata_ptr_bytes_mut(\n\
         \x20   bridge: &mut HostBridge<'_, '_, '_>,\n\
         \x20   ptr: StrataPtr,\n\
         \x20   slots: &mut [StrataVal],\n\
         \x20   migrate_dst: &mut StrataObj,\n\
         \x20   f: impl FnOnce(&mut [u8], usize),\n\
         ) {{\n\
         \x20   let base_off = match ptr {{\n\
         \x20       StrataPtr::Slot {{ off, .. }} | StrataPtr::Res {{ off, .. }} | StrataPtr::ChunkRow {{ off, .. }} | StrataPtr::EntityPoint {{ off, .. }} | StrataPtr::MigrateDst {{ off }} => off as usize,\n\
         \x20       _ => 0,\n\
         \x20   }};\n\
         \x20   let empty = StrataObj::Empty;\n\
         \x20   let cur_obj = match strata_ptr_read(bridge, ptr.set_exact_offset(0), 0, \"\", slots, &empty, migrate_dst, &empty) {{\n\
         \x20       StrataVal::Obj(o) => Some(o),\n\
         \x20       _ => None,\n\
         \x20   }};\n\
         \x20   if let Some(mut o) = cur_obj {{\n\
         \x20       let mut _b = o.read_le_bytes();\n\
         \x20       f(&mut _b, base_off);\n\
         \x20       o.write_le_bytes(&_b);\n\
         \x20       strata_ptr_write(bridge, ptr.set_exact_offset(0), 0, \"\", StrataVal::Obj(o), slots, migrate_dst);\n\
         \x20   }}\n\
         }}\n"
    )
    .ok();

    // 4. `strata_opt_present`
    writeln!(
        out,
        "fn strata_opt_present(bridge: &mut HostBridge<'_, '_, '_>, ptr: StrataPtr) -> bool {{\n\
         \x20   let StrataPtr::ChunkCol {{ qi, phys_col, comp_id, is_mut, is_sparse, .. }} = ptr else {{ return false; }};\n\
         \x20   match comp_id {{"
    )
    .ok();
    for c in &cat.components {
        if !c.register_dynamic && c.layout.fields.is_empty() {
            continue;
        }
        let sname = &c.struct_name;
        writeln!(
            out,
            "        {} => match bridge {{\n\
             \x20           HostBridge::System(sys_ctx) => sys_ctx.query_mut(qi).is_some_and(|it| {{\n\
             \x20               if is_sparse {{\n\
             \x20                   it.component_rows::<{sname}>(phys_col).is_some()\n\
             \x20               }} else if is_mut {{\n\
             \x20                   it.mutable_slice_untracked(phys_col).as_component_slice_mut::<{sname}>().is_some()\n\
             \x20               }} else {{\n\
             \x20                   it.readonly_slice(phys_col).as_component_slice::<{sname}>().is_some()\n\
             \x20               }}\n\
             \x20           }}),\n\
             \x20           HostBridge::ParChunkReadonly(ch) => ch.component::<{sname}>(phys_col).is_some(),\n\
             \x20           HostBridge::ParChunkMut(ch) => {{\n\
             \x20               if is_sparse {{\n\
             \x20                   ch.component_rows::<{sname}>(phys_col).is_some()\n\
             \x20               }} else if is_mut {{\n\
             \x20                   ch.component_mut_untracked::<{sname}>(phys_col).is_some()\n\
             \x20               }} else {{\n\
             \x20                   ch.component::<{sname}>(phys_col).is_some()\n\
             \x20               }}\n\
             \x20           }}\n\
             \x20           _ => false,\n\
             \x20       }},",
            c.id
        )
        .ok();
    }
    writeln!(out, "        _ => false,\n    }}\n}}\n").ok();
}

// ============================================================================
// GuestPlugin Registration: Migrations, Components/Tags, Relations, Objects,
// Observers, Schedules (Slots 60-62), & Run Conditions
// ============================================================================

fn emit_plugin_and_registration(out: &mut String, mir: &MirModule, cat: &GuestCatalog, stem: &str) {
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
    writeln!(
        out,
        "        let world_state: Arc<Mutex<StrataWorldState>> = Arc::new(Mutex::new(StrataWorldState::default()));\n\
         \x20       let mut handles = StrataHandles::default();"
    )
    .ok();

    // 1. Live schema migrations (`Slot 67`) BEFORE component registration
    for (idx, func) in mir.functions.iter().enumerate() {
        if let MirFnKind::Migration {
            component,
            src_layout,
            dst_layout,
            ..
        } = &func.kind
        {
            let src_comp = cat.resolve_comp(src_layout);
            let dst_comp = cat
                .resolve_comp(dst_layout)
                .or_else(|| cat.resolve_comp(component));
            if let (Some(src), Some(dst)) = (src_comp, dst_comp) {
                let fn_ident = format!("strata_sys_fn_{idx}_{}", sanitize_ident(&func.name));
                let old_s = &src.struct_name;
                let old_v = &src.variant_name;
                let new_s = &dst.struct_name;
                let new_v = &dst.variant_name;
                writeln!(
                    out,
                    "        if let Ok(_existing_h) = app.resolve_component_named(Some(<{new_s} as ModComponent>::COMPONENT_CSTR), None) {{\n\
                     \x20           let _needs_mig = app.component_layout_info(_existing_h).is_ok_and(|info| {{\n\
                     \x20               info.schema_fingerprint != <{new_s} as ModComponent>::SCHEMA_FINGERPRINT\n\
                     \x20                   || info.size != core::mem::size_of::<{new_s}>()\n\
                     \x20                   || info.align != core::mem::align_of::<{new_s}>()\n\
                     \x20           }});\n\
                     \x20           if _needs_mig {{\n\
                     \x20               let _w_mig = Arc::clone(&world_state);\n\
                     \x20               let _h_mig = handles;\n\
                     \x20               let _mig_res = app.migrate_pod_component_column::<{old_s}, {new_s}, _>(\n\
                     \x20                   _existing_h,\n\
                     \x20                   0x{old_fp:016X},\n\
                     \x20                   <{new_s} as ModComponent>::SCHEMA_FINGERPRINT,\n\
                     \x20                   move |old: &{old_s}| -> Result<{new_s}, FfiResult> {{\n\
                     \x20                       let _res = {fn_ident}(&_w_mig, &_h_mig, StrataObj::{old_v}(*old), StrataObj::{new_v}({new_s}::default()));\n\
                     \x20                       if let StrataObj::{new_v}(new_val) = _res {{\n\
                     \x20                           Ok(new_val)\n\
                     \x20                       }} else {{\n\
                     \x20                           Ok({new_s}::default())\n\
                     \x20                       }}\n\
                     \x20                   }},\n\
                     \x20               );\n\
                     \x20               if !_mig_res.is_ok() {{\n\
                     \x20                   return _mig_res;\n\
                     \x20               }}\n\
                     \x20           }}\n\
                     \x20       }}",
                    old_fp = src.layout.schema_fingerprint
                )
                .ok();
            }
        }
    }

    // 2. Register components, tags, resources, events, streams, spatial grids in topological order
    for &cid in &cat.topo_order {
        let c = &cat.components[cid];
        if !c.register_dynamic {
            continue;
        }
        let sname = &c.struct_name;
        let hfield = &c.handle_field;
        writeln!(
            out,
            "        handles.{hfield} = match app.resolve_component::<{sname}>() {{\n\
             \x20           Ok(h) => h,\n\
             \x20           Err(FfiResult::NOT_FOUND) => match app.register_dynamic_component::<{sname}>() {{\n\
             \x20               Ok(h) => h,\n\
             \x20               Err(e) => return e,\n\
             \x20           }},\n\
             \x20           Err(e) => return e,\n\
             \x20       }};"
        )
        .ok();
    }

    // 3. Register relations (`register_relation`)
    for rel in &cat.relations {
        let esc = escape_rust_str(&rel.canonical_name);
        let uuid_lit = format_u8_array_16(&rel.uuid_bytes);
        let mut builder_chain = format!(
            "RelationDescBuilder::new(\"{esc}\").with_uuid(ComponentUuid::from_bytes({uuid_lit}))"
        );
        for flag in &rel.flags {
            match flag.as_str() {
                "exclusive" => builder_chain.push_str(".exclusive()"),
                "symmetric" => builder_chain.push_str(".symmetric()"),
                "acyclic" => builder_chain.push_str(".acyclic()"),
                "cascade_despawn" | "cascade_delete" => {
                    builder_chain.push_str(".cascade_despawn()")
                }
                "cleanup_remove" => builder_chain.push_str(".cleanup_remove()"),
                _ => {}
            }
        }
        if let Some(pid) = rel.payload_comp_id {
            let psname = &cat.components[pid].struct_name;
            builder_chain.push_str(&format!(".with_payload::<{psname}>()"));
        }
        writeln!(
            out,
            "        handles.{} = match app.register_relation({builder_chain}) {{\n\
             \x20           Ok(h) => h,\n\
             \x20           Err(e) => return e,\n\
             \x20       }};",
            rel.handle_field
        )
        .ok();
    }

    // 4. Register Startup named-object initializer if `mir.objects` non-empty
    if !mir.objects.is_empty() {
        emit_named_objects_startup(out, mir, cat);
    }

    // 5. Register reactive observers (`MirFnKind::Observer`)
    for (idx, func) in mir.functions.iter().enumerate() {
        let MirFnKind::Observer { event, .. } = &func.kind else {
            continue;
        };
        let Some(ev_comp) = cat.resolve_comp(event) else {
            continue;
        };
        let fn_ident = format!("strata_sys_fn_{idx}_{}", sanitize_ident(&func.name));
        let obs_esc = escape_rust_str(&func.name);
        let ev_s = &ev_comp.struct_name;
        let ev_v = &ev_comp.variant_name;
        writeln!(
            out,
            "        {{\n\
             \x20           let _w_obs = Arc::clone(&world_state);\n\
             \x20           let _h_obs = handles;\n\
             \x20           if let Err(e) = app.observe_entity::<{ev_s}, _>(\n\
             \x20               \"{obs_esc}\",\n\
             \x20               FfiEntity::NULL,\n\
             \x20               move |tgt: FfiEntity, ev: &{ev_s}, cmds: &mut GuestCommands<'_>| {{\n\
             \x20                   {fn_ident}(cmds, &_w_obs, &_h_obs, tgt, StrataObj::{ev_v}(*ev));\n\
             \x20               }},\n\
             \x20           ) {{\n\
             \x20               return e;\n\
             \x20           }}\n\
             \x20       }}"
        )
        .ok();
    }

    // 6. Register scheduled systems (`SystemBuilder::register_handle`, `ScheduleSetBuilder`, `mount_system`)
    //    and direct unscheduled systems (`SystemBuilder::build`).
    let mut scheduled_names = HashSet::new();
    for sched in &mir.schedules {
        collect_schedule_leaf_names(&sched.nodes, &mut scheduled_names);
    }

    let mut sys_handle_vars: HashMap<String, String> = HashMap::new();
    for (idx, func) in mir.functions.iter().enumerate() {
        if matches!(
            func.kind,
            MirFnKind::Observer { .. } | MirFnKind::Migration { .. } | MirFnKind::HelperFn
        ) {
            continue;
        }
        let phys_queries = build_physical_queries(func, cat);
        let stream_decls = collect_func_stream_decls(func);
        let named_fallback_queries = collect_named_fallback_queries(mir, func, &phys_queries, cat);
        let sched_run_if = mir.schedules.iter().find_map(|s| {
            let mut leaves = HashSet::new();
            collect_schedule_leaf_names(&s.nodes, &mut leaves);
            if leaves.contains(&func.name) {
                s.run_if_expr.as_ref()
            } else {
                None
            }
        });

        let sys_var = format!("_sys_h_{idx}");
        let is_scheduled = scheduled_names.contains(&func.name);
        let sched_label = system_schedule_label(mir, &func.name);
        emit_system_builder_registration(
            out,
            mir,
            cat,
            func,
            idx,
            &phys_queries,
            &stream_decls,
            &named_fallback_queries,
            sched_run_if,
            sched_label,
            is_scheduled.then_some(sys_var.as_str()),
        );
        if is_scheduled {
            sys_handle_vars.insert(func.name.clone(), sys_var);
        }
    }

    // Configure ScheduleSetBuilder & mount systems for each `mir.schedules`
    let mut set_counter = 0usize;
    for (s_idx, sched) in mir.schedules.iter().enumerate() {
        let sched_id = schedule_id_expr(&sched.label);
        emit_schedule_nodes(
            out,
            stem,
            s_idx,
            &sched.nodes,
            sched_id,
            "BamSystemSet::INVALID",
            false,
            &mut None,
            &mut set_counter,
            &sys_handle_vars,
        );
    }

    writeln!(out, "        FfiResult::OK").ok();
    writeln!(out, "    }}").ok();
    writeln!(out, "}}\n").ok();
    writeln!(out, "export_mod!(plugin: StrataGuestMod);").ok();
}

fn emit_named_objects_startup(out: &mut String, mir: &MirModule, cat: &GuestCatalog) {
    writeln!(out, "        {{").ok();
    writeln!(
        out,
        "            let _w_obj = Arc::clone(&world_state);\n\
         \x20           let _h_obj = handles;\n\
         \x20           let _r = app\n\
         \x20               .system(c\"__strata_named_objects_startup\")\n\
         \x20               .schedule(ScheduleId::STARTUP)"
    )
    .ok();
    for obj in &mir.objects {
        if let Some(first_comp) = obj
            .components
            .iter()
            .find_map(|c| cat.resolve_comp(c))
            .or_else(|| {
                obj.inits.iter().find_map(|ci| {
                    let cname = ci.canonical_component.as_deref().unwrap_or(&ci.component);
                    cat.resolve_comp(cname)
                })
            })
        {
            writeln!(
                out,
                "                .query(|q| q.with::<{}>())",
                first_comp.struct_name
            )
            .ok();
        }
    }
    writeln!(
        out,
        "                .build(move |ctx: &mut SystemContext<'_>| {{"
    )
    .ok();
    for (oi, obj) in mir.objects.iter().enumerate() {
        let esc_name = escape_rust_str(&obj.name);
        writeln!(
            out,
            "                    let mut _existing_{oi} = FfiEntity::NULL;\n\
             \x20                   if let Some(it) = ctx.query_mut({oi}) {{\n\
             \x20                       if let Some(n) = it.next_chunk() {{ if n > 0 {{ _existing_{oi} = it.entities()[0]; }} }}\n\
             \x20                   }}\n\
             \x20                   let _ent_{oi} = if !_existing_{oi}.is_null() {{\n\
             \x20                       _existing_{oi}\n\
             \x20                   }} else {{"
        )
        .ok();
        let mut built_vars = Vec::new();
        // Build initialized components cleanly
        let mut covered_comps = HashSet::new();
        for (ci, init) in obj.inits.iter().enumerate() {
            let cname = init
                .canonical_component
                .as_deref()
                .unwrap_or(&init.component);
            if let Some(comp) = cat.resolve_comp(cname) {
                covered_comps.insert(comp.id);
                let sname = &comp.struct_name;
                let vname = &comp.variant_name;
                let var = format!("_init_{oi}_{ci}");
                writeln!(
                    out,
                    "                        let mut {var} = {sname}::default();"
                )
                .ok();
                if !init.fields.is_empty() {
                    writeln!(
                        out,
                        "                        let mut {var}_obj = StrataObj::{vname}({var});"
                    )
                    .ok();
                    for (fname, fexpr) in &init.fields {
                        let f_ty = comp
                            .layout
                            .fields
                            .iter()
                            .find(|f| f.name == *fname)
                            .map(|f| f.ty.clone())
                            .unwrap_or(Ty::Unknown);
                        let val_expr = hir_expr_to_strata_val(fexpr, &f_ty, mir, cat);
                        let esc_f = escape_rust_str(fname);
                        writeln!(
                            out,
                            "                        {var}_obj.set_field(0, \"{esc_f}\", {val_expr});"
                        )
                        .ok();
                    }
                    writeln!(
                        out,
                        "                        if let StrataObj::{vname}(_filled) = {var}_obj {{ {var} = _filled; }}"
                    )
                    .ok();
                }
                built_vars.push((
                    comp.handle_field.clone(),
                    var,
                    comp.layout.size == 0 || comp.layout.fields.is_empty(),
                ));
            }
        }
        for (ti, cname) in obj.components.iter().enumerate() {
            if let Some(comp) = cat.resolve_comp(cname)
                && !covered_comps.contains(&comp.id)
            {
                covered_comps.insert(comp.id);
                let sname = &comp.struct_name;
                let var = format!("_def_{oi}_{ti}");
                writeln!(
                    out,
                    "                        let {var} = {sname}::default();"
                )
                .ok();
                built_vars.push((
                    comp.handle_field.clone(),
                    var,
                    comp.layout.size == 0 || comp.layout.fields.is_empty(),
                ));
            }
        }
        writeln!(out, "                        let _ents = [").ok();
        for (hf, var, is_zst) in &built_vars {
            if *is_zst {
                writeln!(
                    out,
                    "                            SpawnEntry::marker(_h_obj.{hf}),"
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "                            SpawnEntry::new(_h_obj.{hf}, &{var}),"
                )
                .ok();
            }
        }
        let spawn_fn = if obj.is_persist {
            "spawn_persistent"
        } else {
            "spawn"
        };
        writeln!(
            out,
            "                        ];\n\
             \x20                       ctx.commands().{spawn_fn}(&_ents).unwrap_or(FfiEntity::NULL)\n\
             \x20                   }};\n\
             \x20                   if !_ent_{oi}.is_null() {{\n\
             \x20                       let _ = ctx.bind_named_object(\"{esc_name}\", _ent_{oi});\n\
             \x20                       if let Ok(mut _w) = _w_obj.lock() {{ _w.named_objects.insert(\"{esc_name}\".to_owned(), _ent_{oi}); }}\n\
             \x20                   }}"
        )
        .ok();
    }
    writeln!(
        out,
        "                    FfiResult::OK\n\
         \x20               }});\n\
         \x20           if !_r.is_ok() {{ return _r; }}\n\
         \x20       }}"
    )
    .ok();
}

#[allow(clippy::too_many_arguments)]
fn emit_system_builder_registration(
    out: &mut String,
    mir: &MirModule,
    cat: &GuestCatalog,
    func: &MirFunction,
    idx: usize,
    phys_queries: &[PhysicalQuery],
    stream_decls: &HashMap<String, usize>,
    named_fallback_queries: &HashMap<String, usize>,
    run_if_expr: Option<&HirExpr>,
    sched_label: &str,
    handle_var: Option<&str>,
) {
    let fn_ident = format!("strata_sys_fn_{idx}_{}", sanitize_ident(&func.name));
    let sys_name_esc = escape_rust_str(&func.name);
    let sched_id = schedule_id_expr(sched_label);
    let use_param_set = phys_queries.len() > 1 && queries_have_conflict(phys_queries);

    writeln!(out, "        let _w_s{idx} = Arc::clone(&world_state);").ok();
    writeln!(out, "        let _h_s{idx} = handles;").ok();
    if let Some(hvar) = handle_var {
        writeln!(
            out,
            "        let {hvar} = match app.system(c\"{sys_name_esc}\")"
        )
        .ok();
    } else {
        writeln!(out, "        let _res_s{idx} = app.system(c\"{sys_name_esc}\")\n            .schedule({sched_id})").ok();
    }

    // 1. Singleton resources (`func.resources`)
    for rb in &func.resources {
        if let Some(rc) = cat
            .resolve_comp(&rb.canonical_name)
            .or_else(|| cat.resolve_comp(&rb.resource_name))
        {
            if rb.mutable {
                writeln!(out, "            .resource_write::<{}>()", rc.struct_name).ok();
            } else {
                writeln!(out, "            .resource_read::<{}>()", rc.struct_name).ok();
            }
        }
    }

    // 2. Message stream writers (`StreamEmit`)
    let mut ordered_streams: Vec<(&String, &usize)> = stream_decls.iter().collect();
    ordered_streams.sort_by_key(|(_, i)| **i);
    for (sname, _) in ordered_streams {
        if let Some(sc) = cat.resolve_comp(sname) {
            writeln!(out, "            .message_write::<{}>()", sc.struct_name).ok();
        }
    }

    // 3. Queries (and optional ParamSet grouping when multi-query conflict exists)
    if use_param_set {
        writeln!(out, "            .param_set(|ps| {{").ok();
        for pq in phys_queries {
            emit_query_builder_chain(out, cat, pq, "ps", true);
        }
        writeln!(out, "            }})").ok();
    } else {
        for pq in phys_queries {
            emit_query_builder_chain(out, cat, pq, "builder", false);
        }
    }

    // 4. Hidden fallback queries for `ResolveNamedObject`
    let mut ordered_fb: Vec<(&String, &usize)> = named_fallback_queries.iter().collect();
    ordered_fb.sort_by_key(|(_, i)| **i);
    for (obj_name, _) in ordered_fb {
        if let Some(obj) = mir.objects.iter().find(|o| o.name == *obj_name)
            && let Some(first_comp) = obj
                .components
                .iter()
                .find_map(|c| cat.resolve_comp(c))
                .or_else(|| {
                    obj.inits.iter().find_map(|ci| {
                        let cname = ci.canonical_component.as_deref().unwrap_or(&ci.component);
                        cat.resolve_comp(cname)
                    })
                })
        {
            writeln!(
                out,
                "            .query(|q| q.with::<{}>())",
                first_comp.struct_name
            )
            .ok();
        }
    }

    // 5. Optional `schedule ... run_if(...)` predicate
    if let Some(rif) = run_if_expr {
        let mut res_refs: Vec<String> = Vec::new();
        collect_hir_res_refs(rif, &mut res_refs);
        if !res_refs.is_empty() {
            writeln!(out, "            .run_if_with(").ok();
            writeln!(out, "                |mut q| {{").ok();
            for rname in &res_refs {
                if let Some(rc) = cat.resolve_comp(rname) {
                    writeln!(
                        out,
                        "                    q = q.resource_read::<{}>();",
                        rc.struct_name
                    )
                    .ok();
                }
            }
            writeln!(out, "                    q\n                }},").ok();
            let cond_expr = format_run_if_hir_expr(rif, &res_refs, mir, cat);
            writeln!(
                out,
                "                move |rctx| {{ ({cond_expr}).as_bool() }},\n\
                 \x20           )"
            )
            .ok();
        }
    }

    if handle_var.is_some() {
        writeln!(
            out,
            "            .register_handle(move |mut ctx| {fn_ident}(&mut ctx, &_w_s{idx}, &_h_s{idx})) {{\n\
             \x20           Ok(h) => h,\n\
             \x20           Err(e) => return e,\n\
             \x20       }};"
        )
        .ok();
    } else {
        writeln!(
            out,
            "            .build(move |mut ctx| {fn_ident}(&mut ctx, &_w_s{idx}, &_h_s{idx}));\n\
             \x20       if !_res_s{idx}.is_ok() {{ return _res_s{idx}; }}"
        )
        .ok();
    }
}

fn emit_query_builder_chain(
    out: &mut String,
    cat: &GuestCatalog,
    pq: &PhysicalQuery,
    _target: &str,
    in_param_set: bool,
) {
    let indent = if in_param_set {
        "                "
    } else {
        "            "
    };
    let head = if in_param_set {
        "                ps.query(|mut q| {"
    } else {
        "            .query(|mut q| {"
    };
    writeln!(out, "{head}").ok();
    for pt in &pq.terms {
        let sname = &cat.components[pt.comp_id].struct_name;
        let method = match pt.mode {
            TermAccessMode::Write | TermAccessMode::SelectiveWrite => "write",
            TermAccessMode::OptionalRead => "optional_read",
            TermAccessMode::OptionalWrite => "optional_write",
            TermAccessMode::Allow => "allow",
            TermAccessMode::Has => "has",
            TermAccessMode::RemovedRead => "removed",
            TermAccessMode::With => "with",
            TermAccessMode::Without => "without",
            _ => "read",
        };
        writeln!(out, "{indent}    q = q.{method}::<{sname}>();").ok();
        if pt.changed_filter {
            writeln!(out, "{indent}    q = q.changed::<{sname}>();").ok();
        }
        if pt.added_filter {
            writeln!(out, "{indent}    q = q.added::<{sname}>();").ok();
        }
    }
    for cid in &pq.with_filters {
        let sname = &cat.components[*cid].struct_name;
        writeln!(out, "{indent}    q = q.with::<{sname}>();").ok();
    }
    for cid in &pq.without_filters {
        let sname = &cat.components[*cid].struct_name;
        writeln!(out, "{indent}    q = q.without::<{sname}>();").ok();
    }
    writeln!(out, "{indent}    q\n{indent}}})").ok();
    if in_param_set {
        writeln!(out, ";").ok();
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_schedule_nodes(
    out: &mut String,
    stem: &str,
    sched_idx: usize,
    nodes: &[HirScheduleGroup],
    sched_id: &str,
    parent_set: &str,
    parent_is_seq: bool,
    prev_sibling_set: &mut Option<String>,
    set_counter: &mut usize,
    sys_handles: &HashMap<String, String>,
) {
    for node in nodes {
        if node.kind == "leaf" {
            if let Some(sys_var) = sys_handles.get(&node.name) {
                writeln!(
                    out,
                    "        let _mnt = app.mount_system({sys_var}, {sched_id}, {parent_set});\n\
                     \x20       if !_mnt.is_ok() {{ return _mnt; }}"
                )
                .ok();
            }
            continue;
        }

        let k = *set_counter;
        *set_counter += 1;
        let raw_name = if node.name.trim().is_empty() {
            format!(
                "{stem}::sched_{sched_idx}_{}_{k}",
                sanitize_ident(&node.kind)
            )
        } else {
            format!("{stem}::{}::{}_{k}", sched_idx, sanitize_ident(&node.name))
        };
        let esc_set = escape_rust_str(&raw_name);
        let set_var = format!("_set_{k}");

        let mode_call = match node.kind.as_str() {
            "seq" => ".sequence()",
            "seq_weak" => ".sequence_weak()",
            "par" => ".parallel()",
            _ => "",
        };
        let after_call = if parent_is_seq && let Some(prev) = prev_sibling_set.as_ref() {
            format!(".after({prev})")
        } else {
            String::new()
        };

        writeln!(
            out,
            "        let {set_var} = match app.configure_schedule_set(\n\
             \x20           ScheduleSetBuilder::new(\"{esc_set}\").schedule({sched_id}){mode_call}{after_call}\n\
             \x20       ) {{\n\
             \x20           Ok(s) => s,\n\
             \x20           Err(e) => return e,\n\
             \x20       }};"
        )
        .ok();
        if parent_is_seq {
            *prev_sibling_set = Some(set_var.clone());
        }

        let child_is_seq = matches!(node.kind.as_str(), "seq" | "seq_weak");
        let mut child_prev: Option<String> = None;
        emit_schedule_nodes(
            out,
            stem,
            sched_idx,
            &node.children,
            sched_id,
            &set_var,
            child_is_seq,
            &mut child_prev,
            set_counter,
            sys_handles,
        );
    }
}

fn collect_schedule_leaf_names(nodes: &[HirScheduleGroup], out: &mut HashSet<String>) {
    for n in nodes {
        if n.kind == "leaf" {
            out.insert(n.name.clone());
        } else {
            collect_schedule_leaf_names(&n.children, out);
        }
    }
}

fn schedule_id_expr(label: &str) -> &'static str {
    match label {
        "Startup" => "ScheduleId::STARTUP",
        "PreUpdate" => "ScheduleId::PRE_UPDATE",
        "Update" => "ScheduleId::UPDATE",
        "PostUpdate" => "ScheduleId::POST_UPDATE",
        "Last" => "ScheduleId::LAST",
        "PreStartup" => "BevySchedules::DEFAULT.pre_startup()",
        "PostStartup" => "BevySchedules::DEFAULT.post_startup()",
        "First" => "BevySchedules::DEFAULT.first()",
        "FixedFirst" => "BevySchedules::DEFAULT.fixed_first()",
        "FixedPreUpdate" => "BevySchedules::DEFAULT.fixed_pre_update()",
        "FixedPostUpdate" => "BevySchedules::DEFAULT.fixed_post_update()",
        "FixedLast" => "BevySchedules::DEFAULT.fixed_last()",
        "SpawnScene" => "BevySchedules::DEFAULT.spawn_scene()",
        _ => "ScheduleId::FIXED_UPDATE",
    }
}

// ============================================================================
// HIR Constant / Run-If / Table Expression Formatting Helpers
// ============================================================================

fn collect_hir_res_refs(expr: &HirExpr, out: &mut Vec<String>) {
    match expr {
        HirExpr::Call(c) => {
            if c.callee == "res"
                && let Some(r) = c.generic_args.first()
                && !out.contains(r)
            {
                out.push(r.clone());
            }
            if let Some(ref r) = c.receiver {
                collect_hir_res_refs(r, out);
            }
            for a in &c.args {
                collect_hir_res_refs(a, out);
            }
        }
        HirExpr::Field { base, .. }
        | HirExpr::Unary { expr: base, .. }
        | HirExpr::Cast { expr: base, .. } => {
            collect_hir_res_refs(base, out);
        }
        HirExpr::Binary { lhs, rhs, .. } => {
            collect_hir_res_refs(lhs, out);
            collect_hir_res_refs(rhs, out);
        }
        HirExpr::Index { base, index, .. } => {
            collect_hir_res_refs(base, out);
            collect_hir_res_refs(index, out);
        }
        _ => {}
    }
}

fn format_run_if_hir_expr(
    expr: &HirExpr,
    res_refs: &[String],
    mir: &MirModule,
    cat: &GuestCatalog,
) -> String {
    match expr {
        HirExpr::BoolLit(b) => format!("StrataVal::Bool({b})"),
        HirExpr::IntLit { value, .. } => format!("StrataVal::I32({}i32)", *value as i32),
        HirExpr::FloatLit { value, .. } => format!("StrataVal::F32({})", fmt_f32(*value as f32)),
        HirExpr::Unary { op, expr, .. } => {
            let op_s = match op {
                strata_sema::hir::HirUnOp::Neg => "-",
                strata_sema::hir::HirUnOp::Not => "!",
                strata_sema::hir::HirUnOp::BitNot => "~",
                _ => "",
            };
            let inner = format_run_if_hir_expr(expr, res_refs, mir, cat);
            format!("strata_unop(\"{op_s}\", &{inner})")
        }
        HirExpr::Binary { op, lhs, rhs, .. } => {
            let op_s = hir_binop_str(*op);
            let l = format_run_if_hir_expr(lhs, res_refs, mir, cat);
            let r = format_run_if_hir_expr(rhs, res_refs, mir, cat);
            format!("strata_binop(\"{op_s}\", &{l}, &{r}, false)")
        }
        HirExpr::Field { base, field, .. } => {
            if let HirExpr::Call(c) = base.as_ref()
                && c.callee == "res"
                && let Some(rname) = c.generic_args.first()
                && let Some(decl_idx) = res_refs.iter().position(|r| r == rname)
                && let Some(rc) = cat.resolve_comp(rname)
            {
                let esc = escape_rust_str(field);
                let sname = &rc.struct_name;
                return format!(
                    "rctx.res::<{sname}>({decl_idx}).map_or(StrataVal::Unit, |r| r.strata_get(0, \"{esc}\"))"
                );
            }
            "StrataVal::Unit".to_owned()
        }
        HirExpr::Path { name, .. } => {
            if let Some(disc) = lookup_enum_path_disc(name, mir) {
                format!("StrataVal::I32({disc}i32)")
            } else {
                "StrataVal::Bool(true)".to_owned()
            }
        }
        _ => "StrataVal::Bool(true)".to_owned(),
    }
}

fn hir_binop_str(op: strata_sema::hir::HirBinOp) -> &'static str {
    use strata_sema::hir::HirBinOp as B;
    match op {
        B::Add => "+",
        B::Sub => "-",
        B::Mul => "*",
        B::Div => "/",
        B::Rem => "%",
        B::BitAnd => "&",
        B::BitOr => "|",
        B::BitXor => "^",
        B::Shl => "<<",
        B::Shr => ">>",
        B::Ne => "!=",
        B::Lt => "<",
        B::Le => "<=",
        B::Gt => ">",
        B::Ge => ">=",
        B::And => "&&",
        B::Or => "||",
        _ => "==",
    }
}

fn format_hir_expr_rust(
    expr: &HirExpr,
    target_ty: &Ty,
    mir: &MirModule,
    _cat: &GuestCatalog,
) -> String {
    match expr {
        HirExpr::BoolLit(b) => {
            if matches!(target_ty, Ty::Bool) {
                format!("{b}")
            } else {
                format!("FfiBool::from_bool({b})")
            }
        }
        HirExpr::IntLit { value, .. } => match target_ty {
            Ty::U8 => format!("{value}i64 as u8"),
            Ty::I8 => format!("{value}i64 as i8"),
            Ty::U16 => format!("{value}i64 as u16"),
            Ty::I16 => format!("{value}i64 as i16"),
            Ty::U32 | Ty::Sym | Ty::Rgba8 => format!("{value}i64 as u32"),
            Ty::U64 => format!("{value}i64 as u64"),
            Ty::I64 => format!("{value}i64"),
            Ty::F32 | Ty::UnitScalar { .. } => format!("{}f32", *value as f32),
            Ty::F64 => format!("{}f64", *value as f64),
            _ => format!("{value}i64 as i32"),
        },
        HirExpr::FloatLit { value, .. } => match target_ty {
            Ty::F64 => fmt_f64(*value),
            _ => fmt_f32(*value as f32),
        },
        HirExpr::StringLit(s) => format!("\"{}\"", escape_rust_str(s)),
        HirExpr::Path { name, .. } => {
            if let Some(disc) = lookup_enum_path_disc(name, mir) {
                match find_enum_width_by_path(name, mir) {
                    1 => format!("{disc}i64 as u8"),
                    2 => format!("{disc}i64 as u16"),
                    _ => format!("{disc}i64 as u32"),
                }
            } else if let Some(c) = mir.consts.iter().find(|c| c.name == *name)
                && let Some(ref inner) = c.expr
            {
                format_hir_expr_rust(inner, target_ty, mir, _cat)
            } else {
                "0".to_owned()
            }
        }
        HirExpr::Call(c) if c.callee == "bits" => {
            let words = match target_ty {
                Ty::BitSet(bits) => (*bits).div_ceil(32).max(1),
                _ => 1,
            };
            let mut mask_words = vec![0u32; words];
            for arg in &c.args {
                let bit_opt = match arg {
                    HirExpr::IntLit { value, .. } if *value >= 0 => Some(*value as usize),
                    HirExpr::Path { name, .. } => {
                        lookup_enum_path_disc(name, mir).map(|v| v.max(0) as usize)
                    }
                    _ => None,
                };
                if let Some(b) = bit_opt
                    && b / 32 < words
                {
                    mask_words[b / 32] |= 1u32 << (b % 32);
                }
            }
            let parts: Vec<String> = mask_words.iter().map(|w| format!("{w}u32")).collect();
            format!("[{}]", parts.join(", "))
        }
        HirExpr::Call(c) if matches!(c.callee.as_str(), "vec2" | "vec3" | "vec4") => {
            let vals: Vec<String> = c
                .args
                .iter()
                .map(|a| format_hir_expr_rust(a, &Ty::F32, mir, _cat))
                .collect();
            format!("[{}]", vals.join(", "))
        }
        HirExpr::Unary {
            op: strata_sema::hir::HirUnOp::Neg,
            expr,
            ..
        } => {
            let inner = format_hir_expr_rust(expr, target_ty, mir, _cat);
            if inner.starts_with('-') {
                format!("-({inner})")
            } else {
                format!("-{inner}")
            }
        }
        _ => table_field_default(target_ty, mir),
    }
}

fn hir_expr_to_strata_val(expr: &HirExpr, ty: &Ty, mir: &MirModule, cat: &GuestCatalog) -> String {
    let r = format_hir_expr_rust(expr, ty, mir, cat);
    match ty {
        Ty::Bool => format!("StrataVal::Bool({r})"),
        Ty::U8 | Ty::U16 | Ty::U32 | Ty::Sym | Ty::Rgba8 => format!("StrataVal::U32(({r}) as u32)"),
        Ty::I8 | Ty::I16 | Ty::I32 | Ty::Fix32 => format!("StrataVal::I32(({r}) as i32)"),
        Ty::U64 => format!("StrataVal::U64(({r}) as u64)"),
        Ty::I64 | Ty::Fix64 => format!("StrataVal::I64(({r}) as i64)"),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => {
            format!("StrataVal::F32(({r}) as f32)")
        }
        Ty::F64 => format!("StrataVal::F64(({r}) as f64)"),
        Ty::Vec2 => format!("StrataVal::Vec2({r})"),
        Ty::Vec3 => format!("StrataVal::Vec3({r})"),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => format!("StrataVal::Vec4({r})"),
        _ => format!("StrataVal::F32(({r}) as f32)"),
    }
}

fn lookup_enum_variant_disc(enum_name: &str, variant: &str, mir: &MirModule) -> Option<i64> {
    let short = enum_name.rsplit("::").next().unwrap_or(enum_name);
    let en = mir.enums.iter().find(|e| {
        e.canonical_name == enum_name || e.canonical_name.rsplit("::").next() == Some(short)
    })?;
    en.variants
        .iter()
        .find(|(vn, _)| vn == variant)
        .map(|(_, d)| *d)
}

fn lookup_enum_path_disc(path: &str, mir: &MirModule) -> Option<i64> {
    let (en, var) = path.rsplit_once("::")?;
    lookup_enum_variant_disc(en, var, mir)
}

fn find_enum_width_by_path(path: &str, mir: &MirModule) -> usize {
    if let Some((en, _)) = path.rsplit_once("::") {
        find_enum_layout_or_def(en, mir).unwrap_or(4)
    } else {
        4
    }
}

fn default_strata_val_for_mir_ty(ty: &MirType) -> &'static str {
    match ty {
        MirType::Bool => "StrataVal::Bool(false)",
        MirType::U8 | MirType::U16 | MirType::U32 | MirType::Sym => "StrataVal::U32(0)",
        MirType::U64 => "StrataVal::U64(0)",
        MirType::I8 | MirType::I16 | MirType::I32 | MirType::Fix32 => "StrataVal::I32(0)",
        MirType::I64 | MirType::Fix64 => "StrataVal::I64(0)",
        MirType::F32 => "StrataVal::F32(0.0)",
        MirType::F64 => "StrataVal::F64(0.0)",
        MirType::Vec2 => "StrataVal::Vec2([0.0; 2])",
        MirType::Vec3 => "StrataVal::Vec3([0.0; 3])",
        MirType::Vec4 => "StrataVal::Vec4([0.0; 4])",
        MirType::Entity => "StrataVal::Entity(FfiEntity::NULL)",
        MirType::Checkpoint => "StrataVal::Checkpoint(0)",
        _ => "StrataVal::Unit",
    }
}

fn fmt_f32(v: f32) -> String {
    if v.is_nan() {
        "f32::NAN".to_owned()
    } else if v.is_infinite() {
        if v.is_sign_positive() {
            "f32::INFINITY".to_owned()
        } else {
            "f32::NEG_INFINITY".to_owned()
        }
    } else {
        let s = format!("{v:?}");
        if s.contains('.') || s.contains('e') || s.contains('E') {
            format!("{s}f32")
        } else {
            format!("{s}.0f32")
        }
    }
}

fn fmt_f64(v: f64) -> String {
    if v.is_nan() {
        "f64::NAN".to_owned()
    } else if v.is_infinite() {
        if v.is_sign_positive() {
            "f64::INFINITY".to_owned()
        } else {
            "f64::NEG_INFINITY".to_owned()
        }
    } else {
        let s = format!("{v:?}");
        if s.contains('.') || s.contains('e') || s.contains('E') {
            format!("{s}f64")
        } else {
            format!("{s}.0f64")
        }
    }
}

fn escape_rust_str(s: &str) -> String {
    s.replace('\0', "")
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn format_u8_array_16(bytes: &[u8; 16]) -> String {
    let parts: Vec<String> = bytes.iter().map(|b| format!("0x{b:02X}")).collect();
    format!("[{}]", parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_mir::lower_to_mir;
    use strata_sema::analyze_source;

    #[test]
    fn rust_guest_emits_zero_unsafe_typed_query_and_resource_bind() {
        let src = r#"
module test::rain @version(1.0.0);

resource SimClock { dt: f32 = 0.0083333, elapsed: f32 = 0.0 }
component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component Vel { vx: f32 = 0.0, vy: f32 = -9.8 }

sys integrate(clk: &res SimClock) {
    uniform let dt = clk.dt;
    for r in query(pos: &mut Pos, vel: &Vel) {
        r.pos.x += r.vel.vx * dt;
        r.pos.y += r.vel.vy * dt;
    }
}

schedule FixedUpdate { integrate }
"#;
        let sema = analyze_source("rain.strata", src);
        assert!(sema.ok(), "{:?}", sema.diagnostics);
        let mir = lower_to_mir(&sema);
        let art = emit(
            &mir,
            &RustGuestOptions {
                crate_name: "rain_guest".to_owned(),
            },
        )
        .expect("emit rust guest");

        assert!(art.files[0].content.contains("branch = \"main\""));
        assert!(!art.files[0].content.contains("rev ="));
        assert!(!art.files[0].content.contains("bevy"));
        let lib = &art.files[1].content;
        assert!(lib.contains("#![forbid(unsafe_code)]"));
        assert!(!lib.contains("unsafe "));
        assert!(lib.contains("export_mod!(plugin: StrataGuestMod);"));
        assert!(lib.contains("resource_read"));
        assert!(lib.contains("0.0083333f32"));
        assert!(lib.contains("register_handle"));
        assert!(lib.contains("mount_system"));
    }

    #[test]
    fn rust_guest_emits_selective_untracked_and_dirty_range() {
        let src = r#"
module test::selective @version(1.0.0);

component Hull @summary_tick { hp: f32 = 100.0, heat: f32 = 0.0 }

sys cool_drones() {
    for d in query(hp: &mut? Hull.hp, heat: &mut? Hull.heat) {
        if d.heat > 0.0 {
            d.heat -= 1.0;
        }
    }
}
"#;
        let sema = analyze_source("selective.strata", src);
        assert!(sema.ok(), "{:?}", sema.diagnostics);
        let mir = lower_to_mir(&sema);
        let art = emit(&mir, &RustGuestOptions::default()).expect("emit");
        let lib = &art.files[1].content;
        assert!(lib.contains("mutable_slice_untracked"));
        assert!(lib.contains("mark_changed_range"));
        assert!(lib.contains("100.0f32"));
    }

    #[test]
    fn rust_guest_emits_migration_observer_relations_and_schedule_sets() {
        let src = r#"
module test::full_features @version(2.0.0);

component HealthV1 { hp: f32 = 50.0 }
component Health { hp: f64 = 100.0, armor: i32 = 5 }
event Hit { amount: f32 = 10.0 }
relation Ally [symmetric];
tag BossTag;

migrate Health from 1.0.0 to 2.0.0 (old: &HealthV1) -> Health {
    Health { hp: (old.hp as f64) * 2.0, armor: 10 }
}

fn add_bonus(h: &mut Health, bonus: f64) {
    h.hp += bonus;
}

sys step_health() {
    for e in query(h: &mut Health).with<BossTag>() {
        add_bonus(e.h, 1.0);
    }
}

obs on_hit(trg: &Trigger<Hit>) {
    let _amt = trg.amount;
}

schedule FixedUpdate {
    seq main_phase {
        step_health
    }
}
"#;
        let sema = analyze_source("full.strata", src);
        assert!(sema.ok(), "{:?}", sema.diagnostics);
        let mir = lower_to_mir(&sema);
        let art = emit(&mir, &RustGuestOptions::default()).expect("emit");
        let lib = &art.files[1].content;
        assert!(lib.contains("migrate_pod_component_column"));
        assert!(lib.contains("observe_entity"));
        assert!(lib.contains("register_relation"));
        assert!(lib.contains(".symmetric()"));
        assert!(lib.contains("ScheduleSetBuilder::new"));
        assert!(lib.contains("configure_schedule_set"));
        assert!(lib.contains("mount_system"));
        assert!(lib.contains("strata_helper_add_bonus"));
    }

    #[test]
    fn rust_guest_emits_sparse_optional_par_commands_atomic_and_named_objects() {
        let src = r#"
module test::rich @version(1.0.0);

component Body { hp: f32 = 80.0 }
@sparse component Buff { mult: f32 = 1.5 }
tag Alive;
tag Transient;

object Hero { Body {}, Alive {} }

@par(read_only, chunk = 64)
sys audit_and_tx() {
    let total = for b in query(body: &Body.hp) reduce (sum: sum(0.0, b.body));
    let _ = total;
}

sys spawn_and_check() {
    atomic {
        let e = spawn { Body { hp: 10.0 }, Transient };
        require_true(e != Hero);
    } on_rollback {
        despawn_all<With<Transient>>();
    }
    for r in query(body: &mut? Body, buff: &mut? Buff, opt: Option<&Alive>) {
        if r.opt.is_some() {
            r.body.hp += 1.0;
        }
    }
}
"#;
        let sema = analyze_source("rich.strata", src);
        assert!(sema.ok(), "{:?}", sema.diagnostics);
        let mir = lower_to_mir(&sema);
        let art = emit(&mir, &RustGuestOptions::default()).expect("emit");
        let lib = &art.files[1].content;
        assert!(lib.contains("par_chunks_readonly"));
        assert!(lib.contains("component_rows_mut"));
        assert!(lib.contains("strata_opt_present"));
        assert!(lib.contains("checkpoint()"));
        assert!(lib.contains("rollback("));
        assert!(lib.contains("despawn_all("));
        assert!(lib.contains("__strata_named_objects_startup"));
        assert!(lib.contains("bind_named_object"));
    }
}
