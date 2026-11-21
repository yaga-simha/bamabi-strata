//! Tier 3 static Bevy `0.20` `Plugin` (`--target bevy-native`) code generator targeting
//! `bamabi_native_rt` (`#![forbid(unsafe_code)]`, supporting both `shared-bridge` and
//! `dlopen`-free `static-console` profiles).

use crate::rust_guest::{
    rust_abi_type_for_field, rust_default_expr_for_field, sanitize_rust_ident,
};
use crate::{
    BevyNativeOptions, CodegenError, GeneratedArtifact, GeneratedFile, TargetKind,
    is_ecs_component_kind, module_stem, sanitize_ident,
};
use core::fmt::Write as _;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use strata_mir::{
    BlockId, Inst, LocalId, MirConstVal, MirFnKind, MirFunction, MirModule, MirStmt, MirType,
    Terminator,
};
use strata_sema::access::TermAccessMode;
use strata_sema::hir::{HirBinOp, HirExpr, HirParamKind, HirScheduleGroup, HirUnOp};
use strata_sema::layout::{EnumDef, SchemaItemKind, SolvedField, SolvedLayout};
use strata_sema::types::Ty;

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

    let ctx = NativeCtx::new(mir);
    let mut lib = String::with_capacity(16384);
    emit_preamble(&mut lib);
    emit_runtime_helpers(&mut lib);
    emit_enums_and_consts(&mut lib, &ctx);
    emit_native_layouts(&mut lib, &ctx);
    emit_synthesized_tags(&mut lib, &ctx);
    emit_spatial_and_relation_resources(&mut lib, &ctx);
    emit_tables_and_curves(&mut lib, &ctx);
    emit_helper_functions(&mut lib, &ctx)?;
    emit_native_functions(&mut lib, &ctx)?;
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

#[derive(Clone)]
struct LayoutEntry<'a> {
    struct_name: String,
    layout: &'a SolvedLayout,
}

#[derive(Clone)]
struct TagEntry {
    canonical_name: String,
    struct_name: String,
    uuid_bytes: [u8; 16],
    schema_fingerprint: u64,
}

struct NativeCtx<'a> {
    mir: &'a MirModule,
    layouts: Vec<LayoutEntry<'a>>,
    layouts_by_key: HashMap<String, usize>,
    entity_events: HashSet<String>,
    tags: Vec<TagEntry>,
    tags_by_key: HashMap<String, usize>,
    enums_by_key: HashMap<String, &'a EnumDef>,
    tables_by_key: HashMap<String, &'a strata_sema::hir::HirTable>,
    spatial_by_key: HashMap<String, &'a strata_sema::hir::HirSpatialIndex>,
    timelines_by_key: HashMap<String, &'a strata_sema::hir::HirTimeline>,
    tasks_by_key: HashMap<String, &'a strata_sema::hir::HirTask>,
    fsms_by_key: HashMap<String, &'a strata_sema::hir::HirFsm>,
    objects_by_key: HashMap<String, &'a strata_sema::hir::HirObject>,
    helpers_by_key: HashMap<String, &'a MirFunction>,
}

impl<'a> NativeCtx<'a> {
    fn new(mir: &'a MirModule) -> Self {
        let mut layouts = Vec::with_capacity(mir.layouts.len());
        let mut layouts_by_key = HashMap::new();
        let mut entity_events = HashSet::new();

        for (idx, layout) in mir.layouts.iter().enumerate() {
            let ident = sanitize_ident(&layout.canonical_name);
            let struct_name = format!("Strata{ident}_{idx}");
            layouts.push(LayoutEntry {
                struct_name,
                layout,
            });
            insert_layout_aliases(
                &mut layouts_by_key,
                &layout.canonical_name,
                layout.item_kind,
                idx,
            );

            if layout.item_kind == SchemaItemKind::Event
                && layout.fields.iter().any(|f| {
                    !f.is_padding
                        && f.name == "entity"
                        && (matches!(f.ty, Ty::Ref(_))
                            || matches!(&f.ty, Ty::Named(n) if n == "Entity"))
                })
            {
                entity_events.insert(layout.canonical_name.clone());
            }
        }

        let mut enums_by_key = HashMap::new();
        for en in &mir.enums {
            enums_by_key.insert(en.canonical_name.clone(), en);
            if let Some(short) = en.canonical_name.rsplit("::").next() {
                enums_by_key.insert(short.to_owned(), en);
            }
        }

        let mut tables_by_key = HashMap::new();
        for tb in &mir.tables {
            tables_by_key.insert(tb.name.clone(), tb);
        }
        let mut spatial_by_key = HashMap::new();
        for sp in &mir.spatial_indices {
            spatial_by_key.insert(sp.name.clone(), sp);
        }
        let mut timelines_by_key = HashMap::new();
        for tl in &mir.timelines {
            timelines_by_key.insert(tl.name.clone(), tl);
            timelines_by_key.insert(tl.canonical_name.clone(), tl);
        }
        let mut tasks_by_key = HashMap::new();
        for tk in &mir.tasks {
            tasks_by_key.insert(tk.name.clone(), tk);
        }
        let mut fsms_by_key = HashMap::new();
        for fsm in &mir.fsms {
            fsms_by_key.insert(fsm.name.clone(), fsm);
        }
        let mut objects_by_key = HashMap::new();
        for obj in &mir.objects {
            objects_by_key.insert(obj.name.clone(), obj);
        }
        let mut helpers_by_key = HashMap::new();
        for hf in &mir.fns {
            helpers_by_key.insert(hf.name.clone(), hf);
        }

        let mut ctx = Self {
            mir,
            layouts,
            layouts_by_key,
            entity_events,
            tags: Vec::new(),
            tags_by_key: HashMap::new(),
            enums_by_key,
            tables_by_key,
            spatial_by_key,
            timelines_by_key,
            tasks_by_key,
            fsms_by_key,
            objects_by_key,
            helpers_by_key,
        };
        ctx.collect_synthesized_tags();
        ctx
    }

    fn collect_synthesized_tags(&mut self) {
        let mut candidate_names: BTreeSet<String> = BTreeSet::new();
        for layout in &self.mir.layouts {
            for req in &layout.required_components {
                candidate_names.insert(req.clone());
            }
        }
        for sp in &self.mir.spatial_indices {
            candidate_names.insert(sp.over_component.clone());
        }
        for obj in &self.mir.objects {
            for c in &obj.components {
                candidate_names.insert(c.clone());
            }
            for init in &obj.inits {
                candidate_names.insert(
                    init.canonical_component
                        .clone()
                        .unwrap_or_else(|| init.component.clone()),
                );
            }
        }
        for func in self.mir.functions.iter().chain(self.mir.fns.iter()) {
            for qb in &func.query_bindings {
                for wf in &qb.with_filters {
                    candidate_names.insert(strip_filter_wrapper(wf));
                }
                for wof in &qb.without_filters {
                    candidate_names.insert(strip_filter_wrapper(wof));
                }
                for t in &qb.terms {
                    candidate_names.insert(t.canonical_component.clone());
                }
            }
            for bb in &func.blocks {
                for st in &bb.stmts {
                    match &st.inst {
                        Inst::CmdSpawn { components, .. }
                        | Inst::CmdSpawnBatch { components, .. }
                        | Inst::SpawnBatchPush { components, .. } => {
                            for (cname, _) in components {
                                candidate_names.insert(cname.clone());
                            }
                        }
                        Inst::SpawnBatchBegin { components, .. } => {
                            for cname in components {
                                candidate_names.insert(cname.clone());
                            }
                        }
                        Inst::CmdInsert { component, .. } | Inst::CmdRemove { component, .. } => {
                            candidate_names.insert(component.clone());
                        }
                        Inst::CmdDespawnAll { filter } => {
                            for (_, cname) in parse_despawn_filters(filter) {
                                candidate_names.insert(cname);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        for raw in candidate_names {
            let trimmed = raw.trim();
            if trimmed.is_empty()
                || matches!(trimmed, "Entity" | "Bundle" | "ChildOf" | "Component")
                || self.find_layout_entry(trimmed).is_some()
                || self.tags_by_key.contains_key(trimmed)
            {
                continue;
            }
            let short = trimmed.rsplit("::").next().unwrap_or(trimmed);
            if self.find_layout_entry(short).is_some() || self.tags_by_key.contains_key(short) {
                continue;
            }
            let canonical = if trimmed.contains("::") {
                trimmed.to_owned()
            } else {
                format!("{}::{short}", self.mir.module_path)
            };
            let idx = self.tags.len();
            let struct_name = format!("StrataTag_{}_{idx}", sanitize_ident(short));
            let uuid = bamabi_sys::ComponentUuid::from_parts(&canonical, 0, 1, 0);
            let mut fp = bamabi_sys::fnv1a_64_init();
            fp = bamabi_sys::fnv1a_64_update_bytes(fp, canonical.as_bytes());
            fp = bamabi_sys::fnv1a_64_update_u64(fp, 0);
            fp = bamabi_sys::fnv1a_64_update_u64(fp, 1);
            fp = bamabi_sys::fnv1a_64_update_u64(fp, 0);

            self.tags_by_key.insert(trimmed.to_owned(), idx);
            self.tags_by_key.insert(short.to_owned(), idx);
            self.tags_by_key.insert(canonical.clone(), idx);
            self.tags.push(TagEntry {
                canonical_name: canonical,
                struct_name,
                uuid_bytes: *uuid.as_bytes(),
                schema_fingerprint: fp,
            });
        }
    }

    fn find_layout_entry(&self, key: &str) -> Option<&LayoutEntry<'a>> {
        let norm = key.split('.').next().unwrap_or(key).trim();
        if let Some(&idx) = self.layouts_by_key.get(norm) {
            return Some(&self.layouts[idx]);
        }
        let short = norm.rsplit("::").next().unwrap_or(norm);
        if let Some(&idx) = self.layouts_by_key.get(short) {
            return Some(&self.layouts[idx]);
        }
        let san = sanitize_ident(norm);
        self.layouts_by_key.get(&san).map(|&idx| &self.layouts[idx])
    }

    fn resolve_ecs_struct_name(&self, key: &str) -> Option<String> {
        let clean = strip_filter_wrapper(key);
        if let Some(entry) = self.find_layout_entry(&clean) {
            return Some(entry.struct_name.clone());
        }
        if let Some(&tidx) = self.tags_by_key.get(&clean).or_else(|| {
            self.tags_by_key
                .get(clean.rsplit("::").next().unwrap_or(&clean))
        }) {
            return Some(self.tags[tidx].struct_name.clone());
        }
        None
    }

    fn is_zst_component(&self, key: &str) -> bool {
        if let Some(entry) = self.find_layout_entry(key) {
            entry.layout.size == 0 || entry.layout.fields.is_empty()
        } else {
            self.tags_by_key.contains_key(key)
                || self
                    .tags_by_key
                    .contains_key(key.rsplit("::").next().unwrap_or(key))
        }
    }

    fn resolve_field_info(&self, layout_key: &str, field_path: &str) -> Option<&'a SolvedField> {
        let mut entry = self.find_layout_entry(layout_key)?;
        let parts: Vec<&str> = field_path.split('.').collect();
        for (i, part) in parts.iter().enumerate() {
            let sf = entry.layout.fields.iter().find(|f| f.name == *part)?;
            if i + 1 == parts.len() {
                return Some(sf);
            }
            if let Ty::Named(ref inner) = sf.ty
                && let Some(next_entry) = self.find_layout_entry(inner)
            {
                entry = next_entry;
                continue;
            }
            return Some(sf);
        }
        None
    }
}

fn insert_layout_aliases(
    map: &mut HashMap<String, usize>,
    canonical_name: &str,
    item_kind: SchemaItemKind,
    idx: usize,
) {
    map.insert(canonical_name.to_owned(), idx);
    let short = canonical_name.rsplit("::").next().unwrap_or(canonical_name);
    map.entry(short.to_owned()).or_insert(idx);
    map.entry(sanitize_ident(canonical_name)).or_insert(idx);
    if let Some((comp, stratum)) = short.split_once("__") {
        map.entry(format!("{comp}::{stratum}")).or_insert(idx);
        if let Some((prefix, _)) = canonical_name.rsplit_once("::") {
            map.entry(format!("{prefix}::{comp}::{stratum}"))
                .or_insert(idx);
        }
    } else if item_kind == SchemaItemKind::SoaHot {
        map.entry(format!("{short}::hot")).or_insert(idx);
        map.entry(format!("{canonical_name}::hot")).or_insert(idx);
    }
}

fn strip_filter_wrapper(raw: &str) -> String {
    let t = raw.trim();
    for prefix in ["With<", "Without<", "Allow<", "Has<"] {
        if let Some(rest) = t.strip_prefix(prefix)
            && let Some(inner) = rest.strip_suffix('>')
        {
            return inner.trim().to_owned();
        }
    }
    t.to_owned()
}

fn parse_despawn_filters(filter: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for part in filter.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(inner) = part.strip_prefix("With<").and_then(|s| s.strip_suffix('>')) {
            out.push(("With", inner.trim().to_owned()));
        } else if let Some(inner) = part
            .strip_prefix("Without<")
            .and_then(|s| s.strip_suffix('>'))
        {
            out.push(("Without", inner.trim().to_owned()));
        } else {
            out.push(("With", strip_filter_wrapper(part)));
        }
    }
    out
}

fn emit_preamble(out: &mut String) {
    writeln!(out, "#![forbid(unsafe_code)]").ok();
    writeln!(
        out,
        "#![allow(unused_imports, dead_code, unused_variables, unused_mut, unused_assignments, unused_parens, unreachable_code, non_camel_case_types, non_snake_case, non_upper_case_globals, clippy::all)]"
    )
    .ok();
    writeln!(
        out,
        "//! Auto-generated Tier 3 Static Native Bevy `Plugin` (`#![forbid(unsafe_code)]`)."
    )
    .ok();
    writeln!(out).ok();
    writeln!(out, "use bamabi_native_rt::{{").ok();
    writeln!(
        out,
        "    ChunkSliceQueryExt, Fixed32, Fixed64, SelectiveMutSlice, SharedBridgeAppExt,\n\
         \x20   StrataComponentOptions,"
    )
    .ok();
    writeln!(out, "}};").ok();
    writeln!(
        out,
        "use bamabi_sys::{{\n\
         \x20   BamFieldDesc, BamFieldKind, ComponentUuid, FfiAssetHandle, FfiBool, FfiEntity,\n\
         \x20   ModComponent, StrView, SymbolEntry, VTableHeader, fnv1a_64_str,\n\
         }};"
    )
    .ok();
    writeln!(
        out,
        "use bevy_app::{{App, FixedUpdate, Last, Plugin, PostUpdate, PreUpdate, Startup, Update}};"
    )
    .ok();
    writeln!(out, "use bevy_ecs::prelude::*;").ok();
    writeln!(out, "use core::ffi::CStr;\n").ok();
}

fn emit_runtime_helpers(out: &mut String) {
    writeln!(
        out,
        "#[repr(transparent)]\n\
         #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]\n\
         pub struct StrataTargetEntity(pub FfiEntity);\n\n\
         impl StrataTargetEntity {{\n\
         \x20   #[inline]\n\
         \x20   pub const fn from_entity(entity: Entity) -> Self {{\n\
         \x20       Self(FfiEntity::from_bits(entity.to_bits()))\n\
         \x20   }}\n\
         \x20   #[inline]\n\
         \x20   pub const fn to_entity(self) -> Entity {{\n\
         \x20       if let Some(e) = Entity::try_from_bits(self.0.to_bits()) {{ e }} else {{ Entity::PLACEHOLDER }}\n\
         \x20   }}\n\
         }}\n\
         impl From<Entity> for StrataTargetEntity {{\n\
         \x20   #[inline]\n\
         \x20   fn from(e: Entity) -> Self {{ Self::from_entity(e) }}\n\
         }}\n\
         impl From<FfiEntity> for StrataTargetEntity {{\n\
         \x20   #[inline]\n\
         \x20   fn from(e: FfiEntity) -> Self {{ Self(e) }}\n\
         }}\n\
         impl From<StrataTargetEntity> for FfiEntity {{\n\
         \x20   #[inline]\n\
         \x20   fn from(e: StrataTargetEntity) -> Self {{ e.0 }}\n\
         }}\n\
         impl ContainsEntity for StrataTargetEntity {{\n\
         \x20   #[inline]\n\
         \x20   fn entity(&self) -> Entity {{ self.to_entity() }}\n\
         }}\n"
    )
    .ok();

    writeln!(
        out,
        "#[derive(Resource, Default, Debug, Clone)]\n\
         pub struct StrataNamedObjects {{\n\
         \x20   pub entries: std::collections::BTreeMap<&'static str, Entity>,\n\
         }}\n\
         impl StrataNamedObjects {{\n\
         \x20   #[inline]\n\
         \x20   pub fn get(&self, name: &str) -> Option<Entity> {{ self.entries.get(name).copied() }}\n\
         \x20   #[inline]\n\
         \x20   pub fn bind(&mut self, name: &'static str, entity: Entity) {{ self.entries.insert(name, entity); }}\n\
         }}\n\n\
         #[derive(Resource, Default, Debug)]\n\
         pub struct StrataTriggerTargetStack(pub Vec<FfiEntity>);\n"
    )
    .ok();

    writeln!(
        out,
        "#[inline]\n\
         fn strata_input_buf_push(words: &mut [u32], action_id: u16, window_sec: f32) {{\n\
         \x20   if window_sec <= 0.0 || words.len() < 2 {{ return; }}\n\
         \x20   let n = words.len() / 2;\n\
         \x20   let mut empty_idx: Option<usize> = None;\n\
         \x20   let mut min_idx = 0usize;\n\
         \x20   let mut min_rem = f32::MAX;\n\
         \x20   for i in 0..n {{\n\
         \x20       let act = (words[2 * i] & 0xFFFF) as u16;\n\
         \x20       let rem = f32::from_bits(words[2 * i + 1]);\n\
         \x20       let live = act != u16::MAX && rem > 0.0;\n\
         \x20       if live && act == action_id {{\n\
         \x20           words[2 * i + 1] = rem.max(window_sec).to_bits();\n\
         \x20           return;\n\
         \x20       }}\n\
         \x20       if !live && empty_idx.is_none() {{ empty_idx = Some(i); }}\n\
         \x20       if rem < min_rem {{ min_rem = rem; min_idx = i; }}\n\
         \x20   }}\n\
         \x20   let dst = empty_idx.unwrap_or(min_idx);\n\
         \x20   words[2 * dst] = action_id as u32;\n\
         \x20   words[2 * dst + 1] = window_sec.to_bits();\n\
         }}\n\
         #[inline]\n\
         fn strata_input_buf_peek(words: &[u32], action_id: u16) -> bool {{\n\
         \x20   let n = words.len() / 2;\n\
         \x20   for i in 0..n {{\n\
         \x20       let act = (words[2 * i] & 0xFFFF) as u16;\n\
         \x20       let rem = f32::from_bits(words[2 * i + 1]);\n\
         \x20       if act != u16::MAX && rem > 0.0 && act == action_id {{ return true; }}\n\
         \x20   }}\n\
         \x20   false\n\
         }}\n\
         #[inline]\n\
         fn strata_input_buf_consume(words: &mut [u32], action_id: u16) -> bool {{\n\
         \x20   let n = words.len() / 2;\n\
         \x20   let mut best_idx: Option<usize> = None;\n\
         \x20   let mut best_rem = -1.0f32;\n\
         \x20   for i in 0..n {{\n\
         \x20       let act = (words[2 * i] & 0xFFFF) as u16;\n\
         \x20       let rem = f32::from_bits(words[2 * i + 1]);\n\
         \x20       if act != u16::MAX && rem > 0.0 && act == action_id && rem > best_rem {{\n\
         \x20           best_rem = rem;\n\
         \x20           best_idx = Some(i);\n\
         \x20       }}\n\
         \x20   }}\n\
         \x20   if let Some(idx) = best_idx {{\n\
         \x20       words[2 * idx] = u16::MAX as u32;\n\
         \x20       words[2 * idx + 1] = 0.0f32.to_bits();\n\
         \x20       true\n\
         \x20   }} else {{\n\
         \x20       false\n\
         \x20   }}\n\
         }}\n\
         #[inline]\n\
         fn strata_input_buf_tick(words: &mut [u32], dt_sec: f32) {{\n\
         \x20   let n = words.len() / 2;\n\
         \x20   for i in 0..n {{\n\
         \x20       let act = (words[2 * i] & 0xFFFF) as u16;\n\
         \x20       let mut rem = f32::from_bits(words[2 * i + 1]);\n\
         \x20       if act != u16::MAX && rem > 0.0 {{\n\
         \x20           rem -= dt_sec;\n\
         \x20           if rem <= 0.0 {{\n\
         \x20               words[2 * i] = u16::MAX as u32;\n\
         \x20               words[2 * i + 1] = 0.0f32.to_bits();\n\
         \x20           }} else {{\n\
         \x20               words[2 * i + 1] = rem.to_bits();\n\
         \x20           }}\n\
         \x20       }}\n\
         \x20   }}\n\
         }}\n\
         #[inline]\n\
         fn strata_bitset_set(words: &mut [u32], bit: u32) {{\n\
         \x20   if let Some(w) = words.get_mut((bit / 32) as usize) {{ *w |= 1u32 << (bit % 32); }}\n\
         }}\n\
         #[inline]\n\
         fn strata_bitset_clear(words: &mut [u32], bit: u32) {{\n\
         \x20   if let Some(w) = words.get_mut((bit / 32) as usize) {{ *w &= !(1u32 << (bit % 32)); }}\n\
         }}\n\
         #[inline]\n\
         fn strata_bitset_get(words: &[u32], bit: u32) -> bool {{\n\
         \x20   words.get((bit / 32) as usize).is_some_and(|w| (*w & (1u32 << (bit % 32))) != 0)\n\
         }}\n\
         #[inline]\n\
         fn strata_sample_curve(pts: &[(f32, f32)], x: f32) -> f32 {{\n\
         \x20   if pts.is_empty() {{ return 0.0; }}\n\
         \x20   if x <= pts[0].0 {{ return pts[0].1; }}\n\
         \x20   let last = pts[pts.len() - 1];\n\
         \x20   if x >= last.0 {{ return last.1; }}\n\
         \x20   for w in pts.windows(2) {{\n\
         \x20       if x <= w[1].0 {{\n\
         \x20           let span = (w[1].0 - w[0].0).max(1e-12);\n\
         \x20           return w[0].1 + (w[1].1 - w[0].1) * ((x - w[0].0) / span);\n\
         \x20       }}\n\
         \x20   }}\n\
         \x20   last.1\n\
         }}\n\
         #[inline]\n\
         fn strata_inline_str_pack<const W: usize>(s: &str) -> [u32; W] {{\n\
         \x20   let mut out = [0u32; W];\n\
         \x20   if W <= 1 {{ return out; }}\n\
         \x20   let cap = (W - 1) * 4;\n\
         \x20   let mut end = s.len().min(cap);\n\
         \x20   while end > 0 && !s.is_char_boundary(end) {{ end -= 1; }}\n\
         \x20   out[0] = end as u32;\n\
         \x20   let bytes = &s.as_bytes()[..end];\n\
         \x20   for (i, chunk) in bytes.chunks(4).enumerate() {{\n\
         \x20       let mut w = [0u8; 4];\n\
         \x20       w[..chunk.len()].copy_from_slice(chunk);\n\
         \x20       out[1 + i] = u32::from_le_bytes(w);\n\
         \x20   }}\n\
         \x20   out\n\
         }}\n"
    )
    .ok();

    writeln!(
        out,
        "#[inline] fn strata_v2_add(a: [f32; 2], b: [f32; 2]) -> [f32; 2] {{ [a[0]+b[0], a[1]+b[1]] }}\n\
         #[inline] fn strata_v2_sub(a: [f32; 2], b: [f32; 2]) -> [f32; 2] {{ [a[0]-b[0], a[1]-b[1]] }}\n\
         #[inline] fn strata_v2_mul(a: [f32; 2], b: [f32; 2]) -> [f32; 2] {{ [a[0]*b[0], a[1]*b[1]] }}\n\
         #[inline] fn strata_v2_div(a: [f32; 2], b: [f32; 2]) -> [f32; 2] {{ [a[0]/b[0], a[1]/b[1]] }}\n\
         #[inline] fn strata_v2_scale(a: [f32; 2], s: f32) -> [f32; 2] {{ [a[0]*s, a[1]*s] }}\n\
         #[inline] fn strata_v3_add(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {{ [a[0]+b[0], a[1]+b[1], a[2]+b[2]] }}\n\
         #[inline] fn strata_v3_sub(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {{ [a[0]-b[0], a[1]-b[1], a[2]-b[2]] }}\n\
         #[inline] fn strata_v3_mul(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {{ [a[0]*b[0], a[1]*b[1], a[2]*b[2]] }}\n\
         #[inline] fn strata_v3_div(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {{ [a[0]/b[0], a[1]/b[1], a[2]/b[2]] }}\n\
         #[inline] fn strata_v3_scale(a: [f32; 3], s: f32) -> [f32; 3] {{ [a[0]*s, a[1]*s, a[2]*s] }}\n\
         #[inline] fn strata_v4_add(a: [f32; 4], b: [f32; 4]) -> [f32; 4] {{ [a[0]+b[0], a[1]+b[1], a[2]+b[2], a[3]+b[3]] }}\n\
         #[inline] fn strata_v4_sub(a: [f32; 4], b: [f32; 4]) -> [f32; 4] {{ [a[0]-b[0], a[1]-b[1], a[2]-b[2], a[3]-b[3]] }}\n\
         #[inline] fn strata_v4_mul(a: [f32; 4], b: [f32; 4]) -> [f32; 4] {{ [a[0]*b[0], a[1]*b[1], a[2]*b[2], a[3]*b[3]] }}\n\
         #[inline] fn strata_v4_div(a: [f32; 4], b: [f32; 4]) -> [f32; 4] {{ [a[0]/b[0], a[1]/b[1], a[2]/b[2], a[3]/b[3]] }}\n\
         #[inline] fn strata_v4_scale(a: [f32; 4], s: f32) -> [f32; 4] {{ [a[0]*s, a[1]*s, a[2]*s, a[3]*s] }}\n\
         #[inline] fn strata_dot(a: &[f32], b: &[f32]) -> f32 {{ a.iter().zip(b.iter()).map(|(x, y)| x * y).sum() }}\n\
         #[inline] fn strata_len(a: &[f32]) -> f32 {{ strata_dot(a, a).sqrt() }}\n\
         #[inline] fn strata_dist_sq(a: &[f32], b: &[f32]) -> f32 {{ a.iter().zip(b.iter()).map(|(x, y)| {{ let d = x - y; d * d }}).sum() }}\n\
         #[inline] fn strata_dist(a: &[f32], b: &[f32]) -> f32 {{ strata_dist_sq(a, b).sqrt() }}\n\
         #[inline] fn strata_norm_v2(a: [f32; 2]) -> [f32; 2] {{ let l = strata_len(&a); if l > 1e-12 {{ [a[0]/l, a[1]/l] }} else {{ [0.0; 2] }} }}\n\
         #[inline] fn strata_norm_v3(a: [f32; 3]) -> [f32; 3] {{ let l = strata_len(&a); if l > 1e-12 {{ [a[0]/l, a[1]/l, a[2]/l] }} else {{ [0.0; 3] }} }}\n\
         #[inline] fn strata_norm_v4(a: [f32; 4]) -> [f32; 4] {{ let l = strata_len(&a); if l > 1e-12 {{ [a[0]/l, a[1]/l, a[2]/l, a[3]/l] }} else {{ [0.0; 4] }} }}\n\
         #[inline] fn strata_cross(a: [f32; 3], b: [f32; 3]) -> [f32; 3] {{ [a[1]*b[2]-a[2]*b[1], a[2]*b[0]-a[0]*b[2], a[0]*b[1]-a[1]*b[0]] }}\n"
    )
    .ok();
}

fn emit_enums_and_consts(out: &mut String, ctx: &NativeCtx<'_>) {
    for en in &ctx.mir.enums {
        let ename = sanitize_ident(&en.canonical_name);
        let repr = match en.repr_bytes {
            1 => "u8",
            2 => "u16",
            _ => "u32",
        };
        writeln!(out, "pub mod strata_enum_{ename} {{").ok();
        for (vname, disc) in &en.variants {
            let vident = sanitize_rust_ident(vname);
            writeln!(out, "    pub const {vident}: {repr} = {disc} as {repr};").ok();
        }
        writeln!(out, "}}").ok();
    }
    for c in &ctx.mir.consts {
        if let Some(ref expr) = c.expr
            && let Some((ty_s, val_s)) = eval_hir_expr_static(expr, Some(&c.ty), ctx)
        {
            let cname = sanitize_ident(&c.name);
            writeln!(out, "pub const STRATA_CONST_{cname}: {ty_s} = {val_s};").ok();
        }
    }
    if !ctx.mir.enums.is_empty() || !ctx.mir.consts.is_empty() {
        writeln!(out).ok();
    }
}

fn format_f32_lit(v: f64) -> String {
    let f = v as f32;
    if f.is_nan() {
        "f32::NAN".to_owned()
    } else if f == f32::INFINITY {
        "f32::INFINITY".to_owned()
    } else if f == f32::NEG_INFINITY {
        "f32::NEG_INFINITY".to_owned()
    } else {
        let mut s = format!("{f:?}");
        if !s.contains('.') && !s.contains('e') && !s.contains('E') {
            s.push_str(".0");
        }
        format!("{s}_f32")
    }
}

fn format_f64_lit(v: f64) -> String {
    if v.is_nan() {
        "f64::NAN".to_owned()
    } else if v == f64::INFINITY {
        "f64::INFINITY".to_owned()
    } else if v == f64::NEG_INFINITY {
        "f64::NEG_INFINITY".to_owned()
    } else {
        let mut s = format!("{v:?}");
        if !s.contains('.') && !s.contains('e') && !s.contains('E') {
            s.push_str(".0");
        }
        format!("{s}_f64")
    }
}

fn format_const_for_field(val: &MirConstVal, field: &SolvedField, ctx: &NativeCtx<'_>) -> String {
    match (&field.ty, val) {
        (Ty::Bool, MirConstVal::Bool(b)) => {
            if *b {
                "FfiBool::TRUE".to_owned()
            } else {
                "FfiBool::FALSE".to_owned()
            }
        }
        (Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow, MirConstVal::Float(f)) => {
            format_f32_lit(*f)
        }
        (Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow, MirConstVal::Int(i)) => {
            format_f32_lit(*i as f64)
        }
        (Ty::F64, MirConstVal::Float(f)) => format_f64_lit(*f),
        (Ty::F64, MirConstVal::Int(i)) => format_f64_lit(*i as f64),
        (Ty::Fix32, MirConstVal::Float(f)) => {
            format!("Fixed32::from_f32({}).0", format_f32_lit(*f))
        }
        (Ty::Fix32, MirConstVal::Int(i)) => format!("Fixed32::from_int({i} as i16).0"),
        (Ty::Fix64, MirConstVal::Float(f)) => {
            format!("Fixed64::from_f64({}).0", format_f64_lit(*f))
        }
        (Ty::Fix64, MirConstVal::Int(i)) => format!("Fixed64::from_int({i} as i32).0"),
        (Ty::U8, MirConstVal::Int(i)) => format!("{i} as u8"),
        (Ty::I8, MirConstVal::Int(i)) => format!("{i} as i8"),
        (Ty::U16, MirConstVal::Int(i)) => format!("{i} as u16"),
        (Ty::I16, MirConstVal::Int(i)) => format!("{i} as i16"),
        (Ty::U32 | Ty::Sym | Ty::Rgba8, MirConstVal::Int(i)) => format!("{i} as u32"),
        (Ty::I32, MirConstVal::Int(i)) => format!("{i} as i32"),
        (Ty::U64, MirConstVal::Int(i)) => format!("{i} as u64"),
        (Ty::I64, MirConstVal::Int(i)) => format!("{i}i64"),
        (Ty::Vec2, MirConstVal::Vec2(v)) => {
            format!("[{}, {}]", format_f32_lit(v[0]), format_f32_lit(v[1]))
        }
        (Ty::IVec2, MirConstVal::Vec2(v)) => {
            format!("[{}i32, {}i32]", v[0] as i32, v[1] as i32)
        }
        (Ty::UVec2, MirConstVal::Vec2(v)) => {
            format!("[{}u32, {}u32]", v[0] as u32, v[1] as u32)
        }
        (Ty::Vec3, MirConstVal::Vec3(v)) => format!(
            "[{}, {}, {}]",
            format_f32_lit(v[0]),
            format_f32_lit(v[1]),
            format_f32_lit(v[2])
        ),
        (Ty::IVec3, MirConstVal::Vec3(v)) => {
            format!(
                "[{}i32, {}i32, {}i32]",
                v[0] as i32, v[1] as i32, v[2] as i32
            )
        }
        (Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba, MirConstVal::Vec4(v)) => format!(
            "[{}, {}, {}, {}]",
            format_f32_lit(v[0]),
            format_f32_lit(v[1]),
            format_f32_lit(v[2]),
            format_f32_lit(v[3])
        ),
        (Ty::InlineStr(cap), MirConstVal::String(s)) => {
            let words = 1 + cap.div_ceil(4);
            format!("strata_inline_str_pack::<{words}>({s:?})")
        }
        (Ty::Named(n), MirConstVal::Int(i)) => {
            if let Some(en) = ctx.enums_by_key.get(n.as_str()) {
                let rty = match en.repr_bytes {
                    1 => "u8",
                    2 => "u16",
                    _ => "u32",
                };
                format!("{i} as {rty}")
            } else {
                rust_default_expr_for_field(field, ctx.mir)
            }
        }
        (Ty::Array { elem, len }, MirConstVal::Array(items)) if items.len() == *len => {
            let dummy = SolvedField {
                name: field.name.clone(),
                ty: (**elem).clone(),
                offset: 0,
                size: field.size / (*len).max(1),
                align: field.align,
                is_padding: false,
                bam_field_kind: 0,
                type_tag: String::new(),
            };
            let elems: Vec<String> = items
                .iter()
                .map(|it| format_const_for_field(it, &dummy, ctx))
                .collect();
            format!("[{}]", elems.join(", "))
        }
        _ => rust_default_expr_for_field(field, ctx.mir),
    }
}

fn eval_hir_expr_static(
    expr: &HirExpr,
    expected_ty: Option<&Ty>,
    ctx: &NativeCtx<'_>,
) -> Option<(String, String)> {
    match expr {
        HirExpr::BoolLit(b) => Some(("bool".to_owned(), b.to_string())),
        HirExpr::IntLit { value, ty } => {
            let eff = expected_ty.unwrap_or(ty);
            let rty = rust_scalar_ty_from_hir(eff).unwrap_or("i64");
            Some((rty.to_owned(), format!("{value} as {rty}")))
        }
        HirExpr::FloatLit { value, ty } => {
            let eff = expected_ty.unwrap_or(ty);
            if matches!(eff, Ty::F64) {
                Some(("f64".to_owned(), format_f64_lit(*value)))
            } else {
                Some(("f32".to_owned(), format_f32_lit(*value)))
            }
        }
        HirExpr::Path { name, ty } => {
            if let Some((en_name, var_name)) = name.split_once("::")
                && let Some(en) = ctx.enums_by_key.get(en_name)
                && let Some((_, disc)) = en.variants.iter().find(|(v, _)| v == var_name)
            {
                let rty = match en.repr_bytes {
                    1 => "u8",
                    2 => "u16",
                    _ => "u32",
                };
                return Some((rty.to_owned(), format!("{disc} as {rty}")));
            }
            match name.as_str() {
                "vec2::ZERO" => Some(("[f32; 2]".to_owned(), "[0.0_f32, 0.0_f32]".to_owned())),
                "vec3::ZERO" => Some((
                    "[f32; 3]".to_owned(),
                    "[0.0_f32, 0.0_f32, 0.0_f32]".to_owned(),
                )),
                "vec4::ZERO" => Some((
                    "[f32; 4]".to_owned(),
                    "[0.0_f32, 0.0_f32, 0.0_f32, 0.0_f32]".to_owned(),
                )),
                _ => {
                    let _ = ty;
                    None
                }
            }
        }
        HirExpr::Unary { op, expr, ty } => {
            let (rty, inner) = eval_hir_expr_static(expr, expected_ty.or(Some(ty)), ctx)?;
            let op_s = match op {
                HirUnOp::Neg => "-",
                HirUnOp::Not | HirUnOp::BitNot => "!",
                _ => return None,
            };
            Some((rty, format!("({op_s}({inner}))")))
        }
        HirExpr::Binary { op, lhs, rhs, ty } => {
            let eff = expected_ty.unwrap_or(ty);
            let (_, l) = eval_hir_expr_static(lhs, Some(eff), ctx)?;
            let (_, r) = eval_hir_expr_static(rhs, Some(eff), ctx)?;
            let op_s = match op {
                HirBinOp::Add => "+",
                HirBinOp::Sub => "-",
                HirBinOp::Mul => "*",
                HirBinOp::Div => "/",
                HirBinOp::Rem => "%",
                HirBinOp::BitAnd => "&",
                HirBinOp::BitOr => "|",
                HirBinOp::BitXor => "^",
                _ => return None,
            };
            let rty = rust_scalar_ty_from_hir(eff).unwrap_or("f32");
            Some((rty.to_owned(), format!("(({l}) {op_s} ({r}))")))
        }
        HirExpr::Call(call) => match call.callee.as_str() {
            "bits" => {
                let words = match expected_ty {
                    Some(Ty::BitSet(b)) => (*b).div_ceil(32).max(1),
                    _ => 1,
                };
                let mut arr = vec![0u32; words];
                for a in &call.args {
                    if let HirExpr::IntLit { value, .. } = a {
                        let b = (*value).max(0) as usize;
                        if b / 32 < words {
                            arr[b / 32] |= 1u32 << (b % 32);
                        }
                    }
                }
                let parts: Vec<String> = arr.iter().map(|w| format!("0x{w:08X}u32")).collect();
                Some((format!("[u32; {words}]"), format!("[{}]", parts.join(", "))))
            }
            "vec2" => {
                let x = eval_hir_f32(call.args.first(), ctx);
                let y = eval_hir_f32(call.args.get(1), ctx);
                Some(("[f32; 2]".to_owned(), format!("[{x}, {y}]")))
            }
            "vec3" => {
                let x = eval_hir_f32(call.args.first(), ctx);
                let y = eval_hir_f32(call.args.get(1), ctx);
                let z = eval_hir_f32(call.args.get(2), ctx);
                Some(("[f32; 3]".to_owned(), format!("[{x}, {y}, {z}]")))
            }
            "ivec2" => {
                let x = eval_hir_i32(call.args.first());
                let y = eval_hir_i32(call.args.get(1));
                Some(("[i32; 2]".to_owned(), format!("[{x}i32, {y}i32]")))
            }
            "meters" | "sec" | "ms" | "rad" | "deg" | "mps" | "mps2" | "hz" | "frames" => {
                eval_hir_expr_static(call.args.first()?, expected_ty, ctx)
            }
            _ => None,
        },
        _ => None,
    }
}

fn eval_hir_f32(expr: Option<&HirExpr>, ctx: &NativeCtx<'_>) -> String {
    match expr {
        Some(HirExpr::FloatLit { value, .. }) => format_f32_lit(*value),
        Some(HirExpr::IntLit { value, .. }) => format_f32_lit(*value as f64),
        Some(other) => eval_hir_expr_static(other, Some(&Ty::F32), ctx)
            .map_or_else(|| "0.0_f32".to_owned(), |(_, v)| v),
        None => "0.0_f32".to_owned(),
    }
}

fn eval_hir_i32(expr: Option<&HirExpr>) -> i32 {
    match expr {
        Some(HirExpr::IntLit { value, .. }) => *value as i32,
        Some(HirExpr::FloatLit { value, .. }) => *value as i32,
        _ => 0,
    }
}

fn rust_scalar_ty_from_hir(ty: &Ty) -> Option<&'static str> {
    match ty {
        Ty::U8 => Some("u8"),
        Ty::I8 => Some("i8"),
        Ty::U16 => Some("u16"),
        Ty::I16 => Some("i16"),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => Some("u32"),
        Ty::I32 => Some("i32"),
        Ty::U64 => Some("u64"),
        Ty::I64 => Some("i64"),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => Some("f32"),
        Ty::F64 => Some("f64"),
        Ty::Bool => Some("bool"),
        _ => None,
    }
}

fn lookup_field_default<'a>(
    mir: &'a MirModule,
    layout: &SolvedLayout,
    field_name: &str,
) -> Option<&'a MirConstVal> {
    if let Some(m) = mir.field_defaults.get(&layout.canonical_name)
        && let Some(v) = m.get(field_name)
    {
        return Some(v);
    }
    let short = layout
        .canonical_name
        .rsplit("::")
        .next()
        .unwrap_or(&layout.canonical_name);
    if let Some((comp, strat)) = short.split_once("__") {
        let alt = format!("{comp}::{strat}");
        if let Some(m) = mir.field_defaults.get(&alt)
            && let Some(v) = m.get(field_name)
        {
            return Some(v);
        }
        if let Some((prefix, _)) = layout.canonical_name.rsplit_once("::") {
            let alt2 = format!("{prefix}::{comp}::{strat}");
            if let Some(m) = mir.field_defaults.get(&alt2)
                && let Some(v) = m.get(field_name)
            {
                return Some(v);
            }
        }
    } else if layout.item_kind == SchemaItemKind::SoaHot {
        let alt = format!("{short}::hot");
        if let Some(m) = mir.field_defaults.get(&alt)
            && let Some(v) = m.get(field_name)
        {
            return Some(v);
        }
        let alt2 = format!("{}::hot", layout.canonical_name);
        if let Some(m) = mir.field_defaults.get(&alt2)
            && let Some(v) = m.get(field_name)
        {
            return Some(v);
        }
    }
    mir.field_defaults
        .get(short)
        .and_then(|m| m.get(field_name))
}

fn emit_native_layouts(out: &mut String, ctx: &NativeCtx<'_>) {
    let mir = ctx.mir;
    for entry in &ctx.layouts {
        let layout = entry.layout;
        let struct_name = &entry.struct_name;
        let is_zst = layout.size == 0 || layout.fields.is_empty();
        let is_comp = is_ecs_component_kind(layout.item_kind);
        let is_res = matches!(
            layout.item_kind,
            SchemaItemKind::Resource | SchemaItemKind::SpatialGrid | SchemaItemKind::SpatialHistory
        );
        let is_ev = layout.item_kind == SchemaItemKind::Event;
        let is_entity_ev = is_ev && ctx.entity_events.contains(&layout.canonical_name);
        let is_stream = layout.item_kind == SchemaItemKind::Stream;

        writeln!(out, "#[repr(C)]").ok();
        let mut derives = vec!["Clone", "Copy", "Debug", "PartialEq"];
        if is_comp {
            derives.push("Component");
        } else if is_res {
            derives.push("Resource");
        } else if is_entity_ev {
            derives.push("EntityEvent");
        } else if is_ev {
            derives.push("Event");
        } else if is_stream {
            derives.push("Message");
        }
        writeln!(out, "#[derive({})]", derives.join(", ")).ok();
        if is_comp && (layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET) != 0 {
            writeln!(out, "#[component(storage = \"SparseSet\")]").ok();
        } else if is_comp
            && (layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SUMMARY_TICK) != 0
        {
            writeln!(out, "#[component(summary_tick)]").ok();
        }

        if is_comp && !layout.required_components.is_empty() {
            let mut req_names = Vec::new();
            for req in &layout.required_components {
                if let Some(req_struct) = ctx.resolve_ecs_struct_name(req)
                    && req_struct != *struct_name
                    && !req_names.contains(&req_struct)
                {
                    req_names.push(req_struct);
                }
            }
            if !req_names.is_empty() {
                writeln!(out, "#[require({})]", req_names.join(", ")).ok();
            }
        }

        let spatial_meta = if matches!(
            layout.item_kind,
            SchemaItemKind::SpatialGrid | SchemaItemKind::SpatialHistory
        ) {
            let short = layout
                .canonical_name
                .rsplit("::")
                .next()
                .unwrap_or(&layout.canonical_name);
            ctx.spatial_by_key.get(short).copied()
        } else {
            None
        };

        if is_zst {
            writeln!(out, "pub struct {struct_name};").ok();
            writeln!(out, "impl Default for {struct_name} {{").ok();
            writeln!(out, "    fn default() -> Self {{ Self }}").ok();
            writeln!(out, "}}").ok();
        } else {
            writeln!(out, "pub struct {struct_name} {{").ok();
            for field in &layout.fields {
                let fname = sanitize_rust_ident(&field.name);
                if is_entity_ev && field.name == "entity" && !field.is_padding {
                    writeln!(out, "    #[event_target]").ok();
                    writeln!(out, "    pub {fname}: StrataTargetEntity,").ok();
                } else {
                    let rty = rust_abi_type_for_field(field, mir);
                    writeln!(out, "    pub {fname}: {rty},").ok();
                }
            }
            writeln!(out, "}}").ok();
            writeln!(out, "impl Default for {struct_name} {{").ok();
            writeln!(out, "    fn default() -> Self {{").ok();
            writeln!(out, "        Self {{").ok();
            for field in &layout.fields {
                let fname = sanitize_rust_ident(&field.name);
                let def = if is_entity_ev && field.name == "entity" && !field.is_padding {
                    "StrataTargetEntity(FfiEntity::NULL)".to_owned()
                } else if !field.is_padding
                    && let Some(cval) = lookup_field_default(mir, layout, &field.name)
                {
                    format_const_for_field(cval, field, ctx)
                } else if let Some(sp) = spatial_meta {
                    match field.name.as_str() {
                        "frames" => format!("{}u32", sp.frames),
                        _ => rust_default_expr_for_field(field, mir),
                    }
                } else {
                    rust_default_expr_for_field(field, mir)
                };
                writeln!(out, "            {fname}: {def},").ok();
            }
            writeln!(out, "        }}").ok();
            writeln!(out, "    }}").ok();
            writeln!(out, "}}").ok();
        }

        emit_mod_component_impl(
            out,
            struct_name,
            &layout.canonical_name,
            layout.is_abi_pod,
            layout.component_flags,
            layout.schema_fingerprint,
            &layout.uuid_bytes,
            &layout.fields,
            layout.size,
            layout.align,
        );
    }
}

fn emit_synthesized_tags(out: &mut String, ctx: &NativeCtx<'_>) {
    for tag in &ctx.tags {
        let sname = &tag.struct_name;
        writeln!(out, "#[repr(C)]").ok();
        writeln!(
            out,
            "#[derive(Clone, Copy, Default, Debug, PartialEq, Component)]"
        )
        .ok();
        writeln!(out, "pub struct {sname};").ok();
        emit_mod_component_impl(
            out,
            sname,
            &tag.canonical_name,
            true,
            0,
            tag.schema_fingerprint,
            &tag.uuid_bytes,
            &[],
            0,
            1,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_mod_component_impl(
    out: &mut String,
    struct_name: &str,
    canonical_name: &str,
    is_abi_pod: bool,
    component_flags: u32,
    schema_fingerprint: u64,
    uuid_bytes: &[u8; 16],
    fields: &[SolvedField],
    size: usize,
    align: usize,
) {
    writeln!(out, "#[repr(C)]").ok();
    writeln!(out, "#[derive(Clone, Copy)]").ok();
    writeln!(out, "pub struct {struct_name}VTable {{").ok();
    writeln!(out, "    header: VTableHeader,").ok();
    writeln!(out, "}}").ok();

    writeln!(out, "static {struct_name}_FIELDS: &[BamFieldDesc] = &[").ok();
    for field in fields {
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

    let uuid_parts: Vec<String> = uuid_bytes.iter().map(|b| format!("0x{b:02X}")).collect();
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
         \x20   const CANONICAL_NAME: &'static str = \"{canonical_name}\";\n\
         \x20   const COMPONENT_CSTR: &'static CStr = c\"{canonical_name}\";\n\
         \x20   const UUID: ComponentUuid = ComponentUuid::from_bytes({uuid_lit});\n\
         \x20   const IS_ABI_POD: bool = {is_abi_pod};\n\
         \x20   const IS_RAW_INSERTABLE: bool = true;\n\
         \x20   const COMPONENT_FLAGS: u32 = 0x{component_flags:08X};\n\
         \x20   const SCHEMA_FINGERPRINT: u64 = 0x{schema_fingerprint:016X};\n\
         \x20   const BAM_FIELDS: &'static [BamFieldDesc] = {struct_name}_FIELDS;\n\
         \x20   type VTable = {struct_name}VTable;\n\
         \x20   fn vtable() -> &'static Self::VTable {{ &{struct_name}_VTABLE }}\n\
         \x20   fn symbols() -> &'static [SymbolEntry] {{ {struct_name}_SYMS }}\n\
         }}\n\
         const _: () = {{\n\
         \x20   assert!(core::mem::size_of::<{struct_name}>() == {size});\n\
         \x20   assert!(core::mem::align_of::<{struct_name}>() == {align});\n\
         }};\n"
    )
    .ok();
}

fn emit_spatial_and_relation_resources(out: &mut String, ctx: &NativeCtx<'_>) {
    for sp in &ctx.mir.spatial_indices {
        let sname = format!("StrataSpatialBacking_{}", sanitize_ident(&sp.name));
        let frames = sp.frames.max(1);
        writeln!(
            out,
            "#[derive(Resource, Debug, Clone)]\n\
             pub struct {sname} {{\n\
             \x20   pub entries: Vec<(Entity, [f32; 3])>,\n\
             \x20   pub history: std::collections::VecDeque<Vec<(Entity, [f32; 3])>>,\n\
             \x20   pub frames: usize,\n\
             }}\n\
             impl Default for {sname} {{\n\
             \x20   fn default() -> Self {{\n\
             \x20       Self {{ entries: Vec::new(), history: std::collections::VecDeque::new(), frames: {frames} }}\n\
             \x20   }}\n\
             }}\n\
             impl {sname} {{\n\
             \x20   pub fn rebuild(&mut self, rows: Vec<(Entity, [f32; 3])>) {{\n\
             \x20       self.entries = rows.clone();\n\
             \x20       if self.frames > 1 {{\n\
             \x20           if self.history.len() >= self.frames {{ self.history.pop_front(); }}\n\
             \x20           self.history.push_back(rows);\n\
             \x20       }}\n\
             \x20   }}\n\
             \x20   pub fn query_disc(&self, center: [f32; 3], radius: f32) -> Vec<FfiEntity> {{\n\
             \x20       let r_sq = radius * radius;\n\
             \x20       let mut out = Vec::new();\n\
             \x20       for &(ent, pos) in &self.entries {{\n\
             \x20           let dx = pos[0] - center[0];\n\
             \x20           let dy = pos[1] - center[1];\n\
             \x20           let dz = pos[2] - center[2];\n\
             \x20           if dx * dx + dy * dy + dz * dz <= r_sq {{\n\
             \x20               out.push(FfiEntity::from_bits(ent.to_bits()));\n\
             \x20           }}\n\
             \x20       }}\n\
             \x20       out\n\
             \x20   }}\n\
             \x20   pub fn query_segment_at(&self, tick_offset: u32, start: [f32; 3], end: [f32; 3], radius: f32) -> Vec<FfiEntity> {{\n\
             \x20       let slice: &[(Entity, [f32; 3])] = if self.history.is_empty() {{\n\
             \x20           &self.entries\n\
             \x20       }} else {{\n\
             \x20           let idx = (tick_offset as usize) % self.history.len();\n\
             \x20           self.history.get(idx).map_or(&self.entries, |v| v.as_slice())\n\
             \x20       }};\n\
             \x20       let ab = [end[0] - start[0], end[1] - start[1], end[2] - start[2]];\n\
             \x20       let ab_sq = ab[0] * ab[0] + ab[1] * ab[1] + ab[2] * ab[2];\n\
             \x20       let r_sq = radius * radius;\n\
             \x20       let mut out = Vec::new();\n\
             \x20       for &(ent, pos) in slice {{\n\
             \x20           let ap = [pos[0] - start[0], pos[1] - start[1], pos[2] - start[2]];\n\
             \x20           let t = if ab_sq > 1e-12 {{ ((ap[0]*ab[0] + ap[1]*ab[1] + ap[2]*ab[2]) / ab_sq).clamp(0.0, 1.0) }} else {{ 0.0 }};\n\
             \x20           let dx = start[0] + ab[0] * t - pos[0];\n\
             \x20           let dy = start[1] + ab[1] * t - pos[1];\n\
             \x20           let dz = start[2] + ab[2] * t - pos[2];\n\
             \x20           if dx * dx + dy * dy + dz * dz <= r_sq {{\n\
             \x20               out.push(FfiEntity::from_bits(ent.to_bits()));\n\
             \x20           }}\n\
             \x20       }}\n\
             \x20       out\n\
             \x20   }}\n\
             }}\n"
        )
        .ok();
    }

    for rel in &ctx.mir.relations {
        let rname = format!("StrataRelation_{}", sanitize_ident(&rel.name));
        let payload_ty = rel
            .payload_layout
            .as_ref()
            .and_then(|pl| ctx.find_layout_entry(&pl.canonical_name))
            .map_or_else(|| "()".to_owned(), |e| e.struct_name.clone());
        let is_symmetric = rel.flags.iter().any(|f| f == "symmetric");
        let is_exclusive = rel.flags.iter().any(|f| f == "exclusive");
        writeln!(
            out,
            "#[derive(Resource, Default, Debug, Clone)]\n\
             pub struct {rname} {{\n\
             \x20   pub edges: Vec<(Entity, Entity, {payload_ty})>,\n\
             }}\n\
             impl {rname} {{\n\
             \x20   pub fn insert(&mut self, src: Entity, dst: Entity, payload: {payload_ty}) {{\n\
             \x20       if {is_exclusive} {{ self.edges.retain(|&(s, _, _)| s != src); }}\n\
             \x20       self.edges.retain(|&(s, d, _)| !(s == src && d == dst));\n\
             \x20       self.edges.push((src, dst, payload));\n\
             \x20       if {is_symmetric} && src != dst {{\n\
             \x20           self.edges.retain(|&(s, d, _)| !(s == dst && d == src));\n\
             \x20           self.edges.push((dst, src, payload));\n\
             \x20       }}\n\
             \x20   }}\n\
             \x20   pub fn remove(&mut self, src: Entity, dst: Entity) {{\n\
             \x20       self.edges.retain(|&(s, d, _)| !(s == src && d == dst));\n\
             \x20       if {is_symmetric} {{\n\
             \x20           self.edges.retain(|&(s, d, _)| !(s == dst && d == src));\n\
             \x20       }}\n\
             \x20   }}\n\
             }}\n"
        )
        .ok();
    }
}

fn emit_tables_and_curves(out: &mut String, ctx: &NativeCtx<'_>) {
    for tb in &ctx.mir.tables {
        let tident = sanitize_ident(&tb.name);
        let row_struct = format!("StrataTable_{tident}Row");
        writeln!(
            out,
            "#[derive(Clone, Copy, Debug, PartialEq, Default)]\npub struct {row_struct} {{"
        )
        .ok();
        for (fname, fty) in &tb.fields {
            let rfname = sanitize_rust_ident(fname);
            let rty = rust_ty_from_hir_ty(fty, ctx);
            writeln!(out, "    pub {rfname}: {rty},").ok();
        }
        writeln!(out, "}}").ok();

        let key_enum = ctx.enums_by_key.get(&tb.key_enum).copied();
        let mut row_entries: Vec<(i64, String)> = Vec::new();
        for (row_var, typed_fields) in &tb.typed_rows {
            let disc = key_enum
                .and_then(|en| {
                    en.variants
                        .iter()
                        .find(|(v, _)| v == row_var)
                        .map(|(_, d)| *d)
                })
                .unwrap_or(row_entries.len() as i64);
            let mut field_strs = Vec::new();
            for (fname, fty) in &tb.fields {
                let rfname = sanitize_rust_ident(fname);
                let val_s = typed_fields
                    .iter()
                    .find(|(fnm, _)| fnm == fname)
                    .and_then(|(_, fexpr)| eval_hir_expr_static(fexpr, Some(fty), ctx))
                    .map(|(_, s)| s)
                    .unwrap_or_else(|| rust_default_expr_from_hir_ty(fty, ctx));
                field_strs.push(format!("{rfname}: {val_s}"));
            }
            row_entries.push((
                disc,
                format!("{row_struct} {{ {} }}", field_strs.join(", ")),
            ));
        }
        row_entries.sort_by_key(|(d, _)| *d);

        let max_disc = row_entries.iter().map(|(d, _)| *d).max().unwrap_or(-1);
        let mut ordered = vec![format!("{row_struct}::default()"); (max_disc + 1).max(0) as usize];
        for (d, lit) in row_entries {
            if d >= 0 && (d as usize) < ordered.len() {
                ordered[d as usize] = lit;
            }
        }
        writeln!(
            out,
            "static STRATA_TABLE_{tident}: &[{row_struct}] = &[\n    {}\n];\n",
            ordered.join(",\n    ")
        )
        .ok();
    }

    for cv in &ctx.mir.curves {
        let cident = sanitize_ident(&cv.name);
        let pts: Vec<String> = cv
            .points
            .iter()
            .map(|(x, y)| format!("({}, {})", format_f32_lit(*x), format_f32_lit(*y)))
            .collect();
        writeln!(
            out,
            "static STRATA_CURVE_{cident}: &[(f32, f32)] = &[{}];",
            pts.join(", ")
        )
        .ok();
    }
    if !ctx.mir.curves.is_empty() {
        writeln!(out).ok();
    }
}

fn rust_ty_from_hir_ty(ty: &Ty, ctx: &NativeCtx<'_>) -> String {
    match ty {
        Ty::U8 => "u8".to_owned(),
        Ty::I8 => "i8".to_owned(),
        Ty::Bool => "bool".to_owned(),
        Ty::U16 => "u16".to_owned(),
        Ty::I16 => "i16".to_owned(),
        Ty::I32 => "i32".to_owned(),
        Ty::Fix32 => "Fixed32".to_owned(),
        Ty::U64 => "u64".to_owned(),
        Ty::I64 => "i64".to_owned(),
        Ty::Fix64 => "Fixed64".to_owned(),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => "f32".to_owned(),
        Ty::F64 => "f64".to_owned(),
        Ty::Vec2 => "[f32; 2]".to_owned(),
        Ty::Vec3 => "[f32; 3]".to_owned(),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => "[f32; 4]".to_owned(),
        Ty::IVec2 => "[i32; 2]".to_owned(),
        Ty::IVec3 => "[i32; 3]".to_owned(),
        Ty::UVec2 => "[u32; 2]".to_owned(),
        Ty::BitSet(bits) => format!("[u32; {}]", (*bits).div_ceil(32).max(1)),
        Ty::Ref(_) => "FfiEntity".to_owned(),
        Ty::Asset(_) => "FfiAssetHandle".to_owned(),
        Ty::Named(n) => {
            if let Some(en) = ctx.enums_by_key.get(n.as_str()) {
                match en.repr_bytes {
                    1 => "u8".to_owned(),
                    2 => "u16".to_owned(),
                    _ => "u32".to_owned(),
                }
            } else if let Some(entry) = ctx.find_layout_entry(n) {
                entry.struct_name.clone()
            } else {
                "u32".to_owned()
            }
        }
        _ => "u32".to_owned(),
    }
}

fn rust_default_expr_from_hir_ty(ty: &Ty, ctx: &NativeCtx<'_>) -> String {
    match ty {
        Ty::Bool => "false".to_owned(),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => "0.0_f32".to_owned(),
        Ty::F64 => "0.0_f64".to_owned(),
        Ty::Ref(_) => "FfiEntity::NULL".to_owned(),
        Ty::Asset(_) => "FfiAssetHandle::NONE".to_owned(),
        Ty::BitSet(bits) => format!("[0u32; {}]", (*bits).div_ceil(32).max(1)),
        Ty::Named(n) if ctx.enums_by_key.contains_key(n.as_str()) => {
            let rty = rust_ty_from_hir_ty(ty, ctx);
            format!("0 as {rty}")
        }
        _ => "Default::default()".to_owned(),
    }
}

// =========================================================================
// MIR Function Analysis, Type Inference & Complete SSA CFG Lowering
// =========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
enum ValTy {
    Unit,
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    Fix32,
    Fix64,
    Vec2,
    Vec3,
    Vec4,
    Entity,
    Checkpoint,
    QueryIter,
    Array(Box<ValTy>, usize),
    Tuple(Vec<ValTy>),
    Struct(String),
    TableRow(String),
    BitSet(usize),
    InputBuf(usize),
    InlineStr(usize),
    PtrMarker,
}

impl ValTy {
    fn from_mir(mty: &MirType, ctx: &NativeCtx<'_>) -> Self {
        match mty {
            MirType::Unit => Self::Unit,
            MirType::Bool => Self::Bool,
            MirType::U8 => Self::U8,
            MirType::U16 => Self::U16,
            MirType::U32 | MirType::Sym => Self::U32,
            MirType::U64 => Self::U64,
            MirType::I8 => Self::I8,
            MirType::I16 => Self::I16,
            MirType::I32 => Self::I32,
            MirType::I64 => Self::I64,
            MirType::F32 => Self::F32,
            MirType::F64 => Self::F64,
            MirType::Fix32 => Self::Fix32,
            MirType::Fix64 => Self::Fix64,
            MirType::Vec2 => Self::Vec2,
            MirType::Vec3 => Self::Vec3,
            MirType::Vec4 => Self::Vec4,
            MirType::Entity => Self::Entity,
            MirType::Checkpoint => Self::Checkpoint,
            MirType::QueryIter => Self::QueryIter,
            MirType::Ptr | MirType::MutPtr => Self::PtrMarker,
            MirType::Array { elem, len } => Self::Array(Box::new(Self::from_mir(elem, ctx)), *len),
            MirType::Tuple(items) => {
                Self::Tuple(items.iter().map(|t| Self::from_mir(t, ctx)).collect())
            }
            MirType::Named(n) => {
                if n == "GraceWindow" {
                    Self::F32
                } else if n == "InlineStr" {
                    Self::InlineStr(64)
                } else if let Some(inner) = n
                    .strip_prefix("InlineStr<")
                    .and_then(|s| s.strip_suffix('>'))
                {
                    Self::InlineStr(inner.parse().unwrap_or(64))
                } else if let Some(inner) =
                    n.strip_prefix("BitSet<").and_then(|s| s.strip_suffix('>'))
                {
                    Self::BitSet(inner.parse().unwrap_or(32))
                } else if let Some(inner) = n
                    .strip_prefix("InputBuffer<")
                    .and_then(|s| s.strip_suffix('>'))
                    && let Some((_, cap_s)) = inner.split_once(',')
                {
                    Self::InputBuf(cap_s.trim().parse().unwrap_or(4))
                } else if let Some(en) = ctx.enums_by_key.get(n.as_str()) {
                    match en.repr_bytes {
                        1 => Self::U8,
                        2 => Self::U16,
                        _ => Self::U32,
                    }
                } else if ctx.tables_by_key.contains_key(n.as_str()) {
                    Self::TableRow(n.clone())
                } else if let Some(entry) = ctx.find_layout_entry(n) {
                    Self::Struct(entry.struct_name.clone())
                } else if let Some(sname) = ctx.resolve_ecs_struct_name(n) {
                    Self::Struct(sname)
                } else if n == "mat3" {
                    Self::Array(Box::new(Self::F32), 9)
                } else if n == "mat4" {
                    Self::Array(Box::new(Self::F32), 16)
                } else if n.starts_with("Asset<") {
                    Self::Struct("FfiAssetHandle".to_owned())
                } else {
                    Self::U64
                }
            }
        }
    }

    fn from_solved_field(field: &SolvedField, ctx: &NativeCtx<'_>) -> Self {
        Self::from_sema_ty(&field.ty, ctx)
    }

    fn from_sema_ty(ty: &Ty, ctx: &NativeCtx<'_>) -> Self {
        match ty {
            Ty::Bool => Self::Bool,
            Ty::U8 => Self::U8,
            Ty::I8 => Self::I8,
            Ty::U16 => Self::U16,
            Ty::I16 => Self::I16,
            Ty::U32 | Ty::Sym | Ty::Rgba8 => Self::U32,
            Ty::I32 => Self::I32,
            Ty::Fix32 => Self::Fix32,
            Ty::U64 => Self::U64,
            Ty::I64 => Self::I64,
            Ty::Fix64 => Self::Fix64,
            Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => Self::F32,
            Ty::F64 => Self::F64,
            Ty::Vec2 | Ty::IVec2 | Ty::UVec2 => Self::Vec2,
            Ty::Vec3 | Ty::Vec3a | Ty::IVec3 => Self::Vec3,
            Ty::Vec4 | Ty::Quat | Ty::Rgba => Self::Vec4,
            Ty::Ref(_) => Self::Entity,
            Ty::BitSet(b) => Self::BitSet(*b),
            Ty::InputBuffer { cap, .. } => Self::InputBuf(*cap),
            Ty::InlineStr(cap) => Self::InlineStr(*cap),
            Ty::Array { elem, len } => Self::Array(Box::new(Self::from_sema_ty(elem, ctx)), *len),
            Ty::Tuple(items) => {
                Self::Tuple(items.iter().map(|t| Self::from_sema_ty(t, ctx)).collect())
            }
            Ty::Named(n) => Self::from_mir(&MirType::Named(n.clone()), ctx),
            _ => Self::from_mir(&MirType::Unit, ctx),
        }
    }

    fn rust_type(&self) -> String {
        match self {
            Self::Unit | Self::PtrMarker => "()".to_owned(),
            Self::Bool => "bool".to_owned(),
            Self::U8 => "u8".to_owned(),
            Self::U16 => "u16".to_owned(),
            Self::U32 => "u32".to_owned(),
            Self::U64 => "u64".to_owned(),
            Self::I8 => "i8".to_owned(),
            Self::I16 => "i16".to_owned(),
            Self::I32 => "i32".to_owned(),
            Self::I64 => "i64".to_owned(),
            Self::F32 => "f32".to_owned(),
            Self::F64 => "f64".to_owned(),
            Self::Fix32 => "Fixed32".to_owned(),
            Self::Fix64 => "Fixed64".to_owned(),
            Self::Vec2 => "[f32; 2]".to_owned(),
            Self::Vec3 => "[f32; 3]".to_owned(),
            Self::Vec4 => "[f32; 4]".to_owned(),
            Self::Entity => "FfiEntity".to_owned(),
            Self::Checkpoint => "usize".to_owned(),
            Self::QueryIter => "Vec<FfiEntity>".to_owned(),
            Self::Array(e, n) => format!("[{}; {n}]", e.rust_type()),
            Self::Tuple(items) => {
                let parts: Vec<String> = items.iter().map(Self::rust_type).collect();
                format!("({})", parts.join(", "))
            }
            Self::Struct(sname) => sname.clone(),
            Self::TableRow(tname) => format!("StrataTable_{}Row", sanitize_ident(tname)),
            Self::BitSet(bits) => format!("[u32; {}]", (*bits).div_ceil(32).max(1)),
            Self::InputBuf(cap) => format!("[u32; {}]", (*cap).max(1) * 2),
            Self::InlineStr(cap) => format!("[u32; {}]", 1 + cap.div_ceil(4)),
        }
    }

    fn default_expr(&self) -> String {
        match self {
            Self::Unit | Self::PtrMarker => "()".to_owned(),
            Self::Bool => "false".to_owned(),
            Self::U8 => "0u8".to_owned(),
            Self::U16 => "0u16".to_owned(),
            Self::U32 => "0u32".to_owned(),
            Self::U64 => "0u64".to_owned(),
            Self::I8 => "0i8".to_owned(),
            Self::I16 => "0i16".to_owned(),
            Self::I32 => "0i32".to_owned(),
            Self::I64 => "0i64".to_owned(),
            Self::F32 => "0.0_f32".to_owned(),
            Self::F64 => "0.0_f64".to_owned(),
            Self::Fix32 => "Fixed32(0)".to_owned(),
            Self::Fix64 => "Fixed64(0)".to_owned(),
            Self::Vec2 => "[0.0_f32; 2]".to_owned(),
            Self::Vec3 => "[0.0_f32; 3]".to_owned(),
            Self::Vec4 => "[0.0_f32; 4]".to_owned(),
            Self::Entity => "FfiEntity::NULL".to_owned(),
            Self::Checkpoint => "0usize".to_owned(),
            Self::QueryIter => "Vec::new()".to_owned(),
            Self::Array(e, n) => format!("[{}; {n}]", e.default_expr()),
            Self::Tuple(items) => {
                let parts: Vec<String> = items.iter().map(Self::default_expr).collect();
                format!("({})", parts.join(", "))
            }
            Self::Struct(_) | Self::TableRow(_) => "Default::default()".to_owned(),
            Self::BitSet(bits) => format!("[0u32; {}]", (*bits).div_ceil(32).max(1)),
            Self::InputBuf(cap) => format!("[0u32; {}]", (*cap).max(1) * 2),
            Self::InlineStr(cap) => format!("[0u32; {}]", 1 + cap.div_ceil(4)),
        }
    }

    fn is_int(&self) -> bool {
        matches!(
            self,
            Self::U8
                | Self::U16
                | Self::U32
                | Self::U64
                | Self::I8
                | Self::I16
                | Self::I32
                | Self::I64
        )
    }

    fn is_float(&self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }

    fn is_vec(&self) -> Option<usize> {
        match self {
            Self::Vec2 => Some(2),
            Self::Vec3 => Some(3),
            Self::Vec4 => Some(4),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
enum PtrTarget {
    Resource {
        var_name: String,
    },
    QueryCol {
        query_idx: u32,
        slot_idx: usize,
        selective: bool,
        optional: bool,
        is_sparse: bool,
        projected: Option<(String, String, ValTy)>,
    },
    QueryRow {
        query_idx: u32,
        slot_idx: usize,
        row_idx_local: LocalId,
        selective: bool,
        optional: bool,
        is_sparse: bool,
        projected: Option<(String, String, ValTy)>,
    },
    EntityRow {
        query_idx: u32,
        slot_idx: usize,
        entity_local: LocalId,
        optional: bool,
        projected: Option<(String, String, ValTy)>,
    },
    EntitiesSlice {
        query_idx: u32,
    },
    TriggerPayload,
    ParamPtr {
        var_name: String,
        layout_key: String,
    },
    Field {
        base: Box<PtrTarget>,
        field: String,
    },
    SlotRef {
        slot_local: LocalId,
    },
}

#[derive(Clone)]
struct DedupTermSlot {
    slot_idx: usize,
    canonical: String,
    struct_name: String,
    mode: TermAccessMode,
}

struct QueryEmitPlan {
    query_idx: u32,
    param_name: String,
    param_set_idx: Option<usize>,
    is_sparse: bool,
    needs_entity: bool,
    has_any_mut: bool,
    slots: Vec<DedupTermSlot>,
    term_to_slot: HashMap<u32, usize>,
    with_filters: Vec<String>,
    without_filters: Vec<String>,
}

struct ChunkLoopInfo {
    hdr_bb: BlockId,
    query_idx: u32,
    chunk_body_bb: BlockId,
    exit_bb: BlockId,
    is_up_cascade: bool,
    is_pset_snap: bool,
    up_relation: Option<String>,
    loop_blocks: HashSet<BlockId>,
    use_par: bool,
}

impl ChunkLoopInfo {
    const fn is_1row(&self) -> bool {
        self.is_up_cascade || self.is_pset_snap
    }
}

fn emit_helper_functions(out: &mut String, ctx: &NativeCtx<'_>) -> Result<(), CodegenError> {
    for hf in &ctx.mir.fns {
        emit_single_function(out, hf, ctx)?;
    }
    Ok(())
}

fn emit_native_functions(out: &mut String, ctx: &NativeCtx<'_>) -> Result<(), CodegenError> {
    for func in &ctx.mir.functions {
        emit_single_function(out, func, ctx)?;
    }
    Ok(())
}

fn build_query_plans(func: &MirFunction, ctx: &NativeCtx<'_>) -> Vec<QueryEmitPlan> {
    let mut plans = Vec::with_capacity(func.query_bindings.len());
    for qb in &func.query_bindings {
        let mut slots: Vec<DedupTermSlot> = Vec::new();
        let mut term_to_slot = HashMap::new();
        let mut with_filters = Vec::new();
        let mut without_filters = Vec::new();

        for wf in &qb.with_filters {
            if let Some(sname) = ctx.resolve_ecs_struct_name(wf)
                && !with_filters.contains(&sname)
            {
                with_filters.push(sname);
            }
        }
        for wof in &qb.without_filters {
            if let Some(sname) = ctx.resolve_ecs_struct_name(wof)
                && !without_filters.contains(&sname)
            {
                without_filters.push(sname);
            }
        }

        let mut is_sparse = false;
        for term in &qb.terms {
            match term.mode {
                TermAccessMode::With => {
                    if let Some(sname) = ctx.resolve_ecs_struct_name(&term.canonical_component) {
                        if let Some(le) = ctx.find_layout_entry(&term.canonical_component)
                            && (le.layout.component_flags
                                & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET)
                                != 0
                        {
                            is_sparse = true;
                        }
                        if !with_filters.contains(&sname) {
                            with_filters.push(sname);
                        }
                    }
                    continue;
                }
                TermAccessMode::Without => {
                    if let Some(sname) = ctx.resolve_ecs_struct_name(&term.canonical_component) {
                        if let Some(le) = ctx.find_layout_entry(&term.canonical_component)
                            && (le.layout.component_flags
                                & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET)
                                != 0
                        {
                            is_sparse = true;
                        }
                        if !without_filters.contains(&sname) {
                            without_filters.push(sname);
                        }
                    }
                    continue;
                }
                _ => {}
            }

            if term.is_sparse {
                is_sparse = true;
            }
            if let Some(le) = ctx.find_layout_entry(&term.canonical_component)
                && (le.layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET) != 0
            {
                is_sparse = true;
            }
            let Some(struct_name) = ctx.resolve_ecs_struct_name(&term.canonical_component) else {
                continue;
            };
            let canonical = ctx
                .find_layout_entry(&term.canonical_component)
                .map_or_else(
                    || term.canonical_component.clone(),
                    |e| e.layout.canonical_name.clone(),
                );

            if let Some(existing_idx) = slots.iter().position(|s| s.canonical == canonical) {
                let merged = merge_term_access_mode(slots[existing_idx].mode, term.mode);
                slots[existing_idx].mode = merged;
                term_to_slot.insert(term.term_idx, existing_idx);
            } else {
                let sidx = slots.len();
                slots.push(DedupTermSlot {
                    slot_idx: sidx,
                    canonical,
                    struct_name,
                    mode: term.mode,
                });
                term_to_slot.insert(term.term_idx, sidx);
            }
        }

        // Check if Entity is referenced for this query, or if all data slots are optional / empty.
        let uses_entities = func.blocks.iter().any(|bb| {
            bb.stmts.iter().any(|s| {
                matches!(
                    s.inst,
                    Inst::IterEntities { query_idx } if query_idx == qb.query_idx
                )
            })
        });
        let all_optional_or_empty = slots.is_empty()
            || slots.iter().all(|s| {
                matches!(
                    s.mode,
                    TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite
                )
            });
        let needs_entity =
            !qb.is_point_lookup && (uses_entities || all_optional_or_empty || is_sparse);
        let has_any_mut = slots.iter().any(|s| s.mode.is_mutable());

        plans.push(QueryEmitPlan {
            query_idx: qb.query_idx,
            param_name: format!("q_{}", qb.query_idx),
            param_set_idx: None,
            is_sparse,
            needs_entity,
            has_any_mut,
            slots,
            term_to_slot,
            with_filters,
            without_filters,
        });
    }

    // Detect conflicting queries in the same function (for ParamSet grouping).
    let mut conflicting = vec![false; plans.len()];
    for i in 0..plans.len() {
        for j in (i + 1)..plans.len() {
            if queries_conflict(&plans[i], &plans[j]) {
                conflicting[i] = true;
                conflicting[j] = true;
            }
        }
    }
    let mut pset_idx = 0usize;
    for i in 0..plans.len() {
        if conflicting[i] {
            plans[i].param_set_idx = Some(pset_idx);
            let is_pt = func
                .query_bindings
                .iter()
                .find(|qb| qb.query_idx == plans[i].query_idx)
                .is_some_and(|qb| qb.is_point_lookup);
            if !is_pt {
                plans[i].needs_entity = true;
            }
            pset_idx += 1;
        }
    }

    plans
}

fn queries_conflict(a: &QueryEmitPlan, b: &QueryEmitPlan) -> bool {
    let a_with: HashSet<&str> = a.with_filters.iter().map(String::as_str).collect();
    let a_without: HashSet<&str> = a.without_filters.iter().map(String::as_str).collect();
    let b_with: HashSet<&str> = b.with_filters.iter().map(String::as_str).collect();
    let b_without: HashSet<&str> = b.without_filters.iter().map(String::as_str).collect();
    if !a_with.is_disjoint(&b_without) || !b_with.is_disjoint(&a_without) {
        return false;
    }
    for sa in &a.slots {
        for sb in &b.slots {
            if sa.struct_name == sb.struct_name && (sa.mode.is_mutable() || sb.mode.is_mutable()) {
                return true;
            }
        }
    }
    false
}

fn merge_term_access_mode(a: TermAccessMode, b: TermAccessMode) -> TermAccessMode {
    if a == b {
        return a;
    }
    match (a, b) {
        (TermAccessMode::Write, _) | (_, TermAccessMode::Write) => TermAccessMode::Write,
        (TermAccessMode::SelectiveWrite, _) | (_, TermAccessMode::SelectiveWrite) => {
            TermAccessMode::SelectiveWrite
        }
        (TermAccessMode::Read, _) | (_, TermAccessMode::Read) => TermAccessMode::Read,
        (TermAccessMode::OptionalWrite, _) | (_, TermAccessMode::OptionalWrite) => {
            TermAccessMode::OptionalWrite
        }
        _ => a,
    }
}

fn query_rust_types(plan: &QueryEmitPlan) -> (String, String) {
    let mut d_parts = Vec::new();
    if plan.needs_entity {
        d_parts.push("Entity".to_owned());
    }
    for slot in &plan.slots {
        let s = match slot.mode {
            TermAccessMode::Write | TermAccessMode::SelectiveWrite => {
                format!("&'static mut {}", slot.struct_name)
            }
            TermAccessMode::Read => format!("&'static {}", slot.struct_name),
            TermAccessMode::OptionalWrite => format!("Option<&'static mut {}>", slot.struct_name),
            TermAccessMode::OptionalRead => format!("Option<&'static {}>", slot.struct_name),
            _ => continue,
        };
        d_parts.push(s);
    }
    let data_ty = if d_parts.is_empty() {
        "Entity".to_owned()
    } else {
        format!("({},)", d_parts.join(", "))
    };
    let mut f_parts = Vec::new();
    for wf in &plan.with_filters {
        f_parts.push(format!("With<{wf}>"));
    }
    for wof in &plan.without_filters {
        f_parts.push(format!("Without<{wof}>"));
    }
    let filter_ty = if f_parts.is_empty() {
        "()".to_owned()
    } else {
        format!("({},)", f_parts.join(", "))
    };
    (data_ty, filter_ty)
}

fn resolve_spatial_name(ctx: &NativeCtx<'_>, func: &MirFunction, raw: &str) -> String {
    if ctx.spatial_by_key.contains_key(raw) {
        return raw.to_owned();
    }
    for rb in &func.resources {
        if (rb.param_name == raw || rb.resource_name == raw || rb.canonical_name == raw)
            && ctx.spatial_by_key.contains_key(rb.resource_name.as_str())
        {
            return rb.resource_name.clone();
        }
    }
    if let Some(sp) = ctx.spatial_by_key.values().find(|sp| {
        sp.resource_layout.canonical_name == raw
            || sp.resource_layout.canonical_name.rsplit("::").next() == Some(raw)
    }) {
        return sp.name.clone();
    }
    raw.to_owned()
}

fn projected_field_for_term(
    func: &MirFunction,
    query_idx: u32,
    term_idx: u32,
    ctx: &NativeCtx<'_>,
) -> Option<(String, String, ValTy)> {
    let qb = func
        .query_bindings
        .iter()
        .find(|q| q.query_idx == query_idx)?;
    let term = qb.terms.iter().find(|t| t.term_idx == term_idx)?;
    let pf = term.field_name.as_ref()?;
    let sf = ctx.resolve_field_info(&term.canonical_component, pf)?;
    let vt = ValTy::from_solved_field(sf, ctx);
    Some((term.canonical_component.clone(), pf.clone(), vt))
}

fn compute_reachable_blocks(func: &MirFunction) -> HashSet<BlockId> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    if let Some(entry) = func.blocks.first() {
        visited.insert(entry.id);
        queue.push_back(entry.id);
    }
    while let Some(bid) = queue.pop_front() {
        if let Some(bb) = func.blocks.iter().find(|b| b.id == bid) {
            for succ in terminator_succs(&bb.terminator) {
                if visited.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }
    }
    visited
}

fn collect_chunk_loops(func: &MirFunction, query_plans: &[QueryEmitPlan]) -> Vec<ChunkLoopInfo> {
    let reachable = compute_reachable_blocks(func);
    let mut loops = Vec::new();
    for bb in &func.blocks {
        if !reachable.contains(&bb.id) {
            continue;
        }
        let found = bb.stmts.iter().find_map(|s| match &s.inst {
            Inst::IterNextChunk { query_idx } => Some((*query_idx, false, None, s.dst)),
            Inst::IterUpCascade {
                query_idx,
                relation,
            } => Some((*query_idx, true, Some(relation.clone()), s.dst)),
            _ => None,
        });
        let Some((query_idx, is_up_cascade, up_relation, _)) = found else {
            continue;
        };
        let Terminator::Branch {
            then_bb, else_bb, ..
        } = bb.terminator
        else {
            continue;
        };

        let mut loop_blocks = HashSet::new();
        let mut queue = VecDeque::new();
        loop_blocks.insert(then_bb);
        queue.push_back(then_bb);
        while let Some(cur) = queue.pop_front() {
            for succ in terminator_succs(&func.blocks[cur.0 as usize].terminator) {
                if succ != bb.id && succ != else_bb && loop_blocks.insert(succ) {
                    queue.push_back(succ);
                }
            }
        }

        let plan = query_plans.iter().find(|p| p.query_idx == query_idx);
        let is_sparse = plan.is_some_and(|p| p.is_sparse);
        let in_param_set = plan.is_some_and(|p| p.param_set_idx.is_some());
        let is_pset_snap = in_param_set
            && !is_up_cascade
            && loop_blocks.iter().any(|bid| {
                func.blocks[bid.0 as usize]
                    .stmts
                    .iter()
                    .any(|s| match s.inst {
                        Inst::EntityGet { query_idx: q2, .. }
                        | Inst::EntityGetMut { query_idx: q2, .. }
                        | Inst::IterNextChunk { query_idx: q2 }
                            if q2 != query_idx =>
                        {
                            query_plans
                                .iter()
                                .find(|p| p.query_idx == q2)
                                .is_some_and(|p| p.param_set_idx.is_some())
                        }
                        _ => false,
                    })
            });
        let has_unsupported_par_write = has_non_reducible_outer_slot_write(func, &loop_blocks);
        let use_par = func.par_chunk.is_some()
            && !is_sparse
            && !is_up_cascade
            && !in_param_set
            && !has_unsupported_par_write;

        loops.push(ChunkLoopInfo {
            hdr_bb: bb.id,
            query_idx,
            chunk_body_bb: then_bb,
            exit_bb: else_bb,
            is_up_cascade,
            is_pset_snap,
            up_relation,
            loop_blocks,
            use_par,
        });
    }
    loops
}

fn has_non_reducible_outer_slot_write(func: &MirFunction, loop_blocks: &HashSet<BlockId>) -> bool {
    let mut inner_slots = HashSet::new();
    let mut reduce_slots = HashSet::new();
    let mut reduce_locals = HashSet::new();

    for &bid in loop_blocks {
        for s in &func.blocks[bid.0 as usize].stmts {
            if let Inst::SlotAlloc { .. } = s.inst
                && let Some(d) = s.dst
            {
                inner_slots.insert(d);
            }
            if let Inst::ReduceAccum { .. } = s.inst
                && let Some(d) = s.dst
            {
                reduce_locals.insert(d);
            }
        }
    }
    for &bid in loop_blocks {
        for s in &func.blocks[bid.0 as usize].stmts {
            if let Inst::SlotStore { slot, val } = s.inst
                && !inner_slots.contains(&slot)
            {
                if reduce_locals.contains(&val) {
                    reduce_slots.insert(slot);
                } else {
                    return true;
                }
            }
        }
    }
    let _ = reduce_slots;
    false
}

fn terminator_succs(term: &Terminator) -> Vec<BlockId> {
    match term {
        Terminator::Return(_) => Vec::new(),
        Terminator::Goto(b) => vec![*b],
        Terminator::Branch {
            then_bb, else_bb, ..
        } => vec![*then_bb, *else_bb],
        Terminator::Switch {
            cases, default_bb, ..
        } => {
            let mut out: Vec<BlockId> = cases.iter().map(|(_, b)| *b).collect();
            out.push(*default_bb);
            out
        }
    }
}

#[derive(Clone)]
struct SpawnBatchCompSlot {
    struct_name: String,
    is_zst: bool,
}

#[derive(Clone)]
struct SpawnBatchPlan {
    id: usize,
    dst_local: LocalId,
    slots: Vec<SpawnBatchCompSlot>,
    bundle_ty: String,
    var_name: String,
    only_chunk_loop: Option<usize>,
}

struct FnAnalysis {
    val_tys: Vec<ValTy>,
    slot_tys: HashMap<LocalId, ValTy>,
    ptr_targets: HashMap<LocalId, PtrTarget>,
    res_map: BTreeMap<String, (String, bool, String)>, // canonical -> (var_name, mutable, struct_name)
    spatial_res_map: BTreeMap<String, (String, bool)>, // index_name -> (var_name, mutable)
    relation_res_map: BTreeMap<String, (String, bool)>, // rel_name -> (var_name, mutable)
    stream_writers: BTreeMap<String, String>,          // stream_name -> writer_var
    needs_commands: bool,
    needs_par_commands: bool,
    needs_named_objects: bool,
    named_objects_mut: bool,
    object_queries: BTreeMap<String, (String, String)>, // obj_name -> (q_var, primary_comp_struct)
    needs_trigger_stack: bool,
    has_checkpoint: bool,
    sp_lim_clamp: HashMap<LocalId, LocalId>, // sp_lim ConstInt(64) -> query_iter LocalId
    csr_pos_captures: HashMap<(usize, usize), String>, // (bb_idx, stmt_idx) -> index_name
    spawn_batches: Vec<SpawnBatchPlan>,
    batch_sources: HashMap<LocalId, BTreeSet<usize>>,
}

fn analyze_function(
    func: &MirFunction,
    ctx: &NativeCtx<'_>,
    query_plans: &[QueryEmitPlan],
    chunk_loops: &[ChunkLoopInfo],
) -> FnAnalysis {
    let mut val_tys: Vec<ValTy> = func
        .locals
        .iter()
        .map(|l| ValTy::from_mir(&l.ty, ctx))
        .collect();
    let mut slot_tys: HashMap<LocalId, ValTy> = HashMap::new();
    let mut ptr_targets: HashMap<LocalId, PtrTarget> = HashMap::new();
    let reachable_blocks = compute_reachable_blocks(func);
    let mut spawn_batches: Vec<SpawnBatchPlan> = Vec::new();
    let mut batch_sources: HashMap<LocalId, BTreeSet<usize>> = HashMap::new();

    // Pre-populate resources, params, streams, commands.
    let mut res_map: BTreeMap<String, (String, bool, String)> = BTreeMap::new();
    let mut spatial_res_map: BTreeMap<String, (String, bool)> = BTreeMap::new();
    let mut relation_res_map: BTreeMap<String, (String, bool)> = BTreeMap::new();
    let mut stream_writers: BTreeMap<String, String> = BTreeMap::new();
    let mut needs_commands = false;
    let has_par_loop = chunk_loops.iter().any(|c| c.use_par);
    let mut needs_named_objects = false;
    let mut named_objects_mut = false;
    let mut object_queries: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut needs_trigger_stack = false;
    let mut has_checkpoint = false;

    for rb in &func.resources {
        if let Some(entry) = ctx.find_layout_entry(&rb.canonical_name) {
            let vname = format!("res_{}", sanitize_ident(&entry.layout.canonical_name));
            let prev = res_map
                .get(&entry.layout.canonical_name)
                .map(|v| v.1)
                .unwrap_or(false);
            res_map.insert(
                entry.layout.canonical_name.clone(),
                (vname.clone(), prev || rb.mutable, entry.struct_name.clone()),
            );
            ptr_targets.insert(rb.ptr_local, PtrTarget::Resource { var_name: vname });
        }
    }

    for p in &func.params {
        if let Some(pl) = p.local {
            match p.kind {
                HirParamKind::Ref | HirParamKind::RefMut | HirParamKind::StreamIn => {
                    ptr_targets.insert(
                        pl,
                        PtrTarget::ParamPtr {
                            var_name: format!("arg_{}", sanitize_rust_ident(&p.name)),
                            layout_key: match &p.ty {
                                MirType::Named(n) => n.clone(),
                                _ => String::new(),
                            },
                        },
                    );
                }
                HirParamKind::ResRead | HirParamKind::ResWrite => {
                    if matches!(func.kind, MirFnKind::HelperFn) {
                        ptr_targets.insert(
                            pl,
                            PtrTarget::ParamPtr {
                                var_name: format!("arg_{}", sanitize_rust_ident(&p.name)),
                                layout_key: match &p.ty {
                                    MirType::Named(n) => n.clone(),
                                    _ => String::new(),
                                },
                            },
                        );
                    }
                }
                _ => {}
            }
        }
    }

    let par_blocks: HashSet<BlockId> = chunk_loops
        .iter()
        .filter(|c| c.use_par)
        .flat_map(|c| c.loop_blocks.iter().copied())
        .collect();

    for bb in &func.blocks {
        let in_par = par_blocks.contains(&bb.id);
        for st in &bb.stmts {
            match &st.inst {
                Inst::SlotAlloc { ty } => {
                    if let Some(d) = st.dst {
                        slot_tys.insert(d, ValTy::from_mir(ty, ctx));
                    }
                }
                Inst::ResRead { resource } | Inst::ResWrite { resource } => {
                    let is_mut = matches!(st.inst, Inst::ResWrite { .. });
                    if let Some(entry) = ctx.find_layout_entry(resource) {
                        let vname = format!("res_{}", sanitize_ident(&entry.layout.canonical_name));
                        let prev = res_map
                            .get(&entry.layout.canonical_name)
                            .map(|v| v.1)
                            .unwrap_or(false);
                        res_map.insert(
                            entry.layout.canonical_name.clone(),
                            (vname.clone(), prev || is_mut, entry.struct_name.clone()),
                        );
                        if let Some(d) = st.dst {
                            ptr_targets.insert(d, PtrTarget::Resource { var_name: vname });
                        }
                    }
                }
                Inst::SpatialRebuildCsr { index_name, .. } => {
                    let resolved = resolve_spatial_name(ctx, func, index_name);
                    let vname = format!("sp_res_{}", sanitize_ident(&resolved));
                    spatial_res_map.insert(resolved, (vname, true));
                }
                Inst::SpatialQueryDisc { grid_name, .. } => {
                    let resolved = resolve_spatial_name(ctx, func, grid_name);
                    let vname = format!("sp_res_{}", sanitize_ident(&resolved));
                    spatial_res_map.entry(resolved).or_insert((vname, false));
                }
                Inst::SpatialQuerySegmentAt { history_name, .. } => {
                    let resolved = resolve_spatial_name(ctx, func, history_name);
                    let vname = format!("sp_res_{}", sanitize_ident(&resolved));
                    spatial_res_map.entry(resolved).or_insert((vname, false));
                }
                Inst::CmdInsertRelation { relation, .. }
                | Inst::CmdRemoveRelation { relation, .. } => {
                    let vname = format!("rel_res_{}", sanitize_ident(relation));
                    relation_res_map.insert(relation.clone(), (vname, true));
                }
                Inst::IterUpCascade { relation, .. } => {
                    let vname = format!("rel_res_{}", sanitize_ident(relation));
                    relation_res_map
                        .entry(relation.clone())
                        .or_insert((vname, false));
                }
                Inst::StreamEmit { stream, .. } => {
                    if in_par {
                        needs_commands = true;
                    } else if let Some(entry) = ctx.find_layout_entry(stream) {
                        let mw_name = format!("mw_{}", sanitize_ident(stream));
                        stream_writers.insert(entry.layout.canonical_name.clone(), mw_name);
                    }
                }
                Inst::CmdSpawn { .. }
                | Inst::CmdSpawnBatch { .. }
                | Inst::SpawnBatchCommit { .. }
                | Inst::CmdDespawn { .. }
                | Inst::CmdDespawnAll { .. }
                | Inst::CmdInsert { .. }
                | Inst::CmdRemove { .. }
                | Inst::CmdTrigger { .. } => {
                    needs_commands = true;
                }
                Inst::SpawnBatchBegin { components, .. } => {
                    if reachable_blocks.contains(&bb.id)
                        && let Some(d) = st.dst
                    {
                        let mut slots: Vec<SpawnBatchCompSlot> = Vec::new();
                        for cname in components {
                            if let Some(sname) = ctx.resolve_ecs_struct_name(cname)
                                && !slots.iter().any(|s| s.struct_name == sname)
                            {
                                slots.push(SpawnBatchCompSlot {
                                    struct_name: sname,
                                    is_zst: ctx.is_zst_component(cname),
                                });
                            }
                        }
                        let ty_parts: Vec<String> =
                            slots.iter().map(|s| s.struct_name.clone()).collect();
                        let bundle_ty = format_bundle_tuple(&ty_parts);
                        let id = spawn_batches.len();
                        spawn_batches.push(SpawnBatchPlan {
                            id,
                            dst_local: d,
                            slots,
                            bundle_ty,
                            var_name: format!("__batch_buf_{id}"),
                            only_chunk_loop: None,
                        });
                        batch_sources.entry(d).or_default().insert(id);
                    }
                }
                Inst::CmdCheckpoint => {
                    has_checkpoint = true;
                }
                Inst::ResolveNamedObject { name } | Inst::BindNamedObject { name } => {
                    needs_named_objects = true;
                    if matches!(st.inst, Inst::BindNamedObject { .. }) {
                        named_objects_mut = true;
                    }
                    if let Some(obj) = ctx.objects_by_key.get(name.as_str())
                        && let Some(first_comp) = obj.components.first()
                        && let Some(sname) = ctx.resolve_ecs_struct_name(first_comp)
                    {
                        object_queries.insert(
                            name.clone(),
                            (format!("obj_q_{}", sanitize_ident(name)), sname),
                        );
                    }
                }
                Inst::TriggerTarget => {
                    if let MirFnKind::Observer { ref event, .. } = func.kind
                        && let Some(ev_entry) = ctx.find_layout_entry(event)
                        && !ctx.entity_events.contains(&ev_entry.layout.canonical_name)
                    {
                        needs_trigger_stack = true;
                    }
                }
                _ => {}
            }
        }
    }

    if let MirFnKind::Observer {
        ref event,
        ref target_comp,
    } = func.kind
        && target_comp.is_some()
        && let Some(ev_entry) = ctx.find_layout_entry(event)
        && !ctx.entity_events.contains(&ev_entry.layout.canonical_name)
    {
        needs_trigger_stack = true;
    }

    // Fixed-point propagation for ValTy & PtrTarget across instructions.
    for _ in 0..4 {
        for bb in &func.blocks {
            for st in &bb.stmts {
                match &st.inst {
                    Inst::Copy { val } => {
                        if let Some(d) = st.dst {
                            val_tys[d.0 as usize] = val_tys[val.0 as usize].clone();
                            if let Some(pt) = ptr_targets.get(val).cloned() {
                                ptr_targets.insert(d, pt);
                            }
                            if let Some(srcs) = batch_sources.get(val).cloned() {
                                batch_sources.entry(d).or_default().extend(srcs);
                            }
                        }
                    }
                    Inst::VecInsert { vec, .. } => {
                        if let Some(d) = st.dst {
                            val_tys[d.0 as usize] = val_tys[vec.0 as usize].clone();
                        }
                    }
                    Inst::SlotStore { slot, val } => {
                        if let Some(srcs) = batch_sources.get(val).cloned() {
                            batch_sources.entry(*slot).or_default().extend(srcs);
                        }
                        let vt = &val_tys[val.0 as usize];
                        let is_rich = matches!(
                            vt,
                            ValTy::TableRow(_)
                                | ValTy::Struct(_)
                                | ValTy::Array(_, _)
                                | ValTy::Tuple(_)
                                | ValTy::BitSet(_)
                                | ValTy::InputBuf(_)
                                | ValTy::InlineStr(_)
                                | ValTy::Entity
                                | ValTy::Vec2
                                | ValTy::Vec4
                        );
                        let cur = slot_tys.get(slot);
                        let should_update = (matches!(
                            cur,
                            None | Some(ValTy::Unit | ValTy::PtrMarker | ValTy::U64 | ValTy::I64)
                        ) && *vt != ValTy::Unit
                            && *vt != ValTy::PtrMarker)
                            || (matches!(cur, Some(ValTy::Vec3)) && *vt == ValTy::Vec2)
                            || (is_rich && cur != Some(vt));
                        if should_update {
                            slot_tys.insert(*slot, vt.clone());
                        }
                    }
                    Inst::SlotLoad { slot } => {
                        if let Some(d) = st.dst {
                            if let Some(srcs) = batch_sources.get(slot).cloned() {
                                batch_sources.entry(d).or_default().extend(srcs);
                            }
                            if let Some(st_ty) = slot_tys.get(slot)
                                && *st_ty != ValTy::Unit
                                && *st_ty != ValTy::PtrMarker
                            {
                                val_tys[d.0 as usize] = st_ty.clone();
                            }
                        }
                    }
                    Inst::IterEntities { query_idx } => {
                        if let Some(d) = st.dst {
                            ptr_targets.insert(
                                d,
                                PtrTarget::EntitiesSlice {
                                    query_idx: *query_idx,
                                },
                            );
                        }
                    }
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
                    }
                    | Inst::IterColRowsRead {
                        query_idx,
                        term_idx,
                        ..
                    }
                    | Inst::IterColRowsWrite {
                        query_idx,
                        term_idx,
                        ..
                    } => {
                        if let Some(d) = st.dst
                            && let Some(qp) = query_plans.iter().find(|p| p.query_idx == *query_idx)
                            && let Some(&sidx) = qp.term_to_slot.get(term_idx)
                        {
                            let slot = &qp.slots[sidx];
                            let projected =
                                projected_field_for_term(func, *query_idx, *term_idx, ctx);
                            ptr_targets.insert(
                                d,
                                PtrTarget::QueryCol {
                                    query_idx: *query_idx,
                                    slot_idx: sidx,
                                    selective: slot.mode == TermAccessMode::SelectiveWrite
                                        || matches!(st.inst, Inst::IterColWriteUntracked { .. }),
                                    optional: matches!(
                                        slot.mode,
                                        TermAccessMode::OptionalRead
                                            | TermAccessMode::OptionalWrite
                                    ),
                                    is_sparse: qp.is_sparse,
                                    projected,
                                },
                            );
                        }
                    }
                    Inst::RowPtr {
                        col_ptr, row_idx, ..
                    } => {
                        if let Some(d) = st.dst
                            && let Some(PtrTarget::QueryCol {
                                query_idx,
                                slot_idx,
                                selective,
                                optional,
                                is_sparse,
                                projected,
                            }) = ptr_targets.get(col_ptr).cloned()
                        {
                            ptr_targets.insert(
                                d,
                                PtrTarget::QueryRow {
                                    query_idx,
                                    slot_idx,
                                    row_idx_local: *row_idx,
                                    selective,
                                    optional,
                                    is_sparse,
                                    projected,
                                },
                            );
                        }
                    }
                    Inst::EntityGet {
                        query_idx,
                        term_idx,
                        entity,
                        ..
                    }
                    | Inst::EntityGetMut {
                        query_idx,
                        term_idx,
                        entity,
                        ..
                    } => {
                        if let Some(d) = st.dst {
                            val_tys[d.0 as usize] = ValTy::Bool;
                            if let Some(qp) = query_plans.iter().find(|p| p.query_idx == *query_idx)
                                && let Some(&sidx) = qp.term_to_slot.get(term_idx)
                            {
                                let slot = &qp.slots[sidx];
                                let projected =
                                    projected_field_for_term(func, *query_idx, *term_idx, ctx);
                                ptr_targets.insert(
                                    d,
                                    PtrTarget::EntityRow {
                                        query_idx: *query_idx,
                                        slot_idx: sidx,
                                        entity_local: *entity,
                                        optional: matches!(
                                            slot.mode,
                                            TermAccessMode::OptionalRead
                                                | TermAccessMode::OptionalWrite
                                        ),
                                        projected,
                                    },
                                );
                            }
                        }
                    }
                    Inst::TriggerPayload { .. } => {
                        if let Some(d) = st.dst {
                            ptr_targets.insert(d, PtrTarget::TriggerPayload);
                        }
                    }
                    Inst::MigrateSrcPtr { layout_key } => {
                        if let Some(d) = st.dst {
                            ptr_targets.insert(
                                d,
                                PtrTarget::ParamPtr {
                                    var_name: "old_row".to_owned(),
                                    layout_key: layout_key.clone(),
                                },
                            );
                        }
                    }
                    Inst::MigrateDstPtr { layout_key } => {
                        if let Some(d) = st.dst {
                            ptr_targets.insert(
                                d,
                                PtrTarget::ParamPtr {
                                    var_name: "dst_row".to_owned(),
                                    layout_key: layout_key.clone(),
                                },
                            );
                        }
                    }
                    Inst::FieldPtr {
                        base_ptr, field, ..
                    } => {
                        if let Some(d) = st.dst {
                            if let Some(base) = ptr_targets.get(base_ptr).cloned() {
                                ptr_targets.insert(
                                    d,
                                    PtrTarget::Field {
                                        base: Box::new(base),
                                        field: field.clone(),
                                    },
                                );
                            } else {
                                ptr_targets.insert(
                                    d,
                                    PtrTarget::SlotRef {
                                        slot_local: *base_ptr,
                                    },
                                );
                            }
                        }
                    }
                    Inst::FieldLoad {
                        base_ptr,
                        layout_key,
                        field,
                        ..
                    } => {
                        if let Some(d) = st.dst {
                            if let Some(sf) = ctx.resolve_field_info(layout_key, field) {
                                let fvt = ValTy::from_solved_field(sf, ctx);
                                if matches!(fvt, ValTy::BitSet(_) | ValTy::InputBuf(_)) {
                                    val_tys[d.0 as usize] = fvt;
                                }
                            } else if let Some(tb) =
                                ctx.tables_by_key.get(layout_key.as_str()).or_else(|| {
                                    if let ValTy::TableRow(ref tn) = val_tys[base_ptr.0 as usize] {
                                        ctx.tables_by_key.get(tn.as_str())
                                    } else {
                                        None
                                    }
                                })
                                && let Some((_, fty)) =
                                    tb.fields.iter().find(|(fnm, _)| fnm == field)
                            {
                                val_tys[d.0 as usize] = ValTy::from_sema_ty(fty, ctx);
                            }
                        }
                    }
                    Inst::TableLoad {
                        table_name, field, ..
                    } => {
                        if let Some(d) = st.dst
                            && let Some(tb) = ctx.tables_by_key.get(table_name.as_str())
                        {
                            if field.is_empty() {
                                val_tys[d.0 as usize] = ValTy::TableRow(table_name.clone());
                            } else if let Some((_, fty)) =
                                tb.fields.iter().find(|(fnm, _)| fnm == field)
                            {
                                val_tys[d.0 as usize] = ValTy::from_sema_ty(fty, ctx);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Detect `sp_lim` spatial loop limit constants so we don't iterate 64 empty slots.
    let mut sp_lim_clamp = HashMap::new();
    for bb in &func.blocks {
        for st in &bb.stmts {
            if let Inst::EntityAtRow { entities_ptr, .. } = st.inst
                && val_tys[entities_ptr.0 as usize] == ValTy::QueryIter
            {
                // Find the Branch in predecessors comparing against sp_lim.
                for pbb in &func.blocks {
                    if let Terminator::Branch { cond, then_bb, .. } = pbb.terminator
                        && then_bb == bb.id
                        && let Some(cmp_stmt) = pbb.stmts.iter().find(|s| s.dst == Some(cond))
                        && let Inst::BinOp { rhs, .. } = cmp_stmt.inst
                    {
                        sp_lim_clamp.insert(rhs, entities_ptr);
                    }
                }
            }
        }
    }

    // Detect Pass 2 CSR position captures in `SynthesizedSpatialCsr`.
    let mut csr_pos_captures = HashMap::new();
    if matches!(func.kind, MirFnKind::SynthesizedSpatialCsr)
        && let Some(idx_name) = func.blocks.iter().flat_map(|b| &b.stmts).find_map(|s| {
            if let Inst::SpatialRebuildCsr { index_name, .. } = &s.inst {
                Some(index_name.clone())
            } else {
                None
            }
        })
    {
        for (bi, bb) in func.blocks.iter().enumerate() {
            let has_ent = bb
                .stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::EntityAtRow { .. }));
            if has_ent {
                for (si, st) in bb.stmts.iter().enumerate() {
                    if matches!(st.inst, Inst::FieldLoad { .. }) {
                        csr_pos_captures.insert((bi, si), idx_name.clone());
                    }
                }
            }
        }
    }

    let mut block_to_loop: HashMap<BlockId, usize> = HashMap::new();
    for (li, cl) in chunk_loops.iter().enumerate() {
        for &bid in &cl.loop_blocks {
            block_to_loop.insert(bid, li);
        }
    }
    for bp in &mut spawn_batches {
        let mut seen_outside = false;
        let mut loops_used: HashSet<usize> = HashSet::new();
        for bb in &func.blocks {
            if !reachable_blocks.contains(&bb.id) {
                continue;
            }
            let loop_opt = block_to_loop.get(&bb.id).copied();
            for st in &bb.stmts {
                let touches_batch = match &st.inst {
                    Inst::SpawnBatchBegin { .. } => st.dst == Some(bp.dst_local),
                    Inst::SpawnBatchPush { batch, .. } | Inst::SpawnBatchCommit { batch } => {
                        batch_sources
                            .get(batch)
                            .is_some_and(|srcs| srcs.contains(&bp.id))
                    }
                    _ => false,
                };
                if touches_batch {
                    if let Some(li) = loop_opt {
                        loops_used.insert(li);
                    } else {
                        seen_outside = true;
                    }
                }
            }
        }
        if !seen_outside && loops_used.len() == 1 {
            bp.only_chunk_loop = loops_used.into_iter().next();
        }
    }

    let needs_par_commands = needs_commands && has_par_loop;
    FnAnalysis {
        val_tys,
        slot_tys,
        ptr_targets,
        res_map,
        spatial_res_map,
        relation_res_map,
        stream_writers,
        needs_commands: needs_commands && !has_par_loop,
        needs_par_commands,
        needs_named_objects,
        named_objects_mut,
        object_queries,
        needs_trigger_stack,
        has_checkpoint,
        sp_lim_clamp,
        csr_pos_captures,
        spawn_batches,
        batch_sources,
    }
}

fn emit_single_function(
    out: &mut String,
    func: &MirFunction,
    ctx: &NativeCtx<'_>,
) -> Result<(), CodegenError> {
    if func.blocks.is_empty() {
        let fname = sanitize_ident(&func.name);
        match &func.kind {
            MirFnKind::HelperFn => writeln!(out, "fn strata_fn_{fname}() {{}}\n").ok(),
            MirFnKind::Migration { .. } => writeln!(out, "pub fn strata_mig_{fname}() {{}}\n").ok(),
            MirFnKind::Observer { .. } => writeln!(out, "fn strata_obs_{fname}() {{}}\n").ok(),
            _ => writeln!(out, "fn strata_sys_{fname}() {{}}\n").ok(),
        };
        return Ok(());
    }

    let query_plans = build_query_plans(func, ctx);
    let chunk_loops = collect_chunk_loops(func, &query_plans);
    let analysis = analyze_function(func, ctx, &query_plans, &chunk_loops);

    let fname = sanitize_ident(&func.name);
    let mut sig_params = Vec::new();
    let mut is_observer = false;
    let mut obs_event_info: Option<(String, bool, Option<String>)> = None;

    match &func.kind {
        MirFnKind::HelperFn => {
            for p in &func.params {
                let pname = format!("arg_{}", sanitize_rust_ident(&p.name));
                let pty = match p.kind {
                    HirParamKind::Ref => {
                        let s = p
                            .local
                            .and_then(|l| analysis.ptr_targets.get(&l))
                            .and_then(|pt| match pt {
                                PtrTarget::ParamPtr { layout_key, .. } => ctx
                                    .find_layout_entry(layout_key)
                                    .map(|e| e.struct_name.clone()),
                                _ => None,
                            })
                            .unwrap_or_else(|| "()".to_owned());
                        format!("&{s}")
                    }
                    HirParamKind::RefMut => {
                        let s = p
                            .local
                            .and_then(|l| analysis.ptr_targets.get(&l))
                            .and_then(|pt| match pt {
                                PtrTarget::ParamPtr { layout_key, .. } => ctx
                                    .find_layout_entry(layout_key)
                                    .map(|e| e.struct_name.clone()),
                                _ => None,
                            })
                            .unwrap_or_else(|| "()".to_owned());
                        format!("&mut {s}")
                    }
                    _ => ValTy::from_mir(&p.ty, ctx).rust_type(),
                };
                sig_params.push(format!("{pname}: {pty}"));
            }
            let ret_ty = ValTy::from_mir(&func.ret_ty, ctx).rust_type();
            if ret_ty == "()" {
                writeln!(
                    out,
                    "pub(crate) fn strata_fn_{fname}({}) {{",
                    sig_params.join(", ")
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "pub(crate) fn strata_fn_{fname}({}) -> {ret_ty} {{",
                    sig_params.join(", ")
                )
                .ok();
            }
        }
        MirFnKind::Migration {
            src_layout,
            dst_layout,
            ..
        } => {
            let src_s = ctx
                .find_layout_entry(src_layout)
                .map_or_else(|| "()".to_owned(), |e| e.struct_name.clone());
            let dst_s = ctx
                .find_layout_entry(dst_layout)
                .map_or_else(|| "()".to_owned(), |e| e.struct_name.clone());
            writeln!(
                out,
                "pub fn strata_mig_{fname}(old_row: &{src_s}, dst_row: &mut {dst_s}) {{"
            )
            .ok();
        }
        MirFnKind::Observer { event, target_comp } => {
            is_observer = true;
            let ev_entry = ctx.find_layout_entry(event);
            let ev_struct = ev_entry
                .as_ref()
                .map_or_else(|| "()".to_owned(), |e| e.struct_name.clone());
            let is_entity_ev = ev_entry
                .as_ref()
                .is_some_and(|e| ctx.entity_events.contains(&e.layout.canonical_name));
            obs_event_info = Some((ev_struct.clone(), is_entity_ev, target_comp.clone()));
            sig_params.push(format!("on: On<{ev_struct}>"));
        }
        _ => {}
    }

    if !matches!(func.kind, MirFnKind::HelperFn | MirFnKind::Migration { .. }) {
        // Resources
        for (vname, is_mut, sname) in analysis.res_map.values() {
            if *is_mut {
                sig_params.push(format!("mut {vname}: ResMut<{sname}>"));
            } else {
                sig_params.push(format!("{vname}: Res<{sname}>"));
            }
        }
        for (idx_name, (vname, is_mut)) in &analysis.spatial_res_map {
            let sname = format!("StrataSpatialBacking_{}", sanitize_ident(idx_name));
            if *is_mut {
                sig_params.push(format!("mut {vname}: ResMut<{sname}>"));
            } else {
                sig_params.push(format!("{vname}: Res<{sname}>"));
            }
        }
        for (rel_name, (vname, is_mut)) in &analysis.relation_res_map {
            let rname = format!("StrataRelation_{}", sanitize_ident(rel_name));
            if *is_mut {
                sig_params.push(format!("mut {vname}: ResMut<{rname}>"));
            } else {
                sig_params.push(format!("{vname}: Res<{rname}>"));
            }
        }
        for (canon_stream, mw_name) in &analysis.stream_writers {
            if let Some(entry) = ctx.find_layout_entry(canon_stream) {
                sig_params.push(format!(
                    "mut {mw_name}: MessageWriter<{}>",
                    entry.struct_name
                ));
            }
        }
        if analysis.needs_par_commands {
            sig_params.push("par_commands: ParallelCommands".to_owned());
        } else if analysis.needs_commands {
            sig_params.push("mut commands: Commands".to_owned());
        }
        if analysis.needs_named_objects {
            if analysis.named_objects_mut {
                sig_params.push("mut named_objects: ResMut<StrataNamedObjects>".to_owned());
            } else {
                sig_params.push("named_objects: Res<StrataNamedObjects>".to_owned());
            }
        }
        for (q_var, comp_struct) in analysis.object_queries.values() {
            sig_params.push(format!("{q_var}: Query<Entity, With<{comp_struct}>>"));
        }
        if analysis.needs_trigger_stack {
            sig_params.push("trigger_targets: Res<StrataTriggerTargetStack>".to_owned());
        }
        if let Some((_, _, Some(ref tc))) = obs_event_info
            && let Some(tc_struct) = ctx.resolve_ecs_struct_name(tc)
        {
            sig_params.push(format!("obs_target_q: Query<(), With<{tc_struct}>>"));
        }

        // Queries: non-ParamSet direct Query params + single ParamSet if conflicts exist.
        let mut pset_types = Vec::new();
        for qp in &query_plans {
            let (d_ty, f_ty) = query_rust_types(qp);
            if qp.param_set_idx.is_some() {
                pset_types.push(format!("Query<'static, 'static, {d_ty}, {f_ty}>"));
            } else if qp.has_any_mut {
                sig_params.push(format!("mut {}: Query<{d_ty}, {f_ty}>", qp.param_name));
            } else {
                sig_params.push(format!("{}: Query<{d_ty}, {f_ty}>", qp.param_name));
            }
        }
        if !pset_types.is_empty() {
            sig_params.push(format!("mut q_set: ParamSet<({})>", pset_types.join(", ")));
        }

        if is_observer {
            writeln!(out, "fn strata_obs_{fname}({}) {{", sig_params.join(", ")).ok();
        } else {
            writeln!(out, "fn strata_sys_{fname}({}) {{", sig_params.join(", ")).ok();
        }
    }

    // Observer target component guard
    if let Some((_, is_entity_ev, Some(_))) = &obs_event_info {
        if *is_entity_ev {
            writeln!(
                out,
                "    if obs_target_q.get(on.event().event_target()).is_err() {{ return; }}"
            )
            .ok();
        } else {
            writeln!(
                out,
                "    let __obs_tgt = trigger_targets.0.last().copied().unwrap_or(FfiEntity::NULL);\n\
                 \x20   let Some(__obs_ent) = Entity::try_from_bits(__obs_tgt.to_bits()) else {{ return; }};\n\
                 \x20   if obs_target_q.get(__obs_ent).is_err() {{ return; }}"
            )
            .ok();
        }
    }

    // Bind `Value` parameters into their `SlotAlloc` locals for helper functions.
    for p in &func.params {
        if matches!(func.kind, MirFnKind::HelperFn)
            && p.kind == HirParamKind::Value
            && let Some(pl) = p.local
        {
            let vt = &analysis.val_tys[pl.0 as usize];
            writeln!(
                out,
                "    let mut __loc_{}: {} = arg_{};",
                pl.0,
                vt.rust_type(),
                sanitize_rust_ident(&p.name)
            )
            .ok();
        }
    }

    // Determine which locals are strictly inside one chunk loop vs outer function scope.
    let mut block_to_loop: HashMap<BlockId, usize> = HashMap::new();
    for (li, cl) in chunk_loops.iter().enumerate() {
        for &bid in &cl.loop_blocks {
            block_to_loop.insert(bid, li);
        }
    }

    let reachable_blocks = compute_reachable_blocks(func);
    let mut local_used_outer = vec![false; func.locals.len()];
    let mut local_loops: Vec<HashSet<usize>> = vec![HashSet::new(); func.locals.len()];
    for p in &func.params {
        if let Some(pl) = p.local {
            local_used_outer[pl.0 as usize] = true;
        }
    }
    for bb in &func.blocks {
        if !reachable_blocks.contains(&bb.id) {
            continue;
        }
        let loop_opt = block_to_loop.get(&bb.id).copied();
        for st in &bb.stmts {
            if let Some(d) = st.dst {
                if let Some(li) = loop_opt {
                    local_loops[d.0 as usize].insert(li);
                } else {
                    local_used_outer[d.0 as usize] = true;
                }
            }
            for l in inst_used_locals(&st.inst) {
                if let Some(li) = loop_opt {
                    local_loops[l.0 as usize].insert(li);
                } else {
                    local_used_outer[l.0 as usize] = true;
                }
            }
        }
        for l in terminator_used_locals(&bb.terminator) {
            if let Some(li) = loop_opt {
                local_loops[l.0 as usize].insert(li);
            } else {
                local_used_outer[l.0 as usize] = true;
            }
        }
    }

    // Declare outer locals (excluding PtrMarker unless unused, and excluding Value helper params already bound).
    let param_value_locals: HashSet<LocalId> = if matches!(func.kind, MirFnKind::HelperFn) {
        func.params
            .iter()
            .filter(|p| p.kind == HirParamKind::Value)
            .filter_map(|p| p.local)
            .collect()
    } else {
        HashSet::new()
    };

    for (idx, vt) in analysis.val_tys.iter().enumerate() {
        let lid = LocalId(idx as u32);
        if param_value_locals.contains(&lid) {
            continue;
        }
        let is_outer = local_used_outer[idx] || local_loops[idx].len() > 1;
        if is_outer {
            if let Some(slot_vt) = analysis.slot_tys.get(&lid) {
                writeln!(
                    out,
                    "    let mut __slot_{idx}: {} = {};",
                    slot_vt.rust_type(),
                    slot_vt.default_expr()
                )
                .ok();
            } else if *vt != ValTy::PtrMarker && *vt != ValTy::Unit {
                writeln!(
                    out,
                    "    let mut __loc_{idx}: {} = {};",
                    vt.rust_type(),
                    vt.default_expr()
                )
                .ok();
            }
        }
    }

    for bp in &analysis.spawn_batches {
        if bp.only_chunk_loop.is_none() {
            writeln!(
                out,
                "    let mut {}: Vec<{}> = Vec::new();",
                bp.var_name, bp.bundle_ty
            )
            .ok();
        }
    }

    if !analysis.csr_pos_captures.is_empty() {
        for idx_name in analysis.csr_pos_captures.values().collect::<BTreeSet<_>>() {
            writeln!(
                out,
                "    let mut __csr_rows_{}: Vec<(Entity, [f32; 3])> = Vec::new();",
                sanitize_ident(idx_name)
            )
            .ok();
        }
    }

    if analysis.has_checkpoint {
        writeln!(
            out,
            "    enum __StrataTxCmd {{ Spawn(Box<dyn FnOnce(&mut Commands) + Send + Sync>) }}\n\
             \x20   let mut __tx_cmds: Vec<__StrataTxCmd> = Vec::new();\n\
             \x20   let mut __tx_active = false;"
        )
        .ok();
    }

    // Emit outer CFG loop
    writeln!(
        out,
        "    let mut __bb: u32 = 0;\n    loop {{\n        match __bb {{"
    )
    .ok();
    for bb in &func.blocks {
        if !reachable_blocks.contains(&bb.id) || block_to_loop.contains_key(&bb.id) {
            continue;
        }
        if let Some(cl_idx) = chunk_loops.iter().position(|c| c.hdr_bb == bb.id) {
            let cl = &chunk_loops[cl_idx];
            writeln!(out, "            {} => {{", bb.id.0).ok();
            emit_chunk_loop(
                out,
                func,
                ctx,
                &query_plans,
                cl,
                &analysis,
                &local_used_outer,
                &local_loops,
                cl_idx,
            )?;
            writeln!(out, "                __bb = {};", cl.exit_bb.0).ok();
            writeln!(out, "            }}").ok();
            continue;
        }

        writeln!(out, "            {} => {{", bb.id.0).ok();
        for (si, st) in bb.stmts.iter().enumerate() {
            emit_stmt(
                out,
                func,
                ctx,
                &query_plans,
                &analysis,
                bb.id.0 as usize,
                si,
                st,
                "                ",
                None,
                &HashMap::new(),
            )?;
        }
        emit_terminator(
            out,
            func,
            &analysis,
            &bb.terminator,
            "                ",
            None,
        );
        writeln!(out, "            }}").ok();
    }
    writeln!(out, "            _ => break,\n        }}\n    }}").ok();

    if analysis.has_checkpoint {
        writeln!(
            out,
            "    for cmd in __tx_cmds {{\n\
             \x20       match cmd {{ __StrataTxCmd::Spawn(f) => f(&mut commands) }}\n\
             \x20   }}"
        )
        .ok();
    }

    if matches!(func.kind, MirFnKind::HelperFn) && !matches!(func.ret_ty, MirType::Unit) {
        if matches!(func.ret_ty, MirType::Named(_)) {
            writeln!(out, "    Default::default()").ok();
        } else {
            writeln!(
                out,
                "    {}",
                ValTy::from_mir_ret(&func.ret_ty).default_expr()
            )
            .ok();
        }
    }

    writeln!(out, "}}\n").ok();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_chunk_loop(
    out: &mut String,
    func: &MirFunction,
    ctx: &NativeCtx<'_>,
    query_plans: &[QueryEmitPlan],
    cl: &ChunkLoopInfo,
    analysis: &FnAnalysis,
    local_used_outer: &[bool],
    local_loops: &[HashSet<usize>],
    cl_idx: usize,
) -> Result<(), CodegenError> {
    let plan = query_plans
        .iter()
        .find(|p| p.query_idx == cl.query_idx)
        .ok_or_else(|| CodegenError::Unsupported {
            context: func.name.clone(),
            detail: format!("missing QueryEmitPlan for query {}", cl.query_idx),
        })?;

    // Collect outer reduction slots written via ReduceAccum inside this loop.
    let mut reduce_info: Vec<(LocalId, String, ValTy)> = Vec::new();
    for &bid in &cl.loop_blocks {
        for st in &func.blocks[bid.0 as usize].stmts {
            if let Inst::SlotStore { slot, val } = st.inst
                && local_used_outer[slot.0 as usize]
                && let Some(op_s) = cl.loop_blocks.iter().find_map(|b| {
                    func.blocks[b.0 as usize].stmts.iter().find_map(|s| {
                        if s.dst == Some(val)
                            && let Inst::ReduceAccum { ref op, .. } = s.inst
                        {
                            Some(op.clone())
                        } else {
                            None
                        }
                    })
                })
                && !reduce_info.iter().any(|(l, _, _)| *l == slot)
            {
                let vty = analysis.slot_tys.get(&slot).cloned().unwrap_or(ValTy::F32);
                reduce_info.push((slot, op_s, vty));
            }
        }
    }

    let mut slot_remap: HashMap<LocalId, String> = HashMap::new();
    if cl.use_par && !reduce_info.is_empty() {
        let types: Vec<String> = reduce_info.iter().map(|(_, _, t)| t.rust_type()).collect();
        let vals: Vec<String> = reduce_info
            .iter()
            .map(|(l, _, _)| format!("__slot_{}", l.0))
            .collect();
        let mut tuple_init = vals.join(", ");
        if vals.len() == 1 {
            tuple_init.push(',');
        }
        writeln!(
            out,
            "                let __par_red = std::sync::Mutex::new(({tuple_init}));",
        )
        .ok();
        let _ = types;
    }

    // Capture `on.event()` value before `.for_each` if this is a @par observer.
    if cl.use_par && matches!(func.kind, MirFnKind::Observer { .. }) {
        writeln!(out, "                let __obs_ev_copy = *on.event();").ok();
    }

    let q_access = if let Some(pidx) = plan.param_set_idx {
        format!("q_set.p{pidx}()")
    } else {
        plan.param_name.clone()
    };

    let mut pat_elems = Vec::new();
    if plan.needs_entity {
        pat_elems.push(if plan.is_sparse {
            format!("__q{}_ent", plan.query_idx)
        } else {
            format!("__q{}_entities", plan.query_idx)
        });
    }
    for slot in &plan.slots {
        let mut p = format!("__q{}_raw_{}", plan.query_idx, slot.slot_idx);
        if slot.mode == TermAccessMode::Write || slot.mode == TermAccessMode::OptionalWrite {
            p = format!("mut {p}");
        }
        pat_elems.push(p);
    }
    let pat_str = if pat_elems.is_empty() {
        "_".to_owned()
    } else {
        format!("({},)", pat_elems.join(", "))
    };

    if cl.is_up_cascade {
        let rel_name = cl.up_relation.as_deref().unwrap_or("");
        let rel_var = analysis
            .relation_res_map
            .get(rel_name)
            .map_or("rel_res", |(v, _)| v.as_str());
        writeln!(
            out,
            "                let mut __bfs_queue: std::collections::VecDeque<Entity> = {rel_var}.edges.iter().map(|&(s, _, _)| s).collect();\n\
             \x20               let mut __bfs_seen: std::collections::HashSet<Entity> = std::collections::HashSet::new();\n\
             \x20               while let Some(__ent) = __bfs_queue.pop_front() {{\n\
             \x20                   if !__bfs_seen.insert(__ent) {{ continue; }}\n\
             \x20                   for &(s, d, _) in &{rel_var}.edges {{ if s == __ent {{ __bfs_queue.push_back(d); }} }}\n\
             \x20                   if let Ok({pat_str}) = {q_access}.{} {{\n",
            if plan.has_any_mut { "get_mut(__ent)" } else { "get(__ent)" }
        )
        .ok();
    } else if cl.is_pset_snap {
        let qi = plan.query_idx;
        let mut pat_elems_ro = Vec::new();
        let mut map_elems = Vec::new();
        if plan.needs_entity {
            pat_elems_ro.push("__se".to_owned());
            map_elems.push("__se".to_owned());
        }
        for slot in &plan.slots {
            let si = slot.slot_idx;
            pat_elems_ro.push(format!("__s{si}"));
            match slot.mode {
                TermAccessMode::OptionalRead | TermAccessMode::OptionalWrite => {
                    map_elems.push(format!("__s{si}.copied()"));
                }
                _ => map_elems.push(format!("*__s{si}")),
            }
            if slot.mode == TermAccessMode::SelectiveWrite {
                map_elems.push("false".to_owned());
            }
        }
        let pat_ro = format!("({},)", pat_elems_ro.join(", "));
        let map_out = format!("({},)", map_elems.join(", "));
        writeln!(
            out,
            "                let mut __q{qi}_snap: Vec<_> = {q_access}.iter().map(|{pat_ro}| {map_out}).collect();\n\
             \x20               for __q{qi}_srow in &mut __q{qi}_snap {{"
        )
        .ok();
    } else if plan.is_sparse {
        let iter_m = if plan.has_any_mut {
            "iter_mut()"
        } else {
            "iter()"
        };
        writeln!(
            out,
            "                for {pat_str} in {q_access}.{iter_m} {{"
        )
        .ok();
    } else if cl.use_par {
        let par_m = if plan.has_any_mut {
            "strata_contiguous_par_iter_mut()"
        } else {
            "strata_contiguous_par_iter()"
        };
        writeln!(
            out,
            "                if let Ok(__par_it) = {q_access}.{par_m} {{\n\
             \x20                   __par_it.for_each(|{pat_str}| {{"
        )
        .ok();
    } else {
        let seq_m = if plan.has_any_mut {
            "strata_contiguous_iter_mut()"
        } else {
            "strata_contiguous_iter()"
        };
        writeln!(
            out,
            "                if let Ok(__chunks) = {q_access}.{seq_m} {{\n\
             \x20                   let mut __broke_loop = false;\n\
             \x20                   for {pat_str} in __chunks {{\n\
             \x20                       if __broke_loop {{ break; }}"
        )
        .ok();
    }

    let indent = "                        ";
    // Convert chunk raw slices / sparse items into uniform per-slot accessors.
    if cl.is_pset_snap {
        let qi = plan.query_idx;
        let mut snap_idx = 0usize;
        if plan.needs_entity {
            writeln!(out, "{indent}let __q{qi}_ent = __q{qi}_srow.0;").ok();
            snap_idx = 1;
        }
        for slot in &plan.slots {
            let si = slot.slot_idx;
            match slot.mode {
                TermAccessMode::SelectiveWrite => {
                    writeln!(
                        out,
                        "{indent}let __q{qi}_sel_{si} = &mut __q{qi}_srow.{snap_idx};\n\
                         {indent}let mut __q{qi}_dirty_{si} = false;"
                    )
                    .ok();
                    snap_idx += 2;
                }
                TermAccessMode::Write => {
                    writeln!(
                        out,
                        "{indent}let __q{qi}_col_{si} = &mut __q{qi}_srow.{snap_idx};"
                    )
                    .ok();
                    snap_idx += 1;
                }
                TermAccessMode::OptionalWrite => {
                    writeln!(
                        out,
                        "{indent}let mut __q{qi}_col_{si} = __q{qi}_srow.{snap_idx}.as_mut();"
                    )
                    .ok();
                    snap_idx += 1;
                }
                TermAccessMode::OptionalRead => {
                    writeln!(
                        out,
                        "{indent}let __q{qi}_col_{si} = __q{qi}_srow.{snap_idx}.as_ref();"
                    )
                    .ok();
                    snap_idx += 1;
                }
                TermAccessMode::Read => {
                    writeln!(
                        out,
                        "{indent}let __q{qi}_col_{si} = &__q{qi}_srow.{snap_idx};"
                    )
                    .ok();
                    snap_idx += 1;
                }
                _ => {}
            }
        }
    } else {
        for slot in &plan.slots {
            let qi = plan.query_idx;
            let si = slot.slot_idx;
            if plan.is_sparse || cl.is_up_cascade {
                match slot.mode {
                    TermAccessMode::SelectiveWrite => {
                        writeln!(
                            out,
                            "{indent}let mut __q{qi}_sel_{si} = __q{qi}_raw_{si};\n\
                             {indent}let mut __q{qi}_dirty_{si} = false;"
                        )
                        .ok();
                    }
                    TermAccessMode::Write => {
                        writeln!(out, "{indent}let mut __q{qi}_col_{si} = __q{qi}_raw_{si};").ok();
                    }
                    TermAccessMode::OptionalWrite => {
                        writeln!(
                            out,
                            "{indent}let mut __q{qi}_opt_own_{si} = __q{qi}_raw_{si};\n\
                             {indent}let mut __q{qi}_col_{si} = __q{qi}_opt_own_{si}.as_deref_mut();"
                        )
                        .ok();
                    }
                    TermAccessMode::Read | TermAccessMode::OptionalRead => {
                        writeln!(out, "{indent}let __q{qi}_col_{si} = __q{qi}_raw_{si};").ok();
                    }
                    _ => {}
                }
            } else {
                match slot.mode {
                    TermAccessMode::SelectiveWrite => {
                        writeln!(
                            out,
                            "{indent}let mut __q{qi}_sel_{si} = SelectiveMutSlice::from_contiguous_mut(__q{qi}_raw_{si});"
                        )
                        .ok();
                    }
                    TermAccessMode::Write => {
                        writeln!(
                            out,
                            "{indent}let __q{qi}_col_{si} = &mut *__q{qi}_raw_{si};"
                        )
                        .ok();
                    }
                    TermAccessMode::OptionalWrite => {
                        writeln!(
                            out,
                            "{indent}let mut __q{qi}_opt_own_{si} = __q{qi}_raw_{si};\n\
                             {indent}let mut __q{qi}_col_{si} = __q{qi}_opt_own_{si}.as_deref_mut();"
                        )
                        .ok();
                    }
                    TermAccessMode::Read | TermAccessMode::OptionalRead => {
                        writeln!(out, "{indent}let __q{qi}_col_{si} = __q{qi}_raw_{si};").ok();
                    }
                    _ => {}
                }
            }
        }
    }

    // Declare inner-loop-only locals
    for (idx, vt) in analysis.val_tys.iter().enumerate() {
        let lid = LocalId(idx as u32);
        if !local_used_outer[idx]
            && local_loops[idx].len() == 1
            && local_loops[idx].contains(&cl_idx)
        {
            if let Some(slot_vt) = analysis.slot_tys.get(&lid) {
                writeln!(
                    out,
                    "{indent}let mut __slot_{idx}: {} = {};",
                    slot_vt.rust_type(),
                    slot_vt.default_expr()
                )
                .ok();
            } else if *vt != ValTy::PtrMarker && *vt != ValTy::Unit {
                writeln!(
                    out,
                    "{indent}let mut __loc_{idx}: {} = {};",
                    vt.rust_type(),
                    vt.default_expr()
                )
                .ok();
            }
        }
    }

    for bp in &analysis.spawn_batches {
        if bp.only_chunk_loop == Some(cl_idx) {
            writeln!(
                out,
                "{indent}let mut {}: Vec<{}> = Vec::new();",
                bp.var_name, bp.bundle_ty
            )
            .ok();
        }
    }

    if cl.use_par && !reduce_info.is_empty() {
        for (ri, (slot_l, op, vty)) in reduce_info.iter().enumerate() {
            let local_var = format!("__chunk_red_{ri}");
            let init_v = reduce_identity_expr(op, vty);
            writeln!(
                out,
                "{indent}let mut {local_var}: {} = {init_v};",
                vty.rust_type()
            )
            .ok();
            slot_remap.insert(*slot_l, local_var);
        }
    }

    writeln!(
        out,
        "{indent}let mut __inner_bb: u32 = {};\n\
         {indent}loop {{\n\
         {indent}    match __inner_bb {{",
        cl.chunk_body_bb.0
    )
    .ok();

    let mut ordered_blocks: Vec<BlockId> = cl.loop_blocks.iter().copied().collect();
    ordered_blocks.sort_by_key(|b| b.0);
    for bid in ordered_blocks {
        let bb = &func.blocks[bid.0 as usize];
        writeln!(out, "{indent}        {} => {{", bid.0).ok();
        for (si, st) in bb.stmts.iter().enumerate() {
            emit_stmt(
                out,
                func,
                ctx,
                query_plans,
                analysis,
                bid.0 as usize,
                si,
                st,
                "                                    ",
                Some(cl),
                &slot_remap,
            )?;
        }
        emit_terminator(
            out,
            func,
            analysis,
            &bb.terminator,
            "                                    ",
            Some(cl),
        );
        writeln!(out, "{indent}        }}").ok();
    }

    writeln!(
        out,
        "{indent}        _ => break,\n\
         {indent}    }}\n\
         {indent}}}"
    )
    .ok();

    // Flush sparse selective change ticks if any (for non-snapshot loops)
    if (plan.is_sparse || cl.is_up_cascade) && !cl.is_pset_snap {
        for slot in &plan.slots {
            if slot.mode == TermAccessMode::SelectiveWrite {
                let qi = plan.query_idx;
                let si = slot.slot_idx;
                writeln!(
                    out,
                    "{indent}if __q{qi}_dirty_{si} {{ __q{qi}_sel_{si}.set_changed(); }}"
                )
                .ok();
            }
        }
    }

    if cl.is_pset_snap {
        let qi = plan.query_idx;
        let mut snap_idx = usize::from(plan.needs_entity);
        for slot in &plan.slots {
            let si = slot.slot_idx;
            if slot.mode == TermAccessMode::SelectiveWrite {
                writeln!(
                    out,
                    "{indent}__q{qi}_srow.{} = __q{qi}_dirty_{si};",
                    snap_idx + 1
                )
                .ok();
                snap_idx += 2;
            } else {
                snap_idx += 1;
            }
        }
    }

    if cl.use_par && !reduce_info.is_empty() {
        writeln!(out, "{indent}if let Ok(mut __g) = __par_red.lock() {{").ok();
        for (ri, (_, op, vty)) in reduce_info.iter().enumerate() {
            let expr =
                reduce_combine_expr(op, vty, &format!("__g.{ri}"), &format!("__chunk_red_{ri}"));
            writeln!(out, "{indent}    __g.{ri} = {expr};").ok();
        }
        writeln!(out, "{indent}}}").ok();
    }

    if cl.is_up_cascade {
        writeln!(out, "                    }}\n                }}").ok();
    } else if cl.is_pset_snap {
        writeln!(out, "                }}").ok();
        if plan.has_any_mut {
            let qi = plan.query_idx;
            writeln!(
                out,
                "                for __q{qi}_srow in __q{qi}_snap {{\n\
                 \x20                   if let Ok(mut __wb) = {q_access}.get_mut(__q{qi}_srow.0) {{"
            )
            .ok();
            let mut snap_idx = usize::from(plan.needs_entity);
            for (tup_idx_base, slot) in plan.slots.iter().enumerate() {
                let tup_idx = tup_idx_base + usize::from(plan.needs_entity);
                match slot.mode {
                    TermAccessMode::Write => {
                        writeln!(
                            out,
                            "                        *__wb.{tup_idx} = __q{qi}_srow.{snap_idx};"
                        )
                        .ok();
                        snap_idx += 1;
                    }
                    TermAccessMode::OptionalWrite => {
                        writeln!(
                            out,
                            "                        if let (Some(mut __dst), Some(__src)) = (__wb.{tup_idx}, __q{qi}_srow.{snap_idx}) {{ *__dst = __src; }}"
                        )
                        .ok();
                        snap_idx += 1;
                    }
                    TermAccessMode::SelectiveWrite => {
                        writeln!(
                            out,
                            "                        if __q{qi}_srow.{} {{ *__wb.{tup_idx} = __q{qi}_srow.{snap_idx}; }}",
                            snap_idx + 1
                        )
                        .ok();
                        snap_idx += 2;
                    }
                    _ => {
                        snap_idx += 1;
                    }
                }
            }
            writeln!(out, "                    }}\n                }}").ok();
        }
    } else if plan.is_sparse {
        writeln!(out, "                }}").ok();
    } else if cl.use_par {
        writeln!(out, "                    }});\n                }}").ok();
        for (ri, (slot_l, _, _)) in reduce_info.iter().enumerate() {
            writeln!(
                out,
                "                if let Ok(__g) = __par_red.lock() {{ __slot_{} = __g.{ri}; }}",
                slot_l.0
            )
            .ok();
        }
    } else {
        writeln!(out, "                    }}\n                }}").ok();
    }
    Ok(())
}

fn reduce_identity_expr(op: &str, vty: &ValTy) -> String {
    match op {
        "min" => match vty {
            ValTy::F32 => "f32::MAX".to_owned(),
            ValTy::F64 => "f64::MAX".to_owned(),
            ValTy::U32 => "u32::MAX".to_owned(),
            ValTy::I32 => "i32::MAX".to_owned(),
            _ => vty.default_expr(),
        },
        "max" => match vty {
            ValTy::F32 => "f32::MIN".to_owned(),
            ValTy::F64 => "f64::MIN".to_owned(),
            ValTy::U32 => "0u32".to_owned(),
            ValTy::I32 => "i32::MIN".to_owned(),
            _ => vty.default_expr(),
        },
        "prod" => match vty {
            ValTy::F32 => "1.0_f32".to_owned(),
            ValTy::F64 => "1.0_f64".to_owned(),
            ValTy::U32 => "1u32".to_owned(),
            ValTy::I32 => "1i32".to_owned(),
            _ => vty.default_expr(),
        },
        "all" => "true".to_owned(),
        _ => vty.default_expr(),
    }
}

fn reduce_combine_expr(op: &str, vty: &ValTy, acc: &str, val: &str) -> String {
    let rhs = if *vty == ValTy::Bool {
        val.to_owned()
    } else {
        format!("({val}) as {}", vty.rust_type())
    };
    match op {
        "min" => format!("({acc}).min({rhs})"),
        "max" => format!("({acc}).max({rhs})"),
        "prod" => format!("({acc}) * ({rhs})"),
        "any" => format!("({acc}) || ({rhs})"),
        "all" => format!("({acc}) && ({rhs})"),
        _ => format!("({acc}) + ({rhs})"),
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_stmt(
    out: &mut String,
    func: &MirFunction,
    ctx: &NativeCtx<'_>,
    query_plans: &[QueryEmitPlan],
    analysis: &FnAnalysis,
    bb_idx: usize,
    stmt_idx: usize,
    st: &MirStmt,
    indent: &str,
    in_chunk: Option<&ChunkLoopInfo>,
    slot_remap: &HashMap<LocalId, String>,
) -> Result<(), CodegenError> {
    let dst_s = st.dst.map(|d| format!("__loc_{}", d.0));
    let dst_ty = st.dst.map(|d| &analysis.val_tys[d.0 as usize]);

    match &st.inst {
        Inst::ConstInt { value } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                if *dt == ValTy::PtrMarker || *dt == ValTy::Unit {
                    return Ok(());
                }
                let val_expr = if let Some(&qiter_l) = analysis.sp_lim_clamp.get(&d) {
                    format!("(__loc_{}.len().min({value}) as u32)", qiter_l.0)
                } else {
                    match dt {
                        ValTy::Entity => {
                            if *value == 0 {
                                "FfiEntity::NULL".to_owned()
                            } else {
                                format!("FfiEntity::from_bits({value}u64)")
                            }
                        }
                        ValTy::F32 => format_f32_lit(*value as f64),
                        ValTy::F64 => format_f64_lit(*value as f64),
                        ValTy::Fix32 => format!("Fixed32::from_int({value} as i16)"),
                        ValTy::Fix64 => format!("Fixed64::from_int({value} as i32)"),
                        ValTy::Bool => format!("({value} != 0)"),
                        _ => format!("({value}i64 as {})", dt.rust_type()),
                    }
                };
                writeln!(out, "{indent}__loc_{} = {val_expr};", d.0).ok();
            }
        }
        Inst::ConstFloat { value } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                let val_expr = match dt {
                    ValTy::F64 => format_f64_lit(*value),
                    ValTy::Fix32 => format!("Fixed32::from_f32({})", format_f32_lit(*value)),
                    ValTy::Fix64 => format!("Fixed64::from_f64({})", format_f64_lit(*value)),
                    _ => format_f32_lit(*value),
                };
                writeln!(out, "{indent}__loc_{} = {val_expr};", d.0).ok();
            }
        }
        Inst::ConstBool { value } => {
            if let Some(d) = st.dst
                && analysis.val_tys[d.0 as usize] != ValTy::Unit
            {
                writeln!(out, "{indent}__loc_{} = {value};", d.0).ok();
            }
        }
        Inst::ConstVec { dims, values } => {
            if let Some(d) = st.dst {
                let expr = match dims {
                    2 => format!(
                        "[{}, {}]",
                        format_f32_lit(values[0]),
                        format_f32_lit(values[1])
                    ),
                    3 => format!(
                        "[{}, {}, {}]",
                        format_f32_lit(values[0]),
                        format_f32_lit(values[1]),
                        format_f32_lit(values[2])
                    ),
                    _ => format!(
                        "[{}, {}, {}, {}]",
                        format_f32_lit(values[0]),
                        format_f32_lit(values[1]),
                        format_f32_lit(values[2]),
                        format_f32_lit(values[3])
                    ),
                };
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::ConstString { value } => {
            if let Some(d) = st.dst {
                let words = match analysis.val_tys[d.0 as usize] {
                    ValTy::InlineStr(cap) => 1 + cap.div_ceil(4),
                    _ => 17,
                };
                writeln!(
                    out,
                    "{indent}__loc_{} = strata_inline_str_pack::<{words}>({value:?});",
                    d.0
                )
                .ok();
            }
        }
        Inst::Copy { val } => {
            if let Some(d) = st.dst
                && analysis.val_tys[d.0 as usize] != ValTy::PtrMarker
                && analysis.val_tys[d.0 as usize] != ValTy::Unit
            {
                let src_e = format!("__loc_{}", val.0);
                let coerced = coerce_expr(
                    &src_e,
                    &analysis.val_tys[val.0 as usize],
                    &analysis.val_tys[d.0 as usize],
                );
                writeln!(out, "{indent}__loc_{} = {coerced};", d.0).ok();
            }
        }
        Inst::BinOp {
            op,
            lhs,
            rhs,
            allow_fma: _,
        } => {
            if let Some(d) = st.dst {
                let expr = emit_binop_expr(
                    op,
                    *lhs,
                    *rhs,
                    &analysis.val_tys[d.0 as usize],
                    analysis,
                    query_plans,
                    in_chunk,
                    ctx,
                );
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::UnOp { op, val } => {
            if let Some(d) = st.dst {
                let (vt, v) =
                    effective_local_val_and_expr(*val, analysis, query_plans, in_chunk, ctx);
                let expr = match op.as_str() {
                    "-" => match vt.is_vec() {
                        Some(2) => format!("[-{v}[0], -{v}[1]]"),
                        Some(3) => format!("[-{v}[0], -{v}[1], -{v}[2]]"),
                        Some(4) => format!("[-{v}[0], -{v}[1], -{v}[2], -{v}[3]]"),
                        _ => format!("(-{v})"),
                    },
                    "!" | "~" => format!("(!{v})"),
                    _ => v,
                };
                let coerced = coerce_expr(&expr, &vt, &analysis.val_tys[d.0 as usize]);
                writeln!(out, "{indent}__loc_{} = {coerced};", d.0).ok();
            }
        }
        Inst::Cast { val, target_ty } => {
            if let Some(d) = st.dst {
                let (from_vt, ve) =
                    effective_local_val_and_expr(*val, analysis, query_plans, in_chunk, ctx);
                let to_vt = ValTy::from_mir(target_ty, ctx);
                let coerced = coerce_expr(&ve, &from_vt, &to_vt);
                let final_e = coerce_expr(&coerced, &to_vt, &analysis.val_tys[d.0 as usize]);
                writeln!(out, "{indent}__loc_{} = {final_e};", d.0).ok();
            }
        }
        Inst::VecExtract { vec, lane } => {
            if let Some(d) = st.dst {
                let (_, ve) =
                    effective_local_val_and_expr(*vec, analysis, query_plans, in_chunk, ctx);
                writeln!(out, "{indent}__loc_{} = {ve}[{lane}];", d.0).ok();
            }
        }
        Inst::VecInsert { vec, lane, val } => {
            if let Some(d) = st.dst {
                let (v_vt, v) =
                    effective_local_val_and_expr(*vec, analysis, query_plans, in_chunk, ctx);
                let (val_vt, val_e) =
                    effective_local_val_and_expr(*val, analysis, query_plans, in_chunk, ctx);
                let dt = &analysis.val_tys[d.0 as usize];
                let scalar = coerce_expr(&val_e, &val_vt, &ValTy::F32);
                writeln!(
                    out,
                    "{indent}{{ let mut __tv: {} = {}; __tv[{lane}] = {scalar}; __loc_{} = __tv; }}",
                    dt.rust_type(),
                    coerce_expr(&v, &v_vt, dt),
                    d.0
                )
                .ok();
            }
        }
        Inst::VecSwizzle { vec, lanes } => {
            if let Some(d) = st.dst {
                let (_, v) =
                    effective_local_val_and_expr(*vec, analysis, query_plans, in_chunk, ctx);
                let elems: Vec<String> = lanes.iter().map(|l| format!("{v}[{l}]")).collect();
                writeln!(out, "{indent}__loc_{} = [{}];", d.0, elems.join(", ")).ok();
            }
        }
        Inst::IntrinsicMath {
            name,
            args,
            deterministic: _,
        } => {
            if let Some(d) = st.dst {
                let expr = emit_intrinsic_math(
                    name,
                    args,
                    &analysis.val_tys[d.0 as usize],
                    analysis,
                    query_plans,
                    in_chunk,
                    ctx,
                );
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::Call { callee, args } => {
            let expr = emit_call_expr(callee, args, dst_ty, ctx, analysis, query_plans, in_chunk)?;
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                if *dt != ValTy::Unit && *dt != ValTy::PtrMarker {
                    writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
                } else {
                    writeln!(out, "{indent}let _ = {expr};").ok();
                }
            } else {
                writeln!(out, "{indent}{expr};").ok();
            }
        }
        Inst::StructInit { type_name, fields } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                if *dt == ValTy::Unit || *dt == ValTy::PtrMarker {
                    return Ok(());
                }
                if type_name == "tuple" {
                    let parts: Vec<String> = fields
                        .iter()
                        .map(|(_, l)| format!("__loc_{}", l.0))
                        .collect();
                    writeln!(out, "{indent}__loc_{} = ({});", d.0, parts.join(", ")).ok();
                } else if ctx.is_zst_component(type_name) {
                    let sname = ctx
                        .resolve_ecs_struct_name(type_name)
                        .unwrap_or_else(|| dt.rust_type());
                    writeln!(out, "{indent}__loc_{} = {sname};", d.0).ok();
                } else if let Some(entry) = ctx.find_layout_entry(type_name) {
                    let mut finits = Vec::new();
                    for (fname, flocal) in fields {
                        let rfname = sanitize_rust_ident(fname);
                        let src_vt = &analysis.val_tys[flocal.0 as usize];
                        let fval = if let Some(sf) =
                            entry.layout.fields.iter().find(|f| f.name == *fname)
                        {
                            let dst_vt = ValTy::from_solved_field(sf, ctx);
                            let e = coerce_expr(&format!("__loc_{}", flocal.0), src_vt, &dst_vt);
                            wrap_abi_field_store(
                                &e,
                                sf,
                                ctx,
                                entry.layout.item_kind == SchemaItemKind::Event
                                    && ctx.entity_events.contains(&entry.layout.canonical_name),
                            )
                        } else {
                            format!("__loc_{}", flocal.0)
                        };
                        finits.push(format!("{rfname}: {fval}"));
                    }
                    writeln!(
                        out,
                        "{indent}__loc_{} = {} {{ {}, ..Default::default() }};",
                        d.0,
                        entry.struct_name,
                        finits.join(", ")
                    )
                    .ok();
                }
            }
        }
        Inst::ArrayInit { elems } => {
            if let Some(d) = st.dst {
                let parts: Vec<String> = elems.iter().map(|l| format!("__loc_{}", l.0)).collect();
                writeln!(out, "{indent}__loc_{} = [{}];", d.0, parts.join(", ")).ok();
            }
        }
        Inst::ArrayIndex { base, index } => {
            if let Some(d) = st.dst {
                writeln!(
                    out,
                    "{indent}__loc_{} = __loc_{}[__loc_{} as usize];",
                    d.0, base.0, index.0
                )
                .ok();
            }
        }
        Inst::SlotLoad { slot } => {
            if let Some(d) = st.dst
                && analysis.val_tys[d.0 as usize] != ValTy::PtrMarker
                && analysis.val_tys[d.0 as usize] != ValTy::Unit
            {
                let slot_name = slot_remap
                    .get(slot)
                    .cloned()
                    .unwrap_or_else(|| format!("__slot_{}", slot.0));
                let slot_vt = analysis
                    .slot_tys
                    .get(slot)
                    .unwrap_or(&analysis.val_tys[d.0 as usize]);
                let coerced = coerce_expr(&slot_name, slot_vt, &analysis.val_tys[d.0 as usize]);
                writeln!(out, "{indent}__loc_{} = {coerced};", d.0).ok();
            }
        }
        Inst::SlotStore { slot, val } => {
            let slot_name = slot_remap
                .get(slot)
                .cloned()
                .unwrap_or_else(|| format!("__slot_{}", slot.0));
            let val_vt = &analysis.val_tys[val.0 as usize];
            if *val_vt == ValTy::PtrMarker || *val_vt == ValTy::Unit {
                return Ok(());
            }
            let slot_vt = analysis.slot_tys.get(slot).unwrap_or(val_vt);
            let coerced = coerce_expr(&format!("__loc_{}", val.0), val_vt, slot_vt);
            writeln!(out, "{indent}{slot_name} = {coerced};").ok();
        }
        Inst::SlotAlloc { .. }
        | Inst::FieldPtr { .. }
        | Inst::IterNextChunk { .. }
        | Inst::IterEntities { .. }
        | Inst::IterColRead { .. }
        | Inst::IterColWrite { .. }
        | Inst::IterColWriteUntracked { .. }
        | Inst::IterColRowsRead { .. }
        | Inst::IterColRowsWrite { .. }
        | Inst::IterUpCascade { .. }
        | Inst::RowPtr { .. }
        | Inst::ResRead { .. }
        | Inst::ResWrite { .. }
        | Inst::TriggerPayload { .. }
        | Inst::MigrateSrcPtr { .. }
        | Inst::MigrateDstPtr { .. }
        | Inst::DirtyRunInit { .. }
        | Inst::ParForEachChunk { .. }
        | Inst::ParForEachChunkReadonly { .. }
        | Inst::FsmDispatch { .. }
        | Inst::TaskStep { .. }
        | Inst::RequireTrue { .. }
        | Inst::ShadowWrite { .. } => {}

        Inst::IterChunkLen { query_idx } => {
            if let Some(d) = st.dst {
                let expr = chunk_len_expr(*query_idx, query_plans, in_chunk);
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::EntityAtRow {
            entities_ptr,
            row_idx,
        } => {
            if let Some(d) = st.dst {
                if let Some(PtrTarget::EntitiesSlice { query_idx }) =
                    analysis.ptr_targets.get(entities_ptr)
                {
                    let plan = query_plans.iter().find(|p| p.query_idx == *query_idx);
                    if plan.is_some_and(|p| p.is_sparse)
                        || in_chunk.is_some_and(ChunkLoopInfo::is_1row)
                    {
                        writeln!(
                            out,
                            "{indent}__loc_{} = FfiEntity::from_bits(__q{query_idx}_ent.to_bits());",
                            d.0
                        )
                        .ok();
                    } else {
                        writeln!(
                            out,
                            "{indent}__loc_{} = FfiEntity::from_bits(__q{query_idx}_entities[__loc_{} as usize].to_bits());",
                            d.0, row_idx.0
                        )
                        .ok();
                    }
                } else {
                    writeln!(
                        out,
                        "{indent}__loc_{} = __loc_{}.get(__loc_{} as usize).copied().unwrap_or(FfiEntity::NULL);",
                        d.0, entities_ptr.0, row_idx.0
                    )
                    .ok();
                }
            }
        }
        Inst::FieldLoad {
            base_ptr,
            layout_key,
            field,
            ..
        } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                let load_expr = emit_field_load_expr(
                    *base_ptr,
                    layout_key,
                    field,
                    dt,
                    func,
                    ctx,
                    query_plans,
                    analysis,
                    in_chunk,
                );
                writeln!(out, "{indent}__loc_{} = {load_expr};", d.0).ok();
                if let Some(idx_name) = analysis.csr_pos_captures.get(&(bb_idx, stmt_idx)) {
                    let sname = sanitize_ident(idx_name);
                    let pos3 = match dt {
                        ValTy::Vec2 => format!("[__loc_{0}[0], __loc_{0}[1], 0.0_f32]", d.0),
                        _ => format!("__loc_{}", d.0),
                    };
                    if let Some(ent_local) =
                        func.blocks[bb_idx].stmts.iter().find_map(|s| match s.inst {
                            Inst::EntityAtRow { .. } => s.dst,
                            _ => None,
                        })
                    {
                        writeln!(
                            out,
                            "{indent}if let Some(__ce) = Entity::try_from_bits(__loc_{}.to_bits()) {{ __csr_rows_{sname}.push((__ce, {pos3})); }}",
                            ent_local.0
                        )
                        .ok();
                    }
                }
            }
        }
        Inst::FieldStore {
            base_ptr,
            layout_key,
            field,
            val,
            ..
        } => {
            emit_field_store_stmt(
                out,
                *base_ptr,
                layout_key,
                field,
                *val,
                ctx,
                query_plans,
                analysis,
                indent,
                in_chunk,
            );
        }
        Inst::DirtyRunRecordRow { row_idx, .. } => {
            if let Some(cl) = in_chunk
                && let Some(plan) = query_plans.iter().find(|p| p.query_idx == cl.query_idx)
            {
                for slot in &plan.slots {
                    if slot.mode == TermAccessMode::SelectiveWrite {
                        let qi = plan.query_idx;
                        let si = slot.slot_idx;
                        if plan.is_sparse || cl.is_1row() {
                            writeln!(out, "{indent}__q{qi}_dirty_{si} = true;").ok();
                        } else {
                            writeln!(
                                out,
                                "{indent}__q{qi}_sel_{si}.mark_dirty_row(__loc_{} as usize);",
                                row_idx.0
                            )
                            .ok();
                        }
                    }
                }
            }
        }
        Inst::IterMarkChangedRange { query_idx, .. } => {
            if let Some(cl) = in_chunk
                && let Some(plan) = query_plans.iter().find(|p| p.query_idx == *query_idx)
                && !plan.is_sparse
                && !cl.is_1row()
            {
                for slot in &plan.slots {
                    if slot.mode == TermAccessMode::SelectiveWrite {
                        writeln!(
                            out,
                            "{indent}let _ = __q{}_sel_{}.flush_dirty_runs();",
                            plan.query_idx, slot.slot_idx
                        )
                        .ok();
                    }
                }
            }
        }
        Inst::IterCount { query_idx } => {
            if let Some(d) = st.dst
                && let Some(plan) = query_plans.iter().find(|p| p.query_idx == *query_idx)
            {
                let qa = query_access_expr(plan);
                writeln!(out, "{indent}__loc_{} = {qa}.iter().count() as u32;", d.0).ok();
            }
        }
        Inst::ReduceInit { op, identity } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                let iv = coerce_expr(
                    &format!("__loc_{}", identity.0),
                    &analysis.val_tys[identity.0 as usize],
                    dt,
                );
                let _ = op;
                writeln!(out, "{indent}__loc_{} = {iv};", d.0).ok();
            }
        }
        Inst::ReduceAccum { acc, op, val } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                let expr = reduce_combine_expr(
                    op,
                    dt,
                    &format!("__loc_{}", acc.0),
                    &format!("__loc_{}", val.0),
                );
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::EntityGet {
            query_idx, entity, ..
        }
        | Inst::EntityGetMut {
            query_idx, entity, ..
        } => {
            if let Some(d) = st.dst
                && let Some(plan) = query_plans.iter().find(|p| p.query_idx == *query_idx)
            {
                let qa = query_access_expr(plan);
                writeln!(
                    out,
                    "{indent}__loc_{} = Entity::try_from_bits(__loc_{}.to_bits()).is_some_and(|__e| {qa}.get(__e).is_ok());",
                    d.0, entity.0
                )
                .ok();
            }
        }
        Inst::OptionalChunkIsPresent { slice_ptr, .. } => {
            if let Some(d) = st.dst {
                let cond_expr = match analysis.ptr_targets.get(slice_ptr) {
                    Some(PtrTarget::QueryCol {
                        query_idx,
                        slot_idx,
                        ..
                    }) => format!("__q{query_idx}_col_{slot_idx}.is_some()"),
                    Some(PtrTarget::EntityRow {
                        query_idx,
                        slot_idx,
                        entity_local,
                        optional,
                        ..
                    }) => {
                        let plan = &query_plans[*query_idx as usize];
                        let qa = query_access_expr(plan);
                        let tup_idx = slot_idx + usize::from(plan.needs_entity);
                        if *optional {
                            format!(
                                "Entity::try_from_bits(__loc_{}.to_bits()).is_some_and(|__e| {qa}.get(__e).ok().is_some_and(|__row| __row.{tup_idx}.is_some()))",
                                entity_local.0
                            )
                        } else {
                            format!(
                                "Entity::try_from_bits(__loc_{}.to_bits()).is_some_and(|__e| {qa}.get(__e).is_ok())",
                                entity_local.0
                            )
                        }
                    }
                    _ => "false".to_owned(),
                };
                writeln!(out, "{indent}__loc_{} = {cond_expr};", d.0).ok();
            }
        }
        Inst::BindNamedObject { name } => {
            if let Some((q_var, _)) = analysis.object_queries.get(name.as_str()) {
                writeln!(
                    out,
                    "{indent}if named_objects.get({name:?}).is_none() {{\n\
                     {indent}    if let Some(__e) = {q_var}.iter().next() {{ named_objects.bind({name:?}, __e); }}\n\
                     {indent}}}"
                )
                .ok();
            }
        }
        Inst::ResolveNamedObject { name } => {
            if let Some(d) = st.dst {
                let fallback = if let Some((q_var, _)) = analysis.object_queries.get(name.as_str())
                {
                    format!(".or_else(|| {q_var}.iter().next())")
                } else {
                    String::new()
                };
                writeln!(
                    out,
                    "{indent}__loc_{} = named_objects.get({name:?}){fallback}.map_or(FfiEntity::NULL, |e| FfiEntity::from_bits(e.to_bits()));",
                    d.0
                )
                .ok();
            }
        }
        Inst::InternSymbol { symbol } => {
            if let Some(d) = st.dst {
                let dt = &analysis.val_tys[d.0 as usize];
                if *dt == ValTy::Entity {
                    writeln!(out, "{indent}__loc_{} = FfiEntity::NULL;", d.0).ok();
                } else if *dt != ValTy::Unit && *dt != ValTy::PtrMarker {
                    writeln!(
                        out,
                        "{indent}__loc_{} = (fnv1a_64_str({symbol:?}) as u32) as {};",
                        d.0,
                        dt.rust_type()
                    )
                    .ok();
                }
            }
        }
        Inst::TriggerTarget => {
            if let Some(d) = st.dst {
                let is_entity_ev = matches!(&func.kind, MirFnKind::Observer { event, .. } if ctx.find_layout_entry(event).is_some_and(|e| ctx.entity_events.contains(&e.layout.canonical_name)));
                if is_entity_ev {
                    writeln!(
                        out,
                        "{indent}__loc_{} = FfiEntity::from_bits(on.event().event_target().to_bits());",
                        d.0
                    )
                    .ok();
                } else {
                    writeln!(
                        out,
                        "{indent}__loc_{} = trigger_targets.0.last().copied().unwrap_or(FfiEntity::NULL);",
                        d.0
                    )
                    .ok();
                }
            }
        }

        // Gameplay primitives
        Inst::GraceArm { ptr, duration_sec } => {
            let dur = coerce_expr(
                &format!("__loc_{}", duration_sec.0),
                &analysis.val_tys[duration_sec.0 as usize],
                &ValTy::F32,
            );
            emit_place_mut(
                out,
                *ptr,
                analysis,
                query_plans,
                in_chunk,
                indent,
                |place| format!("let __d = {dur}; if __d > *{place} {{ *{place} = __d; }}"),
            );
        }
        Inst::GraceTick { ptr, dt_sec } => {
            let dt = coerce_expr(
                &format!("__loc_{}", dt_sec.0),
                &analysis.val_tys[dt_sec.0 as usize],
                &ValTy::F32,
            );
            emit_place_mut(
                out,
                *ptr,
                analysis,
                query_plans,
                in_chunk,
                indent,
                |place| {
                    format!(
                        "let __dt = {dt}; if *{place} > 0.0_f32 {{ *{place} = (*{place} - __dt).max(0.0_f32); }}"
                    )
                },
            );
        }
        Inst::GraceIsActive { ptr } => {
            if let Some(d) = st.dst {
                let expr = emit_place_ref_expr(
                    *ptr,
                    analysis,
                    query_plans,
                    in_chunk,
                    |place| format!("(*{place} > 0.0_f32)"),
                    "false",
                );
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::GraceClear { ptr } => {
            emit_place_mut(
                out,
                *ptr,
                analysis,
                query_plans,
                in_chunk,
                indent,
                |place| format!("*{place} = 0.0_f32;"),
            );
        }
        Inst::InputBufPush {
            ptr,
            action_id,
            window_sec,
            ..
        } => {
            let aid = format!("(__loc_{} as u16)", action_id.0);
            let win = coerce_expr(
                &format!("__loc_{}", window_sec.0),
                &analysis.val_tys[window_sec.0 as usize],
                &ValTy::F32,
            );
            emit_place_mut(
                out,
                *ptr,
                analysis,
                query_plans,
                in_chunk,
                indent,
                |place| format!("strata_input_buf_push({place}.as_mut_slice(), {aid}, {win});"),
            );
        }
        Inst::InputBufConsume { ptr, action_id, .. } => {
            if let Some(d) = st.dst {
                let aid = format!("(__loc_{} as u16)", action_id.0);
                let mut wrote = false;
                if let Some(place_expr) =
                    emit_place_mut_res_expr(*ptr, analysis, query_plans, in_chunk, |place| {
                        format!("strata_input_buf_consume({place}.as_mut_slice(), {aid})")
                    })
                {
                    writeln!(out, "{indent}__loc_{} = {place_expr};", d.0).ok();
                    wrote = true;
                }
                if !wrote {
                    writeln!(out, "{indent}__loc_{} = false;", d.0).ok();
                }
            }
        }
        Inst::InputBufPeek { ptr, action_id, .. } => {
            if let Some(d) = st.dst {
                let aid = format!("(__loc_{} as u16)", action_id.0);
                let expr = emit_place_ref_expr(
                    *ptr,
                    analysis,
                    query_plans,
                    in_chunk,
                    |place| format!("strata_input_buf_peek({place}.as_slice(), {aid})"),
                    "false",
                );
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::InputBufTick { ptr, dt_sec, .. } => {
            let dt = coerce_expr(
                &format!("__loc_{}", dt_sec.0),
                &analysis.val_tys[dt_sec.0 as usize],
                &ValTy::F32,
            );
            emit_place_mut(
                out,
                *ptr,
                analysis,
                query_plans,
                in_chunk,
                indent,
                |place| format!("strata_input_buf_tick({place}.as_mut_slice(), {dt});"),
            );
        }
        Inst::BitSetSet { ptr, bit, .. } => {
            let b = format!("(__loc_{} as u32)", bit.0);
            emit_place_mut(
                out,
                *ptr,
                analysis,
                query_plans,
                in_chunk,
                indent,
                |place| format!("strata_bitset_set({place}.as_mut_slice(), {b});"),
            );
        }
        Inst::BitSetClear { ptr, bit, .. } => {
            let b = format!("(__loc_{} as u32)", bit.0);
            emit_place_mut(
                out,
                *ptr,
                analysis,
                query_plans,
                in_chunk,
                indent,
                |place| format!("strata_bitset_clear({place}.as_mut_slice(), {b});"),
            );
        }
        Inst::BitSetGet { ptr, bit, .. } => {
            if let Some(d) = st.dst {
                let b = format!("(__loc_{} as u32)", bit.0);
                let expr = emit_place_ref_expr(
                    *ptr,
                    analysis,
                    query_plans,
                    in_chunk,
                    |place| format!("strata_bitset_get({place}.as_slice(), {b})"),
                    "false",
                );
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::TimelineInWindow { ptr, window_bit } => {
            if let Some(d) = st.dst {
                let mask = 1u32 << (*window_bit).min(31);
                let expr = emit_place_ref_expr(
                    *ptr,
                    analysis,
                    query_plans,
                    in_chunk,
                    |place| format!("(({place}.active_mask & 0x{mask:08X}u32) != 0)"),
                    "false",
                );
                writeln!(out, "{indent}__loc_{} = {expr};", d.0).ok();
            }
        }
        Inst::TimelineAdvance {
            cursor_ptr,
            rate_hz,
            window_masks,
            ..
        } => {
            let hz = (*rate_hz).max(1) as f32;
            let frame_dt = format_f32_lit(1.0 / f64::from(hz));
            let win_lit: Vec<String> = window_masks
                .iter()
                .map(|(_, s, e, m)| format!("({s}u32, {e}u32, 0x{m:08X}u32)"))
                .collect();
            let win_arr = format!("[{}]", win_lit.join(", "));
            emit_place_mut(
                out,
                *cursor_ptr,
                analysis,
                query_plans,
                in_chunk,
                indent,
                |place| {
                    format!(
                        "let mut __cf = {place}.cur_frame;\n\
                         let mut __acc = {place}.accum_sec;\n\
                         while __acc >= {frame_dt} {{\n\
                         \x20   __acc -= {frame_dt};\n\
                         \x20   __cf = __cf.saturating_add(1);\n\
                         }}\n\
                         {place}.cur_frame = __cf;\n\
                         {place}.accum_sec = __acc;\n\
                         let mut __mask = 0u32;\n\
                         for &(ws, we, wm) in &{win_arr} {{\n\
                         \x20   if (__cf as u32) >= ws && (__cf as u32) < we {{ __mask |= wm; }}\n\
                         }}\n\
                         {place}.active_mask = __mask;"
                    )
                },
            );
        }

        // Tables & Curves & Spatial
        Inst::TableLoad {
            table_name,
            key,
            field,
        } => {
            if let Some(d) = st.dst {
                let tident = sanitize_ident(table_name);
                let row_e = format!(
                    "STRATA_TABLE_{tident}.get(__loc_{} as usize).copied().unwrap_or_default()",
                    key.0
                );
                if field.is_empty() {
                    writeln!(out, "{indent}__loc_{} = {row_e};", d.0).ok();
                } else {
                    writeln!(
                        out,
                        "{indent}__loc_{} = {row_e}.{};",
                        d.0,
                        sanitize_rust_ident(field)
                    )
                    .ok();
                }
            }
        }
        Inst::CurveSample { curve_name, x } => {
            if let Some(d) = st.dst {
                let cident = sanitize_ident(curve_name);
                let xe = coerce_expr(
                    &format!("__loc_{}", x.0),
                    &analysis.val_tys[x.0 as usize],
                    &ValTy::F32,
                );
                writeln!(
                    out,
                    "{indent}__loc_{} = strata_sample_curve(STRATA_CURVE_{cident}, {xe});",
                    d.0
                )
                .ok();
            }
        }
        Inst::SpatialRebuildCsr { index_name, .. } => {
            let resolved = resolve_spatial_name(ctx, func, index_name);
            let sname = sanitize_ident(&resolved);
            if let Some((vname, _)) = analysis.spatial_res_map.get(resolved.as_str()) {
                writeln!(
                    out,
                    "{indent}{vname}.rebuild(core::mem::take(&mut __csr_rows_{sname}));"
                )
                .ok();
            }
        }
        Inst::SpatialQueryDisc {
            grid_name,
            center,
            radius,
        } => {
            let resolved = resolve_spatial_name(ctx, func, grid_name);
            if let Some(d) = st.dst
                && let Some((vname, _)) = analysis.spatial_res_map.get(resolved.as_str())
            {
                let c3 = match analysis.val_tys[center.0 as usize] {
                    ValTy::Vec2 => format!("[__loc_{0}[0], __loc_{0}[1], 0.0_f32]", center.0),
                    _ => format!("__loc_{}", center.0),
                };
                let r = coerce_expr(
                    &format!("__loc_{}", radius.0),
                    &analysis.val_tys[radius.0 as usize],
                    &ValTy::F32,
                );
                writeln!(
                    out,
                    "{indent}__loc_{} = {vname}.query_disc({c3}, {r});",
                    d.0
                )
                .ok();
            }
        }
        Inst::SpatialQuerySegmentAt {
            history_name,
            start,
            end,
            radius,
            tick_offset,
        } => {
            let resolved = resolve_spatial_name(ctx, func, history_name);
            if let Some(d) = st.dst
                && let Some((vname, _)) = analysis.spatial_res_map.get(resolved.as_str())
            {
                let s3 = match analysis.val_tys[start.0 as usize] {
                    ValTy::Vec2 => format!("[__loc_{0}[0], __loc_{0}[1], 0.0_f32]", start.0),
                    _ => format!("__loc_{}", start.0),
                };
                let e3 = match analysis.val_tys[end.0 as usize] {
                    ValTy::Vec2 => format!("[__loc_{0}[0], __loc_{0}[1], 0.0_f32]", end.0),
                    _ => format!("__loc_{}", end.0),
                };
                let r = coerce_expr(
                    &format!("__loc_{}", radius.0),
                    &analysis.val_tys[radius.0 as usize],
                    &ValTy::F32,
                );
                writeln!(
                    out,
                    "{indent}__loc_{} = {vname}.query_segment_at(__loc_{} as u32, {s3}, {e3}, {r});",
                    d.0, tick_offset.0
                )
                .ok();
            }
        }

        // Deferred Commands & Transactions
        Inst::CmdSpawn { components, .. } => {
            let bundle_parts: Vec<String> = components
                .iter()
                .filter_map(|(cname, l)| {
                    if ctx.is_zst_component(cname) {
                        ctx.resolve_ecs_struct_name(cname)
                    } else {
                        Some(format!("__loc_{}", l.0))
                    }
                })
                .collect();
            let bundle_expr = format_bundle_tuple(&bundle_parts);
            emit_cmd_block(out, analysis, indent, |cmds| {
                if let Some(d) = st.dst
                    && analysis.val_tys[d.0 as usize] == ValTy::Entity
                {
                    format!(
                        "let __sp = {cmds}.spawn({bundle_expr}).id(); __loc_{} = FfiEntity::from_bits(__sp.to_bits());",
                        d.0
                    )
                } else {
                    format!("{cmds}.spawn({bundle_expr});")
                }
            });
        }
        Inst::CmdSpawnBatch { count, components } => {
            let bundle_parts: Vec<String> = components
                .iter()
                .filter_map(|(cname, l)| {
                    if ctx.is_zst_component(cname) {
                        ctx.resolve_ecs_struct_name(cname)
                    } else {
                        Some(format!("__loc_{}", l.0))
                    }
                })
                .collect();
            let bundle_expr = format_bundle_tuple(&bundle_parts);
            let cnt_e = format!("(__loc_{} as usize)", count.0);
            emit_cmd_block(out, analysis, indent, |cmds| {
                format!("{cmds}.spawn_batch((0..{cnt_e}).map(move |_| {bundle_expr}));")
            });
        }
        Inst::SpawnBatchBegin { count, .. } => {
            if let Some(d) = st.dst
                && let Some(bp) = analysis.spawn_batches.iter().find(|b| b.dst_local == d)
            {
                writeln!(
                    out,
                    "{indent}{} = Vec::with_capacity(__loc_{} as usize);\n\
                     {indent}__loc_{} = {}u64;",
                    bp.var_name, count.0, d.0, bp.id
                )
                .ok();
            }
        }
        Inst::SpawnBatchPush {
            batch,
            index,
            components,
        } => {
            if let Some(srcs) = analysis.batch_sources.get(batch) {
                let emit_push_for = |out: &mut String, bp: &SpawnBatchPlan, arm_indent: &str| {
                    let row_parts: Vec<String> = bp
                        .slots
                        .iter()
                        .map(|slot| {
                            if slot.is_zst {
                                slot.struct_name.clone()
                            } else if let Some((_, val_l)) = components.iter().rfind(|(cn, _)| {
                                ctx.resolve_ecs_struct_name(cn).as_deref()
                                    == Some(slot.struct_name.as_str())
                            }) {
                                format!("__loc_{}", val_l.0)
                            } else {
                                format!("{}::default()", slot.struct_name)
                            }
                        })
                        .collect();
                    let row_expr = format_bundle_tuple(&row_parts);
                    let var = &bp.var_name;
                    writeln!(
                        out,
                        "{arm_indent}{{\n\
                         {arm_indent}    let __batch_row = {row_expr};\n\
                         {arm_indent}    let __batch_idx = __loc_{} as usize;\n\
                         {arm_indent}    if __batch_idx == {var}.len() {{\n\
                         {arm_indent}        {var}.push(__batch_row);\n\
                         {arm_indent}    }} else if __batch_idx < {var}.len() {{\n\
                         {arm_indent}        {var}[__batch_idx] = __batch_row;\n\
                         {arm_indent}    }} else {{\n\
                         {arm_indent}        {var}.resize_with(__batch_idx + 1, Default::default);\n\
                         {arm_indent}        {var}[__batch_idx] = __batch_row;\n\
                         {arm_indent}    }}\n\
                         {arm_indent}}}",
                        index.0
                    )
                    .ok();
                };
                if srcs.len() == 1 {
                    if let Some(&id) = srcs.iter().next()
                        && let Some(bp) = analysis.spawn_batches.get(id)
                    {
                        emit_push_for(out, bp, indent);
                    }
                } else if !srcs.is_empty() {
                    writeln!(out, "{indent}match __loc_{} {{", batch.0).ok();
                    let arm_ind = format!("{indent}        ");
                    for &id in srcs {
                        if let Some(bp) = analysis.spawn_batches.get(id) {
                            writeln!(out, "{indent}    {id}u64 => {{").ok();
                            emit_push_for(out, bp, &arm_ind);
                            writeln!(out, "{indent}    }}").ok();
                        }
                    }
                    writeln!(out, "{indent}    _ => {{}}\n{indent}}}").ok();
                }
            }
        }
        Inst::SpawnBatchCommit { batch } => {
            if let Some(srcs) = analysis.batch_sources.get(batch) {
                let emit_commit_for = |out: &mut String, bp: &SpawnBatchPlan, arm_indent: &str| {
                    writeln!(
                        out,
                        "{arm_indent}{{\n\
                         {arm_indent}    let __batch_rows = core::mem::take(&mut {});",
                        bp.var_name
                    )
                    .ok();
                    let inner_ind = format!("{arm_indent}    ");
                    emit_cmd_block(out, analysis, &inner_ind, |cmds| {
                        format!("{cmds}.spawn_batch(__batch_rows);")
                    });
                    writeln!(out, "{arm_indent}}}").ok();
                };
                if srcs.len() == 1 {
                    if let Some(&id) = srcs.iter().next()
                        && let Some(bp) = analysis.spawn_batches.get(id)
                    {
                        emit_commit_for(out, bp, indent);
                    }
                } else if !srcs.is_empty() {
                    writeln!(out, "{indent}match __loc_{} {{", batch.0).ok();
                    let arm_ind = format!("{indent}        ");
                    for &id in srcs {
                        if let Some(bp) = analysis.spawn_batches.get(id) {
                            writeln!(out, "{indent}    {id}u64 => {{").ok();
                            emit_commit_for(out, bp, &arm_ind);
                            writeln!(out, "{indent}    }}").ok();
                        }
                    }
                    writeln!(out, "{indent}    _ => {{}}\n{indent}}}").ok();
                }
            }
        }
        Inst::CmdDespawn { entity } => {
            let ent = format!("__loc_{}", entity.0);
            emit_cmd_block(out, analysis, indent, |cmds| {
                format!(
                    "if let Some(__e) = Entity::try_from_bits({ent}.to_bits()) {{ {cmds}.entity(__e).despawn(); }}"
                )
            });
        }
        Inst::CmdDespawnAll { filter } => {
            let parsed = parse_despawn_filters(filter);
            let mut f_parts = Vec::new();
            for (kind, cname) in parsed {
                if let Some(sname) = ctx.resolve_ecs_struct_name(&cname) {
                    f_parts.push(format!("{kind}<{sname}>"));
                }
            }
            let filter_ty = if f_parts.is_empty() {
                "()".to_owned()
            } else if f_parts.len() == 1 {
                f_parts[0].clone()
            } else {
                format!("({})", f_parts.join(", "))
            };
            emit_cmd_block(out, analysis, indent, |cmds| {
                format!("{cmds}.despawn_all::<{filter_ty}>();")
            });
        }
        Inst::CmdInsert {
            entity,
            component,
            data,
            if_new,
        } => {
            let ent = format!("__loc_{}", entity.0);
            let val_expr = if let Some(d) = data {
                if ctx.is_zst_component(component) {
                    ctx.resolve_ecs_struct_name(component)
                        .unwrap_or_else(|| "()".to_owned())
                } else {
                    format!("__loc_{}", d.0)
                }
            } else {
                format!(
                    "{}::default()",
                    ctx.resolve_ecs_struct_name(component)
                        .unwrap_or_else(|| "()".to_owned())
                )
            };
            let method = if *if_new { "insert_if_new" } else { "insert" };
            emit_cmd_block(out, analysis, indent, |cmds| {
                format!(
                    "if let Some(__e) = Entity::try_from_bits({ent}.to_bits()) {{ {cmds}.entity(__e).{method}({val_expr}); }}"
                )
            });
        }
        Inst::CmdRemove { entity, component } => {
            if let Some(sname) = ctx.resolve_ecs_struct_name(component) {
                let ent = format!("__loc_{}", entity.0);
                emit_cmd_block(out, analysis, indent, |cmds| {
                    format!(
                        "if let Some(__e) = Entity::try_from_bits({ent}.to_bits()) {{ {cmds}.entity(__e).remove::<{sname}>(); }}"
                    )
                });
            }
        }
        Inst::CmdTrigger {
            event,
            target,
            payload,
            ..
        } => {
            if let Some(ev_entry) = ctx.find_layout_entry(event) {
                let mut ev_expr = if let Some(pl) = payload {
                    if ev_entry.layout.size == 0 || ev_entry.layout.fields.is_empty() {
                        ev_entry.struct_name.clone()
                    } else {
                        format!("__loc_{}", pl.0)
                    }
                } else if ev_entry.layout.size == 0 || ev_entry.layout.fields.is_empty() {
                    ev_entry.struct_name.clone()
                } else {
                    format!("{}::default()", ev_entry.struct_name)
                };
                let is_entity_ev = ctx.entity_events.contains(&ev_entry.layout.canonical_name);
                let resolve_trig_target = |tgt: LocalId| -> String {
                    if analysis.val_tys[tgt.0 as usize] == ValTy::Entity {
                        return format!("__loc_{}", tgt.0);
                    }
                    if let Some(cl) = in_chunk {
                        for &bid in &cl.loop_blocks {
                            for s in &func.blocks[bid.0 as usize].stmts {
                                if matches!(s.inst, Inst::EntityAtRow { .. })
                                    && let Some(ed) = s.dst
                                    && analysis.val_tys[ed.0 as usize] == ValTy::Entity
                                {
                                    return format!("__loc_{}", ed.0);
                                }
                            }
                        }
                    }
                    "FfiEntity::NULL".to_owned()
                };
                if is_entity_ev {
                    if let Some(tgt) = target {
                        let t_expr = resolve_trig_target(*tgt);
                        ev_expr = format!(
                            "{{ let mut __ev = {ev_expr}; if __ev.entity.0 == FfiEntity::NULL {{ __ev.entity = StrataTargetEntity({t_expr}); }} __ev }}"
                        );
                    }
                    emit_cmd_block(out, analysis, indent, |cmds| {
                        format!("{cmds}.trigger({ev_expr});")
                    });
                } else if let Some(tgt) = target {
                    let t_expr = resolve_trig_target(*tgt);
                    emit_cmd_block(out, analysis, indent, |cmds| {
                        format!(
                            "let __ev_p = {ev_expr}; let __ev_t = {t_expr};\n\
                             {cmds}.queue(move |__w: &mut World| {{\n\
                             \x20   let __has = __w.contains_resource::<StrataTriggerTargetStack>();\n\
                             \x20   if __has {{ __w.resource_mut::<StrataTriggerTargetStack>().0.push(__ev_t); }}\n\
                             \x20   __w.trigger(__ev_p);\n\
                             \x20   if __has {{ __w.resource_mut::<StrataTriggerTargetStack>().0.pop(); }}\n\
                             }});"
                        )
                    });
                } else {
                    emit_cmd_block(out, analysis, indent, |cmds| {
                        format!("{cmds}.trigger({ev_expr});")
                    });
                }
            }
        }
        Inst::StreamEmit { stream, payload } => {
            if let Some(entry) = ctx.find_layout_entry(stream) {
                let p_expr = if entry.layout.size == 0 || entry.layout.fields.is_empty() {
                    entry.struct_name.clone()
                } else {
                    format!("__loc_{}", payload.0)
                };
                if in_chunk.is_some_and(|c| c.use_par) {
                    writeln!(
                        out,
                        "{indent}par_commands.command_scope(|mut __c| {{ __c.write_message({p_expr}); }});"
                    )
                    .ok();
                } else if let Some(mw_name) =
                    analysis.stream_writers.get(&entry.layout.canonical_name)
                {
                    writeln!(out, "{indent}{mw_name}.write({p_expr});").ok();
                }
            }
        }
        Inst::CmdCheckpoint => {
            if let Some(d) = st.dst {
                writeln!(
                    out,
                    "{indent}__loc_{} = __tx_cmds.len(); __tx_active = true;",
                    d.0
                )
                .ok();
            }
        }
        Inst::CmdRollback { checkpoint } => {
            writeln!(
                out,
                "{indent}__tx_cmds.truncate(__loc_{}); __tx_active = false;",
                checkpoint.0
            )
            .ok();
        }
        Inst::ShadowCommit { .. } => {
            if analysis.has_checkpoint {
                writeln!(out, "{indent}__tx_active = false;").ok();
            }
        }
        Inst::CmdInsertRelation {
            relation,
            entity,
            target,
            payload,
        } => {
            if let Some((vname, _)) = analysis.relation_res_map.get(relation.as_str()) {
                let p_expr = payload
                    .map(|p| format!("__loc_{}", p.0))
                    .unwrap_or_else(|| "()".to_owned());
                writeln!(
                    out,
                    "{indent}if let (Some(__s), Some(__d)) = (Entity::try_from_bits(__loc_{}.to_bits()), Entity::try_from_bits(__loc_{}.to_bits())) {{\n\
                     {indent}    {vname}.insert(__s, __d, {p_expr});\n\
                     {indent}}}",
                    entity.0, target.0
                )
                .ok();
            }
        }
        Inst::CmdRemoveRelation {
            relation,
            entity,
            target,
        } => {
            if let Some((vname, _)) = analysis.relation_res_map.get(relation.as_str()) {
                writeln!(
                    out,
                    "{indent}if let (Some(__s), Some(__d)) = (Entity::try_from_bits(__loc_{}.to_bits()), Entity::try_from_bits(__loc_{}.to_bits())) {{\n\
                     {indent}    {vname}.remove(__s, __d);\n\
                     {indent}}}",
                    entity.0, target.0
                )
                .ok();
            }
        }
    }
    let _ = dst_s;
    Ok(())
}

fn format_bundle_tuple(parts: &[String]) -> String {
    if parts.is_empty() {
        return "()".to_owned();
    }
    if parts.len() <= 12 {
        return format!("({},)", parts.join(", "));
    }
    let chunks: Vec<String> = parts.chunks(12).map(format_bundle_tuple).collect();
    format_bundle_tuple(&chunks)
}

fn emit_cmd_block(
    out: &mut String,
    analysis: &FnAnalysis,
    indent: &str,
    build: impl FnOnce(&str) -> String,
) {
    if analysis.needs_par_commands {
        let body = build("__cmds");
        writeln!(
            out,
            "{indent}par_commands.command_scope(|mut __cmds| {{ {body} }});"
        )
        .ok();
    } else if analysis.has_checkpoint {
        let body = build("__cmds");
        writeln!(
            out,
            "{indent}if __tx_active {{\n\
             {indent}    __tx_cmds.push(__StrataTxCmd::Spawn(Box::new(move |mut __cmds| {{ {body} }})));\n\
             {indent}}} else {{\n\
             {indent}    let __cmds = &mut commands;\n\
             {indent}    {body}\n\
             {indent}}}"
        )
        .ok();
    } else {
        let body = build("commands");
        writeln!(out, "{indent}{body}").ok();
    }
}

fn query_access_expr(plan: &QueryEmitPlan) -> String {
    if let Some(pidx) = plan.param_set_idx {
        format!("q_set.p{pidx}()")
    } else {
        plan.param_name.clone()
    }
}

fn chunk_len_expr(
    query_idx: u32,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
) -> String {
    let Some(plan) = query_plans.iter().find(|p| p.query_idx == query_idx) else {
        return "0u32".to_owned();
    };
    if plan.is_sparse || in_chunk.is_some_and(ChunkLoopInfo::is_1row) {
        return "1u32".to_owned();
    }
    if plan.needs_entity {
        return format!("(__q{query_idx}_entities.len() as u32)");
    }
    if let Some(slot) = plan.slots.first() {
        let si = slot.slot_idx;
        if slot.mode == TermAccessMode::SelectiveWrite {
            return format!("(__q{query_idx}_sel_{si}.len() as u32)");
        }
        return format!("(__q{query_idx}_col_{si}.len() as u32)");
    }
    "0u32".to_owned()
}

fn peel_ptr_fields(mut pt: &PtrTarget) -> (&PtrTarget, String) {
    let mut fields = Vec::new();
    while let PtrTarget::Field { base, field, .. } = pt {
        fields.push(sanitize_rust_ident(field));
        pt = base;
    }
    fields.reverse();
    let suffix: String = fields.into_iter().map(|f| format!(".{f}")).collect();
    (pt, suffix)
}

fn emit_place_mut(
    out: &mut String,
    ptr: LocalId,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    indent: &str,
    build: impl FnOnce(&str) -> String,
) {
    if let Some(pt) = analysis.ptr_targets.get(&ptr) {
        emit_place_mut_for_target(out, pt, query_plans, in_chunk, indent, build);
    }
}

fn emit_place_mut_for_target(
    out: &mut String,
    pt: &PtrTarget,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    indent: &str,
    build: impl FnOnce(&str) -> String,
) {
    let (base_pt, suffix) = peel_ptr_fields(pt);
    let apply = |base_expr: &str| {
        if suffix.is_empty() {
            build(base_expr)
        } else {
            build(&format!("(&mut {base_expr}{suffix})"))
        }
    };
    match base_pt {
        PtrTarget::Resource { var_name, .. } => {
            let body = apply(&format!("(&mut *{var_name})"));
            writeln!(out, "{indent}{body}").ok();
        }
        PtrTarget::ParamPtr { var_name, .. } => {
            let body = apply(var_name);
            writeln!(out, "{indent}{body}").ok();
        }
        PtrTarget::QueryRow {
            query_idx,
            slot_idx,
            row_idx_local,
            selective,
            optional,
            is_sparse,
            ..
        } => {
            let is_1row = *is_sparse || in_chunk.is_some_and(ChunkLoopInfo::is_1row);
            let is_pset_snap = in_chunk.is_some_and(|c| c.is_pset_snap);
            if *selective {
                if is_pset_snap {
                    let body = apply(&format!("(&mut *__q{query_idx}_sel_{slot_idx})"));
                    writeln!(
                        out,
                        "{indent}{body}\n{indent}__q{query_idx}_dirty_{slot_idx} = true;"
                    )
                    .ok();
                } else if is_1row {
                    let body = apply(&format!(
                        "(&mut *__q{query_idx}_sel_{slot_idx}.bypass_change_detection())"
                    ));
                    writeln!(
                        out,
                        "{indent}{body}\n{indent}__q{query_idx}_dirty_{slot_idx} = true;"
                    )
                    .ok();
                } else {
                    let body = apply(&format!(
                        "(&mut __q{query_idx}_sel_{slot_idx}.as_mut_untracked()[__loc_{} as usize])",
                        row_idx_local.0
                    ));
                    writeln!(
                        out,
                        "{indent}{body}\n{indent}__q{query_idx}_sel_{slot_idx}.mark_dirty_row(__loc_{} as usize);",
                        row_idx_local.0
                    )
                    .ok();
                }
            } else if *optional {
                let body = apply("__opt_item");
                if is_1row {
                    writeln!(
                        out,
                        "{indent}if let Some(ref mut __opt_item) = __q{query_idx}_col_{slot_idx} {{ {body} }}"
                    )
                    .ok();
                } else {
                    writeln!(
                        out,
                        "{indent}if let Some(ref mut __opt_s) = __q{query_idx}_col_{slot_idx} {{ let __opt_item = &mut __opt_s[__loc_{} as usize]; {body} }}",
                        row_idx_local.0
                    )
                    .ok();
                }
            } else if is_1row {
                let body = apply(&format!("(&mut *__q{query_idx}_col_{slot_idx})"));
                writeln!(out, "{indent}{body}").ok();
            } else {
                let body = apply(&format!(
                    "(&mut __q{query_idx}_col_{slot_idx}[__loc_{} as usize])",
                    row_idx_local.0
                ));
                writeln!(out, "{indent}{body}").ok();
            }
        }
        PtrTarget::EntityRow {
            query_idx,
            slot_idx,
            entity_local,
            optional,
            ..
        } => {
            let plan = &query_plans[*query_idx as usize];
            let qa = query_access_expr(plan);
            let tup_idx = slot_idx + usize::from(plan.needs_entity);
            let body = apply("__ent_comp");
            if *optional {
                writeln!(
                    out,
                    "{indent}if let Some(__e) = Entity::try_from_bits(__loc_{}.to_bits()) {{ if let Ok(mut __row) = {qa}.get_mut(__e) {{ if let Some(mut __mc) = __row.{tup_idx} {{ let __ent_comp = &mut *__mc; {body} }} }} }}",
                    entity_local.0
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "{indent}if let Some(__e) = Entity::try_from_bits(__loc_{}.to_bits()) {{ if let Ok(mut __row) = {qa}.get_mut(__e) {{ let __ent_comp = &mut *__row.{tup_idx}; {body} }} }}",
                    entity_local.0
                )
                .ok();
            }
        }
        PtrTarget::SlotRef { slot_local, .. } => {
            let body = apply(&format!("(&mut __slot_{})", slot_local.0));
            writeln!(out, "{indent}{body}").ok();
        }
        _ => {}
    }
}

fn emit_place_mut_res_expr(
    ptr: LocalId,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    build: impl FnOnce(&str) -> String,
) -> Option<String> {
    let pt = analysis.ptr_targets.get(&ptr)?;
    emit_place_mut_res_for_target(pt, query_plans, in_chunk, build)
}

fn emit_place_mut_res_for_target(
    pt: &PtrTarget,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    build: impl FnOnce(&str) -> String,
) -> Option<String> {
    let (base_pt, suffix) = peel_ptr_fields(pt);
    let apply = |base_expr: &str| {
        if suffix.is_empty() {
            build(base_expr)
        } else {
            build(&format!("(&mut {base_expr}{suffix})"))
        }
    };
    match base_pt {
        PtrTarget::Resource { var_name, .. } => Some(apply(&format!("(&mut *{var_name})"))),
        PtrTarget::ParamPtr { var_name, .. } => Some(apply(var_name)),
        PtrTarget::QueryRow {
            query_idx,
            slot_idx,
            row_idx_local,
            selective,
            optional,
            is_sparse,
            ..
        } => {
            let is_1row = *is_sparse || in_chunk.is_some_and(ChunkLoopInfo::is_1row);
            let is_pset_snap = in_chunk.is_some_and(|c| c.is_pset_snap);
            if *selective {
                if is_pset_snap {
                    let b = apply(&format!("(&mut *__q{query_idx}_sel_{slot_idx})"));
                    Some(format!(
                        "{{ let __r = {b}; if __r {{ __q{query_idx}_dirty_{slot_idx} = true; }} __r }}"
                    ))
                } else if is_1row {
                    let b = apply(&format!(
                        "(&mut *__q{query_idx}_sel_{slot_idx}.bypass_change_detection())"
                    ));
                    Some(format!(
                        "{{ let __r = {b}; if __r {{ __q{query_idx}_dirty_{slot_idx} = true; }} __r }}"
                    ))
                } else {
                    let b = apply(&format!(
                        "(&mut __q{query_idx}_sel_{slot_idx}.as_mut_untracked()[__loc_{} as usize])",
                        row_idx_local.0
                    ));
                    Some(format!(
                        "{{ let __r = {b}; if __r {{ __q{query_idx}_sel_{slot_idx}.mark_dirty_row(__loc_{} as usize); }} __r }}",
                        row_idx_local.0
                    ))
                }
            } else if *optional {
                let b = apply("__opt_item");
                if is_1row {
                    Some(format!(
                        "__q{query_idx}_col_{slot_idx}.as_deref_mut().map_or(false, |__opt_item| {b})"
                    ))
                } else {
                    Some(format!(
                        "__q{query_idx}_col_{slot_idx}.as_mut().map_or(false, |__opt_s| {{ let __opt_item = &mut __opt_s[__loc_{} as usize]; {b} }})",
                        row_idx_local.0
                    ))
                }
            } else if is_1row {
                Some(apply(&format!("(&mut *__q{query_idx}_col_{slot_idx})")))
            } else {
                Some(apply(&format!(
                    "(&mut __q{query_idx}_col_{slot_idx}[__loc_{} as usize])",
                    row_idx_local.0
                )))
            }
        }
        PtrTarget::EntityRow {
            query_idx,
            slot_idx,
            entity_local,
            optional,
            ..
        } => {
            let plan = &query_plans[*query_idx as usize];
            let qa = query_access_expr(plan);
            let tup_idx = slot_idx + usize::from(plan.needs_entity);
            let b = apply("__ent_comp");
            if *optional {
                Some(format!(
                    "Entity::try_from_bits(__loc_{}.to_bits()).is_some_and(|__e| {qa}.get_mut(__e).ok().is_some_and(|__row| __row.{tup_idx}.is_some_and(|mut __mc| {{ let __ent_comp = &mut *__mc; {b} }})))",
                    entity_local.0
                ))
            } else {
                Some(format!(
                    "Entity::try_from_bits(__loc_{}.to_bits()).is_some_and(|__e| {qa}.get_mut(__e).ok().is_some_and(|mut __row| {{ let __ent_comp = &mut *__row.{tup_idx}; {b} }}))",
                    entity_local.0
                ))
            }
        }
        PtrTarget::SlotRef { slot_local, .. } => {
            Some(apply(&format!("(&mut __slot_{})", slot_local.0)))
        }
        _ => None,
    }
}

fn emit_place_ref_expr(
    ptr: LocalId,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    build: impl FnOnce(&str) -> String,
    default_expr: &str,
) -> String {
    let Some(pt) = analysis.ptr_targets.get(&ptr) else {
        return format!("({})", build(&format!("(&__loc_{})", ptr.0)));
    };
    emit_place_ref_for_target(pt, analysis, query_plans, in_chunk, build, default_expr)
}

fn emit_place_ref_for_target(
    pt: &PtrTarget,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    build: impl FnOnce(&str) -> String,
    default_expr: &str,
) -> String {
    let (base_pt, suffix) = peel_ptr_fields(pt);
    let apply = |base_expr: &str| {
        if suffix.is_empty() {
            build(base_expr)
        } else {
            build(&format!("(&{base_expr}{suffix})"))
        }
    };
    match base_pt {
        PtrTarget::Resource { var_name, .. } => apply(&format!("(&*{var_name})")),
        PtrTarget::ParamPtr { var_name, .. } => apply(var_name),
        PtrTarget::TriggerPayload => {
            if in_chunk.is_some_and(|c| c.use_par) {
                apply("(&__obs_ev_copy)")
            } else {
                apply("on.event()")
            }
        }
        PtrTarget::QueryRow {
            query_idx,
            slot_idx,
            row_idx_local,
            selective,
            optional,
            is_sparse,
            ..
        } => {
            let is_1row = *is_sparse || in_chunk.is_some_and(ChunkLoopInfo::is_1row);
            if *selective {
                if is_1row {
                    apply(&format!("(&*__q{query_idx}_sel_{slot_idx})"))
                } else {
                    apply(&format!(
                        "(&__q{query_idx}_sel_{slot_idx}.as_slice()[__loc_{} as usize])",
                        row_idx_local.0
                    ))
                }
            } else if *optional {
                let b = apply("__opt_item");
                if is_1row {
                    format!(
                        "__q{query_idx}_col_{slot_idx}.as_deref().map_or({default_expr}, |__opt_item| {b})"
                    )
                } else {
                    format!(
                        "__q{query_idx}_col_{slot_idx}.as_ref().map_or({default_expr}, |__opt_s| {{ let __opt_item = &__opt_s[__loc_{} as usize]; {b} }})",
                        row_idx_local.0
                    )
                }
            } else if is_1row {
                apply(&format!("(&*__q{query_idx}_col_{slot_idx})"))
            } else {
                apply(&format!(
                    "(&__q{query_idx}_col_{slot_idx}[__loc_{} as usize])",
                    row_idx_local.0
                ))
            }
        }
        PtrTarget::EntityRow {
            query_idx,
            slot_idx,
            entity_local,
            optional,
            ..
        } => {
            let plan = &query_plans[*query_idx as usize];
            let qa = query_access_expr(plan);
            let tup_idx = slot_idx + usize::from(plan.needs_entity);
            let b = apply("__ent_comp");
            if *optional {
                format!(
                    "Entity::try_from_bits(__loc_{}.to_bits()).map_or({default_expr}, |__e| {qa}.get(__e).ok().map_or({default_expr}, |__row| __row.{tup_idx}.map_or({default_expr}, |__ent_comp| {b})))",
                    entity_local.0
                )
            } else {
                format!(
                    "Entity::try_from_bits(__loc_{}.to_bits()).map_or({default_expr}, |__e| {qa}.get(__e).ok().map_or({default_expr}, |__row| {{ let __ent_comp = &*__row.{tup_idx}; {b} }}))",
                    entity_local.0
                )
            }
        }
        PtrTarget::SlotRef { slot_local, .. } => {
            if let Some(s) = analysis.slot_tys.get(slot_local) {
                let _ = s;
                apply(&format!("(&__slot_{})", slot_local.0))
            } else {
                apply(&format!("(&__loc_{})", slot_local.0))
            }
        }
        _ => default_expr.to_owned(),
    }
}

fn resolve_field_access_chain<'a>(
    layout_key: &str,
    field: &str,
    ctx: &'a NativeCtx<'a>,
) -> (String, Option<&'a SolvedField>, bool) {
    if let Some((base_f, lane)) = field.rsplit_once('.')
        && let Some(sf) = ctx.resolve_field_info(layout_key, base_f)
        && matches!(
            sf.ty,
            Ty::Vec2
                | Ty::Vec3
                | Ty::Vec3a
                | Ty::Vec4
                | Ty::Quat
                | Ty::Rgba
                | Ty::IVec2
                | Ty::IVec3
                | Ty::UVec2
        )
    {
        let idx = match lane {
            "x" | "r" => Some(0),
            "y" | "g" => Some(1),
            "z" | "b" => Some(2),
            "w" | "a" => Some(3),
            _ => None,
        };
        if let Some(li) = idx {
            let rbase = sanitize_rust_ident(base_f);
            return (format!("{rbase}[{li}]"), None, true);
        }
    }
    if let Some(sf) = ctx.resolve_field_info(layout_key, field) {
        let field_parts: Vec<&str> = field.split('.').collect();
        let chain = field_parts
            .iter()
            .map(|p| sanitize_rust_ident(p))
            .collect::<Vec<_>>()
            .join(".");
        return (chain, Some(sf), false);
    }
    let field_parts: Vec<&str> = field.split('.').collect();
    let chain = field_parts
        .iter()
        .map(|p| sanitize_rust_ident(p))
        .collect::<Vec<_>>()
        .join(".");
    (chain, None, false)
}

#[allow(clippy::too_many_arguments)]
fn emit_field_load_expr(
    base_ptr: LocalId,
    layout_key: &str,
    field: &str,
    dst_vt: &ValTy,
    _func: &MirFunction,
    ctx: &NativeCtx<'_>,
    query_plans: &[QueryEmitPlan],
    analysis: &FnAnalysis,
    in_chunk: Option<&ChunkLoopInfo>,
) -> String {
    if layout_key == "tuple" || matches!(analysis.val_tys[base_ptr.0 as usize], ValTy::Tuple(_)) {
        let idx = field.trim_start_matches('_');
        return format!("__loc_{}.{idx}", base_ptr.0);
    }

    // Value-held table row or struct in an SSA register
    if !analysis.ptr_targets.contains_key(&base_ptr) {
        let (access_chain, sf_opt, _) = resolve_field_access_chain(layout_key, field, ctx);
        let raw = format!("__loc_{}.{access_chain}", base_ptr.0);
        if let Some(sf) = sf_opt {
            return unwrap_abi_field_load(&raw, sf, dst_vt, ctx);
        }
        return raw;
    }

    let (access_chain, sf_opt, _) = resolve_field_access_chain(layout_key, field, ctx);
    let def_expr = dst_vt.default_expr();

    emit_place_ref_expr(
        base_ptr,
        analysis,
        query_plans,
        in_chunk,
        |place| {
            let raw = format!("{place}.{access_chain}");
            if let Some(sf) = sf_opt {
                unwrap_abi_field_load(&raw, sf, dst_vt, ctx)
            } else {
                raw
            }
        },
        &def_expr,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_field_store_stmt(
    out: &mut String,
    base_ptr: LocalId,
    layout_key: &str,
    field: &str,
    val: LocalId,
    ctx: &NativeCtx<'_>,
    query_plans: &[QueryEmitPlan],
    analysis: &FnAnalysis,
    indent: &str,
    in_chunk: Option<&ChunkLoopInfo>,
) {
    let (access_chain, sf_opt, is_vec_lane) = resolve_field_access_chain(layout_key, field, ctx);
    if sf_opt.is_none() && !is_vec_lane && ctx.find_layout_entry(layout_key).is_some() {
        return;
    }

    let (src_vt, src_raw_expr) =
        effective_local_val_and_expr(val, analysis, query_plans, in_chunk, ctx);
    let val_expr = if let Some(sf) = sf_opt {
        let target_vt = ValTy::from_solved_field(sf, ctx);
        let coerced = coerce_expr(&src_raw_expr, &src_vt, &target_vt);
        let is_ent_ev = ctx
            .find_layout_entry(layout_key)
            .is_some_and(|e| ctx.entity_events.contains(&e.layout.canonical_name));
        wrap_abi_field_store(&coerced, sf, ctx, is_ent_ev)
    } else if is_vec_lane {
        coerce_expr(&src_raw_expr, &src_vt, &ValTy::F32)
    } else {
        src_raw_expr
    };

    emit_place_mut(
        out,
        base_ptr,
        analysis,
        query_plans,
        in_chunk,
        indent,
        |place| format!("{place}.{access_chain} = {val_expr};"),
    );
}

fn unwrap_abi_field_load(
    raw: &str,
    sf: &SolvedField,
    dst_vt: &ValTy,
    ctx: &NativeCtx<'_>,
) -> String {
    let field_vt = ValTy::from_solved_field(sf, ctx);
    let normalized = match &sf.ty {
        Ty::Bool => format!("({raw}).get()"),
        Ty::Fix32 => format!("Fixed32({raw})"),
        Ty::Fix64 => format!("Fixed64({raw})"),
        Ty::IVec2 | Ty::UVec2 => format!("[({raw})[0] as f32, ({raw})[1] as f32]"),
        Ty::IVec3 => format!("[({raw})[0] as f32, ({raw})[1] as f32, ({raw})[2] as f32]"),
        _ => raw.to_owned(),
    };
    let eff_from = match &sf.ty {
        Ty::Bool => ValTy::Bool,
        _ => field_vt,
    };
    coerce_expr(&normalized, &eff_from, dst_vt)
}

fn wrap_abi_field_store(
    val_expr: &str,
    sf: &SolvedField,
    ctx: &NativeCtx<'_>,
    is_entity_ev: bool,
) -> String {
    if is_entity_ev && sf.name == "entity" {
        return format!("StrataTargetEntity({val_expr})");
    }
    let _ = ctx;
    match &sf.ty {
        Ty::Bool => format!("FfiBool::from_bool({val_expr})"),
        Ty::Fix32 | Ty::Fix64 => format!("({val_expr}).0"),
        Ty::IVec2 => format!("[({val_expr})[0] as i32, ({val_expr})[1] as i32]"),
        Ty::UVec2 => format!("[({val_expr})[0] as u32, ({val_expr})[1] as u32]"),
        Ty::IVec3 => {
            format!("[({val_expr})[0] as i32, ({val_expr})[1] as i32, ({val_expr})[2] as i32]")
        }
        _ => val_expr.to_owned(),
    }
}

fn coerce_expr(expr: &str, from: &ValTy, to: &ValTy) -> String {
    if from == to || *to == ValTy::Unit || *to == ValTy::PtrMarker {
        return expr.to_owned();
    }
    match (from, to) {
        (ValTy::Entity, ValTy::U64) => format!("({expr}).to_bits()"),
        (ValTy::U64, ValTy::Entity) => format!("FfiEntity::from_bits({expr})"),
        (ValTy::Fix32, ValTy::F32) => format!("({expr}).to_f32()"),
        (ValTy::F32, ValTy::Fix32) => format!("Fixed32::from_f32({expr})"),
        (ValTy::Fix64, ValTy::F64) => format!("({expr}).to_f64()"),
        (ValTy::F64, ValTy::Fix64) => format!("Fixed64::from_f64({expr})"),
        (ValTy::Fix32, ValTy::I32) | (ValTy::Fix64, ValTy::I64) => format!("({expr}).0"),
        (ValTy::I32, ValTy::Fix32) => format!("Fixed32({expr})"),
        (ValTy::I64, ValTy::Fix64) => format!("Fixed64({expr})"),
        (ValTy::Vec3, ValTy::Vec2) | (ValTy::Vec4, ValTy::Vec2) => {
            format!("[({expr})[0], ({expr})[1]]")
        }
        (ValTy::Vec2, ValTy::Vec3) => format!("[({expr})[0], ({expr})[1], 0.0_f32]"),
        (ValTy::Vec4, ValTy::Vec3) => format!("[({expr})[0], ({expr})[1], ({expr})[2]]"),
        (ValTy::Bool, t) if t.is_int() => format!("(({expr} as u8) as {})", t.rust_type()),
        (f, ValTy::Bool) if f.is_int() => format!("(({expr}) != 0)"),
        (f, t) if (f.is_int() || f.is_float()) && (t.is_int() || t.is_float()) => {
            format!("(({expr}) as {})", t.rust_type())
        }
        _ => expr.to_owned(),
    }
}

fn ptr_projected_field(pt: &PtrTarget) -> Option<&(String, String, ValTy)> {
    match pt {
        PtrTarget::QueryCol { projected, .. }
        | PtrTarget::QueryRow { projected, .. }
        | PtrTarget::EntityRow { projected, .. } => projected.as_ref(),
        _ => None,
    }
}

fn effective_local_val_and_expr(
    lid: LocalId,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    ctx: &NativeCtx<'_>,
) -> (ValTy, String) {
    let vt = &analysis.val_tys[lid.0 as usize];
    if *vt == ValTy::PtrMarker
        && let Some(pt) = analysis.ptr_targets.get(&lid)
        && let Some((canon, pf, fvt)) = ptr_projected_field(pt)
    {
        let (access_chain, sf_opt, _) = resolve_field_access_chain(canon, pf, ctx);
        let def_e = fvt.default_expr();
        let expr = emit_place_ref_for_target(
            pt,
            analysis,
            query_plans,
            in_chunk,
            |place| {
                let raw = format!("{place}.{access_chain}");
                if let Some(sf) = sf_opt {
                    unwrap_abi_field_load(&raw, sf, fvt, ctx)
                } else {
                    raw
                }
            },
            &def_e,
        );
        return (fvt.clone(), expr);
    }
    (vt.clone(), format!("__loc_{}", lid.0))
}

#[allow(clippy::too_many_arguments)]
fn emit_binop_expr(
    op: &str,
    lhs: LocalId,
    rhs: LocalId,
    dst_vt: &ValTy,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    ctx: &NativeCtx<'_>,
) -> String {
    let (lt_val, le) = effective_local_val_and_expr(lhs, analysis, query_plans, in_chunk, ctx);
    let (rt_val, re) = effective_local_val_and_expr(rhs, analysis, query_plans, in_chunk, ctx);
    let lt = &lt_val;
    let rt = &rt_val;

    // Null pointer checks produced by `emit_query_one_lookup`: `ptr_l != null_p`
    if *lt == ValTy::Bool && *rt == ValTy::PtrMarker && !analysis.ptr_targets.contains_key(&rhs) {
        return match op {
            "==" => format!("(!{le})"),
            _ => le,
        };
    }
    if *rt == ValTy::Bool && *lt == ValTy::PtrMarker && !analysis.ptr_targets.contains_key(&lhs) {
        return match op {
            "==" => format!("(!{re})"),
            _ => re,
        };
    }
    if *lt == ValTy::PtrMarker || *rt == ValTy::PtrMarker {
        return match op {
            "==" => "false".to_owned(),
            _ => "true".to_owned(),
        };
    }

    // Vector binary ops
    match (lt.is_vec(), rt.is_vec()) {
        (Some(d), Some(_)) => {
            if matches!(op, "==" | "!=") {
                let re_c = coerce_expr(&re, rt, lt);
                return format!("({le} {op} {re_c})");
            }
            let fn_name = match (d, op) {
                (2, "+") => "strata_v2_add",
                (2, "-") => "strata_v2_sub",
                (2, "*") => "strata_v2_mul",
                (2, "/") => "strata_v2_div",
                (3, "-") => "strata_v3_sub",
                (3, "*") => "strata_v3_mul",
                (3, "/") => "strata_v3_div",
                (4, "+") => "strata_v4_add",
                (4, "-") => "strata_v4_sub",
                (4, "*") => "strata_v4_mul",
                (4, "/") => "strata_v4_div",
                _ => "strata_v3_add",
            };
            let re_c = coerce_expr(&re, rt, lt);
            return format!("{fn_name}({le}, {re_c})");
        }
        (Some(d), None) => {
            let s = coerce_expr(&re, rt, &ValTy::F32);
            let fn_name = match d {
                2 => "strata_v2_scale",
                3 => "strata_v3_scale",
                _ => "strata_v4_scale",
            };
            let expr = if op == "/" {
                format!("{fn_name}({le}, 1.0_f32 / {s})")
            } else {
                format!("{fn_name}({le}, {s})")
            };
            return coerce_expr(&expr, lt, dst_vt);
        }
        (None, Some(d)) => {
            let s = coerce_expr(&le, lt, &ValTy::F32);
            let fn_name = match d {
                2 => "strata_v2_scale",
                3 => "strata_v3_scale",
                _ => "strata_v4_scale",
            };
            return format!("{fn_name}({re}, {s})");
        }
        (None, None) => {}
    }

    // Scalar binary ops & comparisons
    let is_cmp = matches!(op, "==" | "!=" | "<" | "<=" | ">" | ">=");
    let common_ty = if is_cmp {
        common_scalar_type(lt, rt)
    } else if *dst_vt != ValTy::Unit && *dst_vt != ValTy::PtrMarker {
        dst_vt.clone()
    } else {
        common_scalar_type(lt, rt)
    };
    let lc = coerce_expr(&le, lt, &common_ty);
    let rc = coerce_expr(&re, rt, &common_ty);
    format!("({lc} {op} {rc})")
}

fn common_scalar_type(a: &ValTy, b: &ValTy) -> ValTy {
    if a == b {
        return a.clone();
    }
    if *a == ValTy::Entity || *b == ValTy::Entity {
        return ValTy::Entity;
    }
    if *a == ValTy::Fix64 || *b == ValTy::Fix64 {
        return ValTy::Fix64;
    }
    if *a == ValTy::Fix32 || *b == ValTy::Fix32 {
        return ValTy::Fix32;
    }
    if *a == ValTy::F64 || *b == ValTy::F64 {
        return ValTy::F64;
    }
    if *a == ValTy::F32 || *b == ValTy::F32 {
        return ValTy::F32;
    }
    if a.is_int() && b.is_int() {
        // Prefer specific non-i64 operand width when comparing against untyped IntLit (I64)
        if *a != ValTy::I64 && *b == ValTy::I64 {
            return a.clone();
        }
        if *b != ValTy::I64 && *a == ValTy::I64 {
            return b.clone();
        }
    }
    a.clone()
}

fn emit_intrinsic_math(
    name: &str,
    args: &[LocalId],
    dst_vt: &ValTy,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
    ctx: &NativeCtx<'_>,
) -> String {
    let arg_raw = |idx: usize| -> (ValTy, String) {
        if let Some(&lid) = args.get(idx) {
            effective_local_val_and_expr(lid, analysis, query_plans, in_chunk, ctx)
        } else {
            (ValTy::F32, "0.0_f32".to_owned())
        }
    };
    let arg_s = |idx: usize, expected: &ValTy| -> String {
        if args.get(idx).is_some() {
            let (vt, expr) = arg_raw(idx);
            coerce_expr(&expr, &vt, expected)
        } else {
            expected.default_expr()
        }
    };
    match name {
        "vec2" => format!("[{}, {}]", arg_s(0, &ValTy::F32), arg_s(1, &ValTy::F32)),
        "vec3" => format!(
            "[{}, {}, {}]",
            arg_s(0, &ValTy::F32),
            arg_s(1, &ValTy::F32),
            arg_s(2, &ValTy::F32)
        ),
        "vec4" => format!(
            "[{}, {}, {}, {}]",
            arg_s(0, &ValTy::F32),
            arg_s(1, &ValTy::F32),
            arg_s(2, &ValTy::F32),
            arg_s(3, &ValTy::F32)
        ),
        "sin" | "cos" | "tan" | "sqrt" | "abs" | "floor" | "ceil" | "round" | "exp" | "ln" => {
            let fty = if *dst_vt == ValTy::F64 {
                ValTy::F64
            } else {
                ValTy::F32
            };
            format!("({}).{name}()", arg_s(0, &fty))
        }
        "atan2" | "pow" => {
            let fty = if *dst_vt == ValTy::F64 {
                ValTy::F64
            } else {
                ValTy::F32
            };
            let m = if name == "pow" { "powf" } else { "atan2" };
            format!("({}).{m}({})", arg_s(0, &fty), arg_s(1, &fty))
        }
        "min" | "max" => {
            let (t0, _) = arg_raw(0);
            let (t1, _) = arg_raw(1);
            let ct = if *dst_vt != ValTy::Unit {
                dst_vt.clone()
            } else {
                common_scalar_type(&t0, &t1)
            };
            format!("({}).{name}({})", arg_s(0, &ct), arg_s(1, &ct))
        }
        "clamp" => {
            let ct = if *dst_vt != ValTy::Unit {
                dst_vt.clone()
            } else {
                ValTy::F32
            };
            format!(
                "({}).clamp({}, {})",
                arg_s(0, &ct),
                arg_s(1, &ct),
                arg_s(2, &ct)
            )
        }
        "lerp" => {
            let ct = if *dst_vt != ValTy::Unit {
                dst_vt.clone()
            } else {
                ValTy::F32
            };
            let a = arg_s(0, &ct);
            let b = arg_s(1, &ct);
            let t = arg_s(2, &ValTy::F32);
            match ct.is_vec() {
                Some(2) => {
                    format!("strata_v2_add({a}, strata_v2_scale(strata_v2_sub({b}, {a}), {t}))")
                }
                Some(3) => {
                    format!("strata_v3_add({a}, strata_v3_scale(strata_v3_sub({b}, {a}), {t}))")
                }
                Some(4) => {
                    format!("strata_v4_add({a}, strata_v4_scale(strata_v4_sub({b}, {a}), {t}))")
                }
                _ => format!("({a} + ({b} - {a}) * {t})"),
            }
        }
        "dot" => {
            let (_, e0) = arg_raw(0);
            let (_, e1) = arg_raw(1);
            format!("strata_dot(&({e0}), &({e1}))")
        }
        "length" => {
            let (_, e0) = arg_raw(0);
            format!("strata_len(&({e0}))")
        }
        "distance" => {
            let (_, e0) = arg_raw(0);
            let (_, e1) = arg_raw(1);
            format!("strata_dist(&({e0}), &({e1}))")
        }
        "normalize" => {
            let (t0, e0) = arg_raw(0);
            match t0.is_vec() {
                Some(2) => format!("strata_norm_v2({e0})"),
                Some(4) => format!("strata_norm_v4({e0})"),
                _ => format!("strata_norm_v3({e0})"),
            }
        }
        "cross" => {
            let (_, e0) = arg_raw(0);
            let (_, e1) = arg_raw(1);
            format!("strata_cross({e0}, {e1})")
        }
        _ => dst_vt.default_expr(),
    }
}

fn emit_call_expr(
    callee: &str,
    args: &[LocalId],
    dst_vt: Option<&ValTy>,
    ctx: &NativeCtx<'_>,
    analysis: &FnAnalysis,
    query_plans: &[QueryEmitPlan],
    in_chunk: Option<&ChunkLoopInfo>,
) -> Result<String, CodegenError> {
    if let Some(hf) = ctx.helpers_by_key.get(callee) {
        let mut arg_strs = Vec::with_capacity(args.len());
        for (i, a) in args.iter().enumerate() {
            let arg_expr = if let Some(p) = hf.params.get(i) {
                match p.kind {
                    HirParamKind::Ref => {
                        if let Some(pt) = analysis.ptr_targets.get(a) {
                            match pt {
                                PtrTarget::Resource { var_name, .. } => format!("(&*{var_name})"),
                                PtrTarget::ParamPtr { var_name, .. } => var_name.clone(),
                                _ => format!("(&__loc_{})", a.0),
                            }
                        } else {
                            format!("(&__loc_{})", a.0)
                        }
                    }
                    HirParamKind::RefMut => {
                        if let Some(pt) = analysis.ptr_targets.get(a) {
                            match pt {
                                PtrTarget::Resource { var_name, .. } => {
                                    format!("(&mut *{var_name})")
                                }
                                PtrTarget::ParamPtr { var_name, .. } => var_name.clone(),
                                _ => format!("(&mut __loc_{})", a.0),
                            }
                        } else {
                            format!("(&mut __loc_{})", a.0)
                        }
                    }
                    _ => {
                        let target_vt = ValTy::from_mir(&p.ty, ctx);
                        let (avt, aexpr) =
                            effective_local_val_and_expr(*a, analysis, query_plans, in_chunk, ctx);
                        coerce_expr(&aexpr, &avt, &target_vt)
                    }
                }
            } else {
                effective_local_val_and_expr(*a, analysis, query_plans, in_chunk, ctx).1
            };
            arg_strs.push(arg_expr);
        }
        let fn_ident = sanitize_ident(&hf.name);
        return Ok(format!("strata_fn_{fn_ident}({})", arg_strs.join(", ")));
    }

    if let Some(item_name) = callee.strip_suffix("::start") {
        if let Some(tl) = ctx.timelines_by_key.get(item_name)
            && let Some(entry) = ctx.find_layout_entry(&tl.canonical_name)
        {
            return Ok(format!(
                "{} {{ cur_frame: 0, flags: 1, active_mask: 0, accum_sec: 0.0_f32, ..Default::default() }}",
                entry.struct_name
            ));
        }
        if let Some(tk) = ctx.tasks_by_key.get(item_name)
            && let Some(entry) = ctx.find_layout_entry(&tk.state_layout.canonical_name)
        {
            let mut inits = vec!["__pc: 0u8".to_owned(), "__timer: 0.0_f32".to_owned()];
            for (pi, tp) in tk.typed_params.iter().enumerate() {
                let pident = sanitize_rust_ident(&tp.name);
                if let Some(&arg_l) = args.get(pi) {
                    let sf = entry.layout.fields.iter().find(|f| f.name == tp.name);
                    let val_s = if let Some(sf) = sf {
                        let target_vt = ValTy::from_solved_field(sf, ctx);
                        let c = coerce_expr(
                            &format!("__loc_{}", arg_l.0),
                            &analysis.val_tys[arg_l.0 as usize],
                            &target_vt,
                        );
                        wrap_abi_field_store(&c, sf, ctx, false)
                    } else {
                        format!("__loc_{}", arg_l.0)
                    };
                    inits.push(format!("{pident}: {val_s}"));
                }
            }
            return Ok(format!(
                "{} {{ {}, ..Default::default() }}",
                entry.struct_name,
                inits.join(", ")
            ));
        }
        if let Some(fsm) = ctx.fsms_by_key.get(item_name)
            && let Some(entry) = ctx.find_layout_entry(&fsm.state_layout.canonical_name)
        {
            return Ok(format!(
                "{} {{ __state: 0, __flags: 0, ..Default::default() }}",
                entry.struct_name
            ));
        }
    }

    match callee {
        "sqr" => {
            let a0 = args.first().copied().unwrap_or(LocalId(0));
            let vt = dst_vt.unwrap_or(&ValTy::F32);
            let (avt, ae) = effective_local_val_and_expr(a0, analysis, query_plans, in_chunk, ctx);
            let x = coerce_expr(&ae, &avt, vt);
            Ok(format!("({x} * {x})"))
        }
        "distance_sq" => {
            let a0 = args.first().copied().unwrap_or(LocalId(0));
            let a1 = args.get(1).copied().unwrap_or(LocalId(0));
            let e0 = effective_local_val_and_expr(a0, analysis, query_plans, in_chunk, ctx).1;
            let e1 = effective_local_val_and_expr(a1, analysis, query_plans, in_chunk, ctx).1;
            Ok(format!("strata_dist_sq(&({e0}), &({e1}))"))
        }
        "ivec2" | "uvec2" => {
            let x = args.first().map_or_else(
                || "0.0_f32".to_owned(),
                |l| format!("(__loc_{} as f32)", l.0),
            );
            let y = args.get(1).map_or_else(
                || "0.0_f32".to_owned(),
                |l| format!("(__loc_{} as f32)", l.0),
            );
            Ok(format!("[{x}, {y}]"))
        }
        "ivec3" => {
            let x = args.first().map_or_else(
                || "0.0_f32".to_owned(),
                |l| format!("(__loc_{} as f32)", l.0),
            );
            let y = args.get(1).map_or_else(
                || "0.0_f32".to_owned(),
                |l| format!("(__loc_{} as f32)", l.0),
            );
            let z = args.get(2).map_or_else(
                || "0.0_f32".to_owned(),
                |l| format!("(__loc_{} as f32)", l.0),
            );
            Ok(format!("[{x}, {y}, {z}]"))
        }
        _ => Ok(dst_vt.map_or_else(|| "()".to_owned(), ValTy::default_expr)),
    }
}

fn emit_terminator(
    out: &mut String,
    func: &MirFunction,
    analysis: &FnAnalysis,
    term: &Terminator,
    indent: &str,
    in_chunk: Option<&ChunkLoopInfo>,
) {
    match term {
        Terminator::Return(opt_l) => {
            if let Some(cl) = in_chunk {
                if !cl.use_par {
                    writeln!(out, "{indent}__broke_loop = true;").ok();
                }
                writeln!(out, "{indent}break;").ok();
            } else if let Some(l) = opt_l
                && matches!(func.kind, MirFnKind::HelperFn)
                && analysis.val_tys[l.0 as usize] != ValTy::Unit
            {
                let ret_vt = ValTy::from_mir_ret(&func.ret_ty);
                let coerced = if matches!(func.ret_ty, MirType::Named(_)) {
                    format!("__loc_{}", l.0)
                } else {
                    coerce_expr(
                        &format!("__loc_{}", l.0),
                        &analysis.val_tys[l.0 as usize],
                        &ret_vt,
                    )
                };
                writeln!(out, "{indent}return {coerced};").ok();
            } else {
                writeln!(out, "{indent}return;").ok();
            }
        }
        Terminator::Goto(dst) => {
            if let Some(cl) = in_chunk {
                if *dst == cl.hdr_bb {
                    writeln!(out, "{indent}break;").ok();
                } else if *dst == cl.exit_bb {
                    if !cl.use_par {
                        writeln!(out, "{indent}__broke_loop = true;").ok();
                    }
                    writeln!(out, "{indent}break;").ok();
                } else {
                    writeln!(out, "{indent}__inner_bb = {};", dst.0).ok();
                }
            } else {
                writeln!(out, "{indent}__bb = {};", dst.0).ok();
            }
        }
        Terminator::Branch {
            cond,
            then_bb,
            else_bb,
        } => {
            let c_expr = format!("__loc_{}", cond.0);
            let then_arm = format_branch_target(*then_bb, in_chunk);
            let else_arm = format_branch_target(*else_bb, in_chunk);
            writeln!(
                out,
                "{indent}if {c_expr} {{ {then_arm} }} else {{ {else_arm} }}"
            )
            .ok();
        }
        Terminator::Switch {
            scrutinee,
            cases,
            default_bb,
        } => {
            writeln!(out, "{indent}match __loc_{} as u32 {{", scrutinee.0).ok();
            for (disc, target) in cases {
                let arm = format_branch_target(*target, in_chunk);
                writeln!(out, "{indent}    {disc} => {{ {arm} }}").ok();
            }
            let def_arm = format_branch_target(*default_bb, in_chunk);
            writeln!(out, "{indent}    _ => {{ {def_arm} }}\n{indent}}}").ok();
        }
    }
}

impl ValTy {
    fn from_mir_ret(ty: &MirType) -> Self {
        match ty {
            MirType::Bool => ValTy::Bool,
            MirType::U8 => ValTy::U8,
            MirType::U16 => ValTy::U16,
            MirType::U32 | MirType::Sym => ValTy::U32,
            MirType::U64 => ValTy::U64,
            MirType::I8 => ValTy::I8,
            MirType::I16 => ValTy::I16,
            MirType::I32 => ValTy::I32,
            MirType::I64 => ValTy::I64,
            MirType::F32 => ValTy::F32,
            MirType::F64 => ValTy::F64,
            MirType::Fix32 => ValTy::Fix32,
            MirType::Fix64 => ValTy::Fix64,
            MirType::Vec2 => ValTy::Vec2,
            MirType::Vec3 => ValTy::Vec3,
            MirType::Vec4 => ValTy::Vec4,
            MirType::Entity => ValTy::Entity,
            _ => ValTy::Unit,
        }
    }
}

fn format_branch_target(target: BlockId, in_chunk: Option<&ChunkLoopInfo>) -> String {
    if let Some(cl) = in_chunk {
        if target == cl.hdr_bb {
            "break;".to_owned()
        } else if target == cl.exit_bb {
            if cl.use_par {
                "break;".to_owned()
            } else {
                "__broke_loop = true; break;".to_owned()
            }
        } else {
            format!("__inner_bb = {};", target.0)
        }
    } else {
        format!("__bb = {};", target.0)
    }
}

fn inst_used_locals(inst: &Inst) -> Vec<LocalId> {
    match inst {
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
        | Inst::GraceIsActive { ptr: val }
        | Inst::GraceClear { ptr: val }
        | Inst::TimelineInWindow { ptr: val, .. }
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
        | Inst::ReduceInit { identity: val, .. }
        | Inst::SpawnBatchBegin { count: val, .. }
        | Inst::SpawnBatchCommit { batch: val } => vec![*val],

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
        _ => Vec::new(),
    }
}

fn terminator_used_locals(term: &Terminator) -> Vec<LocalId> {
    match term {
        Terminator::Return(Some(l)) => vec![*l],
        Terminator::Branch { cond, .. } => vec![*cond],
        Terminator::Switch { scrutinee, .. } => vec![*scrutinee],
        _ => Vec::new(),
    }
}

// =========================================================================
// Named Object Initialization, Schedule SystemSets, run_if, & Plugin Wiring
// =========================================================================

fn emit_named_object_initializer(out: &mut String, ctx: &NativeCtx<'_>) {
    if ctx.mir.objects.is_empty() {
        return;
    }
    let mut params = vec![
        "mut commands: Commands".to_owned(),
        "mut named_objects: ResMut<StrataNamedObjects>".to_owned(),
    ];
    let mut obj_queries = Vec::new();
    for (oi, obj) in ctx.mir.objects.iter().enumerate() {
        let primary = obj
            .inits
            .first()
            .and_then(|i| {
                ctx.resolve_ecs_struct_name(
                    i.canonical_component.as_deref().unwrap_or(&i.component),
                )
            })
            .or_else(|| {
                obj.components
                    .first()
                    .and_then(|c| ctx.resolve_ecs_struct_name(c))
            });
        if let Some(pstruct) = primary {
            let qv = format!("oq_{oi}");
            params.push(format!("{qv}: Query<Entity, With<{pstruct}>>"));
            obj_queries.push((oi, obj, Some(qv)));
        } else {
            obj_queries.push((oi, obj, None));
        }
    }

    writeln!(
        out,
        "fn strata_init_named_objects({}) {{",
        params.join(", ")
    )
    .ok();
    for (_oi, obj, qv_opt) in obj_queries {
        let mut bundle_items = Vec::new();
        for init in &obj.inits {
            let key = init
                .canonical_component
                .as_deref()
                .unwrap_or(&init.component);
            if let Some(entry) = ctx.find_layout_entry(key) {
                if entry.layout.size == 0 || entry.layout.fields.is_empty() {
                    bundle_items.push(entry.struct_name.clone());
                } else {
                    let mut finits = Vec::new();
                    for (fname, fexpr) in &init.fields {
                        let rfname = sanitize_rust_ident(fname);
                        if let Some(sf) = entry.layout.fields.iter().find(|f| f.name == *fname)
                            && let Some((_, val_s)) = eval_hir_expr_static(fexpr, Some(&sf.ty), ctx)
                        {
                            let wrapped = wrap_abi_field_store(&val_s, sf, ctx, false);
                            finits.push(format!("{rfname}: {wrapped}"));
                        }
                    }
                    if finits.is_empty() {
                        bundle_items.push(format!("{}::default()", entry.struct_name));
                    } else {
                        bundle_items.push(format!(
                            "{} {{ {}, ..Default::default() }}",
                            entry.struct_name,
                            finits.join(", ")
                        ));
                    }
                }
            } else if let Some(sname) = ctx.resolve_ecs_struct_name(key) {
                bundle_items.push(sname);
            }
        }
        if bundle_items.is_empty() {
            for c in &obj.components {
                if let Some(sname) = ctx.resolve_ecs_struct_name(c) {
                    if ctx.is_zst_component(c) {
                        bundle_items.push(sname);
                    } else {
                        bundle_items.push(format!("{sname}::default()"));
                    }
                }
            }
        }
        let bundle_expr = if bundle_items.is_empty() {
            "()".to_owned()
        } else {
            format!("({},)", bundle_items.join(", "))
        };
        writeln!(out, "    if named_objects.get({:?}).is_none() {{", obj.name).ok();
        if let Some(qv) = qv_opt {
            writeln!(
                out,
                "        if let Some(__existing) = {qv}.iter().next() {{\n\
                 \x20           named_objects.bind({:?}, __existing);\n\
                 \x20       }} else {{\n\
                 \x20           let __e = commands.spawn({bundle_expr}).id();\n\
                 \x20           named_objects.bind({:?}, __e);\n\
                 \x20       }}",
                obj.name, obj.name
            )
            .ok();
        } else {
            writeln!(
                out,
                "        let __e = commands.spawn({bundle_expr}).id();\n\
                 \x20       named_objects.bind({:?}, __e);",
                obj.name
            )
            .ok();
        }
        writeln!(out, "    }}").ok();
    }
    writeln!(out, "}}\n").ok();
}

fn emit_run_if_condition(
    out: &mut String,
    idx: usize,
    expr: &HirExpr,
    ctx: &NativeCtx<'_>,
) -> Option<String> {
    let mut resources: BTreeMap<String, String> = BTreeMap::new();
    collect_run_if_resources(expr, ctx, &mut resources);
    let body = render_run_if_expr(expr, ctx, &resources)?;
    let fn_name = format!("strata_run_if_{idx}");
    let params: Vec<String> = resources
        .iter()
        .map(|(sname, vname)| format!("{vname}: Res<{sname}>"))
        .collect();
    writeln!(
        out,
        "fn {fn_name}({}) -> bool {{\n    {body}\n}}\n",
        params.join(", ")
    )
    .ok();
    Some(fn_name)
}

fn collect_run_if_resources(
    expr: &HirExpr,
    ctx: &NativeCtx<'_>,
    out: &mut BTreeMap<String, String>,
) {
    match expr {
        HirExpr::Call(c) => {
            if c.callee == "res"
                && let Some(rname) = c.generic_args.first()
                && let Some(entry) = ctx.find_layout_entry(rname)
            {
                let vname = format!("r_{}", sanitize_ident(&entry.layout.canonical_name));
                out.insert(entry.struct_name.clone(), vname);
            }
            if let Some(ref recv) = c.receiver {
                collect_run_if_resources(recv, ctx, out);
            }
            for a in &c.args {
                collect_run_if_resources(a, ctx, out);
            }
        }
        HirExpr::Field { base, .. } => collect_run_if_resources(base, ctx, out),
        HirExpr::Unary { expr, .. } | HirExpr::Cast { expr, .. } => {
            collect_run_if_resources(expr, ctx, out);
        }
        HirExpr::Binary { lhs, rhs, .. } => {
            collect_run_if_resources(lhs, ctx, out);
            collect_run_if_resources(rhs, ctx, out);
        }
        _ => {}
    }
}

fn render_run_if_expr(
    expr: &HirExpr,
    ctx: &NativeCtx<'_>,
    resources: &BTreeMap<String, String>,
) -> Option<String> {
    match expr {
        HirExpr::BoolLit(b) => Some(b.to_string()),
        HirExpr::IntLit { value, .. } => Some(format!("{value}i64")),
        HirExpr::FloatLit { value, .. } => Some(format_f32_lit(*value)),
        HirExpr::Call(c) => {
            if c.callee == "res"
                && let Some(rname) = c.generic_args.first()
                && let Some(entry) = ctx.find_layout_entry(rname)
            {
                return resources.get(&entry.struct_name).cloned();
            }
            if matches!(c.callee.as_str(), "as_secs" | "raw")
                && let Some(ref recv) = c.receiver
            {
                return render_run_if_expr(recv, ctx, resources);
            }
            eval_hir_expr_static(expr, None, ctx).map(|(_, v)| v)
        }
        HirExpr::Field { base, field, .. } => {
            let b = render_run_if_expr(base, ctx, resources)?;
            let rf = sanitize_rust_ident(field);
            if matches!(expr.ty(), Ty::Bool) {
                Some(format!("{b}.{rf}.as_bool()"))
            } else {
                Some(format!("{b}.{rf}"))
            }
        }
        HirExpr::Unary { op, expr, .. } => {
            let inner = render_run_if_expr(expr, ctx, resources)?;
            let op_s = match op {
                HirUnOp::Neg => "-",
                HirUnOp::Not | HirUnOp::BitNot => "!",
                _ => return None,
            };
            Some(format!("({op_s}({inner}))"))
        }
        HirExpr::Binary { op, lhs, rhs, .. } => {
            let l = render_run_if_expr(lhs, ctx, resources)?;
            let r = render_run_if_expr(rhs, ctx, resources)?;
            let sym = match op {
                HirBinOp::Add => "+",
                HirBinOp::Sub => "-",
                HirBinOp::Mul => "*",
                HirBinOp::Div => "/",
                HirBinOp::Eq => "==",
                HirBinOp::Ne => "!=",
                HirBinOp::Lt => "<",
                HirBinOp::Le => "<=",
                HirBinOp::Gt => ">",
                HirBinOp::Ge => ">=",
                HirBinOp::And => "&&",
                HirBinOp::Or => "||",
                _ => return None,
            };
            Some(format!("(({l}) {sym} ({r}))"))
        }
        _ => eval_hir_expr_static(expr, None, ctx).map(|(_, v)| v),
    }
}

fn schedule_label_ident(label: &str) -> &'static str {
    match label {
        "Startup" => "Startup",
        "PreUpdate" => "PreUpdate",
        "Update" => "Update",
        "PostUpdate" => "PostUpdate",
        "Last" => "Last",
        _ => "FixedUpdate",
    }
}

fn collect_schedule_sets(nodes: &[HirScheduleGroup], out: &mut Vec<String>) {
    for node in nodes {
        if node.kind != "leaf" {
            let sname = format!("StrataSet_{}", sanitize_ident(&node.name));
            if !out.contains(&sname) {
                out.push(sname);
            }
            collect_schedule_sets(&node.children, out);
        }
    }
}

fn emit_native_plugin(out: &mut String, ctx: &NativeCtx<'_>) {
    let mir = ctx.mir;

    // Emit SystemSet structs for schedule groups and per-schedule root sets / run_if fns.
    let mut set_names: Vec<String> = Vec::new();
    let mut leaf_set_names: Vec<String> = Vec::new();
    let mut sched_run_ifs: Vec<(usize, String)> = Vec::new();

    for (si, sched) in mir.schedules.iter().enumerate() {
        collect_schedule_sets(&sched.nodes, &mut set_names);
        let root_set = format!("StrataSchedRoot_{si}_{}", sanitize_ident(&sched.label));
        if !set_names.contains(&root_set) {
            set_names.push(root_set);
        }
        if let Some(ref expr) = sched.run_if_expr
            && let Some(fn_name) = emit_run_if_condition(out, si, expr, ctx)
        {
            sched_run_ifs.push((si, fn_name));
        }
    }

    // Also emit leaf-wrapper SystemSets for any leaf system that needs cross-set ordering (e.g. strata_timer_tick).
    for func in &mir.functions {
        if !matches!(
            func.kind,
            MirFnKind::Observer { .. } | MirFnKind::Migration { .. }
        ) {
            let ls = format!("StrataLeafSet_{}", sanitize_ident(&func.name));
            if !leaf_set_names.contains(&ls) {
                leaf_set_names.push(ls);
            }
        }
    }

    for sname in set_names.iter().chain(leaf_set_names.iter()) {
        writeln!(
            out,
            "#[derive(SystemSet, Debug, Clone, PartialEq, Eq, Hash)]\npub struct {sname};"
        )
        .ok();
    }
    if !set_names.is_empty() || !leaf_set_names.is_empty() {
        writeln!(out).ok();
    }

    writeln!(
        out,
        "/// Tier 3 static Bevy `Plugin` generated by Strata v2.0."
    )
    .ok();
    writeln!(out, "pub struct StrataNativePlugin;\n").ok();
    writeln!(out, "impl Plugin for StrataNativePlugin {{").ok();
    writeln!(out, "    fn build(&self, app: &mut App) {{").ok();
    writeln!(out, "        app.init_resource::<StrataNamedObjects>();").ok();
    writeln!(
        out,
        "        app.init_resource::<StrataTriggerTargetStack>();"
    )
    .ok();

    for entry in &ctx.layouts {
        let layout = entry.layout;
        let struct_name = &entry.struct_name;
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
        } else if matches!(
            layout.item_kind,
            SchemaItemKind::Resource | SchemaItemKind::SpatialGrid | SchemaItemKind::SpatialHistory
        ) {
            writeln!(
                out,
                "        app.init_resource::<{struct_name}>();\n\
                 \x20       app.register_strata_resource::<{struct_name}>().expect(\"valid resource registration\");"
            )
            .ok();
        } else if layout.item_kind == SchemaItemKind::Stream {
            writeln!(
                out,
                "        app.register_strata_stream::<{struct_name}>().expect(\"valid stream registration\");"
            )
            .ok();
        } else if layout.item_kind == SchemaItemKind::Event {
            if ctx.entity_events.contains(&layout.canonical_name) {
                writeln!(
                    out,
                    "        app.register_strata_entity_event::<{struct_name}>().expect(\"valid entity event registration\");"
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "        app.register_strata_event::<{struct_name}>().expect(\"valid event registration\");"
                )
                .ok();
            }
        }
    }

    for tag in &ctx.tags {
        writeln!(
            out,
            "        app.register_strata_component::<{}>(StrataComponentOptions::new()).expect(\"valid tag registration\");",
            tag.struct_name
        )
        .ok();
    }
    for sp in &mir.spatial_indices {
        writeln!(
            out,
            "        app.init_resource::<StrataSpatialBacking_{}>();",
            sanitize_ident(&sp.name)
        )
        .ok();
    }
    for rel in &mir.relations {
        writeln!(
            out,
            "        app.init_resource::<StrataRelation_{}>();",
            sanitize_ident(&rel.name)
        )
        .ok();
    }

    // Named objects initializer on Startup
    let mut startup_user_sets: Vec<String> = Vec::new();
    for sched in &mir.schedules {
        if sched.label == "Startup" {
            collect_first_sets(&sched.nodes, &mut startup_user_sets);
        }
    }
    if !mir.objects.is_empty() {
        if startup_user_sets.is_empty() {
            writeln!(
                out,
                "        app.add_systems(Startup, strata_init_named_objects);"
            )
            .ok();
        } else {
            let befores: Vec<String> = startup_user_sets
                .iter()
                .map(|s| format!(".before({s})"))
                .collect();
            writeln!(
                out,
                "        app.add_systems(Startup, strata_init_named_objects{});",
                befores.join("")
            )
            .ok();
        }
    }

    // Observers
    for func in &mir.functions {
        if matches!(func.kind, MirFnKind::Observer { .. }) {
            let fn_ident = sanitize_ident(&func.name);
            writeln!(out, "        app.add_observer(strata_obs_{fn_ident});").ok();
        }
    }

    // Systems & Schedule hierarchy
    let mut registered_systems: HashSet<String> = HashSet::new();
    let sched_sys_names: HashSet<String> = mir
        .functions
        .iter()
        .filter(|f| {
            !matches!(
                f.kind,
                MirFnKind::Observer { .. } | MirFnKind::Migration { .. }
            )
        })
        .map(|f| f.name.clone())
        .collect();

    for (si, sched) in mir.schedules.iter().enumerate() {
        let sched_lbl = schedule_label_ident(&sched.label);
        let root_set = format!("StrataSchedRoot_{si}_{}", sanitize_ident(&sched.label));
        if let Some((_, run_if_fn)) = sched_run_ifs.iter().find(|(idx, _)| *idx == si) {
            writeln!(
                out,
                "        app.configure_sets({sched_lbl}, {root_set}.run_if({run_if_fn}));"
            )
            .ok();
        }
        emit_schedule_nodes(
            out,
            sched_lbl,
            &sched.nodes,
            Some(&root_set),
            &sched_sys_names,
            &mut registered_systems,
        );
    }

    // Any remaining systems not explicitly listed in `mir.schedules` mount in `FixedUpdate`.
    let has_timer_tick = mir
        .functions
        .iter()
        .any(|f| f.kind == MirFnKind::SynthesizedTimerTick);
    let timer_set = "StrataLeafSet_strata_timer_tick";
    for func in &mir.functions {
        if matches!(
            func.kind,
            MirFnKind::Observer { .. } | MirFnKind::Migration { .. }
        ) {
            continue;
        }
        if registered_systems.insert(func.name.clone()) {
            let fn_ident = sanitize_ident(&func.name);
            let leaf_set = format!("StrataLeafSet_{fn_ident}");
            if has_timer_tick && func.kind != MirFnKind::SynthesizedTimerTick {
                writeln!(
                    out,
                    "        app.add_systems(FixedUpdate, strata_sys_{fn_ident}.in_set({leaf_set}).after({timer_set}));"
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "        app.add_systems(FixedUpdate, strata_sys_{fn_ident}.in_set({leaf_set}));"
                )
                .ok();
            }
        }
    }

    // Ensure `strata_timer_tick` always precedes every user system in `FixedUpdate` even if scheduled alongside sets.
    if has_timer_tick {
        for func in &mir.functions {
            if matches!(
                func.kind,
                MirFnKind::System
                    | MirFnKind::SynthesizedTimeline
                    | MirFnKind::SynthesizedTask
                    | MirFnKind::SynthesizedFsm
            ) {
                let user_set = format!("StrataLeafSet_{}", sanitize_ident(&func.name));
                writeln!(
                    out,
                    "        app.configure_sets(FixedUpdate, {timer_set}.before({user_set}));"
                )
                .ok();
            }
        }
    }

    writeln!(out, "    }}").ok();
    writeln!(out, "}}").ok();
}

fn collect_first_sets(nodes: &[HirScheduleGroup], out: &mut Vec<String>) {
    for n in nodes {
        if n.kind == "leaf" {
            out.push(format!("StrataLeafSet_{}", sanitize_ident(&n.name)));
        } else {
            out.push(format!("StrataSet_{}", sanitize_ident(&n.name)));
        }
    }
}

fn group_set_name(node: &HirScheduleGroup) -> String {
    if node.kind == "leaf" {
        format!("StrataLeafSet_{}", sanitize_ident(&node.name))
    } else {
        format!("StrataSet_{}", sanitize_ident(&node.name))
    }
}

fn emit_schedule_nodes(
    out: &mut String,
    sched_lbl: &str,
    nodes: &[HirScheduleGroup],
    parent_set: Option<&str>,
    valid_systems: &HashSet<String>,
    registered_systems: &mut HashSet<String>,
) {
    let mut child_sets = Vec::new();
    for node in nodes {
        if node.kind == "leaf" {
            if !valid_systems.contains(&node.name) {
                continue;
            }
            let fn_ident = sanitize_ident(&node.name);
            let leaf_set = format!("StrataLeafSet_{fn_ident}");
            if registered_systems.insert(node.name.clone()) {
                if let Some(ps) = parent_set {
                    writeln!(
                        out,
                        "        app.add_systems({sched_lbl}, strata_sys_{fn_ident}.in_set({leaf_set}).in_set({ps}));"
                    )
                    .ok();
                } else {
                    writeln!(
                        out,
                        "        app.add_systems({sched_lbl}, strata_sys_{fn_ident}.in_set({leaf_set}));"
                    )
                    .ok();
                }
            } else if let Some(ps) = parent_set {
                writeln!(
                    out,
                    "        app.configure_sets({sched_lbl}, {leaf_set}.in_set({ps}));"
                )
                .ok();
            }
            child_sets.push(leaf_set);
        } else {
            let gset = group_set_name(node);
            if let Some(ps) = parent_set {
                writeln!(
                    out,
                    "        app.configure_sets({sched_lbl}, {gset}.in_set({ps}));"
                )
                .ok();
            }
            emit_schedule_nodes(
                out,
                sched_lbl,
                &node.children,
                Some(&gset),
                valid_systems,
                registered_systems,
            );
            if matches!(node.kind.as_str(), "seq" | "seq_weak") {
                let mut ordered_children = Vec::new();
                for ch in &node.children {
                    if ch.kind == "leaf" && !valid_systems.contains(&ch.name) {
                        continue;
                    }
                    ordered_children.push(group_set_name(ch));
                }
                if ordered_children.len() >= 2 {
                    let chain_m = if node.kind == "seq_weak" {
                        "chain_weak"
                    } else {
                        "chain"
                    };
                    writeln!(
                        out,
                        "        app.configure_sets({sched_lbl}, ({}).{chain_m}());",
                        ordered_children.join(", ")
                    )
                    .ok();
                }
            }
            child_sets.push(gset);
        }
    }
    let _ = child_sets;
}

#[cfg(test)]
mod tests {
    use super::emit;
    use crate::{BevyNativeOptions, TargetKind};
    use strata_mir::{lower_to_mir, verify_mir};
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

    /// Verifies `field_defaults`, `@par` contiguous iterators, selective `&mut?`, `OptionalRead`,
    /// `Observers` (`On<E>`), `EntityEvent`, `MessageWriter`, `SystemSet` chaining, and
    /// `SharedBridgeAppExt` wiring across all Tier 3 native constructs.
    #[test]
    fn bevy_native_emits_full_mir_cfg_observers_par_optional_and_schedules() {
        let src = r#"
module bn::full @version(1.0.0);

resource SimClock { dt: sec = 8.3333_ms }
component Pos { x: f32 = 1.5, y: f32 = 2.5 }
component Vel { vx: f32 = 3.0, vy: f32 = 0.0 }
component Heat @summary_tick { temp: f32 = 10.0, hot: bool = false }
component Blessing { bonus: f32 = 2.0 }
@sparse component Shield { cap: f32 = 50.0 }

event GlobalPulse { amp: f32 }
event HitEntity { entity: Ref<Pos>, dmg: f32 }
stream DigestOut { total: f32 }

fn add_boost(x: f32, b: f32) -> f32 { x + b }

@par(chunk = 256)
sys step(clk: &res SimClock) {
    uniform let dt = clk.dt.as_secs();
    for r in query(p: &mut Pos, v: &Vel, h: &mut? Heat, b: ?&Blessing) {
        r.p.x += add_boost(r.v.vx, 0.5) * dt;
        if let Some(bl) = r.b {
            r.h.temp += bl.bonus;
            r.h.hot = true;
        }
    }
}

sys step_sparse() {
    for r in query(p: &mut Pos, s: ?&Shield) {
        if let Some(sh) = r.s {
            r.p.y += sh.cap * 0.01;
        }
    }
}

sys emit_digest(mw_dummy: &res SimClock) {
    let total = for r in query(h: &Heat.temp) reduce (total: sum(0.0, r.h));
    emit(DigestOut { total: total });
}

obs on_global(trg: &Trigger<GlobalPulse>) {
    let _a = trg.payload.amp;
}

obs on_hit(trg: &Trigger<HitEntity, Pos>) {
    let e = trg.target;
    let d = trg.payload.dmg;
    let _ = (e, d);
}

schedule FixedUpdate {
    seq Frame {
        set Physics { step, step_sparse }
        set Report { emit_digest }
    }
}
"#;
        let sema = analyze_source("full.strata", src);
        assert!(sema.ok(), "{:?}", sema.diagnostics);
        let mir = lower_to_mir(&sema);
        verify_mir(&mir).expect("MIR must verify");
        let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy native");
        let code = &art.files[1].content;

        // Defaults honored
        assert!(code.contains("0.0083333_f32"));
        assert!(code.contains("1.5_f32"));
        assert!(code.contains("10.0_f32"));

        // Par contiguous + selective + optional + sparse
        assert!(code.contains("strata_contiguous_par_iter_mut()"));
        assert!(code.contains(".iter_mut()"));
        assert!(code.contains("SelectiveMutSlice::from_contiguous_mut"));
        assert!(code.contains("mark_dirty_row("));
        assert!(code.contains("flush_dirty_runs()"));
        assert!(code.contains("Option<&'static"));

        // Observers, EntityEvent, Streams, SharedBridgeAppExt, SystemSets
        assert!(code.contains("On<"));
        assert!(code.contains("#[derive(Clone, Copy, Debug, PartialEq, EntityEvent)]"));
        assert!(code.contains("app.add_observer(strata_obs_on_global)"));
        assert!(code.contains("app.add_observer(strata_obs_on_hit)"));
        assert!(code.contains("MessageWriter<"));
        assert!(code.contains(".write("));
        assert!(code.contains("register_strata_component"));
        assert!(code.contains("register_strata_resource"));
        assert!(code.contains("register_strata_stream"));
        assert!(code.contains("register_strata_event"));
        assert!(code.contains("register_strata_entity_event"));
        assert!(code.contains("StrataSet_Physics"));
        assert!(code.contains(".chain()"));
        assert!(code.contains("strata_fn_add_boost"));
    }

    /// Verifies `MirFnKind::Observer` with `@par` and `commands.spawn_batch` / `despawn_all` /
    /// `MirFnKind::Migration` emit clean safe Bevy-native Rust.
    #[test]
    fn bevy_native_emits_migrations_spawn_batch_and_named_objects() {
        let src = r#"
module bn::mig @version(2.0.0);

resource SimClock { dt: sec = 16.6667_ms }
component BodyV1 { hp: i32 = 10 }
component Body { hp: f32 = 100.0 }
tag Ephemeral;

object Hero { Body {} }

migrate Body from 1.0.0 to 2.0.0 (old: &BodyV1) -> Body {
    Body { hp: old.hp as f32 }
}

sys spawn_wave() {
    spawn_batch(10) |i| {
        { Body { hp: (i as f32) + 1.0 }, Ephemeral }
    };
}

sys clear_wave() {
    despawn_all<With<Ephemeral>>();
    if let Some(h) = query_one(b: &mut Body).on(Hero) {
        h.b.hp += 5.0;
    }
}
"#;
        let sema = analyze_source("mig.strata", src);
        assert!(sema.ok(), "{:?}", sema.diagnostics);
        let mir = lower_to_mir(&sema);
        verify_mir(&mir).expect("MIR must verify");
        let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy native");
        let code = &art.files[1].content;

        assert!(code.contains("pub fn strata_mig_"));
        assert!(code.contains("spawn_batch("));
        assert!(code.contains("despawn_all::<With<StrataTag_Ephemeral_"));
        assert!(code.contains("StrataNamedObjects"));
        assert!(code.contains("strata_init_named_objects"));
    }

    #[test]
    fn bevy_native_emits_paramset_snapshot_primitives_and_zero_unsafe() {
        let src = r#"
module bn::pset @version(1.0.0);

component Actor { alive: bool = true, flags: u32 = 0, hp: f32 = 100.0 }
component Order { target: Ref<Actor>, grace: GraceWindow, buf: InputBuffer<u32, 4> }

sys tick_orders() {
    for row in query(o: &mut Order) {
        row.o.grace.arm(0.2);
        row.o.buf.push(1, 0.15);
    }
}

task ProcessOrder(target: Ref<Actor>)
    on (a: &Actor)
{
    if a.alive {
        if let Some(t) = query_one(tgt: &mut Actor).on(target) {
            if t.tgt.alive {
                t.tgt.hp -= 10.0;
            }
        }
    }
    yield_tick;
}
"#;
        let sema = analyze_source("pset.strata", src);
        assert!(sema.ok(), "{:?}", sema.diagnostics);
        let mir = lower_to_mir(&sema);
        verify_mir(&mir).expect("MIR must verify");
        let art = emit(&mir, &BevyNativeOptions::default()).expect("emit");
        let code = &art.files[1].content;

        assert!(code.contains("#![forbid(unsafe_code)]"));
        assert!(!code.contains("unsafe "));
        assert!(code.contains("ParamSet<"));
        assert!(code.contains("_snap: Vec<_>"));
        assert!(code.contains(".get()"));
        assert!(code.contains("if __d > *"));
        assert!(code.contains("strata_input_buf_push"));
    }

    #[test]
    fn bevy_native_emits_indexed_and_unindexed_spawn_batch_and_require() {
        let src = r#"
module bn::sb @version(1.0.0);

resource Cfg { count: u32 = 8 }
component Pos3D { xyz: vec3 = vec3::ZERO }
component Vel3D { dxyz: vec3 = vec3::ZERO }
component Raindrop @require(Pos3D, Vel3D) { elasticity: f32 = 0.65 }
component Item { val: i32 = 0 }
tag Fresh;

sys spawn_indexed(cfg: &res Cfg) effects(spawns: [Raindrop, Pos3D]) {
    let n = cfg.count;
    spawn_batch(n) |i| {
        let mut e = 0.60;
        if i % 2 == 0 {
            e = 0.75;
        }
        {
            Raindrop { elasticity: e },
            Pos3D { xyz: vec3((i as f32), 2.0, 0.0) },
        }
    };
}

sys spawn_unindexed() effects(spawns: [Item, Fresh]) {
    spawn_batch(4) |_| {
        let base = 0;
        { Item { val: base + 7 }, Fresh }
    };
}
"#;
        let sema = analyze_source("sb.strata", src);
        assert!(sema.ok(), "{:?}", sema.diagnostics);
        let mir = lower_to_mir(&sema);
        verify_mir(&mir).expect("MIR must verify");
        let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy native");
        let code = &art.files[1].content;

        assert!(code.contains("#[require("));
        assert!(code.contains("Vec::with_capacity("));
        assert!(code.contains(".push(__batch_row);"));
        assert!(code.contains(".resize_with(__batch_idx + 1, Default::default);"));
        assert!(code.contains("core::mem::take(&mut __batch_buf_0);"));
        assert!(code.contains("commands.spawn_batch(__batch_rows);"));
        assert!(code.contains("commands.spawn_batch((0..(__loc_"));
        assert!(code.contains(".map(move |_| "));
        assert!(!code.contains("move |__batch_i|"));
    }

    #[test]
    fn bevy_native_emits_rain_swarm_and_metroidvania_cookbooks_cleanly() {
        let rain_src = include_str!("../../../fixtures/cookbooks/01_rain_swarm.strata");
        let rain_sema = analyze_source("01_rain_swarm.strata", rain_src);
        assert!(rain_sema.ok(), "{:?}", rain_sema.diagnostics);
        let rain_mir = lower_to_mir(&rain_sema);
        verify_mir(&rain_mir).expect("01_rain_swarm MIR must verify");
        let rain_art = emit(&rain_mir, &BevyNativeOptions::default()).expect("emit rain_swarm");
        let rain_code = &rain_art.files[1].content;
        assert!(rain_code.contains("#[require("));
        assert!(rain_code.contains("Vec::with_capacity("));
        assert!(rain_code.contains(".push(__batch_row);"));
        assert!(rain_code.contains("commands.spawn_batch(__batch_rows);"));
        assert!(rain_code.contains("strata_contiguous_par_iter_mut()"));

        let mv_src = include_str!("../../../fixtures/cookbooks/03_metroidvania_core.strata");
        let mv_sema = analyze_source("03_metroidvania_core.strata", mv_src);
        assert!(mv_sema.ok(), "{:?}", mv_sema.diagnostics);
        let mv_mir = lower_to_mir(&mv_sema);
        verify_mir(&mv_mir).expect("03_metroidvania_core MIR must verify");
        let mv_art = emit(&mv_mir, &BevyNativeOptions::default()).expect("emit metroidvania");
        let mv_code = &mv_art.files[1].content;
        assert!(mv_code.contains("#[require("));
        assert!(mv_code.contains("strata_run_if_"));
        assert!(mv_code.contains("StrataLeafSet_strata_timer_tick.before("));
        assert!(mv_code.contains("StrataSet_InputAndTasks"));
        assert!(mv_code.contains(".chain()"));
    }
}
