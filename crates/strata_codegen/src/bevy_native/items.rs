//! BevyNative context, preamble, layouts, net codecs, named objects, and schedule wiring.

use super::*;

#[derive(Clone)]
pub(super) struct LayoutEntry<'a> {
    pub(super) struct_name: String,
    pub(super) layout: &'a SolvedLayout,
}

#[derive(Clone)]
pub(super) struct TagEntry {
    pub(super) canonical_name: String,
    pub(super) struct_name: String,
    pub(super) uuid_bytes: [u8; 16],
    pub(super) schema_fingerprint: u64,
}

pub(super) struct NativeCtx<'a> {
    pub(super) mir: &'a MirModule,
    pub(super) layouts: Vec<LayoutEntry<'a>>,
    pub(super) layouts_by_key: HashMap<String, usize>,
    pub(super) entity_events: HashSet<String>,
    pub(super) tags: Vec<TagEntry>,
    pub(super) tags_by_key: HashMap<String, usize>,
    pub(super) enums_by_key: HashMap<String, &'a EnumDef>,
    pub(super) tables_by_key: HashMap<String, &'a strata_sema::hir::HirTable>,
    pub(super) spatial_by_key: HashMap<String, &'a strata_sema::hir::HirSpatialIndex>,
    pub(super) timelines_by_key: HashMap<String, &'a strata_sema::hir::HirTimeline>,
    pub(super) tasks_by_key: HashMap<String, &'a strata_sema::hir::HirTask>,
    pub(super) fsms_by_key: HashMap<String, &'a strata_sema::hir::HirFsm>,
    pub(super) objects_by_key: HashMap<String, &'a strata_sema::hir::HirObject>,
    pub(super) helpers_by_key: HashMap<String, &'a MirFunction>,
}

impl<'a> NativeCtx<'a> {
    pub(super) fn new(mir: &'a MirModule) -> Self {
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

    pub(super) fn collect_synthesized_tags(&mut self) {
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

    pub(super) fn find_layout_entry(&self, key: &str) -> Option<&LayoutEntry<'a>> {
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

    pub(super) fn resolve_ecs_struct_name(&self, key: &str) -> Option<String> {
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

    pub(super) fn is_zst_component(&self, key: &str) -> bool {
        if let Some(entry) = self.find_layout_entry(key) {
            entry.layout.size == 0 || entry.layout.fields.is_empty()
        } else {
            self.tags_by_key.contains_key(key)
                || self
                    .tags_by_key
                    .contains_key(key.rsplit("::").next().unwrap_or(key))
        }
    }

    pub(super) fn resolve_field_info(
        &self,
        layout_key: &str,
        field_path: &str,
    ) -> Option<&'a SolvedField> {
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

pub(super) fn insert_layout_aliases(
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

pub(super) fn strip_filter_wrapper(raw: &str) -> String {
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

pub(super) fn parse_despawn_filters(filter: &str) -> Vec<(&'static str, String)> {
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

pub(super) fn emit_preamble(out: &mut String, mir: &MirModule) {
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
    if has_net_protocol(mir) {
        writeln!(
            out,
            "    FLAG_IS_HANDSHAKE, FLAG_IS_PREDICTED, FLAG_IS_RELIABLE, FLAG_IS_RESOURCE, FLAG_IS_RPC,\n\
             \x20   PACKET_KIND_COMPONENT_DELTA, PACKET_KIND_HANDSHAKE, PACKET_KIND_RESOURCE_DELTA,\n\
             \x20   PACKET_KIND_RPC, STRATA_NET_MAX_PAYLOAD_BYTES, STRATA_NET_PACKET_CANONICAL_NAME,\n\
             \x20   STRATA_NET_PACKET_MAGIC, STRATA_NET_WIRE_VERSION, StrataNetPacket,\n\
             \x20   dequantize_scalar_f64 as strata_net_dequantize_scalar_f64,\n\
             \x20   pack_bits_le as strata_net_pack_bits_le,\n\
             \x20   quantize_scalar_f64 as strata_net_quantize_scalar_f64,\n\
             \x20   unpack_bits_le as strata_net_unpack_bits_le,"
        )
        .ok();
    }
    writeln!(out, "}};").ok();
    writeln!(
        out,
        "use bamabi_sys::{{\n\
         \x20   BamComponent, BamFieldDesc, BamFieldKind, ComponentUuid, FfiAssetHandle, FfiBool,\n\
         \x20   FfiEntity, ModComponent, StrView, SymbolEntry, VTableHeader, fnv1a_64_str,\n\
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

pub(super) fn emit_runtime_helpers(out: &mut String) {
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
         #[allow(dead_code)]\n\
         const fn strata_inline_str_pack<const W: usize>(s: &str) -> [u32; W] {{\n\
         \x20   let mut out = [0u32; W];\n\
         \x20   if W <= 1 {{ return out; }}\n\
         \x20   let cap = (W - 1) * 4;\n\
         \x20   let bytes = s.as_bytes();\n\
         \x20   let mut end = if bytes.len() < cap {{ bytes.len() }} else {{ cap }};\n\
         \x20   while end > 0 && end < bytes.len() && (bytes[end] & 0xC0) == 0x80 {{ end -= 1; }}\n\
         \x20   out[0] = end as u32;\n\
         \x20   let mut i = 0usize;\n\
         \x20   while i * 4 < end {{\n\
         \x20       let b0 = bytes[i * 4];\n\
         \x20       let b1 = if i * 4 + 1 < end {{ bytes[i * 4 + 1] }} else {{ 0 }};\n\
         \x20       let b2 = if i * 4 + 2 < end {{ bytes[i * 4 + 2] }} else {{ 0 }};\n\
         \x20       let b3 = if i * 4 + 3 < end {{ bytes[i * 4 + 3] }} else {{ 0 }};\n\
         \x20       out[1 + i] = u32::from_le_bytes([b0, b1, b2, b3]);\n\
         \x20       i += 1;\n\
         \x20   }}\n\
         \x20   out\n\
         }}\n"
    )
    .ok();

    writeln!(
        out,
        "#[allow(dead_code)] const fn strata_write_le_bytes<const N: usize, const M: usize>(out: &mut [u8; N], off: usize, bytes: [u8; M]) {{\n\
         \x20   let mut i = 0usize;\n\
         \x20   while i < M {{\n\
         \x20       out[off + i] = bytes[i];\n\
         \x20       i += 1;\n\
         \x20   }}\n\
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

fn format_enum_disc_cast(disc: i64, rty: &str) -> String {
    if disc < 0 {
        format!("({disc}i64) as {rty}")
    } else {
        format!("{disc} as {rty}")
    }
}

fn format_static_int_cast(val: i64, rty: &str) -> String {
    if val < 0 {
        match rty {
            "u8" => format!("{}u8", val as u8),
            "u16" => format!("{}u16", val as u16),
            "u32" => format!("{}u32", val as u32),
            "u64" => format!("{}u64", val as u64),
            "i64" => format!("{val}i64"),
            _ => format!("({val}i64) as {rty}"),
        }
    } else if rty == "i64" {
        format!("{val}i64")
    } else {
        format!("{val} as {rty}")
    }
}

pub(super) fn emit_enums_and_consts(out: &mut String, ctx: &NativeCtx<'_>) {
    for en in &ctx.mir.enums {
        let ename = sanitize_ident(&en.canonical_name);
        let repr = en.rust_repr();
        writeln!(out, "pub mod strata_enum_{ename} {{").ok();
        for (vname, disc) in &en.variants {
            let vident = sanitize_rust_ident(vname);
            let val = format_enum_disc_cast(*disc, repr);
            writeln!(out, "    pub const {vident}: {repr} = {val};").ok();
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

pub(super) fn format_f32_lit(v: f64) -> String {
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

pub(super) fn format_f64_lit(v: f64) -> String {
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

pub(super) fn blob_pack_method_for_blob_ty(blob_ty: &str) -> &'static str {
    if blob_ty.starts_with("[u64;") {
        "strata_to_u64_words"
    } else if blob_ty.starts_with("[u32;") {
        "strata_to_u32_words"
    } else if blob_ty.starts_with("[u16;") {
        "strata_to_u16_words"
    } else {
        "strata_to_u8_bytes"
    }
}

pub(super) fn blob_unpack_method_for_blob_ty(blob_ty: &str) -> &'static str {
    if blob_ty.starts_with("[u64;") {
        "strata_from_u64_words"
    } else if blob_ty.starts_with("[u32;") {
        "strata_from_u32_words"
    } else if blob_ty.starts_with("[u16;") {
        "strata_from_u16_words"
    } else {
        "strata_from_u8_bytes_val"
    }
}

pub(super) fn native_default_expr_for_ty(
    ty: &Ty,
    byte_size: usize,
    align: usize,
    ctx: &NativeCtx<'_>,
) -> String {
    match ty {
        Ty::Named(n) => {
            let short = n.rsplit("::").next().unwrap_or(n);
            if ctx.enums_by_key.contains_key(n.as_str()) || ctx.enums_by_key.contains_key(short) {
                return rust_default_expr_for_field(
                    &SolvedField {
                        name: String::new(),
                        ty: ty.clone(),
                        offset: 0,
                        size: byte_size,
                        align,
                        is_padding: false,
                        bam_field_kind: 0,
                        type_tag: String::new(),
                    },
                    ctx.mir,
                );
            }
            if let Some(entry) = ctx.find_layout_entry(n)
                && entry.layout.size > 0
                && !entry.layout.fields.is_empty()
            {
                let blob_ty = aligned_blob_type(byte_size, entry.layout.align);
                let pack_fn = blob_pack_method_for_blob_ty(&blob_ty);
                return format!("{}::strata_default().{pack_fn}()", entry.struct_name);
            }
        }
        Ty::Array { elem, len } => {
            let elem_size = byte_size / (*len).max(1);
            let elem_align = if let Ty::Named(en_key) = elem.as_ref() {
                ctx.find_layout_entry(en_key)
                    .map_or(align, |e| e.layout.align)
            } else {
                align
            };
            let elem_def = native_default_expr_for_ty(elem, elem_size, elem_align, ctx);
            return format!("[{elem_def}; {len}]");
        }
        _ => {}
    }
    rust_default_expr_for_field(
        &SolvedField {
            name: String::new(),
            ty: ty.clone(),
            offset: 0,
            size: byte_size,
            align,
            is_padding: false,
            bam_field_kind: 0,
            type_tag: String::new(),
        },
        ctx.mir,
    )
}

pub(super) fn native_default_expr_for_field(field: &SolvedField, ctx: &NativeCtx<'_>) -> String {
    if field.is_padding {
        return format!("[0u8; {}]", field.size.max(1));
    }
    if let Ty::Named(n) = &field.ty
        && let Some(entry) = ctx.find_layout_entry(n)
        && entry.layout.item_kind != SchemaItemKind::Enum
        && entry.layout.size > 0
        && !entry.layout.fields.is_empty()
    {
        let blob_ty = rust_abi_type_for_field(field, ctx.mir);
        let pack_fn = blob_pack_method_for_blob_ty(&blob_ty);
        return format!("{}::strata_default().{pack_fn}()", entry.struct_name);
    }
    if let Ty::Array { .. } = &field.ty {
        return native_default_expr_for_ty(&field.ty, field.size, field.align, ctx);
    }
    rust_default_expr_for_field(field, ctx.mir)
}

pub(super) fn format_const_for_field(
    val: &MirConstVal,
    field: &SolvedField,
    ctx: &NativeCtx<'_>,
) -> String {
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
        (Ty::Fix32, MirConstVal::Float(f)) => format_fix32_i32_lit(scale_float_fix32(*f)),
        (Ty::Fix32, MirConstVal::Int(i)) => format_fix32_i32_lit(scale_int_fix32(*i)),
        (Ty::Fix64, MirConstVal::Float(f)) => format_fix64_i64_lit(scale_float_fix64(*f)),
        (Ty::Fix64, MirConstVal::Int(i)) => format_fix64_i64_lit(scale_int_fix64(*i)),
        (Ty::U8, MirConstVal::Int(i)) => format_static_int_cast(*i, "u8"),
        (Ty::I8, MirConstVal::Int(i)) => format_static_int_cast(*i, "i8"),
        (Ty::U16, MirConstVal::Int(i)) => format_static_int_cast(*i, "u16"),
        (Ty::I16, MirConstVal::Int(i)) => format_static_int_cast(*i, "i16"),
        (Ty::U32 | Ty::Sym | Ty::Rgba8, MirConstVal::Int(i)) => format_static_int_cast(*i, "u32"),
        (Ty::I32, MirConstVal::Int(i)) => format_static_int_cast(*i, "i32"),
        (Ty::U64, MirConstVal::Int(i)) => format_static_int_cast(*i, "u64"),
        (Ty::I64, MirConstVal::Int(i)) => format!("{i}i64"),
        (Ty::BitSet(bits), MirConstVal::Int(v)) => {
            let words = (*bits).div_ceil(32).max(1);
            let mask = *v as u64;
            let parts: Vec<String> = (0..words)
                .map(|w| {
                    let word = if w < 2 {
                        ((mask >> (w * 32)) & 0xFFFF_FFFF) as u32
                    } else {
                        0
                    };
                    format!("{word}u32")
                })
                .collect();
            format!("[{}]", parts.join(", "))
        }
        (Ty::BitSet(bits), MirConstVal::Array(items)) => {
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
                format_enum_disc_cast(*i, en.rust_repr())
            } else {
                native_default_expr_for_field(field, ctx)
            }
        }
        (
            Ty::Named(tn),
            MirConstVal::Struct {
                name,
                fields: finits,
            },
        ) => {
            let key = if name.is_empty() {
                tn.as_str()
            } else {
                name.as_str()
            };
            if let Some(entry) = ctx
                .find_layout_entry(key)
                .or_else(|| ctx.find_layout_entry(tn))
            {
                if entry.layout.size == 0 || entry.layout.fields.is_empty() {
                    return native_default_expr_for_field(field, ctx);
                }
                let blob_ty = rust_abi_type_for_field(field, ctx.mir);
                let pack_fn = blob_pack_method_for_blob_ty(&blob_ty);
                if finits.is_empty() {
                    return format!("{}::strata_default().{pack_fn}()", entry.struct_name);
                }
                let mut parts = Vec::new();
                for sf in &entry.layout.fields {
                    let rfname = sanitize_rust_ident(&sf.name);
                    if sf.is_padding {
                        parts.push(format!("{rfname}: [0u8; {}]", sf.size.max(1)));
                    } else if let Some((_, fval)) = finits.iter().find(|(fnm, _)| fnm == &sf.name) {
                        parts.push(format!(
                            "{rfname}: {}",
                            format_const_for_field(fval, sf, ctx)
                        ));
                    } else if let Some(cval) = lookup_field_default(ctx.mir, entry.layout, &sf.name)
                    {
                        parts.push(format!(
                            "{rfname}: {}",
                            format_const_for_field(cval, sf, ctx)
                        ));
                    } else {
                        parts.push(format!(
                            "{rfname}: {}",
                            native_default_expr_for_field(sf, ctx)
                        ));
                    }
                }
                format!(
                    "{} {{ {} }}.{pack_fn}()",
                    entry.struct_name,
                    parts.join(", ")
                )
            } else {
                native_default_expr_for_field(field, ctx)
            }
        }
        (Ty::Array { elem, len }, MirConstVal::Array(items)) => {
            let elem_align = if let Ty::Named(en_key) = elem.as_ref() {
                ctx.find_layout_entry(en_key)
                    .map_or(field.align, |e| e.layout.align)
            } else {
                field.align
            };
            let dummy = SolvedField {
                name: field.name.clone(),
                ty: (**elem).clone(),
                offset: 0,
                size: field.size / (*len).max(1),
                align: elem_align,
                is_padding: false,
                bam_field_kind: 0,
                type_tag: String::new(),
            };
            let mut elems: Vec<String> = items
                .iter()
                .take(*len)
                .map(|it| format_const_for_field(it, &dummy, ctx))
                .collect();
            while elems.len() < *len {
                elems.push(native_default_expr_for_field(&dummy, ctx));
            }
            format!("[{}]", elems.join(", "))
        }
        _ => native_default_expr_for_field(field, ctx),
    }
}

fn effective_expected_ty<'a>(expected_ty: Option<&'a Ty>, fallback: &'a Ty) -> &'a Ty {
    match expected_ty {
        Some(t) if !matches!(t, Ty::Unknown) => t,
        _ => fallback,
    }
}

fn val_ty_from_rust_ty(rty: &str, hir_ty: &Ty, ctx: &NativeCtx<'_>) -> ValTy {
    if !matches!(hir_ty, Ty::Unknown) {
        return ValTy::from_sema_ty(hir_ty, ctx);
    }
    match rty {
        "bool" => ValTy::Bool,
        "u8" => ValTy::U8,
        "i8" => ValTy::I8,
        "u16" => ValTy::U16,
        "i16" => ValTy::I16,
        "u32" => ValTy::U32,
        "i32" => ValTy::I32,
        "u64" => ValTy::U64,
        "i64" => ValTy::I64,
        "f32" => ValTy::F32,
        "f64" => ValTy::F64,
        "Fixed32" => ValTy::Fix32,
        "Fixed64" => ValTy::Fix64,
        _ => ValTy::Unit,
    }
}

fn const_safe_coerce_expr(expr: &str, from: &ValTy, to: &ValTy) -> String {
    if from == to || *to == ValTy::Unit || *to == ValTy::PtrMarker {
        return expr.to_owned();
    }
    match (from, to) {
        (ValTy::F32 | ValTy::F64, ValTy::Fix32) => format!(
            "Fixed32({{ let __x = ({expr}) as f64; if !__x.is_finite() {{ 0i32 }} else {{ let __s = __x * 65536.0_f64; let __r = if __s >= 0.0_f64 {{ __s + 0.5_f64 }} else {{ __s - 0.5_f64 }}; let __qi = __r as i64; if __qi < i32::MIN as i64 {{ i32::MIN }} else if __qi > i32::MAX as i64 {{ i32::MAX }} else {{ __qi as i32 }} }} }})"
        ),
        (ValTy::F32 | ValTy::F64, ValTy::Fix64) => format!(
            "Fixed64({{ let __x = ({expr}) as f64; if !__x.is_finite() {{ 0i64 }} else {{ let __s = __x * 4294967296.0_f64; let __r = if __s >= 0.0_f64 {{ __s + 0.5_f64 }} else {{ __s - 0.5_f64 }}; __r as i64 }} }})"
        ),
        (ValTy::Fix32, ValTy::F32) => format!("(((({expr}).0 as f64) / 65536.0_f64) as f32)"),
        (ValTy::Fix32, ValTy::F64) => format!("((({expr}).0 as f64) / 65536.0_f64)"),
        (ValTy::Fix64, ValTy::F32) => {
            format!("(((({expr}).0 as f64) / 4294967296.0_f64) as f32)")
        }
        (ValTy::Fix64, ValTy::F64) => format!("((({expr}).0 as f64) / 4294967296.0_f64)"),
        _ => coerce_expr(expr, from, to),
    }
}

pub(super) fn eval_hir_expr_static(
    expr: &HirExpr,
    expected_ty: Option<&Ty>,
    ctx: &NativeCtx<'_>,
) -> Option<(String, String)> {
    match expr {
        HirExpr::BoolLit(b) => Some(("bool".to_owned(), b.to_string())),
        HirExpr::StringLit(s) => {
            let cap = match expected_ty {
                Some(Ty::InlineStr(c)) => *c,
                _ => 64,
            };
            let words = 1 + cap.div_ceil(4);
            Some((
                format!("[u32; {words}]"),
                format!("strata_inline_str_pack::<{words}>({s:?})"),
            ))
        }
        HirExpr::CharLit(c) => {
            let eff = effective_expected_ty(expected_ty, &Ty::U8);
            let rty = rust_scalar_ty_from_hir(eff).unwrap_or("u8");
            Some((rty.to_owned(), format!("{} as {rty}", *c as u32)))
        }
        HirExpr::IntLit { value, ty } => {
            let eff = effective_expected_ty(expected_ty, ty);
            match eff {
                Ty::Fix32 => Some((
                    "Fixed32".to_owned(),
                    format!("Fixed32({})", format_fix32_i32_lit(scale_int_fix32(*value))),
                )),
                Ty::Fix64 => Some((
                    "Fixed64".to_owned(),
                    format!("Fixed64({})", format_fix64_i64_lit(scale_int_fix64(*value))),
                )),
                Ty::Named(n) => {
                    let short = n.rsplit("::").next().unwrap_or(n);
                    if let Some(en) = ctx
                        .enums_by_key
                        .get(n.as_str())
                        .or_else(|| ctx.enums_by_key.get(short))
                    {
                        let rty = en.rust_repr();
                        Some((rty.to_owned(), format_enum_disc_cast(*value, rty)))
                    } else {
                        let rty = rust_scalar_ty_from_hir(eff).unwrap_or("i64");
                        Some((rty.to_owned(), format_static_int_cast(*value, rty)))
                    }
                }
                _ => {
                    let rty = rust_scalar_ty_from_hir(eff).unwrap_or("i64");
                    Some((rty.to_owned(), format_static_int_cast(*value, rty)))
                }
            }
        }
        HirExpr::FloatLit { value, ty } => {
            let eff = effective_expected_ty(expected_ty, ty);
            match eff {
                Ty::Fix32 => Some((
                    "Fixed32".to_owned(),
                    format!(
                        "Fixed32({})",
                        format_fix32_i32_lit(scale_float_fix32(*value))
                    ),
                )),
                Ty::Fix64 => Some((
                    "Fixed64".to_owned(),
                    format!(
                        "Fixed64({})",
                        format_fix64_i64_lit(scale_float_fix64(*value))
                    ),
                )),
                Ty::F64 => Some(("f64".to_owned(), format_f64_lit(*value))),
                _ => Some(("f32".to_owned(), format_f32_lit(*value))),
            }
        }
        HirExpr::Path { name, ty } => {
            if let Some((en_name, var_name)) = name.rsplit_once("::")
                && let Some(en) = ctx.enums_by_key.get(en_name).or_else(|| {
                    ctx.enums_by_key
                        .get(en_name.rsplit("::").next().unwrap_or(en_name))
                })
                && let Some((_, disc)) = en.variants.iter().find(|(v, _)| v == var_name)
            {
                let rty = en.rust_repr();
                return Some((rty.to_owned(), format_enum_disc_cast(*disc, rty)));
            }
            match name.as_str() {
                "vec2::ZERO" => Some(("[f32; 2]".to_owned(), "[0.0_f32, 0.0_f32]".to_owned())),
                "vec2::ONE" => Some(("[f32; 2]".to_owned(), "[1.0_f32, 1.0_f32]".to_owned())),
                "vec2::X" => Some(("[f32; 2]".to_owned(), "[1.0_f32, 0.0_f32]".to_owned())),
                "vec2::Y" => Some(("[f32; 2]".to_owned(), "[0.0_f32, 1.0_f32]".to_owned())),
                "vec3::ZERO" => Some((
                    "[f32; 3]".to_owned(),
                    "[0.0_f32, 0.0_f32, 0.0_f32]".to_owned(),
                )),
                "vec3::ONE" => Some((
                    "[f32; 3]".to_owned(),
                    "[1.0_f32, 1.0_f32, 1.0_f32]".to_owned(),
                )),
                "vec3::X" => Some((
                    "[f32; 3]".to_owned(),
                    "[1.0_f32, 0.0_f32, 0.0_f32]".to_owned(),
                )),
                "vec3::Y" | "vec3::UP" => Some((
                    "[f32; 3]".to_owned(),
                    "[0.0_f32, 1.0_f32, 0.0_f32]".to_owned(),
                )),
                "vec3::Z" => Some((
                    "[f32; 3]".to_owned(),
                    "[0.0_f32, 0.0_f32, 1.0_f32]".to_owned(),
                )),
                "vec4::ZERO" => Some((
                    "[f32; 4]".to_owned(),
                    "[0.0_f32, 0.0_f32, 0.0_f32, 0.0_f32]".to_owned(),
                )),
                "vec4::ONE" => Some((
                    "[f32; 4]".to_owned(),
                    "[1.0_f32, 1.0_f32, 1.0_f32, 1.0_f32]".to_owned(),
                )),
                "vec4::X" => Some((
                    "[f32; 4]".to_owned(),
                    "[1.0_f32, 0.0_f32, 0.0_f32, 0.0_f32]".to_owned(),
                )),
                "vec4::Y" => Some((
                    "[f32; 4]".to_owned(),
                    "[0.0_f32, 1.0_f32, 0.0_f32, 0.0_f32]".to_owned(),
                )),
                "vec4::Z" => Some((
                    "[f32; 4]".to_owned(),
                    "[0.0_f32, 0.0_f32, 1.0_f32, 0.0_f32]".to_owned(),
                )),
                "vec4::W" => Some((
                    "[f32; 4]".to_owned(),
                    "[0.0_f32, 0.0_f32, 0.0_f32, 1.0_f32]".to_owned(),
                )),
                "ivec2::ZERO" => Some(("[i32; 2]".to_owned(), "[0i32, 0i32]".to_owned())),
                "ivec2::ONE" => Some(("[i32; 2]".to_owned(), "[1i32, 1i32]".to_owned())),
                "ivec2::X" => Some(("[i32; 2]".to_owned(), "[1i32, 0i32]".to_owned())),
                "ivec2::Y" => Some(("[i32; 2]".to_owned(), "[0i32, 1i32]".to_owned())),
                "ivec3::ZERO" => Some(("[i32; 3]".to_owned(), "[0i32, 0i32, 0i32]".to_owned())),
                "ivec3::ONE" => Some(("[i32; 3]".to_owned(), "[1i32, 1i32, 1i32]".to_owned())),
                "ivec3::X" => Some(("[i32; 3]".to_owned(), "[1i32, 0i32, 0i32]".to_owned())),
                "ivec3::Y" => Some(("[i32; 3]".to_owned(), "[0i32, 1i32, 0i32]".to_owned())),
                "ivec3::Z" => Some(("[i32; 3]".to_owned(), "[0i32, 0i32, 1i32]".to_owned())),
                "uvec2::ZERO" => Some(("[u32; 2]".to_owned(), "[0u32, 0u32]".to_owned())),
                "uvec2::ONE" => Some(("[u32; 2]".to_owned(), "[1u32, 1u32]".to_owned())),
                "uvec2::X" => Some(("[u32; 2]".to_owned(), "[1u32, 0u32]".to_owned())),
                "uvec2::Y" => Some(("[u32; 2]".to_owned(), "[0u32, 1u32]".to_owned())),
                _ => {
                    if let Some(c) = ctx.mir.consts.iter().find(|c| {
                        c.name == *name || c.name.rsplit("::").next() == Some(name.as_str())
                    }) && let Some(ref ce) = c.expr
                        && let Some((cty, _)) = eval_hir_expr_static(ce, Some(&c.ty), ctx)
                    {
                        let cname = format!("STRATA_CONST_{}", sanitize_ident(&c.name));
                        if let Some(exp) = expected_ty.filter(|t| !matches!(t, Ty::Unknown))
                            && *exp != c.ty
                        {
                            let src_vt = ValTy::from_sema_ty(&c.ty, ctx);
                            let dst_vt = ValTy::from_sema_ty(exp, ctx);
                            if src_vt != dst_vt {
                                return Some((
                                    rust_ty_from_hir_ty(exp, ctx),
                                    coerce_expr(&cname, &src_vt, &dst_vt),
                                ));
                            }
                        }
                        return Some((cty, cname));
                    }
                    let _ = ty;
                    None
                }
            }
        }
        HirExpr::Unary { op, expr, ty } => {
            let eff = effective_expected_ty(expected_ty, ty);
            if matches!(op, HirUnOp::Neg) {
                if let HirExpr::IntLit { value, .. } = expr.as_ref() {
                    if matches!(eff, Ty::Fix32) {
                        return Some((
                            "Fixed32".to_owned(),
                            format!(
                                "Fixed32({})",
                                format_fix32_i32_lit(scale_int_fix32(value.wrapping_neg()))
                            ),
                        ));
                    }
                    if matches!(eff, Ty::Fix64) {
                        return Some((
                            "Fixed64".to_owned(),
                            format!(
                                "Fixed64({})",
                                format_fix64_i64_lit(scale_int_fix64(value.wrapping_neg()))
                            ),
                        ));
                    }
                    if matches!(
                        eff,
                        Ty::I8
                            | Ty::I16
                            | Ty::I32
                            | Ty::I64
                            | Ty::U8
                            | Ty::U16
                            | Ty::U32
                            | Ty::U64
                            | Ty::Sym
                            | Ty::Rgba8
                    ) {
                        let rty = rust_scalar_ty_from_hir(eff).unwrap_or("i64");
                        return Some((
                            rty.to_owned(),
                            format!("((0i128.wrapping_sub({value}i128)) as {rty})"),
                        ));
                    }
                }
                if let HirExpr::FloatLit { value, .. } = expr.as_ref() {
                    if matches!(eff, Ty::Fix32) {
                        return Some((
                            "Fixed32".to_owned(),
                            format!(
                                "Fixed32({})",
                                format_fix32_i32_lit(scale_float_fix32(-(*value)))
                            ),
                        ));
                    }
                    if matches!(eff, Ty::Fix64) {
                        return Some((
                            "Fixed64".to_owned(),
                            format!(
                                "Fixed64({})",
                                format_fix64_i64_lit(scale_float_fix64(-(*value)))
                            ),
                        ));
                    }
                }
            }
            let (rty, inner) = eval_hir_expr_static(expr, Some(eff), ctx)?;
            if matches!(op, HirUnOp::Neg) && (rty == "Fixed32" || rty == "Fixed64") {
                return Some((rty.clone(), format!("{rty}(({inner}).0.wrapping_neg())")));
            }
            let op_s = match op {
                HirUnOp::Neg => "-",
                HirUnOp::Not | HirUnOp::BitNot => "!",
                _ => return None,
            };
            Some((rty, format!("({op_s}({inner}))")))
        }
        HirExpr::Binary { op, lhs, rhs, ty } => {
            let eff = effective_expected_ty(expected_ty, ty);
            let (l_rty, l) = eval_hir_expr_static(lhs, Some(eff), ctx)?;
            let (_, r) = eval_hir_expr_static(rhs, Some(eff), ctx)?;
            if matches!(eff, Ty::Fix32 | Ty::Fix64) {
                let is_64 = matches!(eff, Ty::Fix64);
                let rty = if is_64 { "Fixed64" } else { "Fixed32" };
                let expr_s = match op {
                    HirBinOp::Add => format!("{rty}(({l}).0.wrapping_add(({r}).0))"),
                    HirBinOp::Sub => format!("{rty}(({l}).0.wrapping_sub(({r}).0))"),
                    HirBinOp::Mul => {
                        if is_64 {
                            format!(
                                "Fixed64((((({l}).0 as i128) * (({r}).0 as i128)) >> 32) as i64)"
                            )
                        } else {
                            format!("Fixed32((((({l}).0 as i64) * (({r}).0 as i64)) >> 16) as i32)")
                        }
                    }
                    HirBinOp::Div => {
                        if is_64 {
                            format!(
                                "Fixed64(if ({r}).0 == 0 {{ 0 }} else {{ (((({l}).0 as i128) << 32) / (({r}).0 as i128)) as i64 }})"
                            )
                        } else {
                            format!(
                                "Fixed32(if ({r}).0 == 0 {{ 0 }} else {{ (((({l}).0 as i64) << 16) / (({r}).0 as i64)) as i32 }})"
                            )
                        }
                    }
                    HirBinOp::Rem => {
                        format!(
                            "{rty}(if ({r}).0 == 0 {{ 0 }} else {{ ({l}).0.wrapping_rem(({r}).0) }})"
                        )
                    }
                    _ => return None,
                };
                return Some((rty.to_owned(), expr_s));
            }
            let rty = rust_scalar_ty_from_hir(eff).unwrap_or(l_rty.as_str());
            let is_int = matches!(
                rty,
                "u8" | "i8" | "u16" | "i16" | "u32" | "i32" | "u64" | "i64"
            );
            if is_int {
                let expr_s = match op {
                    HirBinOp::Add => format!("(({l}).wrapping_add({r}))"),
                    HirBinOp::Sub => format!("(({l}).wrapping_sub({r}))"),
                    HirBinOp::Mul => format!("(({l}).wrapping_mul({r}))"),
                    HirBinOp::Div => {
                        format!("(if ({r}) == 0 {{ 0 }} else {{ ({l}).wrapping_div({r}) }})")
                    }
                    HirBinOp::Rem => {
                        format!("(if ({r}) == 0 {{ 0 }} else {{ ({l}).wrapping_rem({r}) }})")
                    }
                    HirBinOp::BitAnd => format!("(({l}) & ({r}))"),
                    HirBinOp::BitOr => format!("(({l}) | ({r}))"),
                    HirBinOp::BitXor => format!("(({l}) ^ ({r}))"),
                    HirBinOp::Shl => format!("(({l}).wrapping_shl(({r}) as u32))"),
                    HirBinOp::Shr => format!("(({l}).wrapping_shr(({r}) as u32))"),
                    _ => return None,
                };
                return Some((rty.to_owned(), expr_s));
            }
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
            Some((rty.to_owned(), format!("(({l}) {op_s} ({r}))")))
        }
        HirExpr::Cast { expr, target_ty } => {
            let eff = effective_expected_ty(expected_ty, target_ty);
            let is_lit_or_neg_lit = matches!(
                expr.as_ref(),
                HirExpr::IntLit { .. } | HirExpr::FloatLit { .. }
            ) || matches!(
                expr.as_ref(),
                HirExpr::Unary {
                    op: HirUnOp::Neg,
                    expr: inner,
                    ..
                } if matches!(inner.as_ref(), HirExpr::IntLit { .. } | HirExpr::FloatLit { .. })
            );
            if is_lit_or_neg_lit
                && matches!(target_ty, Ty::F32 | Ty::F64)
                && matches!(eff, Ty::F32 | Ty::F64 | Ty::Fix32 | Ty::Fix64)
            {
                return eval_hir_expr_static(expr, Some(eff), ctx);
            }
            if target_ty == eff
                && matches!(eff, Ty::Fix32 | Ty::Fix64)
                && let Some(cs) = eval_hir_const_scalar(expr, ctx)
            {
                return Some(match eff {
                    Ty::Fix32 => {
                        let q = match cs {
                            ConstScalar::Int(i) => scale_int_fix32(i),
                            ConstScalar::Float(f) => scale_float_fix32(f),
                        };
                        (
                            "Fixed32".to_owned(),
                            format!("Fixed32({})", format_fix32_i32_lit(q)),
                        )
                    }
                    _ => {
                        let q = match cs {
                            ConstScalar::Int(i) => scale_int_fix64(i),
                            ConstScalar::Float(f) => scale_float_fix64(f),
                        };
                        (
                            "Fixed64".to_owned(),
                            format!("Fixed64({})", format_fix64_i64_lit(q)),
                        )
                    }
                });
            }
            let (src_rty, src_val) = eval_hir_expr_static(expr, None, ctx)?;
            let src_vt = val_ty_from_rust_ty(&src_rty, &expr.ty(), ctx);
            let mid_vt = ValTy::from_sema_ty(target_ty, ctx);
            let mid_val = if matches!(target_ty, Ty::Unknown) || src_vt == mid_vt {
                src_val
            } else {
                const_safe_coerce_expr(&src_val, &src_vt, &mid_vt)
            };
            let dst_vt = ValTy::from_sema_ty(eff, ctx);
            let out_val = if matches!(eff, Ty::Unknown) || mid_vt == dst_vt {
                mid_val
            } else {
                const_safe_coerce_expr(&mid_val, &mid_vt, &dst_vt)
            };
            let out_ty = if matches!(eff, Ty::Unknown) {
                rust_ty_from_hir_ty(target_ty, ctx)
            } else {
                rust_ty_from_hir_ty(eff, ctx)
            };
            Some((out_ty, out_val))
        }
        HirExpr::ArrayLit { elems, ty } => {
            let eff = effective_expected_ty(expected_ty, ty);
            let mut elem_ty_opt = match eff {
                Ty::Array { elem, .. } | Ty::SmallVec { elem, .. } => Some(elem.as_ref()),
                Ty::Vec2 | Ty::Vec3 | Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => Some(&Ty::F32),
                Ty::IVec2 | Ty::IVec3 => Some(&Ty::I32),
                Ty::UVec2 => Some(&Ty::U32),
                _ => None,
            };
            if elem_ty_opt.is_none_or(|t| matches!(t, Ty::Unknown))
                && let Ty::Array { elem, .. } | Ty::SmallVec { elem, .. } = ty
                && !matches!(elem.as_ref(), Ty::Unknown)
            {
                elem_ty_opt = Some(elem.as_ref());
            }
            let target_len = match eff {
                Ty::Array { len, .. } => *len,
                Ty::SmallVec { cap, .. } => *cap,
                Ty::Vec2 | Ty::IVec2 | Ty::UVec2 => 2,
                Ty::Vec3 | Ty::IVec3 => 3,
                Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => 4,
                _ => match ty {
                    Ty::Array { len, .. } => *len,
                    Ty::SmallVec { cap, .. } => *cap,
                    _ => elems.len(),
                },
            };
            let child_expected = elem_ty_opt.filter(|t| !matches!(t, Ty::Unknown));
            let mut parts = Vec::with_capacity(target_len);
            let mut first_elem_rty: Option<String> = None;
            for el in elems.iter().take(target_len) {
                let (el_rty, el_val) = eval_hir_expr_static(el, child_expected, ctx)?;
                if first_elem_rty.is_none() {
                    first_elem_rty = Some(el_rty);
                }
                parts.push(el_val);
            }
            while parts.len() < target_len {
                let pad = if let Some(ety) = child_expected {
                    rust_default_expr_from_hir_ty(ety, ctx)
                } else {
                    "Default::default()".to_owned()
                };
                parts.push(pad);
            }
            let elem_rty = if let Some(ety) = child_expected {
                rust_ty_from_hir_ty(ety, ctx)
            } else {
                first_elem_rty.unwrap_or_else(|| "i32".to_owned())
            };
            Some((
                format!("[{elem_rty}; {target_len}]"),
                format!("[{}]", parts.join(", ")),
            ))
        }
        HirExpr::StructLit { name, fields, ty } => {
            let entry_opt = ctx.find_layout_entry(name).or_else(|| {
                let eff = effective_expected_ty(expected_ty, ty);
                if let Ty::Named(en) = eff {
                    ctx.find_layout_entry(en)
                } else {
                    None
                }
            });
            let entry = entry_opt?;
            if entry.layout.size == 0 || entry.layout.fields.is_empty() {
                return Some((entry.struct_name.clone(), entry.struct_name.clone()));
            }
            let mut finits = Vec::with_capacity(entry.layout.fields.len());
            for sf in &entry.layout.fields {
                let rfname = sanitize_rust_ident(&sf.name);
                if sf.is_padding {
                    finits.push(format!("{rfname}: [0u8; {}]", sf.size.max(1)));
                } else if let Some((_, fexpr)) = fields.iter().find(|(fnm, _)| fnm == &sf.name)
                    && let Some((_, val_s)) = eval_hir_expr_static(fexpr, Some(&sf.ty), ctx)
                {
                    let wrapped = wrap_abi_field_store(&val_s, sf, ctx, false);
                    finits.push(format!("{rfname}: {wrapped}"));
                } else if let Some(cval) = lookup_field_default(ctx.mir, entry.layout, &sf.name) {
                    finits.push(format!(
                        "{rfname}: {}",
                        format_const_for_field(cval, sf, ctx)
                    ));
                } else {
                    finits.push(format!(
                        "{rfname}: {}",
                        native_default_expr_for_field(sf, ctx)
                    ));
                }
            }
            let expr_s = format!("{} {{ {} }}", entry.struct_name, finits.join(", "));
            Some((entry.struct_name.clone(), expr_s))
        }
        HirExpr::Call(call) => match call
            .callee
            .rsplit("::")
            .next()
            .unwrap_or(call.callee.as_str())
        {
            "bits" => {
                if let Some(Ty::BitSet(b)) = expected_ty {
                    let words = (*b).div_ceil(32).max(1);
                    let mut arr = vec![0u32; words];
                    for a in &call.args {
                        if let Some(ConstScalar::Int(v)) = eval_hir_const_scalar(a, ctx)
                            && v >= 0
                        {
                            let bit = v as usize;
                            if bit / 32 < words {
                                arr[bit / 32] |= 1u32 << (bit % 32);
                            }
                        }
                    }
                    let parts: Vec<String> = arr.iter().map(|w| format!("0x{w:08X}u32")).collect();
                    Some((format!("[u32; {words}]"), format!("[{}]", parts.join(", "))))
                } else {
                    let mut mask = 0u64;
                    for a in &call.args {
                        if let Some(ConstScalar::Int(v)) = eval_hir_const_scalar(a, ctx)
                            && v >= 0
                            && (v as u32) < 64
                        {
                            mask |= 1u64 << (v as u32);
                        }
                    }
                    let rust_ty = expected_ty
                        .and_then(|t| match t {
                            Ty::U8 => Some("u8"),
                            Ty::U16 => Some("u16"),
                            Ty::U32 => Some("u32"),
                            Ty::U64 => Some("u64"),
                            Ty::I8 => Some("i8"),
                            Ty::I16 => Some("i16"),
                            Ty::I32 => Some("i32"),
                            Ty::I64 => Some("i64"),
                            _ => None,
                        })
                        .unwrap_or("u64");
                    Some((rust_ty.to_owned(), format!("0x{mask:X}u64 as {rust_ty}")))
                }
            }
            "vec2" | "Vec2" => {
                let x = eval_hir_f32(call.args.first(), ctx);
                let y = eval_hir_f32(call.args.get(1), ctx);
                Some(("[f32; 2]".to_owned(), format!("[{x}, {y}]")))
            }
            "vec3" | "Vec3" => {
                let x = eval_hir_f32(call.args.first(), ctx);
                let y = eval_hir_f32(call.args.get(1), ctx);
                let z = eval_hir_f32(call.args.get(2), ctx);
                Some(("[f32; 3]".to_owned(), format!("[{x}, {y}, {z}]")))
            }
            "vec3a" | "Vec3a" => {
                let x = eval_hir_f32(call.args.first(), ctx);
                let y = eval_hir_f32(call.args.get(1), ctx);
                let z = eval_hir_f32(call.args.get(2), ctx);
                Some(("[f32; 4]".to_owned(), format!("[{x}, {y}, {z}, 0.0_f32]")))
            }
            "vec4" | "Vec4" | "quat" | "Quat" | "rgba" | "Rgba" => {
                let x = eval_hir_f32(call.args.first(), ctx);
                let y = eval_hir_f32(call.args.get(1), ctx);
                let z = eval_hir_f32(call.args.get(2), ctx);
                let w = eval_hir_f32(call.args.get(3), ctx);
                Some(("[f32; 4]".to_owned(), format!("[{x}, {y}, {z}, {w}]")))
            }
            "ivec2" | "IVec2" => {
                let x = eval_hir_i32(call.args.first(), ctx);
                let y = eval_hir_i32(call.args.get(1), ctx);
                Some(("[i32; 2]".to_owned(), format!("[{x}i32, {y}i32]")))
            }
            "ivec3" | "IVec3" => {
                let x = eval_hir_i32(call.args.first(), ctx);
                let y = eval_hir_i32(call.args.get(1), ctx);
                let z = eval_hir_i32(call.args.get(2), ctx);
                Some(("[i32; 3]".to_owned(), format!("[{x}i32, {y}i32, {z}i32]")))
            }
            "uvec2" | "UVec2" => {
                let x = eval_hir_u32(call.args.first(), ctx);
                let y = eval_hir_u32(call.args.get(1), ctx);
                Some(("[u32; 2]".to_owned(), format!("[{x}u32, {y}u32]")))
            }
            "meters" | "sec" | "ms" | "rad" | "deg" | "mps" | "mps2" | "hz" | "frames" => {
                eval_hir_expr_static(call.args.first()?, expected_ty, ctx)
            }
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn eval_hir_f32(expr: Option<&HirExpr>, ctx: &NativeCtx<'_>) -> String {
    match expr {
        Some(HirExpr::FloatLit { value, .. }) => format_f32_lit(*value),
        Some(HirExpr::IntLit { value, .. }) => format_f32_lit(*value as f64),
        Some(other) => eval_hir_expr_static(other, Some(&Ty::F32), ctx)
            .map_or_else(|| "0.0_f32".to_owned(), |(_, v)| v),
        None => "0.0_f32".to_owned(),
    }
}

#[derive(Clone, Copy)]
enum ConstScalar {
    Int(i64),
    Float(f64),
}

fn eval_hir_const_scalar(expr: &HirExpr, ctx: &NativeCtx<'_>) -> Option<ConstScalar> {
    match expr {
        HirExpr::IntLit { value, .. } => Some(ConstScalar::Int(*value)),
        HirExpr::FloatLit { value, .. } => Some(ConstScalar::Float(*value)),
        HirExpr::BoolLit(b) => Some(ConstScalar::Int(i64::from(*b))),
        HirExpr::CharLit(c) => Some(ConstScalar::Int(i64::from(*c as u32))),
        HirExpr::Path { name, .. } => {
            if let Some((en_name, var_name)) = name.rsplit_once("::")
                && let Some(en) = ctx.enums_by_key.get(en_name).or_else(|| {
                    ctx.enums_by_key
                        .get(en_name.rsplit("::").next().unwrap_or(en_name))
                })
                && let Some((_, disc)) = en.variants.iter().find(|(v, _)| v == var_name)
            {
                return Some(ConstScalar::Int(*disc));
            }
            if let Some(c) = ctx
                .mir
                .consts
                .iter()
                .find(|c| c.name == *name || c.name.rsplit("::").next() == Some(name.as_str()))
                && let Some(ref ce) = c.expr
            {
                return eval_hir_const_scalar(ce, ctx);
            }
            None
        }
        HirExpr::Unary { op, expr, .. } => {
            let v = eval_hir_const_scalar(expr, ctx)?;
            match (op, v) {
                (HirUnOp::Neg, ConstScalar::Int(i)) => Some(ConstScalar::Int(i.wrapping_neg())),
                (HirUnOp::Neg, ConstScalar::Float(f)) => Some(ConstScalar::Float(-f)),
                (HirUnOp::BitNot, ConstScalar::Int(i)) => Some(ConstScalar::Int(!i)),
                (HirUnOp::Not, ConstScalar::Int(i)) => Some(ConstScalar::Int(i64::from(i == 0))),
                _ => None,
            }
        }
        HirExpr::Cast { expr, target_ty } => {
            let v = eval_hir_const_scalar(expr, ctx)?;
            let src_fix = match expr.ty() {
                Ty::Fix32 => Some(false),
                Ty::Fix64 => Some(true),
                _ => match expr.as_ref() {
                    HirExpr::Cast {
                        target_ty: Ty::Fix32,
                        ..
                    } => Some(false),
                    HirExpr::Cast {
                        target_ty: Ty::Fix64,
                        ..
                    } => Some(true),
                    _ => None,
                },
            };
            if let Some(is_fix64) = src_fix
                && matches!(
                    target_ty,
                    Ty::I8
                        | Ty::I16
                        | Ty::I32
                        | Ty::I64
                        | Ty::U8
                        | Ty::U16
                        | Ty::U32
                        | Ty::U64
                        | Ty::Sym
                        | Ty::Rgba8
                )
            {
                let trunc: i64 = if is_fix64 {
                    let q = match v {
                        ConstScalar::Int(i) => i.wrapping_shl(32),
                        ConstScalar::Float(f) if f.is_finite() => {
                            (f * 4_294_967_296.0).round() as i64
                        }
                        ConstScalar::Float(_) => 0,
                    };
                    q / 4_294_967_296
                } else {
                    let q = match v {
                        ConstScalar::Int(i) => i.saturating_mul(65_536) as i32,
                        ConstScalar::Float(f) if f.is_finite() => (f * 65_536.0).round() as i32,
                        ConstScalar::Float(_) => 0,
                    };
                    i64::from(q / 65_536)
                };
                return match target_ty {
                    Ty::I8 => Some(ConstScalar::Int(i64::from(trunc as i8))),
                    Ty::I16 => Some(ConstScalar::Int(i64::from(trunc as i16))),
                    Ty::I32 => Some(ConstScalar::Int(i64::from(trunc as i32))),
                    Ty::I64 | Ty::U64 => Some(ConstScalar::Int(trunc)),
                    Ty::U8 => Some(ConstScalar::Int(i64::from(trunc as u8))),
                    Ty::U16 => Some(ConstScalar::Int(i64::from(trunc as u16))),
                    Ty::U32 | Ty::Sym | Ty::Rgba8 => {
                        Some(ConstScalar::Int(i64::from(trunc as u32)))
                    }
                    _ => None,
                };
            }
            match target_ty {
                Ty::U8 => Some(ConstScalar::Int(match v {
                    ConstScalar::Int(i) => i64::from(i as u8),
                    ConstScalar::Float(f) => i64::from(f as u8),
                })),
                Ty::I8 => Some(ConstScalar::Int(match v {
                    ConstScalar::Int(i) => i64::from(i as i8),
                    ConstScalar::Float(f) => i64::from(f as i8),
                })),
                Ty::U16 => Some(ConstScalar::Int(match v {
                    ConstScalar::Int(i) => i64::from(i as u16),
                    ConstScalar::Float(f) => i64::from(f as u16),
                })),
                Ty::I16 => Some(ConstScalar::Int(match v {
                    ConstScalar::Int(i) => i64::from(i as i16),
                    ConstScalar::Float(f) => i64::from(f as i16),
                })),
                Ty::U32 | Ty::Sym | Ty::Rgba8 => Some(ConstScalar::Int(match v {
                    ConstScalar::Int(i) => i64::from(i as u32),
                    ConstScalar::Float(f) => i64::from(f as u32),
                })),
                Ty::I32 => Some(ConstScalar::Int(match v {
                    ConstScalar::Int(i) => i64::from(i as i32),
                    ConstScalar::Float(f) => i64::from(f as i32),
                })),
                Ty::U64 => Some(ConstScalar::Int(match v {
                    ConstScalar::Int(i) => i,
                    ConstScalar::Float(f) => (f as u64) as i64,
                })),
                Ty::I64 => Some(ConstScalar::Int(match v {
                    ConstScalar::Int(i) => i,
                    ConstScalar::Float(f) => f as i64,
                })),
                Ty::Fix32 => Some(match v {
                    ConstScalar::Int(i) => ConstScalar::Int(i),
                    ConstScalar::Float(f) if f.is_finite() => {
                        let q = (f * 65_536.0).round() as i32;
                        ConstScalar::Float(f64::from(q) / 65_536.0)
                    }
                    ConstScalar::Float(_) => ConstScalar::Float(0.0),
                }),
                Ty::Fix64 => Some(match v {
                    ConstScalar::Int(i) => ConstScalar::Int(i),
                    ConstScalar::Float(f) if f.is_finite() => {
                        let q = (f * 4_294_967_296.0).round() as i64;
                        ConstScalar::Float((q as f64) / 4_294_967_296.0)
                    }
                    ConstScalar::Float(_) => ConstScalar::Float(0.0),
                }),
                Ty::F32 => Some(ConstScalar::Float(match v {
                    ConstScalar::Int(i) => (i as f32) as f64,
                    ConstScalar::Float(f) => (f as f32) as f64,
                })),
                Ty::F64 => Some(ConstScalar::Float(match v {
                    ConstScalar::Int(i) => i as f64,
                    ConstScalar::Float(f) => f,
                })),
                _ => Some(v),
            }
        }
        HirExpr::Binary { op, lhs, rhs, .. } => {
            let l = eval_hir_const_scalar(lhs, ctx)?;
            let r = eval_hir_const_scalar(rhs, ctx)?;
            match (l, r) {
                (ConstScalar::Int(a), ConstScalar::Int(b)) => match op {
                    HirBinOp::Add => Some(ConstScalar::Int(a.wrapping_add(b))),
                    HirBinOp::Sub => Some(ConstScalar::Int(a.wrapping_sub(b))),
                    HirBinOp::Mul => Some(ConstScalar::Int(a.wrapping_mul(b))),
                    HirBinOp::Div if b != 0 => Some(ConstScalar::Int(a.wrapping_div(b))),
                    HirBinOp::Rem if b != 0 => Some(ConstScalar::Int(a.wrapping_rem(b))),
                    HirBinOp::BitAnd => Some(ConstScalar::Int(a & b)),
                    HirBinOp::BitOr => Some(ConstScalar::Int(a | b)),
                    HirBinOp::BitXor => Some(ConstScalar::Int(a ^ b)),
                    HirBinOp::Shl => Some(ConstScalar::Int(a.wrapping_shl(b as u32))),
                    HirBinOp::Shr => Some(ConstScalar::Int(a.wrapping_shr(b as u32))),
                    _ => None,
                },
                _ => {
                    let fa = match l {
                        ConstScalar::Int(i) => i as f64,
                        ConstScalar::Float(f) => f,
                    };
                    let fb = match r {
                        ConstScalar::Int(i) => i as f64,
                        ConstScalar::Float(f) => f,
                    };
                    match op {
                        HirBinOp::Add => Some(ConstScalar::Float(fa + fb)),
                        HirBinOp::Sub => Some(ConstScalar::Float(fa - fb)),
                        HirBinOp::Mul => Some(ConstScalar::Float(fa * fb)),
                        HirBinOp::Div => Some(ConstScalar::Float(fa / fb)),
                        HirBinOp::Rem => Some(ConstScalar::Float(fa % fb)),
                        _ => None,
                    }
                }
            }
        }
        HirExpr::Call(call)
            if matches!(
                call.callee
                    .rsplit("::")
                    .next()
                    .unwrap_or(call.callee.as_str()),
                "meters" | "sec" | "ms" | "rad" | "deg" | "mps" | "mps2" | "hz" | "frames"
            ) =>
        {
            eval_hir_const_scalar(call.args.first()?, ctx)
        }
        _ => None,
    }
}

pub(super) fn eval_hir_i32(expr: Option<&HirExpr>, ctx: &NativeCtx<'_>) -> i32 {
    match expr.and_then(|e| eval_hir_const_scalar(e, ctx)) {
        Some(ConstScalar::Int(i)) => i as i32,
        Some(ConstScalar::Float(f)) => f as i32,
        None => 0,
    }
}

pub(super) fn eval_hir_u32(expr: Option<&HirExpr>, ctx: &NativeCtx<'_>) -> u32 {
    match expr.and_then(|e| eval_hir_const_scalar(e, ctx)) {
        Some(ConstScalar::Int(i)) => i as u32,
        Some(ConstScalar::Float(f)) => f as u32,
        None => 0,
    }
}

pub(super) fn rust_scalar_ty_from_hir(ty: &Ty) -> Option<&'static str> {
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
        Ty::Fix32 => Some("Fixed32"),
        Ty::Fix64 => Some("Fixed64"),
        Ty::Bool => Some("bool"),
        _ => None,
    }
}

pub(super) fn lookup_field_default<'a>(
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

pub(super) fn emit_native_layouts(out: &mut String, ctx: &NativeCtx<'_>) {
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

        if !is_zst && layout.align > 1 {
            writeln!(out, "#[repr(C, align({}))]", layout.align).ok();
        } else {
            writeln!(out, "#[repr(C)]").ok();
        }
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
            writeln!(out, "impl {struct_name} {{").ok();
            writeln!(out, "    #[allow(dead_code)]").ok();
            writeln!(out, "    pub const fn strata_default() -> Self {{ Self }}").ok();
            writeln!(out, "}}").ok();
            writeln!(out, "impl Default for {struct_name} {{").ok();
            writeln!(out, "    fn default() -> Self {{ Self::strata_default() }}").ok();
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
            writeln!(
                out,
                "    fn default() -> Self {{\n        Self::strata_default()\n    }}"
            )
            .ok();
            writeln!(out, "}}").ok();

            let sz = layout.size;
            writeln!(out, "impl {struct_name} {{").ok();
            writeln!(
                out,
                "    #[allow(dead_code)]\n    pub const fn strata_default() -> Self {{\n        Self {{"
            )
            .ok();
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
                        _ => native_default_expr_for_field(field, ctx),
                    }
                } else {
                    native_default_expr_for_field(field, ctx)
                };
                writeln!(out, "            {fname}: {def},").ok();
            }
            writeln!(out, "        }}\n    }}").ok();
            writeln!(
                out,
                "    #[allow(dead_code)]\n    const fn strata_to_u8_bytes(&self) -> [u8; {sz}] {{\n        let mut out = [0u8; {sz}];"
            )
            .ok();
            for f in &layout.fields {
                if f.is_padding {
                    continue;
                }
                let fname = sanitize_rust_ident(&f.name);
                if is_entity_ev && f.name == "entity" {
                    emit_write_field_to_bytes(
                        out,
                        &format!("self.{fname}.0"),
                        "FfiEntity",
                        f.offset,
                        f.size,
                    );
                } else {
                    let rty = rust_abi_type_for_field(f, mir);
                    emit_write_field_to_bytes(
                        out,
                        &format!("self.{fname}"),
                        &rty,
                        f.offset,
                        f.size,
                    );
                }
            }
            writeln!(out, "        out\n    }}").ok();
            writeln!(
                out,
                "    #[allow(dead_code)]\n    fn strata_from_u8_bytes(&mut self, b: &[u8]) {{\n        if b.len() < {sz} {{ return; }}"
            )
            .ok();
            for f in &layout.fields {
                if f.is_padding {
                    continue;
                }
                let fname = sanitize_rust_ident(&f.name);
                if is_entity_ev && f.name == "entity" {
                    emit_read_field_from_bytes(
                        out,
                        &format!("self.{fname}.0"),
                        "FfiEntity",
                        f.offset,
                        f.size,
                    );
                } else {
                    let rty = rust_abi_type_for_field(f, mir);
                    emit_read_field_from_bytes(
                        out,
                        &format!("self.{fname}"),
                        &rty,
                        f.offset,
                        f.size,
                    );
                }
            }
            writeln!(out, "    }}").ok();
            writeln!(
                out,
                "    #[allow(dead_code)]\n    fn strata_from_u8_bytes_val(b: &[u8]) -> Self {{\n        let mut out = Self::default();\n        out.strata_from_u8_bytes(b);\n        out\n    }}"
            )
            .ok();
            for (w, from_w, ty, elem_sz, conv) in [
                (
                    "u64_words",
                    "from_u64_words",
                    "u64",
                    8usize,
                    "u64::from_le_bytes",
                ),
                (
                    "u32_words",
                    "from_u32_words",
                    "u32",
                    4usize,
                    "u32::from_le_bytes",
                ),
                (
                    "u16_words",
                    "from_u16_words",
                    "u16",
                    2usize,
                    "u16::from_le_bytes",
                ),
            ] {
                if sz >= elem_sz && sz.is_multiple_of(elem_sz) {
                    let n = sz / elem_sz;
                    let slice_lit = match elem_sz {
                        8 => {
                            "[bytes[s], bytes[s + 1], bytes[s + 2], bytes[s + 3], bytes[s + 4], bytes[s + 5], bytes[s + 6], bytes[s + 7]]"
                        }
                        4 => "[bytes[s], bytes[s + 1], bytes[s + 2], bytes[s + 3]]",
                        _ => "[bytes[s], bytes[s + 1]]",
                    };
                    writeln!(
                        out,
                        "    #[allow(dead_code)]\n\
                         \x20   const fn strata_to_{w}(&self) -> [{ty}; {n}] {{\n\
                         \x20       let bytes = self.strata_to_u8_bytes();\n\
                         \x20       let mut out = [0{ty}; {n}];\n\
                         \x20       let mut i = 0usize;\n\
                         \x20       while i < {n} {{\n\
                         \x20           let s = i * {elem_sz};\n\
                         \x20           out[i] = {conv}({slice_lit});\n\
                         \x20           i += 1;\n\
                         \x20       }}\n\
                         \x20       out\n\
                         \x20   }}\n\
                         \x20   #[allow(dead_code)]\n\
                         \x20   fn strata_{from_w}(words: &[{ty}; {n}]) -> Self {{\n\
                         \x20       let mut bytes = [0u8; {sz}];\n\
                         \x20       for (i, w) in words.iter().enumerate() {{\n\
                         \x20           bytes[i * {elem_sz}..(i + 1) * {elem_sz}].copy_from_slice(&w.to_le_bytes());\n\
                         \x20       }}\n\
                         \x20       Self::strata_from_u8_bytes_val(&bytes)\n\
                         \x20   }}"
                    )
                    .ok();
                }
            }
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

pub(super) fn emit_synthesized_tags(out: &mut String, ctx: &NativeCtx<'_>) {
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
pub(super) fn emit_mod_component_impl(
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

pub(super) fn emit_spatial_and_relation_resources(out: &mut String, ctx: &NativeCtx<'_>) {
    for sp in &ctx.mir.spatial_indices {
        let sname = format!("StrataSpatialBacking_{}", sanitize_ident(&sp.name));
        let frames = sp.frames.max(1);
        let capacity = sp.capacity.max(1);
        let cols = sp.cols.max(1);
        let rows = sp.rows.max(1);
        let cell_count = cols * rows;
        let cell_size = if sp.cell_size > 0.0 {
            sp.cell_size
        } else {
            1.0
        };
        let inv_cell_size = 1.0_f32 / cell_size;
        let bmin_x = sp.bounds_min[0];
        let bmin_y = sp.bounds_min[1];
        let ax0 = (sp.plane_axes[0] as usize).min(2);
        let ax1 = (sp.plane_axes[1] as usize).min(2);
        let cell_offs_len = cell_count + 1;
        writeln!(
            out,
            "#[derive(Debug, Clone)]\n\
             pub struct {sname}Frame {{\n\
             \x20   pub count: u32,\n\
             \x20   pub cell_offsets: Vec<u32>,\n\
             \x20   pub entities: Vec<Entity>,\n\
             \x20   pub positions: Vec<[f32; 3]>,\n\
             }}\n\
             #[derive(Resource, Debug, Clone)]\n\
             pub struct {sname} {{\n\
             \x20   pub history: Vec<{sname}Frame>,\n\
             \x20   pub write_cursors: Vec<u32>,\n\
             \x20   pub head_tick: u32,\n\
             \x20   pub frames: usize,\n\
             \x20   pub capacity: usize,\n\
             \x20   pub cols: usize,\n\
             \x20   pub rows: usize,\n\
             \x20   pub cell_count: usize,\n\
             \x20   pub cell_size: f32,\n\
             \x20   pub inv_cell_size: f32,\n\
             \x20   pub bounds_min: [f32; 2],\n\
             \x20   pub plane_axes: [usize; 2],\n\
             }}\n\
             impl Default for {sname} {{\n\
             \x20   fn default() -> Self {{\n\
             \x20       let mut history = Vec::with_capacity({frames});\n\
             \x20       for _ in 0..{frames} {{\n\
             \x20           history.push({sname}Frame {{\n\
             \x20               count: 0,\n\
             \x20               cell_offsets: vec![0u32; {cell_offs_len}],\n\
             \x20               entities: Vec::new(),\n\
             \x20               positions: Vec::new(),\n\
             \x20           }});\n\
             \x20       }}\n\
             \x20       Self {{\n\
             \x20           history,\n\
             \x20           write_cursors: vec![0u32; {cell_count}],\n\
             \x20           head_tick: 0,\n\
             \x20           frames: {frames},\n\
             \x20           capacity: {capacity},\n\
             \x20           cols: {cols},\n\
             \x20           rows: {rows},\n\
             \x20           cell_count: {cell_count},\n\
             \x20           cell_size: {},\n\
             \x20           inv_cell_size: {},\n\
             \x20           bounds_min: [{}, {}],\n\
             \x20           plane_axes: [{ax0}, {ax1}],\n\
             \x20       }}\n\
             \x20   }}\n\
             }}\n\
             impl {sname} {{\n\
             \x20   #[inline]\n\
             \x20   fn cell_coords(&self, x: f32, y: f32) -> (usize, usize) {{\n\
             \x20       let cx = (((x - self.bounds_min[0]) * self.inv_cell_size).floor() as i32).clamp(0, self.cols as i32 - 1) as usize;\n\
             \x20       let cy = (((y - self.bounds_min[1]) * self.inv_cell_size).floor() as i32).clamp(0, self.rows as i32 - 1) as usize;\n\
             \x20       (cx, cy)\n\
             \x20   }}\n\
             \x20   #[inline]\n\
             \x20   fn cell_of(&self, pos: [f32; 3]) -> usize {{\n\
             \x20       let (cx, cy) = self.cell_coords(pos[self.plane_axes[0]], pos[self.plane_axes[1]]);\n\
             \x20       cy * self.cols + cx\n\
             \x20   }}\n\
             \x20   pub fn csr_begin(&mut self) {{\n\
             \x20       self.head_tick = self.head_tick.wrapping_add(1);\n\
             \x20       let slot = (self.head_tick as usize) % self.frames;\n\
             \x20       let f = &mut self.history[slot];\n\
             \x20       f.count = 0;\n\
             \x20       f.cell_offsets.fill(0);\n\
             \x20       f.entities.clear();\n\
             \x20       f.positions.clear();\n\
             \x20       self.write_cursors.fill(0);\n\
             \x20   }}\n\
             \x20   pub fn csr_count(&mut self, pos: [f32; 3]) {{\n\
             \x20       let slot = (self.head_tick as usize) % self.frames;\n\
             \x20       let cell = self.cell_of(pos);\n\
             \x20       let f = &mut self.history[slot];\n\
             \x20       if (f.count as usize) < self.capacity {{\n\
             \x20           f.cell_offsets[cell + 1] = f.cell_offsets[cell + 1].saturating_add(1);\n\
             \x20           f.count = f.count.saturating_add(1);\n\
             \x20       }}\n\
             \x20   }}\n\
             \x20   pub fn csr_prefix_sum(&mut self) {{\n\
             \x20       let slot = (self.head_tick as usize) % self.frames;\n\
             \x20       let f = &mut self.history[slot];\n\
             \x20       let mut sum = 0u32;\n\
             \x20       for c in 0..self.cell_count {{\n\
             \x20           let cnt = f.cell_offsets[c + 1];\n\
             \x20           f.cell_offsets[c] = sum;\n\
             \x20           self.write_cursors[c] = sum;\n\
             \x20           sum = sum.saturating_add(cnt);\n\
             \x20       }}\n\
             \x20       f.cell_offsets[self.cell_count] = sum;\n\
             \x20       let total = (sum as usize).min(self.capacity);\n\
             \x20       f.count = total as u32;\n\
             \x20       f.entities.resize(total, Entity::PLACEHOLDER);\n\
             \x20       f.positions.resize(total, [0.0; 3]);\n\
             \x20   }}\n\
             \x20   pub fn csr_scatter(&mut self, ent: Entity, pos: [f32; 3]) {{\n\
             \x20       let cell = self.cell_of(pos);\n\
             \x20       let slot = (self.head_tick as usize) % self.frames;\n\
             \x20       let f = &mut self.history[slot];\n\
             \x20       let cursor = self.write_cursors[cell] as usize;\n\
             \x20       let cell_end = f.cell_offsets[cell + 1] as usize;\n\
             \x20       if cursor < cell_end && cursor < f.entities.len() {{\n\
             \x20           f.entities[cursor] = ent;\n\
             \x20           f.positions[cursor] = pos;\n\
             \x20           self.write_cursors[cell] = (cursor + 1) as u32;\n\
             \x20       }}\n\
             \x20   }}\n\
             \x20   pub fn rebuild(&mut self, rows: Vec<(Entity, [f32; 3])>) {{\n\
             \x20       self.csr_begin();\n\
             \x20       for &(_, p) in &rows {{ self.csr_count(p); }}\n\
             \x20       self.csr_prefix_sum();\n\
             \x20       for (e, p) in rows {{ self.csr_scatter(e, p); }}\n\
             \x20   }}\n\
             \x20   pub fn query_disc(&self, center: [f32; 3], radius: f32) -> Vec<FfiEntity> {{\n\
             \x20       let slot = (self.head_tick as usize) % self.frames;\n\
             \x20       let f = &self.history[slot];\n\
             \x20       let r = radius.max(0.0);\n\
             \x20       let r_sq = r * r;\n\
             \x20       let cx = center[self.plane_axes[0]];\n\
             \x20       let cy = center[self.plane_axes[1]];\n\
             \x20       let (min_cx, min_cy) = self.cell_coords(cx - r, cy - r);\n\
             \x20       let (max_cx, max_cy) = self.cell_coords(cx + r, cy + r);\n\
             \x20       let total = (f.count as usize).min(f.entities.len());\n\
             \x20       let mut out = Vec::new();\n\
             \x20       for row in min_cy..=max_cy {{\n\
             \x20           for col in min_cx..=max_cx {{\n\
             \x20               let cell = row * self.cols + col;\n\
             \x20               let start = f.cell_offsets[cell] as usize;\n\
             \x20               let end = f.cell_offsets[cell + 1] as usize;\n\
             \x20               if start <= end && end <= total {{\n\
             \x20                   for k in start..end {{\n\
             \x20                       let pos = f.positions[k];\n\
             \x20                       let dx = pos[0] - center[0];\n\
             \x20                       let dy = pos[1] - center[1];\n\
             \x20                       let dz = pos[2] - center[2];\n\
             \x20                       if dx * dx + dy * dy + dz * dz <= r_sq {{\n\
             \x20                           out.push(FfiEntity::from_bits(f.entities[k].to_bits()));\n\
             \x20                           if out.len() >= 64 {{ return out; }}\n\
             \x20                       }}\n\
             \x20                   }}\n\
             \x20               }}\n\
             \x20           }}\n\
             \x20       }}\n\
             \x20       out\n\
             \x20   }}\n\
             \x20   pub fn query_segment_at(&self, tick_offset: u32, start: [f32; 3], end: [f32; 3], radius: f32) -> Vec<FfiEntity> {{\n\
             \x20       let off = (tick_offset as usize) % self.frames;\n\
             \x20       let slot = ((self.head_tick as usize) + self.frames - off) % self.frames;\n\
             \x20       let f = &self.history[slot];\n\
             \x20       let r = radius.max(0.0);\n\
             \x20       let r_sq = r * r;\n\
             \x20       let sx = start[self.plane_axes[0]];\n\
             \x20       let sy = start[self.plane_axes[1]];\n\
             \x20       let ex = end[self.plane_axes[0]];\n\
             \x20       let ey = end[self.plane_axes[1]];\n\
             \x20       let (min_cx, min_cy) = self.cell_coords(sx.min(ex) - r, sy.min(ey) - r);\n\
             \x20       let (max_cx, max_cy) = self.cell_coords(sx.max(ex) + r, sy.max(ey) + r);\n\
             \x20       let ab = [end[0] - start[0], end[1] - start[1], end[2] - start[2]];\n\
             \x20       let ab_sq = ab[0] * ab[0] + ab[1] * ab[1] + ab[2] * ab[2];\n\
             \x20       let total = (f.count as usize).min(f.entities.len());\n\
             \x20       let mut out = Vec::new();\n\
             \x20       for row in min_cy..=max_cy {{\n\
             \x20           for col in min_cx..=max_cx {{\n\
             \x20               let cell = row * self.cols + col;\n\
             \x20               let s_idx = f.cell_offsets[cell] as usize;\n\
             \x20               let e_idx = f.cell_offsets[cell + 1] as usize;\n\
             \x20               if s_idx <= e_idx && e_idx <= total {{\n\
             \x20                   for k in s_idx..e_idx {{\n\
             \x20                       let pos = f.positions[k];\n\
             \x20                       let ap = [pos[0] - start[0], pos[1] - start[1], pos[2] - start[2]];\n\
             \x20                       let t = if ab_sq > 1e-12 {{ ((ap[0]*ab[0] + ap[1]*ab[1] + ap[2]*ab[2]) / ab_sq).clamp(0.0, 1.0) }} else {{ 0.0 }};\n\
             \x20                       let dx = start[0] + ab[0] * t - pos[0];\n\
             \x20                       let dy = start[1] + ab[1] * t - pos[1];\n\
             \x20                       let dz = start[2] + ab[2] * t - pos[2];\n\
             \x20                       if dx * dx + dy * dy + dz * dz <= r_sq {{\n\
             \x20                           out.push(FfiEntity::from_bits(f.entities[k].to_bits()));\n\
             \x20                           if out.len() >= 64 {{ return out; }}\n\
             \x20                       }}\n\
             \x20                   }}\n\
             \x20               }}\n\
             \x20           }}\n\
             \x20       }}\n\
             \x20       out\n\
             \x20   }}\n\
             }}\n",
            format_f32_lit(f64::from(cell_size)),
            format_f32_lit(f64::from(inv_cell_size)),
            format_f32_lit(f64::from(bmin_x)),
            format_f32_lit(f64::from(bmin_y)),
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

pub(super) fn emit_tables_and_curves(out: &mut String, ctx: &NativeCtx<'_>) {
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

pub(super) fn rust_ty_from_hir_ty(ty: &Ty, ctx: &NativeCtx<'_>) -> String {
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
        Ty::Mat3 => "[f32; 9]".to_owned(),
        Ty::Mat4 => "[f32; 16]".to_owned(),
        Ty::Array { elem, len } => format!("[{}; {len}]", rust_ty_from_hir_ty(elem, ctx)),
        Ty::BitSet(bits) => format!("[u32; {}]", (*bits).div_ceil(32).max(1)),
        Ty::InlineStr(cap) => format!("[u32; {}]", 1 + cap.div_ceil(4)),
        Ty::Ref(_) => "FfiEntity".to_owned(),
        Ty::Asset(_) => "FfiAssetHandle".to_owned(),
        Ty::Named(n) => {
            let short = n.rsplit("::").next().unwrap_or(n);
            if let Some(en) = ctx
                .enums_by_key
                .get(n.as_str())
                .or_else(|| ctx.enums_by_key.get(short))
            {
                en.rust_repr().to_owned()
            } else if let Some(entry) = ctx.find_layout_entry(n) {
                entry.struct_name.clone()
            } else {
                "u32".to_owned()
            }
        }
        _ => "u32".to_owned(),
    }
}

pub(super) fn rust_default_expr_from_hir_ty(ty: &Ty, ctx: &NativeCtx<'_>) -> String {
    match ty {
        Ty::Bool => "false".to_owned(),
        Ty::U8 => "0u8".to_owned(),
        Ty::I8 => "0i8".to_owned(),
        Ty::U16 => "0u16".to_owned(),
        Ty::I16 => "0i16".to_owned(),
        Ty::U32 | Ty::Sym | Ty::Rgba8 => "0u32".to_owned(),
        Ty::I32 => "0i32".to_owned(),
        Ty::U64 => "0u64".to_owned(),
        Ty::I64 => "0i64".to_owned(),
        Ty::Fix32 => "Fixed32(0i32)".to_owned(),
        Ty::Fix64 => "Fixed64(0i64)".to_owned(),
        Ty::F32 | Ty::UnitScalar { .. } | Ty::GraceWindow => "0.0_f32".to_owned(),
        Ty::F64 => "0.0_f64".to_owned(),
        Ty::Vec2 => "[0.0_f32; 2]".to_owned(),
        Ty::Vec3 => "[0.0_f32; 3]".to_owned(),
        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => "[0.0_f32; 4]".to_owned(),
        Ty::IVec2 => "[0i32; 2]".to_owned(),
        Ty::IVec3 => "[0i32; 3]".to_owned(),
        Ty::UVec2 => "[0u32; 2]".to_owned(),
        Ty::Mat3 => "[0.0_f32; 9]".to_owned(),
        Ty::Mat4 => "[0.0_f32; 16]".to_owned(),
        Ty::Array { elem, len } => {
            format!("[{}; {len}]", rust_default_expr_from_hir_ty(elem, ctx))
        }
        Ty::Ref(_) => "FfiEntity::NULL".to_owned(),
        Ty::Asset(_) => "FfiAssetHandle::NONE".to_owned(),
        Ty::BitSet(bits) => format!("[0u32; {}]", (*bits).div_ceil(32).max(1)),
        Ty::InlineStr(cap) => format!("[0u32; {}]", 1 + cap.div_ceil(4)),
        Ty::Named(n) => {
            let short = n.rsplit("::").next().unwrap_or(n);
            if ctx.enums_by_key.contains_key(n.as_str()) || ctx.enums_by_key.contains_key(short) {
                let rty = rust_ty_from_hir_ty(ty, ctx);
                format!("0 as {rty}")
            } else if let Some(entry) = ctx.find_layout_entry(n) {
                format!("{}::strata_default()", entry.struct_name)
            } else {
                "Default::default()".to_owned()
            }
        }
        _ => "Default::default()".to_owned(),
    }
}

// =========================================================================
// Networking Protocol, Codecs, Handshake & Synthesized TX/RX (Bevy Native)
// =========================================================================

pub(super) fn emit_net_protocol_and_codecs(
    out: &mut String,
    ctx: &NativeCtx<'_>,
) -> Result<(), CodegenError> {
    let mir = ctx.mir;
    let mod_fp = mir.net_handshake.module_net_fingerprint;
    writeln!(
        out,
        "pub const STRATA_NET_MODULE_FINGERPRINT: u64 = 0x{mod_fp:016X};\n\
         pub const STRATA_NET_PACKET_SCHEMA_FINGERPRINT: u64 = 0x{pkt_fp:016X};\n\
         const _: () = {{\n\
         \x20   assert!(<StrataNetPacket as ModComponent>::SCHEMA_FINGERPRINT == STRATA_NET_PACKET_SCHEMA_FINGERPRINT);\n\
         }};\n\n\
         pub fn strata_net_verify_handshake(pkt: &StrataNetPacket, expected_item_fp: u64) -> bool {{\n\
         \x20   pkt.magic == STRATA_NET_PACKET_MAGIC\n\
         \x20       && pkt.version == STRATA_NET_WIRE_VERSION\n\
         \x20       && pkt.module_net_fingerprint == STRATA_NET_MODULE_FINGERPRINT\n\
         \x20       && pkt.module_net_fingerprint != 0\n\
         \x20       && pkt.item_schema_fingerprint == expected_item_fp\n\
         \x20       && expected_item_fp != 0\n\
         \x20       && (pkt.payload_bytes as usize) <= STRATA_NET_MAX_PAYLOAD_BYTES\n\
         }}\n",
        pkt_fp = STRATA_NET_PACKET_SCHEMA_FINGERPRINT,
    )
    .ok();

    for rpc in &mir.rpcs {
        emit_native_rpc_struct_and_codec(out, mir, rpc)?;
    }
    for nc in &mir.net_components {
        if nc.is_replicated || !nc.quantize_specs.is_empty() {
            let Some(entry) = ctx.find_layout_entry(&nc.canonical_name) else {
                return Err(CodegenError::Unsupported {
                    context: format!("bevy_native::net_component({})", nc.canonical_name),
                    detail: "missing solved layout for network component".to_owned(),
                });
            };
            emit_native_net_component_codec(out, mir, nc, &entry.struct_name, entry.layout)?;
        }
    }
    Ok(())
}

pub(super) fn emit_native_net_component_codec(
    out: &mut String,
    mir: &MirModule,
    nc: &MirNetComponent,
    struct_name: &str,
    layout: &SolvedLayout,
) -> Result<(), CodegenError> {
    let ident = sanitize_ident(&nc.name);
    let fp = nc.schema_fingerprint;
    let target_id = fnv1a_64_str(&nc.canonical_name);
    let kind_expr = if nc.is_resource {
        "PACKET_KIND_RESOURCE_DELTA"
    } else {
        "PACKET_KIND_COMPONENT_DELTA"
    };
    let mut flags_parts = Vec::new();
    if matches!(nc.reliability, strata_sema::hir::NetReliability::Reliable) {
        flags_parts.push("FLAG_IS_RELIABLE");
    }
    if nc.is_predicted || nc.authority == strata_sema::hir::AuthorityKind::Predicted {
        flags_parts.push("FLAG_IS_PREDICTED");
    }
    if nc.is_resource {
        flags_parts.push("FLAG_IS_RESOURCE");
    }
    let flags_expr = if flags_parts.is_empty() {
        "0".to_owned()
    } else {
        flags_parts.join(" | ")
    };

    writeln!(
        out,
        "pub fn strata_net_encode_{ident}(src: &{struct_name}, entity_bits: u64, tick_or_seq: u32, client_id: u8) -> StrataNetPacket {{\n\
         \x20   let mut pkt = StrataNetPacket::default();\n\
         \x20   pkt.module_net_fingerprint = STRATA_NET_MODULE_FINGERPRINT;\n\
         \x20   pkt.item_schema_fingerprint = 0x{fp:016X};\n\
         \x20   pkt.target_id = 0x{target_id:016X};\n\
         \x20   pkt.entity_bits = entity_bits;\n\
         \x20   pkt.tick_or_seq = tick_or_seq;\n\
         \x20   pkt.payload_bits = {pbits};\n\
         \x20   pkt.flags = {flags_expr};\n\
         \x20   pkt.kind = {kind_expr};\n\
         \x20   pkt.channel = {ch};\n\
         \x20   pkt.payload_bytes = {pbytes};\n\
         \x20   pkt.client_id = client_id;",
        pbits = nc.packed_bits,
        ch = nc.channel,
        pbytes = nc.packed_bytes,
    )
    .ok();
    for wf in &nc.wire_fields {
        let Some(sf) = layout.fields.iter().find(|f| f.name == wf.field_name) else {
            return Err(CodegenError::Unsupported {
                context: format!("bevy_native::net_component({})", nc.canonical_name),
                detail: format!(
                    "wire field `{}` missing from solved layout `{}`",
                    wf.field_name, layout.canonical_name
                ),
            });
        };
        let fname = sanitize_rust_ident(&wf.field_name);
        let rty = rust_abi_type_for_field(sf, mir);
        emit_rust_wire_field_encode(out, wf, &fname, &rty, "src")?;
    }
    writeln!(out, "    pkt\n}}\n").ok();

    let len_check = if nc.packed_bytes > 0 {
        format!(" || pkt.payload_bytes < {}", nc.packed_bytes)
    } else {
        String::new()
    };
    writeln!(
        out,
        "pub fn strata_net_decode_{ident}(pkt: &StrataNetPacket, out_val: &mut {struct_name}) -> bool {{\n\
         \x20   if !strata_net_verify_handshake(pkt, 0x{fp:016X}) || pkt.item_schema_fingerprint != 0x{fp:016X} {{\n\
         \x20       return false;\n\
         \x20   }}\n\
         \x20   if pkt.target_id != 0x{target_id:016X} || pkt.kind != {kind_expr}{len_check} {{\n\
         \x20       return false;\n\
         \x20   }}",
    )
    .ok();
    for wf in &nc.wire_fields {
        let Some(sf) = layout.fields.iter().find(|f| f.name == wf.field_name) else {
            return Err(CodegenError::Unsupported {
                context: format!("bevy_native::net_component({})", nc.canonical_name),
                detail: format!(
                    "wire field `{}` missing from solved layout `{}`",
                    wf.field_name, layout.canonical_name
                ),
            });
        };
        let fname = sanitize_rust_ident(&wf.field_name);
        let rty = rust_abi_type_for_field(sf, mir);
        emit_rust_wire_field_decode(out, wf, &fname, &rty, "out_val")?;
    }
    writeln!(out, "    true\n}}\n").ok();
    Ok(())
}

pub(super) fn emit_native_rpc_struct_and_codec(
    out: &mut String,
    mir: &MirModule,
    rpc: &MirRpc,
) -> Result<(), CodegenError> {
    let ident = sanitize_ident(&rpc.name);
    let rty = format!("StrataRpc_{ident}");
    if rpc.fields.is_empty() {
        writeln!(
            out,
            "#[repr(C)]\n#[derive(Clone, Copy, Debug, Default, PartialEq)]\npub struct {rty};\n"
        )
        .ok();
    } else {
        writeln!(
            out,
            "#[repr(C)]\n#[derive(Clone, Copy, Debug, Default, PartialEq)]\npub struct {rty} {{"
        )
        .ok();
        for (fname, mty, _, sz) in &rpc.fields {
            let rf = sanitize_rust_ident(fname);
            let rt = rust_abi_type_for_mir_ty(mty, *sz, mir);
            writeln!(out, "    pub {rf}: {rt},").ok();
        }
        writeln!(out, "}}\n").ok();
    }

    let fp = rpc.schema_fingerprint;
    let rpc_id = rpc.rpc_id;
    let mut flags_parts = vec!["FLAG_IS_RPC"];
    if matches!(rpc.reliability, strata_sema::hir::NetReliability::Reliable) {
        flags_parts.push("FLAG_IS_RELIABLE");
    }
    let flags_expr = flags_parts.join(" | ");

    writeln!(
        out,
        "pub fn strata_net_encode_rpc_{ident}(rpc: &{rty}, tick_or_seq: u32, client_id: u8) -> StrataNetPacket {{\n\
         \x20   let mut pkt = StrataNetPacket::default();\n\
         \x20   pkt.module_net_fingerprint = STRATA_NET_MODULE_FINGERPRINT;\n\
         \x20   pkt.item_schema_fingerprint = 0x{fp:016X};\n\
         \x20   pkt.target_id = 0x{rpc_id:016X};\n\
         \x20   pkt.entity_bits = 0;\n\
         \x20   pkt.tick_or_seq = tick_or_seq;\n\
         \x20   pkt.payload_bits = {pbits};\n\
         \x20   pkt.flags = {flags_expr};\n\
         \x20   pkt.kind = PACKET_KIND_RPC;\n\
         \x20   pkt.channel = {ch};\n\
         \x20   pkt.payload_bytes = {pbytes};\n\
         \x20   pkt.client_id = client_id;",
        pbits = rpc.packed_bits,
        ch = rpc.channel,
        pbytes = rpc.packed_bytes,
    )
    .ok();
    for wf in &rpc.wire_fields {
        let Some((_, mty, _, sz)) = rpc.fields.iter().find(|(n, _, _, _)| n == &wf.field_name)
        else {
            return Err(CodegenError::Unsupported {
                context: format!("bevy_native::rpc({})", rpc.canonical_name),
                detail: format!("wire field `{}` missing from RPC payload", wf.field_name),
            });
        };
        let rf = sanitize_rust_ident(&wf.field_name);
        let rt = rust_abi_type_for_mir_ty(mty, *sz, mir);
        emit_rust_wire_field_encode(out, wf, &rf, &rt, "rpc")?;
    }
    writeln!(out, "    pkt\n}}\n").ok();

    let len_check = if rpc.packed_bytes > 0 {
        format!(" || pkt.payload_bytes < {}", rpc.packed_bytes)
    } else {
        String::new()
    };
    writeln!(
        out,
        "pub fn strata_net_decode_rpc_{ident}(pkt: &StrataNetPacket, out_rpc: &mut {rty}) -> bool {{\n\
         \x20   if !strata_net_verify_handshake(pkt, 0x{fp:016X}) || pkt.item_schema_fingerprint != 0x{fp:016X} {{\n\
         \x20       return false;\n\
         \x20   }}\n\
         \x20   if pkt.target_id != 0x{rpc_id:016X} || pkt.kind != PACKET_KIND_RPC{len_check} {{\n\
         \x20       return false;\n\
         \x20   }}",
    )
    .ok();
    for wf in &rpc.wire_fields {
        let Some((_, mty, _, sz)) = rpc.fields.iter().find(|(n, _, _, _)| n == &wf.field_name)
        else {
            return Err(CodegenError::Unsupported {
                context: format!("bevy_native::rpc({})", rpc.canonical_name),
                detail: format!("wire field `{}` missing from RPC payload", wf.field_name),
            });
        };
        let rf = sanitize_rust_ident(&wf.field_name);
        let rt = rust_abi_type_for_mir_ty(mty, *sz, mir);
        emit_rust_wire_field_decode(out, wf, &rf, &rt, "out_rpc")?;
    }
    writeln!(out, "    true\n}}\n").ok();
    Ok(())
}

pub(super) fn emit_net_synthesized_systems(out: &mut String, ctx: &NativeCtx<'_>) {
    let rep_comps: Vec<&MirNetComponent> = ctx
        .mir
        .net_components
        .iter()
        .filter(|nc| nc.is_replicated)
        .collect();
    if rep_comps.is_empty() {
        return;
    }

    // RX system
    let mut rx_params = vec!["mut mr_net: MessageReader<StrataNetPacket>".to_owned()];
    let mut tx_params = vec!["mut mw_net: MessageWriter<StrataNetPacket>".to_owned()];
    for (idx, nc) in rep_comps.iter().enumerate() {
        let Some(entry) = ctx.find_layout_entry(&nc.canonical_name) else {
            continue;
        };
        let sname = &entry.struct_name;
        if nc.is_resource {
            rx_params.push(format!("mut net_res_{idx}: ResMut<{sname}>"));
            tx_params.push(format!("net_res_{idx}: Res<{sname}>"));
        } else {
            rx_params.push(format!(
                "mut net_q_{idx}: Query<(Entity, &'static mut {sname})>"
            ));
            tx_params.push(format!(
                "net_q_{idx}: Query<(Entity, &'static {sname}), Changed<{sname}>>"
            ));
        }
    }

    writeln!(out, "fn strata_sys_net_rx({}) {{", rx_params.join(", ")).ok();
    writeln!(
        out,
        "    let pkts: Vec<StrataNetPacket> = mr_net.read().copied().collect();\n\
         \x20   if pkts.is_empty() {{ return; }}"
    )
    .ok();
    for (idx, nc) in rep_comps.iter().enumerate() {
        let Some(entry) = ctx.find_layout_entry(&nc.canonical_name) else {
            continue;
        };
        let ident = sanitize_ident(&nc.name);
        let target_id = fnv1a_64_str(&nc.canonical_name);
        if nc.is_resource {
            writeln!(
                out,
                "    if let Some(last_pkt) = pkts.iter().rev().find(|p| p.kind == PACKET_KIND_RESOURCE_DELTA && p.target_id == 0x{target_id:016X}) {{\n\
                 \x20       let mut decoded = *net_res_{idx};\n\
                 \x20       if strata_net_decode_{ident}(last_pkt, &mut decoded) && decoded != *net_res_{idx} {{\n\
                 \x20           *net_res_{idx} = decoded;\n\
                 \x20       }}\n\
                 \x20   }}"
            )
            .ok();
        } else {
            let is_sparse =
                (entry.layout.component_flags & bamabi_sys::BAM_COMPONENT_FLAG_SPARSE_SET) != 0;
            writeln!(
                out,
                "    if pkts.iter().any(|p| p.kind == PACKET_KIND_COMPONENT_DELTA && p.target_id == 0x{target_id:016X}) {{"
            )
            .ok();
            if is_sparse {
                writeln!(
                    out,
                    "        for (ent, mut comp_mut) in net_q_{idx}.iter_mut() {{\n\
                     \x20           let ebits = ent.to_bits();\n\
                     \x20           if let Some(pkt) = pkts.iter().rev().find(|p| p.kind == PACKET_KIND_COMPONENT_DELTA && p.target_id == 0x{target_id:016X} && p.entity_bits == ebits) {{\n\
                     \x20               let mut decoded = *comp_mut;\n\
                     \x20               if strata_net_decode_{ident}(pkt, &mut decoded) && decoded != *comp_mut {{\n\
                     \x20                   *comp_mut = decoded;\n\
                     \x20               }}\n\
                     \x20           }}\n\
                     \x20       }}"
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "        if let Ok(chunks) = net_q_{idx}.strata_contiguous_iter_mut() {{\n\
                     \x20           for (entities, raw_col) in chunks {{\n\
                     \x20               let mut sel = SelectiveMutSlice::from_contiguous_mut(raw_col);\n\
                     \x20               let len = entities.len().min(sel.len());\n\
                     \x20               for row in 0..len {{\n\
                     \x20                   let ebits = entities[row].to_bits();\n\
                     \x20                   if let Some(pkt) = pkts.iter().rev().find(|p| p.kind == PACKET_KIND_COMPONENT_DELTA && p.target_id == 0x{target_id:016X} && p.entity_bits == ebits) {{\n\
                     \x20                       sel.update_if(row, |cur| {{\n\
                     \x20                           let mut decoded = *cur;\n\
                     \x20                           if strata_net_decode_{ident}(pkt, &mut decoded) && decoded != *cur {{\n\
                     \x20                               *cur = decoded;\n\
                     \x20                               true\n\
                     \x20                           }} else {{\n\
                     \x20                               false\n\
                     \x20                           }}\n\
                     \x20                       }});\n\
                     \x20                   }}\n\
                     \x20               }}\n\
                     \x20           }}\n\
                     \x20       }}"
                )
                .ok();
            }
            writeln!(out, "    }}").ok();
        }
    }
    writeln!(out, "}}\n").ok();

    // TX system
    writeln!(out, "fn strata_sys_net_tx({}) {{", tx_params.join(", ")).ok();
    writeln!(
        out,
        "    let mut out_pkts: Vec<StrataNetPacket> = Vec::new();"
    )
    .ok();
    for (idx, nc) in rep_comps.iter().enumerate() {
        if ctx.find_layout_entry(&nc.canonical_name).is_none() {
            continue;
        }
        let ident = sanitize_ident(&nc.name);
        if nc.is_resource {
            writeln!(
                out,
                "    if net_res_{idx}.is_changed() {{\n\
                 \x20       out_pkts.push(strata_net_encode_{ident}(&net_res_{idx}, 0, 0, 0));\n\
                 \x20   }}"
            )
            .ok();
        } else {
            writeln!(
                out,
                "    for (ent, val) in net_q_{idx}.iter() {{\n\
                 \x20       out_pkts.push(strata_net_encode_{ident}(val, ent.to_bits(), 0, 0));\n\
                 \x20   }}"
            )
            .ok();
        }
    }
    writeln!(
        out,
        "    if !out_pkts.is_empty() {{\n\
         \x20       mw_net.write_batch(out_pkts);\n\
         \x20   }}\n\
         }}\n"
    )
    .ok();
}

// =========================================================================
// MIR Function Analysis, Type Inference & Complete SSA CFG Lowering
// =========================================================================

pub(super) fn emit_named_object_initializer(out: &mut String, ctx: &NativeCtx<'_>) {
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
        let mut covered: HashSet<String> = HashSet::new();
        for init in &obj.inits {
            let key = init
                .canonical_component
                .as_deref()
                .unwrap_or(&init.component);
            if let Some(entry) = ctx.find_layout_entry(key) {
                covered.insert(entry.layout.canonical_name.clone());
                covered.insert(entry.struct_name.clone());
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
                covered.insert(key.to_owned());
                covered.insert(sname.clone());
                bundle_items.push(sname);
            }
        }
        for c in &obj.components {
            let canon = ctx
                .find_layout_entry(c)
                .map_or_else(|| c.as_str(), |e| e.layout.canonical_name.as_str());
            if let Some(sname) = ctx.resolve_ecs_struct_name(c) {
                if covered.contains(c) || covered.contains(canon) || covered.contains(&sname) {
                    continue;
                }
                covered.insert(canon.to_owned());
                covered.insert(sname.clone());
                if ctx.is_zst_component(c) {
                    bundle_items.push(sname);
                } else {
                    bundle_items.push(format!("{sname}::default()"));
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

pub(super) fn emit_run_if_condition(
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

pub(super) fn collect_run_if_resources(
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

pub(super) fn render_run_if_expr(
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

pub(super) fn schedule_label_ident(label: &str) -> &'static str {
    match label {
        "Startup" => "Startup",
        "PreUpdate" => "PreUpdate",
        "Update" => "Update",
        "PostUpdate" => "PostUpdate",
        "Last" => "Last",
        _ => "FixedUpdate",
    }
}

pub(super) fn collect_schedule_sets(nodes: &[HirScheduleGroup], out: &mut Vec<String>) {
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

pub(super) fn emit_native_plugin(out: &mut String, ctx: &NativeCtx<'_>) {
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

    let has_rep_net = has_net_protocol(mir) && mir.net_components.iter().any(|nc| nc.is_replicated);
    if has_rep_net {
        leaf_set_names.push("StrataLeafSet_strata_net_rx".to_owned());
        leaf_set_names.push("StrataLeafSet_strata_net_tx".to_owned());
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
    if has_net_protocol(mir) {
        writeln!(
            out,
            "        app.register_strata_net_transport().expect(\"valid strata net transport registration\");"
        )
        .ok();
    }

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

    // Ensure synthesized spatial CSR rebuild systems run before systems that read that specific
    // spatial index on the same schedule (avoiding schedule cycles with unrelated `seq` steps).
    for csr_fn in mir
        .functions
        .iter()
        .filter(|f| f.kind == MirFnKind::SynthesizedSpatialCsr)
    {
        let csr_set = format!("StrataLeafSet_{}", sanitize_ident(&csr_fn.name));
        let csr_sched = schedule_label_ident(crate::system_schedule_label(mir, &csr_fn.name));
        let index_name = csr_fn
            .blocks
            .iter()
            .flat_map(|bb| bb.stmts.iter())
            .find_map(|st| match &st.inst {
                Inst::SpatialRebuildCsr { index_name, .. }
                | Inst::SpatialCsrBegin { index_name } => Some(index_name.clone()),
                _ => None,
            })
            .unwrap_or_else(|| {
                csr_fn
                    .name
                    .strip_suffix("__rebuild_csr")
                    .unwrap_or(&csr_fn.name)
                    .to_owned()
            });
        for func in &mir.functions {
            if matches!(
                func.kind,
                MirFnKind::System
                    | MirFnKind::SynthesizedTimeline
                    | MirFnKind::SynthesizedTask
                    | MirFnKind::SynthesizedFsm
            ) {
                let user_sched =
                    schedule_label_ident(crate::system_schedule_label(mir, &func.name));
                if user_sched != csr_sched {
                    continue;
                }
                let uses_this_index = func.resources.iter().any(|r| {
                    r.resource_name == index_name
                        || r.canonical_name == index_name
                        || resolve_spatial_name(ctx, func, &r.resource_name) == index_name
                }) || func.blocks.iter().any(|bb| {
                    bb.stmts.iter().any(|st| match &st.inst {
                        Inst::ResRead { resource } | Inst::ResWrite { resource } => {
                            resolve_spatial_name(ctx, func, resource) == index_name
                        }
                        Inst::SpatialQueryDisc { grid_name, .. } => {
                            resolve_spatial_name(ctx, func, grid_name) == index_name
                        }
                        Inst::SpatialQuerySegmentAt { history_name, .. } => {
                            resolve_spatial_name(ctx, func, history_name) == index_name
                        }
                        _ => false,
                    })
                });
                if uses_this_index {
                    let user_set = format!("StrataLeafSet_{}", sanitize_ident(&func.name));
                    writeln!(
                        out,
                        "        app.configure_sets({csr_sched}, {csr_set}.before({user_set}));"
                    )
                    .ok();
                }
            }
        }
    }

    if has_rep_net {
        writeln!(
            out,
            "        app.add_systems(FixedUpdate, strata_sys_net_rx.in_set(StrataLeafSet_strata_net_rx));\n\
             \x20       app.add_systems(FixedUpdate, strata_sys_net_tx.in_set(StrataLeafSet_strata_net_tx));\n\
             \x20       app.configure_sets(FixedUpdate, StrataLeafSet_strata_net_rx.before(StrataLeafSet_strata_net_tx));"
        )
        .ok();
        if has_timer_tick {
            writeln!(
                out,
                "        app.configure_sets(FixedUpdate, StrataLeafSet_strata_net_rx.before({timer_set}));\n\
                 \x20       app.configure_sets(FixedUpdate, StrataLeafSet_strata_net_tx.after({timer_set}));"
            )
            .ok();
        }
        for (si, sched) in mir.schedules.iter().enumerate() {
            if schedule_label_ident(&sched.label) == "FixedUpdate" {
                let root_set = format!("StrataSchedRoot_{si}_{}", sanitize_ident(&sched.label));
                writeln!(
                    out,
                    "        app.configure_sets(FixedUpdate, StrataLeafSet_strata_net_rx.before({root_set}));\n\
                     \x20       app.configure_sets(FixedUpdate, StrataLeafSet_strata_net_tx.after({root_set}));"
                )
                .ok();
            }
        }
        for func in &mir.functions {
            if !matches!(
                func.kind,
                MirFnKind::Observer { .. } | MirFnKind::Migration { .. }
            ) {
                let user_set = format!("StrataLeafSet_{}", sanitize_ident(&func.name));
                writeln!(
                    out,
                    "        app.configure_sets(FixedUpdate, StrataLeafSet_strata_net_rx.before({user_set}));\n\
                     \x20       app.configure_sets(FixedUpdate, StrataLeafSet_strata_net_tx.after({user_set}));"
                )
                .ok();
            }
        }
    }

    writeln!(out, "    }}").ok();
    writeln!(out, "}}").ok();
}

pub(super) fn collect_first_sets(nodes: &[HirScheduleGroup], out: &mut Vec<String>) {
    for n in nodes {
        if n.kind == "leaf" {
            out.push(format!("StrataLeafSet_{}", sanitize_ident(&n.name)));
        } else {
            out.push(format!("StrataSet_{}", sanitize_ident(&n.name)));
        }
    }
}

pub(super) fn group_set_name(node: &HirScheduleGroup) -> String {
    if node.kind == "leaf" {
        format!("StrataLeafSet_{}", sanitize_ident(&node.name))
    } else {
        format!("StrataSet_{}", sanitize_ident(&node.name))
    }
}

pub(super) fn emit_schedule_nodes(
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
