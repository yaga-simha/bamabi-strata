//! C99 enum, layout, default, rodata, state struct, startup object, and manifest emission.

use super::*;

impl<'a> EmitCtx<'a> {
    pub(super) fn emit_enums(&mut self) {
        for e in &self.mir.enums {
            let short = short_name(&e.canonical_name);
            let enum_ident = sanitize_ident(short);
            let _ = writeln!(self.out, "/* Enum {} */", e.canonical_name);
            for (v_name, disc) in &e.variants {
                let v_ident = sanitize_ident(v_name);
                let val_lit = match (e.repr_bytes, e.is_signed) {
                    (1, _) => format!("((uint8_t){}u)", *disc as u8),
                    (2, _) => format!("((uint16_t){}u)", *disc as u16),
                    (_, true) => c_i32_lit(*disc as i32),
                    _ => format!("((uint32_t){}u)", *disc as u32),
                };
                let _ = writeln!(
                    self.out,
                    "#define STRATA_ENUM_{enum_ident}_{v_ident} {val_lit}"
                );
            }
            self.out.push('\n');
        }
    }

    pub(super) fn emit_layouts(&mut self) -> Result<(), CodegenError> {
        for (idx, layout) in self.layouts.iter().enumerate() {
            let cname = &self.layout_c_names[idx];
            if layout.size == 0 {
                let _ = writeln!(
                    self.out,
                    "typedef struct {cname} {{\n    uint8_t _zst_pad;\n}} {cname};"
                );
                let _ = writeln!(
                    self.out,
                    "BAM_STATIC_ASSERT(sizeof({cname}) == 1u, {cname}_zst_size);\n"
                );
                continue;
            }
            let _ = writeln!(self.out, "typedef struct {cname} {{");
            let mut cursor: usize = 0;
            let mut pad_idx: usize = 0;
            for f in &layout.fields {
                if f.offset > cursor {
                    let gap = f.offset - cursor;
                    let _ = writeln!(self.out, "    uint8_t _pad_{pad_idx}[{gap}];");
                    pad_idx += 1;
                }
                let f_c = sanitize_c_field(&f.name);
                let f_decl = self.c_field_decl(&f.ty, f.size, &f_c);
                let _ = writeln!(self.out, "    {f_decl};");
                cursor = f.offset.saturating_add(f.size);
            }
            if layout.size > cursor {
                let tail = layout.size - cursor;
                let _ = writeln!(self.out, "    uint8_t _pad_tail[{tail}];");
            }
            let _ = writeln!(self.out, "}} {cname};");
            let _ = writeln!(
                self.out,
                "BAM_STATIC_ASSERT(sizeof({cname}) == {}u, {cname}_size);",
                layout.size
            );
            for f in &layout.fields {
                if f.is_padding {
                    continue;
                }
                let f_c = sanitize_c_field(&f.name);
                let _ = writeln!(
                    self.out,
                    "BAM_STATIC_ASSERT(offsetof({cname}, {f_c}) == {}u, {cname}_off_{f_c});",
                    f.offset
                );
            }
            self.out.push('\n');
        }
        Ok(())
    }

    pub(super) fn c_field_decl(&self, ty: &Ty, byte_size: usize, field_name: &str) -> String {
        match ty {
            Ty::Bool | Ty::U8 => format!("uint8_t {field_name}"),
            Ty::I8 => format!("int8_t {field_name}"),
            Ty::I16 => format!("int16_t {field_name}"),
            Ty::I32 | Ty::Fix32 => format!("int32_t {field_name}"),
            Ty::I64 | Ty::Fix64 => format!("int64_t {field_name}"),
            Ty::U16 => format!("uint16_t {field_name}"),
            Ty::U32 | Ty::Sym | Ty::Rgba8 => format!("uint32_t {field_name}"),
            Ty::U64 => format!("uint64_t {field_name}"),
            Ty::F32 | Ty::UnitScalar { .. } => {
                if byte_size == 8 {
                    format!("double {field_name}")
                } else {
                    format!("float {field_name}")
                }
            }
            Ty::F64 => format!("double {field_name}"),
            Ty::Ref(_) => {
                if byte_size == 8 {
                    format!("BamEntity {field_name}")
                } else {
                    format!("uint8_t {field_name}[{}]", byte_size.max(1))
                }
            }
            Ty::Vec2 => format!("StrataVec2 {field_name}"),
            Ty::Vec3 => format!("StrataVec3 {field_name}"),
            Ty::Vec3a => {
                if byte_size == 12 {
                    format!("StrataVec3 {field_name}")
                } else {
                    format!("StrataVec4 {field_name}")
                }
            }
            Ty::Vec4 | Ty::Quat | Ty::Rgba => format!("StrataVec4 {field_name}"),
            Ty::IVec2 => format!("StrataIVec2 {field_name}"),
            Ty::IVec3 => format!("StrataIVec3 {field_name}"),
            Ty::UVec2 => format!("StrataUVec2 {field_name}"),
            Ty::Mat3 => format!("StrataMat3 {field_name}"),
            Ty::Mat4 => format!("StrataMat4 {field_name}"),
            Ty::Named(key) => {
                if let Some(l_idx) = self.find_layout_idx(key)
                    && self.layouts[l_idx].size == byte_size
                {
                    format!("{} {field_name}", self.layout_c_names[l_idx])
                } else if byte_size == 4 {
                    format!("int32_t {field_name}")
                } else if byte_size == 1 {
                    format!("uint8_t {field_name}")
                } else if byte_size == 2 {
                    format!("uint16_t {field_name}")
                } else if byte_size == 8 {
                    format!("int64_t {field_name}")
                } else {
                    format!("uint8_t {field_name}[{}]", byte_size.max(1))
                }
            }
            _ => format!("uint8_t {field_name}[{}]", byte_size.max(1)),
        }
    }

    pub(super) fn emit_composite_typedefs(&mut self) {
        let order = self.composite_order.clone();
        for decl in order {
            match decl {
                CompositeDecl::Tuple(id) => {
                    let (elems, name) = self.tuple_types[id].clone();
                    let _ = writeln!(self.out, "typedef struct {name} {{");
                    if elems.is_empty() {
                        let _ = writeln!(self.out, "    uint8_t _empty;");
                    } else {
                        for (i, e) in elems.iter().enumerate() {
                            let cty = self.c_ty(e);
                            let _ = writeln!(self.out, "    {cty} f{i};");
                        }
                    }
                    let _ = writeln!(self.out, "}} {name};\n");
                }
                CompositeDecl::Array(id) => {
                    let (elem, len, name) = self.array_types[id].clone();
                    let cty = self.c_ty(&elem);
                    let _ = writeln!(
                        self.out,
                        "typedef struct {name} {{ {cty} data[{}]; }} {name};\n",
                        len.max(1)
                    );
                }
            }
        }
    }

    pub(super) fn emit_defaults(&mut self) -> Result<(), CodegenError> {
        for idx in 0..self.layouts.len() {
            let layout = &self.layouts[idx];
            if layout.size == 0 {
                continue;
            }
            let short = short_name(&layout.canonical_name);
            let cname = &self.layout_c_names[idx];
            let def_fn = format!("strata_default_{idx}_{}", sanitize_ident(short));
            let _ = writeln!(self.out, "static BAM_UNUSED inline {cname} {def_fn}(void);");
        }
        self.out.push('\n');

        for idx in 0..self.layouts.len() {
            let layout = &self.layouts[idx];
            if layout.size == 0 {
                continue;
            }
            let short = short_name(&layout.canonical_name);
            let cname = &self.layout_c_names[idx];
            let def_fn = format!("strata_default_{idx}_{}", sanitize_ident(short));
            let defs_opt = self
                .mir
                .field_defaults
                .get(&layout.canonical_name)
                .or_else(|| self.mir.field_defaults.get(short));

            let mut body = String::new();
            let _ = writeln!(body, "static BAM_UNUSED inline {cname} {def_fn}(void) {{");
            let _ = writeln!(body, "    {cname} out;");
            let _ = writeln!(body, "    memset(&out, 0, sizeof(out));");
            for f in &layout.fields {
                if f.is_padding {
                    continue;
                }
                let fc = sanitize_c_field(&f.name);
                let val_opt = defs_opt.and_then(|defs| defs.get(&f.name));
                self.emit_c_field_default_init(
                    &mut body,
                    "    ",
                    &format!("out.{fc}"),
                    &f.ty,
                    f.size,
                    val_opt,
                    false,
                );
            }
            let _ = writeln!(body, "    return out;");
            let _ = writeln!(body, "}}\n");
            self.out.push_str(&body);
        }
        Ok(())
    }

    pub(super) fn emit_rodata_tables_and_curves(&mut self) -> Result<(), CodegenError> {
        // 1. `.rodata` tables keyed by enum discriminant.
        for t in &self.mir.tables {
            let t_ident = sanitize_ident(&t.name);
            let _ = writeln!(self.out, "/* .rodata Table {} */", t.name);
            let _ = writeln!(self.out, "typedef struct StrataTable_{t_ident} {{");
            if t.fields.is_empty() {
                let _ = writeln!(self.out, "    uint8_t _empty;");
            } else {
                for (fname, fty) in &t.fields {
                    let c_ty = self.c_ty_from_sema(fty);
                    let c_col = sanitize_c_field(fname);
                    let _ = writeln!(self.out, "    {c_ty} {c_col};");
                }
            }
            let _ = writeln!(self.out, "}} StrataTable_{t_ident};");

            let key_enum = self.mir.enums.iter().find(|e| {
                e.canonical_name == t.key_enum
                    || short_name(&e.canonical_name) == short_name(&t.key_enum)
            });
            let mut max_disc: usize = 0;
            let mut row_by_disc: BTreeMap<usize, Vec<String>> = BTreeMap::new();
            for (row_key, col_exprs) in &t.typed_rows {
                let disc = key_enum
                    .and_then(|e| {
                        e.variants
                            .iter()
                            .find(|(vn, _)| vn == row_key)
                            .map(|(_, d)| (*d).max(0) as usize)
                    })
                    .unwrap_or(row_by_disc.len());
                max_disc = max_disc.max(disc);
                let mut vals = Vec::with_capacity(t.fields.len());
                for (fname, fty) in &t.fields {
                    let v = col_exprs
                        .iter()
                        .find(|(k, _)| k == fname)
                        .map(|(_, expr)| self.c_hir_expr(expr, fty))
                        .unwrap_or_else(|| self.c_zero_for_sema(fty));
                    vals.push(v);
                }
                row_by_disc.insert(disc, vals);
            }
            let len = (max_disc + 1).max(1);
            let _ = writeln!(
                self.out,
                "static BAM_UNUSED const StrataTable_{t_ident} STRATA_TABLE_{t_ident}[{len}] = {{"
            );
            for d in 0..len {
                let comma = if d + 1 < len { "," } else { "" };
                if let Some(vals) = row_by_disc.get(&d) {
                    if vals.is_empty() {
                        let _ = writeln!(self.out, "    {{ 0u }}{comma}");
                    } else {
                        let _ = writeln!(self.out, "    {{ {} }}{comma}", vals.join(", "));
                    }
                } else if t.fields.is_empty() {
                    let _ = writeln!(self.out, "    {{ 0u }}{comma}");
                } else {
                    let zeros: Vec<String> = t
                        .fields
                        .iter()
                        .map(|(_, ty)| self.c_zero_for_sema(ty))
                        .collect();
                    let _ = writeln!(self.out, "    {{ {} }}{comma}", zeros.join(", "));
                }
            }
            let _ = writeln!(self.out, "}};");
            let _ = writeln!(
                self.out,
                "static BAM_UNUSED inline StrataTable_{t_ident} strata_table_load_{t_ident}(int32_t key) {{"
            );
            let _ = writeln!(
                self.out,
                "    size_t idx = (key >= 0 && (size_t)key < {len}u) ? (size_t)key : 0u;"
            );
            let _ = writeln!(self.out, "    return STRATA_TABLE_{t_ident}[idx];");
            let _ = writeln!(self.out, "}}\n");
        }

        // 2. `.rodata` piecewise-linear curves.
        for c in &self.mir.curves {
            let c_ident = sanitize_ident(&c.name);
            let n = c.points.len().max(1);
            let xs: Vec<String> = if c.points.is_empty() {
                vec!["0.0f".to_string()]
            } else {
                c.points.iter().map(|(x, _)| c_f32(*x as f32)).collect()
            };
            let ys: Vec<String> = if c.points.is_empty() {
                vec!["0.0f".to_string()]
            } else {
                c.points.iter().map(|(_, y)| c_f32(*y as f32)).collect()
            };
            let _ = writeln!(
                self.out,
                "static BAM_UNUSED const float STRATA_CURVE_X_{c_ident}[{n}] = {{ {} }};",
                xs.join(", ")
            );
            let _ = writeln!(
                self.out,
                "static BAM_UNUSED const float STRATA_CURVE_Y_{c_ident}[{n}] = {{ {} }};",
                ys.join(", ")
            );
            let _ = writeln!(
                self.out,
                "static BAM_UNUSED inline float strata_curve_sample_{c_ident}(float x) {{"
            );
            let _ = writeln!(
                self.out,
                "    if (x <= STRATA_CURVE_X_{c_ident}[0]) {{ return STRATA_CURVE_Y_{c_ident}[0]; }}"
            );
            let _ = writeln!(
                self.out,
                "    if (x >= STRATA_CURVE_X_{c_ident}[{}]) {{ return STRATA_CURVE_Y_{c_ident}[{}]; }}",
                n - 1,
                n - 1
            );
            if n > 1 {
                let _ = writeln!(self.out, "    for (size_t i = 0u; i + 1u < {n}u; ++i) {{");
                let _ = writeln!(self.out, "        float x0 = STRATA_CURVE_X_{c_ident}[i];");
                let _ = writeln!(
                    self.out,
                    "        float x1 = STRATA_CURVE_X_{c_ident}[i + 1u];"
                );
                let _ = writeln!(self.out, "        if (x >= x0 && x <= x1) {{");
                let _ = writeln!(self.out, "            float span = x1 - x0;");
                let _ = writeln!(
                    self.out,
                    "            float t = (span > 1e-6f) ? ((x - x0) / span) : 0.0f;"
                );
                let _ = writeln!(
                    self.out,
                    "            return STRATA_CURVE_Y_{c_ident}[i] + (STRATA_CURVE_Y_{c_ident}[i + 1u] - STRATA_CURVE_Y_{c_ident}[i]) * t;"
                );
                let _ = writeln!(self.out, "        }}");
                let _ = writeln!(self.out, "    }}");
            }
            let _ = writeln!(self.out, "    return STRATA_CURVE_Y_{c_ident}[{}];", n - 1);
            let _ = writeln!(self.out, "}}\n");
        }
        Ok(())
    }

    pub(super) fn emit_state_struct_and_forward_decls(&mut self) {
        let comp_n = self.components.len().max(1);
        let rel_n = self.relations.len().max(1);
        let obj_n = self.objects.len().max(1);
        let sys_n = self.systems.len().max(1);
        let msg_slot_n = (self.systems.len() + self.observers.len()).max(1);
        let set_n = self.sets.len().max(1);

        let mut mod_res_fields = String::new();
        for c in &self.components {
            if c.has_mod_res
                && let Some(l_idx) = c.layout_idx
            {
                let cty = &self.layout_c_names[l_idx];
                let _ = writeln!(mod_res_fields, "    {cty} mod_res_{};", c.idx);
            }
        }
        for sp in &self.mir.spatial_indices {
            let ident = sanitize_ident(&sp.name);
            let frames = sp.frames.max(1);
            let cap = sp.capacity.max(1);
            let cells = (sp.cols.max(1) * sp.rows.max(1)).max(1);
            let off_len = frames * (cells + 1);
            let ent_len = frames * cap;
            let _ = writeln!(
                mod_res_fields,
                "    StrataSpatialHeader spatial_{ident};\n\
                 \x20   uint32_t spatial_{ident}_counts[{frames}u];\n\
                 \x20   uint32_t spatial_{ident}_offsets[{off_len}u];\n\
                 \x20   uint32_t spatial_{ident}_cursors[{cells}u];\n\
                 \x20   BamEntity spatial_{ident}_entities[{ent_len}u];\n\
                 \x20   StrataVec4 spatial_{ident}_positions[{ent_len}u];"
            );
        }
        let net_fields = if has_net_protocol(self.mir) {
            "    BamComponent net_pkt_comp;\n    uint8_t net_pkt_is_msg;\n    StrataNetPacket* net_rx_buf;\n"
        } else {
            ""
        };

        let _ = writeln!(
            self.out,
            "\
typedef struct StrataModState {{
    const BamHostApi* api;
    const BamHostCtx* host_ctx;
    BamComponent components[{comp_n}u];
    uint8_t res_flags[{comp_n}u];
    uint32_t sys_msg_q[{msg_slot_n}u];
    uint32_t sys_msg_ti[{msg_slot_n}u * {comp_n}u];
{net_fields}    BamComponent relations[{rel_n}u];
    BamEntity named_objects[{obj_n}u];
    BamSystem systems[{sys_n}u];
    BamSystemSet sets[{set_n}u];
    BamBool objects_initialized;
{mod_res_fields}}} StrataModState;\n"
        );

        let fns_snapshot: Vec<MirFunction> = self.mir_functions().to_vec();
        for f in &fns_snapshot {
            match &f.kind {
                MirFnKind::HelperFn => {
                    let sig = self.helper_sig(f);
                    let _ = writeln!(self.out, "{sig};");
                }
                MirFnKind::System
                | MirFnKind::SynthesizedTimeline
                | MirFnKind::SynthesizedTask
                | MirFnKind::SynthesizedFsm
                | MirFnKind::SynthesizedSpatialCsr
                | MirFnKind::SynthesizedTimerTick => {
                    let name = sanitize_ident(&f.name);
                    let _ = writeln!(
                        self.out,
                        "static BamResult strata_sys_{name}(BamSystemCtx* sys_ctx, void* user_data);"
                    );
                }
                MirFnKind::Observer { .. } => {
                    let name = sanitize_ident(&f.name);
                    let _ = writeln!(
                        self.out,
                        "static BamResult strata_obs_{name}(BamEntity entity, const void* event_data, BamSystemCtx* sys_ctx, void* user_data);"
                    );
                }
                MirFnKind::Migration { .. } => {
                    let name = sanitize_ident(&f.name);
                    let _ = writeln!(
                        self.out,
                        "static BamResult strata_mig_{name}(const void* src_row, void* dst_row, void* user_data);"
                    );
                }
            }
        }
        if !self.mir.objects.is_empty() {
            let _ = writeln!(
                self.out,
                "static BamResult strata_sys_startup_objects(BamSystemCtx* sys_ctx, void* user_data);"
            );
        }
        self.out.push('\n');
    }

    pub(super) fn helper_sig(&self, f: &MirFunction) -> String {
        let ret = if matches!(f.ret_ty, MirType::Unit) {
            "void".to_string()
        } else {
            self.c_ty(&f.ret_ty)
        };
        let fn_name = format!("strata_fn_{}", sanitize_ident(&f.name));
        let mut params = vec!["StrataModState* state".to_string()];
        for (i, p) in f.params.iter().enumerate() {
            let p_ty = self.c_ty(&p.ty);
            params.push(format!("{p_ty} p_{i}"));
        }
        format!("static BAM_UNUSED {ret} {fn_name}({})", params.join(", "))
    }

    pub(super) fn emit_startup_objects_fn(&mut self) -> Result<(), CodegenError> {
        if self.mir.objects.is_empty() {
            return Ok(());
        }
        let mut s = String::new();
        let _ = writeln!(
            s,
            "static BamResult strata_sys_startup_objects(BamSystemCtx* sys_ctx, void* user_data) {{"
        );
        let _ = writeln!(s, "    StrataModState* state = (StrataModState*)user_data;");
        let _ = writeln!(
            s,
            "    if (sys_ctx == NULL || state == NULL || state->api == NULL) {{ return BAM_RESULT_NULL_POINTER; }}"
        );
        let _ = writeln!(
            s,
            "    if (state->objects_initialized) {{ return BAM_RESULT_OK; }}"
        );
        let _ = writeln!(s, "    state->objects_initialized = BAM_TRUE;");
        let _ = writeln!(s, "    BamCommands* cmds = NULL;");
        let _ = writeln!(
            s,
            "    if (state->api->sys_commands != NULL) {{ (void)state->api->sys_commands(sys_ctx, &cmds); }}"
        );

        let objs = self.mir.objects.clone();
        let mut probe_q_idx = 0usize;
        for (o_idx, obj) in objs.iter().enumerate() {
            let reg_obj = &self.objects[o_idx];
            let _ = writeln!(s, "    /* Named Object: {} */", obj.name);
            let _ = writeln!(
                s,
                "    if (state->named_objects[{o_idx}] == BAM_ENTITY_NULL) {{"
            );
            if reg_obj.primary_comp_idx.is_some() {
                let qi = probe_q_idx;
                probe_q_idx += 1;
                let _ = writeln!(s, "        BamIter* it = NULL;");
                let _ = writeln!(
                    s,
                    "        if (state->api->sys_query != NULL && state->api->sys_query(sys_ctx, {qi}u, &it) == BAM_RESULT_OK && it != NULL) {{"
                );
                let _ = writeln!(s, "            size_t len = 0u;");
                let _ = writeln!(
                    s,
                    "            if (state->api->iter_next_chunk != NULL && state->api->iter_next_chunk(it, &len) != BAM_FALSE && len > 0u && state->api->iter_entities != NULL) {{"
                );
                let _ = writeln!(
                    s,
                    "                const BamEntity* ents = state->api->iter_entities(it);"
                );
                let _ = writeln!(
                    s,
                    "                if (ents != NULL && ents[0] != BAM_ENTITY_NULL) {{ state->named_objects[{o_idx}] = ents[0]; }}"
                );
                let _ = writeln!(s, "            }}");
                let _ = writeln!(s, "        }}");
            }
            let _ = writeln!(
                s,
                "        if (state->named_objects[{o_idx}] == BAM_ENTITY_NULL && cmds != NULL) {{"
            );
            let bundle = self.build_object_component_bundle(obj);
            let n_comps = bundle.len().max(1);
            let _ = writeln!(s, "            BamComponent comps[{n_comps}u];");
            let _ = writeln!(s, "            const uint8_t* datas[{n_comps}u];");
            for (bi, (c_idx, init_opt)) in bundle.iter().enumerate() {
                let comp = &self.components[*c_idx];
                let _ = writeln!(s, "            comps[{bi}u] = state->components[{c_idx}u];");
                if let Some(l_idx) = comp.layout_idx
                    && self.layouts[l_idx].size > 0
                {
                    let cty = &self.layout_c_names[l_idx];
                    let def_fn = format!(
                        "strata_default_{l_idx}_{}",
                        sanitize_ident(short_name(&self.layouts[l_idx].canonical_name))
                    );
                    let _ = writeln!(s, "            {cty} val_{bi} = {def_fn}();");
                    if let Some(ci) = init_opt {
                        for (fname, fexpr) in &ci.fields {
                            let fc = sanitize_c_field(fname);
                            let sf_opt =
                                self.layouts[l_idx].fields.iter().find(|f| f.name == *fname);
                            let field_ty = sf_opt.map(|f| f.ty.clone()).unwrap_or(Ty::Unknown);
                            let field_sz = sf_opt.map_or(0, |f| f.size);
                            self.emit_c_object_field_override(
                                &mut s,
                                "            ",
                                &format!("val_{bi}.{fc}"),
                                &field_ty,
                                field_sz,
                                fexpr,
                                true,
                                0,
                            );
                        }
                    }
                    let _ = writeln!(s, "            datas[{bi}u] = (const uint8_t*)&val_{bi};");
                } else {
                    let _ = writeln!(s, "            datas[{bi}u] = NULL;");
                }
            }
            if bundle.is_empty() {
                let _ = writeln!(s, "            comps[0u] = BAM_COMPONENT_INVALID;");
                let _ = writeln!(s, "            datas[0u] = NULL;");
            }
            let spawn_fn = if obj.is_persist {
                "cmd_spawn_persistent"
            } else {
                "cmd_spawn"
            };
            let real_count = bundle.len();
            let _ = writeln!(
                s,
                "            BamEntity spawned = BAM_ENTITY_NULL;\n            if (state->api->{spawn_fn} != NULL) {{\n                (void)state->api->{spawn_fn}(cmds, comps, datas, {real_count}u, &spawned);\n            }}\n            state->named_objects[{o_idx}] = spawned;"
            );
            let _ = writeln!(s, "        }}");
            let escaped = c_escape(&obj.name);
            let _ = writeln!(
                s,
                "        if (state->named_objects[{o_idx}] != BAM_ENTITY_NULL && state->host_ctx != NULL && state->api->bind_named_object != NULL) {{"
            );
            let _ = writeln!(
                s,
                "            (void)state->api->bind_named_object(state->host_ctx, bam_str_view(\"{escaped}\"), state->named_objects[{o_idx}]);"
            );
            let _ = writeln!(s, "        }}");
            let _ = writeln!(s, "    }}");
        }
        let _ = writeln!(s, "    return BAM_RESULT_OK;");
        let _ = writeln!(s, "}}\n");
        self.out.push_str(&s);
        Ok(())
    }

    pub(super) fn build_object_component_bundle<'b>(
        &self,
        obj: &'b HirObject,
    ) -> Vec<(usize, Option<&'b HirCompInit>)> {
        let mut seen: HashSet<usize> = HashSet::new();
        let mut out: Vec<(usize, Option<&'b HirCompInit>)> = Vec::new();
        let mut queue: VecDeque<usize> = VecDeque::new();

        for ci in &obj.inits {
            let idx_opt = ci
                .canonical_component
                .as_deref()
                .and_then(|cc| self.find_comp_idx(cc))
                .or_else(|| self.find_comp_idx(&ci.component));
            if let Some(idx) = idx_opt
                && seen.insert(idx)
            {
                out.push((idx, Some(ci)));
                queue.push_back(idx);
            }
        }
        for cname in &obj.components {
            if let Some(idx) = self.find_comp_idx(cname)
                && seen.insert(idx)
            {
                out.push((idx, None));
                queue.push_back(idx);
            }
        }
        while let Some(c_idx) = queue.pop_front() {
            for &req in &self.components[c_idx].required_indices {
                if seen.insert(req) {
                    out.push((req, None));
                    queue.push_back(req);
                }
            }
        }
        out
    }

    pub(super) fn compute_component_reg_order(&self) -> Vec<usize> {
        fn visit(idx: usize, comps: &[RegComponent], state: &mut [u8], order: &mut Vec<usize>) {
            if state[idx] != 0 {
                return;
            }
            state[idx] = 1;
            for &req in &comps[idx].required_indices {
                if req < comps.len() {
                    visit(req, comps, state, order);
                }
            }
            state[idx] = 2;
            order.push(idx);
        }

        let n = self.components.len();
        let mut state = vec![0u8; n];
        let mut order = Vec::with_capacity(n);
        for idx in 0..n {
            visit(idx, &self.components, &mut state, &mut order);
        }
        order
    }

    pub(super) fn layout_has_nonzero_default(&self, l_idx: usize) -> bool {
        let mut visited = HashSet::new();
        self.layout_has_nonzero_default_rec(l_idx, &mut visited)
    }

    pub(super) fn layout_has_nonzero_default_rec(
        &self,
        l_idx: usize,
        visited: &mut HashSet<usize>,
    ) -> bool {
        if !visited.insert(l_idx) {
            return false;
        }
        let layout = &self.layouts[l_idx];
        if layout.size == 0 {
            return false;
        }
        let short = short_name(&layout.canonical_name);
        let defs_opt = self
            .mir
            .field_defaults
            .get(&layout.canonical_name)
            .or_else(|| self.mir.field_defaults.get(short));
        if let Some(defs) = defs_opt
            && defs.values().any(|v| !mir_const_is_all_zero(v))
        {
            return true;
        }
        for f in &layout.fields {
            if !f.is_padding && self.ty_has_nonzero_default_rec(&f.ty, visited) {
                return true;
            }
        }
        false
    }

    pub(super) fn ty_has_nonzero_default_rec(&self, ty: &Ty, visited: &mut HashSet<usize>) -> bool {
        match ty {
            Ty::Named(key) => {
                if let Some(sub_idx) = self.find_layout_idx(key)
                    && self.layouts[sub_idx].size > 0
                {
                    self.layout_has_nonzero_default_rec(sub_idx, visited)
                } else {
                    false
                }
            }
            Ty::Array { elem, len } if *len > 0 => self.ty_has_nonzero_default_rec(elem, visited),
            _ => false,
        }
    }

    pub(super) fn emit_manifest_init_shutdown(&mut self) -> Result<(), CodegenError> {
        let mod_name = c_escape(&self.mir.module_path);

        let _ = writeln!(
            self.out,
            "\
static const BamManifest STRATA_MANIFEST = {{
    (uint32_t)sizeof(BamManifest),
    BAM_ABI_VERSION,
    \"{mod_name}\",
    \"0.3.0\",
    0u,
    0u,
    NULL,
    NULL
}};

BAM_EXPORT const BamManifest* bamabi_manifest(void) {{
    return &STRATA_MANIFEST;
}}
"
        );

        let _ = writeln!(
            self.out,
            "\
BAM_EXPORT BamResult bamabi_init(const BamHostApi* api, BamLoadCtx* load_ctx, BamInstance** instance_out) {{
    if (api == NULL || load_ctx == NULL || instance_out == NULL) {{
        return BAM_RESULT_NULL_POINTER;
    }}
    if (api->struct_size < BAM_HOST_API_MIN_V0_2_SIZE) {{
        return BAM_RESULT_INVALID_VERSION;
    }}
    if (api->register_component == NULL) {{
        return BAM_RESULT_UNSUPPORTED;
    }}
    StrataModState* state = (StrataModState*)calloc(1u, sizeof(StrataModState));
    if (state == NULL) {{
        return BAM_RESULT_INTERNAL_ERROR;
    }}
    state->api = api;
    state->host_ctx = (api->load_host_ctx != NULL) ? api->load_host_ctx(load_ctx) : NULL;
    {{
        uint32_t _mi;
        for (_mi = 0u; _mi < (uint32_t)(sizeof(state->sys_msg_q) / sizeof(state->sys_msg_q[0])); ++_mi) {{
            state->sys_msg_q[_mi] = UINT32_MAX;
        }}
        for (_mi = 0u; _mi < (uint32_t)(sizeof(state->sys_msg_ti) / sizeof(state->sys_msg_ti[0])); ++_mi) {{
            state->sys_msg_ti[_mi] = UINT32_MAX;
        }}
    }}
    *instance_out = (BamInstance*)state;
"
        );

        let spatial_indices = self.mir.spatial_indices.clone();
        for sp in &spatial_indices {
            let ident = sanitize_ident(&sp.name);
            let frames = sp.frames.max(1);
            let cap = sp.capacity.max(1);
            let cols = sp.cols.max(1);
            let rows = sp.rows.max(1);
            let cells = (cols * rows).max(1);
            let cs = if sp.cell_size > 0.0 {
                sp.cell_size
            } else {
                4.0
            };
            let inv_cs = 1.0f32 / cs;
            let bmin_x = c_f32(sp.bounds_min[0]);
            let bmin_y = c_f32(sp.bounds_min[1]);
            let cs_s = c_f32(cs);
            let inv_cs_s = c_f32(inv_cs);
            let ax0 = sp.plane_axes[0];
            let ax1 = sp.plane_axes[1];
            let _ = writeln!(
                self.out,
                "    state->spatial_{ident}.frames = {frames}u;\n\
                 \x20   state->spatial_{ident}.capacity = {cap}u;\n\
                 \x20   state->spatial_{ident}.cols = {cols}u;\n\
                 \x20   state->spatial_{ident}.rows = {rows}u;\n\
                 \x20   state->spatial_{ident}.cell_count = {cells}u;\n\
                 \x20   state->spatial_{ident}.head_tick = 0u;\n\
                 \x20   state->spatial_{ident}.cell_size = {cs_s};\n\
                 \x20   state->spatial_{ident}.inv_cell_size = {inv_cs_s};\n\
                 \x20   state->spatial_{ident}.bounds_min_x = {bmin_x};\n\
                 \x20   state->spatial_{ident}.bounds_min_y = {bmin_y};\n\
                 \x20   state->spatial_{ident}.plane_ax0 = {ax0}u;\n\
                 \x20   state->spatial_{ident}.plane_ax1 = {ax1}u;\n\
                 \x20   state->spatial_{ident}.counts = state->spatial_{ident}_counts;\n\
                 \x20   state->spatial_{ident}.cell_offsets = state->spatial_{ident}_offsets;\n\
                 \x20   state->spatial_{ident}.write_cursors = state->spatial_{ident}_cursors;\n\
                 \x20   state->spatial_{ident}.entities = state->spatial_{ident}_entities;\n\
                 \x20   state->spatial_{ident}.positions = state->spatial_{ident}_positions;"
            );
        }

        let comps = self.components.clone();
        let reg_order = self.compute_component_reg_order();
        for comp in &comps {
            if comp.has_mod_res
                && let Some(l_idx) = comp.layout_idx
            {
                let short = short_name(&self.layouts[l_idx].canonical_name);
                let def_fn = format!("strata_default_{l_idx}_{}", sanitize_ident(short));
                let _ = writeln!(self.out, "    state->mod_res_{} = {def_fn}();", comp.idx);
            }
        }
        for comp_idx in reg_order {
            let comp = &comps[comp_idx];
            let idx = comp.idx;
            let canon_esc = c_escape(&comp.canonical);
            let fp = comp.fingerprint;
            let uuid_bytes: Vec<String> = comp
                .uuid
                .bytes
                .iter()
                .map(|b| format!("0x{b:02X}u"))
                .collect();
            let _ = writeln!(self.out, "    /* Component [{idx}]: {} */", comp.canonical);
            let _ = writeln!(self.out, "    {{");
            let mut field_count = 0usize;
            if let Some(l_idx) = comp.layout_idx {
                let all_fields = &self.layouts[l_idx].fields;
                if !all_fields.is_empty() {
                    field_count = all_fields.len();
                    let _ = writeln!(
                        self.out,
                        "        static const BamFieldDesc fields_{idx}[{field_count}] = {{"
                    );
                    for (fi, fld) in all_fields.iter().enumerate() {
                        let comma = if fi + 1 < all_fields.len() { "," } else { "" };
                        let f_esc = c_escape(&fld.name);
                        let t_esc = c_escape(&fld.type_tag);
                        let _ = writeln!(
                            self.out,
                            "            {{ (uint32_t)sizeof(BamFieldDesc), (BamFieldKind){}, {{ (const uint8_t*)\"{f_esc}\", sizeof(\"{f_esc}\") - 1u }}, {{ (const uint8_t*)\"{t_esc}\", sizeof(\"{t_esc}\") - 1u }}, {}u, {}u, {}u }}{comma}",
                            fld.bam_field_kind, fld.offset, fld.size, fld.align
                        );
                    }
                    let _ = writeln!(self.out, "        }};");
                }
            }
            let _ = writeln!(
                self.out,
                "        BamComponentUuid comp_uuid_{idx} = {{ {{ {} }} }};",
                uuid_bytes.join(", ")
            );
            let _ = writeln!(
                self.out,
                "        BamComponentDesc cdesc = bam_desc_component_with_layout(\"{canon_esc}\", {}u, {}u, NULL);",
                comp.size, comp.align
            );
            let _ = writeln!(self.out, "        cdesc.uuid = comp_uuid_{idx};");
            let _ = writeln!(self.out, "        cdesc.flags = {}u;", comp.flags);
            let _ = writeln!(
                self.out,
                "        cdesc.schema_fingerprint = 0x{fp:016X}ull;"
            );
            if field_count > 0 {
                let _ = writeln!(self.out, "        cdesc.fields = fields_{idx};");
                let _ = writeln!(self.out, "        cdesc.field_count = {field_count}u;");
            }
            if !comp.required_indices.is_empty() {
                let req_n = comp.required_indices.len();
                let _ = writeln!(self.out, "        BamComponent reqs_{idx}[{req_n}u];");
                for (ri, &r_idx) in comp.required_indices.iter().enumerate() {
                    let _ = writeln!(
                        self.out,
                        "        reqs_{idx}[{ri}u] = state->components[{r_idx}u];"
                    );
                }
                let _ = writeln!(self.out, "        cdesc.required_components = reqs_{idx};");
                let _ = writeln!(
                    self.out,
                    "        cdesc.required_component_count = {req_n}u;"
                );

                let nonzero_reqs: Vec<(usize, usize)> = comp
                    .required_indices
                    .iter()
                    .copied()
                    .filter_map(|r_idx| {
                        let rl_idx = comps[r_idx].layout_idx?;
                        if is_ecs_component_kind(self.layouts[rl_idx].item_kind)
                            && self.layout_has_nonzero_default(rl_idx)
                        {
                            Some((r_idx, rl_idx))
                        } else {
                            None
                        }
                    })
                    .collect();
                if !nonzero_reqs.is_empty() {
                    let init_n = nonzero_reqs.len();
                    for (ki, &(_, rl_idx)) in nonzero_reqs.iter().enumerate() {
                        let r_cty = &self.layout_c_names[rl_idx];
                        let r_short = short_name(&self.layouts[rl_idx].canonical_name);
                        let def_fn = format!("strata_default_{rl_idx}_{}", sanitize_ident(r_short));
                        let _ =
                            writeln!(self.out, "        {r_cty} req_def_{idx}_{ki} = {def_fn}();");
                    }
                    let _ = writeln!(
                        self.out,
                        "        BamRequiredComponent req_inits_{idx}[{init_n}u];"
                    );
                    let _ = writeln!(
                        self.out,
                        "        memset(req_inits_{idx}, 0, sizeof(req_inits_{idx}));"
                    );
                    for (ki, &(r_idx, rl_idx)) in nonzero_reqs.iter().enumerate() {
                        let r_size = self.layouts[rl_idx].size;
                        let _ = writeln!(
                            self.out,
                            "        req_inits_{idx}[{ki}u].struct_size = (uint32_t)sizeof(BamRequiredComponent);"
                        );
                        let _ = writeln!(
                            self.out,
                            "        req_inits_{idx}[{ki}u].flags = BAM_REQUIRED_FLAG_CUSTOM_BYTES;"
                        );
                        let _ = writeln!(
                            self.out,
                            "        req_inits_{idx}[{ki}u].component = state->components[{r_idx}u];"
                        );
                        let _ = writeln!(
                            self.out,
                            "        req_inits_{idx}[{ki}u].init_bytes = (const uint8_t*)&req_def_{idx}_{ki};"
                        );
                        let _ = writeln!(
                            self.out,
                            "        req_inits_{idx}[{ki}u].init_size = {r_size}u;"
                        );
                    }
                    let _ = writeln!(
                        self.out,
                        "        cdesc.required_init_descs = req_inits_{idx};"
                    );
                    let _ = writeln!(
                        self.out,
                        "        cdesc.required_init_desc_count = {init_n}u;"
                    );
                }
            }
            let size = comp.size;
            let align = comp.align;
            if let Some(ref mig_fn) = comp.migration_fn {
                let _ = writeln!(
                    self.out,
                    "\
        BamResult reg_rc = BAM_RESULT_NOT_FOUND;
        if (state->host_ctx != NULL && api->resolve_component != NULL) {{
            reg_rc = api->resolve_component(state->host_ctx, cdesc.name, NULL, &state->components[{idx}]);
            if (reg_rc == BAM_RESULT_OK && api->component_layout_info != NULL) {{
                BamLayoutInfo linfo;
                memset(&linfo, 0, sizeof(linfo));
                linfo.struct_size = (uint32_t)sizeof(BamLayoutInfo);
                if (api->component_layout_info(state->host_ctx, state->components[{idx}], &linfo) == BAM_RESULT_OK) {{
                    if (linfo.schema_fingerprint != 0x{fp:016X}ull || linfo.size != {size}u || linfo.align != {align}u) {{
                        if (api->migrate_component_column == NULL) {{
                            free(state);
                            *instance_out = NULL;
                            return BAM_RESULT_TYPE_MISMATCH;
                        }}
                        reg_rc = api->migrate_component_column(load_ctx, state->components[{idx}], 0ull, &cdesc, {mig_fn}, state);
                    }}
                }}
            }}
        }}
        if (reg_rc == BAM_RESULT_NOT_FOUND) {{
            reg_rc = api->register_component(load_ctx, &cdesc, &state->components[{idx}]);
            if (reg_rc == BAM_RESULT_TYPE_MISMATCH) {{
                if (state->host_ctx == NULL || api->resolve_component == NULL || api->migrate_component_column == NULL) {{
                    free(state);
                    *instance_out = NULL;
                    return BAM_RESULT_TYPE_MISMATCH;
                }}
                reg_rc = api->resolve_component(state->host_ctx, cdesc.name, NULL, &state->components[{idx}]);
                if (reg_rc == BAM_RESULT_OK) {{
                    reg_rc = api->migrate_component_column(load_ctx, state->components[{idx}], 0ull, &cdesc, {mig_fn}, state);
                }}
            }}
        }}"
                );
            } else {
                let resolve_by_name_only = comp.layout_idx.is_none()
                    || matches!(
                        comp.item_kind,
                        Some(
                            SchemaItemKind::Resource
                                | SchemaItemKind::Event
                                | SchemaItemKind::Stream
                                | SchemaItemKind::SpatialGrid
                                | SchemaItemKind::SpatialHistory
                        )
                    );
                let uuid_arg = if resolve_by_name_only {
                    "NULL".to_string()
                } else {
                    format!("&comp_uuid_{idx}")
                };
                let _ = writeln!(
                    self.out,
                    "\
        BamResult reg_rc = BAM_RESULT_NOT_FOUND;
        if (state->host_ctx != NULL && api->resolve_component != NULL) {{
            reg_rc = api->resolve_component(state->host_ctx, cdesc.name, {uuid_arg}, &state->components[{idx}]);
        }}
        if (reg_rc == BAM_RESULT_NOT_FOUND) {{
            reg_rc = api->register_component(load_ctx, &cdesc, &state->components[{idx}]);
        }}"
                );
            }
            let _ = writeln!(
                self.out,
                "\
        if (reg_rc == BAM_RESULT_OK && state->host_ctx != NULL && api->component_layout_info != NULL) {{
            BamLayoutInfo linfo;
            memset(&linfo, 0, sizeof(linfo));
            linfo.struct_size = (uint32_t)sizeof(BamLayoutInfo);
            if (api->component_layout_info(state->host_ctx, state->components[{idx}], &linfo) == BAM_RESULT_OK) {{
                if ((linfo.flags & BAM_STORAGE_FLAG_RESOURCE) != 0u) {{
                    state->res_flags[{idx}] = 1u;
                }} else if ((linfo.flags & BAM_STORAGE_FLAG_MESSAGE) != 0u) {{
                    state->res_flags[{idx}] = 2u;
                }}
            }}
        }}
        if (reg_rc != BAM_RESULT_OK) {{ free(state); *instance_out = NULL; return reg_rc; }}"
            );
            let _ = writeln!(self.out, "    }}");
        }

        if !self.relations.is_empty() {
            let rels = self.relations.clone();
            let _ = writeln!(
                self.out,
                "    if (api->register_relation == NULL) {{ free(state); *instance_out = NULL; return BAM_RESULT_UNSUPPORTED; }}"
            );
            for r in &rels {
                let idx = r.idx;
                let esc = c_escape(&r.canonical);
                let uuid_bytes: Vec<String> =
                    r.uuid.bytes.iter().map(|b| format!("0x{b:02X}u")).collect();
                let _ = writeln!(self.out, "    {{");
                let _ = writeln!(
                    self.out,
                    "        BamComponentUuid rel_uuid_{idx} = {{ {{ {} }} }};",
                    uuid_bytes.join(", ")
                );
                let _ = writeln!(self.out, "        BamRelationDesc rdesc;");
                let _ = writeln!(self.out, "        memset(&rdesc, 0, sizeof(rdesc));");
                let _ = writeln!(
                    self.out,
                    "        rdesc.struct_size = (uint32_t)sizeof(BamRelationDesc);"
                );
                let _ = writeln!(self.out, "        rdesc.flags = {};", r.flags_expr);
                let _ = writeln!(self.out, "        rdesc.name = \"{esc}\";");
                let _ = writeln!(self.out, "        rdesc.uuid = rel_uuid_{idx};");
                let _ = writeln!(self.out, "        rdesc.data_size = {}u;", r.data_size);
                let _ = writeln!(self.out, "        rdesc.data_align = {}u;", r.data_align);
                let _ = writeln!(self.out, "        rdesc.max_degree = {}u;", r.max_degree);
                let _ = writeln!(
                    self.out,
                    "        BamResult rrc = api->register_relation(load_ctx, &rdesc, &state->relations[{idx}]);"
                );
                let _ = writeln!(
                    self.out,
                    "        if (rrc != BAM_RESULT_OK) {{ free(state); *instance_out = NULL; return rrc; }}"
                );
                let _ = writeln!(self.out, "    }}");
            }
        }

        if !self.sets.is_empty() {
            let sets = self.sets.clone();
            let set_idx_by_name: HashMap<String, usize> =
                sets.iter().map(|st| (st.name.clone(), st.idx)).collect();
            let _ = writeln!(self.out, "    if (api->configure_schedule_set != NULL) {{");
            for s in &sets {
                let idx = s.idx;
                let esc = c_escape(&s.name);
                let after_handles: Vec<String> = s
                    .after_sets
                    .iter()
                    .filter_map(|n| set_idx_by_name.get(n))
                    .map(|p_idx| format!("state->sets[{p_idx}]"))
                    .collect();
                let _ = writeln!(self.out, "        {{");
                if !after_handles.is_empty() {
                    let _ = writeln!(
                        self.out,
                        "            BamSystemSet after_sets_{idx}[{}] = {{ {} }};",
                        after_handles.len(),
                        after_handles.join(", ")
                    );
                }
                let _ = writeln!(self.out, "            BamScheduleSetDesc set_desc;");
                let _ = writeln!(
                    self.out,
                    "            memset(&set_desc, 0, sizeof(set_desc));"
                );
                let _ = writeln!(
                    self.out,
                    "            set_desc.struct_size = (uint32_t)sizeof(BamScheduleSetDesc);"
                );
                let _ = writeln!(self.out, "            set_desc.flags = {};", s.flags_expr);
                let _ = writeln!(self.out, "            set_desc.schedule = {};", s.schedule);
                let _ = writeln!(self.out, "            set_desc.name = \"{esc}\";");
                if !after_handles.is_empty() {
                    let _ = writeln!(
                        self.out,
                        "            set_desc.after_sets = after_sets_{idx};"
                    );
                    let _ = writeln!(
                        self.out,
                        "            set_desc.after_count = {}u;",
                        after_handles.len()
                    );
                }
                let _ = writeln!(
                    self.out,
                    "            BamResult src = api->configure_schedule_set(load_ctx, &set_desc, &state->sets[{idx}]);"
                );
                let _ = writeln!(
                    self.out,
                    "            if (src != BAM_RESULT_OK) {{ free(state); *instance_out = NULL; return src; }}"
                );
                let _ = writeln!(self.out, "        }}");
            }
            let _ = writeln!(self.out, "    }}");
        }

        if has_net_protocol(self.mir) {
            self.emit_net_init_checks();
            self.emit_net_sys_registration(true);
        }

        let systems = self.systems.clone();
        for sys in &systems {
            self.emit_register_single_system(sys)?;
        }

        if has_net_protocol(self.mir) {
            self.emit_net_sys_registration(false);
        }

        let free_net_rx = if has_net_protocol(self.mir) {
            "free(state->net_rx_buf); "
        } else {
            ""
        };
        let observers = self.observers.clone();
        if !observers.is_empty() {
            let _ = writeln!(
                self.out,
                "    if (api->register_observer == NULL) {{ {free_net_rx}free(state); *instance_out = NULL; return BAM_RESULT_UNSUPPORTED; }}"
            );
            let msg_slot_base = self.systems.len();
            for obs in &observers {
                let esc = c_escape(&obs.reg_name);
                let obs_slot_idx = msg_slot_base + obs.obs_idx;
                let _ = writeln!(self.out, "    {{");
                let (q_ptr, q_cnt) = self.emit_fn_query_descs(
                    obs_slot_idx,
                    Some(obs.mir_fn_idx),
                    false,
                    &[],
                    &format!("c99::observer({})", obs.reg_name),
                )?;
                let _ = writeln!(
                    self.out,
                    "        BamObserverDesc odesc = bam_observer_desc_ctx(state->components[{}], BAM_ENTITY_NULL, {}, {q_ptr}, {q_cnt}, state);",
                    obs.event_comp_idx, obs.c_fn_name
                );
                let _ = writeln!(self.out, "        odesc.name = \"{esc}\";");
                if let Some(tc_idx) = obs.target_comp_idx {
                    let _ = writeln!(
                        self.out,
                        "        BamComponent obs_watch_{}[1];\n        obs_watch_{}[0] = state->components[{tc_idx}];\n        odesc.watched_components = obs_watch_{};\n        odesc.watched_component_count = 1u;",
                        obs.obs_idx, obs.obs_idx, obs.obs_idx
                    );
                }
                let _ = writeln!(
                    self.out,
                    "        BamResult orc = api->register_observer(load_ctx, &odesc);"
                );
                let _ = writeln!(
                    self.out,
                    "        if (orc != BAM_RESULT_OK) {{ {free_net_rx}free(state); *instance_out = NULL; return orc; }}"
                );
                let _ = writeln!(self.out, "    }}");
            }
        }

        let _ = writeln!(self.out, "    return BAM_RESULT_OK;");
        if has_net_protocol(self.mir) {
            let _ = writeln!(
                self.out,
                "}}\n\nBAM_EXPORT void bamabi_shutdown(BamInstance* instance) {{\n    if (instance != NULL) {{\n        free(((StrataModState*)instance)->net_rx_buf);\n        free(instance);\n    }}\n}}"
            );
        } else {
            let _ = writeln!(
                self.out,
                "}}\n\nBAM_EXPORT void bamabi_shutdown(BamInstance* instance) {{\n    if (instance != NULL) {{\n        free(instance);\n    }}\n}}"
            );
        }
        Ok(())
    }

    pub(super) fn emit_fn_query_descs(
        &mut self,
        s_idx: usize,
        mir_fn_idx: Option<usize>,
        is_startup_objects: bool,
        run_if_resources: &[usize],
        err_ctx: &str,
    ) -> Result<(String, String), CodegenError> {
        let comp_n = self.components.len().max(1);
        let mut query_terms_c: Vec<Vec<String>> = Vec::new();
        let mut query_param_set_groups: Vec<u32> = Vec::new();
        let mut res_modes: BTreeMap<usize, bool> = BTreeMap::new();
        let mut msg_modes: BTreeMap<usize, bool> = BTreeMap::new();
        if is_startup_objects {
            for obj in &self.objects {
                if let Some(p_idx) = obj.primary_comp_idx {
                    query_terms_c.push(vec![format!(
                        "bam_term_desc(state->components[{p_idx}], BAM_ACCESS_FILTER_ONLY, 0u)"
                    )]);
                    query_param_set_groups.push(0);
                }
            }
        } else if let Some(fn_idx) = mir_fn_idx {
            let f = &self.mir_functions()[fn_idx];
            query_param_set_groups = self.compute_query_param_set_groups(f);
            let mut query_stream_comps: HashSet<usize> = HashSet::new();

            for qb in &f.query_bindings {
                let mut t_strs = Vec::new();
                let mut extra_changed: Vec<usize> = Vec::new();
                let mut term_comp_indices: Vec<usize> = Vec::new();
                for term in &qb.terms {
                    let c_idx = self
                        .find_comp_idx(&term.canonical_component)
                        .ok_or_else(|| CodegenError::Unsupported {
                            context: err_ctx.to_owned(),
                            detail: format!(
                                "missing component `{}` in query {}",
                                term.canonical_component, qb.query_idx
                            ),
                        })?;
                    term_comp_indices.push(c_idx);
                    if matches!(
                        term.mode,
                        TermAccessMode::StreamRead | TermAccessMode::StreamWrite
                    ) {
                        query_stream_comps.insert(c_idx);
                    }
                    let is_changed = f.changed_terms.iter().any(|ct| {
                        ct.query_idx == qb.query_idx
                            && (ct.term_idx == term.term_idx
                                || ct.canonical_component == term.canonical_component)
                    });
                    let mode_c = if is_changed && term.mode == TermAccessMode::Read {
                        "BAM_ACCESS_CHANGED"
                    } else {
                        if is_changed && !extra_changed.contains(&c_idx) {
                            extra_changed.push(c_idx);
                        }
                        c_access_mode(term.mode)
                    };
                    t_strs.push(format!(
                        "bam_term_desc(state->components[{c_idx}], {mode_c}, 0u)"
                    ));
                }
                if let Some(qdesc) = f.queries.get(qb.query_idx as usize) {
                    for cf in &qdesc.changed_filters {
                        if let Some(c_idx) = self.find_comp_idx(cf)
                            && !term_comp_indices.contains(&c_idx)
                            && !extra_changed.contains(&c_idx)
                        {
                            extra_changed.push(c_idx);
                        }
                    }
                }
                for w in &qb.with_filters {
                    if let Some(c_idx) = self.find_comp_idx(w) {
                        t_strs.push(format!(
                            "bam_term_desc(state->components[{c_idx}], BAM_ACCESS_FILTER_ONLY, 0u)"
                        ));
                    }
                }
                for wo in &qb.without_filters {
                    if let Some(c_idx) = self.find_comp_idx(wo) {
                        t_strs.push(format!(
                            "bam_term_desc(state->components[{c_idx}], BAM_ACCESS_WITHOUT, 0u)"
                        ));
                    }
                }
                for c_idx in extra_changed {
                    t_strs.push(format!(
                        "bam_term_desc(state->components[{c_idx}], BAM_ACCESS_CHANGED, 0u)"
                    ));
                }
                if t_strs.len() > MAX_TERMS_PER_QUERY {
                    return Err(CodegenError::Unsupported {
                        context: err_ctx.to_owned(),
                        detail: format!(
                            "query {} exceeds MAX_TERMS_PER_QUERY ({})",
                            qb.query_idx, MAX_TERMS_PER_QUERY
                        ),
                    });
                }
                query_terms_c.push(t_strs);
            }

            for r in &f.resources {
                if let Some(c_idx) = self.find_comp_idx(&r.canonical_name) {
                    res_modes
                        .entry(c_idx)
                        .and_modify(|m| *m |= r.mutable)
                        .or_insert(r.mutable);
                }
            }
            for op in &f.stream_ops {
                if let Some(c_idx) = self
                    .find_comp_idx(&op.canonical_stream)
                    .or_else(|| self.find_comp_idx(&op.stream))
                    && !query_stream_comps.contains(&c_idx)
                {
                    let is_write = matches!(
                        op.kind,
                        MirStreamOpKind::StreamSend | MirStreamOpKind::StreamWriteBatch
                    );
                    msg_modes
                        .entry(c_idx)
                        .and_modify(|m| *m |= is_write)
                        .or_insert(is_write);
                }
            }
            for bb in &f.blocks {
                for stmt in &bb.stmts {
                    match &stmt.inst {
                        Inst::ResRead { resource }
                        | Inst::SpatialQueryDisc {
                            grid_name: resource,
                            ..
                        }
                        | Inst::SpatialQuerySegmentAt {
                            history_name: resource,
                            ..
                        } => {
                            if let Some(c_idx) = self.find_comp_idx(resource) {
                                res_modes.entry(c_idx).or_insert(false);
                            }
                        }
                        Inst::ResWrite { resource } => {
                            if let Some(c_idx) = self.find_comp_idx(resource) {
                                res_modes.insert(c_idx, true);
                            }
                        }
                        Inst::StreamEmit { stream, .. } => {
                            if let Some(c_idx) = self.find_comp_idx(stream)
                                && !query_stream_comps.contains(&c_idx)
                            {
                                msg_modes.insert(c_idx, true);
                            }
                        }
                        _ => {}
                    }
                }
            }
            for &r_idx in run_if_resources {
                res_modes.entry(r_idx).or_insert(false);
            }
        }

        let ecs_q_count = query_terms_c.len();
        let max_res_queries = res_modes.len().div_ceil(MAX_TERMS_PER_QUERY);
        let max_msg_queries = msg_modes.len().div_ceil(MAX_TERMS_PER_QUERY);
        let max_total_queries = ecs_q_count + max_res_queries + max_msg_queries;
        if max_total_queries > MAX_QUERIES_PER_SYSTEM {
            return Err(CodegenError::Unsupported {
                context: err_ctx.to_owned(),
                detail: format!(
                    "exceeds MAX_QUERIES_PER_SYSTEM ({})",
                    MAX_QUERIES_PER_SYSTEM
                ),
            });
        }

        for (qi, terms) in query_terms_c.iter().enumerate() {
            if !terms.is_empty() {
                let _ = writeln!(
                    self.out,
                    "        BamTermDesc terms_{s_idx}_{qi}[{}];",
                    terms.len()
                );
                for (ti, t_expr) in terms.iter().enumerate() {
                    let _ = writeln!(self.out, "        terms_{s_idx}_{qi}[{ti}] = {t_expr};");
                }
            }
        }

        let has_any_queries = max_total_queries > 0;
        if has_any_queries {
            let _ = writeln!(
                self.out,
                "        BamQueryDesc qdescs_{s_idx}[{max_total_queries}u];"
            );
            let _ = writeln!(
                self.out,
                "        uint32_t q_count_{s_idx} = {ecs_q_count}u;"
            );
            for (qi, terms) in query_terms_c.iter().enumerate() {
                let _ = writeln!(
                    self.out,
                    "        memset(&qdescs_{s_idx}[{qi}], 0, sizeof(BamQueryDesc));"
                );
                let _ = writeln!(
                    self.out,
                    "        qdescs_{s_idx}[{qi}].struct_size = (uint32_t)sizeof(BamQueryDesc);"
                );
                let pset_group = query_param_set_groups.get(qi).copied().unwrap_or(0);
                if pset_group > 0 {
                    let _ = writeln!(
                        self.out,
                        "        qdescs_{s_idx}[{qi}].flags = BAM_QUERY_FLAG_PARAM_SET;"
                    );
                    let _ = writeln!(
                        self.out,
                        "        qdescs_{s_idx}[{qi}].param_set_group = {pset_group}u;"
                    );
                }
                if !terms.is_empty() {
                    let _ = writeln!(
                        self.out,
                        "        qdescs_{s_idx}[{qi}].terms = terms_{s_idx}_{qi};"
                    );
                    let _ = writeln!(
                        self.out,
                        "        qdescs_{s_idx}[{qi}].term_count = {}u;",
                        terms.len()
                    );
                }
            }
            if !res_modes.is_empty() {
                let res_cap = res_modes.len();
                let _ = writeln!(
                    self.out,
                    "        BamTermDesc res_terms_{s_idx}[{res_cap}u];"
                );
                let _ = writeln!(self.out, "        uint32_t res_n_{s_idx} = 0u;");
                for (&c_idx, &is_mut) in &res_modes {
                    let access = if is_mut {
                        "BAM_ACCESS_RESOURCE_WRITE"
                    } else {
                        "BAM_ACCESS_RESOURCE_READ"
                    };
                    let _ = writeln!(
                        self.out,
                        "        if (state->res_flags[{c_idx}] == 1u) {{ res_terms_{s_idx}[res_n_{s_idx}++] = bam_term_desc(state->components[{c_idx}], {access}, 0u); }}"
                    );
                }
                let _ = writeln!(
                    self.out,
                    "\
        uint32_t res_off_{s_idx} = 0u;
        while (res_off_{s_idx} < res_n_{s_idx} && q_count_{s_idx} < {max_total_queries}u) {{
            uint32_t chunk_n = res_n_{s_idx} - res_off_{s_idx};
            if (chunk_n > {MAX_TERMS_PER_QUERY}u) {{ chunk_n = {MAX_TERMS_PER_QUERY}u; }}
            memset(&qdescs_{s_idx}[q_count_{s_idx}], 0, sizeof(BamQueryDesc));
            qdescs_{s_idx}[q_count_{s_idx}].struct_size = (uint32_t)sizeof(BamQueryDesc);
            qdescs_{s_idx}[q_count_{s_idx}].terms = &res_terms_{s_idx}[res_off_{s_idx}];
            qdescs_{s_idx}[q_count_{s_idx}].term_count = chunk_n;
            q_count_{s_idx}++;
            res_off_{s_idx} += chunk_n;
        }}"
                );
            }
            if !msg_modes.is_empty() {
                let msg_cap = msg_modes.len();
                let _ = writeln!(
                    self.out,
                    "        BamTermDesc msg_terms_{s_idx}[{msg_cap}u];"
                );
                let _ = writeln!(self.out, "        uint32_t msg_n_{s_idx} = 0u;");
                for (&c_idx, &is_write) in &msg_modes {
                    let access = if is_write {
                        "BAM_ACCESS_MESSAGE_WRITE"
                    } else {
                        "BAM_ACCESS_MESSAGE_READ"
                    };
                    let _ = writeln!(
                        self.out,
                        "        if (state->res_flags[{c_idx}] == 2u) {{ state->sys_msg_ti[{s_idx}u * {comp_n}u + {c_idx}u] = msg_n_{s_idx} % {MAX_TERMS_PER_QUERY}u; msg_terms_{s_idx}[msg_n_{s_idx}++] = bam_term_desc(state->components[{c_idx}], {access}, 0u); }}"
                    );
                }
                let _ = writeln!(
                    self.out,
                    "\
        if (msg_n_{s_idx} > 0u && q_count_{s_idx} < {max_total_queries}u) {{
            state->sys_msg_q[{s_idx}] = q_count_{s_idx};
            uint32_t msg_off_{s_idx} = 0u;
            while (msg_off_{s_idx} < msg_n_{s_idx} && q_count_{s_idx} < {max_total_queries}u) {{
                uint32_t chunk_n = msg_n_{s_idx} - msg_off_{s_idx};
                if (chunk_n > {MAX_TERMS_PER_QUERY}u) {{ chunk_n = {MAX_TERMS_PER_QUERY}u; }}
                memset(&qdescs_{s_idx}[q_count_{s_idx}], 0, sizeof(BamQueryDesc));
                qdescs_{s_idx}[q_count_{s_idx}].struct_size = (uint32_t)sizeof(BamQueryDesc);
                qdescs_{s_idx}[q_count_{s_idx}].terms = &msg_terms_{s_idx}[msg_off_{s_idx}];
                qdescs_{s_idx}[q_count_{s_idx}].term_count = chunk_n;
                q_count_{s_idx}++;
                msg_off_{s_idx} += chunk_n;
            }}
        }}"
                );
            }
        }

        let q_ptr = if has_any_queries {
            format!("(q_count_{s_idx} > 0u) ? qdescs_{s_idx} : NULL")
        } else {
            "NULL".to_string()
        };
        let q_cnt = if has_any_queries {
            format!("q_count_{s_idx}")
        } else {
            "0u".to_string()
        };
        Ok((q_ptr, q_cnt))
    }

    pub(super) fn emit_register_single_system(
        &mut self,
        sys: &RegSystem,
    ) -> Result<(), CodegenError> {
        let s_idx = sys.idx;
        let _ = writeln!(self.out, "    /* System [{s_idx}]: {} */", sys.reg_name);
        let _ = writeln!(self.out, "    {{");

        let (q_ptr, q_cnt) = self.emit_fn_query_descs(
            s_idx,
            sys.mir_fn_idx,
            sys.is_startup_objects,
            &sys.run_if_resources,
            &format!("c99::system({})", sys.reg_name),
        )?;

        let reg_esc = c_escape(&sys.reg_name);
        let _ = writeln!(self.out, "        BamSystemDesc sdesc;");
        let _ = writeln!(
            self.out,
            "        memset(&sdesc, 0, sizeof(BamSystemDesc));"
        );
        let _ = writeln!(
            self.out,
            "        sdesc.struct_size = (uint32_t)sizeof(BamSystemDesc);"
        );
        let _ = writeln!(self.out, "        sdesc.flags = {};", sys.flags_expr);
        let _ = writeln!(self.out, "        sdesc.name = \"{reg_esc}\";");
        let _ = writeln!(self.out, "        sdesc.queries = {q_ptr};");
        let _ = writeln!(self.out, "        sdesc.query_count = {q_cnt};");
        let _ = writeln!(self.out, "        sdesc.callback = {};", sys.c_fn_name);
        let _ = writeln!(self.out, "        sdesc.user_data = state;");
        let _ = writeln!(self.out, "        sdesc.schedule = {};", sys.schedule);

        if !sys.after_names.is_empty() {
            let after_lits: Vec<String> = sys
                .after_names
                .iter()
                .map(|a| format!("\"{}\"", c_escape(a)))
                .collect();
            let _ = writeln!(
                self.out,
                "        static const char* const sys_after_{s_idx}[{}] = {{ {} }};",
                after_lits.len(),
                after_lits.join(", ")
            );
            let _ = writeln!(self.out, "        sdesc.after = sys_after_{s_idx};");
            let _ = writeln!(
                self.out,
                "        sdesc.after_count = {}u;",
                after_lits.len()
            );
        }
        if !sys.after_weak_names.is_empty() {
            let aw_lits: Vec<String> = sys
                .after_weak_names
                .iter()
                .map(|a| format!("\"{}\"", c_escape(a)))
                .collect();
            let _ = writeln!(
                self.out,
                "        static const char* const sys_after_weak_{s_idx}[{}] = {{ {} }};",
                aw_lits.len(),
                aw_lits.join(", ")
            );
            let _ = writeln!(
                self.out,
                "        sdesc.after_weak = sys_after_weak_{s_idx};"
            );
            let _ = writeln!(
                self.out,
                "        sdesc.after_weak_count = {}u;",
                aw_lits.len()
            );
        }
        if !sys.in_sets.is_empty() {
            let set_lits: Vec<String> = sys
                .in_sets
                .iter()
                .map(|n| format!("\"{}\"", c_escape(n)))
                .collect();
            let _ = writeln!(
                self.out,
                "        static const char* const sys_sets_{s_idx}[{}] = {{ {} }};",
                set_lits.len(),
                set_lits.join(", ")
            );
            let _ = writeln!(self.out, "        sdesc.in_sets = sys_sets_{s_idx};");
            let _ = writeln!(
                self.out,
                "        sdesc.in_set_count = {}u;",
                set_lits.len()
            );
        }
        if let Some(ref rif) = sys.run_if_fn {
            let _ = writeln!(
                self.out,
                "        /* Schedule condition `{rif}` enforced at entry of `{}`. */",
                sys.c_fn_name
            );
        }

        let free_net_rx = if has_net_protocol(self.mir) {
            "free(state->net_rx_buf); "
        } else {
            ""
        };
        let _ = writeln!(
            self.out,
            "\
        BamResult syarc = BAM_RESULT_UNSUPPORTED;
        if (api->register_system_handle != NULL && api->mount_system_in_schedule != NULL) {{
            syarc = api->register_system_handle(load_ctx, &sdesc, &state->systems[{s_idx}]);
            if (syarc == BAM_RESULT_OK) {{
                syarc = api->mount_system_in_schedule(load_ctx, state->systems[{s_idx}], {}, BAM_SYSTEM_SET_INVALID);
            }}
        }} else if (api->register_system != NULL) {{
            syarc = api->register_system(load_ctx, &sdesc);
        }}
        if (syarc != BAM_RESULT_OK) {{
            {free_net_rx}free(state);
            *instance_out = NULL;
            return syarc;
        }}",
            sys.schedule
        );
        let _ = writeln!(self.out, "    }}");
        Ok(())
    }
}
