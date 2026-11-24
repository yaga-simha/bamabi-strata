//! C99 per-function instruction, place, expression, and terminator emission.

use super::*;

pub(super) struct FnEmitCtx<'a, 'b> {
    pub(super) parent: &'a EmitCtx<'b>,
    pub(super) func: &'a MirFunction,
    pub(super) sys_idx: Option<usize>,
    pub(super) is_observer: bool,
    pub(super) is_migration: bool,
    pub(super) is_void_helper: bool,
    pub(super) is_helper: bool,
    pub(super) ptr_meta: HashMap<LocalId, PtrKind>,
    pub(super) restrict_cols: HashMap<LocalId, PtrKind>,
    pub(super) nonnull_cols: HashSet<LocalId>,
    pub(super) nonnull_ptrs: HashSet<LocalId>,
    pub(super) projected_fields: HashMap<LocalId, String>,
    pub(super) dirty_owners: HashMap<(u32, u32), Vec<(u32, u32)>>,
    pub(super) local_types: HashMap<LocalId, MirType>,
    pub(super) slot_types: HashMap<LocalId, MirType>,
    pub(super) const_defs: HashMap<LocalId, MirConstVal>,
    pub(super) array_inits: HashMap<LocalId, Vec<LocalId>>,
    pub(super) field_ptr_arrays: HashMap<LocalId, (Ty, usize)>,
    pub(super) last_checkpoint: Option<LocalId>,
    pub(super) par_query_idx: Option<u32>,
}

impl<'a, 'b> FnEmitCtx<'a, 'b> {
    pub(super) fn local_expr(&self, id: LocalId) -> String {
        if self.restrict_cols.contains_key(&id) {
            format!("col_{}", id.0)
        } else {
            format!("v_{}", id.0)
        }
    }

    pub(super) fn local_ty(&self, id: LocalId) -> Option<&MirType> {
        self.local_types.get(&id)
    }

    pub(super) fn unwrap_operand_expr(
        &self,
        id: LocalId,
        expected_vec: Option<&MirType>,
    ) -> String {
        let p = self.local_expr(id);
        if let Some(PtrKind::LayoutPtr { layout_idx, .. }) = self.ptr_meta.get(&id) {
            let layout = &self.parent.layouts[*layout_idx];
            if let Some(pf) = self.projected_fields.get(&id)
                && let Some(sf) = layout
                    .fields
                    .iter()
                    .find(|f| !f.is_padding && f.name == *pf)
            {
                let fc = sanitize_c_field(&sf.name);
                let z = self.parent.c_zero_for_sema(&sf.ty);
                return format!("({p} != NULL ? {p}->{fc} : {z})");
            }
            if let Some(exp) = expected_vec
                && let Some(sf) = layout
                    .fields
                    .iter()
                    .find(|f| !f.is_padding && ty_matches_sema(&f.ty, exp))
            {
                let fc = sanitize_c_field(&sf.name);
                let z = self.parent.c_zero_for_sema(&sf.ty);
                return format!("({p} != NULL ? {p}->{fc} : {z})");
            }
        }
        p
    }

    pub(super) fn effective_vec_ty(&self, id: LocalId) -> Option<MirType> {
        if let Some(PtrKind::LayoutPtr { layout_idx, .. }) = self.ptr_meta.get(&id) {
            for f in &self.parent.layouts[*layout_idx].fields {
                if !f.is_padding {
                    match f.ty {
                        Ty::Vec2 => return Some(MirType::Vec2),
                        Ty::Vec3 => return Some(MirType::Vec3),
                        Ty::Vec3a | Ty::Vec4 | Ty::Quat | Ty::Rgba => return Some(MirType::Vec4),
                        Ty::IVec2 => return Some(MirType::IVec2),
                        Ty::IVec3 => return Some(MirType::IVec3),
                        Ty::UVec2 => return Some(MirType::UVec2),
                        _ => {}
                    }
                }
            }
        }
        self.local_ty(id).cloned()
    }

    pub(super) fn ptr_c_ty(&self, id: LocalId) -> Option<String> {
        self.ptr_meta
            .get(&id)
            .map(|pk| pk.c_type(&self.parent.layout_c_names))
    }

    pub(super) fn projected_sema_ty(&self, id: LocalId) -> Option<&Ty> {
        let pf = self.projected_fields.get(&id)?;
        let Some(PtrKind::LayoutPtr { layout_idx, .. }) = self.ptr_meta.get(&id) else {
            return None;
        };
        let layout = &self.parent.layouts[*layout_idx];
        layout
            .fields
            .iter()
            .find(|f| !f.is_padding && f.name == *pf)
            .map(|f| &f.ty)
    }

    pub(super) fn operand_c_ty(&self, id: LocalId) -> String {
        if let Some(sty) = self.projected_sema_ty(id) {
            return self.parent.c_ty_from_sema(sty);
        }
        if let Some(pt) = self.ptr_c_ty(id) {
            return pt;
        }
        self.parent.c_ty(self.local_ty(id).unwrap_or(&MirType::I32))
    }

    pub(super) fn is_projected_aggregate(&self, id: LocalId) -> bool {
        let Some(sty) = self.projected_sema_ty(id) else {
            return false;
        };
        Self::is_sema_aggregate(self.parent, sty)
    }

    pub(super) fn is_sema_aggregate(parent: &EmitCtx<'_>, sty: &Ty) -> bool {
        matches!(
            sty,
            Ty::Vec2
                | Ty::Vec3
                | Ty::Vec3a
                | Ty::Vec4
                | Ty::Quat
                | Ty::Rgba
                | Ty::IVec2
                | Ty::IVec3
                | Ty::UVec2
                | Ty::Mat3
                | Ty::Mat4
        ) || matches!(sty, Ty::Named(key) if parent.find_layout_idx(key).is_some())
    }

    pub(super) fn coerce_scalar_to_fix_expr(
        &self,
        val: LocalId,
        src_ty: &MirType,
        is_fix64: bool,
    ) -> String {
        let ve = self.local_expr(val);
        if (is_fix64 && matches!(src_ty, MirType::Fix64))
            || (!is_fix64 && matches!(src_ty, MirType::Fix32))
        {
            return ve;
        }
        if !is_fix64 && matches!(src_ty, MirType::Fix64) {
            return format!("strata_fix64_to_fix32({ve})");
        }
        if is_fix64 && matches!(src_ty, MirType::Fix32) {
            return format!("strata_fix32_to_fix64({ve})");
        }
        if let Some(cv) = self.const_defs.get(&val) {
            let target = if is_fix64 { Ty::Fix64 } else { Ty::Fix32 };
            return self.parent.c_const_val_for_ty(&target, cv);
        }
        match src_ty {
            MirType::F32 | MirType::F64 => {
                if is_fix64 {
                    format!("strata_f64_to_fix64((double)({ve}))")
                } else {
                    format!("strata_f64_to_fix32((double)({ve}))")
                }
            }
            MirType::I8
            | MirType::I16
            | MirType::I32
            | MirType::I64
            | MirType::U8
            | MirType::U16
            | MirType::U32
            | MirType::U64
            | MirType::Bool => {
                if is_fix64 {
                    format!("((int64_t)((uint64_t)(int64_t)({ve}) << 32u))")
                } else {
                    format!("((int32_t)((uint32_t)(int32_t)({ve}) << 16u))")
                }
            }
            _ => ve,
        }
    }

    pub(super) fn c_const_val_for_mir_ty(&self, ty: &MirType, val: &MirConstVal) -> String {
        match (ty, val) {
            (MirType::Fix32, _) => self.parent.c_const_val_for_ty(&Ty::Fix32, val),
            (MirType::Fix64, _) => self.parent.c_const_val_for_ty(&Ty::Fix64, val),
            (MirType::F64, _) => self.parent.c_const_val_for_ty(&Ty::F64, val),
            (MirType::F32, _) => self.parent.c_const_val_for_ty(&Ty::F32, val),
            (MirType::Bool, _) => self.parent.c_const_val_for_ty(&Ty::Bool, val),
            (MirType::I8, _) => self.parent.c_const_val_for_ty(&Ty::I8, val),
            (MirType::I16, _) => self.parent.c_const_val_for_ty(&Ty::I16, val),
            (MirType::I32, _) => self.parent.c_const_val_for_ty(&Ty::I32, val),
            (MirType::I64, _) => self.parent.c_const_val_for_ty(&Ty::I64, val),
            (MirType::U8, _) => self.parent.c_const_val_for_ty(&Ty::U8, val),
            (MirType::U16, _) => self.parent.c_const_val_for_ty(&Ty::U16, val),
            (MirType::U32 | MirType::Sym, _) => self.parent.c_const_val_for_ty(&Ty::U32, val),
            (MirType::U64, _) => self.parent.c_const_val_for_ty(&Ty::U64, val),
            _ => self.parent.c_const_val(val),
        }
    }

    pub(super) fn emit_c_array_init_elem(
        &self,
        dst_lval: &str,
        dst_ty: &MirType,
        src_local: LocalId,
        s: &mut String,
    ) {
        if let MirType::Array {
            elem: inner_elem,
            len: inner_len,
        } = dst_ty
        {
            if self.local_ty(src_local) == Some(dst_ty) {
                let ev = self.local_expr(src_local);
                let _ = writeln!(s, "    {dst_lval} = {ev};");
            } else if let Some(sub_elems) = self.array_inits.get(&src_local).cloned() {
                for (j, sel) in sub_elems.iter().take(*inner_len).enumerate() {
                    self.emit_c_array_init_elem(
                        &format!("{dst_lval}.data[{j}]"),
                        inner_elem,
                        *sel,
                        s,
                    );
                }
            } else if let Some(MirType::Array {
                elem: src_elem,
                len: src_len,
            }) = self.local_ty(src_local).cloned()
                && src_len == *inner_len
            {
                let ev = self.local_expr(src_local);
                for j in 0..*inner_len {
                    let item = format!("{ev}.data[{j}]");
                    let rhs = match (src_elem.as_ref(), inner_elem.as_ref()) {
                        (MirType::F32 | MirType::F64, MirType::Fix32) => {
                            format!("strata_f64_to_fix32((double)({item}))")
                        }
                        (
                            MirType::I8
                            | MirType::I16
                            | MirType::I32
                            | MirType::I64
                            | MirType::U8
                            | MirType::U16
                            | MirType::U32
                            | MirType::U64,
                            MirType::Fix32,
                        ) => {
                            format!("(int32_t)((int64_t)({item}) * 65536ll)")
                        }
                        (MirType::F32 | MirType::F64, MirType::Fix64) => {
                            format!("strata_f64_to_fix64((double)({item}))")
                        }
                        (
                            MirType::I8
                            | MirType::I16
                            | MirType::I32
                            | MirType::I64
                            | MirType::U8
                            | MirType::U16
                            | MirType::U32
                            | MirType::U64,
                            MirType::Fix64,
                        ) => {
                            format!("(int64_t)((int64_t)({item}) * 4294967296ll)")
                        }
                        _ if src_elem != *inner_elem => {
                            let cty = self.parent.c_ty(inner_elem);
                            format!("({cty})({item})")
                        }
                        _ => item,
                    };
                    let _ = writeln!(s, "    {dst_lval}.data[{j}] = {rhs};");
                }
            } else {
                let ev = self.local_expr(src_local);
                let _ = writeln!(s, "    {dst_lval} = {ev};");
            }
            return;
        }
        if matches!(
            dst_ty,
            MirType::Fix32
                | MirType::Fix64
                | MirType::F32
                | MirType::F64
                | MirType::I8
                | MirType::I16
                | MirType::I32
                | MirType::I64
                | MirType::U8
                | MirType::U16
                | MirType::U32
                | MirType::U64
                | MirType::Bool
        ) {
            let rhs = self.coerce_local_to_mir_scalar(src_local, dst_ty);
            let _ = writeln!(s, "    {dst_lval} = {rhs};");
        } else {
            let ev = self.local_expr(src_local);
            let _ = writeln!(s, "    {dst_lval} = {ev};");
        }
    }

    pub(super) fn coerce_local_to_mir_scalar(&self, val: LocalId, dst_ty: &MirType) -> String {
        let src_ty = self.local_ty(val).cloned().unwrap_or(MirType::I32);
        let ve = self.local_expr(val);
        match dst_ty {
            MirType::Fix32 => self.coerce_scalar_to_fix_expr(val, &src_ty, false),
            MirType::Fix64 => self.coerce_scalar_to_fix_expr(val, &src_ty, true),
            MirType::F64 if !matches!(src_ty, MirType::F64) => {
                if let Some(cv) = self.const_defs.get(&val) {
                    self.parent.c_const_val_for_ty(&Ty::F64, cv)
                } else if matches!(src_ty, MirType::Fix32) {
                    format!("((double)({ve}) / 65536.0)")
                } else if matches!(src_ty, MirType::Fix64) {
                    format!("((double)({ve}) / 4294967296.0)")
                } else {
                    format!("(double)({ve})")
                }
            }
            MirType::Bool => format!("({ve}) ? BAM_TRUE : BAM_FALSE"),
            _ if matches!(src_ty, MirType::Fix32)
                && matches!(
                    dst_ty,
                    MirType::I8
                        | MirType::I16
                        | MirType::I32
                        | MirType::I64
                        | MirType::U8
                        | MirType::U16
                        | MirType::U32
                        | MirType::U64
                        | MirType::Sym
                ) =>
            {
                let cty = self.parent.c_ty(dst_ty);
                format!("(({cty})((int32_t)({ve}) / 65536))")
            }
            _ if matches!(src_ty, MirType::Fix64)
                && matches!(
                    dst_ty,
                    MirType::I8
                        | MirType::I16
                        | MirType::I32
                        | MirType::I64
                        | MirType::U8
                        | MirType::U16
                        | MirType::U32
                        | MirType::U64
                        | MirType::Sym
                ) =>
            {
                let cty = self.parent.c_ty(dst_ty);
                format!("(({cty})((int64_t)({ve}) / 4294967296ll))")
            }
            _ if matches!(src_ty, MirType::F32 | MirType::F64)
                && matches!(
                    dst_ty,
                    MirType::I8
                        | MirType::I16
                        | MirType::I32
                        | MirType::I64
                        | MirType::U8
                        | MirType::U16
                        | MirType::U32
                        | MirType::U64
                        | MirType::Sym
                ) =>
            {
                let helper = match dst_ty {
                    MirType::I8 => "strata_f64_to_i8",
                    MirType::I16 => "strata_f64_to_i16",
                    MirType::I32 => "strata_f64_to_i32",
                    MirType::I64 => "strata_f64_to_i64",
                    MirType::U8 => "strata_f64_to_u8",
                    MirType::U16 => "strata_f64_to_u16",
                    MirType::U64 => "strata_f64_to_u64",
                    _ => "strata_f64_to_u32",
                };
                format!("{helper}((double)({ve}))")
            }
            _ if &src_ty != dst_ty => {
                let cty = self.parent.c_ty(dst_ty);
                format!("({cty})({ve})")
            }
            _ => ve,
        }
    }

    pub(super) fn emit_c_array_bytes_write(
        &self,
        target: &str,
        f_ty: &Ty,
        fval: LocalId,
        indent: &str,
        s: &mut String,
    ) {
        if let Some(MirConstVal::Array(elems)) = self.const_defs.get(&fval) {
            let _ = writeln!(s, "{indent}memset({target}, 0, sizeof({target}));");
            self.parent
                .emit_c_array_field_init_to(s, indent, target, f_ty, Some(elems), 0);
            return;
        }
        self.emit_c_array_locals_write(target, f_ty, fval, 0, indent, s);
    }

    pub(super) fn emit_c_array_locals_write(
        &self,
        target: &str,
        f_ty: &Ty,
        fval: LocalId,
        flat_idx_base: usize,
        indent: &str,
        s: &mut String,
    ) {
        let Ty::Array { elem, len } = f_ty else {
            return;
        };
        if let Some(elem_locals) = self.array_inits.get(&fval) {
            if flat_idx_base == 0 && elem_locals.len() < *len {
                let _ = writeln!(s, "{indent}memset({target}, 0, sizeof({target}));");
            }
            if matches!(**elem, Ty::Array { .. }) {
                let mut stride = 1usize;
                let mut cur = &**elem;
                while let Ty::Array { elem: e, len: l } = cur {
                    stride *= *l;
                    cur = e;
                }
                for (i, &el) in elem_locals.iter().take(*len).enumerate() {
                    self.emit_c_array_locals_write(
                        target,
                        elem,
                        el,
                        flat_idx_base + i * stride,
                        indent,
                        s,
                    );
                }
            } else if let Ty::BitSet(bits) = &**elem {
                let bs_bytes = (*bits).div_ceil(32).max(1) * 4;
                for (ei, &el) in elem_locals.iter().take(*len).enumerate() {
                    let flat_ei = flat_idx_base + ei;
                    let el_expr = self.local_expr(el);
                    let _ = writeln!(
                        s,
                        "{indent}if (({flat_ei}u + 1u) * {bs_bytes}u <= sizeof({target})) {{ memset(&({target})[{flat_ei}u * {bs_bytes}u], 0, {bs_bytes}u); memcpy(&({target})[{flat_ei}u * {bs_bytes}u], &{el_expr}, {bs_bytes}u < sizeof({el_expr}) ? {bs_bytes}u : sizeof({el_expr})); }}"
                    );
                }
            } else {
                let elem_cty = self.parent.c_ty_from_sema(elem);
                for (ei, &el) in elem_locals.iter().take(*len).enumerate() {
                    let flat_ei = flat_idx_base + ei;
                    let el_ty = self.local_ty(el).cloned().unwrap_or(MirType::I32);
                    let rhs = match &**elem {
                        Ty::Fix32 => self.coerce_scalar_to_fix_expr(el, &el_ty, false),
                        Ty::Fix64 => self.coerce_scalar_to_fix_expr(el, &el_ty, true),
                        Ty::F64 if !matches!(el_ty, MirType::F64) => {
                            if let Some(cv) = self.const_defs.get(&el) {
                                self.parent.c_const_val_for_ty(elem, cv)
                            } else {
                                format!("(double)({})", self.local_expr(el))
                            }
                        }
                        Ty::Bool => format!("({}) ? BAM_TRUE : BAM_FALSE", self.local_expr(el)),
                        Ty::Named(key)
                            if self
                                .parent
                                .find_layout_idx(key)
                                .is_some_and(|li| self.parent.layouts[li].size > 0) =>
                        {
                            self.local_expr(el)
                        }
                        _ if self.is_c_scalar_field(elem, 4) => {
                            format!("({elem_cty})({})", self.local_expr(el))
                        }
                        _ => self.local_expr(el),
                    };
                    let ae_var = format!("_ae_{}", indent.len());
                    let _ = writeln!(
                        s,
                        "{indent}{{ {elem_cty} {ae_var} = {rhs}; if (({flat_ei}u + 1u) * sizeof({ae_var}) <= sizeof({target})) {{ memcpy(&({target})[{flat_ei}u * sizeof({ae_var})], &{ae_var}, sizeof({ae_var})); }} }}"
                    );
                }
            }
            return;
        }
        let vr = self.local_expr(fval);
        let src_ty = self.local_ty(fval).cloned();
        if !matches!(**elem, Ty::Array { .. })
            && let Some(MirType::Array {
                elem: src_elem,
                len: src_len,
            }) = src_ty
        {
            let copy_len = (*len).min(src_len);
            let need_fix_conv = matches!(
                (&**elem, &*src_elem),
                (Ty::Fix32, e) if !matches!(e, MirType::Fix32)
            ) || matches!(
                (&**elem, &*src_elem),
                (Ty::Fix64, e) if !matches!(e, MirType::Fix64)
            );
            if need_fix_conv {
                let elem_cty = self.parent.c_ty_from_sema(elem);
                let is_fix64 = matches!(**elem, Ty::Fix64);
                let conv = match &*src_elem {
                    MirType::F32 | MirType::F64 => {
                        if is_fix64 {
                            format!("strata_f64_to_fix64((double)({vr}.data[_ai]))")
                        } else {
                            format!("strata_f64_to_fix32((double)({vr}.data[_ai]))")
                        }
                    }
                    MirType::Fix32 if is_fix64 => {
                        format!("strata_fix32_to_fix64({vr}.data[_ai])")
                    }
                    MirType::Fix64 if !is_fix64 => {
                        format!("strata_fix64_to_fix32({vr}.data[_ai])")
                    }
                    _ => {
                        if is_fix64 {
                            format!("((int64_t)((uint64_t)(int64_t)({vr}.data[_ai]) << 32u))")
                        } else {
                            format!("((int32_t)((uint32_t)(int32_t)({vr}.data[_ai]) << 16u))")
                        }
                    }
                };
                if flat_idx_base == 0 {
                    let _ = writeln!(s, "{indent}memset({target}, 0, sizeof({target}));");
                }
                let ae_var = format!("_ae_{}", indent.len());
                let _ = writeln!(
                    s,
                    "{indent}{{ size_t _ai; for (_ai = 0u; _ai < {copy_len}u; ++_ai) {{ {elem_cty} {ae_var} = {conv}; size_t _fi = {flat_idx_base}u + _ai; if ((_fi + 1u) * sizeof({ae_var}) <= sizeof({target})) {{ memcpy(&({target})[_fi * sizeof({ae_var})], &{ae_var}, sizeof({ae_var})); }} }} }}"
                );
                return;
            }
        }
        let elem_bytes = match &**elem {
            Ty::Named(key) => self
                .parent
                .find_layout_idx(key)
                .map_or(4usize, |li| self.parent.layouts[li].size.max(1)),
            Ty::Fix64 | Ty::I64 | Ty::U64 | Ty::F64 | Ty::Vec2 | Ty::IVec2 | Ty::UVec2 => 8,
            Ty::Vec3 | Ty::IVec3 => 12,
            Ty::Vec4 | Ty::Vec3a | Ty::Quat | Ty::Rgba => 16,
            Ty::Bool | Ty::I8 | Ty::U8 => 1,
            Ty::I16 | Ty::U16 => 2,
            Ty::BitSet(bits) => (*bits).div_ceil(32).max(1) * 4,
            _ => 4,
        };
        let byte_off = flat_idx_base * elem_bytes;
        let _ = writeln!(
            s,
            "{indent}if ({byte_off}u < sizeof({target})) {{ size_t _avail = sizeof({target}) - {byte_off}u; size_t _cn = _avail < sizeof({vr}) ? _avail : sizeof({vr}); memcpy(&({target})[{byte_off}u], &{vr}, _cn); }}"
        );
    }

    pub(super) fn emit_c_slot_array_store(
        &self,
        ptr_expr: &str,
        dst_elem: &MirType,
        dst_len: usize,
        val: LocalId,
        indent: &str,
        s: &mut String,
    ) {
        if let Some(MirConstVal::Array(elems)) = self.const_defs.get(&val) {
            let _ = writeln!(s, "{indent}memset({ptr_expr}, 0, sizeof(*({ptr_expr})));");
            for (i, ev) in elems.iter().take(dst_len).enumerate() {
                if let MirType::Array {
                    elem: sub_e,
                    len: sub_l,
                } = dst_elem
                {
                    if let MirConstVal::Array(sub_elems) = ev {
                        self.emit_c_slot_array_const_elems(
                            &format!("(&({ptr_expr}->data[{i}]))"),
                            sub_e,
                            *sub_l,
                            sub_elems,
                            indent,
                            s,
                        );
                    }
                } else {
                    let rhs = self.c_const_val_for_mir_ty(dst_elem, ev);
                    let _ = writeln!(s, "{indent}{ptr_expr}->data[{i}] = {rhs};");
                }
            }
            return;
        }
        if let Some(elem_locals) = self.array_inits.get(&val) {
            let _ = writeln!(s, "{indent}memset({ptr_expr}, 0, sizeof(*({ptr_expr})));");
            for (i, &el) in elem_locals.iter().take(dst_len).enumerate() {
                if let MirType::Array {
                    elem: sub_e,
                    len: sub_l,
                } = dst_elem
                {
                    self.emit_c_slot_array_store(
                        &format!("(&({ptr_expr}->data[{i}]))"),
                        sub_e,
                        *sub_l,
                        el,
                        indent,
                        s,
                    );
                } else {
                    let rhs = self.coerce_local_to_mir_scalar(el, dst_elem);
                    let _ = writeln!(s, "{indent}{ptr_expr}->data[{i}] = {rhs};");
                }
            }
            return;
        }
        let ve = self.local_expr(val);
        let src_ty = self.local_ty(val).cloned();
        if src_ty.as_ref()
            == Some(&MirType::Array {
                elem: Box::new(dst_elem.clone()),
                len: dst_len,
            })
        {
            let _ = writeln!(s, "{indent}*({ptr_expr}) = {ve};");
        } else if let Some(MirType::Array {
            elem: src_elem,
            len: src_len,
        }) = src_ty
            && !matches!(dst_elem, MirType::Array { .. })
            && !matches!(&*src_elem, MirType::Array { .. })
        {
            let copy_len = dst_len.min(src_len);
            let _ = writeln!(s, "{indent}memset({ptr_expr}, 0, sizeof(*({ptr_expr})));");
            let conv = match dst_elem {
                MirType::Fix32 if !matches!(&*src_elem, MirType::Fix32) => match &*src_elem {
                    MirType::F32 | MirType::F64 => {
                        format!("strata_f64_to_fix32((double)({ve}.data[_ai]))")
                    }
                    MirType::Fix64 => format!("strata_fix64_to_fix32({ve}.data[_ai])"),
                    _ => format!("((int32_t)((uint32_t)(int32_t)({ve}.data[_ai]) << 16u))"),
                },
                MirType::Fix64 if !matches!(&*src_elem, MirType::Fix64) => match &*src_elem {
                    MirType::F32 | MirType::F64 => {
                        format!("strata_f64_to_fix64((double)({ve}.data[_ai]))")
                    }
                    MirType::Fix32 => format!("strata_fix32_to_fix64({ve}.data[_ai])"),
                    _ => format!("((int64_t)((uint64_t)(int64_t)({ve}.data[_ai]) << 32u))"),
                },
                _ => {
                    let cty = self.parent.c_ty(dst_elem);
                    format!("({cty})({ve}.data[_ai])")
                }
            };
            let _ = writeln!(
                s,
                "{indent}{{ size_t _ai; for (_ai = 0u; _ai < {copy_len}u; ++_ai) {{ {ptr_expr}->data[_ai] = {conv}; }} }}"
            );
        } else {
            let _ = writeln!(
                s,
                "{indent}memcpy({ptr_expr}, &{ve}, sizeof(*({ptr_expr})) < sizeof({ve}) ? sizeof(*({ptr_expr})) : sizeof({ve}));"
            );
        }
    }

    pub(super) fn emit_c_slot_array_const_elems(
        &self,
        ptr_expr: &str,
        dst_elem: &MirType,
        dst_len: usize,
        elems: &[MirConstVal],
        indent: &str,
        s: &mut String,
    ) {
        for (i, ev) in elems.iter().take(dst_len).enumerate() {
            if let MirType::Array {
                elem: sub_e,
                len: sub_l,
            } = dst_elem
            {
                if let MirConstVal::Array(sub_elems) = ev {
                    self.emit_c_slot_array_const_elems(
                        &format!("(&({ptr_expr}->data[{i}]))"),
                        sub_e,
                        *sub_l,
                        sub_elems,
                        indent,
                        s,
                    );
                }
            } else {
                let rhs = self.c_const_val_for_mir_ty(dst_elem, ev);
                let _ = writeln!(s, "{indent}{ptr_expr}->data[{i}] = {rhs};");
            }
        }
    }

    pub(super) fn emit_stmt(&self, stmt: &MirStmt, s: &mut String) -> Result<(), CodegenError> {
        let dst = stmt.dst;
        match &stmt.inst {
            Inst::ConstInt { value } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    match self.local_ty(d) {
                        Some(MirType::Fix32) => {
                            let q = (*value).saturating_mul(65_536) as i32;
                            let lit = c_i32_lit(q);
                            let _ = writeln!(s, "    {de} = {lit};");
                        }
                        Some(MirType::Fix64) => {
                            let q = value.wrapping_shl(32);
                            let lit = c_i64_lit(q);
                            let _ = writeln!(s, "    {de} = {lit};");
                        }
                        Some(MirType::I32) => {
                            let lit = c_i32_lit(*value as i32);
                            let _ = writeln!(s, "    {de} = {lit};");
                        }
                        Some(MirType::U32) => {
                            let v = *value as u32;
                            let _ = writeln!(s, "    {de} = {v}u;");
                        }
                        Some(MirType::I64) => {
                            let lit = c_i64_lit(*value);
                            let _ = writeln!(s, "    {de} = {lit};");
                        }
                        Some(MirType::U64) => {
                            let v = *value as u64;
                            let _ = writeln!(s, "    {de} = {v}ull;");
                        }
                        _ if *value == i64::MIN => {
                            let _ = writeln!(s, "    {de} = (-9223372036854775807ll - 1ll);");
                        }
                        _ => {
                            let _ = writeln!(s, "    {de} = {value};");
                        }
                    }
                }
            }
            Inst::ConstFloat { value } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    match self.local_ty(d) {
                        Some(MirType::F64) => {
                            let _ = writeln!(s, "    {de} = {};", c_f64(*value));
                        }
                        Some(MirType::Fix32) => {
                            let q = if value.is_finite() {
                                (*value * 65_536.0).round() as i32
                            } else {
                                0
                            };
                            let lit = c_i32_lit(q);
                            let _ = writeln!(s, "    {de} = {lit};");
                        }
                        Some(MirType::Fix64) => {
                            let q = if value.is_finite() {
                                (*value * 4_294_967_296.0).round() as i64
                            } else {
                                0
                            };
                            let lit = c_i64_lit(q);
                            let _ = writeln!(s, "    {de} = {lit};");
                        }
                        _ => {
                            let _ = writeln!(s, "    {de} = {};", c_f32(*value as f32));
                        }
                    }
                }
            }
            Inst::ConstBool { value } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let lit = if *value { "BAM_TRUE" } else { "BAM_FALSE" };
                    let _ = writeln!(s, "    {de} = {lit};");
                }
            }
            Inst::ConstVec { dims, values } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    match self.local_ty(d) {
                        Some(MirType::IVec2) => {
                            let _ = writeln!(
                                s,
                                "    {de} = strata_ivec2({}, {});",
                                c_i32_lit(values[0] as i32),
                                c_i32_lit(values[1] as i32)
                            );
                        }
                        Some(MirType::IVec3) => {
                            let _ = writeln!(
                                s,
                                "    {de} = strata_ivec3({}, {}, {});",
                                c_i32_lit(values[0] as i32),
                                c_i32_lit(values[1] as i32),
                                c_i32_lit(values[2] as i32)
                            );
                        }
                        Some(MirType::UVec2) => {
                            let _ = writeln!(
                                s,
                                "    {de} = strata_uvec2({}u, {}u);",
                                values[0] as u32, values[1] as u32
                            );
                        }
                        dty => {
                            let eff_dims = match dty {
                                Some(MirType::Vec2) => 2u8,
                                Some(MirType::Vec3) => 3u8,
                                Some(MirType::Vec4) => 4u8,
                                _ => *dims,
                            };
                            match eff_dims {
                                2 => {
                                    let _ = writeln!(
                                        s,
                                        "    {de} = strata_vec2({}, {});",
                                        c_f32(values[0] as f32),
                                        c_f32(values[1] as f32)
                                    );
                                }
                                3 => {
                                    let _ = writeln!(
                                        s,
                                        "    {de} = strata_vec3({}, {}, {});",
                                        c_f32(values[0] as f32),
                                        c_f32(values[1] as f32),
                                        c_f32(values[2] as f32)
                                    );
                                }
                                _ => {
                                    let _ = writeln!(
                                        s,
                                        "    {de} = strata_vec4({}, {}, {}, {});",
                                        c_f32(values[0] as f32),
                                        c_f32(values[1] as f32),
                                        c_f32(values[2] as f32),
                                        c_f32(values[3] as f32)
                                    );
                                }
                            }
                        }
                    }
                }
            }
            Inst::ConstString { value } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let esc = c_escape(value);
                    let _ = writeln!(s, "    {de} = (const void*)\"{esc}\";");
                }
            }
            Inst::Copy { val } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ve = self.local_expr(*val);
                    if let Some(dst_ptr_cty) = self.ptr_c_ty(d) {
                        let _ = writeln!(s, "    {de} = ({dst_ptr_cty}){ve};");
                    } else {
                        let _ = writeln!(s, "    {de} = {ve};");
                    }
                }
            }
            Inst::SlotAlloc { .. } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let sid = d.0;
                    if let Some(dst_ptr_cty) = self.ptr_c_ty(d) {
                        let _ = writeln!(s, "    {de} = ({dst_ptr_cty})&slot_buf_{sid};");
                    } else {
                        let _ = writeln!(s, "    {de} = &slot_buf_{sid};");
                    }
                }
            }
            Inst::SlotLoad { slot } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let se = self.local_expr(*slot);
                    let _ = writeln!(
                        s,
                        "    if ({se} != NULL) {{ memcpy(&{de}, {se}, sizeof({de})); }}"
                    );
                }
            }
            Inst::SlotStore { slot, val } => {
                let se = self.local_expr(*slot);
                let ve = self.local_expr(*val);
                let slot_ty_opt = self.slot_types.get(slot).cloned();
                let src_ty = self.local_ty(*val).cloned().unwrap_or(MirType::I32);
                match slot_ty_opt {
                    Some(MirType::Fix32) => {
                        let rhs = self.coerce_scalar_to_fix_expr(*val, &src_ty, false);
                        let _ = writeln!(
                            s,
                            "    if ({se} != NULL) {{ int32_t _sv = {rhs}; memcpy({se}, &_sv, sizeof(_sv)); }}"
                        );
                    }
                    Some(MirType::Fix64) => {
                        let rhs = self.coerce_scalar_to_fix_expr(*val, &src_ty, true);
                        let _ = writeln!(
                            s,
                            "    if ({se} != NULL) {{ int64_t _sv = {rhs}; memcpy({se}, &_sv, sizeof(_sv)); }}"
                        );
                    }
                    Some(MirType::F64) if !matches!(src_ty, MirType::F64) => {
                        let rhs = if let Some(cv) = self.const_defs.get(val) {
                            self.parent.c_const_val_for_ty(&Ty::F64, cv)
                        } else if matches!(src_ty, MirType::Fix32) {
                            format!("((double)({ve}) / 65536.0)")
                        } else if matches!(src_ty, MirType::Fix64) {
                            format!("((double)({ve}) / 4294967296.0)")
                        } else {
                            format!("(double)({ve})")
                        };
                        let _ = writeln!(
                            s,
                            "    if ({se} != NULL) {{ double _sv = {rhs}; memcpy({se}, &_sv, sizeof(_sv)); }}"
                        );
                    }
                    Some(MirType::Array { elem, len }) => {
                        let _ = writeln!(s, "    if ({se} != NULL) {{");
                        self.emit_c_slot_array_store(&se, &elem, len, *val, "        ", s);
                        let _ = writeln!(s, "    }}");
                    }
                    Some(ref st_ty)
                        if st_ty != &src_ty
                            && !self.is_ptr_local(*val)
                            && !self.parent.is_aggregate_mir_ty(st_ty)
                            && !self.parent.is_aggregate_mir_ty(&src_ty) =>
                    {
                        let dst_cty = self.parent.c_ty(st_ty);
                        let rhs = self.coerce_local_to_mir_scalar(*val, st_ty);
                        let _ = writeln!(
                            s,
                            "    if ({se} != NULL) {{ {dst_cty} _sv = ({dst_cty})({rhs}); memcpy({se}, &_sv, sizeof(_sv)); }}"
                        );
                    }
                    _ => {
                        let _ = writeln!(
                            s,
                            "    if ({se} != NULL) {{ memcpy({se}, &{ve}, sizeof({ve})); }}"
                        );
                    }
                }
            }
            Inst::BinOp { op, lhs, rhs, .. } => {
                if let Some(d) = dst {
                    self.emit_binop(d, op, *lhs, *rhs, s)?;
                }
            }
            Inst::UnOp { op, val } => {
                if let Some(d) = dst {
                    self.emit_unop(d, op, *val, s);
                }
            }
            Inst::Cast { val, target_ty } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ve = self.local_expr(*val);
                    let src_ty = self.local_ty(*val).cloned().unwrap_or(MirType::I32);
                    let cty = self.parent.c_ty(target_ty);
                    match target_ty {
                        MirType::Fix32 => {
                            let rhs = self.coerce_scalar_to_fix_expr(*val, &src_ty, false);
                            let _ = writeln!(s, "    {de} = {rhs};");
                        }
                        MirType::Fix64 => {
                            let rhs = self.coerce_scalar_to_fix_expr(*val, &src_ty, true);
                            let _ = writeln!(s, "    {de} = {rhs};");
                        }
                        MirType::F64 => {
                            let rhs = self.coerce_local_to_mir_scalar(*val, target_ty);
                            let _ = writeln!(s, "    {de} = {rhs};");
                        }
                        MirType::F32 if matches!(src_ty, MirType::Fix32 | MirType::Fix64) => {
                            let scale = if matches!(src_ty, MirType::Fix64) {
                                "4294967296.0"
                            } else {
                                "65536.0"
                            };
                            let _ = writeln!(s, "    {de} = ((float)((double)({ve}) / {scale}));");
                        }
                        MirType::Bool => {
                            let _ = writeln!(s, "    {de} = ({ve}) ? BAM_TRUE : BAM_FALSE;");
                        }
                        _ => {
                            if matches!(src_ty, MirType::Fix32)
                                && matches!(
                                    target_ty,
                                    MirType::I8
                                        | MirType::I16
                                        | MirType::I32
                                        | MirType::I64
                                        | MirType::U8
                                        | MirType::U16
                                        | MirType::U32
                                        | MirType::U64
                                        | MirType::Sym
                                )
                            {
                                let _ = writeln!(s, "    {de} = ({cty})((int32_t)({ve}) / 65536);");
                            } else if matches!(src_ty, MirType::Fix64)
                                && matches!(
                                    target_ty,
                                    MirType::I8
                                        | MirType::I16
                                        | MirType::I32
                                        | MirType::I64
                                        | MirType::U8
                                        | MirType::U16
                                        | MirType::U32
                                        | MirType::U64
                                        | MirType::Sym
                                )
                            {
                                let _ = writeln!(
                                    s,
                                    "    {de} = ({cty})((int64_t)({ve}) / 4294967296ll);"
                                );
                            } else if matches!(src_ty, MirType::F32 | MirType::F64)
                                && matches!(
                                    target_ty,
                                    MirType::U8
                                        | MirType::U16
                                        | MirType::U32
                                        | MirType::U64
                                        | MirType::Sym
                                )
                            {
                                let helper = match target_ty {
                                    MirType::U8 => "strata_f64_to_u8",
                                    MirType::U16 => "strata_f64_to_u16",
                                    MirType::U64 => "strata_f64_to_u64",
                                    _ => "strata_f64_to_u32",
                                };
                                let _ = writeln!(s, "    {de} = {helper}((double)({ve}));");
                            } else if matches!(src_ty, MirType::F32 | MirType::F64)
                                && matches!(
                                    target_ty,
                                    MirType::I8 | MirType::I16 | MirType::I32 | MirType::I64
                                )
                            {
                                let helper = match target_ty {
                                    MirType::I8 => "strata_f64_to_i8",
                                    MirType::I16 => "strata_f64_to_i16",
                                    MirType::I32 => "strata_f64_to_i32",
                                    _ => "strata_f64_to_i64",
                                };
                                let _ = writeln!(s, "    {de} = {helper}((double)({ve}));");
                            } else {
                                let _ = writeln!(s, "    {de} = ({cty})({ve});");
                            }
                        }
                    }
                }
            }
            Inst::VecExtract { vec, lane } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ve = self.local_expr(*vec);
                    let field = lane_name(*lane);
                    let _ = writeln!(s, "    {de} = {ve}.{field};");
                }
            }
            Inst::VecInsert { vec, lane, val } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ve = self.local_expr(*vec);
                    let vle = self.local_expr(*val);
                    let field = lane_name(*lane);
                    let _ = writeln!(s, "    {de} = {ve};\n    {de}.{field} = {vle};");
                }
            }
            Inst::VecSwizzle { vec, lanes } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ve = self.local_expr(*vec);
                    match (self.local_ty(d), lanes.len()) {
                        (Some(MirType::IVec2), 2) => {
                            let _ = writeln!(
                                s,
                                "    {de} = strata_ivec2({ve}.{}, {ve}.{});",
                                lane_name(lanes[0]),
                                lane_name(lanes[1])
                            );
                        }
                        (Some(MirType::UVec2), 2) => {
                            let _ = writeln!(
                                s,
                                "    {de} = strata_uvec2({ve}.{}, {ve}.{});",
                                lane_name(lanes[0]),
                                lane_name(lanes[1])
                            );
                        }
                        (Some(MirType::IVec3), 3) => {
                            let _ = writeln!(
                                s,
                                "    {de} = strata_ivec3({ve}.{}, {ve}.{}, {ve}.{});",
                                lane_name(lanes[0]),
                                lane_name(lanes[1]),
                                lane_name(lanes[2])
                            );
                        }
                        (_, 2) => {
                            let _ = writeln!(
                                s,
                                "    {de} = strata_vec2({ve}.{}, {ve}.{});",
                                lane_name(lanes[0]),
                                lane_name(lanes[1])
                            );
                        }
                        (_, 3) => {
                            let _ = writeln!(
                                s,
                                "    {de} = strata_vec3({ve}.{}, {ve}.{}, {ve}.{});",
                                lane_name(lanes[0]),
                                lane_name(lanes[1]),
                                lane_name(lanes[2])
                            );
                        }
                        _ => {
                            let l0 = lane_name(*lanes.first().unwrap_or(&0));
                            let l1 = lane_name(*lanes.get(1).unwrap_or(&0));
                            let l2 = lane_name(*lanes.get(2).unwrap_or(&0));
                            let l3 = lane_name(*lanes.get(3).unwrap_or(&0));
                            let _ = writeln!(
                                s,
                                "    {de} = strata_vec4({ve}.{l0}, {ve}.{l1}, {ve}.{l2}, {ve}.{l3});"
                            );
                        }
                    }
                }
            }
            Inst::IntrinsicMath { name, args, .. } => {
                if let Some(d) = dst {
                    self.emit_intrinsic_math(d, name, args, s);
                }
            }
            Inst::Call { callee, args } => {
                self.emit_call(dst, callee, args, s)?;
            }
            Inst::StructInit { type_name, fields } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let _ = writeln!(s, "    memset(&{de}, 0, sizeof({de}));");
                    if let Some(l_idx) = self.parent.find_layout_idx(type_name) {
                        let layout = &self.parent.layouts[l_idx];
                        let short = short_name(&layout.canonical_name);
                        if layout.size > 0 {
                            let def_fn =
                                format!("strata_default_{l_idx}_{}", sanitize_ident(short));
                            let _ = writeln!(s, "    {de} = {def_fn}();");
                        }
                        let defs_opt = self
                            .parent
                            .mir
                            .field_defaults
                            .get(&layout.canonical_name)
                            .or_else(|| self.parent.mir.field_defaults.get(short));
                        for (fname, fval) in fields {
                            if let Some(cv) = self.const_defs.get(fval)
                                && let Some(dval) = defs_opt.and_then(|defs| defs.get(fname))
                                && mir_const_vals_match(cv, dval)
                            {
                                continue;
                            }
                            let fc = sanitize_c_field(fname);
                            let vr = self.local_expr(*fval);
                            let src_ty = self.local_ty(*fval).cloned().unwrap_or(MirType::I32);
                            let sf_opt = layout
                                .fields
                                .iter()
                                .find(|sf| !sf.is_padding && sf.name == *fname);
                            if let Some(sf) = sf_opt {
                                match &sf.ty {
                                    Ty::Fix32 => {
                                        let rhs =
                                            self.coerce_scalar_to_fix_expr(*fval, &src_ty, false);
                                        let _ = writeln!(s, "    {de}.{fc} = {rhs};");
                                    }
                                    Ty::Fix64 => {
                                        let rhs =
                                            self.coerce_scalar_to_fix_expr(*fval, &src_ty, true);
                                        let _ = writeln!(s, "    {de}.{fc} = {rhs};");
                                    }
                                    Ty::F64 if !matches!(src_ty, MirType::F64) => {
                                        let rhs = if let Some(cv) = self.const_defs.get(fval) {
                                            self.parent.c_const_val_for_ty(&Ty::F64, cv)
                                        } else if matches!(src_ty, MirType::Fix32) {
                                            format!("((double)({vr}) / 65536.0)")
                                        } else if matches!(src_ty, MirType::Fix64) {
                                            format!("((double)({vr}) / 4294967296.0)")
                                        } else {
                                            format!("(double)({vr})")
                                        };
                                        let _ = writeln!(s, "    {de}.{fc} = {rhs};");
                                    }
                                    Ty::Array { .. } => {
                                        self.emit_c_array_bytes_write(
                                            &format!("{de}.{fc}"),
                                            &sf.ty,
                                            *fval,
                                            "    ",
                                            s,
                                        );
                                    }
                                    Ty::BitSet(_) => {
                                        if !matches!(src_ty, MirType::Array { .. })
                                            && let Some(cv) = self.const_defs.get(fval)
                                        {
                                            self.parent.emit_c_field_default_init(
                                                s,
                                                "    ",
                                                &format!("{de}.{fc}"),
                                                &sf.ty,
                                                sf.size,
                                                Some(cv),
                                                false,
                                            );
                                        } else {
                                            let _ = writeln!(
                                                s,
                                                "    memset(&{de}.{fc}, 0, sizeof({de}.{fc})); memcpy(&{de}.{fc}, &{vr}, sizeof({de}.{fc}) < sizeof({vr}) ? sizeof({de}.{fc}) : sizeof({vr}));"
                                            );
                                        }
                                    }
                                    Ty::Named(key)
                                        if self.parent.find_layout_idx(key).is_some_and(|li| {
                                            self.parent.layouts[li].size == sf.size
                                        }) =>
                                    {
                                        if self.is_ptr_local(*fval) {
                                            let _ = writeln!(
                                                s,
                                                "    if ({vr} != NULL) {{ memcpy(&{de}.{fc}, {vr}, sizeof({de}.{fc})); }}"
                                            );
                                        } else {
                                            let _ = writeln!(s, "    {de}.{fc} = {vr};");
                                        }
                                    }
                                    Ty::IVec2
                                    | Ty::IVec3
                                    | Ty::UVec2
                                    | Ty::SmallVec { .. }
                                    | Ty::InlineStr(_)
                                    | Ty::GraceWindow
                                    | Ty::InputBuffer { .. } => {
                                        if self.is_ptr_local(*fval) {
                                            let _ = writeln!(
                                                s,
                                                "    if ({vr} != NULL) {{ memcpy(&{de}.{fc}, {vr}, sizeof({de}.{fc})); }}"
                                            );
                                        } else {
                                            let _ = writeln!(
                                                s,
                                                "    memcpy(&{de}.{fc}, &{vr}, sizeof({de}.{fc}) < sizeof({vr}) ? sizeof({de}.{fc}) : sizeof({vr}));"
                                            );
                                        }
                                    }
                                    Ty::Bool => {
                                        let _ = writeln!(
                                            s,
                                            "    {de}.{fc} = ({vr}) ? BAM_TRUE : BAM_FALSE;"
                                        );
                                    }
                                    _ if self.is_c_scalar_field(&sf.ty, sf.size) => {
                                        let fcty = self.c_field_scalar_ty(&sf.ty, sf.size);
                                        let _ = writeln!(s, "    {de}.{fc} = ({fcty})({vr});");
                                    }
                                    _ => {
                                        let _ = writeln!(s, "    {de}.{fc} = {vr};");
                                    }
                                }
                            } else {
                                let _ = writeln!(s, "    {de}.{fc} = {vr};");
                            }
                        }
                    } else if type_name == "tuple"
                        && let Some(MirType::Tuple(elem_tys)) = self.local_ty(d).cloned()
                    {
                        for (idx, (_, fval)) in fields.iter().enumerate() {
                            if let Some(et) = elem_tys.get(idx) {
                                self.emit_c_array_init_elem(&format!("{de}.f{idx}"), et, *fval, s);
                            }
                        }
                    }
                }
            }
            Inst::ArrayInit { elems } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let _ = writeln!(s, "    memset(&{de}, 0, sizeof({de}));");
                    if let Some(MirType::Array { elem, .. }) = self.local_ty(d).cloned() {
                        for (i, el) in elems.iter().enumerate() {
                            self.emit_c_array_init_elem(&format!("{de}.data[{i}]"), &elem, *el, s);
                        }
                    } else {
                        for (i, el) in elems.iter().enumerate() {
                            let ev = self.local_expr(*el);
                            let _ = writeln!(s, "    {de}.data[{i}] = {ev};");
                        }
                    }
                }
            }
            Inst::ArrayIndex { base, index } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let be = self.local_expr(*base);
                    let ie = self.local_expr(*index);
                    let bty = self.local_ty(*base);
                    if matches!(bty, Some(MirType::Array { .. })) {
                        let _ = writeln!(s, "    {de} = {be}.data[{ie}];");
                    } else {
                        let _ = writeln!(
                            s,
                            "    if ({be} != NULL) {{ memcpy(&{de}, ((const uint8_t*){be}) + ((size_t)({ie}) * sizeof({de})), sizeof({de})); }}"
                        );
                    }
                }
            }
            Inst::ArrayStore {
                base_ptr,
                index,
                val,
                elem_ty,
            } => {
                let be = self.local_expr(*base_ptr);
                let ie = self.local_expr(*index);
                let ve = self.local_expr(*val);
                let vty = self
                    .local_ty(*val)
                    .cloned()
                    .unwrap_or_else(|| elem_ty.clone());
                let idx_is_signed = matches!(
                    self.local_ty(*index),
                    Some(MirType::I8 | MirType::I16 | MirType::I32 | MirType::I64)
                );
                let nonneg_guard = if idx_is_signed {
                    format!("((int64_t)({ie}) >= 0ll) && ")
                } else {
                    String::new()
                };
                if let Some(MirType::Array { elem, len }) = self.slot_types.get(base_ptr).cloned() {
                    let rhs = match &*elem {
                        MirType::Fix32 => self.coerce_scalar_to_fix_expr(*val, &vty, false),
                        MirType::Fix64 => self.coerce_scalar_to_fix_expr(*val, &vty, true),
                        MirType::Bool => format!("({ve}) ? BAM_TRUE : BAM_FALSE"),
                        _ if vty != *elem
                            && !self.parent.is_aggregate_mir_ty(&elem)
                            && !self.parent.is_aggregate_mir_ty(&vty) =>
                        {
                            self.coerce_local_to_mir_scalar(*val, &elem)
                        }
                        _ => ve,
                    };
                    let _ = writeln!(
                        s,
                        "    if ({be} != NULL && {nonneg_guard}(size_t)({ie}) < {len}u) {{ {be}->data[(size_t)({ie})] = {rhs}; }}"
                    );
                } else if let Some((sema_elem, arr_len)) =
                    self.field_ptr_arrays.get(base_ptr).cloned()
                {
                    let elem_cty = self.parent.c_ty_from_sema(&sema_elem);
                    let rhs = match &sema_elem {
                        Ty::Fix32 => self.coerce_scalar_to_fix_expr(*val, &vty, false),
                        Ty::Fix64 => self.coerce_scalar_to_fix_expr(*val, &vty, true),
                        Ty::F64 if !matches!(vty, MirType::F64) => format!("(double)({ve})"),
                        Ty::Bool => format!("({ve}) ? BAM_TRUE : BAM_FALSE"),
                        _ if !Self::is_sema_aggregate(self.parent, &sema_elem) => {
                            format!("({elem_cty})({ve})")
                        }
                        _ => ve,
                    };
                    let _ = writeln!(
                        s,
                        "    if ({be} != NULL && {nonneg_guard}(size_t)({ie}) < {arr_len}u) {{ {elem_cty} _asv = {rhs}; memcpy(((uint8_t*){be}) + ((size_t)({ie}) * sizeof(_asv)), &_asv, sizeof(_asv)); }}"
                    );
                } else {
                    let elem_cty = self.parent.c_ty(elem_ty);
                    let rhs = match elem_ty {
                        MirType::Fix32 => self.coerce_scalar_to_fix_expr(*val, &vty, false),
                        MirType::Fix64 => self.coerce_scalar_to_fix_expr(*val, &vty, true),
                        MirType::Bool => format!("({ve}) ? BAM_TRUE : BAM_FALSE"),
                        _ if vty != *elem_ty
                            && !self.parent.is_aggregate_mir_ty(elem_ty)
                            && !self.parent.is_aggregate_mir_ty(&vty) =>
                        {
                            self.coerce_local_to_mir_scalar(*val, elem_ty)
                        }
                        _ => ve,
                    };
                    let _ = writeln!(
                        s,
                        "    if ({be} != NULL && {nonneg_guard}1) {{ {elem_cty} _asv = {rhs}; memcpy(((uint8_t*){be}) + ((size_t)({ie}) * sizeof(_asv)), &_asv, sizeof(_asv)); }}"
                    );
                }
            }
            Inst::FieldPtr {
                base_ptr,
                layout_key,
                field,
                offset_bytes,
            } => {
                if let Some(d) = dst {
                    self.emit_field_ptr(d, *base_ptr, layout_key, field, *offset_bytes, s);
                }
            }
            Inst::FieldLoad {
                base_ptr,
                layout_key,
                field,
                offset_bytes,
                field_ty,
            } => {
                if let Some(d) = dst {
                    self.emit_field_load(
                        d,
                        *base_ptr,
                        layout_key,
                        field,
                        *offset_bytes,
                        field_ty,
                        s,
                    );
                }
            }
            Inst::FieldStore {
                base_ptr,
                layout_key,
                field,
                offset_bytes,
                val,
            } => {
                self.emit_field_store(*base_ptr, layout_key, field, *offset_bytes, *val, s);
            }
            Inst::RowPtr {
                col_ptr,
                row_idx,
                stride_bytes,
                is_sparse,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ce = self.local_expr(*col_ptr);
                    let re = self.local_expr(*row_idx);
                    let dst_cty = self.ptr_c_ty(d).unwrap_or_else(|| "void*".to_string());
                    let col_sparse =
                        matches!(self.ptr_meta.get(col_ptr), Some(PtrKind::SparseRows { .. }))
                            || (*is_sparse && !self.ptr_meta.contains_key(col_ptr));
                    if col_sparse {
                        let _ = writeln!(
                            s,
                            "    {de} = ({ce} != NULL) ? ({dst_cty})(((const uint8_t* const*){ce})[{re}]) : NULL;"
                        );
                    } else if self.restrict_cols.contains_key(col_ptr) {
                        if self.nonnull_ptrs.contains(col_ptr) {
                            let _ = writeln!(s, "    {de} = ({dst_cty})(&{ce}[{re}]);");
                        } else {
                            let _ = writeln!(
                                s,
                                "    {de} = ({ce} != NULL) ? ({dst_cty})(&{ce}[{re}]) : NULL;"
                            );
                        }
                    } else if self.nonnull_ptrs.contains(col_ptr) {
                        let _ = writeln!(
                            s,
                            "    {de} = ({dst_cty})(((const uint8_t*){ce}) + ((size_t){re} * {stride_bytes}u));"
                        );
                    } else {
                        let _ = writeln!(
                            s,
                            "    {de} = ({ce} != NULL) ? ({dst_cty})(((const uint8_t*){ce}) + ((size_t){re} * {stride_bytes}u)) : NULL;"
                        );
                    }
                }
            }
            Inst::IterNextChunk { query_idx } => {
                let qi = *query_idx;
                let dh = dst
                    .map(|d| self.local_expr(d))
                    .unwrap_or_else(|| "_unused_has_chunk".to_string());
                if dst.is_none() {
                    let _ = writeln!(s, "    {{ BamBool _unused_has_chunk = BAM_FALSE;");
                }
                let _ = writeln!(
                    s,
                    "    iter_{qi}_len = 0u;\n    {dh} = BAM_FALSE;\n    if (state->api->iter_next_chunk != NULL) {{\n        if (iter_{qi} == NULL && sys_ctx != NULL && state->api->sys_query != NULL) {{\n            (void)state->api->sys_query(sys_ctx, {qi}u, &iter_{qi});\n        }}\n        if (iter_{qi} != NULL) {{\n            while (state->api->iter_next_chunk(iter_{qi}, &iter_{qi}_len) != BAM_FALSE) {{\n                if (iter_{qi}_len > 0u) {{\n                    {dh} = BAM_TRUE;\n                    break;\n                }}\n            }}\n        }}\n    }}"
                );
                if dst.is_none() {
                    let _ = writeln!(s, "    (void)_unused_has_chunk; }}");
                }
            }
            Inst::IterChunkLen { query_idx } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let _ = writeln!(s, "    {de} = (uint32_t)iter_{query_idx}_len;");
                }
            }
            Inst::IterEntities { query_idx } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let _ = writeln!(
                        s,
                        "    iter_{query_idx}_ents = (iter_{query_idx} != NULL && state->api->iter_entities != NULL) ? state->api->iter_entities(iter_{query_idx}) : NULL;\n    {de} = iter_{query_idx}_ents;"
                    );
                }
            }
            Inst::EntityAtRow {
                entities_ptr,
                row_idx,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ep = self.local_expr(*entities_ptr);
                    let re = self.local_expr(*row_idx);
                    let _ = writeln!(
                        s,
                        "    {de} = ({ep} != NULL) ? ((const BamEntity*){ep})[{re}] : BAM_ENTITY_NULL;"
                    );
                    if let Some(qi) = self.par_query_idx {
                        let _ = writeln!(s, "    iter_{qi}_cur_ent = {de};");
                    } else {
                        for qb in &self.func.query_bindings {
                            let _ = writeln!(s, "    iter_{}_cur_ent = {de};", qb.query_idx);
                        }
                    }
                }
            }
            Inst::IterColRead {
                query_idx,
                term_idx,
                ..
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let is_sparse = self
                        .func
                        .query_bindings
                        .iter()
                        .find(|qb| qb.query_idx == *query_idx)
                        .and_then(|qb| qb.terms.iter().find(|t| t.term_idx == *term_idx))
                        .is_some_and(|t| t.is_sparse);
                    if is_sparse {
                        let _ = writeln!(
                            s,
                            "    {de} = (iter_{query_idx} != NULL && state->api->iter_column_rows_readonly != NULL) ? (const void*)state->api->iter_column_rows_readonly(iter_{query_idx}, {term_idx}u) : NULL;"
                        );
                    } else {
                        let cty = self
                            .ptr_c_ty(d)
                            .unwrap_or_else(|| "const void*".to_string());
                        let _ = writeln!(
                            s,
                            "    {de} = (iter_{query_idx} != NULL && state->api->iter_column_readonly != NULL) ? ({cty})state->api->iter_column_readonly(iter_{query_idx}, {term_idx}u) : NULL;"
                        );
                        if self.nonnull_cols.contains(&d) {
                            let _ = writeln!(
                                s,
                                "    if ({de} == NULL) {{ return BAM_RESULT_NULL_POINTER; }}"
                            );
                        }
                    }
                }
            }
            Inst::IterColWrite {
                query_idx,
                term_idx,
                ..
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let is_sparse = self
                        .func
                        .query_bindings
                        .iter()
                        .find(|qb| qb.query_idx == *query_idx)
                        .and_then(|qb| qb.terms.iter().find(|t| t.term_idx == *term_idx))
                        .is_some_and(|t| t.is_sparse);
                    if is_sparse {
                        let _ = writeln!(
                            s,
                            "    {de} = (iter_{query_idx} != NULL && state->api->iter_column_rows_mutable != NULL) ? (void*)state->api->iter_column_rows_mutable(iter_{query_idx}, {term_idx}u) : NULL;"
                        );
                    } else {
                        let cty = self.ptr_c_ty(d).unwrap_or_else(|| "void*".to_string());
                        let _ = writeln!(
                            s,
                            "    {de} = (iter_{query_idx} != NULL && state->api->iter_column_mutable != NULL) ? ({cty})state->api->iter_column_mutable(iter_{query_idx}, {term_idx}u) : NULL;"
                        );
                        if self.nonnull_cols.contains(&d) {
                            let _ = writeln!(
                                s,
                                "    if ({de} == NULL) {{ return BAM_RESULT_NULL_POINTER; }}"
                            );
                        }
                    }
                }
            }
            Inst::IterColWriteUntracked {
                query_idx,
                term_idx,
                ..
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let cty = self.ptr_c_ty(d).unwrap_or_else(|| "void*".to_string());
                    let _ = writeln!(
                        s,
                        "    {de} = (iter_{query_idx} != NULL && state->api->iter_column_mutable_untracked != NULL) ? ({cty})state->api->iter_column_mutable_untracked(iter_{query_idx}, {term_idx}u) : NULL;"
                    );
                    if self.nonnull_cols.contains(&d) {
                        let _ = writeln!(
                            s,
                            "    if ({de} == NULL) {{ return BAM_RESULT_NULL_POINTER; }}"
                        );
                    }
                }
            }
            Inst::IterMarkChangedRange {
                query_idx,
                term_idx,
                run_start,
                run_len,
            } => {
                let rs = self.local_expr(*run_start);
                let rl = self.local_expr(*run_len);
                let _ = writeln!(
                    s,
                    "    if ({rl} > 0u && iter_{query_idx} != NULL && state->api->iter_mark_changed_range != NULL) {{\n        (void)state->api->iter_mark_changed_range(iter_{query_idx}, {term_idx}u, (size_t){rs}, (size_t){rl});\n    }}"
                );
            }
            Inst::IterColRowsRead {
                query_idx,
                term_idx,
                storage_key,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    if self.parent.is_query_term_sparse(
                        self.func,
                        *query_idx,
                        *term_idx,
                        storage_key,
                    ) {
                        let _ = writeln!(
                            s,
                            "    {de} = (iter_{query_idx} != NULL && state->api->iter_column_rows_readonly != NULL) ? (const void*)state->api->iter_column_rows_readonly(iter_{query_idx}, {term_idx}u) : NULL;"
                        );
                    } else {
                        let cty = self
                            .ptr_c_ty(d)
                            .unwrap_or_else(|| "const void*".to_string());
                        let _ = writeln!(
                            s,
                            "    {de} = (iter_{query_idx} != NULL && state->api->iter_column_readonly != NULL) ? ({cty})state->api->iter_column_readonly(iter_{query_idx}, {term_idx}u) : NULL;"
                        );
                    }
                }
            }
            Inst::IterColRowsWrite {
                query_idx,
                term_idx,
                storage_key,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    if self.parent.is_query_term_sparse(
                        self.func,
                        *query_idx,
                        *term_idx,
                        storage_key,
                    ) {
                        let _ = writeln!(
                            s,
                            "    {de} = (iter_{query_idx} != NULL && state->api->iter_column_rows_mutable != NULL) ? (void*)state->api->iter_column_rows_mutable(iter_{query_idx}, {term_idx}u) : NULL;"
                        );
                    } else {
                        let cty = self.ptr_c_ty(d).unwrap_or_else(|| "void*".to_string());
                        let _ = writeln!(
                            s,
                            "    {de} = (iter_{query_idx} != NULL && state->api->iter_column_mutable != NULL) ? ({cty})state->api->iter_column_mutable(iter_{query_idx}, {term_idx}u) : NULL;"
                        );
                    }
                }
            }
            Inst::IterCount { query_idx } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let _ = writeln!(
                        s,
                        "    {de} = 0u;\n    if (sys_ctx != NULL && state->api->sys_query != NULL && state->api->iter_count != NULL) {{\n        BamIter* cnt_it = NULL;\n        if (state->api->sys_query(sys_ctx, {query_idx}u, &cnt_it) == BAM_RESULT_OK && cnt_it != NULL) {{\n            size_t raw_cnt = 0u;\n            (void)state->api->iter_count(cnt_it, &raw_cnt);\n            {de} = (uint32_t)raw_cnt;\n        }}\n    }}"
                    );
                }
            }
            Inst::IterUpCascade {
                query_idx,
                relation,
                entity,
                term_idx,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ee = self.local_expr(*entity);
                    let rel_expr = if let Some(r_idx) = self.parent.find_rel_idx(relation) {
                        format!("state->relations[{r_idx}]")
                    } else {
                        "BAM_COMPONENT_INVALID".to_string()
                    };
                    let cty = self
                        .ptr_c_ty(d)
                        .unwrap_or_else(|| "const void*".to_string());
                    let _ = writeln!(
                        s,
                        "    {{\n        const void* raw_up = NULL;\n        BamEntity up_owner = BAM_ENTITY_NULL;\n        if (iter_{query_idx} != NULL && state->api->iter_up_cascade != NULL) {{\n            (void)state->api->iter_up_cascade(iter_{query_idx}, {rel_expr}, {ee}, {term_idx}u, &raw_up, &up_owner);\n        }}\n        (void)up_owner;\n        {de} = ({cty})raw_up;\n    }}"
                    );
                }
            }
            Inst::ParForEachChunk {
                query_idx,
                chunk_size,
            } => {
                let _ = writeln!(
                    s,
                    "    /* @par chunk_size={chunk_size} */\n    (void)(state->api->par_for_each_chunk != NULL && iter_{query_idx} != NULL);"
                );
            }
            Inst::ParForEachChunkReadonly {
                query_idx,
                chunk_size,
                deterministic_order,
            } => {
                let _ = writeln!(
                    s,
                    "    /* @par readonly chunk_size={chunk_size} deterministic={deterministic_order} */\n    (void)(state->api->par_for_each_chunk_readonly != NULL && iter_{query_idx} != NULL);"
                );
            }
            Inst::ReduceInit { identity, .. } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ie = self.local_expr(*identity);
                    let _ = writeln!(s, "    {de} = {ie};");
                }
            }
            Inst::ReduceAccum { acc, op, val } => {
                let ae = self.local_expr(*acc);
                let ve = self.local_expr(*val);
                let aty = self.local_ty(*acc).cloned().unwrap_or(MirType::F32);
                match op.as_str() {
                    "min" | "Min" => {
                        if matches!(aty, MirType::F32) {
                            let _ = writeln!(s, "    {ae} = fminf({ae}, {ve});");
                        } else {
                            let _ = writeln!(s, "    {ae} = ({ae} < {ve}) ? {ae} : {ve};");
                        }
                    }
                    "max" | "Max" => {
                        if matches!(aty, MirType::F32) {
                            let _ = writeln!(s, "    {ae} = fmaxf({ae}, {ve});");
                        } else {
                            let _ = writeln!(s, "    {ae} = ({ae} > {ve}) ? {ae} : {ve};");
                        }
                    }
                    "prod" | "*" | "Mul" => {
                        let _ = writeln!(s, "    {ae} = ({ae}) * ({ve});");
                    }
                    _ => {
                        if matches!(aty, MirType::Vec2) {
                            let _ = writeln!(s, "    {ae} = strata_vec2_add({ae}, {ve});");
                        } else if matches!(aty, MirType::Vec3) {
                            let _ = writeln!(s, "    {ae} = strata_vec3_add({ae}, {ve});");
                        } else if matches!(aty, MirType::Vec4) {
                            let _ = writeln!(s, "    {ae} = strata_vec4_add({ae}, {ve});");
                        } else {
                            let _ = writeln!(s, "    {ae} = ({ae}) + ({ve});");
                        }
                    }
                }
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let _ = writeln!(s, "    {de} = {ae};");
                }
            }
            Inst::ResRead { resource } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let c_idx = self.parent.find_comp_idx(resource).unwrap_or(0);
                    let cty = self
                        .ptr_c_ty(d)
                        .unwrap_or_else(|| "const void*".to_string());
                    let _ = writeln!(
                        s,
                        "    {de} = (state->res_flags[{c_idx}] == 1u && sys_ctx != NULL && state->api->sys_res_ptr != NULL) ? ({cty})state->api->sys_res_ptr(sys_ctx, state->components[{c_idx}], NULL) : NULL;"
                    );
                    if self
                        .parent
                        .components
                        .get(c_idx)
                        .is_some_and(|c| c.has_mod_res)
                    {
                        let _ = writeln!(
                            s,
                            "    if ({de} == NULL) {{ {de} = ({cty})&state->mod_res_{c_idx}; }}"
                        );
                    }
                }
            }
            Inst::ResWrite { resource } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let c_idx = self.parent.find_comp_idx(resource).unwrap_or(0);
                    let cty = self.ptr_c_ty(d).unwrap_or_else(|| "void*".to_string());
                    let _ = writeln!(
                        s,
                        "    {de} = (state->res_flags[{c_idx}] == 1u && sys_ctx != NULL && state->api->sys_res_mut_ptr != NULL) ? ({cty})state->api->sys_res_mut_ptr(sys_ctx, state->components[{c_idx}], NULL) : NULL;"
                    );
                    if self
                        .parent
                        .components
                        .get(c_idx)
                        .is_some_and(|c| c.has_mod_res)
                    {
                        let _ = writeln!(
                            s,
                            "    if ({de} == NULL) {{ {de} = ({cty})&state->mod_res_{c_idx}; }}"
                        );
                    }
                }
            }
            Inst::EntityGet {
                query_idx,
                term_idx,
                entity,
                ..
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ee = self.local_expr(*entity);
                    let cty = self
                        .ptr_c_ty(d)
                        .unwrap_or_else(|| "const void*".to_string());
                    let _ = writeln!(
                        s,
                        "    {de} = (sys_ctx != NULL && state->api->sys_entity_get != NULL && {ee} != BAM_ENTITY_NULL) ? ({cty})state->api->sys_entity_get(sys_ctx, {query_idx}u, {ee}, {term_idx}u) : NULL;"
                    );
                }
            }
            Inst::EntityGetMut {
                query_idx,
                term_idx,
                entity,
                ..
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ee = self.local_expr(*entity);
                    let cty = self.ptr_c_ty(d).unwrap_or_else(|| "void*".to_string());
                    let _ = writeln!(
                        s,
                        "    {de} = (sys_ctx != NULL && state->api->sys_entity_get_mut != NULL && {ee} != BAM_ENTITY_NULL) ? ({cty})state->api->sys_entity_get_mut(sys_ctx, {query_idx}u, {ee}, {term_idx}u) : NULL;"
                    );
                }
            }
            Inst::BindNamedObject { name } => {
                if let Some(&o_idx) = self.parent.obj_by_name.get(name) {
                    let esc = c_escape(name);
                    let _ = writeln!(
                        s,
                        "    if (state->named_objects[{o_idx}] != BAM_ENTITY_NULL && state->host_ctx != NULL && state->api->bind_named_object != NULL) {{\n        (void)state->api->bind_named_object(state->host_ctx, bam_str_view(\"{esc}\"), state->named_objects[{o_idx}]);\n    }}"
                    );
                }
            }
            Inst::ResolveNamedObject { name } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    if let Some(&o_idx) = self.parent.obj_by_name.get(name) {
                        let obj = &self.parent.objects[o_idx];
                        let match_q = obj.primary_comp_idx.and_then(|p_idx| {
                            let p_comp = &self.parent.components[p_idx];
                            self.func.query_bindings.iter().find(|qb| {
                                qb.terms.iter().any(|t| {
                                    t.canonical_component == p_comp.canonical
                                        || short_name(&t.canonical_component) == p_comp.short
                                }) || qb.with_filters.iter().any(|w| {
                                    *w == p_comp.canonical || short_name(w) == p_comp.short
                                })
                            })
                        });
                        let _ = writeln!(
                            s,
                            "    if (state->named_objects[{o_idx}] == BAM_ENTITY_NULL && sys_ctx != NULL && state->api->sys_query != NULL && state->api->iter_next_chunk != NULL && state->api->iter_entities != NULL) {{"
                        );
                        if let Some(qb) = match_q {
                            let qi = qb.query_idx;
                            let _ = writeln!(
                                s,
                                "\
        BamIter* probe_it = NULL;
        if (state->api->sys_query(sys_ctx, {qi}u, &probe_it) == BAM_RESULT_OK && probe_it != NULL) {{
            if (state->api->iter_reset != NULL) {{ (void)state->api->iter_reset(probe_it); }}
            size_t plen = 0u;
            if (state->api->iter_next_chunk(probe_it, &plen) != BAM_FALSE && plen > 0u) {{
                const BamEntity* pents = state->api->iter_entities(probe_it);
                if (pents != NULL && pents[0] != BAM_ENTITY_NULL) {{
                    state->named_objects[{o_idx}] = pents[0];
                }}
            }}
            if (state->api->iter_reset != NULL) {{ (void)state->api->iter_reset(probe_it); }}
        }}"
                            );
                        }
                        let _ = writeln!(s, "    }}");
                        let _ = writeln!(s, "    {de} = state->named_objects[{o_idx}];");
                    } else {
                        let _ = writeln!(s, "    {de} = BAM_ENTITY_NULL;");
                    }
                }
            }
            Inst::InternSymbol { symbol } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let esc = c_escape(symbol);
                    let _ = writeln!(
                        s,
                        "    {de} = BAM_SYMBOL_INVALID;\n    if (state->host_ctx != NULL && state->api->intern_symbol != NULL) {{\n        (void)state->api->intern_symbol(state->host_ctx, bam_str_view(\"{esc}\"), &{de});\n    }}"
                    );
                }
            }
            Inst::TriggerPayload { .. } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let cty = self
                        .ptr_c_ty(d)
                        .unwrap_or_else(|| "const void*".to_string());
                    if self.is_observer {
                        let _ = writeln!(s, "    {de} = ({cty})event_data;");
                    } else {
                        let _ = writeln!(s, "    {de} = NULL;");
                    }
                }
            }
            Inst::TriggerTarget => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    if self.is_observer {
                        let _ = writeln!(s, "    {de} = entity;");
                    } else {
                        let _ = writeln!(s, "    {de} = BAM_ENTITY_NULL;");
                    }
                }
            }
            Inst::GraceArm { ptr, duration_sec } => {
                let p = self.local_expr(*ptr);
                let dur = self.local_expr(*duration_sec);
                let _ = writeln!(s, "    strata_grace_arm({p}, {dur});");
            }
            Inst::GraceTick { ptr, dt_sec } => {
                let p = self.local_expr(*ptr);
                let dtv = self.local_expr(*dt_sec);
                let _ = writeln!(s, "    strata_grace_tick({p}, {dtv});");
            }
            Inst::GraceIsActive { ptr } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let p = self.local_expr(*ptr);
                    let _ = writeln!(s, "    {de} = strata_grace_is_active({p});");
                }
            }
            Inst::GraceClear { ptr } => {
                let p = self.local_expr(*ptr);
                let _ = writeln!(s, "    strata_grace_clear({p});");
            }
            Inst::InputBufPush {
                ptr,
                capacity,
                action_id,
                window_sec,
            } => {
                let p = self.local_expr(*ptr);
                let a = self.local_expr(*action_id);
                let w = self.local_expr(*window_sec);
                let _ = writeln!(
                    s,
                    "    strata_input_push({p}, {capacity}u, (uint16_t){a}, {w});"
                );
            }
            Inst::InputBufConsume {
                ptr,
                capacity,
                action_id,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let p = self.local_expr(*ptr);
                    let a = self.local_expr(*action_id);
                    let _ = writeln!(
                        s,
                        "    {de} = strata_input_consume({p}, {capacity}u, (uint16_t){a});"
                    );
                }
            }
            Inst::InputBufPeek {
                ptr,
                capacity,
                action_id,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let p = self.local_expr(*ptr);
                    let a = self.local_expr(*action_id);
                    let _ = writeln!(
                        s,
                        "    {de} = strata_input_peek({p}, {capacity}u, (uint16_t){a});"
                    );
                }
            }
            Inst::InputBufTick {
                ptr,
                capacity,
                dt_sec,
            } => {
                let p = self.local_expr(*ptr);
                let dtv = self.local_expr(*dt_sec);
                let _ = writeln!(s, "    strata_input_tick({p}, {capacity}u, {dtv});");
            }
            Inst::BitSetSet { ptr, words, bit } => {
                let p = self.local_expr(*ptr);
                let ptr_arg = if self.is_ptr_local(*ptr) {
                    p
                } else {
                    format!("&({p})")
                };
                let b = self.local_expr(*bit);
                let _ = writeln!(
                    s,
                    "    strata_bitset_set({ptr_arg}, {words}u, (uint32_t){b});"
                );
            }
            Inst::BitSetGet { ptr, words, bit } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let p = self.local_expr(*ptr);
                    let ptr_arg = if self.is_ptr_local(*ptr) {
                        p
                    } else {
                        format!("&({p})")
                    };
                    let b = self.local_expr(*bit);
                    let _ = writeln!(
                        s,
                        "    {de} = strata_bitset_get({ptr_arg}, {words}u, (uint32_t){b});"
                    );
                }
            }
            Inst::BitSetClear { ptr, words, bit } => {
                let p = self.local_expr(*ptr);
                let ptr_arg = if self.is_ptr_local(*ptr) {
                    p
                } else {
                    format!("&({p})")
                };
                let b = self.local_expr(*bit);
                let _ = writeln!(
                    s,
                    "    strata_bitset_clear({ptr_arg}, {words}u, (uint32_t){b});"
                );
            }
            Inst::TimelineInWindow { ptr, window_bit } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let p = self.local_expr(*ptr);
                    let _ = writeln!(
                        s,
                        "    {de} = BAM_FALSE;\n    if ({p} != NULL) {{\n        uint32_t mask = 0u;\n        memcpy(&mask, ((const uint8_t*){p}) + sizeof(float) + sizeof(uint32_t), sizeof(uint32_t));\n        {de} = ((mask & (1u << {window_bit}u)) != 0u) ? BAM_TRUE : BAM_FALSE;\n    }}"
                    );
                }
            }
            Inst::TimelineAdvance {
                cursor_ptr,
                dt_sec,
                rate_hz,
                duration_frames,
                window_masks,
                ..
            } => {
                let p = self.local_expr(*cursor_ptr);
                let dt = self.local_expr(*dt_sec);
                let _ = writeln!(s, "    if ({p} != NULL) {{");
                let _ = writeln!(s, "        float elapsed = 0.0f;");
                let _ = writeln!(s, "        memcpy(&elapsed, {p}, sizeof(float));");
                let _ = writeln!(s, "        elapsed += {dt};");
                let _ = writeln!(
                    s,
                    "        uint32_t frame = (uint32_t)(elapsed * (float){rate_hz}u);"
                );
                let _ = writeln!(
                    s,
                    "        if (frame > {duration_frames}u) {{ frame = {duration_frames}u; }}"
                );
                let _ = writeln!(s, "        uint32_t mask = 0u;");
                for (_, start_f, end_f, bit) in window_masks {
                    if *start_f == 0 && *end_f == u32::MAX {
                        let _ = writeln!(s, "        mask |= (1u << {bit}u);");
                    } else if *start_f == 0 {
                        let _ = writeln!(
                            s,
                            "        if (frame <= {end_f}u) {{ mask |= (1u << {bit}u); }}"
                        );
                    } else if *end_f == u32::MAX {
                        let _ = writeln!(
                            s,
                            "        if (frame >= {start_f}u) {{ mask |= (1u << {bit}u); }}"
                        );
                    } else {
                        let _ = writeln!(
                            s,
                            "        if (frame >= {start_f}u && frame <= {end_f}u) {{ mask |= (1u << {bit}u); }}"
                        );
                    }
                }
                let _ = writeln!(s, "        memcpy({p}, &elapsed, sizeof(float));");
                let _ = writeln!(
                    s,
                    "        memcpy(((uint8_t*){p}) + sizeof(float), &frame, sizeof(uint32_t));"
                );
                let _ = writeln!(
                    s,
                    "        memcpy(((uint8_t*){p}) + sizeof(float) + sizeof(uint32_t), &mask, sizeof(uint32_t));"
                );
                let _ = writeln!(s, "    }}");
            }
            Inst::CmdSpawn {
                persistent,
                components,
            } => {
                self.emit_cmd_spawn(dst, components, *persistent, s);
            }
            Inst::CmdSpawnBatch { count, components } => {
                self.emit_cmd_spawn_batch(*count, components, s);
            }
            Inst::SpawnBatchBegin { count, components } => {
                self.emit_spawn_batch_begin(dst, *count, components, s);
            }
            Inst::SpawnBatchPush {
                batch,
                index,
                components,
            } => {
                self.emit_spawn_batch_push(*batch, *index, components, s);
            }
            Inst::SpawnBatchCommit { batch } => {
                self.emit_spawn_batch_commit(*batch, s);
            }
            Inst::CmdDespawn { entity } => {
                let e = self.local_expr(*entity);
                self.ensure_cmds_snippet(s);
                let _ = writeln!(
                    s,
                    "    if (cmds_cache != NULL && state->api->cmd_despawn != NULL && {e} != BAM_ENTITY_NULL) {{\n        (void)state->api->cmd_despawn(cmds_cache, {e});\n    }}"
                );
            }
            Inst::CmdDespawnAll { filter } => {
                self.emit_cmd_despawn_all(filter, s);
            }
            Inst::CmdInsert {
                entity,
                component,
                data,
                if_new,
            } => {
                let e = self.local_expr(*entity);
                let p = data
                    .map(|id| {
                        let is_ptr = self.ptr_meta.contains_key(&id)
                            || matches!(self.local_ty(id), Some(MirType::Ptr | MirType::MutPtr));
                        let pe = self.local_expr(id);
                        if is_ptr {
                            format!("(const uint8_t*){pe}")
                        } else {
                            format!("(const uint8_t*)&{pe}")
                        }
                    })
                    .unwrap_or_else(|| "NULL".to_string());
                let c_idx = self.parent.find_comp_idx(component).unwrap_or(0);
                let sz = self.parent.components.get(c_idx).map_or(0, |c| c.size);
                let slot = if *if_new {
                    "cmd_insert_if_new"
                } else {
                    "cmd_insert"
                };
                self.ensure_cmds_snippet(s);
                let _ = writeln!(
                    s,
                    "    if (cmds_cache != NULL && state->api->{slot} != NULL && {e} != BAM_ENTITY_NULL) {{\n        (void)state->api->{slot}(cmds_cache, {e}, state->components[{c_idx}], {p}, {sz}u);\n    }}"
                );
            }
            Inst::CmdRemove { entity, component } => {
                let e = self.local_expr(*entity);
                let c_idx = self.parent.find_comp_idx(component).unwrap_or(0);
                self.ensure_cmds_snippet(s);
                let _ = writeln!(
                    s,
                    "    if (cmds_cache != NULL && state->api->cmd_remove != NULL && {e} != BAM_ENTITY_NULL) {{\n        (void)state->api->cmd_remove(cmds_cache, {e}, state->components[{c_idx}]);\n    }}"
                );
            }
            Inst::CmdTrigger {
                event,
                target,
                payload,
                propagate,
            } => {
                let c_idx = self.parent.find_comp_idx(event).unwrap_or(0);
                let trg = target
                    .map(|id| self.local_expr(id))
                    .unwrap_or_else(|| "BAM_ENTITY_NULL".to_string());
                let (pp, psz, pp_is_addr_of) = if let Some(pid) = payload {
                    let is_ptr =
                        matches!(self.local_ty(*pid), Some(MirType::Ptr | MirType::MutPtr));
                    let pe = self.local_expr(*pid);
                    let comp_sz = self.parent.components.get(c_idx).map_or(0, |c| c.size);
                    if is_ptr {
                        (format!("(const uint8_t*){pe}"), comp_sz, false)
                    } else {
                        (format!("(const uint8_t*)&{pe}"), comp_sz, true)
                    }
                } else {
                    ("NULL".to_string(), 0usize, false)
                };
                self.ensure_cmds_snippet(s);
                if *propagate {
                    if psz > 0 {
                        let copy_stmt = if pp_is_addr_of {
                            format!("memcpy(trg_buf, {pp}, {psz}u);")
                        } else {
                            format!("if ({pp} != NULL) {{ memcpy(trg_buf, {pp}, {psz}u); }}")
                        };
                        let _ = writeln!(
                            s,
                            "    if (cmds_cache != NULL && state->api->cmd_trigger_ex != NULL) {{\n        uint8_t trg_buf[{psz}u];\n        memset(trg_buf, 0, sizeof(trg_buf));\n        {copy_stmt}\n        BamTriggerDesc tdesc = bam_trigger_desc(state->components[{c_idx}], {trg}, trg_buf, {psz}u);\n        tdesc.flags = BAM_TRIGGER_FLAG_PROPAGATE;\n        (void)state->api->cmd_trigger_ex(cmds_cache, &tdesc);\n    }}"
                        );
                    } else {
                        let _ = writeln!(
                            s,
                            "    if (cmds_cache != NULL && state->api->cmd_trigger_ex != NULL) {{\n        BamTriggerDesc tdesc = bam_trigger_desc(state->components[{c_idx}], {trg}, NULL, 0u);\n        tdesc.flags = BAM_TRIGGER_FLAG_PROPAGATE;\n        (void)state->api->cmd_trigger_ex(cmds_cache, &tdesc);\n    }}"
                        );
                    }
                } else {
                    let _ = writeln!(
                        s,
                        "    if (cmds_cache != NULL && state->api->cmd_trigger != NULL) {{\n        (void)state->api->cmd_trigger(cmds_cache, state->components[{c_idx}], {trg}, {pp}, {psz}u);\n    }}"
                    );
                }
            }
            Inst::StreamEmit { stream, payload } => {
                let c_idx = self.parent.find_comp_idx(stream).unwrap_or(0);
                let sz = self.parent.components.get(c_idx).map_or(0, |c| c.size);
                let is_ptr = self.ptr_meta.contains_key(payload)
                    || matches!(
                        self.local_ty(*payload),
                        Some(MirType::Ptr | MirType::MutPtr)
                    );
                let pe = self.local_expr(*payload);
                let ptr_expr = if is_ptr {
                    format!("(const uint8_t*){pe}")
                } else {
                    format!("(const uint8_t*)&{pe}")
                };
                let stream_short = short_name(stream);
                let match_term = self.func.query_bindings.iter().find_map(|qb| {
                    qb.terms
                        .iter()
                        .find(|t| {
                            t.mode == TermAccessMode::StreamWrite
                                && (t.canonical_component == *stream
                                    || short_name(&t.canonical_component) == stream_short)
                        })
                        .map(|t| (qb.query_idx, t.term_idx))
                });
                if let Some((qi, ti)) = match_term {
                    let _ = writeln!(
                        s,
                        "    if (sys_ctx != NULL && state->api->msg_send != NULL) {{\n        if (iter_{qi} == NULL && state->api->sys_query != NULL) {{ (void)state->api->sys_query(sys_ctx, {qi}u, &iter_{qi}); }}\n        if (iter_{qi} != NULL) {{ (void)state->api->msg_send(iter_{qi}, {ti}u, {ptr_expr}, {sz}u); }}\n    }}"
                    );
                } else if let Some(s_idx) = self.sys_idx {
                    let comp_n = self.parent.components.len().max(1);
                    let _ = writeln!(
                        s,
                        "    if (sys_ctx != NULL && state->res_flags[{c_idx}] == 2u && state->sys_msg_q[{s_idx}] != UINT32_MAX && state->sys_msg_ti[{s_idx}u * {comp_n}u + {c_idx}u] != UINT32_MAX && state->api->sys_query != NULL && state->api->msg_send != NULL) {{\n        BamIter* msg_it = NULL;\n        if (state->api->sys_query(sys_ctx, state->sys_msg_q[{s_idx}], &msg_it) == BAM_RESULT_OK && msg_it != NULL) {{\n            (void)state->api->msg_send(msg_it, state->sys_msg_ti[{s_idx}u * {comp_n}u + {c_idx}u], {ptr_expr}, {sz}u);\n        }}\n    }}"
                    );
                }
            }
            Inst::CmdCheckpoint => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    self.ensure_cmds_snippet(s);
                    let _ = writeln!(
                        s,
                        "    if (cmds_cache != NULL && state->api->cmd_checkpoint != NULL) {{\n        (void)state->api->cmd_checkpoint(cmds_cache, &{de});\n    }}"
                    );
                }
            }
            Inst::CmdRollback { checkpoint } => {
                let cp = self.local_expr(*checkpoint);
                self.ensure_cmds_snippet(s);
                let _ = writeln!(
                    s,
                    "    if (cmds_cache != NULL && state->api->cmd_rollback != NULL) {{\n        (void)state->api->cmd_rollback(cmds_cache, {cp});\n    }}"
                );
            }
            Inst::CmdInsertRelation {
                relation,
                entity,
                target,
                payload,
            } => {
                let r_idx = self.parent.find_rel_idx(relation).unwrap_or(0);
                let ch = self.local_expr(*entity);
                let pa = self.local_expr(*target);
                let sz = self.parent.relations.get(r_idx).map_or(0, |r| r.data_size);
                let pp = if let Some(pid) = payload {
                    let is_ptr =
                        matches!(self.local_ty(*pid), Some(MirType::Ptr | MirType::MutPtr));
                    let pe = self.local_expr(*pid);
                    if is_ptr { pe } else { format!("&{pe}") }
                } else {
                    "NULL".to_string()
                };
                self.ensure_cmds_snippet(s);
                let _ = writeln!(
                    s,
                    "    if (cmds_cache != NULL && state->api->cmd_insert_relation != NULL) {{\n        (void)state->api->cmd_insert_relation(cmds_cache, state->relations[{r_idx}], {ch}, {pa}, {pp}, {sz}u);\n    }}"
                );
            }
            Inst::CmdRemoveRelation {
                relation,
                entity,
                target,
            } => {
                let r_idx = self.parent.find_rel_idx(relation).unwrap_or(0);
                let ch = self.local_expr(*entity);
                let pa = self.local_expr(*target);
                self.ensure_cmds_snippet(s);
                let _ = writeln!(
                    s,
                    "    if (cmds_cache != NULL && state->api->cmd_remove_relation != NULL) {{\n        (void)state->api->cmd_remove_relation(cmds_cache, state->relations[{r_idx}], {ch}, {pa});\n    }}"
                );
            }
            Inst::SpatialRebuildCsr { index_name, .. } => {
                let _ = writeln!(s, "    /* Spatial CSR rebuilt for `{index_name}` */");
            }
            Inst::IterReset { query_idx } => {
                let _ = writeln!(
                    s,
                    "    if (iter_{query_idx} != NULL && state->api->iter_reset != NULL) {{\n        (void)state->api->iter_reset(iter_{query_idx});\n    }}"
                );
            }
            Inst::SpatialCsrBegin { index_name } => {
                if let Some(sp_name) = self.parent.find_spatial_name(self.func, index_name) {
                    let ident = sanitize_ident(&sp_name);
                    let _ = writeln!(s, "    strata_spatial_csr_begin(&state->spatial_{ident});");
                }
            }
            Inst::SpatialCsrCount { index_name, pos } => {
                if let Some(sp_name) = self.parent.find_spatial_name(self.func, index_name) {
                    let ident = sanitize_ident(&sp_name);
                    let pe = self.local_expr(*pos);
                    let p4 = match self.local_ty(*pos) {
                        Some(MirType::Vec2) => format!("strata_spatial_pos_v2({pe})"),
                        Some(MirType::Vec3) => format!("strata_spatial_pos_v3({pe})"),
                        _ => pe,
                    };
                    let _ = writeln!(
                        s,
                        "    strata_spatial_csr_count(&state->spatial_{ident}, {p4});"
                    );
                }
            }
            Inst::SpatialCsrPrefixSum { index_name } => {
                if let Some(sp_name) = self.parent.find_spatial_name(self.func, index_name) {
                    let ident = sanitize_ident(&sp_name);
                    let _ = writeln!(
                        s,
                        "    strata_spatial_csr_prefix_sum(&state->spatial_{ident});"
                    );
                }
            }
            Inst::SpatialCsrScatter {
                index_name,
                entity,
                pos,
            } => {
                if let Some(sp_name) = self.parent.find_spatial_name(self.func, index_name) {
                    let ident = sanitize_ident(&sp_name);
                    let ee = self.local_expr(*entity);
                    let pe = self.local_expr(*pos);
                    let p4 = match self.local_ty(*pos) {
                        Some(MirType::Vec2) => format!("strata_spatial_pos_v2({pe})"),
                        Some(MirType::Vec3) => format!("strata_spatial_pos_v3({pe})"),
                        _ => pe,
                    };
                    let _ = writeln!(
                        s,
                        "    strata_spatial_csr_scatter(&state->spatial_{ident}, {ee}, {p4});"
                    );
                }
            }
            Inst::SpatialQueryDisc {
                grid_name,
                center,
                radius,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let sid = d.0;
                    let ce = self.local_expr(*center);
                    let c3 = match self.local_ty(*center) {
                        Some(MirType::Vec2) => format!("strata_spatial_c3_v2({ce})"),
                        Some(MirType::Vec4) => format!("strata_spatial_c3_v4({ce})"),
                        _ => ce,
                    };
                    let re = self.local_expr(*radius);
                    let grid_ptr_expr = if let Some(sp_name) =
                        self.parent.find_spatial_name(self.func, grid_name)
                    {
                        let ident = sanitize_ident(&sp_name);
                        format!("(const void*)&state->spatial_{ident}")
                    } else {
                        "NULL".to_string()
                    };
                    let _ = writeln!(
                        s,
                        "    {{\n        const void* g_ptr = {grid_ptr_expr};\n        spatial_buf_{sid} = strata_spatial_query_disc(g_ptr, {c3}, (float){re});\n        {de} = (const BamEntity*)spatial_buf_{sid}.entities;\n    }}"
                    );
                }
            }
            Inst::SpatialQuerySegmentAt {
                history_name,
                start,
                end,
                radius,
                tick_offset,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let sid = d.0;
                    let a_raw = self.local_expr(*start);
                    let a = match self.local_ty(*start) {
                        Some(MirType::Vec2) => format!("strata_spatial_c3_v2({a_raw})"),
                        Some(MirType::Vec4) => format!("strata_spatial_c3_v4({a_raw})"),
                        _ => a_raw,
                    };
                    let b_raw = self.local_expr(*end);
                    let b = match self.local_ty(*end) {
                        Some(MirType::Vec2) => format!("strata_spatial_c3_v2({b_raw})"),
                        Some(MirType::Vec4) => format!("strata_spatial_c3_v4({b_raw})"),
                        _ => b_raw,
                    };
                    let r = self.local_expr(*radius);
                    let toff = self.local_expr(*tick_offset);
                    let hist_ptr_expr = if let Some(sp_name) =
                        self.parent.find_spatial_name(self.func, history_name)
                    {
                        let ident = sanitize_ident(&sp_name);
                        format!("(const void*)&state->spatial_{ident}")
                    } else {
                        "NULL".to_string()
                    };
                    let _ = writeln!(
                        s,
                        "    {{\n        const void* h_ptr = {hist_ptr_expr};\n        spatial_buf_{sid} = strata_spatial_query_segment_at(h_ptr, {a}, {b}, (float){r}, (float){toff});\n        {de} = (const BamEntity*)spatial_buf_{sid}.entities;\n    }}"
                    );
                }
            }
            Inst::TableLoad {
                table_name,
                key,
                field,
            } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let ke = self.local_expr(*key);
                    let t_ident = sanitize_ident(table_name);
                    if field.is_empty() {
                        let _ =
                            writeln!(s, "    {de} = strata_table_load_{t_ident}((int32_t){ke});");
                    } else {
                        let fc = sanitize_c_field(field);
                        let _ = writeln!(
                            s,
                            "    {de} = strata_table_load_{t_ident}((int32_t){ke}).{fc};"
                        );
                    }
                }
            }
            Inst::CurveSample { curve_name, x } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let xe = self.local_expr(*x);
                    let c_ident = sanitize_ident(curve_name);
                    let _ = writeln!(s, "    {de} = strata_curve_sample_{c_ident}({xe});");
                }
            }
            Inst::OptionalChunkIsPresent { slice_ptr, .. } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let pe = self.local_expr(*slice_ptr);
                    let _ = writeln!(s, "    {de} = ({pe} != NULL) ? BAM_TRUE : BAM_FALSE;");
                }
            }
            Inst::DirtyRunInit { run_start, run_len } => {
                let rs = self.local_expr(*run_start);
                let rl = self.local_expr(*run_len);
                let _ = writeln!(s, "    {rs} = 0u;\n    {rl} = 0u;");
            }
            Inst::DirtyRunRecordRow {
                run_start,
                run_len,
                row_idx,
            } => {
                let rs = self.local_expr(*run_start);
                let rl = self.local_expr(*run_len);
                let r = self.local_expr(*row_idx);
                let _ = writeln!(s, "    if ({rl} == 0u) {{");
                let _ = writeln!(s, "        {rs} = {r};\n        {rl} = 1u;");
                let _ = writeln!(s, "    }} else if ({rs} + {rl} == {r}) {{");
                let _ = writeln!(s, "        {rl} += 1u;");
                let _ = writeln!(s, "    }} else {{");
                if let Some(owners) = self.dirty_owners.get(&(run_start.0, run_len.0)) {
                    for &(qi, ti) in owners {
                        let _ = writeln!(
                            s,
                            "        if (iter_{qi} != NULL && state->api->iter_mark_changed_range != NULL) {{\n            (void)state->api->iter_mark_changed_range(iter_{qi}, {ti}u, (size_t){rs}, (size_t){rl});\n        }}"
                        );
                    }
                }
                let _ = writeln!(s, "        {rs} = {r};\n        {rl} = 1u;");
                let _ = writeln!(s, "    }}");
            }
            Inst::ShadowWrite {
                target_name,
                shadow_slot,
                val,
            } => {
                // Pre-image was already captured in `undo_slot` (`shadow_slot`) by `tx_save_pre`
                // before `FieldStore`; do NOT overwrite `shadow_slot` with the post-store value.
                let se = self.local_expr(*shadow_slot);
                let ve = self.local_expr(*val);
                let _ = writeln!(
                    s,
                    "    /* Shadow write `{target_name}` (pre-image preserved) */\n    (void){se};\n    (void){ve};"
                );
            }
            Inst::ShadowCommit {
                target_name,
                shadow_slot,
            } => {
                let se = self.local_expr(*shadow_slot);
                let _ = writeln!(
                    s,
                    "    /* Shadow commit `{target_name}` */\n    (void){se};"
                );
            }
            Inst::RequireTrue { cond } => {
                let ce = self.local_expr(*cond);
                if let Some(cp) = self.last_checkpoint {
                    let cpe = self.local_expr(cp);
                    let _ = writeln!(
                        s,
                        "    if (!({ce}) && cmds_cache != NULL && state->api->cmd_rollback != NULL) {{\n        (void)state->api->cmd_rollback(cmds_cache, {cpe});\n    }}"
                    );
                } else {
                    let _ = writeln!(s, "    (void)({ce});");
                }
            }
            Inst::FsmDispatch { fsm, .. } => {
                let _ = writeln!(s, "    /* FSM dispatch hook `{fsm}` */");
            }
            Inst::TaskStep {
                task,
                pc_local,
                timer_local,
                ..
            } => {
                let pe = self.local_expr(*pc_local);
                let te = self.local_expr(*timer_local);
                let _ = writeln!(
                    s,
                    "    /* Task step `{task}` */\n    (void){pe}; (void){te};"
                );
            }
            Inst::MigrateSrcPtr { .. } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let cty = self
                        .ptr_c_ty(d)
                        .unwrap_or_else(|| "const void*".to_string());
                    if self.is_migration {
                        let _ = writeln!(s, "    {de} = ({cty})src_row;");
                    } else {
                        let _ = writeln!(s, "    {de} = NULL;");
                    }
                }
            }
            Inst::MigrateDstPtr { .. } => {
                if let Some(d) = dst {
                    let de = self.local_expr(d);
                    let cty = self.ptr_c_ty(d).unwrap_or_else(|| "void*".to_string());
                    if self.is_migration {
                        let _ = writeln!(s, "    {de} = ({cty})dst_row;");
                    } else {
                        let _ = writeln!(s, "    {de} = NULL;");
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn ensure_cmds_snippet(&self, s: &mut String) {
        let _ = writeln!(
            s,
            "    if (cmds_cache == NULL && sys_ctx != NULL && state->api->sys_commands != NULL) {{\n        (void)state->api->sys_commands(sys_ctx, &cmds_cache);\n    }}"
        );
    }

    pub(super) fn emit_binop(
        &self,
        dst: LocalId,
        op: &str,
        lhs: LocalId,
        rhs: LocalId,
        s: &mut String,
    ) -> Result<(), CodegenError> {
        let d = self.local_expr(dst);
        let lty = self.local_ty(lhs).cloned().unwrap_or(MirType::I32);
        let rty = self.local_ty(rhs).cloned().unwrap_or(MirType::I32);
        let is_eq_ne = matches!(op, "==" | "Eq" | "!=" | "Ne");
        let l = if is_eq_ne && !self.projected_fields.contains_key(&lhs) {
            self.local_expr(lhs)
        } else {
            self.unwrap_operand_expr(lhs, None)
        };
        let r = if is_eq_ne && !self.projected_fields.contains_key(&rhs) {
            self.local_expr(rhs)
        } else {
            self.unwrap_operand_expr(rhs, None)
        };

        match (&lty, &rty, op) {
            (MirType::Vec2, MirType::Vec2, "+" | "Add") => {
                let _ = writeln!(s, "    {d} = strata_vec2_add({l}, {r});");
                return Ok(());
            }
            (MirType::Vec2, MirType::Vec2, "-" | "Sub") => {
                let _ = writeln!(s, "    {d} = strata_vec2_sub({l}, {r});");
                return Ok(());
            }
            (MirType::Vec2, MirType::Vec2, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec2_mul({l}, {r});");
                return Ok(());
            }
            (MirType::Vec2, MirType::F32 | MirType::F64, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec2_scale({l}, (float){r});");
                return Ok(());
            }
            (MirType::F32 | MirType::F64, MirType::Vec2, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec2_scale({r}, (float){l});");
                return Ok(());
            }
            (MirType::Vec2, MirType::F32 | MirType::F64, "/" | "Div") => {
                let _ = writeln!(s, "    {d} = strata_vec2_scale({l}, 1.0f / (float)({r}));");
                return Ok(());
            }
            (MirType::Vec3, MirType::Vec3, "+" | "Add") => {
                let _ = writeln!(s, "    {d} = strata_vec3_add({l}, {r});");
                return Ok(());
            }
            (MirType::Vec3, MirType::Vec3, "-" | "Sub") => {
                let _ = writeln!(s, "    {d} = strata_vec3_sub({l}, {r});");
                return Ok(());
            }
            (MirType::Vec3, MirType::Vec3, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec3_mul({l}, {r});");
                return Ok(());
            }
            (MirType::Vec3, MirType::F32 | MirType::F64, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec3_scale({l}, (float){r});");
                return Ok(());
            }
            (MirType::F32 | MirType::F64, MirType::Vec3, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec3_scale({r}, (float){l});");
                return Ok(());
            }
            (MirType::Vec3, MirType::F32 | MirType::F64, "/" | "Div") => {
                let _ = writeln!(s, "    {d} = strata_vec3_scale({l}, 1.0f / (float)({r}));");
                return Ok(());
            }
            (MirType::Vec4, MirType::Vec4, "+" | "Add") => {
                let _ = writeln!(s, "    {d} = strata_vec4_add({l}, {r});");
                return Ok(());
            }
            (MirType::Vec4, MirType::Vec4, "-" | "Sub") => {
                let _ = writeln!(s, "    {d} = strata_vec4_sub({l}, {r});");
                return Ok(());
            }
            (MirType::Vec4, MirType::Vec4, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec4_mul({l}, {r});");
                return Ok(());
            }
            (MirType::Vec4, MirType::F32 | MirType::F64, "*" | "Mul") => {
                let _ = writeln!(s, "    {d} = strata_vec4_scale({l}, (float){r});");
                return Ok(());
            }
            (MirType::IVec2, MirType::IVec2, "+" | "Add" | "-" | "Sub" | "*" | "Mul") => {
                let cop = match op {
                    "+" | "Add" => "+",
                    "-" | "Sub" => "-",
                    _ => "*",
                };
                let _ = writeln!(
                    s,
                    "    {d} = strata_ivec2((int32_t)((uint32_t)({l}.x) {cop} (uint32_t)({r}.x)), (int32_t)((uint32_t)({l}.y) {cop} (uint32_t)({r}.y)));"
                );
                return Ok(());
            }
            (MirType::IVec2, MirType::IVec2, "==" | "Eq" | "!=" | "Ne") => {
                if matches!(op, "==" | "Eq") {
                    let _ = writeln!(
                        s,
                        "    {d} = ({l}.x == {r}.x && {l}.y == {r}.y) ? BAM_TRUE : BAM_FALSE;"
                    );
                } else {
                    let _ = writeln!(
                        s,
                        "    {d} = ({l}.x != {r}.x || {l}.y != {r}.y) ? BAM_TRUE : BAM_FALSE;"
                    );
                }
                return Ok(());
            }
            (MirType::UVec2, MirType::UVec2, "+" | "Add" | "-" | "Sub" | "*" | "Mul") => {
                let cop = match op {
                    "+" | "Add" => "+",
                    "-" | "Sub" => "-",
                    _ => "*",
                };
                let _ = writeln!(
                    s,
                    "    {d} = strata_uvec2({l}.x {cop} {r}.x, {l}.y {cop} {r}.y);"
                );
                return Ok(());
            }
            (MirType::UVec2, MirType::UVec2, "==" | "Eq" | "!=" | "Ne") => {
                if matches!(op, "==" | "Eq") {
                    let _ = writeln!(
                        s,
                        "    {d} = ({l}.x == {r}.x && {l}.y == {r}.y) ? BAM_TRUE : BAM_FALSE;"
                    );
                } else {
                    let _ = writeln!(
                        s,
                        "    {d} = ({l}.x != {r}.x || {l}.y != {r}.y) ? BAM_TRUE : BAM_FALSE;"
                    );
                }
                return Ok(());
            }
            (MirType::IVec3, MirType::IVec3, "+" | "Add" | "-" | "Sub" | "*" | "Mul") => {
                let cop = match op {
                    "+" | "Add" => "+",
                    "-" | "Sub" => "-",
                    _ => "*",
                };
                let _ = writeln!(
                    s,
                    "    {d} = strata_ivec3((int32_t)((uint32_t)({l}.x) {cop} (uint32_t)({r}.x)), (int32_t)((uint32_t)({l}.y) {cop} (uint32_t)({r}.y)), (int32_t)((uint32_t)({l}.z) {cop} (uint32_t)({r}.z)));"
                );
                return Ok(());
            }
            (MirType::IVec3, MirType::IVec3, "==" | "Eq" | "!=" | "Ne") => {
                if matches!(op, "==" | "Eq") {
                    let _ = writeln!(
                        s,
                        "    {d} = ({l}.x == {r}.x && {l}.y == {r}.y && {l}.z == {r}.z) ? BAM_TRUE : BAM_FALSE;"
                    );
                } else {
                    let _ = writeln!(
                        s,
                        "    {d} = ({l}.x != {r}.x || {l}.y != {r}.y || {l}.z != {r}.z) ? BAM_TRUE : BAM_FALSE;"
                    );
                }
                return Ok(());
            }
            _ => {}
        }

        let (c_op, is_cmp) = match op {
            "+" | "Add" => ("+", false),
            "-" | "Sub" => ("-", false),
            "*" | "Mul" => ("*", false),
            "/" | "Div" => ("/", false),
            "%" | "Rem" => ("%", false),
            "==" | "Eq" => ("==", true),
            "!=" | "Ne" => ("!=", true),
            "<" | "Lt" => ("<", true),
            "<=" | "Le" => ("<=", true),
            ">" | "Gt" => (">", true),
            ">=" | "Ge" => (">=", true),
            "&&" | "And" => ("&&", true),
            "||" | "Or" => ("||", true),
            "&" | "BitAnd" => ("&", false),
            "|" | "BitOr" => ("|", false),
            "^" | "BitXor" => ("^", false),
            "<<" | "Shl" => ("<<", false),
            ">>" | "Shr" => (">>", false),
            other => {
                return Err(CodegenError::Unsupported {
                    context: format!("c99::binop({})", self.func.name),
                    detail: format!("unsupported binary operator `{other}`"),
                });
            }
        };

        if matches!(lty, MirType::Fix64) || matches!(rty, MirType::Fix64) {
            let lc = self.coerce_scalar_to_fix_expr(lhs, &lty, true);
            let rc = self.coerce_scalar_to_fix_expr(rhs, &rty, true);
            if is_cmp {
                let _ = writeln!(
                    s,
                    "    {d} = (({lc}) {c_op} ({rc})) ? BAM_TRUE : BAM_FALSE;"
                );
                return Ok(());
            }
            match c_op {
                "+" => {
                    let _ = writeln!(
                        s,
                        "    {d} = (int64_t)((uint64_t)({lc}) + (uint64_t)({rc}));"
                    );
                }
                "-" => {
                    let _ = writeln!(
                        s,
                        "    {d} = (int64_t)((uint64_t)({lc}) - (uint64_t)({rc}));"
                    );
                }
                "*" => {
                    let _ = writeln!(s, "    {d} = strata_fix64_mul({lc}, {rc});");
                }
                "/" => {
                    let _ = writeln!(s, "    {d} = strata_fix64_div({lc}, {rc});");
                }
                "%" => {
                    let _ = writeln!(s, "    {d} = strata_fix64_rem({lc}, {rc});");
                }
                _ => {
                    let _ = writeln!(s, "    {d} = ({lc}) {c_op} ({rc});");
                }
            }
            return Ok(());
        }
        if matches!(lty, MirType::Fix32) || matches!(rty, MirType::Fix32) {
            let lc = self.coerce_scalar_to_fix_expr(lhs, &lty, false);
            let rc = self.coerce_scalar_to_fix_expr(rhs, &rty, false);
            if is_cmp {
                let _ = writeln!(
                    s,
                    "    {d} = (({lc}) {c_op} ({rc})) ? BAM_TRUE : BAM_FALSE;"
                );
                return Ok(());
            }
            match c_op {
                "+" => {
                    let _ = writeln!(
                        s,
                        "    {d} = (int32_t)((uint32_t)({lc}) + (uint32_t)({rc}));"
                    );
                }
                "-" => {
                    let _ = writeln!(
                        s,
                        "    {d} = (int32_t)((uint32_t)({lc}) - (uint32_t)({rc}));"
                    );
                }
                "*" => {
                    let _ = writeln!(s, "    {d} = strata_fix32_mul({lc}, {rc});");
                }
                "/" => {
                    let _ = writeln!(s, "    {d} = strata_fix32_div({lc}, {rc});");
                }
                "%" => {
                    let _ = writeln!(s, "    {d} = strata_fix32_rem({lc}, {rc});");
                }
                _ => {
                    let _ = writeln!(s, "    {d} = ({lc}) {c_op} ({rc});");
                }
            }
            return Ok(());
        }
        if !is_cmp && matches!(c_op, "+" | "-" | "*" | "/" | "%") {
            let common_f64 = matches!(lty, MirType::F64)
                || matches!(rty, MirType::F64)
                || matches!(self.projected_sema_ty(lhs), Some(Ty::F64))
                || matches!(self.projected_sema_ty(rhs), Some(Ty::F64));
            let common_f32 = matches!(lty, MirType::F32)
                || matches!(rty, MirType::F32)
                || matches!(
                    self.projected_sema_ty(lhs),
                    Some(Ty::F32 | Ty::UnitScalar { .. })
                )
                || matches!(
                    self.projected_sema_ty(rhs),
                    Some(Ty::F32 | Ty::UnitScalar { .. })
                );
            if common_f64 {
                if c_op == "%" {
                    let _ = writeln!(s, "    {d} = fmod((double)({l}), (double)({r}));");
                } else {
                    let _ = writeln!(s, "    {d} = ((double)({l})) {c_op} ((double)({r}));");
                }
                return Ok(());
            }
            if common_f32 {
                if c_op == "%" {
                    let _ = writeln!(s, "    {d} = fmodf((float)({l}), (float)({r}));");
                } else {
                    let _ = writeln!(s, "    {d} = ((float)({l})) {c_op} ((float)({r}));");
                }
                return Ok(());
            }
            if matches!(c_op, "/" | "%") {
                let dty = self.local_ty(dst).cloned().unwrap_or(lty.clone());
                let is_64 = matches!(
                    dty,
                    MirType::I64 | MirType::U64 | MirType::Entity | MirType::Sym
                ) || matches!(lty, MirType::I64 | MirType::U64)
                    || matches!(rty, MirType::I64 | MirType::U64);
                let is_unsigned = matches!(
                    dty,
                    MirType::U8 | MirType::U16 | MirType::U32 | MirType::U64
                ) || matches!(lty, MirType::U32 | MirType::U64)
                    || matches!(rty, MirType::U32 | MirType::U64);
                let helper = match (is_64, is_unsigned, c_op) {
                    (true, true, "/") => "strata_u64_div",
                    (true, true, _) => "strata_u64_rem",
                    (true, false, "/") => "strata_i64_div",
                    (true, false, _) => "strata_i64_rem",
                    (false, true, "/") => "strata_u32_div",
                    (false, true, _) => "strata_u32_rem",
                    (false, false, "/") => "strata_i32_div",
                    (false, false, _) => "strata_i32_rem",
                };
                let dst_cty = self.parent.c_ty(&dty);
                let _ = writeln!(s, "    {d} = ({dst_cty}){helper}(({l}), ({r}));");
                return Ok(());
            }
        }
        if is_cmp {
            let l_is_ptr = self.is_ptr_local(lhs) && !self.projected_fields.contains_key(&lhs);
            let r_is_ptr = self.is_ptr_local(rhs) && !self.projected_fields.contains_key(&rhs);
            let l_is_agg = (!l_is_ptr && self.parent.is_aggregate_mir_ty(&lty))
                || self.is_projected_aggregate(lhs);
            let r_is_agg = (!r_is_ptr && self.parent.is_aggregate_mir_ty(&rty))
                || self.is_projected_aggregate(rhs);
            let is_float = |id: LocalId, ty: &MirType| {
                matches!(ty, MirType::F32 | MirType::F64)
                    || matches!(
                        self.projected_sema_ty(id),
                        Some(Ty::F32 | Ty::F64 | Ty::UnitScalar { .. })
                    )
            };
            let is_u64 = |id: LocalId, ty: &MirType| {
                matches!(ty, MirType::U64 | MirType::Entity)
                    || matches!(
                        self.projected_sema_ty(id),
                        Some(Ty::U64 | Ty::BitSet(_) | Ty::Ref(_))
                    )
            };
            let is_scalar = |id: LocalId, ty: &MirType| {
                if is_float(id, ty) {
                    return false;
                }
                if let Some(sty) = self.projected_sema_ty(id) {
                    return !Self::is_sema_aggregate(self.parent, sty);
                }
                matches!(
                    ty,
                    MirType::Unit
                        | MirType::Bool
                        | MirType::I8
                        | MirType::I16
                        | MirType::I32
                        | MirType::I64
                        | MirType::U8
                        | MirType::U16
                        | MirType::U32
                        | MirType::U64
                        | MirType::Fix32
                        | MirType::Fix64
                        | MirType::Sym
                        | MirType::Entity
                )
            };
            if matches!(c_op, "==" | "!=") && (l_is_ptr || r_is_ptr) {
                let cmp = if c_op == "==" { "== 0" } else { "!= 0" };
                if l_is_ptr && !r_is_ptr && !is_scalar(rhs, &rty) {
                    let r_cty = self.operand_c_ty(rhs);
                    let _ = writeln!(s, "    {{");
                    let _ = writeln!(s, "        {r_cty} _cr = {r};");
                    let _ = writeln!(
                        s,
                        "        {d} = ({l} != NULL && memcmp({l}, &_cr, sizeof(_cr)) {cmp}) ? BAM_TRUE : BAM_FALSE;"
                    );
                    let _ = writeln!(s, "    }}");
                } else if r_is_ptr && !l_is_ptr && !is_scalar(lhs, &lty) {
                    let l_cty = self.operand_c_ty(lhs);
                    let _ = writeln!(s, "    {{");
                    let _ = writeln!(s, "        {l_cty} _cl = {l};");
                    let _ = writeln!(
                        s,
                        "        {d} = ({r} != NULL && memcmp({r}, &_cl, sizeof(_cl)) {cmp}) ? BAM_TRUE : BAM_FALSE;"
                    );
                    let _ = writeln!(s, "    }}");
                } else {
                    let _ = writeln!(
                        s,
                        "    {d} = (((uintptr_t)({l})) {c_op} ((uintptr_t)({r}))) ? BAM_TRUE : BAM_FALSE;"
                    );
                }
            } else if matches!(c_op, "==" | "!=") && (l_is_agg || r_is_agg) {
                let l_cty = self.operand_c_ty(lhs);
                let r_cty = self.operand_c_ty(rhs);
                let cmp = if c_op == "==" { "== 0" } else { "!= 0" };
                let _ = writeln!(s, "    {{");
                let _ = writeln!(s, "        {l_cty} _cl = {l};");
                let _ = writeln!(s, "        {r_cty} _cr = {r};");
                let _ = writeln!(
                    s,
                    "        {d} = (memcmp(&_cl, &_cr, sizeof(_cl) <= sizeof(_cr) ? sizeof(_cl) : sizeof(_cr)) {cmp}) ? BAM_TRUE : BAM_FALSE;"
                );
                let _ = writeln!(s, "    }}");
            } else if is_scalar(lhs, &lty) && is_scalar(rhs, &rty) && !matches!(c_op, "&&" | "||") {
                if is_u64(lhs, &lty) || is_u64(rhs, &rty) {
                    let _ = writeln!(
                        s,
                        "    {d} = (((uint64_t)({l})) {c_op} ((uint64_t)({r}))) ? BAM_TRUE : BAM_FALSE;"
                    );
                } else {
                    let _ = writeln!(
                        s,
                        "    {d} = (((int64_t)({l})) {c_op} ((int64_t)({r}))) ? BAM_TRUE : BAM_FALSE;"
                    );
                }
            } else {
                let _ = writeln!(s, "    {d} = (({l}) {c_op} ({r})) ? BAM_TRUE : BAM_FALSE;");
            }
        } else {
            let _ = writeln!(s, "    {d} = ({l}) {c_op} ({r});");
        }
        Ok(())
    }

    pub(super) fn emit_unop(&self, dst: LocalId, op: &str, val: LocalId, s: &mut String) {
        let d = self.local_expr(dst);
        let r = self.local_expr(val);
        let src_ty = self.local_ty(val).cloned().unwrap_or(MirType::I32);
        match op {
            "-" | "Neg" => match src_ty {
                MirType::Vec2 => {
                    let _ = writeln!(s, "    {d} = strata_vec2(-{r}.x, -{r}.y);");
                }
                MirType::Vec3 => {
                    let _ = writeln!(s, "    {d} = strata_vec3(-{r}.x, -{r}.y, -{r}.z);");
                }
                MirType::Vec4 => {
                    let _ = writeln!(s, "    {d} = strata_vec4(-{r}.x, -{r}.y, -{r}.z, -{r}.w);");
                }
                MirType::IVec2 => {
                    let _ = writeln!(
                        s,
                        "    {d} = strata_ivec2((int32_t)(0u - (uint32_t)({r}.x)), (int32_t)(0u - (uint32_t)({r}.y)));"
                    );
                }
                MirType::IVec3 => {
                    let _ = writeln!(
                        s,
                        "    {d} = strata_ivec3((int32_t)(0u - (uint32_t)({r}.x)), (int32_t)(0u - (uint32_t)({r}.y)), (int32_t)(0u - (uint32_t)({r}.z)));"
                    );
                }
                MirType::I32 | MirType::Fix32 => {
                    let _ = writeln!(s, "    {d} = ((int32_t)(0u - (uint32_t)({r})));");
                }
                MirType::I64 | MirType::Fix64 => {
                    let _ = writeln!(s, "    {d} = ((int64_t)(0ull - (uint64_t)({r})));");
                }
                _ => {
                    let _ = writeln!(s, "    {d} = -({r});");
                }
            },
            "!" | "Not" => {
                let _ = writeln!(s, "    {d} = (!({r})) ? BAM_TRUE : BAM_FALSE;");
            }
            _ => {
                let _ = writeln!(s, "    {d} = ~({r});");
            }
        }
    }

    pub(super) fn emit_intrinsic_math(
        &self,
        dst: LocalId,
        name: &str,
        args: &[LocalId],
        s: &mut String,
    ) {
        let d = self.local_expr(dst);
        let a = |i: usize| {
            args.get(i)
                .map(|id| self.local_expr(*id))
                .unwrap_or_else(|| "0.0f".to_string())
        };
        let vec_kind = args
            .iter()
            .find_map(|id| match self.effective_vec_ty(*id) {
                Some(MirType::Vec3) => Some(MirType::Vec3),
                Some(MirType::Vec4) => Some(MirType::Vec4),
                _ => None,
            })
            .or_else(|| args.first().and_then(|id| self.effective_vec_ty(*id)))
            .unwrap_or(MirType::Vec2);
        let av = |i: usize| {
            args.get(i)
                .map(|id| self.unwrap_operand_expr(*id, Some(&vec_kind)))
                .unwrap_or_else(|| "strata_vec2(0.0f, 0.0f)".to_string())
        };
        let d_ty = self.local_ty(dst).cloned().unwrap_or(MirType::F32);
        let is_f64 = matches!(d_ty, MirType::F64)
            || args
                .iter()
                .any(|id| matches!(self.local_ty(*id), Some(MirType::F64)));
        let t0 = vec_kind.clone();
        match short_name(name) {
            "sin" => {
                if is_f64 {
                    let _ = writeln!(s, "    {d} = sin((double){});", a(0));
                } else {
                    let _ = writeln!(s, "    {d} = sinf((float){});", a(0));
                }
            }
            "cos" => {
                if is_f64 {
                    let _ = writeln!(s, "    {d} = cos((double){});", a(0));
                } else {
                    let _ = writeln!(s, "    {d} = cosf((float){});", a(0));
                }
            }
            "tan" => {
                if is_f64 {
                    let _ = writeln!(s, "    {d} = tan((double){});", a(0));
                } else {
                    let _ = writeln!(s, "    {d} = tanf((float){});", a(0));
                }
            }
            "atan2" => {
                if is_f64 {
                    let _ = writeln!(s, "    {d} = atan2((double){}, (double){});", a(0), a(1));
                } else {
                    let _ = writeln!(s, "    {d} = atan2f((float){}, (float){});", a(0), a(1));
                }
            }
            "sqrt" => {
                if is_f64 {
                    let _ = writeln!(s, "    {d} = sqrt((double){});", a(0));
                } else {
                    let _ = writeln!(s, "    {d} = sqrtf((float){});", a(0));
                }
            }
            "abs" => {
                if matches!(
                    d_ty,
                    MirType::I32 | MirType::I64 | MirType::I16 | MirType::I8
                ) {
                    let x = a(0);
                    let _ = writeln!(s, "    {d} = ({x} < 0) ? -{x} : {x};");
                } else if is_f64 {
                    let _ = writeln!(s, "    {d} = fabs((double){});", a(0));
                } else {
                    let _ = writeln!(s, "    {d} = fabsf((float){});", a(0));
                }
            }
            "min" => {
                let x = a(0);
                let y = a(1);
                if is_f64 {
                    let _ = writeln!(s, "    {d} = fmin((double){x}, (double){y});");
                } else if matches!(d_ty, MirType::F32) {
                    let _ = writeln!(s, "    {d} = fminf({x}, {y});");
                } else {
                    let _ = writeln!(s, "    {d} = ({x} < {y}) ? {x} : {y};");
                }
            }
            "max" => {
                let x = a(0);
                let y = a(1);
                if is_f64 {
                    let _ = writeln!(s, "    {d} = fmax((double){x}, (double){y});");
                } else if matches!(d_ty, MirType::F32) {
                    let _ = writeln!(s, "    {d} = fmaxf({x}, {y});");
                } else {
                    let _ = writeln!(s, "    {d} = ({x} > {y}) ? {x} : {y};");
                }
            }
            "floor" => {
                if is_f64 {
                    let _ = writeln!(s, "    {d} = floor((double){});", a(0));
                } else {
                    let _ = writeln!(s, "    {d} = floorf((float){});", a(0));
                }
            }
            "ceil" => {
                if is_f64 {
                    let _ = writeln!(s, "    {d} = ceil((double){});", a(0));
                } else {
                    let _ = writeln!(s, "    {d} = ceilf((float){});", a(0));
                }
            }
            "round" => {
                if is_f64 {
                    let _ = writeln!(s, "    {d} = round((double){});", a(0));
                } else {
                    let _ = writeln!(s, "    {d} = roundf((float){});", a(0));
                }
            }
            "trunc" => {
                if is_f64 {
                    let _ = writeln!(s, "    {d} = trunc((double){});", a(0));
                } else {
                    let _ = writeln!(s, "    {d} = truncf((float){});", a(0));
                }
            }
            "pow" | "powf" => {
                if is_f64 {
                    let _ = writeln!(s, "    {d} = pow((double){}, (double){});", a(0), a(1));
                } else {
                    let _ = writeln!(s, "    {d} = powf((float){}, (float){});", a(0), a(1));
                }
            }
            "exp" => {
                if is_f64 {
                    let _ = writeln!(s, "    {d} = exp((double){});", a(0));
                } else {
                    let _ = writeln!(s, "    {d} = expf((float){});", a(0));
                }
            }
            "log" | "ln" => {
                if is_f64 {
                    let _ = writeln!(s, "    {d} = log((double){});", a(0));
                } else {
                    let _ = writeln!(s, "    {d} = logf((float){});", a(0));
                }
            }
            "clamp" => {
                let x = a(0);
                let lo = a(1);
                let hi = a(2);
                let _ = writeln!(
                    s,
                    "    {d} = ({x} < {lo}) ? {lo} : (({x} > {hi}) ? {hi} : {x});"
                );
            }
            "lerp" => match d_ty {
                MirType::Vec2 => {
                    let _ = writeln!(
                        s,
                        "    {d} = strata_vec2_lerp({}, {}, {});",
                        a(0),
                        a(1),
                        a(2)
                    );
                }
                MirType::Vec3 => {
                    let _ = writeln!(
                        s,
                        "    {d} = strata_vec3_lerp({}, {}, {});",
                        a(0),
                        a(1),
                        a(2)
                    );
                }
                _ if is_f64 => {
                    let x0 = a(0);
                    let x1 = a(1);
                    let t = a(2);
                    let _ = writeln!(
                        s,
                        "    {d} = ((double){x0} + ((double){x1} - (double){x0}) * (double){t});"
                    );
                }
                _ => {
                    let _ = writeln!(
                        s,
                        "    {d} = strata_lerp_f32((float){}, (float){}, (float){});",
                        a(0),
                        a(1),
                        a(2)
                    );
                }
            },
            "dot" => match t0 {
                MirType::Vec3 => {
                    let _ = writeln!(s, "    {d} = strata_vec3_dot({}, {});", av(0), av(1));
                }
                MirType::Vec4 => {
                    let _ = writeln!(s, "    {d} = strata_vec4_dot({}, {});", av(0), av(1));
                }
                _ => {
                    let _ = writeln!(s, "    {d} = strata_vec2_dot({}, {});", av(0), av(1));
                }
            },
            "length" => match t0 {
                MirType::Vec3 => {
                    let _ = writeln!(s, "    {d} = strata_vec3_len({});", av(0));
                }
                MirType::Vec4 => {
                    let _ = writeln!(s, "    {d} = strata_vec4_len({});", av(0));
                }
                _ => {
                    let _ = writeln!(s, "    {d} = strata_vec2_len({});", av(0));
                }
            },
            "length_sq" => match t0 {
                MirType::Vec3 => {
                    let _ = writeln!(s, "    {d} = strata_vec3_len_sq({});", av(0));
                }
                _ => {
                    let _ = writeln!(s, "    {d} = strata_vec2_len_sq({});", av(0));
                }
            },
            "distance" => match t0 {
                MirType::Vec3 => {
                    let _ = writeln!(s, "    {d} = strata_vec3_dist({}, {});", av(0), av(1));
                }
                _ => {
                    let _ = writeln!(s, "    {d} = strata_vec2_dist({}, {});", av(0), av(1));
                }
            },
            "distance_sq" => match t0 {
                MirType::Vec3 => {
                    let _ = writeln!(s, "    {d} = strata_vec3_dist_sq({}, {});", av(0), av(1));
                }
                _ => {
                    let _ = writeln!(s, "    {d} = strata_vec2_dist_sq({}, {});", av(0), av(1));
                }
            },
            "normalize" | "normalize_or_zero" => match d_ty {
                MirType::Vec3 => {
                    let _ = writeln!(s, "    {d} = strata_vec3_norm({});", av(0));
                }
                MirType::Vec4 => {
                    let _ = writeln!(s, "    {d} = strata_vec4_norm({});", av(0));
                }
                _ => {
                    let _ = writeln!(s, "    {d} = strata_vec2_norm({});", av(0));
                }
            },
            "cross" => {
                if self.local_ty(args[0]) == Some(&MirType::Vec4)
                    || matches!(self.local_ty(dst), Some(MirType::Vec4))
                {
                    let a0 = av(0);
                    let a1 = av(1);
                    let _ = writeln!(
                        s,
                        "    {{ StrataVec3 _cr = strata_vec3_cross(strata_vec3({a0}.x, {a0}.y, {a0}.z), strata_vec3({a1}.x, {a1}.y, {a1}.z)); {d} = strata_vec4(_cr.x, _cr.y, _cr.z, 0.0f); }}"
                    );
                } else {
                    let _ = writeln!(s, "    {d} = strata_vec3_cross({}, {});", av(0), av(1));
                }
            }
            "vec2" | "Vec2" => {
                let _ = writeln!(s, "    {d} = strata_vec2({}, {});", a(0), a(1));
            }
            "vec3" | "Vec3" => {
                let _ = writeln!(s, "    {d} = strata_vec3({}, {}, {});", a(0), a(1), a(2));
            }
            "vec3a" | "Vec3a" => {
                let _ = writeln!(
                    s,
                    "    {d} = strata_vec4({}, {}, {}, 0.0f);",
                    a(0),
                    a(1),
                    a(2)
                );
            }
            "vec4" | "Vec4" | "quat" | "Quat" | "rgba" | "Rgba" => {
                let _ = writeln!(
                    s,
                    "    {d} = strata_vec4({}, {}, {}, {});",
                    a(0),
                    a(1),
                    a(2),
                    a(3)
                );
            }
            "ivec2" | "IVec2" => {
                let _ = writeln!(
                    s,
                    "    {d} = strata_ivec2((int32_t)({}), (int32_t)({}));",
                    a(0),
                    a(1)
                );
            }
            "ivec3" | "IVec3" => {
                let _ = writeln!(
                    s,
                    "    {d} = strata_ivec3((int32_t)({}), (int32_t)({}), (int32_t)({}));",
                    a(0),
                    a(1),
                    a(2)
                );
            }
            "uvec2" | "UVec2" => {
                let _ = writeln!(
                    s,
                    "    {d} = strata_uvec2((uint32_t)({}), (uint32_t)({}));",
                    a(0),
                    a(1)
                );
            }
            "from_rotation_y" | "quat_from_rotation_y" => {
                let _ = writeln!(s, "    {d} = strata_quat_from_rotation_y({});", a(0));
            }
            "sqr" => {
                if is_f64 {
                    let x = a(0);
                    let _ = writeln!(s, "    {d} = ((double){x} * (double){x});");
                } else {
                    let _ = writeln!(s, "    {d} = strata_sqr_f32((float){});", a(0));
                }
            }
            "signum" => {
                if is_f64 {
                    let x = a(0);
                    let _ = writeln!(
                        s,
                        "    {d} = ((double){x} > 0.0) ? 1.0 : (((double){x} < 0.0) ? -1.0 : 0.0);"
                    );
                } else {
                    let _ = writeln!(s, "    {d} = strata_signum_f32((float){});", a(0));
                }
            }
            _ => {
                let _ = writeln!(
                    s,
                    "    /* intrinsic `{name}` */ memset(&{d}, 0, sizeof({d}));"
                );
            }
        }
    }

    pub(super) fn resolve_member_in_layout(
        &self,
        layout_key: &str,
        field_name: &str,
        offset_bytes: u32,
        target_ty: Option<&MirType>,
    ) -> Option<(usize, String, String)> {
        let (l_idx, ptr_cast, path, _, _) =
            self.resolve_member_with_ty(layout_key, field_name, offset_bytes, target_ty)?;
        Some((l_idx, ptr_cast, path))
    }

    pub(super) fn resolve_member_with_ty(
        &self,
        layout_key: &str,
        field_name: &str,
        offset_bytes: u32,
        target_ty: Option<&MirType>,
    ) -> Option<(usize, String, String, Ty, usize)> {
        let l_idx = self.parent.find_layout_idx(layout_key)?;
        let layout = &self.parent.layouts[l_idx];
        let (path, fty, fsz) = self.resolve_path_in_fields(
            &layout.fields,
            field_name,
            offset_bytes as usize,
            target_ty,
        )?;
        let ptr_cast = format!("const {}", self.parent.layout_c_names[l_idx]);
        Some((l_idx, ptr_cast, path, fty, fsz))
    }

    pub(super) fn resolve_path_in_fields(
        &self,
        fields: &[SolvedField],
        field_name: &str,
        rel_offset: usize,
        target_ty: Option<&MirType>,
    ) -> Option<(String, Ty, usize)> {
        // Prefer exact offset match when type also aligns in C99 representation.
        for f in fields {
            if f.is_padding {
                continue;
            }
            if f.offset == rel_offset
                && (field_name.is_empty() || f.name == field_name)
                && target_ty.is_none_or(|tt| ty_matches_sema(&f.ty, tt))
            {
                return Some((sanitize_c_field(&f.name), f.ty.clone(), f.size));
            }
        }
        // Try nested subfield traversal.
        for f in fields {
            if f.is_padding {
                continue;
            }
            if rel_offset >= f.offset && rel_offset < f.offset + f.size {
                let sub_off = rel_offset - f.offset;
                let sub_field = field_name
                    .strip_prefix(&format!("{}.", f.name))
                    .unwrap_or(field_name);
                if let Some((sub_path, sub_ty, sub_sz)) =
                    self.resolve_path_in_sema_ty(&f.ty, sub_field, sub_off, target_ty)
                {
                    return Some((
                        format!("{}.{sub_path}", sanitize_c_field(&f.name)),
                        sub_ty,
                        sub_sz,
                    ));
                }
            }
        }
        None
    }

    pub(super) fn resolve_path_in_sema_ty(
        &self,
        ty: &Ty,
        field_name: &str,
        rel_offset: usize,
        target_ty: Option<&MirType>,
    ) -> Option<(String, Ty, usize)> {
        match ty {
            Ty::Vec2 => match (rel_offset, target_ty) {
                (0, None | Some(MirType::F32)) => Some(("x".to_string(), Ty::F32, 4)),
                (4, None | Some(MirType::F32)) => Some(("y".to_string(), Ty::F32, 4)),
                _ => None,
            },
            Ty::Vec3 => match (rel_offset, target_ty) {
                (0, None | Some(MirType::F32)) => Some(("x".to_string(), Ty::F32, 4)),
                (4, None | Some(MirType::F32)) => Some(("y".to_string(), Ty::F32, 4)),
                (8, None | Some(MirType::F32)) => Some(("z".to_string(), Ty::F32, 4)),
                _ => None,
            },
            Ty::Vec4 | Ty::Quat | Ty::Rgba | Ty::Vec3a => match (rel_offset, target_ty) {
                (0, None | Some(MirType::F32)) => Some(("x".to_string(), Ty::F32, 4)),
                (4, None | Some(MirType::F32)) => Some(("y".to_string(), Ty::F32, 4)),
                (8, None | Some(MirType::F32)) => Some(("z".to_string(), Ty::F32, 4)),
                (12, None | Some(MirType::F32)) => Some(("w".to_string(), Ty::F32, 4)),
                _ => None,
            },
            Ty::IVec2 => match (rel_offset, target_ty) {
                (0, None | Some(MirType::I32 | MirType::U32)) => {
                    Some(("x".to_string(), Ty::I32, 4))
                }
                (4, None | Some(MirType::I32 | MirType::U32)) => {
                    Some(("y".to_string(), Ty::I32, 4))
                }
                _ => None,
            },
            Ty::UVec2 => match (rel_offset, target_ty) {
                (0, None | Some(MirType::I32 | MirType::U32)) => {
                    Some(("x".to_string(), Ty::U32, 4))
                }
                (4, None | Some(MirType::I32 | MirType::U32)) => {
                    Some(("y".to_string(), Ty::U32, 4))
                }
                _ => None,
            },
            Ty::IVec3 => match (rel_offset, target_ty) {
                (0, None | Some(MirType::I32)) => Some(("x".to_string(), Ty::I32, 4)),
                (4, None | Some(MirType::I32)) => Some(("y".to_string(), Ty::I32, 4)),
                (8, None | Some(MirType::I32)) => Some(("z".to_string(), Ty::I32, 4)),
                _ => None,
            },
            Ty::Named(key) => {
                let l_idx = self.parent.find_layout_idx(key)?;
                self.resolve_path_in_fields(
                    &self.parent.layouts[l_idx].fields,
                    field_name,
                    rel_offset,
                    target_ty,
                )
            }
            _ => None,
        }
    }

    pub(super) fn is_c_scalar_field(&self, ty: &Ty, byte_size: usize) -> bool {
        match ty {
            Ty::Bool
            | Ty::U8
            | Ty::I8
            | Ty::I16
            | Ty::U16
            | Ty::I32
            | Ty::Fix32
            | Ty::U32
            | Ty::Sym
            | Ty::Rgba8
            | Ty::I64
            | Ty::Fix64
            | Ty::U64
            | Ty::F32
            | Ty::UnitScalar { .. }
            | Ty::F64 => true,
            Ty::Ref(_) => byte_size == 8,
            Ty::Named(key) => {
                !self
                    .parent
                    .find_layout_idx(key)
                    .is_some_and(|l_idx| self.parent.layouts[l_idx].size == byte_size)
                    && matches!(byte_size, 1 | 2 | 4 | 8)
            }
            _ => false,
        }
    }

    pub(super) fn c_field_scalar_ty(&self, ty: &Ty, byte_size: usize) -> &'static str {
        match ty {
            Ty::Bool | Ty::U8 => "uint8_t",
            Ty::I8 => "int8_t",
            Ty::I16 => "int16_t",
            Ty::U16 => "uint16_t",
            Ty::U32 | Ty::Sym | Ty::Rgba8 => "uint32_t",
            Ty::I64 | Ty::Fix64 => "int64_t",
            Ty::U64 => "uint64_t",
            Ty::F32 | Ty::UnitScalar { .. } => {
                if byte_size == 8 {
                    "double"
                } else {
                    "float"
                }
            }
            Ty::F64 => "double",
            Ty::Ref(_) => "BamEntity",
            Ty::Named(_) => match byte_size {
                1 => "uint8_t",
                2 => "uint16_t",
                4 => "int32_t",
                _ => "int64_t",
            },
            // Covers `Ty::I32`, `Ty::Fix32`, and remaining 32-bit integer scalars.
            _ => "int32_t",
        }
    }

    pub(super) fn is_ptr_local(&self, id: LocalId) -> bool {
        self.ptr_meta.contains_key(&id)
            || matches!(self.local_ty(id), Some(MirType::Ptr | MirType::MutPtr))
    }

    pub(super) fn resolve_tuple_or_vec_member(
        &self,
        ty: &MirType,
        field: &str,
        offset_bytes: u32,
    ) -> Option<String> {
        match ty {
            MirType::Tuple(elems) => {
                if let Ok(idx) = field
                    .trim_start_matches('f')
                    .trim_start_matches('_')
                    .parse::<usize>()
                    && idx < elems.len()
                {
                    return Some(format!("f{idx}"));
                }
                let mut off = 0u32;
                for (i, et) in elems.iter().enumerate() {
                    let (sz, al) = approx_mir_size_align(et);
                    let rem = off % al;
                    if rem != 0 {
                        off += al - rem;
                    }
                    if off == offset_bytes {
                        return Some(format!("f{i}"));
                    }
                    off += sz;
                }
                None
            }
            MirType::Vec2 | MirType::IVec2 | MirType::UVec2 => match (field, offset_bytes) {
                ("x", _) | (_, 0) => Some("x".to_string()),
                ("y", _) | (_, 4) => Some("y".to_string()),
                _ => None,
            },
            MirType::Vec3 | MirType::IVec3 => match (field, offset_bytes) {
                ("x", _) | (_, 0) => Some("x".to_string()),
                ("y", _) | (_, 4) => Some("y".to_string()),
                ("z", _) | (_, 8) => Some("z".to_string()),
                _ => None,
            },
            MirType::Vec4 => match (field, offset_bytes) {
                ("x", _) | (_, 0) => Some("x".to_string()),
                ("y", _) | (_, 4) => Some("y".to_string()),
                ("z", _) | (_, 8) => Some("z".to_string()),
                ("w", _) | (_, 12) => Some("w".to_string()),
                _ => None,
            },
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn emit_field_load(
        &self,
        dst: LocalId,
        base_ptr: LocalId,
        layout_key: &str,
        field: &str,
        offset_bytes: u32,
        field_ty: &MirType,
        s: &mut String,
    ) {
        let d = self.local_expr(dst);
        let p = self.local_expr(base_ptr);

        if !self.is_ptr_local(base_ptr) {
            if let Some(MirType::Named(k)) = self.local_ty(base_ptr)
                && let Some(tname) = k.strip_prefix("__strata_table_")
                && let Some(tbl) = self.parent.mir.tables.iter().find(|tb| tb.name == tname)
                && !field.is_empty()
                && tbl.fields.iter().any(|(fnm, _)| fnm == field)
            {
                let fc = sanitize_c_field(field);
                if matches!(field_ty, MirType::Bool) {
                    let _ = writeln!(s, "    {d} = ({p}.{fc}) ? BAM_TRUE : BAM_FALSE;");
                } else {
                    let _ = writeln!(s, "    {d} = {p}.{fc};");
                }
                return;
            }
            if let Some(bty) = self.local_ty(base_ptr).cloned()
                && let Some(mem) = self.resolve_tuple_or_vec_member(&bty, field, offset_bytes)
            {
                let dst_ty = self
                    .local_ty(dst)
                    .cloned()
                    .unwrap_or_else(|| field_ty.clone());
                let src_ty_opt = match &bty {
                    MirType::Tuple(elems) => mem
                        .strip_prefix('f')
                        .and_then(|n| n.parse::<usize>().ok())
                        .and_then(|idx| elems.get(idx).cloned()),
                    _ => None,
                };
                let src_expr = format!("{p}.{mem}");
                if let Some(src_ty) = src_ty_opt
                    && src_ty != dst_ty
                {
                    if let (
                        MirType::Array { elem: se, len: sl },
                        MirType::Array { elem: de, len: dl },
                    ) = (&src_ty, &dst_ty)
                        && sl == dl
                    {
                        for j in 0..*dl {
                            let item = format!("{src_expr}.data[{j}]");
                            let rhs = match (se.as_ref(), de.as_ref()) {
                                (MirType::F32 | MirType::F64, MirType::Fix32) => {
                                    format!("strata_f64_to_fix32((double)({item}))")
                                }
                                (
                                    MirType::I8
                                    | MirType::I16
                                    | MirType::I32
                                    | MirType::I64
                                    | MirType::U8
                                    | MirType::U16
                                    | MirType::U32
                                    | MirType::U64,
                                    MirType::Fix32,
                                ) => format!("(int32_t)((int64_t)({item}) * 65536ll)"),
                                (MirType::F32 | MirType::F64, MirType::Fix64) => {
                                    format!("strata_f64_to_fix64((double)({item}))")
                                }
                                (
                                    MirType::I8
                                    | MirType::I16
                                    | MirType::I32
                                    | MirType::I64
                                    | MirType::U8
                                    | MirType::U16
                                    | MirType::U32
                                    | MirType::U64,
                                    MirType::Fix64,
                                ) => format!("(int64_t)((int64_t)({item}) * 4294967296ll)"),
                                _ if se != de => {
                                    let cty = self.parent.c_ty(de);
                                    format!("({cty})({item})")
                                }
                                _ => item,
                            };
                            let _ = writeln!(s, "    {d}.data[{j}] = {rhs};");
                        }
                        return;
                    }
                    let cty = self.parent.c_ty(&dst_ty);
                    let _ = writeln!(s, "    {d} = ({cty})({src_expr});");
                    return;
                }
                if matches!(field_ty, MirType::Bool) {
                    let _ = writeln!(s, "    {d} = ({src_expr}) ? BAM_TRUE : BAM_FALSE;");
                } else {
                    let _ = writeln!(s, "    {d} = {src_expr};");
                }
                return;
            }
            let effective_key = if !layout_key.is_empty() {
                Some(layout_key.to_string())
            } else if let Some(MirType::Named(k)) = self.local_ty(base_ptr) {
                Some(k.clone())
            } else {
                None
            };
            if let Some(ref lk) = effective_key {
                if let Some((_, _, path)) =
                    self.resolve_member_in_layout(lk, field, offset_bytes, Some(field_ty))
                {
                    if matches!(field_ty, MirType::Bool) {
                        let _ = writeln!(s, "    {d} = ({p}.{path}) ? BAM_TRUE : BAM_FALSE;");
                    } else {
                        let _ = writeln!(s, "    {d} = {p}.{path};");
                    }
                    return;
                }
                if !self.parent.is_aggregate_mir_ty(field_ty)
                    && let Some((_, _, path, fty, fsz)) =
                        self.resolve_member_with_ty(lk, field, offset_bytes, None)
                    && self.is_c_scalar_field(&fty, fsz)
                    && matches!(field_ty, MirType::F32 | MirType::F64)
                        == matches!(fty, Ty::F32 | Ty::F64 | Ty::UnitScalar { .. })
                {
                    if matches!(field_ty, MirType::Bool) {
                        let _ = writeln!(s, "    {d} = ({p}.{path}) ? BAM_TRUE : BAM_FALSE;");
                    } else {
                        let dst_c = self.parent.c_ty(field_ty);
                        let _ = writeln!(s, "    {d} = ({dst_c})({p}.{path});");
                    }
                    return;
                }
            }
            let _ = writeln!(
                s,
                "    memcpy(&{d}, ((const uint8_t*)&{p}) + {offset_bytes}u, sizeof({d}));"
            );
            return;
        }

        let effective_key = if !layout_key.is_empty() {
            Some(layout_key.to_string())
        } else if let Some(PtrKind::LayoutPtr { layout_idx, .. }) = self.ptr_meta.get(&base_ptr) {
            Some(self.parent.layouts[*layout_idx].canonical_name.clone())
        } else {
            None
        };
        if let Some(ref lk) = effective_key {
            if let Some((l_idx, _, path)) =
                self.resolve_member_in_layout(lk, field, offset_bytes, Some(field_ty))
            {
                let same_ptr = matches!(
                    self.ptr_meta.get(&base_ptr),
                    Some(PtrKind::LayoutPtr { layout_idx, .. }) if *layout_idx == l_idx
                );
                let access = if same_ptr {
                    format!("{p}->{path}")
                } else {
                    let cty = &self.parent.layout_c_names[l_idx];
                    format!("((const {cty}* BAM_RESTRICT){p})->{path}")
                };
                if self.nonnull_ptrs.contains(&base_ptr) {
                    if matches!(field_ty, MirType::Bool) {
                        let _ = writeln!(s, "    {d} = ({access}) ? BAM_TRUE : BAM_FALSE;");
                    } else {
                        let _ = writeln!(s, "    {d} = {access};");
                    }
                } else if matches!(field_ty, MirType::Bool) {
                    let _ = writeln!(
                        s,
                        "    if ({p} != NULL) {{ {d} = ({access}) ? BAM_TRUE : BAM_FALSE; }}"
                    );
                } else {
                    let _ = writeln!(s, "    if ({p} != NULL) {{ {d} = {access}; }}");
                }
                return;
            }
            if !self.parent.is_aggregate_mir_ty(field_ty)
                && let Some((l_idx, _, path, fty, fsz)) =
                    self.resolve_member_with_ty(lk, field, offset_bytes, None)
                && self.is_c_scalar_field(&fty, fsz)
                && matches!(field_ty, MirType::F32 | MirType::F64)
                    == matches!(fty, Ty::F32 | Ty::F64 | Ty::UnitScalar { .. })
            {
                let same_ptr = matches!(
                    self.ptr_meta.get(&base_ptr),
                    Some(PtrKind::LayoutPtr { layout_idx, .. }) if *layout_idx == l_idx
                );
                let access = if same_ptr {
                    format!("{p}->{path}")
                } else {
                    let cty = &self.parent.layout_c_names[l_idx];
                    format!("((const {cty}* BAM_RESTRICT){p})->{path}")
                };
                if self.nonnull_ptrs.contains(&base_ptr) {
                    if matches!(field_ty, MirType::Bool) {
                        let _ = writeln!(s, "    {d} = ({access}) ? BAM_TRUE : BAM_FALSE;");
                    } else {
                        let dst_c = self.parent.c_ty(field_ty);
                        let _ = writeln!(s, "    {d} = ({dst_c})({access});");
                    }
                } else if matches!(field_ty, MirType::Bool) {
                    let _ = writeln!(
                        s,
                        "    if ({p} != NULL) {{ {d} = ({access}) ? BAM_TRUE : BAM_FALSE; }}"
                    );
                } else {
                    let dst_c = self.parent.c_ty(field_ty);
                    let _ = writeln!(s, "    if ({p} != NULL) {{ {d} = ({dst_c})({access}); }}");
                }
                return;
            }
        }
        if self.nonnull_ptrs.contains(&base_ptr) {
            let _ = writeln!(
                s,
                "    memcpy(&{d}, ((const uint8_t*){p}) + {offset_bytes}u, sizeof({d}));"
            );
        } else {
            let _ = writeln!(
                s,
                "    if ({p} != NULL) {{ memcpy(&{d}, ((const uint8_t*){p}) + {offset_bytes}u, sizeof({d})); }}"
            );
        }
    }

    pub(super) fn emit_field_store(
        &self,
        base_ptr: LocalId,
        layout_key: &str,
        field: &str,
        offset_bytes: u32,
        val: LocalId,
        s: &mut String,
    ) {
        let p = self.local_expr(base_ptr);
        let v = self.local_expr(val);
        let vty = self.local_ty(val).cloned().unwrap_or(MirType::U32);

        if !self.is_ptr_local(base_ptr) {
            if let Some(bty) = self.local_ty(base_ptr)
                && let Some(mem) = self.resolve_tuple_or_vec_member(bty, field, offset_bytes)
            {
                let _ = writeln!(s, "    {p}.{mem} = {v};");
                return;
            }
            let effective_key = if !layout_key.is_empty() {
                Some(layout_key.to_string())
            } else if let Some(MirType::Named(k)) = self.local_ty(base_ptr) {
                Some(k.clone())
            } else {
                None
            };
            if let Some(ref lk) = effective_key {
                if let Some((_, _, path)) =
                    self.resolve_member_in_layout(lk, field, offset_bytes, Some(&vty))
                {
                    let _ = writeln!(s, "    {p}.{path} = {v};");
                    return;
                }
                if let Some((_, _, path, fty, fsz)) =
                    self.resolve_member_with_ty(lk, field, offset_bytes, None)
                {
                    if matches!(fty, Ty::Fix32 | Ty::Fix64) {
                        let rhs =
                            self.coerce_scalar_to_fix_expr(val, &vty, matches!(fty, Ty::Fix64));
                        let _ = writeln!(s, "    {p}.{path} = {rhs};");
                        return;
                    }
                    if matches!(fty, Ty::F64) && !matches!(vty, MirType::F64) {
                        let rhs = if let Some(cv) = self.const_defs.get(&val) {
                            self.parent.c_const_val_for_ty(&fty, cv)
                        } else {
                            format!("(double)({v})")
                        };
                        let _ = writeln!(s, "    {p}.{path} = {rhs};");
                        return;
                    }
                    if matches!(fty, Ty::Array { .. }) {
                        self.emit_c_array_bytes_write(&format!("{p}.{path}"), &fty, val, "    ", s);
                        return;
                    }
                    if self.is_c_scalar_field(&fty, fsz) {
                        if matches!(fty, Ty::Bool) {
                            let _ = writeln!(s, "    {p}.{path} = ({v}) ? BAM_TRUE : BAM_FALSE;");
                        } else {
                            let fcty = self.c_field_scalar_ty(&fty, fsz);
                            let _ = writeln!(s, "    {p}.{path} = ({fcty})({v});");
                        }
                        return;
                    }
                    if matches!(&fty, Ty::Named(key) if self.parent.find_layout_idx(key).is_some_and(|li| self.parent.layouts[li].size == fsz))
                        && !self.is_ptr_local(val)
                    {
                        let _ = writeln!(s, "    {p}.{path} = {v};");
                        return;
                    }
                    let _ = writeln!(
                        s,
                        "    memcpy(&({p}.{path}), &{v}, sizeof({p}.{path}) < sizeof({v}) ? sizeof({p}.{path}) : sizeof({v}));"
                    );
                    return;
                }
            }
            let _ = writeln!(
                s,
                "    memcpy(((uint8_t*)&{p}) + {offset_bytes}u, &{v}, sizeof({v}));"
            );
            return;
        }

        let effective_key = if !layout_key.is_empty() {
            Some(layout_key.to_string())
        } else if let Some(PtrKind::LayoutPtr { layout_idx, .. }) = self.ptr_meta.get(&base_ptr) {
            Some(self.parent.layouts[*layout_idx].canonical_name.clone())
        } else {
            None
        };
        if let Some(ref lk) = effective_key {
            if let Some((l_idx, _, path)) =
                self.resolve_member_in_layout(lk, field, offset_bytes, Some(&vty))
            {
                let same_ptr = matches!(
                    self.ptr_meta.get(&base_ptr),
                    Some(PtrKind::LayoutPtr { layout_idx, is_mut: true }) if *layout_idx == l_idx
                );
                let access = if same_ptr {
                    format!("{p}->{path}")
                } else {
                    let cty = &self.parent.layout_c_names[l_idx];
                    format!("(({cty}* BAM_RESTRICT){p})->{path}")
                };
                if self.nonnull_ptrs.contains(&base_ptr) {
                    let _ = writeln!(s, "    {access} = {v};");
                } else {
                    let _ = writeln!(s, "    if ({p} != NULL) {{ {access} = {v}; }}");
                }
                return;
            }
            if let Some((l_idx, _, path, fty, fsz)) =
                self.resolve_member_with_ty(lk, field, offset_bytes, None)
            {
                let same_ptr = matches!(
                    self.ptr_meta.get(&base_ptr),
                    Some(PtrKind::LayoutPtr { layout_idx, is_mut: true }) if *layout_idx == l_idx
                );
                let access = if same_ptr {
                    format!("{p}->{path}")
                } else {
                    let cty = &self.parent.layout_c_names[l_idx];
                    format!("(({cty}* BAM_RESTRICT){p})->{path}")
                };
                if matches!(fty, Ty::Fix32 | Ty::Fix64) {
                    let rhs = self.coerce_scalar_to_fix_expr(val, &vty, matches!(fty, Ty::Fix64));
                    if self.nonnull_ptrs.contains(&base_ptr) {
                        let _ = writeln!(s, "    {access} = {rhs};");
                    } else {
                        let _ = writeln!(s, "    if ({p} != NULL) {{ {access} = {rhs}; }}");
                    }
                    return;
                }
                if matches!(fty, Ty::F64) && !matches!(vty, MirType::F64) {
                    let rhs = if let Some(cv) = self.const_defs.get(&val) {
                        self.parent.c_const_val_for_ty(&fty, cv)
                    } else {
                        format!("(double)({v})")
                    };
                    if self.nonnull_ptrs.contains(&base_ptr) {
                        let _ = writeln!(s, "    {access} = {rhs};");
                    } else {
                        let _ = writeln!(s, "    if ({p} != NULL) {{ {access} = {rhs}; }}");
                    }
                    return;
                }
                if matches!(fty, Ty::Array { .. }) {
                    if self.nonnull_ptrs.contains(&base_ptr) {
                        self.emit_c_array_bytes_write(&access, &fty, val, "    ", s);
                    } else {
                        let _ = writeln!(s, "    if ({p} != NULL) {{");
                        self.emit_c_array_bytes_write(&access, &fty, val, "        ", s);
                        let _ = writeln!(s, "    }}");
                    }
                    return;
                }
                if self.is_c_scalar_field(&fty, fsz) {
                    if self.nonnull_ptrs.contains(&base_ptr) {
                        if matches!(fty, Ty::Bool) {
                            let _ = writeln!(s, "    {access} = ({v}) ? BAM_TRUE : BAM_FALSE;");
                        } else {
                            let fcty = self.c_field_scalar_ty(&fty, fsz);
                            let _ = writeln!(s, "    {access} = ({fcty})({v});");
                        }
                    } else if matches!(fty, Ty::Bool) {
                        let _ = writeln!(
                            s,
                            "    if ({p} != NULL) {{ {access} = ({v}) ? BAM_TRUE : BAM_FALSE; }}"
                        );
                    } else {
                        let fcty = self.c_field_scalar_ty(&fty, fsz);
                        let _ = writeln!(s, "    if ({p} != NULL) {{ {access} = ({fcty})({v}); }}");
                    }
                    return;
                }
                if matches!(&fty, Ty::Named(key) if self.parent.find_layout_idx(key).is_some_and(|li| self.parent.layouts[li].size == fsz))
                    && !self.is_ptr_local(val)
                {
                    if self.nonnull_ptrs.contains(&base_ptr) {
                        let _ = writeln!(s, "    {access} = {v};");
                    } else {
                        let _ = writeln!(s, "    if ({p} != NULL) {{ {access} = {v}; }}");
                    }
                    return;
                }
                let zero_bs = if matches!(fty, Ty::BitSet(_)) {
                    format!("memset(&({access}), 0, sizeof({access})); ")
                } else {
                    String::new()
                };
                if self.nonnull_ptrs.contains(&base_ptr) {
                    let _ = writeln!(
                        s,
                        "    {zero_bs}memcpy(&({access}), &{v}, sizeof({access}) < sizeof({v}) ? sizeof({access}) : sizeof({v}));"
                    );
                } else {
                    let _ = writeln!(
                        s,
                        "    if ({p} != NULL) {{ {zero_bs}memcpy(&({access}), &{v}, sizeof({access}) < sizeof({v}) ? sizeof({access}) : sizeof({v})); }}"
                    );
                }
                return;
            }
        }
        if self.nonnull_ptrs.contains(&base_ptr) {
            let _ = writeln!(
                s,
                "    memcpy(((uint8_t*){p}) + {offset_bytes}u, &{v}, sizeof({v}));"
            );
        } else {
            let _ = writeln!(
                s,
                "    if ({p} != NULL) {{ memcpy(((uint8_t*){p}) + {offset_bytes}u, &{v}, sizeof({v})); }}"
            );
        }
    }

    pub(super) fn emit_field_ptr(
        &self,
        dst: LocalId,
        base_ptr: LocalId,
        layout_key: &str,
        field: &str,
        offset_bytes: u32,
        s: &mut String,
    ) {
        let d = self.local_expr(dst);
        let p = self.local_expr(base_ptr);
        let dst_cty = self.ptr_c_ty(dst).unwrap_or_else(|| "void*".to_string());

        if !self.is_ptr_local(base_ptr) {
            if let Some(MirType::Named(k)) = self.local_ty(base_ptr)
                && let Some(tname) = k.strip_prefix("__strata_table_")
                && let Some(tbl) = self.parent.mir.tables.iter().find(|tb| tb.name == tname)
                && !field.is_empty()
                && tbl.fields.iter().any(|(fnm, _)| fnm == field)
            {
                let fc = sanitize_c_field(field);
                let _ = writeln!(s, "    {d} = ({dst_cty})&({p}.{fc});");
                return;
            }
            if let Some(bty) = self.local_ty(base_ptr)
                && let Some(mem) = self.resolve_tuple_or_vec_member(bty, field, offset_bytes)
            {
                let _ = writeln!(s, "    {d} = ({dst_cty})&({p}.{mem});");
                return;
            }
            let effective_key = if !layout_key.is_empty() {
                Some(layout_key.to_string())
            } else if let Some(MirType::Named(k)) = self.local_ty(base_ptr) {
                Some(k.clone())
            } else {
                None
            };
            if let Some(ref lk) = effective_key
                && let Some((_, _, path)) =
                    self.resolve_member_in_layout(lk, field, offset_bytes, None)
            {
                let _ = writeln!(s, "    {d} = ({dst_cty})&({p}.{path});");
                return;
            }
            let _ = writeln!(
                s,
                "    {d} = ({dst_cty})(((uint8_t*)&{p}) + {offset_bytes}u);"
            );
            return;
        }

        let effective_key = if !layout_key.is_empty() {
            Some(layout_key.to_string())
        } else if let Some(PtrKind::LayoutPtr { layout_idx, .. }) = self.ptr_meta.get(&base_ptr) {
            Some(self.parent.layouts[*layout_idx].canonical_name.clone())
        } else {
            None
        };
        if let Some(ref lk) = effective_key
            && let Some((l_idx, _, path)) =
                self.resolve_member_in_layout(lk, field, offset_bytes, None)
        {
            let is_mut = self.ptr_meta.get(&base_ptr).is_none_or(PtrKind::is_mut);
            let cty = &self.parent.layout_c_names[l_idx];
            let access = if is_mut {
                format!("(({cty}*){p})->{path}")
            } else {
                format!("((const {cty}*){p})->{path}")
            };
            if self.nonnull_ptrs.contains(&base_ptr) {
                let _ = writeln!(s, "    {d} = ({dst_cty})&({access});");
            } else {
                let _ = writeln!(
                    s,
                    "    {d} = ({p} != NULL) ? ({dst_cty})&({access}) : NULL;"
                );
            }
            return;
        }
        if self.nonnull_ptrs.contains(&base_ptr) {
            let _ = writeln!(
                s,
                "    {d} = ({dst_cty})(((uint8_t*){p}) + {offset_bytes}u);"
            );
        } else {
            let _ = writeln!(
                s,
                "    {d} = ({p} != NULL) ? ({dst_cty})(((uint8_t*){p}) + {offset_bytes}u) : NULL;"
            );
        }
    }

    pub(super) fn emit_cmd_spawn(
        &self,
        dst_entity: Option<LocalId>,
        components: &[(String, LocalId)],
        is_persistent: bool,
        s: &mut String,
    ) {
        self.ensure_cmds_snippet(s);
        let n = components.len().max(1);
        let slot = if is_persistent {
            "cmd_spawn_persistent"
        } else {
            "cmd_spawn"
        };
        let _ = writeln!(s, "    {{");
        let _ = writeln!(s, "        BamComponent sp_comps[{n}u];");
        let _ = writeln!(s, "        const uint8_t* sp_datas[{n}u];");
        for (i, (cname, lid)) in components.iter().enumerate() {
            let c_idx = self.parent.find_comp_idx(cname).unwrap_or(0);
            let sz = self.parent.components.get(c_idx).map_or(0, |c| c.size);
            let _ = writeln!(s, "        sp_comps[{i}u] = state->components[{c_idx}];");
            if sz == 0 {
                let _ = writeln!(s, "        sp_datas[{i}u] = NULL;");
            } else {
                let is_ptr = self.ptr_meta.contains_key(lid)
                    || matches!(self.local_ty(*lid), Some(MirType::Ptr | MirType::MutPtr));
                let le = self.local_expr(*lid);
                if is_ptr {
                    let _ = writeln!(s, "        sp_datas[{i}u] = (const uint8_t*){le};");
                } else {
                    let _ = writeln!(s, "        sp_datas[{i}u] = (const uint8_t*)&{le};");
                }
            }
        }
        if components.is_empty() {
            let _ = writeln!(s, "        sp_comps[0u] = BAM_COMPONENT_INVALID;");
            let _ = writeln!(s, "        sp_datas[0u] = NULL;");
        }
        let _ = writeln!(s, "        BamEntity out_ent = BAM_ENTITY_NULL;");
        let _ = writeln!(
            s,
            "        if (cmds_cache != NULL && state->api->{slot} != NULL) {{"
        );
        let _ = writeln!(
            s,
            "            (void)state->api->{slot}(cmds_cache, sp_comps, sp_datas, {}u, &out_ent);",
            components.len()
        );
        let _ = writeln!(s, "        }}");
        if let Some(d) = dst_entity {
            let de = self.local_expr(d);
            let _ = writeln!(s, "        {de} = out_ent;");
        }
        let _ = writeln!(s, "    }}");
    }

    pub(super) fn emit_cmd_spawn_batch(
        &self,
        count: LocalId,
        components: &[(String, LocalId)],
        s: &mut String,
    ) {
        self.ensure_cmds_snippet(s);
        let cnt = self.local_expr(count);
        let n = components.len().max(1);
        let _ = writeln!(s, "    if ((int64_t)({cnt}) > 0) {{");
        let _ = writeln!(s, "        size_t batch_n = (size_t)({cnt});");
        let _ = writeln!(s, "        BamComponent sp_comps[{n}u];");
        let _ = writeln!(s, "        const uint8_t* sp_cols[{n}u];");
        let _ = writeln!(s, "        uint8_t* sp_allocs[{n}u];");
        for (i, (cname, lid)) in components.iter().enumerate() {
            let c_idx = self.parent.find_comp_idx(cname).unwrap_or(0);
            let sz = self.parent.components.get(c_idx).map_or(0, |c| c.size);
            let _ = writeln!(s, "        sp_comps[{i}u] = state->components[{c_idx}];");
            let _ = writeln!(s, "        sp_cols[{i}u] = NULL;");
            let _ = writeln!(s, "        sp_allocs[{i}u] = NULL;");
            if sz > 0 {
                let is_ptr = self.ptr_meta.contains_key(lid)
                    || matches!(self.local_ty(*lid), Some(MirType::Ptr | MirType::MutPtr));
                let le = self.local_expr(*lid);
                let src_p = if is_ptr {
                    format!("(const uint8_t*){le}")
                } else {
                    format!("(const uint8_t*)&{le}")
                };
                let _ = writeln!(
                    s,
                    "        sp_allocs[{i}u] = (uint8_t*)calloc(batch_n, {sz}u);\n        if (sp_allocs[{i}u] != NULL) {{\n            const uint8_t* tmpl_{i} = {src_p};\n            if (tmpl_{i} != NULL) {{\n                for (size_t r = 0u; r < batch_n; ++r) {{\n                    memcpy(sp_allocs[{i}u] + r * {sz}u, tmpl_{i}, {sz}u);\n                }}\n            }}\n            sp_cols[{i}u] = sp_allocs[{i}u];\n        }}"
                );
            }
        }
        if components.is_empty() {
            let _ = writeln!(s, "        sp_comps[0u] = BAM_COMPONENT_INVALID;");
            let _ = writeln!(s, "        sp_cols[0u] = NULL;");
            let _ = writeln!(s, "        sp_allocs[0u] = NULL;");
        }
        let _ = writeln!(
            s,
            "        if (cmds_cache != NULL && state->api->cmd_spawn_batch != NULL) {{"
        );
        let _ = writeln!(
            s,
            "            (void)state->api->cmd_spawn_batch(cmds_cache, sp_comps, sp_cols, {}u, batch_n, NULL);",
            components.len()
        );
        let _ = writeln!(s, "        }}");
        for i in 0..n {
            let _ = writeln!(s, "        free(sp_allocs[{i}u]);");
        }
        let _ = writeln!(s, "    }}");
    }

    pub(super) fn emit_spawn_batch_begin(
        &self,
        dst: Option<LocalId>,
        count: LocalId,
        components: &[String],
        s: &mut String,
    ) {
        let Some(d) = dst else {
            return;
        };
        let de = self.local_expr(d);
        let cnt = self.local_expr(count);
        let comp_count = components.len();
        let _ = writeln!(s, "    {{");
        let _ = writeln!(
            s,
            "        StrataSpawnBatch* sb = strata_spawn_batch_alloc_header((uint32_t)({cnt}), {comp_count}u);"
        );
        for (i, cname) in components.iter().enumerate() {
            let c_idx = self.parent.find_comp_idx(cname).unwrap_or(0);
            let sz = self.parent.components.get(c_idx).map_or(0, |c| c.size);
            let _ = writeln!(
                s,
                "        strata_spawn_batch_init_col(sb, {i}u, state->components[{c_idx}u], {sz}u);"
            );
        }
        let _ = writeln!(s, "        {de} = (uint64_t)(uintptr_t)sb;");
        let _ = writeln!(s, "    }}");
    }

    pub(super) fn emit_spawn_batch_push(
        &self,
        batch: LocalId,
        index: LocalId,
        components: &[(String, LocalId)],
        s: &mut String,
    ) {
        let be = self.local_expr(batch);
        let ie = self.local_expr(index);
        let _ = writeln!(s, "    {{");
        let _ = writeln!(
            s,
            "        StrataSpawnBatch* sb = (StrataSpawnBatch*)(uintptr_t)({be});"
        );
        let _ = writeln!(s, "        uint32_t row_i = (uint32_t)({ie});");
        let _ = writeln!(s, "        (void)row_i;");
        for (i, (cname, lid)) in components.iter().enumerate() {
            let c_idx = self.parent.find_comp_idx(cname).unwrap_or(0);
            let sz = self.parent.components.get(c_idx).map_or(0, |c| c.size);
            if sz > 0 {
                let is_ptr = self.is_ptr_local(*lid);
                let le = self.local_expr(*lid);
                let src_p = if is_ptr {
                    format!("(const void*){le}")
                } else {
                    format!("(const void*)&{le}")
                };
                let _ = writeln!(
                    s,
                    "        strata_spawn_batch_push(sb, state->components[{c_idx}u], {i}u, row_i, {src_p}, {sz}u);"
                );
            }
        }
        let _ = writeln!(s, "    }}");
    }

    pub(super) fn emit_spawn_batch_commit(&self, batch: LocalId, s: &mut String) {
        self.ensure_cmds_snippet(s);
        let be = self.local_expr(batch);
        let _ = writeln!(
            s,
            "    strata_spawn_batch_commit((StrataSpawnBatch*)(uintptr_t)({be}), state->api, cmds_cache);"
        );
    }

    pub(super) fn emit_cmd_despawn_all(&self, filter: &str, s: &mut String) {
        self.ensure_cmds_snippet(s);
        let mut t_strs = Vec::new();
        for tok in filter.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            if let Some(inner) = tok
                .strip_prefix("Without<")
                .and_then(|r| r.strip_suffix('>'))
            {
                if let Some(c_idx) = self.parent.find_comp_idx(inner.trim()) {
                    t_strs.push(format!(
                        "bam_term_desc(state->components[{c_idx}], BAM_ACCESS_WITHOUT, 0u)"
                    ));
                }
            } else if let Some(inner) = tok.strip_prefix("With<").and_then(|r| r.strip_suffix('>'))
            {
                if let Some(c_idx) = self.parent.find_comp_idx(inner.trim()) {
                    t_strs.push(format!(
                        "bam_term_desc(state->components[{c_idx}], BAM_ACCESS_FILTER_ONLY, 0u)"
                    ));
                }
            } else if let Some(c_idx) = self.parent.find_comp_idx(tok) {
                t_strs.push(format!(
                    "bam_term_desc(state->components[{c_idx}], BAM_ACCESS_FILTER_ONLY, 0u)"
                ));
            }
        }
        let n = t_strs.len().max(1);
        let _ = writeln!(s, "    {{");
        let _ = writeln!(s, "        BamTermDesc flt_terms[{n}u];");
        for (i, ts) in t_strs.iter().enumerate() {
            let _ = writeln!(s, "        flt_terms[{i}u] = {ts};");
        }
        if t_strs.is_empty() {
            let _ = writeln!(s, "        memset(&flt_terms[0u], 0, sizeof(BamTermDesc));");
        }
        let _ = writeln!(
            s,
            "        if (cmds_cache != NULL && state->api->cmd_despawn_all != NULL) {{"
        );
        let _ = writeln!(
            s,
            "            (void)state->api->cmd_despawn_all(cmds_cache, flt_terms, {}u);",
            t_strs.len()
        );
        let _ = writeln!(s, "        }}");
        let _ = writeln!(s, "    }}");
    }

    pub(super) fn emit_call(
        &self,
        dst: Option<LocalId>,
        callee: &str,
        args: &[LocalId],
        s: &mut String,
    ) -> Result<(), CodegenError> {
        let a = |i: usize| {
            args.get(i)
                .map(|id| self.local_expr(*id))
                .unwrap_or_else(|| "0".to_string())
        };
        if let Some(d) = dst {
            let de = self.local_expr(d);
            let dty = self.local_ty(d).cloned().unwrap_or(MirType::F32);
            if let Some(&h_idx) = self.parent.helper_by_name.get(callee) {
                let hf = &self.parent.mir_functions()[h_idx];
                let h_name = format!("strata_fn_{}", sanitize_ident(&hf.name));
                let mut call_args = vec!["state".to_string()];
                for id in args {
                    call_args.push(self.local_expr(*id));
                }
                if matches!(hf.ret_ty, MirType::Unit) {
                    let _ = writeln!(s, "    {h_name}({});", call_args.join(", "));
                } else {
                    let _ = writeln!(s, "    {de} = {h_name}({});", call_args.join(", "));
                }
                return Ok(());
            }
            match short_name(callee) {
                "sqr" => {
                    if matches!(dty, MirType::F64) {
                        let _ = writeln!(s, "    {de} = strata_sqr_f64((double){});", a(0));
                    } else {
                        let _ = writeln!(s, "    {de} = strata_sqr_f32((float){});", a(0));
                    }
                }
                "signum" => {
                    let _ = writeln!(s, "    {de} = strata_signum_f32((float){});", a(0));
                }
                "length_sq" => {
                    let t0 = args
                        .first()
                        .and_then(|id| self.local_ty(*id))
                        .cloned()
                        .unwrap_or(MirType::Vec2);
                    if matches!(t0, MirType::Vec3) {
                        let _ = writeln!(s, "    {de} = strata_vec3_len_sq({});", a(0));
                    } else {
                        let _ = writeln!(s, "    {de} = strata_vec2_len_sq({});", a(0));
                    }
                }
                "distance_sq" => {
                    let t0 = args
                        .first()
                        .and_then(|id| self.local_ty(*id))
                        .cloned()
                        .unwrap_or(MirType::Vec2);
                    if matches!(t0, MirType::Vec3) {
                        let _ = writeln!(s, "    {de} = strata_vec3_dist_sq({}, {});", a(0), a(1));
                    } else {
                        let _ = writeln!(s, "    {de} = strata_vec2_dist_sq({}, {});", a(0), a(1));
                    }
                }
                "remap" => {
                    let v = a(0);
                    let i0 = a(1);
                    let i1 = a(2);
                    let o0 = a(3);
                    let o1 = a(4);
                    let _ = writeln!(
                        s,
                        "    {{\n        float span = (float)({i1}) - (float)({i0});\n        float t = (fabsf(span) > 1e-6f) ? (((float)({v}) - (float)({i0})) / span) : 0.0f;\n        {de} = (float)({o0}) + ((float)({o1}) - (float)({o0})) * t;\n    }}"
                    );
                }
                _ => {
                    if let Some(item_name) = callee.strip_suffix("::start") {
                        if let Some(tl) = self.parent.mir.timelines.iter().find(|tl| {
                            tl.name == item_name
                                || tl.canonical_name == item_name
                                || short_name(&tl.canonical_name) == item_name
                        }) {
                            let _ = tl;
                            let _ = writeln!(s, "    memset(&{de}, 0, sizeof({de}));");
                            let _ = writeln!(s, "    {de}.flags = 1u;");
                        } else if let Some(tk) = self.parent.mir.tasks.iter().find(|tk| {
                            tk.name == item_name
                                || tk.state_layout.canonical_name == item_name
                                || short_name(&tk.state_layout.canonical_name) == item_name
                        }) {
                            let _ = writeln!(s, "    memset(&{de}, 0, sizeof({de}));");
                            let _ = writeln!(s, "    {de}.__pc = 0u;");
                            let _ = writeln!(s, "    {de}.__timer = 0.0f;");
                            for (pi, tp) in tk.typed_params.iter().enumerate() {
                                if let Some(&arg_l) = args.get(pi) {
                                    let f_c = sanitize_c_field(&tp.name);
                                    let ae = self.local_expr(arg_l);
                                    let _ = writeln!(s, "    {de}.{f_c} = {ae};");
                                }
                            }
                        } else if let Some(fsm) = self.parent.mir.fsms.iter().find(|fsm| {
                            fsm.name == item_name
                                || fsm.state_layout.canonical_name == item_name
                                || short_name(&fsm.state_layout.canonical_name) == item_name
                        }) {
                            let init_idx = fsm
                                .states
                                .iter()
                                .position(|st| st == &fsm.initial_state)
                                .unwrap_or(0);
                            let _ = writeln!(s, "    memset(&{de}, 0, sizeof({de}));");
                            let _ = writeln!(s, "    {de}.__state = {init_idx}u;");
                        } else {
                            let _ = writeln!(
                                s,
                                "    /* call `{callee}` */ memset(&{de}, 0, sizeof({de}));"
                            );
                        }
                    } else {
                        let _ = writeln!(
                            s,
                            "    /* call `{callee}` */ memset(&{de}, 0, sizeof({de}));"
                        );
                    }
                }
            }
        } else if let Some(&h_idx) = self.parent.helper_by_name.get(callee) {
            let h_name = format!(
                "strata_fn_{}",
                sanitize_ident(&self.parent.mir_functions()[h_idx].name)
            );
            let mut call_args = vec!["state".to_string()];
            for id in args {
                call_args.push(self.local_expr(*id));
            }
            let _ = writeln!(s, "    {h_name}({});", call_args.join(", "));
        }
        Ok(())
    }

    pub(super) fn emit_terminator(
        &self,
        term: &Terminator,
        s: &mut String,
    ) -> Result<(), CodegenError> {
        match term {
            Terminator::Goto(target) => {
                let _ = writeln!(s, "    goto bb_{};", target.0);
            }
            Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } => {
                let c = self.local_expr(*cond);
                let _ = writeln!(
                    s,
                    "    if ({c}) {{ goto bb_{}; }} else {{ goto bb_{}; }}",
                    then_bb.0, else_bb.0
                );
            }
            Terminator::Switch {
                scrutinee,
                cases,
                default_bb,
            } => {
                let sc = self.local_expr(*scrutinee);
                let _ = writeln!(s, "    switch ((uint32_t){sc}) {{");
                let mut seen_vals: HashSet<u32> = HashSet::new();
                for (val, target) in cases {
                    if seen_vals.insert(*val) {
                        let _ = writeln!(s, "        case {val}u: goto bb_{};", target.0);
                    }
                }
                let _ = writeln!(s, "        default: goto bb_{};", default_bb.0);
                let _ = writeln!(s, "    }}");
            }
            Terminator::Return(val_opt) => {
                if self.is_void_helper {
                    let _ = writeln!(s, "    return;");
                } else if self.is_helper {
                    if let Some(val) = val_opt {
                        let ret_expr = if matches!(
                            self.func.ret_ty,
                            MirType::Fix32 | MirType::Fix64 | MirType::F64
                        ) {
                            self.coerce_local_to_mir_scalar(*val, &self.func.ret_ty)
                        } else {
                            self.local_expr(*val)
                        };
                        let _ = writeln!(s, "    return {ret_expr};");
                    } else {
                        let rcty = self.parent.c_ty(&self.func.ret_ty);
                        let _ = writeln!(
                            s,
                            "    {{ {rcty} _ret_zero; memset(&_ret_zero, 0, sizeof(_ret_zero)); return _ret_zero; }}"
                        );
                    }
                } else {
                    let _ = writeln!(s, "    return BAM_RESULT_OK;");
                }
            }
        }
        Ok(())
    }
}
