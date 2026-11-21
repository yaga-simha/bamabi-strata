//! Cranelift PIC `ObjectModule` emitter lowering `MirModule` into relocatable machine code
//! targeting `bamabi` (`ABI 0.3.0`, 68 slots).

use crate::abi_offsets::{FFI_NOT_FOUND, WIRE_ABI_VERSION, api_slots, structs};
use crate::{JitCompileOptions, JitError, JitOptLevel};
use cranelift_codegen::ir::condcodes::{FloatCC, IntCC};
use cranelift_codegen::ir::{
    AbiParam, BlockArg, InstBuilder, MemFlagsData, Signature, StackSlot, StackSlotData,
    StackSlotKind, Type, Value, types,
};
use cranelift_codegen::isa::TargetFrontendConfig;
use cranelift_codegen::settings::{self, Configurable};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift_module::{DataDescription, DataId, FuncId, Linkage, Module};
use cranelift_object::{ObjectBuilder, ObjectModule};
use std::collections::HashMap;
use strata_codegen::expr::{
    AssignOp, BinOpKind, FieldRef, KernelExpr, KernelStmt, ScalarKind, SystemPlan,
    extract_system_plan,
};
use strata_codegen::{is_ecs_component_kind, sanitize_ident, system_schedule_label};
use strata_mir::{MirFunction, MirModule};
use strata_sema::access::TermAccessMode;
use strata_sema::layout::{SchemaItemKind, SolvedLayout};
use target_lexicon::Triple;

/// In-memory relocatable PIC object bytes and symbol list produced before platform linking.
pub struct EmittedObject {
    /// Raw ELF / Mach-O / COFF `.o` bytes.
    pub object_bytes: Vec<u8>,
    /// Exported ABI symbol names.
    pub exported_symbols: Vec<String>,
}

struct LayoutMetaData {
    canonical_name: String,
    is_component: bool,
    is_resource: bool,
    name_cstr_id: DataId,
    uuid_data_id: DataId,
    comp_desc_id: DataId,
}

/// Emits relocatable PIC object bytes (`is_pic = true`) for `mir`.
pub fn emit_pic_object(
    mir: &MirModule,
    opts: &JitCompileOptions,
) -> Result<EmittedObject, JitError> {
    let mut flag_builder = settings::builder();
    flag_builder
        .set("is_pic", "true")
        .map_err(|e| JitError::IsaConfig(e.to_string()))?;
    let opt_str = match opts.opt_level {
        JitOptLevel::FastCompile => "none",
        JitOptLevel::Speed => "speed",
    };
    flag_builder
        .set("opt_level", opt_str)
        .map_err(|e| JitError::IsaConfig(e.to_string()))?;
    let flags = settings::Flags::new(flag_builder);

    let isa_builder = cranelift_codegen::isa::lookup(Triple::host())
        .map_err(|e| JitError::IsaConfig(e.to_string()))?;
    let isa = isa_builder
        .finish(flags)
        .map_err(|e| JitError::IsaConfig(e.to_string()))?;

    let obj_builder = ObjectBuilder::new(
        isa,
        opts.module_stem.clone(),
        cranelift_module::default_libcall_names(),
    )
    .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut module = ObjectModule::new(obj_builder);

    let fe_cfg = module.target_config();
    let ptr_ty = fe_cfg.pointer_type();
    let ptr_bytes = ptr_ty.bytes() as usize;
    let call_conv = module.isa().default_call_conv();

    // 1. Static module name/version & `BamManifest`.
    let mod_name_id = define_cstring(&mut module, "strata_mod_name", &opts.module_stem)?;
    let mod_ver_id = define_cstring(&mut module, "strata_mod_ver", "0.3.0")?;
    let manifest_data_id = define_manifest_data(&mut module, mod_name_id, mod_ver_id, ptr_ty)?;

    // 2. Writable BSS state: `[api_ptr (ptr_bytes)] [comp_handles: u32 * layout_count]`.
    let layout_count = mir.layouts.len().max(1);
    let state_comp_offset = ptr_bytes;
    let state_total_bytes = ptr_bytes + layout_count * structs::BAM_COMPONENT_SIZE;
    let state_id = module
        .declare_data("strata_jit_state", Linkage::Local, true, false)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut state_desc = DataDescription::new();
    state_desc.define_zeroinit(state_total_bytes);
    state_desc.set_align(8);
    module
        .define_data(state_id, &state_desc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    // 3. Read-only component / resource descriptors (`BamFieldDesc[]`, `ComponentUuid`, `ComponentDesc`).
    let mut layout_metas = Vec::with_capacity(mir.layouts.len());
    for (idx, layout) in mir.layouts.iter().enumerate() {
        layout_metas.push(define_layout_data(&mut module, idx, layout, ptr_ty)?);
    }

    // 4. Emit every non-observer system callback first so `bamabi_init` can take their `func_addr`.
    let mut sys_entries: Vec<(String, DataId, FuncId, u32, SystemPlan)> = Vec::new();
    for (sidx, func) in mir.functions.iter().enumerate() {
        if func.is_observer {
            continue;
        }
        let plan = extract_system_plan(func, mir);
        let sched = schedule_id_for(system_schedule_label(mir, &func.name));
        let sys_name_id = define_cstring(
            &mut module,
            &format!("strata_sys_name_{sidx}_{}", sanitize_ident(&func.name)),
            &func.name,
        )?;
        let sys_func_id = emit_system_callback(
            &mut module,
            func,
            &plan,
            mir,
            state_comp_offset,
            call_conv,
            fe_cfg,
        )?;
        sys_entries.push((func.name.clone(), sys_name_id, sys_func_id, sched, plan));
    }

    // 5. Emit required C-ABI exports: `bamabi_manifest`, `bamabi_init`, `bamabi_shutdown`.
    emit_bamabi_manifest(&mut module, manifest_data_id, call_conv, fe_cfg)?;
    emit_bamabi_init(
        &mut module,
        state_id,
        state_total_bytes,
        state_comp_offset,
        &layout_metas,
        &sys_entries,
        call_conv,
        fe_cfg,
    )?;
    emit_bamabi_shutdown(&mut module, call_conv, fe_cfg)?;

    let product = module.finish();
    let object_bytes = product
        .emit()
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    Ok(EmittedObject {
        object_bytes,
        exported_symbols: vec![
            "bamabi_manifest".to_owned(),
            "bamabi_init".to_owned(),
            "bamabi_shutdown".to_owned(),
        ],
    })
}

fn schedule_id_for(label: &str) -> u32 {
    match label {
        "Startup" => 1,
        "PreUpdate" => 2,
        "PostUpdate" => 3,
        "FixedUpdate" => 4,
        "Last" => 5,
        _ => 0,
    }
}

fn define_cstring(module: &mut ObjectModule, sym: &str, text: &str) -> Result<DataId, JitError> {
    let id = module
        .declare_data(sym, Linkage::Local, false, false)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    let mut desc = DataDescription::new();
    desc.define(bytes.into_boxed_slice());
    module
        .define_data(id, &desc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    Ok(id)
}

fn write_u32_le(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn write_u64_le(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn write_usize_le(buf: &mut [u8], off: usize, v: usize, ptr_bytes: usize) {
    if ptr_bytes == 8 {
        write_u64_le(buf, off, v as u64);
    } else {
        write_u32_le(buf, off, v as u32);
    }
}

fn define_manifest_data(
    module: &mut ObjectModule,
    name_id: DataId,
    ver_id: DataId,
    ptr_ty: Type,
) -> Result<DataId, JitError> {
    let _ptr_bytes = ptr_ty.bytes() as usize;
    let id = module
        .declare_data("STRATA_JIT_MANIFEST", Linkage::Local, false, false)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let mut raw = vec![0u8; structs::MANIFEST_SIZE];
    write_u32_le(
        &mut raw,
        structs::MANIFEST_STRUCT_SIZE,
        structs::MANIFEST_SIZE as u32,
    );
    write_u32_le(&mut raw, structs::MANIFEST_ABI_VERSION, WIRE_ABI_VERSION);

    let mut desc = DataDescription::new();
    desc.define(raw.into_boxed_slice());
    desc.set_align(8);
    let name_gv = module.declare_data_in_data(name_id, &mut desc);
    desc.write_data_addr(structs::MANIFEST_NAME as u32, name_gv, 0);
    let ver_gv = module.declare_data_in_data(ver_id, &mut desc);
    desc.write_data_addr(structs::MANIFEST_VERSION as u32, ver_gv, 0);

    module
        .define_data(id, &desc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    Ok(id)
}

fn define_layout_data(
    module: &mut ObjectModule,
    idx: usize,
    layout: &SolvedLayout,
    ptr_ty: Type,
) -> Result<LayoutMetaData, JitError> {
    let ptr_bytes = ptr_ty.bytes() as usize;
    let ident = sanitize_ident(&layout.canonical_name);
    let name_cstr_id = define_cstring(
        module,
        &format!("strata_cstr_{idx}_{ident}"),
        &layout.canonical_name,
    )?;

    let uuid_data_id = module
        .declare_data(
            &format!("strata_uuid_{idx}_{ident}"),
            Linkage::Local,
            false,
            false,
        )
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut uuid_desc = DataDescription::new();
    uuid_desc.define(layout.uuid_bytes.to_vec().into_boxed_slice());
    uuid_desc.set_align(1);
    module
        .define_data(uuid_data_id, &uuid_desc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let mut fields_data_id = None;
    if !layout.fields.is_empty() {
        let mut field_str_ids = Vec::with_capacity(layout.fields.len());
        for (fi, f) in layout.fields.iter().enumerate() {
            let fn_id = define_cstring(module, &format!("strata_fn_{idx}_{fi}"), &f.name)?;
            let ft_id = define_cstring(module, &format!("strata_ft_{idx}_{fi}"), &f.type_tag)?;
            field_str_ids.push((fn_id, ft_id));
        }

        let arr_bytes = layout.fields.len() * structs::FIELD_DESC_SIZE;
        let mut arr = vec![0u8; arr_bytes];
        for (fi, f) in layout.fields.iter().enumerate() {
            let base = fi * structs::FIELD_DESC_SIZE;
            write_u32_le(
                &mut arr,
                base + structs::FIELD_STRUCT_SIZE,
                structs::FIELD_DESC_SIZE as u32,
            );
            write_u32_le(&mut arr, base + structs::FIELD_KIND, f.bam_field_kind);
            write_usize_le(
                &mut arr,
                base + structs::FIELD_NAME + structs::STRVIEW_LEN,
                f.name.len(),
                ptr_bytes,
            );
            write_usize_le(
                &mut arr,
                base + structs::FIELD_TYPE_TAG + structs::STRVIEW_LEN,
                f.type_tag.len(),
                ptr_bytes,
            );
            write_usize_le(&mut arr, base + structs::FIELD_OFFSET, f.offset, ptr_bytes);
            write_usize_le(&mut arr, base + structs::FIELD_SIZE, f.size, ptr_bytes);
            write_usize_le(&mut arr, base + structs::FIELD_ALIGN, f.align, ptr_bytes);
        }

        let f_id = module
            .declare_data(
                &format!("strata_fields_{idx}_{ident}"),
                Linkage::Local,
                false,
                false,
            )
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        let mut f_desc = DataDescription::new();
        f_desc.define(arr.into_boxed_slice());
        f_desc.set_align(8);
        for (fi, (fn_id, ft_id)) in field_str_ids.into_iter().enumerate() {
            let base = fi * structs::FIELD_DESC_SIZE;
            let fn_gv = module.declare_data_in_data(fn_id, &mut f_desc);
            f_desc.write_data_addr(
                (base + structs::FIELD_NAME + structs::STRVIEW_PTR) as u32,
                fn_gv,
                0,
            );
            let ft_gv = module.declare_data_in_data(ft_id, &mut f_desc);
            f_desc.write_data_addr(
                (base + structs::FIELD_TYPE_TAG + structs::STRVIEW_PTR) as u32,
                ft_gv,
                0,
            );
        }
        module
            .define_data(f_id, &f_desc)
            .map_err(|e| JitError::Codegen(e.to_string()))?;
        fields_data_id = Some(f_id);
    }

    let mut cbytes = vec![0u8; structs::COMPONENT_DESC_SIZE];
    write_u32_le(
        &mut cbytes,
        structs::COMP_STRUCT_SIZE,
        structs::COMPONENT_DESC_SIZE as u32,
    );
    let cflags = if layout.item_kind == SchemaItemKind::Resource {
        0u32
    } else {
        layout.component_flags
    };
    write_u32_le(&mut cbytes, structs::COMP_FLAGS, cflags);
    cbytes[structs::COMP_UUID..structs::COMP_UUID + 16].copy_from_slice(&layout.uuid_bytes);
    write_usize_le(&mut cbytes, structs::COMP_SIZE, layout.size, ptr_bytes);
    write_usize_le(&mut cbytes, structs::COMP_ALIGN, layout.align, ptr_bytes);
    write_u64_le(
        &mut cbytes,
        structs::COMP_SCHEMA_FINGERPRINT,
        layout.schema_fingerprint,
    );
    if fields_data_id.is_some() {
        write_usize_le(
            &mut cbytes,
            structs::COMP_FIELD_COUNT,
            layout.fields.len(),
            ptr_bytes,
        );
    }

    let comp_desc_id = module
        .declare_data(
            &format!("strata_cdesc_{idx}_{ident}"),
            Linkage::Local,
            false,
            false,
        )
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut cdesc = DataDescription::new();
    cdesc.define(cbytes.into_boxed_slice());
    cdesc.set_align(8);
    let name_gv = module.declare_data_in_data(name_cstr_id, &mut cdesc);
    cdesc.write_data_addr(structs::COMP_NAME as u32, name_gv, 0);
    if let Some(f_id) = fields_data_id {
        let fields_gv = module.declare_data_in_data(f_id, &mut cdesc);
        cdesc.write_data_addr(structs::COMP_FIELDS as u32, fields_gv, 0);
    }
    module
        .define_data(comp_desc_id, &cdesc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    Ok(LayoutMetaData {
        canonical_name: layout.canonical_name.clone(),
        is_component: is_ecs_component_kind(layout.item_kind),
        is_resource: layout.item_kind == SchemaItemKind::Resource,
        name_cstr_id,
        uuid_data_id,
        comp_desc_id,
    })
}

fn emit_bamabi_manifest(
    module: &mut ObjectModule,
    manifest_data_id: DataId,
    call_conv: cranelift_codegen::isa::CallConv,
    fe_cfg: TargetFrontendConfig,
) -> Result<(), JitError> {
    let ptr_ty = fe_cfg.pointer_type();
    let mut sig = Signature::new(call_conv);
    sig.returns.push(AbiParam::new(ptr_ty));
    let func_id = module
        .declare_function("bamabi_manifest", Linkage::Export, &sig)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let mut ctx = module.make_context();
    ctx.func.signature = sig;
    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.switch_to_block(entry);
        b.seal_block(entry);
        let gv = module.declare_data_in_func(manifest_data_id, b.func);
        let addr = b.ins().symbol_value(ptr_ty, gv);
        b.ins().return_(&[addr]);
        b.finalize(fe_cfg);
    }
    module
        .define_function(func_id, &mut ctx)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    module.clear_context(&mut ctx);
    Ok(())
}

fn emit_bamabi_shutdown(
    module: &mut ObjectModule,
    call_conv: cranelift_codegen::isa::CallConv,
    fe_cfg: TargetFrontendConfig,
) -> Result<(), JitError> {
    let ptr_ty = fe_cfg.pointer_type();
    let mut sig = Signature::new(call_conv);
    sig.params.push(AbiParam::new(ptr_ty));
    let func_id = module
        .declare_function("bamabi_shutdown", Linkage::Export, &sig)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let mut ctx = module.make_context();
    ctx.func.signature = sig;
    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);
        b.seal_block(entry);
        b.ins().return_(&[]);
        b.finalize(fe_cfg);
    }
    module
        .define_function(func_id, &mut ctx)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    module.clear_context(&mut ctx);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_bamabi_init(
    module: &mut ObjectModule,
    state_id: DataId,
    state_total_bytes: usize,
    state_comp_offset: usize,
    layout_metas: &[LayoutMetaData],
    sys_entries: &[(String, DataId, FuncId, u32, SystemPlan)],
    call_conv: cranelift_codegen::isa::CallConv,
    fe_cfg: TargetFrontendConfig,
) -> Result<(), JitError> {
    let ptr_ty = fe_cfg.pointer_type();
    let mut sig = Signature::new(call_conv);
    sig.params.push(AbiParam::new(ptr_ty)); // api: *const BamHostApi
    sig.params.push(AbiParam::new(ptr_ty)); // load_ctx: *mut BamLoadCtx
    sig.params.push(AbiParam::new(ptr_ty)); // instance_out: *mut *mut BamInstance
    sig.returns.push(AbiParam::new(types::I32)); // FfiResult

    let func_id = module
        .declare_function("bamabi_init", Linkage::Export, &sig)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let mut ctx = module.make_context();
    ctx.func.signature = sig;
    let mut fb_ctx = FunctionBuilderContext::new();

    {
        let mut b = FunctionBuilder::new(&mut ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);
        b.seal_block(entry);

        let api_ptr = b.block_params(entry)[0];
        let load_ctx = b.block_params(entry)[1];
        let instance_out = b.block_params(entry)[2];

        // Null check `api == NULL || load_ctx == NULL`.
        let err_null_blk = b.create_block();
        let init_ok_blk = b.create_block();
        let api_is_null = b.ins().icmp_imm_s(IntCC::Equal, api_ptr, 0);
        let lctx_is_null = b.ins().icmp_imm_s(IntCC::Equal, load_ctx, 0);
        let any_null = b.ins().bor(api_is_null, lctx_is_null);
        b.ins().brif(any_null, err_null_blk, &[], init_ok_blk, &[]);

        b.switch_to_block(err_null_blk);
        b.seal_block(err_null_blk);
        let null_res = b.ins().iconst(types::I32, 4); // BAM_RESULT_NULL_POINTER
        b.ins().return_(&[null_res]);

        b.switch_to_block(init_ok_blk);
        b.seal_block(init_ok_blk);

        let state_gv = module.declare_data_in_func(state_id, b.func);
        let state_addr = b.ins().symbol_value(ptr_ty, state_gv);
        let zero_byte = b.ins().iconst(types::I8, 0);
        for off in 0..state_total_bytes {
            b.ins()
                .store(MemFlagsData::trusted(), zero_byte, state_addr, off as i32);
        }
        b.ins()
            .store(MemFlagsData::trusted(), api_ptr, state_addr, 0);

        let skip_inst_blk = b.create_block();
        let write_inst_blk = b.create_block();
        let io_null = b.ins().icmp_imm_s(IntCC::Equal, instance_out, 0);
        b.ins()
            .brif(io_null, skip_inst_blk, &[], write_inst_blk, &[]);
        b.switch_to_block(write_inst_blk);
        b.seal_block(write_inst_blk);
        b.ins()
            .store(MemFlagsData::trusted(), state_addr, instance_out, 0);
        b.ins().jump(skip_inst_blk, &[]);
        b.switch_to_block(skip_inst_blk);
        b.seal_block(skip_inst_blk);

        // `host_ctx = api->load_host_ctx(load_ctx)`
        let sig_load_host_ctx = import_sig(&mut b, call_conv, &[ptr_ty], Some(ptr_ty));
        let host_ctx = call_slot(
            &mut b,
            api_ptr,
            api_slots::LOAD_HOST_CTX,
            sig_load_host_ctx,
            ptr_ty,
            &[load_ctx],
        )[0];

        let sig_reg_comp = import_sig(
            &mut b,
            call_conv,
            &[ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
        );
        let sig_resolve_comp = import_sig(
            &mut b,
            call_conv,
            &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
        );
        let sig_reg_sys = import_sig(&mut b, call_conv, &[ptr_ty, ptr_ty], Some(types::I32));

        let fail_blk = b.create_block();
        b.append_block_param(fail_blk, types::I32);

        for (idx, meta) in layout_metas.iter().enumerate() {
            let out_off = (state_comp_offset + idx * structs::BAM_COMPONENT_SIZE) as i32;
            let out_slot = b.ins().iadd_imm_s(state_addr, i64::from(out_off));

            if meta.is_component {
                let cdesc_gv = module.declare_data_in_func(meta.comp_desc_id, b.func);
                let cdesc_ptr = b.ins().symbol_value(ptr_ty, cdesc_gv);
                let rc = call_slot(
                    &mut b,
                    api_ptr,
                    api_slots::REGISTER_COMPONENT,
                    sig_reg_comp,
                    ptr_ty,
                    &[load_ctx, cdesc_ptr, out_slot],
                )[0];
                let next_blk = b.create_block();
                let is_err = b.ins().icmp_imm_s(IntCC::NotEqual, rc, 0);
                b.ins()
                    .brif(is_err, fail_blk, &[BlockArg::Value(rc)], next_blk, &[]);
                b.switch_to_block(next_blk);
                b.seal_block(next_blk);
            } else if meta.is_resource {
                let name_gv = module.declare_data_in_func(meta.name_cstr_id, b.func);
                let name_ptr = b.ins().symbol_value(ptr_ty, name_gv);
                let uuid_gv = module.declare_data_in_func(meta.uuid_data_id, b.func);
                let uuid_ptr = b.ins().symbol_value(ptr_ty, uuid_gv);
                let rc = call_slot(
                    &mut b,
                    api_ptr,
                    api_slots::RESOLVE_COMPONENT,
                    sig_resolve_comp,
                    ptr_ty,
                    &[host_ctx, name_ptr, uuid_ptr, out_slot],
                )[0];
                let check_not_found = b.create_block();
                let reg_fallback = b.create_block();
                let after_res = b.create_block();
                let is_ok = b.ins().icmp_imm_s(IntCC::Equal, rc, 0);
                b.ins().brif(is_ok, after_res, &[], check_not_found, &[]);

                b.switch_to_block(check_not_found);
                b.seal_block(check_not_found);
                let is_nf = b
                    .ins()
                    .icmp_imm_s(IntCC::Equal, rc, i64::from(FFI_NOT_FOUND));
                b.ins()
                    .brif(is_nf, reg_fallback, &[], fail_blk, &[BlockArg::Value(rc)]);

                b.switch_to_block(reg_fallback);
                b.seal_block(reg_fallback);
                let cdesc_gv = module.declare_data_in_func(meta.comp_desc_id, b.func);
                let cdesc_ptr = b.ins().symbol_value(ptr_ty, cdesc_gv);
                let rc2 = call_slot(
                    &mut b,
                    api_ptr,
                    api_slots::REGISTER_COMPONENT,
                    sig_reg_comp,
                    ptr_ty,
                    &[load_ctx, cdesc_ptr, out_slot],
                )[0];
                let is_err2 = b.ins().icmp_imm_s(IntCC::NotEqual, rc2, 0);
                b.ins()
                    .brif(is_err2, fail_blk, &[BlockArg::Value(rc2)], after_res, &[]);

                b.switch_to_block(after_res);
                b.seal_block(after_res);
            }
        }

        let sdesc_slot = alloc_zero_slot(&mut b, structs::SYSTEM_DESC_SIZE, ptr_ty);
        let qdescs_slot = alloc_zero_slot(&mut b, structs::QUERY_DESC_SIZE * 2, ptr_ty);
        let sdesc_ptr = b.ins().stack_addr(ptr_ty, sdesc_slot, 0);
        let qdescs_ptr = b.ins().stack_addr(ptr_ty, qdescs_slot, 0);

        for (_sname, sys_name_id, sys_func_id, sched_id, plan) in sys_entries {
            zero_slot(&mut b, sdesc_slot, structs::SYSTEM_DESC_SIZE, ptr_ty);
            zero_slot(&mut b, qdescs_slot, structs::QUERY_DESC_SIZE * 2, ptr_ty);

            let s_sz = b.ins().iconst(types::I32, structs::SYSTEM_DESC_SIZE as i64);
            b.ins()
                .stack_store(ptr_ty, s_sz, sdesc_slot, structs::SYS_STRUCT_SIZE as i32);
            let name_gv = module.declare_data_in_func(*sys_name_id, b.func);
            let name_ptr = b.ins().symbol_value(ptr_ty, name_gv);
            b.ins()
                .stack_store(ptr_ty, name_ptr, sdesc_slot, structs::SYS_NAME as i32);

            let fn_ref = module.declare_func_in_func(*sys_func_id, b.func);
            let fn_addr = b.ins().func_addr(ptr_ty, fn_ref);
            b.ins()
                .stack_store(ptr_ty, fn_addr, sdesc_slot, structs::SYS_CALLBACK as i32);
            b.ins().stack_store(
                ptr_ty,
                state_addr,
                sdesc_slot,
                structs::SYS_USER_DATA as i32,
            );
            let sched_v = b.ins().iconst(types::I32, i64::from(*sched_id));
            b.ins()
                .stack_store(ptr_ty, sched_v, sdesc_slot, structs::SYS_SCHEDULE as i32);

            let mut active_terms = Vec::new();
            for term in &plan.query0_terms {
                if let Some(lidx) = find_layout_idx(layout_metas, &term.component_canonical) {
                    active_terms.push((lidx, access_mode_u32(term.mode)));
                }
            }
            let mut res_terms = Vec::new();
            for res in &plan.resources {
                if let Some(lidx) = find_layout_idx(layout_metas, &res.canonical_name) {
                    let rmode = if res.mutable {
                        bamabi_sys::AccessMode::RESOURCE_WRITE.0
                    } else {
                        bamabi_sys::AccessMode::RESOURCE_READ.0
                    };
                    res_terms.push((lidx, rmode));
                }
            }

            let mut q_idx = 0usize;
            if !plan.row_stmts.is_empty() && !active_terms.is_empty() {
                populate_query_slot(
                    &mut b,
                    qdescs_slot,
                    q_idx,
                    state_addr,
                    state_comp_offset,
                    &active_terms,
                    ptr_ty,
                );
                q_idx += 1;
            }
            if !res_terms.is_empty() && !plan.row_stmts.is_empty() {
                populate_query_slot(
                    &mut b,
                    qdescs_slot,
                    q_idx,
                    state_addr,
                    state_comp_offset,
                    &res_terms,
                    ptr_ty,
                );
                q_idx += 1;
            }
            if q_idx > 0 {
                b.ins()
                    .stack_store(ptr_ty, qdescs_ptr, sdesc_slot, structs::SYS_QUERIES as i32);
                let qc_v = b.ins().iconst(ptr_ty, q_idx as i64);
                b.ins()
                    .stack_store(ptr_ty, qc_v, sdesc_slot, structs::SYS_QUERY_COUNT as i32);
            }

            let rc = call_slot(
                &mut b,
                api_ptr,
                api_slots::REGISTER_SYSTEM,
                sig_reg_sys,
                ptr_ty,
                &[load_ctx, sdesc_ptr],
            )[0];
            let next_sys = b.create_block();
            let is_err = b.ins().icmp_imm_s(IntCC::NotEqual, rc, 0);
            b.ins()
                .brif(is_err, fail_blk, &[BlockArg::Value(rc)], next_sys, &[]);
            b.switch_to_block(next_sys);
            b.seal_block(next_sys);
        }

        let ok_res = b.ins().iconst(types::I32, 0);
        b.ins().return_(&[ok_res]);

        b.switch_to_block(fail_blk);
        b.seal_block(fail_blk);
        let err_code = b.block_params(fail_blk)[0];
        b.ins().return_(&[err_code]);
        b.finalize(fe_cfg);
    }

    module
        .define_function(func_id, &mut ctx)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    module.clear_context(&mut ctx);
    Ok(())
}

fn populate_query_slot(
    b: &mut FunctionBuilder<'_>,
    qdescs_slot: StackSlot,
    q_idx: usize,
    state_addr: Value,
    state_comp_offset: usize,
    terms: &[(usize, u32)],
    ptr_ty: Type,
) {
    let terms_bytes = terms.len() * structs::TERM_DESC_SIZE;
    let terms_slot = alloc_zero_slot(b, terms_bytes, ptr_ty);
    let terms_ptr = b.ins().stack_addr(ptr_ty, terms_slot, 0);

    for (ti, &(lidx, mode_u32)) in terms.iter().enumerate() {
        let base = ti * structs::TERM_DESC_SIZE;
        let comp_off = (state_comp_offset + lidx * structs::BAM_COMPONENT_SIZE) as i32;
        let comp_id = b
            .ins()
            .load(types::I32, MemFlagsData::trusted(), state_addr, comp_off);
        b.ins().stack_store(
            ptr_ty,
            comp_id,
            terms_slot,
            (base + structs::TERM_COMPONENT) as i32,
        );
        let mode_v = b.ins().iconst(types::I32, i64::from(mode_u32));
        b.ins().stack_store(
            ptr_ty,
            mode_v,
            terms_slot,
            (base + structs::TERM_MODE) as i32,
        );
    }

    let q_base = (q_idx * structs::QUERY_DESC_SIZE) as i32;
    let q_sz = b.ins().iconst(types::I32, structs::QUERY_DESC_SIZE as i64);
    b.ins().stack_store(
        ptr_ty,
        q_sz,
        qdescs_slot,
        q_base + structs::QUERY_STRUCT_SIZE as i32,
    );
    b.ins().stack_store(
        ptr_ty,
        terms_ptr,
        qdescs_slot,
        q_base + structs::QUERY_TERMS as i32,
    );
    let tc_v = b.ins().iconst(ptr_ty, terms.len() as i64);
    b.ins().stack_store(
        ptr_ty,
        tc_v,
        qdescs_slot,
        q_base + structs::QUERY_TERM_COUNT as i32,
    );
}

fn access_mode_u32(mode: TermAccessMode) -> u32 {
    match mode {
        TermAccessMode::Write | TermAccessMode::SelectiveWrite => bamabi_sys::AccessMode::WRITE.0,
        TermAccessMode::With => bamabi_sys::AccessMode::FILTER_ONLY.0,
        TermAccessMode::Without => bamabi_sys::AccessMode::WITHOUT.0,
        TermAccessMode::OptionalRead => bamabi_sys::AccessMode::OPTIONAL_READ.0,
        TermAccessMode::OptionalWrite => bamabi_sys::AccessMode::OPTIONAL_WRITE.0,
        TermAccessMode::Has => bamabi_sys::AccessMode::HAS.0,
        TermAccessMode::Allow => bamabi_sys::AccessMode::ALLOW.0,
        _ => bamabi_sys::AccessMode::READ.0,
    }
}

fn find_layout_idx(metas: &[LayoutMetaData], key: &str) -> Option<usize> {
    let short = key.split('.').next().unwrap_or(key);
    metas.iter().position(|m| {
        m.canonical_name == short
            || m.canonical_name.rsplit("::").next() == Some(short)
            || sanitize_ident(&m.canonical_name) == sanitize_ident(short)
    })
}

fn find_mir_layout_idx(mir: &MirModule, key: &str) -> Option<usize> {
    let short = key.split('.').next().unwrap_or(key);
    mir.layouts.iter().position(|l| {
        l.canonical_name == short
            || l.canonical_name.rsplit("::").next() == Some(short)
            || sanitize_ident(&l.canonical_name) == sanitize_ident(short)
    })
}

#[allow(clippy::too_many_arguments)]
fn emit_system_callback(
    module: &mut ObjectModule,
    func: &MirFunction,
    plan: &SystemPlan,
    mir: &MirModule,
    state_comp_offset: usize,
    call_conv: cranelift_codegen::isa::CallConv,
    fe_cfg: TargetFrontendConfig,
) -> Result<FuncId, JitError> {
    let ptr_ty = fe_cfg.pointer_type();
    let mut sig = Signature::new(call_conv);
    sig.params.push(AbiParam::new(ptr_ty)); // sys_ctx
    sig.params.push(AbiParam::new(ptr_ty)); // user_data (state_addr)
    sig.returns.push(AbiParam::new(types::I32)); // FfiResult

    let sym = format!("strata_jit_sys_{}", sanitize_ident(&func.name));
    let func_id = module
        .declare_function(&sym, Linkage::Local, &sig)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let mut ctx = module.make_context();
    ctx.func.signature = sig;
    let mut fb_ctx = FunctionBuilderContext::new();

    {
        let mut b = FunctionBuilder::new(&mut ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);
        b.seal_block(entry);

        if plan.row_stmts.is_empty() || plan.query0_terms.is_empty() {
            let ok = b.ins().iconst(types::I32, 0);
            b.ins().return_(&[ok]);
            b.finalize(fe_cfg);
            module
                .define_function(func_id, &mut ctx)
                .map_err(|e| JitError::Codegen(e.to_string()))?;
            module.clear_context(&mut ctx);
            return Ok(func_id);
        }

        let sys_ctx = b.block_params(entry)[0];
        let state_addr = b.block_params(entry)[1];
        let api_ptr = b.ins().load(ptr_ty, MemFlagsData::trusted(), state_addr, 0);

        let sig_res_ptr = import_sig(
            &mut b,
            call_conv,
            &[ptr_ty, types::I32, ptr_ty],
            Some(ptr_ty),
        );
        let sig_sys_query = import_sig(
            &mut b,
            call_conv,
            &[ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
        );
        let sig_next_chunk = import_sig(&mut b, call_conv, &[ptr_ty, ptr_ty], Some(types::I8));
        let sig_iter_col = import_sig(&mut b, call_conv, &[ptr_ty, ptr_ty], Some(ptr_ty));
        let sig_mark_changed = import_sig(
            &mut b,
            call_conv,
            &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
        );

        let zero_ptr = b.ins().iconst(ptr_ty, 0);
        let mut res_ptrs: HashMap<String, Value> = HashMap::new();
        for res in &plan.resources {
            if let Some(lidx) = find_mir_layout_idx(mir, &res.canonical_name) {
                let comp_off = (state_comp_offset + lidx * structs::BAM_COMPONENT_SIZE) as i32;
                let comp_id =
                    b.ins()
                        .load(types::I32, MemFlagsData::trusted(), state_addr, comp_off);
                let slot = if res.mutable {
                    api_slots::SYS_RES_MUT_PTR
                } else {
                    api_slots::SYS_RES_PTR
                };
                let rp = call_slot(
                    &mut b,
                    api_ptr,
                    slot,
                    sig_res_ptr,
                    ptr_ty,
                    &[sys_ctx, comp_id, zero_ptr],
                )[0];
                let ok_blk = b.create_block();
                let null_blk = b.create_block();
                let is_null = b.ins().icmp_imm_s(IntCC::Equal, rp, 0);
                b.ins().brif(is_null, null_blk, &[], ok_blk, &[]);
                b.switch_to_block(null_blk);
                b.seal_block(null_blk);
                let ok0 = b.ins().iconst(types::I32, 0);
                b.ins().return_(&[ok0]);
                b.switch_to_block(ok_blk);
                b.seal_block(ok_blk);
                res_ptrs.insert(res.canonical_name.clone(), rp);
            }
        }

        let mut vars: HashMap<String, (Variable, ScalarKind)> = HashMap::new();
        let col_empty: HashMap<usize, Value> = HashMap::new();
        let zero_row = b.ins().iconst(ptr_ty, 0);
        for stmt in &plan.uniforms {
            lower_kernel_stmt(
                &mut b, stmt, &res_ptrs, &col_empty, zero_row, None, &mut vars,
            );
        }

        let iter_slot = alloc_zero_slot(&mut b, ptr_ty.bytes() as usize, ptr_ty);
        let len_slot = alloc_zero_slot(&mut b, ptr_ty.bytes() as usize, ptr_ty);
        let iter_slot_ptr = b.ins().stack_addr(ptr_ty, iter_slot, 0);
        let len_slot_ptr = b.ins().stack_addr(ptr_ty, len_slot, 0);
        let qidx0 = b.ins().iconst(ptr_ty, 0);
        let qrc = call_slot(
            &mut b,
            api_ptr,
            api_slots::SYS_QUERY,
            sig_sys_query,
            ptr_ty,
            &[sys_ctx, qidx0, iter_slot_ptr],
        )[0];

        let query_ok_blk = b.create_block();
        let query_err_blk = b.create_block();
        let q_failed = b.ins().icmp_imm_s(IntCC::NotEqual, qrc, 0);
        b.ins()
            .brif(q_failed, query_err_blk, &[], query_ok_blk, &[]);
        b.switch_to_block(query_err_blk);
        b.seal_block(query_err_blk);
        b.ins().return_(&[qrc]);

        b.switch_to_block(query_ok_blk);
        b.seal_block(query_ok_blk);
        let iter_val = b.ins().stack_load(ptr_ty, ptr_ty, iter_slot, 0);

        let chunk_hdr = b.create_block();
        let chunk_body = b.create_block();
        let chunk_exit = b.create_block();
        b.ins().jump(chunk_hdr, &[]);

        b.switch_to_block(chunk_hdr);
        let has_more = call_slot(
            &mut b,
            api_ptr,
            api_slots::ITER_NEXT_CHUNK,
            sig_next_chunk,
            ptr_ty,
            &[iter_val, len_slot_ptr],
        )[0];
        let done_chunks = b.ins().icmp_imm_s(IntCC::Equal, has_more, 0);
        b.ins().brif(done_chunks, chunk_exit, &[], chunk_body, &[]);

        b.switch_to_block(chunk_body);
        let chunk_len = b.ins().stack_load(ptr_ty, ptr_ty, len_slot, 0);

        let mut col_ptrs = HashMap::new();
        for term in &plan.query0_terms {
            let slot = match term.mode {
                TermAccessMode::Read | TermAccessMode::OptionalRead => {
                    Some(api_slots::ITER_COLUMN_READONLY)
                }
                TermAccessMode::Write | TermAccessMode::OptionalWrite => {
                    Some(api_slots::ITER_COLUMN_MUTABLE)
                }
                TermAccessMode::SelectiveWrite => Some(api_slots::ITER_COLUMN_MUTABLE_UNTRACKED),
                _ => None,
            };
            if let Some(slot_off) = slot {
                let ti_v = b.ins().iconst(ptr_ty, term.term_idx as i64);
                let cp = call_slot(
                    &mut b,
                    api_ptr,
                    slot_off,
                    sig_iter_col,
                    ptr_ty,
                    &[iter_val, ti_v],
                )[0];
                col_ptrs.insert(term.term_idx, cp);
            }
        }

        let dirty_start_var = b.declare_var(ptr_ty);
        let dirty_len_var = b.declare_var(ptr_ty);
        let row_dirty_var = b.declare_var(types::I8);
        let row_var = b.declare_var(ptr_ty);
        let zero_pt = b.ins().iconst(ptr_ty, 0);
        b.def_var(dirty_start_var, zero_pt);
        b.def_var(dirty_len_var, zero_pt);
        b.def_var(row_var, zero_pt);

        let row_hdr = b.create_block();
        let row_body = b.create_block();
        let row_exit = b.create_block();
        b.ins().jump(row_hdr, &[]);

        b.switch_to_block(row_hdr);
        let cur_row = b.use_var(row_var);
        let row_lt = b.ins().icmp(IntCC::UnsignedLessThan, cur_row, chunk_len);
        b.ins().brif(row_lt, row_body, &[], row_exit, &[]);

        b.switch_to_block(row_body);
        let zero_i8 = b.ins().iconst(types::I8, 0);
        b.def_var(row_dirty_var, zero_i8);
        let row_dirty_target = if plan.has_selective_writes {
            Some(row_dirty_var)
        } else {
            None
        };

        for stmt in &plan.row_stmts {
            lower_kernel_stmt(
                &mut b,
                stmt,
                &res_ptrs,
                &col_ptrs,
                cur_row,
                row_dirty_target,
                &mut vars,
            );
        }

        if plan.has_selective_writes {
            let dirty_blk = b.create_block();
            let next_row_blk = b.create_block();
            let rd = b.use_var(row_dirty_var);
            let is_d = b.ins().icmp_imm_s(IntCC::NotEqual, rd, 0);
            b.ins().brif(is_d, dirty_blk, &[], next_row_blk, &[]);

            b.switch_to_block(dirty_blk);
            b.seal_block(dirty_blk);
            let dl = b.use_var(dirty_len_var);
            let ds = b.use_var(dirty_start_var);
            let start_new_blk = b.create_block();
            let check_adj_blk = b.create_block();
            let extend_blk = b.create_block();
            let flush_gap_blk = b.create_block();

            let dl_zero = b.ins().icmp_imm_s(IntCC::Equal, dl, 0);
            b.ins()
                .brif(dl_zero, start_new_blk, &[], check_adj_blk, &[]);

            b.switch_to_block(start_new_blk);
            b.seal_block(start_new_blk);
            b.def_var(dirty_start_var, cur_row);
            let one_pt = b.ins().iconst(ptr_ty, 1);
            b.def_var(dirty_len_var, one_pt);
            b.ins().jump(next_row_blk, &[]);

            b.switch_to_block(check_adj_blk);
            b.seal_block(check_adj_blk);
            let expected_next = b.ins().iadd(ds, dl);
            let is_adj = b.ins().icmp(IntCC::Equal, expected_next, cur_row);
            b.ins().brif(is_adj, extend_blk, &[], flush_gap_blk, &[]);

            b.switch_to_block(extend_blk);
            b.seal_block(extend_blk);
            let dl_inc = b.ins().iadd_imm_s(dl, 1);
            b.def_var(dirty_len_var, dl_inc);
            b.ins().jump(next_row_blk, &[]);

            b.switch_to_block(flush_gap_blk);
            b.seal_block(flush_gap_blk);
            for term in plan.query0_terms.iter().filter(|t| t.is_selective) {
                let ti_v = b.ins().iconst(ptr_ty, term.term_idx as i64);
                let _ = call_slot(
                    &mut b,
                    api_ptr,
                    api_slots::ITER_MARK_CHANGED_RANGE,
                    sig_mark_changed,
                    ptr_ty,
                    &[iter_val, ti_v, ds, dl],
                );
            }
            b.def_var(dirty_start_var, cur_row);
            let one_pt2 = b.ins().iconst(ptr_ty, 1);
            b.def_var(dirty_len_var, one_pt2);
            b.ins().jump(next_row_blk, &[]);

            b.switch_to_block(next_row_blk);
            b.seal_block(next_row_blk);
        }

        let next_r = b.ins().iadd_imm_s(cur_row, 1);
        b.def_var(row_var, next_r);
        b.ins().jump(row_hdr, &[]);

        b.seal_block(row_body);
        b.seal_block(row_hdr);

        b.switch_to_block(row_exit);
        b.seal_block(row_exit);

        if plan.has_selective_writes {
            let tail_dl = b.use_var(dirty_len_var);
            let tail_ds = b.use_var(dirty_start_var);
            let flush_tail_blk = b.create_block();
            let after_flush_blk = b.create_block();
            let has_tail = b.ins().icmp_imm_s(IntCC::NotEqual, tail_dl, 0);
            b.ins()
                .brif(has_tail, flush_tail_blk, &[], after_flush_blk, &[]);

            b.switch_to_block(flush_tail_blk);
            b.seal_block(flush_tail_blk);
            for term in plan.query0_terms.iter().filter(|t| t.is_selective) {
                let ti_v = b.ins().iconst(ptr_ty, term.term_idx as i64);
                let _ = call_slot(
                    &mut b,
                    api_ptr,
                    api_slots::ITER_MARK_CHANGED_RANGE,
                    sig_mark_changed,
                    ptr_ty,
                    &[iter_val, ti_v, tail_ds, tail_dl],
                );
            }
            b.ins().jump(after_flush_blk, &[]);

            b.switch_to_block(after_flush_blk);
            b.seal_block(after_flush_blk);
        }

        b.ins().jump(chunk_hdr, &[]);
        b.seal_block(chunk_body);
        b.seal_block(chunk_hdr);

        b.switch_to_block(chunk_exit);
        b.seal_block(chunk_exit);
        let ok_ret = b.ins().iconst(types::I32, 0);
        b.ins().return_(&[ok_ret]);
        b.finalize(fe_cfg);
    }

    module
        .define_function(func_id, &mut ctx)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    module.clear_context(&mut ctx);
    Ok(func_id)
}

fn lower_kernel_stmt(
    b: &mut FunctionBuilder<'_>,
    stmt: &KernelStmt,
    res_ptrs: &HashMap<String, Value>,
    col_ptrs: &HashMap<usize, Value>,
    row_idx: Value,
    row_dirty: Option<Variable>,
    vars: &mut HashMap<String, (Variable, ScalarKind)>,
) {
    match stmt {
        KernelStmt::Let { name, expr, kind } => {
            let (val, actual_kind) = lower_kernel_expr(b, expr, res_ptrs, col_ptrs, row_idx, vars);
            let cast_v = cast_scalar(b, val, actual_kind, *kind);
            let var = b.declare_var(cl_type(*kind));
            b.def_var(var, cast_v);
            vars.insert(name.clone(), (var, *kind));
        }
        KernelStmt::Assign { target, op, value } => {
            let (rhs_v, rhs_k) = lower_kernel_expr(b, value, res_ptrs, col_ptrs, row_idx, vars);
            match target {
                FieldRef::Local(name) => {
                    if let Some(&(var, dst_k)) = vars.get(name) {
                        let new_v = if *op == AssignOp::Set {
                            cast_scalar(b, rhs_v, rhs_k, dst_k)
                        } else {
                            let cur = b.use_var(var);
                            let rhs_c = cast_scalar(b, rhs_v, rhs_k, dst_k);
                            apply_assign_op(b, cur, rhs_c, *op, dst_k)
                        };
                        b.def_var(var, new_v);
                    }
                }
                FieldRef::ResourceField {
                    resource_canonical,
                    byte_offset,
                    kind,
                    ..
                } => {
                    if let Some(&rp) = res_ptrs.get(resource_canonical) {
                        store_field_at(b, rp, *byte_offset, *kind, *op, rhs_v, rhs_k);
                    }
                }
                FieldRef::ColumnField {
                    term_idx,
                    elem_size,
                    byte_offset,
                    kind,
                    is_selective,
                    ..
                } => {
                    if let Some(&cp) = col_ptrs.get(term_idx) {
                        let row_off = b.ins().imul_imm_s(row_idx, *elem_size as i64);
                        let elem_ptr = b.ins().iadd(cp, row_off);
                        store_field_at(b, elem_ptr, *byte_offset, *kind, *op, rhs_v, rhs_k);
                        if *is_selective && let Some(rd_var) = row_dirty {
                            let one = b.ins().iconst(types::I8, 1);
                            b.def_var(rd_var, one);
                        }
                    }
                }
            }
        }
        KernelStmt::If {
            cond,
            then_stmts,
            else_stmts,
        } => {
            let (cond_v, cond_k) = lower_kernel_expr(b, cond, res_ptrs, col_ptrs, row_idx, vars);
            let cond_b = cast_scalar(b, cond_v, cond_k, ScalarKind::Bool);
            let then_blk = b.create_block();
            let else_blk = b.create_block();
            let merge_blk = b.create_block();
            let is_true = b.ins().icmp_imm_s(IntCC::NotEqual, cond_b, 0);
            b.ins().brif(is_true, then_blk, &[], else_blk, &[]);

            b.switch_to_block(then_blk);
            b.seal_block(then_blk);
            for s in then_stmts {
                lower_kernel_stmt(b, s, res_ptrs, col_ptrs, row_idx, row_dirty, vars);
            }
            b.ins().jump(merge_blk, &[]);

            b.switch_to_block(else_blk);
            b.seal_block(else_blk);
            for s in else_stmts {
                lower_kernel_stmt(b, s, res_ptrs, col_ptrs, row_idx, row_dirty, vars);
            }
            b.ins().jump(merge_blk, &[]);

            b.switch_to_block(merge_blk);
            b.seal_block(merge_blk);
        }
    }
}

fn store_field_at(
    b: &mut FunctionBuilder<'_>,
    base_ptr: Value,
    byte_offset: usize,
    dst_kind: ScalarKind,
    op: AssignOp,
    rhs_v: Value,
    rhs_k: ScalarKind,
) {
    let rhs_c = cast_scalar(b, rhs_v, rhs_k, dst_kind);
    let val = if op == AssignOp::Set {
        rhs_c
    } else {
        let cur = b.ins().load(
            cl_type(dst_kind),
            MemFlagsData::trusted(),
            base_ptr,
            byte_offset as i32,
        );
        apply_assign_op(b, cur, rhs_c, op, dst_kind)
    };
    b.ins()
        .store(MemFlagsData::trusted(), val, base_ptr, byte_offset as i32);
}

fn apply_assign_op(
    b: &mut FunctionBuilder<'_>,
    lhs: Value,
    rhs: Value,
    op: AssignOp,
    kind: ScalarKind,
) -> Value {
    let bin = match op {
        AssignOp::Set => return rhs,
        AssignOp::AddAssign => BinOpKind::Add,
        AssignOp::SubAssign => BinOpKind::Sub,
        AssignOp::MulAssign => BinOpKind::Mul,
        AssignOp::DivAssign => BinOpKind::Div,
    };
    apply_binop(b, bin, lhs, rhs, kind)
}

fn lower_kernel_expr(
    b: &mut FunctionBuilder<'_>,
    expr: &KernelExpr,
    res_ptrs: &HashMap<String, Value>,
    col_ptrs: &HashMap<usize, Value>,
    row_idx: Value,
    vars: &HashMap<String, (Variable, ScalarKind)>,
) -> (Value, ScalarKind) {
    match expr {
        KernelExpr::FloatLit(v) => (b.ins().f32const(*v as f32), ScalarKind::F32),
        KernelExpr::IntLit(v) => (b.ins().iconst(types::I32, *v), ScalarKind::I32),
        KernelExpr::BoolLit(v) => (b.ins().iconst(types::I8, i64::from(*v)), ScalarKind::Bool),
        KernelExpr::Load(fref) => match fref {
            FieldRef::Local(name) => {
                if let Some(&(var, k)) = vars.get(name) {
                    (b.use_var(var), k)
                } else {
                    (b.ins().f32const(0.0), ScalarKind::F32)
                }
            }
            FieldRef::ResourceField {
                resource_canonical,
                byte_offset,
                kind,
                ..
            } => {
                if let Some(&rp) = res_ptrs.get(resource_canonical) {
                    let v = b.ins().load(
                        cl_type(*kind),
                        MemFlagsData::trusted(),
                        rp,
                        *byte_offset as i32,
                    );
                    (v, *kind)
                } else {
                    (b.ins().iconst(types::I32, 0), ScalarKind::I32)
                }
            }
            FieldRef::ColumnField {
                term_idx,
                elem_size,
                byte_offset,
                kind,
                ..
            } => {
                if let Some(&cp) = col_ptrs.get(term_idx) {
                    let row_off = b.ins().imul_imm_s(row_idx, *elem_size as i64);
                    let elem_ptr = b.ins().iadd(cp, row_off);
                    let v = b.ins().load(
                        cl_type(*kind),
                        MemFlagsData::trusted(),
                        elem_ptr,
                        *byte_offset as i32,
                    );
                    (v, *kind)
                } else {
                    (b.ins().iconst(types::I32, 0), ScalarKind::I32)
                }
            }
        },
        KernelExpr::Neg(inner) => {
            let (v, k) = lower_kernel_expr(b, inner, res_ptrs, col_ptrs, row_idx, vars);
            let out = match k {
                ScalarKind::F32 | ScalarKind::F64 => b.ins().fneg(v),
                _ => b.ins().ineg(v),
            };
            (out, k)
        }
        KernelExpr::Not(inner) => {
            let (v, k) = lower_kernel_expr(b, inner, res_ptrs, col_ptrs, row_idx, vars);
            let bool_v = cast_scalar(b, v, k, ScalarKind::Bool);
            let res = b.ins().icmp_imm_s(IntCC::Equal, bool_v, 0);
            (res, ScalarKind::Bool)
        }
        KernelExpr::Binary { op, lhs, rhs } => {
            let (lv, lk) = lower_kernel_expr(b, lhs, res_ptrs, col_ptrs, row_idx, vars);
            let (rv, rk) = lower_kernel_expr(b, rhs, res_ptrs, col_ptrs, row_idx, vars);
            let op_k = promote_kinds(lk, rk);
            let lc = cast_scalar(b, lv, lk, op_k);
            let rc = cast_scalar(b, rv, rk, op_k);
            match op {
                BinOpKind::Lt
                | BinOpKind::Le
                | BinOpKind::Gt
                | BinOpKind::Ge
                | BinOpKind::Eq
                | BinOpKind::Ne
                | BinOpKind::And
                | BinOpKind::Or => (apply_cmp(b, *op, lc, rc, op_k), ScalarKind::Bool),
                _ => (apply_binop(b, *op, lc, rc, op_k), op_k),
            }
        }
    }
}

fn cl_type(kind: ScalarKind) -> Type {
    match kind {
        ScalarKind::F32 => types::F32,
        ScalarKind::F64 => types::F64,
        ScalarKind::I32 | ScalarKind::U32 => types::I32,
        ScalarKind::I64 | ScalarKind::U64 => types::I64,
        ScalarKind::Bool => types::I8,
    }
}

fn promote_kinds(a: ScalarKind, b: ScalarKind) -> ScalarKind {
    if a == b {
        return a;
    }
    match (a, b) {
        (ScalarKind::F64, _) | (_, ScalarKind::F64) => ScalarKind::F64,
        (ScalarKind::F32, _) | (_, ScalarKind::F32) => ScalarKind::F32,
        (ScalarKind::U64, _) | (_, ScalarKind::U64) => ScalarKind::U64,
        (ScalarKind::I64, _) | (_, ScalarKind::I64) => ScalarKind::I64,
        (ScalarKind::U32, _) | (_, ScalarKind::U32) => ScalarKind::U32,
        (ScalarKind::I32, _) | (_, ScalarKind::I32) => ScalarKind::I32,
        _ => ScalarKind::Bool,
    }
}

fn cast_scalar(b: &mut FunctionBuilder<'_>, val: Value, from: ScalarKind, to: ScalarKind) -> Value {
    if from == to || cl_type(from) == cl_type(to) {
        return val;
    }
    match (from, to) {
        (ScalarKind::F32, ScalarKind::F64) => b.ins().fpromote(types::F64, val),
        (ScalarKind::F64, ScalarKind::F32) => b.ins().fdemote(types::F32, val),
        (ScalarKind::I32 | ScalarKind::I64, ScalarKind::F32 | ScalarKind::F64) => {
            b.ins().fcvt_from_sint(cl_type(to), val)
        }
        (
            ScalarKind::U32 | ScalarKind::U64 | ScalarKind::Bool,
            ScalarKind::F32 | ScalarKind::F64,
        ) => b.ins().fcvt_from_uint(cl_type(to), val),
        (ScalarKind::F32 | ScalarKind::F64, ScalarKind::I32 | ScalarKind::I64) => {
            b.ins().fcvt_to_sint_sat(cl_type(to), val)
        }
        (ScalarKind::F32 | ScalarKind::F64, ScalarKind::U32 | ScalarKind::U64) => {
            b.ins().fcvt_to_uint_sat(cl_type(to), val)
        }
        (
            ScalarKind::Bool,
            ScalarKind::I32 | ScalarKind::U32 | ScalarKind::I64 | ScalarKind::U64,
        ) => b.ins().uextend(cl_type(to), val),
        (ScalarKind::I32, ScalarKind::I64) => b.ins().sextend(types::I64, val),
        (ScalarKind::U32, ScalarKind::U64 | ScalarKind::I64) => b.ins().uextend(types::I64, val),
        (_, ScalarKind::Bool) => b.ins().icmp_imm_s(IntCC::NotEqual, val, 0),
        (ScalarKind::I64 | ScalarKind::U64, ScalarKind::I32 | ScalarKind::U32) => {
            b.ins().ireduce(types::I32, val)
        }
        _ => val,
    }
}

fn apply_binop(
    b: &mut FunctionBuilder<'_>,
    op: BinOpKind,
    lhs: Value,
    rhs: Value,
    kind: ScalarKind,
) -> Value {
    match kind {
        ScalarKind::F32 | ScalarKind::F64 => match op {
            BinOpKind::Add => b.ins().fadd(lhs, rhs),
            BinOpKind::Sub => b.ins().fsub(lhs, rhs),
            BinOpKind::Mul => b.ins().fmul(lhs, rhs),
            BinOpKind::Div => b.ins().fdiv(lhs, rhs),
            _ => lhs,
        },
        ScalarKind::I32 | ScalarKind::I64 => match op {
            BinOpKind::Add => b.ins().iadd(lhs, rhs),
            BinOpKind::Sub => b.ins().isub(lhs, rhs),
            BinOpKind::Mul => b.ins().imul(lhs, rhs),
            BinOpKind::Div => b.ins().sdiv(lhs, rhs),
            BinOpKind::Rem => b.ins().srem(lhs, rhs),
            _ => lhs,
        },
        ScalarKind::U32 | ScalarKind::U64 | ScalarKind::Bool => match op {
            BinOpKind::Add => b.ins().iadd(lhs, rhs),
            BinOpKind::Sub => b.ins().isub(lhs, rhs),
            BinOpKind::Mul => b.ins().imul(lhs, rhs),
            BinOpKind::Div => b.ins().udiv(lhs, rhs),
            BinOpKind::Rem => b.ins().urem(lhs, rhs),
            BinOpKind::And => b.ins().band(lhs, rhs),
            BinOpKind::Or => b.ins().bor(lhs, rhs),
            _ => lhs,
        },
    }
}

fn apply_cmp(
    b: &mut FunctionBuilder<'_>,
    op: BinOpKind,
    lhs: Value,
    rhs: Value,
    kind: ScalarKind,
) -> Value {
    match kind {
        ScalarKind::F32 | ScalarKind::F64 => {
            let cc = match op {
                BinOpKind::Lt => FloatCC::LessThan,
                BinOpKind::Le => FloatCC::LessThanOrEqual,
                BinOpKind::Gt => FloatCC::GreaterThan,
                BinOpKind::Ge => FloatCC::GreaterThanOrEqual,
                BinOpKind::Eq => FloatCC::Equal,
                BinOpKind::Ne => FloatCC::NotEqual,
                _ => return lhs,
            };
            b.ins().fcmp(cc, lhs, rhs)
        }
        ScalarKind::I32 | ScalarKind::I64 => {
            let cc = match op {
                BinOpKind::Lt => IntCC::SignedLessThan,
                BinOpKind::Le => IntCC::SignedLessThanOrEqual,
                BinOpKind::Gt => IntCC::SignedGreaterThan,
                BinOpKind::Ge => IntCC::SignedGreaterThanOrEqual,
                BinOpKind::Eq => IntCC::Equal,
                BinOpKind::Ne => IntCC::NotEqual,
                _ => return lhs,
            };
            b.ins().icmp(cc, lhs, rhs)
        }
        ScalarKind::U32 | ScalarKind::U64 | ScalarKind::Bool => match op {
            BinOpKind::And => b.ins().band(lhs, rhs),
            BinOpKind::Or => b.ins().bor(lhs, rhs),
            _ => {
                let cc = match op {
                    BinOpKind::Lt => IntCC::UnsignedLessThan,
                    BinOpKind::Le => IntCC::UnsignedLessThanOrEqual,
                    BinOpKind::Gt => IntCC::UnsignedGreaterThan,
                    BinOpKind::Ge => IntCC::UnsignedGreaterThanOrEqual,
                    BinOpKind::Eq => IntCC::Equal,
                    _ => IntCC::NotEqual,
                };
                b.ins().icmp(cc, lhs, rhs)
            }
        },
    }
}

fn import_sig(
    b: &mut FunctionBuilder<'_>,
    call_conv: cranelift_codegen::isa::CallConv,
    params: &[Type],
    ret: Option<Type>,
) -> cranelift_codegen::ir::SigRef {
    let mut sig = Signature::new(call_conv);
    for &p in params {
        sig.params.push(AbiParam::new(p));
    }
    if let Some(r) = ret {
        sig.returns.push(AbiParam::new(r));
    }
    b.import_signature(sig)
}

fn call_slot(
    b: &mut FunctionBuilder<'_>,
    api_ptr: Value,
    slot_offset: usize,
    sig_ref: cranelift_codegen::ir::SigRef,
    ptr_ty: Type,
    args: &[Value],
) -> Vec<Value> {
    let fn_ptr = b
        .ins()
        .load(ptr_ty, MemFlagsData::trusted(), api_ptr, slot_offset as i32);
    let inst = b.ins().call_indirect(sig_ref, fn_ptr, args);
    b.inst_results(inst).to_vec()
}

fn alloc_zero_slot(b: &mut FunctionBuilder<'_>, size: usize, ptr_ty: Type) -> StackSlot {
    let padded = size.div_ceil(8) * 8;
    let slot = b.create_sized_stack_slot(StackSlotData::new(
        StackSlotKind::ExplicitSlot,
        padded.max(8) as u32,
        3,
    ));
    zero_slot(b, slot, padded.max(8), ptr_ty);
    slot
}

fn zero_slot(b: &mut FunctionBuilder<'_>, slot: StackSlot, size: usize, ptr_ty: Type) {
    let z64 = b.ins().iconst(types::I64, 0);
    let words = size.div_ceil(8);
    for w in 0..words {
        b.ins().stack_store(ptr_ty, z64, slot, (w * 8) as i32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies `access_mode_u32` maps Strata `TermAccessMode` to exact `bamabi_sys::AccessMode` constants.
    #[test]
    fn access_mode_wire_discriminants_match_bamabi_sys() {
        assert_eq!(
            access_mode_u32(TermAccessMode::Read),
            bamabi_sys::AccessMode::READ.0
        );
        assert_eq!(
            access_mode_u32(TermAccessMode::SelectiveWrite),
            bamabi_sys::AccessMode::WRITE.0
        );
        assert_eq!(
            access_mode_u32(TermAccessMode::OptionalRead),
            bamabi_sys::AccessMode::OPTIONAL_READ.0
        );
        assert_eq!(
            access_mode_u32(TermAccessMode::Without),
            bamabi_sys::AccessMode::WITHOUT.0
        );
    }
}
