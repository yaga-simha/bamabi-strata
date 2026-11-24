//! Runtime manifest, shutdown, `bamabi_init`, query descriptors, and startup objects.

use super::*;

pub(super) fn emit_startup_object_initializer(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    if ctx.mir.objects.is_empty() {
        return Ok(());
    }
    let sym = "strata_init_objects";
    let ptr_ty = ctx.ptr_ty;
    let call_conv = ctx.call_conv;
    let mut sig = Signature::new(call_conv);
    sig.params.push(AbiParam::new(ptr_ty)); // sys_ctx
    sig.params.push(AbiParam::new(ptr_ty)); // user_data (state_ptr)
    sig.returns.push(AbiParam::new(types::I32));
    let fid = ctx
        .obj_mod
        .declare_function(sym, Linkage::Local, &sig)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let name_id = ctx.intern_cstr(sym)?;

    // Build per-object primary-component query list and materialize any literal `HirCompInit` defaults.
    let mut obj_queries = Vec::new();
    let mut obj_blobs: Vec<(usize, Vec<(usize, Option<DataId>)>)> = Vec::new();

    for (oi, obj) in ctx.mir.objects.iter().enumerate() {
        let mut comp_blobs = Vec::new();
        for cname in &obj.components {
            if let Some(lidx) = lookup_name_in_map(&ctx.layout_map, cname) {
                let blob_id = define_object_comp_blob(
                    ctx,
                    oi,
                    lidx,
                    obj.inits.iter().find(|init| {
                        lookup_name_in_map(&ctx.layout_map, &init.component) == Some(lidx)
                    }),
                )?;
                comp_blobs.push((lidx, blob_id));
            }
        }
        if let Some(&(primary_lidx, _)) = comp_blobs.first() {
            let qi = obj_queries.len();
            obj_queries.push((oi, primary_lidx));
            obj_blobs.push((qi, comp_blobs));
        } else {
            obj_blobs.push((usize::MAX, comp_blobs));
        }
    }

    let obj_count = ctx.mir.objects.len();
    let mut obj_names = Vec::with_capacity(obj_count);
    let mut obj_persists = Vec::with_capacity(obj_count);
    for obj in &ctx.mir.objects {
        obj_names.push(ctx.intern_bytes(&obj.name)?);
        obj_persists.push(obj.is_persist);
    }

    let mut fn_ctx = ctx.obj_mod.make_context();
    fn_ctx.func.signature = sig;
    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut fn_ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);
        b.seal_block(entry);

        let sys_ctx = b.block_params(entry)[0];
        let state_ptr = b.block_params(entry)[1];
        let api_ptr = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.api_off as i32,
        );
        let host_ctx = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.host_ctx_off as i32,
        );

        let iter_slot = alloc_zero_slot(&mut b, ctx.ptr_bytes, ptr_ty);
        let iter_out = b.ins().stack_addr(ptr_ty, iter_slot, 0);
        let len_slot = alloc_zero_slot(&mut b, ctx.ptr_bytes, ptr_ty);
        let len_ptr = b.ins().stack_addr(ptr_ty, len_slot, 0);
        let cmd_slot = alloc_zero_slot(&mut b, ctx.ptr_bytes, ptr_ty);
        let cmd_out = b.ins().stack_addr(ptr_ty, cmd_slot, 0);
        let _cmd_rc = call_vtable(
            &ctx.obj_mod,
            &mut b,
            api_ptr,
            api_slots::SYS_COMMANDS,
            &[ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            call_conv,
            &[sys_ctx, cmd_out],
        );
        let cmds = b.ins().load(ptr_ty, MemFlagsData::trusted(), cmd_out, 0);

        for oi in 0..obj_count {
            let slot_off = ctx.state_layout.obj_slot_offset(oi) as i32;
            let cur = b
                .ins()
                .load(types::I64, MemFlagsData::trusted(), state_ptr, slot_off);
            let need = b.ins().icmp_imm_s(IntCC::Equal, cur, 0);
            let check_bb = b.create_block();
            let next_bb = b.create_block();
            b.ins().brif(need, check_bb, &[], next_bb, &[]);

            b.switch_to_block(check_bb);
            b.seal_block(check_bb);

            let (qi, comp_blobs) = &obj_blobs[oi];
            let spawn_bb = b.create_block();
            let bind_bb = b.create_block();
            b.append_block_param(bind_bb, types::I64);

            if *qi != usize::MAX {
                let qv = b.ins().iconst(ptr_ty, *qi as i64);
                let qrc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::SYS_QUERY,
                    &[ptr_ty, ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    call_conv,
                    &[sys_ctx, qv, iter_out],
                );
                let iter = b.ins().load(ptr_ty, MemFlagsData::trusted(), iter_out, 0);
                let rc_ok = b.ins().icmp_imm_s(IntCC::Equal, qrc, 0);
                let inz = b.ins().icmp_imm_s(IntCC::NotEqual, iter, 0);
                let ok = b.ins().band(rc_ok, inz);
                let probe_bb = b.create_block();
                b.ins().brif(ok, probe_bb, &[], spawn_bb, &[]);

                b.switch_to_block(probe_bb);
                b.seal_block(probe_bb);
                let has = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::ITER_NEXT_CHUNK,
                    &[ptr_ty, ptr_ty],
                    Some(types::I8),
                    ptr_ty,
                    call_conv,
                    &[iter, len_ptr],
                );
                let clen = b.ins().load(ptr_ty, MemFlagsData::trusted(), len_ptr, 0);
                let has_b = b.ins().icmp_imm_s(IntCC::NotEqual, has, 0);
                let len_p = b.ins().icmp_imm_s(IntCC::SignedGreaterThan, clen, 0);
                let found = b.ins().band(has_b, len_p);
                let take_bb = b.create_block();
                b.ins().brif(found, take_bb, &[], spawn_bb, &[]);

                b.switch_to_block(take_bb);
                b.seal_block(take_bb);
                let ents = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::ITER_ENTITIES,
                    &[ptr_ty],
                    Some(ptr_ty),
                    ptr_ty,
                    call_conv,
                    &[iter],
                );
                let e0 = b.ins().load(types::I64, MemFlagsData::trusted(), ents, 0);
                b.ins().jump(bind_bb, &[BlockArg::Value(e0)]);
            } else {
                b.ins().jump(spawn_bb, &[]);
            }

            b.switch_to_block(spawn_bb);
            b.seal_block(spawn_bb);
            let out_ent_slot = alloc_zero_slot(&mut b, structs::FFI_ENTITY_SIZE, ptr_ty);
            let out_ent_ptr = b.ins().stack_addr(ptr_ty, out_ent_slot, 0);
            if !comp_blobs.is_empty() {
                let comp_arr_slot = alloc_zero_slot(
                    &mut b,
                    comp_blobs.len() * structs::BAM_COMPONENT_SIZE,
                    ptr_ty,
                );
                let comp_arr = b.ins().stack_addr(ptr_ty, comp_arr_slot, 0);
                let ptr_arr_slot =
                    alloc_zero_slot(&mut b, comp_blobs.len() * ctx.ptr_bytes, ptr_ty);
                let ptr_arr = b.ins().stack_addr(ptr_ty, ptr_arr_slot, 0);
                for (ci, &(lidx, blob_opt)) in comp_blobs.iter().enumerate() {
                    let h = b.ins().load(
                        types::I32,
                        MemFlagsData::trusted(),
                        state_ptr,
                        ctx.state_layout.comp_slot_offset(lidx) as i32,
                    );
                    b.ins().store(
                        MemFlagsData::trusted(),
                        h,
                        comp_arr,
                        (ci * structs::BAM_COMPONENT_SIZE) as i32,
                    );
                    let dp = if let Some(bid) = blob_opt {
                        let gv = ctx.obj_mod.declare_data_in_func(bid, b.func);
                        b.ins().symbol_value(ptr_ty, gv)
                    } else {
                        b.ins().iconst(ptr_ty, 0)
                    };
                    b.ins().store(
                        MemFlagsData::trusted(),
                        dp,
                        ptr_arr,
                        (ci * ctx.ptr_bytes) as i32,
                    );
                }
                let cnt = b.ins().iconst(ptr_ty, comp_blobs.len() as i64);
                let sp_slot = if obj_persists[oi] {
                    api_slots::CMD_SPAWN_PERSISTENT
                } else {
                    api_slots::CMD_SPAWN
                };
                let _rc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    sp_slot,
                    &[ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    call_conv,
                    &[cmds, comp_arr, ptr_arr, cnt, out_ent_ptr],
                );
            } else {
                let _rc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::CMD_SPAWN_EMPTY,
                    &[ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    call_conv,
                    &[cmds, out_ent_ptr],
                );
            }
            let spawned = b
                .ins()
                .load(types::I64, MemFlagsData::trusted(), out_ent_ptr, 0);
            b.ins().jump(bind_bb, &[BlockArg::Value(spawned)]);

            b.switch_to_block(bind_bb);
            b.seal_block(bind_bb);
            let ent = b.block_params(bind_bb)[0];
            b.ins()
                .store(MemFlagsData::trusted(), ent, state_ptr, slot_off);
            let (nid, nlen) = obj_names[oi];
            let ngv = ctx.obj_mod.declare_data_in_func(nid, b.func);
            let nptr = b.ins().symbol_value(ptr_ty, ngv);
            let nlen_v = b.ins().iconst(ptr_ty, nlen as i64);
            let _bind_rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::BIND_NAMED_OBJECT,
                &[ptr_ty, ptr_ty, ptr_ty, types::I64],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[host_ctx, nptr, nlen_v, ent],
            );
            b.ins().jump(next_bb, &[]);

            b.switch_to_block(next_bb);
            b.seal_block(next_bb);
        }

        let ok = b.ins().iconst(types::I32, i64::from(FFI_OK));
        b.ins().return_(&[ok]);
        b.finalize(ctx.fe_cfg);
    }
    ctx.obj_mod
        .define_function(fid, &mut fn_ctx)
        .map_err(|e| JitError::Codegen(format!("strata_init_objects failed: {e}")))?;

    ctx.init_objects_fn = Some((fid, name_id, obj_queries));
    Ok(())
}

pub(super) fn define_object_comp_blob(
    ctx: &mut ModuleContext<'_>,
    _obj_idx: usize,
    lidx: usize,
    init: Option<&HirCompInit>,
) -> Result<Option<DataId>, JitError> {
    let layout = &ctx.mir_layouts_sorted[lidx];
    if layout.size == 0 {
        return Ok(None);
    }
    let mut blob = vec![0u8; layout.size];
    fill_layout_defaults(&mut blob, layout, ctx.mir, 0);
    if let Some(defaults) = ctx.mir.field_defaults.get(&layout.canonical_name) {
        for (fname, cval) in defaults {
            if let Some(sf) = layout.fields.iter().find(|f| f.name == *fname) {
                write_const_val_to_buf(&mut blob, sf, cval, ctx.mir);
            }
        }
    }
    if let Some(ci) = init {
        for (fname, fexpr) in &ci.fields {
            if let Some(sf) = layout.fields.iter().find(|f| f.name == *fname)
                && let Some(cval) = eval_const_hir_expr_for_ty(
                    fexpr,
                    Some(&sf.ty),
                    &ctx.enums_by_name,
                    &ctx.consts_by_name,
                    &ctx.mir.layouts,
                )
            {
                write_const_val_to_buf(&mut blob, sf, &cval, ctx.mir);
            }
        }
    }
    let bid = ctx
        .obj_mod
        .declare_anonymous_data(false, false)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    let mut desc = DataDescription::new();
    desc.define(blob.into_boxed_slice());
    desc.set_align(layout.align.max(1) as u64);
    ctx.obj_mod
        .define_data(bid, &desc)
        .map_err(|e| JitError::Codegen(e.to_string()))?;
    Ok(Some(bid))
}

pub(super) fn emit_res_ptr_lookup(
    ctx: &ModuleContext<'_>,
    b: &mut FunctionBuilder<'_>,
    api_ptr: Value,
    sys_ctx: Value,
    state_ptr: Value,
    lidx: usize,
    mutable: bool,
) -> Value {
    let ptr_ty = ctx.ptr_ty;
    let flag = b.ins().load(
        types::I8,
        MemFlagsData::trusted(),
        state_ptr,
        ctx.state_layout.res_flag_offset(lidx) as i32,
    );
    let is_host = b.ins().icmp_imm_s(IntCC::Equal, flag, 1);
    let has_sys = b.ins().icmp_imm_s(IntCC::NotEqual, sys_ctx, 0);
    let use_host = b.ins().band(is_host, has_sys);

    let host_bb = b.create_block();
    let local_bb = b.create_block();
    let merge_bb = b.create_block();
    b.append_block_param(merge_bb, ptr_ty);
    b.ins().brif(use_host, host_bb, &[], local_bb, &[]);

    b.switch_to_block(host_bb);
    b.seal_block(host_bb);
    let comp = b.ins().load(
        types::I32,
        MemFlagsData::trusted(),
        state_ptr,
        ctx.state_layout.comp_slot_offset(lidx) as i32,
    );
    let tick_slot = alloc_zero_slot(b, 16, ptr_ty);
    let tick_ptr = b.ins().stack_addr(ptr_ty, tick_slot, 0);
    let vslot = if mutable {
        api_slots::SYS_RES_MUT_PTR
    } else {
        api_slots::SYS_RES_PTR
    };
    let hptr = call_vtable(
        &ctx.obj_mod,
        b,
        api_ptr,
        vslot,
        &[ptr_ty, types::I32, ptr_ty],
        Some(ptr_ty),
        ptr_ty,
        ctx.call_conv,
        &[sys_ctx, comp, tick_ptr],
    );
    let h_ok = b.ins().icmp_imm_s(IntCC::NotEqual, hptr, 0);
    b.ins()
        .brif(h_ok, merge_bb, &[BlockArg::Value(hptr)], local_bb, &[]);

    b.switch_to_block(local_bb);
    b.seal_block(local_bb);
    let off = ctx.layouts[lidx].mod_res_offset as i64;
    let lptr = b.ins().iadd_imm_s(state_ptr, off);
    b.ins().jump(merge_bb, &[BlockArg::Value(lptr)]);

    b.switch_to_block(merge_bb);
    b.seal_block(merge_bb);
    b.block_params(merge_bb)[0]
}

pub(super) fn emit_bamabi_manifest(
    ctx: &mut ModuleContext<'_>,
    manifest_data_id: DataId,
) -> Result<(), JitError> {
    let mut sig = Signature::new(ctx.call_conv);
    sig.returns.push(AbiParam::new(ctx.ptr_ty));
    let fid = ctx
        .obj_mod
        .declare_function("bamabi_manifest", Linkage::Export, &sig)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let mut fn_ctx = ctx.obj_mod.make_context();
    fn_ctx.func.signature = sig;
    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut fn_ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.switch_to_block(entry);
        b.seal_block(entry);
        let gv = ctx.obj_mod.declare_data_in_func(manifest_data_id, b.func);
        let addr = b.ins().symbol_value(ctx.ptr_ty, gv);
        b.ins().return_(&[addr]);
        b.finalize(ctx.fe_cfg);
    }
    ctx.obj_mod
        .define_function(fid, &mut fn_ctx)
        .map_err(|e| JitError::Codegen(e.to_string()))
}

pub(super) fn emit_bamabi_shutdown(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    let ptr_ty = ctx.ptr_ty;
    let free_fid = ctx.declare_extern_fn("free", &[ptr_ty], None)?;

    let mut sig = Signature::new(ctx.call_conv);
    sig.params.push(AbiParam::new(ptr_ty)); // instance
    let fid = ctx
        .obj_mod
        .declare_function("bamabi_shutdown", Linkage::Export, &sig)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let mut fn_ctx = ctx.obj_mod.make_context();
    fn_ctx.func.signature = sig;
    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut fn_ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);
        b.seal_block(entry);
        let inst = b.block_params(entry)[0];
        let nz = b.ins().icmp_imm_s(IntCC::NotEqual, inst, 0);
        let free_bb = b.create_block();
        let ret_bb = b.create_block();
        b.ins().brif(nz, free_bb, &[], ret_bb, &[]);

        b.switch_to_block(free_bb);
        b.seal_block(free_bb);
        let fref = ctx.obj_mod.declare_func_in_func(free_fid, b.func);
        let rx_buf = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            inst,
            ctx.state_layout.net_rx_buf_off as i32,
        );
        let rx_nz = b.ins().icmp_imm_s(IntCC::NotEqual, rx_buf, 0);
        let free_rx_bb = b.create_block();
        let free_inst_bb = b.create_block();
        b.ins().brif(rx_nz, free_rx_bb, &[], free_inst_bb, &[]);
        b.switch_to_block(free_rx_bb);
        b.seal_block(free_rx_bb);
        b.ins().call(fref, &[rx_buf]);
        b.ins().jump(free_inst_bb, &[]);
        b.switch_to_block(free_inst_bb);
        b.seal_block(free_inst_bb);
        b.ins().call(fref, &[inst]);
        b.ins().jump(ret_bb, &[]);

        b.switch_to_block(ret_bb);
        b.seal_block(ret_bb);
        b.ins().return_(&[]);
        b.finalize(ctx.fe_cfg);
    }
    ctx.obj_mod
        .define_function(fid, &mut fn_ctx)
        .map_err(|e| JitError::Codegen(e.to_string()))
}

pub(super) fn emit_bamabi_init(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    let ptr_ty = ctx.ptr_ty;
    let ptr_bytes = ctx.ptr_bytes;
    let call_conv = ctx.call_conv;
    let calloc_fid = ctx.declare_extern_fn("calloc", &[ptr_ty, ptr_ty], Some(ptr_ty))?;
    let free_fid = ctx.declare_extern_fn("free", &[ptr_ty], None)?;

    let mut sig = Signature::new(call_conv);
    sig.params.push(AbiParam::new(ptr_ty)); // api_ptr
    sig.params.push(AbiParam::new(ptr_ty)); // load_ctx
    sig.params.push(AbiParam::new(ptr_ty)); // instance_out
    sig.returns.push(AbiParam::new(types::I32));
    let fid = ctx
        .obj_mod
        .declare_function("bamabi_init", Linkage::Export, &sig)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let mut fn_ctx = ctx.obj_mod.make_context();
    fn_ctx.func.signature = sig;
    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut fn_ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);
        b.seal_block(entry);

        let api_ptr = b.block_params(entry)[0];
        let load_ctx = b.block_params(entry)[1];
        let instance_out = b.block_params(entry)[2];

        let err_null_blk = b.create_block();
        let init_ok_blk = b.create_block();
        let err_ret_blk = b.create_block();
        b.append_block_param(err_ret_blk, types::I32);
        let err_free_ret_blk = b.create_block();
        b.append_block_param(err_free_ret_blk, types::I32);

        let api_null = b.ins().icmp_imm_s(IntCC::Equal, api_ptr, 0);
        let lctx_null = b.ins().icmp_imm_s(IntCC::Equal, load_ctx, 0);
        let any_null = b.ins().bor(api_null, lctx_null);
        b.ins().brif(any_null, err_null_blk, &[], init_ok_blk, &[]);

        b.switch_to_block(err_null_blk);
        b.seal_block(err_null_blk);
        let null_res = b
            .ins()
            .iconst(types::I32, i64::from(crate::abi_offsets::FFI_NULL_POINTER));
        b.ins().return_(&[null_res]);

        b.switch_to_block(init_ok_blk);
        b.seal_block(init_ok_blk);

        // Allocate per-world `StrataJitState` via `calloc(1, total_bytes)`.
        let cref = ctx.obj_mod.declare_func_in_func(calloc_fid, b.func);
        let one_sz = b.ins().iconst(ptr_ty, 1);
        let tot_sz = b.ins().iconst(ptr_ty, ctx.state_layout.total_bytes as i64);
        let cal = b.ins().call(cref, &[one_sz, tot_sz]);
        let state_addr = b.func.dfg.inst_results(cal)[0];
        let state_null = b.ins().icmp_imm_s(IntCC::Equal, state_addr, 0);
        let state_ok_blk = b.create_block();
        let oom_res = b.ins().iconst(
            types::I32,
            i64::from(bamabi_sys::FfiResult::INTERNAL_ERROR.0),
        );
        b.ins().brif(
            state_null,
            err_ret_blk,
            &[BlockArg::Value(oom_res)],
            state_ok_blk,
            &[],
        );

        b.switch_to_block(state_ok_blk);
        b.seal_block(state_ok_blk);
        b.ins().store(
            MemFlagsData::trusted(),
            api_ptr,
            state_addr,
            ctx.state_layout.api_off as i32,
        );

        let io_null = b.ins().icmp_imm_s(IntCC::Equal, instance_out, 0);
        let write_inst_blk = b.create_block();
        let after_inst_blk = b.create_block();
        b.ins()
            .brif(io_null, after_inst_blk, &[], write_inst_blk, &[]);
        b.switch_to_block(write_inst_blk);
        b.seal_block(write_inst_blk);
        b.ins()
            .store(MemFlagsData::trusted(), state_addr, instance_out, 0);
        b.ins().jump(after_inst_blk, &[]);
        b.switch_to_block(after_inst_blk);
        b.seal_block(after_inst_blk);

        let host_ctx = call_vtable(
            &ctx.obj_mod,
            &mut b,
            api_ptr,
            api_slots::LOAD_HOST_CTX,
            &[ptr_ty],
            Some(ptr_ty),
            ptr_ty,
            call_conv,
            &[load_ctx],
        );
        b.ins().store(
            MemFlagsData::trusted(),
            host_ctx,
            state_addr,
            ctx.state_layout.host_ctx_off as i32,
        );

        // Initialize mod-local resource defaults inside `StrataJitState`.
        for l in &ctx.layouts {
            if (l.is_resource || l.is_stream)
                && let Some(blob_id) = l.default_blob_id
                && l.size > 0
            {
                let gv = ctx.obj_mod.declare_data_in_func(blob_id, b.func);
                let src_ptr = b.ins().symbol_value(ptr_ty, gv);
                let dst_ptr = b.ins().iadd_imm_s(state_addr, l.mod_res_offset as i64);
                emit_memcpy(&mut b, dst_ptr, src_ptr, l.size);
                if l.is_resource {
                    let shadow_ptr = b
                        .ins()
                        .iadd_imm_s(state_addr, l.mod_res_shadow_offset as i64);
                    emit_memcpy(&mut b, shadow_ptr, src_ptr, l.size);
                }
            }
        }

        // Reusable scratch slots for registration.
        let cdesc_slot = alloc_zero_slot(&mut b, structs::COMPONENT_DESC_SIZE, ptr_ty);
        let cdesc_buf = b.ins().stack_addr(ptr_ty, cdesc_slot, 0);
        let req_cap = ctx
            .layouts
            .iter()
            .map(|l| l.required_indices.len())
            .max()
            .unwrap_or(1)
            .max(1);
        let req_slot = alloc_zero_slot(&mut b, req_cap * structs::BAM_COMPONENT_SIZE, ptr_ty);
        let req_buf = b.ins().stack_addr(ptr_ty, req_slot, 0);
        let req_init_slot = alloc_zero_slot(&mut b, req_cap * REQ_COMP_DESC_SIZE, ptr_ty);
        let req_init_buf = b.ins().stack_addr(ptr_ty, req_init_slot, 0);
        let linfo_slot = alloc_zero_slot(&mut b, structs::LAYOUT_INFO_SIZE, ptr_ty);
        let linfo_ptr = b.ins().stack_addr(ptr_ty, linfo_slot, 0);
        let linfo_sz_v = b.ins().iconst(types::I32, structs::LAYOUT_INFO_SIZE as i64);

        // Step 1: Resolve host-registered resources & streams BEFORE registering dynamic mod components,
        // checking `component_layout_info` flags (`RESOURCE` / `MESSAGE`) to distinguish cleanly.
        for (lidx, l) in ctx.layouts.iter().enumerate() {
            if !l.is_resource && !l.is_stream {
                continue;
            }
            let comp_out = b
                .ins()
                .iadd_imm_s(state_addr, ctx.state_layout.comp_slot_offset(lidx) as i64);
            let ngv = ctx.obj_mod.declare_data_in_func(l.name_cstr_id, b.func);
            let nptr = b.ins().symbol_value(ptr_ty, ngv);
            let null_uuid = b.ins().iconst(ptr_ty, 0);
            let rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::RESOLVE_COMPONENT,
                &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[host_ctx, nptr, null_uuid, comp_out],
            );
            let ok = b.ins().icmp_imm_s(IntCC::Equal, rc, 0);
            let info_bb = b.create_block();
            let reg_stream_bb = b.create_block();
            let next_l_bb = b.create_block();
            b.ins().brif(ok, info_bb, &[], reg_stream_bb, &[]);

            b.switch_to_block(info_bb);
            b.seal_block(info_bb);
            b.ins().store(
                MemFlagsData::trusted(),
                linfo_sz_v,
                linfo_ptr,
                structs::LINFO_STRUCT_SIZE as i32,
            );
            let comp_h = b
                .ins()
                .load(types::I32, MemFlagsData::trusted(), comp_out, 0);
            let irc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::COMPONENT_LAYOUT_INFO,
                &[ptr_ty, types::I32, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[host_ctx, comp_h, linfo_ptr],
            );
            let irc_ok = b.ins().icmp_imm_s(IntCC::Equal, irc, 0);
            let lflags = b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                linfo_ptr,
                structs::LINFO_FLAGS as i32,
            );
            let expected_flag = if l.is_stream {
                i64::from(STORAGE_FLAG_MESSAGE)
            } else {
                i64::from(STORAGE_FLAG_RESOURCE)
            };
            let masked = b.ins().band_imm_u(lflags, expected_flag);
            let flag_set = b.ins().icmp_imm_s(IntCC::NotEqual, masked, 0);
            let matched = b.ins().band(irc_ok, flag_set);
            let mark_bb = b.create_block();
            b.ins().brif(matched, mark_bb, &[], reg_stream_bb, &[]);

            b.switch_to_block(mark_bb);
            b.seal_block(mark_bb);
            let kind_val = b.ins().iconst(types::I8, if l.is_stream { 2 } else { 1 });
            b.ins().store(
                MemFlagsData::trusted(),
                kind_val,
                state_addr,
                ctx.state_layout.res_flag_offset(lidx) as i32,
            );
            b.ins().jump(next_l_bb, &[]);

            b.switch_to_block(reg_stream_bb);
            b.seal_block(reg_stream_bb);
            if l.is_stream {
                let cgv = ctx.obj_mod.declare_data_in_func(l.comp_desc_id, b.func);
                let ro_cd = b.ins().symbol_value(ptr_ty, cgv);
                let s_rc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::REGISTER_COMPONENT,
                    &[ptr_ty, ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    call_conv,
                    &[load_ctx, ro_cd, comp_out],
                );
                let s_ok = b.ins().icmp_imm_s(IntCC::Equal, s_rc, 0);
                let reg_mark_bb = b.create_block();
                b.ins().brif(s_ok, reg_mark_bb, &[], next_l_bb, &[]);

                b.switch_to_block(reg_mark_bb);
                b.seal_block(reg_mark_bb);
                let msg_kind_v = b.ins().iconst(types::I8, 2);
                b.ins().store(
                    MemFlagsData::trusted(),
                    msg_kind_v,
                    state_addr,
                    ctx.state_layout.res_flag_offset(lidx) as i32,
                );
            }
            b.ins().jump(next_l_bb, &[]);

            b.switch_to_block(next_l_bb);
            b.seal_block(next_l_bb);
        }

        // Step 2: Register ECS components in topological `@require` order, supporting schema migration
        // (`TYPE_MISMATCH` -> `resolve_component(name, null)` -> `migrate_component_column` Slot 67).
        for (lidx, l) in ctx.layouts.iter().enumerate() {
            if !l.is_ecs_component || l.is_stream {
                continue;
            }
            let comp_out = b
                .ins()
                .iadd_imm_s(state_addr, ctx.state_layout.comp_slot_offset(lidx) as i64);
            let cgv = ctx.obj_mod.declare_data_in_func(l.comp_desc_id, b.func);
            let ro_cd = b.ins().symbol_value(ptr_ty, cgv);
            emit_memcpy(&mut b, cdesc_buf, ro_cd, structs::COMPONENT_DESC_SIZE);

            if !l.required_indices.is_empty() {
                zero_slot(
                    &mut b,
                    req_init_slot,
                    l.required_indices.len() * REQ_COMP_DESC_SIZE,
                    ptr_ty,
                );
                let req_init_sz_v = b.ins().iconst(types::I32, REQ_COMP_DESC_SIZE as i64);
                let custom_flag_v = b
                    .ins()
                    .iconst(types::I32, i64::from(BAM_REQUIRED_FLAG_CUSTOM_BYTES));
                for (ri, &req_lidx) in l.required_indices.iter().enumerate() {
                    let rh = b.ins().load(
                        types::I32,
                        MemFlagsData::trusted(),
                        state_addr,
                        ctx.state_layout.comp_slot_offset(req_lidx) as i32,
                    );
                    b.ins().store(
                        MemFlagsData::trusted(),
                        rh,
                        req_buf,
                        (ri * structs::BAM_COMPONENT_SIZE) as i32,
                    );
                    let entry_off = ri * REQ_COMP_DESC_SIZE;
                    b.ins().store(
                        MemFlagsData::trusted(),
                        req_init_sz_v,
                        req_init_buf,
                        (entry_off + REQ_COMP_STRUCT_SIZE_OFF) as i32,
                    );
                    b.ins().store(
                        MemFlagsData::trusted(),
                        rh,
                        req_init_buf,
                        (entry_off + REQ_COMP_COMPONENT_OFF) as i32,
                    );
                    let req_meta = &ctx.layouts[req_lidx];
                    if req_meta.size > 0
                        && ctx.mir_layouts_sorted[req_lidx].is_abi_pod
                        && let Some(def_bid) = req_meta.default_blob_id
                    {
                        let def_gv = ctx.obj_mod.declare_data_in_func(def_bid, b.func);
                        let def_ptr = b.ins().symbol_value(ptr_ty, def_gv);
                        let def_sz = b.ins().iconst(ptr_ty, req_meta.size as i64);
                        b.ins().store(
                            MemFlagsData::trusted(),
                            custom_flag_v,
                            req_init_buf,
                            (entry_off + REQ_COMP_FLAGS_OFF) as i32,
                        );
                        b.ins().store(
                            MemFlagsData::trusted(),
                            def_ptr,
                            req_init_buf,
                            (entry_off + REQ_COMP_INIT_BYTES_OFF) as i32,
                        );
                        b.ins().store(
                            MemFlagsData::trusted(),
                            def_sz,
                            req_init_buf,
                            (entry_off + REQ_COMP_INIT_SIZE_OFF) as i32,
                        );
                    }
                }
                let rcnt = b.ins().iconst(ptr_ty, l.required_indices.len() as i64);
                b.ins().store(
                    MemFlagsData::trusted(),
                    req_buf,
                    cdesc_buf,
                    structs::COMP_REQUIRED_COMPONENTS as i32,
                );
                b.ins().store(
                    MemFlagsData::trusted(),
                    rcnt,
                    cdesc_buf,
                    structs::COMP_REQUIRED_COMPONENT_COUNT as i32,
                );
                b.ins().store(
                    MemFlagsData::trusted(),
                    req_init_buf,
                    cdesc_buf,
                    COMP_REQUIRED_INIT_DESCS_OFF as i32,
                );
                b.ins().store(
                    MemFlagsData::trusted(),
                    rcnt,
                    cdesc_buf,
                    COMP_REQUIRED_INIT_DESC_COUNT_OFF as i32,
                );
            }

            let rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::REGISTER_COMPONENT,
                &[ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[load_ctx, cdesc_buf, comp_out],
            );
            let is_ok = b.ins().icmp_imm_s(IntCC::Equal, rc, 0);
            let next_comp_bb = b.create_block();
            let err_chk_bb = b.create_block();
            b.ins().brif(is_ok, next_comp_bb, &[], err_chk_bb, &[]);

            b.switch_to_block(err_chk_bb);
            b.seal_block(err_chk_bb);
            if let Some(&mig_fid) = ctx.migrations_by_layout.get(&lidx) {
                let is_mismatch =
                    b.ins()
                        .icmp_imm_s(IntCC::Equal, rc, i64::from(FFI_TYPE_MISMATCH));
                let mig_bb = b.create_block();
                b.ins().brif(
                    is_mismatch,
                    mig_bb,
                    &[],
                    err_ret_blk,
                    &[BlockArg::Value(rc)],
                );

                b.switch_to_block(mig_bb);
                b.seal_block(mig_bb);
                let ngv = ctx.obj_mod.declare_data_in_func(l.name_cstr_id, b.func);
                let nptr = b.ins().symbol_value(ptr_ty, ngv);
                let null_uuid = b.ins().iconst(ptr_ty, 0);
                let rrc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::RESOLVE_COMPONENT,
                    &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    call_conv,
                    &[host_ctx, nptr, null_uuid, comp_out],
                );
                let rrc_ok = b.ins().icmp_imm_s(IntCC::Equal, rrc, 0);
                let do_mig_bb = b.create_block();
                b.ins()
                    .brif(rrc_ok, do_mig_bb, &[], err_ret_blk, &[BlockArg::Value(rrc)]);

                b.switch_to_block(do_mig_bb);
                b.seal_block(do_mig_bb);
                let existing_comp = b
                    .ins()
                    .load(types::I32, MemFlagsData::trusted(), comp_out, 0);
                let old_fp = b.ins().iconst(types::I64, 0);
                let mig_ref = ctx.obj_mod.declare_func_in_func(mig_fid, b.func);
                let mig_fn_ptr = b.ins().func_addr(ptr_ty, mig_ref);
                let mrc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::MIGRATE_COMPONENT_COLUMN,
                    &[ptr_ty, types::I32, types::I64, ptr_ty, ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    call_conv,
                    &[
                        load_ctx,
                        existing_comp,
                        old_fp,
                        cdesc_buf,
                        mig_fn_ptr,
                        state_addr,
                    ],
                );
                let mrc_ok = b.ins().icmp_imm_s(IntCC::Equal, mrc, 0);
                b.ins().brif(
                    mrc_ok,
                    next_comp_bb,
                    &[],
                    err_ret_blk,
                    &[BlockArg::Value(mrc)],
                );
            } else {
                b.ins().jump(err_ret_blk, &[BlockArg::Value(rc)]);
            }

            b.switch_to_block(next_comp_bb);
            b.seal_block(next_comp_bb);
        }

        // Step 2b: When networking is active, verify Slot 53 `SCHEMA_FINGERPRINT` for net components
        // and resolve host `"strata::net::StrataNetPacket"` (`Slot 4` + `Slot 53`).
        if has_net_protocol(ctx.mir) {
            let inv_comp_v = b.ins().iconst(types::I32, i64::from(BAM_COMPONENT_INVALID));
            b.ins().store(
                MemFlagsData::trusted(),
                inv_comp_v,
                state_addr,
                ctx.state_layout.net_pkt_comp_off as i32,
            );
            for nc in &ctx.mir.net_components {
                if let Some(lidx) = lookup_name_in_map(&ctx.layout_map, &nc.canonical_name) {
                    let comp_h = b.ins().load(
                        types::I32,
                        MemFlagsData::trusted(),
                        state_addr,
                        ctx.state_layout.comp_slot_offset(lidx) as i32,
                    );
                    let comp_nz = b.ins().icmp_imm_s(IntCC::NotEqual, comp_h, 0);
                    let comp_valid = b.ins().icmp_imm_s(
                        IntCC::NotEqual,
                        comp_h,
                        i64::from(BAM_COMPONENT_INVALID),
                    );
                    let check_linfo_bb = b.create_block();
                    let next_nc_bb = b.create_block();
                    let comp_both_ok = b.ins().band(comp_nz, comp_valid);
                    b.ins()
                        .brif(comp_both_ok, check_linfo_bb, &[], next_nc_bb, &[]);

                    b.switch_to_block(check_linfo_bb);
                    b.seal_block(check_linfo_bb);
                    zero_slot(&mut b, linfo_slot, structs::LAYOUT_INFO_SIZE, ptr_ty);
                    b.ins().store(
                        MemFlagsData::trusted(),
                        linfo_sz_v,
                        linfo_ptr,
                        structs::LINFO_STRUCT_SIZE as i32,
                    );
                    let irc = call_vtable(
                        &ctx.obj_mod,
                        &mut b,
                        api_ptr,
                        api_slots::COMPONENT_LAYOUT_INFO,
                        &[ptr_ty, types::I32, ptr_ty],
                        Some(types::I32),
                        ptr_ty,
                        call_conv,
                        &[host_ctx, comp_h, linfo_ptr],
                    );
                    let irc_ok = b.ins().icmp_imm_s(IntCC::Equal, irc, 0);
                    let cmp_fp_bb = b.create_block();
                    b.ins().brif(irc_ok, cmp_fp_bb, &[], next_nc_bb, &[]);

                    b.switch_to_block(cmp_fp_bb);
                    b.seal_block(cmp_fp_bb);
                    let host_fp = b.ins().load(
                        types::I64,
                        MemFlagsData::trusted(),
                        linfo_ptr,
                        structs::LINFO_SCHEMA_FINGERPRINT as i32,
                    );
                    let fp_eq =
                        b.ins()
                            .icmp_imm_s(IntCC::Equal, host_fp, nc.schema_fingerprint as i64);
                    let mismatch_v = b.ins().iconst(types::I32, i64::from(FFI_TYPE_MISMATCH));
                    b.ins().brif(
                        fp_eq,
                        next_nc_bb,
                        &[],
                        err_free_ret_blk,
                        &[BlockArg::Value(mismatch_v)],
                    );

                    b.switch_to_block(next_nc_bb);
                    b.seal_block(next_nc_bb);
                }
            }

            let pkt_cstr = ctx.intern_cstr(STRATA_NET_PACKET_CANONICAL_NAME)?;
            let pkt_gv = ctx.obj_mod.declare_data_in_func(pkt_cstr, b.func);
            let pkt_nptr = b.ins().symbol_value(ptr_ty, pkt_gv);
            let null_uuid = b.ins().iconst(ptr_ty, 0);
            let net_comp_out = b
                .ins()
                .iadd_imm_s(state_addr, ctx.state_layout.net_pkt_comp_off as i64);
            let np_rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::RESOLVE_COMPONENT,
                &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[host_ctx, pkt_nptr, null_uuid, net_comp_out],
            );
            let np_ok = b.ins().icmp_imm_s(IntCC::Equal, np_rc, 0);
            let np_info_bb = b.create_block();
            let after_np_bb = b.create_block();
            b.ins().brif(np_ok, np_info_bb, &[], after_np_bb, &[]);

            b.switch_to_block(np_info_bb);
            b.seal_block(np_info_bb);
            zero_slot(&mut b, linfo_slot, structs::LAYOUT_INFO_SIZE, ptr_ty);
            b.ins().store(
                MemFlagsData::trusted(),
                linfo_sz_v,
                linfo_ptr,
                structs::LINFO_STRUCT_SIZE as i32,
            );
            let np_comp = b
                .ins()
                .load(types::I32, MemFlagsData::trusted(), net_comp_out, 0);
            let np_irc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::COMPONENT_LAYOUT_INFO,
                &[ptr_ty, types::I32, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[host_ctx, np_comp, linfo_ptr],
            );
            let np_irc_ok = b.ins().icmp_imm_s(IntCC::Equal, np_irc, 0);
            let np_flags = b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                linfo_ptr,
                structs::LINFO_FLAGS as i32,
            );
            let np_msg_bit = b
                .ins()
                .band_imm_u(np_flags, i64::from(STORAGE_FLAG_MESSAGE));
            let np_is_msg = b.ins().icmp_imm_s(IntCC::NotEqual, np_msg_bit, 0);
            let np_sz = b.ins().load(
                ptr_ty,
                MemFlagsData::trusted(),
                linfo_ptr,
                structs::LINFO_SIZE as i32,
            );
            let np_sz_ok = b
                .ins()
                .icmp_imm_s(IntCC::Equal, np_sz, STRATA_NET_PACKET_SIZE as i64);
            let np_fp = b.ins().load(
                types::I64,
                MemFlagsData::trusted(),
                linfo_ptr,
                structs::LINFO_SCHEMA_FINGERPRINT as i32,
            );
            let np_fp_ok = b.ins().icmp_imm_s(
                IntCC::Equal,
                np_fp,
                STRATA_NET_PACKET_SCHEMA_FINGERPRINT as i64,
            );
            let nv0 = b.ins().band(np_irc_ok, np_is_msg);
            let nv1 = b.ins().band(np_sz_ok, np_fp_ok);
            let np_valid = b.ins().band(nv0, nv1);
            let np_mark_bb = b.create_block();
            let mismatch_v = b.ins().iconst(types::I32, i64::from(FFI_TYPE_MISMATCH));
            b.ins().brif(
                np_valid,
                np_mark_bb,
                &[],
                err_free_ret_blk,
                &[BlockArg::Value(mismatch_v)],
            );

            b.switch_to_block(np_mark_bb);
            b.seal_block(np_mark_bb);
            let one_i8 = b.ins().iconst(types::I8, 1);
            b.ins().store(
                MemFlagsData::trusted(),
                one_i8,
                state_addr,
                ctx.state_layout.net_pkt_is_msg_off as i32,
            );
            let rx_cap_v = b.ins().iconst(ptr_ty, STRATA_NET_RX_BATCH_CAP as i64);
            let rx_elem_sz = b.ins().iconst(ptr_ty, STRATA_NET_PACKET_SIZE as i64);
            let rx_cal = b.ins().call(cref, &[rx_cap_v, rx_elem_sz]);
            let rx_buf_addr = b.func.dfg.inst_results(rx_cal)[0];
            let rx_buf_null = b.ins().icmp_imm_s(IntCC::Equal, rx_buf_addr, 0);
            let rx_ok_bb = b.create_block();
            b.ins().brif(
                rx_buf_null,
                err_free_ret_blk,
                &[BlockArg::Value(oom_res)],
                rx_ok_bb,
                &[],
            );
            b.switch_to_block(rx_ok_bb);
            b.seal_block(rx_ok_bb);
            b.ins().store(
                MemFlagsData::trusted(),
                rx_buf_addr,
                state_addr,
                ctx.state_layout.net_rx_buf_off as i32,
            );
            b.ins().jump(after_np_bb, &[]);

            b.switch_to_block(after_np_bb);
            b.seal_block(after_np_bb);
        }

        // Step 3: Register typed relations (`Slot 54`).
        for (ri, r) in ctx.relations.iter().enumerate() {
            let rel_out = b
                .ins()
                .iadd_imm_s(state_addr, ctx.state_layout.rel_slot_offset(ri) as i64);
            let rgv = ctx.obj_mod.declare_data_in_func(r.desc_id, b.func);
            let rdesc_ptr = b.ins().symbol_value(ptr_ty, rgv);
            let rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::REGISTER_RELATION,
                &[ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[load_ctx, rdesc_ptr, rel_out],
            );
            let is_err = b.ins().icmp_imm_s(IntCC::NotEqual, rc, 0);
            let ok_bb = b.create_block();
            b.ins()
                .brif(is_err, err_free_ret_blk, &[BlockArg::Value(rc)], ok_bb, &[]);
            b.switch_to_block(ok_bb);
            b.seal_block(ok_bb);
        }

        if ctx.uses_child_of {
            let co_out = b
                .ins()
                .iadd_imm_s(state_addr, ctx.state_layout.child_of_comp_off as i64);
            let inv_co = b.ins().iconst(types::I32, i64::from(BAM_COMPONENT_INVALID));
            b.ins().store(MemFlagsData::trusted(), inv_co, co_out, 0);
            let null_uuid = b.ins().iconst(ptr_ty, 0);
            let co_cstr = ctx.intern_cstr(bamabi_sys::BAM_CHILD_OF_NAME)?;
            let co_gv = ctx.obj_mod.declare_data_in_func(co_cstr, b.func);
            let co_nptr = b.ins().symbol_value(ptr_ty, co_gv);
            let rc1 = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::RESOLVE_COMPONENT,
                &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[host_ctx, co_nptr, null_uuid, co_out],
            );
            let rc1_ok = b.ins().icmp_imm_s(IntCC::Equal, rc1, 0);
            let fallback_bb = b.create_block();
            let co_done_bb = b.create_block();
            b.ins().brif(rc1_ok, co_done_bb, &[], fallback_bb, &[]);

            b.switch_to_block(fallback_bb);
            b.seal_block(fallback_bb);
            let short_cstr = ctx.intern_cstr("ChildOf")?;
            let short_gv = ctx.obj_mod.declare_data_in_func(short_cstr, b.func);
            let short_nptr = b.ins().symbol_value(ptr_ty, short_gv);
            let _rc2 = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::RESOLVE_COMPONENT,
                &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[host_ctx, short_nptr, null_uuid, co_out],
            );
            b.ins().jump(co_done_bb, &[]);

            b.switch_to_block(co_done_bb);
            b.seal_block(co_done_bb);
        }

        // Step 4: Register reactive observers (`Slot 36`).
        let obs_slot = alloc_zero_slot(&mut b, structs::OBSERVER_DESC_SIZE, ptr_ty);
        let obs_ptr = b.ins().stack_addr(ptr_ty, obs_slot, 0);
        let watch_slot = alloc_zero_slot(&mut b, structs::BAM_COMPONENT_SIZE, ptr_ty);
        let watch_ptr = b.ins().stack_addr(ptr_ty, watch_slot, 0);
        let obs_qdescs_slot =
            alloc_zero_slot(&mut b, structs::QUERY_DESC_SIZE * SYSTEM_QUERY_CAP, ptr_ty);
        let obs_qdescs_ptr = b.ins().stack_addr(ptr_ty, obs_qdescs_slot, 0);

        for obs in &ctx.observers {
            zero_slot(&mut b, obs_slot, structs::OBSERVER_DESC_SIZE, ptr_ty);
            zero_slot(
                &mut b,
                obs_qdescs_slot,
                structs::QUERY_DESC_SIZE * SYSTEM_QUERY_CAP,
                ptr_ty,
            );
            let osz = b
                .ins()
                .iconst(types::I32, structs::OBSERVER_DESC_SIZE as i64);
            let ngv = ctx
                .obj_mod
                .declare_data_in_func(obs.sys_entry.name_data_id, b.func);
            let nptr = b.ins().symbol_value(ptr_ty, ngv);
            let ev_comp = if let Some(ev_lidx) = obs.event_layout_idx {
                b.ins().load(
                    types::I32,
                    MemFlagsData::trusted(),
                    state_ptr_alias(state_addr),
                    ctx.state_layout.comp_slot_offset(ev_lidx) as i32,
                )
            } else {
                b.ins().iconst(types::I32, i64::from(BAM_COMPONENT_INVALID))
            };
            let ekind = b.ins().iconst(types::I32, i64::from(obs.event_kind));
            let inv_rel = b.ins().iconst(types::I32, i64::from(BAM_COMPONENT_INVALID));
            let fref = ctx
                .obj_mod
                .declare_func_in_func(obs.sys_entry.func_id, b.func);
            let fn_addr = b.ins().func_addr(ptr_ty, fref);

            b.ins()
                .stack_store(ptr_ty, osz, obs_slot, structs::OBS_STRUCT_SIZE as i32);
            b.ins()
                .stack_store(ptr_ty, nptr, obs_slot, structs::OBS_NAME as i32);
            b.ins()
                .stack_store(ptr_ty, ev_comp, obs_slot, structs::OBS_EVENT as i32);
            b.ins()
                .stack_store(ptr_ty, fn_addr, obs_slot, structs::OBS_CTX_CALLBACK as i32);
            b.ins()
                .stack_store(ptr_ty, state_addr, obs_slot, structs::OBS_USER_DATA as i32);
            b.ins()
                .stack_store(ptr_ty, ekind, obs_slot, structs::OBS_EVENT_KIND as i32);
            b.ins().stack_store(
                ptr_ty,
                inv_rel,
                obs_slot,
                structs::OBS_PROPAGATE_RELATIONSHIP as i32,
            );

            if let Some(w_lidx) = obs.watched_layout_idx {
                let wh = b.ins().load(
                    types::I32,
                    MemFlagsData::trusted(),
                    state_addr,
                    ctx.state_layout.comp_slot_offset(w_lidx) as i32,
                );
                b.ins().stack_store(ptr_ty, wh, watch_slot, 0);
                let one = b.ins().iconst(ptr_ty, 1);
                b.ins().stack_store(
                    ptr_ty,
                    watch_ptr,
                    obs_slot,
                    structs::OBS_WATCHED_COMPONENTS as i32,
                );
                b.ins().stack_store(
                    ptr_ty,
                    one,
                    obs_slot,
                    structs::OBS_WATCHED_COMPONENT_COUNT as i32,
                );
            }

            let final_qc = emit_populate_fn_query_descs(
                ctx,
                &mut b,
                state_addr,
                obs_qdescs_ptr,
                &obs.sys_entry,
            )?;
            let has_q = b.ins().icmp_imm_s(IntCC::SignedGreaterThan, final_qc, 0);
            let set_q_bb = b.create_block();
            let after_q_bb = b.create_block();
            b.ins().brif(has_q, set_q_bb, &[], after_q_bb, &[]);
            b.switch_to_block(set_q_bb);
            b.seal_block(set_q_bb);
            b.ins().stack_store(
                ptr_ty,
                obs_qdescs_ptr,
                obs_slot,
                structs::OBS_QUERIES as i32,
            );
            b.ins()
                .stack_store(ptr_ty, final_qc, obs_slot, structs::OBS_QUERY_COUNT as i32);
            b.ins().jump(after_q_bb, &[]);
            b.switch_to_block(after_q_bb);
            b.seal_block(after_q_bb);

            let rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::REGISTER_OBSERVER,
                &[ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[load_ctx, obs_ptr],
            );
            let is_err = b.ins().icmp_imm_s(IntCC::NotEqual, rc, 0);
            let ok_bb = b.create_block();
            b.ins()
                .brif(is_err, err_free_ret_blk, &[BlockArg::Value(rc)], ok_bb, &[]);
            b.switch_to_block(ok_bb);
            b.seal_block(ok_bb);
        }

        // Step 5: Configure schedule sets (`Slot 61`), best-effort (ignores `INVALID_STATE` when `world_ptr` null).
        let sset_slot = alloc_zero_slot(&mut b, structs::SCHEDULE_SET_DESC_SIZE, ptr_ty);
        let sset_ptr = b.ins().stack_addr(ptr_ty, sset_slot, 0);
        let max_set_edges = ctx
            .schedule_sets
            .iter()
            .map(|s| s.before_set_indices.len().max(s.after_set_indices.len()))
            .max()
            .unwrap_or(1)
            .max(1);
        let set_edge_slot =
            alloc_zero_slot(&mut b, max_set_edges * structs::BAM_SYSTEM_SET_SIZE, ptr_ty);
        let set_edge_ptr = b.ins().stack_addr(ptr_ty, set_edge_slot, 0);

        for (set_idx, sset) in ctx.schedule_sets.iter().enumerate() {
            let out_set = b
                .ins()
                .iadd_imm_s(state_addr, ctx.state_layout.set_slot_offset(set_idx) as i64);
            let inv_set = b
                .ins()
                .iconst(types::I32, i64::from(BAM_SYSTEM_SET_INVALID));
            b.ins().store(MemFlagsData::trusted(), inv_set, out_set, 0);

            zero_slot(&mut b, sset_slot, structs::SCHEDULE_SET_DESC_SIZE, ptr_ty);
            let sz = b
                .ins()
                .iconst(types::I32, structs::SCHEDULE_SET_DESC_SIZE as i64);
            let fl = b.ins().iconst(types::I32, i64::from(sset.flags));
            let sid = b.ins().iconst(types::I32, i64::from(sset.schedule_id));
            let ngv = ctx
                .obj_mod
                .declare_data_in_func(sset.qualified_name_cstr, b.func);
            let nptr = b.ins().symbol_value(ptr_ty, ngv);
            b.ins()
                .stack_store(ptr_ty, sz, sset_slot, structs::SSET_STRUCT_SIZE as i32);
            b.ins()
                .stack_store(ptr_ty, fl, sset_slot, structs::SSET_FLAGS as i32);
            b.ins()
                .stack_store(ptr_ty, sid, sset_slot, structs::SSET_SCHEDULE as i32);
            b.ins()
                .stack_store(ptr_ty, nptr, sset_slot, structs::SSET_NAME as i32);
            if !sset.after_set_indices.is_empty() {
                let mut valid_cnt = 0usize;
                for &after_idx in &sset.after_set_indices {
                    if after_idx < set_idx {
                        let ah = b.ins().load(
                            types::I32,
                            MemFlagsData::trusted(),
                            state_addr,
                            ctx.state_layout.set_slot_offset(after_idx) as i32,
                        );
                        b.ins().store(
                            MemFlagsData::trusted(),
                            ah,
                            set_edge_ptr,
                            (valid_cnt * structs::BAM_SYSTEM_SET_SIZE) as i32,
                        );
                        valid_cnt += 1;
                    }
                }
                if valid_cnt > 0 {
                    let acnt = b.ins().iconst(ptr_ty, valid_cnt as i64);
                    b.ins().stack_store(
                        ptr_ty,
                        set_edge_ptr,
                        sset_slot,
                        structs::SSET_AFTER_SETS as i32,
                    );
                    b.ins()
                        .stack_store(ptr_ty, acnt, sset_slot, structs::SSET_AFTER_COUNT as i32);
                }
            }
            let _ = max_set_edges;

            let _rc = call_vtable_opt(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::CONFIGURE_SCHEDULE_SET,
                &[ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[load_ctx, sset_ptr, out_set],
            );
        }

        // Step 6: Register Startup named-object initializer system (if `mir.objects` non-empty).
        let mut cur_sys_slot_idx = 0usize;
        if let Some((init_fid, init_name_id, ref obj_queries)) = ctx.init_objects_fn {
            let sys_out = b.ins().iadd_imm_s(
                state_addr,
                ctx.state_layout.sys_slot_offset(cur_sys_slot_idx) as i64,
            );
            cur_sys_slot_idx += 1;
            let qcount = obj_queries.len().min(SYSTEM_QUERY_CAP);
            let sdesc_slot = alloc_zero_slot(&mut b, structs::SYSTEM_DESC_SIZE, ptr_ty);
            let sdesc_ptr = b.ins().stack_addr(ptr_ty, sdesc_slot, 0);
            let qdescs_slot = alloc_zero_slot(
                &mut b,
                (qcount * structs::QUERY_DESC_SIZE).max(structs::QUERY_DESC_SIZE),
                ptr_ty,
            );
            let qdescs_ptr = b.ins().stack_addr(ptr_ty, qdescs_slot, 0);

            for (qi, &(_, lidx)) in obj_queries.iter().take(qcount).enumerate() {
                let term_slot = alloc_zero_slot(&mut b, structs::TERM_DESC_SIZE, ptr_ty);
                let term_ptr = b.ins().stack_addr(ptr_ty, term_slot, 0);
                let comp = b.ins().load(
                    types::I32,
                    MemFlagsData::trusted(),
                    state_addr,
                    ctx.state_layout.comp_slot_offset(lidx) as i32,
                );
                let mode = b
                    .ins()
                    .iconst(types::I32, i64::from(AccessMode::FILTER_ONLY.0));
                b.ins()
                    .stack_store(ptr_ty, comp, term_slot, structs::TERM_COMPONENT as i32);
                b.ins()
                    .stack_store(ptr_ty, mode, term_slot, structs::TERM_MODE as i32);
                let qb = (qi * structs::QUERY_DESC_SIZE) as i32;
                let qsz = b.ins().iconst(types::I32, structs::QUERY_DESC_SIZE as i64);
                let one = b.ins().iconst(ptr_ty, 1);
                b.ins().stack_store(
                    ptr_ty,
                    qsz,
                    qdescs_slot,
                    qb + structs::QUERY_STRUCT_SIZE as i32,
                );
                b.ins().stack_store(
                    ptr_ty,
                    term_ptr,
                    qdescs_slot,
                    qb + structs::QUERY_TERMS as i32,
                );
                b.ins().stack_store(
                    ptr_ty,
                    one,
                    qdescs_slot,
                    qb + structs::QUERY_TERM_COUNT as i32,
                );
            }
            let ssz = b.ins().iconst(types::I32, structs::SYSTEM_DESC_SIZE as i64);
            let ngv = ctx.obj_mod.declare_data_in_func(init_name_id, b.func);
            let nptr = b.ins().symbol_value(ptr_ty, ngv);
            let fref = ctx.obj_mod.declare_func_in_func(init_fid, b.func);
            let faddr = b.ins().func_addr(ptr_ty, fref);
            let sched_v = b.ins().iconst(types::I32, i64::from(ScheduleId::STARTUP.0));
            let qcv = b.ins().iconst(ptr_ty, qcount as i64);
            b.ins()
                .stack_store(ptr_ty, ssz, sdesc_slot, structs::SYS_STRUCT_SIZE as i32);
            b.ins()
                .stack_store(ptr_ty, nptr, sdesc_slot, structs::SYS_NAME as i32);
            b.ins()
                .stack_store(ptr_ty, qdescs_ptr, sdesc_slot, structs::SYS_QUERIES as i32);
            b.ins()
                .stack_store(ptr_ty, qcv, sdesc_slot, structs::SYS_QUERY_COUNT as i32);
            b.ins()
                .stack_store(ptr_ty, faddr, sdesc_slot, structs::SYS_CALLBACK as i32);
            b.ins().stack_store(
                ptr_ty,
                state_addr,
                sdesc_slot,
                structs::SYS_USER_DATA as i32,
            );
            b.ins()
                .stack_store(ptr_ty, sched_v, sdesc_slot, structs::SYS_SCHEDULE as i32);
            let mut startup_before_ids: Vec<DataId> = Vec::new();
            for s in &ctx.systems {
                if s.schedule_id == ScheduleId::STARTUP.0
                    && !startup_before_ids.contains(&s.name_data_id)
                {
                    startup_before_ids.push(s.name_data_id);
                }
            }
            if !startup_before_ids.is_empty() {
                populate_cstr_ptr_array(
                    &ctx.obj_mod,
                    &mut b,
                    &startup_before_ids,
                    sdesc_slot,
                    structs::SYS_BEFORE,
                    structs::SYS_BEFORE_COUNT,
                    ptr_ty,
                    ptr_bytes,
                );
            }

            let rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::REGISTER_SYSTEM_HANDLE,
                &[ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[load_ctx, sdesc_ptr, sys_out],
            );
            let is_err = b.ins().icmp_imm_s(IntCC::NotEqual, rc, 0);
            let ok_bb = b.create_block();
            b.ins()
                .brif(is_err, err_free_ret_blk, &[BlockArg::Value(rc)], ok_bb, &[]);
            b.switch_to_block(ok_bb);
            b.seal_block(ok_bb);
        }

        // Step 7: Register all module ECS systems via `REGISTER_SYSTEM_HANDLE` (`Slot 60`) and mount into
        // schedule sets (`MOUNT_SYSTEM_IN_SCHEDULE`, `Slot 62`).
        let sdesc_slot = alloc_zero_slot(&mut b, structs::SYSTEM_DESC_SIZE, ptr_ty);
        let sdesc_ptr = b.ins().stack_addr(ptr_ty, sdesc_slot, 0);
        let qdescs_slot =
            alloc_zero_slot(&mut b, structs::QUERY_DESC_SIZE * SYSTEM_QUERY_CAP, ptr_ty);
        let qdescs_ptr = b.ins().stack_addr(ptr_ty, qdescs_slot, 0);

        let mut mount_ops: Vec<(usize, usize, u32, Vec<usize>)> = Vec::new();
        // Register synthesized `strata_sys_net_rx_*` BEFORE user `FixedUpdate` systems when host transport is present.
        if !ctx.net_systems.is_empty() {
            let net_systems = ctx.net_systems.clone();
            for nsys in &net_systems {
                let sys_slot_idx = cur_sys_slot_idx;
                cur_sys_slot_idx += 1;
                emit_register_net_system(
                    ctx,
                    &mut b,
                    api_ptr,
                    load_ctx,
                    state_addr,
                    sys_slot_idx,
                    nsys,
                    true,
                    sdesc_slot,
                    sdesc_ptr,
                    qdescs_slot,
                    qdescs_ptr,
                    err_free_ret_blk,
                );
            }
        }
        for sys in &ctx.systems {
            let sys_slot_idx = cur_sys_slot_idx;
            let sys_out = b.ins().iadd_imm_s(
                state_addr,
                ctx.state_layout.sys_slot_offset(sys_slot_idx) as i64,
            );
            cur_sys_slot_idx += 1;

            zero_slot(&mut b, sdesc_slot, structs::SYSTEM_DESC_SIZE, ptr_ty);
            zero_slot(
                &mut b,
                qdescs_slot,
                structs::QUERY_DESC_SIZE * SYSTEM_QUERY_CAP,
                ptr_ty,
            );

            let ssz = b.ins().iconst(types::I32, structs::SYSTEM_DESC_SIZE as i64);
            let ngv = ctx.obj_mod.declare_data_in_func(sys.name_data_id, b.func);
            let nptr = b.ins().symbol_value(ptr_ty, ngv);
            let fref = ctx.obj_mod.declare_func_in_func(sys.func_id, b.func);
            let fn_addr = b.ins().func_addr(ptr_ty, fref);
            let sched_v = b.ins().iconst(types::I32, i64::from(sys.schedule_id));

            b.ins()
                .stack_store(ptr_ty, ssz, sdesc_slot, structs::SYS_STRUCT_SIZE as i32);
            b.ins()
                .stack_store(ptr_ty, nptr, sdesc_slot, structs::SYS_NAME as i32);
            b.ins()
                .stack_store(ptr_ty, fn_addr, sdesc_slot, structs::SYS_CALLBACK as i32);
            b.ins().stack_store(
                ptr_ty,
                state_addr,
                sdesc_slot,
                structs::SYS_USER_DATA as i32,
            );
            b.ins()
                .stack_store(ptr_ty, sched_v, sdesc_slot, structs::SYS_SCHEDULE as i32);

            let final_qc = emit_populate_fn_query_descs(ctx, &mut b, state_addr, qdescs_ptr, sys)?;
            let has_q = b.ins().icmp_imm_s(IntCC::SignedGreaterThan, final_qc, 0);
            let set_q_bb = b.create_block();
            let after_q_bb = b.create_block();
            b.ins().brif(has_q, set_q_bb, &[], after_q_bb, &[]);
            b.switch_to_block(set_q_bb);
            b.seal_block(set_q_bb);
            b.ins()
                .stack_store(ptr_ty, qdescs_ptr, sdesc_slot, structs::SYS_QUERIES as i32);
            b.ins().stack_store(
                ptr_ty,
                final_qc,
                sdesc_slot,
                structs::SYS_QUERY_COUNT as i32,
            );
            b.ins().jump(after_q_bb, &[]);
            b.switch_to_block(after_q_bb);
            b.seal_block(after_q_bb);

            // Ordering constraints (`after`, `after_weak`, `before`).
            populate_cstr_ptr_array(
                &ctx.obj_mod,
                &mut b,
                &sys.after_names,
                sdesc_slot,
                structs::SYS_AFTER,
                structs::SYS_AFTER_COUNT,
                ptr_ty,
                ptr_bytes,
            );
            populate_cstr_ptr_array(
                &ctx.obj_mod,
                &mut b,
                &sys.after_weak_names,
                sdesc_slot,
                structs::SYS_AFTER_WEAK,
                structs::SYS_AFTER_WEAK_COUNT,
                ptr_ty,
                ptr_bytes,
            );
            populate_cstr_ptr_array(
                &ctx.obj_mod,
                &mut b,
                &sys.before_names,
                sdesc_slot,
                structs::SYS_BEFORE,
                structs::SYS_BEFORE_COUNT,
                ptr_ty,
                ptr_bytes,
            );
            populate_cstr_ptr_array(
                &ctx.obj_mod,
                &mut b,
                &sys.in_set_names,
                sdesc_slot,
                structs::SYS_IN_SETS,
                structs::SYS_IN_SET_COUNT,
                ptr_ty,
                ptr_bytes,
            );

            let rc = call_vtable(
                &ctx.obj_mod,
                &mut b,
                api_ptr,
                api_slots::REGISTER_SYSTEM_HANDLE,
                &[ptr_ty, ptr_ty, ptr_ty],
                Some(types::I32),
                ptr_ty,
                call_conv,
                &[load_ctx, sdesc_ptr, sys_out],
            );
            let is_err = b.ins().icmp_imm_s(IntCC::NotEqual, rc, 0);
            let reg_ok_bb = b.create_block();
            b.ins().brif(
                is_err,
                err_free_ret_blk,
                &[BlockArg::Value(rc)],
                reg_ok_bb,
                &[],
            );

            b.switch_to_block(reg_ok_bb);
            b.seal_block(reg_ok_bb);

            if !sys.mount_set_indices.is_empty() {
                mount_ops.push((
                    sys.sched_order,
                    sys_slot_idx,
                    sys.schedule_id,
                    sys.mount_set_indices.clone(),
                ));
            }
        }

        mount_ops.sort_by_key(|&(ord, slot_idx, _, _)| (ord, slot_idx));
        for (_, sys_slot_idx, schedule_id, set_indices) in mount_ops {
            let sys_handle = b.ins().load(
                types::I32,
                MemFlagsData::trusted(),
                state_addr,
                ctx.state_layout.sys_slot_offset(sys_slot_idx) as i32,
            );
            let sched_v = b.ins().iconst(types::I32, i64::from(schedule_id));
            for set_idx in set_indices {
                let set_h = b.ins().load(
                    types::I32,
                    MemFlagsData::trusted(),
                    state_addr,
                    ctx.state_layout.set_slot_offset(set_idx) as i32,
                );
                let set_valid =
                    b.ins()
                        .icmp_imm_s(IntCC::NotEqual, set_h, i64::from(BAM_SYSTEM_SET_INVALID));
                let mount_bb = b.create_block();
                let next_m_bb = b.create_block();
                b.ins().brif(set_valid, mount_bb, &[], next_m_bb, &[]);

                b.switch_to_block(mount_bb);
                b.seal_block(mount_bb);
                let _mrc = call_vtable_opt(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::MOUNT_SYSTEM_IN_SCHEDULE,
                    &[ptr_ty, types::I32, types::I32, types::I32],
                    Some(types::I32),
                    ptr_ty,
                    call_conv,
                    &[load_ctx, sys_handle, sched_v, set_h],
                );
                b.ins().jump(next_m_bb, &[]);

                b.switch_to_block(next_m_bb);
                b.seal_block(next_m_bb);
            }
        }

        // Register synthesized `strata_sys_net_tx_*` AFTER user `FixedUpdate` systems when host transport is present.
        if !ctx.net_systems.is_empty() {
            let net_systems = ctx.net_systems.clone();
            for nsys in &net_systems {
                let sys_slot_idx = cur_sys_slot_idx;
                cur_sys_slot_idx += 1;
                emit_register_net_system(
                    ctx,
                    &mut b,
                    api_ptr,
                    load_ctx,
                    state_addr,
                    sys_slot_idx,
                    nsys,
                    false,
                    sdesc_slot,
                    sdesc_ptr,
                    qdescs_slot,
                    qdescs_ptr,
                    err_free_ret_blk,
                );
            }
        }

        let ok_res = b.ins().iconst(types::I32, i64::from(FFI_OK));
        b.ins().return_(&[ok_res]);

        b.switch_to_block(err_free_ret_blk);
        b.seal_block(err_free_ret_blk);
        let free_err_code = b.block_params(err_free_ret_blk)[0];
        let io_nz = b.ins().icmp_imm_s(IntCC::NotEqual, instance_out, 0);
        let clear_io_bb = b.create_block();
        let do_free_bb = b.create_block();
        b.ins().brif(io_nz, clear_io_bb, &[], do_free_bb, &[]);
        b.switch_to_block(clear_io_bb);
        b.seal_block(clear_io_bb);
        let null_p = b.ins().iconst(ptr_ty, 0);
        b.ins()
            .store(MemFlagsData::trusted(), null_p, instance_out, 0);
        b.ins().jump(do_free_bb, &[]);
        b.switch_to_block(do_free_bb);
        b.seal_block(do_free_bb);
        let fref = ctx.obj_mod.declare_func_in_func(free_fid, b.func);
        let rx_buf = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_addr,
            ctx.state_layout.net_rx_buf_off as i32,
        );
        let rx_nz = b.ins().icmp_imm_s(IntCC::NotEqual, rx_buf, 0);
        let free_rx_bb = b.create_block();
        let free_state_bb = b.create_block();
        b.ins().brif(rx_nz, free_rx_bb, &[], free_state_bb, &[]);
        b.switch_to_block(free_rx_bb);
        b.seal_block(free_rx_bb);
        b.ins().call(fref, &[rx_buf]);
        b.ins().jump(free_state_bb, &[]);
        b.switch_to_block(free_state_bb);
        b.seal_block(free_state_bb);
        b.ins().call(fref, &[state_addr]);
        b.ins().return_(&[free_err_code]);

        b.switch_to_block(err_ret_blk);
        b.seal_block(err_ret_blk);
        let err_code = b.block_params(err_ret_blk)[0];
        b.ins().return_(&[err_code]);

        b.finalize(ctx.fe_cfg);
    }

    define_fn_checked(
        &mut ctx.obj_mod,
        fid,
        &mut fn_ctx,
        "bamabi_init define failed",
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_populate_fn_query_descs(
    ctx: &ModuleContext<'_>,
    b: &mut FunctionBuilder<'_>,
    state_addr: Value,
    qdescs_ptr: Value,
    sys: &SystemRegistrationEntry,
) -> Result<Value, JitError> {
    let ptr_ty = ctx.ptr_ty;
    let q_idx_var = b.declare_var(ptr_ty);
    let z_ptr = b.ins().iconst(ptr_ty, 0);
    b.def_var(q_idx_var, z_ptr);

    for (qi, wq) in sys.wire_queries.iter().take(SYSTEM_QUERY_CAP).enumerate() {
        let mut term_items: Vec<(usize, u32, u16)> = Vec::new();
        for t in &wq.terms {
            let mode_u = if t.changed && t.mode == TermAccessMode::Read {
                ACCESS_MODE_CHANGED
            } else {
                access_mode_u32(t.mode)
            };
            let flags_u = if t.added { BAM_TERM_FLAG_ADDED } else { 0 };
            term_items.push((t.layout_idx, mode_u, flags_u));
        }
        for &wf in &wq.with_filters {
            term_items.push((wf, AccessMode::FILTER_ONLY.0, 0));
        }
        for &wof in &wq.without_filters {
            term_items.push((wof, AccessMode::WITHOUT.0, 0));
        }
        for &cf in &wq.extra_changed_filters {
            term_items.push((cf, ACCESS_MODE_CHANGED, 0));
        }
        for &af in &wq.extra_added_filters {
            if let Some(existing) = term_items.iter_mut().find(|(li, _, _)| *li == af) {
                existing.2 |= BAM_TERM_FLAG_ADDED;
            } else {
                term_items.push((af, AccessMode::FILTER_ONLY.0, BAM_TERM_FLAG_ADDED));
            }
        }
        if term_items.len() > QUERY_TERM_CAP {
            return Err(JitError::Codegen(format!(
                "query {qi} in system `{}` has {} terms, exceeding QUERY_TERM_CAP ({QUERY_TERM_CAP})",
                ctx.mir.functions[sys.fn_idx].name,
                term_items.len()
            )));
        }
        if !term_items.is_empty() {
            emit_fill_query_slot(
                b,
                state_addr,
                &ctx.state_layout,
                qdescs_ptr,
                qi,
                &term_items,
                wq.param_set_group,
                ptr_ty,
            );
            let nxt = b.ins().iconst(ptr_ty, (qi + 1) as i64);
            b.def_var(q_idx_var, nxt);
        }
    }

    for eq in &sys.extra_obj_queries {
        if let Some(obj) = ctx.mir.objects.get(eq.obj_idx)
            && let Some(cname) = obj.components.first().map(String::as_str).or_else(|| {
                obj.inits.first().map(|ci| {
                    ci.canonical_component
                        .as_deref()
                        .unwrap_or(ci.component.as_str())
                })
            })
            && let Some(lidx) = lookup_name_in_map(&ctx.layout_map, cname)
        {
            let cur_q = b.use_var(q_idx_var);
            let cap_ok =
                b.ins()
                    .icmp_imm_s(IntCC::UnsignedLessThan, cur_q, SYSTEM_QUERY_CAP as i64);
            let w_bb = b.create_block();
            let n_bb = b.create_block();
            b.ins().brif(cap_ok, w_bb, &[], n_bb, &[]);
            b.switch_to_block(w_bb);
            b.seal_block(w_bb);
            emit_fill_dynamic_query_slot(
                b,
                state_addr,
                &ctx.state_layout,
                qdescs_ptr,
                cur_q,
                lidx,
                AccessMode::FILTER_ONLY.0,
                ptr_ty,
            );
            let nxt = b.ins().iadd_imm_s(cur_q, 1);
            b.def_var(q_idx_var, nxt);
            b.ins().jump(n_bb, &[]);
            b.switch_to_block(n_bb);
            b.seal_block(n_bb);
        }
    }

    for sq in &sys.stream_queries {
        let sflag = b.ins().load(
            types::I8,
            MemFlagsData::trusted(),
            state_addr,
            ctx.state_layout.res_flag_offset(sq.stream_layout_idx) as i32,
        );
        let is_msg = b.ins().icmp_imm_s(IntCC::Equal, sflag, 2);
        let add_bb = b.create_block();
        let next_bb = b.create_block();
        b.ins().brif(is_msg, add_bb, &[], next_bb, &[]);
        b.switch_to_block(add_bb);
        b.seal_block(add_bb);
        let cur_q = b.use_var(q_idx_var);
        let cap_ok = b
            .ins()
            .icmp_imm_s(IntCC::UnsignedLessThan, cur_q, SYSTEM_QUERY_CAP as i64);
        let w_bb = b.create_block();
        b.ins().brif(cap_ok, w_bb, &[], next_bb, &[]);
        b.switch_to_block(w_bb);
        b.seal_block(w_bb);
        emit_fill_dynamic_query_slot(
            b,
            state_addr,
            &ctx.state_layout,
            qdescs_ptr,
            cur_q,
            sq.stream_layout_idx,
            if sq.is_write {
                AccessMode::MESSAGE_WRITE.0
            } else {
                AccessMode::MESSAGE_READ.0
            },
            ptr_ty,
        );
        let nxt = b.ins().iadd_imm_s(cur_q, 1);
        b.def_var(q_idx_var, nxt);
        b.ins().jump(next_bb, &[]);
        b.switch_to_block(next_bb);
        b.seal_block(next_bb);
    }

    for &(lidx, mutable, _) in &sys.resource_queries {
        let rflag = b.ins().load(
            types::I8,
            MemFlagsData::trusted(),
            state_addr,
            ctx.state_layout.res_flag_offset(lidx) as i32,
        );
        let is_host = b.ins().icmp_imm_s(IntCC::Equal, rflag, 1);
        let add_bb = b.create_block();
        let next_bb = b.create_block();
        b.ins().brif(is_host, add_bb, &[], next_bb, &[]);

        b.switch_to_block(add_bb);
        b.seal_block(add_bb);
        let cur_q = b.use_var(q_idx_var);
        let cap_ok = b
            .ins()
            .icmp_imm_s(IntCC::UnsignedLessThan, cur_q, SYSTEM_QUERY_CAP as i64);
        let write_bb = b.create_block();
        b.ins().brif(cap_ok, write_bb, &[], next_bb, &[]);

        b.switch_to_block(write_bb);
        b.seal_block(write_bb);
        let mode_u = if mutable {
            AccessMode::RESOURCE_WRITE.0
        } else {
            AccessMode::RESOURCE_READ.0
        };
        emit_fill_dynamic_query_slot(
            b,
            state_addr,
            &ctx.state_layout,
            qdescs_ptr,
            cur_q,
            lidx,
            mode_u,
            ptr_ty,
        );
        let nxt = b.ins().iadd_imm_s(cur_q, 1);
        b.def_var(q_idx_var, nxt);
        b.ins().jump(next_bb, &[]);

        b.switch_to_block(next_bb);
        b.seal_block(next_bb);
    }

    Ok(b.use_var(q_idx_var))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_register_net_system(
    ctx: &mut ModuleContext<'_>,
    b: &mut FunctionBuilder<'_>,
    api_ptr: Value,
    load_ctx: Value,
    state_addr: Value,
    sys_slot_idx: usize,
    nsys: &NetSystemChunkEntry,
    is_rx: bool,
    sdesc_slot: StackSlot,
    sdesc_ptr: Value,
    qdescs_slot: StackSlot,
    qdescs_ptr: Value,
    err_free_ret_blk: Block,
) {
    let ptr_ty = ctx.ptr_ty;
    let ptr_bytes = ctx.ptr_bytes;
    let call_conv = ctx.call_conv;

    let is_msg = b.ins().load(
        types::I8,
        MemFlagsData::trusted(),
        state_addr,
        ctx.state_layout.net_pkt_is_msg_off as i32,
    );
    let msg_active = b.ins().icmp_imm_s(IntCC::NotEqual, is_msg, 0);
    let reg_bb = b.create_block();
    let skip_bb = b.create_block();
    b.ins().brif(msg_active, reg_bb, &[], skip_bb, &[]);

    b.switch_to_block(reg_bb);
    b.seal_block(reg_bb);

    let sys_out = b.ins().iadd_imm_s(
        state_addr,
        ctx.state_layout.sys_slot_offset(sys_slot_idx) as i64,
    );
    zero_slot(b, sdesc_slot, structs::SYSTEM_DESC_SIZE, ptr_ty);
    zero_slot(
        b,
        qdescs_slot,
        structs::QUERY_DESC_SIZE * SYSTEM_QUERY_CAP,
        ptr_ty,
    );

    // Query 0: `StrataNetPacket` (`MESSAGE_READ` / `MESSAGE_WRITE`) + optional host replicated resources.
    let q0_cap = (1 + nsys.res_layout_indices.len()).min(QUERY_TERM_CAP);
    let q0_terms_slot = alloc_zero_slot(b, q0_cap * structs::TERM_DESC_SIZE, ptr_ty);
    let q0_terms_ptr = b.ins().stack_addr(ptr_ty, q0_terms_slot, 0);
    let pkt_comp = b.ins().load(
        types::I32,
        MemFlagsData::trusted(),
        state_addr,
        ctx.state_layout.net_pkt_comp_off as i32,
    );
    let msg_mode = b.ins().iconst(
        types::I32,
        i64::from(if is_rx {
            AccessMode::MESSAGE_READ.0
        } else {
            AccessMode::MESSAGE_WRITE.0
        }),
    );
    b.ins().stack_store(
        ptr_ty,
        pkt_comp,
        q0_terms_slot,
        structs::TERM_COMPONENT as i32,
    );
    b.ins()
        .stack_store(ptr_ty, msg_mode, q0_terms_slot, structs::TERM_MODE as i32);

    let q0_cnt_var = b.declare_var(ptr_ty);
    let one_p = b.ins().iconst(ptr_ty, 1);
    b.def_var(q0_cnt_var, one_p);

    let res_mode_v = b.ins().iconst(
        types::I32,
        i64::from(if is_rx {
            AccessMode::RESOURCE_WRITE.0
        } else {
            AccessMode::RESOURCE_READ.0
        }),
    );
    for &r_lidx in nsys
        .res_layout_indices
        .iter()
        .take(QUERY_TERM_CAP.saturating_sub(1))
    {
        let rflag = b.ins().load(
            types::I8,
            MemFlagsData::trusted(),
            state_addr,
            ctx.state_layout.res_flag_offset(r_lidx) as i32,
        );
        let is_host = b.ins().icmp_imm_s(IntCC::Equal, rflag, 1);
        let add_r_bb = b.create_block();
        let next_r_bb = b.create_block();
        b.ins().brif(is_host, add_r_bb, &[], next_r_bb, &[]);

        b.switch_to_block(add_r_bb);
        b.seal_block(add_r_bb);
        let cur_cnt = b.use_var(q0_cnt_var);
        let t_off = b.ins().imul_imm_s(cur_cnt, structs::TERM_DESC_SIZE as i64);
        let t_addr = b.ins().iadd(q0_terms_ptr, t_off);
        let r_comp = b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            state_addr,
            ctx.state_layout.comp_slot_offset(r_lidx) as i32,
        );
        b.ins().store(
            MemFlagsData::trusted(),
            r_comp,
            t_addr,
            structs::TERM_COMPONENT as i32,
        );
        b.ins().store(
            MemFlagsData::trusted(),
            res_mode_v,
            t_addr,
            structs::TERM_MODE as i32,
        );
        let nxt_cnt = b.ins().iadd_imm_s(cur_cnt, 1);
        b.def_var(q0_cnt_var, nxt_cnt);
        b.ins().jump(next_r_bb, &[]);

        b.switch_to_block(next_r_bb);
        b.seal_block(next_r_bb);
    }

    let qsz = b.ins().iconst(types::I32, structs::QUERY_DESC_SIZE as i64);
    let q0_cnt = b.use_var(q0_cnt_var);
    b.ins()
        .stack_store(ptr_ty, qsz, qdescs_slot, structs::QUERY_STRUCT_SIZE as i32);
    b.ins().stack_store(
        ptr_ty,
        q0_terms_ptr,
        qdescs_slot,
        structs::QUERY_TERMS as i32,
    );
    b.ins().stack_store(
        ptr_ty,
        q0_cnt,
        qdescs_slot,
        structs::QUERY_TERM_COUNT as i32,
    );

    // Queries `1..`: replicated ECS components (`WRITE` on RX, `CHANGED` on TX).
    let comp_mode_u = if is_rx {
        AccessMode::WRITE.0
    } else {
        ACCESS_MODE_CHANGED
    };
    let mut q_total = 1usize;
    for strata in nsys
        .comp_stratum_groups
        .iter()
        .take(SYSTEM_QUERY_CAP.saturating_sub(1))
    {
        if strata.len() <= 1 {
            if let Some(&c_lidx) = strata.first() {
                emit_fill_query_slot(
                    b,
                    state_addr,
                    &ctx.state_layout,
                    qdescs_ptr,
                    q_total,
                    &[(c_lidx, comp_mode_u, 0)],
                    0,
                    ptr_ty,
                );
                q_total += 1;
            }
        } else {
            let mut terms: Vec<(usize, u32, u16)> = Vec::with_capacity(strata.len());
            for (si, &s_lidx) in strata.iter().take(QUERY_TERM_CAP).enumerate() {
                let mode = if is_rx {
                    if si == 0 {
                        AccessMode::WRITE.0
                    } else {
                        AccessMode::OPTIONAL_WRITE.0
                    }
                } else if si == 0 {
                    AccessMode::READ.0
                } else {
                    AccessMode::OPTIONAL_READ.0
                };
                terms.push((s_lidx, mode, 0));
            }
            emit_fill_query_slot(
                b,
                state_addr,
                &ctx.state_layout,
                qdescs_ptr,
                q_total,
                &terms,
                0,
                ptr_ty,
            );
            q_total += 1;
        }
    }

    let ssz = b.ins().iconst(types::I32, structs::SYSTEM_DESC_SIZE as i64);
    let name_id = if is_rx {
        nsys.rx_name_data_id
    } else {
        nsys.tx_name_data_id
    };
    let cb_fid = if is_rx {
        nsys.rx_func_id
    } else {
        nsys.tx_func_id
    };
    let ngv = ctx.obj_mod.declare_data_in_func(name_id, b.func);
    let nptr = b.ins().symbol_value(ptr_ty, ngv);
    let fref = ctx.obj_mod.declare_func_in_func(cb_fid, b.func);
    let fn_addr = b.ins().func_addr(ptr_ty, fref);
    let sched_v = b
        .ins()
        .iconst(types::I32, i64::from(ScheduleId::FIXED_UPDATE.0));
    let qc_v = b.ins().iconst(ptr_ty, q_total as i64);

    b.ins()
        .stack_store(ptr_ty, ssz, sdesc_slot, structs::SYS_STRUCT_SIZE as i32);
    b.ins()
        .stack_store(ptr_ty, nptr, sdesc_slot, structs::SYS_NAME as i32);
    b.ins()
        .stack_store(ptr_ty, qdescs_ptr, sdesc_slot, structs::SYS_QUERIES as i32);
    b.ins()
        .stack_store(ptr_ty, qc_v, sdesc_slot, structs::SYS_QUERY_COUNT as i32);
    b.ins()
        .stack_store(ptr_ty, fn_addr, sdesc_slot, structs::SYS_CALLBACK as i32);
    b.ins().stack_store(
        ptr_ty,
        state_addr,
        sdesc_slot,
        structs::SYS_USER_DATA as i32,
    );
    b.ins()
        .stack_store(ptr_ty, sched_v, sdesc_slot, structs::SYS_SCHEDULE as i32);

    if !is_rx && !nsys.tx_after_weak_names.is_empty() {
        populate_cstr_ptr_array(
            &ctx.obj_mod,
            b,
            &nsys.tx_after_weak_names,
            sdesc_slot,
            structs::SYS_AFTER_WEAK,
            structs::SYS_AFTER_WEAK_COUNT,
            ptr_ty,
            ptr_bytes,
        );
    }

    let rc = call_vtable(
        &ctx.obj_mod,
        b,
        api_ptr,
        api_slots::REGISTER_SYSTEM_HANDLE,
        &[ptr_ty, ptr_ty, ptr_ty],
        Some(types::I32),
        ptr_ty,
        call_conv,
        &[load_ctx, sdesc_ptr, sys_out],
    );
    let is_err = b.ins().icmp_imm_s(IntCC::NotEqual, rc, 0);
    b.ins().brif(
        is_err,
        err_free_ret_blk,
        &[BlockArg::Value(rc)],
        skip_bb,
        &[],
    );

    b.switch_to_block(skip_bb);
    b.seal_block(skip_bb);
}

#[inline]
pub(super) fn state_ptr_alias(v: Value) -> Value {
    v
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_fill_query_slot(
    b: &mut FunctionBuilder<'_>,
    state_addr: Value,
    state_layout: &StateLayout,
    qdescs_ptr: Value,
    q_idx: usize,
    terms: &[(usize, u32, u16)],
    param_set_group: u32,
    ptr_ty: Type,
) {
    let terms_slot = alloc_zero_slot(b, terms.len() * structs::TERM_DESC_SIZE, ptr_ty);
    let terms_ptr = b.ins().stack_addr(ptr_ty, terms_slot, 0);
    for (ti, &(lidx, mode_u, flags_u)) in terms.iter().enumerate() {
        let base = (ti * structs::TERM_DESC_SIZE) as i32;
        let comp_h = b.ins().load(
            types::I32,
            MemFlagsData::trusted(),
            state_addr,
            state_layout.comp_slot_offset(lidx) as i32,
        );
        let mv = b.ins().iconst(types::I32, i64::from(mode_u));
        b.ins().stack_store(
            ptr_ty,
            comp_h,
            terms_slot,
            base + structs::TERM_COMPONENT as i32,
        );
        b.ins()
            .stack_store(ptr_ty, mv, terms_slot, base + structs::TERM_MODE as i32);
        if flags_u != 0 {
            let fv = b.ins().iconst(types::I16, i64::from(flags_u));
            b.ins()
                .stack_store(ptr_ty, fv, terms_slot, base + structs::TERM_FLAGS as i32);
        }
    }
    let q_off = (q_idx * structs::QUERY_DESC_SIZE) as i32;
    let qsz = b.ins().iconst(types::I32, structs::QUERY_DESC_SIZE as i64);
    let tc = b.ins().iconst(ptr_ty, terms.len() as i64);
    b.ins().store(
        MemFlagsData::trusted(),
        qsz,
        qdescs_ptr,
        q_off + structs::QUERY_STRUCT_SIZE as i32,
    );
    if param_set_group != 0 {
        let qflags = b.ins().iconst(types::I32, i64::from(QUERY_FLAG_PARAM_SET));
        let pset_g = b.ins().iconst(types::I32, i64::from(param_set_group));
        b.ins().store(
            MemFlagsData::trusted(),
            qflags,
            qdescs_ptr,
            q_off + structs::QUERY_FLAGS as i32,
        );
        b.ins().store(
            MemFlagsData::trusted(),
            pset_g,
            qdescs_ptr,
            q_off + structs::QUERY_PARAM_SET_GROUP as i32,
        );
    }
    b.ins().store(
        MemFlagsData::trusted(),
        terms_ptr,
        qdescs_ptr,
        q_off + structs::QUERY_TERMS as i32,
    );
    b.ins().store(
        MemFlagsData::trusted(),
        tc,
        qdescs_ptr,
        q_off + structs::QUERY_TERM_COUNT as i32,
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_fill_dynamic_query_slot(
    b: &mut FunctionBuilder<'_>,
    state_addr: Value,
    state_layout: &StateLayout,
    qdescs_ptr: Value,
    q_idx_val: Value,
    lidx: usize,
    mode_u: u32,
    ptr_ty: Type,
) {
    let term_slot = alloc_zero_slot(b, structs::TERM_DESC_SIZE, ptr_ty);
    let term_ptr = b.ins().stack_addr(ptr_ty, term_slot, 0);
    let comp_h = b.ins().load(
        types::I32,
        MemFlagsData::trusted(),
        state_addr,
        state_layout.comp_slot_offset(lidx) as i32,
    );
    let mv = b.ins().iconst(types::I32, i64::from(mode_u));
    b.ins()
        .stack_store(ptr_ty, comp_h, term_slot, structs::TERM_COMPONENT as i32);
    b.ins()
        .stack_store(ptr_ty, mv, term_slot, structs::TERM_MODE as i32);

    let q_off = b
        .ins()
        .imul_imm_s(q_idx_val, structs::QUERY_DESC_SIZE as i64);
    let q_addr = b.ins().iadd(qdescs_ptr, q_off);
    let qsz = b.ins().iconst(types::I32, structs::QUERY_DESC_SIZE as i64);
    let one = b.ins().iconst(ptr_ty, 1);
    b.ins().store(
        MemFlagsData::trusted(),
        qsz,
        q_addr,
        structs::QUERY_STRUCT_SIZE as i32,
    );
    b.ins().store(
        MemFlagsData::trusted(),
        term_ptr,
        q_addr,
        structs::QUERY_TERMS as i32,
    );
    b.ins().store(
        MemFlagsData::trusted(),
        one,
        q_addr,
        structs::QUERY_TERM_COUNT as i32,
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) fn populate_cstr_ptr_array(
    obj_mod: &ObjectModule,
    b: &mut FunctionBuilder<'_>,
    ids: &[DataId],
    sdesc_slot: StackSlot,
    ptr_off: usize,
    cnt_off: usize,
    ptr_ty: Type,
    ptr_bytes: usize,
) {
    if ids.is_empty() {
        return;
    }
    let arr_slot = alloc_zero_slot(b, ids.len() * ptr_bytes, ptr_ty);
    let arr_ptr = b.ins().stack_addr(ptr_ty, arr_slot, 0);
    for (i, &id) in ids.iter().enumerate() {
        let gv = obj_mod.declare_data_in_func(id, b.func);
        let cstr = b.ins().symbol_value(ptr_ty, gv);
        b.ins()
            .stack_store(ptr_ty, cstr, arr_slot, (i * ptr_bytes) as i32);
    }
    let cnt_v = b.ins().iconst(ptr_ty, ids.len() as i64);
    b.ins()
        .stack_store(ptr_ty, arr_ptr, sdesc_slot, ptr_off as i32);
    b.ins()
        .stack_store(ptr_ty, cnt_v, sdesc_slot, cnt_off as i32);
}
