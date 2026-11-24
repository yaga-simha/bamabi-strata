//! Networking quantization/bitpack primitives, schema codecs, and TX/RX systems.

use super::*;

pub(super) struct NetPrimitives {
    round_fn: FuncId,
    quantize_fn: FuncId,
    dequantize_fn: FuncId,
    pack_bits_fn: FuncId,
    unpack_bits_fn: FuncId,
    verify_handshake_fn: FuncId,
}

pub(super) fn emit_all_net_systems(ctx: &mut ModuleContext<'_>) -> Result<(), JitError> {
    if ctx.net_systems.is_empty() {
        return Ok(());
    }
    let prims = emit_net_primitives(ctx)?;
    let mod_fp = ctx.mir.net_handshake.module_net_fingerprint;

    let mut codecs: HashMap<String, (FuncId, FuncId)> = HashMap::new();
    let chunks_cloned = ctx.net_chunks.clone();
    for (chunk_idx, chunk) in chunks_cloned.iter().enumerate() {
        for (nc_idx, nc) in chunk.iter().enumerate() {
            if codecs.contains_key(&nc.canonical_name) {
                continue;
            }
            let Some(lidx) = lookup_name_in_map(&ctx.layout_map, &nc.canonical_name) else {
                return Err(JitError::Codegen(format!(
                    "net component `{}` missing solved layout in JIT module",
                    nc.canonical_name
                )));
            };
            let enc_fid =
                emit_net_component_encoder(ctx, &prims, nc, lidx, mod_fp, chunk_idx, nc_idx)?;
            let dec_fid =
                emit_net_component_decoder(ctx, &prims, nc, lidx, mod_fp, chunk_idx, nc_idx)?;
            codecs.insert(nc.canonical_name.clone(), (enc_fid, dec_fid));
        }
    }

    let net_systems = ctx.net_systems.clone();
    for (chunk_idx, (entry, chunk)) in net_systems.iter().zip(chunks_cloned.iter()).enumerate() {
        emit_net_rx_system(ctx, entry, chunk, &codecs, chunk_idx)?;
        emit_net_tx_system(ctx, entry, chunk, &codecs, chunk_idx)?;
    }

    Ok(())
}

pub(super) fn emit_net_primitives(ctx: &mut ModuleContext<'_>) -> Result<NetPrimitives, JitError> {
    let ptr_ty = ctx.ptr_ty;
    let cc = ctx.call_conv;
    let round_fid = ctx.round_fn;

    // 1. `strata_net_quantize_scalar_f64(val: f64, min_v: f64, max_v: f64, bits: i32, step_v: f64, has_step: i8) -> i64`
    let quantize_fn = {
        let mut sig = Signature::new(cc);
        sig.params.push(AbiParam::new(types::F64));
        sig.params.push(AbiParam::new(types::F64));
        sig.params.push(AbiParam::new(types::F64));
        sig.params.push(AbiParam::new(types::I32));
        sig.params.push(AbiParam::new(types::F64));
        sig.params.push(AbiParam::new(types::I8));
        sig.returns.push(AbiParam::new(types::I64));
        let fid = ctx
            .obj_mod
            .declare_function("strata_net_quantize_scalar_f64", Linkage::Local, &sig)
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

            let ps = b.block_params(entry).to_vec();
            let (val, min_v, max_v, bits, step_v, has_step) =
                (ps[0], ps[1], ps[2], ps[3], ps[4], ps[5]);

            let zero64 = b.ins().iconst(types::I64, 0);
            let inf = b.ins().f64const(f64::INFINITY);
            let zf = b.ins().f64const(0.0);

            let bits_nz = b.ins().icmp_imm_s(IntCC::NotEqual, bits, 0);
            let min_abs = b.ins().fabs(min_v);
            let max_abs = b.ins().fabs(max_v);
            let min_fin = b.ins().fcmp(FloatCC::LessThan, min_abs, inf);
            let max_fin = b.ins().fcmp(FloatCC::LessThan, max_abs, inf);
            let range_ok = b.ins().fcmp(FloatCC::LessThan, min_v, max_v);
            let ok0 = b.ins().band(bits_nz, min_fin);
            let ok1 = b.ins().band(max_fin, range_ok);
            let pre_ok = b.ins().band(ok0, ok1);

            let ret_zero_bb = b.create_block();
            let calc_bb = b.create_block();
            b.ins().brif(pre_ok, calc_bb, &[], ret_zero_bb, &[]);

            b.switch_to_block(ret_zero_bb);
            b.ins().return_(&[zero64]);

            b.switch_to_block(calc_bb);
            b.seal_block(calc_bb);
            let c32 = b.ins().iconst(types::I32, 32);
            let gt32 = b.ins().icmp_imm_s(IntCC::UnsignedGreaterThan, bits, 32);
            let eff_bits = b.ins().select(gt32, c32, bits);
            let is_32 = b.ins().icmp_imm_s(IntCC::Equal, eff_bits, 32);
            let one64 = b.ins().iconst(types::I64, 1);
            let shifted = b.ins().ishl(one64, eff_bits);
            let sub1 = b.ins().iadd_imm_s(shifted, -1);
            let mask32 = b.ins().iconst(types::I64, 0xFFFF_FFFFi64);
            let max_q = b.ins().select(is_32, mask32, sub1);

            let max_q_nz = b.ins().icmp_imm_s(IntCC::NotEqual, max_q, 0);
            let denom_i = b.ins().select(max_q_nz, max_q, one64);
            let denom_f = b.ins().fcvt_from_uint(types::F64, denom_i);
            let max_step = b.ins().fdiv(max_v, denom_f);
            let min_step = b.ins().fdiv(min_v, denom_f);
            let def_step = b.ins().fsub(max_step, min_step);

            let hs_nz = b.ins().icmp_imm_s(IntCC::NotEqual, has_step, 0);
            let step_abs = b.ins().fabs(step_v);
            let step_fin = b.ins().fcmp(FloatCC::LessThan, step_abs, inf);
            let step_pos = b.ins().fcmp(FloatCC::GreaterThan, step_v, zf);
            let step_valid = b.ins().band(step_fin, step_pos);
            let use_custom = b.ins().band(hs_nz, step_valid);
            let eff_step = b.ins().select(use_custom, step_v, def_step);

            let eff_abs = b.ins().fabs(eff_step);
            let eff_fin = b.ins().fcmp(FloatCC::LessThan, eff_abs, inf);
            let eff_pos = b.ins().fcmp(FloatCC::GreaterThan, eff_step, zf);
            let eff_ok = b.ins().band(eff_fin, eff_pos);
            let quant_bb = b.create_block();
            b.ins().brif(eff_ok, quant_bb, &[], ret_zero_bb, &[]);

            b.switch_to_block(quant_bb);
            b.seal_block(quant_bb);
            let is_nan = b.ins().fcmp(FloatCC::Unordered, val, val);
            let lt_min = b.ins().fcmp(FloatCC::LessThan, val, min_v);
            let gt_max = b.ins().fcmp(FloatCC::GreaterThan, val, max_v);
            let c1 = b.ins().select(lt_min, min_v, val);
            let c2 = b.ins().select(gt_max, max_v, c1);
            let clamped = b.ins().select(is_nan, min_v, c2);

            let diff = b.ins().fsub(clamped, min_v);
            let diff_abs = b.ins().fabs(diff);
            let diff_fin = b.ins().fcmp(FloatCC::LessThan, diff_abs, inf);
            let direct_scaled = b.ins().fdiv(diff, eff_step);
            let c_over = b.ins().fdiv(clamped, eff_step);
            let m_over = b.ins().fdiv(min_v, eff_step);
            let safe_scaled = b.ins().fsub(c_over, m_over);
            let scaled = b.ins().select(diff_fin, direct_scaled, safe_scaled);
            let rref = ctx.obj_mod.declare_func_in_func(round_fid, b.func);
            let rcall = b.ins().call(rref, &[scaled]);
            let rounded = b.func.dfg.inst_results(rcall)[0];

            let max_q_f = b.ins().fcvt_from_uint(types::F64, max_q);
            let r_le_zero = b.ins().fcmp(FloatCC::LessThanOrEqual, rounded, zf);
            let r_nan = b.ins().fcmp(FloatCC::Unordered, rounded, rounded);
            let r_ge_max = b.ins().fcmp(FloatCC::GreaterThanOrEqual, rounded, max_q_f);
            let q_raw = b.ins().fcvt_to_uint_sat(types::I64, rounded);
            let q_gt = b.ins().icmp(IntCC::UnsignedGreaterThan, q_raw, max_q);
            let q_cap = b.ins().select(q_gt, max_q, q_raw);
            let q1 = b.ins().select(r_ge_max, max_q, q_cap);
            let q_zero_or_nan = b.ins().bor(r_le_zero, r_nan);
            let q_final = b.ins().select(q_zero_or_nan, zero64, q1);
            b.ins().return_(&[q_final]);

            b.seal_all_blocks();
            b.finalize(ctx.fe_cfg);
        }
        define_fn_checked(
            &mut ctx.obj_mod,
            fid,
            &mut fn_ctx,
            "strata_net_quantize_scalar_f64",
        )?;
        fid
    };

    // 2. `strata_net_dequantize_scalar_f64(raw: i64, min_v: f64, max_v: f64, bits: i32, step_v: f64, has_step: i8) -> f64`
    let dequantize_fn = {
        let mut sig = Signature::new(cc);
        sig.params.push(AbiParam::new(types::I64));
        sig.params.push(AbiParam::new(types::F64));
        sig.params.push(AbiParam::new(types::F64));
        sig.params.push(AbiParam::new(types::I32));
        sig.params.push(AbiParam::new(types::F64));
        sig.params.push(AbiParam::new(types::I8));
        sig.returns.push(AbiParam::new(types::F64));
        let fid = ctx
            .obj_mod
            .declare_function("strata_net_dequantize_scalar_f64", Linkage::Local, &sig)
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

            let ps = b.block_params(entry).to_vec();
            let (raw, min_v, max_v, bits, step_v, has_step) =
                (ps[0], ps[1], ps[2], ps[3], ps[4], ps[5]);

            let inf = b.ins().f64const(f64::INFINITY);
            let zf = b.ins().f64const(0.0);

            let bits_nz = b.ins().icmp_imm_s(IntCC::NotEqual, bits, 0);
            let min_abs = b.ins().fabs(min_v);
            let max_abs = b.ins().fabs(max_v);
            let min_fin = b.ins().fcmp(FloatCC::LessThan, min_abs, inf);
            let max_fin = b.ins().fcmp(FloatCC::LessThan, max_abs, inf);
            let range_ok = b.ins().fcmp(FloatCC::LessThan, min_v, max_v);
            let p0 = b.ins().band(bits_nz, min_fin);
            let p1 = b.ins().band(max_fin, range_ok);
            let pre_ok = b.ins().band(p0, p1);

            let ret_min_bb = b.create_block();
            let calc_bb = b.create_block();
            b.ins().brif(pre_ok, calc_bb, &[], ret_min_bb, &[]);

            b.switch_to_block(ret_min_bb);
            b.ins().return_(&[min_v]);

            b.switch_to_block(calc_bb);
            b.seal_block(calc_bb);
            let c32 = b.ins().iconst(types::I32, 32);
            let gt32 = b.ins().icmp_imm_s(IntCC::UnsignedGreaterThan, bits, 32);
            let eff_bits = b.ins().select(gt32, c32, bits);
            let is_32 = b.ins().icmp_imm_s(IntCC::Equal, eff_bits, 32);
            let one64 = b.ins().iconst(types::I64, 1);
            let shifted = b.ins().ishl(one64, eff_bits);
            let sub1 = b.ins().iadd_imm_s(shifted, -1);
            let mask32 = b.ins().iconst(types::I64, 0xFFFF_FFFFi64);
            let max_q = b.ins().select(is_32, mask32, sub1);
            let q = b.ins().band(raw, max_q);

            let max_q_nz = b.ins().icmp_imm_s(IntCC::NotEqual, max_q, 0);
            let denom_i = b.ins().select(max_q_nz, max_q, one64);
            let denom_f = b.ins().fcvt_from_uint(types::F64, denom_i);
            let max_step = b.ins().fdiv(max_v, denom_f);
            let min_step = b.ins().fdiv(min_v, denom_f);
            let def_step = b.ins().fsub(max_step, min_step);

            let hs_nz = b.ins().icmp_imm_s(IntCC::NotEqual, has_step, 0);
            let step_abs = b.ins().fabs(step_v);
            let step_fin = b.ins().fcmp(FloatCC::LessThan, step_abs, inf);
            let step_pos = b.ins().fcmp(FloatCC::GreaterThan, step_v, zf);
            let step_valid = b.ins().band(step_fin, step_pos);
            let use_custom = b.ins().band(hs_nz, step_valid);
            let eff_step = b.ins().select(use_custom, step_v, def_step);

            let eff_abs = b.ins().fabs(eff_step);
            let eff_fin = b.ins().fcmp(FloatCC::LessThan, eff_abs, inf);
            let eff_pos = b.ins().fcmp(FloatCC::GreaterThan, eff_step, zf);
            let eff_ok = b.ins().band(eff_fin, eff_pos);
            let dequant_bb = b.create_block();
            b.ins().brif(eff_ok, dequant_bb, &[], ret_min_bb, &[]);

            b.switch_to_block(dequant_bb);
            b.seal_block(dequant_bb);
            let q_f = b.ins().fcvt_from_uint(types::F64, q);
            let prod = b.ins().fmul(q_f, eff_step);
            let prod_abs = b.ins().fabs(prod);
            let prod_fin = b.ins().fcmp(FloatCC::LessThan, prod_abs, inf);
            let direct_out = b.ins().fadd(min_v, prod);
            let rem_f = b.ins().fsub(denom_f, q_f);
            let rem_prod = b.ins().fmul(rem_f, eff_step);
            let from_max_out = b.ins().fsub(max_v, rem_prod);
            let custom_or_fin = b.ins().bor(use_custom, prod_fin);
            let out = b.ins().select(custom_or_fin, direct_out, from_max_out);
            let lt_min = b.ins().fcmp(FloatCC::LessThan, out, min_v);
            let gt_max = b.ins().fcmp(FloatCC::GreaterThan, out, max_v);
            let c1 = b.ins().select(lt_min, min_v, out);
            let clamped = b.ins().select(gt_max, max_v, c1);
            b.ins().return_(&[clamped]);

            b.seal_all_blocks();
            b.finalize(ctx.fe_cfg);
        }
        define_fn_checked(
            &mut ctx.obj_mod,
            fid,
            &mut fn_ctx,
            "strata_net_dequantize_scalar_f64",
        )?;
        fid
    };

    // 3. `strata_net_pack_bits_le(buf: ptr, buf_len: ptr_ty, bit_offset: i32, bits: i32, val: i64)`
    let pack_bits_fn = {
        let mut sig = Signature::new(cc);
        sig.params.push(AbiParam::new(ptr_ty));
        sig.params.push(AbiParam::new(ptr_ty));
        sig.params.push(AbiParam::new(types::I32));
        sig.params.push(AbiParam::new(types::I32));
        sig.params.push(AbiParam::new(types::I64));
        let fid = ctx
            .obj_mod
            .declare_function("strata_net_pack_bits_le", Linkage::Local, &sig)
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

            let ps = b.block_params(entry).to_vec();
            let (buf, buf_len, bit_offset, bits, val) = (ps[0], ps[1], ps[2], ps[3], ps[4]);

            let c64 = b.ins().iconst(types::I32, 64);
            let gt64 = b.ins().icmp_imm_s(IntCC::UnsignedGreaterThan, bits, 64);
            let eff_bits = b.ins().select(gt64, c64, bits);
            let bits_nz = b.ins().icmp_imm_s(IntCC::NotEqual, eff_bits, 0);
            let buf_nz = b.ins().icmp_imm_s(IntCC::NotEqual, buf, 0);
            let go = b.ins().band(bits_nz, buf_nz);

            let prep_bb = b.create_block();
            let exit_bb = b.create_block();
            b.ins().brif(go, prep_bb, &[], exit_bb, &[]);

            b.switch_to_block(prep_bb);
            b.seal_block(prep_bb);
            let is_64 = b.ins().icmp_imm_s(IntCC::Equal, eff_bits, 64);
            let one64 = b.ins().iconst(types::I64, 1);
            let all_ones = b.ins().iconst(types::I64, -1);
            let mask_shl = b.ins().ishl(one64, eff_bits);
            let mask_sub = b.ins().iadd_imm_s(mask_shl, -1);
            let mask = b.ins().select(is_64, all_ones, mask_sub);
            let src0 = b.ins().band(val, mask);
            let cur_bit0 = b.ins().uextend(ptr_ty, bit_offset);

            let hdr_bb = b.create_block();
            b.append_block_param(hdr_bb, ptr_ty); // cur_bit
            b.append_block_param(hdr_bb, types::I32); // remaining
            b.append_block_param(hdr_bb, types::I64); // src
            b.ins().jump(
                hdr_bb,
                &[
                    BlockArg::Value(cur_bit0),
                    BlockArg::Value(eff_bits),
                    BlockArg::Value(src0),
                ],
            );

            b.switch_to_block(hdr_bb);
            let cur_bit = b.block_params(hdr_bb)[0];
            let rem = b.block_params(hdr_bb)[1];
            let src = b.block_params(hdr_bb)[2];
            let rem_pos = b.ins().icmp_imm_s(IntCC::UnsignedGreaterThan, rem, 0);
            let check_bounds_bb = b.create_block();
            b.ins().brif(rem_pos, check_bounds_bb, &[], exit_bb, &[]);

            b.switch_to_block(check_bounds_bb);
            b.seal_block(check_bounds_bb);
            let byte_idx = b.ins().ushr_imm_u(cur_bit, 3);
            let in_bounds = b.ins().icmp(IntCC::UnsignedLessThan, byte_idx, buf_len);
            let body_bb = b.create_block();
            b.ins().brif(in_bounds, body_bb, &[], exit_bb, &[]);

            b.switch_to_block(body_bb);
            b.seal_block(body_bb);
            let bit_in_byte = b.ins().band_imm_u(cur_bit, 7);
            let eight_p = b.ins().iconst(ptr_ty, 8);
            let avail = b.ins().isub(eight_p, bit_in_byte);
            let rem_p = b.ins().uextend(ptr_ty, rem);
            let take_avail = b.ins().icmp(IntCC::UnsignedLessThan, avail, rem_p);
            let take = b.ins().select(take_avail, avail, rem_p);

            let take32 = b.ins().ireduce(types::I32, take);
            let bib32 = b.ins().ireduce(types::I32, bit_in_byte);
            let one32 = b.ins().iconst(types::I32, 1);
            let lm_shl = b.ins().ishl(one32, take32);
            let low_mask32 = b.ins().iadd_imm_s(lm_shl, -1);
            let low_mask8 = b.ins().ireduce(types::I8, low_mask32);
            let chunk_mask = b.ins().ishl(low_mask8, bib32);
            let low_mask64 = b.ins().uextend(types::I64, low_mask32);
            let src_masked = b.ins().band(src, low_mask64);
            let src_low8 = b.ins().ireduce(types::I8, src_masked);
            let chunk_bits = b.ins().ishl(src_low8, bib32);

            let byte_ptr = b.ins().iadd(buf, byte_idx);
            let old_b = b.ins().load(types::I8, MemFlagsData::new(), byte_ptr, 0);
            let not_mask = b.ins().bnot(chunk_mask);
            let old_cleared = b.ins().band(old_b, not_mask);
            let new_b = b.ins().bor(old_cleared, chunk_bits);
            b.ins().store(MemFlagsData::new(), new_b, byte_ptr, 0);

            let next_src = b.ins().ushr(src, take32);
            let next_cur = b.ins().iadd(cur_bit, take);
            let next_rem = b.ins().isub(rem, take32);
            b.ins().jump(
                hdr_bb,
                &[
                    BlockArg::Value(next_cur),
                    BlockArg::Value(next_rem),
                    BlockArg::Value(next_src),
                ],
            );
            b.seal_block(hdr_bb);

            b.switch_to_block(exit_bb);
            b.seal_block(exit_bb);
            b.ins().return_(&[]);

            b.finalize(ctx.fe_cfg);
        }
        define_fn_checked(
            &mut ctx.obj_mod,
            fid,
            &mut fn_ctx,
            "strata_net_pack_bits_le",
        )?;
        fid
    };

    // 4. `strata_net_unpack_bits_le(buf: ptr, buf_len: ptr_ty, bit_offset: i32, bits: i32) -> i64`
    let unpack_bits_fn = {
        let mut sig = Signature::new(cc);
        sig.params.push(AbiParam::new(ptr_ty));
        sig.params.push(AbiParam::new(ptr_ty));
        sig.params.push(AbiParam::new(types::I32));
        sig.params.push(AbiParam::new(types::I32));
        sig.returns.push(AbiParam::new(types::I64));
        let fid = ctx
            .obj_mod
            .declare_function("strata_net_unpack_bits_le", Linkage::Local, &sig)
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

            let ps = b.block_params(entry).to_vec();
            let (buf, buf_len, bit_offset, bits) = (ps[0], ps[1], ps[2], ps[3]);

            let c64 = b.ins().iconst(types::I32, 64);
            let gt64 = b.ins().icmp_imm_s(IntCC::UnsignedGreaterThan, bits, 64);
            let eff_bits = b.ins().select(gt64, c64, bits);
            let bits_nz = b.ins().icmp_imm_s(IntCC::NotEqual, eff_bits, 0);
            let buf_nz = b.ins().icmp_imm_s(IntCC::NotEqual, buf, 0);
            let go = b.ins().band(bits_nz, buf_nz);

            let zero64 = b.ins().iconst(types::I64, 0);
            let zero32 = b.ins().iconst(types::I32, 0);
            let exit_bb = b.create_block();
            b.append_block_param(exit_bb, types::I64);
            let prep_bb = b.create_block();
            b.ins()
                .brif(go, prep_bb, &[], exit_bb, &[BlockArg::Value(zero64)]);

            b.switch_to_block(prep_bb);
            b.seal_block(prep_bb);
            let cur_bit0 = b.ins().uextend(ptr_ty, bit_offset);
            let hdr_bb = b.create_block();
            b.append_block_param(hdr_bb, ptr_ty); // cur_bit
            b.append_block_param(hdr_bb, types::I32); // remaining
            b.append_block_param(hdr_bb, types::I64); // out
            b.append_block_param(hdr_bb, types::I32); // shift
            b.ins().jump(
                hdr_bb,
                &[
                    BlockArg::Value(cur_bit0),
                    BlockArg::Value(eff_bits),
                    BlockArg::Value(zero64),
                    BlockArg::Value(zero32),
                ],
            );

            b.switch_to_block(hdr_bb);
            let cur_bit = b.block_params(hdr_bb)[0];
            let rem = b.block_params(hdr_bb)[1];
            let out = b.block_params(hdr_bb)[2];
            let shift = b.block_params(hdr_bb)[3];
            let rem_pos = b.ins().icmp_imm_s(IntCC::UnsignedGreaterThan, rem, 0);
            let check_bounds_bb = b.create_block();
            b.ins().brif(
                rem_pos,
                check_bounds_bb,
                &[],
                exit_bb,
                &[BlockArg::Value(out)],
            );

            b.switch_to_block(check_bounds_bb);
            b.seal_block(check_bounds_bb);
            let byte_idx = b.ins().ushr_imm_u(cur_bit, 3);
            let in_bounds = b.ins().icmp(IntCC::UnsignedLessThan, byte_idx, buf_len);
            let body_bb = b.create_block();
            b.ins()
                .brif(in_bounds, body_bb, &[], exit_bb, &[BlockArg::Value(out)]);

            b.switch_to_block(body_bb);
            b.seal_block(body_bb);
            let bit_in_byte = b.ins().band_imm_u(cur_bit, 7);
            let eight_p = b.ins().iconst(ptr_ty, 8);
            let avail = b.ins().isub(eight_p, bit_in_byte);
            let rem_p = b.ins().uextend(ptr_ty, rem);
            let take_avail = b.ins().icmp(IntCC::UnsignedLessThan, avail, rem_p);
            let take = b.ins().select(take_avail, avail, rem_p);

            let take32 = b.ins().ireduce(types::I32, take);
            let bib32 = b.ins().ireduce(types::I32, bit_in_byte);
            let one32 = b.ins().iconst(types::I32, 1);
            let lm_shl = b.ins().ishl(one32, take32);
            let lm_sub = b.ins().iadd_imm_s(lm_shl, -1);
            let low_mask8 = b.ins().ireduce(types::I8, lm_sub);

            let byte_ptr = b.ins().iadd(buf, byte_idx);
            let byte_val = b.ins().load(types::I8, MemFlagsData::new(), byte_ptr, 0);
            let shifted_b = b.ins().ushr(byte_val, bib32);
            let chunk = b.ins().band(shifted_b, low_mask8);
            let chunk64 = b.ins().uextend(types::I64, chunk);
            let chunk_shl = b.ins().ishl(chunk64, shift);
            let next_out = b.ins().bor(out, chunk_shl);
            let next_shift = b.ins().iadd(shift, take32);
            let next_cur = b.ins().iadd(cur_bit, take);
            let next_rem = b.ins().isub(rem, take32);
            b.ins().jump(
                hdr_bb,
                &[
                    BlockArg::Value(next_cur),
                    BlockArg::Value(next_rem),
                    BlockArg::Value(next_out),
                    BlockArg::Value(next_shift),
                ],
            );
            b.seal_block(hdr_bb);

            b.switch_to_block(exit_bb);
            b.seal_block(exit_bb);
            let final_out = b.block_params(exit_bb)[0];
            b.ins().return_(&[final_out]);

            b.finalize(ctx.fe_cfg);
        }
        define_fn_checked(
            &mut ctx.obj_mod,
            fid,
            &mut fn_ctx,
            "strata_net_unpack_bits_le",
        )?;
        fid
    };

    // 5. `strata_net_verify_handshake(pkt: ptr, expected_module_fp: i64, expected_item_fp: i64) -> i8`
    let verify_handshake_fn = {
        let mut sig = Signature::new(cc);
        sig.params.push(AbiParam::new(ptr_ty));
        sig.params.push(AbiParam::new(types::I64));
        sig.params.push(AbiParam::new(types::I64));
        sig.returns.push(AbiParam::new(types::I8));
        let fid = ctx
            .obj_mod
            .declare_function("strata_net_verify_handshake", Linkage::Local, &sig)
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

            let pkt = b.block_params(entry)[0];
            let exp_mod_fp = b.block_params(entry)[1];
            let exp_item_fp = b.block_params(entry)[2];

            let fail_bb = b.create_block();
            let check_bb = b.create_block();
            let pkt_nz = b.ins().icmp_imm_s(IntCC::NotEqual, pkt, 0);
            b.ins().brif(pkt_nz, check_bb, &[], fail_bb, &[]);

            b.switch_to_block(fail_bb);
            let f_v = b.ins().iconst(types::I8, 0);
            b.ins().return_(&[f_v]);

            b.switch_to_block(check_bb);
            b.seal_block(check_bb);
            let magic = b.ins().load(
                types::I32,
                MemFlagsData::new(),
                pkt,
                packet_offsets::MAGIC as i32,
            );
            let version = b.ins().load(
                types::I16,
                MemFlagsData::new(),
                pkt,
                packet_offsets::VERSION as i32,
            );
            let mod_fp = b.ins().load(
                types::I64,
                MemFlagsData::new(),
                pkt,
                packet_offsets::MODULE_NET_FINGERPRINT as i32,
            );
            let item_fp = b.ins().load(
                types::I64,
                MemFlagsData::new(),
                pkt,
                packet_offsets::ITEM_SCHEMA_FINGERPRINT as i32,
            );
            let pbytes8 = b.ins().load(
                types::I8,
                MemFlagsData::new(),
                pkt,
                packet_offsets::PAYLOAD_BYTES as i32,
            );
            let pbytes32 = b.ins().uextend(types::I32, pbytes8);

            let ok_magic =
                b.ins()
                    .icmp_imm_s(IntCC::Equal, magic, i64::from(STRATA_NET_PACKET_MAGIC));
            let ok_ver =
                b.ins()
                    .icmp_imm_s(IntCC::Equal, version, i64::from(STRATA_NET_WIRE_VERSION));
            let ok_mod_nz = b.ins().icmp_imm_s(IntCC::NotEqual, exp_mod_fp, 0);
            let ok_mod_eq = b.ins().icmp(IntCC::Equal, mod_fp, exp_mod_fp);
            let ok_item_nz = b.ins().icmp_imm_s(IntCC::NotEqual, exp_item_fp, 0);
            let ok_item_eq = b.ins().icmp(IntCC::Equal, item_fp, exp_item_fp);
            let ok_plen = b.ins().icmp_imm_s(
                IntCC::UnsignedLessThanOrEqual,
                pbytes32,
                STRATA_NET_MAX_PAYLOAD_BYTES as i64,
            );

            let c0 = b.ins().band(ok_magic, ok_ver);
            let c1 = b.ins().band(ok_mod_nz, ok_mod_eq);
            let c2 = b.ins().band(ok_item_nz, ok_item_eq);
            let c01 = b.ins().band(c0, c1);
            let c2p = b.ins().band(c2, ok_plen);
            let all_ok = b.ins().band(c01, c2p);
            let ok_bb = b.create_block();
            b.ins().brif(all_ok, ok_bb, &[], fail_bb, &[]);

            b.switch_to_block(ok_bb);
            let t_v = b.ins().iconst(types::I8, 1);
            b.ins().return_(&[t_v]);

            b.seal_all_blocks();
            b.finalize(ctx.fe_cfg);
        }
        define_fn_checked(
            &mut ctx.obj_mod,
            fid,
            &mut fn_ctx,
            "strata_net_verify_handshake",
        )?;
        fid
    };

    Ok(NetPrimitives {
        round_fn: round_fid,
        quantize_fn,
        dequantize_fn,
        pack_bits_fn,
        unpack_bits_fn,
        verify_handshake_fn,
    })
}

pub(super) fn net_component_flags(nc: &MirNetComponent) -> u16 {
    let mut flags = 0u16;
    if matches!(nc.reliability, NetReliability::Reliable) {
        flags |= FLAG_IS_RELIABLE;
    }
    if nc.is_predicted || nc.authority == AuthorityKind::Predicted {
        flags |= FLAG_IS_PREDICTED;
    }
    if nc.is_resource {
        flags |= FLAG_IS_RESOURCE;
    }
    flags
}

pub(super) fn net_quant_lane_to_f64(
    b: &mut FunctionBuilder<'_>,
    src_ptr: Value,
    byte_off: u32,
    ty: &MirType,
    sema_ty: Option<&Ty>,
    lane_count: u8,
    byte_size: u32,
) -> Value {
    if lane_count > 1 {
        let is_ivec = matches!(sema_ty, Some(Ty::IVec2 | Ty::IVec3))
            || matches!(ty, MirType::Named(k) if k.contains("IVec"));
        let is_uvec = matches!(sema_ty, Some(Ty::UVec2))
            || matches!(ty, MirType::Named(k) if k.contains("UVec"));
        if is_ivec {
            let v = b
                .ins()
                .load(types::I32, MemFlagsData::new(), src_ptr, byte_off as i32);
            return b.ins().fcvt_from_sint(types::F64, v);
        } else if is_uvec {
            let v = b
                .ins()
                .load(types::I32, MemFlagsData::new(), src_ptr, byte_off as i32);
            return b.ins().fcvt_from_uint(types::F64, v);
        } else if byte_size == 8 * u32::from(lane_count) {
            return b
                .ins()
                .load(types::F64, MemFlagsData::new(), src_ptr, byte_off as i32);
        } else {
            let v = b
                .ins()
                .load(types::F32, MemFlagsData::new(), src_ptr, byte_off as i32);
            return b.ins().fpromote(types::F64, v);
        }
    }
    match (ty, sema_ty) {
        (MirType::F64, _) | (_, Some(Ty::F64)) => {
            b.ins()
                .load(types::F64, MemFlagsData::new(), src_ptr, byte_off as i32)
        }
        (MirType::I8, _) | (_, Some(Ty::I8)) => {
            let v = b
                .ins()
                .load(types::I8, MemFlagsData::new(), src_ptr, byte_off as i32);
            b.ins().fcvt_from_sint(types::F64, v)
        }
        (MirType::I16, _) | (_, Some(Ty::I16)) => {
            let v = b
                .ins()
                .load(types::I16, MemFlagsData::new(), src_ptr, byte_off as i32);
            b.ins().fcvt_from_sint(types::F64, v)
        }
        (MirType::Fix32, _) | (_, Some(Ty::Fix32)) => {
            let v = b
                .ins()
                .load(types::I32, MemFlagsData::new(), src_ptr, byte_off as i32);
            let fv = b.ins().fcvt_from_sint(types::F64, v);
            let scale = b.ins().f64const(65_536.0);
            b.ins().fdiv(fv, scale)
        }
        (MirType::I32, _) | (_, Some(Ty::I32)) => {
            let v = b
                .ins()
                .load(types::I32, MemFlagsData::new(), src_ptr, byte_off as i32);
            b.ins().fcvt_from_sint(types::F64, v)
        }
        (MirType::Fix64, _) | (_, Some(Ty::Fix64)) => {
            let v = b
                .ins()
                .load(types::I64, MemFlagsData::new(), src_ptr, byte_off as i32);
            let fv = b.ins().fcvt_from_sint(types::F64, v);
            let scale = b.ins().f64const(4_294_967_296.0);
            b.ins().fdiv(fv, scale)
        }
        (MirType::I64, _) | (_, Some(Ty::I64)) => {
            let v = b
                .ins()
                .load(types::I64, MemFlagsData::new(), src_ptr, byte_off as i32);
            b.ins().fcvt_from_sint(types::F64, v)
        }
        (MirType::U8 | MirType::Bool, _) | (_, Some(Ty::U8 | Ty::Bool)) => {
            let v = b
                .ins()
                .load(types::I8, MemFlagsData::new(), src_ptr, byte_off as i32);
            b.ins().fcvt_from_uint(types::F64, v)
        }
        (MirType::U16, _) | (_, Some(Ty::U16)) => {
            let v = b
                .ins()
                .load(types::I16, MemFlagsData::new(), src_ptr, byte_off as i32);
            b.ins().fcvt_from_uint(types::F64, v)
        }
        (MirType::U32 | MirType::Sym, _) | (_, Some(Ty::U32 | Ty::Sym)) => {
            let v = b
                .ins()
                .load(types::I32, MemFlagsData::new(), src_ptr, byte_off as i32);
            b.ins().fcvt_from_uint(types::F64, v)
        }
        (MirType::U64, _) | (_, Some(Ty::U64)) => {
            let v = b
                .ins()
                .load(types::I64, MemFlagsData::new(), src_ptr, byte_off as i32);
            b.ins().fcvt_from_uint(types::F64, v)
        }
        _ => {
            let v = b
                .ins()
                .load(types::F32, MemFlagsData::new(), src_ptr, byte_off as i32);
            b.ins().fpromote(types::F64, v)
        }
    }
}

pub(super) fn net_quant_f64_to_lane(
    b: &mut FunctionBuilder<'_>,
    round_ref: cranelift_codegen::ir::FuncRef,
    dst_ptr: Value,
    byte_off: u32,
    val_f64: Value,
    ty: &MirType,
    sema_ty: Option<&Ty>,
    lane_count: u8,
    byte_size: u32,
) {
    let round_val = |b: &mut FunctionBuilder<'_>, v: Value| -> Value {
        let rc = b.ins().call(round_ref, &[v]);
        b.func.dfg.inst_results(rc)[0]
    };
    if lane_count > 1 {
        let is_ivec = matches!(sema_ty, Some(Ty::IVec2 | Ty::IVec3))
            || matches!(ty, MirType::Named(k) if k.contains("IVec"));
        let is_uvec = matches!(sema_ty, Some(Ty::UVec2))
            || matches!(ty, MirType::Named(k) if k.contains("UVec"));
        if is_ivec {
            let rv = round_val(b, val_f64);
            let iv = b.ins().fcvt_to_sint_sat(types::I32, rv);
            b.ins()
                .store(MemFlagsData::new(), iv, dst_ptr, byte_off as i32);
        } else if is_uvec {
            let rv = round_val(b, val_f64);
            let uv = b.ins().fcvt_to_uint_sat(types::I32, rv);
            b.ins()
                .store(MemFlagsData::new(), uv, dst_ptr, byte_off as i32);
        } else if byte_size == 8 * u32::from(lane_count) {
            b.ins()
                .store(MemFlagsData::new(), val_f64, dst_ptr, byte_off as i32);
        } else {
            let fv = b.ins().fdemote(types::F32, val_f64);
            b.ins()
                .store(MemFlagsData::new(), fv, dst_ptr, byte_off as i32);
        }
        return;
    }
    match (ty, sema_ty) {
        (MirType::F64, _) | (_, Some(Ty::F64)) => {
            b.ins()
                .store(MemFlagsData::new(), val_f64, dst_ptr, byte_off as i32);
        }
        (MirType::I8, _) | (_, Some(Ty::I8)) => {
            let rv = round_val(b, val_f64);
            let iv = b.ins().fcvt_to_sint_sat(types::I32, rv);
            let lo = b.ins().iconst(types::I32, i64::from(i8::MIN));
            let hi = b.ins().iconst(types::I32, i64::from(i8::MAX));
            let lt_lo = b.ins().icmp(IntCC::SignedLessThan, iv, lo);
            let gt_hi = b.ins().icmp(IntCC::SignedGreaterThan, iv, hi);
            let c1 = b.ins().select(lt_lo, lo, iv);
            let clamped = b.ins().select(gt_hi, hi, c1);
            let v8 = b.ins().ireduce(types::I8, clamped);
            b.ins()
                .store(MemFlagsData::new(), v8, dst_ptr, byte_off as i32);
        }
        (MirType::I16, _) | (_, Some(Ty::I16)) => {
            let rv = round_val(b, val_f64);
            let iv = b.ins().fcvt_to_sint_sat(types::I32, rv);
            let lo = b.ins().iconst(types::I32, i64::from(i16::MIN));
            let hi = b.ins().iconst(types::I32, i64::from(i16::MAX));
            let lt_lo = b.ins().icmp(IntCC::SignedLessThan, iv, lo);
            let gt_hi = b.ins().icmp(IntCC::SignedGreaterThan, iv, hi);
            let c1 = b.ins().select(lt_lo, lo, iv);
            let clamped = b.ins().select(gt_hi, hi, c1);
            let v16 = b.ins().ireduce(types::I16, clamped);
            b.ins()
                .store(MemFlagsData::new(), v16, dst_ptr, byte_off as i32);
        }
        (MirType::Fix32, _) | (_, Some(Ty::Fix32)) => {
            let scale = b.ins().f64const(65_536.0);
            let scaled = b.ins().fmul(val_f64, scale);
            let rv = round_val(b, scaled);
            let iv = b.ins().fcvt_to_sint_sat(types::I32, rv);
            b.ins()
                .store(MemFlagsData::new(), iv, dst_ptr, byte_off as i32);
        }
        (MirType::I32, _) | (_, Some(Ty::I32)) => {
            let rv = round_val(b, val_f64);
            let iv = b.ins().fcvt_to_sint_sat(types::I32, rv);
            b.ins()
                .store(MemFlagsData::new(), iv, dst_ptr, byte_off as i32);
        }
        (MirType::Fix64, _) | (_, Some(Ty::Fix64)) => {
            let scale = b.ins().f64const(4_294_967_296.0);
            let scaled = b.ins().fmul(val_f64, scale);
            let rv = round_val(b, scaled);
            let iv = b.ins().fcvt_to_sint_sat(types::I64, rv);
            b.ins()
                .store(MemFlagsData::new(), iv, dst_ptr, byte_off as i32);
        }
        (MirType::I64, _) | (_, Some(Ty::I64)) => {
            let rv = round_val(b, val_f64);
            let iv = b.ins().fcvt_to_sint_sat(types::I64, rv);
            b.ins()
                .store(MemFlagsData::new(), iv, dst_ptr, byte_off as i32);
        }
        (MirType::Bool, _) | (_, Some(Ty::Bool)) => {
            let rv = round_val(b, val_f64);
            let uv = b.ins().fcvt_to_uint_sat(types::I32, rv);
            let hi = b.ins().iconst(types::I32, 1);
            let gt_hi = b.ins().icmp(IntCC::UnsignedGreaterThan, uv, hi);
            let clamped = b.ins().select(gt_hi, hi, uv);
            let v8 = b.ins().ireduce(types::I8, clamped);
            b.ins()
                .store(MemFlagsData::new(), v8, dst_ptr, byte_off as i32);
        }
        (MirType::U8, _) | (_, Some(Ty::U8)) => {
            let rv = round_val(b, val_f64);
            let uv = b.ins().fcvt_to_uint_sat(types::I32, rv);
            let hi = b.ins().iconst(types::I32, i64::from(u8::MAX));
            let gt_hi = b.ins().icmp(IntCC::UnsignedGreaterThan, uv, hi);
            let clamped = b.ins().select(gt_hi, hi, uv);
            let v8 = b.ins().ireduce(types::I8, clamped);
            b.ins()
                .store(MemFlagsData::new(), v8, dst_ptr, byte_off as i32);
        }
        (MirType::U16, _) | (_, Some(Ty::U16)) => {
            let rv = round_val(b, val_f64);
            let uv = b.ins().fcvt_to_uint_sat(types::I32, rv);
            let hi = b.ins().iconst(types::I32, i64::from(u16::MAX));
            let gt_hi = b.ins().icmp(IntCC::UnsignedGreaterThan, uv, hi);
            let clamped = b.ins().select(gt_hi, hi, uv);
            let v16 = b.ins().ireduce(types::I16, clamped);
            b.ins()
                .store(MemFlagsData::new(), v16, dst_ptr, byte_off as i32);
        }
        (MirType::U32 | MirType::Sym, _) | (_, Some(Ty::U32 | Ty::Sym)) => {
            let rv = round_val(b, val_f64);
            let uv = b.ins().fcvt_to_uint_sat(types::I32, rv);
            b.ins()
                .store(MemFlagsData::new(), uv, dst_ptr, byte_off as i32);
        }
        (MirType::U64, _) | (_, Some(Ty::U64)) => {
            let rv = round_val(b, val_f64);
            let uv = b.ins().fcvt_to_uint_sat(types::I64, rv);
            b.ins()
                .store(MemFlagsData::new(), uv, dst_ptr, byte_off as i32);
        }
        _ => {
            let fv = b.ins().fdemote(types::F32, val_f64);
            b.ins()
                .store(MemFlagsData::new(), fv, dst_ptr, byte_off as i32);
        }
    }
}

pub(super) fn net_comp_stratum_lidxs(
    ctx: &ModuleContext<'_>,
    nc: &MirNetComponent,
) -> Result<Vec<usize>, JitError> {
    let Some(root_lidx) = lookup_name_in_map(&ctx.layout_map, &nc.canonical_name) else {
        return Err(JitError::Codegen(format!(
            "net component `{}` missing solved layout in JIT module",
            nc.canonical_name
        )));
    };
    let mut strata = vec![root_lidx];
    for wf in &nc.wire_fields {
        if let Some(ref sl_name) = wf.stratum_layout {
            let Some(sl_lidx) = lookup_name_in_map(&ctx.layout_map, sl_name) else {
                return Err(JitError::Codegen(format!(
                    "net component `{}` missing solved stratum layout `{sl_name}` in JIT module",
                    nc.canonical_name
                )));
            };
            if !strata.contains(&sl_lidx) {
                strata.push(sl_lidx);
            }
        }
    }
    Ok(strata)
}

fn resolve_net_wire_fields<'a>(
    ctx: &ModuleContext<'_>,
    nc: &'a MirNetComponent,
    strata: &[usize],
) -> Result<Vec<(&'a MirNetFieldSpec, Ty, usize)>, JitError> {
    let mut out = Vec::with_capacity(nc.wire_fields.len());
    for wf in &nc.wire_fields {
        let sl_name = wf.stratum_layout.as_deref().unwrap_or(&nc.canonical_name);
        let Some(sl_lidx) = lookup_name_in_map(&ctx.layout_map, sl_name) else {
            return Err(JitError::Codegen(format!(
                "net component `{}` missing solved stratum layout `{sl_name}` in JIT module",
                nc.canonical_name
            )));
        };
        let Some(sf) = ctx.mir_layouts_sorted[sl_lidx]
            .fields
            .iter()
            .find(|sf| sf.name == wf.field_name)
        else {
            return Err(JitError::Codegen(format!(
                "net component `{}` wire field `{}` missing from solved layout `{}`",
                nc.canonical_name, wf.field_name, ctx.mir_layouts_sorted[sl_lidx].canonical_name
            )));
        };
        let stratum_slot = strata
            .iter()
            .position(|&idx| idx == sl_lidx)
            .ok_or_else(|| {
                JitError::Codegen(format!(
                    "net component `{}` stratum `{sl_name}` missing from stratum group",
                    nc.canonical_name
                ))
            })?;
        out.push((wf, sf.ty.clone(), stratum_slot));
    }
    Ok(out)
}

pub(super) fn emit_net_component_encoder(
    ctx: &mut ModuleContext<'_>,
    prims: &NetPrimitives,
    nc: &MirNetComponent,
    _lidx: usize,
    mod_fp: u64,
    chunk_idx: usize,
    nc_idx: usize,
) -> Result<FuncId, JitError> {
    let ptr_ty = ctx.ptr_ty;
    let ptr_bytes = ctx.ptr_bytes;
    let cc = ctx.call_conv;
    let sym = format!(
        "strata_net_encode_{chunk_idx}_{nc_idx}_{}",
        sanitize_ident(&nc.name)
    );
    let mut sig = Signature::new(cc);
    sig.params.push(AbiParam::new(ptr_ty)); // src_ptrs: *const *const u8
    sig.params.push(AbiParam::new(types::I64)); // entity_bits
    sig.params.push(AbiParam::new(types::I32)); // tick_or_seq
    sig.params.push(AbiParam::new(types::I8)); // client_id
    sig.params.push(AbiParam::new(ptr_ty)); // out_pkt
    let fid = ctx
        .obj_mod
        .declare_function(&sym, Linkage::Local, &sig)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let strata = net_comp_stratum_lidxs(ctx, nc)?;
    let resolved_fields = resolve_net_wire_fields(ctx, nc, &strata)?;
    let target_id = fnv1a_64_str(&nc.canonical_name);
    let kind_val = if nc.is_resource {
        PACKET_KIND_RESOURCE_DELTA
    } else {
        PACKET_KIND_COMPONENT_DELTA
    };
    let flags_val = net_component_flags(nc);

    let mut fn_ctx = ctx.obj_mod.make_context();
    fn_ctx.func.signature = sig;
    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut fn_ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);
        b.seal_block(entry);

        let ps = b.block_params(entry).to_vec();
        let (src_ptrs, entity_bits, tick_or_seq, client_id, out_pkt) =
            (ps[0], ps[1], ps[2], ps[3], ps[4]);

        let pkt_nz = b.ins().icmp_imm_s(IntCC::NotEqual, out_pkt, 0);
        let write_hdr_bb = b.create_block();
        let ret_bb = b.create_block();
        b.ins().brif(pkt_nz, write_hdr_bb, &[], ret_bb, &[]);

        b.switch_to_block(write_hdr_bb);
        b.seal_block(write_hdr_bb);
        // Zero all 184 bytes (`23 * 8`) of `out_pkt`.
        let z64 = b.ins().iconst(types::I64, 0);
        for w in 0..(STRATA_NET_PACKET_SIZE / 8) {
            b.ins()
                .store(MemFlagsData::new(), z64, out_pkt, (w * 8) as i32);
        }

        let mod_fp_v = b.ins().iconst(types::I64, mod_fp as i64);
        let item_fp_v = b.ins().iconst(types::I64, nc.schema_fingerprint as i64);
        let tgt_v = b.ins().iconst(types::I64, target_id as i64);
        let magic_v = b
            .ins()
            .iconst(types::I32, i64::from(STRATA_NET_PACKET_MAGIC));
        let ver_v = b
            .ins()
            .iconst(types::I16, i64::from(STRATA_NET_WIRE_VERSION));
        let pbits_v = b.ins().iconst(types::I16, i64::from(nc.packed_bits as u16));
        let flags_v = b.ins().iconst(types::I16, i64::from(flags_val));
        let kind_v = b.ins().iconst(types::I8, i64::from(kind_val));
        let chan_v = b.ins().iconst(types::I8, i64::from(nc.channel));
        let pbytes_v = b.ins().iconst(types::I8, i64::from(nc.packed_bytes as u8));

        b.ins().store(
            MemFlagsData::new(),
            mod_fp_v,
            out_pkt,
            packet_offsets::MODULE_NET_FINGERPRINT as i32,
        );
        b.ins().store(
            MemFlagsData::new(),
            item_fp_v,
            out_pkt,
            packet_offsets::ITEM_SCHEMA_FINGERPRINT as i32,
        );
        b.ins().store(
            MemFlagsData::new(),
            tgt_v,
            out_pkt,
            packet_offsets::TARGET_ID as i32,
        );
        b.ins().store(
            MemFlagsData::new(),
            entity_bits,
            out_pkt,
            packet_offsets::ENTITY_BITS as i32,
        );
        b.ins().store(
            MemFlagsData::new(),
            magic_v,
            out_pkt,
            packet_offsets::MAGIC as i32,
        );
        b.ins().store(
            MemFlagsData::new(),
            tick_or_seq,
            out_pkt,
            packet_offsets::TICK_OR_SEQ as i32,
        );
        b.ins().store(
            MemFlagsData::new(),
            ver_v,
            out_pkt,
            packet_offsets::VERSION as i32,
        );
        b.ins().store(
            MemFlagsData::new(),
            pbits_v,
            out_pkt,
            packet_offsets::PAYLOAD_BITS as i32,
        );
        b.ins().store(
            MemFlagsData::new(),
            flags_v,
            out_pkt,
            packet_offsets::FLAGS as i32,
        );
        b.ins().store(
            MemFlagsData::new(),
            kind_v,
            out_pkt,
            packet_offsets::KIND as i32,
        );
        b.ins().store(
            MemFlagsData::new(),
            chan_v,
            out_pkt,
            packet_offsets::CHANNEL as i32,
        );
        b.ins().store(
            MemFlagsData::new(),
            pbytes_v,
            out_pkt,
            packet_offsets::PAYLOAD_BYTES as i32,
        );
        b.ins().store(
            MemFlagsData::new(),
            client_id,
            out_pkt,
            packet_offsets::CLIENT_ID as i32,
        );

        let src_ptrs_nz = b.ins().icmp_imm_s(IntCC::NotEqual, src_ptrs, 0);
        let chk_src0_bb = b.create_block();
        b.ins().brif(src_ptrs_nz, chk_src0_bb, &[], ret_bb, &[]);

        b.switch_to_block(chk_src0_bb);
        b.seal_block(chk_src0_bb);
        let src0 = b.ins().load(ptr_ty, MemFlagsData::new(), src_ptrs, 0);
        let src0_nz = b.ins().icmp_imm_s(IntCC::NotEqual, src0, 0);
        let encode_bb = b.create_block();
        b.ins().brif(src0_nz, encode_bb, &[], ret_bb, &[]);

        b.switch_to_block(encode_bb);
        b.seal_block(encode_bb);
        let mut stratum_ptrs = Vec::with_capacity(strata.len());
        stratum_ptrs.push(src0);
        for si in 1..strata.len() {
            let sp = b.ins().load(
                ptr_ty,
                MemFlagsData::new(),
                src_ptrs,
                (si * ptr_bytes) as i32,
            );
            stratum_ptrs.push(sp);
        }

        let payload_ptr = b.ins().iadd_imm_s(out_pkt, packet_offsets::PAYLOAD as i64);
        let payload_len = b.ins().iconst(ptr_ty, STRATA_NET_MAX_PAYLOAD_BYTES as i64);
        let quant_ref = ctx.obj_mod.declare_func_in_func(prims.quantize_fn, b.func);
        let pack_ref = ctx.obj_mod.declare_func_in_func(prims.pack_bits_fn, b.func);
        let eight_32 = b.ins().iconst(types::I32, 8);

        for &(wf, ref sf_ty, stratum_slot) in &resolved_fields {
            let s_ptr = stratum_ptrs[stratum_slot];
            let wf_done_bb = if stratum_slot > 0 {
                let wf_bb = b.create_block();
                let done_bb = b.create_block();
                let sp_nz = b.ins().icmp_imm_s(IntCC::NotEqual, s_ptr, 0);
                b.ins().brif(sp_nz, wf_bb, &[], done_bb, &[]);
                b.switch_to_block(wf_bb);
                b.seal_block(wf_bb);
                Some(done_bb)
            } else {
                None
            };

            if let Some(ref q) = wf.quantize {
                let min_v = b.ins().f64const(q.min);
                let max_v = b.ins().f64const(q.max);
                let bits_v = b.ins().iconst(types::I32, i64::from(q.bits));
                let (step_v, has_step) = match q.step {
                    Some(s) => (b.ins().f64const(s), b.ins().iconst(types::I8, 1)),
                    None => (b.ins().f64const(0.0), b.ins().iconst(types::I8, 0)),
                };
                let lane_stride = if q.lane_count > 1 && wf.byte_size == 8 * u32::from(q.lane_count)
                {
                    8u32
                } else {
                    4u32
                };
                for li in 0..q.lane_count {
                    let moff = wf.byte_offset + u32::from(li) * lane_stride;
                    let boff = wf.bit_offset + u32::from(li) * u32::from(q.bits);
                    let fval = net_quant_lane_to_f64(
                        &mut b,
                        s_ptr,
                        moff,
                        &wf.ty,
                        Some(sf_ty),
                        q.lane_count,
                        wf.byte_size,
                    );
                    let qcall = b
                        .ins()
                        .call(quant_ref, &[fval, min_v, max_v, bits_v, step_v, has_step]);
                    let qval = b.func.dfg.inst_results(qcall)[0];
                    let boff_v = b.ins().iconst(types::I32, i64::from(boff));
                    b.ins()
                        .call(pack_ref, &[payload_ptr, payload_len, boff_v, bits_v, qval]);
                }
            } else if wf.byte_size > 0 {
                for bi in 0..wf.byte_size {
                    let byte_v = b.ins().load(
                        types::I8,
                        MemFlagsData::new(),
                        s_ptr,
                        (wf.byte_offset + bi) as i32,
                    );
                    let byte64 = b.ins().uextend(types::I64, byte_v);
                    let boff_v = b
                        .ins()
                        .iconst(types::I32, i64::from(wf.bit_offset + bi * 8));
                    b.ins().call(
                        pack_ref,
                        &[payload_ptr, payload_len, boff_v, eight_32, byte64],
                    );
                }
            }

            if let Some(done_bb) = wf_done_bb {
                b.ins().jump(done_bb, &[]);
                b.switch_to_block(done_bb);
                b.seal_block(done_bb);
            }
        }
        b.ins().jump(ret_bb, &[]);

        b.switch_to_block(ret_bb);
        b.seal_block(ret_bb);
        b.ins().return_(&[]);
        b.finalize(ctx.fe_cfg);
    }
    define_fn_checked(&mut ctx.obj_mod, fid, &mut fn_ctx, &sym)?;
    Ok(fid)
}

pub(super) fn emit_net_component_decoder(
    ctx: &mut ModuleContext<'_>,
    prims: &NetPrimitives,
    nc: &MirNetComponent,
    _lidx: usize,
    mod_fp: u64,
    chunk_idx: usize,
    nc_idx: usize,
) -> Result<FuncId, JitError> {
    let ptr_ty = ctx.ptr_ty;
    let ptr_bytes = ctx.ptr_bytes;
    let cc = ctx.call_conv;
    let sym = format!(
        "strata_net_decode_{chunk_idx}_{nc_idx}_{}",
        sanitize_ident(&nc.name)
    );
    let mut sig = Signature::new(cc);
    sig.params.push(AbiParam::new(ptr_ty)); // pkt
    sig.params.push(AbiParam::new(ptr_ty)); // out_ptrs: *const *mut u8
    sig.returns.push(AbiParam::new(types::I8));
    let fid = ctx
        .obj_mod
        .declare_function(&sym, Linkage::Local, &sig)
        .map_err(|e| JitError::Codegen(e.to_string()))?;

    let strata = net_comp_stratum_lidxs(ctx, nc)?;
    let resolved_fields = resolve_net_wire_fields(ctx, nc, &strata)?;
    let target_id = fnv1a_64_str(&nc.canonical_name);
    let kind_val = if nc.is_resource {
        PACKET_KIND_RESOURCE_DELTA
    } else {
        PACKET_KIND_COMPONENT_DELTA
    };

    let mut fn_ctx = ctx.obj_mod.make_context();
    fn_ctx.func.signature = sig;
    let mut fb_ctx = FunctionBuilderContext::new();
    {
        let mut b = FunctionBuilder::new(&mut fn_ctx.func, &mut fb_ctx);
        let entry = b.create_block();
        b.append_block_params_for_function_params(entry);
        b.switch_to_block(entry);
        b.seal_block(entry);

        let pkt = b.block_params(entry)[0];
        let out_ptrs = b.block_params(entry)[1];

        let fail_bb = b.create_block();
        let hs_bb = b.create_block();
        let pkt_nz = b.ins().icmp_imm_s(IntCC::NotEqual, pkt, 0);
        let out_nz = b.ins().icmp_imm_s(IntCC::NotEqual, out_ptrs, 0);
        let both_nz = b.ins().band(pkt_nz, out_nz);
        b.ins().brif(both_nz, hs_bb, &[], fail_bb, &[]);

        b.switch_to_block(fail_bb);
        let f_v = b.ins().iconst(types::I8, 0);
        b.ins().return_(&[f_v]);

        b.switch_to_block(hs_bb);
        b.seal_block(hs_bb);
        let out0 = b.ins().load(ptr_ty, MemFlagsData::new(), out_ptrs, 0);
        let out0_nz = b.ins().icmp_imm_s(IntCC::NotEqual, out0, 0);
        let hs_ref = ctx
            .obj_mod
            .declare_func_in_func(prims.verify_handshake_fn, b.func);
        let mod_fp_v = b.ins().iconst(types::I64, mod_fp as i64);
        let item_fp_v = b.ins().iconst(types::I64, nc.schema_fingerprint as i64);
        let hs_call = b.ins().call(hs_ref, &[pkt, mod_fp_v, item_fp_v]);
        let hs_ok = b.func.dfg.inst_results(hs_call)[0];

        let pkt_tgt = b.ins().load(
            types::I64,
            MemFlagsData::new(),
            pkt,
            packet_offsets::TARGET_ID as i32,
        );
        let pkt_kind = b.ins().load(
            types::I8,
            MemFlagsData::new(),
            pkt,
            packet_offsets::KIND as i32,
        );
        let pkt_pbytes8 = b.ins().load(
            types::I8,
            MemFlagsData::new(),
            pkt,
            packet_offsets::PAYLOAD_BYTES as i32,
        );
        let pkt_pbytes32 = b.ins().uextend(types::I32, pkt_pbytes8);

        let ok_hs = b.ins().icmp_imm_s(IntCC::NotEqual, hs_ok, 0);
        let ok_tgt = b.ins().icmp_imm_s(IntCC::Equal, pkt_tgt, target_id as i64);
        let ok_kind = b
            .ins()
            .icmp_imm_s(IntCC::Equal, pkt_kind, i64::from(kind_val));
        let ok_pbytes = b.ins().icmp_imm_s(
            IntCC::UnsignedGreaterThanOrEqual,
            pkt_pbytes32,
            i64::from(nc.packed_bytes),
        );
        let v0 = b.ins().band(ok_hs, ok_tgt);
        let v1 = b.ins().band(ok_kind, ok_pbytes);
        let v01 = b.ins().band(v0, v1);
        let valid = b.ins().band(v01, out0_nz);
        let decode_bb = b.create_block();
        b.ins().brif(valid, decode_bb, &[], fail_bb, &[]);

        b.switch_to_block(decode_bb);
        b.seal_block(decode_bb);
        let mut stratum_ptrs = Vec::with_capacity(strata.len());
        stratum_ptrs.push(out0);
        for si in 1..strata.len() {
            let dp = b.ins().load(
                ptr_ty,
                MemFlagsData::new(),
                out_ptrs,
                (si * ptr_bytes) as i32,
            );
            stratum_ptrs.push(dp);
        }

        let payload_ptr = b.ins().iadd_imm_s(pkt, packet_offsets::PAYLOAD as i64);
        let payload_len = b.ins().iconst(ptr_ty, STRATA_NET_MAX_PAYLOAD_BYTES as i64);
        let unpack_ref = ctx
            .obj_mod
            .declare_func_in_func(prims.unpack_bits_fn, b.func);
        let dequant_ref = ctx
            .obj_mod
            .declare_func_in_func(prims.dequantize_fn, b.func);
        let round_ref = ctx.obj_mod.declare_func_in_func(prims.round_fn, b.func);
        let eight_32 = b.ins().iconst(types::I32, 8);

        for &(wf, ref sf_ty, stratum_slot) in &resolved_fields {
            let d_ptr = stratum_ptrs[stratum_slot];
            let wf_done_bb = if stratum_slot > 0 {
                let wf_bb = b.create_block();
                let done_bb = b.create_block();
                let dp_nz = b.ins().icmp_imm_s(IntCC::NotEqual, d_ptr, 0);
                b.ins().brif(dp_nz, wf_bb, &[], done_bb, &[]);
                b.switch_to_block(wf_bb);
                b.seal_block(wf_bb);
                Some(done_bb)
            } else {
                None
            };

            if let Some(ref q) = wf.quantize {
                let min_v = b.ins().f64const(q.min);
                let max_v = b.ins().f64const(q.max);
                let bits_v = b.ins().iconst(types::I32, i64::from(q.bits));
                let (step_v, has_step) = match q.step {
                    Some(s) => (b.ins().f64const(s), b.ins().iconst(types::I8, 1)),
                    None => (b.ins().f64const(0.0), b.ins().iconst(types::I8, 0)),
                };
                let lane_stride = if q.lane_count > 1 && wf.byte_size == 8 * u32::from(q.lane_count)
                {
                    8u32
                } else {
                    4u32
                };
                for li in 0..q.lane_count {
                    let moff = wf.byte_offset + u32::from(li) * lane_stride;
                    let boff = wf.bit_offset + u32::from(li) * u32::from(q.bits);
                    let boff_v = b.ins().iconst(types::I32, i64::from(boff));
                    let ucall = b
                        .ins()
                        .call(unpack_ref, &[payload_ptr, payload_len, boff_v, bits_v]);
                    let raw = b.func.dfg.inst_results(ucall)[0];
                    let dcall = b
                        .ins()
                        .call(dequant_ref, &[raw, min_v, max_v, bits_v, step_v, has_step]);
                    let fval = b.func.dfg.inst_results(dcall)[0];
                    net_quant_f64_to_lane(
                        &mut b,
                        round_ref,
                        d_ptr,
                        moff,
                        fval,
                        &wf.ty,
                        Some(sf_ty),
                        q.lane_count,
                        wf.byte_size,
                    );
                }
            } else if wf.byte_size > 0 {
                for bi in 0..wf.byte_size {
                    let boff_v = b
                        .ins()
                        .iconst(types::I32, i64::from(wf.bit_offset + bi * 8));
                    let ucall = b
                        .ins()
                        .call(unpack_ref, &[payload_ptr, payload_len, boff_v, eight_32]);
                    let raw64 = b.func.dfg.inst_results(ucall)[0];
                    let b8 = b.ins().ireduce(types::I8, raw64);
                    b.ins()
                        .store(MemFlagsData::new(), b8, d_ptr, (wf.byte_offset + bi) as i32);
                }
            }

            if let Some(done_bb) = wf_done_bb {
                b.ins().jump(done_bb, &[]);
                b.switch_to_block(done_bb);
                b.seal_block(done_bb);
            }
        }
        let t_v = b.ins().iconst(types::I8, 1);
        b.ins().return_(&[t_v]);

        b.seal_all_blocks();
        b.finalize(ctx.fe_cfg);
    }
    define_fn_checked(&mut ctx.obj_mod, fid, &mut fn_ctx, &sym)?;
    Ok(fid)
}

pub(super) fn emit_bytes_equal(
    b: &mut FunctionBuilder<'_>,
    ptr_a: Value,
    ptr_b: Value,
    size: usize,
    ptr_ty: Type,
) -> Value {
    if size == 0 {
        return b.ins().iconst(types::I8, 1);
    }
    let idx_0 = b.ins().iconst(ptr_ty, 0);
    let hdr_bb = b.create_block();
    b.append_block_param(hdr_bb, ptr_ty);
    let body_bb = b.create_block();
    let next_bb = b.create_block();
    let done_bb = b.create_block();
    b.append_block_param(done_bb, types::I8);
    b.ins().jump(hdr_bb, &[BlockArg::Value(idx_0)]);

    b.switch_to_block(hdr_bb);
    let idx = b.block_params(hdr_bb)[0];
    let more = b
        .ins()
        .icmp_imm_s(IntCC::UnsignedLessThan, idx, size as i64);
    let t_v = b.ins().iconst(types::I8, 1);
    b.ins()
        .brif(more, body_bb, &[], done_bb, &[BlockArg::Value(t_v)]);

    b.switch_to_block(body_bb);
    b.seal_block(body_bb);
    let pa = b.ins().iadd(ptr_a, idx);
    let pb = b.ins().iadd(ptr_b, idx);
    let ba = b.ins().load(types::I8, MemFlagsData::new(), pa, 0);
    let bb_v = b.ins().load(types::I8, MemFlagsData::new(), pb, 0);
    let eq = b.ins().icmp(IntCC::Equal, ba, bb_v);
    let f_v = b.ins().iconst(types::I8, 0);
    b.ins()
        .brif(eq, next_bb, &[], done_bb, &[BlockArg::Value(f_v)]);

    b.switch_to_block(next_bb);
    b.seal_block(next_bb);
    let next_idx = b.ins().iadd_imm_s(idx, 1);
    b.ins().jump(hdr_bb, &[BlockArg::Value(next_idx)]);
    b.seal_block(hdr_bb);

    b.switch_to_block(done_bb);
    b.seal_block(done_bb);
    b.block_params(done_bb)[0]
}

pub(super) fn emit_net_rx_system(
    ctx: &mut ModuleContext<'_>,
    entry_meta: &NetSystemChunkEntry,
    chunk: &[MirNetComponent],
    codecs: &HashMap<String, (FuncId, FuncId)>,
    chunk_idx: usize,
) -> Result<(), JitError> {
    let ptr_ty = ctx.ptr_ty;
    let ptr_bytes = ctx.ptr_bytes;
    let cc = ctx.call_conv;
    let fid = entry_meta.rx_func_id;

    let mut sig = Signature::new(cc);
    sig.params.push(AbiParam::new(ptr_ty)); // sys_ctx
    sig.params.push(AbiParam::new(ptr_ty)); // user_data (state_ptr)
    sig.returns.push(AbiParam::new(types::I32));

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
        let ok_ret = b.ins().iconst(types::I32, i64::from(FFI_OK));

        let ret_bb = b.create_block();
        let check_msg_bb = b.create_block();
        let sys_nz = b.ins().icmp_imm_s(IntCC::NotEqual, sys_ctx, 0);
        let st_nz = b.ins().icmp_imm_s(IntCC::NotEqual, state_ptr, 0);
        let entry_ok = b.ins().band(sys_nz, st_nz);
        b.ins().brif(entry_ok, check_msg_bb, &[], ret_bb, &[]);

        b.switch_to_block(ret_bb);
        b.ins().return_(&[ok_ret]);

        b.switch_to_block(check_msg_bb);
        b.seal_block(check_msg_bb);
        let api_ptr = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.api_off as i32,
        );
        let api_nz = b.ins().icmp_imm_s(IntCC::NotEqual, api_ptr, 0);
        let is_msg_v = b.ins().load(
            types::I8,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.net_pkt_is_msg_off as i32,
        );
        let msg_on = b.ins().icmp_imm_s(IntCC::NotEqual, is_msg_v, 0);
        let pkts_ptr = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.net_rx_buf_off as i32,
        );
        let pkts_nz = b.ins().icmp_imm_s(IntCC::NotEqual, pkts_ptr, 0);
        let msg_api_ok = b.ins().band(api_nz, msg_on);
        let msg_ready = b.ins().band(msg_api_ok, pkts_nz);
        let query_bb = b.create_block();
        b.ins().brif(msg_ready, query_bb, &[], ret_bb, &[]);

        b.switch_to_block(query_bb);
        b.seal_block(query_bb);
        let msg_it_slot = alloc_zero_slot(&mut b, ptr_bytes, ptr_ty);
        let msg_it_out = b.ins().stack_addr(ptr_ty, msg_it_slot, 0);
        let z_ptr = b.ins().iconst(ptr_ty, 0);
        let qrc = call_vtable(
            &ctx.obj_mod,
            &mut b,
            api_ptr,
            api_slots::SYS_QUERY,
            &[ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            cc,
            &[sys_ctx, z_ptr, msg_it_out],
        );
        let msg_it = b.ins().load(ptr_ty, MemFlagsData::trusted(), msg_it_out, 0);
        let qok = b.ins().icmp_imm_s(IntCC::Equal, qrc, 0);
        let it_nz = b.ins().icmp_imm_s(IntCC::NotEqual, msg_it, 0);
        let msg_it_ok = b.ins().band(qok, it_nz);
        let batch_prep_bb = b.create_block();
        b.ins().brif(msg_it_ok, batch_prep_bb, &[], ret_bb, &[]);

        b.switch_to_block(batch_prep_bb);
        b.seal_block(batch_prep_bb);
        let batch_cap = STRATA_NET_RX_BATCH_CAP;
        let got_slot = alloc_zero_slot(&mut b, ptr_bytes, ptr_ty);
        let got_ptr = b.ins().stack_addr(ptr_ty, got_slot, 0);
        let cap_v = b.ins().iconst(ptr_ty, batch_cap as i64);

        let q_it_slot = alloc_zero_slot(&mut b, ptr_bytes, ptr_ty);
        let q_it_out = b.ins().stack_addr(ptr_ty, q_it_slot, 0);
        let clen_slot = alloc_zero_slot(&mut b, ptr_bytes, ptr_ty);
        let clen_ptr = b.ins().stack_addr(ptr_ty, clen_slot, 0);
        let mut max_comp_sz = 8usize;
        let mut max_strata_count = 1usize;
        for nc in chunk {
            let Ok(strata) = net_comp_stratum_lidxs(ctx, nc) else {
                continue;
            };
            max_strata_count = max_strata_count.max(strata.len());
            let mut sum = 0usize;
            for &s_lidx in &strata {
                let s_sz = ctx.layouts[s_lidx].size;
                sum = sum.saturating_add((s_sz + 7) & !7);
            }
            max_comp_sz = max_comp_sz.max(sum);
        }
        let tmp_slot = alloc_zero_slot(&mut b, max_comp_sz, ptr_ty);
        let tmp_ptr = b.ins().stack_addr(ptr_ty, tmp_slot, 0);
        let ptrs_slot = alloc_zero_slot(&mut b, max_strata_count * ptr_bytes, ptr_ty);
        let ptrs_ptr = b.ins().stack_addr(ptr_ty, ptrs_slot, 0);

        let batch_hdr_bb = b.create_block();
        let dispatch_bb = b.create_block();
        b.ins().jump(batch_hdr_bb, &[]);

        b.switch_to_block(batch_hdr_bb);
        b.ins().store(MemFlagsData::trusted(), z_ptr, got_ptr, 0);
        let rrc = call_vtable(
            &ctx.obj_mod,
            &mut b,
            api_ptr,
            api_slots::MSG_READ_BATCH,
            &[ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            cc,
            &[msg_it, z_ptr, pkts_ptr, cap_v, got_ptr],
        );
        let rrc_ok = b.ins().icmp_imm_s(IntCC::Equal, rrc, 0);
        let got = b.ins().load(ptr_ty, MemFlagsData::trusted(), got_ptr, 0);
        let got_pos = b.ins().icmp_imm_s(IntCC::UnsignedGreaterThan, got, 0);
        let has_batch = b.ins().band(rrc_ok, got_pos);
        b.ins().brif(has_batch, dispatch_bb, &[], ret_bb, &[]);

        b.switch_to_block(dispatch_bb);
        b.seal_block(dispatch_bb);

        let mut entity_q_idx = 1usize;
        for nc in chunk {
            let Ok(strata) = net_comp_stratum_lidxs(ctx, nc) else {
                continue;
            };
            let lidx = strata[0];
            let Some(&(_, dec_fid)) = codecs.get(&nc.canonical_name) else {
                continue;
            };
            let dec_ref = ctx.obj_mod.declare_func_in_func(dec_fid, b.func);
            let target_id = fnv1a_64_str(&nc.canonical_name);
            let sz = ctx.layouts[lidx].size;

            if nc.is_resource {
                let rflag = b.ins().load(
                    types::I8,
                    MemFlagsData::trusted(),
                    state_ptr,
                    ctx.state_layout.res_flag_offset(lidx) as i32,
                );
                let is_host_res = b.ins().icmp_imm_s(IntCC::Equal, rflag, 1);
                let res_scan_bb = b.create_block();
                let after_nc_bb = b.create_block();
                if sz == 0 {
                    b.ins()
                        .brif(is_host_res, res_scan_bb, &[], after_nc_bb, &[]);
                } else {
                    b.ins().jump(res_scan_bb, &[]);
                }

                b.switch_to_block(res_scan_bb);
                b.seal_block(res_scan_bb);
                let scan_hdr = b.create_block();
                b.append_block_param(scan_hdr, ptr_ty); // pi
                b.append_block_param(scan_hdr, ptr_ty); // last_pkt
                let scan_body = b.create_block();
                let apply_res_bb = b.create_block();
                b.ins()
                    .jump(scan_hdr, &[BlockArg::Value(z_ptr), BlockArg::Value(z_ptr)]);

                b.switch_to_block(scan_hdr);
                let pi = b.block_params(scan_hdr)[0];
                let last_pkt = b.block_params(scan_hdr)[1];
                let pi_ok = b.ins().icmp(IntCC::UnsignedLessThan, pi, got);
                b.ins().brif(pi_ok, scan_body, &[], apply_res_bb, &[]);

                b.switch_to_block(scan_body);
                b.seal_block(scan_body);
                let pkt_off = b.ins().imul_imm_s(pi, STRATA_NET_PACKET_SIZE as i64);
                let pkt_ptr = b.ins().iadd(pkts_ptr, pkt_off);
                let pkind = b.ins().load(
                    types::I8,
                    MemFlagsData::new(),
                    pkt_ptr,
                    packet_offsets::KIND as i32,
                );
                let ptgt = b.ins().load(
                    types::I64,
                    MemFlagsData::new(),
                    pkt_ptr,
                    packet_offsets::TARGET_ID as i32,
                );
                let k_ok =
                    b.ins()
                        .icmp_imm_s(IntCC::Equal, pkind, i64::from(PACKET_KIND_RESOURCE_DELTA));
                let t_ok = b.ins().icmp_imm_s(IntCC::Equal, ptgt, target_id as i64);
                let matched = b.ins().band(k_ok, t_ok);
                let next_last = b.ins().select(matched, pkt_ptr, last_pkt);
                let pi_next = b.ins().iadd_imm_s(pi, 1);
                b.ins().jump(
                    scan_hdr,
                    &[BlockArg::Value(pi_next), BlockArg::Value(next_last)],
                );
                b.seal_block(scan_hdr);

                b.switch_to_block(apply_res_bb);
                b.seal_block(apply_res_bb);
                let last_nz = b.ins().icmp_imm_s(IntCC::NotEqual, last_pkt, 0);
                let mut_res_bb = b.create_block();
                b.ins().brif(last_nz, mut_res_bb, &[], after_nc_bb, &[]);

                b.switch_to_block(mut_res_bb);
                b.seal_block(mut_res_bb);
                let host_res_bb = b.create_block();
                let mod_res_bb = b.create_block();
                let dec_res_bb = b.create_block();
                b.append_block_param(dec_res_bb, ptr_ty);
                b.ins().brif(is_host_res, host_res_bb, &[], mod_res_bb, &[]);

                b.switch_to_block(host_res_bb);
                b.seal_block(host_res_bb);
                let comp_h = b.ins().load(
                    types::I32,
                    MemFlagsData::trusted(),
                    state_ptr,
                    ctx.state_layout.comp_slot_offset(lidx) as i32,
                );
                let rptr_host = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::SYS_RES_MUT_PTR,
                    &[ptr_ty, types::I32, ptr_ty],
                    Some(ptr_ty),
                    ptr_ty,
                    cc,
                    &[sys_ctx, comp_h, z_ptr],
                );
                let rptr_nz = b.ins().icmp_imm_s(IntCC::NotEqual, rptr_host, 0);
                b.ins().brif(
                    rptr_nz,
                    dec_res_bb,
                    &[BlockArg::Value(rptr_host)],
                    after_nc_bb,
                    &[],
                );

                b.switch_to_block(mod_res_bb);
                b.seal_block(mod_res_bb);
                let rptr_mod = b
                    .ins()
                    .iadd_imm_s(state_ptr, ctx.layouts[lidx].mod_res_offset as i64);
                b.ins().jump(dec_res_bb, &[BlockArg::Value(rptr_mod)]);

                b.switch_to_block(dec_res_bb);
                b.seal_block(dec_res_bb);
                let rptr = b.block_params(dec_res_bb)[0];
                if sz > 0 {
                    emit_memcpy(&mut b, tmp_ptr, rptr, sz);
                }
                b.ins().store(MemFlagsData::new(), tmp_ptr, ptrs_ptr, 0);
                let dcall = b.ins().call(dec_ref, &[last_pkt, ptrs_ptr]);
                let dec_ok = b.func.dfg.inst_results(dcall)[0];
                let eq = emit_bytes_equal(&mut b, tmp_ptr, rptr, sz, ptr_ty);
                let dec_nz = b.ins().icmp_imm_s(IntCC::NotEqual, dec_ok, 0);
                let changed = b.ins().icmp_imm_s(IntCC::Equal, eq, 0);
                let do_write = b.ins().band(dec_nz, changed);
                let write_res_bb = b.create_block();
                b.ins().brif(do_write, write_res_bb, &[], after_nc_bb, &[]);

                b.switch_to_block(write_res_bb);
                b.seal_block(write_res_bb);
                if sz > 0 {
                    emit_memcpy(&mut b, rptr, tmp_ptr, sz);
                    let upd_shadow_bb = b.create_block();
                    b.ins()
                        .brif(is_host_res, after_nc_bb, &[], upd_shadow_bb, &[]);
                    b.switch_to_block(upd_shadow_bb);
                    b.seal_block(upd_shadow_bb);
                    let sptr = b
                        .ins()
                        .iadd_imm_s(state_ptr, ctx.layouts[lidx].mod_res_shadow_offset as i64);
                    emit_memcpy(&mut b, sptr, tmp_ptr, sz);
                    b.ins().jump(after_nc_bb, &[]);
                } else {
                    b.ins().jump(after_nc_bb, &[]);
                }

                b.switch_to_block(after_nc_bb);
                b.seal_block(after_nc_bb);
            } else {
                let qi = entity_q_idx;
                entity_q_idx += 1;
                let mut tmp_offsets = Vec::with_capacity(strata.len());
                let mut cur_off = 0usize;
                let mut strata_meta = Vec::with_capacity(strata.len());
                for &s_lidx in strata.iter().take(QUERY_TERM_CAP) {
                    let s_sz = ctx.layouts[s_lidx].size;
                    let s_sparse = (ctx.mir_layouts_sorted[s_lidx].component_flags
                        & BAM_COMPONENT_FLAG_SPARSE_SET)
                        != 0;
                    tmp_offsets.push(cur_off);
                    cur_off += (s_sz + 7) & !7;
                    strata_meta.push((s_sz, s_sparse));
                }
                let after_nc_bb = b.create_block();

                // Quick scan: does any packet in `0..got` target this component?
                let scan_hdr = b.create_block();
                b.append_block_param(scan_hdr, ptr_ty);
                let scan_body = b.create_block();
                let scan_next = b.create_block();
                let open_q_bb = b.create_block();
                b.ins().jump(scan_hdr, &[BlockArg::Value(z_ptr)]);

                b.switch_to_block(scan_hdr);
                let spi = b.block_params(scan_hdr)[0];
                let more = b.ins().icmp(IntCC::UnsignedLessThan, spi, got);
                b.ins().brif(more, scan_body, &[], after_nc_bb, &[]);

                b.switch_to_block(scan_body);
                b.seal_block(scan_body);
                let pkt_off = b.ins().imul_imm_s(spi, STRATA_NET_PACKET_SIZE as i64);
                let pkt_ptr = b.ins().iadd(pkts_ptr, pkt_off);
                let pkind = b.ins().load(
                    types::I8,
                    MemFlagsData::new(),
                    pkt_ptr,
                    packet_offsets::KIND as i32,
                );
                let ptgt = b.ins().load(
                    types::I64,
                    MemFlagsData::new(),
                    pkt_ptr,
                    packet_offsets::TARGET_ID as i32,
                );
                let k_ok =
                    b.ins()
                        .icmp_imm_s(IntCC::Equal, pkind, i64::from(PACKET_KIND_COMPONENT_DELTA));
                let t_ok = b.ins().icmp_imm_s(IntCC::Equal, ptgt, target_id as i64);
                let kt_ok = b.ins().band(k_ok, t_ok);
                b.ins().brif(kt_ok, open_q_bb, &[], scan_next, &[]);

                b.switch_to_block(scan_next);
                b.seal_block(scan_next);
                let spi_next = b.ins().iadd_imm_s(spi, 1);
                b.ins().jump(scan_hdr, &[BlockArg::Value(spi_next)]);
                b.seal_block(scan_hdr);

                b.switch_to_block(open_q_bb);
                b.seal_block(open_q_bb);
                let qi_v = b.ins().iconst(ptr_ty, qi as i64);
                b.ins().store(MemFlagsData::trusted(), z_ptr, q_it_out, 0);
                let eqrc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::SYS_QUERY,
                    &[ptr_ty, ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    cc,
                    &[sys_ctx, qi_v, q_it_out],
                );
                let q_it = b.ins().load(ptr_ty, MemFlagsData::trusted(), q_it_out, 0);
                let eqok = b.ins().icmp_imm_s(IntCC::Equal, eqrc, 0);
                let qit_nz = b.ins().icmp_imm_s(IntCC::NotEqual, q_it, 0);
                let q_ready = b.ins().band(eqok, qit_nz);
                let reset_bb = b.create_block();
                b.ins().brif(q_ready, reset_bb, &[], after_nc_bb, &[]);

                b.switch_to_block(reset_bb);
                b.seal_block(reset_bb);
                let _rrc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::ITER_RESET,
                    &[ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    cc,
                    &[q_it],
                );
                let chunk_hdr = b.create_block();
                b.ins().jump(chunk_hdr, &[]);

                b.switch_to_block(chunk_hdr);
                b.ins().store(MemFlagsData::trusted(), z_ptr, clen_ptr, 0);
                let has_ch = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::ITER_NEXT_CHUNK,
                    &[ptr_ty, ptr_ty],
                    Some(types::I8),
                    ptr_ty,
                    cc,
                    &[q_it, clen_ptr],
                );
                let clen = b.ins().load(ptr_ty, MemFlagsData::trusted(), clen_ptr, 0);
                let ch_nz = b.ins().icmp_imm_s(IntCC::NotEqual, has_ch, 0);
                let clen_pos = b.ins().icmp_imm_s(IntCC::UnsignedGreaterThan, clen, 0);
                let ch_ok = b.ins().band(ch_nz, clen_pos);
                let col_bb = b.create_block();
                b.ins().brif(ch_ok, col_bb, &[], after_nc_bb, &[]);

                b.switch_to_block(col_bb);
                b.seal_block(col_bb);
                let ents = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::ITER_ENTITIES,
                    &[ptr_ty],
                    Some(ptr_ty),
                    ptr_ty,
                    cc,
                    &[q_it],
                );
                let mut cols = Vec::with_capacity(strata_meta.len());
                for (si, &(_, s_sparse)) in strata_meta.iter().enumerate() {
                    let col_slot = if s_sparse {
                        api_slots::ITER_COLUMN_ROWS_MUTABLE
                    } else {
                        api_slots::ITER_COLUMN_MUTABLE_UNTRACKED
                    };
                    let term_v = b.ins().iconst(ptr_ty, si as i64);
                    let col = call_vtable(
                        &ctx.obj_mod,
                        &mut b,
                        api_ptr,
                        col_slot,
                        &[ptr_ty, ptr_ty],
                        Some(ptr_ty),
                        ptr_ty,
                        cc,
                        &[q_it, term_v],
                    );
                    cols.push(col);
                }
                let ents_nz = b.ins().icmp_imm_s(IntCC::NotEqual, ents, 0);
                let col0_nz = b.ins().icmp_imm_s(IntCC::NotEqual, cols[0], 0);
                let col_ok = b.ins().band(ents_nz, col0_nz);
                let row_hdr = b.create_block();
                b.append_block_param(row_hdr, ptr_ty);
                b.ins()
                    .brif(col_ok, row_hdr, &[BlockArg::Value(z_ptr)], chunk_hdr, &[]);

                b.switch_to_block(row_hdr);
                let row = b.block_params(row_hdr)[0];
                let row_ok = b.ins().icmp(IntCC::UnsignedLessThan, row, clen);
                let row_body = b.create_block();
                b.ins().brif(row_ok, row_body, &[], chunk_hdr, &[]);

                b.switch_to_block(row_body);
                b.seal_block(row_body);
                let ent_off = b.ins().imul_imm_s(row, 8);
                let ent_ptr = b.ins().iadd(ents, ent_off);
                let ebits = b.ins().load(types::I64, MemFlagsData::new(), ent_ptr, 0);

                // Find last packet for this entity.
                let ep_hdr = b.create_block();
                b.append_block_param(ep_hdr, ptr_ty); // pi
                b.append_block_param(ep_hdr, ptr_ty); // last_pkt
                let ep_body = b.create_block();
                let ep_apply = b.create_block();
                b.ins()
                    .jump(ep_hdr, &[BlockArg::Value(z_ptr), BlockArg::Value(z_ptr)]);

                b.switch_to_block(ep_hdr);
                let epi = b.block_params(ep_hdr)[0];
                let elast = b.block_params(ep_hdr)[1];
                let epi_ok = b.ins().icmp(IntCC::UnsignedLessThan, epi, got);
                b.ins().brif(epi_ok, ep_body, &[], ep_apply, &[]);

                b.switch_to_block(ep_body);
                b.seal_block(ep_body);
                let ep_off = b.ins().imul_imm_s(epi, STRATA_NET_PACKET_SIZE as i64);
                let ep_ptr = b.ins().iadd(pkts_ptr, ep_off);
                let ep_kind = b.ins().load(
                    types::I8,
                    MemFlagsData::new(),
                    ep_ptr,
                    packet_offsets::KIND as i32,
                );
                let ep_tgt = b.ins().load(
                    types::I64,
                    MemFlagsData::new(),
                    ep_ptr,
                    packet_offsets::TARGET_ID as i32,
                );
                let ep_ent = b.ins().load(
                    types::I64,
                    MemFlagsData::new(),
                    ep_ptr,
                    packet_offsets::ENTITY_BITS as i32,
                );
                let ek = b.ins().icmp_imm_s(
                    IntCC::Equal,
                    ep_kind,
                    i64::from(PACKET_KIND_COMPONENT_DELTA),
                );
                let et = b.ins().icmp_imm_s(IntCC::Equal, ep_tgt, target_id as i64);
                let ee = b.ins().icmp(IntCC::Equal, ep_ent, ebits);
                let et_ee = b.ins().band(et, ee);
                let ematch = b.ins().band(ek, et_ee);
                let next_elast = b.ins().select(ematch, ep_ptr, elast);
                let epi_next = b.ins().iadd_imm_s(epi, 1);
                b.ins().jump(
                    ep_hdr,
                    &[BlockArg::Value(epi_next), BlockArg::Value(next_elast)],
                );
                b.seal_block(ep_hdr);

                b.switch_to_block(ep_apply);
                b.seal_block(ep_apply);
                let row_step = b.create_block();
                let has_ep = b.ins().icmp_imm_s(IntCC::NotEqual, elast, 0);
                let get_elem_bb = b.create_block();
                b.ins().brif(has_ep, get_elem_bb, &[], row_step, &[]);

                b.switch_to_block(get_elem_bb);
                b.seal_block(get_elem_bb);
                let mut elem_ptrs = Vec::with_capacity(strata_meta.len());
                for (si, &(s_sz, s_sparse)) in strata_meta.iter().enumerate() {
                    let ep = emit_load_stratum_elem_ptr(
                        &mut b,
                        cols[si],
                        row,
                        s_sz,
                        s_sparse,
                        si > 0,
                        ptr_ty,
                        ptr_bytes,
                    );
                    elem_ptrs.push(ep);
                }
                let elem0_nz = b.ins().icmp_imm_s(IntCC::NotEqual, elem_ptrs[0], 0);
                let dec_comp_bb = b.create_block();
                b.ins().brif(elem0_nz, dec_comp_bb, &[], row_step, &[]);

                b.switch_to_block(dec_comp_bb);
                b.seal_block(dec_comp_bb);
                let mut tmp_ptrs = Vec::with_capacity(strata_meta.len());
                for (si, &(s_sz, _)) in strata_meta.iter().enumerate() {
                    let tp = if tmp_offsets[si] == 0 {
                        tmp_ptr
                    } else {
                        b.ins().iadd_imm_s(tmp_ptr, tmp_offsets[si] as i64)
                    };
                    tmp_ptrs.push(tp);
                    if si == 0 {
                        if s_sz > 0 {
                            emit_memcpy(&mut b, tp, elem_ptrs[0], s_sz);
                        }
                        b.ins().store(MemFlagsData::new(), tp, ptrs_ptr, 0);
                    } else {
                        let cp_bb = b.create_block();
                        let cp_done_bb = b.create_block();
                        b.append_block_param(cp_done_bb, ptr_ty);
                        let ep_nz = b.ins().icmp_imm_s(IntCC::NotEqual, elem_ptrs[si], 0);
                        b.ins()
                            .brif(ep_nz, cp_bb, &[], cp_done_bb, &[BlockArg::Value(z_ptr)]);
                        b.switch_to_block(cp_bb);
                        b.seal_block(cp_bb);
                        if s_sz > 0 {
                            emit_memcpy(&mut b, tp, elem_ptrs[si], s_sz);
                        }
                        b.ins().jump(cp_done_bb, &[BlockArg::Value(tp)]);
                        b.switch_to_block(cp_done_bb);
                        b.seal_block(cp_done_bb);
                        let stored_tp = b.block_params(cp_done_bb)[0];
                        b.ins().store(
                            MemFlagsData::new(),
                            stored_tp,
                            ptrs_ptr,
                            (si * ptr_bytes) as i32,
                        );
                    }
                }
                let dcall = b.ins().call(dec_ref, &[elast, ptrs_ptr]);
                let dec_ok = b.func.dfg.inst_results(dcall)[0];
                let dec_nz = b.ins().icmp_imm_s(IntCC::NotEqual, dec_ok, 0);
                let apply_changes_bb = b.create_block();
                b.ins().brif(dec_nz, apply_changes_bb, &[], row_step, &[]);

                b.switch_to_block(apply_changes_bb);
                b.seal_block(apply_changes_bb);
                for (si, &(s_sz, _)) in strata_meta.iter().enumerate() {
                    if s_sz == 0 {
                        continue;
                    }
                    let next_s_bb = b.create_block();
                    if si > 0 {
                        let cmp_s_bb = b.create_block();
                        let ep_nz = b.ins().icmp_imm_s(IntCC::NotEqual, elem_ptrs[si], 0);
                        b.ins().brif(ep_nz, cmp_s_bb, &[], next_s_bb, &[]);
                        b.switch_to_block(cmp_s_bb);
                        b.seal_block(cmp_s_bb);
                    }
                    let eq = emit_bytes_equal(&mut b, tmp_ptrs[si], elem_ptrs[si], s_sz, ptr_ty);
                    let changed = b.ins().icmp_imm_s(IntCC::Equal, eq, 0);
                    let write_s_bb = b.create_block();
                    b.ins().brif(changed, write_s_bb, &[], next_s_bb, &[]);

                    b.switch_to_block(write_s_bb);
                    b.seal_block(write_s_bb);
                    emit_memcpy(&mut b, elem_ptrs[si], tmp_ptrs[si], s_sz);
                    let si_p = b.ins().iconst(ptr_ty, si as i64);
                    let one_p = b.ins().iconst(ptr_ty, 1);
                    let _mrc = call_vtable(
                        &ctx.obj_mod,
                        &mut b,
                        api_ptr,
                        api_slots::ITER_MARK_CHANGED_RANGE,
                        &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                        Some(types::I32),
                        ptr_ty,
                        cc,
                        &[q_it, si_p, row, one_p],
                    );
                    b.ins().jump(next_s_bb, &[]);

                    b.switch_to_block(next_s_bb);
                    b.seal_block(next_s_bb);
                }
                b.ins().jump(row_step, &[]);

                b.switch_to_block(row_step);
                b.seal_block(row_step);
                let row_next = b.ins().iadd_imm_s(row, 1);
                b.ins().jump(row_hdr, &[BlockArg::Value(row_next)]);
                b.seal_block(row_hdr);
                b.seal_block(chunk_hdr);

                b.switch_to_block(after_nc_bb);
                b.seal_block(after_nc_bb);
            }
        }

        let full_batch = b.ins().icmp_imm_s(IntCC::Equal, got, batch_cap as i64);
        b.ins().brif(full_batch, batch_hdr_bb, &[], ret_bb, &[]);

        b.seal_all_blocks();
        b.finalize(ctx.fe_cfg);
    }
    define_fn_checked(
        &mut ctx.obj_mod,
        fid,
        &mut fn_ctx,
        &format!("strata_sys_net_rx_{chunk_idx}"),
    )
}

fn emit_load_stratum_elem_ptr(
    b: &mut FunctionBuilder<'_>,
    col: Value,
    row: Value,
    sz: usize,
    is_sparse: bool,
    optional_null_guard: bool,
    ptr_ty: Type,
    ptr_bytes: usize,
) -> Value {
    let z_ptr = b.ins().iconst(ptr_ty, 0);
    if !optional_null_guard {
        if is_sparse {
            let r_off = b.ins().imul_imm_s(row, ptr_bytes as i64);
            let r_slot = b.ins().iadd(col, r_off);
            b.ins().load(ptr_ty, MemFlagsData::new(), r_slot, 0)
        } else {
            let e_off = b.ins().imul_imm_s(row, sz as i64);
            b.ins().iadd(col, e_off)
        }
    } else if is_sparse {
        let load_bb = b.create_block();
        let done_bb = b.create_block();
        b.append_block_param(done_bb, ptr_ty);
        let col_nz = b.ins().icmp_imm_s(IntCC::NotEqual, col, 0);
        b.ins()
            .brif(col_nz, load_bb, &[], done_bb, &[BlockArg::Value(z_ptr)]);

        b.switch_to_block(load_bb);
        b.seal_block(load_bb);
        let r_off = b.ins().imul_imm_s(row, ptr_bytes as i64);
        let r_slot = b.ins().iadd(col, r_off);
        let ep = b.ins().load(ptr_ty, MemFlagsData::new(), r_slot, 0);
        b.ins().jump(done_bb, &[BlockArg::Value(ep)]);

        b.switch_to_block(done_bb);
        b.seal_block(done_bb);
        b.block_params(done_bb)[0]
    } else {
        let col_nz = b.ins().icmp_imm_s(IntCC::NotEqual, col, 0);
        let e_off = b.ins().imul_imm_s(row, sz as i64);
        let ep = b.ins().iadd(col, e_off);
        b.ins().select(col_nz, ep, z_ptr)
    }
}

pub(super) fn emit_net_tx_system(
    ctx: &mut ModuleContext<'_>,
    entry_meta: &NetSystemChunkEntry,
    chunk: &[MirNetComponent],
    codecs: &HashMap<String, (FuncId, FuncId)>,
    chunk_idx: usize,
) -> Result<(), JitError> {
    let ptr_ty = ctx.ptr_ty;
    let ptr_bytes = ctx.ptr_bytes;
    let cc = ctx.call_conv;
    let fid = entry_meta.tx_func_id;

    let mut sig = Signature::new(cc);
    sig.params.push(AbiParam::new(ptr_ty)); // sys_ctx
    sig.params.push(AbiParam::new(ptr_ty)); // user_data (state_ptr)
    sig.returns.push(AbiParam::new(types::I32));

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
        let ok_ret = b.ins().iconst(types::I32, i64::from(FFI_OK));

        let ret_bb = b.create_block();
        let check_msg_bb = b.create_block();
        let sys_nz = b.ins().icmp_imm_s(IntCC::NotEqual, sys_ctx, 0);
        let st_nz = b.ins().icmp_imm_s(IntCC::NotEqual, state_ptr, 0);
        let entry_ok = b.ins().band(sys_nz, st_nz);
        b.ins().brif(entry_ok, check_msg_bb, &[], ret_bb, &[]);

        b.switch_to_block(ret_bb);
        b.ins().return_(&[ok_ret]);

        b.switch_to_block(check_msg_bb);
        b.seal_block(check_msg_bb);
        let api_ptr = b.ins().load(
            ptr_ty,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.api_off as i32,
        );
        let api_nz = b.ins().icmp_imm_s(IntCC::NotEqual, api_ptr, 0);
        let is_msg_v = b.ins().load(
            types::I8,
            MemFlagsData::trusted(),
            state_ptr,
            ctx.state_layout.net_pkt_is_msg_off as i32,
        );
        let msg_on = b.ins().icmp_imm_s(IntCC::NotEqual, is_msg_v, 0);
        let msg_ready = b.ins().band(api_nz, msg_on);
        let query_bb = b.create_block();
        b.ins().brif(msg_ready, query_bb, &[], ret_bb, &[]);

        b.switch_to_block(query_bb);
        b.seal_block(query_bb);
        let msg_it_slot = alloc_zero_slot(&mut b, ptr_bytes, ptr_ty);
        let msg_it_out = b.ins().stack_addr(ptr_ty, msg_it_slot, 0);
        let z_ptr = b.ins().iconst(ptr_ty, 0);
        let qrc = call_vtable(
            &ctx.obj_mod,
            &mut b,
            api_ptr,
            api_slots::SYS_QUERY,
            &[ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            cc,
            &[sys_ctx, z_ptr, msg_it_out],
        );
        let msg_it = b.ins().load(ptr_ty, MemFlagsData::trusted(), msg_it_out, 0);
        let qok = b.ins().icmp_imm_s(IntCC::Equal, qrc, 0);
        let it_nz = b.ins().icmp_imm_s(IntCC::NotEqual, msg_it, 0);
        let msg_it_ok = b.ins().band(qok, it_nz);
        let body_start_bb = b.create_block();
        b.ins().brif(msg_it_ok, body_start_bb, &[], ret_bb, &[]);

        b.switch_to_block(body_start_bb);
        b.seal_block(body_start_bb);
        let batch_cap = 64usize;
        let out_pkts_slot = alloc_zero_slot(&mut b, batch_cap * STRATA_NET_PACKET_SIZE, ptr_ty);
        let out_pkts_ptr = b.ins().stack_addr(ptr_ty, out_pkts_slot, 0);
        let out_n_var = b.declare_var(ptr_ty);
        b.def_var(out_n_var, z_ptr);

        let mut max_strata_count = 1usize;
        for nc in chunk {
            if let Ok(strata) = net_comp_stratum_lidxs(ctx, nc) {
                max_strata_count = max_strata_count.max(strata.len());
            }
        }
        let ptrs_slot = alloc_zero_slot(&mut b, max_strata_count * ptr_bytes, ptr_ty);
        let ptrs_ptr = b.ins().stack_addr(ptr_ty, ptrs_slot, 0);

        let ticks_slot = alloc_zero_slot(&mut b, structs::CHANGE_TICKS_SIZE, ptr_ty);
        let ticks_ptr = b.ins().stack_addr(ptr_ty, ticks_slot, 0);
        let col_add_slot = alloc_zero_slot(&mut b, ptr_bytes, ptr_ty);
        let col_add_out = b.ins().stack_addr(ptr_ty, col_add_slot, 0);
        let col_chg_slot = alloc_zero_slot(&mut b, ptr_bytes, ptr_ty);
        let col_chg_out = b.ins().stack_addr(ptr_ty, col_chg_slot, 0);
        let col_last_slot = alloc_zero_slot(&mut b, 4, ptr_ty);
        let col_last_out = b.ins().stack_addr(ptr_ty, col_last_slot, 0);
        let col_this_slot = alloc_zero_slot(&mut b, 4, ptr_ty);
        let col_this_out = b.ins().stack_addr(ptr_ty, col_this_slot, 0);

        let q_it_slot = alloc_zero_slot(&mut b, ptr_bytes, ptr_ty);
        let q_it_out = b.ins().stack_addr(ptr_ty, q_it_slot, 0);
        let clen_slot = alloc_zero_slot(&mut b, ptr_bytes, ptr_ty);
        let clen_ptr = b.ins().stack_addr(ptr_ty, clen_slot, 0);

        let z64 = b.ins().iconst(types::I64, 0);
        let z32 = b.ins().iconst(types::I32, 0);
        let z8 = b.ins().iconst(types::I8, 0);
        let one8 = b.ins().iconst(types::I8, 1);

        let mut entity_q_idx = 1usize;
        for nc in chunk {
            let Ok(strata) = net_comp_stratum_lidxs(ctx, nc) else {
                continue;
            };
            let lidx = strata[0];
            let Some(&(enc_fid, _)) = codecs.get(&nc.canonical_name) else {
                continue;
            };
            let enc_ref = ctx.obj_mod.declare_func_in_func(enc_fid, b.func);
            let sz = ctx.layouts[lidx].size;

            if nc.is_resource {
                let rflag = b.ins().load(
                    types::I8,
                    MemFlagsData::trusted(),
                    state_ptr,
                    ctx.state_layout.res_flag_offset(lidx) as i32,
                );
                let is_host_res = b.ins().icmp_imm_s(IntCC::Equal, rflag, 1);
                let check_res_bb = b.create_block();
                let mod_res_bb = b.create_block();
                let emit_res_bb = b.create_block();
                b.append_block_param(emit_res_bb, ptr_ty);
                b.append_block_param(emit_res_bb, types::I32);
                let after_nc_bb = b.create_block();
                b.ins()
                    .brif(is_host_res, check_res_bb, &[], mod_res_bb, &[]);

                b.switch_to_block(check_res_bb);
                b.seal_block(check_res_bb);
                zero_slot(&mut b, ticks_slot, structs::CHANGE_TICKS_SIZE, ptr_ty);
                let comp_h = b.ins().load(
                    types::I32,
                    MemFlagsData::trusted(),
                    state_ptr,
                    ctx.state_layout.comp_slot_offset(lidx) as i32,
                );
                let rptr_host = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::SYS_RES_PTR,
                    &[ptr_ty, types::I32, ptr_ty],
                    Some(ptr_ty),
                    ptr_ty,
                    cc,
                    &[sys_ctx, comp_h, ticks_ptr],
                );
                let rptr_nz = b.ins().icmp_imm_s(IntCC::NotEqual, rptr_host, 0);
                let t_chg = b.ins().load(
                    types::I32,
                    MemFlagsData::trusted(),
                    ticks_ptr,
                    structs::CHANGE_TICKS_CHANGED as i32,
                );
                let t_last = b.ins().load(
                    types::I32,
                    MemFlagsData::trusted(),
                    ticks_ptr,
                    structs::CHANGE_TICKS_LAST_RUN as i32,
                );
                let t_this = b.ins().load(
                    types::I32,
                    MemFlagsData::trusted(),
                    ticks_ptr,
                    structs::CHANGE_TICKS_THIS_RUN as i32,
                );
                let d_chg = b.ins().isub(t_this, t_chg);
                let d_last = b.ins().isub(t_this, t_last);
                let max_age = b
                    .ins()
                    .iconst(types::I32, i64::from(bamabi_sys::BAM_MAX_CHANGE_AGE));
                let chg_lt = b.ins().icmp(IntCC::UnsignedLessThan, d_chg, max_age);
                let clamped_chg = b.ins().select(chg_lt, d_chg, max_age);
                let last_lt = b.ins().icmp(IntCC::UnsignedLessThan, d_last, max_age);
                let clamped_last = b.ins().select(last_lt, d_last, max_age);
                let is_chg = b
                    .ins()
                    .icmp(IntCC::UnsignedGreaterThan, clamped_last, clamped_chg);
                let emit_res_cond = b.ins().band(rptr_nz, is_chg);
                b.ins().brif(
                    emit_res_cond,
                    emit_res_bb,
                    &[BlockArg::Value(rptr_host), BlockArg::Value(t_this)],
                    after_nc_bb,
                    &[],
                );

                b.switch_to_block(mod_res_bb);
                b.seal_block(mod_res_bb);
                if sz == 0 {
                    b.ins().jump(after_nc_bb, &[]);
                } else {
                    let rptr_mod = b
                        .ins()
                        .iadd_imm_s(state_ptr, ctx.layouts[lidx].mod_res_offset as i64);
                    let sptr_mod = b
                        .ins()
                        .iadd_imm_s(state_ptr, ctx.layouts[lidx].mod_res_shadow_offset as i64);
                    let eq = emit_bytes_equal(&mut b, rptr_mod, sptr_mod, sz, ptr_ty);
                    let changed = b.ins().icmp_imm_s(IntCC::Equal, eq, 0);
                    let mod_emit_bb = b.create_block();
                    b.ins().brif(changed, mod_emit_bb, &[], after_nc_bb, &[]);

                    b.switch_to_block(mod_emit_bb);
                    b.seal_block(mod_emit_bb);
                    emit_memcpy(&mut b, sptr_mod, rptr_mod, sz);
                    b.ins().jump(
                        emit_res_bb,
                        &[BlockArg::Value(rptr_mod), BlockArg::Value(z32)],
                    );
                }

                b.switch_to_block(emit_res_bb);
                b.seal_block(emit_res_bb);
                let src_ptr = b.block_params(emit_res_bb)[0];
                let tick_v = b.block_params(emit_res_bb)[1];
                let cur_n = b.use_var(out_n_var);
                let dst_off = b.ins().imul_imm_s(cur_n, STRATA_NET_PACKET_SIZE as i64);
                let dst_pkt = b.ins().iadd(out_pkts_ptr, dst_off);
                b.ins().store(MemFlagsData::new(), src_ptr, ptrs_ptr, 0);
                b.ins().call(enc_ref, &[ptrs_ptr, z64, tick_v, z8, dst_pkt]);
                let nxt_n = b.ins().iadd_imm_s(cur_n, 1);
                b.def_var(out_n_var, nxt_n);
                let full = b.ins().icmp_imm_s(IntCC::Equal, nxt_n, batch_cap as i64);
                let flush_bb = b.create_block();
                b.ins().brif(full, flush_bb, &[], after_nc_bb, &[]);

                b.switch_to_block(flush_bb);
                b.seal_block(flush_bb);
                let _wrc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::MSG_WRITE_BATCH,
                    &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    cc,
                    &[msg_it, z_ptr, out_pkts_ptr, nxt_n],
                );
                b.def_var(out_n_var, z_ptr);
                b.ins().jump(after_nc_bb, &[]);

                b.switch_to_block(after_nc_bb);
                b.seal_block(after_nc_bb);
            } else {
                let qi = entity_q_idx;
                entity_q_idx += 1;
                let mut strata_meta = Vec::with_capacity(strata.len());
                for &s_lidx in strata.iter().take(QUERY_TERM_CAP) {
                    let s_sz = ctx.layouts[s_lidx].size;
                    let s_sparse = (ctx.mir_layouts_sorted[s_lidx].component_flags
                        & BAM_COMPONENT_FLAG_SPARSE_SET)
                        != 0;
                    strata_meta.push((s_sz, s_sparse));
                }
                let is_soa_multi = strata_meta.len() > 1;
                let after_nc_bb = b.create_block();
                let qi_v = b.ins().iconst(ptr_ty, qi as i64);
                b.ins().store(MemFlagsData::trusted(), z_ptr, q_it_out, 0);
                let eqrc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::SYS_QUERY,
                    &[ptr_ty, ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    cc,
                    &[sys_ctx, qi_v, q_it_out],
                );
                let q_it = b.ins().load(ptr_ty, MemFlagsData::trusted(), q_it_out, 0);
                let eqok = b.ins().icmp_imm_s(IntCC::Equal, eqrc, 0);
                let qit_nz = b.ins().icmp_imm_s(IntCC::NotEqual, q_it, 0);
                let q_ready = b.ins().band(eqok, qit_nz);
                let reset_bb = b.create_block();
                b.ins().brif(q_ready, reset_bb, &[], after_nc_bb, &[]);

                b.switch_to_block(reset_bb);
                b.seal_block(reset_bb);
                let _rrc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::ITER_RESET,
                    &[ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    cc,
                    &[q_it],
                );
                let chunk_hdr = b.create_block();
                b.ins().jump(chunk_hdr, &[]);

                b.switch_to_block(chunk_hdr);
                b.ins().store(MemFlagsData::trusted(), z_ptr, clen_ptr, 0);
                let has_ch = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::ITER_NEXT_CHUNK,
                    &[ptr_ty, ptr_ty],
                    Some(types::I8),
                    ptr_ty,
                    cc,
                    &[q_it, clen_ptr],
                );
                let clen = b.ins().load(ptr_ty, MemFlagsData::trusted(), clen_ptr, 0);
                let ch_nz = b.ins().icmp_imm_s(IntCC::NotEqual, has_ch, 0);
                let clen_pos = b.ins().icmp_imm_s(IntCC::UnsignedGreaterThan, clen, 0);
                let ch_ok = b.ins().band(ch_nz, clen_pos);
                let col_bb = b.create_block();
                b.ins().brif(ch_ok, col_bb, &[], after_nc_bb, &[]);

                b.switch_to_block(col_bb);
                b.seal_block(col_bb);
                let ents = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::ITER_ENTITIES,
                    &[ptr_ty],
                    Some(ptr_ty),
                    ptr_ty,
                    cc,
                    &[q_it],
                );
                let mut cols = Vec::with_capacity(strata_meta.len());
                for (si, &(_, s_sparse)) in strata_meta.iter().enumerate() {
                    let col_slot = if s_sparse {
                        api_slots::ITER_COLUMN_ROWS_READONLY
                    } else {
                        api_slots::ITER_COLUMN_READONLY
                    };
                    let term_v = b.ins().iconst(ptr_ty, si as i64);
                    let col = call_vtable(
                        &ctx.obj_mod,
                        &mut b,
                        api_ptr,
                        col_slot,
                        &[ptr_ty, ptr_ty],
                        Some(ptr_ty),
                        ptr_ty,
                        cc,
                        &[q_it, term_v],
                    );
                    cols.push(col);
                }
                let ents_nz = b.ins().icmp_imm_s(IntCC::NotEqual, ents, 0);
                let col0_nz = b.ins().icmp_imm_s(IntCC::NotEqual, cols[0], 0);
                let col_ok = b.ins().band(ents_nz, col0_nz);

                let ticks_setup_bb = if is_soa_multi {
                    Some(b.create_block())
                } else {
                    None
                };
                let row_hdr = b.create_block();
                b.append_block_param(row_hdr, ptr_ty);
                if let Some(ts_bb) = ticks_setup_bb {
                    b.ins().brif(col_ok, ts_bb, &[], chunk_hdr, &[]);
                } else {
                    b.ins()
                        .brif(col_ok, row_hdr, &[BlockArg::Value(z_ptr)], chunk_hdr, &[]);
                }

                // For `@soa` multi-stratum TX, query per-stratum change/added tick arrays so
                // mutations in either `hot` or any `cold` stratum trigger replication.
                let mut ticks_info: Vec<(Value, Value, Value, Value, Value)> = Vec::new();
                let mut any_untracked = z8;
                if let Some(ts_bb) = ticks_setup_bb {
                    b.switch_to_block(ts_bb);
                    b.seal_block(ts_bb);
                    let ticks_fn = b.ins().load(
                        ptr_ty,
                        MemFlagsData::trusted(),
                        api_ptr,
                        (api_slots::ITER_COLUMN_TICKS * ptr_bytes) as i32,
                    );
                    let ticks_fn_nz = b.ins().icmp_imm_s(IntCC::NotEqual, ticks_fn, 0);
                    for (si, &(_, s_sparse)) in strata_meta.iter().enumerate() {
                        if s_sparse {
                            let col_nz = b.ins().icmp_imm_s(IntCC::NotEqual, cols[si], 0);
                            let inc = b.ins().select(col_nz, one8, z8);
                            any_untracked = b.ins().bor(any_untracked, inc);
                            ticks_info.push((z8, z_ptr, z_ptr, z32, z32));
                            continue;
                        }
                        let try_bb = b.create_block();
                        let done_bb = b.create_block();
                        b.append_block_param(done_bb, types::I8); // has_t
                        b.append_block_param(done_bb, ptr_ty); // add_arr
                        b.append_block_param(done_bb, ptr_ty); // chg_arr
                        b.append_block_param(done_bb, types::I32); // last_run
                        b.append_block_param(done_bb, types::I32); // this_run
                        b.append_block_param(done_bb, types::I8); // untracked_inc
                        let col_nz = b.ins().icmp_imm_s(IntCC::NotEqual, cols[si], 0);
                        let can_call = b.ins().band(ticks_fn_nz, col_nz);
                        let fallback_inc = b.ins().select(col_nz, one8, z8);
                        b.ins().brif(
                            can_call,
                            try_bb,
                            &[],
                            done_bb,
                            &[
                                BlockArg::Value(z8),
                                BlockArg::Value(z_ptr),
                                BlockArg::Value(z_ptr),
                                BlockArg::Value(z32),
                                BlockArg::Value(z32),
                                BlockArg::Value(fallback_inc),
                            ],
                        );

                        b.switch_to_block(try_bb);
                        b.seal_block(try_bb);
                        b.ins()
                            .store(MemFlagsData::trusted(), z_ptr, col_add_out, 0);
                        b.ins()
                            .store(MemFlagsData::trusted(), z_ptr, col_chg_out, 0);
                        b.ins().store(MemFlagsData::trusted(), z32, col_last_out, 0);
                        b.ins().store(MemFlagsData::trusted(), z32, col_this_out, 0);
                        let si_v = b.ins().iconst(ptr_ty, si as i64);
                        let trc = call_vtable(
                            &ctx.obj_mod,
                            &mut b,
                            api_ptr,
                            api_slots::ITER_COLUMN_TICKS,
                            &[ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                            Some(types::I32),
                            ptr_ty,
                            cc,
                            &[
                                q_it,
                                si_v,
                                col_add_out,
                                col_chg_out,
                                col_last_out,
                                col_this_out,
                            ],
                        );
                        let trc_ok = b.ins().icmp_imm_s(IntCC::Equal, trc, 0);
                        let add_arr = b
                            .ins()
                            .load(ptr_ty, MemFlagsData::trusted(), col_add_out, 0);
                        let chg_arr = b
                            .ins()
                            .load(ptr_ty, MemFlagsData::trusted(), col_chg_out, 0);
                        let last_r =
                            b.ins()
                                .load(types::I32, MemFlagsData::trusted(), col_last_out, 0);
                        let this_r =
                            b.ins()
                                .load(types::I32, MemFlagsData::trusted(), col_this_out, 0);
                        let has_t = b.ins().select(trc_ok, one8, z8);
                        let u_inc = b.ins().select(trc_ok, z8, one8);
                        b.ins().jump(
                            done_bb,
                            &[
                                BlockArg::Value(has_t),
                                BlockArg::Value(add_arr),
                                BlockArg::Value(chg_arr),
                                BlockArg::Value(last_r),
                                BlockArg::Value(this_r),
                                BlockArg::Value(u_inc),
                            ],
                        );

                        b.switch_to_block(done_bb);
                        b.seal_block(done_bb);
                        let dp = b.block_params(done_bb).to_vec();
                        any_untracked = b.ins().bor(any_untracked, dp[5]);
                        ticks_info.push((dp[0], dp[1], dp[2], dp[3], dp[4]));
                    }
                    b.ins().jump(row_hdr, &[BlockArg::Value(z_ptr)]);
                }

                b.switch_to_block(row_hdr);
                let row = b.block_params(row_hdr)[0];
                let row_ok = b.ins().icmp(IntCC::UnsignedLessThan, row, clen);
                let row_body = b.create_block();
                b.ins().brif(row_ok, row_body, &[], chunk_hdr, &[]);

                b.switch_to_block(row_body);
                b.seal_block(row_body);
                let row_step = b.create_block();

                let mut src_ptrs = Vec::with_capacity(strata_meta.len());
                for (si, &(s_sz, s_sparse)) in strata_meta.iter().enumerate() {
                    let sp = emit_load_stratum_elem_ptr(
                        &mut b,
                        cols[si],
                        row,
                        s_sz,
                        s_sparse,
                        si > 0,
                        ptr_ty,
                        ptr_bytes,
                    );
                    src_ptrs.push(sp);
                }

                let ent_off = b.ins().imul_imm_s(row, 8);
                let ent_ptr = b.ins().iadd(ents, ent_off);
                let ebits = b.ins().load(types::I64, MemFlagsData::new(), ent_ptr, 0);

                if is_soa_multi {
                    let mut should_send = any_untracked;
                    let tick_off = b.ins().imul_imm_s(row, 4);
                    let max_age = b
                        .ins()
                        .iconst(types::I32, i64::from(bamabi_sys::BAM_MAX_CHANGE_AGE));
                    for &(has_t, add_arr, chg_arr, last_r, this_r) in &ticks_info {
                        let chk_bb = b.create_block();
                        let next_bb = b.create_block();
                        b.append_block_param(next_bb, types::I8);
                        let ht_nz = b.ins().icmp_imm_s(IntCC::NotEqual, has_t, 0);
                        b.ins()
                            .brif(ht_nz, chk_bb, &[], next_bb, &[BlockArg::Value(should_send)]);

                        b.switch_to_block(chk_bb);
                        b.seal_block(chk_bb);
                        let d_last = b.ins().isub(this_r, last_r);
                        let last_lt = b.ins().icmp(IntCC::UnsignedLessThan, d_last, max_age);
                        let clamped_last = b.ins().select(last_lt, d_last, max_age);

                        let mut stratum_hit = z8;
                        for &arr in &[chg_arr, add_arr] {
                            let arr_bb = b.create_block();
                            let arr_done = b.create_block();
                            b.append_block_param(arr_done, types::I8);
                            let arr_nz = b.ins().icmp_imm_s(IntCC::NotEqual, arr, 0);
                            b.ins().brif(
                                arr_nz,
                                arr_bb,
                                &[],
                                arr_done,
                                &[BlockArg::Value(stratum_hit)],
                            );

                            b.switch_to_block(arr_bb);
                            b.seal_block(arr_bb);
                            let tp = b.ins().iadd(arr, tick_off);
                            let tv = b.ins().load(types::I32, MemFlagsData::new(), tp, 0);
                            let dt = b.ins().isub(this_r, tv);
                            let dt_lt = b.ins().icmp(IntCC::UnsignedLessThan, dt, max_age);
                            let clamped_dt = b.ins().select(dt_lt, dt, max_age);
                            let newer =
                                b.ins()
                                    .icmp(IntCC::UnsignedGreaterThan, clamped_last, clamped_dt);
                            let hit_s = b.ins().bor(stratum_hit, newer);
                            b.ins().jump(arr_done, &[BlockArg::Value(hit_s)]);

                            b.switch_to_block(arr_done);
                            b.seal_block(arr_done);
                            stratum_hit = b.block_params(arr_done)[0];
                        }
                        let upd_send = b.ins().bor(should_send, stratum_hit);
                        b.ins().jump(next_bb, &[BlockArg::Value(upd_send)]);

                        b.switch_to_block(next_bb);
                        b.seal_block(next_bb);
                        should_send = b.block_params(next_bb)[0];
                    }
                    let enc_gate_bb = b.create_block();
                    let send_nz = b.ins().icmp_imm_s(IntCC::NotEqual, should_send, 0);
                    b.ins().brif(send_nz, enc_gate_bb, &[], row_step, &[]);
                    b.switch_to_block(enc_gate_bb);
                    b.seal_block(enc_gate_bb);
                }

                let enc_row_bb = b.create_block();
                if strata_meta[0].1 {
                    let src_nz = b.ins().icmp_imm_s(IntCC::NotEqual, src_ptrs[0], 0);
                    b.ins().brif(src_nz, enc_row_bb, &[], row_step, &[]);
                } else {
                    b.ins().jump(enc_row_bb, &[]);
                }

                b.switch_to_block(enc_row_bb);
                b.seal_block(enc_row_bb);
                for (si, &sp) in src_ptrs.iter().enumerate() {
                    b.ins()
                        .store(MemFlagsData::new(), sp, ptrs_ptr, (si * ptr_bytes) as i32);
                }
                let cur_n = b.use_var(out_n_var);
                let dst_off = b.ins().imul_imm_s(cur_n, STRATA_NET_PACKET_SIZE as i64);
                let dst_pkt = b.ins().iadd(out_pkts_ptr, dst_off);
                b.ins().call(enc_ref, &[ptrs_ptr, ebits, z32, z8, dst_pkt]);
                let nxt_n = b.ins().iadd_imm_s(cur_n, 1);
                b.def_var(out_n_var, nxt_n);
                let full = b.ins().icmp_imm_s(IntCC::Equal, nxt_n, batch_cap as i64);
                let flush_bb = b.create_block();
                b.ins().brif(full, flush_bb, &[], row_step, &[]);

                b.switch_to_block(flush_bb);
                b.seal_block(flush_bb);
                let _wrc = call_vtable(
                    &ctx.obj_mod,
                    &mut b,
                    api_ptr,
                    api_slots::MSG_WRITE_BATCH,
                    &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
                    Some(types::I32),
                    ptr_ty,
                    cc,
                    &[msg_it, z_ptr, out_pkts_ptr, nxt_n],
                );
                b.def_var(out_n_var, z_ptr);
                b.ins().jump(row_step, &[]);

                b.switch_to_block(row_step);
                b.seal_block(row_step);
                let row_next = b.ins().iadd_imm_s(row, 1);
                b.ins().jump(row_hdr, &[BlockArg::Value(row_next)]);
                b.seal_block(row_hdr);
                b.seal_block(chunk_hdr);

                b.switch_to_block(after_nc_bb);
                b.seal_block(after_nc_bb);
            }
        }

        let rem_n = b.use_var(out_n_var);
        let rem_pos = b.ins().icmp_imm_s(IntCC::UnsignedGreaterThan, rem_n, 0);
        let final_flush_bb = b.create_block();
        b.ins().brif(rem_pos, final_flush_bb, &[], ret_bb, &[]);

        b.switch_to_block(final_flush_bb);
        let _wrc = call_vtable(
            &ctx.obj_mod,
            &mut b,
            api_ptr,
            api_slots::MSG_WRITE_BATCH,
            &[ptr_ty, ptr_ty, ptr_ty, ptr_ty],
            Some(types::I32),
            ptr_ty,
            cc,
            &[msg_it, z_ptr, out_pkts_ptr, rem_n],
        );
        b.ins().jump(ret_bb, &[]);

        b.seal_all_blocks();
        b.finalize(ctx.fe_cfg);
    }
    define_fn_checked(
        &mut ctx.obj_mod,
        fid,
        &mut fn_ctx,
        &format!("strata_sys_net_tx_{chunk_idx}"),
    )
}
