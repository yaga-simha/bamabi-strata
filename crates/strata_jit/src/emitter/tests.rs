use super::*;

/// Verifies wire `AccessMode` mappings match `bamabi_sys` constants.
#[test]
fn access_mode_wire_discriminants_match_bamabi_sys() {
    assert_eq!(access_mode_u32(TermAccessMode::Read), AccessMode::READ.0);
    assert_eq!(access_mode_u32(TermAccessMode::Write), AccessMode::WRITE.0);
    assert_eq!(
        access_mode_u32(TermAccessMode::SelectiveWrite),
        AccessMode::WRITE.0
    );
    assert_eq!(
        access_mode_u32(TermAccessMode::OptionalRead),
        AccessMode::OPTIONAL_READ.0
    );
    assert_eq!(
        access_mode_u32(TermAccessMode::OptionalWrite),
        AccessMode::OPTIONAL_WRITE.0
    );
    assert_eq!(
        access_mode_u32(TermAccessMode::With),
        AccessMode::FILTER_ONLY.0
    );
    assert_eq!(
        access_mode_u32(TermAccessMode::Without),
        AccessMode::WITHOUT.0
    );
    assert_eq!(access_mode_u32(TermAccessMode::Allow), AccessMode::ALLOW.0);
    assert_eq!(access_mode_u32(TermAccessMode::Has), AccessMode::HAS.0);
    assert_eq!(
        access_mode_u32(TermAccessMode::RemovedRead),
        AccessMode::REMOVED_READ.0
    );
    assert_eq!(
        access_mode_u32(TermAccessMode::ResRead),
        AccessMode::RESOURCE_READ.0
    );
    assert_eq!(
        access_mode_u32(TermAccessMode::ResWrite),
        AccessMode::RESOURCE_WRITE.0
    );
    assert_eq!(
        access_mode_u32(TermAccessMode::StreamRead),
        AccessMode::MESSAGE_READ.0
    );
    assert_eq!(
        access_mode_u32(TermAccessMode::StreamWrite),
        AccessMode::MESSAGE_WRITE.0
    );
    assert_eq!(
        AccessMode::FILTER_ONLY.0,
        bamabi_sys::AccessMode::FILTER_ONLY.0
    );
}

#[test]
fn bare_schedule_target_strips_multi_module_prefixes_and_preserves_host() {
    assert_eq!(
        bare_schedule_target("genres::metroidvania::MetroidvaniaFrame"),
        "MetroidvaniaFrame"
    );
    assert_eq!(bare_schedule_target("foo::bar"), "bar");
    assert_eq!(bare_schedule_target("host::PreUpdate"), "host::PreUpdate");
    assert_eq!(bare_schedule_target("Movement"), "Movement");
}

#[test]
fn find_res_access_in_hir_matches_generic_res_call_expression() {
    let call_expr = HirExpr::Call(HirCall {
        receiver: None,
        callee: "res".to_string(),
        generic_args: vec!["SimClock".to_string()],
        args: Vec::new(),
        arg_names: Vec::new(),
        ty: Ty::Unknown,
    });
    let field_expr = HirExpr::Field {
        base: Box::new(call_expr),
        field: "hitstop_rem".to_string(),
        ty: Ty::F32,
    };
    assert_eq!(
        find_res_access_in_hir(&field_expr),
        Some(("SimClock".to_string(), "hitstop_rem".to_string()))
    );
}

#[test]
fn metroidvania_obj_query_reuse_and_jit_emit_succeed() {
    let src = include_str!("../../../../fixtures/cookbooks/03_metroidvania_core.strata");
    let analyzed = strata_sema::analyze_source("03_metroidvania_core.strata", src);
    assert!(
        analyzed.ok(),
        "03_metroidvania_core diagnostics: {:?}",
        analyzed.diagnostics
    );

    let mir = strata_mir::lower_to_mir(&analyzed);
    assert!(mir.objects.iter().any(|o| o.name == "PlayerHero"));
    assert!(
        mir.functions
            .iter()
            .any(|f| f.name == "sample_platformer_inputs")
    );

    let opts = JitCompileOptions {
        out_dir: std::env::temp_dir(),
        module_stem: "test_03_mv".into(),
        opt_level: JitOptLevel::Speed,
    };
    let artifact = emit_pic_object(&mir, &opts).expect("03_metroidvania_core JIT should emit");
    assert!(!artifact.object_bytes.is_empty());
}

#[test]
fn rain_swarm_indexed_spawn_batch_emits_pic_object() {
    let src = include_str!("../../../../fixtures/cookbooks/01_rain_swarm.strata");
    let analyzed = strata_sema::analyze_source("01_rain_swarm.strata", src);
    assert!(
        analyzed.ok(),
        "01_rain_swarm diagnostics: {:?}",
        analyzed.diagnostics
    );
    let mir = strata_mir::lower_to_mir(&analyzed);
    let has_spawn_batch_begin = mir.functions.iter().any(|f| {
        f.blocks.iter().any(|b| {
            b.stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::SpawnBatchBegin { .. }))
        })
    });
    assert!(has_spawn_batch_begin);
    let opts = JitCompileOptions {
        out_dir: std::env::temp_dir(),
        module_stem: "test_01_rain".into(),
        opt_level: JitOptLevel::Speed,
    };
    let artifact = emit_pic_object(&mir, &opts).expect("01_rain_swarm JIT should emit");
    assert!(!artifact.object_bytes.is_empty());
}

#[test]
fn subword_field_store_narrowing_emits_cleanly() {
    assert_eq!(mir_type_from_ty(&Ty::GraceWindow), MirType::F32);
    let src = r#"
module test_subword;
component Flags { count: u8 = 0, pad_u8: u8 = 0, armed: bool = true }
sys set_count() {
for f in query(fl: &mut Flags) {
    f.fl.count = 1;
}
}
"#;
    let analyzed = strata_sema::analyze_source("test_subword.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = strata_mir::lower_to_mir(&analyzed);
    let opts = JitCompileOptions {
        out_dir: std::env::temp_dir(),
        module_stem: "test_subword".into(),
        opt_level: JitOptLevel::Speed,
    };
    let artifact = emit_pic_object(&mir, &opts).expect("subword JIT should emit");
    assert!(!artifact.object_bytes.is_empty());
}

#[test]
fn eval_const_hir_expr_wrapping_neg_and_binop_handles_i64_min() {
    let enums = HashMap::new();
    let consts = HashMap::new();
    let neg_i32_min = HirExpr::Unary {
        op: HirUnOp::Neg,
        expr: Box::new(HirExpr::IntLit {
            value: 2_147_483_648,
            ty: Ty::I64,
        }),
        ty: Ty::I64,
    };
    assert_eq!(
        eval_const_hir_expr(&neg_i32_min, &enums, &consts),
        Some(MirConstVal::Int(-2_147_483_648))
    );

    let neg_i64_min = HirExpr::Unary {
        op: HirUnOp::Neg,
        expr: Box::new(HirExpr::IntLit {
            value: i64::MIN,
            ty: Ty::I64,
        }),
        ty: Ty::I64,
    };
    assert_eq!(
        eval_const_hir_expr(&neg_i64_min, &enums, &consts),
        Some(MirConstVal::Int(i64::MIN))
    );

    let div_i64_min_neg1 = HirExpr::Binary {
        op: HirBinOp::Div,
        lhs: Box::new(HirExpr::IntLit {
            value: i64::MIN,
            ty: Ty::I64,
        }),
        rhs: Box::new(HirExpr::IntLit {
            value: -1,
            ty: Ty::I64,
        }),
        ty: Ty::I64,
    };
    assert_eq!(
        eval_const_hir_expr(&div_i64_min_neg1, &enums, &consts),
        None
    );
}

#[test]
fn eval_const_hir_expr_handles_ivec_uvec_and_negative_constructors() {
    let enums = HashMap::new();
    let consts = HashMap::new();
    let analyzed = strata_sema::analyze_source("dummy.strata", "module test::dummy;");
    let dummy_mir = strata_mir::lower_to_mir(&analyzed);

    let ivec2_expr = HirExpr::Call(HirCall {
        receiver: None,
        callee: "ivec2".to_string(),
        generic_args: Vec::new(),
        args: vec![
            HirExpr::Unary {
                op: HirUnOp::Neg,
                expr: Box::new(HirExpr::IntLit {
                    value: 1,
                    ty: Ty::I32,
                }),
                ty: Ty::I32,
            },
            HirExpr::Unary {
                op: HirUnOp::Neg,
                expr: Box::new(HirExpr::IntLit {
                    value: 2,
                    ty: Ty::I32,
                }),
                ty: Ty::I32,
            },
        ],
        arg_names: Vec::new(),
        ty: Ty::IVec2,
    });
    let cv_iv2 = eval_const_hir_expr(&ivec2_expr, &enums, &consts).expect("ivec2");
    assert_eq!(cv_iv2, MirConstVal::Vec2([-1.0, -2.0]));
    let mut buf2 = [0u8; 8];
    write_const_val_to_buf_at(&mut buf2, 0, 8, &Ty::IVec2, &cv_iv2, &dummy_mir);
    assert_eq!(&buf2[0..4], &(-1i32).to_le_bytes());
    assert_eq!(&buf2[4..8], &(-2i32).to_le_bytes());

    let ivec3_expr = HirExpr::Call(HirCall {
        receiver: None,
        callee: "ivec3".to_string(),
        generic_args: Vec::new(),
        args: vec![
            HirExpr::IntLit {
                value: -10,
                ty: Ty::I32,
            },
            HirExpr::IntLit {
                value: 20,
                ty: Ty::I32,
            },
            HirExpr::Unary {
                op: HirUnOp::Neg,
                expr: Box::new(HirExpr::IntLit {
                    value: 30,
                    ty: Ty::I32,
                }),
                ty: Ty::I32,
            },
        ],
        arg_names: Vec::new(),
        ty: Ty::IVec3,
    });
    let cv_iv3 = eval_const_hir_expr(&ivec3_expr, &enums, &consts).expect("ivec3");
    assert_eq!(cv_iv3, MirConstVal::Vec3([-10.0, 20.0, -30.0]));
    let mut buf3 = [0u8; 12];
    write_const_val_to_buf_at(&mut buf3, 0, 12, &Ty::IVec3, &cv_iv3, &dummy_mir);
    assert_eq!(&buf3[0..4], &(-10i32).to_le_bytes());
    assert_eq!(&buf3[4..8], &(20i32).to_le_bytes());
    assert_eq!(&buf3[8..12], &(-30i32).to_le_bytes());

    let uvec2_expr = HirExpr::Call(HirCall {
        receiver: None,
        callee: "uvec2".to_string(),
        generic_args: Vec::new(),
        args: vec![
            HirExpr::IntLit {
                value: 7,
                ty: Ty::U32,
            },
            HirExpr::IntLit {
                value: 4_000_000_000,
                ty: Ty::U32,
            },
        ],
        arg_names: Vec::new(),
        ty: Ty::UVec2,
    });
    let cv_uv2 = eval_const_hir_expr(&uvec2_expr, &enums, &consts).expect("uvec2");
    let mut buf_uv2 = [0u8; 8];
    write_const_val_to_buf_at(&mut buf_uv2, 0, 8, &Ty::UVec2, &cv_uv2, &dummy_mir);
    assert_eq!(&buf_uv2[0..4], &7u32.to_le_bytes());
    assert_eq!(&buf_uv2[4..8], &4_000_000_000u32.to_le_bytes());
}

#[test]
fn spatial_resource_param_alias_resolves_in_emit_pic_object() {
    let src = r#"
module test::spatial_alias;

component Pos2 { xy: vec2 = vec2(0.0, 0.0) }
component OutHit { count: u32 = 0 }

spatial_grid Grid2D(cell_size: 4.0_m, bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m), capacity: 32) over Pos2 by Pos2.xy;
spatial_history Hist3D(frames: 4, cell_size: 4.0_m, bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m), capacity: 32) over Pos2 by Pos2.xy;

sys scan_alias(g: &res Grid2D, h: &res Hist3D) {
    let mut c: u32 = 0;
    for _hit in g.query_disc(vec2(0.0, 0.0), 5.0_m) {
        c += 1;
    }
    for _sh in h.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(8.0, 0.0, 0.0)) {
        c += 1;
    }
    for row in query(o: &mut OutHit) {
        row.o.count = c;
    }
}

schedule FixedUpdate { scan_alias }
"#;
    let analyzed = strata_sema::analyze_source("spatial_alias.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = strata_mir::lower_to_mir(&analyzed);
    let opts = JitCompileOptions {
        out_dir: std::env::temp_dir(),
        module_stem: "test_spatial_alias".into(),
        opt_level: JitOptLevel::Speed,
    };
    let artifact = emit_pic_object(&mir, &opts).expect("spatial alias JIT should emit");
    assert!(!artifact.object_bytes.is_empty());
}

#[test]
fn zst_tag_schema_fingerprint_matches_compute_wire_identity() {
    let src = r#"
module parity::spatial_csr @version(1.0.0);

component Vault {
    gold: i32 = 100,
}

tag Target2D;

object Unit {
    Vault { gold: 100 },
    Target2D {},
}

sys step() {
    for row in query(v: &mut Vault) {
        row.v.gold += 1;
    }
}

schedule FixedUpdate { step }
"#;
    let analyzed = strata_sema::analyze_source("zst_tag_fp.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = strata_mir::lower_to_mir(&analyzed);

    let (expected_uuid, expected_fp) = strata_sema::layout::compute_wire_identity(
        "parity::spatial_csr::Target2D",
        0,
        1,
        0,
        true,
        &[],
    );

    let layouts = collect_all_layouts_with_zst_tags(&mir);
    let tag_layout = layouts
        .iter()
        .find(|l| l.canonical_name == "parity::spatial_csr::Target2D")
        .expect("ZST tag layout should be synthesized");
    assert_eq!(tag_layout.size, 0);
    assert_eq!(tag_layout.align, 1);
    assert!(tag_layout.is_abi_pod);
    assert_eq!(tag_layout.component_flags, 0);
    assert_eq!(tag_layout.uuid_bytes, *expected_uuid.as_bytes());
    assert_eq!(tag_layout.schema_fingerprint, expected_fp);
    assert_ne!(
        tag_layout.schema_fingerprint,
        fnv1a_64_str("parity::spatial_csr::Target2D"),
        "ZST tag schema_fingerprint must use compute_wire_identity, not raw fnv1a_64_str"
    );

    let opts = JitCompileOptions {
        out_dir: std::env::temp_dir(),
        module_stem: "test_zst_tag_fp".into(),
        opt_level: JitOptLevel::Speed,
    };
    let artifact = emit_pic_object(&mir, &opts).expect("ZST tag JIT should emit");
    assert!(
        artifact
            .object_bytes
            .windows(8)
            .any(|w| w == expected_fp.to_le_bytes()),
        "emitted PIC object must embed canonical ZST tag schema_fingerprint"
    );
}

#[test]
fn param_set_group_assigns_connected_components_and_respects_disjoint_filters() {
    let src = r#"
module test::pset_unit @version(1.0.0);

component Actor { alive: bool = true, hp: f32 = 100.0 }
component CompA { x: f32 = 0.0 }
component CompB { y: f32 = 0.0 }
component Marker { tag_val: u32 = 0 }
tag TagA;

@sparse
task ProcessOrder(target: Ref<Actor>, extra: Ref<Marker>)
on (a: &Actor)
{
    if a.alive {
        if let Some(t) = query_one(tgt: &mut Actor).on(target) {
            if t.tgt.alive {
                t.tgt.hp -= 10.0;
            }
        }
        if let Some(m) = query_one(mk: &Marker).on(extra) {
            let _ = m.mk.tag_val;
        }
    }
    yield_tick;
}

@sparse
task TransitiveTask(e1: Ref<Actor>, e2: Ref<CompB>)
on (a: &Actor, b: &mut CompB)
{
    if a.alive {
        if let Some(t) = query_one(tgt: &mut Actor).on(e1) {
            t.tgt.hp -= 5.0;
        }
        if let Some(rb) = query_one(bb: &CompB).on(e2) {
            b.y += rb.bb.y;
        }
    }
    yield_tick;
}

sys disjoint_filters() {
    for r in query(a: &mut CompA).with<TagA>() { r.a.x += 1.0; }
    for r in query(a: &CompA).without<TagA>() { let _ = r.a.x; }
}

sys readonly_shared() {
    for r in query(a: &CompA) { let _ = r.a.x; }
    for r in query(a: &CompA) { let _ = r.a.x; }
}
"#;
    let analyzed = strata_sema::analyze_source("pset_unit.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = strata_mir::lower_to_mir(&analyzed);

    let triple = target_lexicon::Triple::host();
    let mut flag_builder = cranelift_codegen::settings::builder();
    flag_builder.set("is_pic", "true").unwrap();
    let isa = cranelift_codegen::isa::lookup(triple.clone())
        .unwrap()
        .finish(cranelift_codegen::settings::Flags::new(flag_builder))
        .unwrap();
    let fe_cfg = isa.frontend_config();
    let call_conv = isa.default_call_conv();
    let ptr_ty = Type::triple_pointer_type(&triple);
    let ptr_bytes = usize::from(fe_cfg.pointer_bytes());
    let obj_builder = cranelift_object::ObjectBuilder::new(
        isa,
        "pset_unit",
        cranelift_module::default_libcall_names(),
    )
    .unwrap();
    let obj_mod = ObjectModule::new(obj_builder);
    let ctx = build_module_context(&mir, obj_mod, triple, ptr_ty, ptr_bytes, call_conv, fe_cfg)
        .expect("build_module_context");

    let find_sys = |name: &str| -> &SystemRegistrationEntry {
        ctx.systems
            .iter()
            .find(|s| ctx.mir.functions[s.fn_idx].name == name)
            .unwrap_or_else(|| panic!("missing system `{name}`"))
    };

    let task_sys = find_sys("ProcessOrder");
    assert_eq!(task_sys.wire_queries.len(), 3);
    assert_eq!(task_sys.wire_queries[0].param_set_group, 1);
    assert_eq!(task_sys.wire_queries[1].param_set_group, 1);
    assert_eq!(task_sys.wire_queries[2].param_set_group, 0);

    let tr_sys = find_sys("TransitiveTask");
    assert_eq!(tr_sys.wire_queries.len(), 3);
    assert_eq!(tr_sys.wire_queries[0].param_set_group, 1);
    assert_eq!(tr_sys.wire_queries[1].param_set_group, 1);
    assert_eq!(tr_sys.wire_queries[2].param_set_group, 1);

    let dj = find_sys("disjoint_filters");
    assert_eq!(dj.wire_queries.len(), 2);
    assert_eq!(dj.wire_queries[0].param_set_group, 0);
    assert_eq!(dj.wire_queries[1].param_set_group, 0);

    let ro = find_sys("readonly_shared");
    assert_eq!(ro.wire_queries.len(), 2);
    assert_eq!(ro.wire_queries[0].param_set_group, 0);
    assert_eq!(ro.wire_queries[1].param_set_group, 0);

    // Direct unit checks for connected components, multi-cluster grouping, `Changed`, `OptionalRead`,
    // `With`/`Without` disjointness, and resource/stream conflict rules.
    let mk_q = |terms: Vec<(usize, TermAccessMode, bool)>,
                with_filters: Vec<usize>,
                without_filters: Vec<usize>,
                extra_changed_filters: Vec<usize>| WireQuerySpec {
        term_map: (0..terms.len()).collect(),
        terms: terms
            .into_iter()
            .map(|(layout_idx, mode, changed)| WireTermSpec {
                layout_idx,
                mode,
                changed,
                added: false,
            })
            .collect(),
        with_filters,
        without_filters,
        extra_changed_filters,
        extra_added_filters: Vec::new(),
        param_set_group: 0,
    };

    let mut multi_cluster = vec![
        mk_q(
            vec![(0, TermAccessMode::Write, false)],
            vec![],
            vec![],
            vec![],
        ),
        mk_q(
            vec![
                (0, TermAccessMode::Read, false),
                (1, TermAccessMode::Write, false),
            ],
            vec![],
            vec![],
            vec![],
        ),
        mk_q(
            vec![(1, TermAccessMode::Read, false)],
            vec![],
            vec![],
            vec![],
        ),
        mk_q(
            vec![(2, TermAccessMode::Read, false)],
            vec![],
            vec![],
            vec![],
        ),
        mk_q(
            vec![(3, TermAccessMode::Write, false)],
            vec![],
            vec![],
            vec![],
        ),
        mk_q(
            vec![(3, TermAccessMode::Read, false)],
            vec![],
            vec![],
            vec![],
        ),
    ];
    assign_param_set_groups(&mut multi_cluster);
    assert_eq!(
        multi_cluster
            .iter()
            .map(|q| q.param_set_group)
            .collect::<Vec<_>>(),
        vec![1, 1, 1, 0, 2, 2]
    );

    let q_opt_ro = mk_q(
        vec![(0, TermAccessMode::OptionalRead, false)],
        vec![],
        vec![],
        vec![],
    );
    let q_mut = mk_q(
        vec![(0, TermAccessMode::Write, false)],
        vec![],
        vec![],
        vec![],
    );
    let q_with = mk_q(vec![], vec![0], vec![], vec![]);
    let q_changed = mk_q(
        vec![(0, TermAccessMode::Read, true)],
        vec![],
        vec![],
        vec![],
    );
    let q_res_ro = mk_q(
        vec![(4, TermAccessMode::ResRead, false)],
        vec![10],
        vec![],
        vec![],
    );
    let q_res_wr = mk_q(
        vec![(4, TermAccessMode::ResWrite, false)],
        vec![],
        vec![10],
        vec![],
    );
    assert!(wire_queries_conflict(&q_opt_ro, &q_mut));
    assert!(!wire_queries_conflict(&q_with, &q_mut));
    assert!(wire_queries_conflict(&q_changed, &q_mut));
    assert!(wire_queries_conflict(&q_res_ro, &q_res_wr));
}

#[test]
fn x86_64_linux_pic_compile_regression_helpers_and_narrow_casts() {
    let x64_triple: target_lexicon::Triple = "x86_64-unknown-linux-gnu".parse().expect("triple");
    if cranelift_codegen::isa::lookup(x64_triple.clone()).is_err() {
        return;
    }

    let full_mir_src = r#"
module test::full_mir_test @version(1.0.0) @deterministic;
enum WeaponKind { Sword = 0, Bow = 1 }
@sparse component Pos { xy: vec2 }
component Flags { mask: BitSet<64> }
relation ChildRel [exclusive, cascade_despawn];
table WeaponStats by WeaponKind { damage: f32, range: f32 } = {
    Sword => { damage: 25.0, range: 2.0 },
    Bow   => { damage: 15.0, range: 30.0 },
};
curve Falloff(f32 -> f32) = [(0.0, 1.0), (10.0, 0.5), (30.0, 0.0)];
fn compute_falloff(d: f32, kind: WeaponKind) -> f32 {
    let w = WeaponStats[kind].damage;
    let s = sin(d) + cos(d) + atan2(d, 1.0) + pow(2.0, 0.5) + exp(0.0) + log(1.0) + round(1.6);
    w * Falloff.sample(d) + s * 0.001
}
sys update_all() {
    for row in query(pos: &mut Pos, fl: &mut Flags) {
        let dmg = compute_falloff(length(row.pos.xy), WeaponKind::Sword);
        if dmg > 0.0 {
            row.fl.mask.set(3);
            if row.fl.mask.get(3) { row.fl.mask.clear(3); }
        }
        insert_relation<ChildRel>(row.id, row.id);
    }
}
schedule FixedUpdate { update_all }
"#;

    let helper_and_casts_src = r#"
module test::x64_reg @version(1.0.0);
component Box {
    iv3: ivec3 = ivec3(0, 0, 0),
    v3: vec3 = vec3(0.0, 0.0, 0.0),
    v4: vec4 = vec4(0.0, 0.0, 0.0, 0.0),
    si8: i8 = 0,
    su8: u8 = 0,
    si16: i16 = 0,
    su16: u16 = 0,
    f32v: f32 = 1e20_f32,
    f64v: f64 = -1e25_f64,
}
fn make_iv3(x: i32, y: i32, z: i32) -> ivec3 { return ivec3(x, y, z); }
fn make_v3(x: f32, y: f32, z: f32) -> vec3 { return vec3(x, y, z); }
fn make_v4(x: f32, y: f32, z: f32, w: f32) -> vec4 { return vec4(x, y, z, w); }
sys run_all() {
    for r in query(b: &mut Box) {
        r.b.iv3 = make_iv3(1, -2, 3);
        r.b.v3 = make_v3(1.0, 2.0, 3.0);
        r.b.v4 = make_v4(1.0, 2.0, 3.0, 4.0);
        r.b.si8 = (r.b.f32v) as i8;
        r.b.su8 = (r.b.f32v) as u8;
        r.b.si16 = (r.b.f64v) as i16;
        r.b.su16 = (r.b.f64v) as u16;
    }
}
schedule FixedUpdate { run_all }
"#;

    let net_subword_src = r#"
module test::x64_net_subword @version(1.0.0);
@net(reliable, channel = 0)
@authority(server)
component SubNet {
    @quantize(min = -10.0, max = 10.0, bits = 8)
    a: i8 = 0,
    @quantize(min = 0.0, max = 100.0, bits = 8)
    b: u8 = 0,
    @quantize(min = -100.0, max = 100.0, bits = 12)
    c: i16 = 0,
    @quantize(min = 0.0, max = 1000.0, bits = 12)
    d: u16 = 0,
}
schedule FixedUpdate {}
"#;

    let tmp = tempfile::tempdir().expect("tempdir");
    for (name, src) in [
        ("full_mir_test", full_mir_src),
        ("helper_and_casts", helper_and_casts_src),
        ("net_subword", net_subword_src),
    ] {
        let sema = strata_sema::analyze_source(name, src);
        assert!(sema.ok(), "{name} sema: {:?}", sema.diagnostics);
        let mir = strata_mir::lower_to_mir(&sema);
        let opts = JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: name.to_owned(),
            opt_level: JitOptLevel::Speed,
        };
        let art = emit_pic_object_for_triple(&mir, &opts, x64_triple.clone())
            .unwrap_or_else(|e| panic!("{name} x86_64 PIC emit failed: {e}"));
        assert!(!art.object_bytes.is_empty());
    }
}

#[test]
fn schedule_topology_avoids_seq_static_edges_and_honors_modifiers_added_and_stream() {
    let src = r#"
module test::sw_eq_unit @version(1.0.0);

component Tag { v: i32 = 0 }
stream Ping { code: u32 }

sys f_a() {}
sys f_b() {}
sys s_a() {}
sys s_b() {}
sys s_c() {}
sys m1() {}
sys m2() {}
sys p1() {}
sys p2() {}
sys scan_added() {
    for _r in query(t: &Tag).added<Tag>() {}
}

schedule Update {
    seq Main { f_a, f_b }
    seq Outer { s_a, seq Inner { s_b, s_c } }
    seq Wrap {
        m2 after(m1)
        m1
        par S2 after(S1) { p2 }
        par S1 { p1 }
    }
    seq_weak WeakSeq {
        par WA { scan_added }
        par WB { scan_added }
    }
}
"#;
    let sema = strata_sema::analyze_source("sw_eq_unit.strata", src);
    assert!(sema.ok(), "sema: {:?}", sema.diagnostics);
    let mir = strata_mir::lower_to_mir(&sema);

    let triple = target_lexicon::Triple::host();
    let isa_b = cranelift_codegen::isa::lookup(triple.clone()).expect("host isa");
    let isa = isa_b
        .finish(cranelift_codegen::settings::Flags::new(
            cranelift_codegen::settings::builder(),
        ))
        .unwrap();
    let fe_cfg = isa.frontend_config();
    let call_conv = isa.default_call_conv();
    let ptr_ty = Type::triple_pointer_type(&triple);
    let ptr_bytes = usize::from(fe_cfg.pointer_bytes());
    let obj_builder = cranelift_object::ObjectBuilder::new(
        isa,
        "sw_eq_unit",
        cranelift_module::default_libcall_names(),
    )
    .unwrap();
    let obj_mod = ObjectModule::new(obj_builder);
    let ctx = build_module_context(&mir, obj_mod, triple, ptr_ty, ptr_bytes, call_conv, fe_cfg)
        .expect("build_module_context");

    let find_sys = |name: &str| -> &SystemRegistrationEntry {
        ctx.systems
            .iter()
            .find(|s| ctx.mir.functions[s.fn_idx].name == name)
            .unwrap_or_else(|| panic!("missing system `{name}`"))
    };

    // BUG-SW-02b: direct sibling leaves in `seq Main` / `seq Inner` must NOT bake immutable static `after`.
    assert!(find_sys("f_b").after_names.is_empty());
    assert!(
        !find_sys("s_c")
            .after_names
            .contains(&find_sys("s_b").name_data_id)
    );

    // BUG-SW-07c: `m2 after(m1), m1` in `seq Wrap` orders `m1` ahead of `m2` (`sched_order`) with no cycle,
    // and `par S2 after(S1)` populates `after_set_indices` / `before_set_indices`.
    let sym_m1 = find_sys("m1");
    let sym_m2 = find_sys("m2");
    assert!(sym_m1.sched_order < sym_m2.sched_order);
    assert_eq!(sym_m2.after_names, vec![sym_m1.name_data_id]);

    assert!(ctx.schedule_sets.iter().any(|s| {
        (s.flags & SCHEDULE_SET_FLAG_BEFORE_WEAK) != 0 && !s.before_set_indices.is_empty()
    }));
    assert!(ctx.schedule_sets.iter().any(|s| {
        (s.flags & SCHEDULE_SET_FLAG_AFTER_WEAK) != 0 && !s.after_set_indices.is_empty()
    }));

    // EQ-07: `.added<Tag>()` propagates into `WireTermSpec::added` or `extra_added_filters`.
    let sa = find_sys("scan_added");
    assert!(
        sa.wire_queries
            .iter()
            .any(|q| q.terms.iter().any(|t| t.added) || !q.extra_added_filters.is_empty()),
        "expected added filter on scan_added query"
    );

    // EQ-02 / GF-14: standalone `stream` layout exists and marks `SchemaItemKind::Stream`.
    let ping_layout = ctx
        .mir_layouts_sorted
        .iter()
        .find(|l| l.canonical_name.ends_with("::Ping"))
        .expect("Ping stream layout");
    assert_eq!(
        ping_layout.item_kind,
        strata_sema::layout::SchemaItemKind::Stream
    );
}
