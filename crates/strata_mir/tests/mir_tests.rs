use strata_mir::{Inst, Terminator, lower_to_mir, verify_mir};
use strata_sema::analyze_source;
use strata_sema::hir::HirScheduleGroup;

const COOKBOOKS: [(&str, &str); 6] = [
    (
        "01_rain_swarm.strata",
        include_str!("../../../fixtures/cookbooks/01_rain_swarm.strata"),
    ),
    (
        "02_soa_and_ticks.strata",
        include_str!("../../../fixtures/cookbooks/02_soa_and_ticks.strata"),
    ),
    (
        "03_metroidvania_core.strata",
        include_str!("../../../fixtures/cookbooks/03_metroidvania_core.strata"),
    ),
    (
        "04_cozy_valley.strata",
        include_str!("../../../fixtures/cookbooks/04_cozy_valley.strata"),
    ),
    (
        "05_soulslike_combat.strata",
        include_str!("../../../fixtures/cookbooks/05_soulslike_combat.strata"),
    ),
    (
        "06_battle_royale_server.strata",
        include_str!("../../../fixtures/cookbooks/06_battle_royale_server.strata"),
    ),
];

#[test]
fn all_cookbooks_lower_and_verify_end_to_end() {
    for (name, src) in COOKBOOKS {
        let sema = analyze_source(name, src);
        assert!(sema.ok(), "{name} sema errors: {:#?}", sema.diagnostics);

        let mir = lower_to_mir(&sema);
        verify_mir(&mir).unwrap_or_else(|errs| panic!("{name} MIR verification failed: {errs:#?}"));
        assert!(
            !mir.functions.is_empty(),
            "{name} lowered zero MIR functions"
        );
    }
}

#[test]
fn pass_optional_split_hoists_chunk_presence_branch() {
    let sema = analyze_source("05_soulslike_combat.strata", COOKBOOKS[4].1);
    let mir = lower_to_mir(&sema);
    let f = mir
        .functions
        .iter()
        .find(|f| f.name == "on_weapon_strike")
        .expect("on_weapon_strike");

    let has_opt_check = f.blocks.iter().any(|b| {
        b.stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::OptionalChunkIsPresent { .. }))
    });
    assert!(has_opt_check, "expected OptionalChunkIsPresent");

    // Chunked optional query splits real row-loop CFG into `opt_present_*` and `opt_absent_*`.
    let chunked_src = r#"
module test::opt_chunk @version(1.0.0);
component Health { hp: f32 = 100.0 }
component Shield { cap: f32 = 50.0 }
sys apply_tick() {
    for row in query(h: &mut Health, s: ?&Shield) {
        if let Some(sh) = row.s {
            row.h.hp += sh.cap;
        } else {
            row.h.hp -= 1.0;
        }
    }
}
"#;
    let c_sema = analyze_source("opt_chunk.strata", chunked_src);
    assert!(c_sema.ok(), "{:?}", c_sema.diagnostics);
    let c_mir = lower_to_mir(&c_sema);
    verify_mir(&c_mir).expect("chunked optional CFG must verify");
    let cf = c_mir
        .functions
        .iter()
        .find(|fnm| fnm.name == "apply_tick")
        .expect("apply_tick");
    assert!(
        cf.blocks
            .iter()
            .any(|b| b.label.starts_with("opt_present_"))
            && cf.blocks.iter().any(|b| b.label.starts_with("opt_absent_")),
        "expected specialized opt_present_* / opt_absent_* basic blocks"
    );
}

#[test]
fn pass_tick_coalesce_emits_untracked_write_and_range_flush() {
    let sema = analyze_source("02_soa_and_ticks.strata", COOKBOOKS[1].1);
    let mir = lower_to_mir(&sema);
    let f = mir
        .functions
        .iter()
        .find(|f| f.name == "clamp_overheated_drones")
        .expect("clamp_overheated_drones");

    let stmts: Vec<_> = f.blocks.iter().flat_map(|b| &b.stmts).collect();
    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::IterColWriteUntracked { .. })),
        "expected Slot 14 IterColWriteUntracked"
    );
    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::DirtyRunInit { .. })),
        "expected DirtyRunInit"
    );
    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::DirtyRunRecordRow { .. })),
        "expected DirtyRunRecordRow"
    );
    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::IterMarkChangedRange { .. })),
        "expected Slot 15 IterMarkChangedRange"
    );
}

#[test]
fn pass_state_machines_synthesizes_timeline_task_and_fsm() {
    let mv = lower_to_mir(&analyze_source(
        "03_metroidvania_core.strata",
        COOKBOOKS[2].1,
    ));
    verify_mir(&mv).expect("metroidvania MIR must verify");
    let tl = mv
        .functions
        .iter()
        .find(|f| f.name == "BladeSlash")
        .expect("BladeSlash timeline tick");
    assert!(
        tl.blocks.iter().flat_map(|b| &b.stmts).any(|s| matches!(
            s.inst,
            Inst::TimelineAdvance {
                rate_hz: 120,
                duration_frames: 24,
                ..
            }
        )),
        "expected TimelineAdvance in BladeSlash CFG"
    );

    let task = mv
        .functions
        .iter()
        .find(|f| f.name == "AirDashTask")
        .expect("AirDashTask coroutine tick");
    assert!(
        task.blocks
            .iter()
            .any(|b| matches!(b.terminator, Terminator::Switch { .. })),
        "expected __pc Switch dispatcher in AirDashTask CFG"
    );
    assert!(task.blocks.iter().any(|b| b.label == "abort_cleanup"));

    let cozy = lower_to_mir(&analyze_source("04_cozy_valley.strata", COOKBOOKS[3].1));
    verify_mir(&cozy).expect("cozy_valley MIR must verify");
    let fsm = cozy
        .functions
        .iter()
        .find(|f| f.name == "VillagerRoutine")
        .expect("VillagerRoutine fsm");
    assert!(
        fsm.blocks
            .iter()
            .flat_map(|b| &b.stmts)
            .any(|s| matches!(s.inst, Inst::FsmDispatch { .. })),
        "expected FsmDispatch in VillagerRoutine CFG"
    );
    assert!(
        fsm.blocks
            .iter()
            .any(|b| matches!(b.terminator, Terminator::Switch { .. })),
        "expected state Switch in VillagerRoutine CFG"
    );
}

fn flatten_schedule_leaves(nodes: &[HirScheduleGroup], out: &mut Vec<String>) {
    for n in nodes {
        if n.kind == "leaf" {
            out.push(n.name.clone());
        }
        flatten_schedule_leaves(&n.children, out);
    }
}

#[test]
fn pass_spatial_csr_orders_rebuild_immediately_before_earliest_reader() {
    let br = lower_to_mir(&analyze_source(
        "06_battle_royale_server.strata",
        COOKBOOKS[5].1,
    ));
    let rebuild = br
        .functions
        .iter()
        .find(|f| f.name == "PlayerHitHistory__rebuild_csr")
        .expect("PlayerHitHistory__rebuild_csr");
    assert!(
        rebuild
            .blocks
            .iter()
            .any(|b| b.label == "csr_pass1_chunk_hdr")
    );
    assert!(rebuild.blocks.iter().any(|b| b.label == "csr_prefix_sum"));
    assert!(
        rebuild
            .blocks
            .iter()
            .any(|b| b.label == "csr_pass2_chunk_hdr")
    );
    assert!(
        rebuild.blocks.iter().flat_map(|b| &b.stmts).any(|s| {
            matches!(
                s.inst,
                Inst::SpatialRebuildCsr {
                    is_history: true,
                    frames: 16,
                    ..
                }
            )
        }),
        "expected SpatialRebuildCsr instruction in 2-pass CSR rebuild CFG"
    );

    let fixed = br
        .schedules
        .iter()
        .find(|s| s.label == "FixedUpdate")
        .expect("FixedUpdate");
    let mut order = Vec::new();
    flatten_schedule_leaves(&fixed.nodes, &mut order);
    let pos_rebuild = order
        .iter()
        .position(|n| n == "PlayerHitHistory__rebuild_csr")
        .expect("rebuild in schedule");
    let pos_reader = order
        .iter()
        .position(|n| n == "simulate_ballistics")
        .expect("simulate_ballistics in schedule");
    assert!(
        pos_rebuild < pos_reader,
        "CSR rebuild must execute before simulate_ballistics: {order:?}"
    );
}

#[test]
fn pass_atomic_tx_emits_checkpoint_shadow_and_rollback() {
    let cozy = lower_to_mir(&analyze_source("04_cozy_valley.strata", COOKBOOKS[3].1));
    let f = cozy
        .functions
        .iter()
        .find(|f| f.name == "on_place_decor")
        .expect("on_place_decor");

    let stmts: Vec<_> = f.blocks.iter().flat_map(|b| &b.stmts).collect();
    assert!(stmts.iter().any(|s| matches!(s.inst, Inst::CmdCheckpoint)));
    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::ShadowWrite { .. }))
    );
    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::RequireTrue { .. }))
    );
    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::ShadowCommit { .. }))
    );
    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::CmdRollback { .. }))
    );
}

#[test]
fn pass_determinism_enforces_no_fma_and_deterministic_transcendentals() {
    let mut br = lower_to_mir(&analyze_source(
        "06_battle_royale_server.strata",
        COOKBOOKS[5].1,
    ));
    assert!(br.is_deterministic);
    for f in &br.functions {
        assert!(f.is_deterministic);
        for bb in &f.blocks {
            for st in &bb.stmts {
                match &st.inst {
                    Inst::BinOp { allow_fma, .. } => assert!(!allow_fma),
                    Inst::IntrinsicMath { deterministic, .. } => assert!(*deterministic),
                    Inst::ParForEachChunkReadonly {
                        deterministic_order,
                        ..
                    } => assert!(*deterministic_order),
                    _ => {}
                }
            }
        }
    }

    // Mutate an op to violate determinism and prove `verify_mir` rejects it.
    let target_fn = br
        .functions
        .iter_mut()
        .find(|f| {
            f.blocks
                .iter()
                .flat_map(|b| &b.stmts)
                .any(|s| matches!(s.inst, Inst::BinOp { .. }))
        })
        .expect("function with BinOp");
    for bb in &mut target_fn.blocks {
        for st in &mut bb.stmts {
            if let Inst::BinOp { allow_fma, .. } = &mut st.inst {
                *allow_fma = true;
            }
        }
    }
    assert!(verify_mir(&br).is_err());
}

#[test]
fn mir_module_populates_field_defaults_helpers_migrations_timer_tick_and_primitives() {
    use strata_mir::{MirConstVal, MirFnKind, MirVerifyError};

    // 1. Field defaults & timer tick across Metroidvania and Soulslike cookbooks
    let mv = lower_to_mir(&analyze_source(
        "03_metroidvania_core.strata",
        COOKBOOKS[2].1,
    ));
    assert_eq!(
        mv.field_defaults["genres::metroidvania::KinematicBody"]["air_dashes_left"],
        MirConstVal::Int(1)
    );
    assert_eq!(
        mv.field_defaults["genres::metroidvania::KinematicBody"]["has_air_dash"],
        MirConstVal::Bool(true)
    );
    match mv.field_defaults["genres::metroidvania::SimClock"]["dt"] {
        MirConstVal::Float(v) => assert!((v - 0.008_333_3).abs() < 1e-6, "dt={v}"),
        ref other => panic!("expected Float for SimClock.dt, got {other:?}"),
    }
    let mv_tick = mv
        .functions
        .iter()
        .find(|f| f.kind == MirFnKind::SynthesizedTimerTick)
        .expect("strata_timer_tick in metroidvania");
    assert_eq!(mv_tick.name, "strata_timer_tick");
    assert!(
        mv_tick
            .blocks
            .iter()
            .flat_map(|b| &b.stmts)
            .any(|s| matches!(s.inst, Inst::GraceTick { .. }))
    );
    let mv_fixed = mv
        .schedules
        .iter()
        .find(|s| s.label == "FixedUpdate")
        .expect("FixedUpdate");
    let mut mv_leaves = Vec::new();
    flatten_schedule_leaves(&mv_fixed.nodes, &mut mv_leaves);
    let pos_tick = mv_leaves
        .iter()
        .position(|s| s == "strata_timer_tick")
        .expect("strata_timer_tick in FixedUpdate");
    let pos_user = mv_leaves
        .iter()
        .position(|s| s == "sample_platformer_inputs")
        .expect("sample_platformer_inputs in FixedUpdate");
    assert!(
        pos_tick < pos_user,
        "strata_timer_tick must execute before user systems: {mv_leaves:?}"
    );

    let sl = lower_to_mir(&analyze_source(
        "05_soulslike_combat.strata",
        COOKBOOKS[4].1,
    ));
    assert_eq!(
        sl.field_defaults["genres::soulslike::CombatantBody::hot"]["hp"],
        MirConstVal::Float(800.0)
    );
    let sl_tick = sl
        .functions
        .iter()
        .find(|f| f.kind == MirFnKind::SynthesizedTimerTick)
        .expect("strata_timer_tick in soulslike");
    assert!(
        sl_tick
            .blocks
            .iter()
            .flat_map(|b| &b.stmts)
            .any(|s| matches!(s.inst, Inst::InputBufTick { .. }))
    );

    // 2. Helper `fn`, `migrate`, and `par reduce`
    let src = r#"
module test::full_mir @version(2.0.0);

component HealthV1 { hp: i32 }
component Health { hp: f32 = 100.0, regen: f32 = 2.5 }

fn add_regen(h: f32, r: f32) -> f32 {
    h + r
}

migrate Health from 1.0.0 to 2.0.0 (old: &HealthV1) -> Health {
    Health { hp: old.hp as f32 }
}

@par(read_only, chunk = 128)
sys sum_hp() {
    let total = for r in query(h: &Health.hp) reduce (total: sum(0.0, r.h));
    let _ = total;
}

sys heal() {
    for r in query(h: &mut Health) {
        r.h.hp = add_regen(r.h.hp, r.h.regen);
    }
}
"#;
    let sema = analyze_source("full_mir.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mut mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("full_mir should verify cleanly");

    assert_eq!(mir.fns.len(), 1);
    assert_eq!(mir.fns[0].kind, MirFnKind::HelperFn);
    assert_eq!(mir.fns[0].name, "add_regen");

    let mig_fn = mir
        .functions
        .iter()
        .find(|f| matches!(f.kind, MirFnKind::Migration { .. }))
        .expect("Migration MirFunction");
    assert!(
        mig_fn
            .blocks
            .iter()
            .flat_map(|b| &b.stmts)
            .any(|s| matches!(s.inst, Inst::MigrateSrcPtr { .. }))
            && mig_fn
                .blocks
                .iter()
                .flat_map(|b| &b.stmts)
                .any(|s| matches!(s.inst, Inst::MigrateDstPtr { .. }))
    );

    let sum_fn = mir
        .functions
        .iter()
        .find(|f| f.name == "sum_hp")
        .expect("sum_hp");
    assert!(
        sum_fn
            .blocks
            .iter()
            .flat_map(|b| &b.stmts)
            .any(|s| matches!(s.inst, Inst::ParForEachChunkReadonly { .. }))
            && sum_fn
                .blocks
                .iter()
                .flat_map(|b| &b.stmts)
                .any(|s| matches!(s.inst, Inst::ReduceInit { .. }))
            && sum_fn
                .blocks
                .iter()
                .flat_map(|b| &b.stmts)
                .any(|s| matches!(s.inst, Inst::ReduceAccum { .. }))
    );

    let heal_fn = mir
        .functions
        .iter()
        .find(|f| f.name == "heal")
        .expect("heal");
    assert!(
        heal_fn
            .blocks
            .iter()
            .flat_map(|b| &b.stmts)
            .any(|s| matches!(s.inst, Inst::Call { ref callee, .. } if callee == "add_regen"))
    );

    // 3. Negative verify_mir check on helper fn invalid local
    mir.fns[0].blocks[0].stmts.push(strata_mir::MirStmt {
        dst: None,
        inst: Inst::RequireTrue {
            cond: strata_mir::LocalId(999),
        },
    });
    let errs = verify_mir(&mir).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| matches!(e, MirVerifyError::InvalidLocalRef { local: 999, .. }))
    );
}
