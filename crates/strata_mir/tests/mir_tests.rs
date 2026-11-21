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
    assert!(
        f.blocks.iter().any(|b| b.label.starts_with("opt_present_"))
            && f.blocks.iter().any(|b| b.label.starts_with("opt_absent_")),
        "expected specialized opt_present / opt_absent basic blocks"
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
    let tl = mv
        .functions
        .iter()
        .find(|f| f.name == "BladeSlash")
        .expect("BladeSlash timeline tick");
    assert!(tl.blocks[0].stmts.iter().any(|s| {
        matches!(
            s.inst,
            Inst::TimelineAdvance {
                rate_hz: 120,
                duration_frames: 24,
                ..
            }
        )
    }));

    let task = mv
        .functions
        .iter()
        .find(|f| f.name == "AirDashTask")
        .expect("AirDashTask coroutine tick");
    assert!(matches!(
        task.blocks[0].terminator,
        Terminator::Switch { .. }
    ));
    assert!(task.blocks.iter().any(|b| b.label == "abort_cleanup"));

    let cozy = lower_to_mir(&analyze_source("04_cozy_valley.strata", COOKBOOKS[3].1));
    let fsm = cozy
        .functions
        .iter()
        .find(|f| f.name == "VillagerRoutine")
        .expect("VillagerRoutine fsm");
    assert!(
        fsm.blocks[0]
            .stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::FsmDispatch { .. }))
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
    assert!(rebuild.blocks[0].stmts.iter().any(|s| {
        matches!(
            s.inst,
            Inst::SpatialRebuildCsr {
                is_history: true,
                frames: 16,
                ..
            }
        )
    }));

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
