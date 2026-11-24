use strata_mir::{Inst, Terminator, lower_to_mir, verify_mir};
use strata_sema::analyze_source;
use strata_sema::hir::HirScheduleGroup;

const COOKBOOKS: [(&str, &str); 8] = [
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
    (
        "07_visual_boss_graph.strata",
        include_str!("../../../fixtures/cookbooks/07_visual_boss_graph.strata"),
    ),
    (
        "08_authoritative_multiplayer.strata",
        include_str!("../../../fixtures/cookbooks/08_authoritative_multiplayer.strata"),
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

#[test]
fn indexed_spawn_batch_lowers_to_multi_block_loop() {
    use strata_mir::MirType;

    let sema = analyze_source("01_rain_swarm.strata", COOKBOOKS[0].1);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("01_rain_swarm MIR must verify");

    let seed = mir
        .functions
        .iter()
        .find(|f| f.name == "seed_rainstorm")
        .expect("seed_rainstorm");

    assert!(
        !seed
            .blocks
            .iter()
            .flat_map(|b| &b.stmts)
            .any(|s| matches!(s.inst, Inst::CmdSpawnBatch { .. })),
        "indexed spawn_batch must NOT lower to single-shot CmdSpawnBatch"
    );
    assert!(
        !seed.blocks.iter().flat_map(|b| &b.stmts).any(|s| {
            matches!(s.inst, Inst::ConstInt { value: 0 })
                && s.dst.is_some_and(|d| seed.locals[d.0 as usize].name == "i")
        }),
        "batch induction var `i` must NOT be bound once to ConstInt(0)"
    );

    let (begin_dst, begin_cnt, begin_comps) = seed.blocks[0]
        .stmts
        .iter()
        .find_map(|s| match &s.inst {
            Inst::SpawnBatchBegin { count, components } => Some((
                s.dst.expect("SpawnBatchBegin dst"),
                *count,
                components.clone(),
            )),
            _ => None,
        })
        .expect("SpawnBatchBegin in entry block");
    assert_eq!(seed.locals[begin_dst.0 as usize].ty, MirType::U64);
    assert_eq!(seed.locals[begin_cnt.0 as usize].ty, MirType::U32);
    assert_eq!(begin_comps, vec!["Raindrop".to_owned(), "Pos3D".to_owned()]);

    let hdr_bb = seed
        .blocks
        .iter()
        .find(|b| b.label == "spawn_batch_hdr")
        .expect("spawn_batch_hdr block");
    let body_bb = seed
        .blocks
        .iter()
        .find(|b| b.label == "spawn_batch_body")
        .expect("spawn_batch_body block");
    let exit_bb = seed
        .blocks
        .iter()
        .find(|b| b.label == "spawn_batch_exit")
        .expect("spawn_batch_exit block");

    assert_eq!(
        hdr_bb.terminator,
        Terminator::Branch {
            cond: hdr_bb
                .stmts
                .last()
                .and_then(|s| s.dst)
                .expect("loop comparison cond"),
            then_bb: body_bb.id,
            else_bb: exit_bb.id,
        }
    );
    let i_val = hdr_bb
        .stmts
        .iter()
        .find_map(|s| {
            if matches!(s.inst, Inst::SlotLoad { .. }) {
                s.dst
            } else {
                None
            }
        })
        .expect("SlotLoad for induction counter i");
    assert_eq!(seed.locals[i_val.0 as usize].ty, MirType::U32);

    let (push_batch, push_idx, push_comps) = body_bb
        .stmts
        .iter()
        .find_map(|s| match &s.inst {
            Inst::SpawnBatchPush {
                batch,
                index,
                components,
            } => Some((*batch, *index, components.clone())),
            _ => None,
        })
        .expect("SpawnBatchPush in spawn_batch_body");
    assert_eq!(push_batch, begin_dst);
    assert_eq!(push_idx, i_val);
    assert_eq!(push_comps.len(), 2);
    assert_eq!(push_comps[0].0, "Raindrop");
    assert_eq!(push_comps[1].0, "Pos3D");
    assert_eq!(body_bb.terminator, Terminator::Goto(hdr_bb.id));

    assert!(
        exit_bb
            .stmts
            .iter()
            .any(|s| { matches!(s.inst, Inst::SpawnBatchCommit { batch } if batch == begin_dst) }),
        "expected SpawnBatchCommit in spawn_batch_exit"
    );
}

#[test]
fn spawn_batch_unindexed_wildcard_and_variable_scoping() {
    let src = r#"
module test::spawn_batch_cases @version(1.0.0);

component Item { val: i32 = 0 }

sys unindexed_batch() effects(spawns: [Item]) {
    spawn_batch(16) |_| {
        { Item { val: 7 } }
    };
}

sys scoped_batch() effects(spawns: [Item]) {
    let i = 42;
    let n: i32 = 4;
    spawn_batch(n) |i| {
        let local_tmp = i + 1;
        { Item { val: local_tmp } }
    };
    let after = i;
    let _ = after;
}
"#;
    let sema = analyze_source("spawn_batch_cases.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("spawn_batch_cases MIR must verify");

    let unindexed = mir
        .functions
        .iter()
        .find(|f| f.name == "unindexed_batch")
        .expect("unindexed_batch");
    assert!(
        unindexed
            .blocks
            .iter()
            .flat_map(|b| &b.stmts)
            .any(|s| matches!(s.inst, Inst::CmdSpawnBatch { .. })),
        "wildcard `|_|` spawn_batch should keep CmdSpawnBatch"
    );

    let scoped = mir
        .functions
        .iter()
        .find(|f| f.name == "scoped_batch")
        .expect("scoped_batch");
    let exit_bb = scoped
        .blocks
        .iter()
        .find(|b| b.label == "spawn_batch_exit")
        .expect("spawn_batch_exit");
    // `let after = i;` after the loop must load from the outer `slot_i` (not `batch_i`)
    let outer_i_slot = scoped.blocks[0]
        .stmts
        .iter()
        .find_map(|s| {
            if matches!(s.inst, Inst::SlotAlloc { .. })
                && s.dst
                    .is_some_and(|d| scoped.locals[d.0 as usize].name == "slot_i")
            {
                s.dst
            } else {
                None
            }
        })
        .expect("outer slot_i");
    assert!(
        exit_bb
            .stmts
            .iter()
            .any(|s| { matches!(s.inst, Inst::SlotLoad { slot } if slot == outer_i_slot) }),
        "outer `i` binding must be restored after spawn_batch loop"
    );
}

#[test]
fn mir_net_component_quantize_bit_packing_rpcs_and_handshake() {
    use strata_mir::{MirStreamOpKind, MirVerifyError};
    use strata_sema::AuthorityKind;

    let src = r#"
module test::net_mir @version(1.0.0);

@net(reliable, rate = 20Hz, channel = 0)
@authority(server)
component NetState {
    @quantize(min = 0.0, max = 1.0, bits = 1)
    grounded: f32,
    @quantize(min = -512.0, max = 512.0, bits = 16)
    pos: vec3,
    @quantize(min = 0.0, max = 1000000.0, bits = 32)
    score: f32,
    seq: u32,
}

@net_rpc(direction = client_to_server, reliability = reliable, channel = 1)
rpc MoveInput {
    dx: f32,
    dy: f32,
    seq: u32,
}

@node_group("pure")
@node_pure
fn double(x: f32) -> f32 {
    x * 2.0
}

@authority(server)
sys server_tick() {
    for s in query(ns: &mut NetState).changed<NetState>() {
        s.ns.score = double(s.ns.score);
    }
}

net_sim_test "sync"(latency: 30ms, jitter: 5ms, loss: 0.02, seed: 7, clients: 2) {
    step_net(5);
}
"#;
    let sema = analyze_source("net_mir.strata", src);
    assert!(sema.ok(), "sema failed: {:#?}", sema.diagnostics);

    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("networking MIR must verify cleanly");

    // No dummy networking MirFunction stubs synthesized into `mir.functions`.
    assert_eq!(mir.functions.len(), 1);
    assert_eq!(mir.functions[0].name, "server_tick");
    assert_eq!(mir.functions[0].authority, AuthorityKind::Server);
    assert_eq!(mir.functions[0].changed_terms.len(), 1);
    assert_eq!(mir.functions[0].changed_terms[0].storage_key, "NetState");

    assert_eq!(mir.fns.len(), 1);
    assert!(mir.fns[0].is_node_pure);
    assert_eq!(mir.fns[0].node_group.as_deref(), Some("pure"));

    assert_eq!(mir.net_components.len(), 1);
    let nc = &mir.net_components[0];
    assert_eq!(nc.name, "NetState");
    assert!(nc.is_replicated);
    assert_eq!(nc.authority, AuthorityKind::Server);
    assert!(!nc.is_predicted);
    assert_eq!(
        nc.schema_fingerprint,
        sema.layouts["test::net_mir::NetState"].schema_fingerprint
    );
    assert_eq!(
        nc.uuid_bytes,
        sema.layouts["test::net_mir::NetState"].uuid_bytes
    );
    // Bit layout: grounded (1b @ 0) + pos (3*16=48b @ 1) + score (32b @ 49) + seq (32b @ 81) = 113 bits -> 15 bytes
    assert_eq!(nc.packed_bits, 1 + 48 + 32 + 32);
    assert_eq!(nc.packed_bytes, 113u32.div_ceil(8));
    assert_eq!(nc.quantize_specs.len(), 3);
    assert_eq!(nc.quantize_specs[0].bit_offset, 0);
    assert_eq!(nc.quantize_specs[0].max_quantized_u64(), 1);
    assert_eq!(nc.quantize_specs[1].bit_offset, 1);
    assert_eq!(nc.quantize_specs[1].lane_count, 3);
    assert_eq!(nc.quantize_specs[1].total_bits, 48);
    assert_eq!(nc.quantize_specs[2].bit_offset, 49);
    assert_eq!(nc.quantize_specs[2].max_quantized_u64(), u32::MAX as u64);
    assert_eq!(nc.wire_fields[3].bit_offset, 81);
    assert_eq!(nc.wire_fields[3].total_bits, 32);

    assert_eq!(mir.rpcs.len(), 1);
    assert_eq!(mir.rpcs[0].name, "MoveInput");
    assert_ne!(mir.rpcs[0].schema_fingerprint, 0);
    assert_eq!(mir.rpcs[0].fields.len(), 3);

    assert_eq!(mir.net_sim_tests.len(), 1);
    assert!((mir.net_sim_tests[0].latency_ms - 30.0).abs() < 1e-6);

    assert_ne!(mir.net_handshake.module_net_fingerprint, 0);
    assert_eq!(mir.net_handshake.component_fingerprints.len(), 1);
    assert_eq!(mir.net_handshake.rpc_fingerprints.len(), 1);

    // Channels 0 (NetState) and 1 (MoveInput) each get StreamRead (Slot 30) & StreamWriteBatch (Slot 32)
    assert_eq!(mir.net_stream_ops.len(), 4);
    assert!(mir.net_stream_ops.iter().all(|op| op.requires_outside_par
        && matches!(
            op.kind,
            MirStreamOpKind::StreamRead | MirStreamOpKind::StreamWriteBatch
        )));

    // Negative verifier checks
    let mut bad_mir = mir.clone();
    bad_mir.net_components[0].quantize_specs[0].bits = 33;
    bad_mir.net_components[0].quantize_specs[0].min = 10.0;
    bad_mir.net_components[0].quantize_specs[0].max = 5.0;
    bad_mir.net_components[0].packed_bytes = 999;
    bad_mir.net_sim_tests[0].loss = 1.5;
    bad_mir.net_handshake.module_net_fingerprint = 0;
    let errs = verify_mir(&bad_mir).unwrap_err();
    assert!(
        errs.iter()
            .filter(|e| matches!(e, MirVerifyError::InvalidNetworkInvariant { .. }))
            .count()
            >= 5,
        "expected >= 5 InvalidNetworkInvariant errors, got {errs:#?}"
    );
}

#[test]
fn mir_stream_ops_and_changed_terms_verification() {
    use strata_mir::{MirStreamOpKind, MirVerifyError};

    let src = r#"
module test::streams_and_changed @version(1.0.0);

component Pos { x: f32 = 0.0 }
stream Hit { dmg: f32 }

sys emitter() {
    for p in query(pos: &Pos).changed() {
        emit(Hit { dmg: p.pos.x });
    }
}

sys reader(hits: stream_in<Hit>) {
    let _ = hits.dmg;
}
"#;
    let sema = analyze_source("streams.strata", src);
    assert!(sema.ok(), "{:#?}", sema.diagnostics);

    let mut mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("stream & changed MIR must verify");

    let emitter = mir.functions.iter().find(|f| f.name == "emitter").unwrap();
    assert_eq!(emitter.changed_terms.len(), 1);
    assert!(emitter.queries[0].is_term_changed("Pos"));
    assert_eq!(emitter.stream_ops.len(), 1);
    assert_eq!(emitter.stream_ops[0].kind, MirStreamOpKind::StreamSend);
    assert!(!emitter.stream_ops[0].requires_outside_par);

    let reader = mir.functions.iter().find(|f| f.name == "reader").unwrap();
    assert_eq!(reader.stream_ops.len(), 1);
    assert_eq!(reader.stream_ops[0].kind, MirStreamOpKind::StreamRead);
    assert!(reader.stream_ops[0].requires_outside_par);

    // `@par` chunk function MUST reject `StreamRead` (`requires_outside_par: true`)
    mir.functions[1].par_chunk = Some(64);
    let errs = verify_mir(&mir).unwrap_err();
    assert!(
        errs.iter().any(|e| {
            matches!(e, MirVerifyError::InvalidCfgInvariant { detail, .. } if detail.contains("Slots 30/32"))
        }),
        "expected @par StreamRead rejection, got {errs:#?}"
    );
}

#[test]
fn m2_r2_regression_handshake_fingerprint_sensitivity_and_verify_hardening() {
    use strata_mir::MirVerifyError;

    let base_src = r#"
module test::handshake_r2 @version(1.0.0);

@net(reliable, rate = 20Hz, channel = 0)
@authority(server)
component NetState {
    @quantize(min = 0.0, max = 10.0, bits = 8)
    hp: f32,
    seq: u32,
}

@net_rpc(direction = client_to_server, reliability = reliable, channel = 0)
rpc MoveCmd {
    @quantize(min = -1.0, max = 1.0, bits = 8)
    dx: f32,
    seq: u16,
}

@authority(server)
sys tick() {}
"#;
    let sema_base = analyze_source("hs_base.strata", base_src);
    assert!(sema_base.ok(), "{:#?}", sema_base.diagnostics);
    let mir_base = lower_to_mir(&sema_base);
    verify_mir(&mir_base).expect("base MIR must verify");

    // Layout fingerprint parity MUST be preserved on MirNetComponent & MirNetHandshake.component_fingerprints
    let layout_fp = sema_base.layouts["test::handshake_r2::NetState"].schema_fingerprint;
    assert_eq!(mir_base.net_components[0].schema_fingerprint, layout_fp);
    assert_eq!(
        mir_base.net_handshake.component_fingerprints,
        vec![("test::handshake_r2::NetState".to_owned(), layout_fp)]
    );
    // MirRpc retains wire_fields, packed_bits, packed_bytes
    assert_eq!(mir_base.rpcs[0].wire_fields.len(), 2);
    assert_eq!(mir_base.rpcs[0].packed_bits, 8 + 16);
    assert_eq!(mir_base.rpcs[0].packed_bytes, 3);

    // 1. Visual-only @node_group edit preserves module_net_fingerprint
    let grouped_src = base_src.replace(
        "component NetState",
        "@node_group(\"net\")\ncomponent NetState",
    );
    let sema_grouped = analyze_source("hs_grouped.strata", &grouped_src);
    assert!(sema_grouped.ok());
    let mir_grouped = lower_to_mir(&sema_grouped);
    assert_eq!(
        mir_grouped.net_handshake.module_net_fingerprint,
        mir_base.net_handshake.module_net_fingerprint
    );

    // 2. Component @quantize(bits = 8 -> 16) updates module_net_fingerprint while keeping layout parity
    let comp_q16_src = base_src.replace(
        "@quantize(min = 0.0, max = 10.0, bits = 8)",
        "@quantize(min = 0.0, max = 10.0, bits = 16)",
    );
    let sema_comp_q16 = analyze_source("hs_comp_q16.strata", &comp_q16_src);
    assert!(sema_comp_q16.ok());
    let mir_comp_q16 = lower_to_mir(&sema_comp_q16);
    verify_mir(&mir_comp_q16).expect("comp_q16 MIR must verify");
    assert_eq!(mir_comp_q16.net_components[0].schema_fingerprint, layout_fp);
    assert_ne!(
        mir_comp_q16.net_handshake.module_net_fingerprint,
        mir_base.net_handshake.module_net_fingerprint
    );

    // 3. Component @net(channel = 0 -> 2) updates module_net_fingerprint
    let comp_ch2_src = base_src.replace(
        "@net(reliable, rate = 20Hz, channel = 0)",
        "@net(reliable, rate = 20Hz, channel = 2)",
    );
    let sema_comp_ch2 = analyze_source("hs_comp_ch2.strata", &comp_ch2_src);
    assert!(sema_comp_ch2.ok());
    let mir_comp_ch2 = lower_to_mir(&sema_comp_ch2);
    verify_mir(&mir_comp_ch2).expect("comp_ch2 MIR must verify");
    assert_ne!(
        mir_comp_ch2.net_handshake.module_net_fingerprint,
        mir_base.net_handshake.module_net_fingerprint
    );

    // 4. RPC @quantize(bits = 8 -> 16) updates MirRpc::schema_fingerprint, packed_bits/bytes, and module_net_fingerprint
    let rpc_q16_src = base_src.replace(
        "@quantize(min = -1.0, max = 1.0, bits = 8)",
        "@quantize(min = -1.0, max = 1.0, bits = 16)",
    );
    let sema_rpc_q16 = analyze_source("hs_rpc_q16.strata", &rpc_q16_src);
    assert!(sema_rpc_q16.ok());
    let mir_rpc_q16 = lower_to_mir(&sema_rpc_q16);
    verify_mir(&mir_rpc_q16).expect("rpc_q16 MIR must verify");
    assert_eq!(mir_rpc_q16.rpcs[0].packed_bits, 16 + 16);
    assert_eq!(mir_rpc_q16.rpcs[0].packed_bytes, 4);
    assert_ne!(
        mir_rpc_q16.rpcs[0].schema_fingerprint,
        mir_base.rpcs[0].schema_fingerprint
    );
    assert_ne!(
        mir_rpc_q16.net_handshake.module_net_fingerprint,
        mir_base.net_handshake.module_net_fingerprint
    );

    // 5. verify_network_ir catches overlapping MirRpc::quantize_specs and duplicate MirNetComponent
    let two_q_src = r#"
module test::rpc_overlap @version(1.0.0);
@net(reliable) component C { x: f32 }
@net_rpc(client_to_server) rpc R {
    @quantize(min = 0.0, max = 1.0, bits = 8) a: f32,
    @quantize(min = 0.0, max = 1.0, bits = 8) b: f32,
}
"#;
    let sema_two_q = analyze_source("rpc_overlap.strata", two_q_src);
    assert!(sema_two_q.ok());
    let mut bad_rpc_mir = lower_to_mir(&sema_two_q);
    bad_rpc_mir.rpcs[0].quantize_specs[1].bit_offset = 0; // overlaps [0, 8)
    let dup_comp = bad_rpc_mir.net_components[0].clone();
    bad_rpc_mir.net_components.push(dup_comp);
    let errs = verify_mir(&bad_rpc_mir).unwrap_err();
    assert!(
        errs.iter().any(|e| matches!(
            e,
            MirVerifyError::InvalidNetworkInvariant { detail, .. } if detail.contains("overlaps")
        )),
        "expected RPC quantize_specs overlap error, got {errs:#?}"
    );
    assert!(
        errs.iter().any(|e| matches!(
            e,
            MirVerifyError::InvalidNetworkInvariant { detail, .. } if detail.contains("duplicate MirNetComponent")
        )),
        "expected duplicate MirNetComponent error, got {errs:#?}"
    );

    // 6. verify_function rejects StreamRead/StreamWriteBatch in @par even if requires_outside_par=false,
    //    and rejects requires_outside_par=false on StreamRead/StreamWriteBatch even outside @par.
    let stream_src = r#"
module test::stream_par_r2 @version(1.0.0);
stream Hit { dmg: f32 }
sys reader(hits: stream_in<Hit>) { let _ = hits.dmg; }
"#;
    let sema_stream = analyze_source("stream_par_r2.strata", stream_src);
    assert!(sema_stream.ok());
    let mut bad_stream_mir = lower_to_mir(&sema_stream);
    bad_stream_mir.functions[0].par_chunk = Some(64);
    bad_stream_mir.functions[0].stream_ops[0].requires_outside_par = false;
    let stream_errs = verify_mir(&bad_stream_mir).unwrap_err();
    assert!(
        stream_errs.iter().any(|e| matches!(
            e,
            MirVerifyError::InvalidCfgInvariant { detail, .. } if detail.contains("outside @par")
        )),
        "expected unconditional @par StreamRead rejection, got {stream_errs:#?}"
    );
    assert!(
        stream_errs.iter().any(|e| matches!(
            e,
            MirVerifyError::InvalidCfgInvariant { detail, .. } if detail.contains("requires_outside_par=true")
        )),
        "expected requires_outside_par=true invariant check, got {stream_errs:#?}"
    );
}

#[test]
fn m2_r3_regression_soa_cold_prefix_overflow_and_quantize_desync_hardening() {
    use strata_mir::MirVerifyError;

    // 1. `@soa @net component Body` must NOT absorb `@soa component Body__extra` cold strata
    let soa_src = r#"
module test::soa_collision @version(1.0.0);

@soa
@net(reliable, channel = 0)
component Body {
    hot { x: f32 }
    cold stats { hp: f32 }
}

@soa
component Body__extra {
    hot { y: f32 }
    cold sub { w: f32 }
}

@authority(server)
sys tick() {}
"#;
    let sema_soa = analyze_source("soa_collision.strata", soa_src);
    assert!(sema_soa.ok(), "{:#?}", sema_soa.diagnostics);
    let mir_soa = lower_to_mir(&sema_soa);
    verify_mir(&mir_soa).expect("soa_collision MIR must verify");
    assert_eq!(mir_soa.net_components.len(), 1);
    let wf_names: Vec<&str> = mir_soa.net_components[0]
        .wire_fields
        .iter()
        .map(|wf| wf.field_name.as_str())
        .collect();
    assert_eq!(
        wf_names,
        vec!["x", "hp"],
        "Body wire_fields must exclude Body__extra cold stratum `w`"
    );

    // 2 & 3. `verify_mir` rejects u32 bit-interval overflow and `wire_fields[i].quantize` desync
    // on both `MirNetComponent` and `MirRpc`.
    let net_src = r#"
module test::verify_hardening @version(1.0.0);

@net(reliable)
component Comp {
    @quantize(min = 0.0, max = 1.0, bits = 8)
    v: f32,
}

@net_rpc(client_to_server)
rpc Cmd {
    @quantize(min = 0.0, max = 1.0, bits = 8)
    dx: f32,
}
"#;
    let sema_net = analyze_source("verify_hardening.strata", net_src);
    assert!(sema_net.ok(), "{:#?}", sema_net.diagnostics);
    let base_mir = lower_to_mir(&sema_net);
    verify_mir(&base_mir).expect("base MIR must verify");

    // 2a. u32::MAX overflow in MirNetComponent wire_fields & quantize_specs
    let mut ovf_comp = base_mir.clone();
    ovf_comp.net_components[0].packed_bits = u32::MAX;
    ovf_comp.net_components[0].packed_bytes = u32::MAX.div_ceil(8);
    ovf_comp.net_components[0].wire_fields[0].bit_offset = u32::MAX - 4;
    ovf_comp.net_components[0].wire_fields[0]
        .quantize
        .as_mut()
        .unwrap()
        .bit_offset = u32::MAX - 4;
    ovf_comp.net_components[0].quantize_specs[0].bit_offset = u32::MAX - 4;
    let ovf_comp_errs = verify_mir(&ovf_comp).unwrap_err();
    assert!(
        ovf_comp_errs.iter().any(|e| matches!(
            e,
            MirVerifyError::InvalidNetworkInvariant { detail, .. } if detail.contains("overflows u32")
        )),
        "expected MirNetComponent u32 overflow error, got {ovf_comp_errs:#?}"
    );

    // 2b. u32::MAX overflow in MirRpc wire_fields & quantize_specs
    let mut ovf_rpc = base_mir.clone();
    ovf_rpc.rpcs[0].packed_bits = u32::MAX;
    ovf_rpc.rpcs[0].packed_bytes = u32::MAX.div_ceil(8);
    ovf_rpc.rpcs[0].wire_fields[0].bit_offset = u32::MAX - 4;
    ovf_rpc.rpcs[0].wire_fields[0]
        .quantize
        .as_mut()
        .unwrap()
        .bit_offset = u32::MAX - 4;
    ovf_rpc.rpcs[0].quantize_specs[0].bit_offset = u32::MAX - 4;
    let ovf_rpc_errs = verify_mir(&ovf_rpc).unwrap_err();
    assert!(
        ovf_rpc_errs.iter().any(|e| matches!(
            e,
            MirVerifyError::InvalidNetworkInvariant { detail, .. } if detail.contains("overflows u32")
        )),
        "expected MirRpc u32 overflow error, got {ovf_rpc_errs:#?}"
    );

    // 3a. wire_fields[0].quantize bit_offset / total_bits desync in MirNetComponent
    let mut desync_comp = base_mir.clone();
    desync_comp.net_components[0].wire_fields[0]
        .quantize
        .as_mut()
        .unwrap()
        .bit_offset = 4;
    let desync_comp_errs = verify_mir(&desync_comp).unwrap_err();
    assert!(
        desync_comp_errs.iter().any(|e| matches!(
            e,
            MirVerifyError::InvalidNetworkInvariant { detail, .. } if detail.contains("mismatches wire_field")
        )),
        "expected MirNetComponent quantize desync error, got {desync_comp_errs:#?}"
    );

    // 3b. wire_fields[0].quantize bit_offset / total_bits desync in MirRpc
    let mut desync_rpc = base_mir;
    desync_rpc.rpcs[0].wire_fields[0]
        .quantize
        .as_mut()
        .unwrap()
        .bit_offset = 4;
    let desync_rpc_errs = verify_mir(&desync_rpc).unwrap_err();
    assert!(
        desync_rpc_errs.iter().any(|e| matches!(
            e,
            MirVerifyError::InvalidNetworkInvariant { detail, .. } if detail.contains("mismatches wire_field")
        )),
        "expected MirRpc quantize desync error, got {desync_rpc_errs:#?}"
    );
}

#[test]
fn sparse_net_component_with_selective_write_preserves_iter_col_rows_write() {
    use strata_mir::Inst;

    let src = r#"
module test::sparse_selective @version(1.0.0);

@sparse
@net(reliable, channel = 0)
@authority(server)
component SparseNet {
    val: u32 = 0,
}

@authority(server)
sys bump_sparse() {
    for row in query(s: &mut? SparseNet) {
        row.s.val += 1_u32;
    }
}

schedule FixedUpdate { bump_sparse }
"#;
    let sema = analyze_source("sparse_selective.strata", src);
    assert!(sema.ok(), "{:#?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("@sparse @net component with `&mut?` must pass verify_mir");

    let bump = mir
        .functions
        .iter()
        .find(|f| f.name.ends_with("bump_sparse"))
        .expect("bump_sparse function");
    let has_rows_write = bump.blocks.iter().any(|bb| {
        bb.stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::IterColRowsWrite { .. }))
    });
    let has_untracked = bump.blocks.iter().any(|bb| {
        bb.stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::IterColWriteUntracked { .. }))
    });
    assert!(
        has_rows_write,
        "bump_sparse must emit IterColRowsWrite for @sparse @net"
    );
    assert!(
        !has_untracked,
        "bump_sparse must NOT emit dense IterColWriteUntracked for @sparse"
    );
}

#[test]
fn multi_term_selective_write_flushes_all_terms() {
    use strata_mir::Inst;

    let src = r#"
module test::multi_selective @version(1.0.0);

component CompA { a: u32 = 0 }
component CompB { b: u32 = 0 }

sys bump_both() {
    for row in query(x: &mut? CompA, y: &mut? CompB) {
        row.x.a += 1_u32;
        row.y.b += 2_u32;
    }
}

schedule FixedUpdate { bump_both }
"#;
    let sema = analyze_source("multi_selective.strata", src);
    assert!(sema.ok(), "{:#?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("multi-term selective write MIR must verify");

    let bump = mir
        .functions
        .iter()
        .find(|f| f.name.ends_with("bump_both"))
        .expect("bump_both function");
    let flushed_terms: Vec<u32> = bump
        .blocks
        .iter()
        .flat_map(|bb| bb.stmts.iter())
        .filter_map(|s| match s.inst {
            Inst::IterMarkChangedRange { term_idx, .. } => Some(term_idx),
            _ => None,
        })
        .collect();
    assert!(
        flushed_terms.contains(&0) && flushed_terms.contains(&1),
        "expected IterMarkChangedRange for both term_idx 0 and 1, got {flushed_terms:?}"
    );
}

#[test]
fn fix1_atomic_tx_preimage_undo_log_and_multi_entity_guard() {
    use strata_mir::MirVerifyError;
    use strata_mir::ir::{
        BasicBlock, BlockId, LocalId, MirFnKind, MirFunction, MirModule, MirStmt, MirType,
    };

    let src = r#"
module test::atomic_undo @version(1.0.0);

resource Bank { gold: i32 = 100 }
component Wallet { coins: i32 = 50 }
stream Rejected { ok: bool }

sys buy_item(bank: &mut Bank, ent: Entity) {
    let mut attempts: i32 = 0;
    atomic {
        attempts += 1;
        let Some(w) = query_one(wallet: &mut Wallet).on(ent) else { require_true(false); };
        bank.gold -= 20;
        w.wallet.coins -= 10;
        require_true(w.wallet.coins >= 0);
    } on_rollback {
        emit(Rejected { ok: false });
    }
}
"#;
    let sema = analyze_source("atomic_undo.strata", src);
    assert!(sema.ok(), "{:#?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("atomic undo MIR must verify");

    let buy = mir
        .functions
        .iter()
        .find(|f| f.name == "buy_item")
        .expect("buy_item");

    // Pre-image save blocks execute FieldLoad + SlotStore before FieldStore
    let save_blocks: Vec<_> = buy
        .blocks
        .iter()
        .filter(|b| b.label == "tx_save_pre")
        .collect();
    assert!(
        save_blocks.len() >= 2,
        "expected tx_save_pre blocks for bank.gold and w.wallet.coins"
    );
    for sb in &save_blocks {
        assert!(
            sb.stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::FieldLoad { .. }))
                && sb
                    .stmts
                    .iter()
                    .any(|s| matches!(s.inst, Inst::SlotStore { .. })),
            "tx_save_pre must capture FieldLoad into undo SlotStore"
        );
    }

    // Rollback restores FieldStores via `tx_undo_field` BEFORE `StreamEmit` in `on_rollback`
    assert!(
        buy.blocks.iter().any(|b| b.label == "tx_undo_field"
            && b.stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::FieldStore { .. }))),
        "expected conditional tx_undo_field restoration blocks"
    );
    let rb_idx = buy
        .blocks
        .iter()
        .position(|b| b.label == "atomic_rollback")
        .expect("atomic_rollback");
    let emit_bb_idx = buy
        .blocks
        .iter()
        .position(|b| {
            b.stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::StreamEmit { .. }))
        })
        .expect("on_rollback StreamEmit");
    assert!(
        buy.blocks[rb_idx]
            .stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::CmdRollback { .. }))
            && emit_bb_idx > rb_idx,
        "undo chain must execute between CmdRollback and on_rollback StreamEmit"
    );

    // Negative verifier test: multi-entity RowPtr FieldStore inside a tx loop must be rejected
    let mut bad_func = MirFunction::new("bad_tx", MirFnKind::System);
    let ckpt = bad_func.alloc_local("ckpt", MirType::Checkpoint);
    let col = bad_func.alloc_local("col", MirType::MutPtr);
    let ridx = bad_func.alloc_local("ridx", MirType::U32);
    let rptr = bad_func.alloc_local("rptr", MirType::MutPtr);
    let val = bad_func.alloc_local("val", MirType::F32);
    let cond = bad_func.alloc_local("cond", MirType::Bool);
    bad_func.blocks = vec![
        BasicBlock {
            id: BlockId(0),
            label: "entry".to_owned(),
            stmts: vec![
                MirStmt {
                    dst: Some(ckpt),
                    inst: Inst::CmdCheckpoint,
                },
                MirStmt {
                    dst: Some(col),
                    inst: Inst::IterColWrite {
                        query_idx: 0,
                        term_idx: 0,
                        storage_key: "Wallet".to_owned(),
                    },
                },
                MirStmt {
                    dst: Some(ridx),
                    inst: Inst::ConstInt { value: 0 },
                },
                MirStmt {
                    dst: Some(val),
                    inst: Inst::ConstFloat { value: 1.0 },
                },
                MirStmt {
                    dst: Some(cond),
                    inst: Inst::ConstBool { value: true },
                },
            ],
            terminator: Terminator::Goto(BlockId(1)),
        },
        BasicBlock {
            id: BlockId(1),
            label: "atomic_body".to_owned(),
            stmts: vec![
                MirStmt {
                    dst: Some(rptr),
                    inst: Inst::RowPtr {
                        col_ptr: col,
                        row_idx: ridx,
                        stride_bytes: 4,
                        is_sparse: false,
                    },
                },
                MirStmt {
                    dst: None,
                    inst: Inst::FieldStore {
                        base_ptr: rptr,
                        layout_key: "test::Wallet".to_owned(),
                        field: "coins".to_owned(),
                        offset_bytes: 0,
                        val,
                    },
                },
            ],
            terminator: Terminator::Branch {
                cond,
                then_bb: BlockId(1),
                else_bb: BlockId(3),
            },
        },
        BasicBlock {
            id: BlockId(2),
            label: "atomic_rollback".to_owned(),
            stmts: vec![MirStmt {
                dst: None,
                inst: Inst::CmdRollback { checkpoint: ckpt },
            }],
            terminator: Terminator::Goto(BlockId(3)),
        },
        BasicBlock {
            id: BlockId(3),
            label: "atomic_merge".to_owned(),
            stmts: Vec::new(),
            terminator: Terminator::Return(None),
        },
    ];
    let _ = LocalId(0);
    let bad_mod = MirModule {
        module_path: "test::bad".to_owned(),
        is_deterministic: false,
        layouts: Vec::new(),
        enums: Vec::new(),
        consts: Vec::new(),
        tables: Vec::new(),
        curves: Vec::new(),
        relations: Vec::new(),
        spatial_indices: Vec::new(),
        timelines: Vec::new(),
        tasks: Vec::new(),
        fsms: Vec::new(),
        objects: Vec::new(),
        migrations: Vec::new(),
        fns: Vec::new(),
        functions: vec![bad_func],
        schedules: Vec::new(),
        sim_tests: Vec::new(),
        field_defaults: Default::default(),
        rpcs: Vec::new(),
        net_components: Vec::new(),
        net_sim_tests: Vec::new(),
        net_handshake: Default::default(),
        net_stream_ops: Vec::new(),
    };
    let errs = verify_mir(&bad_mod).expect_err("multi-entity RowPtr tx loop must fail verify_mir");
    assert!(
        errs.iter()
            .any(|e| matches!(e, MirVerifyError::InvalidCfgInvariant { .. })),
        "expected InvalidCfgInvariant, got {errs:?}"
    );
}

#[test]
fn fix2_spatial_index_dimensions_and_2pass_csr_instructions() {
    let br = lower_to_mir(&analyze_source(
        "06_battle_royale_server.strata",
        COOKBOOKS[5].1,
    ));
    verify_mir(&br).expect("battle royale MIR must verify");
    let ph = br
        .spatial_indices
        .iter()
        .find(|s| s.name == "PlayerHitHistory")
        .expect("PlayerHitHistory");
    assert_eq!(ph.frames, 16);
    assert!((ph.cell_size - 16.0).abs() < 1e-5);
    assert_eq!(ph.bounds_min, [-2048.0, -2048.0]);
    assert_eq!(ph.bounds_max, [2048.0, 2048.0]);
    assert_eq!(ph.capacity, 128);
    assert_eq!(ph.cols, 256);
    assert_eq!(ph.rows, 256);
    assert_eq!(ph.plane_axes, [0, 2]);

    let mv = lower_to_mir(&analyze_source(
        "03_metroidvania_core.strata",
        COOKBOOKS[2].1,
    ));
    verify_mir(&mv).expect("metroidvania MIR must verify");
    let rg = mv
        .spatial_indices
        .iter()
        .find(|s| s.name == "RoomEnemyGrid")
        .expect("RoomEnemyGrid");
    assert_eq!(rg.frames, 1);
    assert!((rg.cell_size - 4.0).abs() < 1e-5);
    assert_eq!(rg.bounds_min, [-128.0, -64.0]);
    assert_eq!(rg.bounds_max, [128.0, 64.0]);
    assert_eq!(rg.capacity, 512);
    assert_eq!(rg.cols, 64);
    assert_eq!(rg.rows, 32);
    assert_eq!(rg.plane_axes, [0, 1]);

    let rebuild = br
        .functions
        .iter()
        .find(|f| f.name == "PlayerHitHistory__rebuild_csr")
        .expect("PlayerHitHistory__rebuild_csr");
    let stmts: Vec<_> = rebuild.blocks.iter().flat_map(|b| &b.stmts).collect();
    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::SpatialCsrBegin { .. }))
    );
    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::SpatialCsrCount { .. }))
    );
    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::SpatialCsrPrefixSum { .. }))
    );
    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::IterReset { query_idx: 0 }))
    );
    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::SpatialCsrScatter { .. }))
    );

    // Candidate loop must branch out on FfiEntity::NULL (`spatial_hit` block)
    let bal = br
        .functions
        .iter()
        .find(|f| f.name == "simulate_ballistics")
        .expect("simulate_ballistics");
    assert!(
        bal.blocks.iter().any(|b| b.label == "spatial_hit"),
        "expected spatial_hit null-termination check block in simulate_ballistics"
    );
}

#[test]
fn fix3_lvalue_insert_casts_option_methods_and_up_cascade() {
    let src = r#"
module test::fix3_mir @version(1.0.0);

relation ChildOf [exclusive];
component Pos { v: fix64 = 0.0 }
component TagA;
component TagB;
component Shield { hp: f32 = 10.0 }
component Transform { val: f32 = 1.0 }

sys test_ops(e: Entity, flag: bool) {
    let mut arr = [1.0, 2];
    arr[0] += 3;

    insert(e, if flag { { TagA {}, Shield { hp: 5.0 } } } else { TagB {} });

    for row in query(p: &mut Pos, sh: Option<&mut Shield>) {
        row.p.v += 0.5;
        if row.sh.is_some() && !row.sh.is_none() {
            row.sh.unwrap().hp += 1.0;
        }
    }

    for row in query(tr: &Transform).up<ChildOf>() {
        let _x = row.tr.val;
    }
}
"#;
    let sema = analyze_source("fix3_mir.strata", src);
    assert!(sema.ok(), "{:#?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("fix3 MIR must verify");

    let f = mir
        .functions
        .iter()
        .find(|f| f.name == "test_ops")
        .expect("test_ops");
    let stmts: Vec<_> = f.blocks.iter().flat_map(|b| &b.stmts).collect();

    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::ArrayStore { .. })),
        "expected ArrayStore for arr[0] += 3"
    );
    assert!(
        stmts.iter().any(|s| matches!(
            s.inst,
            Inst::Cast {
                target_ty: strata_mir::MirType::Fix64,
                ..
            }
        )),
        "expected explicit Cast to Fix64 for p.p.v += 0.5"
    );
    assert!(
        stmts.iter().any(|s| matches!(
            s.inst,
            Inst::CmdInsert {
                ref component,
                data: None,
                ..
            } if component == "TagA" || component == "TagB"
        )),
        "expected ZST TagA/TagB CmdInsert with data: None across if/bundle arms"
    );
    assert!(
        !stmts.iter().any(|s| matches!(
            s.inst,
            Inst::CmdInsert { ref component, .. } if component == "Component"
        )),
        "must not emit bogus Component CmdInsert"
    );

    // OptionalWrite coalescing must flush ONLY on opt_present_* path, never opt_absent_*
    for bb in &f.blocks {
        if bb.label.starts_with("opt_absent_") {
            assert!(
                !bb.stmts.iter().any(|s| matches!(
                    s.inst,
                    Inst::IterMarkChangedRange { .. } | Inst::DirtyRunRecordRow { .. }
                )),
                "opt_absent block `{}` must never record or flush dirty runs",
                bb.label
            );
            if let Terminator::Branch { else_bb, .. } = bb.terminator {
                assert!(
                    !f.blocks[else_bb.0 as usize].label.ends_with("_flush"),
                    "opt_absent_row_hdr must not branch to a flush block"
                );
            }
        }
    }

    // IterUpCascade must appear in row_body (not chunk_hdr) while chunk_hdr uses IterNextChunk
    let q1_hdr = f
        .blocks
        .iter()
        .find(|b| b.label == "q1_chunk_hdr")
        .expect("q1_chunk_hdr");
    assert!(
        q1_hdr
            .stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::IterNextChunk { query_idx: 1 })),
        "q1_chunk_hdr must use IterNextChunk"
    );
    assert!(
        stmts.iter().any(|s| matches!(
            s.inst,
            Inst::IterUpCascade {
                query_idx: 1,
                ref relation,
                term_idx: 0,
                ..
            } if relation == "ChildOf"
        )),
        "expected per-row IterUpCascade in q1_row_body"
    );
}

#[test]
fn multi_option_terms_up_cascade_and_spatial_name_resolution() {
    let src = r#"
module test::gate3_mir_fixes @version(1.0.0);

component Pos2 { xy: vec2 = vec2(0.0, 0.0) }
component Pos3 { xyz: vec3 = vec3(0.0, 0.0, 0.0) }
component OptRO { w: f32 = 1.0 }
component OptRW { bonus: i32 = 10 }
component OptSel { mark: i32 = 0 }
component OptStat { some_ro: u32 = 0, some_rw: u32 = 0, sum_w: f32 = 0.0 }
component Faction { team: u32 = 0, mult: f32 = 1.0 }
component NodeAcc { node_id: u32 = 0, total: f32 = 0.0, ticks: u32 = 0 }

spatial_grid Grid2D(
    cell_size: 4.0_m,
    bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m),
    capacity: 64,
) over Pos2 by Pos2.xy;

spatial_history Hist3D(
    frames: 4,
    cell_size: 4.0_m,
    bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m),
    capacity: 64,
) over Pos3 by Pos3.xyz;

sys multi_opt(g: &res Grid2D, h: &res Hist3D) {
    for row in query(st: &mut OptStat, sel: Option<&mut? OptSel>, ro: Option<&OptRO>, rw: Option<&mut OptRW>) {
        if row.ro.is_some() {
            row.st.some_ro += 1;
            row.st.sum_w += row.ro.unwrap().w;
        }
        if row.sel.is_some() {
            row.sel.unwrap().mark += 1;
        }
        if row.rw.is_some() {
            row.st.some_rw += 1;
            row.rw.unwrap().bonus += 5;
        }
        if row.st.some_ro > 999 {
            break;
        }
    }

    for row in query(acc: &mut NodeAcc, fac: Option<&Faction>).up<ChildOf>() {
        if row.fac.is_some() {
            let f = row.fac.unwrap();
            row.acc.total += f.mult;
            row.acc.ticks += 1;
        }
    }

    for hit in g.query_disc(vec2(0.0, 0.0), 4.0_m) {
        let _e = hit.id;
    }
    for hit in h.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(4.0, 0.0, 0.0)) {
        let _e = hit.id;
    }
}
"#;
    let sema = analyze_source("gate3_mir_fixes.strata", src);
    assert!(sema.ok(), "{:#?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("gate3_mir_fixes MIR must verify");

    let f = mir
        .functions
        .iter()
        .find(|f| f.name == "multi_opt")
        .expect("multi_opt");

    // 1. Entry block 0 must NOT contain fallback OptionalChunkIsPresent or IterCol* from multi-Option queries.
    assert!(
        !f.blocks[0].stmts.iter().any(|s| matches!(
            s.inst,
            Inst::OptionalChunkIsPresent { .. }
                | Inst::IterColRead { .. }
                | Inst::IterColWrite { .. }
        )),
        "multi-Option query must not fall back to entry block 0"
    );

    // 3 optional terms -> 2^3 = 8 specialized q0_row_hdr blocks.
    let q0_row_hdrs: Vec<_> = f
        .blocks
        .iter()
        .filter(|b| b.label.ends_with("q0_row_hdr"))
        .collect();
    assert_eq!(
        q0_row_hdrs.len(),
        8,
        "expected 2^3 = 8 specialized q0_row_hdr blocks"
    );

    // `OptSel` (term 1) and `OptRW` (term 3) are both `OptionalWrite`: each must flush on
    // exactly 4 of the 8 specialized paths (and both flush on the 2 paths where both are present).
    let exits_through = |start_bb: strata_mir::BlockId, target_label: &str| -> bool {
        let mut cur = start_bb;
        for _ in 0..8 {
            let bb = &f.blocks[cur.0 as usize];
            if bb.label == target_label {
                return true;
            }
            match bb.terminator {
                Terminator::Goto(nxt) => cur = nxt,
                _ => break,
            }
        }
        false
    };
    let mut t1_flushes = 0usize;
    let mut t3_flushes = 0usize;
    let mut both_flushes = 0usize;
    for b in &q0_row_hdrs {
        if let Terminator::Branch { else_bb, .. } = b.terminator {
            let has_t1 = exits_through(else_bb, "q0_t1_flush");
            let has_t3 = exits_through(else_bb, "q0_t3_flush");
            if has_t1 {
                t1_flushes += 1;
            }
            if has_t3 {
                t3_flushes += 1;
            }
            if has_t1 && has_t3 {
                both_flushes += 1;
            }
        }
    }
    assert_eq!(
        (t1_flushes, t3_flushes, both_flushes),
        (4, 4, 2),
        "expected OptSel and OptRW flushes on their exact 4 present paths (2 overlapping)"
    );

    // 2. In q1 (`query(acc: &mut NodeAcc, fac: Option<&Faction>).up<ChildOf>()`):
    //    `acc` (term 0) must use RowPtr (local entity component), NOT IterUpCascade;
    //    `fac` (term 1) must use IterUpCascade; and `row.fac.is_some()` must check `!= 0` on ptr.
    let stmts: Vec<_> = f.blocks.iter().flat_map(|b| &b.stmts).collect();
    assert!(
        !stmts.iter().any(|s| matches!(
            s.inst,
            Inst::IterUpCascade {
                query_idx: 1,
                term_idx: 0,
                ..
            }
        )),
        "required term `acc` in `.up<ChildOf>()` with Option term must read local RowPtr, not IterUpCascade"
    );
    assert!(
        stmts.iter().any(|s| matches!(
            s.inst,
            Inst::IterUpCascade {
                query_idx: 1,
                ref relation,
                term_idx: 1,
                ..
            } if relation == "ChildOf"
        )),
        "optional term `fac` must emit IterUpCascade for term_idx 1"
    );
    assert!(
        stmts.iter().any(|s| {
            s.dst
                .is_some_and(|d| f.locals[d.0 as usize].name == "up_opt_present")
                && matches!(s.inst, Inst::BinOp { ref op, .. } if op == "!=")
        }),
        "row.fac.is_some() on Option<&T>.up<ChildOf>() must check effective pointer != null"
    );

    // 3. Spatial queries must resolve param names `"g"`/`"h"` to `"Grid2D"`/`"Hist3D"`.
    assert!(
        stmts.iter().any(|s| matches!(
            s.inst,
            Inst::SpatialQueryDisc { ref grid_name, .. } if grid_name == "Grid2D"
        )),
        "expected SpatialQueryDisc grid_name == \"Grid2D\""
    );
    assert!(
        stmts.iter().any(|s| matches!(
            s.inst,
            Inst::SpatialQuerySegmentAt { ref history_name, .. } if history_name == "Hist3D"
        )),
        "expected SpatialQuerySegmentAt history_name == \"Hist3D\""
    );
}

#[test]
fn task_lowering_distinguishes_dense_and_sparse_task_state() {
    let src = r#"
module test::task_storage @version(1.0.0);

component Actor { alive: bool = true, hp: f32 = 100.0 }
@sparse component SparseAura { radius: f32 = 2.0 }

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

task DenseOnSparse(dur: f32)
    on (aura: &mut SparseAura)
{
    aura.radius += 1.0;
    wait(dur);
}

@sparse
task SparseDash(dur: f32)
    on (a: &mut Actor)
{
    a.hp += 5.0;
    wait(dur);
}

schedule FixedUpdate { ProcessOrder, DenseOnSparse, SparseDash }
"#;
    let analyzed = analyze_source("task_storage.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    verify_mir(&mir).expect("mixed dense and @sparse tasks must verify");

    // 1. Non-@sparse `ProcessOrder` with dense `on (a: &Actor)`:
    //    term 0 (`Actor`) -> dense IterColRead + RowPtr(is_sparse: false)
    //    term 1 (`__task_state`) -> dense IterColWrite + RowPtr(is_sparse: false)
    let proc_fn = mir
        .functions
        .iter()
        .find(|f| f.name == "ProcessOrder")
        .expect("ProcessOrder");
    assert_eq!(proc_fn.query_bindings[0].terms.len(), 2);
    assert!(!proc_fn.query_bindings[0].terms[0].is_sparse);
    assert!(!proc_fn.query_bindings[0].terms[1].is_sparse);
    let proc_stmts: Vec<_> = proc_fn.blocks.iter().flat_map(|b| &b.stmts).collect();
    let proc_state_col = proc_stmts
        .iter()
        .find(|s| {
            matches!(
                s.inst,
                Inst::IterColWrite {
                    query_idx: 0,
                    term_idx: 1,
                    ..
                }
            )
        })
        .and_then(|s| s.dst)
        .expect("ProcessOrder state term must emit IterColWrite");
    assert!(
        !proc_stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::IterColRowsWrite { .. })),
        "ProcessOrder has no sparse terms and must not emit IterColRowsWrite"
    );
    assert!(
        proc_stmts.iter().any(|s| matches!(
            s.inst,
            Inst::RowPtr { col_ptr, is_sparse: false, .. } if col_ptr == proc_state_col
        )),
        "ProcessOrder state RowPtr must have is_sparse: false"
    );

    // 2. Non-@sparse `DenseOnSparse` with `@sparse` `on (aura: &mut SparseAura)`:
    //    term 0 (`SparseAura`) -> sparse IterColRowsWrite + RowPtr(is_sparse: true)
    //    term 1 (`__task_state`) -> dense IterColWrite + RowPtr(is_sparse: false)
    let dos_fn = mir
        .functions
        .iter()
        .find(|f| f.name == "DenseOnSparse")
        .expect("DenseOnSparse");
    assert!(dos_fn.query_bindings[0].terms[0].is_sparse);
    assert!(!dos_fn.query_bindings[0].terms[1].is_sparse);
    let dos_stmts: Vec<_> = dos_fn.blocks.iter().flat_map(|b| &b.stmts).collect();
    let dos_on_col = dos_stmts
        .iter()
        .find(|s| {
            matches!(
                s.inst,
                Inst::IterColRowsWrite {
                    query_idx: 0,
                    term_idx: 0,
                    ..
                }
            )
        })
        .and_then(|s| s.dst)
        .expect("DenseOnSparse @sparse on-term must emit IterColRowsWrite");
    let dos_state_col = dos_stmts
        .iter()
        .find(|s| {
            matches!(
                s.inst,
                Inst::IterColWrite {
                    query_idx: 0,
                    term_idx: 1,
                    ..
                }
            )
        })
        .and_then(|s| s.dst)
        .expect("DenseOnSparse non-@sparse state term must emit IterColWrite");
    assert!(dos_stmts.iter().any(|s| matches!(
        s.inst,
        Inst::RowPtr { col_ptr, is_sparse: true, .. } if col_ptr == dos_on_col
    )));
    assert!(dos_stmts.iter().any(|s| matches!(
        s.inst,
        Inst::RowPtr { col_ptr, is_sparse: false, .. } if col_ptr == dos_state_col
    )));

    // 3. `@sparse task SparseDash` with dense `on (a: &mut Actor)`:
    //    term 0 (`Actor`) -> dense IterColWrite + RowPtr(is_sparse: false)
    //    term 1 (`__task_state`) -> sparse IterColRowsWrite + RowPtr(is_sparse: true)
    let dash_fn = mir
        .functions
        .iter()
        .find(|f| f.name == "SparseDash")
        .expect("SparseDash");
    assert!(!dash_fn.query_bindings[0].terms[0].is_sparse);
    assert!(dash_fn.query_bindings[0].terms[1].is_sparse);
    let dash_stmts: Vec<_> = dash_fn.blocks.iter().flat_map(|b| &b.stmts).collect();
    let dash_on_col = dash_stmts
        .iter()
        .find(|s| {
            matches!(
                s.inst,
                Inst::IterColWrite {
                    query_idx: 0,
                    term_idx: 0,
                    ..
                }
            )
        })
        .and_then(|s| s.dst)
        .expect("SparseDash dense on-term must emit IterColWrite");
    let dash_state_col = dash_stmts
        .iter()
        .find(|s| {
            matches!(
                s.inst,
                Inst::IterColRowsWrite {
                    query_idx: 0,
                    term_idx: 1,
                    ..
                }
            )
        })
        .and_then(|s| s.dst)
        .expect("SparseDash @sparse state term must emit IterColRowsWrite");
    assert!(dash_stmts.iter().any(|s| matches!(
        s.inst,
        Inst::RowPtr { col_ptr, is_sparse: false, .. } if col_ptr == dash_on_col
    )));
    assert!(dash_stmts.iter().any(|s| matches!(
        s.inst,
        Inst::RowPtr { col_ptr, is_sparse: true, .. } if col_ptr == dash_state_col
    )));
}

#[test]
fn verify_rejects_dense_term_using_sparse_iter_col_rows() {
    use indexmap::IndexMap;
    use strata_mir::{
        BasicBlock, BlockId, MirFnKind, MirFunction, MirModule, MirNetHandshake, MirQueryBinding,
        MirQueryTermBinding, MirStmt, MirType, Terminator,
    };
    use strata_sema::access::{QueryAccessDesc, QueryTerm, TermAccessMode};

    let mut f = MirFunction::new("bad_dense_task", MirFnKind::SynthesizedTask);
    f.queries.push(QueryAccessDesc {
        terms: vec![QueryTerm {
            storage_key: "bad_dense_task".to_owned(),
            field_name: None,
            mode: TermAccessMode::Write,
            byte_start: 0,
            byte_end: 0,
        }],
        ..Default::default()
    });
    f.query_bindings.push(MirQueryBinding {
        query_idx: 0,
        terms: vec![MirQueryTermBinding {
            term_idx: 0,
            alias: "__task_state".to_owned(),
            storage_key: "bad_dense_task".to_owned(),
            canonical_component: "m::bad_dense_task".to_owned(),
            field_name: None,
            mode: TermAccessMode::Write,
            is_sparse: false,
        }],
        with_filters: Vec::new(),
        without_filters: Vec::new(),
        is_point_lookup: false,
    });
    let col = f.alloc_local("bad_rows", MirType::MutPtr);
    f.blocks.push(BasicBlock {
        id: BlockId(0),
        label: "entry".to_owned(),
        stmts: vec![MirStmt {
            dst: Some(col),
            inst: Inst::IterColRowsWrite {
                query_idx: 0,
                term_idx: 0,
                storage_key: "bad_dense_task".to_owned(),
            },
        }],
        terminator: Terminator::Return(None),
    });
    let module = MirModule {
        module_path: "m".to_owned(),
        is_deterministic: false,
        layouts: Vec::new(),
        enums: Vec::new(),
        consts: Vec::new(),
        tables: Vec::new(),
        curves: Vec::new(),
        relations: Vec::new(),
        spatial_indices: Vec::new(),
        timelines: Vec::new(),
        tasks: Vec::new(),
        fsms: Vec::new(),
        objects: Vec::new(),
        migrations: Vec::new(),
        fns: Vec::new(),
        functions: vec![f],
        schedules: Vec::new(),
        sim_tests: Vec::new(),
        field_defaults: IndexMap::new(),
        rpcs: Vec::new(),
        net_components: Vec::new(),
        net_sim_tests: Vec::new(),
        net_handshake: MirNetHandshake::default(),
        net_stream_ops: Vec::new(),
    };
    let errs = verify_mir(&module).expect_err("dense term using IterColRowsWrite must fail");
    assert!(
        errs.iter()
            .any(|e| format!("{e:?}").contains("used sparse IterColRows* instead of IterCol*")),
        "unexpected verify errors: {errs:?}"
    );
}

#[test]
fn mir_step2_iter5_guarded_query_one_non_unit_fail_returns_zero() {
    use strata_sema::access::TermAccessMode;
    use strata_sema::hir::{AnalyzedModule, HirExpr, HirFn, HirQuery, HirQueryTerm, HirStmt};
    use strata_sema::types::Ty;

    let mut analyzed = AnalyzedModule {
        module_path: "test::q1_non_unit".to_owned(),
        version: None,
        is_deterministic: false,
        layouts: Default::default(),
        soa_strata: Default::default(),
        enums: Default::default(),
        tags: Vec::new(),
        consts: Vec::new(),
        tables: Vec::new(),
        curves: Vec::new(),
        relations: Vec::new(),
        spatial_indices: Vec::new(),
        timelines: Vec::new(),
        tasks: Vec::new(),
        fsms: Vec::new(),
        callables: Vec::new(),
        fns: Vec::new(),
        objects: Vec::new(),
        migrations: Vec::new(),
        schedules: Vec::new(),
        sim_tests: Vec::new(),
        field_defaults: Default::default(),
        concurrency_graph: Default::default(),
        diagnostics: Vec::new(),
        rpcs: Vec::new(),
        net_sim_tests: Vec::new(),
        net_components: Vec::new(),
        net_schema_fingerprint: 0,
        node_groups: Default::default(),
        pure_fns: Vec::new(),
        authorities: Default::default(),
    };
    analyzed.fns.push(HirFn {
        name: "non_unit_q1".to_owned(),
        generic_params: Vec::new(),
        params: Vec::new(),
        ret_ty: Ty::I32,
        body: vec![HirStmt::Let {
            pattern: strata_sema::hir::HirPattern::Binding {
                name: "r".to_owned(),
                mutable: false,
            },
            ty: None,
            value: HirExpr::Query(HirQuery {
                is_point_lookup: true,
                terms: vec![HirQueryTerm {
                    alias: "w".to_owned(),
                    storage_key: "Wallet".to_owned(),
                    canonical_component: "test::q1_non_unit::Wallet".to_owned(),
                    field_name: None,
                    mode: TermAccessMode::Read,
                    is_sparse: false,
                }],
                with_filters: Vec::new(),
                without_filters: Vec::new(),
                allow_filters: Vec::new(),
                has_filters: Vec::new(),
                changed_filters: Vec::new(),
                added_filters: Vec::new(),
                where_pred: None,
                on_target: None,
                up_relation: None,
                is_count: false,
                is_unwrap: true,
                query_idx: Some(0),
            }),
            is_uniform: false,
            else_block: Vec::new(),
        }],
        tail: Some(HirExpr::IntLit {
            value: 7,
            ty: Ty::I32,
        }),
        byte_range: (0, 0),
        is_node_pure: false,
        node_group: None,
    });

    let mir = strata_mir::lower_to_mir(&analyzed);
    verify_mir(&mir).expect("lowered MIR must verify");
    let f = &mir.fns[0];
    let ok_bb = f
        .blocks
        .iter()
        .find(|b| b.label.starts_with("q1_unwrap_ok"))
        .expect("q1_unwrap_ok block")
        .id;
    let fail_bb = f
        .blocks
        .iter()
        .find(|b| b.label.starts_with("q1_unwrap_fail"))
        .expect("q1_unwrap_fail block");
    assert!(
        !matches!(fail_bb.terminator, Terminator::Goto(dst) if dst == ok_bb),
        "fail_bb must never fall through to ok_bb with null pointers: {:?}",
        fail_bb.terminator
    );
    assert!(
        matches!(fail_bb.terminator, Terminator::Return(Some(_))),
        "non-Unit fail_bb must return typed fallback value: {:?}",
        fail_bb.terminator
    );
}

#[test]
fn mir_step2_iter6_local_copied_struct_field_write_uses_slot_alloc_directly() {
    use strata_mir::ir::Inst;
    let src = r#"
module test::local_struct_write @version(1.0.0);

struct Sub { x: i32 = 5 }
component Out { sub: Sub = Sub { x: 5 }, last_sx: i32 = 0 }
object ObjA { Out {} }

sys update_sub() {
    let r = query_one(o: &mut Out).on(ObjA).unwrap();
    let mut sv = r.o.sub;
    sv.x = 77;
    r.o.last_sx = sv.x;
}
"#;
    let analyzed = strata_sema::analyze_source("local_struct_write.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = strata_mir::lower_to_mir(&analyzed);
    verify_mir(&mir).expect("MIR must verify");

    let f = mir
        .functions
        .iter()
        .find(|s| s.name == "update_sub")
        .expect("update_sub system");
    let mut slot_allocs = std::collections::HashSet::new();
    let mut found_sub_store = false;
    for bb in &f.blocks {
        for st in &bb.stmts {
            if let Inst::SlotAlloc { .. } = &st.inst
                && let Some(d) = st.dst
            {
                slot_allocs.insert(d);
            }
            if let Inst::FieldStore {
                base_ptr, field, ..
            } = &st.inst
                && field == "x"
            {
                assert!(
                    slot_allocs.contains(base_ptr),
                    "FieldStore to local struct field `sv.x` must target SlotAlloc directly (not SlotLoad), got base_ptr={base_ptr:?}"
                );
                found_sub_store = true;
            }
        }
    }
    assert!(found_sub_store, "expected FieldStore to `sv.x`");
}

#[test]
fn mir_step2_iter7_stored_optional_row_and_loop_scope_restored() {
    let src = r#"
module test::iter7_opt_row_scope @version(1.0.0);

component Main { val: i32 = 10 }
component OptComp { bonus: i32 = 5 }
resource Out {
    s_if_let: i32 = 0,
    s_match: i32 = 0,
    s_else: i32 = 0,
    s_is_some: bool = false,
    s_is_none: bool = true,
    s_unwrap: i32 = 0,
    s_expect: i32 = 0,
    s_oc_hp: i32 = 0,
    s_d_pos: i32 = 0,
}

object ObjTarget {
    Main { val: 42 },
    OptComp { bonus: 7 },
}

sys step_all(out: &mut res Out) {
    let opt_r = query_one(m: &Main, oc: Option<&OptComp>).on(ObjTarget);
    let opt2 = opt_r;
    out.s_is_some = opt2.is_some();
    out.s_is_none = opt2.is_none();

    if let Some(r1) = opt2 {
        out.s_if_let = r1.m.val;
        if r1.oc.is_some() {
            out.s_oc_hp = r1.oc.unwrap().bonus;
        }
    }

    match opt2 {
        Some(rm) => { out.s_match = rm.m.val; }
        None => { out.s_match = -1; }
    }

    let Some(re) = opt2 else {
        out.s_else = -2;
        return;
    };
    out.s_else = re.m.val;

    let ru = opt2.unwrap();
    out.s_unwrap = ru.m.val;

    let rex = Some(ru).expect("must exist");
    out.s_expect = rex.m.val;

    // Loop-local `s_d_pos` shadowing an outer `s_d_pos` must not leak out of the query loop.
    let s_d_pos: i32 = 100;
    for s_d_pos in query(s_d_pos: &Main.val) {
        let _inner = s_d_pos;
    }
    out.s_d_pos = s_d_pos + 1;
}

schedule FixedUpdate { step_all }
"#;
    let analyzed = analyze_source("iter7_opt_row_scope.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    verify_mir(&mir).expect("MIR with stored Option<QueryRow> and shadowed loop vars must verify");
}

#[test]
fn mir_step2_iter8_all_fixes_lower_and_verify() {
    use strata_mir::{MirConstVal, MirType};
    let src = r#"
module test::mir_iter8 @version(1.0.0);

struct Sub {
    x: i32 = 3,
    fx: fix32 = 1.5,
}
const C_SUB: Sub = Sub { x: 7, fx: 2.5 };
const C_ARR: [fix32; 2] = [1.5, 2.5];

component RoComp { val: i32 = 10 }
component RwComp { val: i32 = 10 }
component VecBitComp {
    bs64: BitSet<64> = bits(0, 63),
    bs128: BitSet<128> = bits(0, 70),
    va: vec3a = vec3a(1.0, 2.0, 3.0),
    va_arr: [vec3a; 2] = [vec3a(1.0, 0.0, 0.0), Vec3a(0.0, 1.0, 0.0)],
}
component Out {
    val: i32 = 10,
    sub: Sub = C_SUB,
    fx_arr: [fix32; 2] = C_ARR,
    rt_fx32_arr: [fix32; 2] = [0.0, 0.0],
    sum_ro: i32 = 0,
}

event EvA { inc: i32 }
event EvB { entity: Ref<Entity>, inc: i32 }

fn helper_touch(h: &mut Out, d: i32) {
    h.val += d;
}

@node_pure fn id_f32(v: f32) -> f32 { v }

sys step_ops(e: Entity) {
    // Fix 1: projected SingleTermPtr read vs write isolation
    for x in query(x: &RoComp.val) {
        let mut hp = x;
        hp = 99;
    }
    for mut v in query(v: &mut RwComp.val) {
        let mut copy_v = v;
        copy_v = 99;
        v = 42;
    }
    for row in query(vb: &mut VecBitComp) {
        row.vb.bs128 = bits(1, 75);
        row.vb.va = Vec3a(4.0, 5.0, 6.0);
    }
    // Fix 2 + 9: tuple destructuring with RowAlias + &mut Comp helper fn
    let opt_q = query_one(o: &mut Out).on(e);
    if let Some(q1) = opt_q {
        let (mut n, row_b) = (10, q1);
        n += 1;
        helper_touch(row_b.o, n);
        row_b.o.rt_fx32_arr = [id_f32(1.25_f32), id_f32(-0.5_f32)];
        trigger(EvA { inc: 2 });
        trigger(EvB { entity: e, inc: 3 });
    }
}

obs on_ev_a(trg: &Trigger<EvA>) {
    for row in query(o: &mut Out) {
        row.o.sum_ro += trg.payload.inc;
    }
}

obs on_ev_b(trg: &Trigger<EvB, Out>) {
    let opt = query_one(o: &mut Out).on(trg.target);
    if let Some(r) = opt {
        r.o.sum_ro += trg.payload.inc;
    }
}

schedule FixedUpdate { step_ops }
"#;
    let analyzed = analyze_source("mir_iter8.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    verify_mir(&mir).expect("iter8 MIR must verify");

    let hf = mir
        .fns
        .iter()
        .find(|f| f.name.ends_with("helper_touch"))
        .expect("helper_touch");
    assert!(
        hf.params[0]
            .layout_key
            .as_deref()
            .is_some_and(|k| k.ends_with("Out")),
        "MirParam.layout_key must preserve component layout key: {:?}",
        hf.params
    );

    let defs = mir
        .field_defaults
        .get("test::mir_iter8::Out")
        .expect("Out field defaults");
    assert!(
        matches!(defs.get("sub"), Some(MirConstVal::Struct { .. })),
        "const-indirected StructLit default must materialize: {:?}",
        defs.get("sub")
    );
    assert!(
        matches!(defs.get("fx_arr"), Some(MirConstVal::Array(_))),
        "const-indirected ArrayLit default must materialize: {:?}",
        defs.get("fx_arr")
    );

    let step = mir
        .functions
        .iter()
        .find(|f| f.name == "step_ops")
        .expect("step_ops");
    let has_vec4_vec3a = step.locals.iter().any(|l| l.ty == MirType::Vec4);
    assert!(has_vec4_vec3a, "vec3a must lower to 16-byte MirType::Vec4");
}

#[test]
fn mir_step2_iter9_const_struct_u64_bits_and_bitset128_arrays() {
    use strata_mir::MirConstVal;
    let src = r#"
module test::mir_iter9_bits @version(1.0.0);

enum BitKind { A = 0, B = 1, C = 2 }

struct BsU64 { mask: u64 = 0 }
struct BsBox {
    s_bs64: BitSet<64> = bits(BitKind::A, BitKind::C),
    s_bs128: BitSet<128> = bits(1, 33, 70),
    s_u64: u64 = 0,
}

const C_MASK: BsU64 = BsU64 { mask: bits(BitKind::A, BitKind::C) };
const C_BOX: BsBox = BsBox {
    s_bs64: bits(BitKind::A, BitKind::B),
    s_bs128: bits(1, 33, 70),
    s_u64: bits(BitKind::B, BitKind::C),
};

component MaskPod {
    ov_m: BsU64 = C_MASK,
    rt_m: BsU64 = BsU64 {},
    arr128: [BitSet<128>; 2] = [bits(0, 65), bits(1, 90)],
}

object ObjBox {
    MaskPod {
        ov_m: C_MASK,
        arr128: [bits(1, 33, 70), bits(2, 75)],
    },
}

sys step_mask() {
    for row in query(p: &mut MaskPod) {
        row.p.rt_m = C_MASK;
        let _b = C_BOX;
    }
}

schedule FixedUpdate { step_mask }
"#;
    let analyzed = analyze_source("mir_iter9_bits.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    verify_mir(&mir).expect("iter9 MIR must verify");

    let defs = mir
        .field_defaults
        .get("test::mir_iter9_bits::MaskPod")
        .expect("MaskPod field defaults");
    match defs.get("ov_m") {
        Some(MirConstVal::Struct { fields, .. }) => {
            let mask_val = fields
                .iter()
                .find(|(k, _)| k == "mask")
                .map(|(_, v)| v)
                .expect("mask field in ov_m default");
            assert_eq!(
                *mask_val,
                MirConstVal::Int(5),
                "C_MASK.mask must evaluate to MirConstVal::Int(5), not Array(bit_indices)"
            );
        }
        other => panic!("expected Struct default for ov_m, got {other:?}"),
    }

    let step = mir
        .functions
        .iter()
        .find(|f| f.name == "step_mask")
        .expect("step_mask");
    let has_const_5 = step
        .blocks
        .iter()
        .flat_map(|b| &b.stmts)
        .any(|s| matches!(s.inst, Inst::ConstInt { value: 5 }));
    assert!(
        has_const_5,
        "runtime C_MASK materialization must emit ConstInt {{ value: 5 }}"
    );
}

#[test]
fn mir_wave2a_pm04_quat_mul_pm07_reduce_pm15_par_mut_pm16_i64_min() {
    use strata_mir::MirType;
    let src = r#"
module test::wave2a_pm @version(1.0.0);

const C_MIN: i64 = -9223372036854775808;

component Body {
    rot: quat = quat(0.0, 0.0, 0.0, 1.0),
    dir: vec3 = vec3(1.0, 0.0, 0.0),
    hp: i32 = 10,
    flag: bool = true,
}

component Counters {
    c: u32 = 0,
    any_alive: bool = false,
    all_flag: bool = false,
    min_val: i64 = 0,
}

component DummyTag {}

@deterministic
fn det_rot_step(q1: quat, q2: quat, v: vec3) -> vec3 {
    let mut qr = q1 * q2;
    qr *= q2;
    qr * v
}

sys rot_and_lit(out: &mut Counters) {
    let _m: i64 = -9223372036854775808;
    let _c = C_MIN;
    for row in query(b: &mut Body) {
        let q = row.b.rot * row.b.rot;
        row.b.rot = q;
        row.b.dir = row.b.rot * row.b.dir;
    }
    out.min_val = _m;
}

sys count_and_check(out: &mut Counters) {
    let (cnt, has_any, every_flag) = for row in query(b: &Body) reduce (
        cnt: count(row.b.hp > 0),
        has_any: any(row.b.hp > 5),
        every_flag: all(row.b.flag)
    );
    out.c = cnt;
    out.any_alive = has_any;
    out.all_flag = every_flag;
}

@par(chunk = 64, read_only)
sys par_mut_guard() {
    for _t in query(t: &DummyTag) {}
    for row in query(b: &mut Body) {
        row.b.hp += 1;
    }
}

schedule FixedUpdate { rot_and_lit, count_and_check, par_mut_guard }
"#;
    let analyzed = analyze_source("wave2a_pm.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    verify_mir(&mir).expect("wave2a PM MIR must verify");

    // PM-04: quat * quat and quat * vec3 emit quat_mul / quat_mul_vec3 (both fn and sys)
    let det_fn = mir
        .fns
        .iter()
        .find(|f| f.name == "det_rot_step")
        .expect("det_rot_step");
    let qmul_count = det_fn
        .blocks
        .iter()
        .flat_map(|b| &b.stmts)
        .filter(|s| matches!(&s.inst, Inst::BinOp { op, .. } if op == "quat_mul"))
        .count();
    let has_det_qvec = det_fn.blocks.iter().flat_map(|b| &b.stmts).any(|s| {
        s.dst
            .is_some_and(|d| det_fn.locals[d.0 as usize].ty == MirType::Vec3)
            && matches!(&s.inst, Inst::BinOp { op, .. } if op == "quat_mul_vec3")
    });
    assert_eq!(
        qmul_count, 2,
        "quat * quat and quat *= quat must emit 2 quat_mul ops"
    );
    assert!(
        has_det_qvec,
        "quat * vec3 must emit BinOp(quat_mul_vec3) -> Vec3"
    );

    // PM-16: i64::MIN literal intact without overflow
    let rot_fn = mir
        .functions
        .iter()
        .find(|f| f.name == "rot_and_lit")
        .expect("rot_and_lit");
    assert!(
        rot_fn
            .blocks
            .iter()
            .flat_map(|b| &b.stmts)
            .any(|s| matches!(
                s.inst,
                Inst::ConstInt { value } if value == i64::MIN
            )),
        "i64::MIN literal must lower cleanly without overflow"
    );

    // PM-07: 1-arg count/any/all accumulate inside row_body (not before loop)
    let sys_fn = mir
        .functions
        .iter()
        .find(|f| f.name == "count_and_check")
        .expect("count_and_check");
    let has_row_count = sys_fn.blocks.iter().any(|b| {
        b.label.contains("row_body")
            && b.stmts.iter().any(|s| {
                matches!(
                    &s.inst,
                    Inst::ReduceAccum { op, val, .. }
                        if op == "count" && sys_fn.locals[val.0 as usize].ty == MirType::Bool
                )
            })
    });
    let has_row_any = sys_fn.blocks.iter().any(|b| {
        b.label.contains("row_body")
            && b.stmts
                .iter()
                .any(|s| matches!(&s.inst, Inst::ReduceAccum { op, .. } if op == "any"))
    });
    let has_row_all = sys_fn.blocks.iter().any(|b| {
        b.label.contains("row_body")
            && b.stmts
                .iter()
                .any(|s| matches!(&s.inst, Inst::ReduceAccum { op, .. } if op == "all"))
    });
    assert!(has_row_count && has_row_any && has_row_all);
    let entry_red_init_cnt = sys_fn.blocks.iter().any(|b| {
        !b.label.contains("row_body")
            && b.stmts.iter().any(|s| {
                matches!(&s.inst, Inst::ReduceInit { op, .. } if op == "count")
                    && s.dst
                        .is_some_and(|d| sys_fn.locals[d.0 as usize].ty == MirType::U32)
            })
    });
    assert!(entry_red_init_cnt, "count(pred) init must be U32(0)");

    // PM-15: @par(read_only) with a &mut query must emit ParForEachChunk for the &mut query
    let par_fn = mir
        .functions
        .iter()
        .find(|f| f.name == "par_mut_guard")
        .expect("par_mut_guard");
    let stmts: Vec<_> = par_fn.blocks.iter().flat_map(|b| &b.stmts).collect();
    assert_eq!(
        stmts
            .iter()
            .filter(|s| matches!(s.inst, Inst::ParForEachChunk { .. }))
            .count(),
        1,
        "@par(read_only) mutable query must emit ParForEachChunk"
    );
    assert_eq!(
        stmts
            .iter()
            .filter(|s| matches!(s.inst, Inst::ParForEachChunkReadonly { .. }))
            .count(),
        1,
        "only the readonly query may emit ParForEachChunkReadonly"
    );
}

#[test]
fn mir_wave2a_nested_lvalues_bitset_prop_smallvec_and_unknown_method_reject() {
    use strata_mir::MirType;
    use strata_sema::hir::{HirBinOp, HirCall, HirExpr, HirFn, HirParam, HirParamKind, HirStmt};
    use strata_sema::types::Ty;

    let src = r#"
module test::wave2a_tl @version(1.0.0);

struct Item {
    hp: i32 = 10,
    bs: BitSet<128> = bits(0),
}

struct Bag {
    arr128: [BitSet<128>; 2] = [bits(0, 70), bits(1, 90)],
}

component NestedState {
    mat: [[f32; 2]; 2] = [[1.0, 2.0], [3.0, 4.0]],
    cube: [[[i32; 2]; 2]; 2] = [[[1, 2], [3, 4]], [[5, 6], [7, 8]]],
    items: [Item; 2] = [Item {}, Item {}],
    arr128: [BitSet<128>; 2] = [bits(0, 70), bits(1, 90)],
    sv: SmallVec<i32, 4>,
    has_bit70: bool = false,
    sv_len: u32 = 0,
    sv_first: i32 = 0,
}

sys step_tl() {
    let mut local_bs128: BitSet<128> = bits(0, 70);
    local_bs128 = bits(1, 80);
    let mut local_arr128: [BitSet<128>; 2] = [bits(2, 75), bits(3, 95)];
    local_arr128 = [bits(4, 100), bits(5, 110)];
    let _bag = Bag { arr128: [bits(6, 72), bits(7, 120)] };

    for row in query(s: &mut NestedState) {
        row.s.mat[1][0] = 9.5;
        row.s.cube[1][0][1] = 42;
        row.s.items[1].hp = 99;
        row.s.arr128[1].set(70);
        row.s.arr128[1].clear(90);
        row.s.has_bit70 = row.s.arr128[1].has(70);
        row.s.sv.push(11);
        row.s.sv_len = row.s.sv.len();
        row.s.sv_first = row.s.sv[0];
        row.s.sv[0] = 22;
    }
}

schedule FixedUpdate { step_tl }
"#;
    let analyzed = analyze_source("wave2a_tl.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    verify_mir(&mir).expect("wave2a TL MIR must verify");

    let step = mir
        .functions
        .iter()
        .find(|f| f.name == "step_tl")
        .expect("step_tl");
    let stmts: Vec<_> = step.blocks.iter().flat_map(|b| &b.stmts).collect();

    // BUG-TL-01: expected BitSet<128> propagates into bits(...) via let, Assign, ArrayLit, StructLit
    let has_4word_arr = stmts.iter().any(|s| {
        matches!(
            &s.inst,
            Inst::ArrayInit { elems } if elems.len() == 4
        )
    });
    assert!(
        has_4word_arr,
        "BitSet<128> bits() must lower to 4-word ArrayInit"
    );
    // Word 2 for bit 70 (70 - 64 = 6 -> 1 << 6 = 64)
    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::ConstInt { value: 64 })),
        "bit 70 must pack into word 2 (ConstInt 64)"
    );

    // BUG-TL-06: nested lvalues emit ArrayIndex with MutPtr dst + ArrayStore / FieldStore / BitSet*
    let has_ptr_arr_idx = stmts.iter().any(|s| {
        matches!(s.inst, Inst::ArrayIndex { .. })
            && s.dst
                .is_some_and(|d| matches!(step.locals[d.0 as usize].ty, MirType::MutPtr))
    });
    assert!(
        has_ptr_arr_idx,
        "nested lvalue mat[i][j]/cube[i][j][k]/items[i].hp/arr128[i] must chain ArrayIndex -> MutPtr"
    );
    assert!(
        stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::BitSetSet { words: 4, .. }))
            && stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::BitSetClear { words: 4, .. }))
            && stmts
                .iter()
                .any(|s| matches!(s.inst, Inst::BitSetGet { words: 4, .. })),
        "arr128[1].set/clear/has must lower with words=4"
    );

    // BUG-TL-09a: SmallVec.push MUST NOT emit InputBufPush; lowers via len/data/ArrayStore
    assert!(
        !stmts
            .iter()
            .any(|s| matches!(s.inst, Inst::InputBufPush { .. })),
        "SmallVec.push must NEVER emit InputBufPush"
    );
    assert!(
        stmts.iter().any(|s| matches!(
            &s.inst,
            Inst::FieldLoad { layout_key, field, offset_bytes: 0, .. }
                if layout_key == "SmallVec" && field == "len"
        )) && stmts.iter().any(|s| matches!(
            &s.inst,
            Inst::FieldPtr { layout_key, field, offset_bytes: 8, .. }
                if layout_key == "SmallVec" && field == "data"
        )),
        "SmallVec push/len/index must access SmallVec len@0 and data@8"
    );

    // BUG-TL-02 & EQ-08: Unknown method and unknown field on known layout fail cleanly (never silent fallback)
    let mut bad_analyzed = analyzed.clone();
    bad_analyzed.fns.push(HirFn {
        name: "bad_method_fn".to_owned(),
        generic_params: Vec::new(),
        params: vec![HirParam {
            name: "x".to_owned(),
            ty: Ty::F32,
            kind: HirParamKind::Value,
            default: None,
            trigger_target: None,
        }],
        ret_ty: Ty::Unit,
        body: vec![HirStmt::Expr(HirExpr::Call(HirCall {
            receiver: Some(Box::new(HirExpr::Path {
                name: "x".to_owned(),
                ty: Ty::F32,
            })),
            callee: "totally_unknown_method".to_owned(),
            generic_args: Vec::new(),
            args: Vec::new(),
            arg_names: Vec::new(),
            ty: Ty::Unit,
        }))],
        tail: None,
        byte_range: (0, 0),
        is_node_pure: false,
        node_group: None,
    });
    let bad_mir = lower_to_mir(&bad_analyzed);
    assert!(
        verify_mir(&bad_mir).is_err(),
        "unknown method call must fail MIR verification cleanly instead of silent fallback"
    );

    // EQ-08: unknown field on known Item layout must fail cleanly
    let mut bad_field_analyzed = analyzed;
    bad_field_analyzed.fns.push(HirFn {
        name: "bad_field_fn".to_owned(),
        generic_params: Vec::new(),
        params: vec![HirParam {
            name: "it".to_owned(),
            ty: Ty::Named("Item".to_owned()),
            kind: HirParamKind::Value,
            default: None,
            trigger_target: None,
        }],
        ret_ty: Ty::F32,
        body: Vec::new(),
        tail: Some(HirExpr::Field {
            base: Box::new(HirExpr::Path {
                name: "it".to_owned(),
                ty: Ty::Named("Item".to_owned()),
            }),
            field: "nonexistent".to_owned(),
            ty: Ty::F32,
        }),
        byte_range: (0, 0),
        is_node_pure: false,
        node_group: None,
    });
    let bad_field_mir = lower_to_mir(&bad_field_analyzed);
    assert!(
        verify_mir(&bad_field_mir).is_err(),
        "unknown field on known layout must fail verification cleanly instead of (0, F32)"
    );
    let _ = HirBinOp::Add;
}

#[test]
fn mir_wave2a_spatial_radius_added_filters_and_custom_relation_parent() {
    use strata_mir::MirType;
    let src = r#"
module test::wave2a_rel_sw @version(1.0.0);

component Pos { xyz: vec3 = vec3(0.0, 0.0, 0.0), val: f32 = 0.0 }
component PosAdd { val: f32 = 0.0 }
component PosRel { val: f32 = 0.0 }
component PosBuiltIn { val: f32 = 0.0 }
relation Follows [exclusive];
relation ChildOf [exclusive];

spatial_history Hist(
    frames: 8,
    cell_size: 4.0_m,
    bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m),
    capacity: 64,
) over Pos by Pos.xyz;

sys seg_queries(h: &Hist, t: u32) {
    let p0 = vec3(0.0, 0.0, 0.0);
    let p1 = vec3(10.0, 0.0, 0.0);
    for hit in h.query_segment_at(t, p0, p1, 2.25) {
        let _e = hit.entity;
    }
    let _it = h.query_segment_at(t, p0, p1, 3.75);
    let _it_def = h.query_segment_at(t, p0, p1);
}

sys added_step() {
    for row in query(p: &mut PosAdd).added<PosAdd>() {
        row.p.val += 1.0;
    }
}

sys rel_follows() {
    for row in query(p: &PosRel).up<Follows>() {
        let _v = row.p.val;
    }
}

sys rel_childof() {
    for row in query(p: &PosBuiltIn).up<ChildOf>() {
        let _v2 = row.p.val;
    }
}

schedule FixedUpdate { seg_queries, added_step, rel_follows, rel_childof }
"#;
    let analyzed = analyze_source("wave2a_rel_sw.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    verify_mir(&mir).expect("wave2a rel/spatial MIR must verify");

    // BUG-SW-01: explicit radius in both SpatialSegmentAt loop and query_segment_at call, default 0.5
    let sys_fn = mir
        .functions
        .iter()
        .find(|f| f.name == "seg_queries")
        .expect("seg_queries");
    let seg_insts: Vec<_> = sys_fn
        .blocks
        .iter()
        .flat_map(|b| &b.stmts)
        .filter_map(|s| match &s.inst {
            Inst::SpatialQuerySegmentAt {
                start,
                end,
                radius,
                tick_offset,
                ..
            } => Some((*tick_offset, *start, *end, *radius)),
            _ => None,
        })
        .collect();
    assert_eq!(seg_insts.len(), 3);
    let const_float_for = |lid| {
        sys_fn.blocks.iter().flat_map(|b| &b.stmts).find_map(|s| {
            if s.dst == Some(lid)
                && let Inst::ConstFloat { value } = s.inst
            {
                Some(value)
            } else {
                None
            }
        })
    };
    assert_eq!(const_float_for(seg_insts[0].3), Some(2.25));
    assert_eq!(const_float_for(seg_insts[1].3), Some(3.75));
    assert_eq!(const_float_for(seg_insts[2].3), Some(0.5));
    // First arg (tick_offset) must match parameter `t` local (U32)
    assert_eq!(sys_fn.locals[seg_insts[0].0.0 as usize].ty, MirType::U32);
    let added_fn = mir
        .functions
        .iter()
        .find(|f| f.name == "added_step")
        .expect("added_step");
    assert!(
        !added_fn.added_terms.is_empty(),
        "added_terms must capture .added()"
    );

    // EQ-05 & GF-02: companion 8-byte FfiEntity component for Follows, NONE for ChildOf
    let follows_comp = mir
        .layouts
        .iter()
        .find(|l| l.canonical_name == "test::wave2a_rel_sw::__strata_rel_parent_Follows")
        .expect("companion parent layout for custom Follows relation");
    assert_eq!(follows_comp.size, 8);
    assert_eq!(follows_comp.align, 8);
    assert_eq!(follows_comp.fields.len(), 1);
    assert_eq!(follows_comp.fields[0].name, "parent");
    assert!(
        !mir.layouts
            .iter()
            .any(|l| l.canonical_name.contains("__strata_rel_parent_ChildOf")),
        "built-in ChildOf must NOT synthesize companion __strata_rel_parent_ChildOf"
    );

    // Negative verifier check for missing companion layout
    let mut missing_comp = mir.clone();
    missing_comp
        .layouts
        .retain(|l| l.canonical_name != "test::wave2a_rel_sw::__strata_rel_parent_Follows");
    assert!(
        verify_mir(&missing_comp).is_err(),
        "verify_mir must reject custom IterUpCascade without companion parent layout"
    );
}

#[test]
fn mir_wave2a_recursive_timer_tick_and_net_soa_nested_quantize_effective_step() {
    use strata_mir::{MirQuantizeSpec, MirType};

    // NT-09: effective_step avoids infinity on wide ranges (-1e308..1e308)
    let wide_q = MirQuantizeSpec {
        field_name: "wide".to_owned(),
        lane_count: 1,
        bits: 8,
        min: -1e308,
        max: 1e308,
        step: None,
        bit_offset: 0,
        total_bits: 8,
        field_byte_offset: 0,
        field_ty: MirType::F64,
    };
    let step_val = wide_q.effective_step();
    assert!(step_val.is_finite() && step_val > 0.0, "got {step_val}");

    // BUG-TL-07a + NT-03 + NT-10b
    let src = r#"
module test::wave2a_net_tmr @version(1.0.0);

enum Attack {
    Slash,
}
resource Clock { dt: f32 = 0.016 }

struct SubTimers {
    g: GraceWindow,
    b: InputBuffer<Attack, 2>,
}

component NestedTimers {
    sub: SubTimers,
    arr_g: [GraceWindow; 2],
    sv_g: SmallVec<GraceWindow, 3>,
}

struct InnerQuant {
    @quantize(min = -10.0, max = 10.0, bits = 8)
    z: f32,
}

struct SubPos {
    @quantize(min = -100.0, max = 100.0, bits = 12)
    x: f32,
    inner: InnerQuant,
    flags: u16,
}

@soa
@net(reliable, channel = 0)
component SoaBody {
    hot { x: f32 = 0.0 }
    cold meta { hp: f32 = 10.0 }
}

@net(reliable, channel = 1)
component NestedQuantComp {
    pad_hdr: u32 = 0,
    sub: SubPos,
}

@net_rpc(client_to_server, channel = 2)
rpc NestedQuantRpc {
    sub: SubPos,
}
"#;
    let analyzed = analyze_source("wave2a_net_tmr.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    verify_mir(&mir).expect("wave2a timer/net MIR must verify");

    // BUG-TL-07a: strata_timer_tick ticks nested struct, array, and SmallVec timers
    let tmr = mir
        .functions
        .iter()
        .find(|f| f.name == "strata_timer_tick")
        .expect("strata_timer_tick");
    let tmr_stmts: Vec<_> = tmr.blocks.iter().flat_map(|b| &b.stmts).collect();
    let grace_ticks = tmr_stmts
        .iter()
        .filter(|s| matches!(s.inst, Inst::GraceTick { .. }))
        .count();
    let input_ticks = tmr_stmts
        .iter()
        .filter(|s| matches!(s.inst, Inst::InputBufTick { .. }))
        .count();
    assert!(
        grace_ticks >= 3,
        "expected nested/array/SmallVec GraceTick >= 3, got {grace_ticks}"
    );
    assert_eq!(input_ticks, 1, "expected nested InputBufTick");

    // NT-03: SoaBody wire_fields carry exact stratum_layout for hot and cold strata
    let soa_nc = mir
        .net_components
        .iter()
        .find(|c| c.name == "SoaBody")
        .expect("SoaBody");
    assert_eq!(
        soa_nc.wire_fields[0].stratum_layout.as_deref(),
        Some("test::wave2a_net_tmr::SoaBody")
    );
    assert_eq!(
        soa_nc.wire_fields[1].stratum_layout.as_deref(),
        Some("test::wave2a_net_tmr::SoaBody__meta")
    );

    // NT-10b: NestedQuantComp and NestedQuantRpc emit dotted "sub.x" & "sub.inner.z" without parent "sub"
    let nqc = mir
        .net_components
        .iter()
        .find(|c| c.name == "NestedQuantComp")
        .expect("NestedQuantComp");
    assert_eq!(nqc.quantize_specs.len(), 2);
    assert_eq!(nqc.quantize_specs[0].field_name, "sub.x");
    assert_eq!(nqc.quantize_specs[0].field_byte_offset, 4);
    assert_eq!(nqc.quantize_specs[1].field_name, "sub.inner.z");
    assert_eq!(nqc.quantize_specs[1].field_byte_offset, 8);
    assert!(
        !nqc.wire_fields
            .iter()
            .any(|w| w.field_name == "sub" || w.field_name == "sub.inner"),
        "parent structs `sub`/`sub.inner` must be flattened into leaf wire_fields"
    );
    let nqr = mir
        .rpcs
        .iter()
        .find(|r| r.name == "NestedQuantRpc")
        .expect("NestedQuantRpc");
    assert_eq!(nqr.quantize_specs.len(), 2);
    assert_eq!(nqr.quantize_specs[0].field_name, "sub.x");
    assert_eq!(nqr.quantize_specs[1].field_name, "sub.inner.z");
}
