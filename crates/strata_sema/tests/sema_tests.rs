use bamabi_sys::{
    BAM_COMPONENT_FLAG_SUMMARY_TICK, BamFieldKind, ComponentUuid, fnv1a_64_init,
    fnv1a_64_update_bytes, fnv1a_64_update_u64,
};
use salsa::Setter;
use std::sync::Arc;
use strata_sema::{SemaDb, analyze_source, codes};

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
fn all_cookbooks_analyze_cleanly_with_zero_errors() {
    for (name, src) in COOKBOOKS {
        let mod_ir = analyze_source(name, src);
        assert!(
            mod_ir.ok(),
            "{name} failed sema with diagnostics: {:#?}",
            mod_ir.diagnostics
        );
        assert!(
            mod_ir.diagnostics.is_empty(),
            "{name} emitted unexpected warnings: {:#?}",
            mod_ir.diagnostics
        );
        for c in &mod_ir.callables {
            assert!(
                !c.body.is_empty(),
                "{name}: callable `{}` lowered to empty HIR body",
                c.name
            );
        }
        for t in &mod_ir.tasks {
            assert!(
                !t.body.is_empty(),
                "{name}: task `{}` lowered to empty HIR body",
                t.name
            );
        }
        for tl in &mod_ir.timelines {
            assert_eq!(
                tl.typed_triggers.len(),
                tl.triggers.len(),
                "{name}: timeline `{}` trigger mismatch",
                tl.name
            );
        }
        for f in &mod_ir.fsms {
            assert_eq!(
                f.state_hooks.len(),
                f.states.len(),
                "{name}: fsm `{}` state_hooks mismatch",
                f.name
            );
            assert_eq!(
                f.typed_transitions.len(),
                f.transitions.len(),
                "{name}: fsm `{}` transitions mismatch",
                f.name
            );
        }
        for o in &mod_ir.objects {
            assert_eq!(
                o.inits.len(),
                o.components.len(),
                "{name}: object `{}` inits mismatch",
                o.name
            );
        }
        for tb in &mod_ir.tables {
            assert_eq!(
                tb.typed_rows.len(),
                tb.rows.len(),
                "{name}: table `{}` rows mismatch",
                tb.name
            );
        }
        for st in &mod_ir.sim_tests {
            assert!(
                !st.body.is_empty(),
                "{name}: sim_test `{}` lowered to empty HIR body",
                st.name
            );
        }
        for nst in &mod_ir.net_sim_tests {
            assert!(
                !nst.body.is_empty(),
                "{name}: net_sim_test `{}` lowered to empty HIR body",
                nst.name
            );
        }
    }
    let mp_ir = analyze_source(COOKBOOKS[7].0, COOKBOOKS[7].1);
    assert!(
        !mp_ir.net_sim_tests.is_empty(),
        "08_authoritative_multiplayer.strata must contain at least one net_sim_test"
    );
}

#[test]
fn bit_exact_component_uuid_and_schema_fingerprint_parity() {
    let src = r#"
module parity::test @version(1.0.0);

@summary_tick
component DroneHeat {
    hp: f32 = 100.0,
    active: bool = true,
    heat: f32 = 0.0,
}
"#;
    let mod_ir = analyze_source("parity.strata", src);
    assert!(mod_ir.ok(), "diagnostics: {:#?}", mod_ir.diagnostics);

    let layout = mod_ir
        .layouts
        .get("parity::test::DroneHeat")
        .expect("DroneHeat layout");
    // Expected layout: hp (0..4, f32), active (4..5, FfiBool), _strata_pad_0 (5..8, [u8;3]), heat (8..12, f32) -> 12 B, align 4
    assert_eq!(layout.size, 12);
    assert_eq!(layout.align, 4);
    assert_eq!(layout.explicit_pad_bytes, 3);
    assert_eq!(
        layout.fields.iter().map(|f| f.size).sum::<usize>(),
        layout.size
    );

    // Independent bit-exact reference computation matching `bamabi_macros`:
    let mut sh = 0u64;
    sh = ComponentUuid::hash_field_schema(sh, "hp", "f32", 0);
    sh = ComponentUuid::hash_field_schema(sh, "active", "FfiBool", 4);
    sh = ComponentUuid::hash_field_schema(sh, "_strata_pad_0", "[u8;3]", 5);
    sh = ComponentUuid::hash_field_schema(sh, "heat", "f32", 8);
    let expected_uuid = ComponentUuid::from_parts("parity::test::DroneHeat", 12, 4, sh);
    assert_eq!(&layout.uuid_bytes, expected_uuid.as_bytes());

    let mut fp = fnv1a_64_init();
    fp = fnv1a_64_update_bytes(fp, b"parity::test::DroneHeat");
    fp = fnv1a_64_update_u64(fp, 12);
    fp = fnv1a_64_update_u64(fp, 4);
    fp = fnv1a_64_update_u64(fp, BAM_COMPONENT_FLAG_SUMMARY_TICK as u64);
    for (kind, fname, ftag, off, sz, al) in [
        (BamFieldKind::F32, "hp", "f32", 0usize, 4usize, 4usize),
        (BamFieldKind::BOOL, "active", "FfiBool", 4, 1, 1),
        (BamFieldKind::NESTED, "_strata_pad_0", "[u8;3]", 5, 3, 1),
        (BamFieldKind::F32, "heat", "f32", 8, 4, 4),
    ] {
        fp = fnv1a_64_update_u64(fp, kind.0 as u64);
        fp = fnv1a_64_update_bytes(fp, fname.as_bytes());
        fp = fnv1a_64_update_bytes(fp, ftag.as_bytes());
        fp = fnv1a_64_update_u64(fp, off as u64);
        fp = fnv1a_64_update_u64(fp, sz as u64);
        fp = fnv1a_64_update_u64(fp, al as u64);
    }
    assert_eq!(layout.schema_fingerprint, fp);
}

#[test]
fn salsa_early_cutoff_skips_layout_resolution_on_body_only_edit() {
    let mut db = SemaDb::new();
    let v1 = r#"
module inc::test @version(1.0.0);
component Health { hp: f32 = 100.0 }
sys regen() {
    for h in query(v: &mut Health.hp) {
        h.v += 1.0;
    }
}
"#;
    let file = db.new_source("inc.strata", v1);
    let mod1 = db.analyze_file(file);
    let layouts1 = db.resolve_layouts_arc(file);
    let executed_initial = db.take_executed_queries();
    assert!(
        executed_initial
            .iter()
            .any(|q| q.contains("resolve_layouts")),
        "initial compile should execute resolve_layouts; executed: {executed_initial:?}"
    );

    // Edit ONLY the system body formula (`1.0` -> `2.5`)
    let v2 = r#"
module inc::test @version(1.0.0);
component Health { hp: f32 = 100.0 }
sys regen() {
    for h in query(v: &mut Health.hp) {
        h.v += 2.5;
    }
}
"#;
    file.set_text(&mut db).to(v2.to_owned());
    let mod2 = db.analyze_file(file);
    let layouts2 = db.resolve_layouts_arc(file);
    let executed_after_body_edit = db.take_executed_queries();

    assert_eq!(
        mod1.layouts["inc::test::Health"].schema_fingerprint,
        mod2.layouts["inc::test::Health"].schema_fingerprint
    );
    assert!(
        !executed_after_body_edit
            .iter()
            .any(|q| q.contains("resolve_layouts")),
        "body-only edit should early-cutoff before resolve_layouts, executed: {executed_after_body_edit:?}"
    );
    assert!(
        Arc::ptr_eq(&layouts1, &layouts2),
        "body-only edit must preserve the memoized resolve_layouts Arc pointer"
    );

    // Schema edit (adding field `max_hp: f32`) MUST re-execute `resolve_layouts`
    let v3 = r#"
module inc::test @version(1.0.0);
component Health { hp: f32 = 100.0, max_hp: f32 = 100.0 }
sys regen() {
    for h in query(v: &mut Health.hp) {
        h.v += 2.5;
    }
}
"#;
    file.set_text(&mut db).to(v3.to_owned());
    let mod3 = db.analyze_file(file);
    let layouts3 = db.resolve_layouts_arc(file);
    let executed_after_schema_edit = db.take_executed_queries();
    assert!(
        executed_after_schema_edit
            .iter()
            .any(|q| q.contains("resolve_layouts")),
        "schema edit should re-execute resolve_layouts, executed: {executed_after_schema_edit:?}"
    );
    assert!(
        !Arc::ptr_eq(&layouts2, &layouts3),
        "schema edit should produce a new resolve_layouts Arc allocation"
    );
    assert_eq!(mod3.layouts["inc::test::Health"].size, 8);
}

#[test]
fn salsa_arc_cache_hits_preserve_pointer_identity_with_zero_executions() {
    let db = SemaDb::new();
    let src = r#"
module cache::test @version(1.0.0);
component Pos { x: f32 = 0.0 }
sys step() {
    for p in query(x: &mut Pos.x) {
        p.x += 1.0;
    }
}
"#;
    let file = db.new_source("cache.strata", src);

    let mod1 = db.analyze_file(file);
    let layouts1 = db.resolve_layouts_arc(file);
    let cg1 = db.concurrency_graph(file);
    let initial_exec = db.take_executed_queries();
    assert!(
        initial_exec.iter().any(|q| q.contains("resolve_layouts")),
        "initial warm-up should execute resolve_layouts; saw {initial_exec:?}"
    );
    assert!(
        initial_exec.iter().any(|q| q.contains("analyze_module")),
        "initial warm-up should execute analyze_module; saw {initial_exec:?}"
    );
    assert!(
        initial_exec.iter().any(|q| q.contains("concurrency_graph")),
        "initial warm-up should execute concurrency_graph; saw {initial_exec:?}"
    );

    // Repeated reads without input edits must hit Salsa memos with 0 query executions.
    let mod2 = db.analyze_file(file);
    let layouts2 = db.resolve_layouts_arc(file);
    let cg2 = db.concurrency_graph(file);
    let owned_layouts = db.resolve_layouts(file);
    let cached_exec = db.take_executed_queries();

    assert!(
        cached_exec.is_empty(),
        "repeated unedited queries must execute 0 queries; saw {cached_exec:?}"
    );
    assert!(Arc::ptr_eq(&mod1, &mod2));
    assert!(Arc::ptr_eq(&layouts1, &layouts2));
    assert!(Arc::ptr_eq(&cg1, &cg2));
    assert_eq!(owned_layouts, *layouts1);
}

#[test]
fn theorem_01_archetype_disjoint_queries_pass_assert_par() {
    let src = r#"
module par::disjoint @version(1.0.0);
component Health { hp: f32 = 100.0 }
tag Hero, Enemy;

sys heal_heroes() {
    for h in query(hp: &mut Health.hp).with<Hero>() {
        h.hp += 1.0;
    }
}

sys damage_enemies() {
    for h in query(hp: &mut Health.hp).without<Hero>() {
        h.hp -= 1.0;
    }
}

assert_par(heal_heroes, damage_enemies);
"#;
    let mod_ir = analyze_source("par_ok.strata", src);
    assert!(mod_ir.ok(), "diagnostics: {:#?}", mod_ir.diagnostics);
    assert!(
        mod_ir.concurrency_graph.conflicts.is_empty(),
        "expected 0 conflicts between With<Hero> and Without<Hero>: {:#?}",
        mod_ir.concurrency_graph.conflicts
    );
}

#[test]
fn diagnostic_suite_catches_all_semantic_errors_and_lints() {
    let bad_units_and_abi = r#"
module bad::suite @version(1.0.0);

const BAD_DIST: meters = 5.0_s;

@sparse @summary_tick
component BadFlags {
    ptr_sized: usize,
    name: InlineStr<15>,
}

enum Color { Red = 0, Blue = 1 }
table Palette by Color { val: u32 } = {
    Red => { val: 1 },
};

curve BadCurve(f32 -> f32) = [
    (0.0, 1.0),
    (5.0, 2.0),
    (5.0, 3.0),
];

@sparse
timeline BadTl @rate(60_hz) @duration(10_f) {
    window bad = 5_f .. 12_f;
}

fsm BadFsm {
    initial MissingStart;
    state Idle {
        to Nowhere when true;
    }
}

task BadTask(bad: String) {
    wait 1.0_s;
}

assert_layout(BadFlags, size == 999);
"#;
    let res = analyze_source("bad_suite.strata", bad_units_and_abi);
    let codes_seen: Vec<&str> = res.diagnostics.iter().map(|d| d.code.as_str()).collect();
    for expected in [
        codes::E0102_UNIT_MISMATCH,
        codes::E0103_INVALID_ABI_POD_FIELD,
        codes::E0104_PADDING_HAZARD,
        codes::E0105_ASSERT_LAYOUT_FAILED,
        codes::E0106_TABLE_NOT_EXHAUSTIVE,
        codes::E0107_CURVE_NON_MONOTONIC,
        codes::E0108_TIMELINE_INVALID_WINDOW,
        codes::E0109_FSM_INVALID_TARGET,
        codes::E0110_SPARSE_SUMMARY_TICK,
        codes::E0302_NON_POD_ACROSS_WAIT,
    ] {
        assert!(
            codes_seen.contains(&expected),
            "missing expected diagnostic {expected}; saw {codes_seen:?}"
        );
    }

    let bad_access_and_lints = r#"
module bad::par_and_lints @version(1.0.0);

component Huge {
    a: [f32; 20],
}

component Pos { x: f32 }
component Vel { dx: f32 }

sys bad_alias() {
    for p in query(a: &mut Pos, b: &Pos) {
        p.a.x += 1.0;
    }
}

sys sys_w1() effects(reads: [Pos]) {
    for a in query(p: &mut Pos) {
        a.p.x += 1.0;
    }
}

sys sys_w2() {
    for b in query(p: &Pos) {
        for c in query(v: &Vel) {
            let _ = b.p.x + c.v.dx;
        }
    }
}

sys sys_w3() {
    for i in 0..10 {
        spawn { Pos { x: i as f32 } };
    }
}

sys sys_rare_mut() {
    for p in query(x: &mut Pos.x) {
        if p.x < 0.0 {
            p.x = 0.0;
        }
    }
}

assert_par(sys_w1, sys_w2);
"#;
    let res2 = analyze_source("bad_lints.strata", bad_access_and_lints);
    let codes_seen2: Vec<&str> = res2.diagnostics.iter().map(|d| d.code.as_str()).collect();
    for expected in [
        codes::E0201_ALIASING_CONFLICT,
        codes::E0202_ASSERT_PAR_FAILED,
        codes::E0204_EFFECTS_MISMATCH,
        codes::W0401_QUADRATIC_NESTED_QUERY,
        codes::W0402_USE_SELECTIVE_MUT_TICK,
        codes::W0403_USE_SPAWN_BATCH,
        codes::W0404_LARGE_AOS_COMPONENT_SPLIT_SOA,
    ] {
        assert!(
            codes_seen2.contains(&expected),
            "missing expected diagnostic {expected}; saw {codes_seen2:?}"
        );
    }
}

#[test]
fn query_limit_exceeds_bamabi_sys_max_terms() {
    let mut terms = Vec::new();
    for i in 0..=bamabi_sys::MAX_TERMS_PER_QUERY {
        terms.push(format!("t{i}: &C{i}"));
    }
    let src = format!(
        "module bad::limits @version(1.0.0);\nsys big() {{\n for x in query({}) {{}}\n}}\n",
        terms.join(", ")
    );
    let res = analyze_source("limits.strata", &src);
    assert!(
        res.diagnostics
            .iter()
            .any(|d| d.code == codes::E0203_QUERY_LIMIT_EXCEEDED),
        "expected E0203_QUERY_LIMIT_EXCEEDED, saw {:?}",
        res.diagnostics
    );
}

#[test]
fn typed_hir_lowering_covers_si_units_defaults_fns_migrations_and_queries() {
    let src = r#"
module test::typed_hir @version(2.0.0);

enum StateTag { Idle, Active }

const STEP_MS: sec = 8.3333_ms;
const TURN_ANGLE: rad = 90.0_deg;

resource SimClock {
    dt: sec = 8.3333_ms,
}

@soa component CombatantBody {
    hot {
        hp: f32 = 800.0,
        grace: GraceWindow,
    }
    cold caps {
        stamina_delay_rem: sec = 500.0_ms,
    }
}

tag TagA, TagB;

component HealthV1 { hp: i32 }
component Health { hp: f32 = 100.0, shield: f32 = 0.0 }

event HitEvent { dmg: f32 }

fn clamp_dmg(raw: f32, max_v: f32) -> f32 {
    if raw > max_v { max_v } else { raw }
}

object Hero {
    CombatantBody { hp: 1200.0 },
    TagA {},
}

migrate Health from 1.0.0 to 2.0.0 (old: &HealthV1) -> Health {
    Health { hp: old.hp as f32, shield: 10.0 }
}

timeline Slash @rate(60_hz) @duration(20_f) {
    window active = 4_f..12_f;
    at 6_f => emit(HitEvent { dmg: 25.0 });
}

task DashTask(speed: f32) on (b: &mut CombatantBody) using (clk: &res SimClock) {
    yield_tick;
    b.hp -= speed * clk.dt;
}

fsm AIState(clk: &res SimClock) {
    initial Patrol;
    state Patrol {
        to Chase when true @priority(5);
    }
    state Chase {
        on_tick { let _d = clk.dt; }
    }
}

sys step(clk: &res SimClock) {
    for row in query(b: &mut CombatantBody).with<TagA>().without<TagB>() {
        row.b.hp = clamp_dmg(row.b.hp - clk.dt, 800.0);
    }
}

sim_test "smoke" {
    step();
}
"#;
    let res = analyze_source("typed_hir.strata", src);
    assert!(res.ok(), "unexpected diagnostics: {:?}", res.diagnostics);

    // SI unit normalization on consts & field_defaults
    let step_c = res.consts.iter().find(|c| c.name == "STEP_MS").unwrap();
    match step_c.expr.as_ref().unwrap() {
        strata_sema::HirExpr::FloatLit { value, .. } => {
            assert!((*value - 0.008_333_3).abs() < 1e-7, "got {value}");
        }
        other => panic!("expected FloatLit, got {other:?}"),
    }
    let angle_c = res.consts.iter().find(|c| c.name == "TURN_ANGLE").unwrap();
    match angle_c.expr.as_ref().unwrap() {
        strata_sema::HirExpr::FloatLit { value, .. } => {
            assert!((*value - std::f64::consts::FRAC_PI_2).abs() < 1e-9);
        }
        other => panic!("expected FloatLit, got {other:?}"),
    }

    let clk_def = &res.field_defaults["test::typed_hir::SimClock"]["dt"];
    match clk_def {
        strata_sema::HirExpr::FloatLit { value, .. } => {
            assert!((*value - 0.008_333_3).abs() < 1e-7);
        }
        other => panic!("expected SimClock.dt FloatLit, got {other:?}"),
    }
    assert!(
        res.field_defaults
            .contains_key("test::typed_hir::CombatantBody::hot"),
        "expected hot stratum defaults"
    );
    assert!(
        res.field_defaults
            .contains_key("test::typed_hir::CombatantBody__caps"),
        "expected cold stratum defaults"
    );

    // Helper fn, object inits, migrate, timeline, task, fsm, sim_test
    assert_eq!(res.fns.len(), 1);
    assert_eq!(res.fns[0].name, "clamp_dmg");
    assert!(res.fns[0].tail.is_some());

    assert_eq!(res.objects[0].inits.len(), 2);
    assert_eq!(res.objects[0].inits[0].fields.len(), 1);

    let mg = &res.migrations[0];
    assert_eq!(mg.param_name, "old");
    assert!(mg.tail.is_some());

    assert_eq!(res.timelines[0].typed_triggers.len(), 1);
    assert_eq!(res.tasks[0].typed_params.len(), 1);
    assert_eq!(res.tasks[0].typed_on_terms.len(), 1);
    assert_eq!(res.tasks[0].typed_using_params.len(), 1);
    assert!(!res.tasks[0].body.is_empty());

    assert_eq!(res.fsms[0].params.len(), 1);
    assert_eq!(res.fsms[0].typed_transitions.len(), 1);
    assert_eq!(res.fsms[0].state_hooks.len(), 2);

    assert!(!res.sim_tests[0].body.is_empty());

    // `.with<TagA>().without<TagB>()` should NOT leak TagA/TagB across filters
    let step_sys = res.callables.iter().find(|c| c.name == "step").unwrap();
    let q = &step_sys.access.queries[0];
    assert!(q.with_filters.contains("TagA"));
    assert!(!q.with_filters.contains("TagB"));
    assert!(q.without_filters.contains("TagB"));
    assert!(!q.without_filters.contains("TagA"));
    assert!(!step_sys.body.is_empty());
}

#[test]
fn unit_lit_and_numeric_prefix_parsing_with_net_sim_and_timelines() {
    use strata_sema::{Ty, UnitDim};

    assert_eq!(
        Ty::unit_from_literal("50ms"),
        Some(Ty::UnitScalar {
            name: "ms".to_owned(),
            dim: UnitDim::SEC,
        })
    );
    assert_eq!(
        Ty::unit_from_literal("1_000ms"),
        Some(Ty::UnitScalar {
            name: "ms".to_owned(),
            dim: UnitDim::SEC,
        })
    );
    assert_eq!(
        Ty::unit_from_literal("20Hz"),
        Some(Ty::UnitScalar {
            name: "hz".to_owned(),
            dim: UnitDim::HZ,
        })
    );
    assert_eq!(
        Ty::unit_from_literal("1.5s"),
        Some(Ty::UnitScalar {
            name: "sec".to_owned(),
            dim: UnitDim::SEC,
        })
    );
    assert_eq!(
        Ty::unit_from_literal("1_000_f"),
        Some(Ty::UnitScalar {
            name: "frames".to_owned(),
            dim: UnitDim::FRAMES,
        })
    );

    let src = r#"
module test::units_and_net_sim @version(1.0.0);

const TIMEOUT: sec = 1.5s;
const POLL: hz = 20Hz;

resource SimClock { dt: f32 = 0.016 }
component QuantPos { x: f32 = 0.0, y: f32 = 0.0 }
object Marker { QuantPos { x: 0.0, y: 0.0 } }

@net_rpc(direction = client_to_server, reliability = reliable)
rpc MoveInput { dx: f32, dy: f32, seq: u32 }

@rate(60Hz)
@duration(1_000_f)
timeline Anim {
    window active = 10_f..200_f;
    at 50_f => {}
}

net_sim_test "units_test"(latency: 50ms, jitter: 1_000ms, loss: 0.05, seed: 42, clients: 2) {
    clients(2);
    send_rpc(0, MoveInput { dx: 1.0, dy: 0.0, seq: 1 });
    step_net(5);
    let _sclk = server_res<SimClock>();
    let _cclk = client_res<SimClock>(0);
    let qx = client_query(0, p: &QuantPos).on(Marker).unwrap().p.x;
    assert(qx == 0.0);
}
"#;
    let res = analyze_source("units_net_sim.strata", src);
    assert!(res.ok(), "unexpected diagnostics: {:#?}", res.diagnostics);

    let timeout = res.consts.iter().find(|c| c.name == "TIMEOUT").unwrap();
    match timeout.expr.as_ref().unwrap() {
        strata_sema::HirExpr::FloatLit { value, .. } => assert!((*value - 1.5).abs() < 1e-9),
        other => panic!("expected FloatLit, got {other:?}"),
    }
    let tl = &res.timelines[0];
    assert_eq!(tl.rate_hz, 60);
    assert_eq!(tl.duration_frames, 1000);

    assert_eq!(res.net_sim_tests.len(), 1);
    let nst = &res.net_sim_tests[0];
    assert!(
        (nst.latency_ms - 50.0).abs() < 1e-6,
        "got {}",
        nst.latency_ms
    );
    assert!(
        (nst.jitter_ms - 1000.0).abs() < 1e-6,
        "got {}",
        nst.jitter_ms
    );
    assert!((nst.loss - 0.05).abs() < 1e-9);
    assert_eq!(nst.seed, 42);
    assert_eq!(nst.clients, 2);
}

#[test]
fn salsa_early_cutoff_skips_layout_resolution_on_net_sim_test_edit() {
    let mut db = SemaDb::new();
    let v1 = r#"
module inc::net @version(1.0.0);
component NetPos { x: f32 = 0.0 }
@net_rpc(direction = client_to_server, reliability = reliable)
rpc MoveInput { dx: f32 }
net_sim_test "sim"(latency: 10ms, jitter: 0ms, loss: 0.0, seed: 1) {
    step_net(1);
}
"#;
    let file = db.new_source("inc_net.strata", v1);
    let _ = db.analyze_file(file);
    let layouts1 = db.resolve_layouts_arc(file);
    let _ = db.take_executed_queries();

    // Editing `net_sim_test` body/params must early-cutoff before `resolve_layouts`.
    let v2 = r#"
module inc::net @version(1.0.0);
component NetPos { x: f32 = 0.0 }
@net_rpc(direction = client_to_server, reliability = reliable)
rpc MoveInput { dx: f32 }
net_sim_test "sim"(latency: 40ms, jitter: 5ms, loss: 0.1, seed: 99) {
    step_net(10);
}
"#;
    file.set_text(&mut db).to(v2.to_owned());
    let _ = db.analyze_file(file);
    let layouts2 = db.resolve_layouts_arc(file);
    let exec_after_test_edit = db.take_executed_queries();
    assert!(
        !exec_after_test_edit
            .iter()
            .any(|q| q.contains("resolve_layouts")),
        "net_sim_test edit should early-cutoff before resolve_layouts, executed: {exec_after_test_edit:?}"
    );
    assert!(Arc::ptr_eq(&layouts1, &layouts2));

    // Editing `rpc` schema MUST invalidate schema_signature and re-run `resolve_layouts`.
    let v3 = r#"
module inc::net @version(1.0.0);
component NetPos { x: f32 = 0.0 }
@net_rpc(direction = client_to_server, reliability = reliable)
rpc MoveInput { dx: f32, dy: f32 }
net_sim_test "sim"(latency: 40ms, jitter: 5ms, loss: 0.1, seed: 99) {
    step_net(10);
}
"#;
    file.set_text(&mut db).to(v3.to_owned());
    let _ = db.analyze_file(file);
    let exec_after_rpc_edit = db.take_executed_queries();
    assert!(
        exec_after_rpc_edit
            .iter()
            .any(|q| q.contains("resolve_layouts")),
        "rpc schema edit must re-run resolve_layouts, executed: {exec_after_rpc_edit:?}"
    );
}

#[test]
fn node_pure_and_node_group_validation() {
    let valid_src = r#"
module test::graph @version(1.0.0);

enum Mode { Idle, Attack }
resource Clock { dt: f32 = 0.016 }

@node_group("combat")
component Health { hp: f32 = 100.0 }

@node_group("math")
@node_pure
fn sq(x: f32) -> f32 {
    x * x
}

@node_pure
fn dist_sq(dx: f32, dy: f32) -> f32 {
    sq(dx) + sq(dy)
}

@node_group(name = "tables")
table Loot by Mode {
    weight: f32,
} = {
    Idle => { weight: 0.0 },
    Attack => { weight: 1.0 },
};

@node_group("curves")
curve Falloff(f32 -> f32) = [
    (0.0, 1.0),
    (1.0, 0.0),
];

@node_group("timelines")
@rate(60Hz)
@duration(30_f)
timeline Swing {
    window hit = 5_f..15_f;
}

@node_group("fsms")
fsm BossAi {
    initial Idle;
    state Idle {
        to Enrage when true;
    }
    state Enrage {}
}

@node_group("tasks")
task Patrol() on (h: &mut Health) {
    h.hp += 1.0;
}

@node_group("systems")
sys heal() {
    for h in query(v: &mut Health) {
        h.v.hp += 1.0;
    }
}

@node_group("rpcs")
@net_rpc(direction = client_to_server, reliability = reliable)
rpc SwingCmd { seq: u32 }

@node_group("schedules")
schedule Update {
    seq main { heal }
}
"#;
    let ok_mod = analyze_source("graph_ok.strata", valid_src);
    assert!(ok_mod.ok(), "valid graph failed: {:#?}", ok_mod.diagnostics);
    assert_eq!(ok_mod.pure_fns, vec!["sq".to_owned(), "dist_sq".to_owned()]);
    assert_eq!(
        ok_mod
            .node_groups
            .get("test::graph::Health")
            .map(String::as_str),
        Some("combat")
    );
    assert_eq!(
        ok_mod
            .node_groups
            .get("test::graph::Loot")
            .map(String::as_str),
        Some("tables")
    );
    assert_eq!(
        ok_mod
            .node_groups
            .get("test::graph::SwingCmd")
            .map(String::as_str),
        Some("rpcs")
    );

    let bad_src = r#"
module test::graph_bad @version(1.0.0);

resource SimClock { dt: f32 = 0.016 }
component Tag { v: i32 = 0 }

fn impure_helper() -> i32 { 1 }

@node_pure
sys bad_sys() {}

@node_pure(1)
fn bad_args(x: f32) -> f32 { x }

@node_pure
fn mutator() -> i32 {
    spawn { Tag { v: 1 } };
    1
}

@node_pure
fn caller() -> i32 {
    impure_helper()
}

@node_pure
fn reader(clk: &res SimClock) -> f32 {
    clk.dt
}

@node_group("")
fn empty_group() {}

@node_group
fn missing_group() {}

@node_group(42)
fn numeric_group() {}

@node_group("bad_struct")
struct Plain { x: f32 }
"#;
    let bad_mod = analyze_source("graph_bad.strata", bad_src);
    assert!(!bad_mod.ok());
    let pure_errs: Vec<_> = bad_mod
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::E0601_NODE_PURE_VIOLATION)
        .collect();
    assert!(
        pure_errs.len() >= 5,
        "expected >= 5 E0601 errors, got {pure_errs:#?}"
    );
    assert!(
        pure_errs
            .iter()
            .any(|d| d.message.contains("impure_helper"))
    );
    assert!(pure_errs.iter().any(|d| d.message.contains("spawn")));
    assert!(pure_errs.iter().any(|d| d.message.contains("resource")));

    let group_errs: Vec<_> = bad_mod
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::E0602_INVALID_NODE_GROUP)
        .collect();
    assert_eq!(
        group_errs.len(),
        4,
        "expected 4 E0602 errors, got {group_errs:#?}"
    );
}

#[test]
fn net_quantize_rpc_authority_and_net_sim_validation() {
    let valid_src = r#"
module test::net_valid @version(1.0.0);

@net(reliable, rate = 20Hz, channel = 0)
@authority(server)
component NetPos {
    @quantize(min = -512.0, max = 512.0, bits = 16)
    xyz: vec3,
    seq: u32,
}

@net(unreliable, interval = 2, channel = 1)
resource NetState {
    @quantize(min = 0.0, max = 100.0, bits = 8, step = 0.5)
    energy: f32,
}

@predicted
component ClientInput {
    move_x: f32,
}

@net_rpc(direction = bidirectional, reliability = unreliable, channel = 2)
@authority(shared)
rpc Ping {
    ts: u32,
}

net_sim_test "ok"(latency: 0ms, jitter: 0ms, loss: 0.0, seed: 1, clients: 1) {
    step_net(1);
}
"#;
    let ok_mod = analyze_source("net_valid.strata", valid_src);
    assert!(ok_mod.ok(), "unexpected errors: {:#?}", ok_mod.diagnostics);
    assert_eq!(ok_mod.rpcs.len(), 1);
    assert_eq!(ok_mod.net_components.len(), 3);

    // Visual-only @node_group edit must preserve net_schema_fingerprint and SolvedLayout::schema_fingerprint
    let with_group =
        valid_src.replace("component NetPos", "@node_group(\"net\")\ncomponent NetPos");
    let grouped_mod = analyze_source("net_valid_grouped.strata", &with_group);
    assert!(grouped_mod.ok(), "{:#?}", grouped_mod.diagnostics);
    assert_eq!(
        ok_mod.layouts["test::net_valid::NetPos"].schema_fingerprint,
        grouped_mod.layouts["test::net_valid::NetPos"].schema_fingerprint
    );
    assert_eq!(
        ok_mod.net_schema_fingerprint,
        grouped_mod.net_schema_fingerprint
    );

    let bad_src = r#"
module test::net_bad @version(1.0.0);

@net(reliable, rate = 10ms, interval = 2, channel = 300)
component BadNet {
    @quantize(min = 10.0, max = 10.0, bits = 0)
    a: f32,
    @quantize(min = 50.0, max = -50.0, bits = 33, step = 0.0)
    b: f32,
    @quantize(min = 0.0, max = 1.0, bits = 8)
    flag: bool,
    @quantize(min = 0.0, max = 1.0, bits = 8)
    label: InlineStr<16>,
}

@authority(alien)
@predicted
component BadAuth {
    x: f32,
}

@authority(server)
@predicted
component ConflictAuth {
    x: f32,
}

@net_rpc(reliability = reliable)
rpc BadRpc { x: f32 }

rpc DupRpc { a: u32 }
rpc DupRpc { b: u32 }

net_sim_test "bad_params"(latency: -5ms, jitter: -1ms, loss: 1.5, seed: -1, clients: 0, extra: 1) {
    step_net(1);
}
"#;
    let bad_mod = analyze_source("net_bad.strata", bad_src);
    assert!(!bad_mod.ok());
    assert!(
        bad_mod
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0502_INVALID_NET_ATTR)
    );
    assert!(
        bad_mod
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0503_INVALID_QUANTIZE)
    );
    assert!(
        bad_mod
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0504_INVALID_AUTHORITY)
    );
    assert!(
        bad_mod
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0303_DUPLICATE_SYMBOL)
    );
    assert!(
        bad_mod
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0505_INVALID_NET_SIM_PARAM)
            .count()
            >= 6
    );
    assert!(
        !bad_mod
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0002_PARSE_ERROR),
        "unexpected parse errors: {:#?}",
        bad_mod.diagnostics
    );
}

#[test]
fn e0501_authority_violation_all_write_vectors_and_reads_allowed() {
    let bad_src = r#"
module test::auth_bad @version(1.0.0);

@authority(server)
component ServerHp { hp: f32 = 100.0 }

@authority(server)
component ServerTag { id: u32 = 0 }

@soa
@authority(server)
component ServerSoa {
    @hot { x: f32 = 0.0 }
    @cold { tag: u32 = 0 }
}

@authority(server)
resource ServerBank { gold: i32 = 0 }

fn direct_mutate_res() {
    res_mut<ServerBank>().gold += 100;
}

fn transitive_mutate() {
    direct_mutate_res();
}

@authority(client)
sys client_mut_queries(bank: &mut res ServerBank) {
    for h in query(hp: &mut ServerHp) {
        h.hp.hp = 9999.0;
    }
    for h in query(hp: &mut? ServerHp) {
        h.hp.hp = 9999.0;
    }
    for h in query(hp: ?&mut ServerHp) {
        if let Some(v) = h.hp {
            let _ = v;
        }
    }
    for s in query(x: &mut ServerSoa.x) {
        s.x = 1.0;
    }
    bank.gold = 9999;
    spawn { ServerTag { id: 1 } };
    spawn_batch(2) |_| {
        { ServerTag { id: 2 } }
    };
    for row in query(e: &ServerHp) {
        insert(row.id, ServerTag { id: 3 });
        remove<ServerTag>(row.id);
    }
    despawn_all<ServerTag>();
}

@predicted
sys predicted_helper_and_res_mut() {
    res_mut<ServerBank>().gold = 500;
    transitive_mutate();
    let b = res<ServerBank>();
    b.gold = 1;
}
"#;
    let bad_mod = analyze_source("auth_bad.strata", bad_src);
    assert!(!bad_mod.ok());
    let e0501s: Vec<_> = bad_mod
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
        .collect();
    assert!(
        e0501s.len() >= 12,
        "expected >= 12 E0501 diagnostics across all write vectors, got {}:\n{:#?}",
        e0501s.len(),
        e0501s
    );

    let ok_src = r#"
module test::auth_ok @version(1.0.0);

@authority(server)
component AuthPos { x: f32 = 0.0 }

@authority(server)
resource ServerCfg { speed: f32 = 5.0 }

@predicted
component ClientPredPos { x: f32 = 0.0 }

@authority(client)
component ClientOnly { v: f32 = 0.0 }

@authority(shared)
component SharedVal { v: f32 = 0.0 }

component Unmarked { v: f32 = 0.0 }

@authority(server)
sys server_writer(cfg: &mut res ServerCfg) {
    cfg.speed = 10.0;
    for a in query(p: &mut AuthPos) {
        a.p.x += cfg.speed;
    }
}

@authority(client)
sys client_reconcile(cfg: &res ServerCfg) {
    for row in query(auth: &AuthPos, pred: &mut ClientPredPos, cl: &mut ClientOnly, sh: &mut SharedVal, um: &mut Unmarked) {
        row.pred.x = row.auth.x + cfg.speed;
        row.cl.v = 1.0;
        row.sh.v = 2.0;
        row.um.v = 3.0;
    }
}
"#;
    let ok_mod = analyze_source("auth_ok.strata", ok_src);
    assert!(
        ok_mod.ok(),
        "allowed reads and non-server writes must pass cleanly: {:#?}",
        ok_mod.diagnostics
    );
}

#[test]
fn m2_r2_regression_quantize_net_rpc_and_unit_literal_edge_cases() {
    use strata_sema::types::Ty;

    // 1. @quantize missing `bits` & duplicate keyed args -> E0503_INVALID_QUANTIZE
    let missing_bits_src = r#"
module test::q_missing_bits @version(1.0.0);

@net(reliable)
component C {
    @quantize(min = 0.0, max = 10.0)
    x: f32 = 0.0,
}
"#;
    let missing_bits = analyze_source("q_missing_bits.strata", missing_bits_src);
    assert!(!missing_bits.ok());
    assert!(
        missing_bits
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0503_INVALID_QUANTIZE),
        "expected E0503 for missing bits, got {:#?}",
        missing_bits.diagnostics
    );

    let dup_quantize_src = r#"
module test::q_dup @version(1.0.0);

@net(reliable)
component C {
    @quantize(min = 0.0, max = 10.0, bits = 8, bits = 16)
    x: f32 = 0.0,
    @quantize(min = 0.0, min = 1.0, max = 10.0, bits = 8)
    y: f32 = 0.0,
}
"#;
    let dup_q = analyze_source("q_dup.strata", dup_quantize_src);
    assert!(!dup_q.ok());
    assert!(
        dup_q
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0503_INVALID_QUANTIZE)
            .count()
            >= 2,
        "expected >= 2 E0503 for duplicate @quantize keys, got {:#?}",
        dup_q.diagnostics
    );

    // 2. @net(rate = -20Hz) negative rate & invalid nested expr -> E0502_INVALID_NET_ATTR
    for (name, rate_expr) in [
        ("neg_hz", "-20Hz"),
        ("neg_ms", "-10ms"),
        ("bin_hz", "10Hz + 10Hz"),
    ] {
        let src = format!(
            "module test::{name} @version(1.0.0);\n@net(reliable, rate = {rate_expr})\ncomponent C {{ x: f32 = 0.0 }}\n"
        );
        let analyzed = analyze_source(format!("{name}.strata"), &src);
        assert!(
            !analyzed.ok(),
            "expected failure for rate = {rate_expr}, got ok"
        );
        assert!(
            analyzed
                .diagnostics
                .iter()
                .any(|d| d.code == codes::E0502_INVALID_NET_ATTR),
            "expected E0502 for rate = {rate_expr}, got {:#?}",
            analyzed.diagnostics
        );
    }

    let pos_hz_src = r#"
module test::pos_hz @version(1.0.0);
@net(reliable, rate = 20Hz)
component C { x: f32 = 0.0 }
"#;
    let pos_hz = analyze_source("pos_hz.strata", pos_hz_src);
    assert!(pos_hz.ok(), "{:#?}", pos_hz.diagnostics);
    assert_eq!(
        pos_hz.net_components[0]
            .net_config
            .as_ref()
            .and_then(|c| c.rate_hz),
        Some(20.0)
    );

    // 5. @net_rpc positional conflicts -> E0502_INVALID_NET_ATTR
    let rpc_conflict_src = r#"
module test::rpc_conflict @version(1.0.0);

@net_rpc(client_to_server, server_to_client)
rpc BadDir { x: f32 }

@net_rpc(client_to_server, reliable, unreliable)
rpc BadRel { x: f32 }

@net_rpc(direction = client_to_server, server_to_client)
rpc BadMixed { x: f32 }
"#;
    let rpc_conflict = analyze_source("rpc_conflict.strata", rpc_conflict_src);
    assert!(!rpc_conflict.ok());
    assert!(
        rpc_conflict
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0502_INVALID_NET_ATTR)
            .count()
            >= 3,
        "expected >= 3 E0502 for @net_rpc conflicts, got {:#?}",
        rpc_conflict.diagnostics
    );

    // 7. Ty::split_unit_literal stem check & parse_numeric_prefix hex literal handling
    assert_eq!(Ty::split_unit_literal("1abc_ms"), None);
    assert_eq!(Ty::split_unit_literal("0x1f"), None);
    assert!(Ty::split_unit_literal("50ms").is_some());
    assert!(Ty::split_unit_literal("1_000ms").is_some());
    assert!(Ty::split_unit_literal("20Hz").is_some());
    assert!(Ty::split_unit_literal("1.5s").is_some());
    assert!(Ty::split_unit_literal("1_000_f").is_some());

    let hex_timeline_src = r#"
module test::hex_tl @version(1.0.0);
timeline T {
    at 0x1f => {}
}
"#;
    let hex_tl = analyze_source("hex_tl.strata", hex_timeline_src);
    assert!(hex_tl.ok(), "{:#?}", hex_tl.diagnostics);
    assert_eq!(hex_tl.timelines.len(), 1);
    assert_eq!(hex_tl.timelines[0].triggers.len(), 1);
    assert_eq!(hex_tl.timelines[0].triggers[0].0, 31);
}

#[test]
fn m2_r2_regression_qualified_calls_lvalue_index_and_subfield_refmut() {
    // 3, 4, 6: Module-qualified calls, HirLValue::Index subexpressions, &mut primitive sub-field,
    // and compute_fn_server_writes traversal coverage.
    let bad_src = r#"
module p::m @version(1.0.0);

@authority(server)
resource ServerBank { gold: u32 = 0 }

@authority(server)
component ServerHp { hp: f32 = 100.0 }

stream Evt { v: u32 }

fn impure_idx() -> u32 { 0 }

@node_pure
fn pure_ok() -> u32 { 2 }

@node_pure
fn bad_pure_qualified() -> u32 {
    p::m::impure_idx()
}

@node_pure
fn bad_pure_lvalue_index() -> u32 {
    let mut arr = [1, 2, 3];
    arr[impure_idx()] = 9;
    arr[0]
}

@node_pure
fn ok_pure_qualified() -> u32 {
    p::m::pure_ok()
}

fn helper_bank() {
    res_mut<ServerBank>().gold = 1;
}

fn helper_qualified_chain() {
    p::m::helper_bank();
}

fn helper_lvalue_idx() {
    let mut arr = [1, 2];
    arr[res_mut<ServerBank>().gold] = 5;
}

fn helper_for_range() {
    for i in 0..res_mut<ServerBank>().gold {
        let _ = i;
    }
}

fn helper_emit() {
    emit(Evt { v: res_mut<ServerBank>().gold });
}

fn take_mut_f32(x: &mut f32) {
    let _ = x;
}

@authority(client)
sys cheat_qualified() {
    p::m::helper_bank();
}

@authority(client)
sys cheat_transitive_qualified() {
    helper_qualified_chain();
}

@authority(client)
sys cheat_lvalue_index() {
    let mut arr = [1, 2];
    arr[res_mut<ServerBank>().gold] = 5;
}

@authority(client)
sys cheat_helper_lvalue_index() {
    helper_lvalue_idx();
}

@authority(client)
sys cheat_helper_range() {
    helper_for_range();
}

@authority(client)
sys cheat_helper_emit() {
    helper_emit();
}

@authority(client)
sys cheat_subfield_refmut() {
    for row in query(h: &ServerHp) {
        take_mut_f32(&mut row.h.hp);
    }
}
"#;
    let analyzed = analyze_source("m2_r2_bypasses.strata", bad_src);
    assert!(!analyzed.ok());
    assert!(
        !analyzed
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0002_PARSE_ERROR),
        "unexpected parse errors: {:#?}",
        analyzed.diagnostics
    );

    let e0601s: Vec<_> = analyzed
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::E0601_NODE_PURE_VIOLATION)
        .collect();
    assert_eq!(
        e0601s.len(),
        2,
        "expected exactly 2 E0601 errors (bad_pure_qualified + bad_pure_lvalue_index; ok_pure_qualified allowed), got {e0601s:#?}"
    );

    let e0501s: Vec<_> = analyzed
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
        .collect();
    assert!(
        e0501s.len() >= 7,
        "expected >= 7 E0501 errors across all 7 bypass vectors, got {}:\n{:#?}",
        e0501s.len(),
        e0501s
    );
}

#[test]
fn m2_r3_regression_helper_fn_query_row_and_intermediate_lvalue_server_writes() {
    // 1. Helper fn mutating `row.h.hp = 0.0` through read-only `query(h: &Health)`
    let case1_src = r#"
module test::r3_case1 @version(1.0.0);

@authority(server)
component Health { hp: f32 = 100.0 }

fn sneaky_helper() {
    for row in query(h: &Health) {
        row.h.hp = 0.0;
    }
}

@authority(client)
sys cheat() {
    sneaky_helper();
}
"#;
    let res1 = analyze_source("r3_case1.strata", case1_src);
    assert!(
        !res1
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0002_PARSE_ERROR),
        "unexpected parse errors in case1: {:#?}",
        res1.diagnostics
    );
    assert!(
        res1.diagnostics
            .iter()
            .any(|d| d.code == codes::E0501_AUTHORITY_VIOLATION),
        "expected E0501_AUTHORITY_VIOLATION for helper fn `query(h: &Health)` row.h.hp write, got {:#?}",
        res1.diagnostics
    );

    // 2. Helper fn mutating `row.h.hp = 0.0` through `if let Some(row) = query_one(h: &Health)`
    let case2_src = r#"
module test::r3_case2 @version(1.0.0);

@authority(server)
component Health { hp: f32 = 100.0 }

fn sneaky_helper() {
    if let Some(row) = query_one(h: &Health) {
        row.h.hp = 0.0;
    }
}

@authority(client)
sys cheat() {
    sneaky_helper();
}
"#;
    let res2 = analyze_source("r3_case2.strata", case2_src);
    assert!(
        !res2
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0002_PARSE_ERROR),
        "unexpected parse errors in case2: {:#?}",
        res2.diagnostics
    );
    assert!(
        res2.diagnostics
            .iter()
            .any(|d| d.code == codes::E0501_AUTHORITY_VIOLATION),
        "expected E0501_AUTHORITY_VIOLATION for helper fn `query_one(h: &Health)` row.h.hp write, got {:#?}",
        res2.diagnostics
    );

    // 3. Helper fn mutating `row.h.arr[0] = 5` through `query(h: &Health)`
    let case3_src = r#"
module test::r3_case3 @version(1.0.0);

@authority(server)
component Health { arr: [u32; 4] }

fn sneaky_helper() {
    for row in query(h: &Health) {
        row.h.arr[0] = 5;
    }
}

@authority(client)
sys cheat() {
    sneaky_helper();
}
"#;
    let res3 = analyze_source("r3_case3.strata", case3_src);
    assert!(
        !res3
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0002_PARSE_ERROR),
        "unexpected parse errors in case3: {:#?}",
        res3.diagnostics
    );
    assert!(
        res3.diagnostics
            .iter()
            .any(|d| d.code == codes::E0501_AUTHORITY_VIOLATION),
        "expected E0501_AUTHORITY_VIOLATION for helper fn `row.h.arr[0] = 5` write, got {:#?}",
        res3.diagnostics
    );

    // 4. Helper fn mutating projected `row.hp = 0.0` through `query(hp: &Health.hp)`
    let case4_src = r#"
module test::r3_case4 @version(1.0.0);

@authority(server)
component Health { hp: f32 = 100.0 }

fn sneaky_proj() {
    for row in query(hp: &Health.hp) {
        row.hp = 0.0;
    }
}

@authority(client)
sys cheat() {
    sneaky_proj();
}
"#;
    let res4 = analyze_source("r3_case4.strata", case4_src);
    assert!(
        !res4
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0002_PARSE_ERROR),
        "unexpected parse errors in case4: {:#?}",
        res4.diagnostics
    );
    assert!(
        res4.diagnostics
            .iter()
            .any(|d| d.code == codes::E0501_AUTHORITY_VIOLATION),
        "expected E0501_AUTHORITY_VIOLATION for helper fn `query(hp: &Health.hp)` row.hp write, got {:#?}",
        res4.diagnostics
    );

    // 5. Intermediate `Index` (`arr[0].hp = 0.0`) and `@soa` `Comp::stratum` (`row.b.mana = 0.0`) in helper fn
    let case5_src = r#"
module test::r3_case5 @version(1.0.0);

@authority(server)
component Health { hp: f32 = 100.0 }

@soa
@authority(server)
component Body {
    hot { hp: f32 = 100.0 }
    cold stats { mana: f32 = 50.0 }
}

fn sneaky_arr() {
    let mut arr = [Health { hp: 100.0 }];
    arr[0].hp = 0.0;
}

fn sneaky_soa() {
    for row in query(b: &Body::stats) {
        row.b.mana = 0.0;
    }
}

@authority(client)
sys cheat_arr() {
    sneaky_arr();
}

@predicted
sys cheat_soa() {
    sneaky_soa();
}
"#;
    let res5 = analyze_source("r3_case5.strata", case5_src);
    assert!(
        !res5
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0002_PARSE_ERROR),
        "unexpected parse errors in case5: {:#?}",
        res5.diagnostics
    );
    let e0501_5: Vec<_> = res5
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
        .collect();
    assert_eq!(
        e0501_5.len(),
        2,
        "expected E0501_AUTHORITY_VIOLATION on both cheat_arr and cheat_soa, got {e0501_5:#?}"
    );
}

#[test]
fn m2_r4_regression_authority_bypass_vectors_and_allowed_primitive_mutations() {
    fn assert_e0501_no_parse_err(name: &str, src: &str, min_e0501: usize) {
        let res = analyze_source(name, src);
        assert!(
            !res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0002_PARSE_ERROR),
            "unexpected parse errors in {name}: {:#?}",
            res.diagnostics
        );
        let e0501s: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        assert!(
            e0501s.len() >= min_e0501,
            "expected >= {min_e0501} E0501_AUTHORITY_VIOLATION in {name}, got {}:\n{:#?}",
            e0501s.len(),
            res.diagnostics
        );
    }

    // Vector 1: Nested `Field`/`Index` intermediate `Ty::Named` inside `@authority(client)` / `@predicted` `sys` bodies
    assert_e0501_no_parse_err(
        "r4_vec1_nested_lvalue_sys.strata",
        r#"
module test::r4_vec1 @version(1.0.0);

@authority(server)
component Health { hp: f32 = 100.0 }

@authority(client)
component Wrapper { h: Health }

@authority(client)
resource ClientRes { h: Health }

@authority(client)
sys cheat_row_read() {
    for row in query(w: &Wrapper) {
        row.w.h.hp = 0.0;
    }
}

@authority(client)
sys cheat_row_mut() {
    for row in query(w: &mut Wrapper) {
        row.w.h.hp = 0.0;
    }
}

@predicted
sys cheat_grid() {
    let mut grid = [[Health { hp: 100.0 }]];
    grid[0][0].hp = 0.0;
}

@authority(client)
sys cheat_arr_wrapper() {
    let mut g = [Wrapper { h: Health { hp: 100.0 } }];
    g[0].h.hp = 0.0;
}

@authority(client)
sys cheat_res_nested() {
    res_mut<ClientRes>().h.hp = 0.0;
}
"#,
        5,
    );

    // Vector 2: `match query_one(...)` in both `sys` and helper `fn` (assignment, `&mut`, projected scalar)
    assert_e0501_no_parse_err(
        "r4_vec2_match_query_one.strata",
        r#"
module test::r4_vec2 @version(1.0.0);

@authority(server)
component Health { hp: f32 = 100.0 }

fn take_mut(x: &mut f32) {}

fn helper_match_assign() {
    match query_one(h: &Health) {
        Some(row) => { row.h.hp = 0.0; }
        None => {}
    }
}

fn helper_match_refmut() {
    match query_one(h: &Health) {
        Some(row) => { take_mut(&mut row.h.hp); }
        None => {}
    }
}

fn helper_match_proj() {
    match query_one(hp: &Health.hp) {
        Some(row) => { row.hp = 0.0; }
        None => {}
    }
}

@authority(client)
sys sys_match_assign() {
    match query_one(h: &Health) {
        Some(row) => { row.h.hp = 0.0; }
        None => {}
    }
}

@predicted
sys sys_match_refmut() {
    match query_one(h: &Health) {
        Some(row) => { take_mut(&mut row.h.hp); }
        None => {}
    }
}

@authority(client)
sys sys_match_proj() {
    match query_one(hp: &Health.hp) {
        Some(row) => { row.hp = 0.0; }
        None => {}
    }
}

@authority(client)
sys sys_call_helpers() {
    helper_match_assign();
    helper_match_refmut();
    helper_match_proj();
}
"#,
        6,
    );

    // Vector 3: Query-row `let` aliasing & `Path` propagation + lexical `query_rows` scoping
    assert_e0501_no_parse_err(
        "r4_vec3_alias_and_scope.strata",
        r#"
module test::r4_vec3 @version(1.0.0);

@authority(server)
component Health { hp: f32 = 100.0 }

@authority(client)
component ClientComp { x: f32 = 1.0 }

fn take_mut(x: &mut f32) {}

fn helper_let_alias() {
    for row in query(h: &Health) {
        let r = row;
        r.h.hp = 0.0;
    }
}

fn helper_opt_if_let() {
    let opt = query_one(h: &Health);
    if let Some(row) = opt {
        row.h.hp = 0.0;
    }
}

fn helper_opt_let_else() {
    let opt = query_one(h: &Health);
    let Some(row) = opt else { return; };
    row.h.hp = 0.0;
}

fn helper_opt_match() {
    let opt = query_one(h: &Health);
    match opt {
        Some(row) => { take_mut(&mut row.h.hp); }
        None => {}
    }
}

@authority(client)
sys sys_let_alias() {
    for row in query(h: &Health) {
        let r = row;
        r.h.hp = 0.0;
        take_mut(&mut r.h.hp);
    }
}

@authority(client)
sys sys_opt_if_let_and_else() {
    let opt = query_one(h: &Health);
    if let Some(row) = opt {
        row.h.hp = 0.0;
    }
    let Some(row2) = opt else { return; };
    row2.h.hp = 0.0;
}

@predicted
sys sys_opt_match() {
    let opt = query_one(h: &Health);
    match opt {
        Some(row) => { row.h.hp = 0.0; }
        None => {}
    }
}

@authority(client)
sys sys_lexical_shadow_preserved() {
    for row in query(hp: &Health.hp) {
        if true {
            for row in query(c: &ClientComp) {
                row.c.x = 2.0;
            }
        }
        row.hp = 0.0;
    }
}

@authority(client)
sys sys_call_helpers() {
    helper_let_alias();
    helper_opt_if_let();
    helper_opt_let_else();
    helper_opt_match();
}
"#,
        10,
    );

    // Vector 4: Direct `query_one(...).unwrap().h.hp = 0.0;` and projected `query_one(hp: &Health.hp).unwrap().hp = 0.0;`
    assert_e0501_no_parse_err(
        "r4_vec4_direct_unwrap_assign.strata",
        r#"
module test::r4_vec4 @version(1.0.0);

@authority(server)
component Health { hp: f32 = 100.0 }

fn helper_unwrap_comp() {
    query_one(h: &Health).unwrap().h.hp = 0.0;
}

fn helper_unwrap_proj() {
    query_one(hp: &Health.hp).unwrap().hp = 0.0;
}

fn helper_opt_unwrap_proj() {
    let opt = query_one(hp: &Health.hp);
    opt.unwrap().hp = 0.0;
}

@authority(client)
sys sys_unwrap_comp() {
    query_one(h: &Health).unwrap().h.hp = 0.0;
}

@predicted
sys sys_unwrap_proj() {
    query_one(hp: &Health.hp).unwrap().hp = 0.0;
}

@authority(client)
sys sys_opt_unwrap_proj() {
    let opt = query_one(hp: &Health.hp);
    opt.unwrap().hp = 0.0;
}

@authority(client)
sys sys_call_helpers() {
    helper_unwrap_comp();
    helper_unwrap_proj();
    helper_opt_unwrap_proj();
}
"#,
        6,
    );

    // Vector 5: Mutating primitive methods `.arm()`, `.clear()`, `.push()`, `.consume()`, `.set()`
    assert_e0501_no_parse_err(
        "r4_vec5_mutating_primitives.strata",
        r#"
module test::r4_vec5 @version(1.0.0);

enum Action { Jump, Dash }

@authority(server)
component Boss {
    invuln: GraceWindow,
    buf: InputBuffer<Action, 4>,
    flags: BitSet<32>,
}

@authority(server)
resource ServerState {
    flags: BitSet<32>,
}

fn helper_arm() {
    for row in query(b: &Boss) { row.b.invuln.arm(1.0_sec); }
}

fn helper_clear() {
    for row in query(b: &Boss) { row.b.invuln.clear(); }
}

fn helper_push() {
    for row in query(b: &Boss) { row.b.buf.push(0, 0.2_sec); }
}

fn helper_consume() {
    for row in query(b: &Boss) { let _ = row.b.buf.consume(0); }
}

fn helper_set_res() {
    res<ServerState>().flags.set(0);
}

fn helper_proj_set() {
    for row in query(flags: &Boss.flags) { row.flags.set(0); }
}

@authority(client)
sys sys_prim_mutations() {
    for row in query(b: &Boss) {
        row.b.invuln.arm(1.0_sec);
        row.b.invuln.clear();
        row.b.buf.push(0, 0.2_sec);
        let _ = row.b.buf.consume(0);
        row.b.flags.set(0);
    }
    res<ServerState>().flags.set(0);
    for row in query(flags: &Boss.flags) {
        row.flags.set(0);
    }
}

@predicted
sys sys_call_helpers() {
    helper_arm();
    helper_clear();
    helper_push();
    helper_consume();
    helper_set_res();
    helper_proj_set();
}
"#,
        13,
    );

    // Allowed: `@authority(client)` primitive mutations on `@authority(client)` items + read-only primitive queries on `@authority(server)` emit 0 E0501s
    let allowed_src = r#"
module test::r4_allowed_prims @version(1.0.0);

enum Action { Jump, Dash }

@authority(client)
component ClientPrims {
    invuln: GraceWindow,
    buf: InputBuffer<Action, 4>,
    flags: BitSet<32>,
}

@authority(client)
resource ClientState {
    flags: BitSet<32>,
}

@authority(server)
component ServerPrims {
    invuln: GraceWindow,
    buf: InputBuffer<Action, 4>,
    flags: BitSet<32>,
}

fn mutate_client_prims() {
    for row in query(c: &ClientPrims) {
        row.c.invuln.arm(1.0_sec);
        row.c.invuln.clear();
        row.c.buf.push(0, 0.2_sec);
        let _ = row.c.buf.consume(0);
        row.c.flags.set(0);
    }
    res<ClientState>().flags.set(0);
}

@authority(client)
sys allowed_client_sys() {
    mutate_client_prims();
    for row in query(s: &ServerPrims) {
        let _a = s_active(row.s.invuln.is_active());
        let _p = row.s.buf.peek(0);
        let _g = row.s.flags.get(0);
    }
}

fn s_active(v: bool) -> bool { v }
"#;
    let allowed_res = analyze_source("r4_allowed_prims.strata", allowed_src);
    assert!(
        !allowed_res
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0002_PARSE_ERROR),
        "unexpected parse errors in allowed_prims: {:#?}",
        allowed_res.diagnostics
    );
    let allowed_e0501: Vec<_> = allowed_res
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
        .collect();
    assert!(
        allowed_e0501.is_empty(),
        "expected 0 E0501_AUTHORITY_VIOLATION for allowed client primitive mutations & server reads, got {allowed_e0501:#?}"
    );
}

#[test]
fn m2_r5_regression_block_if_match_tuple_provenance_and_negative_controls() {
    fn assert_probe_emits_e0501(name: &str, body: &str) {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

@authority(server)
component Health {{ hp: f32 = 100.0 }}

@authority(client)
component ClientHealth {{ hp: f32 = 50.0 }}

@authority(server)
component Boss {{ flags: BitSet<32> }}

fn take_mut(x: &mut f32) {{}}

{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            !res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0002_PARSE_ERROR),
            "unexpected parse errors in {name}: {:#?}",
            res.diagnostics
        );
        let e0501_count = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .count();
        assert!(
            e0501_count >= 1,
            "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
            res.diagnostics
        );
    }

    // All 12 Bypass A probes (Block / If / Match provenance in both sys and helper fn)
    let bypass_a_probes = [
        (
            "r5_a01_block_tail_unwrap_sys",
            r#"@authority(client) sys cheat() { let r = { query_one(h: &Health).unwrap() }; r.h.hp = 0.0; }"#,
        ),
        (
            "r5_a02_block_tail_unwrap_fn",
            r#"fn h() { let r = { query_one(h: &Health).unwrap() }; r.h.hp = 0.0; } @authority(client) sys cheat() { h(); }"#,
        ),
        (
            "r5_a03_block_tail_unwrap_proj_sys",
            r#"@authority(client) sys cheat() { let r = { query_one(hp: &Health.hp).unwrap() }; r.hp = 0.0; }"#,
        ),
        (
            "r5_a04_block_tail_unwrap_proj_fn",
            r#"fn h() { let r = { query_one(hp: &Health.hp).unwrap() }; r.hp = 0.0; } @predicted sys cheat() { h(); }"#,
        ),
        (
            "r5_a05_block_inner_let_sys",
            r#"@authority(client) sys cheat() { let r = { let x = query_one(h: &Health).unwrap(); x }; r.h.hp = 0.0; }"#,
        ),
        (
            "r5_a06_block_inner_let_fn",
            r#"fn h() { let r = { let x = query_one(h: &Health).unwrap(); x }; r.h.hp = 0.0; } @authority(client) sys cheat() { h(); }"#,
        ),
        (
            "r5_a07_if_else_row_sys",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { let r = if true { row } else { row }; r.h.hp = 0.0; } }"#,
        ),
        (
            "r5_a08_if_else_row_fn",
            r#"fn h() { for row in query(h: &Health) { let r = if true { row } else { row }; r.h.hp = 0.0; } } @predicted sys cheat() { h(); }"#,
        ),
        (
            "r5_a09_if_else_query_one_sys",
            r#"@authority(client) sys cheat() { let opt = if true { query_one(h: &Health) } else { query_one(h: &Health) }; if let Some(r) = opt { r.h.hp = 0.0; } }"#,
        ),
        (
            "r5_a10_if_else_query_one_fn",
            r#"fn h() { let opt = if true { query_one(h: &Health) } else { query_one(h: &Health) }; if let Some(r) = opt { r.h.hp = 0.0; } } @authority(client) sys cheat() { h(); }"#,
        ),
        (
            "r5_a11_match_yield_row_sys",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { let r = match 0 { _ => row }; r.h.hp = 0.0; } }"#,
        ),
        (
            "r5_a12_match_yield_row_fn",
            r#"fn h() { for row in query(h: &Health) { let r = match 0 { _ => row }; r.h.hp = 0.0; } } @authority(client) sys cheat() { h(); }"#,
        ),
    ];

    for (name, body) in bypass_a_probes {
        assert_probe_emits_e0501(name, body);
    }

    // All 10 Bypass B probes (Tuple destructuring & tuple pattern matching in both sys and helper fn)
    let bypass_b_probes = [
        (
            "r5_b01_tuple_destructure_row_sys",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { let (a, b) = (row, 1); a.h.hp = 0.0; } }"#,
        ),
        (
            "r5_b02_tuple_destructure_row_fn",
            r#"fn h() { for row in query(h: &Health) { let (a, b) = (row, 1); a.h.hp = 0.0; } } @authority(client) sys cheat() { h(); }"#,
        ),
        (
            "r5_b03_tuple_refmut_sys",
            r#"@predicted sys cheat() { for row in query(h: &Health) { let (a, b) = (row, 1); take_mut(&mut a.h.hp); } }"#,
        ),
        (
            "r5_b04_tuple_refmut_fn",
            r#"fn h() { for row in query(h: &Health) { let (a, b) = (row, 1); take_mut(&mut a.h.hp); } } @authority(client) sys cheat() { h(); }"#,
        ),
        (
            "r5_b05_tuple_destructure_unwrap_sys",
            r#"@authority(client) sys cheat() { let (a, b) = (query_one(h: &Health).unwrap(), 1); a.h.hp = 0.0; }"#,
        ),
        (
            "r5_b06_tuple_destructure_unwrap_fn",
            r#"fn h() { let (a, b) = (query_one(h: &Health).unwrap(), 1); a.h.hp = 0.0; } @predicted sys cheat() { h(); }"#,
        ),
        (
            "r5_b07_tuple_match_opt_sys",
            r#"@authority(client) sys cheat() { match (query_one(h: &Health), 1) { (Some(row), _) => { row.h.hp = 0.0; } _ => {} } }"#,
        ),
        (
            "r5_b08_tuple_match_opt_fn",
            r#"fn h() { match (query_one(h: &Health), 1) { (Some(row), _) => { row.h.hp = 0.0; } _ => {} } } @authority(client) sys cheat() { h(); }"#,
        ),
        (
            "r5_b09_tuple_if_let_opt_sys",
            r#"@authority(client) sys cheat() { if let (Some(row), _) = (query_one(h: &Health), 1) { row.h.hp = 0.0; } }"#,
        ),
        (
            "r5_b10_tuple_if_let_opt_fn",
            r#"fn h() { if let (Some(row), _) = (query_one(h: &Health), 1) { row.h.hp = 0.0; } } @authority(client) sys cheat() { h(); }"#,
        ),
    ];

    for (name, body) in bypass_b_probes {
        assert_probe_emits_e0501(name, body);
    }

    // Additional edge-case probes: tuple variable aliasing, nested tuples, direct Block/If/Match lvalues, mixed branches, outer .unwrap()
    let extra_probes = [
        (
            "r5_extra_tuple_alias_sys",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { let t = (row, 1); let (a, b) = t; a.h.hp = 0.0; } }"#,
        ),
        (
            "r5_extra_tuple_alias_fn",
            r#"fn h() { for row in query(h: &Health) { let t = (row, 1); let (a, b) = t; a.h.hp = 0.0; } } @authority(client) sys cheat() { h(); }"#,
        ),
        (
            "r5_extra_nested_tuple",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { let ((a, _), _) = ((row, 1), 2); a.h.hp = 0.0; } }"#,
        ),
        (
            "r5_extra_tuple_opt_then_if_let",
            r#"@authority(client) sys cheat() { let (opt, _) = (query_one(h: &Health), 1); if let Some(r) = opt { r.h.hp = 0.0; } }"#,
        ),
        (
            "r5_extra_direct_block_lvalue",
            r#"@authority(client) sys cheat() { ({ query_one(h: &Health).unwrap() }).h.hp = 0.0; }"#,
        ),
        (
            "r5_extra_direct_block_proj_lvalue",
            r#"@authority(client) sys cheat() { ({ query_one(hp: &Health.hp).unwrap() }).hp = 0.0; }"#,
        ),
        (
            "r5_extra_direct_if_lvalue",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { (if true { row } else { row }).h.hp = 0.0; } }"#,
        ),
        (
            "r5_extra_direct_match_lvalue",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { (match 0 { _ => row }).h.hp = 0.0; } }"#,
        ),
        (
            "r5_extra_block_outer_unwrap",
            r#"@authority(client) sys cheat() { let r = { query_one(h: &Health) }.unwrap(); r.h.hp = 0.0; }"#,
        ),
        (
            "r5_extra_block_direct_primitive_set",
            r#"@authority(client) sys cheat() { ({ query_one(b: &Boss).unwrap() }).b.flags.set(0); }"#,
        ),
        (
            "r5_extra_mixed_client_server_if_branches",
            r#"
@authority(client)
sys cheat() {
    let r = if false { query_one(h: &ClientHealth).unwrap() } else { query_one(h: &Health).unwrap() };
    r.h.hp = 0.0;
}
"#,
        ),
        (
            "r5_extra_if_let_block_scrutinee",
            r#"@authority(client) sys cheat() { if let Some(r) = { query_one(h: &Health) } { r.h.hp = 0.0; } }"#,
        ),
    ];

    for (name, body) in extra_probes {
        assert_probe_emits_e0501(name, body);
    }

    // Negative controls: allowed @authority(client) Block/If/Match/Tuple operations and shadowing must emit 0 E0501s and 0 parse errors
    let negative_controls_src = r#"
module test::r5_negative_controls @version(1.0.0);

@authority(server)
component Health { hp: f32 = 100.0 }

@authority(client)
component ClientHealth { hp: f32 = 50.0 }

@authority(client)
component ClientWrapper { h: ClientHealth }

fn take_mut_client(x: &mut f32) {}

fn helper_allowed_client_forms() {
    let r1 = { query_one(c: &ClientHealth).unwrap() };
    r1.c.hp = 10.0;

    let r2 = { let x = query_one(c: &ClientHealth).unwrap(); x };
    r2.c.hp = 20.0;

    for row in query(c: &ClientHealth) {
        let r3 = if true { row } else { row };
        r3.c.hp = 30.0;

        let r4 = match 0 { _ => row };
        r4.c.hp = 40.0;

        let t = (row, 1);
        let (a, _) = t;
        a.c.hp = 50.0;
        take_mut_client(&mut a.c.hp);
    }

    match (query_one(c: &ClientHealth), 1) {
        (Some(row), _) => { row.c.hp = 60.0; }
        _ => {}
    }

    if let (Some(row), _) = (query_one(c: &ClientHealth), 1) {
        row.c.hp = 70.0;
    }
}

@authority(client)
sys allowed_client_sys() {
    helper_allowed_client_forms();

    let mut local_c = ClientHealth { hp: 1.0 };
    let mut local_w = ClientWrapper { h: ClientHealth { hp: 2.0 } };

    // Shadowing outer `row` in Block, Tuple destructuring, if-let, match, and for must NOT cause false positives
    for row in query(h: &Health) {
        let shadowed = {
            let row = local_c;
            row
        };
        let mut s_mut = shadowed;
        s_mut.hp = 5.0;

        let (_keep_srv, mut row) = (row, local_c);
        row.hp = 6.0;

        if let Some(mut row) = Some(local_w) {
            row.h.hp = 7.0;
        }

        match Some(local_w) {
            Some(mut row) => { row.h.hp = 8.0; }
            _ => {}
        }

        for row in 0..1 {
            let _ = row;
        }
    }
}
"#;
    let neg_res = analyze_source("r5_negative_controls.strata", negative_controls_src);
    assert!(
        !neg_res
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0002_PARSE_ERROR),
        "unexpected parse errors in r5_negative_controls: {:#?}",
        neg_res.diagnostics
    );
    let neg_e0501: Vec<_> = neg_res
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
        .collect();
    assert!(
        neg_e0501.is_empty(),
        "expected 0 E0501_AUTHORITY_VIOLATION for negative controls, got {neg_e0501:#?}"
    );
}

#[test]
fn m2_r6_regression_all_five_consolidated_fixes_and_negative_controls() {
    fn assert_probe_e0501(name: &str, body: &str, expect_e0501: bool) {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

@authority(server)
component Health {{ hp: f32 = 100.0, flags: BitSet<32> }}

@authority(client)
component ClientHealth {{ hp: f32 = 50.0, flags: BitSet<32> }}

@authority(server)
component Boss {{ flags: BitSet<32> }}

@authority(client)
component ClientBoss {{ flags: BitSet<32> }}

@authority(client)
component ClientWrap {{ h: ClientHealth }}

@authority(client)
component ClientWrap2 {{ h: ClientHealth }}

@authority(server)
component ServerWrap {{ h: Health }}

component SharedWrap {{ h: Health, ch: ClientHealth }}

@authority(server)
resource ServerState {{ flags: BitSet<32> }}

@authority(client)
resource ClientState {{ flags: BitSet<32> }}

@authority(server)
resource ServerBank {{ gold: i32 = 0 }}

fn take_mut(x: &mut f32) {{}}
fn take_mut_i32(x: &mut i32) {{}}

{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            !res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0002_PARSE_ERROR),
            "unexpected parse errors in {name}: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
    }

    // Fix 1: Mixed-authority If / Match / Block direct lvalues & nested shared-wrapper projections
    let fix1_positive = [
        (
            "r6_f1_direct_if_mixed_sys",
            r#"@authority(client) sys cheat(flag: bool) { (if flag { query_one(h: &ClientHealth).unwrap() } else { query_one(h: &Health).unwrap() }).h.hp = 0.0; }"#,
        ),
        (
            "r6_f1_direct_if_mixed_fn",
            r#"fn h(flag: bool) { (if flag { query_one(h: &ClientHealth).unwrap() } else { query_one(h: &Health).unwrap() }).h.hp = 0.0; } @authority(client) sys cheat() { h(false); }"#,
        ),
        (
            "r6_f1_direct_match_mixed_sys",
            r#"@authority(client) sys cheat() { (match 0 { 1 => query_one(h: &ClientHealth).unwrap(), _ => query_one(h: &Health).unwrap() }).h.hp = 0.0; }"#,
        ),
        (
            "r6_f1_direct_match_mixed_fn",
            r#"fn h() { (match 0 { 1 => query_one(h: &ClientHealth).unwrap(), _ => query_one(h: &Health).unwrap() }).h.hp = 0.0; } @authority(client) sys cheat() { h(); }"#,
        ),
        (
            "r6_f1_direct_block_mixed_if_sys",
            r#"@authority(client) sys cheat(flag: bool) { ({ if flag { query_one(h: &ClientHealth).unwrap() } else { query_one(h: &Health).unwrap() } }).h.hp = 0.0; }"#,
        ),
        (
            "r6_f1_direct_if_mixed_proj_lvalue",
            r#"@authority(client) sys cheat() { (if false { query_one(hp: &ClientHealth.hp).unwrap() } else { query_one(hp: &Health.hp).unwrap() }).hp = 0.0; }"#,
        ),
        (
            "r6_f1_direct_if_mixed_server_wrap_sys",
            r#"@authority(client) sys cheat() { (if false { query_one(w: &ClientWrap).unwrap() } else { query_one(w: &ServerWrap).unwrap() }).w.h.hp = 0.0; }"#,
        ),
        (
            "r6_f1_let_if_mixed_nested_shared_wrap",
            r#"@authority(client) sys cheat() { let r = if false { query_one(w: &ClientWrap).unwrap() } else { query_one(w: &SharedWrap).unwrap() }; r.w.h.hp = 0.0; }"#,
        ),
        (
            "r6_f1_direct_if_mixed_nested_shared_wrap",
            r#"@authority(client) sys cheat() { (if false { query_one(w: &ClientWrap).unwrap() } else { query_one(w: &SharedWrap).unwrap() }).w.h.hp = 0.0; }"#,
        ),
        (
            "r6_f1_let_unwrap_field_mixed_shared_wrap",
            r#"@authority(client) sys cheat() { let w = if false { query_one(w: &ClientWrap).unwrap().w } else { query_one(w: &SharedWrap).unwrap().w }; w.h.hp = 0.0; }"#,
        ),
    ];
    for (name, body) in fix1_positive {
        assert_probe_e0501(name, body, true);
    }

    let fix1_negative = [
        (
            "r6_f1_neg_client_only_if_wraps",
            r#"@authority(client) sys ok(flag: bool) { (if flag { query_one(w: &ClientWrap).unwrap() } else { query_one(w: &ClientWrap2).unwrap() }).w.h.hp = 0.0; }"#,
        ),
        (
            "r6_f1_neg_shared_wrap_client_field",
            r#"@authority(client) sys ok() { let r = if false { query_one(w: &ClientWrap).unwrap() } else { query_one(w: &SharedWrap).unwrap() }; r.w.ch.hp = 0.0; }"#,
        ),
    ];
    for (name, body) in fix1_negative {
        assert_probe_e0501(name, body, false);
    }

    // Fix 2: Assign (`=`) scope sync + conditional If / Match / Block branch Assign escape
    let fix2_positive = [
        (
            "r6_f2_if_assign_escape_sys",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { let mut r = query_one(h: &ClientHealth).unwrap(); if true { r = row; } r.h.hp = 0.0; } }"#,
        ),
        (
            "r6_f2_if_assign_escape_fn",
            r#"fn h() { for row in query(h: &Health) { let mut r = query_one(h: &ClientHealth).unwrap(); if true { r = row; } r.h.hp = 0.0; } } @authority(client) sys cheat() { h(); }"#,
        ),
        (
            "r6_f2_match_assign_escape_sys",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { let mut r = query_one(h: &ClientHealth).unwrap(); match 0 { 0 => { r = row; } _ => {} } r.h.hp = 0.0; } }"#,
        ),
        (
            "r6_f2_block_assign_escape_sys",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { let mut r = query_one(h: &ClientHealth).unwrap(); { r = row; } r.h.hp = 0.0; } }"#,
        ),
        (
            "r6_f2_if_cond_client_reassign_keeps_server",
            r#"@authority(client) sys cheat(flag: bool) { let mut r = query_one(h: &Health).unwrap(); if flag { r = query_one(h: &ClientHealth).unwrap(); } r.h.hp = 0.0; }"#,
        ),
        (
            "r6_f2_reassign_client_to_server_sys",
            r#"@authority(client) sys cheat() { let mut r = query_one(h: &ClientHealth).unwrap(); r = query_one(h: &Health).unwrap(); r.h.hp = 0.0; }"#,
        ),
    ];
    for (name, body) in fix2_positive {
        assert_probe_e0501(name, body, true);
    }

    let fix2_negative = [
        (
            "r6_f2_neg_reassign_query_to_client_false_pos",
            r#"@authority(client) sys ok() { let mut r = query_one(h: &Health).unwrap(); r = query_one(h: &ClientHealth).unwrap(); r.h.hp = 0.0; }"#,
        ),
        (
            "r6_f2_neg_reassign_query_to_client_fn_false_pos",
            r#"fn h() { let mut r = query_one(h: &Health).unwrap(); r = query_one(h: &ClientHealth).unwrap(); r.h.hp = 0.0; } @authority(client) sys ok() { h(); }"#,
        ),
        (
            "r6_f2_neg_block_reassign_to_client_false_pos",
            r#"@authority(client) sys ok() { let local_w = ClientWrap { h: ClientHealth { hp: 10.0, flags: bits(0) } }; let r = { let mut x = query_one(h: &Health).unwrap(); x = local_w; x }; r.h = ClientHealth { hp: 20.0, flags: bits(0) }; }"#,
        ),
        (
            "r6_f2_neg_both_branches_reassign_to_client",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &Health).unwrap(); if flag { r = query_one(h: &ClientHealth).unwrap(); } else { r = query_one(h: &ClientHealth).unwrap(); } r.h.hp = 0.0; }"#,
        ),
        (
            "r6_f2_neg_inner_shadow_let_does_not_leak",
            r#"@authority(client) sys ok(cond: bool) { for row in query(h: &Health) { let mut r = query_one(h: &ClientHealth).unwrap(); if cond { let r = row; } r.h.hp = 0.0; } }"#,
        ),
        (
            "r6_f2_neg_inner_shadow_let_client_ok",
            r#"@authority(client) sys ok(cond: bool) { let local_w = ClientWrap { h: ClientHealth { hp: 10.0, flags: bits(0) } }; let mut r = query_one(h: &Health).unwrap(); if cond { let r = local_w; r.h.hp = 0.0; } }"#,
        ),
    ];
    for (name, body) in fix2_negative {
        assert_probe_e0501(name, body, false);
    }

    // Fix 3: Some(...) constructor wrapper provenance
    let fix3_positive = [
        (
            "r6_f3_match_some_tuple_sys",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { match Some((row, 1)) { Some((a, _)) => { a.h.hp = 0.0; } _ => {} } } }"#,
        ),
        (
            "r6_f3_if_let_some_row",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { if let Some(r) = Some(row) { r.h.hp = 0.0; } } }"#,
        ),
        (
            "r6_f3_if_let_some_tuple",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { if let Some((a, b)) = Some((row, 1)) { a.h.hp = 0.0; } } }"#,
        ),
        (
            "r6_f3_if_else_some_none",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { let opt = if true { Some(row) } else { None }; if let Some(r) = opt { r.h.hp = 0.0; } } }"#,
        ),
        (
            "r6_f3_match_tuple_some_row",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { match (Some(row), 1) { (Some(a), _) => { a.h.hp = 0.0; } _ => {} } } }"#,
        ),
    ];
    for (name, body) in fix3_positive {
        assert_probe_e0501(name, body, true);
    }
    assert_probe_e0501(
        "r6_f3_neg_match_some_local_client",
        r#"@authority(client) sys ok() { let local_w = ClientWrap { h: ClientHealth { hp: 10.0, flags: bits(0) } }; match Some((local_w, 1)) { Some((a, _)) => { a.h.hp = 0.0; } _ => {} } }"#,
        false,
    );

    // Fix 4: for/while/abort_if Block iter/cond + if let IfExpr scrutinee
    let fix4_positive = [
        (
            "r6_f4_for_block_iter_query_sys",
            r#"@authority(client) sys cheat() { for row in { query(h: &Health) } { row.h.hp = 0.0; } }"#,
        ),
        (
            "r6_f4_for_block_iter_query_one_sys",
            r#"@authority(client) sys cheat() { for row in { query_one(h: &Health) } { row.h.hp = 0.0; } }"#,
        ),
        (
            "r6_f4_while_block_cond_body_not_dropped",
            r#"@authority(client) sys cheat() { while { false } { let r = query_one(h: &Health).unwrap(); r.h.hp = 0.0; } }"#,
        ),
        (
            "r6_f4_if_let_cond_if_expr_sys",
            r#"@authority(client) sys cheat() { if let Some(r) = if true { query_one(h: &Health) } else { query_one(h: &Health) } { r.h.hp = 0.0; } }"#,
        ),
        (
            "r6_f4_if_let_cond_if_expr_fn",
            r#"fn h() { if let Some(r) = if true { query_one(h: &Health) } else { query_one(h: &Health) } { r.h.hp = 0.0; } } @authority(client) sys cheat() { h(); }"#,
        ),
        (
            "r6_f4_if_let_cond_if_expr_with_else",
            r#"@authority(client) sys cheat() { if let Some(r) = if true { query_one(h: &Health) } else { None } { r.h.hp = 0.0; } else { } }"#,
        ),
    ];
    for (name, body) in fix4_positive {
        assert_probe_e0501(name, body, true);
    }

    // Verify abort_if { cond } { cleanup } lowers both cond and cleanup cleanly
    let abort_if_src = r#"
module test::r6_f4_abort_if @version(1.0.0);
@authority(server) component Health { hp: f32 = 100.0 }
task t() {
    abort_if { false } {
        let r = query_one(h: &Health).unwrap();
        r.h.hp = 0.0;
    }
}
"#;
    let abort_res = analyze_source("r6_f4_abort_if.strata", abort_if_src);
    assert!(
        !abort_res
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0002_PARSE_ERROR)
    );
    assert!(abort_res.tasks.iter().any(|t| {
        t.body.iter().any(|s| {
            matches!(
                s,
                strata_sema::hir::HirStmt::AbortIf {
                    cond: strata_sema::hir::HirExpr::Block { .. },
                    cleanup,
                } if !cleanup.is_empty()
            )
        })
    }));

    // Fix 5: expr_root_server_target wrapped Block / If / Match / Some (all 11 probes + nested .w.h in sys and fn)
    let fix5_positive = [
        (
            "r6_f5_block_wrap_field_prim_set_sys",
            r#"@authority(client) sys cheat() { for row in query(b: &Boss) { ({ row.b.flags }).set(0); } }"#,
        ),
        (
            "r6_f5_block_wrap_field_prim_set_fn",
            r#"fn h() { for row in query(b: &Boss) { ({ row.b.flags }).set(0); } } @authority(client) sys cheat() { h(); }"#,
        ),
        (
            "r6_f5_if_wrap_field_prim_set_sys",
            r#"@authority(client) sys cheat() { for row in query(b: &Boss) { (if true { row.b.flags } else { row.b.flags }).set(0); } }"#,
        ),
        (
            "r6_f5_match_wrap_field_prim_set_sys",
            r#"@authority(client) sys cheat() { for row in query(b: &Boss) { (match 0 { _ => row.b.flags }).set(0); } }"#,
        ),
        (
            "r6_f5_block_wrap_proj_prim_set_sys",
            r#"@authority(client) sys cheat() { for row in query(flags: &Boss.flags) { ({ row.flags }).set(0); } }"#,
        ),
        (
            "r6_f5_block_wrap_res_prim_set_sys",
            r#"@authority(client) sys cheat() { ({ res<ServerState>().flags }).set(0); }"#,
        ),
        (
            "r6_f5_if_wrap_res_prim_set_sys",
            r#"@authority(client) sys cheat() { (if true { res<ServerState>().flags } else { res<ServerState>().flags }).set(0); }"#,
        ),
        (
            "r6_f5_block_wrap_field_refmut_sys",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { take_mut(&mut ({ row.h.hp })); } }"#,
        ),
        (
            "r6_f5_if_wrap_field_refmut_sys",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { take_mut(&mut (if true { row.h.hp } else { row.h.hp })); } }"#,
        ),
        (
            "r6_f5_match_wrap_field_refmut_sys",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { take_mut(&mut (match 0 { _ => row.h.hp })); } }"#,
        ),
        (
            "r6_f5_block_wrap_res_refmut_sys",
            r#"@authority(client) sys cheat() { take_mut_i32(&mut ({ res<ServerBank>().gold })); }"#,
        ),
        (
            "r6_f5_nested_shared_wrap_block_prim_set_fn",
            r#"fn h() { for row in query(w: &SharedWrap) { ({ row.w.h.flags }).set(0); } } @authority(client) sys cheat() { h(); }"#,
        ),
        (
            "r6_f5_nested_shared_wrap_if_refmut_fn",
            r#"fn h() { for row in query(w: &SharedWrap) { take_mut(&mut (if true { row.w.h.hp } else { row.w.h.hp })); } } @authority(client) sys cheat() { h(); }"#,
        ),
        (
            "r6_f5_some_unwrap_prim_set_sys",
            r#"@authority(client) sys cheat() { for row in query(b: &Boss) { Some(row.b.flags).unwrap().set(0); } }"#,
        ),
    ];
    for (name, body) in fix5_positive {
        assert_probe_e0501(name, body, true);
    }

    let fix5_negative = [(
        "r6_f5_neg_client_wrapped_prim_set_and_refmut",
        r#"@authority(client) sys ok() { for row in query(cb: &ClientBoss, ch: &ClientHealth) { ({ row.cb.flags }).set(0); (if true { row.cb.flags } else { row.cb.flags }).set(0); take_mut(&mut ({ row.ch.hp })); } ({ res<ClientState>().flags }).set(0); }"#,
    )];
    for (name, body) in fix5_negative {
        assert_probe_e0501(name, body, false);
    }
}

#[test]
fn m2_r7_regression_iter6_consolidated_fixes_and_negative_controls() {
    fn assert_probe_e0501(name: &str, body: &str, expect_e0501: bool) {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

component Item {{ hp: f32 = 10.0 }}

@authority(server)
component Health {{ hp: f32 = 100.0, arr: [i32; 4], matrix: [[i32; 2]; 2], items: [Item; 2] }}

@authority(client)
component ClientHealth {{ hp: f32 = 50.0, arr: [i32; 4], matrix: [[i32; 2]; 2], items: [Item; 2] }}

@authority(client)
component ClientWrap {{ h: ClientHealth }}

@authority(client)
component ClientWrap2 {{ h: ClientHealth }}

@authority(server)
component ServerWrap {{ h: Health }}

@authority(server)
component ServerWrap2 {{ h: Health }}

component SharedWrap {{ h: Health, ch: ClientHealth }}

component ServerHolder {{ w: ServerWrap }}

component ClientHolder {{ w: ClientWrap2 }}

@authority(server)
resource ServerBank {{ gold: i32 = 0, arr: [i32; 4] }}

@authority(client)
resource ClientBank {{ gold: i32 = 0, arr: [i32; 4] }}

{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            !res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0002_PARSE_ERROR),
            "unexpected parse errors in {name}: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
    }

    // Fix 1: IndexExpr lvalues wrapping Block / IfExpr / MatchExpr over array fields
    let fix1_positive = [
        (
            "r7_f1_block_wrapped_array_field_index_sys",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { ({ row.h.arr })[0] = 5; } }"#,
        ),
        (
            "r7_f1_block_wrapped_array_field_index_fn",
            r#"fn helper() { for row in query(h: &Health) { ({ row.h.arr })[0] = 5; } } @authority(client) sys cheat() { helper(); }"#,
        ),
        (
            "r7_f1_if_mixed_array_field_index_sys",
            r#"@authority(client) sys cheat(flag: bool) { (if flag { query_one(h: &ClientHealth).unwrap().h.arr } else { query_one(h: &Health).unwrap().h.arr })[0] = 5; }"#,
        ),
        (
            "r7_f1_if_mixed_array_compound_assign_sys",
            r#"@authority(client) sys cheat(flag: bool) { (if flag { query_one(h: &ClientHealth).unwrap().h.arr } else { query_one(h: &Health).unwrap().h.arr })[0] += 5; }"#,
        ),
        (
            "r7_f1_match_wrapped_array_field_index_sys",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { (match 0 { _ => row.h.arr })[0] = 5; } }"#,
        ),
        (
            "r7_f1_block_wrapped_res_array_index_sys",
            r#"@authority(client) sys cheat() { ({ res<ServerBank>().arr })[0] = 5; }"#,
        ),
        (
            "r7_f1_if_mixed_nested_shared_wrap_arr_sys",
            r#"@authority(client) sys cheat(flag: bool) { for row in query(w: &SharedWrap) { (if flag { row.w.ch.arr } else { row.w.h.arr })[0] = 5; } }"#,
        ),
        (
            "r7_f1_block_wrapped_multidim_array_index_sys",
            r#"@authority(client) sys cheat() { for row in query(h: &Health) { ({ row.h.matrix })[0][1] = 5; } }"#,
        ),
        (
            "r7_f1_if_mixed_array_of_structs_field_assign_sys",
            r#"@authority(client) sys cheat(flag: bool) { for row in query(ch: &ClientHealth, h: &Health) { (if flag { row.ch.items } else { row.h.items })[0].hp = 0.0; } }"#,
        ),
    ];
    for (name, body) in fix1_positive {
        assert_probe_e0501(name, body, true);
    }

    let fix1_negative = [
        (
            "r7_f1_neg_block_wrapped_client_array",
            r#"@authority(client) sys ok() { for row in query(ch: &ClientHealth) { ({ row.ch.arr })[0] = 5; } }"#,
        ),
        (
            "r7_f1_neg_if_mixed_client_only_arrays",
            r#"@authority(client) sys ok(flag: bool) { let client_h1 = ClientHealth { hp: 10.0, arr: [0, 0, 0, 0], matrix: [[0, 0], [0, 0]], items: [Item { hp: 1.0 }, Item { hp: 1.0 }] }; let client_h2 = ClientHealth { hp: 20.0, arr: [0, 0, 0, 0], matrix: [[0, 0], [0, 0]], items: [Item { hp: 1.0 }, Item { hp: 1.0 }] }; (if flag { client_h1.arr } else { client_h2.arr })[0] = 5; }"#,
        ),
        (
            "r7_f1_neg_block_wrapped_client_res_array",
            r#"@authority(client) sys ok() { ({ res<ClientBank>().arr })[0] = 5; }"#,
        ),
        (
            "r7_f1_neg_shared_wrap_client_branch_arr",
            r#"@authority(client) sys ok(flag: bool) { for row in query(w: &SharedWrap, cw: &ClientWrap) { (if flag { row.w.ch.arr } else { row.cw.h.arr })[0] = 5; } }"#,
        ),
    ];
    for (name, body) in fix1_negative {
        assert_probe_e0501(name, body, false);
    }

    // Fix 2: Asymmetric mixed-authority tuple destructuring & per-element cands propagation
    let fix2_positive = [
        (
            "r7_f2_tuple_asymmetric_mixed_if_destructure_sys",
            r#"@authority(client) sys cheat(flag: bool) { let (_, h) = if flag { (query_one(w: &SharedWrap).unwrap().w, query_one(h: &ClientHealth).unwrap().h) } else { (query_one(w: &ClientWrap).unwrap().w, query_one(h: &Health).unwrap().h) }; h.hp = 0.0; }"#,
        ),
        (
            "r7_f2_tuple_asymmetric_mixed_if_destructure_fn",
            r#"fn helper(flag: bool) { let (_, h) = if flag { (query_one(w: &SharedWrap).unwrap().w, query_one(h: &ClientHealth).unwrap().h) } else { (query_one(w: &ClientWrap).unwrap().w, query_one(h: &Health).unwrap().h) }; h.hp = 0.0; } @authority(client) sys cheat(flag: bool) { helper(flag); }"#,
        ),
        (
            "r7_f2_tuple_asymmetric_mixed_match_destructure_sys",
            r#"@authority(client) sys cheat() { let (_, h) = match 0 { 0 => (query_one(w: &SharedWrap).unwrap().w, query_one(h: &ClientHealth).unwrap().h), _ => (query_one(w: &ClientWrap).unwrap().w, query_one(h: &Health).unwrap().h) }; h.hp = 0.0; }"#,
        ),
        (
            "r7_f2_nested_tuple_asymmetric_if_destructure_sys",
            r#"@authority(client) sys cheat(flag: bool) { let ((_, h), _) = if flag { ((query_one(w: &SharedWrap).unwrap().w, query_one(h: &ClientHealth).unwrap().h), 1) } else { ((query_one(w: &ClientWrap).unwrap().w, query_one(h: &Health).unwrap().h), 2) }; h.hp = 0.0; }"#,
        ),
        (
            "r7_f2_tuple_of_ifs_intermediate_var_sys",
            r#"@authority(client) sys cheat(flag: bool) { let t = (if flag { query_one(w: &SharedWrap).unwrap().w } else { query_one(w: &ClientWrap).unwrap().w }, if flag { (query_one(w: &SharedWrap).unwrap().w, query_one(h: &ClientHealth).unwrap().h) } else { (query_one(w: &ClientWrap).unwrap().w, query_one(h: &Health).unwrap().h) }); let (_, (_, h)) = t; h.hp = 0.0; }"#,
        ),
        (
            "r7_f2_query_shape_tuple_mixed_non_query_elem_sys",
            r#"@authority(client) sys cheat(flag: bool) { let (r, w, h) = if flag { (query_one(h: &ClientHealth).unwrap(), query_one(w: &SharedWrap).unwrap().w, query_one(h: &ClientHealth).unwrap().h) } else { (query_one(h: &ClientHealth).unwrap(), query_one(w: &ClientWrap).unwrap().w, query_one(h: &Health).unwrap().h) }; h.hp = 0.0; }"#,
        ),
    ];
    for (name, body) in fix2_positive {
        assert_probe_e0501(name, body, true);
    }

    let fix2_negative = [(
        "r7_f2_neg_client_only_mixed_tuple_destructure",
        r#"@authority(client) sys ok(flag: bool) { let (w, h) = if flag { (query_one(w: &SharedWrap).unwrap().w, query_one(h: &ClientHealth).unwrap().h) } else { (query_one(w: &ClientWrap).unwrap().w, query_one(h: &ClientHealth).unwrap().h) }; w.ch.hp = 0.0; h.hp = 0.0; }"#,
    )];
    for (name, body) in fix2_negative {
        assert_probe_e0501(name, body, false);
    }

    // Fix 3: merge_opt_scope_bindings / bind_pattern keeping Var/MultiVar with QueryRow/QueryTuple
    let fix3_positive = [
        (
            "r7_f3_mixed_query_and_non_query_var_escape_if",
            r#"@authority(client) sys cheat(flag: bool) { let sh = ServerHolder { w: ServerWrap { h: Health { hp: 100.0, arr: [0, 0, 0, 0], matrix: [[0, 0], [0, 0]], items: [Item { hp: 1.0 }, Item { hp: 1.0 }] } } }; let mut r = query_one(w: &ClientWrap).unwrap(); if flag { r = query_one(w: &ClientWrap).unwrap(); } else { r = sh; } r.w.h.hp = 0.0; }"#,
        ),
        (
            "r7_f3_let_if_query_and_non_query_var",
            r#"@authority(client) sys cheat(flag: bool) { let sh = ServerHolder { w: ServerWrap { h: Health { hp: 100.0, arr: [0, 0, 0, 0], matrix: [[0, 0], [0, 0]], items: [Item { hp: 1.0 }, Item { hp: 1.0 }] } } }; let r = if flag { query_one(w: &ClientWrap).unwrap() } else { sh }; r.w.h.hp = 0.0; }"#,
        ),
        (
            "r7_f3_if_reassign_query_row_to_server_var",
            r#"@authority(client) sys cheat(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(w: &ServerWrap).unwrap().w; } r.h.hp = 0.0; }"#,
        ),
        (
            "r7_f3_var_merged_with_query_row_order_reversed",
            r#"@authority(client) sys cheat(flag: bool) { let mut r = ServerHolder { w: ServerWrap { h: Health { hp: 100.0, arr: [0, 0, 0, 0], matrix: [[0, 0], [0, 0]], items: [Item { hp: 1.0 }, Item { hp: 1.0 }] } } }; if flag { r = query_one(w: &ClientWrap).unwrap(); } r.w.h.hp = 0.0; }"#,
        ),
    ];
    for (name, body) in fix3_positive {
        assert_probe_e0501(name, body, true);
    }

    let fix3_negative = [(
        "r7_f3_neg_mixed_client_query_and_client_holder",
        r#"@authority(client) sys ok(flag: bool) { let ch = ClientHolder { w: ClientWrap2 { h: ClientHealth { hp: 50.0, arr: [0, 0, 0, 0], matrix: [[0, 0], [0, 0]], items: [Item { hp: 1.0 }, Item { hp: 1.0 }] } } }; let r = if flag { query_one(w: &ClientWrap).unwrap() } else { ch }; r.w.h.hp = 0.0; }"#,
    )];
    for (name, body) in fix3_negative {
        assert_probe_e0501(name, body, false);
    }

    // Fix 4: Exhaustive bool / Option::None match catch-all parity
    let fix4_negative = [
        (
            "r7_f4_match_bool_both_reassign_to_client_false_pos",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &Health).unwrap(); match flag { true => { r = query_one(h: &ClientHealth).unwrap(); } false => { r = query_one(h: &ClientHealth).unwrap(); } } r.h.hp = 0.0; }"#,
        ),
        (
            "r7_f4_match_option_both_reassign_to_client_false_pos",
            r#"@authority(client) sys ok() { let mut r = query_one(h: &Health).unwrap(); match Some(1) { Some(_) => { r = query_one(h: &ClientHealth).unwrap(); } Option::None => { r = query_one(h: &ClientHealth).unwrap(); } } r.h.hp = 0.0; }"#,
        ),
    ];
    for (name, body) in fix4_negative {
        assert_probe_e0501(name, body, false);
    }

    let fix4_positive = [
        (
            "r7_f4_match_guarded_bool_not_catch_all",
            r#"@authority(client) sys cheat(flag: bool, g: bool) { let mut r = query_one(h: &Health).unwrap(); match flag { true => { r = query_one(h: &ClientHealth).unwrap(); } false if g => { r = query_one(h: &ClientHealth).unwrap(); } } r.h.hp = 0.0; }"#,
        ),
        (
            "r7_f4_match_none_alone_not_catch_all",
            r#"@authority(client) sys cheat() { let mut r = query_one(h: &Health).unwrap(); match Some(1) { None => { r = query_one(h: &ClientHealth).unwrap(); } } r.h.hp = 0.0; }"#,
        ),
    ];
    for (name, body) in fix4_positive {
        assert_probe_e0501(name, body, true);
    }

    // Fix 5: LetStmt else_block diverging scope isolation
    let fix5_negative = [
        (
            "r7_f5_let_else_diverging_reassign_false_pos",
            r#"@authority(client) sys ok() { let mut r = query_one(h: &ClientHealth).unwrap(); let Some(_x) = Some(1) else { r = query_one(h: &Health).unwrap(); return; }; r.h.hp = 0.0; }"#,
        ),
        (
            "r7_f5_let_else_diverging_reassign_fn_false_pos",
            r#"fn helper() { let mut r = query_one(h: &ClientHealth).unwrap(); let Some(_x) = Some(1) else { r = query_one(h: &Health).unwrap(); return; }; r.h.hp = 0.0; } @authority(client) sys ok() { helper(); }"#,
        ),
    ];
    for (name, body) in fix5_negative {
        assert_probe_e0501(name, body, false);
    }

    let fix5_positive = [(
        "r7_f5_let_else_inner_server_write_still_caught",
        r#"@authority(client) sys cheat() { let Some(_x) = Some(1) else { let r = query_one(h: &Health).unwrap(); r.h.hp = 0.0; return; }; }"#,
    )];
    for (name, body) in fix5_positive {
        assert_probe_e0501(name, body, true);
    }
}

#[test]
fn node_pure_rejects_impure_default_param_expressions() {
    let src = r#"
module test::node_pure_default @version(1.0.0);

resource Bank { g: i32 = 0 }
component H { hp: i32 = 1 }

fn impure() -> i32 { 1 }

@node_pure
fn pure_helper(v: i32) -> i32 {
    return v * 2;
}

@node_pure
fn ok_default(x: i32 = pure_helper(2)) -> i32 {
    return x + 1;
}

@node_pure
fn bad1(x: i32 = impure()) -> i32 {
    return x;
}

@node_pure
fn bad2(x: i32 = res_mut<Bank>().g) -> i32 {
    return x;
}

@node_pure
fn bad3(x: i32 = query_one(h: &H).unwrap().h.hp) -> i32 {
    return x;
}

@node_pure
fn bad4(x: i32 = ({ let _e = spawn { H { hp: 2 } }; 1 })) -> i32 {
    return x;
}
"#;
    let res = analyze_source("node_pure_default.strata", src);
    assert!(!res.ok(), "expected E0601 errors for impure defaults");
    let errs: Vec<_> = res
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::E0601_NODE_PURE_VIOLATION)
        .collect();
    assert_eq!(
        errs.len(),
        4,
        "expected 4 E0601_NODE_PURE_VIOLATION diagnostics, got: {errs:#?}"
    );
    assert!(
        !errs.iter().any(|d| d.message.contains("ok_default")),
        "valid @node_pure default param must not trigger E0601: {errs:#?}"
    );
}

#[test]
fn m1_r1_extract_insert_components_nested_bundle_lit_and_negative_controls() {
    fn assert_probe_e0501(name: &str, body: &str, expect_e0501: bool) -> usize {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

@authority(server)
component ServerComp {{ x: f32 = 1.0 }}

@authority(client)
component ClientComp {{ x: f32 = 2.0 }}

@authority(client)
component ClientComp2 {{ y: f32 = 3.0 }}

component Target {{ id: u32 = 0 }}

{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            !res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0002_PARSE_ERROR),
            "unexpected parse errors in {name}: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
        e0501.len()
    }

    let positive_cases = [
        (
            "bundle_direct_single",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, { ServerComp { x: 1.0 } }); } }"#,
        ),
        (
            "bundle_direct_mixed",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, { ServerComp { x: 1.0 }, ClientComp { x: 2.0 } }); } }"#,
        ),
        (
            "bundle_block_wrapped",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, { let _k = 1; { ServerComp { x: 1.0 }, ClientComp { x: 2.0 } } }); } }"#,
        ),
        (
            "bundle_block_inner_let",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, { let b = { ServerComp { x: 1.0 } }; b }); } }"#,
        ),
        (
            "bundle_if_branches",
            r#"@authority(client) sys cheat(flag: bool) { for r in query(t: &Target) { insert(r.id, if flag { { ClientComp { x: 2.0 } } } else { { ServerComp { x: 1.0 } } }); } }"#,
        ),
        (
            "bundle_match_arms",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, match 0 { 0 => { ClientComp { x: 2.0 } }, _ => { ServerComp { x: 1.0 } } }); } }"#,
        ),
        (
            "bundle_let_bound_direct",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let b = { ServerComp { x: 1.0 }, ClientComp { x: 2.0 } }; insert(r.id, b); } }"#,
        ),
        (
            "bundle_let_bound_if",
            r#"@authority(client) sys cheat(flag: bool) { for r in query(t: &Target) { let b = if flag { { ClientComp { x: 2.0 } } } else { { ServerComp { x: 1.0 } } }; insert(r.id, b); } }"#,
        ),
        (
            "bundle_let_bound_match",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let b = match 0 { 0 => { ClientComp { x: 2.0 } }, _ => { ServerComp { x: 1.0 } } }; insert(r.id, b); } }"#,
        ),
        (
            "bundle_let_bound_block",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let b = { let _k = 1; { ServerComp { x: 1.0 } } }; insert(r.id, b); } }"#,
        ),
        (
            "bundle_unconditional_reassign_to_server",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; b = { ServerComp { x: 1.0 } }; insert(r.id, b); } }"#,
        ),
        (
            "bundle_cond_reassign_to_server",
            r#"@authority(client) sys cheat(flag: bool) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; if flag { b = { ServerComp { x: 1.0 } }; } insert(r.id, b); } }"#,
        ),
        (
            "bundle_cond_reassign_from_server_to_client",
            r#"@authority(client) sys cheat(flag: bool) { for r in query(t: &Target) { let mut b = { ServerComp { x: 1.0 } }; if flag { b = { ClientComp { x: 2.0 } }; } insert(r.id, b); } }"#,
        ),
        (
            "bundle_tuple_destructure",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let (a, _) = ({ ServerComp { x: 1.0 } }, { ClientComp { x: 2.0 } }); insert(r.id, a); } }"#,
        ),
        (
            "bundle_if_let_some_tuple_destructure",
            r#"@authority(client) sys cheat(flag: bool) { for r in query(t: &Target) { if let Some((a, _)) = if flag { Some(({ ServerComp { x: 1.0 } }, 1)) } else { None } { insert(r.id, a); } } }"#,
        ),
        (
            "bundle_insert_if_new",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert @if_new(r.id, { let _k = 1; { ServerComp { x: 1.0 } } }); } }"#,
        ),
        (
            "bundle_nested_control_flow_while_loop_let_else",
            r#"@authority(client) sys cheat(flag: bool) { for r in query(t: &Target) { let Some(_x) = Some(1) else { return; }; let mut i = 0; while i < 1 { i += 1; if flag { match 1 { 1 => { loop { insert(r.id, { let _k = 1; { ServerComp { x: 1.0 } } }); break; } } _ => {} } } } } }"#,
        ),
        (
            "bundle_side_effect_order_then_returns_server",
            r#"@authority(client) sys cheat(flag: bool) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; insert(r.id, if flag { b = { ServerComp { x: 1.0 } }; { ServerComp { x: 1.0 } } } else { b }); } }"#,
        ),
        (
            "bundle_predicted_system",
            r#"@predicted sys cheat_pred(flag: bool) { for r in query(t: &Target) { insert(r.id, if flag { { ServerComp { x: 1.0 } } } else { { ClientComp { x: 2.0 } } }); } }"#,
        ),
        (
            "bundle_transitive_helper_fn",
            r#"fn h_inner(e: Entity) { insert(e, { let _k = 1; { ServerComp { x: 1.0 }, ClientComp { x: 2.0 } } }); } fn h_outer(e: Entity) { h_inner(e); } @authority(client) sys cheat() { for r in query(t: &Target) { h_outer(r.id); } }"#,
        ),
    ];

    for (name, body) in positive_cases {
        assert_probe_e0501(name, body, true);
    }

    // Deduplication check: both branches yielding `ServerComp` must emit exactly 1 E0501.
    let dedup_count = assert_probe_e0501(
        "bundle_dedup_both_branches",
        r#"@authority(client) sys cheat(flag: bool) { for r in query(t: &Target) { insert(r.id, if flag { { ServerComp { x: 1.0 } } } else { { ServerComp { x: 1.0 } } }); } }"#,
        true,
    );
    assert_eq!(dedup_count, 1, "expected deduplicated single E0501");

    let negative_cases = [
        (
            "neg_client_only_direct",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { insert(r.id, { ClientComp { x: 2.0 }, ClientComp2 { y: 3.0 } }); } }"#,
        ),
        (
            "neg_client_only_nested_block_if_match",
            r#"@authority(client) sys ok(flag: bool) { for r in query(t: &Target) { insert(r.id, { let _k = 1; if flag { { ClientComp { x: 2.0 } } } else { match 0 { _ => { ClientComp2 { y: 3.0 } } } } }); } }"#,
        ),
        (
            "neg_client_only_let_and_helper",
            r#"fn h_ok(e: Entity) { let b = { ClientComp { x: 2.0 }, ClientComp2 { y: 3.0 } }; insert(e, b); } @authority(client) sys ok() { for r in query(t: &Target) { h_ok(r.id); } }"#,
        ),
        (
            "neg_shadow_outer_server_with_inner_let_client",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let b = { ServerComp { x: 1.0 } }; insert(r.id, { let b = { ClientComp { x: 2.0 } }; b }); } }"#,
        ),
        (
            "neg_inner_block_server_does_not_leak_to_outer_client",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let b = { ClientComp { x: 2.0 } }; { let b = { ServerComp { x: 1.0 } }; } insert(r.id, b); } }"#,
        ),
        (
            "neg_if_let_some_shadows_outer_server",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let b = { ServerComp { x: 1.0 } }; if let Some(b) = Some({ ClientComp { x: 2.0 } }) { insert(r.id, b); } } }"#,
        ),
        (
            "neg_match_arm_shadows_outer_server",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let b = { ServerComp { x: 1.0 } }; match Some({ ClientComp { x: 2.0 } }) { Some(b) => { insert(r.id, b); } _ => {} } } }"#,
        ),
        (
            "neg_unconditional_reassign_server_to_client",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let mut b = { ServerComp { x: 1.0 } }; b = { ClientComp { x: 2.0 } }; insert(r.id, b); } }"#,
        ),
        (
            "neg_exhaustive_if_else_reassign_server_to_client",
            r#"@authority(client) sys ok(flag: bool) { for r in query(t: &Target) { let mut b = { ServerComp { x: 1.0 } }; if flag { b = { ClientComp { x: 2.0 } }; } else { b = { ClientComp2 { y: 3.0 } }; } insert(r.id, b); } }"#,
        ),
        (
            "neg_tuple_select_client_element",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let (_, b) = ({ ServerComp { x: 1.0 } }, { ClientComp { x: 2.0 } }); insert(r.id, b); } }"#,
        ),
        (
            "neg_side_effect_order_then_mutates_b_else_uses_pre_b",
            r#"@authority(client) sys ok(flag: bool) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; insert(r.id, if flag { b = { ServerComp { x: 1.0 } }; { ClientComp { x: 2.0 } } } else { b }); } }"#,
        ),
        (
            "neg_server_system_inserting_nested_server_bundle",
            r#"@authority(server) sys ok() { for r in query(t: &Target) { insert(r.id, { let _k = 1; { ServerComp { x: 1.0 } } }); } }"#,
        ),
    ];

    for (name, body) in negative_cases {
        assert_probe_e0501(name, body, false);
    }

    // Read-only scalar/value copies from immutable `@authority(server)` `&res ServerRes` or `&ServerComp`
    // into `@authority(client)` components (via `insert`, `spawn`, or helper `fn(v: f32)`) MUST be
    // permitted (`expect_e0501 = false`), whereas actual server mutations (`res_mut`, `&mut`) or
    // spawning/inserting `@authority(server)` components MUST emit E0501.
    assert_probe_e0501(
        "comp_init_reading_server_res_in_client_sys",
        r#"
@authority(server)
resource ServerRes { v: f32 = 1.0 }
@authority(client)
sys ok_copy(sr: &res ServerRes) {
    spawn { ClientComp { x: sr.v } };
    for r in query(t: &Target) {
        insert(r.id, { ClientComp { x: sr.v } });
        insert(r.id, ClientComp { x: sr.v });
    }
}
"#,
        false,
    );
    assert_probe_e0501(
        "comp_init_helper_value_param_from_server_query",
        r#"
@authority(server)
component Health { hp: f32 = 100.0 }
fn spawn_client(v: f32) {
    spawn { ClientComp { x: v } };
}
@authority(client)
sys ok_helper() {
    for h in query(h: &Health) {
        spawn_client(h.hp);
    }
}
"#,
        false,
    );
    assert_probe_e0501(
        "comp_init_server_mutation_inside_client_field_expr",
        r#"
@authority(server)
resource ServerBank { gold: i32 = 0 }
@authority(client)
sys bad_mut_res() {
    for r in query(t: &Target) {
        insert(r.id, { ClientComp { x: { res_mut<ServerBank>().gold = 1; 1.0 } } });
    }
}
"#,
        true,
    );
    assert_probe_e0501(
        "comp_init_refmut_server_comp_inside_spawn_client_field",
        r#"
@authority(client)
sys bad_refmut() {
    for r in query(sc: &mut ServerComp) {
        spawn { ClientComp { x: { let p = &mut r.sc; p.x } } };
    }
}
"#,
        true,
    );
    assert_probe_e0501(
        "bundle_lit_in_struct_and_array_and_fn",
        r#"
struct Holder { val: f32 }
fn make_val() -> f32 { return 1.0; }
@authority(client)
sys bad() {
    let _h = Holder { val: make_val() };
    for r in query(t: &Target) {
        let _arr = [1.0, 2.0];
        insert(r.id, { ClientComp { x: _h.val }, ServerComp { x: _arr[0] } });
    }
}
"#,
        true,
    );

    // Reversed `match` on Option (`None => ..., Some(x) => ...` and `None => ..., _ => ...`)
    // must lower bare `None` as `HirPattern::Path("None")`, never as `HirPattern::Binding`.
    let rev_src = r#"
module test::rev_none_pat @version(1.0.0);
component Target { id: u32 = 0 }
component Out { v: i32 = 0 }
sys check() {
    for row in query(o: &mut Out, t: Option<&Target>) {
        match row.t {
            None => { row.o.v -= 1; },
            Some(x) => { row.o.v += x.id as i32; },
        }
        match row.t {
            None => { row.o.v -= 2; },
            _ => { row.o.v += 5; },
        }
    }
}
"#;
    let rev_res = analyze_source("rev_none_pat.strata", rev_src);
    assert!(rev_res.ok(), "{:?}", rev_res.diagnostics);
    let check_fn = rev_res
        .callables
        .iter()
        .find(|f| f.name == "check")
        .expect("check fn");
    let has_path_none = format!("{:?}", check_fn.body).contains("Path(\"None\")");
    assert!(
        has_path_none,
        "bare `None` must lower to HirPattern::Path(\"None\"): {:?}",
        check_fn.body
    );
}

#[test]
fn m1_r2_regression_loops_side_effects_divergence_and_option_shapes() {
    fn assert_probe(name: &str, extra_decls: &str, body: &str, expect_e0501: bool) -> usize {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

@authority(server)
component ServerComp {{ x: f32 = 1.0 }}

@authority(server)
component Health {{ hp: f32 = 100.0 }}

@authority(client)
component ClientHealth {{ hp: f32 = 50.0 }}

@authority(client)
component ClientComp {{ x: f32 = 2.0 }}

@authority(server)
resource ServerBank {{ gold: i32 = 0 }}

component Target {{ id: u32 = 0 }}

{extra_decls}

{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            !res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0002_PARSE_ERROR),
            "unexpected parse errors in {name}: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
        e0501.len()
    }

    // 1. Loop back-edge positives (each must emit exactly 1 deduplicated E0501).
    let loop_positives = [
        (
            "pos_while_backedge_insert_before_reassign",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let mut i = 0; while i < 2 { insert(r.id, b); b = { ServerComp { x: 1.0 } }; i += 1; } } }"#,
        ),
        (
            "pos_loop_backedge_insert_before_reassign",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let mut i = 0; loop { insert(r.id, b); b = { ServerComp { x: 1.0 } }; i += 1; if i >= 2 { break; } } } }"#,
        ),
        (
            "pos_for_range_backedge_insert_before_reassign",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; for _i in 0..2 { insert(r.id, b); b = { ServerComp { x: 1.0 } }; } } }"#,
        ),
        (
            "pos_fn_while_backedge",
            "",
            r#"fn helper(e: Entity) { let mut b = { ClientComp { x: 2.0 } }; let mut i = 0; while i < 2 { insert(e, b); b = { ServerComp { x: 1.0 } }; i += 1; } } @authority(client) sys cheat() { for r in query(t: &Target) { helper(r.id); } }"#,
        ),
        (
            "pos_while_cond_guard_backedge_insert",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let mut i = 0; while i < 2 { if i == 1 { insert(r.id, b); } b = { ServerComp { x: 1.0 } }; i += 1; } } }"#,
        ),
        (
            "pos_block_for_backedge_out_var",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, { let mut b = { ClientComp { x: 2.0 } }; let mut out = { ClientComp { x: 2.0 } }; for _i in 0..2 { out = b; b = { ServerComp { x: 1.0 } }; } out }); } }"#,
        ),
        (
            "pos_while_cond_reads_b_body_reassigns",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let mut i = 0; while { let keep = i < 2; if keep { insert(r.id, b); } keep } { b = { ServerComp { x: 1.0 } }; i += 1; } } }"#,
        ),
        (
            "pos_while_continue_backedge_mutates_b",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let mut i = 0; while i < 2 { i += 1; if i == 1 { b = { ServerComp { x: 1.0 } }; continue; } insert(r.id, b); } } }"#,
        ),
        (
            "pos_loop_break_with_server_then_insert_after",
            "",
            r#"@authority(client) sys cheat(flag: bool) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; loop { if flag { b = { ServerComp { x: 1.0 } }; break; } break; } insert(r.id, b); } }"#,
        ),
        (
            "pos_nested_while_for_backedge",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let mut i = 0; while i < 2 { for _j in 0..2 { insert(r.id, b); } b = { ServerComp { x: 1.0 } }; i += 1; } } }"#,
        ),
        (
            "pos_query_scope_loop_backedge",
            "",
            r#"@authority(client) sys cheat() { let mut r = query_one(h: &ClientHealth).unwrap(); let mut i = 0; while i < 2 { r.h.hp = 0.0; r = query_one(h: &Health).unwrap(); i += 1; } }"#,
        ),
        (
            "pos_while_let_else_break_mutates_b",
            "",
            r#"@authority(client) sys cheat(flag: bool) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let mut i = 0; while i < 2 { let opt = if flag { None } else { Some(1) }; let Some(_) = opt else { b = { ServerComp { x: 1.0 } }; break; }; i += 1; } insert(r.id, b); } }"#,
        ),
    ];
    for (name, decls, body) in loop_positives {
        let count = assert_probe(name, decls, body, true);
        assert_eq!(
            count, 1,
            "expected exactly 1 E0501 (no loop duplicate) in {name}"
        );
    }

    // 2. Loop negative controls.
    let loop_negatives = [
        (
            "neg_while_unconditional_client_before_insert",
            "",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let mut b = { ServerComp { x: 1.0 } }; let mut i = 0; while i < 2 { b = { ClientComp { x: 2.0 } }; insert(r.id, b); b = { ServerComp { x: 1.0 } }; i += 1; } } }"#,
        ),
        (
            "neg_loop_unconditional_client_before_break",
            "",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let mut b = { ServerComp { x: 1.0 } }; loop { b = { ClientComp { x: 2.0 } }; break; } insert(r.id, b); } }"#,
        ),
        (
            "neg_while_break_with_server_unreachable_insert_inside",
            "",
            r#"@authority(client) sys ok(flag: bool) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let mut i = 0; while i < 2 { if flag { b = { ServerComp { x: 1.0 } }; break; } insert(r.id, b); i += 1; } } }"#,
        ),
        (
            "neg_while_body_returns_server_does_not_leak",
            "",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let mut i = 0; while i < 2 { b = { ServerComp { x: 1.0 } }; return; } insert(r.id, b); } }"#,
        ),
    ];
    for (name, decls, body) in loop_negatives {
        assert_probe(name, decls, body, false);
    }

    // 3. Side-effect completeness in resolve_expr_insert_shape & simulate_* (If::cond, Match, Tuple, Assign, Spawn, For::reduce, etc.).
    let side_effect_positives = [
        (
            "pos_if_cond_side_effect_mutates_b",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; insert(r.id, if { b = { ServerComp { x: 1.0 } }; true } { b } else { { ClientComp { x: 2.0 } } }); } }"#,
        ),
        (
            "pos_fn_if_cond_side_effect",
            "",
            r#"fn helper(e: Entity) { let mut b = { ClientComp { x: 2.0 } }; insert(e, if { b = { ServerComp { x: 1.0 } }; true } { b } else { { ClientComp { x: 2.0 } } }); } @authority(client) sys cheat() { for r in query(t: &Target) { helper(r.id); } }"#,
        ),
        (
            "pos_if_let_cond_side_effect_else_uses_b",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; insert(r.id, if let Some(_) = { b = { ServerComp { x: 1.0 } }; None } { { ClientComp { x: 2.0 } } } else { b }); } }"#,
        ),
        (
            "pos_match_scrutinee_side_effect_mutates_b",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; insert(r.id, match { b = { ServerComp { x: 1.0 } }; 0 } { _ => b }); } }"#,
        ),
        (
            "pos_match_guard_side_effect_mutates_b",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; insert(r.id, match 0 { _ if { b = { ServerComp { x: 1.0 } }; true } => b, _ => { ClientComp { x: 2.0 } } }); } }"#,
        ),
        (
            "pos_match_guard_in_fn",
            "",
            r#"fn helper(e: Entity) { let mut b = { ClientComp { x: 2.0 } }; insert(e, match 0 { _ if { b = { ServerComp { x: 1.0 } }; true } => b, _ => { ClientComp { x: 2.0 } } }); } @authority(client) sys cheat() { for r in query(t: &Target) { helper(r.id); } }"#,
        ),
        (
            "pos_match_failed_guard_fallthrough_to_next_arm",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; insert(r.id, match 0 { _ if { b = { ServerComp { x: 1.0 } }; false } => { ClientComp { x: 2.0 } }, _ => b }); } }"#,
        ),
        (
            "pos_match_failed_guard_fallthrough_non_exhaustive",
            "",
            r#"@authority(client) sys cheat(x: i32) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; match x { 0 if { b = { ServerComp { x: 1.0 } }; false } => {} _ => {} } insert(r.id, b); } }"#,
        ),
        (
            "pos_tuple_elem_side_effect_mutates_b",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let (_, d) = ({ b = { ServerComp { x: 1.0 } }; 1 }, b); insert(r.id, d); } }"#,
        ),
        (
            "pos_fn_tuple_elem_side_effect",
            "",
            r#"fn helper(e: Entity) { let mut b = { ClientComp { x: 2.0 } }; let (_, d) = ({ b = { ServerComp { x: 1.0 } }; 1 }, b); insert(e, d); } @authority(client) sys cheat() { for r in query(t: &Target) { helper(r.id); } }"#,
        ),
        (
            "pos_compound_assign_rhs_side_effect_in_block",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let mut k = 0; insert(r.id, { k += { b = { ServerComp { x: 1.0 } }; 1 }; b }); } }"#,
        ),
        (
            "pos_index_assign_rhs_side_effect_in_block",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let mut arr = [0, 1]; insert(r.id, { arr[0] = { b = { ServerComp { x: 1.0 } }; 5 }; b }); } }"#,
        ),
        (
            "pos_index_assign_index_side_effect_in_block",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let mut arr = [0, 1]; insert(r.id, { arr[{ b = { ServerComp { x: 1.0 } }; 0 }] = 5; b }); } }"#,
        ),
        (
            "pos_short_circuit_and_side_effect_in_block",
            "",
            r#"@authority(client) sys cheat(flag: bool) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; insert(r.id, { let _ok = flag && { b = { ServerComp { x: 1.0 } }; true }; b }); } }"#,
        ),
        (
            "pos_for_reduce_identity_side_effect",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; insert(r.id, { let _tot = for _x in query(t2: &Target) reduce (s: sum({ b = { ServerComp { x: 1.0 } }; 0.0 }, 1.0)); b }); } }"#,
        ),
        (
            "pos_for_reduce_value_side_effect",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; insert(r.id, { let _tot = for _x in query(t2: &Target) reduce (s: sum(0.0, { b = { ServerComp { x: 1.0 } }; 1.0 })); b }); } }"#,
        ),
        (
            "pos_spawn_batch_count_side_effect_before_preamble",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; spawn_batch({ b = { ServerComp { x: 1.0 } }; 1 }) |_| { insert(r.id, b); ClientComp { x: 2.0 } }; } }"#,
        ),
        (
            "pos_spawn_batch_preamble_mutates_outer_b",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; spawn_batch(1) |_| { b = { ServerComp { x: 1.0 } }; ClientComp { x: 2.0 } }; insert(r.id, b); } }"#,
        ),
        (
            "pos_spawn_batch_preamble_backedge",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; spawn_batch(2) |_| { insert(r.id, b); b = { ServerComp { x: 1.0 } }; ClientComp { x: 2.0 } }; } }"#,
        ),
        (
            "pos_query_on_target_side_effect_in_block",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; insert(r.id, { let _q = query_one(t2: &Target).on(if true { b = { ServerComp { x: 1.0 } }; r.id } else { r.id }); b }); } }"#,
        ),
        (
            "pos_insert_entity_side_effect_in_block",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; insert(r.id, { insert({ b = { ServerComp { x: 1.0 } }; r.id }, { ClientComp { x: 2.0 } }); b }); } }"#,
        ),
        (
            "pos_unary_ref_nested_bundle",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let br = &{ let b = { ServerComp { x: 1.0 } }; b }; insert(r.id, br); } }"#,
        ),
    ];
    for (name, decls, body) in side_effect_positives {
        let count = assert_probe(name, decls, body, true);
        assert_eq!(count, 1, "expected exactly 1 E0501 in {name}");
    }

    let side_effect_negatives = [
        (
            "neg_tuple_later_elem_mutation_does_not_affect_earlier_elem",
            "",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let (d, _) = (b, { b = { ServerComp { x: 1.0 } }; 1 }); insert(r.id, d); } }"#,
        ),
        (
            "neg_spawn_batch_preamble_shadow_isolated",
            "",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let b = { ClientComp { x: 2.0 } }; spawn_batch(1) |_| { let b = { ServerComp { x: 1.0 } }; ClientComp { x: 2.0 } }; insert(r.id, b); } }"#,
        ),
    ];
    for (name, decls, body) in side_effect_negatives {
        assert_probe(name, decls, body, false);
    }

    // 4. Option A: `fn() -> Option<ServerComp>` & Tuple return shape summary + companion hardening.
    let option_positives = [
        (
            "pos_make_srv_fn_unwrap",
            "fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, wrap_opt().unwrap()); } }"#,
        ),
        (
            "pos_fn_opt_if_let_some",
            "fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { if let Some(c) = wrap_opt() { insert(r.id, c); } } }"#,
        ),
        (
            "pos_fn_opt_match",
            "fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { match wrap_opt() { Some(c) => { insert(r.id, c); } _ => {} } } }"#,
        ),
        (
            "pos_fn_opt_let_else",
            "fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let Some(c) = wrap_opt() else { return; }; insert(r.id, c); } }"#,
        ),
        (
            "pos_fn_opt_transitive_chain",
            r#"
fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }
fn wrap2() -> Option<ServerComp> { wrap_opt() }
fn h(e: Entity) { insert(e, wrap2().unwrap()); }
"#,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { h(r.id); } }"#,
        ),
        (
            "pos_fn_opt_param_helper",
            r#"
fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }
fn take_opt(e: Entity, opt: Option<ServerComp>) { insert(e, opt.unwrap()); }
"#,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { take_opt(r.id, wrap_opt()); } }"#,
        ),
        (
            "pos_fn_tuple_return_server_elem",
            "fn make_pair() -> (ServerComp, ClientComp) { (ServerComp { x: 1.0 }, ClientComp { x: 2.0 }) }",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let (s, _) = make_pair(); insert(r.id, s); } }"#,
        ),
        (
            "pos_fn_opt_unwrap_field_mutation",
            "fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }",
            r#"@authority(client) sys cheat() { let mut c = wrap_opt().unwrap(); c.x = 2.0; }"#,
        ),
        (
            "pos_fn_opt_if_let_field_mutation",
            "fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }",
            r#"@authority(client) sys cheat() { if let Some(mut c) = wrap_opt() { c.x = 2.0; } }"#,
        ),
        (
            "pos_fn_opt_unwrap_ref_mut",
            "fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }",
            r#"@authority(client) sys cheat() { let mut c = wrap_opt().unwrap(); let _p = &mut c; }"#,
        ),
    ];
    for (name, decls, body) in option_positives {
        let count = assert_probe(name, decls, body, true);
        assert_eq!(count, 1, "expected exactly 1 E0501 in {name}");
    }

    let option_negatives = [
        (
            "neg_fn_opt_client_unwrap",
            "fn wrap_cli() -> Option<ClientComp> { Some(ClientComp { x: 2.0 }) }",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let mut c = wrap_cli().unwrap(); c.x = 2.0; insert(r.id, c); } }"#,
        ),
        (
            "neg_fn_tuple_return_client_elem",
            "fn make_pair() -> (ServerComp, ClientComp) { (ServerComp { x: 1.0 }, ClientComp { x: 2.0 }) }",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let (_, c) = make_pair(); insert(r.id, c); } }"#,
        ),
        (
            "neg_fn_opt_server_sys_allowed",
            "fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }",
            r#"@authority(server) sys ok() { for r in query(t: &Target) { insert(r.id, wrap_opt().unwrap()); } }"#,
        ),
    ];
    for (name, decls, body) in option_negatives {
        assert_probe(name, decls, body, false);
    }

    // 5. Qualified `BundleLit` / `Spawn` paths & `@soa`.
    let qualified_positives = [
        (
            "pos_qualified_bundle_lit_server",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, { test::pos_qualified_bundle_lit_server::ServerComp { x: 1.0 } }); } }"#,
        ),
        (
            "pos_soa_qualified_bundle_lit_server",
            r#"
@soa
@authority(server)
component ServerSoa {
    hot { x: f32 = 0.0 }
    cold stats { id_tag: u32 = 0 }
}
"#,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, { test::pos_soa_qualified_bundle_lit_server::ServerSoa::stats { id_tag: 1 } }); } }"#,
        ),
        (
            "pos_qualified_spawn_server",
            "",
            r#"@authority(client) sys cheat() { spawn { test::pos_qualified_spawn_server::ServerComp { x: 1.0 } }; }"#,
        ),
    ];
    for (name, decls, body) in qualified_positives {
        let count = assert_probe(name, decls, body, true);
        assert_eq!(count, 1, "expected exactly 1 E0501 in {name}");
    }

    // 6. Diverging branch isolation (`If`, `Match`, `Atomic`, `Race`, `Block`, `QueryScope`, `fn`).
    let diverging_negatives = [
        (
            "neg_if_diverging_return_isolation",
            "",
            r#"@authority(client) sys ok(flag: bool) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; if flag { b = { ServerComp { x: 1.0 } }; return; } insert(r.id, b); } }"#,
        ),
        (
            "neg_diverging_match_arm_return_isolation",
            "",
            r#"@authority(client) sys ok(flag: bool) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; match flag { true => { b = { ServerComp { x: 1.0 } }; return; } false => {} } insert(r.id, b); } }"#,
        ),
        (
            "neg_nested_if_both_return_isolation",
            "",
            r#"@authority(client) sys ok(flag: bool, flag2: bool) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; if flag { if flag2 { b = { ServerComp { x: 1.0 } }; return; } else { return; } } insert(r.id, b); } }"#,
        ),
        (
            "neg_atomic_diverging_body_return_isolation",
            "",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; atomic { b = { ServerComp { x: 1.0 } }; return; } on_rollback {} insert(r.id, b); } }"#,
        ),
        (
            "neg_race_diverging_branch_return_isolation",
            "",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; race { branch { b = { ServerComp { x: 1.0 } }; return; } branch {} } insert(r.id, b); } }"#,
        ),
        (
            "neg_block_tail_diverging_if_isolation",
            "",
            r#"@authority(client) sys ok(flag: bool) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; insert(r.id, if flag { b = { ServerComp { x: 1.0 } }; return; } else { { ClientComp { x: 2.0 } } }); } }"#,
        ),
        (
            "neg_query_scope_if_diverging_return_isolation",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } r.h.hp = 0.0; }"#,
        ),
        (
            "neg_fn_if_diverging_return_isolation",
            "",
            r#"fn helper(e: Entity, flag: bool) { let mut b = { ClientComp { x: 2.0 } }; if flag { b = { ServerComp { x: 1.0 } }; return; } insert(e, b); } @authority(client) sys ok(flag: bool) { for r in query(t: &Target) { helper(r.id, flag); } }"#,
        ),
        (
            "neg_diverging_loop_without_break_isolation",
            "",
            r#"@authority(client) sys ok(flag: bool) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; if flag { loop { b = { ServerComp { x: 1.0 } }; return; } } insert(r.id, b); } }"#,
        ),
    ];
    for (name, decls, body) in diverging_negatives {
        assert_probe(name, decls, body, false);
    }

    let diverging_positives = [
        (
            "pos_if_diverging_branch_insert_before_return",
            "",
            r#"@authority(client) sys cheat(flag: bool) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; if flag { b = { ServerComp { x: 1.0 } }; insert(r.id, b); return; } } }"#,
        ),
        (
            "pos_if_one_diverges_other_assigns_server",
            "",
            r#"@authority(client) sys cheat(flag: bool) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; if flag { return; } else { b = { ServerComp { x: 1.0 } }; } insert(r.id, b); } }"#,
        ),
        (
            "pos_unreachable_after_return_direct_res_mut_caught",
            "",
            r#"@authority(client) sys cheat() { return; res_mut<ServerBank>().gold += 1; }"#,
        ),
        (
            "pos_match_diverging_arm_does_not_hide_live_server_arm",
            "",
            r#"@authority(client) sys cheat(flag: bool) { for r in query(t: &Target) { insert(r.id, match flag { true => { return; } false => { { ServerComp { x: 1.0 } } } }); } }"#,
        ),
    ];
    for (name, decls, body) in diverging_positives {
        let count = assert_probe(name, decls, body, true);
        assert_eq!(count, 1, "expected exactly 1 E0501 in {name}");
    }
}

#[test]
fn m1_r3_regression_callable_params_option_arrays_and_query_precision() {
    fn assert_probe(name: &str, extra_decls: &str, body: &str, expect_e0501: bool) -> usize {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

@authority(server)
component ServerComp {{ x: f32 = 1.0, cd: Cooldown = 50.0_ms }}

@authority(server)
component Health {{ hp: f32 = 100.0, cd: Cooldown = 50.0_ms }}

@authority(client)
component ClientHealth {{ hp: f32 = 50.0, cd: Cooldown = 50.0_ms }}

@authority(client)
component ClientComp {{ x: f32 = 2.0, cd: Cooldown = 50.0_ms }}

component Target {{ id: u32 = 0 }}

{extra_decls}

{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            !res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0002_PARSE_ERROR),
            "unexpected parse errors in {name}: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
        e0501.len()
    }

    // 1. Callable (`sys` / `@predicted`) parameter seeding (`Option<ServerComp>`, tuples, arrays) + negative controls.
    let callable_param_positives = [
        (
            "pos_sys_param_option_server_unwrap",
            "",
            r#"@authority(client) sys cheat(opt: Option<ServerComp>) { for r in query(t: &Target) { insert(r.id, opt.unwrap()); } }"#,
        ),
        (
            "pos_sys_param_opt_if_let_insert",
            "",
            r#"@authority(client) sys cheat(opt: Option<ServerComp>) { for r in query(t: &Target) { if let Some(c) = opt { insert(r.id, c); } } }"#,
        ),
        (
            "pos_sys_param_opt_match_insert",
            "",
            r#"@authority(client) sys cheat(opt: Option<ServerComp>) { for r in query(t: &Target) { match opt { Some(c) => { insert(r.id, c); } _ => {} } } }"#,
        ),
        (
            "pos_sys_param_opt_let_else_insert",
            "",
            r#"@authority(client) sys cheat(opt: Option<ServerComp>) { for r in query(t: &Target) { let Some(c) = opt else { return; }; insert(r.id, c); } }"#,
        ),
        (
            "pos_sys_param_opt_unwrap_field_mut",
            "",
            r#"@authority(client) sys cheat(opt: Option<ServerComp>) { let mut c = opt.unwrap(); c.x = 2.0; }"#,
        ),
        (
            "pos_sys_param_tuple_opt_unwrap",
            "",
            r#"@authority(client) sys cheat(p: (Option<ServerComp>, ClientComp)) { for r in query(t: &Target) { let (o, _) = p; insert(r.id, o.unwrap()); } }"#,
        ),
        (
            "pos_predicted_sys_param_opt_unwrap",
            "",
            r#"@predicted sys cheat(opt: Option<ServerComp>) { for r in query(t: &Target) { insert(r.id, opt.unwrap()); } }"#,
        ),
        (
            "pos_sys_param_array_opt_unwrap",
            "",
            r#"@authority(client) sys cheat(arr: [Option<ServerComp>; 1]) { for r in query(t: &Target) { insert(r.id, arr[0].unwrap()); } }"#,
        ),
    ];
    for (name, decls, body) in callable_param_positives {
        let count = assert_probe(name, decls, body, true);
        assert_eq!(count, 1, "expected exactly 1 E0501 in {name}");
    }

    let callable_param_negatives = [
        (
            "neg_sys_param_opt_client_unwrap",
            "",
            r#"@authority(client) sys ok(opt: Option<ClientComp>) { for r in query(t: &Target) { let mut c = opt.unwrap(); c.x = 2.0; insert(r.id, c); } }"#,
        ),
        (
            "neg_sys_param_tuple_client_elem_only",
            "",
            r#"@authority(client) sys ok(p: (Option<ServerComp>, ClientComp)) { for r in query(t: &Target) { let (_, mut c) = p; c.x = 2.0; insert(r.id, c); } }"#,
        ),
        (
            "neg_sys_param_array_opt_client_unwrap",
            "",
            r#"@authority(client) sys ok(arr: [Option<ClientComp>; 1]) { for r in query(t: &Target) { insert(r.id, arr[0].unwrap()); } }"#,
        ),
    ];
    for (name, decls, body) in callable_param_negatives {
        assert_probe(name, decls, body, false);
    }

    // 2. `.expect(...)` and `.unwrap_or(...)` on `Option` and queries.
    let opt_helper_decls = r#"
fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }
fn wrap_client() -> Option<ClientComp> { Some(ClientComp { x: 2.0 }) }
"#;
    let expect_unwrap_or_positives = [
        (
            "pos_wrap_opt_unwrap_or_server",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, wrap_opt().unwrap_or(ServerComp { x: 1.0 })); } }"#,
        ),
        (
            "pos_wrap_opt_unwrap_or_client_fallback",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, wrap_opt().unwrap_or(ClientComp { x: 2.0 })); } }"#,
        ),
        (
            "pos_wrap_client_unwrap_or_server_fallback",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, wrap_client().unwrap_or(ServerComp { x: 1.0 })); } }"#,
        ),
        (
            "pos_none_unwrap_or_server_fallback",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, None.unwrap_or(ServerComp { x: 1.0 })); } }"#,
        ),
        (
            "pos_wrap_opt_expect",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, wrap_opt().expect("boom")); } }"#,
        ),
        (
            "pos_wrap_opt_expect_field_mut",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { let mut c = wrap_opt().expect("boom"); c.x = 2.0; }"#,
        ),
        (
            "pos_wrap_opt_unwrap_or_field_mut",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { let mut c = wrap_opt().unwrap_or(ClientComp { x: 2.0 }); c.x = 2.0; }"#,
        ),
        (
            "pos_wrap_opt_expect_ref_mut",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { let _p = &mut wrap_opt().expect("boom"); }"#,
        ),
        (
            "pos_wrap_opt_unwrap_or_ref_mut",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { let _p = &mut wrap_opt().unwrap_or(ClientComp { x: 2.0 }); }"#,
        ),
        (
            "pos_wrap_opt_expect_arg_side_effect",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let _c = wrap_client().expect({ b = { ServerComp { x: 1.0 } }; "boom" }); insert(r.id, b); } }"#,
        ),
        (
            "pos_wrap_opt_unwrap_or_recv_side_effect_into_fallback",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; insert(r.id, { b = { ServerComp { x: 1.0 } }; wrap_client() }.unwrap_or(b)); } }"#,
        ),
        (
            "pos_query_one_expect_ro_mutate",
            "",
            r#"@authority(client) sys cheat() { let mut r = query_one(h: &Health).expect("missing"); r.h.hp = 0.0; }"#,
        ),
    ];
    for (name, decls, body) in expect_unwrap_or_positives {
        let count = assert_probe(name, decls, body, true);
        assert_eq!(count, 1, "expected exactly 1 E0501 in {name}");
    }

    let expect_unwrap_or_negatives = [
        (
            "neg_wrap_client_expect",
            opt_helper_decls,
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let mut c = wrap_client().expect("ok"); c.x = 2.0; insert(r.id, c); } }"#,
        ),
        (
            "neg_wrap_client_unwrap_or_client",
            opt_helper_decls,
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let mut c = wrap_client().unwrap_or(ClientComp { x: 2.0 }); c.x = 2.0; insert(r.id, c); } }"#,
        ),
    ];
    for (name, decls, body) in expect_unwrap_or_negatives {
        assert_probe(name, decls, body, false);
    }

    // 3. `ArrayLit` & `Index` handling.
    let array_positives = [
        (
            "pos_array_lit_opt_index_unwrap",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, [wrap_opt()][0].unwrap()); } }"#,
        ),
        (
            "pos_let_array_opt_index_unwrap",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let arr = [wrap_opt()]; insert(r.id, arr[0].unwrap()); } }"#,
        ),
        (
            "pos_array_lit_bundle_index",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, [{ ServerComp { x: 1.0 } }][0]); } }"#,
        ),
        (
            "pos_let_array_bundle_index",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let arr = [{ ServerComp { x: 1.0 } }]; insert(r.id, arr[0]); } }"#,
        ),
        (
            "pos_nested_array_opt_index_unwrap",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let arr = [[wrap_opt()]]; insert(r.id, arr[0][0].unwrap()); } }"#,
        ),
        (
            "pos_array_elem_side_effect_mutates_later_elem",
            "",
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; let arr = [{ b = { ServerComp { x: 1.0 } }; { ClientComp { x: 2.0 } } }, b]; insert(r.id, arr[1]); } }"#,
        ),
        (
            "pos_array_index_assign_server_opt",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut arr = [wrap_client()]; arr[0] = wrap_opt(); insert(r.id, arr[0].unwrap()); } }"#,
        ),
        (
            "pos_array_lit_opt_index_unwrap_ref_mut",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { let _p = &mut [wrap_opt()][0].unwrap(); }"#,
        ),
    ];
    for (name, decls, body) in array_positives {
        let count = assert_probe(name, decls, body, true);
        assert_eq!(count, 1, "expected exactly 1 E0501 in {name}");
    }

    let array_negatives = [
        (
            "neg_array_lit_client_opt_index_unwrap",
            opt_helper_decls,
            r#"@authority(client) sys ok() { for r in query(t: &Target) { insert(r.id, [wrap_client()][0].unwrap()); } }"#,
        ),
        (
            "neg_let_array_client_opt_index_unwrap",
            opt_helper_decls,
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let arr = [wrap_client()]; insert(r.id, arr[0].unwrap()); } }"#,
        ),
        (
            "neg_let_array_client_bundle_index",
            "",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let arr = [{ ClientComp { x: 2.0 } }]; insert(r.id, arr[0]); } }"#,
        ),
        (
            "neg_array_of_tuples_client_elem_only",
            "",
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let arr = [(ServerComp { x: 1.0 }, ClientComp { x: 2.0 })]; let (_, c) = arr[0]; insert(r.id, c); } }"#,
        ),
    ];
    for (name, decls, body) in array_negatives {
        assert_probe(name, decls, body, false);
    }

    // 4. Precision probes (false-positive elimination after diverging branches & irrefutable binding guards).
    let precision_negatives = [
        (
            "neg_p1_a_ref_mut_query_row_field",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } let _p = &mut r.h; }"#,
        ),
        (
            "neg_c1_hp_ref_mut_nested_query_row_field",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } let _p = &mut r.h.hp; }"#,
        ),
        (
            "neg_c1_method_arm_on_query_row_subfield",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } r.h.cd.arm(10.0_ms); }"#,
        ),
        (
            "neg_p1_k_query_row_field_alias_mutate",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } let mut h_ref = r.h; h_ref.hp = 0.0; }"#,
        ),
        (
            "neg_p1_k_query_row_field_alias_ref_mut_and_arm",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } let mut h_ref = r.h; let _p = &mut h_ref.hp; h_ref.cd.arm(10.0_ms); }"#,
        ),
        (
            "neg_p1_k_query_row_field_alias_insert",
            "",
            r#"@authority(client) sys ok(flag: bool) { for t in query(t: &Target) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } let h_ref = r.h; insert(t.id, h_ref); } }"#,
        ),
        (
            "neg_p4_e_match_binding_guard_diverges_cuts_off_arms",
            "",
            r#"@authority(client) sys ok(x: i32) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; match x { v if { return; } => {} _ => { b = { ServerComp { x: 1.0 } }; } } insert(r.id, b); } }"#,
        ),
        (
            "neg_p4_e_match_binding_guard_diverges_in_fn",
            "",
            r#"fn helper(e: Entity, x: i32) { let mut b = { ClientComp { x: 2.0 } }; match x { v if { return; } => {} _ => { b = { ServerComp { x: 1.0 } }; } } insert(e, b); } @authority(client) sys ok(x: i32) { for r in query(t: &Target) { helper(r.id, x); } }"#,
        ),
    ];
    for (name, decls, body) in precision_negatives {
        assert_probe(name, decls, body, false);
    }

    // 5. Soundness counterparts for precision probes (must still emit E0501!).
    let precision_soundness_positives = [
        (
            "pos_ro_query_row_field_ref_mut",
            "",
            r#"@authority(client) sys cheat() { for r_ro in query(h: &Health) { let _p = &mut r_ro.h; } }"#,
        ),
        (
            "pos_ro_query_row_subfield_ref_mut",
            "",
            r#"@authority(client) sys cheat() { for r_ro in query(h: &Health) { let _p = &mut r_ro.h.hp; } }"#,
        ),
        (
            "pos_ro_query_row_subfield_method_arm",
            "",
            r#"@authority(client) sys cheat() { for r_ro in query(h: &Health) { r_ro.h.cd.arm(10.0_ms); } }"#,
        ),
        (
            "pos_ro_query_row_field_alias_mutate",
            "",
            r#"@authority(client) sys cheat() { for r_ro in query(h: &Health) { let mut h_ro = r_ro.h; h_ro.hp = 0.0; } }"#,
        ),
        (
            "pos_ro_query_row_field_alias_ref_mut",
            "",
            r#"@authority(client) sys cheat() { for r_ro in query(h: &Health) { let mut h_ro = r_ro.h; let _p = &mut h_ro.hp; } }"#,
        ),
        (
            "pos_ro_query_row_field_alias_method_arm",
            "",
            r#"@authority(client) sys cheat() { for r_ro in query(h: &Health) { let mut h_ro = r_ro.h; h_ro.cd.arm(10.0_ms); } }"#,
        ),
        (
            "pos_live_branch_query_row_field_alias_mutate",
            "",
            r#"@authority(client) sys cheat(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); } let mut h_ref = r.h; h_ref.hp = 0.0; }"#,
        ),
        (
            "pos_match_binding_failed_guard_falls_through",
            "",
            r#"@authority(client) sys cheat(x: i32) { for r in query(t: &Target) { let mut b = { ClientComp { x: 2.0 } }; match x { v if { b = { ServerComp { x: 1.0 } }; false } => { b = { ClientComp { x: 2.0 } }; } _ => {} } insert(r.id, b); } }"#,
        ),
    ];
    for (name, decls, body) in precision_soundness_positives {
        let count = assert_probe(name, decls, body, true);
        assert_eq!(count, 1, "expected exactly 1 E0501 in {name}");
    }
}

#[test]
fn m1_r4_regression_iter4_consolidated_fixes_and_negative_controls() {
    fn assert_probe(name: &str, extra_decls: &str, body: &str, expect_e0501: bool) -> usize {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

@authority(server)
component ServerComp {{ x: f32 = 1.0, cd: Cooldown = 50.0_ms }}

@authority(server)
component Health {{ hp: f32 = 100.0, cd: Cooldown = 50.0_ms }}

@authority(client)
component ClientHealth {{ hp: f32 = 50.0, cd: Cooldown = 50.0_ms }}

@authority(client)
component ClientComp {{ x: f32 = 2.0, cd: Cooldown = 50.0_ms }}

component Target {{ id: u32 = 0 }}

{extra_decls}

{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            !res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0002_PARSE_ERROR),
            "unexpected parse errors in {name}: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
        e0501.len()
    }

    let opt_helper_decls = r#"
fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }
fn wrap_client() -> Option<ClientComp> { Some(ClientComp { x: 2.0 }) }
"#;

    let struct_decls = r#"
fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }
fn wrap_client() -> Option<ClientComp> { Some(ClientComp { x: 2.0 }) }
struct Holder { arr: [Option<ServerComp>; 1] }
struct OptBox { o: Option<ServerComp>, x: f32 }
struct ClientHolder { arr: [Option<ClientComp>; 1] }
struct ClientOptBox { o: Option<ClientComp>, x: f32 }
"#;

    // 1. Multi-dimensional `HirLValue::Index` assignments (`arr[0][0] = ...`) + `QueryShape::Row` through `Index` / block-lvalue.
    let single_write_positives = [
        // m1_r3_challenger_2 #1 (b03, w3_01, w3_02, w3_03) & m1_r3_reviewer_1 #1 (p_2d_assign)
        (
            "pos_b03_array_nested_index_assign",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut arr = [[wrap_client()]]; arr[0][0] = wrap_opt(); insert(r.id, arr[0][0].unwrap()); } }"#,
        ),
        (
            "pos_w3_01_nested_arr_assign_in_fn",
            opt_helper_decls,
            r#"fn helper(e: Entity) { let mut arr = [[wrap_client()]]; arr[0][0] = wrap_opt(); insert(e, arr[0][0].unwrap()); } @authority(client) sys cheat() { for r in query(t: &Target) { helper(r.id); } }"#,
        ),
        (
            "pos_w3_02_nested_arr_none_assign",
            opt_helper_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut arr = [[None]]; arr[0][0] = wrap_opt(); insert(r.id, arr[0][0].unwrap()); } }"#,
        ),
        (
            "pos_w3_03_nested_arr_query_row_assign_then_let",
            "",
            r#"@authority(client) sys cheat() { let mut arr = [[query_one(h: &ClientHealth).unwrap()]]; arr[0][0] = query_one(h: &Health).unwrap(); let r = arr[0][0]; r.h.hp = 0.0; }"#,
        ),
        (
            "pos_nested_arr_query_term_assign_then_mut",
            "",
            r#"@authority(client) sys cheat() { for r_ro in query(h: &Health) { let mut arr = [[ClientHealth { hp: 50.0, cd: 50.0_ms }]]; arr[0][0] = r_ro.h; arr[0][0].hp = 0.0; } }"#,
        ),
        (
            "pos_nested_arr_client_query_term_assign_server_then_mut",
            "",
            r#"@authority(client) sys cheat() { for r_ro in query(h: &Health) { let r_cl = query_one(h: &ClientHealth).unwrap(); let mut arr = [[r_cl.h]]; arr[0][0] = r_ro.h; arr[0][0].hp = 0.0; } }"#,
        ),
        // m1_r3_challenger_2 #2 (b10, w3_04, w4_04, w4_05) & m1_r3_challenger_1 #1
        (
            "pos_b10_array_of_query_rows_field_mut",
            "",
            r#"@authority(client) sys cheat() { let mut arr = [query_one(h: &Health).unwrap()]; arr[0].h.hp = 0.0; }"#,
        ),
        (
            "pos_arr_qrow_ro_mut_bad",
            "",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let mut arr = [r]; arr[0].h.hp = 0.0; } }"#,
        ),
        (
            "pos_arr_qrow_ro_mut_in_fn_bad",
            "",
            r#"fn helper_mut() { for r in query(h: &Health) { let mut arr = [r]; arr[0].h.hp = 0.0; } } @authority(client) sys cheat() { helper_mut(); }"#,
        ),
        (
            "pos_w3_04_arr_query_row_assign_then_direct_field",
            "",
            r#"@authority(client) sys cheat() { let mut arr = [query_one(h: &ClientHealth).unwrap()]; arr[0] = query_one(h: &Health).unwrap(); arr[0].h.hp = 0.0; }"#,
        ),
        (
            "pos_w4_04_arr_nested_query_row_field_mut_direct",
            "",
            r#"@authority(client) sys cheat() { let mut arr = [[query_one(h: &Health).unwrap()]]; arr[0][0].h.hp = 0.0; }"#,
        ),
        (
            "pos_w4_05_arr_query_row_alias_via_block_field_mut",
            "",
            r#"@authority(client) sys cheat() { let mut arr = [query_one(h: &Health).unwrap()]; { arr[0] }.h.hp = 0.0; }"#,
        ),
        // m1_r3_challenger_2 #3 (w3_18, w3_19, w4_01)
        (
            "pos_w3_18_sys_param_ref_mut_arr_server_empty_body",
            "",
            r#"@authority(client) sys cheat(arr: &mut [ServerComp; 1]) {}"#,
        ),
        (
            "pos_w3_19_sys_param_ref_mut_opt_server_empty_body",
            "",
            r#"@authority(client) sys cheat(opt: &mut Option<ServerComp>) {}"#,
        ),
        (
            "pos_w4_01_sys_param_ref_mut_tuple_server_empty_body",
            "",
            r#"@authority(client) sys cheat(p: &mut (ServerComp, ClientComp)) {}"#,
        ),
        // m1_r3_challenger_2 #4 (w3_22, w4_03) + struct param/fn/field-assign variants
        (
            "pos_w3_22_struct_field_holding_arr_opt",
            struct_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let h = Holder { arr: [wrap_opt()] }; insert(r.id, h.arr[0].unwrap()); } }"#,
        ),
        (
            "pos_w4_03_struct_field_opt_server",
            struct_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let bx = OptBox { o: wrap_opt(), x: 1.0 }; insert(r.id, bx.o.unwrap()); } }"#,
        ),
        (
            "pos_struct_param_field_arr_opt_unwrap",
            struct_decls,
            r#"@authority(client) sys cheat(h: Holder) { for r in query(t: &Target) { insert(r.id, h.arr[0].unwrap()); } }"#,
        ),
        (
            "pos_struct_field_assign_opt_then_insert",
            struct_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut bx = OptBox { o: None, x: 1.0 }; bx.o = wrap_opt(); insert(r.id, bx.o.unwrap()); } }"#,
        ),
        (
            "pos_struct_field_arr_assign_opt_then_insert",
            struct_decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { let mut h = Holder { arr: [None] }; h.arr[0] = wrap_opt(); insert(r.id, h.arr[0].unwrap()); } }"#,
        ),
        (
            "pos_struct_field_opt_unwrap_field_mut",
            struct_decls,
            r#"@authority(client) sys cheat() { let mut bx = OptBox { o: wrap_opt(), x: 1.0 }; bx.o.unwrap().x = 2.0; }"#,
        ),
        // m1_r3_reviewer_2 #3 (intra-expression QueryScope mutation visibility)
        (
            "pos_intra_expr_unwrap_or_query_scope_mut",
            "",
            r#"@authority(client) sys cheat() { for t in query(t: &Target) { let mut r = query_one(h: &ClientHealth).unwrap(); insert(t.id, { r = query_one(h: &Health).unwrap(); None }.unwrap_or(r.h)); } }"#,
        ),
        (
            "pos_opt_qterm_unwrap_or_server_fallback_ref_mut",
            "",
            r#"@authority(client) sys cheat() { let r = query_one(h: &ClientHealth).unwrap(); let mut opt = Some(r.h); let _p = &mut opt.unwrap_or(Health { hp: 100.0, cd: 50.0_ms }); }"#,
        ),
    ];
    for (name, decls, body) in single_write_positives {
        let count = assert_probe(name, decls, body, true);
        assert_eq!(count, 1, "expected exactly 1 E0501 in {name}");
    }

    // 2. Precision & negative controls (must emit 0 E0501 and 0 E0002).
    let precision_and_negative_controls = [
        // m1_r3_challenger_1 #2 (arr_qterm_*_diverging_ok)
        (
            "neg_arr_qterm_diverging_ok",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } let mut arr = [r.h]; arr[0].hp = 0.0; }"#,
        ),
        (
            "neg_arr_qterm_refmut_diverging_ok",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } let mut arr = [r.h]; let _p = &mut arr[0]; }"#,
        ),
        (
            "neg_arr_qterm_hp_refmut_diverging_ok",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } let mut arr = [r.h]; let _p = &mut arr[0].hp; }"#,
        ),
        (
            "neg_arr_qterm_arm_diverging_ok",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } let mut arr = [r.h]; arr[0].cd.arm(10.0_ms); }"#,
        ),
        // m1_r3_reviewer_1 #2 (p_some_rh_unwrap, p_arr_rh_index)
        (
            "neg_p_some_rh_unwrap",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } let opt = Some(r.h); let _p = &mut opt.unwrap().hp; }"#,
        ),
        (
            "neg_p_arr_rh_index",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } let arr = [r.h]; let _p = &mut arr[0].hp; }"#,
        ),
        // m1_r3_reviewer_2 #2 (3 scenarios)
        (
            "neg_r2_client_health_to_diverging_r_server",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut h_ref = ClientHealth { hp: 50.0, cd: 50.0_ms }; if flag { let r = query_one(h: &Health).unwrap(); h_ref = r.h; return; } h_ref.hp = 0.0; let _p = &mut h_ref; h_ref.cd.arm(10.0_ms); }"#,
        ),
        (
            "neg_r2_qterm_reassigned_to_client_health",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } let mut h_ref = r.h; h_ref = ClientHealth { hp: 50.0, cd: 50.0_ms }; h_ref.hp = 0.0; let _p = &mut h_ref; h_ref.cd.arm(10.0_ms); }"#,
        ),
        (
            "neg_r2_arr_client_health_diverging_health",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut arr = [ClientHealth { hp: 50.0, cd: 50.0_ms }]; if flag { arr = [Health { hp: 100.0, cd: 50.0_ms }]; return; } arr[0].hp = 0.0; let _p = &mut arr[0]; arr[0].cd.arm(10.0_ms); }"#,
        ),
        // Negative controls for #3 and #4
        (
            "neg_sys_param_ref_mut_client_arr",
            "",
            r#"@authority(client) sys ok(arr: &mut [ClientComp; 1]) { arr[0].x = 3.0; }"#,
        ),
        (
            "neg_struct_holder_client_only",
            struct_decls,
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let h = ClientHolder { arr: [wrap_client()] }; let bx = ClientOptBox { o: wrap_client(), x: 1.0 }; insert(r.id, h.arr[0].unwrap()); insert(r.id, bx.o.unwrap()); } }"#,
        ),
        (
            "neg_struct_holder_server_field_unrelated_mut",
            struct_decls,
            r#"@authority(client) sys ok() { let mut bx = OptBox { o: wrap_opt(), x: 1.0 }; bx.x = 2.0; }"#,
        ),
        (
            "neg_struct_opt_none_unwrap",
            struct_decls,
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let bx = OptBox { o: None, x: 1.0 }; insert(r.id, bx.o.unwrap()); } }"#,
        ),
    ];
    for (name, decls, body) in precision_and_negative_controls {
        assert_probe(name, decls, body, false);
    }
}

#[test]
fn m1_r5_regression_iter5_block_lvalue_slot_reassignment_deep_structs_and_for_iter() {
    fn assert_probe(name: &str, extra_decls: &str, body: &str, expect_e0501: bool) -> usize {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

@authority(server)
component ServerComp {{ x: f32 = 1.0, cd: Cooldown = 50.0_ms }}

@authority(server)
component Health {{ hp: f32 = 100.0, cd: Cooldown = 50.0_ms }}

@authority(client)
component ClientHealth {{ hp: f32 = 50.0, cd: Cooldown = 50.0_ms }}

@authority(client)
component ClientComp {{ x: f32 = 2.0, cd: Cooldown = 50.0_ms }}

@authority(server)
resource ServerBank {{ gold: i32 = 0 }}

component Target {{ id: u32 = 0 }}

{extra_decls}

{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            !res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0002_PARSE_ERROR),
            "unexpected parse errors in {name}: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
        e0501.len()
    }

    let decls = r#"
fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }
fn wrap_health() -> Option<Health> { Some(Health { hp: 100.0 }) }
fn wrap_client_health() -> Option<ClientHealth> { Some(ClientHealth { hp: 50.0 }) }
fn wrap_client() -> Option<ClientComp> { Some(ClientComp { x: 2.0 }) }
struct Holder { o: Option<Health> }
struct OptBox { o: Option<ServerComp>, x: f32 }
struct SBox { s: ServerComp, x: f32 }
struct ArrHolder { arr: [ServerComp; 1] }
struct NestedHolder { arr: [Option<ServerComp>; 1], arr2: [[Option<ServerComp>; 1]; 1] }
struct OuterOpt { inner: Option<OptBox> }
struct OuterTup { inner: (OptBox, i32) }
struct OuterBox { inner: OptBox }
struct ClientOptBox { o: Option<ClientComp>, x: f32 }
struct ClientSBox { s: ClientComp, x: f32 }
@authority(server) component BadComp { o: Option<ServerComp> }
fn make_sbox() -> SBox { SBox { s: ServerComp { x: 1.0 }, x: 1.0 } }
fn make_empty_box() -> OptBox { OptBox { o: None, x: 1.0 } }
fn make_none() -> Option<ServerComp> { None }
fn fail_none() -> Option<ServerComp> { return None; }
fn rec_none(n: i32) -> Option<ServerComp> { if n == 0 { None } else { rec_none(n - 1) } }
fn rec_srv(n: i32) -> Option<ServerComp> { if n == 0 { wrap_opt() } else { rec_srv(n - 1) } }
fn mutual_a(n: i32) -> Option<ServerComp> { if n == 0 { wrap_opt() } else { mutual_b(n - 1) } }
fn mutual_b(n: i32) -> Option<ServerComp> { if n == 0 { None } else { mutual_a(n - 1) } }
fn mixed_ret(flag: bool) -> Option<ServerComp> { if flag { return None; } Some(ServerComp { x: 1.0 }) }
fn touch_sbox(h: &mut SBox) {}
fn touch_optbox(h: &mut OptBox) {}
fn tweak_holder(h: &mut Holder) { h.o = None; }
"#;

    // 1. Single-write positives (must emit E0501 with dedup_count == 1).
    let single_write_positives = [
        // Explorer 1: Block/Expr lvalue preservation
        (
            "pos_blws1_n33_block_lvalue_with_let_qrow",
            "",
            r#"@authority(client) sys cheat() { let mut arr = [query_one(h: &Health).unwrap()]; { let x = arr[0]; x }.h.hp = 0.0; }"#,
        ),
        (
            "pos_block_lvalue_res_mut_side_effect_client_tail",
            "",
            r#"@authority(client) sys cheat() { let mut client_local = ClientComp { x: 1.0 }; { res_mut<ServerBank>().gold = 1; client_local }.x = 2.0; }"#,
        ),
        (
            "pos_block_lvalue_optbox_field_unwrap_mut",
            decls,
            r#"@authority(client) sys cheat() { { let x = OptBox { o: wrap_opt(), x: 1.0 }; x }.o.unwrap().x = 2.0; }"#,
        ),
        // Explorer 2: Interior field writes & &mut param writes + recursive/mixed fn return shapes
        (
            "pos_local_server_comp_field_mut",
            "",
            r#"@authority(client) sys cheat() { let mut s = ServerComp { x: 1.0 }; s.x = 2.0; }"#,
        ),
        (
            "pos_sbox_server_field_mut",
            decls,
            r#"@authority(client) sys cheat() { let mut sb = SBox { s: ServerComp { x: 1.0 }, x: 1.0 }; sb.s.x = 2.0; }"#,
        ),
        (
            "pos_arr_server_elem_field_mut",
            "",
            r#"@authority(client) sys cheat() { let mut arr = [ServerComp { x: 1.0 }]; arr[0].x = 2.0; }"#,
        ),
        (
            "pos_optbox_unwrap_field_mut",
            decls,
            r#"@authority(client) sys cheat() { let mut bx = OptBox { o: wrap_opt(), x: 1.0 }; bx.o.unwrap().x = 2.0; }"#,
        ),
        (
            "pos_param_mut_holder_field_none",
            decls,
            r#"@authority(client) sys cheat(h: &mut Holder) { h.o = None; }"#,
        ),
        (
            "pos_fn_rec_server_opt_insert",
            decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, rec_srv(2).unwrap()); } }"#,
        ),
        (
            "pos_fn_mutual_rec_server_opt_insert",
            decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { insert(r.id, mutual_a(2).unwrap()); } }"#,
        ),
        (
            "pos_fn_mixed_ret_server_opt_insert",
            decls,
            r#"@authority(client) sys cheat(flag: bool) { for r in query(t: &Target) { insert(r.id, mixed_ret(flag).unwrap()); } }"#,
        ),
        // Explorer 3 Defect 1: Deep struct flattening
        (
            "pos_n17_ref_mut_sbox",
            decls,
            r#"@authority(client) sys cheat() { let mut sb = SBox { s: ServerComp { x: 1.0 }, x: 1.0 }; let _p = &mut sb; }"#,
        ),
        (
            "pos_n18_sys_param_ref_mut_optbox",
            decls,
            r#"@authority(client) sys cheat(h: &mut OptBox) {}"#,
        ),
        (
            "pos_n19_sys_param_ref_mut_sbox",
            decls,
            r#"@authority(client) sys cheat(h: &mut SBox) {}"#,
        ),
        (
            "pos_n20_sys_param_ref_mut_nested_holder",
            decls,
            r#"@authority(client) sys cheat(h: &mut NestedHolder) {}"#,
        ),
        (
            "pos_n21_sys_param_ref_mut_arr_optbox",
            decls,
            r#"@authority(client) sys cheat(arr: &mut [OptBox; 1]) {}"#,
        ),
        (
            "pos_w6_10_ref_mut_make_sbox",
            decls,
            r#"@authority(client) sys cheat() { let _p = &mut make_sbox(); }"#,
        ),
        (
            "pos_w6_20_sys_param_ref_mut_outer_opt",
            decls,
            r#"@authority(client) sys cheat(o: &mut OuterOpt) {}"#,
        ),
        (
            "pos_w6_21_sys_param_ref_mut_outer_tup",
            decls,
            r#"@authority(client) sys cheat(o: &mut OuterTup) {}"#,
        ),
        (
            "pos_outer_box_inner_ref_mut",
            decls,
            r#"@authority(client) sys cheat() { let mut outer = OuterBox { inner: OptBox { o: wrap_opt(), x: 1.0 } }; let _p = &mut outer.inner; }"#,
        ),
        (
            "pos_p6_sys_param_ref_mut_holder",
            decls,
            r#"@authority(client) sys cheat(h: &mut Holder) {}"#,
        ),
        (
            "pos_p7_sys_param_ref_mut_holder_reassign",
            decls,
            r#"@authority(client) sys cheat(h: &mut Holder) { h = Holder { o: None }; }"#,
        ),
        (
            "pos_p8_local_holder_ref_mut",
            decls,
            r#"@authority(client) sys cheat() { let mut h = Holder { o: wrap_health() }; let _p = &mut h; }"#,
        ),
        (
            "pos_p11_sys_param_ref_mut_arr_holder",
            decls,
            r#"@authority(client) sys cheat(h: &mut ArrHolder) {}"#,
        ),
        (
            "pos_p12_sys_param_ref_mut_bad_comp",
            decls,
            r#"@authority(client) sys cheat(b: &mut BadComp) {}"#,
        ),
        (
            "pos_p17_fn_tweak_holder_none_called_from_client",
            decls,
            r#"@authority(client) sys cheat() { let mut h = Holder { o: None }; tweak_holder(&mut h); }"#,
        ),
        // Explorer 3 Defect 2: HirForIter::Expr & HirExpr::Path empty-shape fallback
        (
            "pos_n29_for_iter_expr_query_row_mut",
            "",
            r#"@authority(client) sys cheat() { for row in [query_one(h: &Health).unwrap()] { row.h.hp = 0.0; } }"#,
        ),
        (
            "pos_n30_for_iter_expr_query_row_cd_arm",
            "",
            r#"@authority(client) sys cheat() { for row in [query_one(h: &Health).unwrap()] { row.h.cd.arm(10.0_ms); } }"#,
        ),
        (
            "pos_n31_for_iter_expr_query_row_ref_mut",
            "",
            r#"@authority(client) sys cheat() { for row in [query_one(h: &Health).unwrap()] { let _p = &mut row.h; } }"#,
        ),
        (
            "pos_n32_for_iter_expr_opt_insert_shadowed",
            decls,
            r#"@authority(client) sys cheat() { for opt in [wrap_opt()] { for t in query(t: &Target) { let mut c = ClientComp { x: 2.0 }; if true { c = opt.unwrap(); } insert(t.id, c); } } }"#,
        ),
        (
            "pos_n35_for_iter_expr_opt_arr_nested",
            decls,
            r#"@authority(client) sys cheat() { for sub in [[wrap_opt()]] { let mut arr = sub; let _p = &mut arr[0]; } }"#,
        ),
        (
            "pos_w6_03_for_iter_expr_optbox_shadowed_insert",
            decls,
            r#"@authority(client) sys cheat() { for bx in [OptBox { o: wrap_opt(), x: 1.0 }] { for t in query(t: &Target) { let mut c = ClientComp { x: 2.0 }; if true { c = bx.o.unwrap(); } insert(t.id, c); } } }"#,
        ),
        (
            "pos_w6_04_for_iter_expr_optbox_mut_unwrap",
            decls,
            r#"@authority(client) sys cheat() { for bx in [OptBox { o: wrap_opt(), x: 1.0 }] { let mut c = ClientComp { x: 2.0 }; if true { c = bx.o.unwrap(); } c.x = 3.0; } }"#,
        ),
        (
            "pos_w6_05_for_iter_expr_local_arr_query_row",
            "",
            r#"@authority(client) sys cheat() { let arr = [query_one(h: &Health).unwrap()]; for row in arr { row.h.hp = 0.0; } }"#,
        ),
        (
            "pos_w6_06_for_iter_expr_tuple_query_row",
            "",
            r#"@authority(client) sys cheat() { for (row, _) in [(query_one(h: &Health).unwrap(), 1)] { row.h.hp = 0.0; } }"#,
        ),
        (
            "pos_w6_07_for_iter_expr_opt_unwrap_direct",
            decls,
            r#"@authority(client) sys cheat() { for opt in [wrap_opt()] { for t in query(t: &Target) { insert(t.id, opt.unwrap()); } } }"#,
        ),
        (
            "pos_w7_01_for_iter_expr_optbox_direct_insert",
            decls,
            r#"@authority(client) sys cheat() { for bx in [OptBox { o: wrap_opt(), x: 1.0 }] { for t in query(t: &Target) { insert(t.id, bx.o.unwrap()); } } }"#,
        ),
        (
            "pos_p1_for_insert_server_comp",
            "",
            r#"@authority(client) sys cheat() { for r_t in query(t: &Target) { for h_srv in [Health { hp: 100.0, cd: 50.0_ms }] { insert(r_t.id, h_srv); } } }"#,
        ),
        (
            "pos_p2_for_unwrap_or_h_srv",
            "",
            r#"@authority(client) sys cheat() { for h_srv in [Health { hp: 100.0, cd: 50.0_ms }] { let r = query_one(h: &ClientHealth).unwrap(); let opt = Some(r.h); let mut x = opt.unwrap_or(h_srv); x.hp = 0.0; } }"#,
        ),
        (
            "pos_p3_for_if_h_srv",
            "",
            r#"@authority(client) sys cheat(flag: bool) { for h_srv in [Health { hp: 100.0, cd: 50.0_ms }] { let r = query_one(h: &ClientHealth).unwrap(); let mut x = if flag { r.h } else { h_srv }; x.hp = 0.0; } }"#,
        ),
        (
            "pos_p10_for_opt_unwrap_insert",
            decls,
            r#"@authority(client) sys cheat() { for r in query(t: &Target) { for opt in [wrap_opt()] { insert(r.id, opt.unwrap()); } } }"#,
        ),
        // Explorer 3 Defect 3: QueryShape::Term + unwrap_or(res<Health>())
        (
            "pos_p4_qterm_unwrap_or_res_ref_mut",
            "",
            r#"@authority(client) sys cheat() { let r = query_one(h: &ClientHealth).unwrap(); let opt = Some(r.h); let _p = &mut opt.unwrap_or(res<Health>()); }"#,
        ),
        (
            "pos_p5_qterm_unwrap_or_res_cd_arm",
            "",
            r#"@authority(client) sys cheat() { let r = query_one(h: &ClientHealth).unwrap(); let opt = Some(r.h); opt.unwrap_or(res<Health>()).cd.arm(10.0_ms); }"#,
        ),
        (
            "pos_p15_qterm_unwrap_or_res_mut_field",
            "",
            r#"@authority(client) sys cheat() { let r = query_one(h: &ClientHealth).unwrap(); let opt = Some(r.h); let _p = &mut opt.unwrap_or(res<Health>()).hp; }"#,
        ),
        // Explorer 3 Defect 4: Assign index side-effects ordering
        (
            "pos_p9_arr_index_side_effect_assign",
            "",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let mut arr = [ClientHealth { hp: 50.0, cd: 50.0_ms }]; arr[{ arr[0] = r.h; 0 }].hp = 0.0; } }"#,
        ),
    ];
    for (name, extra, body) in single_write_positives {
        let count = assert_probe(name, extra, body, true);
        assert_eq!(count, 1, "expected exactly 1 E0501 in {name}");
    }

    // Multi-diagnostic positives (`touch(&mut sb)` / `touch(&mut bx)` fire both fn call + &mut arg).
    let multi_write_positives = [
        (
            "pos_n23_fn_ref_mut_sbox_called_from_client",
            decls,
            r#"@authority(client) sys cheat() { let mut sb = SBox { s: ServerComp { x: 1.0 }, x: 1.0 }; touch_sbox(&mut sb); }"#,
        ),
        (
            "pos_n24_fn_ref_mut_optbox_called_from_client",
            decls,
            r#"@authority(client) sys cheat() { let mut bx = OptBox { o: wrap_opt(), x: 1.0 }; touch_optbox(&mut bx); }"#,
        ),
    ];
    for (name, extra, body) in multi_write_positives {
        let count = assert_probe(name, extra, body, true);
        assert!(count >= 1, "expected >= 1 E0501 in {name}");
    }

    // 2. Precision & negative controls (must emit 0 E0501 and 0 E0002).
    let precision_controls = [
        (
            "neg_bsqd1_block_stmt_qrow_diverging_ok",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } { let x = r; x }.h.hp = 0.0; }"#,
        ),
        (
            "neg_hrc1_holder_reassign_client_then_insert",
            decls,
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let mut h = Holder { o: wrap_health() }; h.o = wrap_client_health(); insert(r.id, h.o.unwrap()); } }"#,
        ),
        (
            "neg_hrn1_holder_reassign_none_then_insert",
            decls,
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let mut h = Holder { o: wrap_health() }; h.o = None; insert(r.id, h.o.unwrap()); } }"#,
        ),
        (
            "neg_owowc1_optbox_wrap_opt_then_wrap_client",
            decls,
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let mut h = OptBox { o: wrap_opt(), x: 1.0 }; h.o = wrap_client(); insert(r.id, h.o.unwrap()); } }"#,
        ),
        (
            "neg_adv13_optbox_field_reassign_none_then_insert",
            decls,
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let mut bx = OptBox { o: wrap_opt(), x: 1.0 }; bx.o = None; insert(r.id, bx.o.unwrap()); } }"#,
        ),
        (
            "neg_arr_opt_server_reassign_none_ok",
            decls,
            r#"@authority(client) sys ok() { let mut arr = [wrap_opt()]; arr[0] = None; }"#,
        ),
        (
            "neg_sbox_field_server_reassign_server_ok",
            decls,
            r#"@authority(client) sys ok() { let mut sb = SBox { s: ServerComp { x: 1.0 }, x: 1.0 }; sb.s = ServerComp { x: 2.0 }; }"#,
        ),
        (
            "neg_arr_server_elem_reassign_server_ok",
            "",
            r#"@authority(client) sys ok() { let mut arr = [ServerComp { x: 1.0 }]; arr[0] = ServerComp { x: 2.0 }; }"#,
        ),
        (
            "neg_sfrh2_fn_make_empty_box_unwrap_insert_ok",
            decls,
            r#"@authority(client) sys ok() { for r in query(t: &Target) { let bx = make_empty_box(); insert(r.id, bx.o.unwrap()); } }"#,
        ),
        (
            "neg_fmn1_fn_make_none_unwrap_insert_ok",
            decls,
            r#"@authority(client) sys ok() { for r in query(t: &Target) { insert(r.id, make_none().unwrap()); } }"#,
        ),
        (
            "neg_fn_return_none_diverging_ok",
            decls,
            r#"@authority(client) sys ok() { for r in query(t: &Target) { insert(r.id, fail_none().unwrap()); } }"#,
        ),
        (
            "neg_fn_rec_none_unwrap_insert_ok",
            decls,
            r#"@authority(client) sys ok() { for r in query(t: &Target) { insert(r.id, rec_none(2).unwrap()); } }"#,
        ),
        (
            "neg_ref_mut_optbox_unrelated_field_x",
            decls,
            r#"@authority(client) sys ok() { let mut bx = OptBox { o: wrap_opt(), x: 1.0 }; let _p = &mut bx.x; bx.x = 2.0; }"#,
        ),
        (
            "neg_ref_mut_make_sbox_unrelated_field_x",
            decls,
            r#"@authority(client) sys ok() { let _p = &mut make_sbox().x; }"#,
        ),
        (
            "neg_block_lvalue_optbox_unrelated_field_x",
            decls,
            r#"@authority(client) sys ok() { { let x = OptBox { o: wrap_opt(), x: 1.0 }; x }.x = 2.0; }"#,
        ),
        (
            "neg_param_ref_mut_client_optbox_ok",
            decls,
            r#"@authority(client) sys ok(h: &mut ClientOptBox) { h.x = 2.0; }"#,
        ),
        (
            "neg_param_by_value_optbox_ok",
            decls,
            r#"@authority(client) sys ok(bx: OptBox) { let mut bx2 = bx; bx2.x = 2.0; }"#,
        ),
        (
            "neg_for_iter_expr_client_query_row_ok",
            "",
            r#"@authority(client) sys ok() { for row in [query_one(h: &ClientHealth).unwrap()] { row.h.hp = 0.0; } }"#,
        ),
        (
            "neg_assign_diverging_index_skips_unreachable_write",
            "",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let mut arr = [ClientHealth { hp: 50.0, cd: 50.0_ms }]; arr[{ arr[0] = r.h; return; }].hp = 0.0; } }"#,
        ),
    ];
    for (name, extra, body) in precision_controls {
        assert_probe(name, extra, body, false);
    }
}

#[test]
fn m1_r6_regression_iter6_qterm_container_lvalue_and_tuple_struct_checks() {
    fn assert_probe(name: &str, extra_decls: &str, body: &str, expect_e0501: bool) -> usize {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

@authority(server)
component ServerComp {{ x: f32 = 1.0, cd: Cooldown = 50.0_ms }}

@authority(server)
component Health {{ hp: f32 = 100.0, cd: Cooldown = 50.0_ms }}

@authority(client)
component ClientHealth {{ hp: f32 = 50.0, cd: Cooldown = 50.0_ms }}

@authority(client)
component ClientComp {{ x: f32 = 2.0, cd: Cooldown = 50.0_ms }}

@authority(server)
resource ServerBank {{ gold: i32 = 0 }}

component Target {{ id: u32 = 0 }}

{extra_decls}

{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            !res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0002_PARSE_ERROR),
            "unexpected parse errors in {name}: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
        e0501.len()
    }

    let decls = r#"
fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }
struct OptBox { o: Option<ServerComp>, x: f32 }
struct SBox { s: ServerComp, x: f32 }
struct BankBox { b: ServerBank, x: f32 }
struct BoxH { h: Health }
fn sneak_unwrap_or() {
    let r = query_one(h: &ClientHealth).unwrap();
    let opt = Some(r.h);
    opt.unwrap_or(res<Health>()).hp = 0.0;
}
fn sneak_if(flag: bool) {
    let r = query_one(h: &ClientHealth).unwrap();
    (if flag { r.h } else { res<Health>() }).hp = 0.0;
}
fn sneak_match(flag: bool) {
    let r = query_one(h: &ClientHealth).unwrap();
    (match flag { true => r.h, false => res<Health>() }).hp = 0.0;
}
"#;

    let positives = [
        // Issue 1: lvalue_root_server_target_inner QueryShape::Term fallthrough
        (
            "pos_r6_qterm_unwrap_or_res_assign",
            "",
            r#"@authority(client) sys cheat() { let r = query_one(h: &ClientHealth).unwrap(); let opt = Some(r.h); opt.unwrap_or(res<Health>()).hp = 0.0; }"#,
        ),
        (
            "pos_r6_qterm_if_mixed_res_assign",
            "",
            r#"@authority(client) sys cheat(flag: bool) { let r = query_one(h: &ClientHealth).unwrap(); (if flag { r.h } else { res<Health>() }).hp = 0.0; }"#,
        ),
        (
            "pos_r6_qterm_match_mixed_res_assign",
            "",
            r#"@authority(client) sys cheat(flag: bool) { let r = query_one(h: &ClientHealth).unwrap(); (match flag { true => r.h, false => res<Health>() }).hp = 0.0; }"#,
        ),
        (
            "pos_r6_qterm_helper_sneak_unwrap_or",
            decls,
            r#"@authority(client) sys cheat() { sneak_unwrap_or(); }"#,
        ),
        (
            "pos_r6_qterm_helper_sneak_if",
            decls,
            r#"@authority(client) sys cheat(flag: bool) { sneak_if(flag); }"#,
        ),
        (
            "pos_r6_qterm_helper_sneak_match",
            decls,
            r#"@authority(client) sys cheat(flag: bool) { sneak_match(flag); }"#,
        ),
        // Issue 2: interior mutations on block/array containers still caught under SelfOnly
        (
            "pos_r6_block_arr_elem_field_mut",
            "",
            r#"@authority(client) sys cheat() { { let mut arr = [ServerComp { x: 1.0 }]; arr }[0].x = 2.0; }"#,
        ),
        (
            "pos_r6_block_struct_field_mut",
            "",
            r#"@authority(client) sys cheat() { { let mut s = ServerComp { x: 1.0 }; s }.x = 2.0; }"#,
        ),
        (
            "pos_r6_nested_arr_lit_res_field_mut",
            "",
            r#"@authority(client) sys cheat() { [[res<Health>()]][0][0].hp = 0.0; }"#,
        ),
        (
            "pos_r6_arr_lit_unwrap_or_res_field_mut",
            "",
            r#"@authority(client) sys cheat() { let r = query_one(h: &ClientHealth).unwrap(); let opt = Some(r.h); [opt.unwrap_or(res<Health>())][0].hp = 0.0; }"#,
        ),
        // Issue 3: ArrayLitExpr / StructLitExpr / RecordLitExpr lvalue bases
        (
            "pos_r6_arr_lit_qrow_index_mut",
            "",
            r#"@authority(client) sys cheat() { [query_one(h: &Health).unwrap()][0].h.hp = 0.0; }"#,
        ),
        (
            "pos_r6_arr_lit_server_comp_index_mut",
            "",
            r#"@authority(client) sys cheat() { [ServerComp { x: 1.0 }][0].x = 2.0; }"#,
        ),
        (
            "pos_r6_arr_lit_optbox_index_unwrap_mut",
            decls,
            r#"@authority(client) sys cheat() { [OptBox { o: wrap_opt(), x: 1.0 }][0].o.unwrap().x = 2.0; }"#,
        ),
        (
            "pos_r6_arr_lit_res_index_mut",
            "",
            r#"@authority(client) sys cheat() { [res<Health>()][0].hp = 0.0; }"#,
        ),
        (
            "pos_r6_arr_lit_res_mut_side_effect_index_mut",
            "",
            r#"@authority(client) sys cheat() { [{ res_mut<ServerBank>().gold = 1; ClientComp { x: 1.0 } }][0].x = 2.0; }"#,
        ),
        (
            "pos_r6_struct_lit_sbox_s_x_mut",
            decls,
            r#"@authority(client) sys cheat() { (SBox { s: ServerComp { x: 1.0 }, x: 1.0 }).s.x = 2.0; }"#,
        ),
        (
            "pos_r6_struct_lit_optbox_unwrap_x_mut",
            decls,
            r#"@authority(client) sys cheat() { (OptBox { o: wrap_opt(), x: 1.0 }).o.unwrap().x = 2.0; }"#,
        ),
        (
            "pos_r6_struct_lit_res_mut_side_effect_mut",
            decls,
            r#"@authority(client) sys cheat() { (SBox { s: { res_mut<ServerBank>().gold = 1; ServerComp { x: 1.0 } }, x: 1.0 }).x = 2.0; }"#,
        ),
        (
            "pos_r6_spawn_preamble_arr_lit_mut",
            "",
            r#"@authority(client) sys cheat() { spawn(ClientComp { x: 1.0 }) where { [ServerComp { x: 1.0 }][0].x = 2.0; }; }"#,
        ),
        (
            "pos_r6_if_let_cond_arr_lit_mut",
            "",
            r#"@authority(client) sys cheat() { if let Some(_) = { [ServerComp { x: 1.0 }][0].x = 2.0; Some(1) } {} }"#,
        ),
        (
            "pos_r6_record_lit_server_field_mut",
            "",
            r#"@authority(client) sys cheat() { ({ s: ServerComp { x: 1.0 }, x: 1.0 }).s.x = 2.0; }"#,
        ),
        // Issue 4: expr_root_server_target_inner Tuple / StructLit / RecordLit recursion
        (
            "pos_r6_refmut_tuple_res_serverbank",
            "",
            r#"@authority(client) sys cheat() { let _p = &mut (res<ServerBank>(), 1); }"#,
        ),
        (
            "pos_r6_refmut_structlit_res_serverbank",
            decls,
            r#"@authority(client) sys cheat() { let _p = &mut BankBox { b: res<ServerBank>(), x: 1.0 }; }"#,
        ),
        (
            "pos_r6_refmut_structlit_unwrap_or_res",
            decls,
            r#"@authority(client) sys cheat() { let r = query_one(h: &ClientHealth).unwrap(); let opt = Some(r.h); let _p = &mut BoxH { h: opt.unwrap_or(res<Health>()) }; }"#,
        ),
        (
            "pos_r6_refmut_tuple_unwrap_or_res",
            "",
            r#"@authority(client) sys cheat() { let r = query_one(h: &ClientHealth).unwrap(); let opt = Some(r.h); let _p = &mut (opt.unwrap_or(res<Health>()), 1); }"#,
        ),
        (
            "pos_r6_refmut_tuple_if_rcli_res",
            "",
            r#"@authority(client) sys cheat(flag: bool) { let r = query_one(h: &ClientHealth).unwrap(); let _p = &mut (if flag { r.h } else { res<Health>() }, 1); }"#,
        ),
        (
            "pos_r6_refmut_tuple_qrow",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let _p = &mut (r_srv, 1); }"#,
        ),
        (
            "pos_r6_refmut_local_tuple_qrow",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let tup = (r_srv, 1); let _p = &mut tup; }"#,
        ),
        (
            "pos_r6_refmut_nested_tuple_struct_res",
            decls,
            r#"@authority(client) sys cheat() { let _p = &mut (BankBox { b: res<ServerBank>(), x: 1.0 }, 1); }"#,
        ),
        (
            "pos_r6_refmut_some_tuple_res",
            "",
            r#"@authority(client) sys cheat() { let _p = &mut Some((res<ServerBank>(), 1)); }"#,
        ),
        (
            "pos_r6_refmut_recordlit_res_serverbank",
            "",
            r#"@authority(client) sys cheat() { let _p = &mut { b: res<ServerBank>(), x: 1.0 }; }"#,
        ),
    ];
    for (name, extra, body) in positives {
        let count = assert_probe(name, extra, body, true);
        assert!(count >= 1, "expected >= 1 E0501 in {name}");
    }

    let precision_controls = [
        // Issue 1 precision controls
        (
            "neg_r6_p_some_rh_unwrap_assign",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } let opt = Some(r.h); opt.unwrap().hp = 0.0; }"#,
        ),
        (
            "neg_r6_p_arr_rh_index_assign",
            "",
            r#"@authority(client) sys ok(flag: bool) { let mut r = query_one(h: &ClientHealth).unwrap(); if flag { r = query_one(h: &Health).unwrap(); return; } let mut arr = [r.h]; arr[0].hp = 0.0; }"#,
        ),
        // Issue 2 precision controls: slot reassignments on Block/ArrayLit containers
        (
            "neg_r6_block_arr_opt_slot_reassign_none",
            decls,
            r#"@authority(client) sys ok() { { let mut arr = [wrap_opt()]; arr }[0] = None; }"#,
        ),
        (
            "neg_r6_block_arr_srv_slot_reassign_srv",
            "",
            r#"@authority(client) sys ok() { { let mut arr = [ServerComp { x: 1.0 }]; arr }[0] = ServerComp { x: 2.0 }; }"#,
        ),
        (
            "neg_r6_arr_lit_opt_slot_reassign_none",
            decls,
            r#"@authority(client) sys ok() { [wrap_opt()][0] = None; }"#,
        ),
        (
            "neg_r6_arr_lit_srv_slot_reassign_srv",
            "",
            r#"@authority(client) sys ok() { [ServerComp { x: 1.0 }][0] = ServerComp { x: 2.0 }; }"#,
        ),
        (
            "neg_r6_nested_block_arr_opt_slot_reassign_none",
            decls,
            r#"@authority(client) sys ok() { { let mut arr = [[wrap_opt()]]; arr }[0][0] = None; }"#,
        ),
        (
            "neg_r6_nested_arr_lit_opt_slot_reassign_none",
            decls,
            r#"@authority(client) sys ok() { [[wrap_opt()]][0][0] = None; }"#,
        ),
        // Issue 3 precision controls
        (
            "neg_r6_arr_lit_client_comp_index_mut",
            "",
            r#"@authority(client) sys ok() { [ClientComp { x: 1.0 }][0].x = 2.0; }"#,
        ),
        (
            "neg_r6_struct_lit_optbox_unrelated_field_mut",
            decls,
            r#"@authority(client) sys ok() { (OptBox { o: wrap_opt(), x: 1.0 }).x = 2.0; }"#,
        ),
        (
            "neg_r6_struct_lit_optbox_slot_none",
            decls,
            r#"@authority(client) sys ok() { (OptBox { o: wrap_opt(), x: 1.0 }).o = None; }"#,
        ),
        (
            "neg_r6_record_lit_opt_unrelated_field_mut",
            decls,
            r#"@authority(client) sys ok() { ({ o: wrap_opt(), x: 1.0 }).x = 2.0; }"#,
        ),
        // Issue 4 precision controls
        (
            "neg_r6_refmut_tuple_client_comp",
            "",
            r#"@authority(client) sys ok() { let _p = &mut (ClientComp { x: 1.0 }, 1); }"#,
        ),
        (
            "neg_r6_refmut_bankbox_unrelated_field_x",
            decls,
            r#"@authority(client) sys ok() { let _p = &mut BankBox { b: res<ServerBank>(), x: 1.0 }.x; }"#,
        ),
        (
            "neg_r6_refmut_optbox_unrelated_field_x",
            decls,
            r#"@authority(client) sys ok() { let _p = &mut OptBox { o: wrap_opt(), x: 1.0 }.x; }"#,
        ),
        (
            "neg_r6_refmut_tuple_client_qrow",
            "",
            r#"@authority(client) sys ok() { let r_cli = query_one(h: &ClientHealth).unwrap(); let _p = &mut (r_cli, 1); }"#,
        ),
        (
            "neg_r6_refmut_qrow_entity_id",
            "",
            r#"@authority(client) sys ok() { let r_srv = query_one(h: &Health).unwrap(); let _p = &mut r_srv.id; let _p2 = &mut (r_srv.id, 1); }"#,
        ),
    ];
    for (name, extra, body) in precision_controls {
        assert_probe(name, extra, body, false);
    }
}

#[test]
fn m1_r7_regression_iter7_query_struct_prefix_cast_and_block_args() {
    fn assert_probe(name: &str, extra_decls: &str, body: &str, expect_e0501: bool) {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

@authority(server)
component ServerComp {{ x: f32 = 1.0, cd: Cooldown = 50.0_ms }}

@authority(server)
component Health {{ hp: f32 = 100.0, cd: Cooldown = 50.0_ms }}

@authority(client)
component ClientHealth {{ hp: f32 = 50.0, cd: Cooldown = 50.0_ms }}

@authority(client)
component ClientComp {{ x: f32 = 2.0, cd: Cooldown = 50.0_ms }}

@authority(server)
resource ServerBank {{ gold: i32 = 0 }}

component Target {{ id: u32 = 0 }}

{extra_decls}

{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            !res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0002_PARSE_ERROR),
            "unexpected parse errors in {name}: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
    }

    let decls = r#"
fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }
struct OptBox { o: Option<ServerComp>, x: f32 }
struct SBox { s: ServerComp, x: f32 }
struct BankBox { b: ServerBank, x: f32 }
struct AnyBox { r: Entity, x: f32 }
fn sneak_prefix_refmut() {
    (&mut res<Health>()).hp = 0.0;
}
fn sneak_reclit_qrow() {
    let r_srv = query_one(h: &Health).unwrap();
    ({ row: r_srv, x: 1.0 }).row.h.hp = 0.0;
}
"#;

    let positives = [
        // Issue 1: QueryShape::Struct across RecordLit / StructLit
        (
            "pos_r7_reclit_qrow_field_hp",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); ({ row: r_srv, x: 1.0 }).row.h.hp = 0.0; }"#,
        ),
        (
            "pos_r7_reclit_qrow_refmut_row",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let _p = &mut ({ row: r_srv, x: 1.0 }).row; }"#,
        ),
        (
            "pos_r7_reclit_qrow_refmut_row_h",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let _p = &mut ({ row: r_srv, x: 1.0 }).row.h; }"#,
        ),
        (
            "pos_r7_reclit_qrow_let_box_hp",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let bx = { row: r_srv, x: 1.0 }; bx.row.h.hp = 0.0; }"#,
        ),
        (
            "pos_r7_reclit_qrow_let_box_refmut",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let bx = { row: r_srv, x: 1.0 }; let _p = &mut bx; }"#,
        ),
        (
            "pos_r7_reclit_qrow_let_box_row_refmut",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let bx = { row: r_srv, x: 1.0 }; let _p = &mut bx.row; }"#,
        ),
        (
            "pos_r7_reclit_qrow_cd_arm",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); ({ row: r_srv, x: 1.0 }).row.h.cd.arm(10.0_ms); }"#,
        ),
        (
            "pos_r7_reclit_tup_rsrv_refmut",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let _p = &mut { t: (r_srv, 1), x: 1.0 }.t; }"#,
        ),
        (
            "pos_r7_reclit_tup_rsrv_let_destruct",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let bx = { t: (r_srv, 1), x: 1.0 }; let (a, _) = bx.t; a.h.hp = 0.0; }"#,
        ),
        (
            "pos_r7_reclit_arr_rsrv_refmut_a",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let _p = &mut { a: [r_srv], x: 1.0 }.a; }"#,
        ),
        (
            "pos_r7_reclit_arr_rsrv_refmut_idx",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let _p = &mut { arr: [r_srv], x: 1.0 }.arr[0]; }"#,
        ),
        (
            "pos_r7_reclit_arr_rsrv_idx_hp",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); ({ arr: [r_srv], x: 1.0 }).arr[0].h.hp = 0.0; }"#,
        ),
        (
            "pos_r7_reclit_let_rsrv_refmut_a",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let bx = { a: r_srv, b: 2 }; let _p = &mut bx.a; }"#,
        ),
        (
            "pos_r7_for_reclit_rsrv_hp",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); for item in [{ row: r_srv, x: 1.0 }] { item.row.h.hp = 0.0; } }"#,
        ),
        (
            "pos_r7_for_tup_reclit_rsrv_hp",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); for (a, _) in [({ row: r_srv, x: 1.0 }, 1)] { a.row.h.hp = 0.0; } }"#,
        ),
        (
            "pos_r7_reclit_arr_tup_rsrv_destruct",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let bx = { arr: [(r_srv, 1)], x: 1.0 }; for (a, _) in bx.arr { a.h.hp = 0.0; } }"#,
        ),
        (
            "pos_r7_reclit_opt_rsrv_unwrap",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let bx = { opt: Some(r_srv), x: 1.0 }; bx.opt.unwrap().h.hp = 0.0; }"#,
        ),
        (
            "pos_r7_insert_reclit_rsrv_row_h",
            "",
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); let r_srv = query_one(h: &Health).unwrap(); let bx = { row: r_srv }; insert(t.id, bx.row.h); }"#,
        ),
        (
            "pos_r7_structlit_qrow_refmut",
            decls,
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let _p = &mut AnyBox { r: r_srv, x: 1.0 }.r; }"#,
        ),
        (
            "pos_r7_reclit_nested_reclit_qrow_hp",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); ({ outer: { row: r_srv, x: 1.0 }, y: 2.0 }).outer.row.h.hp = 0.0; }"#,
        ),
        (
            "pos_r7_reclit_qrow_if_match_predicted_fn",
            decls,
            r#"
@authority(client) sys cheat_if(flag: bool) { let r_srv = query_one(h: &Health).unwrap(); (if flag { { row: r_srv, x: 1.0 } } else { { row: r_srv, x: 2.0 } }).row.h.hp = 0.0; }
@authority(client) sys cheat_match(flag: bool) { let r_srv = query_one(h: &Health).unwrap(); (match flag { true => { row: r_srv, x: 1.0 }, false => { row: r_srv, x: 2.0 } }).row.h.hp = 0.0; }
@predicted sys cheat_pred() { let r_srv = query_one(h: &Health).unwrap(); ({ row: r_srv, x: 1.0 }).row.h.hp = 0.0; }
@authority(client) sys cheat_fn() { sneak_reclit_qrow(); }
"#,
        ),
        (
            "pos_r7_reclit_flow_field_set_rsrv",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let mut bx = { opt: None, x: 1.0 }; bx.opt = Some(r_srv); bx.opt.unwrap().h.hp = 0.0; }"#,
        ),
        (
            "pos_r7_reclit_flow_arr_field_set_rsrv",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let mut bx = { arr: [None], x: 1.0 }; bx.arr[0] = Some(r_srv); bx.arr[0].unwrap().h.hp = 0.0; }"#,
        ),
        // Issue 2: PrefixExpr and CastExpr lvalue bases
        (
            "pos_r7_prefix_refmut_res_hp",
            "",
            r#"@authority(client) sys cheat() { (&mut res<Health>()).hp = 0.0; }"#,
        ),
        (
            "pos_r7_prefix_refmut_srvcomp_x",
            "",
            r#"@authority(client) sys cheat() { (&mut ServerComp { x: 1.0 }).x = 2.0; }"#,
        ),
        (
            "pos_r7_prefix_refmut_let_srvcomp_x",
            "",
            r#"@authority(client) sys cheat() { let mut sc = ServerComp { x: 1.0 }; (&mut sc).x = 2.0; }"#,
        ),
        (
            "pos_r7_prefix_refmut_side_effect_x",
            "",
            r#"@authority(client) sys cheat() { (&mut { res_mut<ServerBank>().gold = 1; ClientComp { x: 1.0 } }).x = 2.0; }"#,
        ),
        (
            "pos_r7_prefix_ref_side_effect_x",
            "",
            r#"@authority(client) sys cheat() { (&{ res_mut<ServerBank>().gold = 1; ClientComp { x: 1.0 } }).x = 2.0; }"#,
        ),
        (
            "pos_r7_prefix_ref_srvcomp_x",
            "",
            r#"@authority(client) sys cheat() { (&ServerComp { x: 1.0 }).x = 2.0; }"#,
        ),
        (
            "pos_r7_prefix_refmut_rsrv_h_hp",
            "",
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); (&mut r_srv).h.hp = 0.0; }"#,
        ),
        (
            "pos_r7_prefix_idx_refmut_srvcomp",
            "",
            r#"@authority(client) sys cheat() { (&mut [ServerComp { x: 1.0 }])[0].x = 2.0; }"#,
        ),
        (
            "pos_r7_prefix_idx_refmut_side_effect",
            "",
            r#"@authority(client) sys cheat() { (&mut [{ res_mut<ServerBank>().gold = 1; ClientComp { x: 1.0 } }])[0].x = 2.0; }"#,
        ),
        (
            "pos_r7_fn_helper_prefix_refmut",
            decls,
            r#"@authority(client) sys cheat() { sneak_prefix_refmut(); }"#,
        ),
        (
            "pos_r7_cast_res_hp",
            "",
            r#"@authority(client) sys cheat() { (res<Health>() as Health).hp = 0.0; }"#,
        ),
        (
            "pos_r7_cast_side_effect_x",
            "",
            r#"@authority(client) sys cheat() { ({ res_mut<ServerBank>().gold = 1; ClientComp { x: 1.0 } } as ClientComp).x = 2.0; }"#,
        ),
        // Issue 3: HirExpr::Cast provenance
        (
            "pos_r7_cast_refmut_bankbox",
            decls,
            r#"@authority(client) sys cheat() { let _p = &mut (BankBox { b: res<ServerBank>(), x: 1.0 } as BankBox); }"#,
        ),
        (
            "pos_r7_cast_sbox_s_x",
            decls,
            r#"@authority(client) sys cheat() { (SBox { s: ServerComp { x: 1.0 }, x: 1.0 } as SBox).s.x = 2.0; }"#,
        ),
        (
            "pos_r7_cast_let_sbox_s_x",
            decls,
            r#"@authority(client) sys cheat() { let bx = SBox { s: ServerComp { x: 1.0 }, x: 1.0 }; (bx as SBox).s.x = 2.0; }"#,
        ),
        (
            "pos_r7_cast_optbox_unwrap_x",
            decls,
            r#"@authority(client) sys cheat() { (OptBox { o: wrap_opt(), x: 1.0 } as OptBox).o.unwrap().x = 2.0; }"#,
        ),
        (
            "pos_r7_cast_opt_unwrap_or_res_hp",
            "",
            r#"@authority(client) sys cheat() { let r = query_one(h: &ClientHealth).unwrap(); let opt = Some(r.h); (opt.unwrap_or(res<Health>()) as Health).hp = 0.0; }"#,
        ),
        // Issue 4: .where({ ... }) and .on({ ... }) Block arguments
        (
            "pos_r7_query_where_block_res_mut",
            "",
            r#"@authority(client) sys cheat() { for _r in query(h: &ClientHealth).where({ res_mut<ServerBank>().gold = 1; true }) {} }"#,
        ),
        (
            "pos_r7_query_where_block_let_res_mut",
            "",
            r#"@authority(client) sys cheat() { for _r in query(h: &ClientHealth).where({ let _a = 1; res_mut<ServerBank>().gold = 1; true }) {} }"#,
        ),
        (
            "pos_r7_query_on_block_res_mut",
            "",
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); let _r = query_one(h: &ClientHealth).on({ res_mut<ServerBank>().gold = 1; t.id }); }"#,
        ),
        (
            "pos_r7_query_on_block_let_res_mut",
            "",
            r#"@authority(client) sys cheat() { let _r = query_one(h: &ClientHealth).on({ let _a = 1; res_mut<ServerBank>().gold = 1; query_one(id: Entity).unwrap().id }).unwrap(); }"#,
        ),
    ];

    for (name, extra, body) in positives {
        assert_probe(name, extra, body, true);
    }

    let precision_controls = [
        // Issue 1 precision controls
        (
            "neg_r7_reclit_rsrv_unrelated_x",
            "",
            r#"@authority(client) sys ok() { let r_srv = query_one(h: &Health).unwrap(); ({ row: r_srv, x: 1.0 }).x = 2.0; }"#,
        ),
        (
            "neg_r7_reclit_rsrv_refmut_unrelated_x",
            "",
            r#"@authority(client) sys ok() { let r_srv = query_one(h: &Health).unwrap(); let _p = &mut { r: r_srv, x: 1.0 }.x; }"#,
        ),
        (
            "neg_r7_reclit_let_rsrv_refmut_unrelated_b",
            "",
            r#"@authority(client) sys ok() { let r_srv = query_one(h: &Health).unwrap(); let bx = { a: r_srv, b: 2 }; let _p = &mut bx.b; }"#,
        ),
        (
            "neg_r7_reclit_rsrv_id_refmut",
            "",
            r#"@authority(client) sys ok() { let r_srv = query_one(h: &Health).unwrap(); let _p1 = &mut r_srv.id; let _p2 = &mut ({ r: r_srv, x: 1.0 }).r.id; }"#,
        ),
        (
            "neg_r7_reclit_rcli_row_and_arr",
            "",
            r#"@authority(client) sys ok() { let r_cli = query_one(h: &ClientHealth).unwrap(); ({ row: r_cli, x: 1.0 }).row.h.hp = 0.0; ({ arr: [r_cli], x: 1.0 }).arr[0].h.hp = 0.0; }"#,
        ),
        (
            "neg_r7_reclit_flow_clear_opt_and_row",
            "",
            r#"@authority(client) sys ok() { let t = query_one(id: Entity).unwrap(); let r_srv = query_one(h: &Health).unwrap(); let r_cli = query_one(h: &ClientHealth).unwrap(); let mut bx = { opt: Some(r_srv), row: r_srv, x: 1.0 }; bx.opt = None; bx.row = r_cli; insert(t.id, bx.opt.unwrap()); bx.row.h.hp = 0.0; }"#,
        ),
        // Issue 2 precision controls
        (
            "neg_r7_prefix_refmut_clientcomp_x",
            "",
            r#"@authority(client) sys ok() { (&mut ClientComp { x: 1.0 }).x = 2.0; }"#,
        ),
        (
            "neg_r7_prefix_refmut_optbox_none_x",
            decls,
            r#"@authority(client) sys ok() { (&mut OptBox { o: None, x: 1.0 }).x = 2.0; }"#,
        ),
        (
            "neg_r7_prefix_refmut_rcli_h_hp",
            "",
            r#"@authority(client) sys ok() { let r_cli = query_one(h: &ClientHealth).unwrap(); (&mut r_cli).h.hp = 0.0; }"#,
        ),
        // Issue 3 precision controls
        (
            "neg_r7_cast_refmut_optbox_none",
            decls,
            r#"@authority(client) sys ok() { let _p = &mut (OptBox { o: None, x: 1.0 } as OptBox); }"#,
        ),
        (
            "neg_r7_cast_optbox_unrelated_x",
            decls,
            r#"@authority(client) sys ok() { (OptBox { o: wrap_opt(), x: 1.0 } as OptBox).x = 2.0; }"#,
        ),
        (
            "neg_r7_cast_bankbox_refmut_unrelated_x",
            decls,
            r#"@authority(client) sys ok() { let _p = &mut (BankBox { b: res<ServerBank>(), x: 1.0 } as BankBox).x; }"#,
        ),
        (
            "neg_r7_cast_rcli_h_hp",
            "",
            r#"@authority(client) sys ok() { let r_cli = query_one(h: &ClientHealth).unwrap(); (r_cli.h as ClientHealth).hp = 0.0; }"#,
        ),
        // Issue 4 precision controls
        (
            "neg_r7_query_where_and_on_clean_blocks",
            "",
            r#"@authority(client) sys ok() { let t = query_one(id: Entity).unwrap(); for _r in query(h: &ClientHealth).where({ let _a = 1; true }) {} let _one = query_one(h: &ClientHealth).on({ let _a = 1; t.id }); }"#,
        ),
    ];

    for (name, extra, body) in precision_controls {
        assert_probe(name, extra, body, false);
    }
}

#[test]
fn m1_r8_regression_iter8_query_field_reduce_lvalue_and_fn_defaults() {
    fn assert_probe(name: &str, extra_decls: &str, body: &str, expect_e0501: bool) {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

@authority(server)
component ServerComp {{ x: f32 = 1.0, cd: Cooldown = 50.0_ms }}

@authority(server)
component Health {{ hp: f32 = 100.0, cd: Cooldown = 50.0_ms }}

@authority(client)
component ClientComp {{ x: f32 = 1.0 }}

@authority(client)
component ClientHealth {{ hp: f32 = 50.0, cd: Cooldown = 50.0_ms }}

@authority(server)
resource ServerBank {{ gold: i32 = 100 }}

{extra_decls}
{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        let parse_errs: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0002_PARSE_ERROR)
            .collect();
        assert!(
            parse_errs.is_empty(),
            "unexpected E0002_PARSE_ERROR in {name}: {parse_errs:#?}\nall diagnostics: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
    }

    let decls = r#"
fn add(a: i32, b: i32) -> i32 { a + b }
fn sneak_void() { res_mut<ServerBank>().gold = 1; }
fn sneak_bool() -> bool { res_mut<ServerBank>().gold = 1; true }
fn sneak_i32() -> i32 { res_mut<ServerBank>().gold = 1; 0 }
fn sneak_def(x: i32 = { res_mut<ServerBank>().gold = 1; 1 }) -> i32 { x }
fn sneak_def_indirect(x: i32 = { sneak_void(); 1 }) -> i32 { x }
fn wrap_sneak_def() -> i32 { sneaky_caller() }
fn sneaky_caller() -> i32 { sneak_def() }
fn ok_def(x: i32 = 1) -> i32 { x }
fn wrap_opt() -> Option<ServerComp> { Some(ServerComp { x: 1.0 }) }
"#;

    let positives = [
        // Finding 1: Query FieldExpr lvalue bases must preserve .on(...) / .where(...)
        (
            "pos_r8_lv_qone_on_block_unwrap_h_hp",
            decls,
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); query_one(h: &ClientHealth).on({ res_mut<ServerBank>().gold = 1; t.id }).unwrap().h.hp = 0.0; }"#,
        ),
        (
            "pos_r8_lv_qone_where_block_unwrap_h_hp",
            decls,
            r#"@authority(client) sys cheat() { query_one(h: &ClientHealth).where({ res_mut<ServerBank>().gold = 1; true }).unwrap().h.hp = 0.0; }"#,
        ),
        (
            "pos_r8_lv_qone_where_direct_res_mut_unwrap_h_hp",
            decls,
            r#"@authority(client) sys cheat() { query_one(h: &ClientHealth).where(res_mut<ServerBank>().gold == 0).unwrap().h.hp = 0.0; }"#,
        ),
        (
            "pos_r8_lv_qone_on_direct_res_mut_h_hp",
            decls,
            r#"@authority(client) sys cheat() { query_one(h: &ClientHealth).on({ let _ = res_mut<ServerBank>().gold; query_one(id: Entity).unwrap().id }).h.hp = 0.0; }"#,
        ),
        (
            "pos_r8_lv_paren_qone_on_block_h_hp",
            decls,
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); (query_one(h: &ClientHealth).on({ res_mut<ServerBank>().gold = 1; t.id }).unwrap().h).hp = 0.0; }"#,
        ),
        (
            "pos_r8_some_qone_on_block_unwrap_h_hp",
            decls,
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); Some(query_one(h: &ClientHealth).on({ res_mut<ServerBank>().gold = 1; t.id }).unwrap().h).unwrap().hp = 0.0; }"#,
        ),
        (
            "pos_r8_lv_client_query_on_block_h_hp",
            decls,
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); client_query(h: &ClientHealth).on({ res_mut<ServerBank>().gold = 1; t.id }).unwrap().h.hp = 0.0; }"#,
        ),
        (
            "pos_r8_lv_field_qone_on_fn_helper",
            decls,
            r#"@authority(client) sys cheat() { query_one(h: &ClientHealth).where(sneak_bool()).unwrap().h.hp = 0.0; }"#,
        ),
        (
            "pos_r8_lv_field_qone_on_refmut_inside",
            decls,
            r#"@authority(client) sys cheat() { let mut sc = ServerComp { x: 1.0 }; query_one(h: &ClientHealth).where({ let _p = &mut sc; true }).unwrap().h.hp = 0.0; }"#,
        ),
        // Finding 2: lower_for_expr must preserve non-Call and general Call reduce(...) expressions
        (
            "pos_r8_reduce_block_raw",
            decls,
            r#"@authority(client) sys cheat() { let _s = for _i in 0..2 reduce(acc: { res_mut<ServerBank>().gold = 1; 0 }); }"#,
        ),
        (
            "pos_r8_reduce_block_add",
            decls,
            r#"@authority(client) sys cheat() { let _s = for _i in 0..2 reduce(acc: { res_mut<ServerBank>().gold = 1; add(0, 1) }); }"#,
        ),
        (
            "pos_r8_reduce_binary_add",
            decls,
            r#"@authority(client) sys cheat() { let _s = for _i in 0..2 reduce(acc: add(0, 1) + { res_mut<ServerBank>().gold = 1; 0 }); }"#,
        ),
        (
            "pos_r8_reduce_paren_block",
            decls,
            r#"@authority(client) sys cheat() { let _s = for _i in 0..2 reduce(acc: ({ res_mut<ServerBank>().gold = 1; 0 })); }"#,
        ),
        (
            "pos_r8_reduce_if_expr",
            decls,
            r#"@authority(client) sys cheat(flag: bool) { let _s = for _i in 0..2 reduce(acc: if flag { add(0, { res_mut<ServerBank>().gold = 1; 1 }) } else { add(0, 2) }); }"#,
        ),
        (
            "pos_r8_reduce_match_expr",
            decls,
            r#"@authority(client) sys cheat(flag: bool) { let _s = for _i in 0..2 reduce(acc: match flag { true => add(0, { res_mut<ServerBank>().gold = 1; 1 }), false => add(0, 2) }); }"#,
        ),
        (
            "pos_r8_reduce_fn_helper_inside_block",
            decls,
            r#"@authority(client) sys cheat() { let _s = for _i in 0..2 reduce(acc: { sneak_void(); add(0, 1) }); }"#,
        ),
        (
            "pos_r8_reduce_refmut_inside_block",
            decls,
            r#"@authority(client) sys cheat() { let mut sc = ServerComp { x: 1.0 }; let _s = for _i in 0..2 reduce(acc: { let _p = &mut sc; 0 }); }"#,
        ),
        (
            "pos_r8_reduce_zero_arg_fn_call",
            decls,
            r#"@authority(client) sys cheat() { let _s = for _i in 0..2 reduce(acc: sneak_i32()); }"#,
        ),
        (
            "pos_r8_reduce_extra_arg_and_receiver",
            decls,
            r#"@authority(client) sys cheat() { let _s1 = for _i in 0..2 reduce(acc: sum(0, 1, { res_mut<ServerBank>().gold = 1; 2 })); let _s2 = for _i in 0..2 reduce(acc: ({ res_mut<ServerBank>().gold = 1; 0 }).sum(0, 1)); }"#,
        ),
        // Finding 3: expr_to_lvalue_candidates must preserve If.cond, empty Match.scrutinee, Block without tail, For/Spawn/Insert/Binary
        (
            "pos_r8_if_no_else_cond_block_lvalue",
            decls,
            r#"@authority(client) sys cheat() { (if { res_mut<ServerBank>().gold = 1; true } { ClientComp { x: 1.0 } }).x = 2.0; }"#,
        ),
        (
            "pos_r8_if_no_else_cond_res_mut_and_fn_lvalue",
            decls,
            r#"@authority(client) sys cheat() { (if res_mut<ServerBank>().gold == 0 { ClientComp { x: 1.0 } }).x = 2.0; (if sneak_bool() { ClientComp { x: 1.0 } }).x = 2.0; }"#,
        ),
        (
            "pos_r8_match_empty_arms_scrutinee_lvalue",
            decls,
            r#"@authority(client) sys cheat() { (match { res_mut<ServerBank>().gold = 1; 1 } {}).x = 2.0; }"#,
        ),
        (
            "pos_r8_for_lvalue_field_assign",
            decls,
            r#"@authority(client) sys cheat() { (for _i in 0..1 { res_mut<ServerBank>().gold = 1; }).x = 2.0; }"#,
        ),
        (
            "pos_r8_for_reduce_spawn_insert_block_binary_lvalue",
            decls,
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); (for _i in 0..2 reduce(acc: { res_mut<ServerBank>().gold = 1; 0 })).x = 2.0; (spawn { ClientComp { x: { res_mut<ServerBank>().gold = 1; 1.0 } } }).x = 2.0; (insert(t.id, ClientComp { x: { res_mut<ServerBank>().gold = 1; 1.0 } })).x = 2.0; ({ res_mut<ServerBank>().gold = 1; }).x = 2.0; (1 + { res_mut<ServerBank>().gold = 1; 2 }).x = 2.0; }"#,
        ),
        // Finding 4: HirParam::default expressions in helper fn and sys/obs callables
        (
            "pos_r8_fn_param_default_omitted_arg",
            decls,
            r#"@authority(client) sys cheat() { let _v = sneak_def(); }"#,
        ),
        (
            "pos_r8_fn_param_default_explicit_arg",
            decls,
            r#"@authority(client) sys cheat() { let _v = sneak_def(1); }"#,
        ),
        (
            "pos_r8_fn_param_default_indirect_and_transitive",
            decls,
            r#"@authority(client) sys cheat() { let _a = sneak_def_indirect(); let _b = wrap_sneak_def(); }"#,
        ),
        // Precision/Soundness controls for QueryShape::Option and &mut container borrow (split individually)
        (
            "pos_r8_opt_term_soundness_c1_unwrap",
            decls,
            r#"@authority(client) sys c1() { let r_srv = query_one(h: &Health).unwrap(); let mut o = Some(r_srv.h); o.unwrap().hp = 0.0; }"#,
        ),
        (
            "pos_r8_opt_term_soundness_c2_reclit_unwrap",
            decls,
            r#"@authority(client) sys c2() { let r_srv = query_one(h: &Health).unwrap(); let mut bx = { o: Some(r_srv.h), x: 1.0 }; bx.o.unwrap().hp = 0.0; }"#,
        ),
        (
            "pos_r8_opt_term_soundness_c3_refmut_opt",
            decls,
            r#"@authority(client) sys c3() { let r_srv = query_one(h: &Health).unwrap(); let mut o = Some(r_srv.h); let _p = &mut o; }"#,
        ),
        (
            "pos_r8_opt_term_soundness_c4_refmut_some",
            decls,
            r#"@authority(client) sys c4() { let r_srv = query_one(h: &Health).unwrap(); let _p = &mut Some(r_srv.h); }"#,
        ),
        (
            "pos_r8_opt_term_soundness_c5_if_let_some",
            decls,
            r#"@authority(client) sys c5() { let r_srv = query_one(h: &Health).unwrap(); let mut o = Some(r_srv.h); if let Some(h) = o { h.hp = 0.0; } }"#,
        ),
        (
            "pos_r8_opt_term_soundness_c6_unwrap_or",
            decls,
            r#"@authority(client) sys c6() { let r_srv = query_one(h: &Health).unwrap(); let r_cli = query_one(h: &ClientHealth).unwrap(); let mut o = Some(r_srv.h); o.unwrap_or(r_cli.h).hp = 0.0; }"#,
        ),
        (
            "pos_r8_opt_term_soundness_c7_arr_refmut_wrap_opt",
            decls,
            r#"@authority(client) sys c7() { (&mut [wrap_opt()])[0] = None; }"#,
        ),
    ];

    for (name, extra, body) in positives {
        assert_probe(name, extra, body, true);
    }

    let precision_controls = [
        (
            "neg_r8_qone_on_clean_block",
            decls,
            r#"@authority(client) sys ok() { let t = query_one(id: Entity).unwrap(); query_one(h: &ClientHealth).on({ let _a = 1; t.id }).unwrap().h.hp = 0.0; }"#,
        ),
        (
            "neg_r8_qone_mixed_client_term_with_server_term_clean_block",
            decls,
            r#"@authority(client) sys ok() { let t = query_one(id: Entity).unwrap(); query_one(h: &ClientHealth, s: &ServerComp).on({ let _a = 1; t.id }).unwrap().h.hp = 0.0; }"#,
        ),
        (
            "neg_r8_client_query_and_some_clean_block",
            decls,
            r#"@authority(client) sys ok() { let t = query_one(id: Entity).unwrap(); client_query(h: &ClientHealth).on({ let _a = 1; t.id }).unwrap().h.hp = 0.0; Some(query_one(h: &ClientHealth).on({ let _a = 1; t.id }).unwrap().h).unwrap().hp = 0.0; }"#,
        ),
        (
            "neg_r8_for_reduce_clean_call",
            decls,
            r#"@authority(client) sys ok() { let _s = for _i in 0..2 reduce(acc: add(0, 1)); }"#,
        ),
        (
            "neg_r8_if_clean_clientcomp_and_reclit_lvalue",
            decls,
            r#"@authority(client) sys ok() { let r_srv = query_one(h: &Health).unwrap(); (if true { ClientComp { x: 1.0 } }).x = 2.0; (if true { { row: r_srv, x: 1.0 } }).x = 2.0; }"#,
        ),
        (
            "neg_r8_fn_clean_defaults",
            decls,
            r#"@authority(client) sys ok(x: i32) { let _v = ok_def() + ok_def(x); }"#,
        ),
        (
            "neg_r8_opt_term_set_none_and_reclit_set_none",
            decls,
            r#"@authority(client) sys ok() { let r_srv = query_one(h: &Health).unwrap(); let mut o = Some(r_srv.h); o = None; o.unwrap().hp = 0.0; let mut bx = { o: Some(r_srv.h), x: 1.0 }; bx.o = None; bx.o.unwrap().hp = 0.0; }"#,
        ),
    ];

    for (name, extra, body) in precision_controls {
        assert_probe(name, extra, body, false);
    }
}

#[test]
fn m1_r9_regression_iter9_assign_in_expr_spawn_batch_query_spatial_stmt_and_option_adapters() {
    fn assert_probe(name: &str, extra_decls: &str, body: &str, expect_e0501: bool) {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

@authority(server)
component ServerComp {{ x: f32 = 1.0, cd: Cooldown = 50.0_ms }}

@authority(server)
component Health {{ hp: f32 = 100.0, cd: Cooldown = 50.0_ms }}

@authority(client)
component ClientComp {{ x: f32 = 1.0 }}

@authority(client)
component ClientHealth {{ hp: f32 = 50.0, cd: Cooldown = 50.0_ms }}

@authority(client)
component ClientTag;

@authority(client)
component Pos2D {{ x: f32 = 0.0, y: f32 = 0.0 }}

@authority(server)
resource ServerBank {{ gold: i32 = 100 }}

event ClientEv {{ v: i32 }}
relation ChildOf;

spatial_grid grid(cell: 4.0) over Pos2D by Pos2D.x;
spatial_history hist(frames: 8) over Pos2D by Pos2D.x;

{extra_decls}
{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        let parse_errs: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0002_PARSE_ERROR)
            .collect();
        assert!(
            parse_errs.is_empty(),
            "unexpected E0002_PARSE_ERROR in {name}: {parse_errs:#?}\nall diagnostics: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
    }

    let decls = r#"
fn sneak_void() { res_mut<ServerBank>().gold = 1; }
fn sneak_i32() -> i32 { res_mut<ServerBank>().gold = 1; 0 }
"#;

    let positives = [
        // 1. m1_r8_reviewer_1: BinaryExpr assignment in expression position & omitted-semicolon tails (10 probes)
        (
            "pos_r9_assign_match_arm_option_unbraced",
            decls,
            r#"@authority(client) sys p3() { let r_srv = query_one(h: &Health).unwrap(); let mut o = Some(r_srv.h); match o { Some(h) => h.hp = 0.0, None => {} } }"#,
        ),
        (
            "pos_r9_assign_match_arm_direct_row_unbraced",
            decls,
            r#"@authority(client) sys e1() { let r_srv = query_one(h: &Health).unwrap(); match r_srv { _ => r_srv.h.hp = 0.0 } }"#,
        ),
        (
            "pos_r9_assign_if_tail_no_semi",
            decls,
            r#"@authority(client) sys e2(flag: bool) { let r_srv = query_one(h: &Health).unwrap(); if flag { r_srv.h.hp = 0.0 } }"#,
        ),
        (
            "pos_r9_assign_block_tail_no_semi",
            decls,
            r#"@authority(client) sys e3() { let r_srv = query_one(h: &Health).unwrap(); let _x = { r_srv.h.hp = 0.0 }; }"#,
        ),
        (
            "pos_r9_assign_sys_tail_no_semi",
            decls,
            r#"@authority(client) sys s_tail() { let r_srv = query_one(h: &Health).unwrap(); r_srv.h.hp = 0.0 }"#,
        ),
        (
            "pos_r9_assign_fn_tail_no_semi",
            decls,
            r#"fn f_tail() { let r_srv = query_one(h: &Health).unwrap(); r_srv.h.hp = 0.0 }
@authority(client) sys s_fn() { f_tail(); }"#,
        ),
        (
            "pos_r9_assign_paren_expr",
            decls,
            r#"@authority(client) sys e4() { let r_srv = query_one(h: &Health).unwrap(); let _x = (r_srv.h.hp = 0.0); }"#,
        ),
        (
            "pos_r9_assign_for_reduce",
            decls,
            r#"@authority(client) sys e5() { let r_srv = query_one(h: &Health).unwrap(); let _s = for _i in 0..2 reduce(acc: r_srv.h.hp = 0.0); }"#,
        ),
        (
            "pos_r9_assign_return_expr",
            decls,
            r#"@authority(client) sys s_ret() { let r_srv = query_one(h: &Health).unwrap(); return r_srv.h.hp = 0.0; }"#,
        ),
        (
            "pos_r9_assign_compound_match_arm_no_semi",
            decls,
            r#"@authority(client) sys e6() { let r_srv = query_one(h: &Health).unwrap(); match r_srv { _ => r_srv.h.hp += 1.0 } }"#,
        ),
        // 2. m1_r8_challenger_2 Finding 1: SpawnBatchExpr non-BundleLit tails & nested/if/match/let BundleLit (8 repros + extra count arg)
        (
            "pos_r9_sb_tail_block_resmut",
            decls,
            r#"@authority(client) sys cheat() { spawn_batch(1) |i| { { res_mut<ServerBank>().gold = 1; ClientComp { x: 1.0 } } }; }"#,
        ),
        (
            "pos_r9_sb_tail_if_bundle_server",
            decls,
            r#"@authority(client) sys cheat(flag: bool) { spawn_batch(1) |i| { if flag { { Health { hp: 100.0 } } } else { { ClientComp { x: 1.0 } } } }; }"#,
        ),
        (
            "pos_r9_sb_tail_if_cond_resmut",
            decls,
            r#"@authority(client) sys cheat() { spawn_batch(1) |i| { if res_mut<ServerBank>().gold == 0 { { ClientComp { x: 1.0 } } } }; }"#,
        ),
        (
            "pos_r9_sb_tail_call_no_semi",
            decls,
            r#"@authority(client) sys cheat() { spawn_batch(1) |i| { sneak_void() }; }"#,
        ),
        (
            "pos_r9_sb_tail_resmut_no_semi",
            decls,
            r#"@authority(client) sys cheat() { spawn_batch(1) |i| { res_mut<ServerBank>().gold = 1 }; }"#,
        ),
        (
            "pos_r9_sb_let_bundle_server",
            decls,
            r#"@authority(client) sys cheat() { spawn_batch(1) |i| { let b = { Health { hp: 100.0 } }; b }; }"#,
        ),
        (
            "pos_r9_sb_block_nested_bundle_server",
            decls,
            r#"@authority(client) sys cheat() { spawn_batch(1) |i| { { let _ = 1; { Health { hp: 100.0 } } } }; }"#,
        ),
        (
            "pos_r9_sb_match_bundle_server",
            decls,
            r#"@authority(client) sys cheat(flag: bool) { spawn_batch(1) |i| { match flag { true => { Health { hp: 100.0 } }, false => { ClientComp { x: 1.0 } } } }; }"#,
        ),
        (
            "pos_r9_sb_extra_count_arg",
            decls,
            r#"@authority(client) sys cheat() { spawn_batch(1, { res_mut<ServerBank>().gold = 1; 0 }) |i| { { ClientComp { x: 1.0 } } }; }"#,
        ),
        // 3. m1_r8_challenger_2 Finding 2: Chained .where/.on & query method ArgList drops (10 repros)
        (
            "pos_r9_chained_where_overwrite_for",
            decls,
            r#"@authority(client) sys cheat() { for _r in query(h: &ClientHealth).where({ res_mut<ServerBank>().gold = 1; true }).where(true) {} }"#,
        ),
        (
            "pos_r9_chained_where_overwrite_qone",
            decls,
            r#"@authority(client) sys cheat() { query_one(h: &ClientHealth).where({ res_mut<ServerBank>().gold = 1; true }).where(true).unwrap().h.hp = 0.0; }"#,
        ),
        (
            "pos_r9_chained_on_overwrite_qone",
            decls,
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); query_one(h: &ClientHealth).on({ res_mut<ServerBank>().gold = 1; t.id }).on(t.id).unwrap().h.hp = 0.0; }"#,
        ),
        (
            "pos_r9_q_chained_where_fn",
            decls,
            r#"@authority(client) sys cheat() { for _r in query(h: &ClientHealth).where(sneak_i32() == 0).where(true) {} }"#,
        ),
        (
            "pos_r9_q_chained_where_refmut",
            decls,
            r#"@authority(client) sys cheat() { let mut sc = ServerComp { x: 1.0 }; for _r in query(h: &ClientHealth).where({ let _p = &mut sc; true }).where(true) {} }"#,
        ),
        (
            "pos_r9_q_chained_on_fn",
            decls,
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); query_one(h: &ClientHealth).on({ sneak_void(); t.id }).on(t.id).unwrap().h.hp = 0.0; }"#,
        ),
        (
            "pos_r9_q_unwrap_arg",
            decls,
            r#"@authority(client) sys cheat() { query_one(h: &ClientHealth).unwrap({ res_mut<ServerBank>().gold = 1; }).h.hp = 0.0; }"#,
        ),
        (
            "pos_r9_q_count_arg",
            decls,
            r#"@authority(client) sys cheat() { let _c = query(h: &ClientHealth).count({ res_mut<ServerBank>().gold = 1; }); }"#,
        ),
        (
            "pos_r9_q_where_extra_arg",
            decls,
            r#"@authority(client) sys cheat() { for _r in query(h: &ClientHealth).where(true, { res_mut<ServerBank>().gold = 1; true }) {} }"#,
        ),
        (
            "pos_r9_q_on_extra_arg",
            decls,
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); query_one(h: &ClientHealth).on(t.id, { res_mut<ServerBank>().gold = 1; t.id }).unwrap().h.hp = 0.0; }"#,
        ),
        // 4. m1_r8_challenger_2 Finding 3: SpatialDisc & SpatialSegmentAt drop recv & extra args (4 repros)
        (
            "pos_r9_spatial_disc_recv_block",
            decls,
            r#"@authority(client) sys cheat() { for _e in ({ res_mut<ServerBank>().gold = 1; grid }).query_disc(0.0, 10.0) {} }"#,
        ),
        (
            "pos_r9_spatial_disc_extra_arg",
            decls,
            r#"@authority(client) sys cheat() { for _e in grid.query_disc(0.0, 10.0, { res_mut<ServerBank>().gold = 1; 0 }) {} }"#,
        ),
        (
            "pos_r9_spatial_seg_recv_block",
            decls,
            r#"@authority(client) sys cheat() { for _e in ({ res_mut<ServerBank>().gold = 1; hist }).query_segment_at(0, 0.0, 1.0) {} }"#,
        ),
        (
            "pos_r9_spatial_seg_extra_arg",
            decls,
            r#"@authority(client) sys cheat() { for _e in hist.query_segment_at(0, 0.0, 1.0, { res_mut<ServerBank>().gold = 1; 0 }) {} }"#,
        ),
        // 5. m1_r8_challenger_2 Finding 4: lower_expr_as_stmt / InsertExpr / RemoveExpr / DespawnAllExpr trailing args (8 repros + despawn_all)
        (
            "pos_r9_trigger_propagate_resmut",
            decls,
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); trigger(t.id, ClientEv { v: 1 }, propagate: { res_mut<ServerBank>().gold = 1; true }); }"#,
        ),
        (
            "pos_r9_insert_extra_arg",
            decls,
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); insert(t.id, ClientComp { x: 1.0 }, { res_mut<ServerBank>().gold = 1; 1 }); }"#,
        ),
        (
            "pos_r9_remove_extra_arg",
            decls,
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); remove<ClientComp>(t.id, { res_mut<ServerBank>().gold = 1; 1 }); }"#,
        ),
        (
            "pos_r9_emit_extra_arg",
            decls,
            r#"@authority(client) sys cheat() { emit(ClientEv { v: 1 }, { res_mut<ServerBank>().gold = 1; 1 }); }"#,
        ),
        (
            "pos_r9_despawn_extra_arg",
            decls,
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); despawn(t.id, { res_mut<ServerBank>().gold = 1; 1 }); }"#,
        ),
        (
            "pos_r9_require_true_extra_arg",
            decls,
            r#"@authority(client) sys cheat() { require_true(true, { res_mut<ServerBank>().gold = 1; 1 }); }"#,
        ),
        (
            "pos_r9_insert_rel_extra_arg",
            decls,
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); insert_relation<ChildOf>(t.id, t.id, 1, { res_mut<ServerBank>().gold = 1; 1 }); }"#,
        ),
        (
            "pos_r9_remove_rel_extra_arg",
            decls,
            r#"@authority(client) sys cheat() { let t = query_one(id: Entity).unwrap(); remove_relation<ChildOf>(t.id, t.id, { res_mut<ServerBank>().gold = 1; 1 }); }"#,
        ),
        (
            "pos_r9_despawn_all_extra_arg",
            decls,
            r#"@authority(client) sys cheat() { despawn_all<With<ClientTag>>({ res_mut<ServerBank>().gold = 1; }); }"#,
        ),
        // 6. m1_r8_challenger_2 Finding 5: Option::unwrap, .as_mut(), .as_ref(), .take() (7 repros)
        (
            "pos_r9_opt_assoc_unwrap",
            decls,
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); Option::unwrap(Some(r_srv.h)).hp = 0.0; }"#,
        ),
        (
            "pos_r9_opt_assoc_unwrap_let",
            decls,
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let h = Option::unwrap(Some(r_srv.h)); h.hp = 0.0; }"#,
        ),
        (
            "pos_r9_opt_as_mut_unwrap",
            decls,
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let mut o = Some(r_srv.h); o.as_mut().unwrap().hp = 0.0; }"#,
        ),
        (
            "pos_r9_opt_as_mut_unwrap_let",
            decls,
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let mut o = Some(r_srv.h); let h = o.as_mut().unwrap(); h.hp = 0.0; }"#,
        ),
        (
            "pos_r9_opt_take_unwrap",
            decls,
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let mut o = Some(r_srv.h); o.take().unwrap().hp = 0.0; }"#,
        ),
        (
            "pos_r9_opt_take_unwrap_let",
            decls,
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let mut o = Some(r_srv.h); let h = o.take().unwrap(); h.hp = 0.0; }"#,
        ),
        (
            "pos_r9_opt_as_ref_unwrap_let",
            decls,
            r#"@authority(client) sys cheat() { let r_srv = query_one(h: &Health).unwrap(); let o = Some(r_srv.h); o.as_ref().unwrap().hp = 0.0; }"#,
        ),
    ];

    for (name, extra, body) in positives {
        assert_probe(name, extra, body, true);
    }

    let precision_controls = [
        (
            "neg_r9_assign_match_arm_client_and_none",
            decls,
            r#"@authority(client) sys ok() { let r_cli = query_one(h: &ClientHealth).unwrap(); let mut o1 = Some(r_cli.h); match o1 { Some(h) => h.hp = 0.0, None => {} } let r_srv = query_one(h: &Health).unwrap(); let mut o2 = Some(r_srv.h); o2 = None; match o2 { Some(h) => h.hp = 0.0, None => {} } }"#,
        ),
        (
            "neg_r9_sb_clean_client_bundle_and_let",
            decls,
            r#"@authority(client) sys ok() { spawn_batch(1) |i| { let _a = 1; { ClientComp { x: 1.0 } } }; spawn_batch(1) |i| { let b = { ClientComp { x: 1.0 } }; b }; }"#,
        ),
        (
            "neg_r9_q_chained_where_and_on_clean",
            decls,
            r#"@authority(client) sys ok() { let t = query_one(id: Entity).unwrap(); for _r in query(h: &ClientHealth).where(h.hp > 0.0).where(true) {} query_one(h: &ClientHealth).on(t.id).on(t.id).unwrap().h.hp = 0.0; }"#,
        ),
        (
            "neg_r9_spatial_disc_and_seg_clean",
            decls,
            r#"@authority(client) sys ok() { for _e in grid.query_disc(0.0, 10.0) {} for _e in hist.query_segment_at(0, 0.0, 1.0) {} }"#,
        ),
        (
            "neg_r9_trigger_propagate_clean",
            decls,
            r#"@authority(client) sys ok() { let t = query_one(id: Entity).unwrap(); trigger(t.id, ClientEv { v: 1 }, propagate: true); }"#,
        ),
        (
            "neg_r9_opt_assoc_and_adapters_client_and_none",
            decls,
            r#"@authority(client) sys ok() { let r_cli = query_one(h: &ClientHealth).unwrap(); Option::unwrap(Some(r_cli.h)).hp = 0.0; let mut o1 = Some(r_cli.h); o1.as_mut().unwrap().hp = 0.0; o1.take().unwrap().hp = 0.0; let o2 = Some(r_cli.h); o2.as_ref().unwrap().hp = 0.0; let r_srv = query_one(h: &Health).unwrap(); let mut o3 = Some(r_srv.h); o3 = None; o3.as_mut().unwrap().hp = 0.0; o3.take().unwrap().hp = 0.0; o3.as_ref().unwrap().hp = 0.0; }"#,
        ),
    ];

    for (name, extra, body) in precision_controls {
        assert_probe(name, extra, body, false);
    }
}

#[test]
fn m1_r10_regression_iter10_projected_query_term_for_and_where_provenance() {
    fn assert_probe(name: &str, body: &str, expect_e0501: bool) {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

struct Sub {{ hp: f32 }}

@authority(server)
component Health {{ hp: f32 = 100.0, pos: Vec2 = vec2(0.0, 0.0), sub: Sub = Sub {{ hp: 10.0 }} }}

@authority(server)
component StratHealth {{ hp: f32 = 100.0, pos: Vec2 = vec2(0.0, 0.0), cd: Cooldown = 50.0_ms }}

@authority(client)
component ClientHealth {{ hp: f32 = 50.0, pos: Vec2 = vec2(0.0, 0.0), sub: Sub = Sub {{ hp: 10.0 }} }}

{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        let parse_errs: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0002_PARSE_ERROR)
            .collect();
        assert!(
            parse_errs.is_empty(),
            "unexpected E0002_PARSE_ERROR in {name}: {parse_errs:#?}\nall diagnostics: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
    }

    let positives = [
        // Finding 1: Single-projected-term `for` loop variable matching `term.alias`
        (
            "pos_r10_vec_for_v_x",
            r#"@authority(client) sys s() { for v in query(v: &Health.pos) { v.x = 0.0; } }"#,
        ),
        (
            "pos_r10_vec_for_v_x_add",
            r#"@authority(client) sys s() { for v in query(v: &Health.pos) { v.x += 1.0; } }"#,
        ),
        (
            "pos_r10_vec_for_v_arm_refmut",
            r#"@authority(client) sys s() { for v in query(v: &Health.pos) { let _p = &mut v.x; } }"#,
        ),
        (
            "pos_r10_vec_qmark_for_v_x",
            r#"@authority(client) sys s() { for v in query(v: ?&Health.pos) { v.x = 0.0; } }"#,
        ),
        (
            "pos_r10_vec_strat_for_v_x",
            r#"@authority(client) sys s() { for v in query(v: &StratHealth.pos) { v.x = 0.0; } }"#,
        ),
        (
            "pos_r10_sub_for_s_hp",
            r#"@authority(client) sys s() { for sub in query(sub: &Health.sub) { sub.hp = 0.0; } }"#,
        ),
        (
            "pos_r10_q_for_proj_direct_set",
            r#"@authority(client) sys s() { for x in query(x: &Health.hp) { x = 0.0; } }"#,
        ),
        (
            "pos_r10_q_for_proj_direct_add",
            r#"@authority(client) sys s() { for x in query(x: &Health.hp) { x += 1.0; } }"#,
        ),
        (
            "pos_r10_q_for_qmark_proj_set",
            r#"@authority(client) sys s() { for x in query(x: ?&Health.hp) { x = 0.0; } }"#,
        ),
        (
            "pos_r10_vec_for_v_alias_copy",
            r#"@authority(client) sys s() { for v in query(v: &Health.pos) { let mut v2 = v; v2.x = 0.0; } }"#,
        ),
        (
            "pos_r10_vec_for_v_reduce_write",
            r#"@authority(client) sys s() { let _t = for v in query(v: &Health.pos) reduce (acc: sum(0.0, { v.x = 0.0; v.x })); }"#,
        ),
        (
            "pos_r10_row_for_r_v_x_control",
            r#"@authority(client) sys s() { for r in query(v: &Health.pos) { r.v.x = 0.0; } }"#,
        ),
        // Finding 2: Bare projected aliases inside `.where(...)` predicates
        (
            "pos_r10_q_where_proj_set",
            r#"@authority(client) sys s() { for _r in query(x: &Health.hp).where({ x = 0.0; true }) {} }"#,
        ),
        (
            "pos_r10_q_where_proj_add",
            r#"@authority(client) sys s() { for _r in query(x: &Health.hp).where({ x += 1.0; true }) {} }"#,
        ),
        (
            "pos_r10_q_where_proj_refmut",
            r#"@authority(client) sys s() { for _r in query(x: &Health.hp).where({ let _p = &mut x; true }) {} }"#,
        ),
        (
            "pos_r10_q_where_proj_count_set",
            r#"@authority(client) sys s() { let _c = query(x: &Health.hp).where({ x = 0.0; true }).count(); }"#,
        ),
        (
            "pos_r10_q_where_proj_count_add",
            r#"@authority(client) sys s() { let _c = query(x: &Health.hp).where({ x += 1.0; true }).count(); }"#,
        ),
        (
            "pos_r10_q_where_proj_count_refmut",
            r#"@authority(client) sys s() { let _c = query(x: &Health.hp).where({ let _p = &mut x; true }).count(); }"#,
        ),
        (
            "pos_r10_q_for_proj_qone_where_set",
            r#"@authority(client) sys s() { let _r = query_one(x: &Health.hp).where({ x = 0.0; true }).unwrap(); }"#,
        ),
        (
            "pos_r10_q_for_proj_qone_where_add",
            r#"@authority(client) sys s() { let _r = query_one(x: &Health.hp).where({ x += 1.0; true }).unwrap(); }"#,
        ),
        (
            "pos_r10_q_for_proj_qone_where_refmut",
            r#"@authority(client) sys s() { let _r = query_one(x: &Health.hp).where({ let _p = &mut x; true }).unwrap(); }"#,
        ),
        (
            "pos_r10_q_where_qmark_proj_add",
            r#"@authority(client) sys s() { for _r in query(x: ?&Health.hp).where({ x += 1.0; true }) {} }"#,
        ),
        (
            "pos_r10_fn_where_proj_add",
            r#"fn f() { for _r in query(x: &Health.hp).where({ x += 1.0; true }) {} }
@authority(client) sys s() { f(); }"#,
        ),
        (
            "pos_r10_pred_where_proj_add",
            r#"@predicted sys s() { for _r in query(x: &Health.hp).where({ x += 1.0; true }) {} }"#,
        ),
        (
            "pos_r10_q_where_strat_proj_set",
            r#"@authority(client) sys s() { for _r in query(x: &StratHealth.hp).where({ x = 0.0; true }) {} }"#,
        ),
        (
            "pos_r10_q_where_chained_proj_set",
            r#"@authority(client) sys s() { for _r in query(x: &Health.hp).where({ x = 0.0; true }).where(true) {} }"#,
        ),
        (
            "pos_r10_q_where_vec_field_set",
            r#"@authority(client) sys s() { for _r in query(v: &Health.pos).where({ v.x = 0.0; true }) {} }"#,
        ),
        (
            "pos_r10_q_where_whole_comp_set",
            r#"@authority(client) sys s() { for _r in query(h: &Health).where({ h.hp = 0.0; true }) {} }"#,
        ),
        (
            "pos_r10_qone_if_let_where_proj_set",
            r#"@authority(client) sys s() { if let Some(_r) = query_one(x: &Health.hp).where({ x = 0.0; true }) {} }"#,
        ),
    ];

    for (name, body) in positives {
        assert_probe(name, body, true);
    }

    let precision_controls = [
        (
            "neg_r10_where_server_readonly",
            r#"@authority(client) sys ok() { for _r in query(x: &Health.hp).where(x > 0.0) {} }"#,
        ),
        (
            "neg_r10_where_client_proj_set",
            r#"@authority(client) sys ok() { for _r in query(x: &ClientHealth.hp).where({ x = 0.0; true }) {} }"#,
        ),
        (
            "neg_r10_for_client_proj_set",
            r#"@authority(client) sys ok() { for x in query(x: &ClientHealth.hp) { x = 0.0; } }"#,
        ),
        (
            "neg_r10_for_client_proj_refmut",
            r#"@authority(client) sys ok() { for x in query(x: &ClientHealth.hp) { let _p = &mut x; } }"#,
        ),
        (
            "neg_r10_for_client_vec_set",
            r#"@authority(client) sys ok() { for v in query(v: &ClientHealth.pos) { v.x = 0.0; } }"#,
        ),
        (
            "neg_r10_for_client_sub_set",
            r#"@authority(client) sys ok() { for sub in query(sub: &ClientHealth.sub) { sub.hp = 0.0; } }"#,
        ),
        (
            "neg_r10_for_server_vec_readonly",
            r#"@authority(client) sys ok() { for v in query(v: &Health.pos) { let _px = v.x; } }"#,
        ),
        (
            "neg_r10_for_server_vec_scalar_copy_mut",
            r#"@authority(client) sys ok() { for v in query(v: &Health.pos) { let mut px = v.x; px = 1.0; } }"#,
        ),
        (
            "neg_r10_for_server_row_id_readonly",
            r#"@authority(client) sys ok() { for r in query(v: &Health.pos) { let _id = r.id; } }"#,
        ),
        (
            "neg_r10_where_server_whole_comp_readonly",
            r#"@authority(client) sys ok() { for _r in query(h: &Health).where(h.hp > 0.0) {} }"#,
        ),
        (
            "neg_r10_where_shadowed_outer_local",
            r#"@authority(client) sys ok() { let mut x = 1.0; for _r in query(x: &Health.hp).where(x > 0.0) { x = 2.0; } }"#,
        ),
    ];

    for (name, body) in precision_controls {
        assert_probe(name, body, false);
    }
}

#[test]
fn m1_r11_regression_scalar_copy_precision_and_non_scalar_soundness() {
    fn assert_probe(name: &str, body: &str, expect_e0501: bool) {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

enum State {{ Idle = 0, Active = 1 }}
struct Sub {{ hp: f32 }}

@authority(server)
component Health {{
    hp: f32 = 100.0,
    hp64: f64 = 100.0,
    cnt: i32 = 1,
    ucnt: u32 = 1,
    alive: bool = true,
    fx32: fix32 = 1.0,
    fx64: fix64 = 1.0,
    cd: sec = 1.0_s,
    state: State = State::Idle,
    target: Ref<Entity>,
    pos: vec2 = vec2(0.0, 0.0),
    sub: Sub = Sub {{ hp: 10.0 }},
    flags: BitSet<64>
}}

@authority(server)
component StratHealth {{ hp: f32 = 100.0, pos: vec2 = vec2(0.0, 0.0), cd: sec = 0.5_s }}

@authority(client)
component ClientHealth {{ hp: f32 = 50.0, pos: vec2 = vec2(0.0, 0.0), sub: Sub = Sub {{ hp: 10.0 }} }}

{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        let non_e0501_errs: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| {
                d.severity == strata_sema::diagnostics::Severity::Error
                    && d.code != codes::E0501_AUTHORITY_VIOLATION
            })
            .collect();
        assert!(
            non_e0501_errs.is_empty(),
            "unexpected parse/type errors in {name}: {non_e0501_errs:#?}\nall diagnostics: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
    }

    // Precision controls: scalar `let` copies / reassignments / containers must NOT emit E0501.
    let scalar_copy_precision = [
        // All 8 m1_r10_challenger_1 repros
        (
            "neg_r11_where_let_x_set",
            r#"@authority(client) sys ok() { for _r in query(x: &Health.hp).where({ let mut y = x; y = 0.0; true }) {} }"#,
        ),
        (
            "neg_r11_for_let_x_set",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let mut y = x; y = 0.0; } }"#,
        ),
        (
            "neg_r11_for_row_let_rx_set",
            r#"@authority(client) sys ok() { for r in query(x: &Health.hp) { let mut y = r.x; y = 0.0; } }"#,
        ),
        (
            "neg_r11_where_let_x_add",
            r#"@authority(client) sys ok() { for _r in query(x: &Health.hp).where({ let mut y = x; y += 1.0; true }) {} }"#,
        ),
        (
            "neg_r11_where_let_x_refmut",
            r#"@authority(client) sys ok() { for _r in query(x: &Health.hp).where({ let mut y = x; let _p = &mut y; true }) {} }"#,
        ),
        (
            "neg_r11_where_let_x_typed_f32_set",
            r#"@authority(client) sys ok() { for _r in query(x: &Health.hp).where({ let mut y: f32 = x; y = 0.0; true }) {} }"#,
        ),
        (
            "neg_r11_where_let_paren_x_set",
            r#"@authority(client) sys ok() { for _r in query(x: &Health.hp).where({ let mut y = (x); y = 0.0; true }) {} }"#,
        ),
        (
            "neg_r11_where_let_if_x_set",
            r#"@authority(client) sys ok() { for _r in query(x: &Health.hp).where({ let mut y = if true { x } else { 1.0 }; y = 0.0; true }) {} }"#,
        ),
        // InsertCompScope + QueryScope consistency for `r.x` compound assign & `&mut`
        (
            "neg_r11_for_row_let_rx_add_and_refmut",
            r#"@authority(client) sys ok() { for r in query(x: &Health.hp) { let mut y = r.x; y += 1.0; let _p = &mut y; } }"#,
        ),
        (
            "neg_r11_for_row_let_if_rx_add",
            r#"@authority(client) sys ok() { for r in query(x: &Health.hp) { let mut y = if true { r.x } else { 1.0 }; y += 1.0; } }"#,
        ),
        // Reassignment & containers of copied scalars
        (
            "neg_r11_where_reassign_scalar_x",
            r#"@authority(client) sys ok() { for _r in query(x: &Health.hp).where({ let mut y = 0.0; y = x; y = 1.0; true }) {} }"#,
        ),
        (
            "neg_r11_for_row_reassign_scalar_rx",
            r#"@authority(client) sys ok() { for r in query(x: &Health.hp) { let mut y = 0.0; y = r.x; y += 1.0; } }"#,
        ),
        (
            "neg_r11_where_tuple_destruct_scalar_x",
            r#"@authority(client) sys ok() { for _r in query(x: &Health.hp).where({ let (mut a, _b) = (x, 1); a = 0.0; true }) {} }"#,
        ),
        (
            "neg_r11_for_row_tuple_destruct_scalar_rx",
            r#"@authority(client) sys ok() { for r in query(x: &Health.hp) { let (mut a, _b) = (r.x, 1); a += 1.0; } }"#,
        ),
        (
            "neg_r11_where_some_unwrap_scalar_x",
            r#"@authority(client) sys ok() { for _r in query(x: &Health.hp).where({ let o = Some(x); let mut a = o.unwrap(); a = 0.0; true }) {} }"#,
        ),
        (
            "neg_r11_where_if_let_some_scalar_x",
            r#"@authority(client) sys ok() { for _r in query(x: &Health.hp).where({ if let Some(mut a) = Some(x) { a = 0.0; } true }) {} }"#,
        ),
        (
            "neg_r11_where_array_rec_scalar_x",
            r#"@authority(client) sys ok() { for _r in query(x: &Health.hp).where({ let mut arr = [x]; arr[0] = 0.0; let mut rec = { p: x }; rec.p = 0.0; true }) {} }"#,
        ),
        // Additional scalar types & stratified/helper/client controls
        (
            "neg_r11_scalar_i32_u32_bool_f64",
            r#"@authority(client) sys ok() {
                for a in query(a: &Health.cnt) { let mut y = a; y = 2; }
                for b in query(b: &Health.ucnt) { let mut y = b; y = 2; }
                for c in query(c: &Health.alive) { let mut y = c; y = false; }
                for d in query(d: &Health.hp64) { let mut y = d; y = 2.0; }
            }"#,
        ),
        (
            "neg_r11_scalar_fix32_fix64_unit_entity_enum",
            r#"@authority(client) sys ok() {
                for f32v in query(f32v: &Health.fx32) { let mut y = f32v; y = 2.0; }
                for f64v in query(f64v: &Health.fx64) { let mut y = f64v; y = 2.0; }
                for cd in query(cd: &Health.cd) { let mut y = cd; y = 2.0_s; }
                for st in query(st: &Health.state) { let mut y = st; y = State::Active; }
                for r in query(tgt: &Health.target) { let mut y = r.tgt; y = r.id; }
            }"#,
        ),
        (
            "neg_r11_stratified_scalar_copy",
            r#"@authority(client) sys ok() { for _r in query(x: &StratHealth.hp).where({ let mut y = x; y = 0.0; true }) {} }"#,
        ),
        (
            "neg_r11_helper_fn_scalar_copy",
            r#"fn f(x: f32) { let mut y = x; y = 0.0; }
@authority(client) sys ok() { for x in query(x: &Health.hp) { f(x); } }"#,
        ),
        (
            "neg_r11_client_scalar_copy",
            r#"@authority(client) sys ok() { for x in query(x: &ClientHealth.hp) { let mut y = x; y = 0.0; } }"#,
        ),
    ];

    for (name, body) in scalar_copy_precision {
        assert_probe(name, body, false);
    }

    // Soundness guards: direct query term mutations/borrows & non-scalar copies MUST emit E0501.
    let soundness_guards = [
        (
            "pos_r11_direct_for_x_set",
            r#"@authority(client) sys cheat() { for x in query(x: &Health.hp) { x = 0.0; } }"#,
        ),
        (
            "pos_r11_direct_for_x_add",
            r#"@authority(client) sys cheat() { for x in query(x: &Health.hp) { x += 1.0; } }"#,
        ),
        (
            "pos_r11_direct_for_x_refmut",
            r#"@authority(client) sys cheat() { for x in query(x: &Health.hp) { let _p = &mut x; } }"#,
        ),
        (
            "pos_r11_direct_where_x_set",
            r#"@authority(client) sys cheat() { for _r in query(x: &Health.hp).where({ x = 0.0; true }) {} }"#,
        ),
        (
            "pos_r11_direct_where_x_add",
            r#"@authority(client) sys cheat() { for _r in query(x: &Health.hp).where({ x += 1.0; true }) {} }"#,
        ),
        (
            "pos_r11_direct_where_x_refmut",
            r#"@authority(client) sys cheat() { for _r in query(x: &Health.hp).where({ let _p = &mut x; true }) {} }"#,
        ),
        (
            "pos_r11_direct_where_if_x_refmut",
            r#"@authority(client) sys cheat() { for _r in query(x: &Health.hp).where({ let _p = &mut (if true { x } else { 1.0 }); true }) {} }"#,
        ),
        (
            "pos_r11_direct_row_rx_set",
            r#"@authority(client) sys cheat() { for r in query(x: &Health.hp) { r.x = 0.0; } }"#,
        ),
        (
            "pos_r11_direct_row_rx_refmut",
            r#"@authority(client) sys cheat() { for r in query(x: &Health.hp) { let _p = &mut r.x; } }"#,
        ),
        (
            "pos_r11_nonscalar_vec_let_copy",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { let mut v2 = v; v2.x = 0.0; } }"#,
        ),
        (
            "pos_r11_nonscalar_vec_reassign_copy",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { let mut v2 = vec2(0.0, 0.0); v2 = v; v2.x = 0.0; } }"#,
        ),
        (
            "pos_r11_nonscalar_whole_comp_let_copy",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let mut h2 = r.h; h2.hp = 0.0; } }"#,
        ),
        (
            "pos_r11_nonscalar_sub_let_copy",
            r#"@authority(client) sys cheat() { for sub in query(sub: &Health.sub) { let mut s2 = sub; s2.hp = 0.0; } }"#,
        ),
        (
            "pos_r11_nonscalar_row_let_copy",
            r#"@authority(client) sys cheat() { for r in query(v: &Health.pos) { let mut r2 = r; r2.v.x = 0.0; } }"#,
        ),
        (
            "pos_r11_nonscalar_tuple_wrap_vec",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { let (a, _b) = (v, 1); a.x = 0.0; } }"#,
        ),
        (
            "pos_r11_nonscalar_array_wrap_vec",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { let arr = [v]; arr[0].x = 0.0; } }"#,
        ),
        (
            "pos_r11_nonscalar_record_wrap_vec",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { let rec = { p: v }; rec.p.x = 0.0; } }"#,
        ),
        (
            "pos_r11_nonscalar_some_wrap_vec",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { let o = Some(v); o.unwrap().x = 0.0; } }"#,
        ),
        (
            "pos_r11_nonscalar_some_wrap_comp",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let o = Some(r.h); o.unwrap().hp = 0.0; } }"#,
        ),
        (
            "pos_r11_nonscalar_bitset_let_copy",
            r#"@authority(client) sys cheat() { for flags in query(flags: &Health.flags) { let mut f2 = flags; f2.set(0); } }"#,
        ),
    ];

    for (name, body) in soundness_guards {
        assert_probe(name, body, true);
    }
}

#[test]
fn m1_r12_regression_temp_container_scalar_copy_precision() {
    fn assert_probe(name: &str, body: &str, expect_e0501: bool) {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

struct Sub {{ hp: f32 }}
struct Holder {{ v: vec2 }}
struct SubMixed {{ hp: f32, pos: vec2 }}

@authority(server)
component Health {{
    hp: f32 = 100.0,
    pos: vec2 = vec2(0.0, 0.0),
    sub: Sub = Sub {{ hp: 10.0 }}
}}

@authority(client)
component ClientHealth {{
    hp: f32 = 50.0,
    pos: vec2 = vec2(0.0, 0.0)
}}

{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        let non_e0501_errs: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| {
                d.severity == strata_sema::diagnostics::Severity::Error
                    && d.code != codes::E0501_AUTHORITY_VIOLATION
            })
            .collect();
        assert!(
            non_e0501_errs.is_empty(),
            "unexpected parse/type errors in {name}: {non_e0501_errs:#?}\nall diagnostics: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
    }

    // All 24 temporary-container/constructor scalar-copy precision cases + nested controls.
    let precision_cases = [
        (
            "c6_refmut_array_temp_x",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = &mut [x]; } }"#,
        ),
        (
            "c7_refmut_tuple_temp_x",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = &mut (x, 1); } }"#,
        ),
        (
            "c8_refmut_some_temp_x",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = &mut Some(x); } }"#,
        ),
        (
            "c9_refmut_record_temp_x",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = &mut { a: x }; } }"#,
        ),
        (
            "c10_some_x_as_mut",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = Some(x).as_mut(); } }"#,
        ),
        (
            "c11_some_x_take",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = Some(x).take(); } }"#,
        ),
        (
            "c25_refmut_rx_array_temp",
            r#"@authority(client) sys ok() { for r in query(x: &Health.hp) { let _p = &mut [r.x]; } }"#,
        ),
        (
            "c26_refmut_rx_some_temp",
            r#"@authority(client) sys ok() { for r in query(x: &Health.hp) { let _p = &mut Some(r.x); } }"#,
        ),
        (
            "c27_refmut_rx_record_temp",
            r#"@authority(client) sys ok() { for r in query(x: &Health.hp) { let _p = &mut { a: r.x }; } }"#,
        ),
        (
            "c28_refmut_rx_tuple_temp",
            r#"@authority(client) sys ok() { for r in query(x: &Health.hp) { let _p = &mut (r.x, 1); } }"#,
        ),
        (
            "e9_refmut_array_index_temp_x",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = &mut [x][0]; } }"#,
        ),
        (
            "e10_refmut_array_index_temp_rx",
            r#"@authority(client) sys ok() { for r in query(x: &Health.hp) { let _p = &mut [r.x][0]; } }"#,
        ),
        (
            "e11_refmut_rec_field_temp_x",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = &mut { a: x }.a; } }"#,
        ),
        (
            "e12_refmut_rec_field_temp_rx",
            r#"@authority(client) sys ok() { for r in query(x: &Health.hp) { let _p = &mut { a: r.x }.a; } }"#,
        ),
        (
            "e13_refmut_some_unwrap_temp_x",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = &mut Some(x).unwrap(); } }"#,
        ),
        (
            "e14_refmut_some_unwrap_temp_rx",
            r#"@authority(client) sys ok() { for r in query(x: &Health.hp) { let _p = &mut Some(r.x).unwrap(); } }"#,
        ),
        (
            "e15_refmut_some_unwrap_or_x",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = &mut Some(x).unwrap_or(1.0); } }"#,
        ),
        (
            "e16_assign_array_lit_index_x",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { [x][0] = 0.0; } }"#,
        ),
        (
            "e17_assign_array_lit_index_rx",
            r#"@authority(client) sys ok() { for r in query(x: &Health.hp) { [r.x][0] = 0.0; } }"#,
        ),
        (
            "e18_option_as_mut_call_x",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = Option::as_mut(&mut Some(x)); } }"#,
        ),
        (
            "e19_option_take_call_x",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = Option::take(&mut Some(x)); } }"#,
        ),
        (
            "f2_struct_lit_from_x_refmut",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = &mut Sub { hp: x }; } }"#,
        ),
        (
            "f3_struct_lit_from_x_field_refmut",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = &mut Sub { hp: x }.hp; } }"#,
        ),
        (
            "f4_struct_lit_from_x_field_assign",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { Sub { hp: x }.hp = 0.0; } }"#,
        ),
        // Nested container & mixed-struct scalar-field precision cases
        (
            "nested_tuple_in_array_index_refmut_x",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = &mut [(x, 1)][0]; } }"#,
        ),
        (
            "nested_some_array_rx_as_mut",
            r#"@authority(client) sys ok() { for r in query(x: &Health.hp) { let _p = Some([r.x]).as_mut(); } }"#,
        ),
        (
            "nested_record_some_x_field_refmut",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = &mut { a: Some(x) }.a; } }"#,
        ),
        (
            "nested_struct_paren_x_field_assign",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { Sub { hp: (x) }.hp = 0.0; } }"#,
        ),
        (
            "nested_some_if_x_refmut",
            r#"@authority(client) sys ok() { for x in query(x: &Health.hp) { let _p = &mut Some(if true { x } else { 1.0 }); } }"#,
        ),
        (
            "mixed_struct_scalar_field_refmut",
            r#"@authority(client) sys ok() { for r in query(x: &Health.hp, v: &Health.pos) { let _p = &mut SubMixed { hp: r.x, pos: r.v }.hp; } }"#,
        ),
        (
            "helper_fn_temp_array_scalar_refmut",
            r#"fn f(x: f32) { let _p = &mut [x]; }
@authority(client) sys ok() { for x in query(x: &Health.hp) { f(x); } }"#,
        ),
    ];

    for (name, body) in precision_cases {
        assert_probe(name, body, false);
    }

    // Soundness controls: direct `&mut` inside containers & non-scalar containers MUST emit E0501.
    let soundness_controls = [
        (
            "snd_some_refmut_x",
            r#"@authority(client) sys cheat() { for x in query(x: &Health.hp) { let _p = Some(&mut x); } }"#,
        ),
        (
            "snd_array_refmut_x",
            r#"@authority(client) sys cheat() { for x in query(x: &Health.hp) { let _p = [&mut x]; } }"#,
        ),
        (
            "snd_record_refmut_x",
            r#"@authority(client) sys cheat() { for x in query(x: &Health.hp) { let _p = { p: &mut x }; } }"#,
        ),
        (
            "snd_tuple_refmut_x",
            r#"@authority(client) sys cheat() { for x in query(x: &Health.hp) { let _p = (&mut x, 1); } }"#,
        ),
        (
            "snd_refmut_array_v",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { let _p = &mut [v]; } }"#,
        ),
        (
            "snd_refmut_some_v",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { let _p = &mut Some(v); } }"#,
        ),
        (
            "snd_some_v_as_mut",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { let _p = Some(v).as_mut(); } }"#,
        ),
        (
            "snd_some_v_take",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { let _p = Some(v).take(); } }"#,
        ),
        (
            "snd_array_v_index_field_assign",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { [v][0].x = 0.0; } }"#,
        ),
        (
            "snd_record_v_field_assign",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { { a: v }.a.x = 0.0; } }"#,
        ),
        (
            "snd_struct_holder_v_field_assign",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { Holder { v: v }.v.x = 0.0; } }"#,
        ),
        (
            "snd_some_rh_unwrap_field_assign",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { Some(r.h).unwrap().hp = 0.0; } }"#,
        ),
        (
            "snd_some_unwrap_or_x_refmut",
            r#"@authority(client) sys cheat() { for x in query(x: &Health.hp) { let _p = &mut Some(1.0).unwrap_or(x); } }"#,
        ),
        (
            "snd_mixed_struct_nonscalar_field_refmut",
            r#"@authority(client) sys cheat() { for r in query(x: &Health.hp, v: &Health.pos) { let _p = &mut SubMixed { hp: r.x, pos: r.v }.pos; } }"#,
        ),
        (
            "snd_mixed_struct_whole_refmut",
            r#"@authority(client) sys cheat() { for r in query(x: &Health.hp, v: &Health.pos) { let _p = &mut SubMixed { hp: r.x, pos: r.v }; } }"#,
        ),
        (
            "snd_nested_tuple_in_array_v",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { let _p = &mut [(v, 1)][0]; } }"#,
        ),
        (
            "snd_nested_some_array_v_as_mut",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { let _p = Some([v]).as_mut(); } }"#,
        ),
        (
            "snd_record_row_alias_rx_assign",
            r#"@authority(client) sys cheat() { for r in query(x: &Health.hp) { { a: r }.a.x = 0.0; } }"#,
        ),
        (
            "snd_record_row_alias_rx_refmut",
            r#"@authority(client) sys cheat() { for r in query(x: &Health.hp) { let _p = &mut { a: r }.a.x; } }"#,
        ),
        (
            "snd_let_v2_and_h2",
            r#"@authority(client) sys cheat() { for r in query(v: &Health.pos, h: &Health) { let mut v2 = r.v; v2.x = 0.0; let mut h2 = r.h; h2.hp = 0.0; } }"#,
        ),
        (
            "snd_helper_fn_temp_array_v_refmut",
            r#"fn f(v: &mut vec2) { let _p = &mut [v]; }
@authority(client) sys cheat() { for v in query(v: &Health.pos) { f(&mut v); } }"#,
        ),
    ];

    for (name, body) in soundness_controls {
        assert_probe(name, body, true);
    }
}

#[test]
fn m1_r13_regression_scalar_field_and_index_in_temp_container_precision() {
    fn assert_probe(name: &str, body: &str, expect_e0501: bool) {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

enum State {{ Idle = 0, Active = 1 }}
struct Sub {{ hp: f32 }}
struct SubMixed {{ hp: f32, pos: vec2 }}

@authority(server)
component Health {{
    hp: f32 = 100.0,
    cd: sec = 1.0_s,
    state: State = State::Idle,
    target: Ref<Entity>,
    fx32: fix32 = 1.0,
    pos: vec2 = vec2(0.0, 0.0),
    sub: Sub = Sub {{ hp: 10.0 }},
    arr: [f32; 2] = [1.0, 2.0],
    flags: BitSet<64>
}}

@authority(client)
component ClientHealth {{
    hp: f32 = 50.0,
    pos: vec2 = vec2(0.0, 0.0),
    sub: Sub = Sub {{ hp: 10.0 }},
    arr: [f32; 2] = [1.0, 2.0]
}}

{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        let non_e0501_errs: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| {
                d.severity == strata_sema::diagnostics::Severity::Error
                    && d.code != codes::E0501_AUTHORITY_VIOLATION
            })
            .collect();
        assert!(
            non_e0501_errs.is_empty(),
            "unexpected parse/type errors in {name}: {non_e0501_errs:#?}\nall diagnostics: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
    }

    // All 27 m1_r12_challenger_1 precision repros + direct assignment / local container variants.
    let precision_cases = [
        (
            "p1_refmut_array_rh_hp",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.hp]; } }"#,
        ),
        (
            "p2_refmut_tuple_rh_hp",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut (r.h.hp, 1); } }"#,
        ),
        (
            "p3_refmut_some_rh_hp",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut Some(r.h.hp); } }"#,
        ),
        (
            "p4_refmut_record_rh_hp",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut { a: r.h.hp }; } }"#,
        ),
        (
            "p5_some_rh_hp_as_mut",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = Some(r.h.hp).as_mut(); } }"#,
        ),
        (
            "p6_some_rh_hp_take",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = Some(r.h.hp).take(); } }"#,
        ),
        (
            "p7_option_as_mut_some_rh_hp",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = Option::as_mut(&mut Some(r.h.hp)); } }"#,
        ),
        (
            "p8_refmut_array_idx_rh_hp",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.hp][0]; } }"#,
        ),
        (
            "p10_refmut_some_unwrap_rh_hp",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut Some(r.h.hp).unwrap(); } }"#,
        ),
        (
            "p11_refmut_struct_rh_hp",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut Sub { hp: r.h.hp }; } }"#,
        ),
        (
            "p15_refmut_array_rh_sub_hp",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.sub.hp]; } }"#,
        ),
        (
            "p16_refmut_array_rh_pos_x",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.pos.x]; } }"#,
        ),
        (
            "p17_refmut_array_rh_cd",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.cd]; } }"#,
        ),
        (
            "p18_refmut_array_rh_state",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.state]; } }"#,
        ),
        (
            "p19_refmut_array_rh_target",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.target]; } }"#,
        ),
        (
            "p20_refmut_array_rh_fx32",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.fx32]; } }"#,
        ),
        (
            "p21_refmut_array_vx",
            r#"@authority(client) sys ok() { for v in query(v: &Health.pos) { let _p = &mut [v.x]; } }"#,
        ),
        (
            "p22_some_vx_as_mut",
            r#"@authority(client) sys ok() { for v in query(v: &Health.pos) { let _p = Some(v.x).as_mut(); } }"#,
        ),
        (
            "p23_refmut_struct_vx",
            r#"@authority(client) sys ok() { for v in query(v: &Health.pos) { let _p = &mut Sub { hp: v.x }; } }"#,
        ),
        (
            "p24_refmut_array_rvx",
            r#"@authority(client) sys ok() { for r in query(v: &Health.pos) { let _p = &mut [r.v.x]; } }"#,
        ),
        (
            "p25_refmut_array_sub_hp",
            r#"@authority(client) sys ok() { for sub in query(sub: &Health.sub) { let _p = &mut [sub.hp]; } }"#,
        ),
        (
            "p26_refmut_array_rsub_hp",
            r#"@authority(client) sys ok() { for r in query(sub: &Health.sub) { let _p = &mut [r.sub.hp]; } }"#,
        ),
        (
            "n22_arr_if_rh_hp",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [if true { r.h.hp } else { 0.0 }]; } }"#,
        ),
        (
            "n23_some_if_vx_as_mut",
            r#"@authority(client) sys ok() { for v in query(v: &Health.pos) { let _p = Some(if true { v.x } else { 0.0 }).as_mut(); } }"#,
        ),
        (
            "x1_arr_field_elem_in_temp_arr",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.arr[0]]; } }"#,
        ),
        (
            "x2_arr_field_elem_in_some_as_mut",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = Some(r.h.arr[0]).as_mut(); } }"#,
        ),
        (
            "x3_arr_term_elem_in_temp_arr",
            r#"@authority(client) sys ok() { for a in query(a: &Health.arr) { let _p = &mut [a[0]]; } }"#,
        ),
        // Direct assignment, compound assignment, and local container precision variants
        (
            "dir_arr_rh_hp_assign_and_add",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { [r.h.hp][0] = 0.0; [r.h.hp][0] += 1.0; } }"#,
        ),
        (
            "dir_arr_vx_assign_and_add",
            r#"@authority(client) sys ok() { for v in query(v: &Health.pos) { [v.x][0] = 0.0; [v.x][0] += 1.0; } }"#,
        ),
        (
            "dir_arr_a0_assign",
            r#"@authority(client) sys ok() { for a in query(a: &Health.arr) { [a[0]][0] = 0.0; } }"#,
        ),
        (
            "dir_arr_rh_arr0_assign",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { [r.h.arr[0]][0] = 0.0; } }"#,
        ),
        (
            "dir_sub_vx_assign_and_add",
            r#"@authority(client) sys ok() { for v in query(v: &Health.pos) { Sub { hp: v.x }.hp = 0.0; Sub { hp: v.x }.hp += 1.0; } }"#,
        ),
        (
            "dir_sub_rh_hp_assign",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { Sub { hp: r.h.hp }.hp = 0.0; } }"#,
        ),
        (
            "local_containers_rh_hp",
            r#"@authority(client) sys ok() {
                for r in query(h: &Health) {
                    let mut a = [r.h.hp]; a[0] = 0.0;
                    let mut rec = { a: r.h.hp }; rec.a = 0.0;
                    let mut o = Some(r.h.hp); let _p = o.as_mut();
                }
            }"#,
        ),
        (
            "local_arr_rh_scalar_field_in_temp_arr",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let arr = [r.h]; let _p = &mut [arr[0].hp]; } }"#,
        ),
    ];

    for (name, body) in precision_cases {
        assert_probe(name, body, false);
    }

    // Critical soundness guards: direct borrows/mutations & non-scalar containers MUST emit E0501.
    let soundness_guards = [
        (
            "guard_refmut_rh_hp",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut r.h.hp; } }"#,
        ),
        (
            "guard_set_rh_hp",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { r.h.hp = 0.0; } }"#,
        ),
        (
            "guard_add_rh_hp",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { r.h.hp += 1.0; } }"#,
        ),
        (
            "guard_refmut_vx",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { let _p = &mut v.x; } }"#,
        ),
        (
            "guard_set_vx",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { v.x = 0.0; } }"#,
        ),
        (
            "guard_refmut_sub_hp",
            r#"@authority(client) sys cheat() { for sub in query(sub: &Health.sub) { let _p = &mut sub.hp; } }"#,
        ),
        (
            "guard_set_sub_hp",
            r#"@authority(client) sys cheat() { for sub in query(sub: &Health.sub) { sub.hp = 0.0; } }"#,
        ),
        (
            "guard_refmut_a0",
            r#"@authority(client) sys cheat() { for a in query(a: &Health.arr) { let _p = &mut a[0]; } }"#,
        ),
        (
            "guard_set_a0",
            r#"@authority(client) sys cheat() { for a in query(a: &Health.arr) { a[0] = 0.0; } }"#,
        ),
        (
            "guard_refmut_rh_arr0",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut r.h.arr[0]; } }"#,
        ),
        (
            "guard_set_rh_arr0",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { r.h.arr[0] = 0.0; } }"#,
        ),
        (
            "guard_some_refmut_rh_hp",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = Some(&mut r.h.hp); } }"#,
        ),
        (
            "guard_arr_refmut_vx",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { let _p = [&mut v.x]; } }"#,
        ),
        (
            "guard_rec_refmut_sub_hp",
            r#"@authority(client) sys cheat() { for sub in query(sub: &Health.sub) { let _p = { p: &mut sub.hp }; } }"#,
        ),
        (
            "guard_refmut_arr_rh_pos",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut [r.h.pos]; } }"#,
        ),
        (
            "guard_refmut_arr_rh_sub",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut [r.h.sub]; } }"#,
        ),
        (
            "guard_refmut_arr_rh_flags",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut [r.h.flags]; } }"#,
        ),
        (
            "guard_refmut_arr_rh",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut [r.h]; } }"#,
        ),
        (
            "guard_refmut_some_rh",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut Some(r.h); } }"#,
        ),
        (
            "guard_some_rh_sub_unwrap_set",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { Some(r.h.sub).unwrap().hp = 0.0; } }"#,
        ),
        (
            "guard_submixed_whole",
            r#"@authority(client) sys cheat() { for r in query(x: &Health.hp, v: &Health.pos) { let _p = &mut SubMixed { hp: r.x, pos: r.v }; } }"#,
        ),
        (
            "guard_submixed_pos",
            r#"@authority(client) sys cheat() { for r in query(x: &Health.hp, v: &Health.pos) { let _p = &mut SubMixed { hp: r.x, pos: r.v }.pos; } }"#,
        ),
        (
            "guard_refmut_arr_v",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { let _p = &mut [v]; } }"#,
        ),
        (
            "guard_arr_v_idx_x_set",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.pos) { [v][0].x = 0.0; } }"#,
        ),
        (
            "guard_rec_row_a_x_set",
            r#"@authority(client) sys cheat() { for r in query(x: &Health.hp) { { a: r }.a.x = 0.0; } }"#,
        ),
        (
            "guard_local_arr_rh_field_set",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let mut arr = [r.h]; arr[0].hp = 0.0; } }"#,
        ),
        (
            "guard_local_arr_rh_nonscalar_pos_in_temp_arr",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let arr = [r.h]; let _p = &mut [arr[0].pos]; } }"#,
        ),
    ];

    for (name, body) in soundness_guards {
        assert_probe(name, body, true);
    }
}

#[test]
fn m1_r14_regression_swizzle_bitset_option_scalar_precision() {
    fn assert_probe(name: &str, body: &str, expect_e0501: bool) {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);

struct Sub {{ hp: f32 }}
struct OptSub {{ o: Option<f32>, s: Option<Sub> }}

@authority(server)
component Health {{
    hp: f32 = 100.0,
    pos: vec2 = vec2(0.0, 0.0),
    iv2: ivec2 = ivec2(1, 2),
    iv3: ivec3 = ivec3(1, 2, 3),
    uv2: uvec2 = uvec2(1, 2),
    flags: BitSet<64>,
    opt_hp: Option<f32> = None,
    opt_sub: OptSub,
    opt_s: Option<Sub> = None,
    q_lc: quat = quat(0.0, 0.0, 0.0, 1.0),
    col8_lc: rgba8 = 0,
    q_uc: Quat = quat(0.0, 0.0, 0.0, 1.0),
    col8_uc: Rgba8 = 0
}}

{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        let non_e0501_errs: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| {
                d.severity == strata_sema::diagnostics::Severity::Error
                    && d.code != codes::E0501_AUTHORITY_VIOLATION
            })
            .collect();
        assert!(
            non_e0501_errs.is_empty(),
            "unexpected parse/type errors in {name}: {non_e0501_errs:#?}\nall diagnostics: {:#?}",
            res.diagnostics
        );
        let e0501: Vec<_> = res
            .diagnostics
            .iter()
            .filter(|d| d.code == codes::E0501_AUTHORITY_VIOLATION)
            .collect();
        if expect_e0501 {
            assert!(
                !e0501.is_empty(),
                "expected >= 1 E0501_AUTHORITY_VIOLATION in {name}, got 0:\n{:#?}",
                res.diagnostics
            );
        } else {
            assert!(
                e0501.is_empty(),
                "expected 0 E0501_AUTHORITY_VIOLATION in {name}, got {e0501:#?}"
            );
        }
    }

    let precision_cases = [
        // Class 1: ivec2 / ivec3 / uvec2 2- and 3-char swizzles + Quat.w + Rgba8
        (
            "iv1_iv2_xy_x",
            r#"@authority(client) sys ok() { for v in query(v: &Health.iv2) { let _p = &mut [v.xy.x]; } }"#,
        ),
        (
            "iv2_iv2_yx_y",
            r#"@authority(client) sys ok() { for v in query(v: &Health.iv2) { let _p = &mut [v.yx.y]; } }"#,
        ),
        (
            "p_iv2_arr_idx",
            r#"@authority(client) sys ok() { for v in query(v: &Health.iv2) { let _p = &mut [v.xy.x][0]; } }"#,
        ),
        (
            "p_iv2_some",
            r#"@authority(client) sys ok() { for v in query(v: &Health.iv2) { let _p = Some(v.xy.x).as_mut(); } }"#,
        ),
        (
            "p_iv2_rec",
            r#"@authority(client) sys ok() { for v in query(v: &Health.iv2) { let _p = &mut { a: v.xy.x }; } }"#,
        ),
        (
            "p_if_iv2_xy_x",
            r#"@authority(client) sys ok() { for v in query(v: &Health.iv2) { let _p = &mut [if true { v.xy.x } else { 0 }]; } }"#,
        ),
        (
            "iv3_iv3_xyz_z",
            r#"@authority(client) sys ok() { for v in query(v: &Health.iv3) { let _p = &mut [v.xyz.z]; } }"#,
        ),
        (
            "iv4_uv2_xy_x",
            r#"@authority(client) sys ok() { for v in query(v: &Health.uv2) { let _p = &mut [v.xy.x]; } }"#,
        ),
        (
            "iv5_rh_iv2_xy_x",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.iv2.xy.x]; } }"#,
        ),
        (
            "iv6_rh_iv3_zyx_x",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.iv3.zyx.x]; } }"#,
        ),
        (
            "iv7_uv2_yx_x",
            r#"@authority(client) sys ok() { for v in query(v: &Health.uv2) { let _p = &mut [v.yx.x]; } }"#,
        ),
        (
            "quat_w_lc",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.q_lc.w]; } }"#,
        ),
        (
            "rgba8_lc",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.col8_lc]; } }"#,
        ),
        (
            "quat_w_uc",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.q_uc.w]; } }"#,
        ),
        (
            "rgba8_uc",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.col8_uc]; } }"#,
        ),
        // Class 2: BitSet<N> bool element projections
        (
            "f1_flags_idx",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.flags[0]]; } }"#,
        ),
        (
            "p_flags_some",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = Some(r.h.flags[0]).as_mut(); } }"#,
        ),
        (
            "p_if_flags0",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [if true { r.h.flags[0] } else { false }]; } }"#,
        ),
        (
            "f2_flags_term_idx",
            r#"@authority(client) sys ok() { for flags in query(flags: &Health.flags) { let _p = &mut [flags[0]]; } }"#,
        ),
        (
            "p_flags_rec",
            r#"@authority(client) sys ok() { for flags in query(flags: &Health.flags) { let _p = &mut { a: flags[0] }; } }"#,
        ),
        // Class 3: Option<scalar> .unwrap() / .unwrap_or() / .expect() / Some(...)
        (
            "op1_opt_hp_unwrap",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.opt_hp.unwrap()]; } }"#,
        ),
        (
            "op2_opt_hp_unwrap_or",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.opt_hp.unwrap_or(0.0)]; } }"#,
        ),
        (
            "op2b_opt_hp_expect",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.opt_hp.expect("hp")]; } }"#,
        ),
        (
            "op3_opt_hp_some_as_mut",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = Some(r.h.opt_hp).as_mut(); } }"#,
        ),
        (
            "p_opt_some_take",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = Some(r.h.opt_hp).take(); } }"#,
        ),
        (
            "p_opt_unwrap_some",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = Some(r.h.opt_hp.unwrap()).as_mut(); } }"#,
        ),
        (
            "op4_opt_hp_term_unwrap",
            r#"@authority(client) sys ok() { for o in query(o: &Health.opt_hp) { let _p = &mut [o.unwrap()]; } }"#,
        ),
        (
            "op5_opt_hp_term_some_as_mut",
            r#"@authority(client) sys ok() { for o in query(o: &Health.opt_hp) { let _p = Some(o).as_mut(); } }"#,
        ),
        (
            "op6_opt_sub_o_unwrap",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _p = &mut [r.h.opt_sub.o.unwrap()]; } }"#,
        ),
        (
            "op7_assoc_option_unwrap_and_unwrap_or",
            r#"@authority(client) sys ok() { for r in query(h: &Health) { let _a = &mut [Option::unwrap(r.h.opt_hp)]; let _b = &mut [Option::unwrap_or(r.h.opt_hp, 0.0)]; } }"#,
        ),
    ];

    for (name, body) in precision_cases {
        assert_probe(name, body, false);
    }

    let soundness_guards = [
        // Class 1 guards
        (
            "guard_refmut_arr_iv2_xy",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.iv2) { let _p = &mut [v.xy]; } }"#,
        ),
        (
            "guard_refmut_v_xy_x",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.iv2) { let _p = &mut v.xy.x; } }"#,
        ),
        (
            "guard_set_v_xy_x",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.iv2) { v.xy.x = 0; } }"#,
        ),
        (
            "guard_invalid_iv2_xz_x",
            r#"@authority(client) sys cheat() { for v in query(v: &Health.iv2) { let _p = &mut [v.xz.x]; } }"#,
        ),
        (
            "guard_refmut_arr_quat_lc",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut [r.h.q_lc]; } }"#,
        ),
        (
            "guard_refmut_arr_quat_uc",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut [r.h.q_uc]; } }"#,
        ),
        (
            "guard_refmut_col8_uc",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut r.h.col8_uc; } }"#,
        ),
        // Class 2 guards
        (
            "guard_refmut_arr_flags",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut [r.h.flags]; } }"#,
        ),
        (
            "guard_refmut_flags_0",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut r.h.flags[0]; } }"#,
        ),
        (
            "guard_set_flags_0",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { r.h.flags[0] = true; } }"#,
        ),
        (
            "guard_set_flags_term_0",
            r#"@authority(client) sys cheat() { for flags in query(flags: &Health.flags) { flags[0] = true; } }"#,
        ),
        // Class 3 guards
        (
            "guard_refmut_opt_hp",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut r.h.opt_hp; } }"#,
        ),
        (
            "guard_set_opt_hp_none",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { r.h.opt_hp = None; } }"#,
        ),
        (
            "guard_opt_hp_as_mut",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = r.h.opt_hp.as_mut(); } }"#,
        ),
        (
            "guard_refmut_opt_hp_unwrap",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut r.h.opt_hp.unwrap(); } }"#,
        ),
        (
            "guard_some_opt_s_as_mut",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = Some(r.h.opt_s).as_mut(); } }"#,
        ),
        (
            "guard_some_rh_as_mut",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = Some(r.h).as_mut(); } }"#,
        ),
        (
            "guard_refmut_arr_opt_s_unwrap",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut [r.h.opt_s.unwrap()]; } }"#,
        ),
        (
            "guard_opt_s_unwrap_hp_set",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { r.h.opt_s.unwrap().hp = 0.0; } }"#,
        ),
        (
            "guard_opt_sub_s_unwrap",
            r#"@authority(client) sys cheat() { for r in query(h: &Health) { let _p = &mut [r.h.opt_sub.s.unwrap()]; } }"#,
        ),
        (
            "guard_some_1_unwrap_or_x_refmut",
            r#"@authority(client) sys cheat() { for x in query(x: &Health.hp) { let _p = &mut Some(1.0).unwrap_or(x); } }"#,
        ),
        (
            "guard_opt_query_health_unwrap",
            r#"@authority(client) sys cheat() { for o in query(o: ?&Health) { let _p = &mut [o.unwrap()]; } }"#,
        ),
        (
            "guard_opt_query_health_pos_unwrap",
            r#"@authority(client) sys cheat() { for o in query(o: ?&Health.pos) { let _p = &mut [o.unwrap()]; } }"#,
        ),
        (
            "guard_opt_query_health_some_as_mut",
            r#"@authority(client) sys cheat() { for o in query(o: ?&Health) { let _p = Some(o).as_mut(); } }"#,
        ),
    ];

    for (name, body) in soundness_guards {
        assert_probe(name, body, true);
    }
}

#[test]
fn challenger1_class_a_resource_and_struct_non_pod_fields_precision_and_soundness() {
    let ok_src = r#"module test::class_a_ok @version(1.0.0);

struct Stats {
    hp: Option<f32>,
    delta: vec3,
}

@authority(server)
resource ServerVault {
    stats: Stats,
    bonus: Option<i32>,
}

@authority(server)
component Boss {
    stats: Stats,
}

@predicted
sys read_non_pod_copies(vault: &res ServerVault) {
    let copied_opt: Option<i32> = vault.bonus;
    let copied_hp: Option<f32> = vault.stats.hp;
    let copied_dx: f32 = vault.stats.delta.x;
    for b in query(boss: &Boss) {
        let local_b = boss.stats.delta.y;
        let _ = (copied_opt, copied_hp, copied_dx, local_b);
    }
}
"#;
    let ok_mod = analyze_source("class_a_ok.strata", ok_src);
    assert!(
        ok_mod.ok(),
        "Class A non-POD resource/struct scalar reads must pass without E0501: {:#?}",
        ok_mod.diagnostics
    );

    let bad_src = r#"module test::class_a_bad @version(1.0.0);

struct Stats {
    hp: Option<f32>,
    delta: vec3,
}

@authority(server)
resource ServerVault {
    stats: Stats,
}

@predicted
sys mutate_non_pod_server_resource(vault: &mut res ServerVault) {
    vault.stats.delta.x = 42.0;
}
"#;
    let bad_mod = analyze_source("class_a_bad.strata", bad_src);
    assert!(
        bad_mod
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0501_AUTHORITY_VIOLATION),
        "Mutating @authority(server) non-POD resource field in @net sys must emit E0501: {:#?}",
        bad_mod.diagnostics
    );
}

#[test]
fn challenger1_class_b_if_match_array_and_option_borrow_query_modes_and_fix64() {
    use strata_sema::access::TermAccessMode;
    use strata_sema::hir::{HirExpr, HirStmt};

    let ok_src = r#"module test::class_b_ok @version(1.0.0);

@authority(server)
component Health { hp: f32 = 100.0 }

component Timer { elapsed: fix64 = 0.0 }

@predicted
sys branch_array_and_option_queries(flag: bool) {
    for row in query(h: Option<&Health>) {
        let copy_hp = if flag {
            match h {
                Some(inner) => inner.hp,
                None => 0.0,
            }
        } else {
            1.0
        };
        let arr = [copy_hp, 2.5];
        let total = arr[0] + arr[1];
        let _ = total;
    }
}

sys fix64_and_opt_mut() {
    for row in query(t: &mut Timer, h: Option<&mut Health>) {
        let dt: f32 = 0.5;
        t.elapsed += dt;
        let _mixed = [1, 2.0];
        if let Some(hp) = h {
            hp.hp += 1.0;
        }
    }
}
"#;
    let analyzed = analyze_source("class_b_ok.strata", ok_src);
    assert!(
        analyzed.ok(),
        "Class B If/Match/Array/Option<&T>/Fix64 program must analyze cleanly: {:#?}",
        analyzed.diagnostics
    );

    // Verify Option<&Health> -> OptionalRead and Option<&mut Health> -> OptionalWrite
    let c0 = analyzed
        .callables
        .iter()
        .find(|c| c.name == "branch_array_and_option_queries")
        .expect("callable 0");
    assert_eq!(
        c0.access.queries[0].terms[0].mode,
        TermAccessMode::OptionalRead
    );

    let c1 = analyzed
        .callables
        .iter()
        .find(|c| c.name == "fix64_and_opt_mut")
        .expect("callable 1");
    assert_eq!(
        c1.access.queries[0].terms[1].mode,
        TermAccessMode::OptionalWrite
    );

    // Verify Fix64 compound assign inserted an explicit HirExpr::Cast
    fn has_cast_expr(e: &HirExpr) -> bool {
        match e {
            HirExpr::Cast { .. } => true,
            HirExpr::Binary { lhs, rhs, .. } => has_cast_expr(lhs) || has_cast_expr(rhs),
            HirExpr::Block { stmts, tail, .. } => {
                stmts.iter().any(has_cast_stmt) || tail.as_deref().is_some_and(has_cast_expr)
            }
            HirExpr::ArrayLit { elems, .. } | HirExpr::Tuple { elems, .. } => {
                elems.iter().any(has_cast_expr)
            }
            HirExpr::If {
                cond,
                then_stmts,
                then_tail,
                else_stmts,
                else_tail,
                ..
            } => {
                has_cast_expr(cond)
                    || then_stmts.iter().any(has_cast_stmt)
                    || then_tail.as_deref().is_some_and(has_cast_expr)
                    || else_stmts.iter().any(has_cast_stmt)
                    || else_tail.as_deref().is_some_and(has_cast_expr)
            }
            HirExpr::For(f) => f.body.iter().any(has_cast_stmt),
            _ => false,
        }
    }
    fn has_cast_stmt(s: &HirStmt) -> bool {
        match s {
            HirStmt::Let { value, .. } | HirStmt::Assign { value, .. } => has_cast_expr(value),
            HirStmt::Expr(e) => has_cast_expr(e),
            _ => false,
        }
    }
    assert!(
        c1.body.iter().any(has_cast_stmt),
        "Fix64 += f32 and [1, 2.0] should lower explicit HirExpr::Cast nodes"
    );

    // Soundness guard: mutating ECS borrow selected through If/Match/ArrayLit MUST emit E0501
    let bad_src = r#"module test::class_b_bad @version(1.0.0);

@authority(server)
component Health { hp: f32 = 100.0 }

@predicted
sys bad_branch_write(flag: bool) {
    for row in query(h: &mut Health) {
        let arr = [h];
        let picked = if flag { arr[0] } else { h };
        picked.hp -= 5.0;
    }
}
"#;
    let bad_mod = analyze_source("class_b_bad.strata", bad_src);
    assert!(
        bad_mod
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0501_AUTHORITY_VIOLATION),
        "Writing through &mut Health routed via ArrayLit+If in @net sys must emit E0501: {:#?}",
        bad_mod.diagnostics
    );
}

#[test]
fn verify_effects_enforces_despawns_triggers_and_emits() {
    let missing_src = r#"module test::effects_bad @version(1.0.0);

component Target { id: i32 = 0 }
event Hit { dmg: i32 }
event Pulse { seq: i32 }

sys bad_effects() effects(reads: [Target]) {
    for row in query(e: Entity, t: &Target) {
        let _ = t.id;
        despawn(e);
        trigger(e, Hit { dmg: 5 });
        emit(Pulse { seq: 1 });
    }
}
"#;
    let bad_mod = analyze_source("effects_bad.strata", missing_src);
    let e0204_msgs: Vec<&str> = bad_mod
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::E0204_EFFECTS_MISMATCH)
        .map(|d| d.message.as_str())
        .collect();
    assert!(
        e0204_msgs.iter().any(|m| m.contains("despawn")),
        "expected E0204 for missing despawns: {e0204_msgs:?}"
    );
    assert!(
        e0204_msgs.iter().any(|m| m.contains("triggers")),
        "expected E0204 for missing triggers: {e0204_msgs:?}"
    );
    assert!(
        e0204_msgs.iter().any(|m| m.contains("emits")),
        "expected E0204 for missing emits: {e0204_msgs:?}"
    );

    let ok_src = r#"module test::effects_ok @version(1.0.0);

component Target { id: i32 = 0 }
event Hit { dmg: i32 }
event Pulse { seq: i32 }

sys good_effects() effects(reads: [Entity, Target], despawns: [Entity], triggers: [Hit], emits: [Pulse]) {
    for row in query(e: Entity, t: &Target) {
        let _ = t.id;
        despawn(e);
        trigger(e, Hit { dmg: 5 });
        emit(Pulse { seq: 1 });
    }
}
"#;
    let ok_mod = analyze_source("effects_ok.strata", ok_src);
    assert!(
        ok_mod.ok(),
        "Explicit effects(despawns, triggers, emits) must pass: {:#?}",
        ok_mod.diagnostics
    );
}

#[test]
fn salsa_per_item_body_edit_skips_layouts_and_untouched_sibling_item() {
    let src_v1 = r#"module test::per_item @version(1.0.0);

component Pos { x: f32 = 0.0 }

sys sys_a() {
    for row in query(p: &mut Pos) {
        row.p.x += 1.0;
    }
}

sys sys_b() {
    for row in query(p: &mut Pos) {
        row.p.x += 2.0;
    }
}
"#;
    let mut db = SemaDb::new();
    let file = db.new_source("per_item.strata", src_v1);
    let _ = db.analyze_file(file);
    let initial_exec = db.take_executed_queries();
    let initial_item_runs = initial_exec
        .iter()
        .filter(|q| q.contains("analyze_item"))
        .count();
    assert_eq!(
        initial_item_runs, 2,
        "initial run must analyze both sys_a and sys_b: {initial_exec:?}"
    );

    // Body-only edit inside `sys_a` leaving `Pos` and `sys_b` unchanged:
    let src_v2 = src_v1.replace("row.p.x += 1.0;", "row.p.x += 3.5;");
    file.set_text(&mut db).to(src_v2);
    let _ = db.analyze_file(file);
    let delta_exec = db.take_executed_queries();

    assert!(
        !delta_exec.iter().any(|q| q.contains("resolve_layouts")),
        "body-only edit must trigger 0 resolve_layouts runs: {delta_exec:?}"
    );
    assert!(
        !delta_exec.iter().any(|q| q.contains("module_env_summary")),
        "body-only edit must trigger 0 module_env_summary runs: {delta_exec:?}"
    );
    let delta_item_runs = delta_exec
        .iter()
        .filter(|q| q.contains("analyze_item"))
        .count();
    assert_eq!(
        delta_item_runs, 1,
        "editing sys_a body must re-analyze ONLY 1 item (skipping untouched sys_b): {delta_exec:?}"
    );
}

#[test]
fn step2_iter3_enum_repr16_nested_str_e0103_and_single_term_option_alias_typing() {
    use strata_sema::hir::{HirExpr, HirStmt};
    use strata_sema::types::Ty;

    // 1. C1-4: Enum discriminants > 255 and @repr(u16)
    let enum_src = r#"module test::enum16 @version(1.0.0);

enum Kind16 {
    Low = 1,
    High = 60000,
}

@repr(u16)
enum Explicit16 {
    Zero = 0,
    One = 1,
}

enum NegEnum {
    MinusOne = -1,
    PlusOne = 1,
}

component Box16 {
    k: Kind16 = Kind16::High,
    arr: [Kind16; 3] = [Kind16::Low, Kind16::High, Kind16::Low],
    e: Explicit16 = Explicit16::One,
    n: NegEnum = NegEnum::MinusOne,
}
"#;
    let enum_res = analyze_source("enum16.strata", enum_src);
    assert!(
        enum_res.ok(),
        "enum16 sema failed: {:?}",
        enum_res.diagnostics
    );
    assert_eq!(enum_res.enums.get("Kind16").unwrap().repr_bytes, 2);
    assert_eq!(enum_res.enums.get("Explicit16").unwrap().repr_bytes, 2);
    assert_eq!(enum_res.enums.get("NegEnum").unwrap().repr_bytes, 4);
    assert_eq!(
        enum_res.enums.get("NegEnum").unwrap().variants,
        vec![("MinusOne".to_owned(), -1), ("PlusOne".to_owned(), 1)]
    );
    let box_layout = enum_res.layouts.get("test::enum16::Box16").unwrap();
    // 2 + 6 + 2 + (2 pad) + 4 = 16 bytes
    assert_eq!(
        box_layout.size, 16,
        "Box16 layout size mismatch: {box_layout:?}"
    );

    // 2. C1-5a: `str` inside nested struct & component must emit E0103 (not silently collapse to ZST),
    // while empty 0-field tag component remains a valid 0-byte ZST.
    let bad_str_src = r#"module test::bad_str @version(1.0.0);

struct BadStruct {
    label: str = "init",
    x: i32 = 1,
}

component EWithStr {
    s: BadStruct,
    hp: f32 = 1.0,
}

component EmptyTag {}
"#;
    let bad_str_res = analyze_source("bad_str.strata", bad_str_src);
    assert!(
        bad_str_res
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0103_INVALID_ABI_POD_FIELD),
        "str in struct/component must emit E0103_INVALID_ABI_POD_FIELD: {:?}",
        bad_str_res.diagnostics
    );
    assert!(
        bad_str_res
            .layouts
            .get("test::bad_str::EmptyTag")
            .is_some_and(|l| l.size == 0),
        "0-field EmptyTag component must remain a valid 0-byte ZST"
    );

    // 3. C2-2: Single-term Option<&mut OtherComp> `.expect()` / `if let Some` / `match` alias typing
    let opt_alias_src = r#"module test::opt_alias @version(1.0.0);

tag Tag;

component OtherComp {
    pad: i32 = 123,
    hp: f32 = 55.0,
}

sys test_single_alias() {
    for oc in query(oc: Option<&mut OtherComp>).with<Tag>() {
        if oc.is_some() {
            let op = oc.expect("single oc");
            let op2 = op;
            op2.hp += 3.0;
        }
        if let Some(op3) = oc {
            let op4 = op3;
            op4.hp += 1.0;
        }
        match oc {
            Some(op5) => {
                let op6 = op5;
                op6.hp += 2.0;
            },
            None => {},
        }
    }
}
"#;
    let opt_res = analyze_source("opt_alias.strata", opt_alias_src);
    assert!(
        opt_res.ok(),
        "opt_alias sema failed: {:?}",
        opt_res.diagnostics
    );
    let f = &opt_res.callables[0];
    let HirStmt::Expr(HirExpr::For(hf)) = &f.body[0] else {
        panic!("expected for loop");
    };
    let mut assign_target_tys = Vec::new();
    fn collect_assign_bases(stmts: &[HirStmt], out: &mut Vec<Ty>) {
        for s in stmts {
            match s {
                HirStmt::Assign {
                    target: strata_sema::hir::HirLValue::Field { base, .. },
                    ..
                } => out.push(base.ty().clone()),
                HirStmt::Expr(HirExpr::If {
                    then_stmts,
                    else_stmts,
                    ..
                }) => {
                    collect_assign_bases(then_stmts, out);
                    collect_assign_bases(else_stmts, out);
                }
                HirStmt::Expr(HirExpr::Match(m)) => {
                    for a in &m.arms {
                        if let HirExpr::Block { stmts, .. } = &a.body {
                            collect_assign_bases(stmts, out);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    collect_assign_bases(&hf.body, &mut assign_target_tys);
    assert_eq!(
        assign_target_tys.len(),
        3,
        "expected 3 op*.hp += assignments"
    );
    for (idx, ty) in assign_target_tys.iter().enumerate() {
        assert!(
            matches!(ty, Ty::Borrow { mutable: true, inner } if matches!(inner.as_ref(), Ty::Named(n) if n == "OtherComp")),
            "assignment #{idx} base must be &mut OtherComp (not Entity fallback), got {ty:?}"
        );
    }
}

#[test]
fn sema_step2_iter4_signed_enums_repr_u32_neg_rejection_and_query_row_alias_forms() {
    let pos_src = r#"module test::iter4_enum_pos @version(1.0.0);

enum NegAuto {
    Neg = -5,
    Zero = 0,
    Pos = 5,
}

@repr(i32)
enum NegExplicit {
    MinNeg = -300,
    BigPos = 70000,
}

@repr(i32)
enum PosSigned {
    A = 0,
    B = 1,
}

enum PosUnsigned32 {
    Low = 0,
    High = 70000,
}

component BoxSigned {
    a: NegAuto = NegAuto::Neg,
    b: NegExplicit = NegExplicit::MinNeg,
    c: PosSigned = PosSigned::A,
    d: PosUnsigned32 = PosUnsigned32::High,
}
"#;
    let res = analyze_source("iter4_enum_pos.strata", pos_src);
    assert!(
        res.ok(),
        "iter4_enum_pos sema failed: {:?}",
        res.diagnostics
    );
    let neg_auto = res.enums.get("NegAuto").unwrap();
    assert_eq!(neg_auto.repr_bytes, 4);
    assert!(neg_auto.is_signed);
    let neg_exp = res.enums.get("NegExplicit").unwrap();
    assert_eq!(neg_exp.repr_bytes, 4);
    assert!(neg_exp.is_signed);
    let pos_sig = res.enums.get("PosSigned").unwrap();
    assert_eq!(pos_sig.repr_bytes, 4);
    assert!(pos_sig.is_signed);
    let pos_u32 = res.enums.get("PosUnsigned32").unwrap();
    assert_eq!(pos_u32.repr_bytes, 4);
    assert!(!pos_u32.is_signed);

    let layout = res.layouts.get("test::iter4_enum_pos::BoxSigned").unwrap();
    assert_eq!(layout.fields[0].bam_field_kind, BamFieldKind::I32.0);
    assert_eq!(layout.fields[0].type_tag, "i32");
    assert_eq!(layout.fields[1].bam_field_kind, BamFieldKind::I32.0);
    assert_eq!(layout.fields[1].type_tag, "i32");
    assert_eq!(layout.fields[2].bam_field_kind, BamFieldKind::I32.0);
    assert_eq!(layout.fields[2].type_tag, "i32");
    assert_eq!(layout.fields[3].bam_field_kind, BamFieldKind::U32.0);
    assert_eq!(layout.fields[3].type_tag, "u32");

    let bad_u32_neg = r#"module test::iter4_bad_u32_neg @version(1.0.0);

@repr(u32)
enum BadU32Neg {
    Neg = -1,
    Pos = 1,
}
"#;
    let bad_res = analyze_source("iter4_bad_u32_neg.strata", bad_u32_neg);
    assert!(
        bad_res
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0103_INVALID_ABI_POD_FIELD),
        "@repr(u32) with negative discriminant must emit E0103_INVALID_ABI_POD_FIELD: {:?}",
        bad_res.diagnostics
    );
}

#[test]
fn sema_step2_iter5_query_handle_reassign_fn_query_and_enum_repr_overflow() {
    // 1. QueryRow / SingleTermPtr reassignment rejection (unconditional, conditional, query_one, for, optional)
    let reassign_cases = [
        (
            "cond_reassign",
            r#"
sys step_reassign_cond() {
    let mut r = query_one(o: &mut Out).with<TagA>().without<TagB>().on(ObjA).unwrap();
    let other = query_one(o: &mut Out).with<TagB>().without<TagA>().on(ObjB).unwrap();
    if r.o.val == 1 {
        r = other;
    }
    r.o.val += 7;
}
"#,
        ),
        (
            "direct_q1_reassign",
            r#"
sys step_assign_direct_q1() {
    let mut r = query_one(o: &mut Out).with<TagA>().without<TagB>().on(ObjA).unwrap();
    r = query_one(o: &mut Out).with<TagB>().without<TagA>().on(ObjB).unwrap();
    r.o.val += 5;
}
"#,
        ),
        (
            "for_row_reassign",
            r#"
sys step_for_reassign() {
    let other = query_one(o: &mut Out).with<TagB>().without<TagA>().on(ObjB).unwrap();
    for mut row in query(o: &mut Out).with<TagA>().without<TagB>() {
        row = other;
    }
}
"#,
        ),
        (
            "opt_single_term_reassign",
            r#"
sys step_opt_reassign() {
    let other = query_one(o: &mut Out).with<TagB>().without<TagA>().on(ObjB).unwrap();
    for oc in query(oc: Option<&mut Out>).with<TagA>().without<TagB>() {
        if let Some(mut op) = oc {
            op = other.o;
        }
    }
}
"#,
        ),
    ];
    for (name, body) in reassign_cases {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);
tag TagA;
tag TagB;
component Out {{ val: i32 = 0 }}
object ObjA {{ Out {{ val: 1 }}, TagA }}
object ObjB {{ Out {{ val: 2 }}, TagB }}
{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0201_ALIASING_CONFLICT
                    && d.message.contains("cannot be reassigned")),
            "{name}: expected E0201_ALIASING_CONFLICT reassignment diagnostic, got: {:?}",
            res.diagnostics
        );
    }

    // Positive controls: field mutation, fresh let alias, inner block shadowing, scalar value copy,
    // and projected field value write MUST remain valid.
    let valid_handle_src = r#"
module test::valid_handles @version(1.0.0);
tag TagA;
tag TagB;
component Out { val: i32 = 10 }
object ObjA { Out { val: 10 }, TagA }
object ObjB { Out { val: 20 }, TagB }

sys ok_q1(cond: bool) {
    let mut r = query_one(o: &mut Out).with<TagA>().without<TagB>().on(ObjA).unwrap();
    let other = query_one(o: &mut Out).with<TagB>().without<TagA>().on(ObjB).unwrap();
    r.o.val += 5;
    if cond {
        let r = other;
        r.o.val += 1;
    }
}

sys ok_for_alias() {
    for row in query(o: &mut Out) {
        let row2 = row;
        row2.o.val += 2;
    }
}

sys ok_proj_write() {
    for mut v in query(v: &mut Out.val) {
        let mut copy_v = v;
        copy_v = 99;
        let _ = copy_v;
        v = 42;
    }
}
"#;
    let valid_res = analyze_source("valid_handles.strata", valid_handle_src);
    assert!(
        valid_res.ok(),
        "valid QueryRow alias/field-write patterns must analyze cleanly: {:?}",
        valid_res.diagnostics
    );

    // 2. query / query_one / query_many inside non-sys helper fn must emit E0204_EFFECTS_MISMATCH
    let fn_query_cases = [
        (
            "fn_query_one_ret_i32",
            r#"
fn read_absent_wallet() -> i32 {
    let r = query_one(w: &Out).on(ObjA).unwrap();
    return r.w.val;
}
"#,
        ),
        (
            "fn_for_query",
            r#"
fn iter_out() {
    for row in query(o: &Out) {
        let _ = row.o.val;
    }
}
"#,
        ),
        (
            "fn_query_many",
            r#"
fn call_many() {
    let _ = query_many();
}
"#,
        ),
    ];
    for (name, body) in fn_query_cases {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);
component Out {{ val: i32 = 10 }}
object ObjA {{ Out {{ val: 10 }} }}
{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0204_EFFECTS_MISMATCH),
            "{name}: expected E0204_EFFECTS_MISMATCH for query in helper fn, got: {:?}",
            res.diagnostics
        );
    }

    // 3. @repr(i32) / @repr(u32) / implicit signed enum discriminant overflow checks
    let enum_overflow_cases = [
        (
            "repr_i32_gt_max",
            "@repr(i32)\nenum TooBigI32 { Big = 3000000000 }",
        ),
        (
            "repr_i32_lt_min",
            "@repr(i32)\nenum TooSmallI32 { Small = -3000000000 }",
        ),
        (
            "repr_u32_gt_max",
            "@repr(u32)\nenum TooBigU32 { Huge = 5000000000 }",
        ),
        (
            "implicit_signed_gt_max",
            "enum MixedOverflow { Neg = -1, Huge = 3000000000 }",
        ),
    ];
    for (name, decl) in enum_overflow_cases {
        let src = format!("module test::{name} @version(1.0.0);\n{decl}\n");
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0103_INVALID_ABI_POD_FIELD),
            "{name}: expected E0103_INVALID_ABI_POD_FIELD for discriminant overflow, got: {:?}",
            res.diagnostics
        );
    }

    let valid_edge_i32 = r#"
module test::edge_i32 @version(1.0.0);
@repr(i32)
enum EdgeI32 {
    Min = -2147483648,
    Max = 2147483647,
}
"#;
    let edge_res = analyze_source("edge_i32.strata", valid_edge_i32);
    assert!(
        edge_res.ok(),
        "valid @repr(i32) boundary discriminants must pass: {:?}",
        edge_res.diagnostics
    );
}

#[test]
fn sema_step2_iter6_handle_reassign_edge_cases_helper_queries_enum_u64_and_nonconst_object() {
    // 1. Optional query_one handle stored in local, QueryRow component field extraction,
    //    If with let statements before tail, Match, and Tuple destructuring must all emit E0201.
    let reassign_cases = [
        (
            "opt_row_single_if_let",
            r#"
sys bad() {
    let opt_r = query_one(o: &mut Out).with<TagA>().without<TagB>().on(ObjA);
    let other = query_one(o: &mut Out).with<TagB>().without<TagA>().on(ObjB).unwrap();
    if let Some(mut r) = opt_r {
        r = other;
    }
}
"#,
        ),
        (
            "opt_row_multi_match",
            r#"
sys bad() {
    let opt_r = query_one(o: &mut Out, ex: &Extra).with<TagA>().without<TagB>().on(ObjA);
    let other = query_one(o: &mut Out, ex: &Extra).with<TagB>().without<TagA>().on(ObjB).unwrap();
    match opt_r {
        Some(mut r) => {
            r = other;
        }
        None => {}
    }
}
"#,
        ),
        (
            "opt_row_multi_unwrap",
            r#"
sys bad() {
    let opt_r = query_one(o: &mut Out, ex: &Extra).with<TagA>().without<TagB>().on(ObjA);
    let other = query_one(o: &mut Out, ex: &Extra).with<TagB>().without<TagA>().on(ObjB).unwrap();
    let mut r = opt_r.unwrap();
    r = other;
}
"#,
        ),
        (
            "opt_row_let_else",
            r#"
sys bad() {
    let opt_r = query_one(o: &mut Out).with<TagA>().without<TagB>().on(ObjA);
    let other = query_one(o: &mut Out).with<TagB>().without<TagA>().on(ObjB).unwrap();
    let Some(mut r) = opt_r else { return; };
    r = other;
}
"#,
        ),
        (
            "comp_field_handle_extract",
            r#"
sys bad() {
    let r1 = query_one(o: &mut Out).with<TagA>().without<TagB>().on(ObjA).unwrap();
    let r2 = query_one(o: &mut Out).with<TagB>().without<TagA>().on(ObjB).unwrap();
    let mut p = r1.o;
    p = r2.o;
}
"#,
        ),
        (
            "if_expr_let_tail_handle",
            r#"
sys bad(cond: bool) {
    let r1 = query_one(o: &mut Out).with<TagA>().without<TagB>().on(ObjA).unwrap();
    let r2 = query_one(o: &mut Out).with<TagB>().without<TagA>().on(ObjB).unwrap();
    let mut r = if cond {
        let a = r1;
        a
    } else {
        let b = r2;
        b
    };
    r = r2;
}
"#,
        ),
        (
            "tuple_destructure_handle",
            r#"
sys bad() {
    let (mut r1, r2) = (
        query_one(o: &mut Out).with<TagA>().without<TagB>().on(ObjA).unwrap(),
        query_one(o: &mut Out).with<TagB>().without<TagA>().on(ObjB).unwrap(),
    );
    r1 = r2;
}
"#,
        ),
        (
            "tuple_indirect_destructure_handle",
            r#"
sys bad() {
    let q1 = query_one(o: &mut Out).with<TagA>().without<TagB>().on(ObjA).unwrap();
    let q2 = query_one(o: &mut Out).with<TagB>().without<TagA>().on(ObjB).unwrap();
    let tup = (q1, 42);
    let (mut r1, mut _n) = tup;
    _n = 99;
    r1 = q2;
}
"#,
        ),
    ];
    for (name, body) in reassign_cases {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);
tag TagA;
tag TagB;
struct Sub {{ x: i32 = 5 }}
component Out {{ val: i32 = 0, sub: Sub = Sub {{ x: 5 }} }}
component Extra {{ tag_v: i32 = 1 }}
object ObjA {{ Out {{ val: 1 }}, Extra {{ tag_v: 1 }}, TagA }}
object ObjB {{ Out {{ val: 2 }}, Extra {{ tag_v: 2 }}, TagB }}
{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0201_ALIASING_CONFLICT
                    && d.message.contains("cannot be reassigned")),
            "{name}: expected E0201_ALIASING_CONFLICT reassignment diagnostic, got: {:?}",
            res.diagnostics
        );
    }

    // Positive controls: copying struct/scalar fields from component handle (`r1.o.sub`, `r1.o.val`)
    // and non-handle tuple element reassignment must remain valid.
    let valid_src = r#"
module test::iter6_pos @version(1.0.0);
tag TagA;
tag TagB;
struct Sub { x: i32 = 5 }
component Out { val: i32 = 10, sub: Sub = Sub { x: 5 } }
object ObjA { Out { val: 10 }, TagA }
object ObjB { Out { val: 20 }, TagB }

sys ok_copies() {
    let r1 = query_one(o: &mut Out).with<TagA>().without<TagB>().on(ObjA).unwrap();
    let r2 = query_one(o: &mut Out).with<TagB>().without<TagA>().on(ObjB).unwrap();
    let mut sv = r1.o.sub;
    sv.x = 77;
    sv = r2.o.sub;
    let mut v = r1.o.val;
    v = 99;
    let tup = (r1, 42);
    let (_h, mut n) = tup;
    n = 100;
    let _ = (sv.x, v, n);
}
"#;
    let valid_res = analyze_source("iter6_pos.strata", valid_src);
    assert!(
        valid_res.ok(),
        "valid struct/scalar copy and non-handle tuple element must analyze cleanly: {:?}",
        valid_res.diagnostics
    );

    // 2. Spatial and net queries inside plain helper fn must emit E0204_EFFECTS_MISMATCH
    let fn_query_cases = [
        (
            "fn_query_disc",
            r#"
fn count_near() -> i32 {
    let mut n = 0;
    for _e in Grid.query_disc(vec2(0.0, 0.0), 5.0_m) { n += 1; }
    return n;
}
"#,
        ),
        (
            "fn_query_segment_at",
            r#"
fn count_seg() -> i32 {
    let mut n = 0;
    for _e in Hist.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(1.0, 0.0, 0.0), 1.0_m) { n += 1; }
    return n;
}
"#,
        ),
        (
            "fn_server_query",
            r#"
fn srv_read() -> i32 {
    return server_query(o: &Out).on(ObjA).unwrap().o.val;
}
"#,
        ),
        (
            "fn_client_query",
            r#"
fn cli_read() -> i32 {
    return client_query(0, o: &Out).on(ObjA).unwrap().o.val;
}
"#,
        ),
    ];
    for (name, body) in fn_query_cases {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);
component Pos2 {{ xy: vec2 = vec2(0.0, 0.0) }}
component Pos3 {{ xyz: vec3 = vec3(0.0, 0.0, 0.0) }}
component Out {{ val: i32 = 10 }}
spatial_grid Grid(cell: 4.0_m) over Pos2 by Pos2.xy;
spatial_history Hist(frames: 8) over Pos3 by Pos3.xyz;
object ObjA {{ Out {{ val: 10 }} }}
{body}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            !res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0002_PARSE_ERROR),
            "{name}: unexpected E0002_PARSE_ERROR in spatial/net query fn test: {:?}",
            res.diagnostics
        );
        assert!(
            res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0204_EFFECTS_MISMATCH),
            "{name}: expected E0204_EFFECTS_MISMATCH for query in helper fn, got: {:?}",
            res.diagnostics
        );
    }

    // 3. Enum discriminant > i64::MAX and > i128::MAX must emit E0103_INVALID_ABI_POD_FIELD
    for (name, decl) in [
        (
            "enum_gt_i64_max",
            "@repr(u32)\nenum Huge64 { A = 18446744073709551615 }",
        ),
        (
            "enum_gt_i128_max",
            "enum Huge128 { A = 9999999999999999999999999999999999999999 }",
        ),
    ] {
        let src = format!("module test::{name} @version(1.0.0);\n{decl}\n");
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0103_INVALID_ABI_POD_FIELD),
            "{name}: expected E0103_INVALID_ABI_POD_FIELD, got: {:?}",
            res.diagnostics
        );
    }

    // 4. Non-constant `if` and `@node_pure fn` calls in `object` overrides must emit E0103
    for (name, ov_expr) in [
        (
            "obj_nonconst_if",
            "(if true { 1.0_f32 } else { 0.0_f32 }) as i32",
        ),
        ("obj_nonconst_fn", "make_val()"),
    ] {
        let src = format!(
            r#"
module test::{name} @version(1.0.0);
@node_pure fn make_val() -> i32 {{ 42 }}
component Box {{ v: i32 = 0 }}
object ObjBad {{ Box {{ v: {ov_expr} }} }}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0103_INVALID_ABI_POD_FIELD),
            "{name}: expected E0103_INVALID_ABI_POD_FIELD for non-constant object override, got: {:?}",
            res.diagnostics
        );
    }
}

#[test]
fn step2_iter7_const_indirect_cycle_uvec3_and_handle_aliasing_checks() {
    // 1. Valid chained consts + all constructors (meters/ms/vec3a/quat/rgba/bits/PascalCase) pass.
    let valid_const_src = r#"
module test::iter7_valid_consts @version(1.0.0);

enum Flags {
    Bit0 = 0,
    Bit3 = 3,
}

const STEP_M: meters = meters(4.0);
const STEP_MS: ms = ms(25.0);
const CHAIN_V3A: vec3a = Vec3a(1.0, 2.0, 3.0);
const CHAIN_Q: quat = Quat(0.0, 0.0, 0.0, 1.0);
const CHAIN_COL: rgba = Rgba(0.25, 0.5, 0.75, 1.0);
const CHAIN_MASK: u64 = bits(Flags::Bit0, Flags::Bit3);

component Pod {
    dist: meters = STEP_M,
    dur: ms = STEP_MS,
    va: vec3a = CHAIN_V3A,
    q: quat = CHAIN_Q,
    col: rgba = CHAIN_COL,
    mask: u64 = CHAIN_MASK,
}

object ObjOk {
    Pod {
        dist: STEP_M,
        dur: STEP_MS,
        va: CHAIN_V3A,
        q: CHAIN_Q,
        col: CHAIN_COL,
        mask: CHAIN_MASK,
    }
}
"#;
    let res_ok = analyze_source("iter7_valid_consts.strata", valid_const_src);
    assert!(
        res_ok.ok(),
        "valid chained consts and constructors must pass: {:?}",
        res_ok.diagnostics
    );

    // 2. Non-constant `const` initializers, indirect object `const`, cyclic `const`, and `uvec3` must fail with E0103.
    let invalid_consts = [
        (
            "bad_if_const",
            "const BAD: i32 = if true { 1 } else { 2 };",
            "BAD",
        ),
        (
            "bad_fn_const",
            "@node_pure fn f() -> i32 { 1 }\nconst BAD: i32 = f();",
            "BAD",
        ),
        (
            "chained_bad_const",
            "@node_pure fn f() -> i32 { 1 }\nconst A: i32 = f();\nconst BAD: i32 = A;",
            "BAD",
        ),
        (
            "cyclic_const",
            "const CA: i32 = CB;\nconst CB: i32 = CA;",
            "CA",
        ),
        ("uvec3_ctor", "", "uvec3(1, 2, 3)"),
    ];
    for (name, preamble, ov_expr) in invalid_consts {
        let field_ty = if name == "uvec3_ctor" { "vec3" } else { "i32" };
        let src = format!(
            r#"
module test::{name} @version(1.0.0);
{preamble}
component Box {{ v: {field_ty} = 0 }}
object ObjBad {{ Box {{ v: {ov_expr} }} }}
"#
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0103_INVALID_ABI_POD_FIELD),
            "{name}: expected E0103_INVALID_ABI_POD_FIELD, got: {:?}",
            res.diagnostics
        );
    }

    // 3. E0201_ALIASING_CONFLICT for Option/Array/Tuple/FnParam handle aliasing & multi-source merges.
    let aliasing_cases = [
        (
            "some_tuple_borrow",
            r#"
sys s(e1: Entity, e2: Entity) {
    let q1 = query_one(o: &mut Out).on(e1).unwrap();
    let mut opt_t = Some((q1, 1_i32));
    let q2 = query_one(o: &mut Out).on(e2).unwrap();
    opt_t = Some((q2, 2_i32));
}
"#,
        ),
        (
            "array_elem_reassign",
            r#"
sys s(e1: Entity, e2: Entity) {
    let q1 = query_one(o: &mut Out).on(e1).unwrap();
    let q2 = query_one(o: &mut Out).on(e2).unwrap();
    let mut arr = [q1.o, q2.o];
    arr[0] = q2.o;
}
"#,
        ),
        (
            "opt_or_merge",
            r#"
sys s(e1: Entity, e2: Entity) {
    let o1 = query_one(o: &mut Out).on(e1);
    let o2 = query_one(o: &mut Out).on(e2);
    let merged = o1.or(o2);
    let _ = merged;
}
"#,
        ),
        (
            "opt_unwrap_or_merge",
            r#"
sys s(e1: Entity, e2: Entity) {
    let o1 = query_one(o: &mut Out).on(e1);
    let q2 = query_one(o: &mut Out).on(e2).unwrap();
    let merged = o1.unwrap_or(q2);
    let _ = merged;
}
"#,
        ),
        (
            "if_multi_source_opt_row",
            r#"
sys s(cond: bool, e1: Entity, e2: Entity) {
    let o1 = query_one(o: &mut Out).on(e1);
    let o2 = query_one(o: &mut Out).on(e2);
    let chosen = if cond { o1 } else { o2 };
    let _ = chosen;
}
"#,
        ),
        (
            "fn_param_borrow_reassign",
            r#"
fn helper(c: &mut Out, c2: &mut Out) {
    c = c2;
}
"#,
        ),
    ];
    for (name, body) in aliasing_cases {
        let src =
            format!("module test::{name} @version(1.0.0);\ncomponent Out {{ v: i32 = 0 }}\n{body}");
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0201_ALIASING_CONFLICT),
            "{name}: expected E0201_ALIASING_CONFLICT, got: {:?}",
            res.diagnostics
        );
    }

    // 4. Positive control: scalar shadowing an outer handle name must not trigger E0201.
    let shadow_src = r#"
module test::shadow_ok @version(1.0.0);
component Out { v: i32 = 0 }
sys s(e1: Entity) {
    let mut c = query_one(o: &mut Out).on(e1).unwrap();
    {
        let mut c: i32 = 1;
        c = 2;
        let _ = c;
    }
    let _ = c.o.v;
}
"#;
    let res_shadow = analyze_source("shadow_ok.strata", shadow_src);
    assert!(
        !res_shadow
            .diagnostics
            .iter()
            .any(|d| d.code == codes::E0201_ALIASING_CONFLICT),
        "scalar shadowing an outer handle must not emit E0201: {:?}",
        res_shadow.diagnostics
    );
}

#[test]
fn sema_step2_iter8_one_arg_trigger_and_negative_two_arg_rejected() {
    let ok_src = r#"
module test::sema_iter8 @version(1.0.0);

component Marker { tag_v: i32 = 1 }
component Out { val: i32 = 0 }
event GlobalEvt { delta: i32 }
event PingEvt { entity: Ref<Entity>, amt: i32 }

sys emitter(e: Entity) {
    trigger(GlobalEvt { delta: 5 });
    trigger(PingEvt { entity: e, amt: 9 });
}

obs on_global(trg: &Trigger<GlobalEvt>) {
    for row in query(o: &mut Out) {
        row.o.val += trg.payload.delta;
    }
}

obs on_ping(trg: &Trigger<PingEvt, Marker>) {
    let opt = query_one(o: &mut Out).on(trg.target);
    if let Some(r) = opt {
        r.o.val += trg.payload.amt;
    }
}
"#;
    let res_ok = analyze_source("sema_iter8_ok.strata", ok_src);
    assert!(
        res_ok.ok(),
        "1-arg trigger must analyze cleanly: {:?}",
        res_ok.diagnostics
    );

    let bad_src = r#"
module test::sema_iter8_bad @version(1.0.0);
event PingEvt { amt: i32 }
event OtherEvt { amt: i32 }
sys bad_emit() effects(triggers: [OtherEvt]) {
    trigger(PingEvt { amt: 1 });
}
"#;
    let res_bad = analyze_source("sema_iter8_bad.strata", bad_src);
    assert!(
        !res_bad.ok(),
        "1-arg trigger of undeclared event in effects(triggers: [...]) must be rejected by sema"
    );
}

#[test]
fn sema_step2_iter10_array_and_generic_arg_int_extraction_layouts() {
    use strata_sema::Ty;
    let src = r#"
module test::sema_iter10_arr_gen @version(1.0.0);

component Iter10Pod {
    arr64: [BitSet<64>; 2],
    arr128: [BitSet<128>; 2],
    mat_f: [[f32; 3]; 2],
    mat128: [[BitSet<128>; 2]; 2],
    sv_arr: SmallVec<[f32; 3], 2>,
    sv_bs64: SmallVec<BitSet<64>, 2>,
    sv_bs128: SmallVec<BitSet<128>, 2>,
    ib_bs64: InputBuffer<BitSet<64>, 4>,
}
"#;
    let res = analyze_source("sema_iter10_arr_gen.strata", src);
    assert!(
        res.ok(),
        "sema_iter10_arr_gen must analyze cleanly: {:?}",
        res.diagnostics
    );

    let layout = &res.layouts["test::sema_iter10_arr_gen::Iter10Pod"];
    let field = |name: &str| {
        layout
            .fields
            .iter()
            .find(|f| !f.is_padding && f.name == name)
            .unwrap_or_else(|| panic!("missing field `{name}`"))
    };

    assert_eq!(
        field("arr64").ty,
        Ty::Array {
            elem: Box::new(Ty::BitSet(64)),
            len: 2,
        }
    );
    assert_eq!(field("arr64").size, 16);

    assert_eq!(
        field("arr128").ty,
        Ty::Array {
            elem: Box::new(Ty::BitSet(128)),
            len: 2,
        }
    );
    assert_eq!(field("arr128").size, 32);

    assert_eq!(
        field("mat_f").ty,
        Ty::Array {
            elem: Box::new(Ty::Array {
                elem: Box::new(Ty::F32),
                len: 3,
            }),
            len: 2,
        }
    );
    assert_eq!(field("mat_f").size, 24);

    assert_eq!(
        field("mat128").ty,
        Ty::Array {
            elem: Box::new(Ty::Array {
                elem: Box::new(Ty::BitSet(128)),
                len: 2,
            }),
            len: 2,
        }
    );
    assert_eq!(field("mat128").size, 64);

    assert_eq!(
        field("sv_arr").ty,
        Ty::SmallVec {
            elem: Box::new(Ty::Array {
                elem: Box::new(Ty::F32),
                len: 3,
            }),
            cap: 2,
        }
    );
    assert_eq!(field("sv_arr").size, 32);

    assert_eq!(
        field("sv_bs64").ty,
        Ty::SmallVec {
            elem: Box::new(Ty::BitSet(64)),
            cap: 2,
        }
    );
    assert_eq!(field("sv_bs64").size, 24);

    assert_eq!(
        field("sv_bs128").ty,
        Ty::SmallVec {
            elem: Box::new(Ty::BitSet(128)),
            cap: 2,
        }
    );
    assert_eq!(field("sv_bs128").size, 40);

    assert_eq!(
        field("ib_bs64").ty,
        Ty::InputBuffer {
            action: "BitSet<64>".to_owned(),
            cap: 4,
        }
    );
    assert_eq!(field("ib_bs64").size, 32);

    // 16 + 32 + 24 + 64 + 32 + 24 + 40 + 32 = 264 (all 4-aligned, zero padding)
    assert_eq!(layout.size, 264);
}

#[test]
fn bug_tl_10_int_radix_separators_const_exprs_and_array_smallvec_mismatches() {
    use strata_sema::types::Ty;
    let ok_src = r#"
module test::tl10_ok @version(1.0.0);

component Holders {
    big: [u32; 1_024],
    bs: BitSet<1_28>,
    sv: SmallVec<u32, 1_6>,
    istr: InlineStr<1_6>,
    hex_arr: [u8; 0x10],
    bin_arr: [u8; 0b100],
    oct_arr: [u8; 0o10],
    arith_arr: [f32; 2 + 2],
    nested_arith: [f32; 2 * (3 + 1)],
}

struct Bag {
    arr: [f32; 2],
}

fn take_arr(a: [f32; 2]) -> [f32; 2] {
    return a;
}

sys ok_literals() {
    let a: [f32; 2 + 2] = [1.0, 2.0, 3.0, 4.0];
    let mut m: [[f32; 2]; 2] = [[1.0, 2.0], [3.0, 4.0]];
    m = [[5.0, 6.0], [7.0, 8.0]];
    let sv: SmallVec<u32, 4> = [1, 2];
    let bag = Bag { arr: [1.0, 2.0] };
    let r = take_arr(bag.arr);
    let _ = (a, m, sv, r);
}
"#;
    let ok_mod = analyze_source("tl10_ok.strata", ok_src);
    assert!(ok_mod.ok(), "tl10_ok failed: {:#?}", ok_mod.diagnostics);
    let layout = &ok_mod.layouts["test::tl10_ok::Holders"];
    let fty = |name: &str| {
        layout
            .fields
            .iter()
            .find(|f| f.name == name)
            .expect(name)
            .ty
            .clone()
    };
    assert_eq!(
        fty("big"),
        Ty::Array {
            elem: Box::new(Ty::U32),
            len: 1024
        }
    );
    assert_eq!(fty("bs"), Ty::BitSet(128));
    assert_eq!(
        fty("sv"),
        Ty::SmallVec {
            elem: Box::new(Ty::U32),
            cap: 16
        }
    );
    assert_eq!(fty("istr"), Ty::InlineStr(16));
    assert_eq!(
        fty("hex_arr"),
        Ty::Array {
            elem: Box::new(Ty::U8),
            len: 16
        }
    );
    assert_eq!(
        fty("bin_arr"),
        Ty::Array {
            elem: Box::new(Ty::U8),
            len: 4
        }
    );
    assert_eq!(
        fty("oct_arr"),
        Ty::Array {
            elem: Box::new(Ty::U8),
            len: 8
        }
    );
    assert_eq!(
        fty("arith_arr"),
        Ty::Array {
            elem: Box::new(Ty::F32),
            len: 4
        }
    );
    assert_eq!(
        fty("nested_arith"),
        Ty::Array {
            elem: Box::new(Ty::F32),
            len: 8
        }
    );

    let bad_cases = [
        ("overlong", "sys s() { let a: [f32; 2] = [1.0, 2.0, 3.0]; }"),
        ("underlong", "sys s() { let a: [f32; 4] = [1.0, 2.0]; }"),
        (
            "nested_inner",
            "sys s() { let m: [[f32; 2]; 2] = [[1.0, 2.0, 3.0], [4.0, 5.0]]; }",
        ),
        (
            "smallvec_overflow",
            "sys s() { let v: SmallVec<u32, 2> = [1, 2, 3, 4]; }",
        ),
        (
            "struct_field_init",
            "struct Bag { arr: [f32; 2] } sys s() { let _b = Bag { arr: [1.0, 2.0, 3.0] }; }",
        ),
        (
            "spawn_comp_init",
            "component BoxC { arr: [f32; 2] } sys s() { spawn { BoxC { arr: [1.0] } }; }",
        ),
        (
            "fn_arg",
            "fn f(a: [f32; 2]) {} sys s() { f([1.0, 2.0, 3.0]); }",
        ),
        ("fn_ret", "fn f() -> [f32; 2] { return [1.0, 2.0, 3.0]; }"),
    ];
    for (name, body) in bad_cases {
        let src = format!("module test::{name} @version(1.0.0);\n{body}\n");
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            res.diagnostics
                .iter()
                .any(|d| d.severity == strata_sema::diagnostics::Severity::Error
                    && d.code == codes::E0111_TYPE_MISMATCH),
            "{name}: expected E0111_TYPE_MISMATCH, got: {:#?}",
            res.diagnostics
        );
    }
}

#[test]
fn bug_sw_01a_07c_and_eq_07_08_hir_and_query_diagnostics() {
    use strata_sema::hir::{HirExpr, HirForIter, HirStmt};

    let src = r#"
module test::sw_eq @version(1.0.0);

component Pos { p: vec3 = vec3(0.0, 0.0, 0.0) }
component Item { id: i32 = 1, val: i32 = 2 }
spatial_history Hist3D(frames: 8) over Pos by Pos.p;

sys sweep_and_added(h: &Hist3D) {
    for _hit in h.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(10.0, 0.0, 0.0), 3.0_m) {
    }
    for _hit3 in h.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(10.0, 0.0, 0.0)) {
    }
    for _r in query(i: &Item).added<Item>() {
    }
}

sys valid_item_access() {
    for r in query(p: &mut Item) {
        r.p.val += 5;
        p.val += 1;
    }
}

sys m1() {}
sys m2() {}
sys s1() {}
sys s2() {}

schedule FixedUpdate {
    seq Outer {
        m2 after(m1)
        m1
        set Phys before(Audio) after(Input) {
            s1 before(s2)
            s2
        }
    }
}
"#;
    let m = analyze_source("sw_eq.strata", src);
    assert!(m.ok(), "sw_eq failed: {:#?}", m.diagnostics);

    let sys = m
        .callables
        .iter()
        .find(|c| c.name == "sweep_and_added")
        .expect("sweep_and_added");
    assert_eq!(sys.body.len(), 3);
    match &sys.body[0] {
        HirStmt::Expr(HirExpr::For(f)) => match &f.iter {
            HirForIter::SpatialSegmentAt { radius, .. } => {
                assert!(radius.is_some(), "expected 4th arg radius preserved");
            }
            other => panic!("expected SpatialSegmentAt, got {other:?}"),
        },
        other => panic!("expected For, got {other:?}"),
    }
    match &sys.body[1] {
        HirStmt::Expr(HirExpr::For(f)) => match &f.iter {
            HirForIter::SpatialSegmentAt { radius, .. } => {
                assert!(radius.is_none(), "expected 3-arg radius to be None");
            }
            other => panic!("expected SpatialSegmentAt, got {other:?}"),
        },
        other => panic!("expected For, got {other:?}"),
    }
    match &sys.body[2] {
        HirStmt::Expr(HirExpr::For(f)) => match &f.iter {
            HirForIter::Query(q) => {
                assert_eq!(q.added_filters, vec!["Item".to_owned()]);
            }
            other => panic!("expected Query, got {other:?}"),
        },
        other => panic!("expected For, got {other:?}"),
    }

    let sched = &m.schedules[0];
    let outer = &sched.nodes[0];
    assert_eq!(outer.children[0].name, "m2");
    assert_eq!(outer.children[0].after, vec!["m1".to_owned()]);
    assert_eq!(outer.children[2].name, "Phys");
    assert_eq!(outer.children[2].before, vec!["Audio".to_owned()]);
    assert_eq!(outer.children[2].after, vec!["Input".to_owned()]);
    assert_eq!(outer.children[2].children[0].before, vec!["s2".to_owned()]);

    // EQ-08 negative controls
    for (name, body) in [
        (
            "misbound_p_p_val",
            "for r in query(p: &mut Item) { p.p.val += 5; }",
        ),
        (
            "unknown_row_term",
            "for r in query(p: &mut Item) { r.q.val += 5; }",
        ),
        (
            "unknown_comp_field",
            "for r in query(p: &mut Item) { r.p.missing += 5; }",
        ),
        (
            "unknown_row_field",
            "for r in query(p: &mut Item) { r.missing += 5; }",
        ),
    ] {
        let bad = format!(
            "module test::{name} @version(1.0.0);\ncomponent Item {{ id: i32 = 1, val: i32 = 2 }}\nsys bad() {{ {body} }}\n"
        );
        let res = analyze_source(format!("{name}.strata"), &bad);
        assert!(
            res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0301_UNRESOLVED_SYMBOL),
            "{name}: expected E0301_UNRESOLVED_SYMBOL, got: {:#?}",
            res.diagnostics
        );
    }
}

#[test]
fn pm_06_and_pm_15_par_read_only_and_helper_res_writes() {
    // PM-15 rejected cases
    for (name, body) in [
        (
            "ro_mut",
            "@par(read_only, chunk = 4) sys bad() { for row in query(w: &mut Worker) { row.w.x += 1.0; } }",
        ),
        (
            "ro_sel_mut",
            "@par(read_only, chunk = 4) sys bad() { for row in query(w: &mut? Worker) { row.w.x += 1.0; } }",
        ),
        (
            "ro_reduce_mut",
            "@par(read_only, chunk = 4) sys bad() { let _s = for row in query(w: &mut Worker) reduce(acc: sum(0.0, row.w.x)); }",
        ),
    ] {
        let src = format!(
            "module test::{name} @version(1.0.0);\ncomponent Worker {{ x: f32 = 0.0 }}\n{body}\n"
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0202_ASSERT_PAR_FAILED),
            "{name}: expected E0202_ASSERT_PAR_FAILED, got: {:#?}",
            res.diagnostics
        );
    }

    // PM-15 allowed control (par_ro_outbox pattern + sel_reduce without read_only) + PM-06 propagation
    let ok_src = r#"
module test::pm_ok @version(1.0.0);

component Worker { x: f32 = 0.0 }
component OutBox { total: f32 = 0.0 }
resource Counter { val: u32 = 0 }

fn leaf_bump() {
    res_mut<Counter>().val += 1;
}

fn mid_bump() {
    leaf_bump();
}

@par(read_only, chunk = 512)
sys par_ro_outbox() {
    let s = for e in query(w: &Worker) reduce(acc: sum(0.0, e.w.x));
    for o in query(ob: &mut OutBox) {
        o.ob.total = s;
    }
}

@par(chunk = 256)
sys par_sel_reduce() {
    let _s = for e in query(w: &mut? Worker) reduce(acc: sum(0.0, e.w.x));
}

@par(chunk = 4)
sys sneaky_par() {
    for row in query(w: &mut Worker) {
        mid_bump();
        row.w.x += 1.0;
    }
}

sys read_counter(c: &res Counter) {
    let _v = c.val;
}

assert_par(sneaky_par, read_counter);
"#;
    let res = analyze_source("pm_ok.strata", ok_src);
    let sneaky = res
        .callables
        .iter()
        .find(|c| c.name == "sneaky_par")
        .expect("sneaky_par");
    assert!(
        sneaky.access.res_writes.contains("Counter"),
        "expected transitive res_writes to contain Counter, got: {:?}",
        sneaky.access.res_writes
    );
    // sneaky_par + par_ro_outbox + par_sel_reduce produce zero E0202 by themselves; ONLY assert_par(sneaky_par, read_counter) triggers E0202!
    let e0202: Vec<_> = res
        .diagnostics
        .iter()
        .filter(|d| d.code == codes::E0202_ASSERT_PAR_FAILED)
        .collect();
    assert_eq!(
        e0202.len(),
        1,
        "expected exactly 1 assert_par E0202, got: {e0202:#?}"
    );
    assert!(
        e0202[0]
            .message
            .contains("assert_par(sneaky_par, read_counter)")
    );
}

#[test]
fn nt_02_authority_shared_despawn_observer_and_workflow_isolation() {
    let base_schema = r#"
@authority(server)
component ServerHp { hp: f32 = 100.0 }
@authority(server)
resource ServerBank { gold: u32 = 10 }
@authority(shared)
resource SharedGold { gold: u32 = 10 }
@authority(client)
component ClientTag { flag: bool = true }
event CheatEvt { val: u32 = 1 }
"#;

    let bypasses = [
        (
            "shared_sys_writes_server_comp",
            "@authority(shared) sys cheat() { for r in query(h: &mut ServerHp) { r.h.hp = 0.0; } }",
        ),
        (
            "shared_sys_writes_server_res",
            "@authority(shared) sys cheat(b: &mut res ServerBank) { b.gold = 999; }",
        ),
        (
            "client_sys_server_res_shared_gold",
            "@authority(client) sys cheat() { server_res<SharedGold>().gold = 9999; }",
        ),
        (
            "client_sys_despawns_server_entity",
            "@authority(client) sys cheat() { for r in query(h: &ServerHp) { despawn(r.id); } }",
        ),
        (
            "client_sys_despawns_server_entity_via_fn",
            "fn kill(e: Entity) { despawn(e); }\n@authority(client) sys cheat() { for r in query(h: &ServerHp) { kill(r.id); } }",
        ),
        (
            "client_sys_triggers_server_mutating_obs",
            "obs on_cheat(t: &Trigger<CheatEvt>, b: &mut res ServerBank) { b.gold = t.payload.val; }\n@authority(client) sys cheat() { trigger(CheatEvt { val: 777 }); }",
        ),
        (
            "client_sys_starts_server_mutating_task",
            "task CheatTask() using (b: &mut res ServerBank) { b.gold = 555; }\n@authority(client) sys cheat() { for r in query(c: &ClientTag) { insert(r.id, CheatTask::start()); } }",
        ),
        (
            "client_sys_starts_server_mutating_fsm",
            "fsm CheatFsm(b: &mut res ServerBank) { initial A; state A { on_tick { b.gold = 666; } } }\n@authority(client) sys cheat() { for r in query(c: &ClientTag) { insert(r.id, CheatFsm::start()); } }",
        ),
        (
            "client_sys_starts_server_mutating_timeline",
            "timeline CheatTl(rate: 60_hz, duration: 10_f) { at 1_f => res_mut<ServerBank>().gold = 888; }\n@authority(client) sys cheat() { play(CheatTl); }",
        ),
    ];

    for (name, body) in bypasses {
        let src = format!("module test::{name} @version(1.0.0);\n{base_schema}\n{body}\n");
        let salsa_mod = {
            let db = SemaDb::new();
            let sf = db.new_source(format!("{name}.strata"), src.clone());
            db.analyze_file(sf)
        };
        for (mode, res) in [
            (
                "full",
                std::sync::Arc::new(analyze_source(format!("{name}.strata"), &src)),
            ),
            ("salsa", salsa_mod),
        ] {
            assert!(
                res.diagnostics
                    .iter()
                    .any(|d| d.code == codes::E0501_AUTHORITY_VIOLATION),
                "{name} ({mode}): expected E0501_AUTHORITY_VIOLATION, got: {:#?}",
                res.diagnostics
            );
        }
    }

    // Valid controls: server sys triggering server obs, client sys despawning client entity,
    // client sys starting client task, client sys mutating shared resource via res_mut.
    let ok_src = format!(
        "module test::nt02_ok @version(1.0.0);\n{base_schema}\n
obs on_srv(t: &Trigger<CheatEvt>, b: &mut res ServerBank) {{ b.gold = t.payload.val; }}
task ClientTask() {{ yield_tick; }}
@authority(server)
sys srv_ok() {{ trigger(CheatEvt {{ val: 42 }}); }}
@authority(client)
sys cl_ok() {{
    res_mut<SharedGold>().gold = 50;
    for r in query(c: &ClientTag) {{
        insert(r.id, ClientTask::start());
        despawn(r.id);
    }}
}}
"
    );
    let ok_mod = analyze_source("nt02_ok.strata", &ok_src);
    assert!(ok_mod.ok(), "nt02_ok failed: {:#?}", ok_mod.diagnostics);
}

#[test]
fn nt_10_nested_quantize_effects_and_singleton_resource_aliasing() {
    // 1. Nested struct `@quantize` preserved in NetComponentMeta & HirRpc with dotted paths
    let quant_src = r#"
module test::nested_quant @version(1.0.0);

struct Inner {
    @quantize(min = -10.0, max = 10.0, bits = 12)
    z: f32,
}

struct SubStats {
    @quantize(min = 0.0, max = 100.0, bits = 8)
    hp: f32,
    inner: Inner,
}

@authority(server)
@net(reliable, channel = 0)
component Player {
    stats: SubStats,
}

@net_rpc(direction = client_to_server, reliability = reliable, channel = 1)
rpc MoveRpc {
    sub: SubStats,
}
"#;
    let qmod = analyze_source("nested_quant.strata", quant_src);
    assert!(qmod.ok(), "nested_quant failed: {:#?}", qmod.diagnostics);
    let pmeta = qmod
        .net_components
        .iter()
        .find(|n| n.canonical_name.ends_with("::Player"))
        .expect("Player net meta");
    let pnames: Vec<&str> = pmeta
        .quantized_fields
        .iter()
        .map(|q| q.field_name.as_str())
        .collect();
    assert_eq!(pnames, vec!["stats.hp", "stats.inner.z"]);

    let rpc_names: Vec<&str> = qmod.rpcs[0]
        .quantized_fields
        .iter()
        .map(|q| q.field_name.as_str())
        .collect();
    assert_eq!(rpc_names, vec!["sub.hp", "sub.inner.z"]);

    // 2. Effects mismatches (`insert`, `remove`, `res_mut`, `play`, transitive helper `fn`)
    for (name, body) in [
        (
            "eff_insert",
            "sys s() effects(reads: [Entity, A]) { for r in query(a: &A) { insert(r.id, B { v: 1 }); } }",
        ),
        (
            "eff_remove",
            "sys s() effects(reads: [Entity, A]) { for r in query(a: &A) { remove<B>(r.id); } }",
        ),
        (
            "eff_res_mut",
            "sys s() effects(reads: [A]) { res_mut<Bank>().bal += 1; }",
        ),
        (
            "eff_helper_res_mut",
            "fn bump() { res_mut<Bank>().bal += 1; }\nsys s() effects(reads: [A]) { bump(); }",
        ),
        (
            "eff_play_tl",
            "timeline Tl(rate: 60_hz, duration: 5_f) { at 1_f => res_mut<Bank>().bal += 1; }\nsys s() effects(reads: [A]) { play(Tl); }",
        ),
    ] {
        let src = format!(
            "module test::{name} @version(1.0.0);\ncomponent A {{ x: i32 = 0 }}\ncomponent B {{ v: i32 = 0 }}\nresource Bank {{ bal: i32 = 0 }}\n{body}\n"
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0204_EFFECTS_MISMATCH),
            "{name}: expected E0204_EFFECTS_MISMATCH, got: {:#?}",
            res.diagnostics
        );
    }

    // 3. Singleton resource aliasing (`&mut res Bank` + `&mut res Bank`, `&res Bank` + `res_mut<Bank>()`,
    //    `&mut res Bank` + `res<Bank>()`, transitive helper `res_mut`, same-call args)
    for (name, body) in [
        (
            "alias_two_mut_params",
            "sys bad(a: &mut res Bank, b: &mut res Bank) { a.bal = 1; b.bal = 2; }",
        ),
        (
            "alias_param_ro_and_body_mut",
            "sys bad(a: &res Bank) { let _x = a.bal; res_mut<Bank>().bal += 1; }",
        ),
        (
            "alias_param_mut_and_body_ro",
            "sys bad(a: &mut res Bank) { a.bal += res<Bank>().bal; }",
        ),
        (
            "alias_param_ro_and_helper_mut",
            "fn bump() { res_mut<Bank>().bal += 1; }\nsys bad(a: &res Bank) { let _x = a.bal; bump(); }",
        ),
        (
            "alias_same_call_args",
            "fn take(a: &mut Bank, b: &mut Bank) {}\nsys bad() { take(res_mut<Bank>(), res_mut<Bank>()); }",
        ),
    ] {
        let src = format!(
            "module test::{name} @version(1.0.0);\nresource Bank {{ bal: i32 = 0 }}\n{body}\n"
        );
        let res = analyze_source(format!("{name}.strata"), &src);
        assert!(
            res.diagnostics
                .iter()
                .any(|d| d.code == codes::E0201_ALIASING_CONFLICT),
            "{name}: expected E0201_ALIASING_CONFLICT, got: {:#?}",
            res.diagnostics
        );
    }

    // Allowed non-aliasing control: `&res Bank` + `res<Bank>()` + sequential `res_mut` statements
    let ok_alias = r#"
module test::alias_ok @version(1.0.0);
resource Bank { bal: i32 = 0 }
sys ok_reads(a: &res Bank) {
    let _x = a.bal + res<Bank>().bal;
}
sys ok_seq_muts() {
    res_mut<Bank>().bal += 1;
    res_mut<Bank>().bal += 2;
}
"#;
    let ok_alias_mod = analyze_source("alias_ok.strata", ok_alias);
    assert!(
        ok_alias_mod.ok(),
        "alias_ok failed: {:#?}",
        ok_alias_mod.diagnostics
    );
}
