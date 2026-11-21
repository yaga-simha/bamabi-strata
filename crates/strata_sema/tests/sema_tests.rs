use bamabi_sys::{
    BAM_COMPONENT_FLAG_SUMMARY_TICK, BamFieldKind, ComponentUuid, fnv1a_64_init,
    fnv1a_64_update_bytes, fnv1a_64_update_u64,
};
use salsa::Setter;
use strata_sema::{SemaDb, analyze_source, codes};

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
    }
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
    let executed_initial = db.take_executed_queries();
    assert!(
        executed_initial
            .iter()
            .any(|q| q.contains("resolve_layouts_json")),
        "initial compile should execute resolve_layouts_json"
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
    let executed_after_body_edit = db.take_executed_queries();

    assert_eq!(
        mod1.layouts["inc::test::Health"].schema_fingerprint,
        mod2.layouts["inc::test::Health"].schema_fingerprint
    );
    assert!(
        !executed_after_body_edit
            .iter()
            .any(|q| q.contains("resolve_layouts_json")),
        "body-only edit should early-cutoff before resolve_layouts_json, executed: {executed_after_body_edit:?}"
    );
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
