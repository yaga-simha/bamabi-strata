use strata_syntax::ast::{self, AstNode, Item, ScheduleNodeKind, SourceFile};
use strata_syntax::{SyntaxKind, format_source, lex, parse};

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
fn all_cookbooks_parse_losslessly_and_format_idempotently() {
    for (name, src) in COOKBOOKS {
        let parsed = parse(src);
        assert!(
            parsed.ok(),
            "{name} produced parse errors: {:#?}",
            parsed.errors()
        );
        assert_eq!(
            parsed.syntax().text().to_string(),
            src,
            "{name} failed lossless CST round-trip"
        );

        let root = SourceFile::cast(parsed.syntax()).expect("root is SourceFile");
        assert!(
            root.module_decl().is_some(),
            "{name} missing module declaration"
        );
        assert!(
            root.items().count() >= 4,
            "{name} unexpectedly yielded too few items"
        );

        let fmt1 = format_source(src).unwrap_or_else(|e| panic!("{name} fmt1 failed: {e:?}"));
        let fmt1_parsed = parse(&fmt1);
        assert!(
            fmt1_parsed.ok(),
            "{name} formatted output failed re-parse: {:#?}\n{fmt1}",
            fmt1_parsed.errors()
        );
        let fmt2 = format_source(&fmt1).unwrap_or_else(|e| panic!("{name} fmt2 failed: {e:?}"));
        assert_eq!(fmt1, fmt2, "{name} stratafmt is not idempotent");
    }
}

#[test]
fn lexer_preserves_range_operator_next_to_numbers_and_units() {
    let tokens = lex("0_f..18_f 0..10 12.0_m..=24.0_m");
    let non_ws: Vec<_> = tokens
        .into_iter()
        .filter(|t| !t.kind.is_trivia())
        .map(|t| (t.kind, t.text))
        .collect();
    assert_eq!(
        non_ws,
        vec![
            (SyntaxKind::UnitLit, "0_f"),
            (SyntaxKind::DotDot, ".."),
            (SyntaxKind::UnitLit, "18_f"),
            (SyntaxKind::IntLit, "0"),
            (SyntaxKind::DotDot, ".."),
            (SyntaxKind::IntLit, "10"),
            (SyntaxKind::UnitLit, "12.0_m"),
            (SyntaxKind::DotDotEq, "..="),
            (SyntaxKind::UnitLit, "24.0_m"),
        ]
    );
}

#[test]
fn extended_grammar_constructs_parse_cleanly() {
    let src = r#"
module extra::coverage @version(2.1.0);

use engine::math::{Vec3, Quat};

struct Header { magic: u32, flags: BitSet<8> }

aspect Movable(pos: &mut Pos3D, vel: &Vel3D) .without<Frozen>() where vel.dxyz.y > 0.0;

prefab Crate {
    Pos3D { xyz: vec3::ZERO },
}

zone DungeonFloor {
    floor_id: u16 = 1,
}

hash_index ItemLookup(capacity: 256) over ItemTag by key(ItemId.raw) cache (pos: &Pos3D);

migrate Health from 1.0.0 to 2.0.0(old: &HealthV1) -> Health {
    Health { hp: old.hp as f32, max_hp: 100.0 }
}

assert_par(tick_a, tick_b);

fn clamp_mode(m: u8) -> u8 {
    match m {
        0 => 1,
        1 => 2,
        _ => 0,
    }
}
"#;
    let parsed = parse(src);
    assert!(parsed.ok(), "errors: {:#?}", parsed.errors());
    assert_eq!(parsed.syntax().text().to_string(), src);
}

#[test]
fn error_recovery_is_lossless_and_recovers_subsequent_items() {
    let malformed = r#"
module bad::recover @version(1.0.0);

component Broken { ??? ;;;

component Healthy { hp: f32 = 10.0 }

/* unterminated block comment
"#;
    let parsed = parse(malformed);
    assert!(!parsed.ok(), "expected parse errors on malformed source");
    assert_eq!(parsed.syntax().text().to_string(), malformed);

    let root = SourceFile::cast(parsed.syntax()).expect("root is SourceFile");
    let item_count = root.items().count();
    assert!(
        item_count >= 2,
        "expected parser to recover module and Healthy component, got {item_count}"
    );
}

#[test]
fn networking_rpc_and_net_sim_test_ast_and_fmt_roundtrip() {
    let src = r#"
module net::demo @version(1.0.0);

@net_rpc(direction = client_to_server, reliability = reliable)
@authority(client)
@node_group("Network")
rpc MoveInput {
    @quantize(min = -1.0, max = 1.0, bits = 12)
    dx: f32,
    dy: f32,
    seq: u32,
}

rpc Ping;

net_sim_test "reconciles_under_loss"(latency: 50ms, jitter: 10ms, loss: 0.05, seed: 42) {
    clients(2);
    send_rpc(0, MoveInput { dx: 1.0, dy: 0.0, seq: 1 });
    step_net(5);
    assert_converged(0, 0.01);
}
"#;
    let parsed = parse(src);
    assert!(parsed.ok(), "errors: {:#?}", parsed.errors());
    assert_eq!(parsed.syntax().text().to_string(), src);

    let root = SourceFile::cast(parsed.syntax()).expect("root");
    let items: Vec<_> = root.items().collect();
    assert_eq!(items.len(), 4);

    let Item::Rpc(move_rpc) = &items[1] else {
        panic!("expected Item::Rpc");
    };
    assert_eq!(move_rpc.name().unwrap().text(), "MoveInput");
    assert_eq!(move_rpc.node_group().as_deref(), Some("Network"));
    assert!(!move_rpc.is_marker());
    assert_eq!(move_rpc.fields().len(), 3);
    assert_eq!(move_rpc.fields()[0].attributes().len(), 1);
    assert_eq!(
        move_rpc.fields()[0].attributes()[0].name_text().as_deref(),
        Some("quantize")
    );

    let Item::Rpc(ping_rpc) = &items[2] else {
        panic!("expected marker Item::Rpc");
    };
    assert!(ping_rpc.is_marker());
    assert!(ping_rpc.fields().is_empty());

    let Item::NetSimTest(net_test) = &items[3] else {
        panic!("expected Item::NetSimTest");
    };
    assert_eq!(net_test.name().as_deref(), Some("reconciles_under_loss"));
    assert!(net_test.param_list().is_some());
    let params = net_test.params();
    assert_eq!(params.len(), 4);
    assert_eq!(params[0].name().unwrap().text(), "latency");
    assert_eq!(params[0].value_text().as_deref(), Some("50ms"));
    assert_eq!(params[1].name().unwrap().text(), "jitter");
    assert_eq!(params[1].value_text().as_deref(), Some("10ms"));
    assert_eq!(params[2].name().unwrap().text(), "loss");
    assert_eq!(params[2].value_text().as_deref(), Some("0.05"));
    assert_eq!(params[3].name().unwrap().text(), "seed");
    assert_eq!(params[3].value_text().as_deref(), Some("42"));
    assert!(net_test.body().is_some());

    let fmt1 = format_source(src).expect("format succeeds");
    let fmt2 = format_source(&fmt1).expect("re-format succeeds");
    assert_eq!(fmt1, fmt2);
    assert!(fmt1.contains("50ms"));
    assert!(fmt1.contains("\"reconciles_under_loss\"("));
}

#[test]
fn typed_ast_accessors_cover_all_graph_constructs() {
    let src = r#"
module ast::coverage @version(1.0.0);

enum Kind { A = 0, B = 1 }

@soa
@node_group("Physics")
component Body @require(Pos2D) {
    hot { hp: f32 = 100.0 }
    cold meta { tag_id: u16 = 0 }
}

component Marker;

@node_pure
fn mix<T>(a: T, b: f32 = 1.0) -> T {
    return a;
}

timeline AttackTl {
    window active = 2_f .. 6_f;
    at 2_f => { let x = 1; }
}

fsm Brain(clk: &res SimClock) @require(Body) {
    initial Idle { timer: 0.0 };
    state Idle {
        timer: f32 = 0.0,
        on_enter { let a = 1; }
        on_tick { let b = 2; }
        on_exit { let c = 3; }
        to Alert { reason: 1 } when clk.dt > 0.0_s;
    }
    state Alert {
        to Idle when true;
    }
}

task DashTask(speed: f32)
    on (vel: &mut Vel2D.dxy)
    .with<Marker>()
    using (clk: &res SimClock)
{
    vel.x = speed;
}

table Stats by Kind {
    power: f32,
} = {
    A => { power: 1.0 },
    B => { power: 2.0 },
};

curve Falloff(meters -> f32) = [
    (0.0_m, 10.0),
    (5.0_m, 2.0),
];

schedule FixedUpdate before(Render) {
    seq Main {
        DashTask
        Brain
    }
}
"#;
    let parsed = parse(src);
    assert!(parsed.ok(), "errors: {:#?}", parsed.errors());
    let sf = SourceFile::cast(parsed.syntax()).unwrap();
    let items: Vec<_> = sf.items().collect();

    let Item::Component(body) = &items[2] else {
        panic!("expected Body component");
    };
    assert!(body.is_soa());
    assert!(!body.is_unit_marker());
    assert_eq!(body.node_group().as_deref(), Some("Physics"));
    assert_eq!(body.require_clauses().len(), 1);
    assert_eq!(body.all_fields().len(), 2);
    assert!(body.strata()[0].is_hot());
    assert!(body.strata()[0].name_token().is_none());
    assert_eq!(body.strata()[1].name_token().unwrap().text(), "meta");
    assert_eq!(
        body.all_fields()[0]
            .default_expr()
            .unwrap()
            .text()
            .to_string()
            .trim(),
        "100.0"
    );

    let Item::Component(marker) = &items[3] else {
        panic!("expected Marker component");
    };
    assert!(marker.is_unit_marker());

    let Item::Fn(mix_fn) = &items[4] else {
        panic!("expected Fn");
    };
    assert!(mix_fn.is_node_pure());
    assert_eq!(mix_fn.generic_params().unwrap().param_names().len(), 1);
    assert_eq!(mix_fn.params().len(), 2);
    assert!(mix_fn.params()[1].default_expr().is_some());
    assert_eq!(mix_fn.return_type().unwrap().text().to_string(), "T");

    let Item::Timeline(tl) = &items[5] else {
        panic!("expected Timeline");
    };
    assert_eq!(tl.windows().len(), 1);
    assert_eq!(tl.at_entries().len(), 1);
    assert!(tl.at_entries()[0].time_expr().is_some());
    assert!(tl.at_entries()[0].action_node().is_some());

    let Item::Fsm(fsm) = &items[6] else {
        panic!("expected Fsm");
    };
    assert_eq!(fsm.params().len(), 1);
    assert_eq!(fsm.initial_state().unwrap().text(), "Idle");
    assert!(fsm.initial_args().is_some());
    assert_eq!(fsm.states().len(), 2);
    let idle = &fsm.states()[0];
    assert_eq!(idle.fields().len(), 1);
    assert!(idle.on_enter().is_some());
    assert!(idle.on_tick().is_some());
    assert!(idle.on_exit().is_some());
    assert_eq!(idle.transitions().len(), 1);
    assert!(idle.transitions()[0].target_args().is_some());
    assert!(idle.transitions()[0].guard().is_some());

    let Item::Task(task) = &items[7] else {
        panic!("expected Task");
    };
    assert_eq!(task.on_terms().len(), 1);
    assert_eq!(task.on_terms()[0].alias().unwrap().text(), "vel");
    let filters = task.on_chain_filters();
    assert_eq!(filters.len(), 1);
    assert_eq!(filters[0].name.text(), "with");
    assert!(filters[0].generic_args.is_some());
    assert!(filters[0].arg_list.is_some());
    assert_eq!(task.using_params().len(), 1);

    let Item::Table(table) = &items[8] else {
        panic!("expected Table");
    };
    assert_eq!(ast::path_text(&table.key_enum().unwrap()), "Kind");
    assert_eq!(table.rows().len(), 2);
    assert_eq!(table.rows()[0].inits().len(), 1);

    let Item::Curve(curve) = &items[9] else {
        panic!("expected Curve");
    };
    assert_eq!(curve.input_type().unwrap().text().to_string(), "meters");
    assert_eq!(curve.output_type().unwrap().text().to_string(), "f32");
    assert_eq!(curve.points().len(), 2);

    let Item::Schedule(sched) = &items[10] else {
        panic!("expected Schedule");
    };
    assert_eq!(sched.label_text().as_deref(), Some("FixedUpdate"));
    assert_eq!(sched.modifiers().len(), 1);
    assert_eq!(sched.nodes()[0].kind(), ScheduleNodeKind::Seq);
    assert_eq!(sched.nodes()[0].children().len(), 2);
    assert!(sched.nodes()[0].children()[0].is_leaf());
}
