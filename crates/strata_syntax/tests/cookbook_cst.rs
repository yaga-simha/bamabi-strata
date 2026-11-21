use strata_syntax::ast::{AstNode, SourceFile};
use strata_syntax::{SyntaxKind, format_source, lex, parse};

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

    let root = SourceFile::cast(parsed.syntax()).expect("root");
    let item_count = root.items().count();
    assert!(
        item_count >= 2,
        "expected parser to recover module and Healthy component, got {item_count}"
    );
}
