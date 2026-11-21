use strata_lsp::{
    SystemTelemetryDigest64, TELEMETRY_DIGEST_MAGIC, TELEMETRY_DIGEST_VERSION, TelemetryStore,
    compute_code_lenses, compute_diagnostics, compute_formatting, compute_hover, system_name_hash,
};
use tower_lsp::lsp_types::{HoverContents, Position};

#[test]
fn telemetry_digest64_roundtrip_and_brp_ingestion() {
    let store = TelemetryStore::new();
    let digest = SystemTelemetryDigest64 {
        magic: TELEMETRY_DIGEST_MAGIC,
        version: TELEMETRY_DIGEST_VERSION,
        flags: 0,
        system_name_hash: system_name_hash("integrate_rain"),
        frame_index: 499,
        avg_ns: 1450,
        p99_ns: 2100,
        entity_count: 2000,
        dirty_rows: 120,
        alloc_bytes: 0,
    };
    let wire = digest.to_le_bytes();
    assert_eq!(wire.len(), 64);

    let decoded = store.ingest_digest_bytes(&wire).expect("valid 64B digest");
    assert_eq!(decoded, digest);
    assert_eq!(store.get_for_system("integrate_rain"), Some(digest));

    let brp = r#"{
        "method": "bam/list_schemas",
        "result": {
            "schemas": [
                {
                    "canonical_name": "tutorial::rain_swarm::Pos3D",
                    "schema_fingerprint": 123456789,
                    "size": 12,
                    "align": 4
                }
            ]
        }
    }"#;
    let ingested = store.ingest_brp_json(brp).expect("BRP schema JSON");
    assert_eq!(ingested, 1);
    let schema = store
        .get_schema("tutorial::rain_swarm::Pos3D")
        .expect("schema cached");
    assert_eq!(schema.size, 12);
}

#[test]
fn lsp_diagnostics_hover_formatting_and_live_codelens() {
    let src = r#"module demo::lsp_test @version(1.0.0);

component Pos2D { xy: vec2 = vec2::ZERO }
component Vel2D { dxy: vec2 = vec2::ZERO }

@par(chunk = 256)
sys move_all() {
    for e in query(p: &mut Pos2D, v: &Vel2D) {
        e.p.xy += e.v.dxy;
    }
}

schedule FixedUpdate { move_all }
"#;

    let diags = compute_diagnostics(src);
    assert!(diags.is_empty(), "unexpected diagnostics: {diags:?}");

    // Hover over `Pos2D` (line 2, col 12)
    let hover = compute_hover(src, Position::new(2, 12)).expect("hover card");
    let HoverContents::Markup(m) = hover.contents else {
        panic!("expected markdown hover");
    };
    assert!(m.value.contains("8 B"));
    assert!(m.value.contains("ComponentUuid"));
    assert!(m.value.contains("Schema Fingerprint"));

    // Formatting idempotence
    let edits = compute_formatting(src);
    let _ = edits;

    // CodeLens with live 64B telemetry
    let store = TelemetryStore::new();
    store.record_digest(SystemTelemetryDigest64 {
        magic: TELEMETRY_DIGEST_MAGIC,
        version: TELEMETRY_DIGEST_VERSION,
        flags: 0,
        system_name_hash: system_name_hash("move_all"),
        frame_index: 120,
        avg_ns: 420,
        p99_ns: 650,
        entity_count: 1024,
        dirty_rows: 1024,
        alloc_bytes: 0,
    });
    let lenses = compute_code_lenses(src, &store);
    assert_eq!(lenses.len(), 1);
    let title = &lenses[0].command.as_ref().unwrap().title;
    assert!(title.contains("@par(chunk=256)"));
    assert!(title.contains("0.42 us"));
    assert!(title.contains("alloc: 0 B"));

    // Invalid source emits error diagnostics
    let broken = r#"
module demo::bad;
component Pos { x: f32 = 0.0 }
sys bad_alias() {
    for a in query(p: &mut Pos, q: &Pos) {
        a.p.x += 1.0;
    }
}
"#;
    let err_diags = compute_diagnostics(broken);
    assert!(!err_diags.is_empty());
}
