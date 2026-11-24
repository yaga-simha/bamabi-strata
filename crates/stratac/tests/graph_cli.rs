#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;
use strata_syntax::graph_ir::{
    GraphIrDelta, GraphIrDocument, GraphIrNode, GraphIrPatch, GraphLayoutSidecar, GraphNodeKind,
    GraphNodePayload, NodeLayout, sidecar_path_for,
};
use stratac::cli::{Cli, OutputFormat};
use stratac::commands::graph_cmd::{GraphApplyReport, cmd_graph_apply, cmd_graph_export};
use stratac::commands::{cmd_check, cmd_layout, execute_cli};
use stratac::{EXIT_COMPILE_ERROR, EXIT_OK};
use tempfile::TempDir;

const ALL_8_CONSTRUCTS_SRC: &str = r#"// ⚔️ Top-level UTF-8 boss header comment
module game::boss @version(1.0.0);

enum Phase { Intro = 0, Enraged = 1 }
tag Marker;
event SlashHit {}

// Keep this comment above BossHealth verbatim!
@node_group("Boss/Stats")
component BossHealth {
    hp: f32 = 500.0, // inline field comment
}

@node_pure
@node_group("Boss/Math")
fn compute_dmg(base: f32, mult: f32) -> f32 {
    return base * mult;
}

timeline SlashTl @rate(60_hz) @duration(20_f) {
    window active = 2_f .. 10_f;
    at 0_f => { let armed: bool = true; }
    at 2_f => trigger(self, SlashHit {});
}

fsm BossFsm @require(BossHealth) {
    initial Intro;
    state Intro {
        on_enter {
            let enter_flag: i32 = 1;
        }
        to Enraged when true;
    }
    state Enraged {
        to Intro when false;
    }
}

task DashTask(speed: f32)
    on (hp: &mut BossHealth.hp)
    .with<Marker>()
{
    hp -= speed;
}

table PhaseCfg by Phase {
    speed_mult: f32,
} = {
    Intro => { speed_mult: 1.0 },
    Enraged => { speed_mult: 1.5 },
};

curve Falloff(meters -> f32) = [
    (0.0_m, 100.0),
    (50.0_m, 25.0),
];

schedule FixedUpdate {
    seq BossTick {
        DashTask
        BossFsm
    }
}
"#;

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).expect("read file for sha256");
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

#[test]
fn graph_export_covers_all_8_constructs_and_edges() {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("boss.strata");
    fs::write(&file, ALL_8_CONSTRUCTS_SRC).unwrap();

    let (code, json) = cmd_graph_export(&file, OutputFormat::Json);
    assert_eq!(code, EXIT_OK, "graph export failed: {json}");

    let doc: GraphIrDocument = serde_json::from_str(&json).expect("valid GraphIrDocument JSON");
    assert_eq!(doc.version, "1.0");
    assert_eq!(doc.module_path, "game::boss");
    assert!(doc.schema_fingerprint.starts_with("0x"));
    assert_eq!(doc.schema_fingerprint.len(), 18);

    let kinds: Vec<GraphNodeKind> = doc.nodes.iter().map(|n| n.kind).collect();
    assert!(kinds.contains(&GraphNodeKind::Component));
    assert!(kinds.contains(&GraphNodeKind::NodePureFn));
    assert!(kinds.contains(&GraphNodeKind::Timeline));
    assert!(kinds.contains(&GraphNodeKind::Fsm));
    assert!(kinds.contains(&GraphNodeKind::Task));
    assert!(kinds.contains(&GraphNodeKind::Table));
    assert!(kinds.contains(&GraphNodeKind::Curve));
    assert!(kinds.contains(&GraphNodeKind::Schedule));
    assert_eq!(doc.nodes.len(), 8);

    let health = doc
        .nodes
        .iter()
        .find(|n| n.id == "game::boss::BossHealth")
        .expect("BossHealth node");
    assert_eq!(health.group.as_deref(), Some("Boss/Stats"));
    assert!(health.position.is_none());

    assert!(!doc.edges.is_empty(), "expected graph edges");
    assert!(doc.edges.iter().any(|e| e.kind == "schedules"));

    // Text output also succeeds concisely.
    let (text_code, text_out) = cmd_graph_export(&file, OutputFormat::Text);
    assert_eq!(text_code, EXIT_OK);
    assert!(text_out.contains("game::boss"));
}

#[test]
fn graph_apply_roundtrip_preserves_comments_and_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("boss_rt.strata");
    fs::write(&file, ALL_8_CONSTRUCTS_SRC).unwrap();

    let (code, exported) = cmd_graph_export(&file, OutputFormat::Json);
    assert_eq!(code, EXIT_OK, "{exported}");
    let mut doc: GraphIrDocument = serde_json::from_str(&exported).unwrap();

    // Mutate BossHealth default value (`500.0` -> `750.0`) and compute_dmg body.
    for node in &mut doc.nodes {
        if node.id == "game::boss::BossHealth"
            && let GraphNodePayload::Component(ref mut comp) = node.payload
        {
            comp.fields[0].default = Some("750.0".to_owned());
        } else if node.id == "game::boss::compute_dmg"
            && let GraphNodePayload::NodePureFn(ref mut func) = node.payload
        {
            func.body = "{\n    return base * mult * 1.5;\n}".to_owned();
        }
    }

    let patch_path = tmp.path().join("patch.json");
    fs::write(&patch_path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();

    let (apply_code, apply_json) = cmd_graph_apply(&file, &patch_path, OutputFormat::Json);
    assert_eq!(apply_code, EXIT_OK, "graph apply failed: {apply_json}");
    let report: GraphApplyReport = serde_json::from_str(&apply_json).unwrap();
    assert!(report.source_modified);
    assert!(
        report
            .updated_nodes
            .contains(&"game::boss::BossHealth".to_owned())
    );
    assert!(
        report
            .updated_nodes
            .contains(&"game::boss::compute_dmg".to_owned())
    );

    let updated_src = fs::read_to_string(&file).unwrap();
    assert!(updated_src.contains("// ⚔️ Top-level UTF-8 boss header comment"));
    assert!(updated_src.contains("// Keep this comment above BossHealth verbatim!"));
    assert!(updated_src.contains("750.0"));
    assert!(updated_src.contains("base * mult * 1.5"));

    let (chk_code, chk_out) = cmd_check(&file, OutputFormat::Json);
    assert_eq!(chk_code, EXIT_OK, "check failed after apply: {chk_out}");

    // Re-export and re-apply unchanged document -> 0-byte diff (idempotent).
    let (re_code, re_exported) = cmd_graph_export(&file, OutputFormat::Json);
    assert_eq!(re_code, EXIT_OK);
    let noop_patch = tmp.path().join("noop.json");
    fs::write(&noop_patch, re_exported).unwrap();

    let sha_before = sha256_file(&file);
    let (noop_code, noop_json) = cmd_graph_apply(&file, &noop_patch, OutputFormat::Json);
    assert_eq!(noop_code, EXIT_OK, "{noop_json}");
    let noop_report: GraphApplyReport = serde_json::from_str(&noop_json).unwrap();
    assert!(!noop_report.source_modified);
    assert_eq!(sha256_file(&file), sha_before);
}

#[test]
fn graph_apply_position_only_produces_zero_diff_and_invariant_fingerprint() {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("boss_pos.strata");
    fs::write(&file, ALL_8_CONSTRUCTS_SRC).unwrap();

    let (exp_code1, exp_json1) = cmd_graph_export(&file, OutputFormat::Json);
    assert_eq!(exp_code1, EXIT_OK);
    let doc1: GraphIrDocument = serde_json::from_str(&exp_json1).unwrap();

    let (lay_code1, lay_json1) = cmd_layout(&file, OutputFormat::Json);
    assert_eq!(lay_code1, EXIT_OK);

    let sha_before = sha256_file(&file);
    let sc_path = sidecar_path_for(&file);
    assert!(!sc_path.exists());

    // Position-only delta patch creates `.strata.graph.json` with 0-byte diff in `.strata`.
    let mut positions = BTreeMap::new();
    positions.insert(
        "game::boss::BossHealth".to_owned(),
        NodeLayout {
            x: 120.5,
            y: -40.0,
            collapsed: None,
        },
    );
    positions.insert(
        "game::boss::BossFsm".to_owned(),
        NodeLayout {
            x: 400.0,
            y: 80.0,
            collapsed: Some(true),
        },
    );
    let delta = GraphIrPatch::Delta(GraphIrDelta {
        upsert: Vec::new(),
        remove: Vec::new(),
        positions,
    });
    let patch_path = tmp.path().join("pos_delta.json");
    fs::write(&patch_path, serde_json::to_string_pretty(&delta).unwrap()).unwrap();

    let (app_code, app_json) = cmd_graph_apply(&file, &patch_path, OutputFormat::Json);
    assert_eq!(app_code, EXIT_OK, "pos apply failed: {app_json}");
    let report: GraphApplyReport = serde_json::from_str(&app_json).unwrap();
    assert!(!report.source_modified);
    assert!(report.sidecar_modified);
    assert_eq!(sha256_file(&file), sha_before);
    assert!(sc_path.exists());

    // Sibling node positions are preserved when updating just one node's position.
    let mut positions2 = BTreeMap::new();
    positions2.insert(
        "game::boss::BossHealth".to_owned(),
        NodeLayout {
            x: 240.0,
            y: -10.0,
            collapsed: None,
        },
    );
    let delta2 = GraphIrPatch::Delta(GraphIrDelta {
        upsert: Vec::new(),
        remove: Vec::new(),
        positions: positions2,
    });
    let patch2 = tmp.path().join("pos_delta2.json");
    fs::write(&patch2, serde_json::to_string_pretty(&delta2).unwrap()).unwrap();
    let (app_code2, _) = cmd_graph_apply(&file, &patch2, OutputFormat::Json);
    assert_eq!(app_code2, EXIT_OK);
    assert_eq!(sha256_file(&file), sha_before);

    let sc_raw = fs::read_to_string(&sc_path).unwrap();
    let sc: GraphLayoutSidecar = serde_json::from_str(&sc_raw).unwrap();
    assert_eq!(
        sc.nodes.get("game::boss::BossHealth"),
        Some(&NodeLayout {
            x: 240.0,
            y: -10.0,
            collapsed: None
        })
    );
    assert_eq!(
        sc.nodes.get("game::boss::BossFsm"),
        Some(&NodeLayout {
            x: 400.0,
            y: 80.0,
            collapsed: Some(true)
        })
    );

    let (exp_code2, exp_json2) = cmd_graph_export(&file, OutputFormat::Json);
    assert_eq!(exp_code2, EXIT_OK);
    let doc2: GraphIrDocument = serde_json::from_str(&exp_json2).unwrap();
    assert_eq!(doc2.schema_fingerprint, doc1.schema_fingerprint);

    let (lay_code2, lay_json2) = cmd_layout(&file, OutputFormat::Json);
    assert_eq!(lay_code2, EXIT_OK);
    assert_eq!(lay_json2, lay_json1);
}

#[test]
fn graph_apply_rejects_semantic_errors_without_modifying_files() {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("sema_guard.strata");
    fs::write(&file, ALL_8_CONSTRUCTS_SRC).unwrap();

    let (exp_code, exp_json) = cmd_graph_export(&file, OutputFormat::Json);
    assert_eq!(exp_code, EXIT_OK);
    let mut doc: GraphIrDocument = serde_json::from_str(&exp_json).unwrap();

    // Introduce ECS mutation (`spawn(...)`) inside `@node_pure fn`.
    for node in &mut doc.nodes {
        if node.id == "game::boss::compute_dmg"
            && let GraphNodePayload::NodePureFn(ref mut func) = node.payload
        {
            func.body = "{\n    spawn(BossHealth { hp: 10.0 });\n    return base;\n}".to_owned();
        }
    }

    let patch_path = tmp.path().join("bad_sema_patch.json");
    fs::write(&patch_path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();

    let sha_before = sha256_file(&file);
    let (code, err_out) = cmd_graph_apply(&file, &patch_path, OutputFormat::Json);
    assert_eq!(code, EXIT_COMPILE_ERROR, "expected sema failure: {err_out}");
    assert_eq!(sha256_file(&file), sha_before);
    assert!(!sidecar_path_for(&file).exists());
}

#[test]
fn graph_error_paths_preserve_source_and_handle_empty_modules() {
    let tmp = TempDir::new().unwrap();

    // 1. Empty module exports empty nodes and edges cleanly.
    let empty_file = tmp.path().join("empty.strata");
    fs::write(&empty_file, "module empty::mod @version(1.0.0);\n").unwrap();
    let (empty_code, empty_json) = cmd_graph_export(&empty_file, OutputFormat::Json);
    assert_eq!(empty_code, EXIT_OK, "{empty_json}");
    let empty_doc: GraphIrDocument = serde_json::from_str(&empty_json).unwrap();
    assert!(empty_doc.nodes.is_empty());
    assert!(empty_doc.edges.is_empty());

    // 2. Parse error on export returns EXIT_COMPILE_ERROR.
    let broken_file = tmp.path().join("broken.strata");
    fs::write(&broken_file, "module broken::mod;\ncomponent {\n").unwrap();
    let (broken_code, broken_err) = cmd_graph_export(&broken_file, OutputFormat::Json);
    assert_eq!(broken_code, EXIT_COMPILE_ERROR);
    assert!(broken_err.to_lowercase().contains("parse"));

    // 3. Corrupted or non-numeric sidecar fails export without touching source.
    let sc_file = tmp.path().join("bad_sc.strata");
    fs::write(
        &sc_file,
        "module bad::sc @version(1.0.0);\ncomponent A { x: f32 = 0.0 }\n",
    )
    .unwrap();
    let sc_sha = sha256_file(&sc_file);
    let sc_path = sidecar_path_for(&sc_file);
    fs::write(&sc_path, "{not valid json").unwrap();
    let (c1, _) = cmd_graph_export(&sc_file, OutputFormat::Json);
    assert_eq!(c1, EXIT_COMPILE_ERROR);
    assert_eq!(sha256_file(&sc_file), sc_sha);

    fs::write(
        &sc_path,
        r#"{"layout_version":"1.0","nodes":{"bad::sc::A":{"x":"nan","y":1.0}}}"#,
    )
    .unwrap();
    let (c2, _) = cmd_graph_export(&sc_file, OutputFormat::Json);
    assert_eq!(c2, EXIT_COMPILE_ERROR);
    assert_eq!(sha256_file(&sc_file), sc_sha);
    fs::remove_file(&sc_path).unwrap();

    // 4. Invalid patch JSON, unknown removal ID, and kind/payload mismatch leave source untouched.
    let bad_patch = tmp.path().join("bad_patch.json");
    fs::write(&bad_patch, "{bad json").unwrap();
    let (p1, _) = cmd_graph_apply(&sc_file, &bad_patch, OutputFormat::Text);
    assert_eq!(p1, EXIT_COMPILE_ERROR);
    assert_eq!(sha256_file(&sc_file), sc_sha);

    let ghost_patch = tmp.path().join("ghost.json");
    fs::write(&ghost_patch, r#"{"remove":["bad::sc::Ghost"]}"#).unwrap();
    let (p2, p2_msg) = cmd_graph_apply(&sc_file, &ghost_patch, OutputFormat::Text);
    assert_eq!(p2, EXIT_COMPILE_ERROR);
    assert!(p2_msg.contains("Ghost"));
    assert_eq!(sha256_file(&sc_file), sc_sha);

    let (_, valid_exp) = cmd_graph_export(&sc_file, OutputFormat::Json);
    let mut mismatch_doc: GraphIrDocument = serde_json::from_str(&valid_exp).unwrap();
    let first: &mut GraphIrNode = &mut mismatch_doc.nodes[0];
    first.kind = GraphNodeKind::Fsm; // mismatched with Component payload
    let mismatch_patch = tmp.path().join("mismatch.json");
    fs::write(
        &mismatch_patch,
        serde_json::to_string_pretty(&mismatch_doc).unwrap(),
    )
    .unwrap();
    let (p3, _) = cmd_graph_apply(&sc_file, &mismatch_patch, OutputFormat::Text);
    assert_eq!(p3, EXIT_COMPILE_ERROR);
    assert_eq!(sha256_file(&sc_file), sc_sha);
}

#[test]
fn graph_cli_dispatch_and_binary_execution() {
    use clap::Parser as _;

    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("bin_boss.strata");
    fs::write(&file, ALL_8_CONSTRUCTS_SRC).unwrap();

    let cli = Cli::try_parse_from([
        "stratac",
        "graph",
        "export",
        file.to_str().unwrap(),
        "--format=json",
    ])
    .unwrap();
    let (code, out) = execute_cli(cli);
    assert_eq!(code, EXIT_OK, "{out}");
    let doc: GraphIrDocument = serde_json::from_str(&out).unwrap();
    assert_eq!(doc.module_path, "game::boss");

    // Verify compiled `stratac` binary end-to-end.
    let bin = env!("CARGO_BIN_EXE_stratac");
    let exp_proc = Command::new(bin)
        .args(["graph", "export", file.to_str().unwrap(), "--format=json"])
        .output()
        .expect("run stratac graph export");
    assert_eq!(exp_proc.status.code(), Some(0));
    let bin_doc: GraphIrDocument =
        serde_json::from_slice(&exp_proc.stdout).expect("binary stdout JSON");
    assert_eq!(bin_doc.nodes.len(), 8);

    let mut delta_pos = BTreeMap::new();
    delta_pos.insert(
        "game::boss::BossHealth".to_owned(),
        NodeLayout {
            x: 10.0,
            y: 20.0,
            collapsed: None,
        },
    );
    let patch_path = tmp.path().join("bin_patch.json");
    fs::write(
        &patch_path,
        serde_json::to_string(&GraphIrPatch::Delta(GraphIrDelta {
            positions: delta_pos,
            ..Default::default()
        }))
        .unwrap(),
    )
    .unwrap();

    let sha_before = sha256_file(&file);
    let app_proc = Command::new(bin)
        .args([
            "graph",
            "apply",
            file.to_str().unwrap(),
            patch_path.to_str().unwrap(),
        ])
        .output()
        .expect("run stratac graph apply");
    assert_eq!(app_proc.status.code(), Some(0));
    assert_eq!(sha256_file(&file), sha_before);
    assert!(sidecar_path_for(&file).exists());
}

#[test]
fn graph_apply_rejects_unknown_delta_position_id_without_mutating_files() {
    let tmp = TempDir::new().unwrap();
    let file = tmp.path().join("pos_guard.strata");
    fs::write(&file, ALL_8_CONSTRUCTS_SRC).unwrap();
    let sha_before = sha256_file(&file);
    let sc_path = sidecar_path_for(&file);
    assert!(!sc_path.exists());

    // Case 1: No sidecar on disk yet; unknown node ID in `delta.positions` must fail cleanly
    // without touching the `.strata` source or creating a `.strata.graph.json` sidecar.
    let bad_patch_1 = tmp.path().join("bad_pos_1.json");
    fs::write(
        &bad_patch_1,
        r#"{"positions":{"game::boss::UnknownNode":{"x":12.0,"y":34.0}}}"#,
    )
    .unwrap();
    let (code_1, out_1) = cmd_graph_apply(&file, &bad_patch_1, OutputFormat::Json);
    assert_eq!(code_1, EXIT_COMPILE_ERROR, "{out_1}");
    assert!(out_1.contains("UnknownNode"), "{out_1}");
    assert_eq!(sha256_file(&file), sha_before);
    assert!(!sc_path.exists());

    // Case 2: Valid sidecar already exists; a delta containing both a valid position and an
    // unknown `Ghost` position must fail atomically without mutating source or sidecar.
    let good_patch = tmp.path().join("good_pos.json");
    fs::write(
        &good_patch,
        r#"{"positions":{"game::boss::BossHealth":{"x":111.0,"y":222.0}}}"#,
    )
    .unwrap();
    let (ok_code, ok_out) = cmd_graph_apply(&file, &good_patch, OutputFormat::Json);
    assert_eq!(ok_code, EXIT_OK, "{ok_out}");
    assert!(sc_path.exists());
    let sc_sha_before = sha256_file(&sc_path);

    let bad_patch_2 = tmp.path().join("bad_pos_2.json");
    fs::write(
        &bad_patch_2,
        r#"{"positions":{"game::boss::BossHealth":{"x":555.0,"y":666.0},"game::boss::Ghost":{"x":1.0,"y":2.0}}}"#,
    )
    .unwrap();
    let (code_2, out_2) = cmd_graph_apply(&file, &bad_patch_2, OutputFormat::Json);
    assert_eq!(code_2, EXIT_COMPILE_ERROR, "{out_2}");
    assert!(out_2.contains("Ghost"), "{out_2}");
    assert_eq!(sha256_file(&file), sha_before);
    assert_eq!(sha256_file(&sc_path), sc_sha_before);
}
