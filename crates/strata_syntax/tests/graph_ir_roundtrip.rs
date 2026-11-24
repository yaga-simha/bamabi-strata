use strata_syntax::graph_ir::{
    ComponentPayload, CurvePointIr, FieldIr, FsmStateIr, FsmTransitionIr, GraphAttrArg,
    GraphAttribute, GraphIrDelta, GraphIrDocument, GraphIrError, GraphIrNode, GraphIrPatch,
    GraphLayoutSidecar, GraphNodeKind, GraphNodePayload, NodeLayout, ScheduleNodeIr,
    SchedulePayload, TableRowIr, TimelineEventIr, TimelineWindowIr, apply_graph_document,
    apply_graph_patch, export_graph_ir, export_graph_ir_with_sidecar, fallback_schema_fingerprint,
    load_sidecar, merge_sidecar, save_sidecar, sidecar_path_for,
};
use strata_syntax::parse;

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
fn all_cookbooks_export_json_roundtrip_and_zero_diff_on_position_edits() {
    for (name, src) in COOKBOOKS {
        let doc = export_graph_ir(src, None)
            .unwrap_or_else(|e| panic!("{name} export_graph_ir failed: {e}"));
        assert_eq!(doc.version, "1.0");
        assert!(!doc.nodes.is_empty(), "{name} should export graph nodes");

        let json = serde_json::to_string_pretty(&doc).expect("serialize GraphIrDocument");
        let mut decoded: GraphIrDocument =
            serde_json::from_str(&json).expect("deserialize GraphIrDocument");
        for (idx, n) in decoded.nodes.iter_mut().enumerate() {
            n.position = Some(NodeLayout {
                x: (idx as f64) * 200.0,
                y: 120.0,
                collapsed: Some(false),
            });
        }

        let fp_before = fallback_schema_fingerprint(src);
        let applied = apply_graph_patch(src, &GraphIrPatch::Document(decoded))
            .unwrap_or_else(|e| panic!("{name} apply_graph_patch failed: {e}"));
        assert!(
            !applied.source_modified,
            "{name} position-only patch modified .strata source"
        );
        assert_eq!(applied.source, src);
        assert_eq!(fallback_schema_fingerprint(&applied.source), fp_before);
    }

    // Cookbook 07 must export all 8 GraphNodeKind variants.
    let boss_doc = export_graph_ir(COOKBOOKS[6].1, None).expect("07 export");
    let kinds: std::collections::HashSet<GraphNodeKind> =
        boss_doc.nodes.iter().map(|n| n.kind).collect();
    for required in [
        GraphNodeKind::Component,
        GraphNodeKind::NodePureFn,
        GraphNodeKind::Timeline,
        GraphNodeKind::Fsm,
        GraphNodeKind::Task,
        GraphNodeKind::Table,
        GraphNodeKind::Curve,
        GraphNodeKind::Schedule,
    ] {
        assert!(
            kinds.contains(&required),
            "07_visual_boss_graph.strata missing GraphNodeKind::{required:?}"
        );
    }
}

#[test]
fn cookbook_edges_capture_require_reads_writes_key_enum_and_schedule() {
    let metroid = export_graph_ir(COOKBOOKS[2].1, None).expect("metroid export");
    assert!(metroid.edges.iter().any(|e| {
        e.from == "genres::metroidvania::KinematicBody"
            && e.to == "genres::metroidvania::Pos2D"
            && e.kind == "require"
    }));
    assert!(metroid.edges.iter().any(|e| {
        e.from == "genres::metroidvania::AirDashTask"
            && e.to == "genres::metroidvania::Vel2D"
            && e.kind == "writes"
    }));
    assert!(metroid.edges.iter().any(|e| {
        e.from == "genres::metroidvania::AirDashTask"
            && e.to == "genres::metroidvania::SimClock"
            && e.kind == "reads_resource"
    }));
    assert!(metroid.edges.iter().any(|e| {
        e.from == "genres::metroidvania::FixedUpdate"
            && e.to == "genres::metroidvania::AirDashTask"
            && e.kind == "schedules"
    }));

    let cozy = export_graph_ir(COOKBOOKS[3].1, None).expect("cozy export");
    assert!(cozy.edges.iter().any(|e| {
        e.from == "genres::cozy_valley::CropSpec"
            && e.to == "genres::cozy_valley::CropKind"
            && e.kind == "key_enum"
    }));
}

#[test]
fn roundtrip_edits_all_8_constructs_and_preserves_untouched_comments() {
    let src = r#"// Top-level header comment
module game::boss @version(1.0.0);

enum Phase { Intro = 0, Enraged = 1 }

// Keep this comment above BossHealth verbatim!
component BossHealth {
    hp:   f32 = 500.0, // inline field comment
}

@node_pure
fn compute_dmg(base: f32, mult: f32) -> f32 {
    return base * mult;
}

timeline SlashTl @rate(60_hz) @duration(20_f) {
    window active = 2_f .. 10_f;
    at 0_f => { let armed = true; }
    at 2_f => trigger(self, SlashHit {});
}

fsm BossFsm @require(BossHealth) {
    initial Intro;
    state Intro {
        on_enter {
            let enter_flag = 1;
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

    let mut doc = export_graph_ir(src, None).expect("export");

    // 1. Modify NodePureFn
    if let GraphNodePayload::NodePureFn(ref mut fn_p) = doc.nodes[1].payload {
        fn_p.body = "{\n    return base * mult * 1.25;\n}".to_owned();
    }
    // 2. Modify Timeline
    if let GraphNodePayload::Timeline(ref mut tl_p) = doc.nodes[2].payload {
        tl_p.windows.push(TimelineWindowIr {
            name: "recovery".to_owned(),
            expr: "10_f .. 20_f".to_owned(),
        });
    }
    // 3. Modify Fsm
    if let GraphNodePayload::Fsm(ref mut fsm_p) = doc.nodes[3].payload {
        fsm_p.states.push(FsmStateIr {
            name: "Staggered".to_owned(),
            fields: vec![],
            on_enter: Some("{\n    let stunned = true;\n}".to_owned()),
            on_tick: None,
            on_exit: None,
            transitions: vec![FsmTransitionIr {
                target: "Intro".to_owned(),
                init: None,
                when: "true".to_owned(),
                attributes: vec![],
            }],
        });
    }
    // 4. Modify Task
    if let GraphNodePayload::Task(ref mut task_p) = doc.nodes[4].payload {
        task_p.body = "{\n    hp -= speed * 2.0;\n}".to_owned();
    }
    // 5. Modify Table
    if let GraphNodePayload::Table(ref mut tbl_p) = doc.nodes[5].payload {
        tbl_p.rows[1] = TableRowIr {
            variant: "Enraged".to_owned(),
            values: tbl_p.rows[1].values.clone(),
        };
        tbl_p.rows[1].values[0].value = Some("2.0".to_owned());
    }
    // 6. Modify Curve
    if let GraphNodePayload::Curve(ref mut crv_p) = doc.nodes[6].payload {
        crv_p.points.push(CurvePointIr {
            x: "100.0_m".to_owned(),
            y: "0.0".to_owned(),
        });
    }
    // 7. Modify Schedule
    if let GraphNodePayload::Schedule(ref mut sch_p) = doc.nodes[7].payload
        && let ScheduleNodeIr::Group { children, .. } = &mut sch_p.nodes[0]
    {
        children.push(ScheduleNodeIr::Leaf {
            target: "SlashTl".to_owned(),
            modifiers: vec![],
        });
    }

    // Notice BossHealth (doc.nodes[0]) was NOT modified!
    let res1 = apply_graph_document(src, &doc).expect("apply modified doc");
    assert!(res1.source_modified);
    assert!(
        !res1
            .updated_nodes
            .contains(&"game::boss::BossHealth".to_owned())
    );
    assert!(res1.source.contains("// Top-level header comment"));
    assert!(
        res1.source
            .contains("// Keep this comment above BossHealth verbatim!")
    );
    assert!(
        res1.source
            .contains("hp:   f32 = 500.0, // inline field comment")
    );
    assert!(parse(&res1.source).ok());

    // Second round-trip: re-export and apply immediately -> must be 0-byte diff!
    let doc2 = export_graph_ir(&res1.source, None).expect("re-export");
    let res2 = apply_graph_document(&res1.source, &doc2).expect("idempotent re-apply");
    assert!(
        !res2.source_modified,
        "second round-trip must produce 0 diff"
    );
    assert_eq!(res2.source, res1.source);
}

#[test]
fn delta_add_remove_rename_and_error_paths() {
    let src = r#"module m;

component A { x: f32 }
component B { y: i32 }
"#;
    let delta = GraphIrDelta {
        upsert: vec![
            GraphIrNode {
                id: "m::ARenamed".to_owned(),
                kind: GraphNodeKind::Component,
                name: "ARenamed".to_owned(),
                group: Some("RenamedGroup".to_owned()),
                attributes: vec![GraphAttribute {
                    name: "persist".to_owned(),
                    args: vec![],
                }],
                payload: GraphNodePayload::Component(ComponentPayload {
                    is_unit: false,
                    requires: vec![],
                    strata: vec![],
                    fields: vec![FieldIr {
                        attributes: vec![],
                        name: "x".to_owned(),
                        ty: "f32".to_owned(),
                        default: Some("1.0".to_owned()),
                    }],
                }),
                span: None,
                position: Some(NodeLayout {
                    x: 10.0,
                    y: 20.0,
                    collapsed: None,
                }),
                previous_id: Some("m::A".to_owned()),
            },
            GraphIrNode {
                id: "m::C".to_owned(),
                kind: GraphNodeKind::Component,
                name: "C".to_owned(),
                group: None,
                attributes: vec![GraphAttribute {
                    name: "net".to_owned(),
                    args: vec![GraphAttrArg {
                        key: None,
                        value: "reliable".to_owned(),
                    }],
                }],
                payload: GraphNodePayload::Component(ComponentPayload {
                    is_unit: true,
                    requires: vec![],
                    strata: vec![],
                    fields: vec![],
                }),
                span: None,
                position: None,
                previous_id: None,
            },
        ],
        remove: vec!["m::B".to_owned()],
        positions: Default::default(),
    };

    let json = serde_json::to_string(&delta).expect("serialize delta");
    let patch: GraphIrPatch = serde_json::from_str(&json).expect("deserialize GraphIrPatch::Delta");
    let res = apply_graph_patch(src, &patch).expect("apply delta");
    assert!(res.source_modified);
    assert!(parse(&res.source).ok());
    assert!(res.source.contains("component ARenamed"));
    assert!(res.source.contains("component C;"));
    assert!(!res.source.contains("component B"));
    assert!(res.sidecar_removals.contains(&"m::A".to_owned()));
    assert!(res.sidecar_removals.contains(&"m::B".to_owned()));
    assert!(res.sidecar_updates.contains_key("m::ARenamed"));

    // Error paths: unknown removal, duplicate id, kind/payload mismatch.
    let err_missing = apply_graph_patch(
        src,
        &GraphIrPatch::Delta(GraphIrDelta {
            remove: vec!["m::Missing".to_owned()],
            ..Default::default()
        }),
    )
    .unwrap_err();
    assert!(matches!(err_missing, GraphIrError::NodeNotFound(_)));

    let err_mismatch = apply_graph_patch(
        src,
        &GraphIrPatch::Delta(GraphIrDelta {
            upsert: vec![GraphIrNode {
                id: "m::Bad".to_owned(),
                kind: GraphNodeKind::Table,
                name: "Bad".to_owned(),
                group: None,
                attributes: vec![],
                payload: GraphNodePayload::Component(ComponentPayload {
                    is_unit: true,
                    requires: vec![],
                    strata: vec![],
                    fields: vec![],
                }),
                span: None,
                position: None,
                previous_id: None,
            }],
            ..Default::default()
        }),
    )
    .unwrap_err();
    assert!(matches!(err_mismatch, GraphIrError::InvalidNode { .. }));
}

#[test]
fn sidecar_persistence_merge_and_fingerprint_invariance() {
    let dir = std::env::temp_dir().join(format!("strata_graph_ir_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let strata_path = dir.join("boss.v1.strata");
    let sc_path = sidecar_path_for(&strata_path);
    assert!(sc_path.ends_with("boss.v1.strata.graph.json"));
    assert!(
        load_sidecar(&sc_path)
            .expect("missing sidecar ok")
            .is_none()
    );

    let src = r#"
module m;
component A { x: f32 = 0.0 }
sys step() { let v = 1; }
net_sim_test "net"(latency: 50ms) { step_net(1); }
"#;
    let fp_orig = fallback_schema_fingerprint(src);

    // Body-only and net_sim_test edits keep fallback_schema_fingerprint identical.
    let src_body_edited = r#"
module m;
// added comment
component A { x: f32 = 0.0 }
sys step() { let v = 999; }
net_sim_test "net"(latency: 90ms) { step_net(10); }
"#;
    assert_eq!(fallback_schema_fingerprint(src_body_edited), fp_orig);

    // Schema edit changes fingerprint.
    let src_schema_edited = r#"
module m;
component A { x: f32 = 0.0, y: f32 = 1.0 }
sys step() { let v = 1; }
"#;
    assert_ne!(fallback_schema_fingerprint(src_schema_edited), fp_orig);

    let mut delta = GraphIrDelta::default();
    delta.positions.insert(
        "m::A".to_owned(),
        NodeLayout {
            x: 320.5,
            y: 140.25,
            collapsed: Some(true),
        },
    );
    let applied = apply_graph_patch(src, &GraphIrPatch::Delta(delta)).expect("apply pos delta");
    assert!(!applied.source_modified);

    let sc = merge_sidecar(None, &applied, &fp_orig);
    save_sidecar(&sc_path, &sc).expect("save sidecar");
    let loaded: GraphLayoutSidecar = load_sidecar(&sc_path)
        .expect("load sidecar")
        .expect("sidecar exists");
    assert_eq!(loaded, sc);

    let exported = export_graph_ir_with_sidecar(src, Some(&fp_orig), Some(&loaded))
        .expect("export with sidecar");
    assert_eq!(exported.schema_fingerprint, fp_orig);
    assert_eq!(
        exported.nodes[0].position,
        Some(NodeLayout {
            x: 320.5,
            y: 140.25,
            collapsed: Some(true),
        })
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn curve_sample_and_receiver_method_edges_and_schedule_group_labels() {
    let src = r#"module m;

curve Falloff(meters -> f32) = [
    (0.0_m, 100.0),
    (50.0_m, 25.0),
];

fsm Brain {
    initial Idle;
    state Idle {
        to Idle when true;
    }
}

task Move() {
    let y = Falloff.sample(10.0_m);
    Brain.reset();
}

schedule FixedUpdate {
    seq BossTick {
        Move
    }
}
"#;

    let doc = export_graph_ir(src, None).expect("export");
    assert!(
        doc.edges.iter().any(|e| {
            e.from == "m::Move"
                && e.to == "m::Falloff"
                && e.kind == "table_lookup"
                && e.label.as_deref() == Some("sample")
        }),
        "expected table_lookup(sample) edge, got {:?}",
        doc.edges
    );
    assert!(
        !doc.edges
            .iter()
            .any(|e| e.from == "m::Move" && e.to == "m::Falloff" && e.kind == "call"),
        "Falloff.sample(...) must not emit a `call` edge: {:?}",
        doc.edges
    );
    assert!(
        doc.edges.iter().any(|e| {
            e.from == "m::Move"
                && e.to == "m::Brain"
                && e.kind == "call"
                && e.label.as_deref() == Some("reset")
        }),
        "expected call(reset) edge, got {:?}",
        doc.edges
    );
    assert!(
        doc.edges.iter().any(|e| {
            e.from == "m::FixedUpdate"
                && e.to == "m::Move"
                && e.kind == "schedules"
                && e.label.as_deref() == Some("BossTick")
        }),
        "expected schedules edge with group label BossTick, got {:?}",
        doc.edges
    );
}

#[test]
fn merge_sidecar_does_not_resurrect_renamed_or_removed_stale_position_keys() {
    let src = r#"module m;

component A { x: f32 }
component B { y: i32 }
"#;
    let mut existing = GraphLayoutSidecar::default();
    existing.nodes.insert(
        "m::A".to_owned(),
        NodeLayout {
            x: 10.0,
            y: 10.0,
            collapsed: None,
        },
    );
    existing.nodes.insert(
        "m::B".to_owned(),
        NodeLayout {
            x: 20.0,
            y: 20.0,
            collapsed: None,
        },
    );

    let mut delta = GraphIrDelta::default();
    // Stale positions for renamed `m::A` and removed `m::B`.
    delta.positions.insert(
        "m::A".to_owned(),
        NodeLayout {
            x: 999.0,
            y: 999.0,
            collapsed: None,
        },
    );
    delta.positions.insert(
        "m::B".to_owned(),
        NodeLayout {
            x: 888.0,
            y: 888.0,
            collapsed: None,
        },
    );
    delta.remove.push("m::B".to_owned());
    delta.upsert.push(GraphIrNode {
        id: "m::A2".to_owned(),
        kind: GraphNodeKind::Component,
        name: "A2".to_owned(),
        group: None,
        attributes: vec![],
        payload: GraphNodePayload::Component(ComponentPayload {
            is_unit: false,
            requires: vec![],
            strata: vec![],
            fields: vec![FieldIr {
                attributes: vec![],
                name: "x".to_owned(),
                ty: "f32".to_owned(),
                default: None,
            }],
        }),
        span: None,
        position: Some(NodeLayout {
            x: 50.0,
            y: 60.0,
            collapsed: None,
        }),
        previous_id: Some("m::A".to_owned()),
    });

    let res = apply_graph_patch(src, &GraphIrPatch::Delta(delta)).expect("apply rename delta");
    assert!(!res.sidecar_updates.contains_key("m::A"));
    assert!(!res.sidecar_updates.contains_key("m::B"));
    let merged_none = merge_sidecar(None, &res, "0x1");
    assert!(!merged_none.nodes.contains_key("m::A"));
    assert!(!merged_none.nodes.contains_key("m::B"));
    assert!(merged_none.nodes.contains_key("m::A2"));

    let merged_existing = merge_sidecar(Some(existing), &res, "0x1");
    assert!(!merged_existing.nodes.contains_key("m::A"));
    assert!(!merged_existing.nodes.contains_key("m::B"));
    assert_eq!(
        merged_existing.nodes.get("m::A2"),
        Some(&NodeLayout {
            x: 50.0,
            y: 60.0,
            collapsed: None,
        })
    );

    // If `m::A` is renamed to `m::A2` AND `m::B` is renamed to `m::A` in the same delta,
    // `m::A` must survive in the sidecar while `m::B` is pruned.
    let mut reuse_delta = GraphIrDelta::default();
    reuse_delta.upsert.push(GraphIrNode {
        id: "m::A2".to_owned(),
        kind: GraphNodeKind::Component,
        name: "A2".to_owned(),
        group: None,
        attributes: vec![],
        payload: GraphNodePayload::Component(ComponentPayload {
            is_unit: false,
            requires: vec![],
            strata: vec![],
            fields: vec![FieldIr {
                attributes: vec![],
                name: "x".to_owned(),
                ty: "f32".to_owned(),
                default: None,
            }],
        }),
        span: None,
        position: Some(NodeLayout {
            x: 100.0,
            y: 100.0,
            collapsed: None,
        }),
        previous_id: Some("m::A".to_owned()),
    });
    reuse_delta.upsert.push(GraphIrNode {
        id: "m::A".to_owned(),
        kind: GraphNodeKind::Component,
        name: "A".to_owned(),
        group: None,
        attributes: vec![],
        payload: GraphNodePayload::Component(ComponentPayload {
            is_unit: true,
            requires: vec![],
            strata: vec![],
            fields: vec![],
        }),
        span: None,
        position: Some(NodeLayout {
            x: 200.0,
            y: 200.0,
            collapsed: None,
        }),
        previous_id: Some("m::B".to_owned()),
    });
    let reuse_res =
        apply_graph_patch(src, &GraphIrPatch::Delta(reuse_delta)).expect("rename A->A2 and B->A");
    let reuse_merged = merge_sidecar(None, &reuse_res, "0x1");
    assert!(!reuse_merged.nodes.contains_key("m::B"));
    assert_eq!(
        reuse_merged.nodes.get("m::A"),
        Some(&NodeLayout {
            x: 200.0,
            y: 200.0,
            collapsed: None,
        })
    );
    assert_eq!(
        reuse_merged.nodes.get("m::A2"),
        Some(&NodeLayout {
            x: 100.0,
            y: 100.0,
            collapsed: None,
        })
    );
}

#[test]
fn document_and_delta_reject_id_plus_previous_id_collision_on_same_existing_node() {
    let src = r#"module m;

component A { x: f32 }
"#;
    let doc = export_graph_ir(src, None).expect("export");
    let mut renamed = doc.nodes[0].clone();
    renamed.id = "m::A2".to_owned();
    renamed.name = "A2".to_owned();
    renamed.previous_id = Some("m::A".to_owned());

    // Unchanged `m::A` followed by `m::A2` (previous_id: m::A).
    let mut bad_doc_1 = doc.clone();
    bad_doc_1.nodes.push(renamed.clone());
    let err_1 = apply_graph_document(src, &bad_doc_1).unwrap_err();
    assert!(
        matches!(err_1, GraphIrError::InvalidNode { .. }),
        "expected InvalidNode error, got {err_1:?}"
    );

    // Reverse order: `m::A2` (previous_id: m::A) followed by unchanged `m::A`.
    let mut bad_doc_2 = doc.clone();
    bad_doc_2.nodes.insert(0, renamed.clone());
    let err_2 = apply_graph_document(src, &bad_doc_2).unwrap_err();
    assert!(
        matches!(err_2, GraphIrError::InvalidNode { .. }),
        "expected InvalidNode error, got {err_2:?}"
    );

    // Delta upsert collision between unchanged `m::A` and `m::A2` (previous_id: m::A).
    let bad_delta = GraphIrDelta {
        upsert: vec![doc.nodes[0].clone(), renamed],
        ..Default::default()
    };
    let err_3 = apply_graph_patch(src, &GraphIrPatch::Delta(bad_delta)).unwrap_err();
    assert!(
        matches!(err_3, GraphIrError::InvalidNode { .. }),
        "expected InvalidNode error, got {err_3:?}"
    );
}

#[test]
fn delta_rejects_target_id_collisions_while_allowing_valid_swaps_and_delete_renames() {
    let src = r#"module m;

component A { x: f32 }
component B { y: i32 }
"#;
    let doc = export_graph_ir(src, None).expect("export");
    let node_a = doc.nodes[0].clone();
    let node_b = doc.nodes[1].clone();

    // (a) Renaming A -> B when B already exists untouched must fail.
    let mut rename_onto_b = node_a.clone();
    rename_onto_b.id = "m::B".to_owned();
    rename_onto_b.name = "B".to_owned();
    rename_onto_b.previous_id = Some("m::A".to_owned());
    let err_rename = apply_graph_patch(
        src,
        &GraphIrPatch::Delta(GraphIrDelta {
            upsert: vec![rename_onto_b],
            ..Default::default()
        }),
    )
    .unwrap_err();
    assert!(
        matches!(err_rename, GraphIrError::InvalidNode { ref id, .. } if id == "m::B"),
        "expected InvalidNode on rename onto existing B, got {err_rename:?}"
    );

    // (b) Upserting B with unknown previous_id ("m::Ghost") when B already exists untouched must fail.
    let mut ghost_onto_b = node_a.clone();
    ghost_onto_b.id = "m::B".to_owned();
    ghost_onto_b.name = "B".to_owned();
    ghost_onto_b.previous_id = Some("m::Ghost".to_owned());
    let err_ghost = apply_graph_patch(
        src,
        &GraphIrPatch::Delta(GraphIrDelta {
            upsert: vec![ghost_onto_b],
            ..Default::default()
        }),
    )
    .unwrap_err();
    assert!(
        matches!(err_ghost, GraphIrError::InvalidNode { ref id, .. } if id == "m::B"),
        "expected InvalidNode on unknown previous_id colliding with existing B, got {err_ghost:?}"
    );

    // Valid swap A <-> B must succeed without duplicate IDs.
    let mut swap_a_to_b = node_a.clone();
    swap_a_to_b.id = "m::B".to_owned();
    swap_a_to_b.name = "B".to_owned();
    swap_a_to_b.previous_id = Some("m::A".to_owned());

    let mut swap_b_to_a = node_b;
    swap_b_to_a.id = "m::A".to_owned();
    swap_b_to_a.name = "A".to_owned();
    swap_b_to_a.previous_id = Some("m::B".to_owned());

    let swap_res = apply_graph_patch(
        src,
        &GraphIrPatch::Delta(GraphIrDelta {
            upsert: vec![swap_a_to_b, swap_b_to_a],
            ..Default::default()
        }),
    )
    .expect("valid swap A <-> B should succeed");
    assert!(parse(&swap_res.source).ok());
    let swap_doc = export_graph_ir(&swap_res.source, None).expect("re-export swap");
    assert_eq!(swap_doc.nodes.len(), 2);

    // Valid remove B + rename A -> B must succeed without duplicate IDs.
    let mut rename_after_remove = node_a;
    rename_after_remove.id = "m::B".to_owned();
    rename_after_remove.name = "B".to_owned();
    rename_after_remove.previous_id = Some("m::A".to_owned());

    let del_rename_res = apply_graph_patch(
        src,
        &GraphIrPatch::Delta(GraphIrDelta {
            upsert: vec![rename_after_remove],
            remove: vec!["m::B".to_owned()],
            ..Default::default()
        }),
    )
    .expect("remove B + rename A -> B should succeed");
    assert!(parse(&del_rename_res.source).ok());
    let del_doc = export_graph_ir(&del_rename_res.source, None).expect("re-export del+rename");
    assert_eq!(del_doc.nodes.len(), 1);
    assert_eq!(del_doc.nodes[0].id, "m::B");
}

#[test]
fn document_and_delta_reject_mismatched_node_id_and_name() {
    let src = r#"module m;

component A { x: f32 }
"#;
    let mut doc = export_graph_ir(src, None).expect("export");
    let mut mismatched = doc.nodes[0].clone();
    mismatched.id = "m::B".to_owned();
    mismatched.name = "A".to_owned();

    doc.nodes.push(mismatched.clone());
    let doc_err = apply_graph_document(src, &doc).unwrap_err();
    assert!(
        matches!(doc_err, GraphIrError::InvalidNode { ref id, .. } if id == "m::B"),
        "expected InvalidNode for mismatched doc node id/name, got {doc_err:?}"
    );

    let delta_err = apply_graph_patch(
        src,
        &GraphIrPatch::Delta(GraphIrDelta {
            upsert: vec![mismatched],
            ..Default::default()
        }),
    )
    .unwrap_err();
    assert!(
        matches!(delta_err, GraphIrError::InvalidNode { ref id, .. } if id == "m::B"),
        "expected InvalidNode for mismatched delta node id/name, got {delta_err:?}"
    );
}

#[test]
fn delta_positions_rejects_unknown_node_ids_and_non_graph_items() {
    let src = r#"module m;

component A { x: f32 }
sys Step() {}
"#;
    for bad_id in ["m::Unknown", "m::Step", "other::A", ""] {
        let mut delta = GraphIrDelta::default();
        delta.positions.insert(
            bad_id.to_owned(),
            NodeLayout {
                x: 10.0,
                y: 20.0,
                collapsed: None,
            },
        );
        let err = apply_graph_patch(src, &GraphIrPatch::Delta(delta)).unwrap_err();
        assert!(
            matches!(err, GraphIrError::InvalidNode { ref id, .. } if id == bad_id),
            "expected InvalidNode for unknown positions key `{bad_id}`, got {err:?}"
        );
    }
}

#[test]
fn delta_positions_accepts_newly_upserted_nodes_and_preserves_patch_node_precedence() {
    let src = r#"module m;

component A { x: f32 }
"#;
    let make_comp = |name: &str, position: Option<NodeLayout>| GraphIrNode {
        id: format!("m::{name}"),
        kind: GraphNodeKind::Component,
        name: name.to_owned(),
        group: None,
        attributes: vec![],
        payload: GraphNodePayload::Component(ComponentPayload {
            is_unit: true,
            requires: vec![],
            strata: vec![],
            fields: vec![],
        }),
        span: None,
        position,
        previous_id: None,
    };

    let mut delta = GraphIrDelta::default();
    delta.upsert.push(make_comp("B", None));
    delta.positions.insert(
        "m::B".to_owned(),
        NodeLayout {
            x: 10.0,
            y: 20.0,
            collapsed: None,
        },
    );
    delta.upsert.push(make_comp(
        "C",
        Some(NodeLayout {
            x: 50.0,
            y: 60.0,
            collapsed: None,
        }),
    ));
    delta.positions.insert(
        "m::C".to_owned(),
        NodeLayout {
            x: 999.0,
            y: 999.0,
            collapsed: None,
        },
    );

    let res = apply_graph_patch(src, &GraphIrPatch::Delta(delta))
        .expect("newly upserted node in delta.positions should succeed");
    assert_eq!(
        res.sidecar_updates.get("m::B"),
        Some(&NodeLayout {
            x: 10.0,
            y: 20.0,
            collapsed: None,
        })
    );
    assert_eq!(
        res.sidecar_updates.get("m::C"),
        Some(&NodeLayout {
            x: 50.0,
            y: 60.0,
            collapsed: None,
        })
    );
}

#[test]
fn patch_and_delta_reject_non_finite_positions() {
    let src = r#"module m;

component A { x: f32 }
"#;
    let bad_coords = [
        (f64::NAN, 0.0),
        (0.0, f64::INFINITY),
        (f64::NEG_INFINITY, 1.0),
    ];

    for (x, y) in bad_coords {
        let mut delta = GraphIrDelta::default();
        delta.positions.insert(
            "m::A".to_owned(),
            NodeLayout {
                x,
                y,
                collapsed: None,
            },
        );
        let err = apply_graph_patch(src, &GraphIrPatch::Delta(delta)).unwrap_err();
        assert!(
            matches!(err, GraphIrError::InvalidNode { ref id, .. } if id == "m::A"),
            "expected InvalidNode for non-finite delta.positions ({x}, {y}), got {err:?}"
        );
    }

    // Non-finite coordinates must still fail even if the node is simultaneously removed.
    let mut rm_delta = GraphIrDelta::default();
    rm_delta.remove.push("m::A".to_owned());
    rm_delta.positions.insert(
        "m::A".to_owned(),
        NodeLayout {
            x: f64::NAN,
            y: 0.0,
            collapsed: None,
        },
    );
    let rm_err = apply_graph_patch(src, &GraphIrPatch::Delta(rm_delta)).unwrap_err();
    assert!(
        matches!(rm_err, GraphIrError::InvalidNode { ref id, .. } if id == "m::A"),
        "expected InvalidNode for non-finite position on removed node, got {rm_err:?}"
    );

    // Non-finite `patch_node.position` in both Delta and Document patches.
    let mut doc = export_graph_ir(src, None).expect("export");
    doc.nodes[0].position = Some(NodeLayout {
        x: f64::NAN,
        y: 1.0,
        collapsed: None,
    });
    let delta_node_err = apply_graph_patch(
        src,
        &GraphIrPatch::Delta(GraphIrDelta {
            upsert: vec![doc.nodes[0].clone()],
            ..Default::default()
        }),
    )
    .unwrap_err();
    assert!(
        matches!(delta_node_err, GraphIrError::InvalidNode { ref id, .. } if id == "m::A"),
        "expected InvalidNode for non-finite upsert position, got {delta_node_err:?}"
    );

    doc.nodes[0].position = Some(NodeLayout {
        x: 1.0,
        y: f64::INFINITY,
        collapsed: None,
    });
    let doc_node_err = apply_graph_document(src, &doc).unwrap_err();
    assert!(
        matches!(doc_node_err, GraphIrError::InvalidNode { ref id, .. } if id == "m::A"),
        "expected InvalidNode for non-finite document node position, got {doc_node_err:?}"
    );
}

#[test]
fn duplicate_schedule_labels_disambiguate_and_roundtrip_idempotently() {
    let src = r#"module test::multi_sched;

sys alpha() {}
sys beta() {}
sys gamma() {}

// First FixedUpdate schedule
schedule FixedUpdate {
    alpha
}

// Second FixedUpdate schedule
schedule FixedUpdate {
    seq Sub {
        beta
    }
}

schedule Update {
    gamma
}
"#;

    let doc = export_graph_ir(src, None).expect("export multi-schedule");
    let sched_ids: Vec<&str> = doc.nodes.iter().map(|n| n.id.as_str()).collect();
    assert_eq!(
        sched_ids,
        vec![
            "test::multi_sched::FixedUpdate",
            "test::multi_sched::FixedUpdate#2",
            "test::multi_sched::Update",
        ]
    );
    assert_eq!(doc.nodes[0].name, "FixedUpdate");
    assert_eq!(doc.nodes[1].name, "FixedUpdate");
    assert_eq!(doc.nodes[2].name, "Update");

    // Edges must originate from the disambiguated schedule node IDs.
    assert!(doc.edges.iter().any(|e| {
        e.from == "test::multi_sched::FixedUpdate"
            && e.to == "test::multi_sched::alpha"
            && e.kind == "schedules"
    }));
    assert!(doc.edges.iter().any(|e| {
        e.from == "test::multi_sched::FixedUpdate#2"
            && e.to == "test::multi_sched::beta"
            && e.kind == "schedules"
            && e.label.as_deref() == Some("Sub")
    }));

    // Self-roundtrip (with layout positions) must produce 0-byte diff.
    let mut positioned = doc.clone();
    for (idx, n) in positioned.nodes.iter_mut().enumerate() {
        n.position = Some(NodeLayout {
            x: (idx as f64) * 100.0,
            y: 50.0,
            collapsed: None,
        });
    }
    let noop = apply_graph_document(src, &positioned).expect("self-roundtrip");
    assert!(!noop.source_modified);
    assert_eq!(noop.source, src);
    assert_eq!(noop.sidecar_updates.len(), 3);

    // Editing only the second duplicate schedule updates it cleanly while preserving the first.
    let mut edited = doc.clone();
    if let GraphNodePayload::Schedule(ref mut sch) = edited.nodes[1].payload
        && let ScheduleNodeIr::Group { children, .. } = &mut sch.nodes[0]
    {
        children.push(ScheduleNodeIr::Leaf {
            target: "gamma".to_owned(),
            modifiers: vec![],
        });
    }
    let updated = apply_graph_document(src, &edited).expect("update duplicate schedule");
    assert!(updated.source_modified);
    assert_eq!(
        updated.updated_nodes,
        vec!["test::multi_sched::FixedUpdate#2"]
    );
    assert!(updated.source.contains("// First FixedUpdate schedule"));
    assert!(
        updated
            .source
            .contains("schedule FixedUpdate {\n    alpha\n}")
    );
    assert!(parse(&updated.source).ok());

    let reexported = export_graph_ir(&updated.source, None).expect("re-export");
    let reapplied = apply_graph_document(&updated.source, &reexported).expect("re-apply");
    assert!(!reapplied.source_modified);

    // Adding a third `FixedUpdate` via Delta is accepted and roundtrips.
    let add_delta = GraphIrPatch::Delta(GraphIrDelta {
        upsert: vec![GraphIrNode {
            id: "test::multi_sched::FixedUpdate#3".to_owned(),
            kind: GraphNodeKind::Schedule,
            name: "FixedUpdate".to_owned(),
            group: None,
            attributes: vec![],
            payload: GraphNodePayload::Schedule(SchedulePayload {
                modifiers: vec![],
                nodes: vec![ScheduleNodeIr::Leaf {
                    target: "alpha".to_owned(),
                    modifiers: vec![],
                }],
            }),
            span: None,
            position: None,
            previous_id: None,
        }],
        ..Default::default()
    });
    let added = apply_graph_patch(src, &add_delta).expect("add third FixedUpdate");
    assert!(parse(&added.source).ok());
    let doc3 = export_graph_ir(&added.source, None).expect("export 3 schedules");
    assert_eq!(
        doc3.nodes.iter().map(|n| n.id.as_str()).collect::<Vec<_>>(),
        vec![
            "test::multi_sched::FixedUpdate",
            "test::multi_sched::FixedUpdate#2",
            "test::multi_sched::Update",
            "test::multi_sched::FixedUpdate#3",
        ]
    );

    // Deleting the first duplicate removes only the first block.
    let mut del_first = doc;
    del_first.nodes.remove(0);
    let del_res = apply_graph_document(src, &del_first).expect("delete first duplicate");
    assert_eq!(
        del_res.removed_nodes,
        vec!["test::multi_sched::FixedUpdate"]
    );
    assert!(del_res.source.contains("// Second FixedUpdate schedule"));
    assert!(parse(&del_res.source).ok());

    // Invalid schedule suffixes and non-schedule `#N` suffixes must still be rejected.
    for bad_id in [
        "test::multi_sched::FixedUpdate#0",
        "test::multi_sched::FixedUpdate#1",
        "test::multi_sched::FixedUpdate#02",
        "test::multi_sched::FixedUpdate#abc",
        "test::multi_sched::Other",
    ] {
        let err = apply_graph_patch(
            src,
            &GraphIrPatch::Delta(GraphIrDelta {
                upsert: vec![GraphIrNode {
                    id: bad_id.to_owned(),
                    kind: GraphNodeKind::Schedule,
                    name: "FixedUpdate".to_owned(),
                    group: None,
                    attributes: vec![],
                    payload: GraphNodePayload::Schedule(SchedulePayload {
                        modifiers: vec![],
                        nodes: vec![],
                    }),
                    span: None,
                    position: None,
                    previous_id: None,
                }],
                ..Default::default()
            }),
        )
        .unwrap_err();
        assert!(
            matches!(err, GraphIrError::InvalidNode { .. }),
            "expected InvalidNode for `{bad_id}`, got {err:?}"
        );
    }
}

#[test]
fn timeline_compound_statements_roundtrip_without_spurious_semicolons() {
    let src = r#"module test::tl_compound;

event Hit {}

timeline BossTl {
    at 1_f => while false { let a: i32 = 1; }
    at 2_f => atomic { let b: i32 = 2; }
    at 3_f => atomic { let c: i32 = 3; } on_rollback { let r: i32 = 0; }
    at 4_f => loop { break; }
    at 5_f => for i in 0..3 { let d: i32 = i; }
    at 6_f => if true { let e: i32 = 4; } else { let e: i32 = 5; }
    at 7_f => match 1 { 0 => { let m: i32 = 0; }, _ => { let m: i32 = 1; } }
    at 8_f => abort_if false { return; }
    at 9_f => race { branch { wait 1_f; } }
    at 10_f => while false {
        let multi: i32 = 9;
    }
}
"#;

    let mut doc = export_graph_ir(src, None).expect("export timeline");
    if let GraphNodePayload::Timeline(ref mut tl) = doc.nodes[0].payload {
        // Also test an expression action supplied without trailing semicolon gets `;`,
        // while a struct-RHS assignment without `;` also gets `;`.
        tl.events.push(TimelineEventIr {
            frame: "11_f".to_owned(),
            action: "trigger(self, Hit {})".to_owned(),
        });
        tl.events.push(TimelineEventIr {
            frame: "12_f".to_owned(),
            action: "if false { let added: i32 = 1; }".to_owned(),
        });
    } else {
        panic!("expected Timeline payload");
    }

    let applied = apply_graph_document(src, &doc).expect("apply timeline compound edits");
    assert!(applied.source_modified);
    assert!(
        parse(&applied.source).ok(),
        "syntax errors in:\n{}\n{:?}",
        applied.source,
        parse(&applied.source).errors()
    );
    assert!(!applied.source.contains("};"));
    assert!(
        applied
            .source
            .contains("at 10_f => while false {\n        let multi: i32 = 9;\n    }")
    );
    assert!(applied.source.contains("at 11_f => trigger(self, Hit {});"));
    assert!(
        applied
            .source
            .contains("at 12_f => if false { let added: i32 = 1; }\n")
    );

    // Re-export -> re-apply must be idempotent (0-byte diff).
    let reexported = export_graph_ir(&applied.source, None).expect("re-export timeline");
    let reapplied = apply_graph_document(&applied.source, &reexported).expect("re-apply timeline");
    assert!(
        !reapplied.source_modified,
        "expected 0-byte diff on re-apply:\n{}",
        reapplied.source
    );
    assert_eq!(reapplied.source, applied.source);
}

#[test]
fn graph_ir_patch_rejects_malformed_documents_and_unknown_delta_keys() {
    let src = "module m;\n\ncomponent A { x: f32 = 1.0 }\ncomponent B { y: i32 = 2 }\n";
    let doc = export_graph_ir(src, None).expect("export");
    let doc_val = serde_json::to_value(&doc).expect("doc to value");

    // 1. Unknown key in Delta must fail deserialization (not silently become a no-op).
    for bad_delta in [
        r#"{"remove_typo":["m::A"]}"#,
        r#"{"upsert_typo":[]}"#,
        r#"{"positions_typo":{"m::A":{"x":1.0,"y":2.0}}}"#,
        r#"{"remove":["m::B"],"extra":true}"#,
    ] {
        let err_patch = serde_json::from_str::<GraphIrPatch>(bad_delta);
        assert!(
            err_patch.is_err(),
            "expected GraphIrPatch error for `{bad_delta}`"
        );
        let err_delta = serde_json::from_str::<GraphIrDelta>(bad_delta);
        assert!(
            err_delta.is_err(),
            "expected GraphIrDelta error for `{bad_delta}`"
        );
    }

    // 2. Malformed GraphIrDocument missing required fields must not silently fall back to Delta.
    for missing_field in ["version", "module_path", "schema_fingerprint", "edges"] {
        let mut obj = doc_val.as_object().expect("doc object").clone();
        obj.remove(missing_field);
        // Also drop node B so silent Delta fallback would have failed to remove B.
        if let Some(nodes) = obj.get_mut("nodes").and_then(|v| v.as_array_mut()) {
            nodes.truncate(1);
        }
        let raw = serde_json::to_string(&obj).expect("serialize malformed doc");
        let parsed = serde_json::from_str::<GraphIrPatch>(&raw);
        assert!(
            parsed.is_err(),
            "expected malformed document missing `{missing_field}` to fail deserialization"
        );
    }
    // Missing `nodes` alone must also fail.
    {
        let mut obj = doc_val.as_object().expect("doc object").clone();
        obj.remove("nodes");
        let raw = serde_json::to_string(&obj).expect("serialize doc without nodes");
        assert!(serde_json::from_str::<GraphIrPatch>(&raw).is_err());
    }

    // 3. Valid GraphIrDocument and all valid GraphIrDelta schema shapes remain accepted.
    let valid_doc_patch: GraphIrPatch =
        serde_json::from_value(doc_val).expect("valid GraphIrDocument");
    assert!(
        !apply_graph_patch(src, &valid_doc_patch)
            .unwrap()
            .source_modified
    );

    let nodes_alias_delta: GraphIrPatch = serde_json::from_str(
        r#"{"nodes":[{"id":"m::C","kind":"component","name":"C","payload":{"type":"component","is_unit":true}}]}"#,
    )
    .expect("valid delta with nodes alias");
    let res_alias = apply_graph_patch(src, &nodes_alias_delta).expect("apply nodes-alias delta");
    assert!(res_alias.source.contains("component C;"));

    let remove_delta: GraphIrPatch =
        serde_json::from_str(r#"{"remove":["m::B"]}"#).expect("valid remove delta");
    let res_rm = apply_graph_patch(src, &remove_delta).expect("apply remove delta");
    assert!(!res_rm.source.contains("component B"));
}

#[test]
fn fallback_schema_fingerprint_ignores_visual_attributes_like_node_group_pos_and_node_pure() {
    let base = r#"module test::vis_fp;

component Hero {
    hp: f32 = 100.0,
}

fn scale(x: f32) -> f32 {
    return x * 2.0;
}

timeline Tl {
    at 1_f => let a: i32 = 1;
}
"#;

    let with_group_a = r#"module test::vis_fp;

@node_group("A")
@pos(10.0, 20.0)
component Hero {
    hp: f32 = 100.0,
}

@node_pure
@node_group(name = "Math")
@pos(x = 50.0, y = 60.0)
fn scale(x: f32) -> f32 {
    return x * 2.0;
}

@node_group("Sequences")
timeline Tl {
    at 1_f => let a: i32 = 1;
}
"#;

    let with_group_b = r#"module test::vis_fp;

@node_group("B")
@pos(999.0, -40.0)
component Hero {
    hp: f32 = 100.0,
}

@node_pure
@node_group("PureFns")
fn scale(x: f32) -> f32 {
    return x * 99.0;
}

timeline Tl @node_group("Other") {
    at 1_f => let a: i32 = 1;
}
"#;

    let fp_base = fallback_schema_fingerprint(base);
    let fp_a = fallback_schema_fingerprint(with_group_a);
    let fp_b = fallback_schema_fingerprint(with_group_b);
    assert_eq!(fp_a, fp_base);
    assert_eq!(fp_b, fp_base);

    let doc_a = export_graph_ir(with_group_a, None).expect("export A");
    let doc_b = export_graph_ir(with_group_b, None).expect("export B");
    assert_eq!(doc_a.schema_fingerprint, fp_base);
    assert_eq!(doc_b.schema_fingerprint, fp_base);

    // Non-visual schema attributes (e.g. `@net` or `@sparse`) MUST still alter the fingerprint.
    let with_sparse = with_group_b.replace("component Hero {", "@sparse\ncomponent Hero {");
    assert_ne!(fallback_schema_fingerprint(&with_sparse), fp_base);
}
