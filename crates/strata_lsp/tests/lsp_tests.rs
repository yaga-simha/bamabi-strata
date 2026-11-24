use strata_lsp::{
    SYSTEM_TELEMETRY_DIGEST_VERSION, SYSTEM_TELEMETRY_MAGIC, SystemTelemetryDigest64,
    SystemTelemetryDigestJson, TELEMETRY_FLAG_QUARANTINED, TelemetryEndpoint, TelemetryError,
    TelemetryStore, compute_code_lenses, compute_diagnostics, compute_formatting, compute_hover,
    fetch_brp_component_schemas, fnv1a_64_hash_system, spawn_telemetry_subscriber,
    system_name_hash,
};
use tower_lsp::lsp_types::{HoverContents, Position};

#[test]
fn telemetry_digest64_roundtrip_and_brp_ingestion() {
    let store = TelemetryStore::new();
    let digest = SystemTelemetryDigest64 {
        magic: SYSTEM_TELEMETRY_MAGIC,
        version: SYSTEM_TELEMETRY_DIGEST_VERSION,
        flags: 0,
        mod_id: 3,
        system_hash: fnv1a_64_hash_system("tutorial::rain_swarm", "integrate_rain"),
        frame_seq: 499,
        matched_entities: 2000,
        matched_tables: 12,
        skipped_summary_tick_tables: 4,
        chunks: 16,
        p50_us: 145,
        p99_us: 210,
        commands_queued: 7,
        reserved: 0,
    };
    let wire = digest.to_le_bytes();
    assert_eq!(wire.len(), 64);
    assert_eq!(&wire[0..4], b"BAMT");

    let decoded = store.ingest_digest_bytes(&wire).expect("valid 64B digest");
    assert_eq!(decoded, digest);
    assert_eq!(
        store.get_for_system("tutorial::rain_swarm::integrate_rain"),
        Some(digest)
    );

    let brp = r#"{
        "method": "bam/component_schemas",
        "result": {
            "components": [
                {
                    "name": "tutorial::rain_swarm::Pos3D",
                    "schema_fingerprint": 123456789,
                    "size": 12,
                    "align": 4,
                    "is_pod": true
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
    assert!(schema.is_pod);
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
        magic: SYSTEM_TELEMETRY_MAGIC,
        version: SYSTEM_TELEMETRY_DIGEST_VERSION,
        flags: 0,
        mod_id: 1,
        system_hash: fnv1a_64_hash_system("demo::lsp_test", "move_all"),
        frame_seq: 120,
        matched_entities: 1024,
        matched_tables: 8,
        skipped_summary_tick_tables: 2,
        chunks: 4,
        p50_us: 42,
        p99_us: 65,
        commands_queued: 0,
        reserved: 0,
    });
    let lenses = compute_code_lenses(src, &store);
    assert_eq!(lenses.len(), 1);
    let title = &lenses[0].command.as_ref().unwrap().title;
    assert!(title.contains("@par(chunk=256)"));
    assert!(title.contains("p50: 42 us"));
    assert!(title.contains("entities: 1024"));

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

#[tokio::test]
async fn lsp_incremental_salsa_skips_layout_recomputation_on_body_only_edits() {
    use strata_lsp::StrataLspBackend;
    use tower_lsp::LanguageServer;
    use tower_lsp::lsp_types::{
        CodeLensParams, DidChangeTextDocumentParams, DidCloseTextDocumentParams,
        DidOpenTextDocumentParams, HoverParams, PartialResultParams,
        TextDocumentContentChangeEvent, TextDocumentIdentifier, TextDocumentItem,
        TextDocumentPositionParams, Url, VersionedTextDocumentIdentifier, WorkDoneProgressParams,
    };

    let backend = StrataLspBackend::headless(TelemetryStore::new());
    let uri = Url::parse("file:///test/incremental.strata").expect("valid uri");

    let v1 = concat!(
        "module demo::lsp_inc @version(1.0.0);\n",
        "\n",
        "component Pos { x: f32 = 0.0 }\n",
        "\n",
        "@par(chunk = 64)\n",
        "sys step() {\n",
        "    for e in query(p: &mut Pos) {\n",
        "        e.p.x += 1.0;\n",
        "    }\n",
        "}\n",
    );

    // 1. did_open executes both `resolve_layouts` and `analyze_module`.
    backend
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "strata".to_owned(),
                version: 1,
                text: v1.to_owned(),
            },
        })
        .await;
    let q_open = backend.take_executed_queries();
    assert!(
        q_open.iter().any(|q| q.contains("resolve_layouts")),
        "did_open should execute resolve_layouts; saw {q_open:?}"
    );
    assert!(
        q_open.iter().any(|q| q.contains("analyze_module")),
        "did_open should execute analyze_module; saw {q_open:?}"
    );

    // 2. Body-only did_change (`1.0` -> `2.5`) triggers 0 `resolve_layouts` recomputations
    //    while `analyze_module` executes.
    let v2 = concat!(
        "module demo::lsp_inc @version(1.0.0);\n",
        "\n",
        "component Pos { x: f32 = 0.0 }\n",
        "\n",
        "@par(chunk = 64)\n",
        "sys step() {\n",
        "    for e in query(p: &mut Pos) {\n",
        "        e.p.x += 2.5;\n",
        "    }\n",
        "}\n",
    );
    backend
        .did_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier {
                uri: uri.clone(),
                version: 2,
            },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: v2.to_owned(),
            }],
        })
        .await;
    let q_body = backend.take_executed_queries();
    assert!(
        !q_body.iter().any(|q| q.contains("resolve_layouts")),
        "body-only edit must trigger 0 resolve_layouts recomputations; saw {q_body:?}"
    );
    assert!(
        q_body.iter().any(|q| q.contains("analyze_module")),
        "body-only edit should execute analyze_module; saw {q_body:?}"
    );

    // 3. Repeated hover and code_lens without edits execute 0 queries (Salsa memoized hits).
    let hover_params = HoverParams {
        text_document_position_params: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
            position: Position::new(2, 11), // `Pos`
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
    };
    let lens_params = CodeLensParams {
        text_document: TextDocumentIdentifier { uri: uri.clone() },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
    };

    let hover1 = backend.hover(hover_params.clone()).await.expect("hover ok");
    assert!(hover1.is_some(), "expected hover card for Pos");
    let lenses1 = backend
        .code_lens(lens_params.clone())
        .await
        .expect("code_lens ok");
    assert_eq!(lenses1.as_ref().map(Vec::len), Some(1));
    let hover2 = backend.hover(hover_params.clone()).await.expect("hover ok");
    assert!(hover2.is_some());
    let lenses2 = backend.code_lens(lens_params).await.expect("code_lens ok");
    assert_eq!(lenses2.as_ref().map(Vec::len), Some(1));

    let q_reads = backend.take_executed_queries();
    assert!(
        q_reads.is_empty(),
        "repeated hover/code_lens without edits must execute 0 queries; saw {q_reads:?}"
    );

    // 4. Schema edit did_change (adding field `y: f32` to `Pos`) DOES trigger `resolve_layouts`.
    let v3 = concat!(
        "module demo::lsp_inc @version(1.0.0);\n",
        "\n",
        "component Pos { x: f32 = 0.0, y: f32 = 0.0 }\n",
        "\n",
        "@par(chunk = 64)\n",
        "sys step() {\n",
        "    for e in query(p: &mut Pos) {\n",
        "        e.p.x += 2.5;\n",
        "    }\n",
        "}\n",
    );
    backend
        .did_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier {
                uri: uri.clone(),
                version: 3,
            },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: v3.to_owned(),
            }],
        })
        .await;
    let q_schema = backend.take_executed_queries();
    assert!(
        q_schema.iter().any(|q| q.contains("resolve_layouts")),
        "schema edit must trigger resolve_layouts; saw {q_schema:?}"
    );
    assert!(
        q_schema.iter().any(|q| q.contains("analyze_module")),
        "schema edit must trigger analyze_module; saw {q_schema:?}"
    );

    // Verify updated layout (8 B) is served via hover with 0 extra queries.
    let hover3 = backend
        .hover(hover_params)
        .await
        .expect("hover ok")
        .expect("hover card for Pos");
    let HoverContents::Markup(m) = hover3.contents else {
        panic!("expected markdown hover");
    };
    assert!(
        m.value.contains("8 B"),
        "expected updated 8 B size in hover: {}",
        m.value
    );
    assert!(backend.take_executed_queries().is_empty());

    // 5. did_close drops the tracked SourceFile from LspState.
    backend
        .did_close(DidCloseTextDocumentParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
        })
        .await;
    let after_close = backend
        .hover(HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri },
                position: Position::new(2, 11),
            },
            work_done_progress_params: WorkDoneProgressParams::default(),
        })
        .await
        .expect("hover ok");
    assert!(after_close.is_none());
}

#[tokio::test]
async fn lsp_did_change_ranged_edit_empty_changes_and_reopen() {
    use strata_lsp::StrataLspBackend;
    use tower_lsp::LanguageServer;
    use tower_lsp::lsp_types::{
        DidChangeTextDocumentParams, DidOpenTextDocumentParams, DocumentFormattingParams,
        FormattingOptions, HoverParams, Range, TextDocumentContentChangeEvent,
        TextDocumentIdentifier, TextDocumentItem, TextDocumentPositionParams, Url,
        VersionedTextDocumentIdentifier, WorkDoneProgressParams,
    };

    let backend = StrataLspBackend::headless(TelemetryStore::new());
    let uri = Url::parse("file:///test/ranged.strata").expect("valid uri");

    let initial = concat!(
        "module demo::ranged @version(1.0.0);\n",
        "component Pos { x: f32 = 0.0 }\n",
        "sys step() {\n",
        "    for e in query(p: &mut Pos) {\n",
        "        e.p.x += 1.0;\n",
        "    }\n",
        "}\n",
    );

    backend
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "strata".to_owned(),
                version: 1,
                text: initial.to_owned(),
            },
        })
        .await;
    let _ = backend.take_executed_queries();

    // Empty content_changes is a no-op with 0 query executions.
    backend
        .did_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier {
                uri: uri.clone(),
                version: 2,
            },
            content_changes: Vec::new(),
        })
        .await;
    assert!(backend.take_executed_queries().is_empty());

    // Ranged body-only edit (`1.0` on line 4 cols 17..20 -> `3.5`) skips `resolve_layouts`.
    backend
        .did_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier {
                uri: uri.clone(),
                version: 3,
            },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: Some(Range::new(Position::new(4, 17), Position::new(4, 20))),
                range_length: None,
                text: "3.5".to_owned(),
            }],
        })
        .await;
    let q_ranged = backend.take_executed_queries();
    assert!(
        !q_ranged.iter().any(|q| q.contains("resolve_layouts")),
        "ranged body-only edit must trigger 0 resolve_layouts recomputations; saw {q_ranged:?}"
    );
    assert!(
        q_ranged.iter().any(|q| q.contains("analyze_module")),
        "ranged body-only edit should execute analyze_module; saw {q_ranged:?}"
    );

    // Formatting works on open document without hitting Salsa.
    let fmt = backend
        .formatting(DocumentFormattingParams {
            text_document: TextDocumentIdentifier { uri: uri.clone() },
            options: FormattingOptions::default(),
            work_done_progress_params: WorkDoneProgressParams::default(),
        })
        .await
        .expect("formatting ok");
    assert!(fmt.is_some());
    assert!(backend.take_executed_queries().is_empty());

    // Re-opening the same URI with identical text reuses existing SourceFile with 0 executions
    // except memoized hit check.
    backend
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "strata".to_owned(),
                version: 4,
                text: initial.replace("+= 1.0", "+= 3.5"),
            },
        })
        .await;
    assert!(backend.take_executed_queries().is_empty());

    // Out-of-order did_change for an unopened URI inserts and analyzes it cleanly.
    let unopened_uri = Url::parse("file:///test/unopened.strata").expect("valid uri");
    backend
        .did_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier {
                uri: unopened_uri.clone(),
                version: 1,
            },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: "module demo::unopened @version(1.0.0);\ncomponent Vel { dx: f32 = 0.0 }\n"
                    .to_owned(),
            }],
        })
        .await;
    let h = backend
        .hover(HoverParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri: unopened_uri },
                position: Position::new(1, 11),
            },
            work_done_progress_params: WorkDoneProgressParams::default(),
        })
        .await
        .expect("hover ok");
    assert!(h.is_some(), "expected hover on out-of-order opened URI");
}

#[tokio::test]
async fn lsp_graph_telemetry_resolves_all_node_kinds_bare_fallback_and_errors() {
    use strata_lsp::{
        GraphTelemetryParams, IngestTelemetryParams, StrataLspBackend, TelemetryFrameInput,
    };
    use tower_lsp::LanguageServer;
    use tower_lsp::lsp_types::{
        DidChangeTextDocumentParams, DidOpenTextDocumentParams, TextDocumentContentChangeEvent,
        TextDocumentItem, Url, VersionedTextDocumentIdentifier,
    };

    let backend = StrataLspBackend::headless(TelemetryStore::new());
    let uri = Url::parse("file:///test/boss_graph.strata").expect("valid uri");
    let src = r#"module demo::boss @version(1.0.0);

enum Phase { A = 0, B = 1 }
tag Marker;
event SlashHit {}

component BossHealth { hp: f32 = 500.0 }

@node_pure
fn calc(x: f32) -> f32 { return x * 2.0; }

timeline SlashTl @rate(60_hz) @duration(10_f) {
    window active = 1_f .. 5_f;
    at 1_f => trigger(self, SlashHit {});
}

fsm BossFsm @require(BossHealth) {
    initial A;
    state A { to B when true; }
    state B { to A when false; }
}

task DashTask(speed: f32) on (h: &mut BossHealth.hp) .with<Marker>() { h -= speed; }

table Cfg by Phase { mult: f32 } = { A => { mult: 1.0 }, B => { mult: 2.0 } };

curve Falloff(meters -> f32) = [ (0.0_m, 10.0), (10.0_m, 0.0) ];

sys sys_a() {
    for e in query(h: &mut BossHealth) {
        e.h.hp -= 1.0;
    }
}

schedule FixedUpdate {
    seq Loop { sys_a }
}
"#;

    backend
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri.clone(),
                language_id: "strata".to_owned(),
                version: 1,
                text: src.to_owned(),
            },
        })
        .await;

    let make_frame =
        |name: &str, frame_seq: u64, p50_us: u32, flags: u16, matched_entities: u32| {
            SystemTelemetryDigest64 {
                magic: SYSTEM_TELEMETRY_MAGIC,
                version: SYSTEM_TELEMETRY_DIGEST_VERSION,
                flags,
                mod_id: 1,
                system_hash: system_name_hash(name),
                frame_seq,
                matched_entities,
                matched_tables: 3,
                skipped_summary_tick_tables: 1,
                chunks: 2,
                p50_us,
                p99_us: p50_us + 50,
                commands_queued: 0,
                reserved: 0,
            }
            .to_le_bytes()
            .to_vec()
        };

    // Inline frames: bare name `sys_a` with out-of-order frame sequences (25 then 10),
    // canonical component `demo::boss::BossHealth` with quarantine flag=1 and u32::MAX,
    // and schedule `demo::boss::FixedUpdate`.
    let resp = backend
        .graph_telemetry(GraphTelemetryParams {
            uri: Some(uri.to_string()),
            node_ids: Some(vec![
                "demo::boss::sys_a".to_owned(),
                "demo::boss::BossHealth".to_owned(),
                "demo::boss::FixedUpdate".to_owned(),
                "demo::boss::DoesNotExist".to_owned(),
            ]),
            frames: vec![
                TelemetryFrameInput::Bytes(make_frame("sys_a", 25, 1200, 0, 64)),
                TelemetryFrameInput::Bytes(make_frame("sys_a", 10, 9999, 0, 64)),
                TelemetryFrameInput::Bytes(make_frame(
                    "demo::boss::BossHealth",
                    26,
                    400,
                    TELEMETRY_FLAG_QUARANTINED,
                    u32::MAX,
                )),
                TelemetryFrameInput::Bytes(make_frame("demo::boss::FixedUpdate", 26, 800, 0, 1)),
            ],
        })
        .await
        .expect("graph_telemetry ok");

    assert_eq!(resp.module_path.as_deref(), Some("demo::boss"));
    assert!(
        !resp.nodes.contains_key("demo::boss::DoesNotExist"),
        "unknown node ID must be omitted"
    );

    let sys_a = resp.nodes.get("demo::boss::sys_a").expect("sys_a matched");
    assert_eq!(sys_a.frame_seq, 25);
    assert_eq!(sys_a.p50_us, 1200);
    assert_eq!(sys_a.matched_by, "bare");
    assert!(!sys_a.quarantined);

    let health = resp
        .nodes
        .get("demo::boss::BossHealth")
        .expect("BossHealth matched");
    assert_eq!(health.flags, TELEMETRY_FLAG_QUARANTINED);
    assert!(health.quarantined);
    assert_eq!(health.matched_entities, u32::MAX);
    assert_eq!(health.matched_by, "canonical");
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("4294967295"));

    assert!(resp.nodes.contains_key("demo::boss::FixedUpdate"));

    // Invalid 63-byte or bad-magic frames return InvalidParams without poisoning TelemetryStore.
    let err_len = backend
        .graph_telemetry(GraphTelemetryParams {
            uri: Some(uri.to_string()),
            node_ids: Some(vec!["demo::boss::sys_a".to_owned()]),
            frames: vec![TelemetryFrameInput::Bytes(vec![0u8; 63])],
        })
        .await
        .expect_err("63B frame must error");
    assert_eq!(err_len.code, tower_lsp::jsonrpc::ErrorCode::InvalidParams);

    let mut bad_magic = make_frame("sys_a", 99, 1, 0, 1);
    bad_magic[0..4].copy_from_slice(&0x4241_4D54u32.to_le_bytes());
    let err_magic = backend
        .graph_telemetry(GraphTelemetryParams {
            uri: Some(uri.to_string()),
            node_ids: None,
            frames: vec![TelemetryFrameInput::Bytes(bad_magic)],
        })
        .await
        .expect_err("bad magic must error");
    assert_eq!(err_magic.code, tower_lsp::jsonrpc::ErrorCode::InvalidParams);

    // Body edit via did_change preserves telemetry lookup; ingest_telemetry updates store.
    backend
        .did_change(DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier {
                uri: uri.clone(),
                version: 2,
            },
            content_changes: vec![TextDocumentContentChangeEvent {
                range: None,
                range_length: None,
                text: src.replace("hp -= 1.0;", "hp -= 2.0;"),
            }],
        })
        .await;
    let ingest = backend
        .ingest_telemetry(IngestTelemetryParams {
            frames: vec![TelemetryFrameInput::Bytes(make_frame(
                "demo::boss::calc",
                30,
                55,
                0,
                12,
            ))],
        })
        .await
        .expect("ingest ok");
    assert_eq!(ingest.ingested, 1);
    assert_eq!(ingest.latest_frame_seq, Some(30));

    let after_edit = backend
        .graph_telemetry(GraphTelemetryParams {
            uri: Some(uri.to_string()),
            node_ids: None,
            frames: Vec::new(),
        })
        .await
        .expect("query after edit ok");
    assert!(after_edit.nodes.contains_key("demo::boss::sys_a"));
    assert!(after_edit.nodes.contains_key("demo::boss::calc"));

    // Unopened URI returns clean empty response without error.
    let unopened = backend
        .graph_telemetry(GraphTelemetryParams {
            uri: Some("file:///test/never_opened.strata".to_owned()),
            node_ids: Some(vec!["demo::boss::NoStore".to_owned()]),
            frames: Vec::new(),
        })
        .await
        .expect("unopened uri returns clean response");
    assert!(unopened.nodes.is_empty());
    assert!(unopened.module_path.is_none());
}

#[tokio::test]
async fn lsp_graph_telemetry_invalid_uri_rejects_without_mutating_telemetry_store() {
    use strata_lsp::{GraphTelemetryParams, StrataLspBackend, TelemetryFrameInput};
    use tower_lsp::LanguageServer;
    use tower_lsp::jsonrpc::ErrorCode;
    use tower_lsp::lsp_types::{DidOpenTextDocumentParams, TextDocumentItem, Url};

    let make_digest = |name: &str, frame_seq: u64, p50_us: u32| SystemTelemetryDigest64 {
        magic: SYSTEM_TELEMETRY_MAGIC,
        version: SYSTEM_TELEMETRY_DIGEST_VERSION,
        flags: 0,
        mod_id: 1,
        system_hash: system_name_hash(name),
        frame_seq,
        matched_entities: 32,
        matched_tables: 4,
        skipped_summary_tick_tables: 0,
        chunks: 2,
        p50_us,
        p99_us: p50_us + 50,
        commands_queued: 0,
        reserved: 0,
    };

    let backend = StrataLspBackend::headless(TelemetryStore::new());

    // 1. Empty store: invalid URI paired with valid 64-byte raw and Digest frames must return
    //    InvalidParams without recording any frame in TelemetryStore.
    let err_invalid_space = backend
        .graph_telemetry(GraphTelemetryParams {
            uri: Some("not a valid uri".to_owned()),
            node_ids: Some(vec!["demo::url_guard::sys_a".to_owned()]),
            frames: vec![
                TelemetryFrameInput::Bytes(
                    make_digest("demo::url_guard::sys_a", 10, 500)
                        .to_le_bytes()
                        .to_vec(),
                ),
                TelemetryFrameInput::Digest(SystemTelemetryDigestJson::from(make_digest(
                    "sys_b", 12, 700,
                ))),
            ],
        })
        .await
        .expect_err("invalid URI must fail with InvalidParams");
    assert_eq!(err_invalid_space.code, ErrorCode::InvalidParams);
    assert!(
        backend
            .telemetry()
            .get_for_system("demo::url_guard::sys_a")
            .is_none()
    );
    assert!(backend.telemetry().get_for_system("sys_a").is_none());
    assert!(backend.telemetry().get_for_system("sys_b").is_none());

    // 2. Pre-populated store: invalid URI `"://bad"` (and `""`) with a higher frame_index must not
    //    overwrite the existing digest or insert any new digest.
    let seeded = make_digest("demo::url_guard::existing_sys", 5, 300);
    backend.telemetry().record_digest(seeded);

    for bad_uri in ["://bad", ""] {
        let err = backend
            .graph_telemetry(GraphTelemetryParams {
                uri: Some(bad_uri.to_owned()),
                node_ids: None,
                frames: vec![
                    TelemetryFrameInput::Bytes(
                        make_digest("demo::url_guard::existing_sys", 99, 1)
                            .to_le_bytes()
                            .to_vec(),
                    ),
                    TelemetryFrameInput::Bytes(
                        make_digest("demo::url_guard::new_sys", 1, 200)
                            .to_le_bytes()
                            .to_vec(),
                    ),
                ],
            })
            .await
            .expect_err("malformed URI must fail with InvalidParams");
        assert_eq!(err.code, ErrorCode::InvalidParams);
    }

    assert_eq!(
        backend
            .telemetry()
            .get_for_system("demo::url_guard::existing_sys"),
        Some(seeded)
    );
    assert!(
        backend
            .telemetry()
            .get_for_system("demo::url_guard::new_sys")
            .is_none()
    );

    // 3. Subsequent did_open + valid-URI graph_telemetry query observes only the pre-seeded entry.
    let valid_uri = Url::parse("file:///test/url_guard.strata").expect("valid uri");
    let src = concat!(
        "module demo::url_guard @version(1.0.0);\n",
        "component Pos { x: f32 = 0.0 }\n",
        "sys sys_a() { for e in query(p: &mut Pos) { e.p.x += 1.0; } }\n",
        "sys existing_sys() { for e in query(p: &mut Pos) { e.p.x += 1.0; } }\n",
        "sys new_sys() { for e in query(p: &mut Pos) { e.p.x += 1.0; } }\n",
    );
    backend
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: valid_uri.clone(),
                language_id: "strata".to_owned(),
                version: 1,
                text: src.to_owned(),
            },
        })
        .await;

    let resp = backend
        .graph_telemetry(GraphTelemetryParams {
            uri: Some(valid_uri.to_string()),
            node_ids: None,
            frames: Vec::new(),
        })
        .await
        .expect("valid URI query ok");
    assert_eq!(resp.module_path.as_deref(), Some("demo::url_guard"));
    assert_eq!(resp.nodes.len(), 1);
    let existing = resp
        .nodes
        .get("demo::url_guard::existing_sys")
        .expect("seeded system present");
    assert_eq!(existing.frame_seq, 5);
    assert_eq!(existing.p50_us, 300);
    assert!(!resp.nodes.contains_key("demo::url_guard::sys_a"));
    assert!(!resp.nodes.contains_key("demo::url_guard::new_sys"));
}

#[test]
fn stdio_strata_lsp_serves_graph_telemetry_end_to_end() {
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::process::{Command, Stdio};

    let write_frame = |stdin: &mut std::process::ChildStdin, msg: &serde_json::Value| {
        let body = serde_json::to_string(msg).expect("serialize JSON-RPC");
        let header = format!("Content-Length: {}\r\n\r\n", body.len());
        stdin.write_all(header.as_bytes()).expect("write header");
        stdin.write_all(body.as_bytes()).expect("write body");
        stdin.flush().expect("flush stdin");
    };

    let read_for_id = |reader: &mut BufReader<std::process::ChildStdout>,
                       target_id: i64|
     -> serde_json::Value {
        loop {
            let mut content_len: Option<usize> = None;
            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line).expect("read header line");
                assert!(n > 0, "unexpected EOF waiting for LSP response {target_id}");
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    break;
                }
                if let Some(rest) = trimmed.strip_prefix("Content-Length:") {
                    content_len = rest.trim().parse().ok();
                }
            }
            let len = content_len.expect("Content-Length header");
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).expect("read JSON-RPC body");
            let val: serde_json::Value = serde_json::from_slice(&buf).expect("parse JSON-RPC body");
            if val.get("id").and_then(serde_json::Value::as_i64) == Some(target_id) {
                return val;
            }
        }
    };

    let mut child = Command::new(env!("CARGO_BIN_EXE_strata-lsp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn strata-lsp");

    let mut stdin = child.stdin.take().unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());

    write_frame(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "processId": null,
                "rootUri": null,
                "capabilities": {}
            }
        }),
    );
    let init_resp = read_for_id(&mut reader, 1);
    assert!(init_resp.get("result").is_some(), "{init_resp}");

    write_frame(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialized",
            "params": {}
        }),
    );

    let doc_uri = "file:///tmp/stdio_boss.strata";
    write_frame(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "method": "textDocument/didOpen",
            "params": {
                "textDocument": {
                    "uri": doc_uri,
                    "languageId": "strata",
                    "version": 1,
                    "text": "module demo::stdio @version(1.0.0);\ncomponent Health { hp: f32 = 10.0 }\nsys tick() { for e in query(h: &mut Health) { e.h.hp += 1.0; } }\n"
                }
            }
        }),
    );

    let frame = SystemTelemetryDigest64 {
        magic: SYSTEM_TELEMETRY_MAGIC,
        version: SYSTEM_TELEMETRY_DIGEST_VERSION,
        flags: 0,
        mod_id: 1,
        system_hash: system_name_hash("tick"),
        frame_seq: 42,
        matched_entities: 128,
        matched_tables: 4,
        skipped_summary_tick_tables: 1,
        chunks: 2,
        p50_us: 950,
        p99_us: 1500,
        commands_queued: 0,
        reserved: 0,
    }
    .to_le_bytes()
    .to_vec();

    write_frame(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "strata/graphTelemetry",
            "params": {
                "uri": doc_uri,
                "node_ids": ["demo::stdio::tick"],
                "frames": [frame]
            }
        }),
    );
    let tel_resp = read_for_id(&mut reader, 2);
    assert_eq!(
        tel_resp["result"]["nodes"]["demo::stdio::tick"]["p50_us"],
        950
    );
    assert_eq!(
        tel_resp["result"]["nodes"]["demo::stdio::tick"]["matched_by"],
        "bare"
    );

    // Subsequent query without inline frames reads from TelemetryStore.
    write_frame(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "strata/graphTelemetry",
            "params": {
                "uri": doc_uri,
                "node_ids": ["demo::stdio::tick"]
            }
        }),
    );
    let cached_resp = read_for_id(&mut reader, 3);
    assert_eq!(
        cached_resp["result"]["nodes"]["demo::stdio::tick"]["frame_seq"],
        42
    );

    // Invalid 63-byte frame returns JSON-RPC error -32602 without crashing server.
    write_frame(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "strata/graphTelemetry",
            "params": {
                "uri": doc_uri,
                "frames": [vec![0u8; 63]]
            }
        }),
    );
    let err_resp = read_for_id(&mut reader, 4);
    assert_eq!(err_resp["error"]["code"], -32602);

    // Clean shutdown + exit -> exit code 0.
    write_frame(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "shutdown"
        }),
    );
    let _ = read_for_id(&mut reader, 5);
    write_frame(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "method": "exit"
        }),
    );
    drop(stdin);

    let status = child.wait().expect("wait strata-lsp");
    assert_eq!(status.code(), Some(0));
}

#[tokio::test]
async fn telemetry_endpoint_subscriber_streams_bamt_tcp_and_unix_frames() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, UnixListener};

    let store = TelemetryStore::new();
    let tcp_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback TCP");
    let tcp_addr = tcp_listener.local_addr().expect("local addr");

    let tcp_sub = spawn_telemetry_subscriber(TelemetryEndpoint::Tcp(tcp_addr), store.clone());
    let (mut tcp_conn, _) = tcp_listener.accept().await.expect("accept TCP stream");
    let tcp_digest = SystemTelemetryDigest64 {
        magic: SYSTEM_TELEMETRY_MAGIC,
        version: SYSTEM_TELEMETRY_DIGEST_VERSION,
        flags: 0,
        mod_id: 9,
        system_hash: fnv1a_64_hash_system("net::sim", "step_tcp"),
        frame_seq: 11,
        matched_entities: 50,
        matched_tables: 2,
        skipped_summary_tick_tables: 1,
        chunks: 2,
        p50_us: 80,
        p99_us: 120,
        commands_queued: 1,
        reserved: 0,
    };
    tcp_conn
        .write_all(&tcp_digest.to_le_bytes())
        .await
        .expect("write BAMT TCP frame");
    tcp_conn.flush().await.expect("flush TCP");

    for _ in 0..40 {
        if store.get_for_system("net::sim::step_tcp").is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(store.get_for_system("net::sim::step_tcp"), Some(tcp_digest));
    tcp_sub.shutdown().await;

    let sock_path = std::env::temp_dir().join(format!(
        "strata_lsp_bamt_{}_{}.sock",
        std::process::id(),
        77
    ));
    let _ = std::fs::remove_file(&sock_path);
    let unix_listener = UnixListener::bind(&sock_path).expect("bind AF_UNIX socket");
    let unix_sub =
        spawn_telemetry_subscriber(TelemetryEndpoint::Unix(sock_path.clone()), store.clone());
    let (mut unix_conn, _) = unix_listener.accept().await.expect("accept AF_UNIX");
    let unix_digest = SystemTelemetryDigest64 {
        magic: SYSTEM_TELEMETRY_MAGIC,
        version: SYSTEM_TELEMETRY_DIGEST_VERSION,
        flags: TELEMETRY_FLAG_QUARANTINED,
        mod_id: 10,
        system_hash: fnv1a_64_hash_system("net::sim", "step_unix"),
        frame_seq: 22,
        matched_entities: 99,
        matched_tables: 3,
        skipped_summary_tick_tables: 0,
        chunks: 3,
        p50_us: 150,
        p99_us: 260,
        commands_queued: 2,
        reserved: 0,
    };
    unix_conn
        .write_all(&unix_digest.to_le_bytes())
        .await
        .expect("write BAMT AF_UNIX frame");
    unix_conn.flush().await.expect("flush AF_UNIX");

    for _ in 0..40 {
        if store.get_for_system("net::sim::step_unix").is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        store.get_for_system("net::sim::step_unix"),
        Some(unix_digest)
    );
    unix_sub.shutdown().await;
    let _ = std::fs::remove_file(&sock_path);
}

#[tokio::test]
async fn fetch_brp_component_schemas_parses_live_http_response() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind BRP mock TCP");
    let addr = listener.local_addr().expect("addr");

    let server_task = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept BRP HTTP");
        let mut req_buf = [0u8; 1024];
        let n = sock.read(&mut req_buf).await.expect("read HTTP req");
        let req_text = String::from_utf8_lossy(&req_buf[..n]);
        assert!(req_text.contains("bam/component_schemas"));

        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"components":[{"name":"arena::Health","size":8,"align":4,"uuid":"0x1234","is_pod":true},{"name":"arena::Buffs","size":24,"align":8,"is_pod":false}]}}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        sock.write_all(resp.as_bytes())
            .await
            .expect("write HTTP resp");
    });

    let schemas = fetch_brp_component_schemas(addr)
        .await
        .expect("BRP HTTP fetch must parse components[]");
    server_task.await.expect("server join");

    assert_eq!(schemas.len(), 2);
    assert_eq!(schemas[0].canonical_name, "arena::Health");
    assert_eq!(schemas[0].size, 8);
    assert_eq!(schemas[0].uuid, 0x1234);
    assert!(schemas[0].is_pod);
    assert_eq!(schemas[1].canonical_name, "arena::Buffs");
    assert!(!schemas[1].is_pod);

    let err = strata_lsp::decode_digest_slice(&[0u8; 64]);
    assert!(matches!(err, Err(TelemetryError::InvalidMagic { .. })));
}

#[test]
fn ide_symbols_definition_references_highlights_completions_and_inlay_hints() {
    use strata_lsp::{
        compute_completions, compute_definition, compute_document_highlights,
        compute_document_symbols, compute_inlay_hints, compute_references,
        parse_telemetry_endpoint,
    };
    use tower_lsp::lsp_types::{DocumentHighlightKind, InlayHintLabel, Range, SymbolKind, Url};

    let src = r#"module demo::zed_ide @version(1.0.0);

enum Stance {
    Idle = 0,
    Guard = 1,
}

// Pos2D mentioned inside comment must not show up in references
component Pos2D {
    xy: vec2 = vec2::ZERO,
}

@node_pure
fn double_x(v: f32) -> f32 {
    return v * 2.0;
}

@par(chunk = 256)
sys move_all() {
    let s = Stance::Guard;
    for e in query(p: &mut Pos2D) {
        e.p.xy.x = double_x(e.p.xy.x);
    }
}

schedule FixedUpdate { move_all }
"#;

    let uri = Url::parse("file:///workspace/demo.strata").expect("valid uri");

    // 1. Hierarchical document symbols
    let syms = compute_document_symbols(src);
    assert!(
        syms.iter()
            .any(|s| s.name == "Pos2D" && s.kind == SymbolKind::STRUCT)
    );
    let stance_sym = syms
        .iter()
        .find(|s| s.name == "Stance" && s.kind == SymbolKind::ENUM)
        .expect("enum symbol");
    let variants = stance_sym.children.as_ref().expect("enum variants");
    assert_eq!(variants.len(), 2);
    assert_eq!(variants[1].name, "Guard");

    // 2. Go-to-definition on `Pos2D` inside `query(p: &mut Pos2D)` (line 20)
    let pos2d_usage = Position::new(20, 29);
    let def = compute_definition(src, &uri, pos2d_usage).expect("Pos2D definition");
    assert_eq!(def.uri, uri);
    assert_eq!(def.range.start.line, 8);

    // Qualified enum variant definition on `Stance::Guard` (line 19)
    let guard_usage = Position::new(19, 21);
    let guard_def = compute_definition(src, &uri, guard_usage).expect("Guard definition");
    assert_eq!(guard_def.range.start.line, 4);

    // 3. Document highlights & references skip comments and mark WRITE vs READ
    let highlights = compute_document_highlights(src, pos2d_usage);
    assert_eq!(highlights.len(), 2);
    assert_eq!(highlights[0].kind, Some(DocumentHighlightKind::WRITE));
    assert_eq!(highlights[1].kind, Some(DocumentHighlightKind::READ));

    let refs_without_decl = compute_references(src, &uri, pos2d_usage, false);
    assert_eq!(refs_without_decl.len(), 1);
    assert_eq!(refs_without_decl[0].range.start.line, 20);

    // 4. Context-aware completions (`@`, `::`, `.`, general)
    let attr_src = "module a::b @version(1.0.0);\n@p";
    let attr_items = compute_completions(attr_src, Position::new(1, 2));
    assert!(attr_items.iter().any(|i| i.label == "par"));
    assert!(attr_items.iter().any(|i| i.label == "persist"));

    let scope_src = format!("{src}\nfn t() {{ let x = Stance:: }}");
    let scope_line = scope_src.lines().count() as u32 - 1;
    let scope_col = scope_src.lines().last().unwrap().find("::").unwrap() as u32 + 2;
    let scope_items = compute_completions(&scope_src, Position::new(scope_line, scope_col));
    assert!(scope_items.iter().any(|i| i.label == "Idle"));
    assert!(scope_items.iter().any(|i| i.label == "Guard"));

    let dot_src =
        format!("{src}\nsys probe() {{ for e in query(p: &mut Pos2D) {{ let _ = e.p. }} }}");
    let dot_line = dot_src.lines().count() as u32 - 1;
    let dot_col = dot_src.lines().last().unwrap().find("e.p.").unwrap() as u32 + 4;
    let dot_items = compute_completions(&dot_src, Position::new(dot_line, dot_col));
    assert!(
        dot_items.iter().any(|i| i.label == "xy"),
        "expected Pos2D field `xy` in dot completions: {dot_items:?}"
    );

    // 5. Inlay hints show AbiPod layout + `@par` badge
    let hints = compute_inlay_hints(src, Range::new(Position::new(0, 0), Position::new(40, 0)));
    assert!(hints.iter().any(|h| matches!(
        &h.label,
        InlayHintLabel::String(s) if s.contains("8 B") && s.contains("AbiPod")
    )));
    assert!(hints.iter().any(|h| matches!(
        &h.label,
        InlayHintLabel::String(s) if s.contains("@par(chunk=256)")
    )));

    // 6. Rich hover includes field table for components and signatures for fn/enum
    let comp_hover = compute_hover(src, Position::new(8, 12)).expect("component hover");
    assert!(comp_hover.range.is_some());
    let HoverContents::Markup(m) = comp_hover.contents else {
        panic!("expected markdown hover");
    };
    assert!(m.value.contains("| Offset | Field | Type | Size |"));
    assert!(m.value.contains("`xy`"));

    let fn_hover = compute_hover(src, Position::new(13, 5)).expect("fn hover");
    let HoverContents::Markup(fn_m) = fn_hover.contents else {
        panic!("expected markdown hover");
    };
    assert!(fn_m.value.contains("fn double_x(v: f32) -> f32"));
    assert!(fn_m.value.contains("@node_pure"));

    let enum_hover = compute_hover(src, Position::new(2, 7)).expect("enum hover");
    let HoverContents::Markup(enum_m) = enum_hover.contents else {
        panic!("expected markdown hover");
    };
    assert!(enum_m.value.contains("Guard = 1"));

    // 7. Telemetry endpoint parsing from Zed settings JSON
    let tcp_cfg = serde_json::json!({ "telemetryEndpoint": "tcp://127.0.0.1:15703" });
    assert!(matches!(
        parse_telemetry_endpoint(&tcp_cfg),
        Some(TelemetryEndpoint::Tcp(_))
    ));
    let unix_cfg =
        serde_json::json!({ "strata": { "telemetry_endpoint": "unix:///tmp/strata.sock" } });
    assert!(matches!(
        parse_telemetry_endpoint(&unix_cfg),
        Some(TelemetryEndpoint::Unix(_))
    ));
}

#[tokio::test]
async fn lsp_backend_initialize_advertises_full_zed_capabilities() {
    use strata_lsp::{StrataLspBackend, TelemetryStore};
    use tower_lsp::LanguageServer;
    use tower_lsp::lsp_types::{
        DidOpenTextDocumentParams, DocumentSymbolParams, DocumentSymbolResponse,
        GotoDefinitionParams, GotoDefinitionResponse, InitializeParams, InlayHintParams, Position,
        Range, TextDocumentIdentifier, TextDocumentItem, TextDocumentPositionParams, Url,
        WorkspaceSymbolParams,
    };

    let backend = StrataLspBackend::headless(TelemetryStore::new());
    let init = backend
        .initialize(InitializeParams::default())
        .await
        .expect("initialize ok");
    assert_eq!(
        init.server_info.as_ref().map(|s| s.name.as_str()),
        Some("strata-lsp")
    );
    assert!(init.capabilities.definition_provider.is_some());
    assert!(init.capabilities.references_provider.is_some());
    assert!(init.capabilities.document_highlight_provider.is_some());
    assert!(init.capabilities.document_symbol_provider.is_some());
    assert!(init.capabilities.workspace_symbol_provider.is_some());
    assert!(init.capabilities.completion_provider.is_some());
    assert!(init.capabilities.inlay_hint_provider.is_some());
    assert!(init.capabilities.hover_provider.is_some());
    assert!(init.capabilities.document_formatting_provider.is_some());
    assert!(init.capabilities.code_lens_provider.is_some());

    let uri_a = Url::parse("file:///workspace/a.strata").expect("uri_a");
    let uri_b = Url::parse("file:///workspace/b.strata").expect("uri_b");

    backend
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri_a.clone(),
                language_id: "strata".to_owned(),
                version: 1,
                text: "module demo::a @version(1.0.0);\ncomponent SharedHp { hp: f32 = 100.0 }\n"
                    .to_owned(),
            },
        })
        .await;
    backend
        .did_open(DidOpenTextDocumentParams {
            text_document: TextDocumentItem {
                uri: uri_b.clone(),
                language_id: "strata".to_owned(),
                version: 1,
                text: "module demo::b @version(1.0.0);\nsys heal() { for e in query(h: &mut SharedHp) { e.h.hp += 1.0; } }\n"
                    .to_owned(),
            },
        })
        .await;

    // Cross-file go-to-definition from b.strata -> a.strata::SharedHp
    let def = backend
        .goto_definition(GotoDefinitionParams {
            text_document_position_params: TextDocumentPositionParams {
                text_document: TextDocumentIdentifier { uri: uri_b.clone() },
                position: Position::new(1, 38),
            },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        })
        .await
        .expect("goto_definition ok");
    let Some(GotoDefinitionResponse::Scalar(loc)) = def else {
        panic!("expected cross-file definition location");
    };
    assert_eq!(loc.uri, uri_a);
    assert_eq!(loc.range.start.line, 1);

    // Workspace symbol search finds SharedHp across files
    let ws_syms = backend
        .symbol(WorkspaceSymbolParams {
            query: "Shared".to_owned(),
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        })
        .await
        .expect("workspace/symbol ok")
        .unwrap_or_default();
    assert!(ws_syms.iter().any(|s| s.name == "SharedHp"));

    // Document symbols & inlay hints on a.strata
    let doc_syms = backend
        .document_symbol(DocumentSymbolParams {
            text_document: TextDocumentIdentifier { uri: uri_a.clone() },
            work_done_progress_params: Default::default(),
            partial_result_params: Default::default(),
        })
        .await
        .expect("document_symbol ok");
    assert!(matches!(doc_syms, Some(DocumentSymbolResponse::Nested(v)) if !v.is_empty()));

    let hints = backend
        .inlay_hint(InlayHintParams {
            text_document: TextDocumentIdentifier { uri: uri_a },
            range: Range::new(Position::new(0, 0), Position::new(10, 0)),
            work_done_progress_params: Default::default(),
        })
        .await
        .expect("inlay_hint ok")
        .unwrap_or_default();
    assert!(!hints.is_empty());
}

#[test]
fn hover_renders_doc_comments_keywords_attributes_and_builtin_types() {
    let hover_md = |src: &str, line: u32, col: u32| -> Option<String> {
        let h = compute_hover(src, Position::new(line, col))?;
        match h.contents {
            HoverContents::Markup(m) => Some(m.value),
            _ => None,
        }
    };

    let src = r#"module demo::docs @version(1.0.0);

/// This is simulation clock
resource SimClock {
    /// Fixed tick step in seconds
    dt: sec = 16.6667_ms,
}

/// SoA combatant state
/// stored in hot and cold strata
@soa @summary_tick
component CombatantBody {
    hot {
        /// Current health points
        hp: f32 = 800.0,
    }
    cold caps {
        max_hp: f32 = 800.0,
    }
}

// Plain comment must NOT attach as doc comment
component PlainComp {
    raw: u32 = 0,
}

/// Detached doc separated by blank line

component DetachedComp {
    val: u32 = 0,
}

/** Combat action enum doc */
enum CombatAction {
    LightAttack = 0,
}

/// Helper clamping stamina
@node_pure
fn clamp_stamina(v: f32) -> f32 {
    return v;
}

/// Regenerates combatant health
@par(chunk = 256)
sys regen_hp(clk: &res SimClock) {
    uniform let step = clk.dt;
    let label = "component in string";
    for c in query(body: &mut CombatantBody) {
        c.body.hp = clamp_stamina(c.body.hp);
    }
}

timeline DodgeRoll @rate(60_hz) @duration(10_f) {
    window iframes = 1_f .. 5_f;
}
"#;

    // 1. Doc comment on `resource SimClock`
    let clk_doc = hover_md(src, 3, 10).expect("SimClock hover");
    assert!(clk_doc.contains("This is simulation clock"), "{clk_doc}");

    // 2. Multi-line doc comment before `@soa @summary_tick` on `component CombatantBody`
    let body_doc = hover_md(src, 11, 14).expect("CombatantBody hover");
    assert!(
        body_doc.contains("SoA combatant state\nstored in hot and cold strata"),
        "{body_doc}"
    );

    // 3. Doc comment on `///` field (`hp` and `dt`)
    let hp_doc = hover_md(src, 14, 9).expect("hp field hover");
    assert!(hp_doc.contains("Current health points"), "{hp_doc}");
    let dt_doc = hover_md(src, 5, 5).expect("dt field hover");
    assert!(dt_doc.contains("Fixed tick step in seconds"), "{dt_doc}");

    // 4. Plain `//` comment and blank-line-separated `///` must NOT attach
    let plain_doc = hover_md(src, 22, 12).expect("PlainComp hover");
    assert!(!plain_doc.contains("Plain comment"), "{plain_doc}");
    let detached_doc = hover_md(src, 28, 12).expect("DetachedComp hover");
    assert!(!detached_doc.contains("Detached doc"), "{detached_doc}");

    // 5. Block `/** ... */`, `fn`, and `sys` doc comments
    let enum_doc = hover_md(src, 33, 7).expect("CombatAction hover");
    assert!(enum_doc.contains("Combat action enum doc"), "{enum_doc}");
    let fn_doc = hover_md(src, 39, 5).expect("clamp_stamina hover");
    assert!(fn_doc.contains("Helper clamping stamina"), "{fn_doc}");
    let sys_doc = hover_md(src, 45, 5).expect("regen_hp hover");
    assert!(
        sys_doc.contains("Regenerates combatant health"),
        "{sys_doc}"
    );

    // 6. Keywords & ECS intrinsics hover docs
    for (kw, line, col) in [
        ("resource", 3, 2),
        ("component", 11, 2),
        ("sys", 45, 1),
        ("uniform", 46, 6),
        ("query", 48, 15),
        ("timeline", 53, 2),
    ] {
        let md = hover_md(src, line, col).unwrap_or_else(|| panic!("expected hover for `{kw}`"));
        assert!(
            md.contains(&format!("`{kw}`")),
            "unexpected hover for {kw}: {md}"
        );
    }

    // 7. `@attribute` hover docs
    let soa_md = hover_md(src, 10, 2).expect("@soa hover");
    assert!(soa_md.contains("`@soa`"), "{soa_md}");
    let par_md = hover_md(src, 44, 2).expect("@par hover");
    assert!(par_md.contains("`@par`"), "{par_md}");

    // 8. Built-in types (`sec`, `f32`, plus `vec3`/`InputBuffer`)
    let sec_md = hover_md(src, 5, 9).expect("sec hover");
    assert!(sec_md.contains("`sec` (built-in type)"), "{sec_md}");
    let f32_md = hover_md(src, 14, 13).expect("f32 hover");
    assert!(f32_md.contains("`f32` (built-in type)"), "{f32_md}");

    let extra_src =
        "module m::t @version(1.0.0);\ncomponent C { pos: vec3, buf: InputBuffer<u8, 4> }\n";
    let vec3_md = hover_md(extra_src, 1, 20).expect("vec3 hover");
    assert!(vec3_md.contains("`vec3` (built-in type)"), "{vec3_md}");
    let ib_md = hover_md(extra_src, 1, 32).expect("InputBuffer hover");
    assert!(ib_md.contains("`InputBuffer` (built-in type)"), "{ib_md}");

    // 9. Keywords inside comments or strings must NOT trigger hover
    assert!(
        hover_md(src, 21, 5).is_none(),
        "plain comment word should not hover"
    );
    assert!(
        hover_md(src, 47, 19).is_none(),
        "keyword inside string literal should not hover"
    );
}
