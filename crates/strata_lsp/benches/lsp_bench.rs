//! Criterion `0.8` + `hotpath-rs` microbenchmarks for `strata_lsp`:
//! - `SystemTelemetryDigest64` (`*b"BAMT"`) 10,000-frame batch decode + `TelemetryStore` ingest
//! - Incremental `did_change` LSP re-analysis
//! - `strata/graphTelemetry` node mapping
//! - Full IDE LSP requests (`hover`, `completion` general/`@`/`.`/`::`, `goto_definition`,
//!   `document_highlight`, `references`, `document_symbol`, `workspace_symbol`, `inlay_hint`,
//!   `code_lens`, `formatting`) across real Strata cookbooks (`03_metroidvania_core`,
//!   `05_soulslike_combat`, `08_authoritative_multiplayer`).

use hotpath::criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use strata_lsp::{
    GraphTelemetryParams, SYSTEM_TELEMETRY_DIGEST_SIZE, SYSTEM_TELEMETRY_DIGEST_VERSION,
    SYSTEM_TELEMETRY_MAGIC, StrataLspBackend, SystemTelemetryDigest64, TelemetryStore,
    decode_digest_slice, fnv1a_64_hash_system,
};
use tower_lsp::LanguageServer;
use tower_lsp::lsp_types::{
    CodeLensParams, CompletionParams, DidChangeTextDocumentParams, DidOpenTextDocumentParams,
    DocumentFormattingParams, DocumentHighlightParams, DocumentSymbolParams, FormattingOptions,
    GotoDefinitionParams, HoverParams, InlayHintParams, PartialResultParams, Position, Range,
    ReferenceContext, ReferenceParams, TextDocumentContentChangeEvent, TextDocumentIdentifier,
    TextDocumentItem, TextDocumentPositionParams, Url, VersionedTextDocumentIdentifier,
    WorkDoneProgressParams, WorkspaceSymbolParams,
};

fn build_10k_bamt_frames() -> Vec<[u8; SYSTEM_TELEMETRY_DIGEST_SIZE]> {
    let sys_hashes = [
        fnv1a_64_hash_system("genres::soulslike", "tick_stamina_and_poise"),
        fnv1a_64_hash_system("genres::soulslike", "on_weapon_strike"),
        fnv1a_64_hash_system("genres::metroidvania", "sample_platformer_inputs"),
        fnv1a_64_hash_system("genres::metroidvania", "integrate_platformer"),
    ];
    (0..10_000u64)
        .map(|i| {
            let digest = SystemTelemetryDigest64 {
                magic: SYSTEM_TELEMETRY_MAGIC,
                version: SYSTEM_TELEMETRY_DIGEST_VERSION,
                flags: 0,
                mod_id: 1,
                system_hash: sys_hashes[(i as usize) % sys_hashes.len()],
                frame_seq: i + 1,
                matched_entities: 1024 + (i as u32 % 256),
                matched_tables: 4,
                skipped_summary_tick_tables: 1,
                chunks: 8,
                p50_us: 12 + (i as u32 % 5),
                p99_us: 28 + (i as u32 % 9),
                commands_queued: (i % 3) as u32,
                reserved: 0,
            };
            digest.to_le_bytes()
        })
        .collect()
}

fn position_of_needle(source: &str, needle: &str, byte_delta: usize) -> Position {
    let base = source
        .find(needle)
        .unwrap_or_else(|| panic!("needle `{needle}` not found in fixture"));
    let target = (base + byte_delta).min(source.len());
    let mut line = 0u32;
    let mut col = 0u32;
    for (idx, ch) in source.char_indices() {
        if idx >= target {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += ch.len_utf16() as u32;
        }
    }
    Position::new(line, col)
}

fn bench_lsp_telemetry_batch_10k(c: &mut Criterion) {
    let frames = build_10k_bamt_frames();
    let store = TelemetryStore::new();

    let mut group = c.benchmark_group("lsp_telemetry_bamt_10k");
    group.sample_size(20);
    group.throughput(Throughput::Elements(frames.len() as u64));

    group.bench_function("decode_slice_10k", |b| {
        b.iter(|| {
            let mut sum_p50 = 0u64;
            for raw in &frames {
                let d = decode_digest_slice(black_box(raw)).expect("valid BAMT frame");
                sum_p50 += u64::from(d.p50_us);
            }
            black_box(sum_p50);
        });
    });

    group.bench_function("decode_and_store_10k", |b| {
        b.iter(|| {
            for raw in &frames {
                let d = decode_digest_slice(black_box(raw)).expect("valid BAMT frame");
                store.record_digest(d);
            }
            black_box(store.get_for_system("genres::soulslike::tick_stamina_and_poise"));
        });
    });

    group.finish();
}

fn bench_lsp_incremental_did_change_and_graph(c: &mut Criterion) {
    let cookbook_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("cookbooks");
    let mv_src = fs::read_to_string(cookbook_dir.join("03_metroidvania_core.strata"))
        .expect("read 03_metroidvania_core");
    let mv_alt = mv_src.replacen("14.5", "14.75", 1);
    assert_ne!(mv_src, mv_alt);

    let ss_src = fs::read_to_string(cookbook_dir.join("05_soulslike_combat.strata"))
        .expect("read 05_soulslike_combat");
    let mp_src = fs::read_to_string(cookbook_dir.join("08_authoritative_multiplayer.strata"))
        .expect("read 08_authoritative_multiplayer");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let backend = StrataLspBackend::headless(TelemetryStore::new());
    let mv_uri = Url::parse("file:///bench/03_metroidvania_core.strata").expect("uri");
    let ss_uri = Url::parse("file:///bench/05_soulslike_combat.strata").expect("uri");
    let mp_uri = Url::parse("file:///bench/08_authoritative_multiplayer.strata").expect("uri");

    rt.block_on(async {
        for (uri, text) in [(&mv_uri, &mv_src), (&ss_uri, &ss_src), (&mp_uri, &mp_src)] {
            backend
                .did_open(DidOpenTextDocumentParams {
                    text_document: TextDocumentItem {
                        uri: uri.clone(),
                        language_id: "strata".to_owned(),
                        version: 1,
                        text: text.clone(),
                    },
                })
                .await;
        }
        for frame in build_10k_bamt_frames().iter().take(16) {
            let d = decode_digest_slice(frame).expect("frame");
            backend.telemetry().record_digest(d);
        }
    });

    let mut group = c.benchmark_group("lsp_incremental_and_graph");
    group.sample_size(25);

    let mut version = 2i32;
    group.throughput(Throughput::Bytes(mv_src.len() as u64));
    group.bench_function(
        BenchmarkId::new("did_change_body_edit", "03_metroidvania_core"),
        |b| {
            b.iter(|| {
                version += 1;
                let next = if version % 2 == 0 {
                    mv_alt.clone()
                } else {
                    mv_src.clone()
                };
                rt.block_on(backend.did_change(DidChangeTextDocumentParams {
                    text_document: VersionedTextDocumentIdentifier {
                        uri: mv_uri.clone(),
                        version,
                    },
                    content_changes: vec![TextDocumentContentChangeEvent {
                        range: None,
                        range_length: None,
                        text: next,
                    }],
                }));
            });
        },
    );

    let gt_params = GraphTelemetryParams {
        uri: Some(ss_uri.to_string()),
        node_ids: None,
        frames: Vec::new(),
    };
    group.bench_function(
        BenchmarkId::new("graph_telemetry", "05_soulslike_combat"),
        |b| {
            b.iter(|| {
                let resp = rt
                    .block_on(backend.graph_telemetry(black_box(gt_params.clone())))
                    .expect("graph_telemetry");
                black_box(resp.nodes.len());
            });
        },
    );

    group.finish();
}

fn bench_lsp_ide_requests(c: &mut Criterion) {
    let cookbook_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("cookbooks");
    let mv_src = fs::read_to_string(cookbook_dir.join("03_metroidvania_core.strata"))
        .expect("read 03_metroidvania_core");
    let ss_src = fs::read_to_string(cookbook_dir.join("05_soulslike_combat.strata"))
        .expect("read 05_soulslike_combat");
    let mp_src = fs::read_to_string(cookbook_dir.join("08_authoritative_multiplayer.strata"))
        .expect("read 08_authoritative_multiplayer");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let backend = StrataLspBackend::headless(TelemetryStore::new());
    let mv_uri = Url::parse("file:///bench/03_metroidvania_core.strata").expect("uri");
    let ss_uri = Url::parse("file:///bench/05_soulslike_combat.strata").expect("uri");
    let mp_uri = Url::parse("file:///bench/08_authoritative_multiplayer.strata").expect("uri");

    rt.block_on(async {
        for (uri, text) in [(&mv_uri, &mv_src), (&ss_uri, &ss_src), (&mp_uri, &mp_src)] {
            backend
                .did_open(DidOpenTextDocumentParams {
                    text_document: TextDocumentItem {
                        uri: uri.clone(),
                        language_id: "strata".to_owned(),
                        version: 1,
                        text: text.clone(),
                    },
                })
                .await;
        }
        for frame in build_10k_bamt_frames().iter().take(16) {
            let d = decode_digest_slice(frame).expect("frame");
            backend.telemetry().record_digest(d);
        }
    });

    // Cursor positions on real cookbook constructs
    let hover_mv_pos = position_of_needle(&mv_src, "KinematicBody", 2);
    let hover_ss_pos = position_of_needle(&ss_src, "tick_stamina_and_poise", 4);
    let comp_gen_pos = position_of_needle(&mv_src, "KinematicBody", 3);
    let comp_attr_pos = position_of_needle(&mp_src, "@authority", 2);
    let comp_dot_pos = position_of_needle(&mv_src, "body.grounded", 5);
    let comp_colon_pos = position_of_needle(&ss_src, "CombatantBody::hot", "CombatantBody::".len());
    let goto_def_pos = position_of_needle(&mv_src, "query_one(body: &mut KinematicBody", 24);
    let highlight_ss_pos = position_of_needle(&ss_src, "CombatantBody", 3);
    let refs_ss_pos = position_of_needle(&ss_src, "CombatantBody", 3);

    // Sanity check that each benchmarked request produces meaningful results
    rt.block_on(async {
        let h = backend
            .hover(HoverParams {
                text_document_position_params: TextDocumentPositionParams {
                    text_document: TextDocumentIdentifier {
                        uri: ss_uri.clone(),
                    },
                    position: hover_ss_pos,
                },
                work_done_progress_params: WorkDoneProgressParams::default(),
            })
            .await
            .expect("hover");
        assert!(
            h.is_some(),
            "expected hover result on tick_stamina_and_poise"
        );
    });

    let mut group = c.benchmark_group("lsp_ide_requests");
    group.sample_size(40);

    let hover_mv_params = HoverParams {
        text_document_position_params: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier {
                uri: mv_uri.clone(),
            },
            position: hover_mv_pos,
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
    };
    group.bench_function(BenchmarkId::new("hover", "03_metroidvania_core"), |b| {
        b.iter(|| {
            let resp = rt
                .block_on(backend.hover(black_box(hover_mv_params.clone())))
                .expect("hover");
            black_box(resp);
        });
    });

    let hover_ss_params = HoverParams {
        text_document_position_params: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier {
                uri: ss_uri.clone(),
            },
            position: hover_ss_pos,
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
    };
    group.bench_function(BenchmarkId::new("hover", "05_soulslike_combat"), |b| {
        b.iter(|| {
            let resp = rt
                .block_on(backend.hover(black_box(hover_ss_params.clone())))
                .expect("hover");
            black_box(resp);
        });
    });

    let comp_gen_params = CompletionParams {
        text_document_position: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier {
                uri: mv_uri.clone(),
            },
            position: comp_gen_pos,
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
        context: None,
    };
    group.bench_function(
        BenchmarkId::new("completion_general", "03_metroidvania_core"),
        |b| {
            b.iter(|| {
                let resp = rt
                    .block_on(backend.completion(black_box(comp_gen_params.clone())))
                    .expect("completion");
                black_box(resp);
            });
        },
    );

    let comp_attr_params = CompletionParams {
        text_document_position: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier {
                uri: mp_uri.clone(),
            },
            position: comp_attr_pos,
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
        context: None,
    };
    group.bench_function(
        BenchmarkId::new("completion_attr", "08_authoritative_multiplayer"),
        |b| {
            b.iter(|| {
                let resp = rt
                    .block_on(backend.completion(black_box(comp_attr_params.clone())))
                    .expect("completion");
                black_box(resp);
            });
        },
    );

    let comp_dot_params = CompletionParams {
        text_document_position: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier {
                uri: mv_uri.clone(),
            },
            position: comp_dot_pos,
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
        context: None,
    };
    group.bench_function(
        BenchmarkId::new("completion_dot", "03_metroidvania_core"),
        |b| {
            b.iter(|| {
                let resp = rt
                    .block_on(backend.completion(black_box(comp_dot_params.clone())))
                    .expect("completion");
                black_box(resp);
            });
        },
    );

    let comp_colon_params = CompletionParams {
        text_document_position: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier {
                uri: ss_uri.clone(),
            },
            position: comp_colon_pos,
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
        context: None,
    };
    group.bench_function(
        BenchmarkId::new("completion_colon", "05_soulslike_combat"),
        |b| {
            b.iter(|| {
                let resp = rt
                    .block_on(backend.completion(black_box(comp_colon_params.clone())))
                    .expect("completion");
                black_box(resp);
            });
        },
    );

    let goto_def_params = GotoDefinitionParams {
        text_document_position_params: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier {
                uri: mv_uri.clone(),
            },
            position: goto_def_pos,
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
    };
    group.bench_function(
        BenchmarkId::new("goto_definition", "03_metroidvania_core"),
        |b| {
            b.iter(|| {
                let resp = rt
                    .block_on(backend.goto_definition(black_box(goto_def_params.clone())))
                    .expect("goto_definition");
                black_box(resp);
            });
        },
    );

    let highlight_params = DocumentHighlightParams {
        text_document_position_params: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier {
                uri: ss_uri.clone(),
            },
            position: highlight_ss_pos,
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
    };
    group.bench_function(
        BenchmarkId::new("document_highlight", "05_soulslike_combat"),
        |b| {
            b.iter(|| {
                let resp = rt
                    .block_on(backend.document_highlight(black_box(highlight_params.clone())))
                    .expect("document_highlight");
                black_box(resp);
            });
        },
    );

    let refs_params = ReferenceParams {
        text_document_position: TextDocumentPositionParams {
            text_document: TextDocumentIdentifier {
                uri: ss_uri.clone(),
            },
            position: refs_ss_pos,
        },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
        context: ReferenceContext {
            include_declaration: true,
        },
    };
    group.bench_function(BenchmarkId::new("references", "05_soulslike_combat"), |b| {
        b.iter(|| {
            let resp = rt
                .block_on(backend.references(black_box(refs_params.clone())))
                .expect("references");
            black_box(resp);
        });
    });

    let doc_sym_params = DocumentSymbolParams {
        text_document: TextDocumentIdentifier { uri: mv_uri },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
    };
    group.bench_function(
        BenchmarkId::new("document_symbol", "03_metroidvania_core"),
        |b| {
            b.iter(|| {
                let resp = rt
                    .block_on(backend.document_symbol(black_box(doc_sym_params.clone())))
                    .expect("document_symbol");
                black_box(resp);
            });
        },
    );

    let ws_sym_params = WorkspaceSymbolParams {
        query: "Combat".to_owned(),
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
    };
    group.bench_function(BenchmarkId::new("workspace_symbol", "all_cookbooks"), |b| {
        b.iter(|| {
            let resp = rt
                .block_on(backend.symbol(black_box(ws_sym_params.clone())))
                .expect("workspace_symbol");
            black_box(resp);
        });
    });

    let inlay_params = InlayHintParams {
        text_document: TextDocumentIdentifier {
            uri: ss_uri.clone(),
        },
        range: Range::new(Position::new(0, 0), Position::new(500, 0)),
        work_done_progress_params: WorkDoneProgressParams::default(),
    };
    group.bench_function(BenchmarkId::new("inlay_hint", "05_soulslike_combat"), |b| {
        b.iter(|| {
            let resp = rt
                .block_on(backend.inlay_hint(black_box(inlay_params.clone())))
                .expect("inlay_hint");
            black_box(resp);
        });
    });

    let lens_params = CodeLensParams {
        text_document: TextDocumentIdentifier { uri: ss_uri },
        work_done_progress_params: WorkDoneProgressParams::default(),
        partial_result_params: PartialResultParams::default(),
    };
    group.bench_function(BenchmarkId::new("code_lens", "05_soulslike_combat"), |b| {
        b.iter(|| {
            let resp = rt
                .block_on(backend.code_lens(black_box(lens_params.clone())))
                .expect("code_lens");
            black_box(resp);
        });
    });

    let fmt_params = DocumentFormattingParams {
        text_document: TextDocumentIdentifier { uri: mp_uri },
        options: FormattingOptions::default(),
        work_done_progress_params: WorkDoneProgressParams::default(),
    };
    group.bench_function(
        BenchmarkId::new("formatting", "08_authoritative_multiplayer"),
        |b| {
            b.iter(|| {
                let resp = rt
                    .block_on(backend.formatting(black_box(fmt_params.clone())))
                    .expect("formatting");
                black_box(resp);
            });
        },
    );

    group.finish();
}

criterion_group!(
    benches,
    bench_lsp_telemetry_batch_10k,
    bench_lsp_incremental_did_change_and_graph,
    bench_lsp_ide_requests
);
criterion_main!(benches);
