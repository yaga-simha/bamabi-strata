//! Criterion `0.8` + `hotpath-rs` microbenchmarks for `strata_lsp`:
//! - `SystemTelemetryDigest64` (`*b"BAMT"`) 10,000-frame batch decode + `TelemetryStore` ingest
//! - Incremental `did_change` LSP re-analysis
//! - `strata/graphTelemetry` node mapping

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
    DidChangeTextDocumentParams, DidOpenTextDocumentParams, TextDocumentContentChangeEvent,
    TextDocumentItem, Url, VersionedTextDocumentIdentifier,
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

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let backend = StrataLspBackend::headless(TelemetryStore::new());
    let mv_uri = Url::parse("file:///bench/03_metroidvania_core.strata").expect("uri");
    let ss_uri = Url::parse("file:///bench/05_soulslike_combat.strata").expect("uri");

    rt.block_on(async {
        backend
            .did_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem {
                    uri: mv_uri.clone(),
                    language_id: "strata".to_owned(),
                    version: 1,
                    text: mv_src.clone(),
                },
            })
            .await;
        backend
            .did_open(DidOpenTextDocumentParams {
                text_document: TextDocumentItem {
                    uri: ss_uri.clone(),
                    language_id: "strata".to_owned(),
                    version: 1,
                    text: ss_src.clone(),
                },
            })
            .await;
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

criterion_group!(
    benches,
    bench_lsp_telemetry_batch_10k,
    bench_lsp_incremental_did_change_and_graph
);
criterion_main!(benches);
