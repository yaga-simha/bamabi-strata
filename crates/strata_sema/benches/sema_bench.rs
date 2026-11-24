//! Criterion `0.8` + `hotpath-rs` microbenchmarks for `strata_sema`:
//! - Cold cookbook `01..08` full semantic analysis (`Throughput::Bytes`)
//! - Warm Salsa incremental body-edit latency & allocations (`0` `resolve_layouts` runs)
//! - Deep nested `@authority` / `PlaceOrigin` expression checking (`08_authoritative_multiplayer` + synthetic tree)

use hotpath::criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use strata_sema::analyze_source;
use strata_sema::db::{SemaDb, Setter};

const COOKBOOKS: &[&str] = &[
    "01_rain_swarm",
    "02_soa_and_ticks",
    "03_metroidvania_core",
    "04_cozy_valley",
    "05_soulslike_combat",
    "06_battle_royale_server",
    "07_visual_boss_graph",
    "08_authoritative_multiplayer",
];

const DEEP_AUTHORITY_SRC: &str = r#"
module bench::authority_deep @version(1.0.0);

@authority(server)
component AuthState {
    hp: f32 = 100.0,
    shield: f32 = 50.0,
    seq: u32 = 0,
    crit: bool = false,
}

@predicted
component LocalPred {
    score: f32 = 0.0,
    combo: u32 = 0,
    bonus: f32 = 1.0,
}

fn clamp_bonus(val: f32, hi: f32) -> f32 {
    if val > hi { hi } else if val < 0.0 { 0.0 } else { val }
}

@authority(client)
sys client_eval_deep() {
    for row in query(auth: &AuthState, pred: &mut LocalPred) {
        let base_hp = row.auth.hp;
        let base_sh = row.auth.shield;
        let scaled = if row.auth.crit {
            let t0 = (base_hp * 0.25) + clamp_bonus(base_sh * 0.1, 12.0);
            let pair = (t0, base_hp * 0.05);
            let (p0, p1) = pair;
            p0 + p1
        } else {
            let alt = match row.auth.seq {
                0_u32 => base_hp * 0.05,
                1_u32 => base_hp * 0.10,
                _ => base_sh * 0.15,
            };
            clamp_bonus(alt, 20.0)
        };
        let arr = [scaled, scaled * 0.5, row.pred.bonus, 1.0];
        row.pred.score += arr[0] + arr[1];
        row.pred.combo += 1_u32;
    }
}

schedule FixedUpdate { client_eval_deep }
"#;

fn load_cookbooks() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("cookbooks");
    COOKBOOKS
        .iter()
        .map(|&name| {
            let path = dir.join(format!("{name}.strata"));
            let src = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed reading {}: {e}", path.display()));
            let analyzed = analyze_source(format!("{name}.strata"), &src);
            assert!(
                analyzed.ok(),
                "cookbook `{name}` must pass sema before bench: {:?}",
                analyzed.diagnostics
            );
            (name.to_owned(), src)
        })
        .collect()
}

fn bench_sema_cold_cookbooks(c: &mut Criterion) {
    let fixtures = load_cookbooks();
    let mut group = c.benchmark_group("sema_cold_cookbooks");
    group.sample_size(20);
    for (name, src) in &fixtures {
        group.throughput(Throughput::Bytes(src.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), src, |b, text| {
            b.iter(|| {
                let analyzed = analyze_source(black_box(name.as_str()), black_box(text.as_str()));
                black_box(analyzed.layouts.len());
            });
        });
    }
    group.finish();
}

fn bench_sema_salsa_incremental_body_edit(c: &mut Criterion) {
    let fixtures = load_cookbooks();
    let (_, mv_src) = fixtures
        .iter()
        .find(|(n, _)| n == "03_metroidvania_core")
        .expect("03_metroidvania_core");
    let mv_alt = mv_src.replacen("14.5", "14.75", 1);
    assert_ne!(
        &mv_alt, mv_src,
        "expected body literal replacement in 03_metroidvania_core"
    );

    let (_, ss_src) = fixtures
        .iter()
        .find(|(n, _)| n == "05_soulslike_combat")
        .expect("05_soulslike_combat");
    let ss_alt = ss_src.replacen("25.0 * dt_s", "26.0 * dt_s", 1);
    assert_ne!(
        &ss_alt, ss_src,
        "expected body literal replacement in 05_soulslike_combat"
    );

    // Verify Salsa early-cutoff invariant once outside timing loop.
    {
        let mut db = SemaDb::new();
        let sf = db.new_source("03_metroidvania_core.strata", mv_src.clone());
        let _ = db.analyze_file(sf);
        let _ = db.take_executed_queries();
        sf.set_text(&mut db).to(mv_alt.clone());
        let _ = db.analyze_file(sf);
        let executed = db.take_executed_queries();
        assert!(
            !executed.iter().any(|q| q.contains("resolve_layouts")),
            "body-only edit must trigger early cutoff with 0 resolve_layouts runs, got: {executed:?}"
        );
    }

    let mut group = c.benchmark_group("sema_salsa_body_edit");
    group.sample_size(30);

    for (name, src_a, src_b) in [
        ("03_metroidvania_core", mv_src, &mv_alt),
        ("05_soulslike_combat", ss_src, &ss_alt),
    ] {
        let mut db = SemaDb::new();
        let sf = db.new_source(format!("{name}.strata"), src_a.clone());
        let _ = db.analyze_file(sf);
        let mut flip = false;

        group.throughput(Throughput::Bytes(src_a.len() as u64));
        group.bench_function(BenchmarkId::from_parameter(name), |b| {
            b.iter(|| {
                flip = !flip;
                let next = if flip { src_b.clone() } else { src_a.clone() };
                sf.set_text(&mut db).to(next);
                let analyzed = db.analyze_file(sf);
                black_box(analyzed.callables.len());
            });
        });
    }
    group.finish();
}

fn bench_sema_authority_place_origin(c: &mut Criterion) {
    let fixtures = load_cookbooks();
    let (_, mp_src) = fixtures
        .iter()
        .find(|(n, _)| n == "08_authoritative_multiplayer")
        .expect("08_authoritative_multiplayer");
    let deep_check = analyze_source("authority_deep.strata", DEEP_AUTHORITY_SRC);
    assert!(
        deep_check.ok(),
        "DEEP_AUTHORITY_SRC failed sema: {:?}",
        deep_check.diagnostics
    );

    let mut group = c.benchmark_group("sema_authority_place_origin");
    group.sample_size(25);
    for (name, src) in [
        ("08_authoritative_multiplayer", mp_src.as_str()),
        ("synthetic_deep_place_origin", DEEP_AUTHORITY_SRC),
    ] {
        group.throughput(Throughput::Bytes(src.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), src, |b, text| {
            b.iter(|| {
                let analyzed = analyze_source(black_box(name), black_box(text));
                black_box((analyzed.diagnostics.len(), analyzed.authorities.len()));
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_sema_cold_cookbooks,
    bench_sema_salsa_incremental_body_edit,
    bench_sema_authority_place_origin
);
criterion_main!(benches);
