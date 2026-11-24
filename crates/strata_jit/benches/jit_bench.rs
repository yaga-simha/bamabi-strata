//! Criterion `0.8` + `hotpath-rs` microbenchmarks for `strata_jit`:
//! - Cranelift PIC object codegen (`emit_pic_object`) across cookbooks `01..08`
//! - `JitOptLevel::FastCompile` vs `JitOptLevel::Speed` vs source-codegen emission

use hotpath::criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use strata_codegen::{BevyNativeOptions, emit_bevy_native, emit_c99, emit_rust_guest};
use strata_jit::emitter::emit_pic_object;
use strata_jit::{JitCompileOptions, JitOptLevel};
use strata_mir::{MirModule, lower_to_mir, verify_mir};
use strata_sema::analyze_source;

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

fn load_mir_cookbooks() -> Vec<(String, usize, MirModule)> {
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
            assert!(analyzed.ok(), "cookbook `{name}` sema failed");
            let mir = lower_to_mir(&analyzed);
            verify_mir(&mir)
                .unwrap_or_else(|e| panic!("cookbook `{name}` MIR verify failed: {e:?}"));
            (name.to_owned(), src.len(), mir)
        })
        .collect()
}

fn bench_jit_emit_cookbooks_speed(c: &mut Criterion) {
    let fixtures = load_mir_cookbooks();
    let mut group = c.benchmark_group("jit_emit_pic_speed");
    group.sample_size(10);

    for (name, bytes, mir) in &fixtures {
        let opts = JitCompileOptions {
            out_dir: PathBuf::from("."),
            module_stem: name.clone(),
            opt_level: JitOptLevel::Speed,
        };
        group.throughput(Throughput::Bytes(*bytes as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), mir, |b, mod_mir| {
            b.iter(|| {
                let obj = emit_pic_object(black_box(mod_mir), &opts).expect("emit_pic_object");
                black_box(obj.object_bytes.len());
            });
        });
    }
    group.finish();
}

fn bench_jit_opt_levels_and_aot_codegen(c: &mut Criterion) {
    let fixtures = load_mir_cookbooks();
    let mut group = c.benchmark_group("jit_opt_level_compare");
    group.sample_size(10);

    for target in ["03_metroidvania_core", "05_soulslike_combat"] {
        let (_, bytes, mir) = fixtures
            .iter()
            .find(|(n, _, _)| n == target)
            .expect("target cookbook");
        group.throughput(Throughput::Bytes(*bytes as u64));

        for (label, level) in [
            ("fast_compile", JitOptLevel::FastCompile),
            ("speed", JitOptLevel::Speed),
        ] {
            let opts = JitCompileOptions {
                out_dir: PathBuf::from("."),
                module_stem: target.to_owned(),
                opt_level: level,
            };
            group.bench_with_input(BenchmarkId::new(label, target), mir, |b, mod_mir| {
                b.iter(|| {
                    let obj = emit_pic_object(black_box(mod_mir), &opts).expect("emit_pic_object");
                    black_box(obj.object_bytes.len());
                });
            });
        }

        group.bench_with_input(
            BenchmarkId::new("aot_emit_all", target),
            mir,
            |b, mod_mir| {
                b.iter(|| {
                    let c99 = emit_c99(black_box(mod_mir)).expect("c99");
                    let rg = emit_rust_guest(black_box(mod_mir)).expect("rust_guest");
                    let bn = emit_bevy_native(black_box(mod_mir), &BevyNativeOptions::default())
                        .expect("bevy_native");
                    black_box((c99.files.len(), rg.files.len(), bn.files.len()));
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_jit_emit_cookbooks_speed,
    bench_jit_opt_levels_and_aot_codegen
);
criterion_main!(benches);
