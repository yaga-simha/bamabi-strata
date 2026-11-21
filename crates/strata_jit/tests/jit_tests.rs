use std::process::Command;
use strata_jit::{JitCompileOptions, JitOptLevel, compile_module_to_dylib};
use strata_mir::lower_to_mir;
use strata_sema::analyze_source;
use tempfile::TempDir;

#[test]
fn cranelift_jit_emits_and_links_pic_shared_library_with_abi_exports() {
    let src = r#"
module jit::demo @version(1.0.0);

resource SimParam { dt: f32 = 0.016 }
component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component Vel { vx: f32 = 1.0, vy: f32 = -2.0 }
component Heat @summary_tick { temp: f32 = 0.0, hot: bool = false }

sys step_demo(p: &res SimParam) {
    uniform let dt = p.dt;
    for e in query(pos: &mut Pos, vel: &Vel, heat: &mut? Heat) {
        e.pos.x += e.vel.vx * dt;
        e.pos.y += e.vel.vy * dt;
        if e.pos.y < -1.0 {
            e.heat.temp += 0.5;
            e.heat.hot = true;
        }
    }
}

schedule FixedUpdate { step_demo }
"#;

    let analyzed = analyze_source("jit_demo.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: "strata_jit_demo".to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .expect("compile_module_to_dylib");

    assert!(artifact.object_path.exists());
    assert!(artifact.dylib_path.exists());
    assert!(
        std::fs::metadata(&artifact.dylib_path).unwrap().len() > 0,
        "linked dylib must be non-empty"
    );

    if cfg!(any(target_os = "macos", target_os = "linux")) {
        let mut nm = Command::new("nm");
        if cfg!(target_os = "macos") {
            nm.arg("-gU");
        } else {
            nm.arg("-D");
        }
        let out = nm.arg(&artifact.dylib_path).output().expect("nm");
        assert!(out.status.success());
        let syms = String::from_utf8_lossy(&out.stdout);
        for required in ["bamabi_manifest", "bamabi_init", "bamabi_shutdown"] {
            assert!(
                syms.contains(required),
                "missing exported symbol `{required}` in:\n{syms}"
            );
        }
    }
}

fn compile_fixture_and_verify(stem: &str, path: &str, opt_level: JitOptLevel) {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let full_path = manifest_dir.join("../..").join(path);
    let src = std::fs::read_to_string(&full_path)
        .unwrap_or_else(|e| panic!("failed reading {}: {e}", full_path.display()));
    compile_source_and_verify(stem, path, &src, opt_level);
}

fn compile_source_and_verify(stem: &str, file_name: &str, src: &str, opt_level: JitOptLevel) {
    let analyzed = analyze_source(file_name, src);
    assert!(
        analyzed.ok(),
        "sema diagnostics for {file_name}: {:?}",
        analyzed.diagnostics
    );
    let mir = lower_to_mir(&analyzed);
    let tmp = TempDir::new().expect("tempdir");
    let artifact = compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: tmp.path().to_path_buf(),
            module_stem: stem.to_owned(),
            opt_level,
        },
    )
    .unwrap_or_else(|e| panic!("JIT compile failed for {file_name}: {e}"));

    assert!(artifact.object_path.exists());
    assert!(artifact.dylib_path.exists());

    if cfg!(any(target_os = "macos", target_os = "linux")) {
        let mut nm_obj = Command::new("nm");
        let out_obj = nm_obj.arg(&artifact.object_path).output().expect("nm .o");
        assert!(out_obj.status.success());
        let obj_syms = String::from_utf8_lossy(&out_obj.stdout);
        assert!(
            !obj_syms.contains("strata_jit_state"),
            "unexpected BSS global `strata_jit_state` found in {file_name}:\n{obj_syms}"
        );
        assert!(
            obj_syms.contains("calloc") && obj_syms.contains("free"),
            "expected heap calloc/free imports in {file_name}:\n{obj_syms}"
        );

        let mut nm_dyn = Command::new("nm");
        if cfg!(target_os = "macos") {
            nm_dyn.arg("-gU");
        } else {
            nm_dyn.arg("-D");
        }
        let out_dyn = nm_dyn.arg(&artifact.dylib_path).output().expect("nm dylib");
        assert!(out_dyn.status.success());
        let dyn_syms = String::from_utf8_lossy(&out_dyn.stdout);
        for required in ["bamabi_manifest", "bamabi_init", "bamabi_shutdown"] {
            assert!(
                dyn_syms.contains(required),
                "missing exported symbol `{required}` in {file_name}:\n{dyn_syms}"
            );
        }
    }
}

#[test]
fn cranelift_jit_compiles_all_six_cookbooks_direct_mir() {
    let cookbooks = [
        ("rain_swarm", "fixtures/cookbooks/01_rain_swarm.strata"),
        (
            "soa_and_ticks",
            "fixtures/cookbooks/02_soa_and_ticks.strata",
        ),
        (
            "metroidvania_core",
            "fixtures/cookbooks/03_metroidvania_core.strata",
        ),
        ("cozy_valley", "fixtures/cookbooks/04_cozy_valley.strata"),
        (
            "soulslike_combat",
            "fixtures/cookbooks/05_soulslike_combat.strata",
        ),
        (
            "battle_royale",
            "fixtures/cookbooks/06_battle_royale_server.strata",
        ),
    ];

    for (stem, path) in cookbooks {
        compile_fixture_and_verify(stem, path, JitOptLevel::Speed);
    }
    compile_fixture_and_verify(
        "rain_fast",
        "fixtures/cookbooks/01_rain_swarm.strata",
        JitOptLevel::FastCompile,
    );
}

#[test]
fn cranelift_jit_compiles_schema_migration_fixture() {
    let src = r#"
module demo::mig @version(2.0.0);

component HealthV1 {
    hp: i32,
}

component Health {
    hp: f32 = 100.0,
    regen: f32 = 2.5,
}

migrate Health from 1.0.0 to 2.0.0(old: &HealthV1) -> Health {
    Health { hp: old.hp as f32, regen: 2.5 }
}

sys heal() {
    for row in query(h: &mut Health) {
        row.h.hp += row.h.regen * 0.016;
    }
}

schedule Update { heal }
"#;
    compile_source_and_verify(
        "migrate_demo",
        "migrate_demo.strata",
        src,
        JitOptLevel::Speed,
    );
}

#[test]
fn cranelift_jit_compiles_libm_helpers_tables_curves_sparse_and_relations() {
    let src = r#"
module test::full_mir_test @version(1.0.0) @deterministic;

enum WeaponKind { Sword = 0, Bow = 1 }

@sparse
component Pos { xy: vec2 }

component Flags { mask: BitSet<64> }

relation ChildRel [exclusive, cascade_despawn];

table WeaponStats by WeaponKind {
    damage: f32,
    range: f32,
} = {
    Sword => { damage: 25.0, range: 2.0 },
    Bow   => { damage: 15.0, range: 30.0 },
};

curve Falloff(f32 -> f32) = [
    (0.0,  1.0),
    (10.0, 0.5),
    (30.0, 0.0),
];

fn compute_falloff(d: f32, kind: WeaponKind) -> f32 {
    let w = WeaponStats[kind].damage;
    let s = sin(d) + cos(d) + atan2(d, 1.0) + pow(2.0, 0.5) + exp(0.0) + log(1.0) + round(1.6);
    w * Falloff.sample(d) + s * 0.001
}

sys update_all() {
    for row in query(pos: &mut Pos, fl: &mut Flags) {
        let dmg = compute_falloff(length(row.pos.xy), WeaponKind::Sword);
        if dmg > 0.0 {
            row.fl.mask.set(3);
            if row.fl.mask.get(3) {
                row.fl.mask.clear(3);
            }
        }
        insert_relation<ChildRel>(row.id, row.id);
    }
}

schedule FixedUpdate { update_all }
"#;
    compile_source_and_verify(
        "full_mir_test",
        "full_mir_test.strata",
        src,
        JitOptLevel::Speed,
    );
}
