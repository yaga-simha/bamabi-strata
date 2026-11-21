#![forbid(unsafe_code)]

use bamabi_host::prelude::*;
use bevy_app::{App, FixedUpdate};
use std::fs;
use std::path::PathBuf;
use stratac::cli::{BuildTarget, OnboardTarget, OutputFormat};
use stratac::commands::{
    cmd_build, cmd_check, cmd_explain_par, cmd_fmt, cmd_layout, cmd_onboard, cmd_test, cmd_watch,
};
use stratac::{EXIT_COMPILE_ERROR, EXIT_OK, EXIT_SIM_TEST_FAILED};
use tempfile::TempDir;

const COOKBOOKS: &[&str] = &[
    "01_rain_swarm.strata",
    "02_soa_and_ticks.strata",
    "03_metroidvania_core.strata",
    "04_cozy_valley.strata",
    "05_soulslike_combat.strata",
    "06_battle_royale_server.strata",
];

fn cookbooks_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("cookbooks")
}

#[test]
fn cli_check_layout_explain_par_fmt_on_all_cookbooks() {
    let dir = cookbooks_dir();
    for name in COOKBOOKS {
        let p = dir.join(name);

        let (code, check_json) = cmd_check(&p, OutputFormat::Json);
        assert_eq!(code, EXIT_OK, "check failed on {name}: {check_json}");
        let v: serde_json::Value = serde_json::from_str(&check_json).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["error_count"], 0);

        let (code, layout_json) = cmd_layout(&p, OutputFormat::Json);
        assert_eq!(code, EXIT_OK, "layout failed on {name}: {layout_json}");
        let lv: serde_json::Value = serde_json::from_str(&layout_json).unwrap();
        assert!(!lv["layouts"].as_array().unwrap().is_empty());

        let (code, par_json) = cmd_explain_par(&p, OutputFormat::Json);
        assert_eq!(code, EXIT_OK, "explain-par failed on {name}: {par_json}");

        let (code, _fmt_msg) = cmd_fmt(&p, true);
        // Either already formatted (0) or clean diff check exit 3.
        assert!(code == EXIT_OK || code == 3);
    }

    // Broken file returns EXIT_COMPILE_ERROR (1)
    let tmp = TempDir::new().unwrap();
    let bad = tmp.path().join("broken.strata");
    fs::write(
        &bad,
        "module bad::mod;\ncomponent A { x: f32 = 0.0 }\nsys f() { for e in query(a: &mut A, b: &A) {} }\n",
    )
    .unwrap();
    let (code, _) = cmd_check(&bad, OutputFormat::Json);
    assert_eq!(code, EXIT_COMPILE_ERROR);
}

#[test]
fn headless_sim_test_metroidvania_passes_and_invalid_assert_fails() {
    let mv_path = cookbooks_dir().join("03_metroidvania_core.strata");
    let (code, out) = cmd_test(&mv_path, OutputFormat::Json);
    assert_eq!(code, EXIT_OK, "metroidvania sim_test failed:\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["all_passed"], true);
    let t0 = &v["tests"][0];
    assert_eq!(t0["name"], "coyote_time_allows_late_jump_within_95ms");
    assert_eq!(t0["passed"], true);
    assert!(t0["frames_simulated"].as_u64().unwrap() >= 8);

    // Negative test: unreachable assertion must fail with EXIT_SIM_TEST_FAILED (2)
    let tmp = TempDir::new().unwrap();
    let fail_file = tmp.path().join("fail_sim.strata");
    fs::write(
        &fail_file,
        r#"
module test::fail_case @version(1.0.0);
component Hero { hp: f32 = 10.0 }
sim_test "expired_coyote_fails" {
    step_fixed(20);
    assert(false);
}
"#,
    )
    .unwrap();
    let (code, out) = cmd_test(&fail_file, OutputFormat::Json);
    assert_eq!(code, EXIT_SIM_TEST_FAILED, "expected exit 2, got:\n{out}");
}

#[test]
fn build_signed_bampack_and_watch_and_onboard_static_console() {
    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("signed_sim.strata");
    fs::write(
        &src_path,
        r#"
module demo::signed_sim @version(1.0.0);
component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component Vel { vx: f32 = 1.0, vy: f32 = 2.0 }
sys move_em() {
    for e in query(p: &mut Pos, v: &Vel) {
        e.p.x += e.v.vx * 0.016;
        e.p.y += e.v.vy * 0.016;
    }
}
schedule FixedUpdate { move_em }
"#,
    )
    .unwrap();

    // 1. C99 build + Ed25519 signature + verified .bampack
    let c_out = tmp.path().join("c99_pack");
    let (code, out) = cmd_build(
        &src_path,
        true,
        BuildTarget::C99,
        Some(&c_out),
        true,
        true,
        OutputFormat::Json,
    );
    assert_eq!(code, EXIT_OK, "C99 bampack failed:\n{out}");
    let cv: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(PathBuf::from(cv["bampack_path"].as_str().unwrap()).exists());
    assert!(PathBuf::from(cv["signature_path"].as_str().unwrap()).exists());
    assert!(PathBuf::from(cv["mod_toml_path"].as_str().unwrap()).exists());

    // 2. JIT build + Ed25519 signature + verified .bampack
    let jit_out = tmp.path().join("jit_pack");
    let (code, out) = cmd_build(
        &src_path,
        true,
        BuildTarget::Jit,
        Some(&jit_out),
        true,
        true,
        OutputFormat::Json,
    );
    assert_eq!(code, EXIT_OK, "JIT bampack failed:\n{out}");

    // 3. `stratac watch --once` incremental rebuild
    let (code, out) = cmd_watch(&src_path, true, true, OutputFormat::Json);
    assert_eq!(code, EXIT_OK, "watch --once failed:\n{out}");
    let wv: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(PathBuf::from(wv["dylib_path"].as_str().unwrap()).exists());
    assert_eq!(wv["salsa_layout_recomputed"], false);

    // 4. `stratac onboard --target bevy-native --static-console --check`
    let onboard_dir = tmp.path().join("native_console");
    let (code, out) = cmd_onboard(
        &src_path,
        OnboardTarget::BevyNative,
        &onboard_dir,
        true,
        true,
        OutputFormat::Json,
    );
    assert_eq!(code, EXIT_OK, "onboard static-console failed:\n{out}");
    let ov: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(ov["cargo_checked"], true);
}

#[test]
fn hot_reload_stability_50_cycles() {
    run_reload_cycles(50);
}

#[test]
#[ignore = "10,000-cycle RSS soak benchmark; run explicitly with --ignored"]
fn hot_reload_soak_10000_cycles() {
    run_reload_cycles(10_000);
}

fn run_reload_cycles(cycles: usize) {
    let tmp = TempDir::new().unwrap();
    let p_a = tmp.path().join("reload_a.strata");
    let p_b = tmp.path().join("reload_b.strata");
    fs::write(
        &p_a,
        "module soak::mod @version(1.0.0);\ncomponent Counter { v: i32 = 0 }\nsys inc() { for e in query(c: &mut Counter) { e.c.v += 1; } }\nschedule FixedUpdate { inc }\n",
    )
    .unwrap();
    fs::write(
        &p_b,
        "module soak::mod @version(1.0.1);\ncomponent Counter { v: i32 = 0 }\nsys inc() { for e in query(c: &mut Counter) { e.c.v += 2; } }\nschedule FixedUpdate { inc }\n",
    )
    .unwrap();

    let dir_a = tmp.path().join("out_a");
    let dir_b = tmp.path().join("out_b");
    let (c1, m1) = cmd_build(
        &p_a,
        false,
        BuildTarget::Jit,
        Some(&dir_a),
        false,
        false,
        OutputFormat::Json,
    );
    assert_eq!(c1, 0, "{m1}");
    let (c2, m2) = cmd_build(
        &p_b,
        false,
        BuildTarget::Jit,
        Some(&dir_b),
        false,
        false,
        OutputFormat::Json,
    );
    assert_eq!(c2, 0, "{m2}");
    let bin_a = PathBuf::from(
        serde_json::from_str::<serde_json::Value>(&m1).unwrap()["binary_path"]
            .as_str()
            .unwrap(),
    );
    let bin_b = PathBuf::from(
        serde_json::from_str::<serde_json::Value>(&m2).unwrap()["binary_path"]
            .as_str()
            .unwrap(),
    );

    let mut app = App::new();
    app.add_plugins(AbiModPlugin::with_error_policy(ModErrorPolicy::Quarantine));
    let mut mod_id = app.load_mod_with(&bin_a, LoadOptions::default()).unwrap();

    for i in 0..cycles {
        let next = if i % 2 == 0 { &bin_b } else { &bin_a };
        mod_id = app
            .reload_mod_from(mod_id, next, LoadOptions::default())
            .expect("reload_mod_from");
        app.world_mut().run_schedule(FixedUpdate);
    }
}
