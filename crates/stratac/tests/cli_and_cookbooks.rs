#![forbid(unsafe_code)]

#[cfg(feature = "sim-runner")]
use bamabi_host::prelude::*;
use bamabi_trust::{
    DEFAULT_BAMPACK_NAMESPACE, DEFAULT_SIGNATURE_NAMESPACE, ModTrustPolicy as TrustPolicy,
    write_openssh_keypair,
};
#[cfg(feature = "sim-runner")]
use bevy_app::{App, FixedUpdate};
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;
#[cfg(feature = "sim-runner")]
use stratac::EXIT_SIM_TEST_FAILED;
use stratac::cli::{BuildTarget, OnboardTarget, OutputFormat};
#[cfg(feature = "sim-runner")]
use stratac::commands::cmd_test;
use stratac::commands::{
    ScheduleDeltaArtifact, ScheduleDeltaMode, WatchReport, WatchSession, cmd_build,
    cmd_build_with_key, cmd_check, cmd_explain_par, cmd_fmt, cmd_layout, cmd_onboard, cmd_watch,
    cmd_watch_bounded, cmd_watch_with_key,
};
use stratac::{EXIT_COMPILE_ERROR, EXIT_OK};
use tempfile::TempDir;

const COOKBOOKS: &[&str] = &[
    "01_rain_swarm.strata",
    "02_soa_and_ticks.strata",
    "03_metroidvania_core.strata",
    "04_cozy_valley.strata",
    "05_soulslike_combat.strata",
    "06_battle_royale_server.strata",
    "07_visual_boss_graph.strata",
    "08_authoritative_multiplayer.strata",
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

#[cfg(feature = "sim-runner")]
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

    let kp = write_openssh_keypair(&tmp.path().join("signing_key"), Some("stratac-test")).unwrap();
    let wrong_kp =
        write_openssh_keypair(&tmp.path().join("wrong_key"), Some("stratac-wrong")).unwrap();
    let sig_policy = TrustPolicy::strict()
        .add_public_key_file(&kp.public_key)
        .unwrap()
        .with_namespace(DEFAULT_SIGNATURE_NAMESPACE)
        .unwrap();
    let bampack_policy = TrustPolicy::strict()
        .add_public_key_file(&kp.public_key)
        .unwrap()
        .with_namespace(DEFAULT_BAMPACK_NAMESPACE)
        .unwrap();

    // 0. Missing `--key` and `--ephemeral-key` fails deterministically when signing/packaging.
    let (missing_code, _) = cmd_build(
        &src_path,
        false,
        BuildTarget::Jit,
        None,
        false,
        true,
        OutputFormat::Json,
    );
    assert_eq!(missing_code, EXIT_COMPILE_ERROR);
    let (missing_watch, _) = cmd_watch(&src_path, true, true, OutputFormat::Json);
    assert_eq!(missing_watch, EXIT_COMPILE_ERROR);

    // 1. C99 build + deterministic Ed25519 signature + verified .bampack
    let c_out = tmp.path().join("c99_pack");
    let (code, out) = cmd_build_with_key(
        &src_path,
        true,
        BuildTarget::C99,
        Some(&c_out),
        true,
        true,
        Some(&kp.private_key),
        false,
        OutputFormat::Json,
    );
    assert_eq!(code, EXIT_OK, "C99 bampack failed:\n{out}");
    let cv: serde_json::Value = serde_json::from_str(&out).unwrap();
    let c_bin = PathBuf::from(cv["binary_path"].as_str().unwrap());
    let c_sig = PathBuf::from(cv["signature_path"].as_str().unwrap());
    let c_bp = PathBuf::from(cv["bampack_path"].as_str().unwrap());
    assert!(c_bp.exists());
    assert!(c_sig.exists());
    assert!(PathBuf::from(cv["mod_toml_path"].as_str().unwrap()).exists());
    assert_eq!(cv["signer_fingerprint"].as_str().unwrap(), kp.fingerprint);
    sig_policy
        .verify_bytes(&fs::read(&c_bin).unwrap(), &fs::read(&c_sig).unwrap())
        .expect("C99 .sig verifies under ModTrustPolicy");
    bampack_policy
        .verify_bampack_file(&c_bp)
        .expect("C99 .bampack verifies under ModTrustPolicy");

    // 2. JIT build + deterministic Ed25519 signature + verified .bampack
    let jit_out = tmp.path().join("jit_pack");
    let (code, out) = cmd_build_with_key(
        &src_path,
        true,
        BuildTarget::Jit,
        Some(&jit_out),
        true,
        true,
        Some(&kp.private_key),
        false,
        OutputFormat::Json,
    );
    assert_eq!(code, EXIT_OK, "JIT bampack failed:\n{out}");
    let jv: serde_json::Value = serde_json::from_str(&out).unwrap();
    let jit_bin = PathBuf::from(jv["binary_path"].as_str().unwrap());
    let jit_sig = PathBuf::from(jv["signature_path"].as_str().unwrap());
    let jit_bp = PathBuf::from(jv["bampack_path"].as_str().unwrap());
    let jit_sig_bytes_1 = fs::read(&jit_sig).unwrap();
    sig_policy
        .verify_bytes(&fs::read(&jit_bin).unwrap(), &jit_sig_bytes_1)
        .expect("JIT .sig verifies under ModTrustPolicy");
    bampack_policy
        .verify_bampack_file(&jit_bp)
        .expect("JIT .bampack verifies under ModTrustPolicy");

    // Repeat JIT build with same `--key` produces byte-for-byte identical `.sig` sidecar.
    let (code, out2) = cmd_build_with_key(
        &src_path,
        true,
        BuildTarget::Jit,
        Some(&jit_out),
        false,
        true,
        Some(&kp.private_key),
        false,
        OutputFormat::Json,
    );
    assert_eq!(code, EXIT_OK, "repeat JIT build failed:\n{out2}");
    assert_eq!(fs::read(&jit_sig).unwrap(), jit_sig_bytes_1);

    // Host `App::set_mod_trust_policy` loads trusted `.dylib` and rejects wrong key.
    #[cfg(feature = "sim-runner")]
    {
        let host_policy = ModTrustPolicy::strict()
            .add_public_key_file(&kp.public_key)
            .unwrap();
        let mut app = App::new();
        app.add_plugins(AbiModPlugin::with_error_policy(ModErrorPolicy::Quarantine));
        app.set_mod_trust_policy(host_policy);
        app.load_mod_with(&jit_bin, LoadOptions::default())
            .expect("trusted signed JIT dylib loads in bamabi_host App");

        let wrong_policy = ModTrustPolicy::strict()
            .add_public_key_file(&wrong_kp.public_key)
            .unwrap();
        let mut bad_app = App::new();
        bad_app.add_plugins(AbiModPlugin::with_error_policy(ModErrorPolicy::Quarantine));
        bad_app.set_mod_trust_policy(wrong_policy);
        assert!(
            bad_app
                .load_mod_with(&jit_bin, LoadOptions::default())
                .is_err(),
            "signed dylib must be rejected by wrong public key"
        );
    }
    let _ = &wrong_kp;

    // `--ephemeral-key` explicit opt-in succeeds on both build and watch.
    let eph_out = tmp.path().join("eph_pack");
    let (eph_code, eph_out_str) = cmd_build_with_key(
        &src_path,
        false,
        BuildTarget::Jit,
        Some(&eph_out),
        true,
        true,
        None,
        true,
        OutputFormat::Json,
    );
    assert_eq!(eph_code, EXIT_OK, "ephemeral build failed:\n{eph_out_str}");
    let (eph_watch, eph_watch_out) =
        cmd_watch_with_key(&src_path, true, None, true, true, OutputFormat::Json);
    assert_eq!(
        eph_watch, EXIT_OK,
        "ephemeral watch failed:\n{eph_watch_out}"
    );

    // 3. `stratac watch --once --key ...` incremental rebuild + deterministic `.sig` verification
    let (code, out) = cmd_watch_with_key(
        &src_path,
        true,
        Some(&kp.private_key),
        false,
        true,
        OutputFormat::Json,
    );
    assert_eq!(code, EXIT_OK, "watch --once failed:\n{out}");
    let wv: serde_json::Value = serde_json::from_str(&out).unwrap();
    let watch_dylib = PathBuf::from(wv["dylib_path"].as_str().unwrap());
    let watch_sig = PathBuf::from(wv["signature_path"].as_str().unwrap());
    assert!(watch_dylib.exists());
    assert!(watch_sig.exists());
    assert_eq!(wv["salsa_layout_recomputed"], false);
    assert_eq!(wv["signer_fingerprint"].as_str().unwrap(), kp.fingerprint);
    sig_policy
        .verify_bytes(
            &fs::read(&watch_dylib).unwrap(),
            &fs::read(&watch_sig).unwrap(),
        )
        .expect("watch .sig verifies under ModTrustPolicy");

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
fn notify_debouncer_watch_handles_edits_and_atomic_renames() {
    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("live_watch.strata");
    let s1 = r#"
module demo::live_watch @version(1.0.0);
component Pos { x: f32 = 0.0 }
sys step_a() {
    for e in query(p: &mut Pos) { e.p.x += 1.0; }
}
sys step_b() {
    for e in query(p: &mut Pos) { e.p.x += 2.0; }
}
schedule FixedUpdate {
    seq MainSeq { step_a, step_b }
}
"#;
    fs::write(&src_path, s1).unwrap();

    let kp = write_openssh_keypair(&tmp.path().join("watch_key"), Some("live-watch")).unwrap();
    let sig_policy = TrustPolicy::strict()
        .add_public_key_file(&kp.public_key)
        .unwrap()
        .with_namespace(DEFAULT_SIGNATURE_NAMESPACE)
        .unwrap();

    let (tx_ready, rx_ready) = mpsc::channel();
    let (tx_cycle, rx_cycle) = mpsc::channel::<WatchReport>();
    let watch_file = src_path.clone();
    let priv_key = kp.private_key.clone();

    let handle = std::thread::spawn(move || {
        cmd_watch_bounded(
            &watch_file,
            true,
            Some(&priv_key),
            false,
            false,
            Some(2),
            Some(tx_ready),
            Some(tx_cycle),
            OutputFormat::Json,
        )
    });

    let r1 = rx_cycle
        .recv_timeout(Duration::from_secs(15))
        .expect("initial watch cycle completes");
    assert!(!r1.schedule_delta_only);
    let dylib_path = PathBuf::from(&r1.dylib_path);
    assert!(dylib_path.exists());
    let dylib_bytes_1 = fs::read(&dylib_path).unwrap();

    rx_ready
        .recv_timeout(Duration::from_secs(15))
        .expect("notify debouncer ready");
    // Allow macOS FSEvents stream start to settle before emitting the first atomic save.
    std::thread::sleep(Duration::from_millis(150));

    // Edit 1 (atomic temp-write + rename): schedule-only reorder & mode change -> zero-JIT delta.
    let s2 = s1.replace(
        "seq MainSeq { step_a, step_b }",
        "par MainSeq { step_b, step_a }",
    );
    let staging = tmp.path().join(".live_watch.strata.tmp");
    fs::write(&staging, &s2).unwrap();
    fs::rename(&staging, &src_path).unwrap();

    let r2 = rx_cycle
        .recv_timeout(Duration::from_secs(15))
        .expect("atomic rename triggers debounced schedule-delta rebuild");
    assert!(r2.schedule_delta_only);
    assert!(!r2.salsa_layout_recomputed);
    assert_eq!(fs::read(&dylib_path).unwrap(), dylib_bytes_1);
    let delta_path = PathBuf::from(r2.schedule_delta_path.as_ref().unwrap());
    let delta: ScheduleDeltaArtifact =
        serde_json::from_slice(&fs::read(&delta_path).unwrap()).unwrap();
    assert_eq!(delta.target_pass, "ModScheduleSetRewirePass");
    assert_eq!(delta.sets[0].mode, ScheduleDeltaMode::Parallel);
    assert_eq!(delta.sets[0].mounted_systems, vec!["step_b", "step_a"]);

    // Edit 2 (direct write): body-only edit -> full JIT + deterministic re-signing with same key.
    let s3 = s2.replace("e.p.x += 1.0;", "e.p.x += 5.0;");
    fs::write(&src_path, &s3).unwrap();

    let r3 = rx_cycle
        .recv_timeout(Duration::from_secs(15))
        .expect("direct write triggers debounced body rebuild");
    assert!(!r3.schedule_delta_only);
    assert!(!r3.salsa_layout_recomputed);
    assert_eq!(
        r3.signer_fingerprint.as_deref(),
        Some(kp.fingerprint.as_str())
    );
    let sig_path = PathBuf::from(r3.signature_path.as_ref().unwrap());
    sig_policy
        .verify_bytes(
            &fs::read(&dylib_path).unwrap(),
            &fs::read(&sig_path).unwrap(),
        )
        .expect("rebuilt watch .sig verifies under ModTrustPolicy");

    let (exit_code, _) = handle.join().expect("watcher thread exits cleanly");
    assert_eq!(exit_code, EXIT_OK);
}

#[cfg(feature = "sim-runner")]
#[test]
fn hot_reload_stability_50_cycles() {
    run_reload_cycles(50);
}

#[cfg(feature = "sim-runner")]
#[test]
#[ignore = "10,000-cycle RSS soak benchmark; run explicitly with --ignored"]
fn hot_reload_soak_10000_cycles() {
    run_reload_cycles(10_000);
}

#[cfg(feature = "sim-runner")]
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

#[test]
fn cookbook_07_graph_export_covers_all_8_kinds_and_fmt_check_passes() {
    let p07 = cookbooks_dir().join("07_visual_boss_graph.strata");
    let (fmt_code, fmt_msg) = cmd_fmt(&p07, true);
    assert_eq!(fmt_code, EXIT_OK, "07 fmt --check failed: {fmt_msg}");
    let (exp_code, exp_json) =
        stratac::commands::graph_cmd::cmd_graph_export(&p07, OutputFormat::Json);
    assert_eq!(exp_code, EXIT_OK, "07 graph export failed: {exp_json}");
    let doc: serde_json::Value = serde_json::from_str(&exp_json).unwrap();
    let kinds: std::collections::HashSet<&str> = doc["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|n| n["kind"].as_str())
        .collect();
    for expected in [
        "component",
        "node_pure_fn",
        "timeline",
        "fsm",
        "task",
        "table",
        "curve",
        "schedule",
    ] {
        assert!(
            kinds.contains(expected),
            "07 graph export missing kind `{expected}` in {kinds:?}"
        );
    }
}

#[cfg(feature = "sim-runner")]
#[test]
fn cookbooks_07_and_08_headless_tests_pass() {
    let p07 = cookbooks_dir().join("07_visual_boss_graph.strata");
    let (code7, out7) = cmd_test(&p07, OutputFormat::Json);
    assert_eq!(code7, EXIT_OK, "07 cmd_test failed:\n{out7}");
    let v7: serde_json::Value = serde_json::from_str(&out7).unwrap();
    assert_eq!(v7["all_passed"], true);
    assert!(!v7["tests"].as_array().unwrap().is_empty());

    let p08 = cookbooks_dir().join("08_authoritative_multiplayer.strata");
    let (fmt_code, fmt_msg) = cmd_fmt(&p08, true);
    assert_eq!(fmt_code, EXIT_OK, "08 fmt --check failed: {fmt_msg}");
    let (code8, out8) = cmd_test(&p08, OutputFormat::Json);
    assert_eq!(code8, EXIT_OK, "08 cmd_test failed:\n{out8}");
    let v8: serde_json::Value = serde_json::from_str(&out8).unwrap();
    assert_eq!(v8["all_passed"], true);
    assert!(v8["tests"].as_array().unwrap().len() >= 2);
}

#[test]
fn bug_sw_02a_watch_delta_emits_module_path_and_preserves_spatial_grid() {
    let tmp = TempDir::new().unwrap();
    let src_path = tmp.path().join("arena_delta.strata");
    let s1 = r#"
module game::arena_demo @version(1.2.3);
component Pos2 { xy: vec2 = vec2(0.0, 0.0) }
tag Target2D;
spatial_grid Grid2D(
    cell_size: 4.0_m,
    bounds: vec2(-32.0_m, -32.0_m)..vec2(32.0_m, 32.0_m),
    capacity: 64,
) over Target2D by Pos2.xy;
object Unit { Pos2 { xy: vec2(1.0, 1.0) }, Target2D }
sys sys_a() {
    for e in query(p: &mut Pos2) { e.p.xy += vec2(1.0, 0.0); }
}
sys sys_b() {
    for e in query(p: &mut Pos2) { e.p.xy += vec2(0.0, 1.0); }
}
schedule FixedUpdate {
    seq MainSeq { sys_a, sys_b }
}
"#;
    fs::write(&src_path, s1).unwrap();

    let mut session = WatchSession::new(&src_path, false, None, false).unwrap();
    let r1 = session.rebuild_from_source(s1).expect("cycle 1 succeeds");
    assert!(!r1.schedule_delta_only);

    let s2 = s1.replace(
        "seq MainSeq { sys_a, sys_b }",
        "seq MainSeq { sys_b, sys_a }",
    );
    let r2 = session.rebuild_from_source(&s2).expect("cycle 2 succeeds");
    assert!(
        r2.schedule_delta_only,
        "schedule-only reorder with spatial_grid must stay on delta fast-path: {r2:?}"
    );
    let delta_path = PathBuf::from(r2.schedule_delta_path.as_ref().unwrap());
    let delta: ScheduleDeltaArtifact =
        serde_json::from_slice(&fs::read(&delta_path).unwrap()).unwrap();
    assert_eq!(delta.mod_name, "game::arena_demo");
    assert!(
        delta
            .sets
            .iter()
            .any(|s| s.mounted_systems == vec!["sys_b", "sys_a"]),
        "unexpected delta sets: {:?}",
        delta.sets
    );
}

#[test]
fn gf_08_cmd_check_and_build_reject_verify_mir_violations() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("bad_atomic_loop.strata");
    fs::write(
        &p,
        r#"
module test::gf08 @version(1.0.0);
component Hp { val: i32 = 10 }
sys bad_tx() {
    atomic {
        for e in query(h: &mut Hp) {
            e.h.val -= 1;
        }
    }
}
schedule FixedUpdate { bad_tx }
"#,
    )
    .unwrap();

    let (check_rc, check_out) = cmd_check(&p, OutputFormat::Json);
    assert_eq!(
        check_rc, EXIT_COMPILE_ERROR,
        "cmd_check must reject verify_mir failure: {check_out}"
    );
    assert!(
        check_out.contains("single-slot") || check_out.contains("MIR verification"),
        "expected MIR verification diagnostic in cmd_check output: {check_out}"
    );

    let out_dir = tmp.path().join("build_out");
    let (build_rc, build_out) = cmd_build(
        &p,
        false,
        BuildTarget::Jit,
        Some(&out_dir),
        false,
        false,
        OutputFormat::Json,
    );
    assert_eq!(
        build_rc, EXIT_COMPILE_ERROR,
        "cmd_build must reject verify_mir failure: {build_out}"
    );
}

#[test]
fn nt_12b_version_in_mod_toml_and_signing_flag_validation() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("ver_test.strata");
    fs::write(
        &p,
        r#"
module game::ver_check @version(2.4.7);
component TagVal { x: u32 = 1 }
object Obj { TagVal { x: 1 } }
"#,
    )
    .unwrap();

    let out_dir = tmp.path().join("out_ok");
    let (rc, msg) = cmd_build(
        &p,
        false,
        BuildTarget::Jit,
        Some(&out_dir),
        false,
        false,
        OutputFormat::Json,
    );
    assert_eq!(rc, EXIT_OK, "build failed: {msg}");
    let mod_toml = fs::read_to_string(out_dir.join("mod.toml")).expect("read mod.toml");
    assert!(
        mod_toml.contains("version = \"2.4.7\""),
        "expected module @version(2.4.7) in mod.toml, got:\n{mod_toml}"
    );

    let dummy_key = tmp.path().join("unused.key");
    fs::write(&dummy_key, "unused").unwrap();
    let (rc_k, msg_k) = cmd_build_with_key(
        &p,
        false,
        BuildTarget::Jit,
        Some(&tmp.path().join("out_k")),
        false,
        false,
        Some(&dummy_key),
        false,
        OutputFormat::Json,
    );
    assert_ne!(
        rc_k, EXIT_OK,
        "--key without --sign/--bampack must error: {msg_k}"
    );

    let (rc_e, msg_e) = cmd_build_with_key(
        &p,
        false,
        BuildTarget::Jit,
        Some(&tmp.path().join("out_e")),
        false,
        false,
        None,
        true,
        OutputFormat::Json,
    );
    assert_ne!(
        rc_e, EXIT_OK,
        "--ephemeral-key without --sign/--bampack must error: {msg_e}"
    );
}

#[cfg(feature = "sim-runner")]
#[test]
fn bug_sw_08_sim_test_with_all_schedules_does_not_hijack_update() {
    let tmp = TempDir::new().unwrap();
    let p = tmp.path().join("all_schedules.strata");
    fs::write(
        &p,
        r#"
module test::all_scheds @version(1.0.0);

resource TickState {
    update_ticks: u32 = 0,
    fixed_ticks: u32 = 0,
}

sys on_start() {}
sys on_pre_update() {}
sys on_update(st: &mut res TickState) {
    st.update_ticks += 1_u32;
}
sys on_fixed(st: &mut res TickState) {
    st.fixed_ticks += 1_u32;
}
sys on_post_update() {}
sys on_last() {}

schedule Startup { on_start }
schedule PreUpdate { on_pre_update }
schedule Update { on_update }
schedule FixedUpdate { on_fixed }
schedule PostUpdate { on_post_update }
schedule Last { on_last }

sim_test "all_schedules_no_update_hijack" {
    assert_eq(res<TickState>().update_ticks, 0_u32);
    step_fixed(3);
    assert_eq(res<TickState>().fixed_ticks, 3_u32);
    assert_eq(res<TickState>().update_ticks, 0_u32);
}
"#,
    )
    .unwrap();

    let (rc, out) = cmd_test(&p, OutputFormat::Json);
    assert_eq!(rc, EXIT_OK, "all-schedules sim_test failed:\n{out}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["all_passed"], true);
}
