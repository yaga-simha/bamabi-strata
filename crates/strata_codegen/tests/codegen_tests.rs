mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use strata_codegen::{
    BevyNativeOptions, RustGuestOptions, TargetKind, emit_bevy_native, emit_c99, emit_rust_guest,
    emit_rust_guest_with,
};
use strata_mir::lower_to_mir;
use strata_sema::analyze_source;
use tempfile::TempDir;

static GENERATED_CARGO_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

fn find_c99_compiler() -> &'static str {
    for cc in ["clang", "gcc", "cc"] {
        if let Ok(out) = Command::new(cc).arg("--version").output()
            && out.status.success()
        {
            return cc;
        }
    }
    "cc"
}

#[test]
fn all_six_cookbooks_emit_strict_iso_c99_and_safe_rust_and_bevy_native() {
    let dir = cookbooks_dir();
    let tmp = TempDir::new().expect("tempdir");
    let cc = find_c99_compiler();

    for name in COOKBOOKS {
        let src = fs::read_to_string(dir.join(name))
            .unwrap_or_else(|e| panic!("failed to read {name}: {e}"));
        let analyzed = analyze_source(*name, &src);
        assert!(
            analyzed.ok(),
            "{name} semantic errors: {:?}",
            analyzed.diagnostics
        );
        let mir = lower_to_mir(&analyzed);

        // 1. ISO C99 backend + strict `-std=c99 -Wall -Wextra -Wpedantic -Werror` check
        let c_art = emit_c99(&mir).expect("emit_c99");
        assert_eq!(c_art.target, TargetKind::C99);
        assert_eq!(c_art.files.len(), 2);

        let sub = tmp.path().join(name.trim_end_matches(".strata"));
        fs::create_dir_all(&sub).unwrap();
        let mut c_src_path = PathBuf::new();
        for f in &c_art.files {
            let p = sub.join(&f.path);
            fs::write(&p, &f.content).unwrap();
            if f.path.ends_with(".c") {
                c_src_path = p;
            }
        }
        let output = Command::new(cc)
            .args([
                "-std=c99",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fsyntax-only",
            ])
            .arg("-I")
            .arg(&sub)
            .arg(&c_src_path)
            .output()
            .expect("invoke C compiler");
        assert!(
            output.status.success(),
            "C99 check failed for {name}:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        // 2. Safe Rust Guest backend
        let rg = emit_rust_guest(&mir).expect("emit_rust_guest");
        assert_eq!(rg.target, TargetKind::RustGuest);
        let rg_lib = rg
            .files
            .iter()
            .find(|f| f.path == "src/lib.rs")
            .expect("src/lib.rs");
        assert!(rg_lib.content.contains("#![forbid(unsafe_code)]"));
        assert!(
            rg_lib
                .content
                .contains("export_mod!(plugin: StrataGuestMod);")
        );

        // 3. Tier 3 Static Bevy Native backend
        let bn = emit_bevy_native(
            &mir,
            &BevyNativeOptions {
                crate_name: format!("native_{}", name.trim_end_matches(".strata")),
                native_rt_path: None,
                static_console: false,
            },
        )
        .expect("emit_bevy_native");
        assert_eq!(bn.target, TargetKind::BevyNative);
        let bn_lib = bn
            .files
            .iter()
            .find(|f| f.path == "src/lib.rs")
            .expect("src/lib.rs");
        assert!(bn_lib.content.contains("#![forbid(unsafe_code)]"));
        assert!(
            bn_lib
                .content
                .contains("impl Plugin for StrataNativePlugin")
        );
    }
}

#[test]
fn deterministic_physics_kernel_lowers_to_c99_rust_and_native() {
    let src = r#"
module sim::parity_test @version(1.0.0);

resource SimParam { dt: f32 = 0.016, damping: f32 = 0.99 }
component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component Vel { vx: f32 = 0.0, vy: f32 = 0.0 }
component Heat @summary_tick { temp: f32 = 0.0, hot: bool = false }

sys step_motion(p: &res SimParam) {
    uniform let dt = p.dt;
    for e in query(pos: &mut Pos, vel: &Vel, heat: &mut? Heat) {
        e.pos.x += e.vel.vx * dt;
        e.pos.y += e.vel.vy * dt;
        if e.pos.y > 10.0 {
            e.heat.temp += 1.5;
            e.heat.hot = true;
        }
    }
}

schedule FixedUpdate { step_motion }
"#;
    let analyzed = analyze_source("parity_test.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let c_art = emit_c99(&mir).unwrap();
    let c_src = &c_art.files[1].content;
    assert!(c_src.contains("iter_column_mutable_untracked"));
    assert!(c_src.contains("iter_mark_changed_range"));

    // Cross-target schema/UUID/fingerprint parity check across C99, RustGuest, and BevyNative.
    let rg_src = &emit_rust_guest(&mir).unwrap().files[1].content;
    let bn_src = &emit_bevy_native(&mir, &BevyNativeOptions::default())
        .unwrap()
        .files[1]
        .content;
    for layout in &mir.layouts {
        let fp_hex = format!("0x{:016X}", layout.schema_fingerprint);
        assert!(c_src.contains(&format!("{fp_hex}ull")));
        assert!(
            rg_src.contains(&fp_hex) || rg_src.contains(&layout.schema_fingerprint.to_string())
        );
        assert!(
            bn_src.contains(&fp_hex) || bn_src.contains(&layout.schema_fingerprint.to_string())
        );
    }

    let tmp = TempDir::new().unwrap();
    for f in &c_art.files {
        fs::write(tmp.path().join(&f.path), &f.content).unwrap();
    }
    let cc = find_c99_compiler();
    let out = Command::new(cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fsyntax-only",
        ])
        .arg("-I")
        .arg(tmp.path())
        .arg(tmp.path().join("parity_test.c"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn par_1024_kernel_lowers_to_c99_rust_guest_and_bevy_native_par() {
    let src = r#"
module bench::sim @version(1.0.0);

component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component Vel { vx: f32 = 0.0, vy: f32 = 0.0 }

@par(chunk = 1024)
sys step_par() {
    uniform let dt = 0.016;
    uniform let damp = 0.995;
    for e in query(pos: &mut Pos, vel: &mut Vel) {
        e.vel.vx *= damp;
        e.vel.vy -= 9.81 * dt;
        e.pos.x += e.vel.vx * dt;
        e.pos.y += e.vel.vy * dt;
        if e.pos.y < 0.0 {
            e.pos.y = 0.0;
            e.vel.vy = -e.vel.vy * 0.8;
        }
    }
}

schedule FixedUpdate { step_par }
"#;
    let analyzed = analyze_source("par_1024.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let c_art = emit_c99(&mir).expect("emit_c99");
    let c_src = &c_art.files[1].content;
    assert!(c_src.contains("static BamResult strata_par_step_par_"));
    assert!(c_src.contains("state->api->par_for_each_chunk("));
    assert!(c_src.contains("BAM_RESTRICT col_"));

    let rg_art = emit_rust_guest(&mir).expect("emit_rust_guest");
    let rg_src = &rg_art.files[1].content;
    assert!(rg_src.contains("query_typed::<"));
    assert!(rg_src.contains(".par_for_each("));

    let bn_art = emit_bevy_native(&mir, &BevyNativeOptions::default()).expect("emit_bevy_native");
    let bn_src = &bn_art.files[1].content;
    assert!(
        bn_src.contains("strata_contiguous_par_iter_mut"),
        "BevyNative @par(chunk = 1024) must emit strata_contiguous_par_iter_mut"
    );
}

fn write_codegen_test_patch_config(ws_root: &Path, crate_dir: &Path) {
    common::write_patch_config(ws_root, crate_dir, false);
}

#[test]
fn iteration2_par_reduce_det_break_f64_u32_and_arrays_compile_c99_and_rust_guest() {
    let src = r#"
module test::iter2_regressions @version(1.0.0);

component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component F64Val { v: f64 = 1.0 }
component Flags { mask: u32 = 0, out_v: u32 = 0 }
component RichArr { flags: [bool; 4] = [false, false, false, false] }
resource SimOut { total: f32 = 0.0 }

fn leaf_res_write(out: &mut res SimOut) -> u32 {
    out.total = 1.0;
    return 1;
}

fn mid_res_write(out: &mut res SimOut) -> u32 {
    return leaf_res_write(out);
}

@par(read_only, chunk = 512)
sys par_reduce_ro(out: &mut res SimOut) {
    let s = for e in query(p: &Pos) reduce (sum: sum(0.0, e.p.x));
    out.total = s;
}

@par(chunk = 256)
sys par_sel_reduce(out: &mut res SimOut) {
    let s = for e in query(p: &mut? Pos) reduce (sum: sum(0.0, e.p.x));
    out.total = s;
}

@par(read_only, deterministic_order, chunk = 512)
sys par_det_acc(out: &mut res SimOut) {
    let mut acc = 0.0;
    for e in query(p: &Pos) {
        acc += e.p.x;
    }
    out.total = acc;
}

@par(chunk = 1024)
sys par_early_ret() {
    for e in query(p: &mut Pos) {
        if e.p.x >= 500.0 {
            return;
        }
        e.p.y += 1.0;
    }
}

@par(chunk = 1024)
sys par_break() {
    for e in query(p: &mut Pos) {
        if e.p.x >= 10.0 {
            break;
        }
        e.p.x += 100.0;
    }
}

@par(chunk = 1024)
sys par_transitive_res_write(out: &mut res SimOut) {
    for e in query(p: &mut Pos) {
        if e.p.x > 0.0 {
            let _ = mid_res_write(out);
        }
    }
}

sys f64_intrinsics() {
    for e in query(f: &mut F64Val) {
        e.f.v = sqrt(e.f.v) + floor(e.f.v) + min(e.f.v, 2.0);
    }
}

sys u32_unsigned() {
    for e in query(f: &mut Flags) {
        if e.f.mask > 1 {
            e.f.out_v = e.f.mask >> 1;
        }
    }
}

sys bool_array_field() {
    for e in query(r: &mut RichArr) {
        if !e.r.flags[0] {
            e.r.flags[0] = true;
        }
    }
}

schedule FixedUpdate {
    par_reduce_ro,
    par_sel_reduce,
    par_det_acc,
    par_early_ret,
    par_break,
    par_transitive_res_write,
    f64_intrinsics,
    u32_unsigned,
    bool_array_field
}
"#;
    let analyzed = analyze_source("iter2_regressions.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    // 1. Strict ISO C99 compile check
    let c_art = emit_c99(&mir).expect("emit_c99");
    let c_src = &c_art.files[1].content;
    assert!(!c_src.contains("static BamResult strata_par_par_break_"));
    assert!(!c_src.contains("static BamResult strata_par_par_transitive_res_write_"));
    assert!(!c_src.contains("static BamResult strata_par_par_det_acc_"));

    let tmp = TempDir::new().expect("tempdir");
    let c_dir = tmp.path().join("c99");
    fs::create_dir_all(&c_dir).unwrap();
    for f in &c_art.files {
        fs::write(c_dir.join(&f.path), &f.content).unwrap();
    }
    let cc = find_c99_compiler();
    let c_out = Command::new(cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fsyntax-only",
        ])
        .arg("-I")
        .arg(&c_dir)
        .arg(c_dir.join("iter2_regressions.c"))
        .output()
        .expect("invoke C99 compiler");
    assert!(
        c_out.status.success(),
        "C99 check failed:\n{}",
        String::from_utf8_lossy(&c_out.stderr)
    );

    // 2. Real `cargo check` compilation of emitted RustGuest crate
    let rg_art = emit_rust_guest_with(
        &mir,
        &RustGuestOptions {
            crate_name: "guest_iter2_regressions_test".to_owned(),
        },
    )
    .expect("emit_rust_guest");
    let rg_dir = tmp.path().join("rg");
    for f in &rg_art.files {
        let p = rg_dir.join(&f.path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, &f.content).unwrap();
    }
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    write_codegen_test_patch_config(&ws_root, &rg_dir);
    let target_dir = ws_root.join("target").join("strata_generated_cache");
    let rg_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        common::sanitized_cargo_cmd()
            .current_dir(&rg_dir)
            .arg("check")
            .args(common::cargo_offline_flag())
            .arg("--manifest-path")
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .expect("invoke cargo check on generated RustGuest crate")
    };
    assert!(
        rg_out.status.success(),
        "RustGuest cargo check failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&rg_out.stdout),
        String::from_utf8_lossy(&rg_out.stderr)
    );
}

#[test]
fn iteration3_edge_cases_compile_c99_and_rust_guest() {
    let src = r#"
module probe::iter3 @version(1.0.0);

component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component OutBox { total: f32 = 0.0 }
@sparse component SP { v: f32 = 0.0 }
component F64Val { v: f64 = 2.0 }
component WithBits { mask: BitSet<64> = bits(0) }
component RichArr { flags: [bool; 4] = [false, false, false, false] }
tag ActiveTag;
resource SimOut { s1: f32 = 0.0, s2: f32 = 0.0 }

@par(chunk = 256)
sys par_sel_reduce_ro(out: &mut res SimOut) {
    let s = for e in query(p: &mut? Pos) reduce (sum: sum(0.0, e.p.x));
    out.s1 = s;
}

@par(read_only, chunk = 512)
sys par_ro_outbox() {
    let s = for e in query(p: &Pos) reduce (sum: sum(0.0, e.p.x));
    for o in query(ob: &mut OutBox) {
        o.ob.total = s;
    }
}

@par(read_only, chunk = 512)
sys sparse_reduce(out: &mut res SimOut) {
    let s = for e in query(sp: &SP) reduce (sum: sum(0.0, e.sp.v));
    out.s2 = s;
}

sys f64_math() {
    for e in query(f: &mut F64Val) {
        e.f.v = sqrt(e.f.v) + floor(e.f.v) + min(e.f.v, 2.0);
    }
}

sys bitset_tag_and_arr() {
    for e in query(p: &mut Pos).with<ActiveTag>() {
        e.p.x += 1.0;
    }
    for e in query(b: &mut WithBits) {
        b;
    }
    for e in query(r: &mut RichArr) {
        e.r.flags = [true, true, false, false];
    }
}

schedule FixedUpdate {
    par_sel_reduce_ro,
    par_ro_outbox,
    sparse_reduce,
    f64_math,
    bitset_tag_and_arr
}
"#;
    let analyzed = analyze_source("iter3_edge_cases.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let c_art = emit_c99(&mir).expect("emit_c99");
    let c_src = &c_art.files[1].content;
    assert!(c_src.contains("iter_column_rows_readonly("));
    assert!(c_src.contains("sqrt((double)"));
    assert!(c_src.contains("floor((double)"));
    assert!(c_src.contains("memset(out.mask, 0, sizeof(out.mask));"));

    let tmp = TempDir::new().expect("tempdir");
    let c_dir = tmp.path().join("c99");
    fs::create_dir_all(&c_dir).unwrap();
    for f in &c_art.files {
        fs::write(c_dir.join(&f.path), &f.content).unwrap();
    }
    let cc = find_c99_compiler();
    let c_file = c_art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .expect("c source file");
    let c_out = Command::new(cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fsyntax-only",
        ])
        .arg("-I")
        .arg(&c_dir)
        .arg(c_dir.join(&c_file.path))
        .output()
        .expect("invoke C99 compiler");
    assert!(
        c_out.status.success(),
        "C99 check failed:\n{}",
        String::from_utf8_lossy(&c_out.stderr)
    );

    let rg_art = emit_rust_guest_with(
        &mir,
        &RustGuestOptions {
            crate_name: "guest_iter3_edge_cases_test".to_owned(),
        },
    )
    .expect("emit_rust_guest");
    let rg_dir = tmp.path().join("rg");
    for f in &rg_art.files {
        let p = rg_dir.join(&f.path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, &f.content).unwrap();
    }
    let rg_lib = &rg_art.files[1].content;
    assert!(rg_lib.contains("\"probe::iter3::ActiveTag\""));
    assert!(rg_lib.contains("if let StrataVal::Arr(_items) = val"));

    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    write_codegen_test_patch_config(&ws_root, &rg_dir);
    let target_dir = ws_root.join("target").join("strata_generated_cache");
    let rg_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        common::sanitized_cargo_cmd()
            .current_dir(&rg_dir)
            .arg("check")
            .args(common::cargo_offline_flag())
            .arg("--manifest-path")
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .expect("invoke cargo check on generated RustGuest crate")
    };
    assert!(
        rg_out.status.success(),
        "RustGuest cargo check failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&rg_out.stdout),
        String::from_utf8_lossy(&rg_out.stderr)
    );
}

#[test]
fn phase2b_end_to_end_c99_rust_guest_and_live_bevy_native_execution() {
    let src = r#"
module test::phase2b_e2e @version(1.0.0);

component Pos3D { xyz: vec3 = vec3(0.0, 0.0, 0.0) }
component Faction { team: u32 = 0 }
component Shield @summary_tick { hp: f32 = 10.0, allow_tx: bool = false }
component OptShield @summary_tick { bonus: f32 = 0.0 }
component ArrBox {
    vals: [fix64; 3] = [1.0, 2.0, 3.0],
    iv: ivec2 = ivec2(0, 0),
    nested: [[bool; 2]; 2] = [[true, false], [false, true]],
}
component DefaultExtra { keep_v: i32 = 42 }
tag Target3D;

object PartialHero {
    ArrBox { vals: [5.0, 6.0, 7.0], iv: ivec2(-1, -2) },
    DefaultExtra {},
}

spatial_history HistXZ(
    frames:    4,
    cell_size: 4.0_m,
    bounds:    vec2(-20.0_m, -20.0_m)..vec2(20.0_m, 20.0_m),
    capacity:  16,
) over Target3D by Pos3D.xyz;

resource OutProbe { hits: u32 = 0, last_team: u32 = 0 }

sys tick_phase2b(h: &res HistXZ, out: &mut res OutProbe) {
    let mut loc_arr: [fix64; 2] = [1.0, 2.0];
    loc_arr[1] = (loc_arr[0] * 6.0) / 2.0;

    for row in query(a: &mut ArrBox, opt_s: Option<&mut OptShield>) {
        row.a.vals[0] = loc_arr[1];
        row.a.vals[99] = 999.0; // out-of-bounds must be safely ignored
        if row.opt_s.is_some() {
            row.opt_s.unwrap().bonus += 2.0;
        }
    }

    for row in query(sh: &mut? Shield) {
        atomic {
            row.sh.hp += 5.0;
            require_true(row.sh.allow_tx);
        }
    }

    for u in query(fac: Option<&Faction>).with<ArrBox>().up<ChildOf>() {
        let t = u.fac.unwrap().team;
        if t > out.last_team {
            out.last_team = t;
        }
    }

    let mut hit_count: u32 = 0;
    for _hit in h.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(10.0, 0.0, 10.0), 2.5_m) {
        hit_count += 1;
    }
    out.hits = hit_count;
}

schedule FixedUpdate { tick_phase2b }
"#;
    let analyzed = analyze_source("phase2b_e2e.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let tmp = TempDir::new().expect("tempdir");
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");

    // 1. Strict ISO C99 (-std=c99 -Wall -Wextra -Wpedantic -Werror)
    let c_art = emit_c99(&mir).expect("emit_c99");
    let c_dir = tmp.path().join("c99");
    fs::create_dir_all(&c_dir).unwrap();
    for f in &c_art.files {
        fs::write(c_dir.join(&f.path), &f.content).unwrap();
    }
    let cc = find_c99_compiler();
    let c_file = c_art.files.iter().find(|f| f.path.ends_with(".c")).unwrap();
    let c_out = Command::new(cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fsyntax-only",
            "-I",
        ])
        .arg(&c_dir)
        .arg(c_dir.join(&c_file.path))
        .output()
        .expect("invoke C99 compiler");
    assert!(
        c_out.status.success(),
        "C99 check failed:\n{}",
        String::from_utf8_lossy(&c_out.stderr)
    );

    // 2. RustGuest cargo check
    let rg_art = emit_rust_guest_with(
        &mir,
        &RustGuestOptions {
            crate_name: "guest_phase2b_e2e_test".to_owned(),
        },
    )
    .expect("emit_rust_guest");
    let rg_dir = tmp.path().join("rg");
    for f in &rg_art.files {
        let p = rg_dir.join(&f.path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, &f.content).unwrap();
    }
    write_codegen_test_patch_config(&ws_root, &rg_dir);
    let target_dir = ws_root.join("target").join("strata_generated_cache");
    let rg_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        common::sanitized_cargo_cmd()
            .current_dir(&rg_dir)
            .arg("check")
            .args(common::cargo_offline_flag())
            .arg("--manifest-path")
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .expect("cargo check RustGuest")
    };
    assert!(
        rg_out.status.success(),
        "RustGuest check failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&rg_out.stdout),
        String::from_utf8_lossy(&rg_out.stderr)
    );

    // 3. BevyNative live execution (`cargo test --offline`)
    let bn_art = emit_bevy_native(
        &mir,
        &BevyNativeOptions {
            crate_name: "native_phase2b_e2e_test".to_owned(),
            native_rt_path: Some(
                fs::canonicalize(ws_root.join("crates").join("bamabi_native_rt"))
                    .expect("canonicalize bamabi_native_rt")
                    .display()
                    .to_string(),
            ),
            static_console: false,
        },
    )
    .expect("emit_bevy_native");
    let bn_dir = tmp.path().join("bn");
    for f in &bn_art.files {
        let p = bn_dir.join(&f.path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut content = f.content.clone();
        if f.path == "src/lib.rs" {
            content.push_str(
                r#"
#[cfg(test)]
mod phase2b_live_tests {
    use super::*;
    use bevy_ecs::hierarchy::ChildOf;

    #[test]
    fn live_bevy_native_phase2b_semantics() {
        let mut app = App::new();
        app.add_plugins(StrataNativePlugin);

        // Run startup so PartialHero named object is spawned
        app.update();
        let named = app.world().resource::<StrataNamedObjects>();
        let hero = named.get("PartialHero").expect("PartialHero spawned");
        let hero_arr = app.world().get::<StrataArrBox_4>(hero).expect("ArrBox on hero");
        let hero_extra = app.world().get::<StrataDefaultExtra_5>(hero).expect("NB-3 DefaultExtra on hero");
        assert_eq!(hero_arr.iv, [-1i32, -2i32], "NB-1 negative ivec2 preserved");
        assert_eq!(hero_extra.keep_v, 42, "NB-3 un-overridden component preserved");

        // Parent holds Faction(77); child holds ArrBox + OptShield(bonus: 1.0) + Shield(allow_tx: false) -> rollback!
        let parent = app.world_mut().spawn((StrataFaction_1 { team: 77 },)).id();
        let child_rb = app.world_mut().spawn((
            ChildOf(parent),
            StrataArrBox_4::default(),
            StrataOptShield_3 { bonus: 1.0 },
            StrataShield_2 { hp: 20.0, allow_tx: FfiBool::FALSE, ..Default::default() },
        )).id();

        // Spatial target at (5, 0, 5) on 3D XZ grid
        let sp_tgt = app.world_mut().spawn((
            StrataPos3D_0 { xyz: [5.0, 0.0, 5.0] },
            StrataTag_Target3D_0,
        )).id();
        let _far_tgt = app.world_mut().spawn((
            StrataPos3D_0 { xyz: [-15.0, 0.0, -15.0] },
            StrataTag_Target3D_0,
        )).id();

        // Run FixedUpdate schedule: HistXZ rebuilds CSR, then tick_phase2b runs
        app.world_mut().run_schedule(FixedUpdate);

        // Verify Spatial CSR hit
        let out = app.world().resource::<StrataOutProbe_7>();
        assert_eq!(out.hits, 1, "expected 1 spatial CSR 3D XZ segment hit, got {}", out.hits);
        assert_eq!(out.last_team, 77, "IterUpCascade must find parent Faction(77)");

        // Verify ArrayStore wrote 3.0_f64 to vals[0] without panicking on vals[99]
        let child_arr = app.world().get::<StrataArrBox_4>(child_rb).unwrap();
        assert_eq!(child_arr.vals[0], 3i64 << 32, "ArrayStore must write Q32.32 3.0");

        // Verify OptionalWrite updated OptShield.bonus
        assert_eq!(app.world().get::<StrataOptShield_3>(child_rb).unwrap().bonus, 3.0);

        // Verify atomic rollback restored Shield.hp to 20.0 AND did NOT mark Shield changed!
        // First clear spawn trackers on a separate warm-up check: instead inspect after clearing trackers!
        app.world_mut().clear_trackers();
        app.world_mut().run_schedule(FixedUpdate);
        let er_rb = app.world().entity(child_rb);
        let sh_ref = er_rb.get_ref::<StrataShield_2>().unwrap();
        assert_eq!(sh_ref.hp, 20.0, "atomic rollback must restore hp");
        assert!(!sh_ref.is_changed(), "rolled-back SelectiveMutSlice must not mark Shield changed");

        // Advance a tick, flip allow_tx = true -> atomic commits hp += 5.0 AND marks changed!
        app.world_mut().clear_trackers();
        app.world_mut().get_mut::<StrataShield_2>(child_rb).unwrap().allow_tx = FfiBool::TRUE;
        app.world_mut().clear_trackers();
        app.world_mut().run_schedule(FixedUpdate);
        let er_commit = app.world().entity(child_rb);
        let sh_after = er_commit.get_ref::<StrataShield_2>().unwrap();
        assert_eq!(sh_after.hp, 25.0, "atomic commit must persist hp = 25.0");
        assert!(sh_after.is_changed(), "committed Shield must be marked changed");
        let _ = sp_tgt;
    }
}
"#,
            );
        }
        fs::write(p, content).unwrap();
    }
    common::write_patch_config(&ws_root, &bn_dir, true);
    let bn_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        common::sanitized_cargo_cmd()
            .current_dir(&bn_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .arg("--manifest-path")
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .expect("cargo test BevyNative")
    };
    assert!(
        bn_out.status.success(),
        "BevyNative cargo test failed:\nstdout:\n{}\nstderr:\n{}\n=== tick_phase2b ===\n{}",
        String::from_utf8_lossy(&bn_out.stdout),
        String::from_utf8_lossy(&bn_out.stderr),
        bn_art.files[1]
            .content
            .split("fn strata_sys_tick_phase2b(")
            .nth(1)
            .and_then(|s| s.split("\nfn ").next())
            .unwrap_or("")
    );
}

#[test]
fn bevy_native_live_seq_with_spatial_grid_and_spatial_history_has_no_schedule_cycle() {
    let src = r#"
module test::bn_spatial_seq_live @version(1.0.0);

component Pos2 { xy: vec2 = vec2(0.0, 0.0) }
component Pos3 { xyz: vec3 = vec3(0.0, 0.0, 0.0) }
resource Probe { d_hits: u32 = 0, h_hits: u32 = 0 }

spatial_grid Grid2D(
    cell_size: 4.0_m,
    bounds: vec2(-16.0_m, -16.0_m)..vec2(16.0_m, 16.0_m),
    capacity: 16,
) over Pos2 by Pos2.xy;

spatial_history Hist3D(
    frames: 4,
    cell_size: 4.0_m,
    bounds: vec2(-16.0_m, -16.0_m)..vec2(16.0_m, 16.0_m),
    capacity: 16,
) over Pos3 by Pos3.xyz;

sys pre_move() {
    for row in query(p: &mut Pos2) {
        row.p.xy.x += 1.0;
    }
}

sys scan_grid(g: &res Grid2D, out: &mut res Probe) {
    let mut c: u32 = 0;
    for _hit in g.query_disc(vec2(1.0, 0.0), 0.5_m) {
        c += 1;
    }
    out.d_hits = c;
}

sys scan_hist(h: &res Hist3D, out: &mut res Probe) {
    let mut c: u32 = 0;
    for _hit in h.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(4.0, 0.0, 4.0), 1.5_m) {
        c += 1;
    }
    out.h_hits = c;
}

sys post_step() {
    for row in query(p: &mut Pos3) {
        row.p.xyz.z += 0.5;
    }
}

schedule FixedUpdate {
    seq SpatialSeq { pre_move, scan_grid, scan_hist, post_step }
}
"#;
    let analyzed = analyze_source("bn_spatial_seq_live.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let tmp = TempDir::new().expect("tempdir");
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let bn_art = emit_bevy_native(
        &mir,
        &BevyNativeOptions {
            crate_name: "native_spatial_seq_live_test".to_owned(),
            native_rt_path: Some(
                fs::canonicalize(ws_root.join("crates").join("bamabi_native_rt"))
                    .expect("canonicalize bamabi_native_rt")
                    .display()
                    .to_string(),
            ),
            static_console: false,
        },
    )
    .expect("emit_bevy_native");
    let bn_dir = tmp.path().join("bn");
    for f in &bn_art.files {
        let p = bn_dir.join(&f.path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut content = f.content.clone();
        if f.path == "src/lib.rs" {
            content.push_str(
                r#"
#[cfg(test)]
mod spatial_seq_live_tests {
    use super::*;

    #[test]
    fn live_bevy_schedule_runs_multiple_spatial_indices_in_seq_without_cycle() {
        let mut app = App::new();
        app.add_plugins(StrataNativePlugin);
        app.world_mut().spawn((StrataPos2_0 { xy: [0.0, 0.0] },));
        app.world_mut().spawn((StrataPos3_1 { xyz: [2.0, 0.0, 2.0] },));
        app.world_mut().run_schedule(FixedUpdate);
        let probe = app.world().resource::<StrataProbe_2>();
        assert_eq!(probe.d_hits, 1, "pre_move moved Pos2 to (1,0), Grid2D rebuilt after pre_move and hit it");
        assert_eq!(probe.h_hits, 1, "Hist3D rebuilt before scan_hist and hit Pos3 at (2,0,2)");
    }
}
"#,
            );
        }
        fs::write(p, content).unwrap();
    }
    common::write_patch_config(&ws_root, &bn_dir, true);
    let target_dir = ws_root.join("target").join("strata_generated_cache");
    let bn_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        common::sanitized_cargo_cmd()
            .current_dir(&bn_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .arg("--manifest-path")
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .expect("cargo test BevyNative spatial_seq_live")
    };
    assert!(
        bn_out.status.success(),
        "BevyNative spatial_seq_live test failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&bn_out.stdout),
        String::from_utf8_lossy(&bn_out.stderr),
    );
}

#[test]
fn bevy_native_live_named_object_array_overrides_and_nested_arrays() {
    let src = r#"
module test::bn_obj_arrays_live @version(1.0.0);

struct Pair { a: i32 = 1, b: f32 = 2.0 }

component ArrayBox {
    f_arr: [f32; 3] = [1.0, 2.0, 3.0],
    fx_arr: [fix64; 3] = [1.0, 2.0, 3.0],
    fx_mix: [fix64; 3] = [0.0, 0.0, 0.0],
    i_to_f: [f32; 3] = [0.0, 0.0, 0.0],
    mat: [[f32; 2]; 2] = [[0.0, 0.0], [0.0, 0.0]],
    flags: [bool; 3] = [false, false, false],
    pairs: [Pair; 2] = [Pair { a: 1, b: 2.0 }, Pair { a: 1, b: 2.0 }],
}

component ExtraDefault {
    keep: i32 = 42,
}

object ArrHero {
    ArrayBox {
        f_arr: [5.0, 6.0, 7.0],
        fx_arr: [5.0, 6.0, 7.0],
        fx_mix: [1, -2.5, 3],
        i_to_f: [5, 6, 7],
        mat: [[1, 2.5], [3.5, -4]],
        flags: [true, false, true],
        pairs: [Pair { a: 7, b: -1.5 }, Pair { a: 9, b: 4.25 }],
    },
    ExtraDefault {},
}
"#;
    let analyzed = analyze_source("bn_obj_arrays_live.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let tmp = TempDir::new().expect("tempdir");
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let bn_art = emit_bevy_native(
        &mir,
        &BevyNativeOptions {
            crate_name: "native_obj_arrays_live_test".to_owned(),
            native_rt_path: Some(
                fs::canonicalize(ws_root.join("crates").join("bamabi_native_rt"))
                    .expect("canonicalize bamabi_native_rt")
                    .display()
                    .to_string(),
            ),
            static_console: false,
        },
    )
    .expect("emit_bevy_native");
    let bn_dir = tmp.path().join("bn");
    for f in &bn_art.files {
        let p = bn_dir.join(&f.path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut content = f.content.clone();
        if f.path == "src/lib.rs" {
            content.push_str(
                r#"
#[cfg(test)]
mod obj_arrays_live_tests {
    use super::*;

    #[test]
    fn live_bevy_named_object_initializes_array_overrides_exactly() {
        let mut app = App::new();
        app.add_plugins(StrataNativePlugin);
        app.world_mut().run_schedule(Startup);
        let named = app.world().resource::<StrataNamedObjects>();
        let ent = named.get("ArrHero").expect("ArrHero spawned");
        let ab = app.world().get::<StrataArrayBox_1>(ent).expect("ArrayBox");
        let ed = app.world().get::<StrataExtraDefault_2>(ent).expect("ExtraDefault");
        assert_eq!(ab.f_arr, [5.0_f32, 6.0_f32, 7.0_f32]);
        assert_eq!(ab.fx_arr, [5i64 << 32, 6i64 << 32, 7i64 << 32]);
        assert_eq!(ab.fx_mix, [1i64 << 32, -(5i64 << 31), 3i64 << 32]);
        assert_eq!(ab.i_to_f, [5.0_f32, 6.0_f32, 7.0_f32]);
        assert_eq!(ab.mat, [[1.0_f32, 2.5_f32], [3.5_f32, -4.0_f32]]);
        assert_eq!(ab.flags, [FfiBool::TRUE, FfiBool::FALSE, FfiBool::TRUE]);
        let p0 = StrataPair_0::strata_from_u32_words(&ab.pairs[0]);
        let p1 = StrataPair_0::strata_from_u32_words(&ab.pairs[1]);
        assert_eq!(p0, StrataPair_0 { a: 7, b: -1.5_f32 });
        assert_eq!(p1, StrataPair_0 { a: 9, b: 4.25_f32 });
        assert_eq!(ed.keep, 42);
    }
}
"#,
            );
        }
        fs::write(p, content).unwrap();
    }
    common::write_patch_config(&ws_root, &bn_dir, true);
    let target_dir = ws_root.join("target").join("strata_generated_cache");
    let bn_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        common::sanitized_cargo_cmd()
            .current_dir(&bn_dir)
            .arg("test")
            .args(common::cargo_offline_flag())
            .arg("--manifest-path")
            .arg(bn_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .expect("cargo test BevyNative obj_arrays_live")
    };
    assert!(
        bn_out.status.success(),
        "BevyNative obj_arrays_live test failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&bn_out.stdout),
        String::from_utf8_lossy(&bn_out.stderr),
    );
}

#[test]
fn param_set_task_compiles_and_executes_c99_and_rust_guest() {
    let src = r#"
module test::pset_e2e @version(1.0.0);

component Actor { alive: bool = true, hp: f32 = 100.0 }
tag TagA;

task ProcessOrder(target: Ref<Actor>)
    on (a: &Actor)
{
    if a.alive {
        if let Some(t) = query_one(tgt: &mut Actor).on(target) {
            if t.tgt.alive {
                t.tgt.hp -= 10.0;
            }
        }
    }
    yield_tick;
}

sys setup() {
    let tgt = spawn { Actor { alive: true, hp: 100.0 }, TagA {} };
    let runner = spawn { Actor { alive: true, hp: 50.0 } };
    insert(runner, ProcessOrder::start(tgt));
}

sys disjoint_steps() {
    for r in query(a: &mut Actor).with<TagA>() {
        r.a.hp += 1.0;
    }
    for r in query(a: &mut Actor).without<TagA>() {
        r.a.hp += 2.0;
    }
}

schedule Startup { setup }
schedule FixedUpdate {
    seq Step { ProcessOrder, disjoint_steps }
}
"#;
    let analyzed = analyze_source("pset_e2e.strata", src);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);

    let tmp = TempDir::new().expect("tempdir");
    let ws_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");

    // 1. Strict ISO C99 compile + shared lib link
    let c_art = emit_c99(&mir).expect("emit_c99");
    let c_dir = tmp.path().join("c99");
    fs::create_dir_all(&c_dir).unwrap();
    for f in &c_art.files {
        fs::write(c_dir.join(&f.path), &f.content).unwrap();
    }
    let c_src = &c_art.files[1].content;
    assert!(c_src.contains("BAM_QUERY_FLAG_PARAM_SET"));
    assert!(c_src.contains(".param_set_group = 1u;"));
    let cc = find_c99_compiler();
    let c_file = c_art.files.iter().find(|f| f.path.ends_with(".c")).unwrap();
    let c_dylib = c_dir.join(format!(
        "{}pset_e2e_c99{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    let mut cc_cmd = Command::new(cc);
    cc_cmd.args([
        "-std=c99",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Werror",
        "-shared",
    ]);
    #[cfg(not(target_os = "windows"))]
    cc_cmd.arg("-fPIC");
    let c_out = cc_cmd
        .arg("-I")
        .arg(&c_dir)
        .arg(c_dir.join(&c_file.path))
        .arg("-lm")
        .arg("-o")
        .arg(&c_dylib)
        .output()
        .expect("invoke C99 compiler");
    assert!(
        c_out.status.success(),
        "C99 param_set shared build failed:\n{}",
        String::from_utf8_lossy(&c_out.stderr)
    );

    // 2. RustGuest compile + cdylib build
    let crate_name = "guest_pset_e2e_test";
    let rg_art = emit_rust_guest_with(
        &mir,
        &RustGuestOptions {
            crate_name: crate_name.to_owned(),
        },
    )
    .expect("emit_rust_guest");
    let rg_dir = tmp.path().join("rg");
    for f in &rg_art.files {
        let p = rg_dir.join(&f.path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, &f.content).unwrap();
    }
    let rg_lib = &rg_art.files[1].content;
    assert!(rg_lib.contains(".param_set(|ps| {"));
    assert!(rg_lib.contains("ps.query(|mut q| {"));
    write_codegen_test_patch_config(&ws_root, &rg_dir);
    let target_dir = ws_root.join("target").join("strata_generated_cache");
    let rg_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        common::sanitized_cargo_cmd()
            .current_dir(&rg_dir)
            .arg("build")
            .args(common::cargo_offline_flag())
            .arg("--manifest-path")
            .arg(rg_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .expect("cargo build RustGuest param_set")
    };
    assert!(
        rg_out.status.success(),
        "RustGuest param_set cargo build failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&rg_out.stdout),
        String::from_utf8_lossy(&rg_out.stderr)
    );
    let rg_dylib = target_dir.join("debug").join(format!(
        "{}{crate_name}{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    assert!(
        rg_dylib.is_file(),
        "missing built RustGuest cdylib: {}",
        rg_dylib.display()
    );

    // 3. Live bamabi_host execution for BOTH C99 and RustGuest cdylibs
    let host_dir = tmp.path().join("host_harness");
    fs::create_dir_all(host_dir.join("src")).unwrap();
    let host_toml = "[package]\n\
        name = \"pset_host_harness\"\n\
        version = \"0.3.0\"\n\
        edition = \"2024\"\n\n\
        [dependencies]\n\
        bamabi_host = { version = \"0.3.0\", git = \"https://github.com/yaga-simha/bamabi-core.git\", branch = \"main\" }\n\
        bevy_app = { version = \"0.20.1\", default-features = false, features = [\"std\"] }\n\
        bevy_ecs = { version = \"0.20.1\", default-features = false, features = [\"std\", \"async_executor\"] }\n";
    fs::write(host_dir.join("Cargo.toml"), host_toml).unwrap();
    common::write_patch_config(&ws_root, &host_dir, true);

    let c_dylib_esc = c_dylib.display().to_string().replace('\\', "\\\\");
    let rg_dylib_esc = rg_dylib.display().to_string().replace('\\', "\\\\");
    let main_rs = format!(
        r#"#![forbid(unsafe_code)]
use bamabi_host::prelude::*;
use bamabi_host::{{ModRegistry, read_entity_pod_bytes}};
use bevy_app::{{App, FixedUpdate, Startup}};
use std::path::Path;

fn run_cdylib(path: &Path, label: &str) {{
    let mut app = App::new();
    app.init_schedule(Startup);
    app.init_schedule(FixedUpdate);
    app.add_plugins(AbiModPlugin::with_error_policy(ModErrorPolicy::ReportToBevy));
    app.load_mod_with(path, LoadOptions::default())
        .unwrap_or_else(|e| panic!("{{label}} load_mod_with failed: {{e:?}}"));
    app.world_mut().run_schedule(Startup);
    app.world_mut().run_schedule(FixedUpdate);

    let world = app.world();
    let reg = world.resource::<ModRegistry>();
    let snap = reg.snapshot();
    let actor_entry = snap
        .entries()
        .iter()
        .find(|e| e.name.as_ref() == "test::pset_e2e::Actor")
        .expect("Actor registered");
    let mut hps = Vec::new();
    for arch in world.archetypes().iter() {{
        if !arch.is_empty() && arch.contains(actor_entry.component_id) {{
            for ae in arch.entities() {{
                let bytes = read_entity_pod_bytes(world, ae.id(), actor_entry.handle).unwrap();
                let hp = f32::from_le_bytes(bytes[4..8].try_into().unwrap());
                hps.push(hp);
            }}
        }}
    }}
    hps.sort_by(|a, b| a.total_cmp(b));
    assert_eq!(hps, vec![52.0_f32, 91.0_f32], "{{label}} expected [52.0, 91.0], got {{hps:?}}");
}}

fn main() {{
    run_cdylib(Path::new("{c_dylib_esc}"), "C99");
    run_cdylib(Path::new("{rg_dylib_esc}"), "RustGuest");
}}
"#
    );
    fs::write(host_dir.join("src").join("main.rs"), main_rs).unwrap();
    let host_out = {
        let _cargo_guard = GENERATED_CARGO_MUTEX
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        common::sanitized_cargo_cmd()
            .current_dir(&host_dir)
            .arg("run")
            .args(common::cargo_offline_flag())
            .arg("--manifest-path")
            .arg(host_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .output()
            .expect("run live bamabi_host harness for C99 & RustGuest")
    };
    assert!(
        host_out.status.success(),
        "live bamabi_host param_set execution failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&host_out.stdout),
        String::from_utf8_lossy(&host_out.stderr),
    );
}
