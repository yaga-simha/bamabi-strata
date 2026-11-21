use std::fs;
use std::path::PathBuf;
use std::process::Command;
use strata_codegen::{BevyNativeOptions, TargetKind, emit_bevy_native, emit_c99, emit_rust_guest};
use strata_mir::lower_to_mir;
use strata_sema::analyze_source;
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
