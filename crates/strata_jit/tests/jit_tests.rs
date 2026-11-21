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
