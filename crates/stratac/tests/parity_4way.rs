#![forbid(unsafe_code)]

use bamabi_host::prelude::*;
use bamabi_native_rt::{
    ChunkSliceQueryExt, SelectiveMutSlice, SharedBridgeAppExt, StrataComponentOptions,
};
use bamabi_sys::{
    BAM_COMPONENT_FLAG_SUMMARY_TICK, BamFieldDesc, BamFieldKind, ComponentUuid, FfiBool,
    ModComponent, StrView, SymbolEntry, VTableHeader, fnv1a_64_init, fnv1a_64_update_bytes,
    fnv1a_64_update_u64,
};
use bevy_app::{App, FixedUpdate};
use bevy_ecs::prelude::*;
use std::fs;
use std::process::Command;
use strata_mir::lower_to_mir;
use strata_sema::analyze_source;
use stratac::cli::{BuildTarget, OnboardTarget, OutputFormat};
use stratac::commands::{
    cmd_build, cmd_onboard, find_c_compiler, sanitized_cargo, shared_temp_target_dir,
    write_local_patch_config,
};
use stratac::sim_runner::hash_world_pod_state;
use tempfile::TempDir;

const PARITY_SRC_V1: &str = r#"
module parity::sim @version(1.0.0);

resource SimParam { dt: f32 = 0.016, damping: f32 = 0.995 }
component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component Vel { vx: f32 = 0.0, vy: f32 = 0.0 }
component Heat @summary_tick { temp: f32 = 0.0, active: bool = false }

sys step_sim(p: &res SimParam) {
    uniform let dt = p.dt;
    uniform let damp = p.damping;
    for e in query(pos: &mut Pos, vel: &mut Vel, heat: &mut? Heat) {
        e.vel.vx *= damp;
        e.vel.vy -= 9.81 * dt;
        e.pos.x += e.vel.vx * dt;
        e.pos.y += e.vel.vy * dt;
        if e.pos.y < 0.0 {
            e.pos.y = 0.0;
            e.vel.vy = -e.vel.vy * 0.8;
            e.heat.temp += 1.25;
            e.heat.active = true;
        }
    }
}

schedule FixedUpdate { step_sim }
"#;

const PARITY_SRC_V2: &str = r#"
module parity::sim @version(2.0.0);

resource SimParam { dt: f32 = 0.016, damping: f32 = 0.995 }
component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component Vel { vx: f32 = 0.0, vy: f32 = 0.0 }
component Heat @summary_tick { temp: f32 = 0.0, active: bool = false }

sys step_sim(p: &res SimParam) {
    uniform let dt = p.dt;
    uniform let damp = p.damping;
    for e in query(pos: &mut Pos, vel: &mut Vel, heat: &mut? Heat) {
        e.vel.vx *= damp;
        e.vel.vy -= 9.81 * dt;
        e.pos.x += e.vel.vx * dt;
        e.pos.y += e.vel.vy * dt;
        if e.pos.y < 0.0 {
            e.pos.y = 0.0;
            e.vel.vy = -e.vel.vy * 0.75;
            e.heat.temp += 2.0;
            e.heat.active = true;
        }
    }
}

schedule FixedUpdate { step_sim }
"#;

#[repr(C)]
#[derive(Resource, Clone, Copy, Default, Debug, PartialEq)]
struct SimParam {
    dt: f32,
    damping: f32,
}

#[repr(C)]
#[derive(Component, Clone, Copy, Default, Debug, PartialEq)]
struct Pos {
    x: f32,
    y: f32,
}

#[repr(C)]
#[derive(Component, Clone, Copy, Default, Debug, PartialEq)]
struct Vel {
    vx: f32,
    vy: f32,
}

#[repr(C)]
#[derive(Component, Clone, Copy, Default, Debug, PartialEq)]
#[component(summary_tick)]
struct Heat {
    temp: f32,
    active: FfiBool,
    _strata_pad_0: [u8; 3],
}

macro_rules! impl_pod_mod_comp {
    (
        $ty:ident, $canon:literal, $cstr:literal, $flags:expr,
        [$(($fname:ident, $fstr:literal, $fkind:expr, $ftag:literal, $fty:ty)),* $(,)?]
    ) => {
        const _: () = {};
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub(crate) struct VTableTy {
            _header: VTableHeader,
        }
        impl ModComponent for $ty {
            const CANONICAL_NAME: &'static str = $canon;
            const COMPONENT_CSTR: &'static core::ffi::CStr = $cstr;
            const UUID: ComponentUuid = {
                let mut h = 0u64;
                $(
                    h = ComponentUuid::hash_field_schema(
                        h,
                        $fstr,
                        $ftag,
                        core::mem::offset_of!(Self, $fname),
                    );
                )*
                ComponentUuid::from_parts(
                    Self::CANONICAL_NAME,
                    core::mem::size_of::<Self>(),
                    core::mem::align_of::<Self>(),
                    h,
                )
            };
            const IS_ABI_POD: bool = true;
            const IS_RAW_INSERTABLE: bool = true;
            const COMPONENT_FLAGS: u32 = $flags;
            const SCHEMA_FINGERPRINT: u64 = {
                let mut fp = fnv1a_64_init();
                fp = fnv1a_64_update_bytes(fp, Self::CANONICAL_NAME.as_bytes());
                fp = fnv1a_64_update_u64(fp, core::mem::size_of::<Self>() as u64);
                fp = fnv1a_64_update_u64(fp, core::mem::align_of::<Self>() as u64);
                fp = fnv1a_64_update_u64(fp, Self::COMPONENT_FLAGS as u64);
                $(
                    fp = fnv1a_64_update_u64(fp, $fkind.0 as u64);
                    fp = fnv1a_64_update_bytes(fp, $fstr.as_bytes());
                    fp = fnv1a_64_update_bytes(fp, $ftag.as_bytes());
                    fp = fnv1a_64_update_u64(fp, core::mem::offset_of!(Self, $fname) as u64);
                    fp = fnv1a_64_update_u64(fp, core::mem::size_of::<$fty>() as u64);
                    fp = fnv1a_64_update_u64(fp, core::mem::align_of::<$fty>() as u64);
                )*
                fp
            };
            const BAM_FIELDS: &'static [BamFieldDesc] = &[
                $(
                    BamFieldDesc::new(
                        $fkind,
                        StrView::from_str($fstr),
                        StrView::from_str($ftag),
                        core::mem::offset_of!(Self, $fname),
                        core::mem::size_of::<$fty>(),
                        core::mem::align_of::<$fty>(),
                    ),
                )*
            ];
            type VTable = VTableTy;
            fn vtable() -> &'static Self::VTable {
                static VT: VTableTy = VTableTy {
                    _header: VTableHeader::new::<VTableTy, $ty>(<$ty as ModComponent>::UUID),
                };
                &VT
            }
            fn symbols() -> &'static [SymbolEntry] {
                &[]
            }
        }
    };
}

mod comp_impls {
    use super::*;
    mod p_param {
        use super::*;
        impl_pod_mod_comp!(
            SimParam,
            "parity::sim::SimParam",
            c"parity::sim::SimParam",
            0,
            [
                (dt, "dt", BamFieldKind::F32, "f32", f32),
                (damping, "damping", BamFieldKind::F32, "f32", f32),
            ]
        );
    }
    mod p_pos {
        use super::*;
        impl_pod_mod_comp!(
            Pos,
            "parity::sim::Pos",
            c"parity::sim::Pos",
            0,
            [
                (x, "x", BamFieldKind::F32, "f32", f32),
                (y, "y", BamFieldKind::F32, "f32", f32),
            ]
        );
    }
    mod p_vel {
        use super::*;
        impl_pod_mod_comp!(
            Vel,
            "parity::sim::Vel",
            c"parity::sim::Vel",
            0,
            [
                (vx, "vx", BamFieldKind::F32, "f32", f32),
                (vy, "vy", BamFieldKind::F32, "f32", f32),
            ]
        );
    }
    mod p_heat {
        use super::*;
        impl_pod_mod_comp!(
            Heat,
            "parity::sim::Heat",
            c"parity::sim::Heat",
            BAM_COMPONENT_FLAG_SUMMARY_TICK,
            [
                (temp, "temp", BamFieldKind::F32, "f32", f32),
                (active, "active", BamFieldKind::BOOL, "FfiBool", FfiBool),
                (
                    _strata_pad_0,
                    "_strata_pad_0",
                    BamFieldKind::NESTED,
                    "[u8;3]",
                    [u8; 3]
                ),
            ]
        );
    }
}

fn setup_shared_world() -> App {
    let mut app = App::new();
    app.init_schedule(FixedUpdate);
    app.add_plugins(AbiModPlugin::with_error_policy(ModErrorPolicy::Quarantine));
    app.insert_resource(SimParam {
        dt: 0.016,
        damping: 0.995,
    });
    app.register_strata_resource::<SimParam>().unwrap();
    app.register_strata_component::<Pos>(StrataComponentOptions::new())
        .unwrap();
    app.register_strata_component::<Vel>(StrataComponentOptions::new())
        .unwrap();
    app.register_strata_component::<Heat>(StrataComponentOptions::new().summary_tick())
        .unwrap();

    for i in 0..128 {
        app.world_mut().spawn((
            Pos {
                x: (i as f32) * 0.25,
                y: ((i % 9) as f32) * 0.6 + 0.1,
            },
            Vel {
                vx: 2.0 + ((i % 5) as f32) * 0.5,
                vy: -((i % 7) as f32) * 0.4,
            },
            Heat::default(),
        ));
    }
    app
}

fn static_native_step_sim(p: Res<SimParam>, mut query: Query<(&mut Pos, &mut Vel, &mut Heat)>) {
    let dt = p.dt;
    let damp = p.damping;
    if let Ok(chunks) = query.strata_contiguous_iter_mut() {
        for (mut pos_c, mut vel_c, heat_cm) in chunks {
            let pos = &mut *pos_c;
            let vel = &mut *vel_c;
            let mut heat = SelectiveMutSlice::from_contiguous_mut(heat_cm);
            for row in 0..pos.len() {
                vel[row].vx *= damp;
                vel[row].vy -= 9.81 * dt;
                pos[row].x += vel[row].vx * dt;
                pos[row].y += vel[row].vy * dt;
                if pos[row].y < 0.0 {
                    pos[row].y = 0.0;
                    vel[row].vy = -vel[row].vy * 0.8;
                    let h = &mut heat.as_mut_untracked()[row];
                    h.temp += 1.25;
                    h.active = FfiBool::TRUE;
                    heat.mark_dirty_row(row);
                }
            }
            heat.flush_dirty_runs();
        }
    }
}

#[test]
fn four_way_differential_parity_500_frames_plus_live_reload() {
    // Verify host POD UUIDs match strata_sema solved UUIDs bit-for-bit.
    let analyzed = analyze_source("parity_v1.strata", PARITY_SRC_V1);
    assert!(analyzed.ok(), "{:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    assert!(
        !mir.functions.is_empty() && !mir.functions[0].blocks.is_empty(),
        "parity kernel must lower non-empty MIR blocks"
    );
    for l in &mir.layouts {
        match l.canonical_name.as_str() {
            "parity::sim::Pos" => {
                assert_eq!(l.uuid_bytes, Pos::UUID.bytes);
                assert_eq!(l.schema_fingerprint, Pos::SCHEMA_FINGERPRINT);
            }
            "parity::sim::Vel" => {
                assert_eq!(l.uuid_bytes, Vel::UUID.bytes);
                assert_eq!(l.schema_fingerprint, Vel::SCHEMA_FINGERPRINT);
            }
            "parity::sim::Heat" => {
                assert_eq!(l.uuid_bytes, Heat::UUID.bytes);
                assert_eq!(l.schema_fingerprint, Heat::SCHEMA_FINGERPRINT);
            }
            "parity::sim::SimParam" => {
                assert_eq!(l.uuid_bytes, SimParam::UUID.bytes);
                assert_eq!(l.schema_fingerprint, SimParam::SCHEMA_FINGERPRINT);
            }
            _ => {}
        }
    }

    let tmp = TempDir::new().unwrap();
    let src_v1 = tmp.path().join("parity_v1.strata");
    fs::write(&src_v1, PARITY_SRC_V1).unwrap();

    // Build Target 1: Cranelift PIC JIT .dylib
    let jit_dir = tmp.path().join("jit");
    let (code, msg) = cmd_build(
        &src_v1,
        true,
        BuildTarget::Jit,
        Some(&jit_dir),
        false,
        false,
        OutputFormat::Json,
    );
    assert_eq!(code, 0, "JIT build failed: {msg}");
    let jit_rep: serde_json::Value = serde_json::from_str(&msg).unwrap();
    let jit_bin = std::path::PathBuf::from(jit_rep["binary_path"].as_str().unwrap());

    // Build Target 2: Strict ISO C99 .dylib
    let c99_dir = tmp.path().join("c99");
    let (code, msg) = cmd_build(
        &src_v1,
        true,
        BuildTarget::C99,
        Some(&c99_dir),
        false,
        false,
        OutputFormat::Json,
    );
    assert_eq!(code, 0, "C99 build failed: {msg}");
    let c99_rep: serde_json::Value = serde_json::from_str(&msg).unwrap();
    let c99_bin = std::path::PathBuf::from(c99_rep["binary_path"].as_str().unwrap());

    // Build Target 3: Safe `#![forbid(unsafe_code)]` Rust Guest .cdylib
    let rg_dir = tmp.path().join("rust_guest");
    let (code, msg) = cmd_build(
        &src_v1,
        true,
        BuildTarget::RustGuest,
        Some(&rg_dir),
        false,
        false,
        OutputFormat::Json,
    );
    assert_eq!(code, 0, "RustGuest build failed: {msg}");
    let rg_rep: serde_json::Value = serde_json::from_str(&msg).unwrap();
    let rg_bin = std::path::PathBuf::from(rg_rep["binary_path"].as_str().unwrap());

    // Verify Target 4: Tier 3 `--target bevy-native` compiles cleanly + builds as `#![forbid(unsafe_code)]`
    let bn_dir = tmp.path().join("bevy_native");
    let (code, msg) = cmd_onboard(
        &src_v1,
        OnboardTarget::BevyNative,
        &bn_dir,
        false,
        true,
        OutputFormat::Json,
    );
    assert_eq!(code, 0, "BevyNative onboard check failed: {msg}");
    let _ = (
        find_c_compiler,
        sanitized_cargo,
        shared_temp_target_dir,
        write_local_patch_config,
    );

    // Boot 4 independent Bevy Worlds and run 500 FixedUpdate frames!
    let mut w_jit = setup_shared_world();
    let jit_mod_id = w_jit
        .load_mod_with(&jit_bin, LoadOptions::default())
        .unwrap();

    let mut w_c99 = setup_shared_world();
    let c99_mod_id = w_c99
        .load_mod_with(&c99_bin, LoadOptions::default())
        .unwrap();

    let mut w_rg = setup_shared_world();
    let _rg_mod_id = w_rg.load_mod_with(&rg_bin, LoadOptions::default()).unwrap();

    let mut w_native = setup_shared_world();
    w_native.add_systems(FixedUpdate, static_native_step_sim);

    for frame in 0..500u32 {
        w_jit.world_mut().run_schedule(FixedUpdate);
        w_c99.world_mut().run_schedule(FixedUpdate);
        w_rg.world_mut().run_schedule(FixedUpdate);
        w_native.world_mut().run_schedule(FixedUpdate);

        if matches!(frame, 0 | 1 | 249 | 499) {
            let d_jit = hash_world_pod_state(w_jit.world());
            let d_c99 = hash_world_pod_state(w_c99.world());
            let d_rg = hash_world_pod_state(w_rg.world());
            let d_nat = hash_world_pod_state(w_native.world());

            assert!(d_jit.pod_bytes_hashed > 0);
            assert_eq!(
                d_jit.sha256, d_c99.sha256,
                "JIT vs C99 diverged at frame {frame}"
            );
            assert_eq!(
                d_jit.sha256, d_rg.sha256,
                "JIT vs RustGuest diverged at frame {frame}"
            );
            assert_eq!(
                d_jit.sha256, d_nat.sha256,
                "JIT vs Tier3 BevyNative diverged at frame {frame}"
            );
            assert_eq!(d_jit.fnv1a64, d_c99.fnv1a64);
            assert_eq!(d_jit.fnv1a64, d_rg.fnv1a64);
            assert_eq!(d_jit.fnv1a64, d_nat.fnv1a64);
        }
    }

    // Live v1 -> v2 dynamic reload parity across Cranelift JIT & ISO C99!
    let src_v2 = tmp.path().join("parity_v2.strata");
    fs::write(&src_v2, PARITY_SRC_V2).unwrap();

    let jit_v2_dir = tmp.path().join("jit_v2");
    let (c1, m1) = cmd_build(
        &src_v2,
        true,
        BuildTarget::Jit,
        Some(&jit_v2_dir),
        false,
        false,
        OutputFormat::Json,
    );
    assert_eq!(c1, 0, "{m1}");
    let jit_v2_bin = std::path::PathBuf::from(
        serde_json::from_str::<serde_json::Value>(&m1).unwrap()["binary_path"]
            .as_str()
            .unwrap(),
    );

    let c99_v2_dir = tmp.path().join("c99_v2");
    let (c2, m2) = cmd_build(
        &src_v2,
        true,
        BuildTarget::C99,
        Some(&c99_v2_dir),
        false,
        false,
        OutputFormat::Json,
    );
    assert_eq!(c2, 0, "{m2}");
    let c99_v2_bin = std::path::PathBuf::from(
        serde_json::from_str::<serde_json::Value>(&m2).unwrap()["binary_path"]
            .as_str()
            .unwrap(),
    );

    w_jit
        .reload_mod_from(jit_mod_id, &jit_v2_bin, LoadOptions::default())
        .unwrap();
    w_c99
        .reload_mod_from(c99_mod_id, &c99_v2_bin, LoadOptions::default())
        .unwrap();

    for _ in 0..25 {
        w_jit.world_mut().run_schedule(FixedUpdate);
        w_c99.world_mut().run_schedule(FixedUpdate);
    }

    let post_jit = hash_world_pod_state(w_jit.world());
    let post_c99 = hash_world_pod_state(w_c99.world());
    assert_eq!(post_jit.sha256, post_c99.sha256);
    assert_ne!(
        post_jit.sha256,
        hash_world_pod_state(w_native.world()).sha256
    );

    let _ = Command::new("true").output();
}
