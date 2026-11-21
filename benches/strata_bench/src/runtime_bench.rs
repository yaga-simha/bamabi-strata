//! 4-tier ECS execution throughput and `&mut?` selective tick-coalescing benchmarks with a
//! mandatory pre-timing bit-exact SHA-256 + FNV-1a parity verification gate.

use crate::compiler_bench::KERNEL_SOURCE;
use crate::stats::{BenchStats, measure_batched_ns};
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
use serde::{Deserialize, Serialize};
use std::fs;
use std::hint::black_box;
use stratac::cli::{BuildTarget, OutputFormat};
use stratac::commands::cmd_build;
use stratac::sim_runner::hash_world_pod_state;
use tempfile::TempDir;

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

macro_rules! impl_pod_comp {
    (
        $ty:ident, $canon:literal, $cstr:literal, $flags:expr,
        [$(($fname:ident, $fstr:literal, $fkind:expr, $ftag:literal, $fty:ty)),* $(,)?]
    ) => {
        #[repr(C)]
        #[derive(Clone, Copy)]
        pub(crate) struct Vt {
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
            type VTable = Vt;
            fn vtable() -> &'static Self::VTable {
                static VT: Vt = Vt {
                    _header: VTableHeader::new::<Vt, $ty>(<$ty as ModComponent>::UUID),
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
    mod r_param {
        use super::*;
        impl_pod_comp!(
            SimParam,
            "bench::sim::SimParam",
            c"bench::sim::SimParam",
            0,
            [
                (dt, "dt", BamFieldKind::F32, "f32", f32),
                (damping, "damping", BamFieldKind::F32, "f32", f32),
            ]
        );
    }
    mod c_pos {
        use super::*;
        impl_pod_comp!(
            Pos,
            "bench::sim::Pos",
            c"bench::sim::Pos",
            0,
            [
                (x, "x", BamFieldKind::F32, "f32", f32),
                (y, "y", BamFieldKind::F32, "f32", f32),
            ]
        );
    }
    mod c_vel {
        use super::*;
        impl_pod_comp!(
            Vel,
            "bench::sim::Vel",
            c"bench::sim::Vel",
            0,
            [
                (vx, "vx", BamFieldKind::F32, "f32", f32),
                (vy, "vy", BamFieldKind::F32, "f32", f32),
            ]
        );
    }
    mod c_heat {
        use super::*;
        impl_pod_comp!(
            Heat,
            "bench::sim::Heat",
            c"bench::sim::Heat",
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

/// Recorded execution throughput measurement for a backend or tick-coalescing workload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeBenchRecord {
    /// Workload name (`"step_sim"` or `"selective_mut_slice"`).
    pub workload: String,
    /// Subject target (`"native"`, `"jit"`, `"c99:release"`, `"rust_guest:release"`,
    /// `"selective_1pct"`, `"selective_100pct"`).
    pub subject: String,
    /// Total ECS entities populated in the `World`.
    pub entities: usize,
    /// Ratio of median latency relative to the corresponding `native` baseline (`None` for baseline).
    pub vs_native: Option<f64>,
    /// Throughput and frame-latency statistics.
    pub stats: BenchStats,
}

fn setup_world(entities: usize) -> App {
    let mut app = App::new();
    app.init_schedule(FixedUpdate);
    app.add_plugins(AbiModPlugin::with_error_policy(ModErrorPolicy::Quarantine));
    app.insert_resource(SimParam {
        dt: 0.016,
        damping: 0.995,
    });
    app.register_strata_resource::<SimParam>()
        .expect("register SimParam");
    app.register_strata_component::<Pos>(StrataComponentOptions::new())
        .expect("register Pos");
    app.register_strata_component::<Vel>(StrataComponentOptions::new())
        .expect("register Vel");
    app.register_strata_component::<Heat>(StrataComponentOptions::new().summary_tick())
        .expect("register Heat");

    let batch: Vec<(Pos, Vel, Heat)> = (0..entities)
        .map(|i| {
            (
                Pos {
                    x: (i as f32) * 0.25,
                    y: ((i % 9) as f32) * 0.6 + 0.1,
                },
                Vel {
                    vx: 2.0 + ((i % 5) as f32) * 0.5,
                    vy: -((i % 7) as f32) * 0.4,
                },
                Heat::default(),
            )
        })
        .collect();
    app.world_mut().spawn_batch(batch);
    app
}

fn native_step_sim(p: Res<SimParam>, mut query: Query<(&mut Pos, &mut Vel, &mut Heat)>) {
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

fn build_target_binary(
    src_path: &std::path::Path,
    target: BuildTarget,
    out_dir: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    let (code, msg) = cmd_build(
        src_path,
        true,
        target,
        Some(out_dir),
        false,
        false,
        OutputFormat::Json,
    );
    if code != 0 {
        return Err(format!("cmd_build failed for {target:?}: {msg}"));
    }
    let val: serde_json::Value = serde_json::from_str(&msg).map_err(|e| e.to_string())?;
    let p = val["binary_path"]
        .as_str()
        .ok_or_else(|| "missing binary_path in cmd_build output".to_owned())?;
    Ok(std::path::PathBuf::from(p))
}

/// Runs the 4-tier execution throughput and selective tick-coalescing benchmarks, enforcing
/// bit-exact SHA-256 & FNV-1a parity across all four targets prior to timing.
pub fn run_runtime_suite(quick: bool) -> Result<Vec<RuntimeBenchRecord>, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let src_path = tmp.path().join("bench_sim.strata");
    fs::write(&src_path, KERNEL_SOURCE).map_err(|e| e.to_string())?;

    let jit_bin = build_target_binary(&src_path, BuildTarget::Jit, &tmp.path().join("jit"))?;
    let c99_bin = build_target_binary(&src_path, BuildTarget::C99, &tmp.path().join("c99"))?;
    let rg_bin = build_target_binary(&src_path, BuildTarget::RustGuest, &tmp.path().join("rg"))?;

    // Mandatory pre-timing correctness & differential parity gate (128 entities, 120 frames).
    {
        let mut w_nat = setup_world(128);
        w_nat.add_systems(FixedUpdate, native_step_sim);
        let mut w_jit = setup_world(128);
        w_jit
            .load_mod_with(&jit_bin, LoadOptions::default())
            .map_err(|e| format!("load jit: {e}"))?;
        let mut w_c99 = setup_world(128);
        w_c99
            .load_mod_with(&c99_bin, LoadOptions::default())
            .map_err(|e| format!("load c99: {e}"))?;
        let mut w_rg = setup_world(128);
        w_rg.load_mod_with(&rg_bin, LoadOptions::default())
            .map_err(|e| format!("load rust_guest: {e}"))?;

        for frame in 0..120u32 {
            w_nat.world_mut().run_schedule(FixedUpdate);
            w_jit.world_mut().run_schedule(FixedUpdate);
            w_c99.world_mut().run_schedule(FixedUpdate);
            w_rg.world_mut().run_schedule(FixedUpdate);
            if matches!(frame, 0 | 59 | 119) {
                let dn = hash_world_pod_state(w_nat.world());
                let dj = hash_world_pod_state(w_jit.world());
                let dc = hash_world_pod_state(w_c99.world());
                let dr = hash_world_pod_state(w_rg.world());
                if dn.sha256 != dj.sha256
                    || dn.sha256 != dc.sha256
                    || dn.sha256 != dr.sha256
                    || dn.fnv1a64 != dj.fnv1a64
                {
                    return Err(format!("pre-timing parity check failed at frame {frame}"));
                }
            }
        }
    }

    let scales: &[usize] = if quick {
        &[1_000, 10_000]
    } else {
        &[1_000, 50_000]
    };
    let (warmup_b, sample_b, batch_size) = if quick { (3, 12, 4) } else { (6, 24, 8) };
    let mut records = Vec::new();

    for &entities in scales {
        let mut w_nat = setup_world(entities);
        w_nat.add_systems(FixedUpdate, native_step_sim);
        let nat_stats = measure_batched_ns(warmup_b, sample_b, batch_size, Some(entities), || {
            w_nat.world_mut().run_schedule(FixedUpdate);
            black_box(());
        });
        let nat_median = nat_stats.median_ns.max(1.0);
        records.push(RuntimeBenchRecord {
            workload: "step_sim".to_owned(),
            subject: "native".to_owned(),
            entities,
            vs_native: None,
            stats: nat_stats,
        });

        let targets = [
            ("jit", &jit_bin),
            ("c99:release", &c99_bin),
            ("rust_guest:release", &rg_bin),
        ];
        for (label, bin_path) in targets {
            let mut app = setup_world(entities);
            app.load_mod_with(bin_path, LoadOptions::default())
                .map_err(|e| format!("load {label}: {e}"))?;
            let st = measure_batched_ns(warmup_b, sample_b, batch_size, Some(entities), || {
                app.world_mut().run_schedule(FixedUpdate);
                black_box(());
            });
            let ratio = st.median_ns / nat_median;
            records.push(RuntimeBenchRecord {
                workload: "step_sim".to_owned(),
                subject: label.to_owned(),
                entities,
                vs_native: Some(ratio),
                stats: st,
            });
        }
    }

    // SelectiveMutSlice sparse vs dense tick-coalescing microbenchmark.
    let sel_entities = if quick { 10_000 } else { 50_000 };
    let mut w_sel = setup_world(sel_entities);
    for (subject, stride) in [("selective_1pct", 100usize), ("selective_100pct", 1usize)] {
        let mut q_state = w_sel.world_mut().query::<&mut Heat>();
        let st = measure_batched_ns(warmup_b, sample_b, batch_size, Some(sel_entities), || {
            if let Ok(chunks) = q_state
                .query_mut(w_sel.world_mut())
                .strata_contiguous_iter_mut()
            {
                for heat_cm in chunks {
                    let mut slice = SelectiveMutSlice::from_contiguous_mut(heat_cm);
                    let len = slice.len();
                    for row in (0..len).step_by(stride) {
                        slice.as_mut_untracked()[row].temp += 0.25;
                        slice.mark_dirty_row(row);
                    }
                    black_box(slice.flush_dirty_runs());
                }
            }
        });
        records.push(RuntimeBenchRecord {
            workload: "selective_mut_slice".to_owned(),
            subject: subject.to_owned(),
            entities: sel_entities,
            vs_native: None,
            stats: st,
        });
    }

    Ok(records)
}
