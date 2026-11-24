#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Shared `.strata` kernel fixtures and compilation helpers for the headless `strata_profile`
//! closed-loop profiling suite (`benches/strata_profile.rs`).
//!
//! Intentionally omits `stratac` (`sim-runner`) so `hotpath-alloc` installs its `#[global_allocator]`
//! cleanly without colliding with `SIM_GLOBAL_ALLOC`.

use std::path::Path;
use strata_jit::{JitBuildArtifact, JitCompileOptions, JitOptLevel, compile_module_to_dylib};
use strata_mir::{lower_to_mir, verify_mir};
use strata_sema::analyze_source;

/// Dense 100k `@par(chunk = 1024)` movement kernel.
pub const PAR_100K_SOURCE: &str = r#"
module profile::par100k @version(1.0.0);

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

/// 2-pass CSR spatial broadphase kernel (`spatial_grid` + `query_disc`).
pub const SPATIAL_GRID_SOURCE: &str = r#"
module profile::spatial @version(1.0.0);

component Pos2 { xy: vec2 = vec2(0.0, 0.0) }
tag Actor2D;
component DiscHit { hits: u32 = 0 }

resource SpatialStats {
    total_hits: u32 = 0,
}

spatial_grid Grid2D(
    cell_size: 8.0_m,
    bounds: vec2(-256.0_m, -256.0_m)..vec2(256.0_m, 256.0_m),
    capacity: 16384,
) over Actor2D by Pos2.xy;

sys scan_broadphase(g: &res Grid2D, out: &mut res SpatialStats) {
    let mut acc: u32 = 0;
    for row in query(p: &Pos2, dh: &mut DiscHit) {
        let mut local_hits: u32 = 0;
        for hit in g.query_disc(row.p.xy, 12.0_m) {
            let _ = hit.id;
            local_hits += 1;
        }
        row.dh.hits = local_hits;
        acc += local_hits;
    }
    out.total_hits = acc;
}

schedule FixedUpdate { scan_broadphase }
"#;

/// 50k `&mut?` selective tick-coalescing kernel (`~1%` dirty entities per tick).
pub const SELECTIVE_50K_SOURCE: &str = r#"
module profile::selective @version(1.0.0);

resource SimParam { dt: f32 = 0.016, damping: f32 = 0.995 }
component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component Vel { vx: f32 = 0.0, vy: f32 = 0.0 }
component Heat @summary_tick { temp: f32 = 0.0, active: bool = false }

sys step_selective(p: &res SimParam) {
    uniform let dt = p.dt;
    uniform let damp = p.damping;
    for e in query(pos: &mut Pos, vel: &mut Vel, heat: &mut? Heat) {
        e.vel.vx *= damp;
        e.vel.vy -= 9.81 * dt;
        e.pos.x += e.vel.vx * dt;
        e.pos.y += e.vel.vy * dt;
        if e.pos.y < 0.0 {
            e.pos.y = 1.0;
            e.vel.vy = -e.vel.vy * 0.8;
            e.heat.temp += 1.25;
            e.heat.active = true;
        }
    }
}

schedule FixedUpdate { step_selective }
"#;

/// 10k-cycle `atomic { ... require_true(...) }` pre-image undo + deferred command rollback kernel.
pub const ATOMIC_STORM_SOURCE: &str = r#"
module profile::atomic_storm @version(1.0.0);

resource Ledger {
    bank: i32 = 500,
    tx_attempts: u32 = 0,
    committed_val: f32 = 1.0,
}

component Vault @summary_tick {
    vault_id: u32 = 0,
    gold: i32 = 100,
    energy: f32 = 25.0,
    should_commit: bool = false,
    ok_ticks: u32 = 0,
}

component GhostSpawn {
    tag_val: u32 = 77,
}

sys step_atomic(led: &mut res Ledger) {
    led.tx_attempts += 1;

    for row in query(v: &mut Vault) {
        atomic {
            row.v.gold += 1;
            row.v.energy += 0.25;
            row.v.ok_ticks += 1;
            require_true(row.v.should_commit);
        }
    }

    atomic {
        let _ghost = spawn { GhostSpawn { tag_val: 99 } };
        led.bank -= 123;
        led.committed_val += 999.0;
        require_true(false);
    }

    led.bank += 1;
}

schedule FixedUpdate { step_atomic }
"#;

/// Multi-world `@authority` + `@predicted` replicated step kernel.
pub const NET_SIM_SOURCE: &str = r#"
module profile::net_sim @version(1.0.0);

@authority(server)
@net(unreliable, rate = 30Hz, channel = 1)
component AuthTransform {
    @quantize(min = -256.0, max = 256.0, bits = 16)
    pos: vec2 = vec2(0.0, 0.0),
    @quantize(min = -3.1416, max = 3.1416, bits = 12)
    yaw: f32 = 0.0,
}

@authority(server)
@net(reliable, rate = 20Hz, channel = 0)
component AuthVitals {
    @quantize(min = 0.0, max = 100.0, bits = 12)
    hp: f32 = 100.0,
    seq: u32 = 0,
}

@predicted
component PredictedMotion {
    pred_pos: vec2 = vec2(0.0, 0.0),
    last_seq: u32 = 0,
}

@authority(server)
sys server_step_match() {
    for p in query(xform: &mut? AuthTransform, vitals: &mut? AuthVitals) {
        p.vitals.seq += 1_u32;
        p.xform.pos += vec2(0.25, 0.125);
        p.xform.yaw = (p.xform.yaw + 0.05) % 3.0;
        p.vitals.hp = max(10.0, p.vitals.hp - 0.1);
    }
}

@predicted
sys client_predict_motion() {
    for p in query(pred: &mut? PredictedMotion) {
        p.pred.last_seq += 1_u32;
        p.pred.pred_pos += vec2(0.25, 0.125);
    }
}

schedule FixedUpdate { server_step_match, client_predict_motion }
"#;

/// Compiles a `.strata` profiling kernel directly via `strata_sema -> strata_mir -> strata_jit`.
pub fn compile_profile_jit(
    name: &str,
    src: &str,
    out_dir: &Path,
) -> Result<JitBuildArtifact, String> {
    let analyzed = analyze_source(format!("{name}.strata"), src);
    if !analyzed.ok() {
        return Err(format!(
            "sema failed for `{name}`: {:?}",
            analyzed.diagnostics
        ));
    }
    let mir = lower_to_mir(&analyzed);
    verify_mir(&mir).map_err(|e| format!("MIR verify failed for `{name}`: {e:?}"))?;
    compile_module_to_dylib(
        &mir,
        &JitCompileOptions {
            out_dir: out_dir.to_path_buf(),
            module_stem: name.to_owned(),
            opt_level: JitOptLevel::Speed,
        },
    )
    .map_err(|e| format!("JIT compile failed for `{name}`: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies all five profiling `.strata` kernels pass sema + MIR verification cleanly.
    #[test]
    fn all_profiling_kernels_pass_sema_and_mir() {
        for (name, src) in [
            ("par100k", PAR_100K_SOURCE),
            ("spatial", SPATIAL_GRID_SOURCE),
            ("selective", SELECTIVE_50K_SOURCE),
            ("atomic_storm", ATOMIC_STORM_SOURCE),
            ("net_sim", NET_SIM_SOURCE),
        ] {
            let analyzed = analyze_source(format!("{name}.strata"), src);
            assert!(
                analyzed.ok(),
                "{name} sema failed: {:?}",
                analyzed.diagnostics
            );
            let mir = lower_to_mir(&analyzed);
            verify_mir(&mir).unwrap_or_else(|e| panic!("{name} MIR failed: {e:?}"));
        }
    }
}
