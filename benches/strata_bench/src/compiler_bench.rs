//! Compiler front-end and backend compilation latency benchmarks (`parse`, `sema`, `mir`,
//! `codegen`, and Cranelift PIC object emission).

use crate::stats::{BenchStats, measure_ns};
use serde::{Deserialize, Serialize};
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use strata_codegen::{BevyNativeOptions, emit_bevy_native, emit_c99, emit_rust_guest};
use strata_jit::emitter::emit_pic_object;
use strata_jit::{JitCompileOptions, JitOptLevel};
use strata_mir::{lower_to_mir, verify_mir};
use strata_sema::analyze_source;
use strata_syntax::{format_source, parse};

/// Parity physics kernel used across compiler and 4-tier runtime benchmarks.
pub const KERNEL_SOURCE: &str = r#"
module bench::sim @version(1.0.0);

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

/// Single compiler-pipeline stage measurement record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompilerBenchRecord {
    /// Workload fixture identifier (e.g. `"01_rain_swarm"`, `"05_soulslike_combat"`).
    pub fixture: String,
    /// Compiler stage (`"parse_format"`, `"sema_analyze"`, `"mir_lower_verify"`,
    /// `"codegen_all_targets"`, `"jit_compile_object"`).
    pub stage: String,
    /// Input byte length.
    pub source_bytes: usize,
    /// Latency distribution statistics (`ns/op`).
    pub stats: BenchStats,
}

fn cookbooks_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("cookbooks")
}

/// Runs the compiler latency suite across representative cookbook fixtures and the physics
/// parity kernel.
pub fn run_compiler_suite(quick: bool) -> Result<Vec<CompilerBenchRecord>, String> {
    let (warmup, samples) = if quick { (3, 10) } else { (6, 25) };
    let fixtures: &[(&str, Option<&str>)] = if quick {
        &[
            ("step_sim_kernel", Some(KERNEL_SOURCE)),
            ("01_rain_swarm", None),
            ("05_soulslike_combat", None),
        ]
    } else {
        &[
            ("step_sim_kernel", Some(KERNEL_SOURCE)),
            ("01_rain_swarm", None),
            ("03_metroidvania_core", None),
            ("05_soulslike_combat", None),
        ]
    };

    let cdir = cookbooks_dir();
    let mut records = Vec::new();
    for &(name, inline) in fixtures {
        let src = match inline {
            Some(s) => s.to_owned(),
            None => fs::read_to_string(cdir.join(format!("{name}.strata")))
                .map_err(|e| format!("failed reading fixture `{name}`: {e}"))?,
        };
        let bytes = src.len();
        let file_name = format!("{name}.strata");

        // Pre-verify correctness once before timing any compiler stage.
        let parsed0 = parse(&src);
        if !parsed0.ok() {
            return Err(format!(
                "fixture `{name}` failed parse: {:?}",
                parsed0.errors()
            ));
        }
        let sema0 = analyze_source(&file_name, &src);
        if !sema0.ok() {
            return Err(format!(
                "fixture `{name}` failed sema: {:?}",
                sema0.diagnostics
            ));
        }
        let mir0 = lower_to_mir(&sema0);
        verify_mir(&mir0).map_err(|e| format!("fixture `{name}` failed MIR verify: {e:?}"))?;

        let parse_fmt = measure_ns(warmup, samples, None, || {
            let p = parse(black_box(&src));
            let f = format_source(black_box(&src)).expect("valid format");
            black_box((p.ok(), f.len()));
        });
        records.push(CompilerBenchRecord {
            fixture: name.to_owned(),
            stage: "parse_format".to_owned(),
            source_bytes: bytes,
            stats: parse_fmt,
        });

        let sema_st = measure_ns(warmup, samples, None, || {
            let a = analyze_source(black_box(&file_name), black_box(&src));
            black_box(a.layouts.len());
        });
        records.push(CompilerBenchRecord {
            fixture: name.to_owned(),
            stage: "sema_analyze".to_owned(),
            source_bytes: bytes,
            stats: sema_st,
        });

        let mir_st = measure_ns(warmup, samples, None, || {
            let m = lower_to_mir(black_box(&sema0));
            let v = verify_mir(&m);
            black_box(v.is_ok());
        });
        records.push(CompilerBenchRecord {
            fixture: name.to_owned(),
            stage: "mir_lower_verify".to_owned(),
            source_bytes: bytes,
            stats: mir_st,
        });

        let codegen_st = measure_ns(warmup, samples, None, || {
            let c = emit_c99(black_box(&mir0)).expect("c99");
            let r = emit_rust_guest(black_box(&mir0)).expect("rust_guest");
            let b = emit_bevy_native(black_box(&mir0), &BevyNativeOptions::default())
                .expect("bevy_native");
            black_box((c.files.len(), r.files.len(), b.files.len()));
        });
        records.push(CompilerBenchRecord {
            fixture: name.to_owned(),
            stage: "codegen_all_targets".to_owned(),
            source_bytes: bytes,
            stats: codegen_st,
        });

        let jit_opts = JitCompileOptions {
            out_dir: PathBuf::from("."),
            module_stem: name.to_owned(),
            opt_level: JitOptLevel::Speed,
        };
        let jit_st = measure_ns(warmup, samples, None, || {
            let obj = emit_pic_object(black_box(&mir0), &jit_opts).expect("jit emit_pic_object");
            black_box(obj.object_bytes.len());
        });
        records.push(CompilerBenchRecord {
            fixture: name.to_owned(),
            stage: "jit_compile_object".to_owned(),
            source_bytes: bytes,
            stats: jit_st,
        });
    }

    Ok(records)
}
