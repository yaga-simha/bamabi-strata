use std::path::PathBuf;
use std::process::Command;

use super::*;

fn compile_strata_to_mir(label: &str, src: &str) -> MirModule {
    let parsed = strata_syntax::parse(src);
    assert!(
        parsed.errors().is_empty(),
        "syntax errors in {label}: {:?}",
        parsed.errors()
    );
    let sema = strata_sema::analyze_source(label, src);
    let fatal: Vec<_> = sema
        .diagnostics
        .iter()
        .filter(|d| matches!(d.severity, strata_sema::diagnostics::Severity::Error))
        .collect();
    assert!(fatal.is_empty(), "sema errors in {label}: {fatal:?}");
    strata_mir::lower_to_mir(&sema)
}

fn verify_strict_c99_syntax(artifact: &GeneratedArtifact, label: &str) {
    let tmp = tempfile::tempdir().expect("tempdir");
    for f in &artifact.files {
        let p = tmp.path().join(&f.path);
        std::fs::write(&p, &f.content).expect("write generated artifact");
    }
    let c_file = artifact
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .expect("C source artifact");
    let primary = tmp.path().join(&c_file.path);
    let compiler = if Command::new("cc").arg("--version").output().is_ok() {
        "cc"
    } else {
        "clang"
    };
    let output = Command::new(compiler)
        .arg("-std=c99")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Wpedantic")
        .arg("-Werror")
        .arg("-fsyntax-only")
        .arg("-I")
        .arg(tmp.path())
        .arg(&primary)
        .output()
        .expect("invoke C99 compiler");
    assert!(
        output.status.success(),
        "Strict ISO C99 compilation failed for `{label}`:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn host_api_slot_constants_aligned_with_bamabi_sys() {
    assert_eq!(
        bamabi_sys::BAM_HOST_API_SLOT_COUNT,
        bamabi_sys::offsets::SLOT_COUNT
    );
    const {
        assert!(bamabi_sys::BAM_HOST_API_SLOT_COUNT >= 68);
        assert!(MAX_TERMS_PER_QUERY >= 16);
        assert!(MAX_QUERIES_PER_SYSTEM >= 8);
    }
}

#[test]
fn all_six_cookbooks_compile_under_strict_c99() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("cookbooks");
    let names = [
        "01_rain_swarm.strata",
        "02_soa_and_ticks.strata",
        "03_metroidvania_core.strata",
        "04_cozy_valley.strata",
        "05_soulslike_combat.strata",
        "06_battle_royale_server.strata",
        "07_visual_boss_graph.strata",
        "08_authoritative_multiplayer.strata",
    ];
    for name in names {
        let path = root.join(name);
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed reading {}: {e}", path.display()));
        let mir = compile_strata_to_mir(name, &src);
        let artifact = emit(&mir).unwrap_or_else(|e| panic!("c99 emit failed for {name}: {e}"));
        let primary_c = &artifact
            .files
            .iter()
            .find(|f| f.path.ends_with(".c"))
            .expect("primary C file")
            .content;
        assert!(
            !primary_c.contains("g_strata_state"),
            "{name}: must not use global state `g_strata_state`"
        );
        assert!(
            primary_c.contains("calloc(1u, sizeof(StrataModState))"),
            "{name}: must heap-allocate StrataModState"
        );
        assert!(
            primary_c.contains("free(instance)"),
            "{name}: must free StrataModState in bamabi_shutdown"
        );
        verify_strict_c99_syntax(&artifact, name);
    }
}

#[test]
fn migration_fixture_wires_migrate_component_column_and_compiles_c99() {
    let src = r#"
module demo::mig @version(2.0.0);

component HealthV1 {
hp: f32,
}

component Health {
hp: f32,
max_hp: f32 = 100.0,
}

migrate Health from 1.0.0 to 2.0.0(old: &HealthV1) -> Health {
Health { hp: old.hp, max_hp: old.hp }
}

sys heal() {
for row in query(h: &mut Health) {
    row.h.hp = row.h.max_hp;
}
}

schedule Update { heal }
"#;
    let mir = compile_strata_to_mir("migration_fixture.strata", src);
    let artifact = emit(&mir).expect("c99 emit for migration fixture");
    let primary_c = &artifact
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .expect("primary C file")
        .content;
    assert!(
        primary_c.contains("migrate_component_column"),
        "migration fixture must emit migrate_component_column wiring"
    );
    verify_strict_c99_syntax(&artifact, "migration_fixture");
}

#[test]
fn indexed_spawn_batch_require_deps_and_bare_schedule_names_compile_c99() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("cookbooks");

    // 1. 01_rain_swarm: indexed spawn_batch + @require(Pos3D, Vel3D)
    let rain_src = std::fs::read_to_string(root.join("01_rain_swarm.strata")).unwrap();
    let rain_mir = compile_strata_to_mir("01_rain_swarm.strata", &rain_src);
    let rain_art = emit(&rain_mir).expect("emit 01_rain_swarm");
    let rain_c = &rain_art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .unwrap()
        .content;
    assert!(rain_c.contains("strata_spawn_batch_alloc_header"));
    assert!(rain_c.contains("strata_spawn_batch_push"));
    assert!(rain_c.contains("strata_spawn_batch_commit"));
    assert!(rain_c.contains("cdesc.required_components = reqs_"));
    assert!(rain_c.contains("cdesc.required_component_count = 2u;"));
    verify_strict_c99_syntax(&rain_art, "01_rain_swarm_indexed_require");

    // 2. 03_metroidvania_core: bare set/system/observer names + required_init_descs for Facing
    let mv_src = std::fs::read_to_string(root.join("03_metroidvania_core.strata")).unwrap();
    let mv_mir = compile_strata_to_mir("03_metroidvania_core.strata", &mv_src);
    let mv_art = emit(&mv_mir).expect("emit 03_metroidvania_core");
    let mv_c = &mv_art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .unwrap()
        .content;
    assert!(mv_c.contains("set_desc.name = \"MetroidvaniaFrame\";"));
    assert!(mv_c.contains("set_desc.name = \"InputAndTasks\";"));
    assert!(mv_c.contains("set_desc.name = \"RoomStreaming\";"));
    assert!(mv_c.contains("sdesc.name = \"sample_platformer_inputs\";"));
    assert!(mv_c.contains("sdesc.name = \"strata_timer_tick\";"));
    assert!(mv_c.contains("odesc.name = \"on_slash_active\";"));
    assert!(
        !mv_c.contains("set_desc.name = \"genres::metroidvania::"),
        "schedule set names must be bare without module::prefix"
    );
    assert!(
        !mv_c.contains("sdesc.name = \"genres::metroidvania::"),
        "system names must be bare without module::prefix"
    );
    assert!(
        !mv_c.contains("\"genres::metroidvania::strata_timer_tick\""),
        "after targets must be bare without module::prefix"
    );
    assert!(mv_c.contains("BAM_REQUIRED_FLAG_CUSTOM_BYTES"));
    assert!(mv_c.contains("cdesc.required_init_descs = req_inits_"));
    assert!(
        mv_c.contains("->air_dashes_left = ") && mv_c.contains("(uint8_t)("),
        "sub-word u8 FieldStore must narrow via explicit uint8_t cast and struct field assignment"
    );
    verify_strict_c99_syntax(&mv_art, "03_metroidvania_core_bare_names");

    // 3. Reverse-order @require (dependent declared before dependency)
    let rev_src = r#"
module demo::rev_req @version(1.0.0);

component Dependent @require(DepWithDefault) { val: f32 = 2.0 }
component DepWithDefault { speed: f32 = 42.0 }

sys seed() {
spawn_batch(4) |i| {
    { Dependent { val: (i as f32) } }
};
}

schedule Startup { seed }
"#;
    let rev_mir = compile_strata_to_mir("rev_req.strata", rev_src);
    let rev_art = emit(&rev_mir).expect("emit rev_req");
    let rev_c = &rev_art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .unwrap()
        .content;
    let dep_pos = rev_c
        .find("Component [1]: demo::rev_req::DepWithDefault")
        .expect("DepWithDefault registration");
    let main_pos = rev_c
        .find("Component [0]: demo::rev_req::Dependent")
        .expect("Dependent registration");
    assert!(
        dep_pos < main_pos,
        "dependency must register before dependent in bamabi_init"
    );
    verify_strict_c99_syntax(&rev_art, "rev_req");
}

#[test]
fn par_chunk_outlines_with_restrict_and_falls_back_on_cmd_or_reduce() {
    let src = r#"
module demo::par_out @version(1.0.0);

component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component Vel { vx: f32 = 0.0, vy: f32 = 0.0 }
resource SimOut { total: f32 = 0.0 }

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

@par(read_only, chunk = 512)
sys scan_ro() {
for e in query(pos: &Pos) {
    let _x = e.pos.x;
}
}

@par(read_only, chunk = 256)
sys sum_ro(out: &mut res SimOut) {
let s = for e in query(pos: &Pos) reduce (total: sum(0.0, e.pos.x));
out.total = s;
}

@par(chunk = 256)
sys despawn_par() {
for e in query(pos: &Pos) {
    if e.pos.x < 0.0 {
        despawn(e.entity);
    }
}
}

schedule FixedUpdate { step_par, scan_ro, sum_ro, despawn_par }
"#;
    let mir = compile_strata_to_mir("par_out.strata", src);
    let art = emit(&mir).expect("emit par_out");
    let c_src = &art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .unwrap()
        .content;
    assert!(
        c_src.contains("static BamResult strata_par_step_par_"),
        "step_par must outline into strata_par_*"
    );
    assert!(
        c_src.contains("state->api->par_for_each_chunk("),
        "step_par must dispatch via Slot 27 par_for_each_chunk"
    );
    assert!(
        c_src.contains("BAM_RESTRICT col_"),
        "outlined @par worker must preserve BAM_RESTRICT column pointers"
    );
    assert!(
        c_src.contains("static BamResult strata_par_scan_ro_"),
        "scan_ro must outline into strata_par_*"
    );
    assert!(
        c_src.contains("state->api->par_for_each_chunk_readonly("),
        "scan_ro must dispatch via Slot 59 par_for_each_chunk_readonly"
    );
    assert!(
        !c_src.contains("static BamResult strata_par_sum_ro_"),
        "reduce @par must fall back to sequential CFG"
    );
    assert!(
        !c_src.contains("static BamResult strata_par_despawn_par_"),
        "command @par must fall back to sequential CFG"
    );
    // Verify non-optional restrict_cols hoist NULL check to IterCol* and omit per-row != NULL.
    assert!(
        c_src.contains("== NULL) { return BAM_RESULT_NULL_POINTER; }"),
        "non-optional restrict_cols must hoist NULL check to IterCol*"
    );
    let par_worker = c_src
        .split("static BamResult strata_par_step_par_")
        .nth(1)
        .and_then(|s| s.split("\nstatic BamResult ").next())
        .expect("strata_par_step_par_* worker");
    let par_row_body = par_worker
        .split("bb_4:;")
        .nth(1)
        .and_then(|s| s.split("\nbb_5:;").next())
        .expect("bb_4 row body");
    assert!(
        !par_row_body.contains("col_7 != NULL")
            && !par_row_body.contains("col_8 != NULL")
            && !par_row_body.contains("v_14 != NULL")
            && !par_row_body.contains("v_15 != NULL"),
        "hoisted restrict_cols must not emit per-row `!= NULL` checks inside @par row body:\n{par_row_body}"
    );
    verify_strict_c99_syntax(&art, "par_out");
}

#[test]
fn par_chunk_falls_back_on_break_and_transitive_unsafe_helper() {
    let src = r#"
module demo::par_fb @version(1.0.0);

component Pos { x: f32 = 0.0, y: f32 = 0.0 }
resource SimOut { flag: u32 = 0 }

fn leaf_res_write(out: &mut res SimOut) -> u32 {
out.flag = 1;
return 1;
}

fn mid_helper(out: &mut res SimOut) -> u32 {
return leaf_res_write(out);
}

fn leaf_safe(x: f32) -> f32 {
return x + 1.0;
}

fn mid_safe(x: f32) -> f32 {
return leaf_safe(x);
}

@par(chunk = 1024)
sys par_with_break() {
for e in query(pos: &mut Pos) {
    if e.pos.x >= 10.0 {
        break;
    }
    e.pos.x += 1.0;
}
}

@par(chunk = 1024)
sys par_with_transitive_res_write(out: &mut res SimOut) {
for e in query(pos: &mut Pos) {
    if e.pos.x > 0.0 {
        let _ = mid_helper(out);
    }
}
}

@par(chunk = 1024)
sys par_with_transitive_safe_helper() {
for e in query(pos: &mut Pos) {
    e.pos.x = mid_safe(e.pos.x);
}
}

schedule FixedUpdate { par_with_break, par_with_transitive_res_write, par_with_transitive_safe_helper }
"#;
    let mir = compile_strata_to_mir("par_fb.strata", src);
    let art = emit(&mir).expect("emit par_fb");
    let c_src = &art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .unwrap()
        .content;
    assert!(
        !c_src.contains("static BamResult strata_par_par_with_break_"),
        "@par loop with break must fall back to sequential CFG"
    );
    assert!(
        !c_src.contains("static BamResult strata_par_par_with_transitive_res_write_"),
        "@par loop with transitive ResWrite helper must fall back to sequential CFG"
    );
    let safe_sys = c_src
        .split("strata_sys_par_with_transitive_safe_helper(")
        .nth(1)
        .unwrap_or("<missing>");
    assert!(
        c_src.contains("static BamResult strata_par_par_with_transitive_safe_helper_"),
        "@par loop with pure transitive helper must outline cleanly:\n{safe_sys}"
    );
    verify_strict_c99_syntax(&art, "par_fb");
}

#[test]
fn iteration3_nonnull_dom_par_ro_write_sparse_reduce_f64_math_and_bitset_default() {
    let src = r#"
module demo::iter3_c99 @version(1.0.0);

component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component OutBox { total: f32 = 0.0 }
@sparse component SP { v: f32 = 0.0 }
component F64Val { v: f64 = 2.0 }
component F32Val { v: f32 = 2.0 }
component WithBits { mask: BitSet<64> = bits(0), nonzero: BitSet<64> = bits(5) }
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
    e.f.v = sqrt(e.f.v) + floor(e.f.v) + ceil(e.f.v) + round(e.f.v)
        + abs(e.f.v) + sin(e.f.v) + cos(e.f.v)
        + pow(e.f.v, 2.0) + min(e.f.v, 2.0) + max(e.f.v, 1.0);
}
}

sys f32_math() {
for e in query(f: &mut F32Val) {
    e.f.v = sqrt(e.f.v) + floor(e.f.v);
}
}

sys use_bits() {
for e in query(b: &mut WithBits) {
    e.b.mask.set(1);
}
}

schedule FixedUpdate {
par_sel_reduce_ro,
par_ro_outbox,
sparse_reduce,
f64_math,
f32_math,
use_bits
}
"#;
    let mir = compile_strata_to_mir("iter3_c99.strata", src);
    let art = emit(&mir).expect("emit iter3_c99");
    let c_src = &art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .unwrap()
        .content;

    // 1. `par_sel_reduce_ro` must NOT abort with BAM_RESULT_NULL_POINTER in bb_0.
    let sel_sys = c_src
        .split("strata_sys_par_sel_reduce_ro(BamSystemCtx* sys_ctx, void* user_data) {")
        .nth(1)
        .and_then(|s| s.split("\nstatic BamResult ").next())
        .expect("strata_sys_par_sel_reduce_ro");
    let sel_bb0 = sel_sys
        .split("bb_1:;")
        .next()
        .expect("bb_0 before bb_1 in par_sel_reduce_ro");
    assert!(
        sel_bb0.contains("iter_column_mutable_untracked(") && !sel_bb0.contains("if (col_"),
        "bb_0 must not hoist col_* nonnull check before IterNextChunk:\n{sel_bb0}"
    );

    // 2. `@par(read_only)` must NOT outline `&mut OutBox` into par_for_each_chunk_readonly.
    let ro_sys = c_src
        .split("strata_sys_par_ro_outbox(BamSystemCtx* sys_ctx, void* user_data) {")
        .nth(1)
        .and_then(|s| s.split("\nstatic BamResult ").next())
        .expect("strata_sys_par_ro_outbox");
    assert!(
        !ro_sys.contains("par_for_each_chunk_readonly("),
        "par_ro_outbox must not dispatch mutable OutBox loop via par_for_each_chunk_readonly:\n{ro_sys}"
    );

    // 3. `@sparse` reduce must call `iter_column_rows_readonly`, not `iter_column_readonly`.
    let sparse_sys = c_src
        .split("strata_sys_sparse_reduce(BamSystemCtx* sys_ctx, void* user_data) {")
        .nth(1)
        .and_then(|s| s.split("\nstatic BamResult ").next())
        .expect("strata_sys_sparse_reduce");
    assert!(
        sparse_sys.contains("iter_column_rows_readonly("),
        "@sparse reduce must read via iter_column_rows_readonly:\n{sparse_sys}"
    );
    assert!(
        !sparse_sys.contains("iter_column_readonly("),
        "@sparse reduce must not call iter_column_readonly:\n{sparse_sys}"
    );

    // 4. `f64_math` must use double math functions without (float)/sqrtf truncation; `f32_math` keeps sqrtf.
    let f64_sys = c_src
        .split("strata_sys_f64_math(BamSystemCtx* sys_ctx, void* user_data) {")
        .nth(1)
        .and_then(|s| s.split("\nstatic BamResult ").next())
        .expect("strata_sys_f64_math");
    assert!(f64_sys.contains("sqrt((double)"), "{f64_sys}");
    assert!(f64_sys.contains("floor((double)"), "{f64_sys}");
    assert!(f64_sys.contains("ceil((double)"), "{f64_sys}");
    assert!(f64_sys.contains("round((double)"), "{f64_sys}");
    assert!(f64_sys.contains("fabs((double)"), "{f64_sys}");
    assert!(f64_sys.contains("sin((double)"), "{f64_sys}");
    assert!(f64_sys.contains("cos((double)"), "{f64_sys}");
    assert!(f64_sys.contains("pow((double)"), "{f64_sys}");
    assert!(f64_sys.contains("fmin((double)"), "{f64_sys}");
    assert!(f64_sys.contains("fmax((double)"), "{f64_sys}");
    assert!(!f64_sys.contains("sqrtf("), "{f64_sys}");
    assert!(!f64_sys.contains("floorf("), "{f64_sys}");

    let f32_sys = c_src
        .split("strata_sys_f32_math(BamSystemCtx* sys_ctx, void* user_data) {")
        .nth(1)
        .and_then(|s| s.split("\nstatic BamResult ").next())
        .expect("strata_sys_f32_math");
    assert!(f32_sys.contains("sqrtf((float)"), "{f32_sys}");
    assert!(f32_sys.contains("floorf((float)"), "{f32_sys}");

    // 5. `BitSet<64>` default must emit `memset` / `memcpy`, never `out.mask = 0;`.
    assert!(
        c_src.contains("memset(out.mask, 0, sizeof(out.mask));"),
        "BitSet<64> zero default must use memset"
    );
    assert!(
        !c_src.contains("out.mask = "),
        "BitSet<64> default must not assign scalar to uint8_t[8]"
    );

    verify_strict_c99_syntax(&art, "iter3_c99");
}

#[test]
fn c99_spatial_csr_2d_and_3d_xz_nonzero_hits_and_executes() {
    let src = r#"
module probe::spatial_csr @version(1.0.0);

component Pos2D { xy: vec2 = vec2(0.0, 0.0) }
component Pos3D { xyz: vec3 = vec3(0.0, 0.0, 0.0) }
tag Enemy;
tag Target3D;

spatial_grid Grid2D(
cell_size: 4.0_m,
bounds:    vec2(-20.0_m, -20.0_m)..vec2(20.0_m, 20.0_m),
capacity:  16,
) over Enemy by Pos2D.xy;

spatial_history HistXZ(
frames:    4,
cell_size: 4.0_m,
bounds:    vec2(-20.0_m, -20.0_m)..vec2(20.0_m, 20.0_m),
capacity:  16,
) over Target3D by Pos3D.xyz;

resource OutHits { count2d: u32 = 0, count3d: u32 = 0 }

sys probe_queries(g: &res Grid2D, h: &res HistXZ, out: &mut res OutHits) {
let mut n2: u32 = 0;
for cand in g.query_disc(vec2(1.0, 2.0), 3.0_m) {
    let _e = cand.id;
    n2 += 1;
}
let mut n3: u32 = 0;
for hit in h.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(10.0, 0.0, 10.0), 2.5_m) {
    let _e = hit.id;
    n3 += 1;
}
out.count2d = n2;
out.count3d = n3;
}

schedule FixedUpdate { probe_queries }
"#;
    let mir = compile_strata_to_mir("c99_spatial_csr.strata", src);
    let art = emit(&mir).expect("emit c99 spatial csr");
    let h_src = &art.files[0].content;
    let c_src = &art.files[1].content;

    assert!(
        c_src.contains("StrataSpatialHeader"),
        "expected StrataSpatialHeader"
    );
    assert!(
        c_src.contains("state->api->iter_reset("),
        "CSR rebuild must emit Slot 10 iter_reset"
    );
    assert!(
        c_src.contains("strata_spatial_csr_cell_range"),
        "expected real CSR cell lookup"
    );
    assert!(
        c_src.contains("hits.entities[hits.count++]"),
        "expected real hit population in spatial query"
    );
    assert!(h_src.contains("BAMABI_C99_HEADER") || !h_src.is_empty());
    verify_strict_c99_syntax(&art, "c99_spatial_csr");

    // Compile generated .c (with main driver) & EXECUTE to verify non-zero hits for both 2D and 3D XZ!
    let tmp = tempfile::tempdir().expect("tempdir");
    for f in &art.files {
        std::fs::write(tmp.path().join(&f.path), &f.content).expect("write generated file");
    }
    let c_file = art.files.iter().find(|f| f.path.ends_with(".c")).unwrap();
    let mut combined = std::fs::read_to_string(tmp.path().join(&c_file.path)).unwrap();
    combined.push_str(
        r#"
int main(void) {
StrataModState st;
memset(&st, 0, sizeof(st));
/* Initialize spatial_Grid2D (2D [0,1]) */
st.spatial_Grid2D.frames = 1u;
st.spatial_Grid2D.capacity = 16u;
st.spatial_Grid2D.cols = 10u;
st.spatial_Grid2D.rows = 10u;
st.spatial_Grid2D.cell_count = 100u;
st.spatial_Grid2D.cell_size = 4.0f;
st.spatial_Grid2D.inv_cell_size = 0.25f;
st.spatial_Grid2D.bounds_min_x = -20.0f;
st.spatial_Grid2D.bounds_min_y = -20.0f;
st.spatial_Grid2D.plane_ax0 = 0u;
st.spatial_Grid2D.plane_ax1 = 1u;
st.spatial_Grid2D.counts = st.spatial_Grid2D_counts;
st.spatial_Grid2D.cell_offsets = st.spatial_Grid2D_offsets;
st.spatial_Grid2D.write_cursors = st.spatial_Grid2D_cursors;
st.spatial_Grid2D.entities = st.spatial_Grid2D_entities;
st.spatial_Grid2D.positions = st.spatial_Grid2D_positions;

strata_spatial_csr_begin(&st.spatial_Grid2D);
strata_spatial_csr_count(&st.spatial_Grid2D, strata_spatial_pos_v2((StrataVec2){ 1.5f, 2.5f }));
strata_spatial_csr_count(&st.spatial_Grid2D, strata_spatial_pos_v2((StrataVec2){ 18.0f, 18.0f }));
strata_spatial_csr_prefix_sum(&st.spatial_Grid2D);
strata_spatial_csr_scatter(&st.spatial_Grid2D, (BamEntity)101ull, strata_spatial_pos_v2((StrataVec2){ 1.5f, 2.5f }));
strata_spatial_csr_scatter(&st.spatial_Grid2D, (BamEntity)102ull, strata_spatial_pos_v2((StrataVec2){ 18.0f, 18.0f }));

StrataSpatialHits hits2d = strata_spatial_query_disc(&st.spatial_Grid2D, (StrataVec3){ 1.0f, 2.0f, 0.0f }, 3.0f);
if (hits2d.count != 1u || hits2d.entities[0] != (BamEntity)101ull) {
    return 11;
}

/* Initialize spatial_HistXZ (3D XZ [0,2]) */
st.spatial_HistXZ.frames = 4u;
st.spatial_HistXZ.capacity = 16u;
st.spatial_HistXZ.cols = 10u;
st.spatial_HistXZ.rows = 10u;
st.spatial_HistXZ.cell_count = 100u;
st.spatial_HistXZ.cell_size = 4.0f;
st.spatial_HistXZ.inv_cell_size = 0.25f;
st.spatial_HistXZ.bounds_min_x = -20.0f;
st.spatial_HistXZ.bounds_min_y = -20.0f;
st.spatial_HistXZ.plane_ax0 = 0u;
st.spatial_HistXZ.plane_ax1 = 2u;
st.spatial_HistXZ.counts = st.spatial_HistXZ_counts;
st.spatial_HistXZ.cell_offsets = st.spatial_HistXZ_offsets;
st.spatial_HistXZ.write_cursors = st.spatial_HistXZ_cursors;
st.spatial_HistXZ.entities = st.spatial_HistXZ_entities;
st.spatial_HistXZ.positions = st.spatial_HistXZ_positions;

strata_spatial_csr_begin(&st.spatial_HistXZ);
strata_spatial_csr_count(&st.spatial_HistXZ, strata_spatial_pos_v3((StrataVec3){ 5.0f, 0.0f, 5.0f }));
strata_spatial_csr_count(&st.spatial_HistXZ, strata_spatial_pos_v3((StrataVec3){ -15.0f, 0.0f, -15.0f }));
strata_spatial_csr_prefix_sum(&st.spatial_HistXZ);
strata_spatial_csr_scatter(&st.spatial_HistXZ, (BamEntity)201ull, strata_spatial_pos_v3((StrataVec3){ 5.0f, 0.0f, 5.0f }));
strata_spatial_csr_scatter(&st.spatial_HistXZ, (BamEntity)202ull, strata_spatial_pos_v3((StrataVec3){ -15.0f, 0.0f, -15.0f }));

StrataSpatialHits hits3d = strata_spatial_query_segment_at(
    &st.spatial_HistXZ,
    (StrataVec3){ 0.0f, 0.0f, 0.0f },
    (StrataVec3){ 10.0f, 0.0f, 10.0f },
    2.5f,
    0.0f
);
if (hits3d.count != 1u || hits3d.entities[0] != (BamEntity)201ull) {
    return 12;
}
return 0;
}
"#,
    );
    let driver_path = tmp.path().join("driver_spatial.c");
    std::fs::write(&driver_path, &combined).unwrap();
    let bin_path = tmp.path().join("driver_spatial");
    let cc = if Command::new("cc").arg("--version").output().is_ok() {
        "cc"
    } else {
        "clang"
    };
    let comp = Command::new(cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&driver_path)
        .arg("-lm")
        .arg("-o")
        .arg(&bin_path)
        .output()
        .expect("compile C99 spatial driver");
    assert!(
        comp.status.success(),
        "C99 spatial driver compile failed:\n{}",
        String::from_utf8_lossy(&comp.stderr)
    );
    let run = Command::new(&bin_path)
        .output()
        .expect("run spatial driver");
    assert!(
        run.status.success(),
        "C99 spatial driver exited with {:?}: stderr={}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn c99_fix64_div_rem_zero_guard_mixed_arith_and_nb123_executes() {
    let src = r#"
module probe::fix64_nb @version(1.0.0);

struct InnerCell {
flags: [bool; 2],
}

component FixBox {
a64: fix64 = 6.0,
b64: fix64 = -2.0,
a32: fix32 = 1.5,
grid_iv: ivec2 = ivec2(-1, -2),
nested_bools: [[bool; 2]; 2] = [[true, false], [false, true]],
nested_cells: [InnerCell; 2] = [InnerCell { flags: [true, false] }, InnerCell { flags: [false, true] }],
arr_vals: [fix64; 3] = [1.0, 2.0, 3.0],
}

component ExtraComp { keep_default: i32 = 42 }

object PartialHero {
FixBox { a64: 12.0, grid_iv: ivec2(-1, -2) },
ExtraComp {},
}

sys compute_fix_and_arrays() {
let mut loc_arr: [fix64; 2] = [1.0, 2.0];
loc_arr[1] = 4.0;
for e in query(f: &mut FixBox) {
    let z64: fix64 = 0.0;
    let _div_zero = e.f.a64 / z64;
    let _rem_zero = e.f.a64 % z64;
    let _mixed = e.f.a64 + e.f.a32;
    e.f.a64 = (e.f.a64 * e.f.b64) / 3.0;
    e.f.arr_vals[0] = loc_arr[1];
}
}

schedule FixedUpdate { compute_fix_and_arrays }
"#;
    let mir = compile_strata_to_mir("c99_fix64_nb.strata", src);
    let art = emit(&mir).expect("emit c99 fix64_nb");
    let c_src = &art.files[1].content;

    assert!(
        !c_src.contains("__int128"),
        "C99 output must NEVER contain __int128"
    );
    assert!(
        c_src.contains("strata_fix64_mul("),
        "expected strata_fix64_mul"
    );
    assert!(
        c_src.contains("strata_fix64_div("),
        "expected strata_fix64_div"
    );
    assert!(
        c_src.contains("strata_fix64_rem("),
        "expected strata_fix64_rem"
    );
    assert!(
        c_src.contains("strata_ivec2((int32_t)(-(1)), (int32_t)(-(2)))")
            || c_src.contains("strata_ivec2(-(1), -(2))")
            || c_src.contains("strata_ivec2(((int32_t)-1), ((int32_t)-2))"),
        "NB-1 ivec2(-1, -2) must preserve negative signs:\n{c_src}"
    );
    assert!(
        c_src.contains("strata_default_2_ExtraComp()")
            || c_src.contains("strata_default_1_ExtraComp()"),
        "NB-3 partial object override must emit un-overridden component"
    );
    assert!(
        c_src.contains("_ae_4") && c_src.contains("_ae_8"),
        "NB-2 nested struct/array init vars must include indent depth"
    );
    verify_strict_c99_syntax(&art, "c99_fix64_nb");

    let tmp = tempfile::tempdir().expect("tempdir");
    for f in &art.files {
        std::fs::write(tmp.path().join(&f.path), &f.content).expect("write generated file");
    }
    let c_file = art.files.iter().find(|f| f.path.ends_with(".c")).unwrap();
    let mut combined = std::fs::read_to_string(tmp.path().join(&c_file.path)).unwrap();
    combined.push_str(
        r#"
int main(void) {
int64_t one = (1ll << 32);
int64_t a = 6ll * one;
int64_t b = 2ll * one;
int64_t neg_half = -(one / 2);
if (strata_fix64_div(a, b) != 3ll * one) return 1;
if (strata_fix64_div(a, 0) != 0) return 2;
if (strata_fix64_rem(a, 0) != 0) return 3;
if (strata_fix64_mul(a, neg_half) != -3ll * one) return 4;
if (strata_fix64_div(INT64_MIN, one) != INT64_MIN && strata_fix64_div(-6ll * one, 2ll * one) != -3ll * one) return 5;
if (strata_fix64_rem(7ll * one, 4ll * one) != 3ll * one) return 6;
if (strata_fix32_div(6 * 65536, 0) != 0) return 7;
if (strata_fix32_mul(-3 * 65536, 2 * 65536) != -6 * 65536) return 8;
return 0;
}
"#,
    );
    let driver_path = tmp.path().join("driver_fix64.c");
    std::fs::write(&driver_path, &combined).unwrap();
    let bin_path = tmp.path().join("driver_fix64");
    let cc = if Command::new("cc").arg("--version").output().is_ok() {
        "cc"
    } else {
        "clang"
    };
    let comp = Command::new(cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&driver_path)
        .arg("-lm")
        .arg("-o")
        .arg(&bin_path)
        .output()
        .expect("compile C99 fix64 driver");
    assert!(
        comp.status.success(),
        "C99 fix64 driver compile failed:\n{}",
        String::from_utf8_lossy(&comp.stderr)
    );
    let run = Command::new(&bin_path).output().expect("run fix64 driver");
    assert!(
        run.status.success(),
        "C99 fix64 driver exited with {:?}",
        run.status.code()
    );
}

#[test]
fn c99_shadow_write_preserves_pre_image_undo_slot_and_tag_wire_identity() {
    let src = r#"
module parity::spatial_csr @version(1.0.0);

component Vault {
    gold: i32 = 100,
    hp: f32 = 25.0,
    ok: bool = false,
}

tag Target2D;

object Unit {
    Vault { gold: 100, hp: 25.0, ok: false },
    Target2D {},
}

sys tx_step() {
    for row in query(v: &mut Vault) {
        atomic {
            row.v.gold += 50;
            row.v.hp += 10.0;
            require_true(row.v.ok);
        }
    }
}

schedule FixedUpdate { tx_step }
"#;
    let mir = compile_strata_to_mir("c99_tx_tag", src);
    let c_art = emit(&mir).expect("emit c99");
    let c_src = &c_art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .unwrap()
        .content;

    assert!(
        c_src.contains("(pre-image preserved)"),
        "ShadowWrite must preserve pre-image without overwriting undo_slot:\n{c_src}"
    );
    assert!(
        !c_src.contains("memcpy(tx_undo_"),
        "ShadowWrite must not memcpy post-store value into tx_undo_*:\n{c_src}"
    );
    verify_strict_c99_syntax(&c_art, "c99_tx_tag");

    // Verify canonical ZST `tag Target2D` wire identity matches across C99, RustGuest, BevyNative, and sema.
    let (_expected_uuid, expected_fp) = strata_sema::layout::compute_wire_identity(
        "parity::spatial_csr::Target2D",
        0,
        1,
        0,
        true,
        &[],
    );
    let expected_hex = format!("0x{expected_fp:016X}");
    assert!(
        c_src.contains(&format!("cdesc.schema_fingerprint = {expected_hex}ull;")),
        "C99 must emit canonical ZST tag fingerprint {expected_hex}:\n{c_src}"
    );

    let rg_art = crate::rust_guest::emit(&mir, &crate::RustGuestOptions::default())
        .expect("emit rust_guest");
    let rg_src = &rg_art.files[1].content;
    assert!(
        rg_src.contains(&format!("const SCHEMA_FINGERPRINT: u64 = {expected_hex};")),
        "RustGuest must emit canonical ZST tag fingerprint {expected_hex}"
    );

    let bn_art = crate::bevy_native::emit(&mir, &crate::BevyNativeOptions::default())
        .expect("emit bevy_native");
    let bn_src = &bn_art.files[1].content;
    assert!(
        bn_src.contains(&format!("const SCHEMA_FINGERPRINT: u64 = {expected_hex};")),
        "BevyNative must emit canonical ZST tag fingerprint {expected_hex}"
    );
}

#[test]
fn c99_emits_param_set_group_for_conflicting_queries_and_zero_for_disjoint() {
    let src = r#"
module c99::pset @version(1.0.0);

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

sys disjoint_steps() {
    for r in query(a: &mut Actor).with<TagA>() {
        r.a.hp += 1.0;
    }
    for r in query(a: &mut Actor).without<TagA>() {
        r.a.hp += 2.0;
    }
}

schedule FixedUpdate { ProcessOrder, disjoint_steps }
"#;
    let mir = compile_strata_to_mir("c99_pset", src);
    let c_art = emit(&mir).expect("emit c99 param_set");
    let c_src = &c_art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .unwrap()
        .content;

    let process_reg = c_src
        .split("/* System [")
        .skip(1)
        .find(|s| s.contains("ProcessOrder */"))
        .and_then(|s| s.split("BamSystemDesc sdesc;").next())
        .expect("ProcessOrder system registration block");
    assert!(
        process_reg.contains(".flags = BAM_QUERY_FLAG_PARAM_SET;"),
        "conflicting task queries must set BAM_QUERY_FLAG_PARAM_SET:\n{process_reg}"
    );
    assert!(
        process_reg.matches(".param_set_group = 1u;").count() == 2,
        "both conflicting queries in ProcessOrder must share param_set_group = 1u:\n{process_reg}"
    );

    let disjoint_reg = c_src
        .split("/* System [")
        .skip(1)
        .find(|s| s.contains("disjoint_steps */"))
        .and_then(|s| s.split("BamSystemDesc sdesc;").next())
        .expect("disjoint_steps system registration block");
    assert!(
        !disjoint_reg.contains("BAM_QUERY_FLAG_PARAM_SET")
            && !disjoint_reg.contains("param_set_group"),
        "disjoint non-conflicting queries must leave param_set_group zeroed:\n{disjoint_reg}"
    );

    verify_strict_c99_syntax(&c_art, "c99_pset");
}

#[test]
fn c99_object_struct_ivec_array_overrides_and_runtime_ivec_constructors() {
    let src = r#"
module test::c99_nb123 @version(1.0.0);

enum Kind { Alpha = 0, Beta = 1 }

struct Pair {
    a: i32,
    b: u32,
}

component Payload {
    one: Pair = Pair { a: 0, b: 0 },
    pairs: [Pair; 2] = [Pair { a: 0, b: 0 }, Pair { a: 0, b: 0 }],
    pts: [ivec2; 2] = [ivec2(0, 0), ivec2(0, 0)],
    kind: Kind = Kind::Alpha,
    iv: ivec2 = ivec2(0, 0),
    iv3: ivec3 = ivec3(0, 0, 0),
    uv: uvec2 = uvec2(0, 0),
}

object ObjOverride {
    Payload {
        one: Pair { a: 30000001, b: 3000000001 },
        pairs: [Pair { a: -7, b: 9 }, Pair { a: 11, b: 13 }],
        pts: [ivec2(30000003, -30000005), ivec2(42, -99)],
        kind: Kind::Beta,
    },
}

fn make_iv3(x: i32, y: i32, z: i32) -> ivec3 {
    return ivec3(x, y, z);
}

sys runtime_vecs() {
    for r in query(p: &mut Payload) {
        r.p.iv = ivec2(30000001, -30000007);
        r.p.iv3 = make_iv3(30000011, -30000013, 30000017);
        r.p.uv = uvec2(3000000001, 4000000003);
    }
}

schedule Update { runtime_vecs }
"#;
    let mir = compile_strata_to_mir("c99_nb123.strata", src);
    let c_art = emit(&mir).expect("c99 emit");
    let c_src = &c_art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .expect("primary C file")
        .content;

    assert!(
        c_src.contains("30000001") && c_src.contains("-30000005") && c_src.contains("3000000001"),
        "expected exact >2^24 object override constants in generated C99:\n{c_src}"
    );
    assert!(
        !c_src.contains(".one = 0;") && !c_src.contains(".pairs = 0;"),
        "must not emit invalid scalar `= 0` for struct/array overrides:\n{c_src}"
    );
    assert!(
        c_src.contains("strata_ivec2((int32_t)(v_")
            && c_src.contains("strata_ivec3((int32_t)(v_")
            && c_src.contains("strata_uvec2((uint32_t)(v_")
            && c_src.contains("30000007")
            && c_src.contains("30000013")
            && c_src.contains("4000000003u"),
        "expected real runtime ivec2/ivec3/uvec2 constructors in generated C99:\n{c_src}"
    );
    verify_strict_c99_syntax(&c_art, "c99_nb123");
}

#[test]
fn c99_enum_arrays_object_casts_ivec_binops_nested_offsets_and_option_fixes() {
    let src = r#"
module test::c99_wave1_fixes @version(1.0.0);

enum Kind { Alpha = 0, Beta = 1 }

struct Inner {
    x: i32 = 10,
    y: u32 = 20,
    pts: [ivec2; 2] = [ivec2(1, 2), ivec2(3, 4)],
}

struct Outer {
    pad: i32 = 0,
    inner: Inner = Inner { x: 10, y: 20, pts: [ivec2(1, 2), ivec2(3, 4)] },
}

component BoxComp {
    kinds: [Kind; 2] = [Kind::Alpha, Kind::Beta],
    cast_i32: i32 = 0,
    cast_fix: fix64 = 0.0,
    iv_bin: ivec2 = ivec2(0, 0),
    uv_cast: uvec2 = uvec2(0, 0),
    outer: Outer = Outer { pad: 0, inner: Inner { x: 10, y: 20, pts: [ivec2(1, 2), ivec2(3, 4)] } },
    out_y: u32 = 0,
    out_pt0: ivec2 = ivec2(0, 0),
}

component OtherComp {
    pad: i32 = 123,
    hp: f32 = 55.0,
}

object ObjBox {
    BoxComp {
        kinds: [Kind::Beta, Kind::Alpha],
        cast_i32: 3.9_f32 as i32,
        cast_fix: 3.9_f32 as i32,
        iv_bin: ivec2(-2147483647 - 1, 2147483647),
        uv_cast: uvec2((-1_i32) as u32, (-(-5)) as u32),
    },
}

sys step_all() {
    for r in query(b: &mut BoxComp, oc: Option<&mut OtherComp>) {
        r.b.out_y = r.b.outer.inner.y;
        r.b.out_pt0 = r.b.outer.inner.pts[0];
        if r.oc.is_some() {
            let op = r.oc.expect("oc present");
            op.hp += 1.0;
        }
        match r.oc {
            None => { r.b.cast_i32 -= 1; },
            Some(x) => { r.b.cast_i32 += x.pad; },
        }
        match r.oc {
            None => { r.b.cast_i32 -= 2; },
            _ => { r.b.cast_i32 += 5; },
        }
    }
}

schedule Update { step_all }
"#;
    let mir = compile_strata_to_mir("c99_wave1_fixes.strata", src);
    let c_art = emit(&mir).expect("c99 emit");
    let c_src = &c_art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .expect("primary C file")
        .content;

    assert!(
        !c_src.contains("= 3.9f;") && !c_src.contains("16750372454ll"),
        "C99 must truncate 3.9_f32 as i32 before fix64/i32 conversion (must not emit 3.9f or 16750372454ll):\n{c_src}"
    );
    assert!(
        c_src.contains("12884901888ll"),
        "C99 cast_fix must emit 3.0 in Q32.32 (12884901888ll):\n{c_src}"
    );
    assert!(
        c_src.contains("(-2147483647 - 1)")
            && c_src.contains("4294967295u")
            && c_src.contains("5u"),
        "C99 must evaluate Binary in ivec2 and Cast/-(-5) in uvec2:\n{c_src}"
    );
    assert!(
        c_src.contains(".y;") && !c_src.contains(") + 0u,"),
        "C99 nested struct non-zero-offset read must resolve field `.y` directly without + 0u fallback:\n{c_src}"
    );
    assert!(
        c_src.contains("->hp") && c_src.contains("iter_mark_changed_range"),
        "C99 let-bound expect() mutation must target `->hp` and flush Changed<OtherComp>:\n{c_src}"
    );
    assert!(
        !c_src.contains("v_33 = BAM_TRUE;") && c_src.contains("!"),
        "C99 reversed `match` None arm must negate presence condition instead of unconditional BAM_TRUE:\n{c_src}"
    );
    verify_strict_c99_syntax(&c_art, "c99_wave1_fixes");
}

#[test]
fn c99_step2_iter3_vec_consts_neg_casts_enum16_inlinestr_and_option_alias() {
    let src = r#"
module test::c99_iter3 @version(1.0.0);

tag Tag;

enum Kind16 {
    Low = 1,
    High = 60000,
}

struct WithInlineStr {
    label: InlineStr<16> = "init",
    k8: [Kind16; 2] = [Kind16::Low, Kind16::High],
}

component OtherComp {
    pad: i32 = 123,
    hp: f32 = 55.0,
}

component BoxC99 {
    uv_one: uvec2 = uvec2::ZERO,
    uv_x: uvec2 = uvec2::ZERO,
    iv_y: ivec2 = ivec2::ZERO,
    iv3_z: ivec3 = ivec3::ZERO,
    v4_w: vec4 = vec4::ZERO,
    neg_i32: i32 = 0,
    neg_u32: u32 = 99,
    k16: Kind16 = Kind16::Low,
    arr16: [Kind16; 2] = [Kind16::Low, Kind16::Low],
    w: WithInlineStr = WithInlineStr { label: "init", k8: [Kind16::Low, Kind16::High] },
    shadow_iflet: i32 = 0,
}

object ObjC99 {
    BoxC99 {
        uv_one: uvec2::ONE,
        uv_x: uvec2::X,
        iv_y: ivec2::Y,
        iv3_z: ivec3::Z,
        v4_w: vec4::W,
        neg_i32: (-3.9_f32) as i32,
        neg_u32: (-3.9_f32) as u32,
        k16: Kind16::High,
        arr16: [Kind16::High, Kind16::Low],
        w: WithInlineStr { label: "ovrd", k8: [Kind16::High, Kind16::Low] },
    },
}

sys step_iter3_iflet() {
    for row in query(b: &mut BoxC99, oc: Option<&mut OtherComp>) {
        let x: i32 = 999;
        if let Some(x) = row.oc {
            let x2 = x;
            x2.hp += 1.0;
        }
        row.b.shadow_iflet = x;
    }
}

sys step_iter3_single() {
    for oc in query(oc: Option<&mut OtherComp>).with<Tag>() {
        if oc.is_some() {
            let op = oc.expect("single oc");
            let op2 = op;
            op2.hp += 3.0;
        }
    }
}

schedule Update {
    seq OrderedAll { step_iter3_iflet, step_iter3_single }
}
"#;
    let mir = compile_strata_to_mir("c99_iter3.strata", src);
    let c_art = emit(&mir).expect("c99 emit");
    let c_src = &c_art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .expect("primary C file")
        .content;

    assert!(
        c_src.contains("strata_uvec2(1u, 1u)")
            && c_src.contains("strata_uvec2(1u, 0u)")
            && c_src.contains("strata_ivec2(((int32_t)0), ((int32_t)1))")
            && c_src.contains("strata_ivec3(((int32_t)0), ((int32_t)0), ((int32_t)1))")
            && c_src.contains("strata_vec4(0.0f, 0.0f, 0.0f, 1.0f)"),
        "C99 vector unit constants must not fall back to 0:\n{c_src}"
    );
    assert!(
        c_src.contains("neg_i32 = ((int32_t)-3);") && c_src.contains("neg_u32 = 0u;"),
        "C99 negative float casts must evaluate cleanly (-3 and 0u):\n{c_src}"
    );
    assert!(
        c_src.contains("uint16_t k16;") && c_src.contains("((uint16_t)60000u)"),
        "C99 Kind16 must use uint16_t without u8 truncation:\n{c_src}"
    );
    assert!(
        !c_src.contains(".label = \"") && c_src.contains("_istr[]"),
        "C99 InlineStr<16> defaults must emit _istr byte memcpy instead of array assignment:\n{c_src}"
    );
    assert!(
        !c_src.contains("-Wpointer-to-int-cast") && c_src.contains("->hp"),
        "C99 single-term Option alias must resolve `->hp` cleanly:\n{c_src}"
    );
    verify_strict_c99_syntax(&c_art, "c99_iter3");
}

#[test]
fn c99_step2_iter4_signed_enums_float_sat_row_alias_and_query_one_unwrap() {
    let src = r#"
module test::c99_iter4 @version(1.0.0);

enum NegAuto {
    Neg = -5,
    Zero = 0,
    Pos = 5,
}

@repr(i32)
enum NegExplicit {
    MinNeg = -300,
    BigPos = 70000,
}

component BoxC99 {
    neg_a: NegAuto = NegAuto::Neg,
    neg_e: NegExplicit = NegExplicit::MinNeg,
    arr_neg: [NegAuto; 2] = [NegAuto::Neg, NegAuto::Pos],
    ov_f64_u64: u64 = 0,
    ov_huge_i8: i8 = 0,
    ov_nhuge_i8: i8 = 0,
    ov_huge_u8: u8 = 0,
    rt_huge_i8: i8 = 0,
    rt_nhuge_i8: i8 = 0,
    rt_huge_i16: i16 = 0,
    rt_nhuge_i16: i16 = 0,
    rt_huge_i32: i32 = 0,
    rt_nhuge_i32: i32 = 0,
    rt_huge_i64: i64 = 0,
    rt_nhuge_i64: i64 = 0,
    rt_nan_i32: i32 = 77,
    rt_nan_i64: i64 = 88,
    alias_sum: i32 = 0,
    f_big32: f32 = 1e20_f32,
    f_nbig32: f32 = -1e20_f32,
    f_big64: f64 = 1e25_f64,
    f_nbig64: f64 = -1e25_f64,
    f_zero: f32 = 0.0_f32,
}

component Wallet1 { coins: i32 = 100 }
component Wallet2 { coins: i32 = 200 }

object ObjBox {
    BoxC99 {
        neg_a: NegAuto::Pos,
        neg_e: NegExplicit::MinNeg,
        arr_neg: [NegAuto::Pos, NegAuto::Neg],
        ov_f64_u64: (1000000000000001.0_f64) as u64,
        ov_huge_i8: (1e20_f32) as i8,
        ov_nhuge_i8: (-1e20_f32) as i8,
        ov_huge_u8: (300.0_f32) as u8,
    },
}

object ObjW1 { Wallet1 { coins: 100 } }
object ObjW2 { Wallet2 { coins: 200 } }

sys step_iter4_a() {
    for row in query(b: &mut BoxC99) {
        let row2 = row;
        let row3 = row2;
        row3.b.alias_sum += 10;
        row3.b.rt_huge_i8 = (row3.b.f_big32) as i8;
        row3.b.rt_nhuge_i8 = (row3.b.f_nbig32) as i8;
        row3.b.rt_huge_i16 = (row3.b.f_big32) as i16;
        row3.b.rt_nhuge_i16 = (row3.b.f_nbig32) as i16;
        row3.b.rt_huge_i32 = (row3.b.f_big32) as i32;
        row3.b.rt_nhuge_i32 = (row3.b.f_nbig32) as i32;
        row3.b.rt_huge_i64 = (row3.b.f_big64) as i64;
        row3.b.rt_nhuge_i64 = (row3.b.f_nbig64) as i64;
        let nan32: f32 = row3.b.f_zero / row3.b.f_zero;
        let nan64: f64 = (nan32) as f64;
        row3.b.rt_nan_i32 = (nan32) as i32;
        row3.b.rt_nan_i64 = (nan64) as i64;
    }
    if let Some(wrow) = query_one(w: &mut Wallet1).on(ObjW1) {
        let wrow2 = wrow;
        wrow2.w.coins += 10;
    }
    let r2 = query_one(w: &mut Wallet2).on(ObjW2).expect("w2");
    r2.w.coins += 7;
}

sys step_iter4_b() {
    let r1 = query_one(w: &mut Wallet1).on(ObjW1).unwrap();
    let r1b = r1;
    r1b.w.coins += 5;
    match query_one(w: &mut Wallet2).on(ObjW2) {
        Some(mr) => { mr.w.coins += 3; },
        None => {},
    }
}

schedule Update {
    seq OrderedAll { step_iter4_a, step_iter4_b }
}
"#;
    let mir = compile_strata_to_mir("c99_iter4.strata", src);
    let c_art = emit(&mir).expect("c99 emit");
    let c_src = &c_art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .expect("primary C file")
        .content;

    assert!(
        c_src.contains("int32_t neg_a;") && c_src.contains("int32_t neg_e;"),
        "C99 signed enums must emit int32_t fields:\n{c_src}"
    );
    assert!(
        c_src.contains("INT8_MAX")
            && c_src.contains("INT16_MIN")
            && c_src.contains("INT32_MAX")
            && c_src.contains("INT64_MIN"),
        "C99 runtime float-to-signed-int casts must emit saturation guards:\n{c_src}"
    );
    assert!(
        !c_src.contains("memcpy(v_4, &v_0") && !c_src.contains("sizeof(BamEntity)"),
        "C99 must not treat QueryRow alias as BamEntity pointer"
    );
    verify_strict_c99_syntax(&c_art, "c99_iter4");

    // Compile and execute a real C99 host driver verifying runtime float-to-signed-int saturation
    // and QueryRow alias / query_one().unwrap() / .expect() behavior (critical for x86_64 UB).
    let tmp = tempfile::tempdir().expect("tempdir");
    for f in &c_art.files {
        std::fs::write(tmp.path().join(&f.path), &f.content).expect("write generated file");
    }
    let c_file = c_art.files.iter().find(|f| f.path.ends_with(".c")).unwrap();
    let mut combined = std::fs::read_to_string(tmp.path().join(&c_file.path)).unwrap();
    let box_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name.ends_with("BoxC99"))
        .unwrap();
    let w1_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name.ends_with("Wallet1"))
        .unwrap();
    let w2_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name.ends_with("Wallet2"))
        .unwrap();
    let box_cty = format!("StrataType_{box_idx}_BoxC99");
    let w1_cty = format!("StrataType_{w1_idx}_Wallet1");
    let w2_cty = format!("StrataType_{w2_idx}_Wallet2");
    combined.push_str(&format!(
        r#"
#include <stdio.h>
static {box_cty} g_box;
static {w1_cty} g_w1 = {{ 100 }};
static {w2_cty} g_w2 = {{ 200 }};
static uint64_t g_ents[1] = {{ 1ull }};
static int g_hctx = 1, g_lctx = 2, g_sctx = 3;
static int g_q_stage = 0, g_in_startup = 1;
typedef struct {{ char name[64]; BamSystemFn cb; void* ud; }} SysEntry;
static SysEntry g_sys[8];
static size_t g_sys_n = 0;
static uint32_t g_comp_next = 1, g_box_id = 0, g_w1_id = 0, g_w2_id = 0;
static const BamHostCtx* d_lhc(const BamLoadCtx* p) {{ (void)p; return (const BamHostCtx*)&g_hctx; }}
static BamResult d_reg_comp(BamLoadCtx* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc;
    uint32_t id = g_comp_next++;
    if (d && d->name) {{
        if (strstr(d->name, "BoxC99")) g_box_id = id;
        else if (strstr(d->name, "Wallet1")) g_w1_id = id;
        else if (strstr(d->name, "Wallet2")) g_w2_id = id;
    }}
    *o = id;
    return 0;
}}
static BamResult d_resolve_comp(const BamHostCtx* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{
    (void)hc; (void)n; (void)u; (void)o; return BAM_RESULT_NOT_FOUND;
}}
static BamResult d_linfo(const BamHostCtx* hc, uint32_t c, BamLayoutInfo* i) {{
    (void)hc; (void)c; (void)i; return BAM_RESULT_NOT_FOUND;
}}
static BamResult d_reg_sys(BamLoadCtx* lc, const BamSystemDesc* d) {{
    (void)lc;
    snprintf(g_sys[g_sys_n].name, 64, "%s", d->name ? d->name : "");
    g_sys[g_sys_n].cb = d->callback;
    g_sys[g_sys_n].ud = d->user_data;
    g_sys_n++;
    return 0;
}}
static BamResult d_reg_sys_h(BamLoadCtx* lc, const BamSystemDesc* d, uint32_t* o) {{
    (void)d_reg_sys(lc, d);
    *o = (uint32_t)g_sys_n;
    return 0;
}}
static BamResult d_sys_q(BamSystemCtx* sc, size_t qi, BamIter** o) {{
    (void)sc; (void)qi;
    if (g_in_startup) {{ *o = NULL; return 0; }}
    g_q_stage = 0; *o = (BamIter*)&g_box; return 0;
}}
static BamBool d_next(BamIter* it, size_t* len) {{
    (void)it;
    if (g_q_stage == 0) {{ g_q_stage = 1; *len = 1; return 1; }}
    *len = 0; return 0;
}}
static const BamEntity* d_ents(const BamIter* it) {{ (void)it; return g_ents; }}
static uint8_t* d_col(BamIter* it, size_t ti) {{ (void)it; (void)ti; return (uint8_t*)&g_box; }}
static BamResult d_mark(BamIter* it, size_t ti, size_t s, size_t l) {{ (void)it; (void)ti; (void)s; (void)l; return 0; }}
static uint8_t* d_ent_get_mut(BamSystemCtx* sc, size_t qi, BamEntity ent, size_t ti) {{
    (void)sc; (void)qi; (void)ti;
    if (ent == 101ull) return (uint8_t*)&g_w1;
    if (ent == 102ull) return (uint8_t*)&g_w2;
    return NULL;
}}
static BamResult d_sys_cmds(BamSystemCtx* sc, BamCommands** out_c) {{ (void)sc; static int c = 1; *out_c = (BamCommands*)&c; return 0; }}
static BamResult d_spawn(BamCommands* cmds, const uint32_t* comps, const uint8_t* const* ptrs, size_t cnt, BamEntity* out_e) {{
    (void)cmds;
    *out_e = 1ull;
    for (size_t i = 0; i < cnt; i++) {{
        if (!ptrs[i]) continue;
        if (comps[i] == g_box_id) {{ memcpy(&g_box, ptrs[i], sizeof(g_box)); *out_e = 1ull; }}
        else if (comps[i] == g_w1_id) {{ memcpy(&g_w1, ptrs[i], sizeof(g_w1)); *out_e = 101ull; }}
        else if (comps[i] == g_w2_id) {{ memcpy(&g_w2, ptrs[i], sizeof(g_w2)); *out_e = 102ull; }}
    }}
    return 0;
}}
static BamResult d_bind(const BamHostCtx* hc, BamStrView n, BamEntity e) {{ (void)hc; (void)n; (void)e; return 0; }}

int main(void) {{
    BamHostApi api;
    memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api);
    api.abi_version = BAM_ABI_VERSION;
    api.load_host_ctx = d_lhc;
    api.register_component = d_reg_comp;
    api.resolve_component = d_resolve_comp;
    api.component_layout_info = d_linfo;
    api.register_system = d_reg_sys;
    api.register_system_handle = d_reg_sys_h;
    api.sys_query = d_sys_q;
    api.iter_next_chunk = d_next;
    api.iter_entities = d_ents;
    api.iter_column_mutable = d_col;
    api.iter_mark_changed_range = d_mark;
    api.bind_named_object = d_bind;
    api.sys_entity_get_mut = d_ent_get_mut;
    api.sys_commands = d_sys_cmds;
    api.cmd_spawn = d_spawn;
    BamInstance* st = NULL;
    if (bamabi_init(&api, (BamLoadCtx*)&g_lctx, &st) != 0) return 2;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strstr(g_sys[i].name, "objects")) {{ g_sys[i].cb((BamSystemCtx*)&g_sctx, g_sys[i].ud); }}
    }}
    g_in_startup = 0;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (!strstr(g_sys[i].name, "objects")) {{
            if (g_sys[i].cb((BamSystemCtx*)&g_sctx, g_sys[i].ud) != 0) return 3;
        }}
    }}
    int32_t arr_neg[2] = {{ 0, 0 }};
    memcpy(arr_neg, g_box.arr_neg, sizeof(arr_neg));
    if (g_box.neg_a != 5 || g_box.neg_e != -300 || arr_neg[0] != 5 || arr_neg[1] != -5) {{
        fprintf(stderr, "box_id=%u sys_n=%zu neg_a=%d neg_e=%d arr=[%d,%d] alias=%d\n",
            g_box_id, g_sys_n, g_box.neg_a, g_box.neg_e, arr_neg[0], arr_neg[1], g_box.alias_sum);
        return 10;
    }}
    if (g_box.ov_f64_u64 != 1000000000000001ull || g_box.ov_huge_i8 != 127 || g_box.ov_nhuge_i8 != -128 || g_box.ov_huge_u8 != 255u) return 11;
    if (g_box.rt_huge_i8 != 127 || g_box.rt_nhuge_i8 != -128 || g_box.rt_huge_i16 != 32767 || g_box.rt_nhuge_i16 != -32768) return 12;
    if (g_box.rt_huge_i32 != INT32_MAX || g_box.rt_nhuge_i32 != INT32_MIN || g_box.rt_huge_i64 != INT64_MAX || g_box.rt_nhuge_i64 != INT64_MIN) return 13;
    if (g_box.rt_nan_i32 != 0 || g_box.rt_nan_i64 != 0) return 14;
    if (g_box.alias_sum != 10 || g_w1.coins != 115 || g_w2.coins != 210) return 15;
    bamabi_shutdown(st);
    return 0;
}}
"#
    ));
    let driver_path = tmp.path().join("driver_iter4.c");
    std::fs::write(&driver_path, &combined).unwrap();
    let bin_path = tmp.path().join("driver_iter4");
    let cc = if Command::new("cc").arg("--version").output().is_ok() {
        "cc"
    } else {
        "clang"
    };
    let comp = Command::new(cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-Wno-overlength-strings",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&driver_path)
        .arg("-lm")
        .arg("-o")
        .arg(&bin_path)
        .output()
        .expect("compile C99 iter4 driver");
    assert!(
        comp.status.success(),
        "C99 iter4 driver compile failed:\n{}",
        String::from_utf8_lossy(&comp.stderr)
    );
    let run = Command::new(&bin_path).output().expect("run iter4 driver");
    assert!(
        run.status.success(),
        "C99 iter4 driver exited with {:?}: {}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn c99_step2_iter5_object_override_non_finite_float_casts() {
    let src = r#"
module test::c99_iter5 @version(1.0.0);

component CastRes {
    ov_nan_i8: i8 = 11,
    ov_nan_i16: i16 = 22,
    ov_nan_i32: i32 = 33,
    ov_nan_i64: i64 = 44,
    ov_inf_i32: i32 = 55,
    ov_ninf_i8: i8 = 66,
    ov_inf_u8: u8 = 77,
    ov_ninf_u64: u64 = 88,
    ov_nan_f32: f32 = 1.0_f32,
    ov_inf_f64: f64 = 2.0_f64,
}

object ObjCast {
    CastRes {
        ov_nan_i8: (0.0_f32 / 0.0_f32) as i8,
        ov_nan_i16: (0.0_f32 / 0.0_f32) as i16,
        ov_nan_i32: (0.0_f32 / 0.0_f32) as i32,
        ov_nan_i64: (0.0_f32 / 0.0_f32) as i64,
        ov_inf_i32: (1.0_f32 / 0.0_f32) as i32,
        ov_ninf_i8: (-1.0_f32 / 0.0_f32) as i8,
        ov_inf_u8: (1.0_f32 / 0.0_f32) as u8,
        ov_ninf_u64: (-1.0_f64 / 0.0_f64) as u64,
        ov_nan_f32: 0.0_f32 / 0.0_f32,
        ov_inf_f64: 1.0_f64 / 0.0_f64,
    },
}
"#;
    let mir = compile_strata_to_mir("c99_iter5.strata", src);
    let c_art = emit(&mir).expect("c99 emit");
    let c_src = &c_art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .expect("primary C file")
        .content;
    assert!(
        !c_src.contains("((int64_t)(((0.0f) / (0.0f))))")
            && !c_src.contains("((int32_t)(((1.0f) / (0.0f))))"),
        "C99 object overrides must not emit unguarded float-to-int casts:\n{c_src}"
    );
    assert!(
        c_src.contains("NAN") && c_src.contains("INFINITY"),
        "C99 object overrides must emit NAN/INFINITY for non-finite float fields:\n{c_src}"
    );
    verify_strict_c99_syntax(&c_art, "c99_iter5");

    let tmp = tempfile::tempdir().expect("tempdir");
    for f in &c_art.files {
        std::fs::write(tmp.path().join(&f.path), &f.content).expect("write generated file");
    }
    let c_file = c_art.files.iter().find(|f| f.path.ends_with(".c")).unwrap();
    let mut combined = std::fs::read_to_string(tmp.path().join(&c_file.path)).unwrap();
    let cr_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name.ends_with("CastRes"))
        .unwrap();
    let cr_cty = format!("StrataType_{cr_idx}_CastRes");
    combined.push_str(&format!(
        r#"
#include <stdio.h>
static {cr_cty} g_cr;
static int g_hctx = 1, g_lctx = 2, g_sctx = 3;
typedef struct {{ char name[64]; BamSystemFn cb; void* ud; }} SysEntry;
static SysEntry g_sys[4];
static size_t g_sys_n = 0;
static uint32_t g_comp_next = 1, g_cr_id = 0;
static const BamHostCtx* d_lhc(const BamLoadCtx* p) {{ (void)p; return (const BamHostCtx*)&g_hctx; }}
static BamResult d_reg_comp(BamLoadCtx* lc, const BamComponentDesc* d, uint32_t* o) {{
    (void)lc; uint32_t id = g_comp_next++;
    if (d && d->name && strstr(d->name, "CastRes")) g_cr_id = id;
    *o = id; return 0;
}}
static BamResult d_resolve_comp(const BamHostCtx* hc, const char* n, const BamComponentUuid* u, uint32_t* o) {{ (void)hc; (void)n; (void)u; (void)o; return BAM_RESULT_NOT_FOUND; }}
static BamResult d_linfo(const BamHostCtx* hc, uint32_t c, BamLayoutInfo* i) {{ (void)hc; (void)c; (void)i; return BAM_RESULT_NOT_FOUND; }}
static BamResult d_reg_sys(BamLoadCtx* lc, const BamSystemDesc* d) {{
    (void)lc; snprintf(g_sys[g_sys_n].name, 64, "%s", d->name ? d->name : "");
    g_sys[g_sys_n].cb = d->callback; g_sys[g_sys_n].ud = d->user_data; g_sys_n++; return 0;
}}
static BamResult d_reg_sys_h(BamLoadCtx* lc, const BamSystemDesc* d, uint32_t* o) {{ (void)d_reg_sys(lc, d); *o = (uint32_t)g_sys_n; return 0; }}
static BamResult d_sys_cmds(BamSystemCtx* sc, BamCommands** out_c) {{ (void)sc; static int c = 1; *out_c = (BamCommands*)&c; return 0; }}
static BamResult d_spawn(BamCommands* cmds, const uint32_t* comps, const uint8_t* const* ptrs, size_t cnt, BamEntity* out_e) {{
    (void)cmds; *out_e = 1ull;
    for (size_t i = 0; i < cnt; i++) {{
        if (ptrs[i] && comps[i] == g_cr_id) memcpy(&g_cr, ptrs[i], sizeof(g_cr));
    }}
    return 0;
}}
static BamResult d_bind(const BamHostCtx* hc, BamStrView n, BamEntity e) {{ (void)hc; (void)n; (void)e; return 0; }}
int main(void) {{
    BamHostApi api; memset(&api, 0, sizeof(api));
    api.struct_size = (uint32_t)sizeof(api); api.abi_version = BAM_ABI_VERSION;
    api.load_host_ctx = d_lhc; api.register_component = d_reg_comp;
    api.resolve_component = d_resolve_comp; api.component_layout_info = d_linfo;
    api.register_system = d_reg_sys; api.register_system_handle = d_reg_sys_h;
    api.bind_named_object = d_bind; api.sys_commands = d_sys_cmds; api.cmd_spawn = d_spawn;
    BamInstance* st = NULL;
    if (bamabi_init(&api, (BamLoadCtx*)&g_lctx, &st) != 0) return 2;
    for (size_t i = 0; i < g_sys_n; i++) {{
        if (strstr(g_sys[i].name, "objects")) g_sys[i].cb((BamSystemCtx*)&g_sctx, g_sys[i].ud);
    }}
    if (g_cr.ov_nan_i8 != 0 || g_cr.ov_nan_i16 != 0 || g_cr.ov_nan_i32 != 0 || g_cr.ov_nan_i64 != 0) return 10;
    if (g_cr.ov_inf_i32 != INT32_MAX || g_cr.ov_ninf_i8 != INT8_MIN || g_cr.ov_inf_u8 != 255u || g_cr.ov_ninf_u64 != 0ull) return 11;
    if (!isnan(g_cr.ov_nan_f32) || !isinf(g_cr.ov_inf_f64)) return 12;
    bamabi_shutdown(st);
    return 0;
}}
"#
    ));
    let driver_path = tmp.path().join("driver_iter5.c");
    std::fs::write(&driver_path, &combined).unwrap();
    let bin_path = tmp.path().join("driver_iter5");
    let cc = if Command::new("cc").arg("--version").output().is_ok() {
        "cc"
    } else {
        "clang"
    };
    let comp = Command::new(cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-Wno-overlength-strings",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&driver_path)
        .arg("-lm")
        .arg("-o")
        .arg(&bin_path)
        .output()
        .expect("compile C99 iter5 driver");
    assert!(
        comp.status.success(),
        "C99 iter5 driver compile failed:\n{}",
        String::from_utf8_lossy(&comp.stderr)
    );
    let run = Command::new(&bin_path).output().expect("run iter5 driver");
    assert!(
        run.status.success(),
        "C99 iter5 driver exited with {:?}: {}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn c99_step2_iter6_non_finite_fix_casts_nested_struct_and_local_struct_write() {
    let src = r#"
module test::c99_iter6 @version(1.0.0);

struct InnerS {
    si: i32 = 11,
    sf: fix32 = 2.0,
}

component CastRes {
    nan_fx32: fix32 = 3.0,
    inf_fx32: fix32 = 4.0,
    ninf_fx32: fix32 = 5.0,
    nan_fx64: fix64 = 6.0,
    inf_fx64: fix64 = 7.0,
    ninf_fx64: fix64 = 8.0,
    chained_fx: i32 = 9,
    nested: InnerS = InnerS { si: 11, sf: 2.0 },
    last_sx: i32 = 0,
    last_sf: fix32 = 0.0,
}

object ObjCast {
    CastRes {
        nan_fx32: (0.0_f32 / 0.0_f32) as fix32,
        inf_fx32: (1.0_f32 / 0.0_f32) as fix32,
        ninf_fx32: (-1.0_f32 / 0.0_f32) as fix32,
        nan_fx64: (0.0_f64 / 0.0_f64) as fix64,
        inf_fx64: (1.0_f64 / 0.0_f64) as fix64,
        ninf_fx64: (-1.0_f64 / 0.0_f64) as fix64,
        chained_fx: ((0.0_f32 / 0.0_f32) as fix32) as i32,
        nested: InnerS {
            si: (0.0_f32 / 0.0_f32) as i32,
            sf: (1.0_f32 / 0.0_f32) as fix32,
        },
    },
}

sys step_local_struct() {
    let r = query_one(c: &mut CastRes).on(ObjCast).unwrap();
    let mut sv = r.c.nested;
    sv.si = 77;
    sv.sf = 1.5;
    r.c.last_sx = sv.si;
    r.c.last_sf = sv.sf;
}

schedule FixedUpdate { step_local_struct }
"#;
    let mir = compile_strata_to_mir("c99_iter6.strata", src);
    let c_art = emit(&mir).expect("c99 emit");
    let c_src = &c_art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .expect("primary C file")
        .content;
    assert!(
        !c_src.contains("NAN")
            && !c_src.contains("INFINITY")
            && c_src.contains("val_0.nan_fx32 = ((int32_t)0);")
            && c_src.contains("val_0.inf_fx64 = ((int64_t)0ll);")
            && c_src.contains("val_0.chained_fx = ((int32_t)0);")
            && c_src.contains("val_0.nested.sf = ((int32_t)0);")
            && c_src.contains("v_5->si = v_6;"),
        "C99 must fold non-finite fix32/fix64 casts to 0, preserve nested struct fields, and write local struct slot fields safely:\n{c_src}"
    );
    verify_strict_c99_syntax(&c_art, "c99_iter6");
}

#[test]
fn c99_step2_iter7_constructors_nested_array_struct_and_ubsan_fix_casts() {
    let src = r#"
module test::c99_iter7 @version(1.0.0);

enum BitKind {
    A = 0,
    C = 2,
}

struct Inner {
    dist: meters = meters(1.0),
    wait_ms: ms = ms(50.0),
    va: vec3a = vec3a(1.0, 2.0, 3.0),
    q: quat = quat(0.0, 0.0, 0.0, 1.0),
    col: rgba = rgba(0.1, 0.2, 0.3, 1.0),
    mask: u64 = 0,
}

struct Outer {
    items: [Inner; 2] = [Inner {}, Inner {}],
    fx32_as_i32: i32 = 0,
    fx64_neg_trunc: i64 = 0,
    fx32_u32: u32 = 0,
}

component Iter7Pod {
    id: u32 = 1,
    outer: Outer = Outer {},
    rt_sat_fx32_i32: i32 = 0,
    rt_neg_fx32_i32: i32 = 0,
    rt_neg_fx64_i64: i64 = 0,
    rt_pos_fx64_i64: i64 = 0,
    rt_sat_fx64_i64: i64 = 0,
    rt_zero_fx32_i32: i32 = 0,
    rt_s_d_pos: i32 = 0,
}

object ObjIter7 {
    Iter7Pod {
        id: 1,
        outer: Outer {
            items: [
                Inner {
                    dist: meters(7.5),
                    wait_ms: ms(125.0),
                    va: vec3a(4.0, 5.0, 6.0),
                    q: quat(0.0, 1.0, 0.0, 0.0),
                    col: rgba(0.5, 0.25, 0.75, 1.0),
                    mask: bits(BitKind::A, BitKind::C),
                },
                Inner {
                    dist: meters(9.0),
                    wait_ms: ms(250.0),
                    va: vec3a(7.0, 8.0, 9.0),
                    q: quat(0.0, 0.0, 1.0, 0.0),
                    col: rgba(1.0, 1.0, 1.0, 0.5),
                    mask: bits(BitKind::C),
                },
            ],
            fx32_as_i32: (100000.0_f32 as fix32) as i32,
            fx64_neg_trunc: (-2.75_f64 as fix64) as i64,
            fx32_u32: (42.75_f32 as fix32) as u32,
        },
    }
}

@node_pure fn id_f32(v: f32) -> f32 { v }
@node_pure fn id_f64(v: f64) -> f64 { v }

component Dummy { k: i32 = 7 }
object ObjDummy { Dummy { k: 7 } }

sys step_iter7() {
    let r = query_one(p: &mut Iter7Pod).on(ObjIter7).unwrap();
    r.p.rt_sat_fx32_i32 = (id_f32(100000.0_f32) as fix32) as i32;
    r.p.rt_neg_fx32_i32 = (id_f32(-100000.0_f32) as fix32) as i32;
    r.p.rt_neg_fx64_i64 = (id_f64(-2.75_f64) as fix64) as i64;
    r.p.rt_pos_fx64_i64 = (id_f64(2.75_f64) as fix64) as i64;
    r.p.rt_sat_fx64_i64 = (id_f64(1.0e12_f64) as fix64) as i64;
    r.p.rt_zero_fx32_i32 = (id_f32(-0.25_f32) as fix32) as i32;

    let s_d_pos: i32 = 10;
    for s_d_pos in query(s_d_pos: &Dummy.k) {
        let _v = s_d_pos;
    }
    r.p.rt_s_d_pos = s_d_pos + 1;
}

schedule FixedUpdate { step_iter7 }
"#;
    let mir = compile_strata_to_mir("c99_iter7.strata", src);
    let art = emit(&mir).expect("c99 iter7 emit");
    verify_strict_c99_syntax(&art, "c99_iter7");

    let c_src = &art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .expect("primary C file")
        .content;
    assert!(
        c_src.contains("strata_f64_to_fix32(") && c_src.contains("strata_f64_to_fix64("),
        "C99 must route float->fix32/fix64 casts through UBSan-safe strata_f64_to_fix helpers:\n{c_src}"
    );

    // Compile and run under -fsanitize=undefined -fno-sanitize-recover=all to prove C99 §6.3.1.4 UB-safety!
    let tmp = tempfile::tempdir().expect("tempdir");
    for f in &art.files {
        std::fs::write(tmp.path().join(&f.path), &f.content).expect("write generated file");
    }
    let c_file = art.files.iter().find(|f| f.path.ends_with(".c")).unwrap();
    let mut combined = std::fs::read_to_string(tmp.path().join(&c_file.path)).unwrap();
    combined.push_str(
        r#"
int main(void) {
    if (strata_f64_to_fix32(100000.0) != INT32_MAX) return 1;
    if (strata_f64_to_fix32(-100000.0) != INT32_MIN) return 2;
    if ((strata_f64_to_fix32(100000.0) / ((int32_t)65536)) != 32767) return 3;
    if ((strata_f64_to_fix64(-2.75) / ((int64_t)4294967296ll)) != -2) return 4;
    if (strata_f64_to_fix64(1.0e12) != INT64_MAX) return 5;
    if (strata_f64_to_fix64(-1.0e12) != INT64_MIN) return 6;
    if ((strata_f64_to_fix32(-0.25) / ((int32_t)65536)) != 0) return 7;
    if (strata_f64_to_fix32(0.0 / 0.0) != 0) return 8;
    if (strata_f64_to_fix64(1.0 / 0.0) != 0) return 9;
    return 0;
}
"#,
    );
    let driver_path = tmp.path().join("driver_iter7_ubsan.c");
    std::fs::write(&driver_path, &combined).unwrap();
    let bin_path = tmp.path().join("driver_iter7_ubsan");
    let cc = if Command::new("cc").arg("--version").output().is_ok() {
        "cc"
    } else {
        "clang"
    };
    let comp = Command::new(cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fsanitize=undefined",
            "-fno-sanitize-recover=all",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&driver_path)
        .arg("-lm")
        .arg("-o")
        .arg(&bin_path)
        .output()
        .expect("compile C99 UBSan iter7 driver");
    assert!(
        comp.status.success(),
        "C99 iter7 UBSan compile failed:\n{}",
        String::from_utf8_lossy(&comp.stderr)
    );
    let run = Command::new(&bin_path)
        .output()
        .expect("run iter7 UBSan driver");
    assert!(
        run.status.success(),
        "C99 iter7 UBSan driver failed (exit={:?}):\n{}",
        run.status,
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn c99_step2_iter8_native_observer_bitset128_vec3a_and_ubsan_array_fix() {
    let src = r#"
module test::c99_iter8 @version(1.0.0);

struct Sub { x: i32 = 3, fx: fix32 = 1.5 }
const C_SUB: Sub = Sub { x: 7, fx: 2.5 };

component Marker;
component Out {
    id: u32 = 1,
    val: i32 = 10,
    bs128: BitSet<128> = bits(0, 70),
    va: vec3a = vec3a(1.0, 2.0, 3.0),
    sub: Sub = C_SUB,
    arr32: [fix32; 2] = [0.0, 0.0],
    arr64: [fix64; 2] = [0.0, 0.0],
    obs_hits: i32 = 0,
}

event EvPing { entity: Ref<Entity>, inc: i32 }
stream TickStream { v: i32 }

@node_pure fn id_f32(v: f32) -> f32 { v }
@node_pure fn id_f64(v: f64) -> f64 { v }

object ObjIter8 {
    Out {
        id: 1,
        bs128: bits(2, 75),
        va: Vec3a(2.0, 4.0, 6.0),
    },
    Marker,
}

sys step_iter8() {
    for row in query(o: &mut Out) {
        row.o.arr32 = [id_f32(100000.0_f32), id_f32(-0.25_f32)];
        row.o.arr64 = [id_f64(-2.75_f64), id_f64(1.0e12_f64)];
        row.o.bs128 = bits(1, 90);
        trigger(EvPing { entity: row.entity, inc: 5 });
    }
}

obs on_ping(trg: &Trigger<EvPing, Marker>) {
    let opt = query_one(o: &mut Out).on(trg.target);
    if let Some(r) = opt {
        r.o.obs_hits += trg.payload.inc;
    }
    emit(TickStream { v: trg.payload.inc });
}

schedule FixedUpdate { step_iter8 }
"#;
    let mir = compile_strata_to_mir("c99_iter8.strata", src);
    let art = emit(&mir).expect("c99 iter8 emit");
    verify_strict_c99_syntax(&art, "c99_iter8");

    let c_src = &art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .expect("primary C file")
        .content;
    assert!(
        c_src.contains("BamSystemCtx* sys_ctx")
            && c_src.contains("bam_observer_desc_ctx(")
            && c_src.contains(".watched_components =")
            && c_src.contains("sys_commands(sys_ctx,"),
        "C99 observer must emit native BamObserverCtxFn with bam_observer_desc_ctx and sys_ctx:\n{c_src}"
    );
}

#[test]
fn c99_step2_iter9_bits_const_u64_nested_struct_and_bitset_arrays() {
    let src = r#"
module test::c99_iter9_bits @version(1.0.0);

enum BitKind { A = 0, B = 1, C = 2 }

struct BsBox {
    s_bs64: BitSet<64> = bits(BitKind::A, BitKind::C),
    s_bs128: BitSet<128> = bits(1, 33, 70),
    s_u64: u64 = 0,
}

struct BsU64 {
    mask: u64 = 0,
}

const C_MASK: BsU64 = BsU64 { mask: bits(BitKind::A, BitKind::C) };

component BitsPod {
    id: u32 = 0,
    ov_nested: BsBox = BsBox {},
    def_m: BsU64 = C_MASK,
    rt_m: BsU64 = BsU64 {},
    arr64: [BitSet<64>; 2] = [bits(0), bits(1)],
    arr128: [BitSet<128>; 2] = [bits(0, 65), bits(1, 90)],
}

event EvProp { entity: Ref<Entity> }

object ObjBits {
    BitsPod {
        id: 1,
        ov_nested: BsBox {
            s_bs64: bits(BitKind::A, BitKind::B),
            s_bs128: bits(1, 33, 70),
            s_u64: bits(BitKind::B, BitKind::C),
        },
        arr64: [bits(BitKind::B, 35), bits(BitKind::C, 63)],
        arr128: [bits(1, 33, 70), bits(2, 75)],
    },
}

sys step_bits() {
    for row in query(p: &mut BitsPod) {
        row.p.rt_m = C_MASK;
        trigger(EvProp { entity: row.entity }, propagate: true);
    }
}

schedule FixedUpdate { step_bits }
"#;
    let mir = compile_strata_to_mir("c99_iter9_bits.strata", src);
    let art = emit(&mir).expect("c99 iter9 emit");
    verify_strict_c99_syntax(&art, "c99_iter9_bits");

    let c_src = &art
        .files
        .iter()
        .find(|f| f.path.ends_with(".c"))
        .expect("primary C file")
        .content;
    assert!(
        !c_src.contains("uint64_t _ae_"),
        "must not emit scalar uint64_t _ae_* for BitSet array elements:\n{c_src}"
    );
    assert!(
        c_src.contains("BAM_TRIGGER_FLAG_PROPAGATE")
            && !c_src.contains("tdesc.flags = BAM_OBSERVER_FLAG_PROPAGATE"),
        "BamTriggerDesc.flags must use BAM_TRIGGER_FLAG_PROPAGATE"
    );

    // Compile and run under strict C99 + UBSan to verify defaults & bit 70/75 retention!
    let tmp = tempfile::tempdir().expect("tempdir");
    for f in &art.files {
        std::fs::write(tmp.path().join(&f.path), &f.content).expect("write generated file");
    }
    let c_file = art.files.iter().find(|f| f.path.ends_with(".c")).unwrap();
    let mut combined = std::fs::read_to_string(tmp.path().join(&c_file.path)).unwrap();
    let pod_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name.ends_with("BitsPod"))
        .expect("BitsPod layout idx");
    combined.push_str(&format!(
        r#"
int main(void) {{
    StrataType_{pod_idx}_BitsPod d = strata_default_{pod_idx}_BitsPod();
    if (d.def_m.mask != 5ull) return 1;
    if (d.ov_nested.s_bs128[8] != 0x40u) return 2;
    if (d.arr128[0] != 0x01u || d.arr128[8] != 0x02u) return 3;
    if (d.arr128[16] != 0x02u || d.arr128[27] != 0x04u) return 4;
    return 0;
}}
"#
    ));
    let driver_path = tmp.path().join("driver_iter9_ubsan.c");
    std::fs::write(&driver_path, &combined).unwrap();
    let bin_path = tmp.path().join("driver_iter9_ubsan");
    let cc = if Command::new("cc").arg("--version").output().is_ok() {
        "cc"
    } else {
        "clang"
    };
    let comp = Command::new(cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fsanitize=undefined",
            "-fno-sanitize-recover=all",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&driver_path)
        .arg("-lm")
        .arg("-o")
        .arg(&bin_path)
        .output()
        .expect("compile C99 UBSan iter9 driver");
    assert!(
        comp.status.success(),
        "C99 iter9 UBSan compile failed:\n{}",
        String::from_utf8_lossy(&comp.stderr)
    );
    let run = Command::new(&bin_path)
        .output()
        .expect("run iter9 UBSan driver");
    assert!(
        run.status.success(),
        "C99 iter9 UBSan driver failed (exit={:?}):\n{}",
        run.status,
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn c99_step2_iter10_nested_bitset_mat128_and_smallvec_bitset64_ubsan() {
    let src = r#"
module test::c99_iter10_bits @version(1.0.0);

struct MatBox {
    mat128: [[BitSet<128>; 2]; 2] = [[bits(1, 70), bits(2, 90)], [bits(3, 100), bits(4, 127)]],
}

component Iter10Pod {
    id: u32 = 0,
    arr64: [BitSet<64>; 2] = [bits(0), bits(1)],
    arr128: [BitSet<128>; 2] = [bits(0, 65), bits(1, 90)],
    mat_f: [[f32; 3]; 2] = [[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]],
    mat128: [[BitSet<128>; 2]; 2] = [[bits(1, 70), bits(2, 90)], [bits(3, 100), bits(4, 127)]],
    sv_bs64: SmallVec<BitSet<64>, 2>,
    box_mat: MatBox = MatBox {},
}

object ObjIter10 {
    Iter10Pod {
        id: 7,
        mat128: [[bits(5, 72), bits(6, 95)], [bits(7, 105), bits(8, 126)]],
    },
}

sys step_iter10() {
    for row in query(p: &mut Iter10Pod) {
        row.p.id += 1;
    }
}

schedule FixedUpdate { step_iter10 }
"#;
    let mir = compile_strata_to_mir("c99_iter10_bits.strata", src);
    let art = emit(&mir).expect("c99 iter10 emit");
    verify_strict_c99_syntax(&art, "c99_iter10_bits");

    let pod_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name.ends_with("Iter10Pod"))
        .expect("Iter10Pod layout idx");
    let matbox_idx = mir
        .layouts
        .iter()
        .position(|l| l.canonical_name.ends_with("MatBox"))
        .expect("MatBox layout idx");
    assert_eq!(mir.layouts[matbox_idx].size, 64);

    // Also verify EmitCtx::c_const_val_for_ty handles (Ty::Array, MirConstVal::Array) inside StructLit cleanly.
    let ectx = EmitCtx::new(&mir).expect("EmitCtx");
    let mat_const = MirConstVal::Struct {
        name: "MatBox".to_owned(),
        fields: vec![(
            "mat128".to_owned(),
            MirConstVal::Array(vec![
                MirConstVal::Array(vec![
                    MirConstVal::Array(vec![MirConstVal::Int(1), MirConstVal::Int(70)]),
                    MirConstVal::Array(vec![MirConstVal::Int(2), MirConstVal::Int(90)]),
                ]),
                MirConstVal::Array(vec![
                    MirConstVal::Array(vec![MirConstVal::Int(3), MirConstVal::Int(100)]),
                    MirConstVal::Array(vec![MirConstVal::Int(4), MirConstVal::Int(127)]),
                ]),
            ]),
        )],
    };
    let c_lit = ectx.c_const_val_for_ty(&Ty::Named("MatBox".to_owned()), &mat_const);
    assert!(
        !c_lit.contains("{ {"),
        "c_const_val_for_ty must emit flat uint8_t byte-array initializer without double braces: {c_lit}"
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    for f in &art.files {
        std::fs::write(tmp.path().join(&f.path), &f.content).expect("write generated file");
    }
    let c_file = art.files.iter().find(|f| f.path.ends_with(".c")).unwrap();
    let mut combined = std::fs::read_to_string(tmp.path().join(&c_file.path)).unwrap();
    combined.push_str(&format!(
        r#"
int main(void) {{
    StrataType_{pod_idx}_Iter10Pod d = strata_default_{pod_idx}_Iter10Pod();
    if (sizeof(d.arr64) != 16u) return 1;
    if (sizeof(d.arr128) != 32u) return 2;
    if (sizeof(d.mat_f) != 24u) return 3;
    if (sizeof(d.mat128) != 64u) return 4;
    if (sizeof(d.sv_bs64) != 24u) return 5;
    if (d.mat128[0] != 0x02u || d.mat128[8] != 0x40u) return 6;
    if (d.mat128[16] != 0x04u || d.mat128[27] != 0x04u) return 7;
    if (d.mat128[32] != 0x08u || d.mat128[44] != 0x10u) return 8;
    if (d.mat128[48] != 0x10u || d.mat128[63] != 0x80u) return 9;
    StrataType_{matbox_idx}_MatBox lit = {c_lit};
    if (lit.mat128[0] != 0x02u || lit.mat128[8] != 0x40u || lit.mat128[63] != 0x80u) return 10;
    return 0;
}}
"#
    ));
    let driver_path = tmp.path().join("driver_iter10_ubsan.c");
    std::fs::write(&driver_path, &combined).unwrap();
    let bin_path = tmp.path().join("driver_iter10_ubsan");
    let cc = if Command::new("cc").arg("--version").output().is_ok() {
        "cc"
    } else {
        "clang"
    };
    let comp = Command::new(cc)
        .args([
            "-std=c99",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fsanitize=undefined",
            "-fno-sanitize-recover=all",
            "-I",
        ])
        .arg(tmp.path())
        .arg(&driver_path)
        .arg("-lm")
        .arg("-o")
        .arg(&bin_path)
        .output()
        .expect("compile C99 UBSan iter10 driver");
    assert!(
        comp.status.success(),
        "C99 iter10 UBSan compile failed:\n{}",
        String::from_utf8_lossy(&comp.stderr)
    );
    let run = Command::new(&bin_path)
        .output()
        .expect("run iter10 UBSan driver");
    assert!(
        run.status.success(),
        "C99 iter10 UBSan driver failed (exit={:?}):\n{}",
        run.status,
        String::from_utf8_lossy(&run.stderr)
    );
}
