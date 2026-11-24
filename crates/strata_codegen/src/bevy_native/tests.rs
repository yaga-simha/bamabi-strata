use super::emit;
use crate::{BevyNativeOptions, TargetKind};
use strata_mir::{lower_to_mir, verify_mir};
use strata_sema::analyze_source;

/// Verifies Tier 3 `--target bevy-native` emits `#![forbid(unsafe_code)]` and respects
/// `static_console` default feature toggles.
#[test]
fn bevy_native_respects_static_console_feature_flag() {
    let src = "module bn::t @version(1.0.0);\ncomponent Pos { x: f32 = 0.0 }\nsys s() { for e in query(p: &mut Pos) { e.p.x += 1.0; } }\n";
    let sema = analyze_source("bn.strata", src);
    let mir = lower_to_mir(&sema);
    let art = emit(
        &mir,
        &BevyNativeOptions {
            crate_name: "native_console".to_owned(),
            native_rt_path: None,
            static_console: true,
        },
    )
    .expect("emit bevy native");
    assert_eq!(art.target, TargetKind::BevyNative);
    assert!(
        art.files[0]
            .content
            .contains("default = [\"static-console\"]")
    );
    assert!(art.files[1].content.contains("#![forbid(unsafe_code)]"));
}

/// Verifies `field_defaults`, `@par` contiguous iterators, selective `&mut?`, `OptionalRead`,
/// `Observers` (`On<E>`), `EntityEvent`, `MessageWriter`, `SystemSet` chaining, and
/// `SharedBridgeAppExt` wiring across all Tier 3 native constructs.
#[test]
fn bevy_native_emits_full_mir_cfg_observers_par_optional_and_schedules() {
    let src = r#"
module bn::full @version(1.0.0);

resource SimClock { dt: sec = 8.3333_ms }
component Pos { x: f32 = 1.5, y: f32 = 2.5 }
component Vel { vx: f32 = 3.0, vy: f32 = 0.0 }
component Heat @summary_tick { temp: f32 = 10.0, hot: bool = false }
component Blessing { bonus: f32 = 2.0 }
@sparse component Shield { cap: f32 = 50.0 }

event GlobalPulse { amp: f32 }
event HitEntity { entity: Ref<Pos>, dmg: f32 }
stream DigestOut { total: f32 }

fn add_boost(x: f32, b: f32) -> f32 { x + b }

@par(chunk = 256)
sys step(clk: &res SimClock) {
uniform let dt = clk.dt.as_secs();
for r in query(p: &mut Pos, v: &Vel, h: &mut? Heat, b: ?&Blessing) {
    r.p.x += add_boost(r.v.vx, 0.5) * dt;
    if let Some(bl) = r.b {
        r.h.temp += bl.bonus;
        r.h.hot = true;
    }
}
}

sys step_sparse() {
for r in query(p: &mut Pos, s: ?&Shield) {
    if let Some(sh) = r.s {
        r.p.y += sh.cap * 0.01;
    }
}
}

sys emit_digest(mw_dummy: &res SimClock) {
let total = for r in query(h: &Heat.temp) reduce (total: sum(0.0, r.h));
emit(DigestOut { total: total });
}

obs on_global(trg: &Trigger<GlobalPulse>) {
let _a = trg.payload.amp;
}

obs on_hit(trg: &Trigger<HitEntity, Pos>) {
let e = trg.target;
let d = trg.payload.dmg;
let _ = (e, d);
}

schedule FixedUpdate {
seq Frame {
    set Physics { step, step_sparse }
    set Report { emit_digest }
}
}
"#;
    let sema = analyze_source("full.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("MIR must verify");
    let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy native");
    let code = &art.files[1].content;

    // Defaults honored
    assert!(code.contains("0.0083333_f32"));
    assert!(code.contains("1.5_f32"));
    assert!(code.contains("10.0_f32"));

    // Par contiguous + selective + optional + sparse
    assert!(code.contains("strata_contiguous_par_iter_mut()"));
    assert!(code.contains(".iter_mut()"));
    assert!(code.contains("SelectiveMutSlice::from_contiguous_mut"));
    assert!(code.contains("mark_dirty_row("));
    assert!(code.contains("flush_dirty_runs()"));
    assert!(code.contains("Option<&'static"));

    // Observers, EntityEvent, Streams, SharedBridgeAppExt, SystemSets
    assert!(code.contains("On<"));
    assert!(code.contains("#[derive(Clone, Copy, Debug, PartialEq, EntityEvent)]"));
    assert!(code.contains("app.add_observer(strata_obs_on_global)"));
    assert!(code.contains("app.add_observer(strata_obs_on_hit)"));
    assert!(code.contains("MessageWriter<"));
    assert!(code.contains(".write("));
    assert!(code.contains("register_strata_component"));
    assert!(code.contains("register_strata_resource"));
    assert!(code.contains("register_strata_stream"));
    assert!(code.contains("register_strata_event"));
    assert!(code.contains("register_strata_entity_event"));
    assert!(code.contains("StrataSet_Physics"));
    assert!(code.contains(".chain()"));
    assert!(code.contains("strata_fn_add_boost"));
}

/// Verifies `MirFnKind::Observer` with `@par` and `commands.spawn_batch` / `despawn_all` /
/// `MirFnKind::Migration` emit clean safe Bevy-native Rust.
#[test]
fn bevy_native_emits_migrations_spawn_batch_and_named_objects() {
    let src = r#"
module bn::mig @version(2.0.0);

resource SimClock { dt: sec = 16.6667_ms }
component BodyV1 { hp: i32 = 10 }
component Body { hp: f32 = 100.0 }
tag Ephemeral;

object Hero { Body {} }

migrate Body from 1.0.0 to 2.0.0 (old: &BodyV1) -> Body {
Body { hp: old.hp as f32 }
}

sys spawn_wave() {
spawn_batch(10) |i| {
    { Body { hp: (i as f32) + 1.0 }, Ephemeral }
};
}

sys clear_wave() {
despawn_all<With<Ephemeral>>();
if let Some(h) = query_one(b: &mut Body).on(Hero) {
    h.b.hp += 5.0;
}
}
"#;
    let sema = analyze_source("mig.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("MIR must verify");
    let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy native");
    let code = &art.files[1].content;

    assert!(code.contains("pub fn strata_mig_"));
    assert!(code.contains("spawn_batch("));
    assert!(code.contains("despawn_all::<With<StrataTag_Ephemeral_"));
    assert!(code.contains("StrataNamedObjects"));
    assert!(code.contains("strata_init_named_objects"));
}

#[test]
fn bevy_native_emits_paramset_snapshot_primitives_and_zero_unsafe() {
    let src = r#"
module bn::pset @version(1.0.0);

component Actor { alive: bool = true, flags: u32 = 0, hp: f32 = 100.0 }
component Order { target: Ref<Actor>, grace: GraceWindow, buf: InputBuffer<u32, 4> }

sys tick_orders() {
for row in query(o: &mut Order) {
    row.o.grace.arm(0.2);
    row.o.buf.push(1, 0.15);
}
}

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
"#;
    let sema = analyze_source("pset.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("MIR must verify");
    let art = emit(&mir, &BevyNativeOptions::default()).expect("emit");
    let code = &art.files[1].content;

    assert!(code.contains("#![forbid(unsafe_code)]"));
    assert!(!code.contains("unsafe "));
    assert!(code.contains("ParamSet<"));
    assert!(code.contains("_snap: Vec<_>"));
    assert!(code.contains(".get()"));
    assert!(code.contains("if __d > *"));
    assert!(code.contains("strata_input_buf_push"));
}

#[test]
fn bevy_native_emits_indexed_and_unindexed_spawn_batch_and_require() {
    let src = r#"
module bn::sb @version(1.0.0);

resource Cfg { count: u32 = 8 }
component Pos3D { xyz: vec3 = vec3::ZERO }
component Vel3D { dxyz: vec3 = vec3::ZERO }
component Raindrop @require(Pos3D, Vel3D) { elasticity: f32 = 0.65 }
component Item { val: i32 = 0 }
tag Fresh;

sys spawn_indexed(cfg: &res Cfg) effects(spawns: [Raindrop, Pos3D]) {
let n = cfg.count;
spawn_batch(n) |i| {
    let mut e = 0.60;
    if i % 2 == 0 {
        e = 0.75;
    }
    {
        Raindrop { elasticity: e },
        Pos3D { xyz: vec3((i as f32), 2.0, 0.0) },
    }
};
}

sys spawn_unindexed() effects(spawns: [Item, Fresh]) {
spawn_batch(4) |_| {
    let base = 0;
    { Item { val: base + 7 }, Fresh }
};
}
"#;
    let sema = analyze_source("sb.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("MIR must verify");
    let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy native");
    let code = &art.files[1].content;

    assert!(code.contains("#[require("));
    assert!(code.contains("Vec::with_capacity("));
    assert!(code.contains(".push(__batch_row);"));
    assert!(code.contains(".resize_with(__batch_idx + 1, Default::default);"));
    assert!(code.contains("core::mem::take(&mut __batch_buf_0);"));
    assert!(code.contains("commands.spawn_batch(__batch_rows);"));
    assert!(code.contains("commands.spawn_batch((0..(__loc_"));
    assert!(code.contains(".map(move |_| "));
    assert!(!code.contains("move |__batch_i|"));
}

#[test]
fn bevy_native_emits_rain_swarm_and_metroidvania_cookbooks_cleanly() {
    let rain_src = include_str!("../../../../fixtures/cookbooks/01_rain_swarm.strata");
    let rain_sema = analyze_source("01_rain_swarm.strata", rain_src);
    assert!(rain_sema.ok(), "{:?}", rain_sema.diagnostics);
    let rain_mir = lower_to_mir(&rain_sema);
    verify_mir(&rain_mir).expect("01_rain_swarm MIR must verify");
    let rain_art = emit(&rain_mir, &BevyNativeOptions::default()).expect("emit rain_swarm");
    let rain_code = &rain_art.files[1].content;
    assert!(rain_code.contains("#[require("));
    assert!(rain_code.contains("Vec::with_capacity("));
    assert!(rain_code.contains(".push(__batch_row);"));
    assert!(rain_code.contains("commands.spawn_batch(__batch_rows);"));
    assert!(rain_code.contains("strata_contiguous_par_iter_mut()"));

    let mv_src = include_str!("../../../../fixtures/cookbooks/03_metroidvania_core.strata");
    let mv_sema = analyze_source("03_metroidvania_core.strata", mv_src);
    assert!(mv_sema.ok(), "{:?}", mv_sema.diagnostics);
    let mv_mir = lower_to_mir(&mv_sema);
    verify_mir(&mv_mir).expect("03_metroidvania_core MIR must verify");
    let mv_art = emit(&mv_mir, &BevyNativeOptions::default()).expect("emit metroidvania");
    let mv_code = &mv_art.files[1].content;
    assert!(mv_code.contains("#[require("));
    assert!(mv_code.contains("strata_run_if_"));
    assert!(mv_code.contains("StrataLeafSet_strata_timer_tick.before("));
    assert!(mv_code.contains("StrataSet_InputAndTasks"));
    assert!(mv_code.contains(".chain()"));
}

#[test]
fn bevy_native_phase2b_csr_up_cascade_array_store_optional_write_atomic_and_nb123() {
    let src = r#"
module probe::bn_phase2b @version(1.0.0);

component Pos3D { xyz: vec3 = vec3(0.0, 0.0, 0.0) }
component Faction { team: u32 = 0 }
component Shield @summary_tick { hp: f32 = 10.0 }
component ArrComp {
vals: [f32; 3] = [0.0, 0.0, 0.0],
nested: [[bool; 2]; 2] = [[true, false], [false, true]],
}
component DefaultExtra { tag_num: i32 = 99 }
tag Target3D;

object PartialHero {
ArrComp { vals: [5.0, 6.0, 7.0] },
DefaultExtra {},
}

component GridOffset { iv: ivec2 = ivec2(0, 0) }
object OffsetObj {
GridOffset { iv: ivec2(-1, -2) },
}

spatial_history HistXZ(
frames:    4,
cell_size: 4.0_m,
bounds:    vec2(-20.0_m, -20.0_m)..vec2(20.0_m, 20.0_m),
capacity:  16,
) over Target3D by Pos3D.xyz;

sys opt_sel_sys() {
for row in query(sh: Option<&mut Shield>) {
    if row.sh.is_some() {
        row.sh.unwrap().hp += 1.0;
    }
}
}

sys ops(h: &res HistXZ) {
let mut loc_arr: [i32; 2] = [10, 20];
loc_arr[0] = 30;
for row in query(a: &mut ArrComp, sh: Option<&mut? Shield>, fac: &Faction).up<ChildOf>() {
    row.a.vals[1] = (loc_arr[0] as f32);
    if row.sh.is_some() {
        atomic {
            row.sh.unwrap().hp += 5.0;
            require_true(row.fac.team == 1);
        }
    }
}
for hit in h.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(8.0, 0.0, 8.0), 2.0_m) {
    let _e = hit.id;
}
}

schedule FixedUpdate { opt_sel_sys, ops }
"#;
    let sema = analyze_source("bn_phase2b.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("bn_phase2b MIR must verify");
    let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy_native phase2b");
    let code = &art.files[1].content;

    assert!(
        code.contains("pub plane_axes: [usize; 2]"),
        "CSR backing must track plane_axes"
    );
    assert!(
        code.contains("plane_axes: [0, 2]"),
        "3D XZ spatial index must use [0, 2] plane axes"
    );
    assert!(code.contains("pub fn csr_begin(") && code.contains("pub fn csr_scatter("));
    assert!(
        code.contains("up_child_of_q: Query<&ChildOf>"),
        "IterUpCascade must query ChildOf"
    );
    assert!(
        code.contains("__up_ent_") && code.contains("__up_flag_"),
        "missing IterUpCascade slot propagation"
    );
    assert!(
        code.contains("SelectiveMutSlice::from_contiguous_mut"),
        "OptionalWrite selective slice missing:\n{code}"
    );
    assert!(
        code.contains("if __tx_active {"),
        "atomic selective dirty guard missing:\n{code}"
    );
    assert!(
        code.contains("[-1i32, -2i32]"),
        "NB-1 ivec2(-1, -2) must preserve negative signs:\n{code}"
    );
    assert!(
        code.contains("DefaultExtra_") && code.contains("StrataDefaultExtra_4::default()"),
        "NB-3 partial object override must emit un-overridden component:\n{code}"
    );
}

#[test]
fn bevy_native_seq_with_multiple_spatial_indices_avoids_schedule_cycle() {
    let src = r#"
module probe::bn_spatial_seq @version(1.0.0);

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
    for _hit in g.query_disc(vec2(0.0, 0.0), 8.0_m) {
        c += 1;
    }
    out.d_hits = c;
}

sys scan_hist(h: &res Hist3D, out: &mut res Probe) {
    let mut c: u32 = 0;
    for _hit in h.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(4.0, 0.0, 4.0), 2.0_m) {
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
    let sema = analyze_source("bn_spatial_seq.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("bn_spatial_seq MIR must verify");
    let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy_native");
    let code = &art.files[1].content;

    assert!(
        code.contains("StrataLeafSet_Grid2D__rebuild_csr.before(StrataLeafSet_scan_grid)"),
        "Grid2D rebuild must precede scan_grid:\n{code}"
    );
    assert!(
        code.contains("StrataLeafSet_Hist3D__rebuild_csr.before(StrataLeafSet_scan_hist)"),
        "Hist3D rebuild must precede scan_hist:\n{code}"
    );
    assert!(
        !code.contains("StrataLeafSet_Hist3D__rebuild_csr.before(StrataLeafSet_pre_move)"),
        "Hist3D rebuild must NOT emit .before(pre_move), which would cycle with seq:\n{code}"
    );
    assert!(
        !code.contains("StrataLeafSet_Hist3D__rebuild_csr.before(StrataLeafSet_scan_grid)"),
        "Hist3D rebuild must NOT emit .before(scan_grid), which would cycle with seq:\n{code}"
    );
    assert!(
        !code.contains("StrataLeafSet_Grid2D__rebuild_csr.before(StrataLeafSet_pre_move)"),
        "Grid2D rebuild must NOT emit .before(pre_move), which would cycle with seq:\n{code}"
    );
}

#[test]
fn bevy_native_emits_named_object_array_field_overrides_and_nested_arrays() {
    let src = r#"
module probe::bn_obj_arrays @version(1.0.0);

struct Pair { a: i32 = 1, b: f32 = 2.0 }

const WEIGHTS: [f32; 3] = [1.0, 2.5, 3.0];

component ArrayBox {
    f_arr: [f32; 3] = [0.0, 0.0, 0.0],
    fx_arr: [fix64; 3] = [1.0, 2.0, 3.0],
    fx_mix: [fix64; 3] = [0.0, 0.0, 0.0],
    i_to_f: [f32; 3] = [0.0, 0.0, 0.0],
    mat: [[f32; 2]; 2] = [[0.0, 0.0], [0.0, 0.0]],
    flags: [bool; 3] = [false, false, false],
    pairs: [Pair; 2] = [Pair { a: 1, b: 2.0 }, Pair { a: 1, b: 2.0 }],
}

object ArrObj {
    ArrayBox {
        f_arr: [5.0, 6.0, 7.0],
        fx_arr: [5.0, 6.0, 7.0],
        fx_mix: [1, -2.5, 3],
        i_to_f: [5, 6, 7],
        mat: [[1, 2.5], [3.5, -4]],
        flags: [true, false, true],
        pairs: [Pair { a: 7, b: -1.5 }, Pair { a: 9, b: 4.25 }],
    },
}
"#;
    let sema = analyze_source("bn_obj_arrays.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("bn_obj_arrays MIR must verify");
    let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy_native");
    let code = &art.files[1].content;

    assert!(
        code.contains("pub const STRATA_CONST_WEIGHTS: [f32; 3] = [1.0_f32, 2.5_f32, 3.0_f32];"),
        "const array missing:\n{code}"
    );
    assert!(
        code.contains("f_arr: [5.0_f32, 6.0_f32, 7.0_f32]"),
        "f_arr override missing:\n{code}"
    );
    assert!(
        code.contains("fx_arr: { let __src_0 = [Fixed64(21474836480i64), Fixed64(25769803776i64), Fixed64(30064771072i64)];")
            && code.contains("__out_0[__i_0] = (__ael_0).0;"),
        "fx_arr fix64 override missing:\n{code}"
    );
    assert!(
        code.contains("fx_mix: { let __src_0 = [Fixed64(4294967296i64), Fixed64(-10737418240i64), Fixed64(12884901888i64)];"),
        "fx_mix mixed-cast fix64 override missing:\n{code}"
    );
    assert!(
        code.contains("i_to_f: [5 as f32, 6 as f32, 7 as f32]"),
        "i_to_f override missing:\n{code}"
    );
    assert!(
        code.contains("mat: [[1 as f32, 2.5_f32], [3.5_f32, (-(4 as f32))]]"),
        "2D nested array override missing:\n{code}"
    );
    assert!(
        code.contains("flags: { let __src_0 = [true, false, true];")
            && code.contains("FfiBool::from_bool(__ael_0)"),
        "bool array override missing:\n{code}"
    );
    assert!(
        code.contains("StrataPair_0 { a: 7 as i32, b: (-(1.5_f32)) }")
            && code.contains("StrataPair_0 { a: 9 as i32, b: 4.25_f32 }")
            && code.contains("(__ael_0).strata_to_u32_words()"),
        "struct array override missing:\n{code}"
    );
}

#[test]
fn bevy_native_const_struct_and_object_ivec_cast_binops_and_unit_consts() {
    let src = r#"
module probe::bn_const_ivec @version(1.0.0);

struct Inner {
    x: i32 = 10,
    y: u32 = 20,
}

const C_INNER: Inner = Inner { x: 1, y: 2 };
const C_PARTIAL: Inner = Inner { x: 55 };
const V_IV2_ONE: ivec2 = ivec2::ONE;
const V_IV3_X: ivec3 = ivec3::X;
const V_UV2_Y: uvec2 = uvec2::Y;

component BoxComp {
    c_in: Inner = Inner { x: 0, y: 0 },
    uv_cast: uvec2 = uvec2(0, 0),
    iv_bin: ivec2 = ivec2(0, 0),
    cast_fix: fix64 = 0.0,
}

object ObjBox {
    BoxComp {
        c_in: C_PARTIAL,
        uv_cast: uvec2((-1_i32) as u32, (-(-5)) as u32),
        iv_bin: ivec2(-2147483647 - 1, 2147483647),
        cast_fix: 3.9_f32 as i32,
    },
}
"#;
    let sema = analyze_source("bn_const_ivec.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("bn_const_ivec MIR must verify");
    let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy_native");
    let code = &art.files[1].content;

    assert!(
        code.contains("pub const STRATA_CONST_C_INNER: StrataInner_0 = StrataInner_0 { x: 1 as i32, y: 2 as u32 };"),
        "pub const struct must emit explicit fields without Default::default():\n{code}"
    );
    assert!(
        code.contains("pub const STRATA_CONST_C_PARTIAL: StrataInner_0 = StrataInner_0 { x: 55 as i32, y: 20 as u32 };"),
        "partial pub const struct must fill explicit field defaults without Default::default():\n{code}"
    );
    assert!(
        !code.contains("pub const STRATA_CONST_C_INNER: StrataInner_0 = StrataInner_0 { x: 1 as i32, y: 2 as u32, ..Default::default() }"),
        "must not emit ..Default::default() inside pub const:\n{code}"
    );
    assert!(
        code.contains("pub const STRATA_CONST_V_IV2_ONE: [i32; 2] = [1i32, 1i32];")
            && code.contains("pub const STRATA_CONST_V_IV3_X: [i32; 3] = [1i32, 0i32, 0i32];")
            && code.contains("pub const STRATA_CONST_V_UV2_Y: [u32; 2] = [0u32, 1u32];"),
        "ivec2::ONE / ivec3::X / uvec2::Y static constants missing:\n{code}"
    );
    assert!(
        code.contains("uv_cast: [4294967295u32, 5u32]"),
        "uvec2((-1_i32) as u32, (-(-5)) as u32) must evaluate accurately instead of 0:\n{code}"
    );
    assert!(
        code.contains("iv_bin: [-2147483648i32, 2147483647i32]"),
        "ivec2(-2147483647 - 1, 2147483647) must evaluate accurately instead of 0:\n{code}"
    );
    assert!(
        code.contains("cast_fix: (Fixed64(((((3.9_f32) as i32) as i64) << 32))).0"),
        "cast_fix must preserve 3.9_f32 as i32 truncation to 3.0:\n{code}"
    );
}

#[test]
fn bevy_native_step2_iter3_enum16_neg_float_casts_iflet_scope_and_option_alias() {
    let src = r#"
module test::bn_iter3 @version(1.0.0);

tag Tag;

enum Kind16 {
    Low = 1,
    High = 60000,
}

component OtherComp {
    pad: i32 = 123,
    hp: f32 = 55.0,
}

component BoxBn {
    k16: Kind16 = Kind16::Low,
    arr16: [Kind16; 2] = [Kind16::Low, Kind16::High],
    neg_i32: i32 = 0,
    neg_u32: u32 = 99,
    v4_w: vec4 = vec4::W,
    shadow_iflet: i32 = 0,
}

object ObjBn {
    BoxBn {
        k16: Kind16::High,
        arr16: [Kind16::High, Kind16::Low],
        neg_i32: (-3.9_f32) as i32,
        neg_u32: (-3.9_f32) as u32,
        v4_w: vec4::W,
    },
}

sys step_iter3_iflet() {
    for row in query(b: &mut BoxBn, oc: Option<&mut OtherComp>) {
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
    let sema = analyze_source("bn_iter3.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("bn_iter3 MIR must verify");
    let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy_native");
    let code = &art.files[1].content;

    assert!(
        code.contains("pub const High: u16 = 60000 as u16;") && !code.contains("60000 as u8"),
        "BevyNative Kind16 must emit u16 constants instead of u8:\n{code}"
    );
    assert!(
        code.contains("[0.0_f32, 0.0_f32, 0.0_f32, 1.0_f32]"),
        "BevyNative must support vec4::W:\n{code}"
    );
}

#[test]
fn bevy_native_step2_iter4_signed_enums_row_alias_and_query_one_unwrap() {
    let src = r#"
module test::bn_iter4 @version(1.0.0);

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

component BoxBn {
    neg_a: NegAuto = NegAuto::Neg,
    neg_e: NegExplicit = NegExplicit::MinNeg,
    arr_neg: [NegAuto; 2] = [NegAuto::Neg, NegAuto::Pos],
    alias_sum: i32 = 0,
}

component Wallet1 { coins: i32 = 100 }

object ObjBn {
    BoxBn {
        neg_a: NegAuto::Pos,
        neg_e: NegExplicit::MinNeg,
        arr_neg: [NegAuto::Pos, NegAuto::Neg],
    },
}

object ObjW1 { Wallet1 { coins: 100 } }

sys step_iter4_iflet() {
    for row in query(b: &mut BoxBn) {
        let row2 = row;
        row2.b.alias_sum += 10;
    }
    if let Some(wrow) = query_one(w: &mut Wallet1).on(ObjW1) {
        let wrow2 = wrow;
        wrow2.w.coins += 10;
    }
}

sys step_iter4_unwrap() {
    let r1 = query_one(w: &mut Wallet1).on(ObjW1).unwrap();
    let r1b = r1;
    r1b.w.coins += 5;
}

sys step_iter4_expect() {
    let r2 = query_one(w: &mut Wallet1).on(ObjW1).expect("w1");
    r2.w.coins += 7;
}

sys step_iter4_match() {
    match query_one(w: &mut Wallet1).on(ObjW1) {
        Some(mr) => { mr.w.coins += 3; },
        None => {},
    }
}

schedule Update {
    seq OrderedAll { step_iter4_iflet, step_iter4_unwrap, step_iter4_expect, step_iter4_match }
}
"#;
    let sema = analyze_source("bn_iter4.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("bn_iter4 MIR must verify");
    let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy_native");
    let code = &art.files[1].content;

    assert!(
        code.contains("pub const Neg: i32 = (-5i64) as i32;")
            && code.contains("pub const MinNeg: i32 = (-300i64) as i32;")
            && code.contains("pub neg_a: i32")
            && code.contains("pub neg_e: i32")
            && code.contains("pub arr_neg: [i32; 2]"),
        "BevyNative signed enums must emit i32 constants, fields, and arrays:\n{code}"
    );
    assert!(
        !code.contains("-5 as u32") && !code.contains("-300 as u32"),
        "BevyNative must not emit negative literals cast to u32:\n{code}"
    );
}

#[test]
fn bevy_native_step2_iter5_object_override_non_finite_float_casts() {
    let src = r#"
module test::bn_iter5 @version(1.0.0);

component CastRes {
    ov_nan_i8: i8 = 11,
    ov_nan_i16: i16 = 22,
    ov_nan_i32: i32 = 33,
    ov_nan_i64: i64 = 44,
    ov_inf_i32: i32 = 55,
    ov_ninf_i8: i8 = 66,
    ov_inf_u8: u8 = 77,
    ov_nan_f32: f32 = 1.0_f32,
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
        ov_nan_f32: 0.0_f32 / 0.0_f32,
    },
}
"#;
    let sema = analyze_source("bn_iter5.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("bn_iter5 MIR must verify");
    let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy_native");
    let code = &art.files[1].content;
    assert!(
        code.contains("as i8")
            && code.contains("as i16")
            && code.contains("as i32")
            && code.contains("as i64")
            && code.contains("as u8"),
        "BevyNative must emit saturating non-finite float-to-int casts:\n{code}"
    );
}

#[test]
fn bevy_native_step2_iter6_non_finite_ivec_and_local_struct_write() {
    let src = r#"
module test::bn_iter6 @version(1.0.0);

struct InnerS {
    si: i32 = 11,
    sf: fix32 = 2.0,
}

component CastRes {
    iv: ivec2 = ivec2(5, 6),
    uv: uvec2 = uvec2(7, 8),
    nested: InnerS = InnerS { si: 11, sf: 2.0 },
    last_sx: i32 = 0,
}

object ObjCast {
    CastRes {
        iv: ivec2((0.0_f32 / 0.0_f32) as i32, (1.0_f32 / 0.0_f32) as i32),
        uv: uvec2((1.0_f32 / 0.0_f32) as u32, (-1.0_f32 / 0.0_f32) as u32),
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
    r.c.last_sx = sv.si;
}

schedule FixedUpdate { step_local_struct }
"#;
    let sema = analyze_source("bn_iter6.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("bn_iter6 MIR must verify");
    let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy_native");
    let code = &art.files[1].content;
    assert!(
        code.contains("[0i32, 2147483647i32]") && code.contains("[4294967295u32, 0u32]"),
        "BevyNative must evaluate non-finite float divisions inside ivec2/uvec2 object overrides:\n{code}"
    );
    assert!(
        code.contains("(&mut __slot_") && code.contains(".si ="),
        "BevyNative must emit direct mutable slot field write for `sv.si = 77`:\n{code}"
    );
}

#[test]
fn bevy_native_step2_iter7_constructors_fix_truncation_opt_row_and_loop_scope() {
    let src = r#"
module test::bn_iter7 @version(1.0.0);

enum BitKind { A = 0, C = 2 }

struct Inner {
    d: meters = meters(1.0),
    t: ms = ms(10.0),
    va: vec3a = vec3a(1.0, 2.0, 3.0),
    q: quat = quat(0.0, 0.0, 0.0, 1.0),
    col: rgba = rgba(0.1, 0.2, 0.3, 1.0),
    mask: u64 = 0,
}

component ResPod {
    id: u32 = 1,
    inner: Inner = Inner {},
    const_sat: i32 = (100000.0_f32 as fix32) as i32,
    const_neg: i64 = (-2.75_f64 as fix64) as i64,
    rt_neg: i64 = 0,
    s_d_pos: i32 = 0,
    opt_val: i32 = 0,
}

object ObjIter7 {
    ResPod {
        id: 1,
        inner: Inner {
            d: meters(6.5),
            t: ms(75.0),
            va: Vec3a(3.0, 4.0, 5.0),
            q: Quat(0.0, 1.0, 0.0, 0.0),
            col: Rgba(0.5, 0.25, 0.75, 1.0),
            mask: bits(BitKind::A, BitKind::C),
        },
    }
}

@node_pure fn id_f64(v: f64) -> f64 { v }

component Dummy { k: i32 = 7 }
object ObjDummy { Dummy { k: 7 } }

sys step_iter7() {
    let opt_r = query_one(p: &mut ResPod).on(ObjIter7);
    if let Some(r) = opt_r {
        r.p.rt_neg = (id_f64(-2.75_f64) as fix64) as i64;
        r.p.opt_val = 99;
    }
    let s_d_pos: i32 = 10;
    for s_d_pos in query(s_d_pos: &Dummy.k) {
        let _x = s_d_pos;
    }
    let r2 = opt_r.unwrap();
    r2.p.s_d_pos = s_d_pos + 1;
}

schedule FixedUpdate { step_iter7 }
"#;
    let sema = analyze_source("bn_iter7.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("bn_iter7 MIR must verify");
    let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy_native iter7");
    let code = &art.files[1].content;
    assert!(
        code.contains("32767 as i32") && code.contains("-2i64") && code.contains("/ 4294967296i64"),
        "BevyNative must unify fix32/fix64 -> int casts (truncating toward zero):\n{code}"
    );
    assert!(
        !code
            .split("9 =>")
            .nth(1)
            .unwrap_or("")
            .contains("__q1_col_0")
            && code.contains("__ent_comp.s_d_pos ="),
        "BevyNative `s_d_pos` after query loop must not reference leaked query column local:\n{code}"
    );
}

#[test]
fn bevy_native_step2_iter8_unsigned_neg_bitset128_vec3a_const_fix_and_helper_ref() {
    let src = r#"
module test::bn_iter8 @version(1.0.0);

struct Sub { x: i32 = 3, fx: fix32 = 1.5 }
const C_SUB: Sub = Sub { x: 7, fx: 2.5 };
const C_FX: fix32 = (1.5_f32 + 0.5_f32) as fix32;
const C_U8: u8 = (-1) as u8;
const C_U64: u64 = (-1) as u64;

component Out {
    u_neg8: u8 = (-1) as u8,
    u_neg64: u64 = (-1) as u64,
    bs128: BitSet<128> = bits(0, 70),
    va: vec3a = vec3a(1.0, 2.0, 3.0),
    sub: Sub = C_SUB,
    fx_c: fix32 = C_FX,
    val: i32 = 10,
}

fn touch_out(h: &mut Out, delta: i32) {
    h.val += delta;
}

sys step_iter8() {
    for q1 in query(o: &mut Out) {
        touch_out(q1.o, 5);
        q1.o.bs128 = bits(1, 80);
        q1.o.va = Vec3a(4.0, 5.0, 6.0);
        let _u8 = C_U8;
        let _u64 = C_U64;
    }
}

schedule FixedUpdate { step_iter8 }
"#;
    let sema = analyze_source("bn_iter8.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    verify_mir(&mir).expect("bn_iter8 MIR must verify");
    let art = emit(&mir, &BevyNativeOptions::default()).expect("emit bevy_native iter8");
    let code = &art.files[1].content;
    assert!(
        !code.contains("-1 as u8") && !code.contains("-1 as u64"),
        "BevyNative must not emit `-1 as u8`/`-1 as u64` (E0600):\n{code}"
    );
    assert!(
        code.contains("strata_fn_touch_out(") && !code.contains("strata_fn_touch_out((&mut __loc_"),
        "BevyNative must borrow component place directly instead of `(&mut __loc_...)`:\n{code}"
    );
    assert!(
        code.contains("[f32; 4]") && !code.contains("Fixed32::from_f32((1.5"),
        "BevyNative must emit 4-lane vec3a and const-safe Fixed32:\n{code}"
    );
}
