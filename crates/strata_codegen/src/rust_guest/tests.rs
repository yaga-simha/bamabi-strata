use super::*;
use strata_mir::lower_to_mir;
use strata_sema::analyze_source;

#[test]
fn rust_guest_emits_zero_unsafe_typed_query_and_resource_bind() {
    let src = r#"
module test::rain @version(1.0.0);

resource SimClock { dt: f32 = 0.0083333, elapsed: f32 = 0.0 }
component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component Vel { vx: f32 = 0.0, vy: f32 = -9.8 }

sys integrate(clk: &res SimClock) {
uniform let dt = clk.dt;
for r in query(pos: &mut Pos, vel: &Vel) {
    r.pos.x += r.vel.vx * dt;
    r.pos.y += r.vel.vy * dt;
}
}

schedule FixedUpdate { integrate }
"#;
    let sema = analyze_source("rain.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    let art = emit(
        &mir,
        &RustGuestOptions {
            crate_name: "rain_guest".to_owned(),
        },
    )
    .expect("emit rust guest");

    assert!(art.files[0].content.contains("branch = \"main\""));
    assert!(!art.files[0].content.contains("rev ="));
    assert!(!art.files[0].content.contains("bevy"));
    let lib = &art.files[1].content;
    assert!(lib.contains("#![forbid(unsafe_code)]"));
    assert!(!lib.contains("unsafe "));
    assert!(lib.contains("export_mod!(plugin: StrataGuestMod);"));
    assert!(lib.contains("resource_read"));
    assert!(lib.contains("0.0083333f32"));
    assert!(lib.contains("register_handle"));
    assert!(lib.contains("mount_system"));
}

#[test]
fn rust_guest_emits_selective_untracked_and_dirty_range() {
    let src = r#"
module test::selective @version(1.0.0);

component Hull @summary_tick { hp: f32 = 100.0, heat: f32 = 0.0 }

sys cool_drones() {
for d in query(hp: &mut? Hull.hp, heat: &mut? Hull.heat) {
    if d.heat > 0.0 {
        d.heat -= 1.0;
    }
}
}
"#;
    let sema = analyze_source("selective.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    let art = emit(&mir, &RustGuestOptions::default()).expect("emit");
    let lib = &art.files[1].content;
    assert!(lib.contains("mutable_slice_untracked"));
    assert!(lib.contains("mark_changed_range"));
    assert!(lib.contains("100.0f32"));
}

#[test]
fn rust_guest_emits_migration_observer_relations_and_schedule_sets() {
    let src = r#"
module test::full_features @version(2.0.0);

component HealthV1 { hp: f32 = 50.0 }
component Health { hp: f64 = 100.0, armor: i32 = 5 }
event Hit { amount: f32 = 10.0 }
relation Ally [symmetric];
tag BossTag;

migrate Health from 1.0.0 to 2.0.0 (old: &HealthV1) -> Health {
Health { hp: (old.hp as f64) * 2.0, armor: 10 }
}

fn add_bonus(h: &mut Health, bonus: f64) {
h.hp += bonus;
}

sys step_health() {
for e in query(h: &mut Health).with<BossTag>() {
    add_bonus(e.h, 1.0);
}
}

obs on_hit(trg: &Trigger<Hit>) {
let _amt = trg.amount;
}

schedule FixedUpdate {
seq main_phase {
    step_health
}
}
"#;
    let sema = analyze_source("full.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    let art = emit(&mir, &RustGuestOptions::default()).expect("emit");
    let lib = &art.files[1].content;
    assert!(lib.contains("migrate_pod_component_column"));
    assert!(lib.contains("0u64,"));
    assert!(lib.contains("observe_event"));
    assert!(lib.contains("build_with_ctx"));
    assert!(lib.contains("register_relation"));
    assert!(lib.contains(".symmetric()"));
    assert!(lib.contains("ScheduleSetBuilder::new(\"sched_"));
    assert!(lib.contains("configure_schedule_set"));
    assert!(lib.contains("mount_system"));
    assert!(lib.contains("strata_helper_add_bonus"));
}

#[test]
fn rust_guest_emits_sparse_optional_par_commands_atomic_and_named_objects() {
    let src = r#"
module test::rich @version(1.0.0);

component Body { hp: f32 = 80.0 }
@sparse component Buff { mult: f32 = 1.5 }
tag Alive;
tag Transient;

object Hero { Body {}, Alive {} }

@par(read_only, chunk = 64)
sys audit_and_tx() {
let total = for b in query(body: &Body.hp) reduce (sum: sum(0.0, b.body));
let _ = total;
}

sys spawn_and_check() {
atomic {
    let e = spawn { Body { hp: 10.0 }, Transient };
    require_true(e != Hero);
} on_rollback {
    despawn_all<With<Transient>>();
}
for r in query(body: &mut? Body, buff: &mut? Buff, opt: Option<&Alive>) {
    if r.opt.is_some() {
        r.body.hp += 1.0;
    }
}
}
"#;
    let sema = analyze_source("rich.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    let art = emit(&mir, &RustGuestOptions::default()).expect("emit");
    let lib = &art.files[1].content;
    assert!(lib.contains("par_chunks_readonly"));
    assert!(lib.contains("component_rows_mut"));
    assert!(lib.contains("strata_opt_present"));
    assert!(lib.contains("checkpoint()"));
    assert!(lib.contains("rollback("));
    assert!(lib.contains("despawn_all("));
    assert!(lib.contains("__strata_named_objects_startup"));
    assert!(lib.contains("bind_named_object"));
}

#[test]
fn rust_guest_cookbooks_emit_wire_compatible_run_if_mod_res_bare_names_and_batch() {
    let rain_src = include_str!("../../../../fixtures/cookbooks/01_rain_swarm.strata");
    let rain_sema = analyze_source("01_rain_swarm.strata", rain_src);
    assert!(rain_sema.ok(), "{:?}", rain_sema.diagnostics);
    let rain_mir = lower_to_mir(&rain_sema);
    let rain_art = emit(&rain_mir, &RustGuestOptions::default()).expect("emit rain");
    let rain_lib = &rain_art.files[1].content;
    assert!(rain_lib.contains("BAM_STORAGE_FLAG_RESOURCE"));
    assert!(rain_lib.contains("is_host_res_"));
    assert!(rain_lib.contains("mod_res_"));
    assert!(rain_lib.contains("StrataBatchBuf::new"));
    assert!(rain_lib.contains("SpawnBatchColumn"));
    assert!(rain_lib.contains("spawn_batches"));
    assert!(
        !rain_lib
            .lines()
            .any(|l| l.contains("register_dynamic_component::<") && l.contains("SimClock")),
        "mod-owned SimClock must never call register_dynamic_component"
    );

    let mv_src = include_str!("../../../../fixtures/cookbooks/03_metroidvania_core.strata");
    let mv_sema = analyze_source("03_metroidvania_core.strata", mv_src);
    assert!(mv_sema.ok(), "{:?}", mv_sema.diagnostics);
    let mv_mir = lower_to_mir(&mv_sema);
    let mv_art = emit(&mv_mir, &RustGuestOptions::default()).expect("emit metroidvania");
    let mv_lib = &mv_art.files[1].content;
    assert!(mv_lib.contains(".run_if_fn("));
    assert!(!mv_lib.contains(".run_if_with("));
    assert!(mv_lib.contains(".query("));
    assert!(mv_lib.contains("with_custom_bytes"));
    for line in mv_lib.lines() {
        let trimmed = line.trim();
        if (trimmed.contains("app.system(c\"") || trimmed.contains("ScheduleSetBuilder::new(\""))
            && let Some((_, rest)) = trimmed.split_once('"')
            && let Some((name, _)) = rest.split_once('"')
        {
            assert!(
                !name.contains("::"),
                "system/schedule set name must be bare: {name}"
            );
        }
    }
}

#[test]
fn rust_guest_fast_path_emits_typed_slices_par_and_selective_write() {
    let src = r#"
module bench::sim @version(1.0.0);

resource SimParam { dt: f32 = 0.016, damp: f32 = 0.995 }
component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component Vel { vx: f32 = 0.0, vy: f32 = 0.0 }
component Heat @summary_tick { temp: f32 = 0.0, hot: bool = false }

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

sys step_sim(p: &res SimParam) {
uniform let dt = p.dt;
uniform let damp = p.damp;
for e in query(pos: &mut Pos, vel: &mut Vel, heat: &mut? Heat) {
    e.vel.vx *= damp;
    e.vel.vy -= 9.81 * dt;
    e.pos.x += e.vel.vx * dt;
    e.pos.y += e.vel.vy * dt;
    if e.pos.y < 0.0 {
        e.pos.y = 0.0;
        e.vel.vy = -e.vel.vy * 0.8;
        e.heat.temp += 1.0;
        e.heat.hot = true;
    }
}
}

schedule FixedUpdate { step_par, scan_ro, step_sim }
"#;
    let sema = analyze_source("fast_path.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    let art = emit(&mir, &RustGuestOptions::default()).expect("emit");
    let lib = &art.files[1].content;
    assert!(
        !lib.contains("vec![StrataVal::Unit"),
        "entry block must not heap-allocate Vec<StrataVal>"
    );
    assert!(
        lib.contains("query_typed::<"),
        "fast path must emit sys_ctx.query_typed::<...>"
    );
    assert!(
        lib.contains(".par_for_each("),
        "step_par must emit TypedChunkIter::par_for_each"
    );
    assert!(
        lib.contains(".par_for_each_chunk_readonly("),
        "scan_ro must emit TypedChunkIter::par_for_each_chunk_readonly"
    );
    assert!(
        lib.contains("component_write_2::<"),
        "step_sim must emit Chunk::component_write_2, got step_sim:\n{}",
        lib.split("fn strata_sys_fn_2_step_sim(")
            .nth(1)
            .unwrap_or("")
            .split("\nfn ")
            .next()
            .unwrap_or("")
    );
    assert!(
        lib.contains("mutable_slice_untracked("),
        "step_sim must emit Chunk::mutable_slice_untracked"
    );
    assert!(
        lib.contains("mark_changed_range("),
        "step_sim must emit Chunk::mark_changed_range"
    );
    let fn_start = lib
        .find("fn strata_sys_fn_2_step_sim(")
        .expect("strata_sys_fn_2_step_sim");
    let fn_end = lib[fn_start..]
        .find("\nfn ")
        .map_or(lib.len(), |o| fn_start + o);
    let step_sim_fn = &lib[fn_start..fn_end];
    let step_sim_loop = step_sim_fn
        .split("next_chunk_view()")
        .nth(1)
        .expect("step_sim fast chunk loop");
    assert!(
        !step_sim_loop.contains("strata_val_or_ptr_read"),
        "step_sim fast path loop must not call strata_val_or_ptr_read:\n{step_sim_loop}"
    );
    assert!(
        !step_sim_loop.contains("strata_ptr_write"),
        "step_sim fast path loop must not call strata_ptr_write:\n{step_sim_loop}"
    );
}

#[test]
fn rust_guest_fixes_par_reduce_det_break_return_f64_u32_and_arrays() {
    let src = r#"
module test::r2_regressions @version(1.0.0);

component Pos { x: f32 = 0.0, y: f32 = 0.0 }
component F64Val { v: f64 = 1.0 }
component Flags { mask: u32 = 0, out_v: u32 = 0 }
component RichArr { flags: [bool; 4] = [false, false, false, false] }
resource SimOut { total: f32 = 0.0 }

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
f64_intrinsics,
u32_unsigned,
bool_array_field
}
"#;
    let sema = analyze_source("r2_regressions.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    let art = emit(&mir, &RustGuestOptions::default()).expect("emit");
    let lib = &art.files[1].content;

    // 1. Arc<Mutex<...>> clone for parallel reduce
    assert!(lib.contains("Arc::new(Mutex::new("));
    assert!(lib.contains("Arc::clone(&__par_red)"));

    // 2. par_det_acc / par_early_ret / par_break must NOT emit par_chunks* or par_for_each*
    for fn_name in ["par_det_acc", "par_early_ret", "par_break"] {
        let body = lib
            .split("fn strata_sys_fn_")
            .find(|s| s.contains(fn_name))
            .unwrap_or_else(|| panic!("missing function for {fn_name}"));
        let fn_body = body.split("\nfn ").next().unwrap_or(body);
        assert!(
            !fn_body.contains("par_chunks") && !fn_body.contains("par_for_each"),
            "{fn_name} must execute sequentially without par dispatch:\n{fn_body}"
        );
    }

    // 3. f64_intrinsics must not cast f64 to f32 inside sqrt/floor/min
    let f64_body = lib
        .split("fn strata_sys_fn_")
        .find(|s| s.contains("f64_intrinsics"))
        .expect("f64_intrinsics");
    let f64_fn = f64_body.split("\nfn ").next().unwrap_or(f64_body);
    assert!(!f64_fn.contains("as f32).sqrt()"), "f64 sqrt must stay f64");

    // 4. u32_unsigned must compare/shift as u32 (not cast to i32)
    let u32_body = lib
        .split("fn strata_sys_fn_")
        .find(|s| s.contains("u32_unsigned"))
        .expect("u32_unsigned");
    let u32_fn = u32_body.split("\nfn ").next().unwrap_or(u32_body);
    assert!(
        u32_fn.contains("as u32") && u32_fn.contains(" > "),
        "u32 > 1 must compare as u32:\n{u32_fn}"
    );
    assert!(
        !u32_fn.contains("as i32) >"),
        "u32 > 1 must not cast to i32:\n{u32_fn}"
    );

    // 5. bool_array_field must fall back cleanly instead of typing [FfiBool; 4] as [bool; 4]
    let arr_body = lib
        .split("fn strata_sys_fn_")
        .find(|s| s.contains("bool_array_field"))
        .expect("bool_array_field");
    let arr_fn = arr_body.split("\nfn ").next().unwrap_or(arr_body);
    assert!(
        !arr_fn.contains("query_typed::<"),
        "bool array field should fall back from typed fast loop:\n{arr_fn}"
    );
}

#[test]
fn rust_guest_fixes_array_literal_assign_and_qualified_tag_canonical_name() {
    let src = r#"
module probe::sim @version(1.0.0);

component Pos { x: f32 = 0.0, y: f32 = 0.0 }
tag ActiveTag;
component RichArr {
flags: [bool; 4] = [false, false, false, false],
vecs: [vec3a; 2] = [vec3a(0.0, 0.0, 0.0), vec3a(0.0, 0.0, 0.0)],
}

sys set_arrays_and_tag() {
for e in query(p: &mut Pos).with<ActiveTag>() {
    e.p.x += 1.0;
}
for e in query(r: &mut RichArr) {
    e.r.flags = [true, true, false, false];
    e.r.vecs = [vec3a(1.0, 2.0, 3.0), vec3a(4.0, 5.0, 6.0)];
}
}

schedule FixedUpdate { set_arrays_and_tag }
"#;
    let sema = analyze_source("probe_sim.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    let art = emit(&mir, &RustGuestOptions::default()).expect("emit");
    let lib = &art.files[1].content;

    // 1. `StrataTag_*` CANONICAL_NAME must be qualified with `probe::sim::`.
    assert!(
        lib.contains("const CANONICAL_NAME: &'static str = \"probe::sim::ActiveTag\";"),
        "StrataTag_* CANONICAL_NAME must be qualified with module path:\n{}",
        lib.lines()
            .filter(|l| l.contains("CANONICAL_NAME"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // 2. `strata_set` must populate `self.flags` and `self.vecs` from `StrataVal::Arr`.
    assert!(
        lib.contains("if let StrataVal::Arr(_items) = val { for (_dst, val) in self.flags.iter_mut().zip(_items.into_iter()) { (*_dst) = FfiBool::from_bool(val.as_bool()); } }"),
        "strata_set for Ty::Array<Bool> must assign via StrataVal::Arr:\n{lib}"
    );
    assert!(
        lib.contains("if let StrataVal::Arr(_items) = val { for (_dst, val) in self.vecs.iter_mut().zip(_items.into_iter()) { (*_dst) = val.as_vec4(); } }"),
        "strata_set for Ty::Array<Vec3a> must assign via StrataVal::Arr"
    );
}

#[test]
fn rust_guest_phase2b_csr_array_store_option_up_cascade_and_fix64() {
    let src = r#"
module probe::phase2b @version(1.0.0);

relation ChildOf [exclusive];
component Pos3D { xyz: vec3 = vec3(0.0, 0.0, 0.0) }
component Faction { team: u32 = 0 }
component ArrBox { vals: [fix64; 3] = [1.0, 2.0, 3.0] }
component Shield { hp: f32 = 10.0 }
tag Target3D;

spatial_history HistXZ(
frames:    4,
cell_size: 4.0_m,
bounds:    vec2(-20.0_m, -20.0_m)..vec2(20.0_m, 20.0_m),
capacity:  16,
) over Target3D by Pos3D.xyz;

sys ops(h: &res HistXZ) {
let mut local_arr: [fix64; 2] = [1.5, 2.5];
local_arr[1] = local_arr[0] / 0.0;
for row in query(a: &mut ArrBox, sh: Option<&mut Shield>, f: &Faction).up<ChildOf>() {
    row.a.vals[0] = local_arr[1] + 2.0;
    if row.sh.is_some() {
        row.sh.unwrap().hp += 5.0;
    }
    let _t = row.f.team;
}
for hit in h.query_segment_at(0, vec3(0.0, 0.0, 0.0), vec3(8.0, 0.0, 8.0), 2.0_m) {
    let _e = hit.id;
}
}

schedule FixedUpdate { ops }
"#;
    let sema = analyze_source("rg_phase2b.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    let art = emit(&mir, &RustGuestOptions::default()).expect("emit rust_guest phase2b");
    let lib = &art.files[1].content;

    assert!(
        lib.contains("struct StrataSpatialCsrFrame"),
        "missing StrataSpatialCsrFrame"
    );
    assert!(
        lib.contains("it.reset()"),
        "CSR rebuild must emit it.reset() (Slot 10)"
    );
    assert!(
        lib.contains(".csr_scatter("),
        "missing CSR scatter helper call"
    );
    assert!(
        lib.contains("strata_query_segment_hits"),
        "missing real segment query"
    );
    assert!(
        lib.contains(".up_cascade::<"),
        "missing Slot 58 up_cascade call:\n{lib}"
    );
    assert!(
        lib.contains("strata_ptr_bytes_mut"),
        "missing ArrayStore on component field"
    );
    assert!(
        lib.contains("StrataVal::Arr("),
        "missing ArrayStore on stack array"
    );
}

#[test]
fn rust_guest_shadow_write_spatial_param_lookup_and_up_cascade_phys_col() {
    let src = r#"
module probe::rg_fixes @version(1.0.0);

component Pos2 { xy: vec2 = vec2(0.0, 0.0) }
component Vault { gold: i32 = 100, ok: bool = false }
component Faction { team: u32 = 0 }
tag Marker;

spatial_grid Grid2D(
    cell_size: 4.0_m,
    bounds: vec2(-16.0_m, -16.0_m)..vec2(16.0_m, 16.0_m),
    capacity: 16,
) over Pos2 by Pos2.xy;

spatial_history Hist2D(
    frames: 4,
    cell_size: 4.0_m,
    bounds: vec2(-16.0_m, -16.0_m)..vec2(16.0_m, 16.0_m),
    capacity: 16,
) over Pos2 by Pos2.xy;

sys check_all(g: &res Grid2D, h: &res Hist2D) {
    for row in query(v: &mut Vault) {
        atomic {
            row.v.gold += 50;
            require_true(row.v.ok);
        }
    }
    for hit in g.query_disc(vec2(0.0, 0.0), 5.0_m) {
        let _e = hit.id;
    }
    for hit in h.query_segment_at(0, vec2(0.0, 0.0), vec2(4.0, 4.0), 2.0_m) {
        let _e2 = hit.id;
    }
    for row in query(fac: Option<&Faction>).with<Marker>().up<ChildOf>() {
        if row.fac.is_some() {
            let _t = row.fac.unwrap().team;
        }
    }
}

schedule FixedUpdate { check_all }
"#;
    let sema = analyze_source("rg_fixes.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    let art = emit(&mir, &RustGuestOptions::default()).expect("emit rust_guest");
    let lib = &art.files[1].content;

    assert!(
        lib.contains("/* Shadow write") && lib.contains("(pre-image preserved) */"),
        "ShadowWrite must preserve pre-image without overwriting undo_slot:\n{lib}"
    );
    // Confirm no `slots[sid] = locals[` follows `/* Shadow write` inside the same match arm.
    for arm in lib.split("/* Shadow write").skip(1) {
        let block_tail = arm.split("__bb =").next().unwrap_or("");
        assert!(
            !block_tail.contains("slots[sid] = locals["),
            "ShadowWrite must not emit slots[sid] overwrite:\n{block_tail}"
        );
    }
    // Ensure ShadowWrite itself emits no slot overwrite by checking for tx_undo/SlotStore only.
    assert!(
        !lib.contains("strata_query_disc_hits(world, \"g\""),
        "must resolve spatial param `g` -> `Grid2D`:\n{lib}"
    );
    assert!(
        lib.contains("strata_query_disc_hits(world, \"Grid2D\""),
        "missing resolved Grid2D spatial lookup:\n{lib}"
    );
    assert!(
        !lib.contains("strata_query_segment_hits(world, \"h\""),
        "must resolve spatial param `h` -> `Hist2D`:\n{lib}"
    );
    assert!(
        lib.contains("strata_query_segment_hits(world, \"Hist2D\""),
        "missing resolved Hist2D spatial lookup:\n{lib}"
    );
    assert!(
        lib.contains("StrataPtr::Null"),
        "IterUpCascade miss must return StrataPtr::Null"
    );
    assert!(
        lib.contains("it.up_cascade::<") && lib.contains("_rel, _e, 0)"),
        "IterUpCascade with .with<Marker>() must pass physical term index 0:\n{lib}"
    );
}

#[test]
fn rust_guest_emits_param_set_for_conflicting_queries_and_query_for_non_conflicting() {
    let src = r#"
module rg::pset @version(1.0.0);

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
    let sema = analyze_source("rg_pset.strata", src);
    assert!(sema.ok(), "{:?}", sema.diagnostics);
    let mir = lower_to_mir(&sema);
    let art = emit(&mir, &RustGuestOptions::default()).expect("emit rust_guest param_set");
    let lib = &art.files[1].content;

    assert!(
        lib.contains(".param_set(|ps| {"),
        "conflicting task queries must emit .param_set(|ps| ...):\n{lib}"
    );
    assert!(
        lib.contains("ps.query(|mut q| {"),
        "param_set members must emit ps.query(...):\n{lib}"
    );

    let disjoint_reg = lib
        .split("app.system(c\"disjoint_steps\")")
        .nth(1)
        .and_then(|s| s.split(".register_handle(").next())
        .expect("disjoint_steps registration");
    assert!(
        disjoint_reg.contains(".query(|mut q| {"),
        "disjoint non-conflicting queries must emit .query(...):\n{disjoint_reg}"
    );
    assert!(
        !disjoint_reg.contains(".param_set("),
        "disjoint non-conflicting queries must NOT emit .param_set(...):\n{disjoint_reg}"
    );
}

#[test]
fn rust_guest_object_struct_ivec_enum_overrides_and_runtime_ivec() {
    let src = r#"
module test::rg_nb123 @version(1.0.0);

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
    let analyzed = analyze_source("rg_nb123.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let out = emit(&mir, &RustGuestOptions::default()).expect("rust_guest emit");
    let all_rs: String = out
        .files
        .iter()
        .filter(|f| f.path.ends_with(".rs"))
        .map(|f| f.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        all_rs.contains("StrataVal::Obj(") && all_rs.contains("StrataVal::U32("),
        "expected StrataVal::Obj / U32 initializers instead of Unit fallback:\n{all_rs}"
    );
    assert!(
        all_rs.contains("30000001")
            && all_rs.contains("-30000005")
            && all_rs.contains("3000000001")
            && all_rs.contains("4000000003"),
        "expected exact >2^24 integer vector literals preserved:\n{all_rs}"
    );
}

#[test]
fn rust_guest_object_casts_uvec_neg_ivec_binops_and_short_consts() {
    let src = r#"
module test::rg_wave1_fixes @version(1.0.0);

const BASE_HP: f32 = 42.5;

component BoxComp {
    cast_i32: i32 = 0,
    cast_fix: fix64 = 0.0,
    uv_cast: uvec2 = uvec2(0, 0),
    iv_bin: ivec2 = ivec2(0, 0),
    hp: f32 = 0.0,
}

object ObjBox {
    BoxComp {
        cast_i32: 3.9_f32 as i32,
        cast_fix: 3.9_f32 as i32,
        uv_cast: uvec2((-1_i32) as u32, (-(-5)) as u32),
        iv_bin: ivec2(-2147483647 - 1, 2147483647),
        hp: BASE_HP,
    },
}
"#;
    let analyzed = analyze_source("rg_wave1_fixes.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let out = emit(&mir, &RustGuestOptions::default()).expect("rust_guest emit");
    let all_rs: String = out
        .files
        .iter()
        .filter(|f| f.path.ends_with(".rs"))
        .map(|f| f.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        !all_rs.contains("16750372454i64") && all_rs.contains("wrapping_shl(32)"),
        "RustGuest cast_fix must truncate 3.9_f32 as i32 before Q32.32 scaling:\n{all_rs}"
    );
    assert!(
        !all_rs.contains("as u32).wrapping_neg()") && all_rs.contains("wrapping_neg()) as u32"),
        "RustGuest uvec2((-1_i32) as u32, (-(-5)) as u32) must not negate unsigned u32:\n{all_rs}"
    );
    assert!(
        all_rs.contains("wrapping_sub("),
        "RustGuest ivec2(-2147483647 - 1, ...) must emit wrapping_sub:\n{all_rs}"
    );
    assert!(
        all_rs.contains("42.5"),
        "RustGuest must resolve const BASE_HP:\n{all_rs}"
    );
}

#[test]
fn rust_guest_step2_iter3_vec_consts_neg_float_casts_enum16_and_option_alias() {
    let src = r#"
module test::rg_iter3 @version(1.0.0);

tag Tag;

enum Kind16 {
    Low = 1,
    High = 60000,
}

struct WithInlineStr {
    label: InlineStr<16> = "init",
}

component OtherComp {
    pad: i32 = 123,
    hp: f32 = 55.0,
}

component BoxRg {
    uv_one: uvec2 = uvec2::ZERO,
    uv_x: uvec2 = uvec2::ZERO,
    iv_y: ivec2 = ivec2::ZERO,
    iv3_z: ivec3 = ivec3::ZERO,
    v4_w: vec4 = vec4::ZERO,
    neg_i32: i32 = 0,
    neg_u32: u32 = 99,
    k16: Kind16 = Kind16::Low,
    arr16: [Kind16; 2] = [Kind16::Low, Kind16::High],
    w: WithInlineStr = WithInlineStr { label: "init" },
    shadow_iflet: i32 = 0,
}

object ObjRg {
    BoxRg {
        uv_one: uvec2::ONE,
        uv_x: uvec2::X,
        iv_y: ivec2::Y,
        iv3_z: ivec3::Z,
        v4_w: vec4::W,
        neg_i32: (-3.9_f32) as i32,
        neg_u32: (-3.9_f32) as u32,
        k16: Kind16::High,
        arr16: [Kind16::High, Kind16::Low],
    },
}

sys step_iter3_iflet() {
    for row in query(b: &mut BoxRg, oc: Option<&mut OtherComp>) {
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
    let analyzed = analyze_source("rg_iter3.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let out = emit(&mir, &RustGuestOptions::default()).expect("rust_guest emit");
    let all_rs: String = out
        .files
        .iter()
        .filter(|f| f.path.ends_with(".rs"))
        .map(|f| f.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        all_rs.contains("StrataVal::UVec2([1u32, 1u32])")
            && all_rs.contains("StrataVal::UVec2([1u32, 0u32])")
            && all_rs.contains("StrataVal::IVec2([0i32, 1i32])")
            && all_rs.contains("StrataVal::IVec3([0i32, 0i32, 1i32])")
            && all_rs.contains("StrataVal::Vec4([0.0f32, 0.0f32, 0.0f32, 1.0f32])"),
        "RustGuest vector unit constants missing:\n{all_rs}"
    );
    assert!(
        !all_rs.contains("(3.9f32).wrapping_neg()"),
        "RustGuest must not emit .wrapping_neg() on f32:\n{all_rs}"
    );
    assert!(
        all_rs.contains("60000i64 as u16") && !all_rs.contains("60000i64 as u8"),
        "RustGuest Kind16 must emit u16 without u8 truncation:\n{all_rs}"
    );
}

#[test]
fn rust_guest_step2_iter4_signed_enums_f64_narrow_casts_and_query_row_alias() {
    let src = r#"
module test::rg_iter4 @version(1.0.0);

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

component BoxRg {
    neg_a: NegAuto = NegAuto::Neg,
    neg_e: NegExplicit = NegExplicit::MinNeg,
    arr_neg: [NegAuto; 2] = [NegAuto::Neg, NegAuto::Pos],
    ov_f64_u64: u64 = 0,
    ov_huge_i8: i8 = 0,
    ov_nhuge_i8: i8 = 0,
    ov_huge_u8: u8 = 0,
    alias_sum: i32 = 0,
}

component Wallet1 { coins: i32 = 100 }

object ObjRg {
    BoxRg {
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

sys step_iter4_unwrap() {
    for row in query(b: &mut BoxRg) {
        let row2 = row;
        row2.b.alias_sum += 10;
    }
    let r1 = query_one(w: &mut Wallet1).on(ObjW1).unwrap();
    let r1b = r1;
    r1b.w.coins += 5;
}

sys step_iter4_expect() {
    let r2 = query_one(w: &mut Wallet1).on(ObjW1).expect("w1");
    r2.w.coins += 7;
}

schedule Update {
    seq OrderedAll { step_iter4_unwrap, step_iter4_expect }
}
"#;
    let analyzed = analyze_source("rg_iter4.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let out = emit(&mir, &RustGuestOptions::default()).expect("rust_guest emit");
    let all_rs: String = out
        .files
        .iter()
        .filter(|f| f.path.ends_with(".rs"))
        .map(|f| f.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        all_rs.contains("pub neg_a: i32")
            && all_rs.contains("pub neg_e: i32")
            && all_rs.contains("pub arr_neg: [i32; 2]")
            && all_rs.contains("BamFieldKind::I32"),
        "RustGuest signed enums must emit i32 fields & BamFieldKind::I32:\n{all_rs}"
    );
    assert!(
        all_rs.contains("1000000000000001.0f64")
            && all_rs.contains("as i8")
            && all_rs.contains("as u8"),
        "RustGuest object overrides must preserve f64 precision and i8/u8 saturating casts:\n{all_rs}"
    );
    assert!(
        !all_rs.contains("1000000000000000.0f32"),
        "RustGuest must not downgrade 1000000000000001.0_f64 to f32:\n{all_rs}"
    );
}

#[test]
fn rust_guest_step2_iter5_object_override_non_finite_float_casts() {
    let src = r#"
module test::rg_iter5 @version(1.0.0);

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
    let analyzed = analyze_source("rg_iter5.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let out = emit(&mir, &RustGuestOptions::default()).expect("rust_guest emit");
    let all_rs: String = out
        .files
        .iter()
        .filter(|f| f.path.ends_with(".rs"))
        .map(|f| f.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        all_rs.contains("as i8")
            && all_rs.contains("as i16")
            && all_rs.contains("as i32")
            && all_rs.contains("as i64")
            && all_rs.contains("as u8"),
        "RustGuest must emit saturating non-finite float-to-int casts:\n{all_rs}"
    );
}

#[test]
fn rust_guest_step2_iter6_non_finite_fix_casts_and_local_struct_write() {
    let src = r#"
module test::rg_iter6 @version(1.0.0);

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
    nested: InnerS = InnerS { si: 11, sf: 2.0 },
    last_sx: i32 = 0,
}

object ObjCast {
    CastRes {
        nan_fx32: (0.0_f32 / 0.0_f32) as fix32,
        inf_fx32: (1.0_f32 / 0.0_f32) as fix32,
        ninf_fx32: (-1.0_f32 / 0.0_f32) as fix32,
        nan_fx64: (0.0_f64 / 0.0_f64) as fix64,
        inf_fx64: (1.0_f64 / 0.0_f64) as fix64,
        ninf_fx64: (-1.0_f64 / 0.0_f64) as fix64,
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
    let analyzed = analyze_source("rg_iter6.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let out = emit(&mir, &RustGuestOptions::default()).expect("rust_guest emit");
    let all_rs: String = out
        .files
        .iter()
        .filter(|f| f.path.ends_with(".rs"))
        .map(|f| f.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        all_rs.contains("is_finite()") && all_rs.contains("StrataPtr::Slot"),
        "RustGuest must guard non-finite float->fix32/fix64 casts with is_finite() and emit Slot pointer writes:\n{all_rs}"
    );
}

#[test]
fn rust_guest_step2_iter7_constructors_fix_truncation_and_optional_row() {
    let src = r#"
module test::rg_iter7 @version(1.0.0);

enum BitKind { A = 0, B = 2 }

struct Sub {
    d: meters = meters(3.0),
    t: ms = ms(40.0),
    va: vec3a = vec3a(1.0, 2.0, 3.0),
    q: quat = quat(0.0, 0.0, 0.0, 1.0),
    col: rgba = rgba(0.25, 0.5, 0.75, 1.0),
    mask: u64 = bits(BitKind::A, BitKind::B),
}

component ResComp {
    id: u32 = 1,
    sub: Sub = Sub {},
    const_i: i32 = (100000.0_f32 as fix32) as i32,
    rt_neg: i64 = 0,
    rt_sat: i32 = 0,
    opt_val: i32 = 0,
    s_d_pos: i32 = 0,
}

object ObjIter7 {
    ResComp {
        id: 1,
        sub: Sub {
            d: meters(8.5),
            t: ms(99.0),
            va: Vec3a(2.0, 4.0, 6.0),
            q: Quat(0.0, 1.0, 0.0, 0.0),
            col: Rgba(1.0, 0.5, 0.25, 1.0),
            mask: bits(BitKind::B),
        },
        const_i: (-2.75_f32 as fix32) as i32,
    }
}

@node_pure fn id_f32(v: f32) -> f32 { v }
@node_pure fn id_f64(v: f64) -> f64 { v }

component Dummy { k: i32 = 7 }
object ObjDummy { Dummy { k: 7 } }

sys step_iter7() {
    let opt_r = query_one(c: &mut ResComp).on(ObjIter7);
    let opt2 = opt_r;
    if let Some(r) = opt2 {
        r.c.rt_neg = (id_f64(-2.75_f64) as fix64) as i64;
        r.c.rt_sat = (id_f32(100000.0_f32) as fix32) as i32;
        r.c.opt_val = r.c.const_i;
    }
    let s_d_pos: i32 = 5;
    for s_d_pos in query(s_d_pos: &Dummy.k) {
        let _x = s_d_pos;
    }
    let r2 = opt2.unwrap();
    r2.c.s_d_pos = s_d_pos + 1;
}

schedule FixedUpdate { step_iter7 }
"#;
    let analyzed = analyze_source("rg_iter7.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let out = emit(&mir, &RustGuestOptions::default()).expect("rust_guest iter7 emit");
    let all_rs: String = out
        .files
        .iter()
        .filter(|f| f.path.ends_with(".rs"))
        .map(|f| f.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        all_rs.contains("/ 65536") && all_rs.contains("/ 4_294_967_296"),
        "RustGuest must use truncating division for fix32/fix64 -> int casts:\n{all_rs}"
    );
}

#[test]
fn rust_guest_step2_iter8_native_observer_const_struct_and_bitset128() {
    let src = r#"
module test::rg_iter8 @version(1.0.0);

struct Sub { x: i32 = 3, fx: fix32 = 1.5 }
const C_SUB: Sub = Sub { x: 7, fx: 2.5 };
const C_ARR: [fix32; 2] = [1.5, 2.5];

component Marker;
component Out {
    val: i32 = 0,
    sub: Sub = C_SUB,
    arr: [fix32; 2] = C_ARR,
    bs128: BitSet<128> = bits(0, 70),
    va: vec3a = vec3a(1.0, 2.0, 3.0),
}
event EvPing { entity: Ref<Entity>, inc: i32 }

sys kick(e: Entity) {
    trigger(EvPing { entity: e, inc: 4 });
}

obs on_ping(trg: &Trigger<EvPing, Marker>) {
    let opt = query_one(o: &mut Out).on(trg.target);
    if let Some(r) = opt {
        r.o.val += trg.payload.inc;
        r.o.bs128 = bits(2, 99);
    }
}

schedule FixedUpdate { kick }
"#;
    let analyzed = analyze_source("rg_iter8.strata", src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let out = emit(&mir, &RustGuestOptions::default()).expect("rust_guest iter8 emit");
    let all_rs: String = out
        .files
        .iter()
        .filter(|f| f.path.ends_with(".rs"))
        .map(|f| f.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        all_rs.contains("observe_event")
            && all_rs.contains("with_watched")
            && all_rs.contains("build_with_ctx")
            && all_rs.contains("HostBridge::System(ctx)"),
        "RustGuest observer must emit native build_with_ctx observer wiring:\n{all_rs}"
    );
}

fn emit_all_rust(file: &str, src: &str) -> (MirModule, String) {
    let analyzed = analyze_source(file, src);
    assert!(analyzed.ok(), "sema failed: {:?}", analyzed.diagnostics);
    let mir = lower_to_mir(&analyzed);
    let out = emit(&mir, &RustGuestOptions::default()).expect("rust_guest emit");
    let all_rs = out
        .files
        .iter()
        .filter(|f| f.path.ends_with(".rs"))
        .map(|f| f.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    (mir, all_rs)
}

#[test]
fn rust_guest_math_types_and_par_reduction_regressions() {
    let src = r#"
module test::wave2b_math @version(1.0.0);

resource Stats {
    prod_i: i64 = 1,
    sum_v2: vec2 = vec2(0.0, 0.0),
    cnt: u32 = 0,
    any_flag: bool = false,
    all_flag: bool = true,
    qres: vec3 = vec3(0.0, 0.0, 0.0),
    fix_prod: fix32 = 1.0,
}

component Body {
    pos: vec3 = vec3(0.0, 0.0, 0.0),
    v4: vec4 = vec4(1.0, 2.0, 3.0, 4.0),
    va: vec3a = vec3a(1.0, 0.0, 0.0),
    vb: vec3a = vec3a(1.0, 0.0, 0.0),
    iv: ivec2 = ivec2(1, -2),
    uv: uvec2 = uvec2(2, 3),
    q: quat = quat(0.0, 0.0, 0.0, 1.0),
    f32x: fix32 = 2.0,
    f64x: fix64 = 3.0,
    sm: i8 = 0,
    val: i32 = 1,
    flag: bool = true,
}

component TagB { w: f32 = 2.0 }

const C_FIX64: fix64 = (4.0 as fix32) as fix64;
const C_FIX32: fix32 = (5.0 as fix64) as fix32;

fn bump_stats(st: &mut res Stats) {
    st.cnt += 1;
}

sys math_and_casts(st: &mut res Stats) {
    let c64 = C_FIX64;
    let c32 = C_FIX32;
    let r64 = c32 as fix64;
    let _r32 = c64 as fix32;
    let _a = abs(-2147483648_i32);
    let _s = sqr(3.0_f32);
    let _d = distance_sq(vec3(0.0, 0.0, 0.0), vec3(3.0, 4.0, 0.0));
    let wide_f: f32 = 500.0_f32;
    let _sat_i8 = wide_f as i8;

    for row in query(b: &mut Body) {
        row.b.sm = (row.b.v4.x * 500.0_f32) as i8;
        row.b.pos.xz = vec2(7.0, 8.0);
        let q1 = row.b.q * quat(0.0, 0.0, 0.0, 1.0);
        st.qres = q1 * row.b.pos;
        let _d4 = distance(row.b.v4, vec4(0.0, 0.0, 0.0, 0.0));
        let _ls4 = length_sq(row.b.v4);
        let _n4 = normalize(row.b.v4);
        let _l4 = lerp(row.b.v4, vec4(2.0, 4.0, 6.0, 8.0), 0.5);
        let _eq3a = row.b.va == row.b.vb;
        row.b.iv = row.b.iv + ivec2(1, 2);
        row.b.uv = row.b.uv * uvec2(2, 2);
        row.b.f64x = r64;
    }
}

@par(read_only, chunk = 64)
sys par_reduce_ops(st: &mut res Stats) {
    let (p_val, s_v2, f_prod, cnt, any_f, all_f) = for row in query(b: &Body) reduce (
        p_val: prod(2_i64, row.b.val as i64),
        s_v2: sum(vec2(0.0, 0.0), vec2(row.b.pos.x, row.b.pos.z)),
        f_prod: prod(1.0, row.b.f32x),
        cnt: count(row.b.val > 0),
        any_f: any(row.b.flag),
        all_f: all(row.b.flag)
    );
    st.prod_i = p_val;
    st.sum_v2 = s_v2;
    st.fix_prod = f_prod;
    st.cnt = cnt;
    st.any_flag = any_f;
    st.all_flag = all_f;

    // Secondary query after first query exercises query_idx == 1
    let mut sum_w = 0.0_f32;
    for sec in query(t: &TagB) {
        sum_w += sec.t.w;
    }
    let _sw = sum_w;
}

@par(chunk = 64)
sys par_transitive_res(st: &mut res Stats) {
    for row in query(b: &Body) {
        if row.b.val > 0 {
            bump_stats(st);
        }
    }
    for sec in query(t: &TagB) {
        if sec.t.w > 0.0 {
            bump_stats(st);
        }
    }
}

schedule FixedUpdate { math_and_casts, par_reduce_ops, par_transitive_res }
"#;
    let (_, all_rs) = emit_all_rust("wave2b_math.strata", src);
    assert!(
        all_rs.contains("wrapping_abs"),
        "PM-03 wrapping_abs missing"
    );
    assert!(
        all_rs.contains("as_i8()"),
        "PM-10 slow-path saturating as_i8 missing"
    );
    assert!(
        all_rs.contains("strata_fix32_mul") || all_rs.contains(">> 16) as i32"),
        "PM-08 fix32 prod missing"
    );
    assert!(
        all_rs.contains("strata_vec2_add") || all_rs.contains(")[0] + ("),
        "PM-14 vec2 sum missing"
    );
    assert!(
        all_rs.contains("query_mut(1)") && all_rs.contains("(1)"),
        "PM-14 secondary query index 1 missing"
    );
    assert!(
        all_rs.contains("strata_helper_bump_stats_") && !all_rs.contains("par_chunks("),
        "PM-06 transitive resource write helper / sequential fallback missing"
    );
}

#[test]
fn rust_guest_composites_tables_and_slot_type_regressions() {
    let src = r#"
module test::wave2b_comp @version(1.0.0);

enum Act { Slash }
resource Clock { dt: f32 = 0.016 }
component HealthV1 { cur: i32 = 10, label: InlineStr<16> = "ok" }
component Health { hp: i32 = 10, name_tag: InlineStr<16> = "ok" }

struct InnerCell {
    x: i32 = 1,
    lbl: InlineStr<16> = "cell",
}

struct TimerWrap {
    gw: GraceWindow,
    ib: InputBuffer<Act, 4>,
}

table Drops by Act {
    id: u32,
    inner: InnerCell,
} = {
    Slash => { id: 1, inner: InnerCell { x: 2, lbl: "cell" } },
};

component Holder {
    grid: [[u32; 2]; 2],
    cells: [InnerCell; 2],
    labels: [InlineStr<16>; 2],
    m: mat3,
    bs: BitSet<64>,
    sv: SmallVec<f32, 4>,
    wrap: TimerWrap,
    pair: (u32, f32) = (7, 2.5),
}

migrate Health from 1.0.0 to 2.0.0 (old: &HealthV1) -> Health {
    Health { hp: old.cur, name_tag: old.label }
}

const C_PAIR: (u32, f32) = (9, 3.5);

sys composite_work(clk: &res Clock) {
    let (pa, pb) = C_PAIR;
    let r0 = Drops[Act::Slash];
    let r1 = r0;
    let _copy_x = r1.inner.x;
    for row in query(h: &mut Holder) {
        row.h.grid[1][0] = pa;
        row.h.cells[1].x = 42;
        let _lbl = row.h.labels[1];
        row.h.bs.set(35);
        let _has = row.h.bs.has(35);
        row.h.sv.push(pb);
        row.h.wrap.gw.arm(0.5);
        row.h.wrap.gw.tick(clk.dt);
        row.h.wrap.ib.buffer(Act::Slash, 0.2);
        row.h.wrap.ib.tick(clk.dt);
    }
}

schedule FixedUpdate { composite_work }
"#;
    let (_, all_rs) = emit_all_rust("wave2b_comp.strata", src);
    assert!(
        all_rs.contains("pub bs: [u32; 2]"),
        "BUG-TL-01 word-aligned BitSet<64> sizing missing"
    );
    assert!(
        all_rs.contains("pub sv: [u32; 6]"),
        "BUG-TL-09 SmallVec<f32, 4> layout missing"
    );
    assert!(
        all_rs.contains("strata_ptr_bytes_mut") || all_rs.contains("strata_get_slot_bytes"),
        "BUG-TL-06 MutPtr/Slot byte write helpers missing"
    );
    assert!(
        all_rs.contains("migrate_src") && all_rs.contains("migrate_pod_component_column"),
        "BUG-TL-04 migrate emission missing"
    );
    assert!(
        all_rs.contains(".max("),
        "BUG-TL-05 GraceArm .max() missing"
    );
}

#[test]
fn rust_guest_ecs_flow_spatial_and_schedule_regressions() {
    let src = r#"
module test::wave2b_ecs @version(1.0.0);

event HitEv { dmg: i32 }
stream PulseMsg { tick: u32 }
relation ChildOf [exclusive];
relation Follows [exclusive];

component Unit {
    pos2: vec2 = vec2(1.0, 2.0),
    pos3: vec3 = vec3(1.0, 0.0, 2.0),
    hp: i32 = 10,
}
component Ally { hp: i32 = 5 }
resource Clock { dt: f32 = 0.02 }

object Hero { Unit { hp: 99 } }

spatial_grid GridXZ(
    cell_size: 4.0_m,
    bounds: vec2(-16.0_m, -16.0_m)..vec2(16.0_m, 16.0_m),
    plane: xz,
    capacity: 16,
) over Unit by Unit.pos3;

spatial_history HistXZ(
    frames: 4,
    cell_size: 4.0_m,
    bounds: vec2(-16.0_m, -16.0_m)..vec2(16.0_m, 16.0_m),
    plane: xz,
    capacity: 16,
) over Unit by Unit.pos3;

timeline StrikeTl @rate(60_hz) @duration(20_f) {
    window active = 4_f..12_f;
    at 6_f => emit(PulseMsg { tick: 1 });
}

sys on_start(cmds: &mut Commands) {
    let _e = Hero.entity();
    let p = cmds.spawn((Unit { hp: 20 },)).id();
    let c = cmds.spawn((Ally { hp: 5 },)).id();
    cmds.insert(c, Follows, p);
}

sys flow_step(
    cmds: &mut Commands,
    g: &res GridXZ,
    h: &res HistXZ,
    evw: &mut StreamWriter<PulseMsg>,
) {
    evw.send(PulseMsg { tick: 1 });
    for row in query(u: &mut? Unit).added() {
        if row.u.hp > 5 {
            row.u.hp += 1;
            if row.u.hp > 50 {
                return;
            }
        }
    }
    for hit in g.query_disc(vec2(1.0, 2.0), 4.0_m) {
        let _he = hit.entity;
    }
    for hit in h.query_segment_at(10_u32, vec3(0.0, 0.0, 0.0), vec3(4.0, 0.0, 0.0), 1.0_m) {
        let _se = hit.entity;
    }
    let pl = HitEv { dmg: 7 };
    cmds.trigger(Hero.entity(), pl);
}

sys flow_childof() {
    for row in query(a: &mut Ally).up<ChildOf>() {
        row.a.hp += 1;
    }
}

sys flow_follows() {
    for row in query(a: &mut Ally).up<Follows>() {
        row.a.hp += 2;
    }
}

sys flow_query_one() {
    for opt in query_one(u: &mut? Unit).on(Hero.entity()) {
        if let Some(r) = opt {
            r.u.hp += 3;
        }
    }
}

schedule Startup { on_start }
schedule FixedUpdate {
    flow_step,
    set InnerGrp after(flow_step) {
        flow_childof,
        flow_follows,
        flow_query_one
    }
}
"#;
    let (_, all_rs) = emit_all_rust("wave2b_ecs.strata", src);
    assert!(
        all_rs.contains("BAM_STORAGE_FLAG_MESSAGE") || all_rs.contains("0x00000008"),
        "EQ-02/GF-14 stream BAM_STORAGE_FLAG_MESSAGE missing"
    );
    assert!(
        all_rs.contains("resolve_component::<FfiChildOf>()"),
        "EQ-05/GF-02 ChildOf FfiChildOf resolve missing"
    );
    assert!(
        all_rs.contains("__strata_rel_parent_Follows"),
        "EQ-05/GF-02 custom relation companion handle missing"
    );
    assert!(
        all_rs.contains(".added::<"),
        "EQ-07 QueryBuilder::added missing"
    );
    assert!(
        all_rs.contains("mark_changed_range"),
        "EQ-06a/b dirty range flush missing"
    );
    assert!(
        all_rs.contains("strata_timeline_advance_bytes"),
        "GF-03 timeline helper missing"
    );
    assert!(
        all_rs.contains("__strata_named_objects_startup"),
        "GF-06 Startup named-objects ordering missing"
    );
    assert!(
        all_rs.contains("(tick_offset as usize) >= frames"),
        "BUG-SW-05 spatial_history OOB frame guard missing"
    );
    assert!(
        all_rs.contains("center_is_vec2"),
        "BUG-SW-06 2D center projection missing"
    );
    assert!(
        all_rs.contains("ScheduleSetBuilder") && all_rs.contains(".after("),
        "BUG-SW-07a/c schedule set & constraint ordering missing"
    );
}

#[test]
fn rust_guest_net_soa_mod_resource_and_large_rpc_regressions() {
    let src = r#"
module test::wave2b_net @version(1.0.0);

@net(reliable, channel = 0)
@soa
component SoaActor {
    hot { pos: vec3 = vec3(0.0, 0.0, 0.0) }
    cold meta { hp: u32 = 100 }
}

@net(reliable, channel = 1)
resource ModNetState {
    score: u32 = 0,
    phase: u8 = 1,
}

@net_rpc(direction = client_to_server, reliability = reliable, channel = 2)
rpc BigBlobRpc {
    seq_id: u32,
    blob: [u8; 48],
}

sys tick_net(st: &mut res ModNetState) {
    st.score += 1;
}

schedule FixedUpdate { tick_net }
"#;
    let (_, all_rs) = emit_all_rust("wave2b_net.strata", src);
    assert!(
        all_rs.contains("strata_net_encode_SoaActor(src_0:")
            && all_rs.contains("strata_net_decode_SoaActor(pkt: &StrataNetPacket, out_0:")
            && all_rs.contains(".or_group(1,"),
        "NT-03 multi-stratum @soa codec & TX or_group missing"
    );
    assert!(
        all_rs.contains("mod_res_") && all_rs.contains("_shadow:"),
        "NT-04 module-local @net resource shadow missing"
    );
    assert!(
        all_rs.contains("pub struct StrataRpc_BigBlobRpc")
            && all_rs.contains("impl Default for StrataRpc_BigBlobRpc")
            && all_rs.contains("[0u8; 48]"),
        "NT-06 explicit Default impl for [u8; 48] RPC missing"
    );
}
